//! Vollständige MFT-Zeitachse einschließlich gelöschter Datensätze.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Write};
use std::rc::Rc;

use rayon::prelude::*;
use serde::Serialize;
use stratum_core::time::filetime_to_iso;
use stratum_core::ImageReader;
use stratum_ntfs::{FileNameInfo, NtfsTimes, NtfsVolume, RecordInfo};

use crate::FsIndex;

/// Beschreibung der Datenquelle im Hauptreport.
pub const MFT_TIMELINE_SOURCE: &str =
    "$MFT aller NTFS-Volumes, gültige belegte und gelöschte FILE-Datensätze";

/// Zusammenfassung einer geschriebenen MFT-Zeitachse.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MftTimelineSummary {
    /// Laut `$MFT` vorhandene Datensatzplätze.
    pub datensaetze: u64,
    /// Erfolgreich gelesene FILE-Datensätze.
    pub lesbar: u64,
    /// Aktuell belegte Datensätze.
    pub belegt: u64,
    /// Nicht mehr belegte, aber noch lesbare Datensätze.
    pub geloescht: u64,
    /// Nicht als gültiger FILE-Datensatz lesbare Plätze.
    pub fehler: u64,
    /// Geschriebene MACB-Ereignisse.
    pub ereignisse: u64,
    /// Ereignisse aus `$STANDARD_INFORMATION`.
    pub si_ereignisse: u64,
    /// Ereignisse aus `$FILE_NAME`.
    pub fn_ereignisse: u64,
    /// Verarbeitete Volume-Offsets.
    pub volumes: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct EventRef {
    filetime: u64,
    record_index: usize,
    name_index: Option<usize>,
    kind: u8,
}

#[derive(Debug, Serialize)]
struct EventLine<'a> {
    volume_offset: u64,
    mft_record: u64,
    sequenz: u16,
    status: &'static str,
    typ: &'static str,
    mft_record_offset: Option<u64>,
    filetime: u64,
    zeit_utc: String,
    macb: &'static str,
    ereignis: &'static str,
    quelle: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_record: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_sequenz: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pfad: Option<String>,
    pfad_status: &'static str,
}

/// Schreibt eine chronologische JSON-Lines-Zeitachse aus allen gültigen
/// MFT-Datensätzen. Jede Zeile ist genau ein SI- oder FN-MACB-Ereignis.
///
/// Gelöschte Datensätze werden über das fehlende `IN_USE`-Flag erkannt. Ein
/// historischer Pfad wird nur ausgegeben, wenn jede Elternreferenz samt
/// Sequenznummer auf einen lesbaren Datensatz zeigt. Dateiinhalte werden nicht
/// gelesen und das Image bleibt unverändert.
pub fn write_mft_timeline<W: Write>(
    img: &ImageReader,
    volumes: &[FsIndex],
    mut out: W,
) -> std::io::Result<MftTimelineSummary> {
    let mut summary = MftTimelineSummary::default();
    for volume in volumes {
        let offset = volume.target.offset;
        let size = volume.target.size;
        let count = NtfsVolume::open(img, offset, size)
            .and_then(|mut v| v.mft_record_count())
            .map_err(invalid_data)?;
        let count_usize = usize::try_from(count)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "$MFT ist zu groß"))?;
        let records: Vec<Option<RecordInfo>> = (0..count_usize)
            .into_par_iter()
            .map_init(
                || NtfsVolume::open(img, offset, size).ok(),
                |volume, record| match volume {
                    Some(volume) => volume.record_info(record as u64, None).ok(),
                    None => None,
                },
            )
            .collect();

        let by_record: HashMap<u64, usize> = records
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|r| (r.mft_record, i)))
            .collect();
        let indexed_paths = indexed_paths(volume);
        let mut cache = PathCache::new(&records, &by_record);
        let mut events = Vec::new();
        for (record_index, record) in records.iter().enumerate() {
            let Some(record) = record else { continue };
            if let Some(times) = record.si_times {
                add_times(&mut events, record_index, None, times);
            }
            for (name_index, name) in record.file_names.iter().enumerate() {
                if name.namespace != "dos" {
                    add_times(&mut events, record_index, Some(name_index), name.times);
                }
            }
        }
        events.sort_unstable_by_key(|e| {
            (
                e.filetime,
                records[e.record_index]
                    .as_ref()
                    .map_or(u64::MAX, |r| r.mft_record),
                e.name_index.unwrap_or(usize::MAX),
                e.kind,
            )
        });

        for event in events {
            let Some(record) = &records[event.record_index] else {
                continue;
            };
            let name = event.name_index.map(|i| &record.file_names[i]);
            let (path, path_status) = event_path(record, name, &mut cache, &indexed_paths);
            let (macb, action) = event_kind(event.kind);
            let Some(utc) = filetime_to_iso(event.filetime) else {
                continue;
            };
            let line = EventLine {
                volume_offset: offset,
                mft_record: record.mft_record,
                sequenz: record.sequence,
                status: if record.in_use { "belegt" } else { "geloescht" },
                typ: if record.is_directory {
                    "verzeichnis"
                } else {
                    "datei"
                },
                mft_record_offset: record.record_offset,
                filetime: event.filetime,
                zeit_utc: utc,
                macb,
                ereignis: action,
                quelle: if name.is_some() {
                    "$FILE_NAME"
                } else {
                    "$STANDARD_INFORMATION"
                },
                name: name.map(|n| n.name.as_str()),
                namespace: name.map(|n| n.namespace),
                parent_record: name.map(|n| n.parent_record),
                parent_sequenz: name.map(|n| n.parent_sequence),
                pfad: path,
                pfad_status: path_status,
            };
            serde_json::to_writer(&mut out, &line).map_err(Error::other)?;
            out.write_all(b"\n")?;
            summary.ereignisse += 1;
            if name.is_some() {
                summary.fn_ereignisse += 1;
            } else {
                summary.si_ereignisse += 1;
            }
        }

        summary.datensaetze += count;
        summary.lesbar += records.iter().filter(|r| r.is_some()).count() as u64;
        summary.belegt += records
            .iter()
            .filter(|r| r.as_ref().is_some_and(|r| r.in_use))
            .count() as u64;
        summary.geloescht += records
            .iter()
            .filter(|r| r.as_ref().is_some_and(|r| !r.in_use))
            .count() as u64;
        summary.fehler += records.iter().filter(|r| r.is_none()).count() as u64;
        summary.volumes.push(offset);
    }
    out.flush()?;
    Ok(summary)
}

fn invalid_data(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::InvalidData, error.to_string())
}

fn add_times(
    events: &mut Vec<EventRef>,
    record_index: usize,
    name_index: Option<usize>,
    times: NtfsTimes,
) {
    for (kind, filetime) in [
        (0, times.created),
        (1, times.modified),
        (2, times.mft_modified),
        (3, times.accessed),
    ] {
        if filetime != 0 {
            events.push(EventRef {
                filetime,
                record_index,
                name_index,
                kind,
            });
        }
    }
}

fn event_kind(kind: u8) -> (&'static str, &'static str) {
    match kind {
        0 => ("B", "erstellt"),
        1 => ("M", "inhalt_geaendert"),
        2 => ("C", "metadaten_geaendert"),
        _ => ("A", "zugegriffen"),
    }
}

fn indexed_paths(volume: &FsIndex) -> HashMap<u64, Vec<&str>> {
    let mut paths: HashMap<u64, Vec<&str>> = HashMap::new();
    for entry in volume.directories.iter().chain(&volume.files) {
        paths.entry(entry.mft_record).or_default().push(&entry.path);
    }
    for values in paths.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    paths
}

fn event_path(
    record: &RecordInfo,
    name: Option<&FileNameInfo>,
    cache: &mut PathCache<'_>,
    indexed: &HashMap<u64, Vec<&str>>,
) -> (Option<String>, &'static str) {
    if record.in_use {
        if let Some(paths) = indexed.get(&record.mft_record) {
            if let Some(name) = name {
                if let Some(path) = paths.iter().find(|p| {
                    p.rsplit('\\')
                        .next()
                        .is_some_and(|n| n.eq_ignore_ascii_case(&name.name))
                }) {
                    return (Some((*path).to_string()), "index");
                }
            } else if let Some(path) = paths.first() {
                return (Some((*path).to_string()), "index");
            }
        }
    }
    let chosen = name.or_else(|| preferred_name(record));
    let Some(chosen) = chosen else {
        return (None, "unbekannt");
    };
    match cache.path(chosen) {
        Some(path) => (Some(path), "rekonstruiert"),
        None => (None, "unbekannt"),
    }
}

/// Höchste rekonstruierte Verzeichnistiefe; tiefere Ketten bleiben unbekannt.
const MAX_DEPTH: usize = 128;

/// Aufgelöster Verzeichnispfad und seine Tiefe unter der Wurzel.
type DirPath = (Rc<str>, usize);

/// Rekonstruiert historische Pfade. Jedes Verzeichnis (Datensatz und
/// Sequenznummer) wird nur einmal aufgelöst und dann wiederverwendet.
struct PathCache<'a> {
    records: &'a [Option<RecordInfo>],
    by_record: &'a HashMap<u64, usize>,
    dirs: HashMap<(u64, u16), Option<DirPath>>,
}

impl<'a> PathCache<'a> {
    fn new(records: &'a [Option<RecordInfo>], by_record: &'a HashMap<u64, usize>) -> Self {
        Self {
            records,
            by_record,
            dirs: HashMap::new(),
        }
    }

    /// Pfad zu einem Namen, nur wenn die ganze Elternkette samt
    /// Sequenznummern zu lesbaren Datensätzen passt.
    fn path(&mut self, name: &FileNameInfo) -> Option<String> {
        let (prefix, _) = self.dir(name.parent_record, name.parent_sequence)?;
        Some(join(&prefix, &name.name))
    }

    /// Pfad und Tiefe eines Verzeichnisses. Die Kette wird iterativ nach oben
    /// verfolgt, damit manipulierte Ketten weder den Stack noch die Laufzeit
    /// sprengen. Zyklen und zu tiefe Ketten ergeben `None`.
    fn dir(&mut self, record: u64, sequence: u16) -> Option<DirPath> {
        let records = self.records;
        let mut chain: Vec<((u64, u16), &'a FileNameInfo)> = Vec::new();
        let mut key = (record, sequence);
        let base = loop {
            if let Some(hit) = self.dirs.get(&key) {
                break hit.clone();
            }
            if chain.len() >= MAX_DEPTH {
                // Nicht zwischenspeichern: flachere Teile der Kette können von
                // sich aus sehr wohl auflösbar sein.
                return None;
            }
            if chain.iter().any(|(k, _)| *k == key) {
                break None;
            }
            let Some(node) = self
                .by_record
                .get(&key.0)
                .and_then(|&i| records.get(i))
                .and_then(Option::as_ref)
                .filter(|node| node.sequence == key.1)
            else {
                break None;
            };
            if key.0 == 5 {
                let root = Some((Rc::from(""), 0));
                self.dirs.insert(key, root.clone());
                break root;
            }
            let Some(name) = preferred_name(node) else {
                break None;
            };
            chain.push((key, name));
            key = (name.parent_record, name.parent_sequence);
        };
        let mut current = base;
        for (key, name) in chain.into_iter().rev() {
            current = current
                .map(|(prefix, depth)| (Rc::from(join(&prefix, &name.name)), depth + 1))
                .filter(|(_, depth)| *depth < MAX_DEPTH);
            self.dirs.insert(key, current.clone());
        }
        current
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}\\{name}")
    }
}

fn preferred_name(record: &RecordInfo) -> Option<&FileNameInfo> {
    record
        .file_names
        .iter()
        .filter(|n| n.namespace != "dos")
        .min_by_key(|n| match n.namespace {
            "win32" => 0,
            "win32_dos" => 1,
            _ => 2,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name: &str, parent: u64, parent_sequence: u16) -> FileNameInfo {
        FileNameInfo {
            name: name.into(),
            namespace: "win32",
            parent_record: parent,
            parent_sequence,
            times: NtfsTimes::default(),
        }
    }

    fn record(number: u64, sequence: u16, file_names: Vec<FileNameInfo>) -> RecordInfo {
        RecordInfo {
            mft_record: number,
            sequence,
            record_offset: Some(number * 1024),
            in_use: false,
            is_directory: false,
            hard_links: 0,
            si_times: None,
            file_attributes: 0,
            fn_times: None,
            file_names,
            data_size: None,
            streams: Vec::new(),
            reparse_tag: None,
            wof: None,
        }
    }

    #[test]
    fn historischer_pfad_nur_mit_passender_sequenz() {
        let records = vec![
            Some(record(5, 1, Vec::new())),
            Some(record(10, 3, vec![name("Ordner", 5, 1)])),
            Some(record(11, 7, vec![name("weg.txt", 10, 3)])),
        ];
        let by_record = HashMap::from([(5, 0), (10, 1), (11, 2)]);
        let pfad = |records: &[Option<RecordInfo>]| {
            PathCache::new(records, &by_record).path(&records[2].as_ref().unwrap().file_names[0])
        };
        assert_eq!(pfad(&records), Some("Ordner\\weg.txt".into()));
        let mut broken = records.clone();
        broken[1].as_mut().unwrap().sequence = 4;
        assert!(pfad(&broken).is_none());
        broken[1].as_mut().unwrap().sequence = 3;
        broken[1].as_mut().unwrap().file_names[0].parent_sequence = 2;
        assert!(pfad(&broken).is_none());
    }

    #[test]
    fn zyklen_und_zu_tiefe_ketten_bleiben_unbekannt() {
        // 12 und 13 verweisen gegenseitig aufeinander.
        let mut records = vec![
            Some(record(5, 1, Vec::new())),
            Some(record(12, 1, vec![name("a", 13, 1)])),
            Some(record(13, 1, vec![name("b", 12, 1)])),
        ];
        let mut by_record = HashMap::from([(5, 0), (12, 1), (13, 2)]);
        assert!(PathCache::new(&records, &by_record)
            .path(&name("x", 12, 1))
            .is_none());

        // Kette aus 200 Verzeichnissen unter der Wurzel.
        records.truncate(1);
        by_record = HashMap::from([(5, 0)]);
        for i in 0..200u64 {
            let parent = if i == 0 { 5 } else { 99 + i };
            records.push(Some(record(100 + i, 1, vec![name("d", parent, 1)])));
            by_record.insert(100 + i, records.len() - 1);
        }
        let mut cache = PathCache::new(&records, &by_record);
        assert!(cache.path(&name("x", 299, 1)).is_none());
        let flach = cache.path(&name("x", 100, 1)).unwrap();
        assert_eq!(flach, "d\\x");
        assert_eq!(
            cache
                .path(&name("x", 226, 1))
                .unwrap()
                .matches('\\')
                .count(),
            MAX_DEPTH - 1
        );
        // Mit und ohne Zwischenspeicher dieselbe Grenze.
        assert!(cache.path(&name("x", 227, 1)).is_none());
        assert!(PathCache::new(&records, &by_record)
            .path(&name("x", 227, 1))
            .is_none());
    }

    #[test]
    fn macb_zuordnung() {
        assert_eq!(event_kind(0), ("B", "erstellt"));
        assert_eq!(event_kind(1), ("M", "inhalt_geaendert"));
        assert_eq!(event_kind(2), ("C", "metadaten_geaendert"));
        assert_eq!(event_kind(3), ("A", "zugegriffen"));
    }

    /// Bisherige rekursive Auflösung als Referenz für den Vergleich.
    fn referenz(
        name: &FileNameInfo,
        records: &[Option<RecordInfo>],
        by_record: &HashMap<u64, usize>,
        seen: &mut std::collections::HashSet<u64>,
    ) -> Option<String> {
        if !seen.insert(name.parent_record) {
            return None;
        }
        let parent = records
            .get(*by_record.get(&name.parent_record)?)?
            .as_ref()?;
        if parent.sequence != name.parent_sequence {
            return None;
        }
        if name.parent_record == 5 {
            return Some(name.name.clone());
        }
        let prefix = referenz(preferred_name(parent)?, records, by_record, seen)?;
        Some(format!("{prefix}\\{}", name.name))
    }

    #[test]
    fn gleiche_pfade_wie_die_rekursive_aufloesung() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        for _ in 0..50 {
            let mut records = vec![Some(record(5, 1, Vec::new()))];
            let mut by_record = HashMap::from([(5, 0)]);
            for i in 0..300u64 {
                let parent = if next(5) == 0 { 5 } else { 100 + next(300) };
                let parent_sequence = if next(20) == 0 { 2 } else { 1 };
                let nummer = 100 + i;
                records.push(Some(record(
                    nummer,
                    1,
                    vec![name(&format!("n{nummer}"), parent, parent_sequence)],
                )));
                by_record.insert(nummer, records.len() - 1);
            }
            let mut cache = PathCache::new(&records, &by_record);
            for index in (1..records.len()).rev() {
                let name = &records[index].as_ref().unwrap().file_names[0];
                let erwartet = referenz(
                    name,
                    &records,
                    &by_record,
                    &mut std::collections::HashSet::new(),
                );
                assert_eq!(cache.path(name), erwartet);
            }
        }
    }
}
