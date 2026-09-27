//! Dateikatalog: alle Dateien und Verzeichnisse der indizierten NTFS-Bereiche
//! mit ihren Metadaten, als JSON Lines (ein Eintrag je Zeile).
//!
//! Grundlage ist der vorhandene Pfad-Index, der Verzeichnisbaum wird also nicht
//! erneut durchlaufen. Je Eintrag wird nur der MFT-Datensatz gelesen, nie der
//! Dateiinhalt. Die Arbeit läuft blockweise parallel und wird direkt
//! geschrieben, der Speicherbedarf hängt daher nicht von der Größe des
//! Dateisystems ab. Die Einträge sind nach Volume und Pfad sortiert, so dass
//! dasselbe Image stets einen bytegleichen Katalog ergibt.
//!
//! Erfasst werden nur Einträge, die über den Verzeichnisbaum erreichbar sind.
//! Gelöschte oder verwaiste MFT-Datensätze fehlen hier.

use std::io::Write;

use rayon::prelude::*;
use serde::Serialize;
use stratum_core::time::filetime_to_iso;
use stratum_core::ImageReader;
use stratum_ntfs::{NtfsTimes, NtfsVolume, RecordInfo};

use crate::{FileEntry, FsIndex};

/// Einträge je Schreibblock. Begrenzt den Speicher für serialisierte Zeilen.
const BATCH: usize = 16_384;
/// Einträge je paralleler Arbeitseinheit innerhalb eines Blocks.
const TASK: usize = 512;

/// Beschreibung der Katalogquelle für den Report.
pub const CATALOG_SOURCE: &str =
    "Verzeichnisindex der NTFS-Volumes, nur zugeordnete Einträge (keine gelöschten MFT-Datensätze)";

/// Zusammenfassung eines geschriebenen Katalogs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CatalogSummary {
    /// Anzahl aller Einträge.
    pub eintraege: u64,
    /// Davon Dateien.
    pub dateien: u64,
    /// Davon Verzeichnisse.
    pub verzeichnisse: u64,
    /// Einträge, deren MFT-Datensatz nicht lesbar war (Eintrag mit `fehler`).
    pub fehler: u64,
    /// Verzeichnisse, deren Inhalt nicht lesbar war (Eintrag mit `inhalt_fehler`).
    pub verzeichnisse_ohne_inhalt: u64,
    /// Volume-Offsets, die in den Katalog eingegangen sind.
    pub volumes: Vec<u64>,
}

/// Die vier Zeitstempel als ISO 8601 UTC mit 100-ns-Auflösung.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct IsoTimes {
    erstellt: Option<String>,
    geaendert: Option<String>,
    mft_geaendert: Option<String>,
    zugriff: Option<String>,
}

impl From<NtfsTimes> for IsoTimes {
    fn from(t: NtfsTimes) -> Self {
        Self {
            erstellt: filetime_to_iso(t.created),
            geaendert: filetime_to_iso(t.modified),
            mft_geaendert: filetime_to_iso(t.mft_modified),
            zugriff: filetime_to_iso(t.accessed),
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Stream {
    name: String,
    groesse: u64,
}

/// Eine Katalogzeile.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct Line<'a> {
    volume_offset: u64,
    mft_record: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequenz: Option<u16>,
    parent_record: u64,
    typ: &'static str,
    pfad: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    groesse: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    si: Option<IsoTimes>,
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    fn_times: Option<IsoTimes>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attribute: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    streams: Vec<Stream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardlinks: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reparse_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wof: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mft_record_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fehler: Option<String>,
    /// Verzeichnis, dessen Einträge nicht lesbar waren; sein Inhalt fehlt im Katalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    inhalt_fehler: Option<&'a str>,
}

/// Windows-Dateiattribute mit ihren Katalognamen.
const ATTRIBUTE_NAMES: [(u32, &str); 11] = [
    (0x0001, "schreibgeschuetzt"),
    (0x0002, "versteckt"),
    (0x0004, "system"),
    (0x0020, "archiv"),
    (0x0100, "temporaer"),
    (0x0200, "sparse"),
    (0x0400, "reparse_point"),
    (0x0800, "komprimiert"),
    (0x1000, "offline"),
    (0x2000, "nicht_indiziert"),
    (0x4000, "verschluesselt"),
];

fn attribute_names(bits: u32) -> Vec<&'static str> {
    ATTRIBUTE_NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Baut eine Katalogzeile aus Indexeintrag und gelesenem Datensatz.
fn line<'a>(
    volume_offset: u64,
    entry: &'a FileEntry,
    is_directory: bool,
    info: Result<RecordInfo, String>,
) -> Line<'a> {
    let name = entry.path.rsplit('\\').next().unwrap_or(&entry.path);
    let mut l = Line {
        volume_offset,
        mft_record: entry.mft_record,
        sequenz: None,
        parent_record: entry.parent_record,
        typ: if is_directory { "verzeichnis" } else { "datei" },
        pfad: &entry.path,
        name,
        groesse: None,
        si: None,
        fn_times: None,
        attribute: Vec::new(),
        streams: Vec::new(),
        hardlinks: None,
        reparse_tag: None,
        wof: None,
        mft_record_offset: None,
        fehler: None,
        inhalt_fehler: None,
    };
    match info {
        Ok(info) => {
            l.sequenz = Some(info.sequence);
            l.groesse = info.data_size;
            l.si = info.si_times.map(IsoTimes::from);
            l.fn_times = info.fn_times.map(IsoTimes::from);
            l.attribute = attribute_names(info.file_attributes);
            l.streams = info
                .streams
                .into_iter()
                .map(|s| Stream {
                    name: s.name,
                    groesse: s.size,
                })
                .collect();
            l.hardlinks = Some(info.hard_links);
            l.reparse_tag = info.reparse_tag.map(|t| format!("0x{t:08x}"));
            l.wof = info.wof;
            l.mft_record_offset = info.record_offset;
        }
        Err(e) => {
            // Ohne lesbaren Datensatz bleibt die Größe aus dem Verzeichniseintrag.
            if !is_directory {
                l.groesse = Some(entry.size);
            }
            l.fehler = Some(e);
        }
    }
    l
}

/// Schreibt den Katalog aller Volumes als JSON Lines nach `out`.
pub fn write_catalog<W: Write>(
    img: &ImageReader,
    volumes: &[FsIndex],
    mut out: W,
) -> std::io::Result<CatalogSummary> {
    let mut summary = CatalogSummary::default();
    for v in volumes {
        let (offset, size) = (v.target.offset, v.target.size);
        let mut entries: Vec<(&FileEntry, bool)> = v
            .directories
            .iter()
            .map(|e| (e, true))
            .chain(v.files.iter().map(|e| (e, false)))
            .collect();
        entries.sort_unstable_by(|a, b| {
            a.0.path
                .cmp(&b.0.path)
                .then(a.0.mft_record.cmp(&b.0.mft_record))
        });

        for batch in entries.chunks(BATCH) {
            let parts: Vec<(Vec<u8>, u64)> = batch
                .par_chunks(TASK)
                .map_init(
                    || NtfsVolume::open(img, offset, size).map_err(|e| e.to_string()),
                    |vol, task| {
                        let mut buf = Vec::with_capacity(task.len() * 400);
                        let mut errors = 0;
                        for &(entry, is_dir) in task {
                            let info = match vol {
                                Ok(vol) => vol
                                    .record_info(entry.mft_record, Some(entry.parent_record))
                                    .map_err(|e| e.to_string()),
                                Err(e) => Err(format!("Volume nicht lesbar: {e}")),
                            };
                            errors += u64::from(info.is_err());
                            let mut l = line(offset, entry, is_dir, info);
                            if is_dir {
                                l.inhalt_fehler = v
                                    .unreadable_dirs
                                    .binary_search_by_key(&entry.mft_record, |(rec, _)| *rec)
                                    .ok()
                                    .map(|i| v.unreadable_dirs[i].1.as_str());
                            }
                            // Serialisierung eines eigenen, einfachen Typs scheitert nicht.
                            if serde_json::to_writer(&mut buf, &l).is_ok() {
                                buf.push(b'\n');
                            }
                        }
                        (buf, errors)
                    },
                )
                .collect();
            for (buf, errors) in parts {
                out.write_all(&buf)?;
                summary.fehler += errors;
            }
        }
        summary.verzeichnisse += v.directories.len() as u64;
        summary.verzeichnisse_ohne_inhalt += v.unreadable_dirs.len() as u64;
        summary.dateien += v.files.len() as u64;
        summary.volumes.push(offset);
    }
    summary.eintraege = summary.dateien + summary.verzeichnisse;
    out.flush()?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> FileEntry {
        FileEntry {
            path: path.into(),
            mft_record: 42,
            size: 7,
            parent_record: 5,
        }
    }

    #[test]
    fn zeile_mit_metadaten() {
        let e = entry(r"Users\a\notiz.txt");
        let info = RecordInfo {
            mft_record: 42,
            sequence: 3,
            record_offset: Some(4096),
            is_directory: false,
            hard_links: 1,
            si_times: Some(NtfsTimes {
                created: 132_539_328_000_000_000,
                modified: 132_539_328_000_000_001,
                mft_modified: 0,
                accessed: 132_539_328_000_000_000,
            }),
            file_attributes: 0x0002 | 0x0020,
            fn_times: None,
            data_size: Some(10),
            streams: vec![stratum_ntfs::NamedStream {
                name: "Zone.Identifier".into(),
                size: 26,
            }],
            reparse_tag: Some(0x8000_0017),
            wof: Some("XPRESS8K"),
        };
        let json = serde_json::to_value(line(1_048_576, &e, false, Ok(info))).unwrap();
        assert_eq!(json["name"], "notiz.txt");
        assert_eq!(json["typ"], "datei");
        assert_eq!(json["groesse"], 10);
        assert_eq!(json["si"]["erstellt"], "2021-01-01T00:00:00.0000000Z");
        assert_eq!(json["si"]["geaendert"], "2021-01-01T00:00:00.0000001Z");
        assert!(json["si"]["mft_geaendert"].is_null());
        assert!(json.get("fn").is_none());
        assert_eq!(
            json["attribute"],
            serde_json::json!(["versteckt", "archiv"])
        );
        assert_eq!(json["streams"][0]["name"], "Zone.Identifier");
        assert_eq!(json["mft_record_offset"], 4096);
        assert_eq!(json["reparse_tag"], "0x80000017");
        assert_eq!(json["wof"], "XPRESS8K");
        assert!(json.get("fehler").is_none());
    }

    #[test]
    fn zeile_bei_lesefehler() {
        let e = entry("kaputt.bin");
        let json =
            serde_json::to_value(line(0, &e, false, Err("Datensatz defekt".into()))).unwrap();
        assert_eq!(json["fehler"], "Datensatz defekt");
        assert_eq!(json["groesse"], 7);
        assert!(json.get("si").is_none());
        let dir = serde_json::to_value(line(0, &e, true, Err("x".into()))).unwrap();
        assert_eq!(dir["typ"], "verzeichnis");
        assert!(dir.get("groesse").is_none());
    }

    #[test]
    fn leerer_katalog() {
        let bytes = [0u8; 4096];
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("img");
        std::fs::write(&p, bytes).unwrap();
        let img = ImageReader::open(&p).unwrap();
        let mut out = Vec::new();
        let s = write_catalog(&img, &[], &mut out).unwrap();
        assert!(out.is_empty());
        assert_eq!(s.eintraege, 0);

        // Kein NTFS an dieser Stelle: jeder Eintrag erscheint trotzdem, mit Fehler.
        let v = FsIndex {
            target: crate::NtfsTarget {
                index: 0,
                offset: 0,
                size: 4096,
            },
            files: vec![entry("b.txt"), entry("a.txt")],
            directories: vec![entry("ordner")],
            warnings: Vec::new(),
            unreadable_dirs: vec![(42, "INDX fehlt".into())],
        };
        let s = write_catalog(&img, &[v], &mut out).unwrap();
        assert_eq!(
            (s.eintraege, s.dateien, s.verzeichnisse, s.fehler),
            (3, 2, 1, 3)
        );
        assert_eq!(s.verzeichnisse_ohne_inhalt, 1);
        let text = String::from_utf8(out).unwrap();
        let pfade: Vec<String> = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["pfad"].to_string())
            .collect();
        assert_eq!(pfade, ["\"a.txt\"", "\"b.txt\"", "\"ordner\""]);
        assert!(text.lines().all(|l| l.contains("Volume nicht lesbar")));
        // Nur das Verzeichnis trägt den Hinweis auf fehlenden Inhalt.
        assert_eq!(text.matches("\"inhalt_fehler\":\"INDX fehlt\"").count(), 1);
        assert!(text.lines().last().unwrap().contains("inhalt_fehler"));
    }
}
