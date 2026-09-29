//! Dateikatalog: alle Dateien und Verzeichnisse der indizierten NTFS-Bereiche
//! mit ihren Metadaten, als JSON Lines (ein Eintrag je Zeile).
//!
//! Grundlage ist der vorhandene Pfad-Index, der Verzeichnisbaum wird also nicht
//! erneut durchlaufen. Dateiinhalt wird für SHA-256 und die Signaturerkennung
//! blockweise gelesen. Die Arbeit läuft blockweise parallel und wird direkt
//! geschrieben, der Speicherbedarf hängt daher nicht von der Größe des
//! Dateisystems oder der Dateien ab. Die Einträge sind nach Volume und Pfad
//! sortiert, so dass dasselbe Image stets einen bytegleichen Katalog ergibt.
//!
//! Erfasst werden nur Einträge, die über den Verzeichnisbaum erreichbar sind.
//! Gelöschte oder verwaiste MFT-Datensätze fehlen hier.

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stratum_core::time::filetime_to_iso;
use stratum_core::ImageReader;
use stratum_ntfs::{NtfsTimes, NtfsVolume, RecordInfo};

use crate::{FileEntry, FsIndex};

/// Einträge je Schreibblock. Begrenzt den Speicher für serialisierte Zeilen.
const BATCH: usize = 16_384;
/// Einträge je paralleler Arbeitseinheit innerhalb eines Blocks.
const TASK: usize = 512;
/// Für Signaturen vorgehaltener Dateianfang. Deckt auch übliche PE-Header ab.
const SIGNATURE_PREFIX: usize = 64 * 1024;

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
    /// Dateien mit vollständigem SHA-256.
    pub dateien_gehasht: u64,
    /// Dateien, deren Inhalt nicht vollständig gelesen und daher nicht gehasht wurde.
    pub hash_fehler: u64,
    /// Dateien mit einem anhand der Inhaltsbytes erkannten Typ.
    pub signaturen_erkannt: u64,
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Signature {
    offset: u64,
    bytes: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ContentInfo {
    sha256: String,
    dateityp: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signatur: Option<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gueltige_laenge: Option<u64>,
}

type CachedContent = Arc<OnceLock<Result<ContentInfo, String>>>;
type HardlinkCache = Mutex<std::collections::HashMap<u64, CachedContent>>;

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
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dateityp: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signatur: Option<Signature>,
    /// Gültige Datenlänge, nur wenn kleiner als die Größe; dahinter Nullen.
    #[serde(skip_serializing_if = "Option::is_none")]
    gueltige_laenge: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_fehler: Option<String>,
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
    content: Option<Result<ContentInfo, String>>,
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
        sha256: None,
        dateityp: None,
        mime: None,
        signatur: None,
        gueltige_laenge: None,
        hash_fehler: None,
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
    if let Some(content) = content {
        match content {
            Ok(content) => {
                l.sha256 = Some(content.sha256);
                l.dateityp = Some(content.dateityp);
                l.mime = content.mime;
                l.signatur = content.signatur;
                l.gueltige_laenge = content.gueltige_laenge;
            }
            Err(error) => l.hash_fehler = Some(error),
        }
    }
    l
}

struct Inspector {
    sha256: Sha256,
    prefix: Vec<u8>,
    bytes: u64,
}

impl Inspector {
    fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            prefix: Vec::with_capacity(4096),
            bytes: 0,
        }
    }

    fn finish(self) -> ContentInfo {
        let (dateityp, mime, signatur) = detect_type(&self.prefix, self.bytes);
        ContentInfo {
            sha256: hex(&self.sha256.finalize()),
            dateityp,
            mime,
            signatur,
            gueltige_laenge: None,
        }
    }
}

impl Write for Inspector {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sha256.update(buf);
        let wanted = SIGNATURE_PREFIX.saturating_sub(self.prefix.len());
        self.prefix.extend_from_slice(&buf[..buf.len().min(wanted)]);
        self.bytes = self.bytes.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn signature(offset: u64, bytes: &[u8]) -> Signature {
    Signature {
        offset,
        bytes: hex(bytes),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn detected(
    name: &'static str,
    mime: Option<&'static str>,
    offset: u64,
    bytes: &[u8],
) -> (&'static str, Option<&'static str>, Option<Signature>) {
    (name, mime, Some(signature(offset, bytes)))
}

/// Bestimmt den Typ ausschließlich anhand fester Bytes im Dateiinhalt.
fn detect_type(
    data: &[u8],
    total_size: u64,
) -> (&'static str, Option<&'static str>, Option<Signature>) {
    if total_size == 0 {
        return ("leer", None, None);
    }
    if data.starts_with(b"MZ") && data.len() >= 0x40 {
        let pe = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if data.get(pe..pe.saturating_add(4)) == Some(b"PE\0\0") {
            return detected(
                "pe",
                Some("application/vnd.microsoft.portable-executable"),
                pe as u64,
                b"PE\0\0",
            );
        }
    }
    const TYPES: &[(&[u8], &str, Option<&str>)] = &[
        (b"\x89PNG\r\n\x1a\n", "png", Some("image/png")),
        (
            b"SQLite format 3\0",
            "sqlite3",
            Some("application/vnd.sqlite3"),
        ),
        (b"%PDF-", "pdf", Some("application/pdf")),
        (b"PK\x03\x04", "zip", Some("application/zip")),
        (b"PK\x05\x06", "zip", Some("application/zip")),
        (b"PK\x07\x08", "zip", Some("application/zip")),
        (b"\x7fELF", "elf", Some("application/x-elf")),
        (b"\xff\xd8\xff", "jpeg", Some("image/jpeg")),
        (b"GIF87a", "gif", Some("image/gif")),
        (b"GIF89a", "gif", Some("image/gif")),
        (b"\x1f\x8b", "gzip", Some("application/gzip")),
        (
            b"7z\xbc\xaf\x27\x1c",
            "7z",
            Some("application/x-7z-compressed"),
        ),
        (b"Rar!\x1a\x07", "rar", Some("application/vnd.rar")),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_cfb", None),
        (b"ElfFile\0", "evtx", None),
        (b"regf", "registry_hive", None),
    ];
    for &(magic, name, mime) in TYPES {
        if data.starts_with(magic) {
            return detected(name, mime, 0, magic);
        }
    }
    const LNK: &[u8] = b"L\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0F";
    if data.starts_with(LNK) {
        return detected("windows_lnk", None, 0, LNK);
    }
    ("unbekannt", None, None)
}

fn inspect_file<R: std::io::Read + std::io::Seek>(
    volume: &mut NtfsVolume<R>,
    img: &ImageReader,
    entry: &FileEntry,
) -> Result<ContentInfo, String> {
    let mut inspector = Inspector::new();
    let prefetch = |offset: u64, len: u64| img.prefetch(offset, len);
    let meta = volume
        .write_file_by_record(entry.mft_record, &entry.path, &prefetch, &mut inspector)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Datei nicht gefunden".to_string())?;
    if inspector.bytes != meta.size {
        return Err(format!(
            "vollständiger Inhalt nicht bestätigt: {} von {} Bytes gelesen",
            inspector.bytes, meta.size
        ));
    }
    let mut content = inspector.finish();
    content.gueltige_laenge = meta.valid_size;
    Ok(content)
}

/// Fortschritt des Katalogs: bearbeitete und gesamte Einträge.
pub type CatalogProgress<'a> = &'a dyn Fn(u64, u64);

/// Schreibt den Katalog aller Volumes als JSON Lines nach `out`.
pub fn write_catalog<W: Write>(
    img: &ImageReader,
    volumes: &[FsIndex],
    out: W,
) -> std::io::Result<CatalogSummary> {
    write_catalog_with_progress(img, volumes, out, None)
}

/// Wie [`write_catalog`], meldet nach jedem Block den Fortschritt.
pub fn write_catalog_with_progress<W: Write>(
    img: &ImageReader,
    volumes: &[FsIndex],
    mut out: W,
    progress: Option<CatalogProgress<'_>>,
) -> std::io::Result<CatalogSummary> {
    let mut summary = CatalogSummary::default();
    let total: u64 = volumes
        .iter()
        .map(|v| (v.files.len() + v.directories.len()) as u64)
        .sum();
    let mut done = 0u64;
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
        // Mehrere Pfade können auf denselben MFT-Datensatz zeigen. Nur solche
        // Hardlinks werden volumeweit zwischengespeichert, damit große Inhalte
        // nicht mehrfach gelesen werden und normale Dateien keinen Cache belegen.
        let hardlink_cache: HardlinkCache = Mutex::new(std::collections::HashMap::new());

        for batch in entries.chunks(BATCH) {
            let parts: Vec<(Vec<u8>, u64, u64, u64, u64)> = batch
                .par_chunks(TASK)
                .map_init(
                    || NtfsVolume::open(img, offset, size).map_err(|e| e.to_string()),
                    |vol, task| {
                        let mut buf = Vec::with_capacity(task.len() * 400);
                        let mut errors = 0;
                        let mut hashed = 0;
                        let mut hash_errors = 0;
                        let mut signatures = 0;
                        for &(entry, is_dir) in task {
                            let info = match vol {
                                Ok(vol) => vol
                                    .record_info(entry.mft_record, Some(entry.parent_record))
                                    .map_err(|e| e.to_string()),
                                Err(e) => Err(format!("Volume nicht lesbar: {e}")),
                            };
                            errors += u64::from(info.is_err());
                            let content = if is_dir || info.is_err() {
                                None
                            } else {
                                let mut inspect = || match vol {
                                    Ok(vol) => inspect_file(vol, img, entry),
                                    Err(e) => Err(format!("Volume nicht lesbar: {e}")),
                                };
                                let result = if matches!(&info, Ok(i) if i.hard_links > 1) {
                                    let cell = {
                                        let mut cache = hardlink_cache
                                            .lock()
                                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                                        cache
                                            .entry(entry.mft_record)
                                            .or_insert_with(|| Arc::new(OnceLock::new()))
                                            .clone()
                                    };
                                    cell.get_or_init(inspect).clone()
                                } else {
                                    inspect()
                                };
                                match &result {
                                    Ok(c) => {
                                        hashed += 1;
                                        signatures += u64::from(c.signatur.is_some());
                                    }
                                    Err(_) => hash_errors += 1,
                                }
                                Some(result)
                            };
                            let mut l = line(offset, entry, is_dir, info, content);
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
                        (buf, errors, hashed, hash_errors, signatures)
                    },
                )
                .collect();
            for (buf, errors, hashed, hash_errors, signatures) in parts {
                out.write_all(&buf)?;
                summary.fehler += errors;
                summary.dateien_gehasht += hashed;
                summary.hash_fehler += hash_errors;
                summary.signaturen_erkannt += signatures;
            }
            done += batch.len() as u64;
            if let Some(progress) = progress {
                progress(done, total);
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
            in_use: true,
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
            file_names: Vec::new(),
            data_size: Some(10),
            streams: vec![stratum_ntfs::NamedStream {
                name: "Zone.Identifier".into(),
                size: 26,
            }],
            reparse_tag: Some(0x8000_0017),
            wof: Some("XPRESS8K"),
        };
        let json = serde_json::to_value(line(1_048_576, &e, false, Ok(info), None)).unwrap();
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
            serde_json::to_value(line(0, &e, false, Err("Datensatz defekt".into()), None)).unwrap();
        assert_eq!(json["fehler"], "Datensatz defekt");
        assert_eq!(json["groesse"], 7);
        assert!(json.get("si").is_none());
        let dir = serde_json::to_value(line(0, &e, true, Err("x".into()), None)).unwrap();
        assert_eq!(dir["typ"], "verzeichnis");
        assert!(dir.get("groesse").is_none());
    }

    #[test]
    fn signaturen_werden_ohne_dateinamen_erkannt() {
        let png = detect_type(b"\x89PNG\r\n\x1a\nrest", 12);
        assert_eq!(png.0, "png");
        assert_eq!(png.1, Some("image/png"));
        assert_eq!(png.2.unwrap().bytes, "89504e470d0a1a0a");

        let sqlite = detect_type(b"SQLite format 3\0weitere bytes", 29);
        assert_eq!(sqlite.0, "sqlite3");
        assert_eq!(sqlite.2.unwrap().offset, 0);

        let empty = detect_type(&[], 0);
        assert_eq!(empty, ("leer", None, None));
        let unknown = detect_type(b"nur text", 8);
        assert_eq!(unknown, ("unbekannt", None, None));
    }

    #[test]
    fn pe_braucht_die_pe_signatur_am_header_offset() {
        let mut pe = vec![0u8; 132];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        pe[128..132].copy_from_slice(b"PE\0\0");
        let detected = detect_type(&pe, pe.len() as u64);
        assert_eq!(detected.0, "pe");
        assert_eq!(detected.2.unwrap().offset, 128);

        pe[128] = b'X';
        assert_eq!(detect_type(&pe, pe.len() as u64).0, "unbekannt");
        assert_eq!(detect_type(b"MZ", 2).0, "unbekannt");
    }

    #[test]
    fn inspector_hasht_alle_geschriebenen_bloecke() {
        let mut inspector = Inspector::new();
        inspector.write_all(b"a").unwrap();
        inspector.write_all(b"bc").unwrap();
        let content = inspector.finish();
        assert_eq!(
            content.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(content.dateityp, "unbekannt");
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
