//! Domäne „EventLog": forensisch relevante Windows-Ereignisse aus den
//! `.evtx`-Protokollen.
//!
//! Gezielt über den Pfad-Index werden die Ereignisprotokolle unter
//! `Windows\System32\winevt\Logs` gelesen und mit dem evtx-Parser ausgewertet.
//! Gemeldet werden nur ausgewählte Ereignis-IDs (Anmeldungen, Kontoänderungen,
//! Dienste, Protokolllöschung, RDP), damit der Report nicht von Routine-
//! ereignissen überschwemmt wird.

use std::collections::HashMap;
use std::io::Cursor;

use evtx::EvtxParser;
use serde_json::Value;

use stratum_ntfs::{DataStreamLayout, NtfsVolume};

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Obergrenze für gemeldete Ereignisse je Protokolldatei.
const MAX_PER_LOG: usize = 50_000;

/// Analyzer für Windows-Ereignisprotokolle.
pub struct EventLogAnalyzer;

impl Analyzer for EventLogAnalyzer {
    fn domain(&self) -> &str {
        "eventlog"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();

        for v in &ctx.volumes {
            let logs: Vec<_> = v
                .by_extension(&["evtx"])
                .filter(|e| e.path.to_ascii_lowercase().contains("winevt"))
                .collect();
            if logs.is_empty() {
                continue;
            }
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };

            for e in logs {
                let file = match vol.read_file_by_record(e.mft_record, &e.path) {
                    Ok(Some(file)) => file,
                    Ok(None) => continue,
                    Err(error) => {
                        out.warnings
                            .push(format!("{}: nicht lesbar: {error}", e.path));
                        continue;
                    }
                };
                // Ablage im Image, damit jeder Datensatz einen physischen Offset
                // erhält. Fehlt sie (etwa bei Kompression), bleibt es beim
                // Datei-Offset.
                let layout = vol.data_stream_layout(&e.path, "").ok().flatten();
                let quelle = LogSource {
                    path: &e.path,
                    volume_offset: v.target.offset,
                    mft_record: e.mft_record,
                    mft_record_offset: file.meta.record_offset,
                    layout: layout.as_ref(),
                };
                parse_log(&file.data, &quelle, &mut out);
            }
        }
        out
    }
}

/// Herkunft einer Protokolldatei im Image.
struct LogSource<'a> {
    path: &'a str,
    volume_offset: u64,
    mft_record: u64,
    mft_record_offset: Option<u64>,
    layout: Option<&'a DataStreamLayout>,
}

impl LogSource<'_> {
    /// Physischer Image-Offset zu einem Offset in der Datei.
    fn image_offset(&self, datei_offset: u64) -> Option<u64> {
        self.layout?.runs.iter().find_map(|run| {
            let rel = datei_offset.checked_sub(run.logical_offset)?;
            (rel < run.length).then_some(run.image_offset? + rel)
        })
    }
}

fn parse_log(data: &[u8], quelle: &LogSource<'_>, out: &mut Outcome) {
    let path = quelle.path;
    let mut parser = match EvtxParser::from_read_seek(Cursor::new(data)) {
        Ok(p) => p,
        Err(e) => {
            out.warnings.push(format!("{path}: nicht lesbar: {e}"));
            return;
        }
    };
    let index = record_index(data);

    let mut count = 0usize;
    let mut ohne_offset = 0usize;
    for record in parser.records_json_value() {
        if count >= MAX_PER_LOG {
            out.warnings
                .push(format!("{path}: Grenze {MAX_PER_LOG} erreicht"));
            break;
        }
        let Ok(record) = record else { continue };
        let Some((id, beschreibung)) = event_of_interest(&record.data) else {
            continue;
        };
        count += 1;

        let mut f = Finding::new("eventlog", beschreibung, path)
            .with("event_id", id.to_string())
            .with("event_record_id", record.event_record_id.to_string())
            .with("zeit_unix", record.timestamp.as_second().to_string())
            .with("volume_offset", quelle.volume_offset.to_string())
            .with("mft_record", quelle.mft_record.to_string());
        if let Some(offset) = quelle.mft_record_offset {
            f = f.with("mft_record_offset", offset.to_string());
        }
        let filetime = to_filetime(
            record.timestamp.as_second(),
            record.timestamp.subsec_nanosecond(),
        );
        if let Some(ft) = filetime {
            f = f.with("filetime", ft.to_string());
            if let Some(utc) = stratum_core::time::filetime_to_iso(ft) {
                f = f.with("zeit_utc", utc);
            }
        }
        // Datei-Offset nur, wenn ID und Zeitstempel im Datensatzkopf genau zu
        // dem passen, was der Parser gelesen hat.
        match (index.get(&record.event_record_id), filetime) {
            (Some(Some((offset, ft))), Some(parsed)) if *ft == parsed => {
                f = f.with("datei_offset", offset.to_string());
                if let Some(image) = quelle.image_offset(*offset) {
                    f = f.at(image);
                }
            }
            _ => ohne_offset += 1,
        }
        if let Some(kanal) = string_at(&record.data, &["Event", "System", "Channel"]) {
            f = f.with("kanal", kanal);
        }
        for (attr, keys) in FIELD_MAP {
            if let Some(val) = event_data(&record.data, keys) {
                if !val.is_empty() {
                    f = f.with(*attr, val);
                }
            }
        }
        out.findings.push(f);
    }
    if ohne_offset > 0 {
        out.warnings.push(format!(
            "{path}: {ohne_offset} Ereignisse ohne bestätigten Datei-Offset"
        ));
    }
}

/// Unix-Zeit mit Nanosekunden als FILETIME (100-ns-Schritte seit 1601).
fn to_filetime(secs: i64, nanos: i32) -> Option<u64> {
    let ticks = (i128::from(secs) + 11_644_473_600) * 10_000_000 + i128::from(nanos) / 100;
    u64::try_from(ticks).ok()
}

/// Lage der Datensätze: EventRecordID auf (Datei-Offset, FILETIME aus dem
/// Datensatzkopf). Doppelte IDs sind nicht eindeutig zuzuordnen und stehen als
/// `None` darin.
pub(crate) type RecordIndex = HashMap<u64, Option<(u64, u64)>>;

/// Durchläuft die Datei wie der evtx-Parser: Dateikopf 4096 Byte, Chunks zu
/// 65536 Byte mit Kennung `ElfChnk` und 512 Byte Kopf (freier Bereich ab dem
/// Wert bei Offset 48), darin Datensätze mit Kennung `**\0\0`, Größe (4),
/// EventRecordID (8) und FILETIME (16). Unplausible Größen beenden den Chunk.
pub(crate) fn record_index(data: &[u8]) -> RecordIndex {
    const FILE_HEADER: usize = 4096;
    const CHUNK: usize = 65536;
    const CHUNK_HEADER: usize = 512;
    const RECORD_HEADER: usize = 24;
    let u32_at = |b: &[u8], at: usize| {
        b.get(at..at + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
    };
    let u64_at = |b: &[u8], at: usize| {
        b.get(at..at + 8).map(|s| {
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            u64::from_le_bytes(a)
        })
    };
    let mut index = RecordIndex::new();
    let mut start = FILE_HEADER;
    while start + CHUNK_HEADER <= data.len() {
        let chunk = &data[start..(start + CHUNK).min(data.len())];
        if chunk.starts_with(b"ElfChnk\0") {
            let free = u32_at(chunk, 48).unwrap_or(0).min(chunk.len());
            let mut pos = CHUNK_HEADER;
            while pos + RECORD_HEADER <= free && chunk[pos..].starts_with(b"\x2a\x2a\0\0") {
                let (Some(size), Some(id), Some(ft)) = (
                    u32_at(chunk, pos + 4),
                    u64_at(chunk, pos + 8),
                    u64_at(chunk, pos + 16),
                ) else {
                    break;
                };
                if size < RECORD_HEADER + 4 || size > chunk.len() - pos {
                    break;
                }
                let offset = (start + pos) as u64;
                index
                    .entry(id)
                    .and_modify(|e| *e = None)
                    .or_insert(Some((offset, ft)));
                pos += size;
            }
        }
        start += CHUNK;
    }
    index
}

/// Prüft, ob ein Ereignis von Interesse ist, und liefert ID und Beschreibung.
fn event_of_interest(v: &Value) -> Option<(u64, &'static str)> {
    let id = event_id(v)?;
    let beschreibung = match id {
        4624 => "Anmeldung erfolgreich",
        4625 => "Anmeldung fehlgeschlagen",
        4634 | 4647 => "Abmeldung",
        4648 => "Anmeldung mit expliziten Anmeldedaten",
        4672 => "Anmeldung mit besonderen Rechten",
        4688 => "Prozess erstellt",
        4720 => "Benutzerkonto erstellt",
        4722 => "Benutzerkonto aktiviert",
        4725 => "Benutzerkonto deaktiviert",
        4726 => "Benutzerkonto gelöscht",
        4728 | 4732 | 4756 => "Zu privilegierter Gruppe hinzugefügt",
        4697 | 7045 => "Dienst installiert",
        1102 | 104 => "Ereignisprotokoll gelöscht",
        6005 => "Ereignisprotokolldienst gestartet (Systemstart)",
        6006 => "Ereignisprotokolldienst gestoppt (Herunterfahren)",
        1149 => "RDP: Netzwerkanmeldung",
        21 | 25 => "RDP: Sitzung angemeldet/wiederverbunden",
        _ => return None,
    };
    Some((id, beschreibung))
}

/// Zuordnung von Report-Attribut zu möglichen EventData-Feldnamen.
const FIELD_MAP: &[(&str, &[&str])] = &[
    ("benutzer", &["TargetUserName", "SubjectUserName"]),
    ("quell_ip", &["IpAddress"]),
    ("arbeitsstation", &["WorkstationName"]),
    ("anmeldetyp", &["LogonType"]),
    ("dienst", &["ServiceName"]),
    ("prozess", &["NewProcessName", "ProcessName"]),
];

/// Liest die Ereignis-ID aus `Event.System.EventID` (Zahl oder Objekt mit
/// `#text`).
fn event_id(v: &Value) -> Option<u64> {
    let node = v.get("Event")?.get("System")?.get("EventID")?;
    match node {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        Value::Object(o) => o.get("#text").and_then(|t| match t {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }),
        _ => None,
    }
}

/// Sucht ein Feld in `Event.EventData` unter mehreren möglichen Namen.
fn event_data(v: &Value, keys: &[&str]) -> Option<String> {
    let data = v.get("Event")?.get("EventData")?;
    for k in keys {
        if let Some(val) = data.get(k) {
            return Some(value_to_string(val));
        }
    }
    None
}

fn string_at(v: &Value, path: &[&str]) -> Option<String> {
    let mut node = v;
    for p in path {
        node = node.get(p)?;
    }
    Some(value_to_string(node))
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Object(o) => o.get("#text").map(value_to_string).unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_id_zahl_und_objekt() {
        let a = json!({"Event": {"System": {"EventID": 4624}}});
        assert_eq!(event_id(&a), Some(4624));
        let b = json!({"Event": {"System": {"EventID": {"#text": 1102, "Qualifiers": 0}}}});
        assert_eq!(event_id(&b), Some(1102));
        let c = json!({"Event": {"System": {"EventID": "4625"}}});
        assert_eq!(event_id(&c), Some(4625));
    }

    #[test]
    fn interesse_und_felder() {
        let v = json!({
            "Event": {
                "System": {"EventID": 4625, "Channel": "Security"},
                "EventData": {"TargetUserName": "alice", "IpAddress": "10.0.0.5", "LogonType": 3}
            }
        });
        let (id, besch) = event_of_interest(&v).unwrap();
        assert_eq!(id, 4625);
        assert_eq!(besch, "Anmeldung fehlgeschlagen");
        assert_eq!(
            event_data(&v, &["TargetUserName"]).as_deref(),
            Some("alice")
        );
        assert_eq!(event_data(&v, &["IpAddress"]).as_deref(), Some("10.0.0.5"));
        assert_eq!(event_data(&v, &["LogonType"]).as_deref(), Some("3"));
        assert_eq!(
            string_at(&v, &["Event", "System", "Channel"]).as_deref(),
            Some("Security")
        );
    }

    fn chunk_mit(records: &[(u64, u64, usize)]) -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        let mut chunk = vec![0u8; 65536];
        chunk[..8].copy_from_slice(b"ElfChnk\0");
        let mut pos = 512;
        for &(id, ft, size) in records {
            chunk[pos..pos + 4].copy_from_slice(b"\x2a\x2a\0\0");
            chunk[pos + 4..pos + 8].copy_from_slice(&(size as u32).to_le_bytes());
            chunk[pos + 8..pos + 16].copy_from_slice(&id.to_le_bytes());
            chunk[pos + 16..pos + 24].copy_from_slice(&ft.to_le_bytes());
            pos += size;
        }
        chunk[48..52].copy_from_slice(&(pos as u32).to_le_bytes());
        data.extend_from_slice(&chunk);
        data
    }

    #[test]
    fn datensatzlage_mit_id_und_filetime() {
        let data = chunk_mit(&[(7, 100, 64), (8, 200, 96), (7, 300, 32)]);
        let index = record_index(&data);
        assert_eq!(index.get(&8), Some(&Some((4096 + 512 + 64, 200))));
        // Doppelte ID: keine eindeutige Zuordnung.
        assert_eq!(index.get(&7), Some(&None));
    }

    #[test]
    fn unplausible_groesse_beendet_den_chunk() {
        let mut data = chunk_mit(&[(1, 10, 64), (2, 20, 64)]);
        // Größe des zweiten Datensatzes auf 4 setzen.
        let at = 4096 + 512 + 64 + 4;
        data[at..at + 4].copy_from_slice(&4u32.to_le_bytes());
        let index = record_index(&data);
        assert!(index.contains_key(&1));
        assert!(!index.contains_key(&2));
        // Abgeschnittene Datei und Unsinn: keine Panik.
        assert!(record_index(&data[..5000]).len() <= 1);
        assert!(record_index(&[0xff; 70_000]).is_empty());
    }

    #[test]
    fn filetime_aus_unix_und_nanosekunden() {
        assert_eq!(to_filetime(0, 0), Some(116_444_736_000_000_000));
        assert_eq!(to_filetime(0, 123_456_789), Some(116_444_736_001_234_567));
        assert_eq!(to_filetime(-11_644_473_601, 0), None);
    }

    /// Gegen ein echtes Protokoll: jeder vom Parser gelesene Datensatz muss
    /// einen bestätigten Offset haben, an dem sein Kopf steht.
    #[test]
    #[ignore = "benötigt STRATUM_EVTX_REFERENCE mit einer echten .evtx-Datei"]
    fn evtx_referenz() {
        let path = std::env::var_os("STRATUM_EVTX_REFERENCE").expect("Referenzdatei setzen");
        let data = std::fs::read(path).unwrap();
        let index = record_index(&data);
        let mut parser = EvtxParser::from_read_seek(Cursor::new(&data[..])).unwrap();
        let mut geprueft = 0;
        for record in parser.records_json_value() {
            let record = record.unwrap();
            let ft = to_filetime(
                record.timestamp.as_second(),
                record.timestamp.subsec_nanosecond(),
            )
            .unwrap();
            let (offset, kopf_ft) = index[&record.event_record_id].unwrap();
            assert_eq!(kopf_ft, ft, "ID {}", record.event_record_id);
            let at = offset as usize;
            assert_eq!(&data[at..at + 4], b"\x2a\x2a\0\0");
            assert_eq!(
                u64::from_le_bytes(data[at + 8..at + 16].try_into().unwrap()),
                record.event_record_id
            );
            geprueft += 1;
        }
        assert!(geprueft > 0);
        eprintln!("{geprueft} Datensätze mit bestätigtem Offset");
    }

    #[test]
    fn uninteressantes_ereignis() {
        let v = json!({"Event": {"System": {"EventID": 4798}}});
        assert!(event_of_interest(&v).is_none());
    }
}
