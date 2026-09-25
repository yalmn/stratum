//! Domäne „EventLog": forensisch relevante Windows-Ereignisse aus den
//! `.evtx`-Protokollen.
//!
//! Gezielt über den Pfad-Index werden die Ereignisprotokolle unter
//! `Windows\System32\winevt\Logs` gelesen und mit dem evtx-Parser ausgewertet.
//! Gemeldet werden nur ausgewählte Ereignis-IDs (Anmeldungen, Kontoänderungen,
//! Dienste, Protokolllöschung, RDP), damit der Report nicht von Routine-
//! ereignissen überschwemmt wird.

use std::io::Cursor;

use evtx::EvtxParser;
use serde_json::Value;

use stratum_ntfs::NtfsVolume;

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
                let Ok(Some(file)) = vol.read_file_by_record(e.mft_record, &e.path) else {
                    continue;
                };
                parse_log(&file.data, &e.path, &mut out);
            }
        }
        out
    }
}

fn parse_log(data: &[u8], path: &str, out: &mut Outcome) {
    let mut parser = match EvtxParser::from_read_seek(Cursor::new(data)) {
        Ok(p) => p,
        Err(e) => {
            out.warnings.push(format!("{path}: nicht lesbar: {e}"));
            return;
        }
    };

    let mut count = 0usize;
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
            .with("zeit_unix", record.timestamp.as_second().to_string());
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

    #[test]
    fn uninteressantes_ereignis() {
        let v = json!({"Event": {"System": {"EventID": 4798}}});
        assert!(event_of_interest(&v).is_none());
    }
}
