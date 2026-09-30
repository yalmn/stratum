//! Windows-Zeitachse: `ActivitiesCache.db` (Connected Devices Platform).
//!
//! Je Benutzer liegt unter `AppData\Local\ConnectedDevicesPlatform\<Konto>\`
//! eine SQLite-Datenbank mit den Tabellen `Activity` (gespeicherte
//! Aktivitäten) und `ActivityOperation` (noch nicht übertragene Änderungen).
//! Zeiten sind Unix-Sekunden in UTC. Der Typ wird als Zahl ausgegeben; seine
//! Bedeutung ist nicht von Microsoft dokumentiert und wird nicht gedeutet.
//! Aus dem Inhalt (`Payload`) werden nur Felder übernommen, die im JSON selbst
//! benannt sind. Binäre Inhalte bleiben als Länge und Anfangsbytes erhalten.
//!
//! Das Original bleibt unverändert: Datenbank, WAL und SHM werden in eine
//! temporäre Kopie geschrieben und dort geöffnet.

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use stratum_core::time::filetime_to_iso;
use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

const MAX_ROWS: usize = 100_000;
const DB_NAME: &str = "activitiescache.db";

/// Analyzer für die Windows-Zeitachse.
pub struct ActivitiesCacheAnalyzer;

impl Analyzer for ActivitiesCacheAnalyzer {
    fn domain(&self) -> &str {
        "useraktivitaet"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            let dateien: Vec<_> = v
                .by_extension(&["db"])
                .filter(|e| {
                    e.path
                        .rsplit('\\')
                        .next()
                        .is_some_and(|n| n.eq_ignore_ascii_case(DB_NAME))
                })
                .cloned()
                .collect();
            if dateien.is_empty() {
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
            for e in dateien {
                let data = match vol.read_file_by_record(e.mft_record, &e.path) {
                    Ok(Some(f)) => f.data,
                    Ok(None) => continue,
                    Err(error) => {
                        out.warnings
                            .push(format!("{}: nicht lesbar: {error}", e.path));
                        continue;
                    }
                };
                let mut neben = |suffix: &str| {
                    vol.read_file(&format!("{}{suffix}", e.path))
                        .ok()
                        .flatten()
                        .map(|f| f.data)
                        .filter(|d| !d.is_empty())
                };
                let wal = neben("-wal");
                let shm = neben("-shm");
                match read_activities(&data, wal.as_deref(), shm.as_deref()) {
                    Ok(rows) => {
                        let benutzer = benutzer_aus_pfad(&e.path);
                        out.findings.push(
                            Finding::new("useraktivitaet", "ActivitiesCache geprüft", &e.path)
                                .with("art", "activities_cache_db")
                                .with("eintraege", rows.len().to_string())
                                .with("wal", if wal.is_some() { "ja" } else { "nein" })
                                .with("mft_record", e.mft_record.to_string())
                                .with("volume_offset", v.target.offset.to_string()),
                        );
                        for row in rows {
                            out.findings.push(row.finding(&e.path, &benutzer));
                        }
                    }
                    Err(error) => out
                        .warnings
                        .push(format!("{}: ActivitiesCache nicht lesbar: {error}", e.path)),
                }
            }
        }
        out
    }
}

fn benutzer_aus_pfad(path: &str) -> String {
    let teile: Vec<&str> = path.split('\\').collect();
    teile
        .iter()
        .position(|p| p.eq_ignore_ascii_case("Users"))
        .and_then(|i| teile.get(i + 1))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Eine Zeile aus `Activity` oder `ActivityOperation`.
#[derive(Debug, Default, PartialEq)]
struct Row {
    tabelle: &'static str,
    rowid: i64,
    id: String,
    app_id: Option<String>,
    app_activity_id: Option<String>,
    typ: Option<i64>,
    status: Option<i64>,
    operation: Option<i64>,
    start: Option<i64>,
    ende: Option<i64>,
    geaendert: Option<i64>,
    ablauf: Option<i64>,
    payload: Option<Vec<u8>>,
    geraet: Option<String>,
}

fn utc(unix: i64) -> Option<String> {
    let ft = u64::try_from(unix.checked_add(11_644_473_600)?).ok()? * 10_000_000;
    filetime_to_iso(ft)
}

/// Erste nicht leere Anwendung aus der JSON-Liste `AppId` samt Plattform.
fn anwendung(app_id: &str) -> Option<(String, String)> {
    let list: Value = serde_json::from_str(app_id).ok()?;
    list.as_array()?.iter().find_map(|e| {
        let app = e.get("application")?.as_str()?;
        let plattform = e.get("platform").and_then(Value::as_str).unwrap_or("");
        (!app.is_empty()).then(|| (app.to_string(), plattform.to_string()))
    })
}

impl Row {
    fn finding(self, path: &str, benutzer: &str) -> Finding {
        let payload: Option<Value> = self
            .payload
            .as_deref()
            .and_then(|p| std::str::from_utf8(p).ok())
            .and_then(|s| serde_json::from_str(s).ok())
            .filter(Value::is_object);
        let text = |key: &str| {
            payload
                .as_ref()
                .and_then(|p| p.get(key))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let name = text("displayText")
            .or_else(|| self.app_activity_id.clone())
            .unwrap_or_else(|| format!("Aktivität {}", self.id));
        let mut f = Finding::new("useraktivitaet", name, path)
            .with("art", "activities_cache")
            .with("tabelle", self.tabelle)
            .with("rowid", self.rowid.to_string())
            .with("aktivitaet_id", &self.id);
        if !benutzer.is_empty() {
            f = f.with("benutzer", benutzer);
        }
        if let Some((app, plattform)) = self.app_id.as_deref().and_then(anwendung) {
            f = f
                .with("anwendung", app)
                .with("anwendung_plattform", plattform);
        }
        let zahlen = [
            ("aktivitaet_typ", self.typ),
            ("aktivitaet_status", self.status),
            ("operation_typ", self.operation),
        ];
        for (k, v) in zahlen {
            if let Some(v) = v {
                f = f.with(k, v.to_string());
            }
        }
        for (k, v) in [
            ("app_activity_id", self.app_activity_id.clone()),
            ("geraet_id", self.geraet.clone()),
        ] {
            if let Some(v) = v.filter(|s| !s.is_empty()) {
                f = f.with(k, v);
            }
        }
        for (k, t) in [
            ("aktivitaet_start", self.start),
            ("aktivitaet_ende", self.ende),
            ("aktivitaet_geaendert", self.geaendert),
            ("aktivitaet_ablauf", self.ablauf),
        ] {
            if let Some(t) = t.filter(|&t| t > 0) {
                if let Some(iso) = utc(t) {
                    f = f.with(format!("{k}_utc"), iso);
                }
                // Der Ablauf ist ein geplanter Zeitpunkt, kein Ereignis.
                if k != "aktivitaet_ablauf" {
                    f = f.with(format!("{k}_unix"), t.to_string());
                }
            }
        }
        match (&payload, &self.payload) {
            (Some(_), _) => {
                for key in [
                    "displayText",
                    "appDisplayName",
                    "description",
                    "contentUri",
                    "activationUri",
                ] {
                    if let Some(v) = text(key) {
                        f = f.with(format!("payload_{key}"), v);
                    }
                }
                if let Some(d) = payload
                    .as_ref()
                    .and_then(|p| p.get("activeDurationSeconds"))
                    .and_then(Value::as_i64)
                {
                    f = f.with("payload_activeDurationSeconds", d.to_string());
                }
            }
            (None, Some(raw)) if !raw.is_empty() => {
                f = f
                    .with("payload_art", "binaer")
                    .with("payload_bytes", raw.len().to_string())
                    .with(
                        "payload_anfang",
                        raw.iter()
                            .take(32)
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>(),
                    );
            }
            _ => {}
        }
        f
    }
}

/// Liest `Activity` und `ActivityOperation` aus einer Kopie der Datenbank.
fn read_activities(
    data: &[u8],
    wal: Option<&[u8]>,
    shm: Option<&[u8]>,
) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("ActivitiesCache.db");
    std::fs::write(&db, data)?;
    if let Some(w) = wal {
        std::fs::write(dir.path().join("ActivitiesCache.db-wal"), w)?;
    }
    if let Some(s) = shm {
        std::fs::write(dir.path().join("ActivitiesCache.db-shm"), s)?;
    }
    let conn = if wal.is_some() {
        // Mit WAL auf der Kopie normal öffnen, damit SQLite sie einspielt.
        Connection::open(&db)?
    } else {
        let uri = format!("file:{}?immutable=1", db.display());
        Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?
    };
    let mut rows = Vec::new();
    rows.extend(query(
        &conn,
        "Activity",
        "SELECT rowid, hex(Id), AppId, AppActivityId, ActivityType, ActivityStatus, NULL, \
         StartTime, EndTime, LastModifiedTime, ExpirationTime, Payload, PlatformDeviceId \
         FROM Activity",
    )?);
    rows.extend(query(
        &conn,
        "ActivityOperation",
        "SELECT rowid, hex(Id), AppId, AppActivityId, ActivityType, NULL, OperationType, \
         StartTime, EndTime, LastModifiedTime, ExpirationTime, Payload, PlatformDeviceId \
         FROM ActivityOperation",
    )?);
    Ok(rows)
}

fn query(conn: &Connection, tabelle: &'static str, sql: &str) -> rusqlite::Result<Vec<Row>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        Ok(Row {
            tabelle,
            rowid: r.get(0)?,
            id: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            app_id: r.get(2).ok().flatten(),
            app_activity_id: r.get(3).ok().flatten(),
            typ: r.get(4).ok().flatten(),
            status: r.get(5).ok().flatten(),
            operation: r.get(6).ok().flatten(),
            start: r.get(7).ok().flatten(),
            ende: r.get(8).ok().flatten(),
            geaendert: r.get(9).ok().flatten(),
            ablauf: r.get(10).ok().flatten(),
            payload: r.get(11).ok().flatten(),
            geraet: r.get(12).ok().flatten(),
        })
    })?;
    Ok(rows.flatten().take(MAX_ROWS).collect())
}

/// Einstieg für das Fuzz-Target: beliebige Bytes als `AppId` und `Payload`.
pub(crate) fn fuzz(data: &[u8]) {
    let row = Row {
        app_id: std::str::from_utf8(data).ok().map(str::to_string),
        payload: Some(data.to_vec()),
        ..Default::default()
    };
    let _ = row.finding("x", "y");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datenbank() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let pfad = dir.path().join("t.db");
        let conn = Connection::open(&pfad).unwrap();
        let spalten = "Id BLOB, AppId TEXT, AppActivityId TEXT, ActivityType INT, \
                       StartTime INT, EndTime INT, LastModifiedTime INT, ExpirationTime INT, \
                       Payload BLOB, PlatformDeviceId TEXT";
        conn.execute_batch(&format!(
            "CREATE TABLE Activity ({spalten}, ActivityStatus INT);
             CREATE TABLE ActivityOperation ({spalten}, OperationType INT);"
        ))
        .unwrap();
        let app = r#"[{"application":"","platform":"packageId"},{"application":"C:\\Tools\\x.exe","platform":"windows_win32"}]"#;
        let json =
            br#"{"displayText":"bericht.docx","appDisplayName":"Word","activeDurationSeconds":42}"#;
        conn.execute(
            "INSERT INTO Activity VALUES (x'0102', ?1, 'a1', 5, 1609459200, 1609459260, 1609459300, 1612137600, ?2, 'dev', 1)",
            rusqlite::params![app, &json[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ActivityOperation VALUES (x'0304', NULL, 'a2', 11, 0, 0, 0, 0, x'43420100', NULL, 2)",
            [],
        )
        .unwrap();
        drop(conn);
        std::fs::read(&pfad).unwrap()
    }

    #[test]
    fn aktivitaet_mit_json_inhalt_und_operation() {
        let rows = read_activities(&datenbank(), None, None).unwrap();
        assert_eq!(rows.len(), 2);
        let mut rows = rows.into_iter();
        let f = rows
            .next()
            .unwrap()
            .finding("u\\ActivitiesCache.db", "alice");
        assert_eq!(f.name, "bericht.docx");
        assert_eq!(f.attributes["aktivitaet_id"], "0102");
        assert_eq!(f.attributes["anwendung"], "C:\\Tools\\x.exe");
        assert_eq!(f.attributes["anwendung_plattform"], "windows_win32");
        assert_eq!(f.attributes["aktivitaet_typ"], "5");
        assert_eq!(
            f.attributes["aktivitaet_start_utc"],
            "2021-01-01T00:00:00.0000000Z"
        );
        assert_eq!(f.attributes["aktivitaet_ende_unix"], "1609459260");
        assert_eq!(f.attributes["payload_appDisplayName"], "Word");
        assert_eq!(f.attributes["payload_activeDurationSeconds"], "42");
        assert!(f.attributes.contains_key("aktivitaet_ablauf_utc"));
        assert!(!f.attributes.contains_key("aktivitaet_ablauf_unix"));

        let op = rows
            .next()
            .unwrap()
            .finding("u\\ActivitiesCache.db", "alice");
        assert_eq!(op.attributes["tabelle"], "ActivityOperation");
        assert_eq!(op.attributes["operation_typ"], "2");
        assert_eq!(op.attributes["payload_art"], "binaer");
        assert_eq!(op.attributes["payload_anfang"], "43420100");
        assert!(!op.attributes.contains_key("aktivitaet_start_unix"));
    }

    #[test]
    fn kaputte_datenbank_ist_ein_fehler() {
        assert!(read_activities(b"keine datenbank", None, None).is_err());
        assert_eq!(benutzer_aus_pfad("Users\\bob\\AppData\\x.db"), "bob");
    }

    /// Gegen die echte ActivitiesCache.db des Testimages: alle Zeilen der
    /// Tabelle Activity mit derselben Startzeit wie in SQLite selbst.
    #[test]
    #[ignore = "benötigt STRATUM_SHELLITEM_REFERENCE mit ActivitiesCache.db"]
    fn activities_referenz() {
        let dir =
            std::path::PathBuf::from(std::env::var_os("STRATUM_SHELLITEM_REFERENCE").unwrap());
        let data = std::fs::read(dir.join("ActivitiesCache.db")).unwrap();
        let rows = read_activities(&data, None, None).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let conn =
            Connection::open_with_flags(tmp.path(), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let erwartet: Vec<(String, i64)> = conn
            .prepare("SELECT hex(Id), StartTime FROM Activity")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .flatten()
            .collect();
        let gelesen: Vec<(String, i64)> = rows
            .iter()
            .filter(|r| r.tabelle == "Activity")
            .map(|r| (r.id.clone(), r.start.unwrap_or(0)))
            .collect();
        assert!(!erwartet.is_empty());
        assert_eq!(gelesen, erwartet);
    }
}
