//! Domäne „Browser": liest den Verlauf aus den SQLite-Datenbanken der Browser.
//!
//! Gezielt über den Pfad-Index: Chromium-basierte Browser (Chrome, Edge, Brave,
//! Opera) legen den Verlauf in einer Datei namens `History` ab, Firefox in
//! `places.sqlite`. Die Datei wird über ihre MFT-Nummer gelesen, als temporäre
//! Kopie geöffnet und abgefragt.
//!
//! Gespeicherte Passwörter (Chromium `Login Data`, Firefox `logins.json`) sind
//! mit DPAPI verschlüsselt und bleiben einer späteren Ausbaustufe vorbehalten.

use std::io::Write;

use rusqlite::{Connection, OpenFlags};

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Obergrenze für Verlaufseinträge je Datenbank.
const MAX_ROWS: usize = 20_000;

/// Ein Verlaufseintrag: URL, Titel, Besuchszeit als Unix-Sekunden.
type HistoryRow = (String, Option<String>, Option<i64>);

/// Art der Zeitstempel in der Datenbank.
#[derive(Clone, Copy)]
enum TimeBase {
    /// Mikrosekunden seit 1601-01-01 (Chromium).
    Chromium,
    /// Mikrosekunden seit 1970-01-01 (Firefox).
    Firefox,
}

/// Analyzer für den Browser-Verlauf.
pub struct BrowserAnalyzer;

impl Analyzer for BrowserAnalyzer {
    fn domain(&self) -> &str {
        "browser"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();

        for v in &ctx.volumes {
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };

            // Chromium: Datei "History" in einem Browser-Profil.
            for e in v.by_name("History") {
                if !is_chromium_path(&e.path) {
                    continue;
                }
                process(
                    &mut vol,
                    e.mft_record,
                    &e.path,
                    browser_of(&e.path),
                    Query::Chromium,
                    &mut out,
                );
            }
            // Firefox: places.sqlite.
            for e in v.by_name("places.sqlite") {
                process(
                    &mut vol,
                    e.mft_record,
                    &e.path,
                    "firefox",
                    Query::Firefox,
                    &mut out,
                );
            }
        }
        out
    }
}

#[derive(Clone, Copy)]
enum Query {
    Chromium,
    Firefox,
}

fn process(
    vol: &mut NtfsVolume<'_>,
    record: u64,
    path: &str,
    browser: &str,
    query: Query,
    out: &mut Outcome,
) {
    let data = match vol.read_file_by_record(record, path) {
        Ok(Some(f)) => f.data,
        _ => return,
    };
    match read_history(&data, query) {
        Ok(rows) => {
            for (url, title, unix) in rows {
                let mut f = Finding::new("browser", url, path)
                    .with("art", "verlauf")
                    .with("browser", browser);
                if let Some(t) = title {
                    if !t.is_empty() {
                        f = f.with("titel", t);
                    }
                }
                if let Some(u) = unix {
                    f = f.with("besucht_unix", u.to_string());
                }
                out.findings.push(f);
            }
        }
        Err(e) => out
            .warnings
            .push(format!("{path}: Verlauf nicht lesbar: {e}")),
    }
}

/// Schreibt die Datenbank-Bytes in eine temporäre Datei und liest den Verlauf.
fn read_history(data: &[u8], query: Query) -> Result<Vec<HistoryRow>, Box<dyn std::error::Error>> {
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(data)?;
    tmp.flush()?;

    let (sql, base) = match query {
        Query::Chromium => (
            "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC",
            TimeBase::Chromium,
        ),
        Query::Firefox => (
            "SELECT url, title, last_visit_date FROM moz_places WHERE url IS NOT NULL \
             ORDER BY last_visit_date DESC",
            TimeBase::Firefox,
        ),
    };
    Ok(read_urls(tmp.path(), sql, base)?)
}

fn read_urls(
    path: &std::path::Path,
    sql: &str,
    base: TimeBase,
) -> rusqlite::Result<Vec<HistoryRow>> {
    // Nur-Lese-Zugriff auf die unveränderliche Kopie; kein Journal/WAL noetig.
    let uri = format!("file:{}?immutable=1", path.display());
    let conn = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: Option<String> = row.get(1).ok().flatten();
        let raw: Option<i64> = row.get(2).ok().flatten();
        Ok((url, title, raw.and_then(|t| to_unix(t, base))))
    })?;

    let mut out = Vec::new();
    for r in rows.flatten() {
        out.push(r);
        if out.len() >= MAX_ROWS {
            break;
        }
    }
    Ok(out)
}

/// Rechnet den Datenbank-Zeitstempel in Unix-Sekunden (UTC) um. `None` bei 0
/// oder Zeiten vor 1970.
fn to_unix(t: i64, base: TimeBase) -> Option<i64> {
    if t <= 0 {
        return None;
    }
    let secs = match base {
        // Mikrosekunden seit 1601: erst in Sekunden, dann Epochendifferenz.
        TimeBase::Chromium => t / 1_000_000 - 11_644_473_600,
        TimeBase::Firefox => t / 1_000_000,
    };
    (secs >= 0).then_some(secs)
}

/// Erkennt anhand des Pfads, ob eine `History`-Datei zu einem Chromium-Browser
/// gehört (gegen zufällige Dateien gleichen Namens).
fn is_chromium_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("user data")
        || p.contains("chrome")
        || p.contains("edge")
        || p.contains("brave")
        || p.contains("opera")
        || p.contains("chromium")
        || p.contains("vivaldi")
}

fn browser_of(path: &str) -> &'static str {
    let p = path.to_ascii_lowercase();
    if p.contains("edge") {
        "edge"
    } else if p.contains("brave") {
        "brave"
    } else if p.contains("opera") {
        "opera"
    } else if p.contains("vivaldi") {
        "vivaldi"
    } else {
        "chrome"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(path: &std::path::Path, setup: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(setup).unwrap();
    }

    #[test]
    fn chromium_verlauf_und_zeit() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // last_visit_time: Mikrosekunden seit 1601. 13400000000000000 ~ 2025.
        make_db(
            tmp.path(),
            "CREATE TABLE urls(url TEXT, title TEXT, last_visit_time INTEGER);\
             INSERT INTO urls VALUES('http://a.tld','Seite A',13400000000000000);\
             INSERT INTO urls VALUES('http://b.tld',NULL,0);",
        );
        let rows = read_urls(
            tmp.path(),
            "SELECT url,title,last_visit_time FROM urls ORDER BY last_visit_time DESC",
            TimeBase::Chromium,
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "http://a.tld");
        assert_eq!(rows[0].1.as_deref(), Some("Seite A"));
        assert!(rows[0].2.unwrap() > 1_700_000_000);
        assert_eq!(rows[1].2, None); // last_visit_time 0 -> keine Zeit
    }

    #[test]
    fn firefox_verlauf() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        make_db(
            tmp.path(),
            "CREATE TABLE moz_places(url TEXT, title TEXT, last_visit_date INTEGER);\
             INSERT INTO moz_places VALUES('http://c.tld','C',1700000000000000);",
        );
        let rows = read_urls(
            tmp.path(),
            "SELECT url,title,last_visit_date FROM moz_places WHERE url IS NOT NULL",
            TimeBase::Firefox,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, Some(1_700_000_000));
    }

    #[test]
    fn browser_erkennung() {
        assert!(is_chromium_path(
            "Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        ));
        assert!(!is_chromium_path("Users\\a\\Documents\\History"));
        assert_eq!(
            browser_of("...\\Microsoft\\Edge\\User Data\\Default\\History"),
            "edge"
        );
    }
}
