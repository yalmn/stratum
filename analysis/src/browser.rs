//! Domäne „Browser": liest den Verlauf aus den SQLite-Datenbanken der Browser.
//!
//! Gezielt über den Pfad-Index: Chromium-basierte Browser (Chrome, Edge, Brave,
//! Opera) legen den Verlauf in einer Datei namens `History` ab, Firefox in
//! `places.sqlite`. Die Datei wird über ihre MFT-Nummer gelesen, als temporäre
//! Kopie geöffnet und abgefragt.
//!
//! Gespeicherte Passwörter (Chromium `Login Data`) sind mit DPAPI und AES-GCM
//! verschlüsselt. Wird ein Benutzergeheimnis übergeben (siehe [`DpapiInput`]),
//! entschlüsselt das Modul sie über [`stratum_creds::dpapi`]; ohne Geheimnis
//! bleibt es bei Anzahl und Hinweis. Firefox-Passwörter (`logins.json` über
//! `key4.db`) werden über [`stratum_creds::nss`] entschlüsselt; ohne gesetztes
//! Hauptpasswort (der Normalfall) genügt der Standardweg, sonst per
//! `firefox_password`.

use rusqlite::{Connection, OpenFlags};

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, DpapiInput, FileEntry, Finding, FsIndex, Outcome};

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
            // Gespeicherte Zugangsdaten. Chromium "Login Data" (SQLite,
            // DPAPI/AES-GCM): ohne Passwort nur Bestandsaufnahme, mit übergebenem
            // DPAPI-Geheimnis wird entschlüsselt. Firefox "logins.json" (DPAPI
            // über key4.db) bleibt einer späteren Stufe vorbehalten.
            let keys = ctx
                .dpapi
                .as_ref()
                .map(|input| chromium_keys(&mut vol, v, input, &mut out))
                .unwrap_or_default();
            for e in v.by_name("Login Data") {
                if !is_chromium_path(&e.path) {
                    continue;
                }
                let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
                    continue;
                };
                let logins = read_logins(&f.data);
                let browser = browser_of(&e.path);
                out.findings.push(
                    Finding::new("browser", "gespeicherte Zugangsdaten", &e.path)
                        .with("art", "passwoerter")
                        .with("browser", browser)
                        .with("anzahl", logins.len().to_string())
                        .with(
                            "hinweis",
                            if keys.is_empty() {
                                "verschluesselt (DPAPI/AES-GCM), Benutzerpasswort noetig"
                            } else {
                                "verschluesselt (DPAPI/AES-GCM), Entschluesselung versucht"
                            },
                        ),
                );
                if keys.is_empty() {
                    continue;
                }
                let mut entschluesselt = 0usize;
                for (url, user, pw_value) in &logins {
                    let Some(klartext) = keys
                        .iter()
                        .find_map(|k| stratum_creds::dpapi::chromium_password(pw_value, k).ok())
                    else {
                        continue;
                    };
                    entschluesselt += 1;
                    let mut fd = Finding::new("browser", "gespeichertes Passwort", &e.path)
                        .with("art", "passwort_klartext")
                        .with("browser", browser)
                        .with("url", url.clone())
                        .with("passwort", klartext);
                    if !user.is_empty() {
                        fd = fd.with("benutzername", user.clone());
                    }
                    out.findings.push(fd);
                }
                if entschluesselt < logins.len() {
                    out.warnings.push(format!(
                        "{}: {} von {} Passwoertern nicht entschluesselbar",
                        e.path,
                        logins.len() - entschluesselt,
                        logins.len()
                    ));
                }
            }
            let firefox_pw = ctx.firefox_password.as_deref().unwrap_or("");
            for e in v.by_name("logins.json") {
                firefox_logins(&mut vol, v, e, firefox_pw, &mut out);
            }
        }
        out
    }
}

/// Ein Eintrag aus `Login Data`: URL, Benutzername, verschlüsseltes Passwort.
type Login = (String, String, Vec<u8>);

/// Liest die Einträge aus einer `Login Data`-SQLite-Datei. Leer bei Fehler.
fn read_logins(data: &[u8]) -> Vec<Login> {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return Vec::new();
    };
    if std::io::Write::write_all(&mut tmp, data).is_err() {
        return Vec::new();
    }
    let uri = format!("file:{}?immutable=1", tmp.path().display());
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ) else {
        return Vec::new();
    };
    let Ok(mut stmt) =
        conn.prepare("SELECT origin_url, username_value, password_value FROM logins")
    else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0).unwrap_or_default(),
            r.get::<_, String>(1).unwrap_or_default(),
            r.get::<_, Vec<u8>>(2).unwrap_or_default(),
        ))
    }) else {
        return Vec::new();
    };
    rows.flatten().collect()
}

/// Prüft, ob ein Pfad auf eine DPAPI-Masterkey-Datei zeigt
/// (`...\Microsoft\Protect\<SID>\<GUID>`).
fn is_masterkey_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.contains("\\microsoft\\protect\\") {
        return false;
    }
    path.rsplit('\\').next().map(is_guid).unwrap_or(false)
}

/// Erkennt einen GUID-Dateinamen (36 Zeichen, `8-4-4-4-12` Hex).
fn is_guid(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = if matches!(i, 8 | 13 | 18 | 23) {
            c == b'-'
        } else {
            c.is_ascii_hexdigit()
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Die SID aus dem Pfad einer Masterkey-Datei (der Ordner über der GUID-Datei).
fn sid_from_path(path: &str) -> Option<String> {
    let mut parts = path.rsplit('\\');
    let _guid = parts.next()?;
    let sid = parts.next()?;
    sid.starts_with("S-1-").then(|| sid.to_string())
}

/// Liest den base64-dekodierten `os_crypt.encrypted_key` (inklusive `DPAPI`-
/// Präfix) aus einer `Local State`-JSON-Datei.
fn local_state_key(data: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let json: serde_json::Value = serde_json::from_slice(data).ok()?;
    let b64 = json.get("os_crypt")?.get("encrypted_key")?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Sammelt aus einem Volume die AES-GCM-Schlüssel der Chromium-Profile: erst die
/// DPAPI-Masterkeys entschlüsseln, dann damit die Schlüssel aus `Local State`.
fn chromium_keys<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    input: &DpapiInput,
    out: &mut Outcome,
) -> Vec<[u8; 32]> {
    use std::collections::HashMap;
    let pwd_sha1 = match input {
        DpapiInput::Password(p) => Some(stratum_creds::dpapi::sha1_password(p)),
        DpapiInput::Sha1(h) => Some(*h),
        DpapiInput::Masterkey(_) => None,
    };

    let mut by_guid: HashMap<String, [u8; 64]> = HashMap::new();
    let mut all: Vec<[u8; 64]> = Vec::new();
    for e in v.files.iter().filter(|f| is_masterkey_path(&f.path)) {
        let Some(sid) = sid_from_path(&e.path) else {
            continue;
        };
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let guid = e
            .path
            .rsplit('\\')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match input {
            DpapiInput::Masterkey(mk) => {
                by_guid.insert(guid, *mk);
                all.push(*mk);
            }
            _ => {
                let sha1 = pwd_sha1.expect("bei Password/Sha1 gesetzt");
                match stratum_creds::dpapi::decrypt_masterkey(&f.data, &sid, &sha1) {
                    Ok(mk) => {
                        by_guid.insert(guid, mk);
                        all.push(mk);
                    }
                    Err(err) => out.warnings.push(format!(
                        "{}: Masterkey nicht entschluesselbar: {err}",
                        e.path
                    )),
                }
            }
        }
    }

    let mut keys: Vec<[u8; 32]> = Vec::new();
    for e in v.by_name("Local State") {
        if !is_chromium_path(&e.path) {
            continue;
        }
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let Some(blob) = local_state_key(&f.data) else {
            continue;
        };
        // Passenden Masterkey über die GUID im Blob wählen, sonst alle probieren.
        let matched = blob
            .strip_prefix(b"DPAPI")
            .and_then(|b| stratum_creds::dpapi::blob_masterkey_guid(b).ok())
            .and_then(|g| by_guid.get(&g).copied());
        let candidates: Vec<[u8; 64]> = matched.map(|m| vec![m]).unwrap_or_else(|| all.clone());
        for m in candidates {
            if let Ok(k) = stratum_creds::dpapi::chromium_key(&blob, &m) {
                keys.push(k);
                break;
            }
        }
    }
    keys
}

/// Ein Firefox-Login-Eintrag aus `logins.json`.
#[derive(serde::Deserialize)]
struct FirefoxLogin {
    hostname: Option<String>,
    #[serde(rename = "encryptedUsername")]
    encrypted_username: Option<String>,
    #[serde(rename = "encryptedPassword")]
    encrypted_password: Option<String>,
}

#[derive(serde::Deserialize)]
struct FirefoxLogins {
    logins: Vec<FirefoxLogin>,
}

/// Liest den Master-Schlüssel aus einer `key4.db` (als Bytes) mit dem
/// Hauptpasswort.
fn firefox_master_key(key4db: &[u8], primary_pw: &str) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = dir.path().join("key4.db");
    std::fs::write(&path, key4db).map_err(|e| e.to_string())?;
    let uri = format!("file:{}?immutable=1", path.display());
    let conn = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| e.to_string())?;
    let (global_salt, item2): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT item1, item2 FROM metaData WHERE id = 'password'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| e.to_string())?;
    let a11: Vec<u8> = conn
        .query_row(
            "SELECT a11 FROM nssPrivate WHERE a102 = ?1",
            [stratum_creds::nss::CKA_ID.as_slice()],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    stratum_creds::nss::master_key(&global_salt, &item2, &a11, primary_pw)
        .map_err(|e| e.to_string())
}

/// Wertet ein Firefox-`logins.json` aus: liest die zugehörige `key4.db` im selben
/// Profilordner, leitet den Master-Schlüssel ab und entschlüsselt die Einträge.
fn firefox_logins<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    entry: &FileEntry,
    primary_pw: &str,
    out: &mut Outcome,
) {
    let Ok(Some(f)) = vol.read_file_by_record(entry.mft_record, &entry.path) else {
        return;
    };
    let Ok(parsed) = serde_json::from_slice::<FirefoxLogins>(&f.data) else {
        return;
    };
    let anzahl = parsed.logins.len();

    // key4.db im selben Profilordner suchen.
    let dir = entry.path.rsplit_once('\\').map(|(d, _)| d).unwrap_or("");
    let key4 = v
        .by_name("key4.db")
        .find(|k| k.path.rsplit_once('\\').map(|(d, _)| d).unwrap_or("") == dir);
    let master = key4.and_then(|k| {
        vol.read_file_by_record(k.mft_record, &k.path)
            .ok()
            .flatten()
            .map(|kf| firefox_master_key(&kf.data, primary_pw))
    });

    let master = match master {
        Some(Ok(m)) => m,
        other => {
            // Kein Master-Schlüssel: nur Bestandsaufnahme.
            let hinweis = match other {
                Some(Err(e)) if e.contains("Hauptpasswort") => {
                    "verschluesselt (key4.db), Hauptpasswort noetig"
                }
                Some(Err(_)) => "verschluesselt (key4.db), Schluessel nicht ableitbar",
                None => "verschluesselt (key4.db), key4.db nicht gefunden",
                _ => unreachable!(),
            };
            out.findings.push(
                Finding::new("browser", "gespeicherte Zugangsdaten", &entry.path)
                    .with("art", "passwoerter")
                    .with("browser", "firefox")
                    .with("anzahl", anzahl.to_string())
                    .with("hinweis", hinweis),
            );
            return;
        }
    };

    out.findings.push(
        Finding::new("browser", "gespeicherte Zugangsdaten", &entry.path)
            .with("art", "passwoerter")
            .with("browser", "firefox")
            .with("anzahl", anzahl.to_string())
            .with(
                "hinweis",
                "verschluesselt (key4.db), Entschluesselung versucht",
            ),
    );

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut entschluesselt = 0usize;
    for login in &parsed.logins {
        let (Some(u), Some(p)) = (&login.encrypted_username, &login.encrypted_password) else {
            continue;
        };
        let (Ok(ub), Ok(pb)) = (b64.decode(u), b64.decode(p)) else {
            continue;
        };
        let (Ok(user), Ok(pass)) = (
            stratum_creds::nss::decrypt_login(&ub, &master),
            stratum_creds::nss::decrypt_login(&pb, &master),
        ) else {
            continue;
        };
        entschluesselt += 1;
        let mut fd = Finding::new("browser", "gespeichertes Passwort", &entry.path)
            .with("art", "passwort_klartext")
            .with("browser", "firefox")
            .with("url", login.hostname.clone().unwrap_or_default())
            .with("passwort", pass);
        if !user.is_empty() {
            fd = fd.with("benutzername", user);
        }
        out.findings.push(fd);
    }
    if entschluesselt < anzahl {
        out.warnings.push(format!(
            "{}: {} von {} Firefox-Passwoertern nicht entschluesselbar",
            entry.path,
            anzahl - entschluesselt,
            anzahl
        ));
    }
}

#[derive(Clone, Copy)]
enum Query {
    Chromium,
    Firefox,
}

fn process<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    record: u64,
    path: &str,
    browser: &str,
    query: Query,
    out: &mut Outcome,
) {
    let data = match vol.read_file_by_record(record, path) {
        Ok(Some(f)) => f.data,
        Ok(None) => {
            out.warnings
                .push(format!("{path}: Verlauf-Datei ohne Dateninhalt"));
            return;
        }
        Err(e) => {
            out.warnings
                .push(format!("{path}: Verlauf-Datei nicht lesbar: {e}"));
            return;
        }
    };
    // Aktuelle Eintraege stehen oft in der WAL-Datei; diese (und -shm) mitlesen,
    // damit sie beim Oeffnen eingespielt werden.
    let wal = vol
        .read_file(&format!("{path}-wal"))
        .ok()
        .flatten()
        .map(|f| f.data);
    let shm = vol
        .read_file(&format!("{path}-shm"))
        .ok()
        .flatten()
        .map(|f| f.data);
    match read_history(&data, wal.as_deref(), shm.as_deref(), query) {
        Ok(rows) => {
            out.findings
                .push(summary_finding(path, browser, rows.len(), wal.is_some()));
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

/// Fund über die geprüfte Verlauf-Datenbank. Wird auch bei 0 Einträgen
/// erzeugt, damit im Bericht steht, dass die Datenbank gefunden und gelesen
/// wurde.
fn summary_finding(path: &str, browser: &str, rows: usize, has_wal: bool) -> Finding {
    let mut f = Finding::new("browser", "Verlauf-Datenbank geprüft", path)
        .with("art", "verlauf_db")
        .with("browser", browser)
        .with("eintraege", rows.to_string())
        .with("wal", if has_wal { "ja" } else { "nein" });
    if rows >= MAX_ROWS {
        f = f.with("gekappt_bei", MAX_ROWS.to_string());
    }
    f
}

/// Schreibt die Datenbank-Bytes (samt WAL/SHM, falls vorhanden) in ein
/// temporäres Verzeichnis und liest den Verlauf.
fn read_history(
    data: &[u8],
    wal: Option<&[u8]>,
    shm: Option<&[u8]>,
    query: Query,
) -> Result<Vec<HistoryRow>, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("db.sqlite");
    std::fs::write(&db, data)?;
    if let Some(w) = wal {
        std::fs::write(dir.path().join("db.sqlite-wal"), w)?;
    }
    if let Some(s) = shm {
        std::fs::write(dir.path().join("db.sqlite-shm"), s)?;
    }

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
    Ok(read_urls(&db, wal.is_some(), sql, base)?)
}

fn read_urls(
    path: &std::path::Path,
    has_wal: bool,
    sql: &str,
    base: TimeBase,
) -> rusqlite::Result<Vec<HistoryRow>> {
    let conn = if has_wal {
        // Mit WAL: normal (schreibend auf die Kopie) öffnen, damit SQLite die
        // WAL-Eintraege einspielt.
        Connection::open(path)?
    } else {
        // Ohne WAL: unveränderlicher Nur-Lese-Zugriff auf die Kopie.
        let uri = format!("file:{}?immutable=1", path.display());
        Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?
    };
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
            false,
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
            false,
            "SELECT url,title,last_visit_date FROM moz_places WHERE url IS NOT NULL",
            TimeBase::Firefox,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, Some(1_700_000_000));
    }

    #[test]
    fn leere_datenbank_wird_gemeldet() {
        let f = summary_finding("Users\\a\\History", "edge", 0, true);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("verlauf_db"));
        assert!(json.contains("\"eintraege\":\"0\""));
        assert!(!json.contains("gekappt_bei"));
        let voll = serde_json::to_string(&summary_finding("x", "chrome", MAX_ROWS, false)).unwrap();
        assert!(voll.contains("gekappt_bei"));
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

    #[test]
    fn guid_und_masterkey_pfad() {
        assert!(is_guid("1f2e3d4c-5b6a-7089-90ab-cdef01234567"));
        assert!(!is_guid("nicht-guid"));
        assert!(!is_guid("1f2e3d4c-5b6a-7089-90ab-cdef0123456")); // zu kurz
        let mk = "Users\\ich\\AppData\\Roaming\\Microsoft\\Protect\\\
                  S-1-5-21-1-2-3-1001\\1f2e3d4c-5b6a-7089-90ab-cdef01234567";
        assert!(is_masterkey_path(mk));
        assert_eq!(sid_from_path(mk).as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert!(!is_masterkey_path(
            "Users\\ich\\AppData\\Roaming\\Microsoft\\Protect\\CREDHIST"
        ));
    }

    #[test]
    fn local_state_schluessel_wird_base64_dekodiert() {
        use base64::Engine;
        let roh = b"DPAPI\x01\x02\x03";
        let b64 = base64::engine::general_purpose::STANDARD.encode(roh);
        let json = format!("{{\"os_crypt\":{{\"encrypted_key\":\"{b64}\"}}}}");
        assert_eq!(local_state_key(json.as_bytes()).as_deref(), Some(&roh[..]));
        assert_eq!(local_state_key(b"{}"), None);
    }

    #[test]
    fn login_data_wird_gelesen() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE logins(origin_url TEXT, username_value TEXT, password_value BLOB);\
             INSERT INTO logins VALUES('https://a.tld','max',x'763130aabb');",
        )
        .unwrap();
        let bytes = std::fs::read(tmp.path()).unwrap();
        let rows = read_logins(&bytes);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "https://a.tld");
        assert_eq!(rows[0].1, "max");
        assert_eq!(rows[0].2, vec![0x76, 0x31, 0x30, 0xaa, 0xbb]); // "v10" + Daten
    }
}
