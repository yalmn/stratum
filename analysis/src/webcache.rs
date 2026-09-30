//! WebCache (`WebCacheV01.dat`): Verlauf, Cache, Cookies und weitere
//! Tabellen der WinINet-Komponente (Internet Explorer, Edge Legacy, Explorer
//! und Apps, die WinINet nutzen). Je Benutzer unter
//! `AppData\Local\Microsoft\Windows\WebCache\`.
//!
//! Gelesen mit dem eigenen ESE-Parser. Die Tabelle `Containers` beschreibt
//! die Container (Name wie `History`, `Content`, `MSHist01...`, Verzeichnis,
//! Unterordner). Ihre Einträge stehen in `Container_<ContainerId>`. Jeder
//! Datensatz jeder Tabelle außer dem Systemkatalog wird ein Fund mit allen
//! belegten Spalten.
//!
//! An echten Daten geprüft:
//! - `SecureDirectory` ist ein bei 1 beginnender Index in
//!   `SecureDirectories` (Unterordnernamen zu je 8 Zeichen). Pfad aus
//!   Containerverzeichnis, Unterordner und `Filename` führt auf die Datei im
//!   Cache. Die Größe stimmte im Container `Content` mit `FileSize` überein,
//!   im Container `DOMStore` nicht; `FileSize` wird daher nicht gedeutet.
//! - `ModifiedTime` in `MSHist`-Containern liegt genau um den UTC-Abstand der
//!   Systemzeitzone nach dem Besuch; der Wert ist vermutlich Ortszeit. Er wird
//!   nicht umgerechnet, sondern als Ortszeit gekennzeichnet ausgegeben.
//!   Die übrigen Zeitspalten sind FILETIME in UTC.
//!
//! In die Timeline gehen `AccessedTime` (zuletzt zugegriffen) und
//! `CreationTime` (erstellt) der Containereinträge.

use std::collections::HashMap;

use stratum_core::time::filetime_to_iso;
use stratum_ese::{Database, Value};
use stratum_ntfs::NtfsVolume;
use stratum_registry::filetime_to_unix;

use crate::esewerte::{self, benutzer_aus_pfad, render, Quelle};
use crate::fsindex::FsIndex;
use crate::{AnalysisContext, Analyzer, Finding, Outcome};

const DB_NAME: &str = "WebCacheV01.dat";
const DOMAIN: &str = "browser";
/// Spalten mit FILETIME-Werten (Namen aus den WinINet-Tabellen).
const FILETIME_SPALTEN: &[&str] = &[
    "SyncTime",
    "CreationTime",
    "ExpiryTime",
    "ModifiedTime",
    "AccessedTime",
    "PostCheckTime",
    "LastScavengeTime",
    "LastAccessTime",
    "Expires",
    "LastTimeUsed",
    "LastModified",
    "AccessTime",
];
/// Bevorzugte Spalten für den Namen eines Funds.
const NAMENSSPALTEN: &[&str] = &["Url", "RDomain", "Name", "Directory", "HostName"];
const MAX_FINDINGS: usize = 500_000;

/// Analyzer für `WebCacheV01.dat`.
pub struct WebCacheAnalyzer;

impl Analyzer for WebCacheAnalyzer {
    fn domain(&self) -> &str {
        DOMAIN
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            let dateien: Vec<_> = v.by_name(DB_NAME).cloned().collect();
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
            let erster = out.findings.len();
            for entry in dateien {
                let Some((data, layout, ohne_image)) = esewerte::lesen(&mut vol, &entry, &mut out)
                else {
                    continue;
                };
                let quelle = Quelle {
                    pfad: &entry.path,
                    mft_record: entry.mft_record,
                    volume_offset: v.target.offset,
                    layout: layout.as_ref(),
                    ohne_image,
                };
                analyze(&data, &quelle, &mut out);
            }
            cache_dateien_suchen(v, &mut out.findings[erster..]);
        }
        out
    }
}

/// Ein Container laut Tabelle `Containers`.
#[derive(Debug, Default)]
struct Container {
    name: String,
    verzeichnis: String,
    partition: String,
    unterordner: Vec<String>,
}

impl Container {
    fn ist_tagesverlauf(&self) -> bool {
        self.name.starts_with("MSHist")
    }
}

fn text(v: Option<Value>) -> String {
    match v {
        Some(Value::Text(t)) => t,
        _ => String::new(),
    }
}

fn containers(db: &Database<'_>) -> HashMap<i64, Container> {
    let mut out = HashMap::new();
    let Some(t) = db.table("Containers") else {
        return out;
    };
    for rec in db.records(t).unwrap_or_default() {
        let Some(Value::I64(id)) = rec.get_by_name("ContainerId") else {
            continue;
        };
        let secure = text(rec.get_by_name("SecureDirectories"));
        out.insert(
            id,
            Container {
                name: text(rec.get_by_name("Name")),
                verzeichnis: text(rec.get_by_name("Directory")),
                partition: text(rec.get_by_name("PartitionId")),
                unterordner: secure
                    .as_bytes()
                    .chunks(8)
                    .filter(|c| c.len() == 8)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect(),
            },
        );
    }
    out
}

/// Zerlegt die URL-Formen der Verlaufscontainer:
/// `Visited: <Konto>@<URL>` und `:<Zeitraum>: <Konto>@<URL>`.
/// Andere Formen bleiben unverändert.
fn verlauf_url(url: &str) -> Option<(Option<&str>, &str, &str)> {
    let (zeitraum, rest) = if let Some(rest) = url.strip_prefix("Visited: ") {
        (None, rest)
    } else {
        let rest = url.strip_prefix(':')?;
        let (zeitraum, rest) = rest.split_once(": ")?;
        if zeitraum.len() != 16 || !zeitraum.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        (Some(zeitraum), rest)
    };
    let (konto, ziel) = rest.split_once('@')?;
    Some((zeitraum, konto, ziel))
}

fn unix(v: &Value) -> Option<i64> {
    match v {
        Value::I64(ft) if *ft > 0 && *ft != i64::MAX => {
            filetime_to_unix(u64::try_from(*ft).ok()?).map(|(s, _)| s)
        }
        _ => None,
    }
}

fn analyze(data: &[u8], quelle: &Quelle<'_>, out: &mut Outcome) {
    let db = match Database::open(data) {
        Ok(db) => db,
        Err(e) => {
            out.warnings
                .push(format!("{}: ESE nicht lesbar: {e}", quelle.pfad));
            return;
        }
    };
    esewerte::zustand_melden(&db, quelle.pfad, out);
    let benutzer = benutzer_aus_pfad(quelle.pfad);
    let container = containers(&db);
    let mut eintraege = 0usize;
    let mut nicht_ausgewertet = 0usize;
    for table in db.tables() {
        if table.name.starts_with("MSys") {
            continue;
        }
        let records = match db.records(table) {
            Ok(r) => r,
            Err(e) => {
                out.warnings.push(format!(
                    "{}: Tabelle {} nicht lesbar: {e}",
                    quelle.pfad, table.name
                ));
                continue;
            }
        };
        let cont = table
            .name
            .strip_prefix("Container_")
            .and_then(|id| id.parse::<i64>().ok())
            .map(|id| container.get(&id));
        for rec in &records {
            if out.findings.len() >= MAX_FINDINGS {
                out.warnings.push(format!(
                    "{}: Grenze von {MAX_FINDINGS} Funden erreicht",
                    quelle.pfad
                ));
                return;
            }
            let art = if cont.is_some() {
                "webcache_eintrag"
            } else {
                "webcache_tabelle"
            };
            let mut f = quelle.herkunft(
                Finding::new(DOMAIN, "", quelle.pfad)
                    .with("art", art)
                    .with("tabelle", &table.name),
                &rec.node,
            );
            if let Some(b) = &benutzer {
                f = f.with("benutzer", b);
            }
            let c_info = cont.flatten();
            if let Some(c) = c_info {
                f = f
                    .with("container", &c.name)
                    .with("container_verzeichnis", &c.verzeichnis)
                    .with("partition", &c.partition);
            }
            let mut name = None;
            for c in &table.columns {
                let Some(v) = rec.get(c) else { continue };
                if matches!(v, Value::Special { .. }) {
                    nicht_ausgewertet += 1;
                }
                let n = c.name.as_str();
                if name.is_none() && NAMENSSPALTEN.contains(&n) {
                    if let Value::Text(t) = &v {
                        name = Some(t.clone());
                    }
                }
                if n == "ModifiedTime" && c_info.is_some_and(Container::ist_tagesverlauf) {
                    f = f.with(n, render(&v)).with(
                        "ModifiedTime_hinweis",
                        "in MSHist-Containern vermutlich Ortszeit; nicht in UTC umgerechnet",
                    );
                    if let Value::I64(ft) = v {
                        if let Some(iso) = u64::try_from(ft).ok().and_then(filetime_to_iso) {
                            f = f.with("ModifiedTime_ortszeit", iso.trim_end_matches('Z'));
                        }
                    }
                    continue;
                }
                if FILETIME_SPALTEN.contains(&n) {
                    if cont.is_some() {
                        let schluessel = match n {
                            "AccessedTime" => Some("letzter_zugriff_unix"),
                            "CreationTime" => Some("erstellt_unix"),
                            _ => None,
                        };
                        if let (Some(k), Some(s)) = (schluessel, unix(&v)) {
                            f = f.with(k, s.to_string());
                        }
                    }
                    f = esewerte::filetime(f, n, &v);
                    continue;
                }
                f = esewerte::spalte(f, rec, c, &v);
            }
            if let Some(c) = c_info {
                f = eintrag_deuten(f, c);
            }
            f.name = name.unwrap_or_else(|| table.name.clone());
            if let Some(url) = f.attributes.get("url") {
                f.name = url.clone();
            }
            out.findings.push(f);
            eintraege += 1;
        }
    }
    let mut summary = Finding::new(DOMAIN, "WebCache geprüft", quelle.pfad)
        .with("art", "webcache_db")
        .with("mft_record", quelle.mft_record.to_string())
        .with("volume_offset", quelle.volume_offset.to_string())
        .with("format_revision", db.header().format_revision.to_string())
        .with("zustand", db.header().state.to_string())
        .with("container", container.len().to_string())
        .with("datensaetze", eintraege.to_string())
        .with("nicht_ausgewertete_werte", nicht_ausgewertet.to_string());
    if let Some(b) = &benutzer {
        summary = summary.with("benutzer", b);
    }
    out.findings.push(summary);
}

/// Verlaufs-URL zerlegen und Cache-Datei zusammensetzen.
fn eintrag_deuten(mut f: Finding, c: &Container) -> Finding {
    if let Some(url) = f.attributes.get("Url").cloned() {
        if let Some((zeitraum, konto, ziel)) = verlauf_url(&url) {
            f = f.with("url", ziel).with("url_konto", konto);
            if let Some(z) = zeitraum {
                f = f.with("zeitraum", format!("{}-{}", &z[..8], &z[8..]));
            }
        }
    }
    let index = f
        .attributes
        .get("SecureDirectory")
        .and_then(|s| s.parse::<usize>().ok());
    let datei = f.attributes.get("Filename").cloned();
    if let (Some(i), Some(datei)) = (index, datei) {
        match i.checked_sub(1).and_then(|i| c.unterordner.get(i)) {
            Some(ordner) => {
                let mut pfad = c.verzeichnis.clone();
                if !pfad.ends_with('\\') {
                    pfad.push('\\');
                }
                f = f
                    .with("cache_unterordner", ordner)
                    .with("cache_datei", format!("{pfad}{ordner}\\{datei}"));
            }
            None if i > 0 => f = f.with("cache_unterordner_fehlt", i.to_string()),
            None => {}
        }
    }
    f
}

/// Sucht die Cache-Dateien der Funde im Volume (ein Durchlauf über den
/// Index). Pfade mit Laufwerksbuchstaben werden ohne ihn gesucht; ein
/// fehlender Treffer kann auch ein anderes Laufwerk bedeuten.
fn cache_dateien_suchen(v: &FsIndex, findings: &mut [Finding]) {
    let mut gesucht: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if let Some(p) = f.attributes.get("cache_datei") {
            let ohne = match p.as_bytes() {
                [_, b':', b'\\', ..] => &p[3..],
                _ => p.as_str(),
            };
            gesucht
                .entry(ohne.to_ascii_lowercase())
                .or_default()
                .push(i);
        }
    }
    if gesucht.is_empty() {
        return;
    }
    let mut gefunden: HashMap<usize, u64> = HashMap::new();
    for e in &v.files {
        if let Some(idx) = gesucht.get(&e.path.to_ascii_lowercase()) {
            for &i in idx {
                gefunden.entry(i).or_insert(e.mft_record);
            }
        }
    }
    for idx in gesucht.values() {
        for &i in idx {
            let a = &mut findings[i].attributes;
            match gefunden.get(&i) {
                Some(r) => {
                    a.insert("cache_datei_im_volume".into(), "ja".into());
                    a.insert("cache_datei_mft_record".into(), r.to_string());
                }
                None => {
                    a.insert("cache_datei_im_volume".into(), "nein".into());
                }
            }
        }
    }
}

/// Einstieg für das Fuzz-Target: beliebige Bytes als WebCacheV01.dat.
pub(crate) fn fuzz(data: &[u8]) {
    analyze(
        data,
        &Quelle::ohne_ablage(DB_NAME, "fuzz"),
        &mut Outcome::default(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esebau::{datenbank, Spalte, Tabelle};
    use crate::fsindex::FileEntry;
    use crate::NtfsTarget;

    const PFAD: &str = "Users\\ich\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat";

    fn u16text(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn ft(v: i64) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    fn utf16_spalte(id: u16, name: &'static str, typ: u32) -> Spalte {
        Spalte {
            codepage: 1200,
            ..Spalte::neu(id, name, typ)
        }
    }

    /// Mini-WebCache: Verlauf, Cache mit Unterordnern, Tagesverlauf und eine
    /// Tabelle ohne Container.
    fn mini_webcache() -> Vec<u8> {
        let containers = Tabelle {
            name: "Containers",
            spalten: vec![
                Spalte::neu(1, "ContainerId", 15),
                utf16_spalte(128, "Name", 10),
                utf16_spalte(256, "Directory", 12),
                utf16_spalte(257, "SecureDirectories", 12),
            ],
            zeilen: vec![
                vec![
                    (1, ft(1)),
                    (128, u16text("History")),
                    (256, u16text("C:\\Users\\ich\\History\\")),
                ],
                vec![
                    (1, ft(3)),
                    (128, u16text("Content")),
                    (256, u16text("C:\\Users\\ich\\INetCache\\IE\\")),
                    (257, u16text("AAAAAAAABBBBBBBB")),
                ],
                vec![
                    (1, ft(11)),
                    (128, u16text("MSHist012026041820260419")),
                    (256, u16text("C:\\Users\\ich\\History\\MSHist01\\")),
                ],
            ],
        };
        let eintrag = |name: &'static str, zeilen| Tabelle {
            name,
            spalten: vec![
                Spalte::neu(1, "EntryId", 15),
                Spalte::neu(2, "SecureDirectory", 14),
                Spalte::neu(3, "AccessedTime", 15),
                Spalte::neu(4, "ModifiedTime", 15),
                Spalte::neu(5, "CreationTime", 15),
                utf16_spalte(256, "Url", 12),
                utf16_spalte(257, "Filename", 12),
            ],
            zeilen,
        };
        // 2026-04-18T09:44:44.6680107Z
        let besuch = 134_209_790_846_680_107i64;
        let verlauf = eintrag(
            "Container_1",
            vec![vec![
                (1, ft(1)),
                (2, 0u32.to_le_bytes().to_vec()),
                (3, ft(besuch)),
                (4, ft(besuch)),
                (5, ft(0)),
                (256, u16text("Visited: ich@https://example.test/a")),
            ]],
        );
        let cache = eintrag(
            "Container_3",
            vec![
                vec![
                    (1, ft(1)),
                    (2, 2u32.to_le_bytes().to_vec()),
                    (3, ft(besuch)),
                    (5, ft(besuch - 10_000_000)),
                    (256, u16text("https://example.test/b.js")),
                    (257, u16text("b[1].js")),
                ],
                vec![
                    (1, ft(2)),
                    (2, 7u32.to_le_bytes().to_vec()),
                    (256, u16text("https://example.test/c")),
                    (257, u16text("c[1]")),
                ],
            ],
        );
        let tag = eintrag(
            "Container_11",
            vec![vec![
                (1, ft(1)),
                (3, ft(besuch)),
                (4, ft(besuch + 7_200 * 10_000_000)),
                (
                    256,
                    u16text(":2026041820260419: ich@https://example.test/a"),
                ),
            ]],
        );
        let hsts = Tabelle {
            name: "HstsEntryEx_7",
            spalten: vec![
                Spalte::neu(1, "EntryId", 15),
                Spalte::neu(2, "Expires", 15),
                utf16_spalte(256, "RDomain", 12),
            ],
            zeilen: vec![vec![
                (1, ft(1)),
                (2, ft(i64::MAX)),
                (256, u16text(":version")),
            ]],
        };
        datenbank(&[containers, verlauf, cache, tag, hsts], 3)
    }

    fn auswerten(data: &[u8]) -> Outcome {
        let mut out = Outcome::default();
        analyze(data, &Quelle::ohne_ablage(PFAD, "test"), &mut out);
        out
    }

    fn fund<'o>(out: &'o Outcome, tabelle: &str, n: usize) -> &'o Finding {
        out.findings
            .iter()
            .filter(|f| f.attributes.get("tabelle").map(String::as_str) == Some(tabelle))
            .nth(n)
            .unwrap()
    }

    #[test]
    fn verlaufsformen_zerlegen() {
        assert_eq!(
            verlauf_url("Visited: ich@https://a.test/x@y"),
            Some((None, "ich", "https://a.test/x@y"))
        );
        assert_eq!(
            verlauf_url(":2026041820260419: ich@:Host: Dieser PC"),
            Some((Some("2026041820260419"), "ich", ":Host: Dieser PC"))
        );
        assert_eq!(verlauf_url("https://a.test/"), None);
        assert_eq!(verlauf_url(":2026: ich@x"), None);
        assert_eq!(verlauf_url("Visited: ohne-konto"), None);
    }

    #[test]
    fn mini_webcache_auswerten() {
        let out = auswerten(&mini_webcache());
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        // 3 Container, 1 + 2 + 1 Einträge, 1 HSTS, Übersicht.
        assert_eq!(out.findings.len(), 9);

        let v = fund(&out, "Container_1", 0);
        assert_eq!(v.name, "https://example.test/a");
        assert_eq!(v.attributes["url_konto"], "ich");
        assert_eq!(v.attributes["container"], "History");
        assert_eq!(v.attributes["benutzer"], "ich");
        assert_eq!(
            v.attributes["AccessedTime_utc"],
            "2026-04-18T09:44:44.6680107Z"
        );
        assert_eq!(v.attributes["letzter_zugriff_unix"], "1776505484");
        assert!(!v.attributes.contains_key("erstellt_unix"));
        assert!(!v.attributes.contains_key("cache_datei"));

        let c = fund(&out, "Container_3", 0);
        assert_eq!(
            c.attributes["cache_datei"],
            "C:\\Users\\ich\\INetCache\\IE\\BBBBBBBB\\b[1].js"
        );
        assert_eq!(c.attributes["erstellt_unix"], "1776505483");
        let c = fund(&out, "Container_3", 1);
        assert_eq!(c.attributes["cache_unterordner_fehlt"], "7");
        assert!(!c.attributes.contains_key("letzter_zugriff_unix"));

        let t = fund(&out, "Container_11", 0);
        assert_eq!(t.attributes["zeitraum"], "20260418-20260419");
        assert_eq!(
            t.attributes["ModifiedTime_ortszeit"],
            "2026-04-18T11:44:44.6680107"
        );
        assert!(!t.attributes.contains_key("ModifiedTime_utc"));
        assert!(t.attributes.contains_key("ModifiedTime_hinweis"));

        let h = fund(&out, "HstsEntryEx_7", 0);
        assert_eq!(h.name, ":version");
        assert_eq!(h.attributes["art"], "webcache_tabelle");
        assert!(!h.attributes.contains_key("Expires_utc"));

        let s = out.findings.last().unwrap();
        assert_eq!(s.attributes["art"], "webcache_db");
        assert_eq!(s.attributes["container"], "3");
        assert_eq!(s.attributes["datensaetze"], "8");
    }

    #[test]
    fn cache_dateien_im_index() {
        let mut out = auswerten(&mini_webcache());
        let v = FsIndex {
            target: NtfsTarget {
                index: 0,
                offset: 0,
                size: 0,
            },
            files: vec![FileEntry {
                path: "Users\\ICH\\INetCache\\IE\\BBBBBBBB\\b[1].js".into(),
                mft_record: 77,
                size: 1,
                parent_record: 5,
            }],
            directories: Vec::new(),
            warnings: Vec::new(),
            unreadable_dirs: Vec::new(),
        };
        cache_dateien_suchen(&v, &mut out.findings);
        let c = fund(&out, "Container_3", 0);
        assert_eq!(c.attributes["cache_datei_im_volume"], "ja");
        assert_eq!(c.attributes["cache_datei_mft_record"], "77");
        let v = fund(&out, "Container_1", 0);
        assert!(!v.attributes.contains_key("cache_datei_im_volume"));
    }

    #[test]
    fn kaputte_daten_ohne_panik() {
        let data = mini_webcache();
        for n in [0, 100, 4096, 8192, 20_000, data.len() - 1] {
            fuzz(&data[..n]);
        }
        let mut kaputt = data.clone();
        for i in (0..kaputt.len()).step_by(89) {
            kaputt[i] ^= 0x5a;
        }
        fuzz(&kaputt);
    }

    fn ganzzahl(hex: &str, typ: u64) -> Option<String> {
        let b: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut w = [0u8; 8];
        w[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
        let u = u64::from_le_bytes(w);
        Some(match typ {
            2 => u.to_string(),
            3 => (u as i16).to_string(),
            4 => (u as i32).to_string(),
            14 | 17 => u.to_string(),
            15 => (u as i64).to_string(),
            _ => return None,
        })
    }

    /// Gegen eine echte WebCacheV01.dat und die dissect-Referenz: gleiche
    /// Datensätze je Tabelle, gleiche Ganzzahlwerte, Cache-Pfade mit den
    /// Unterordnern, in denen die Dateien im Image liegen.
    #[test]
    #[ignore = "benötigt STRATUM_ESE_REFERENCE"]
    fn dissect_referenz() {
        let ese = std::path::PathBuf::from(std::env::var_os("STRATUM_ESE_REFERENCE").unwrap());
        let data = std::fs::read(ese.join("WebCacheV01.dat")).unwrap();
        let referenz: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ese.join("webcache_referenz.json")).unwrap())
                .unwrap();
        let out = auswerten(&data);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);

        let mut werte = 0usize;
        let mut saetze_gesamt = 0usize;
        for (name, erwartet) in referenz.as_object().unwrap() {
            if name.starts_with("MSys") {
                continue;
            }
            let funde: Vec<&Finding> = out
                .findings
                .iter()
                .filter(|f| f.attributes.get("tabelle") == Some(name))
                .collect();
            let saetze = erwartet["datensaetze"].as_array().unwrap();
            assert_eq!(funde.len(), saetze.len(), "{name}: Datensätze");
            saetze_gesamt += saetze.len();
            for (f, satz) in funde.iter().zip(saetze) {
                for s in erwartet["spalten"].as_array().unwrap() {
                    let spalte = s["name"].as_str().unwrap();
                    let Some(hex) = satz[spalte]["hex"].as_str() else {
                        continue;
                    };
                    if let Some(z) = ganzzahl(hex, s["typ"].as_u64().unwrap()) {
                        assert_eq!(f.attributes.get(spalte), Some(&z), "{name} {spalte}");
                        werte += 1;
                    }
                }
            }
        }
        assert_eq!(saetze_gesamt, 35);
        assert_eq!(werte, 295);

        let cache: Vec<(&str, &str)> = out
            .findings
            .iter()
            .filter_map(|f| {
                Some((
                    f.attributes.get("cache_unterordner")?.as_str(),
                    f.attributes.get("Filename")?.as_str(),
                ))
            })
            .collect();
        for erwartet in [
            ("7FD08YXT", "dnserrordiagoff[1]"),
            ("D15N5G4G", "navcancl[1]"),
            ("4DO7BDM2", "views[2]"),
            ("4DO7BDM2", "views[1]"),
            ("Z60KKCEP", "microsoftwindows.client[1].xml"),
        ] {
            assert!(cache.contains(&erwartet), "{erwartet:?} fehlt in {cache:?}");
        }
        let tagesverlauf: Vec<&Finding> = out
            .findings
            .iter()
            .filter(|f| f.attributes.contains_key("ModifiedTime_ortszeit"))
            .collect();
        assert_eq!(tagesverlauf.len(), 2);
        let s = out.findings.last().unwrap();
        assert_eq!(s.attributes["datensaetze"], "35");
        assert_eq!(s.attributes["container"], "9");
        assert_eq!(s.attributes["nicht_ausgewertete_werte"], "0");
    }
}
