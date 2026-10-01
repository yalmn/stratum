//! SRUM (System Resource Usage Monitor): Ressourcen- und Netznutzung je
//! Programm und Konto aus `Windows\System32\sru\SRUDB.dat`.
//!
//! Die Datenbank wird mit dem eigenen ESE-Parser (Crate `stratum-ese`)
//! gelesen. Namen der Tabellen stammen aus der Registry des Systems
//! (`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`). Programme
//! und Konten stehen in `SruDbIdMapTable` und werden nach ihrer Struktur
//! dekodiert: eine gültige SID als SID, sonst UTF-16-Text; die Typnummer
//! bleibt als Zahl erhalten.
//!
//! Zeiten: `TimeStamp` ist ein OLE-Datum (Tage seit 1899-12-30, UTC) und wird
//! als `zeitpunkt_utc` ausgegeben. Geprüft an echten Daten: die FILETIME-Spalten
//! desselben Datensatzes (`EndTime`, `StartTime`, `ConnectStartTime`,
//! `EventTimestamp`) liegen höchstens zehn Minuten vor und nie mehr als eine
//! Sekunde nach diesem Wert. Was genau `TimeStamp` festhält, beschreibt
//! Microsoft nicht; es wird deshalb nicht als Beginn oder Ende einer Nutzung
//! gedeutet. SRUM-Datensätze sind zusammengefasste Messwerte, keine
//! Einzelereignisse, und erscheinen nicht in der Timeline.

use std::collections::HashMap;

use stratum_core::time::filetime_to_iso;
use stratum_ese::{Database, Value};
use stratum_registry::Hive;

use crate::esewerte::{self, hex, render, utf16, Quelle};
use crate::{AnalysisContext, Analyzer, Finding, Outcome};

const DB_NAME: &str = "SRUDB.dat";
const EXTENSIONS: &str = "Microsoft\\Windows NT\\CurrentVersion\\SRUM\\Extensions";
/// Spalten mit FILETIME-Werten, gegen `TimeStamp` derselben Datensätze geprüft.
const FILETIME_SPALTEN: [&str; 4] = ["EndTime", "StartTime", "ConnectStartTime", "EventTimestamp"];
const MAX_FINDINGS: usize = 500_000;

/// Analyzer für SRUM.
pub struct SrumAnalyzer;

impl Analyzer for SrumAnalyzer {
    fn dateibasiert(&self) -> bool {
        true
    }

    fn domain(&self) -> &str {
        "srum"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            // Nach Dateinamen, damit auch Kopien (etwa unter Windows.old)
            // erfasst werden; der Pfad steht in jedem Fund.
            let dateien: Vec<_> = v.by_name(DB_NAME).cloned().collect();
            if dateien.is_empty() {
                continue;
            }
            let (mut vol, abbildung) = match ctx.open_volume(v) {
                Ok(x) => x,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };
            let anbieter = ctx
                .installs
                .iter()
                .find(|i| i.target.offset == v.target.offset && i.origin == "live")
                .and_then(|i| i.hives.software.as_deref())
                .and_then(|b| Hive::parse(b).ok())
                .map(|h| provider_names(&h))
                .unwrap_or_default();
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
                    abbildung,
                };
                analyze(&data, &quelle, &anbieter, &mut out);
            }
        }
        out
    }
}

/// Anbieternamen je Tabellen-GUID (klein geschrieben, ohne Klammern).
fn provider_names(software: &Hive) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(Some(key)) = software.open_key(EXTENSIONS) else {
        return out;
    };
    for sub in key.subkeys().unwrap_or_default() {
        let name = sub
            .value("")
            .ok()
            .flatten()
            .and_then(|v| v.as_string())
            .filter(|s| !s.is_empty());
        if let Some(name) = name {
            out.insert(guid_key(sub.name()), name);
        }
    }
    out
}

fn guid_key(s: &str) -> String {
    s.trim_matches(|c| c == '{' || c == '}')
        .to_ascii_lowercase()
}

fn analyze(
    data: &[u8],
    quelle: &Quelle<'_>,
    anbieter: &HashMap<String, String>,
    out: &mut Outcome,
) {
    let db = match Database::open(data) {
        Ok(db) => db,
        Err(e) => {
            out.warnings
                .push(format!("{}: ESE nicht lesbar: {e}", quelle.pfad));
            return;
        }
    };
    esewerte::zustand_melden(&db, quelle.pfad, out);
    let ids = id_map(&db);
    let mut summary = Finding::new("srum", "SRUM-Datenbank geprüft", quelle.pfad)
        .with("art", "srum_db")
        .with("mft_record", quelle.mft_record.to_string())
        .with("volume_offset", quelle.volume_offset.to_string())
        .with("format_revision", db.header().format_revision.to_string())
        .with("zustand", db.header().state.to_string())
        .with("id_eintraege", ids.len().to_string());
    let mut gesamt = 0usize;
    for table in db.tables() {
        if !table.name.starts_with('{') {
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
        let name = anbieter.get(&guid_key(&table.name));
        for rec in &records {
            if out.findings.len() >= MAX_FINDINGS {
                out.warnings.push(format!(
                    "{}: Grenze von {MAX_FINDINGS} Funden erreicht",
                    quelle.pfad
                ));
                return;
            }
            let mut f = quelle.herkunft(
                Finding::new("srum", "", quelle.pfad)
                    .with("art", "srum")
                    .with("tabelle", &table.name),
                &rec.node,
            );
            if let Some(n) = name {
                f = f.with("anbieter", n);
            }
            let mut titel = None;
            for c in &table.columns {
                let Some(v) = rec.get(c) else { continue };
                match c.name.as_str() {
                    "AppId" | "UserId" => {
                        let Value::I32(id) = v else {
                            f = f.with(&c.name, render(&v));
                            continue;
                        };
                        f = f.with(&c.name, id.to_string());
                        if let Some((typ, text)) = ids.get(&id) {
                            let feld = if c.name == "AppId" {
                                "programm"
                            } else {
                                "konto"
                            };
                            f = f.with(format!("{feld}_id_typ"), typ.to_string());
                            match text {
                                Some(text) => {
                                    f = f.with(feld, text);
                                    if feld == "programm" {
                                        titel = Some(text.clone());
                                    }
                                }
                                None => f = f.with(format!("{feld}_hinweis"), "IdBlob leer"),
                            }
                        }
                    }
                    "TimeStamp" => match (ole_iso(&v), &v) {
                        // Rohwert (Tage als f64) zusätzlich, damit die Zeit
                        // ohne Umweg über den Text nachgeprüft werden kann.
                        (Some(iso), Value::DateTime(raw)) => {
                            f = f
                                .with("zeitpunkt_utc", iso)
                                .with("zeitpunkt_ole", f64::from_bits(*raw).to_string())
                        }
                        _ => f = f.with("TimeStamp_roh", render(&v)),
                    },
                    n if FILETIME_SPALTEN.contains(&n) => f = esewerte::filetime(f, n, &v),
                    _ => f = esewerte::spalte(f, rec, c, &v),
                }
            }
            f.name = titel.unwrap_or_else(|| name.cloned().unwrap_or_else(|| table.name.clone()));
            out.findings.push(f);
            gesamt += 1;
        }
    }
    summary = summary.with("datensaetze", gesamt.to_string());
    out.findings.push(summary);
}

/// `SruDbIdMapTable`: IdIndex auf (IdType, dekodierter IdBlob).
/// Einträge ohne IdBlob bleiben mit ihrem Typ erhalten.
fn id_map(db: &Database<'_>) -> HashMap<i32, (u8, Option<String>)> {
    let mut out = HashMap::new();
    let Some(t) = db.table("SruDbIdMapTable") else {
        return out;
    };
    let (Some(typ), Some(index), Some(blob)) =
        (t.column("IdType"), t.column("IdIndex"), t.column("IdBlob"))
    else {
        return out;
    };
    for rec in db.records(t).unwrap_or_default() {
        let (Some(Value::U8(ty)), Some(Value::I32(ix))) = (rec.get(typ), rec.get(index)) else {
            continue;
        };
        let text = match rec.get(blob) {
            Some(Value::Binary(b)) => Some(decode_blob(&b)),
            Some(v) => Some(render(&v)),
            None => None,
        };
        out.insert(ix, (ty, text));
    }
    out
}

/// SID, wenn die Bytes genau eine SID bilden, sonst UTF-16-Text, sonst Hex.
fn decode_blob(b: &[u8]) -> String {
    if let Some(sid) = sid(b) {
        return sid;
    }
    utf16(b).unwrap_or_else(|| hex(b))
}

/// SID-Binärform: Revision 1, Anzahl, 6 Byte Authority (big-endian), dann
/// Unterautoritäten (je 4 Byte little-endian).
fn sid(b: &[u8]) -> Option<String> {
    let (&rev, &count) = (b.first()?, b.get(1)?);
    if rev != 1 || count > 15 || b.len() != 8 + 4 * usize::from(count) {
        return None;
    }
    let authority = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut s = format!("S-1-{authority}");
    for i in 0..usize::from(count) {
        let at = 8 + 4 * i;
        s.push_str(&format!(
            "-{}",
            u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
        ));
    }
    Some(s)
}

/// OLE-Datum (Tage seit 1899-12-30) als FILETIME, auf die Millisekunde.
fn ole_filetime(raw: u64) -> Option<u64> {
    let days = f64::from_bits(raw);
    if !days.is_finite() || !(1.0..200_000.0).contains(&days) {
        return None;
    }
    // 25_569 Tage liegen zwischen 1899-12-30 und 1970-01-01.
    let unix_ms = ((days - 25_569.0) * 86_400_000.0).round() as i64;
    u64::try_from((unix_ms + 11_644_473_600_000).checked_mul(10_000)?).ok()
}

/// OLE-Datum in ISO 8601 UTC.
fn ole_iso(v: &Value) -> Option<String> {
    let Value::DateTime(raw) = v else { return None };
    filetime_to_iso(ole_filetime(*raw)?)
}

/// Einstieg für das Fuzz-Target: beliebige Bytes als SRUDB.dat.
pub(crate) fn fuzz(data: &[u8]) {
    let quelle = Quelle::ohne_ablage(DB_NAME, "fuzz");
    analyze(data, &quelle, &HashMap::new(), &mut Outcome::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::esebau as bau;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// Mini-SRUDB: IdMap mit Dienstname, Pfad, SID und leerem Eintrag, eine
    /// Netztabelle und eine Tabelle mit UTF-16 in einer 1252-Textspalte.
    fn mini_srudb(zustand: u32) -> Vec<u8> {
        use bau::{datenbank, Spalte, Tabelle};
        let idmap = Tabelle {
            name: "SruDbIdMapTable",
            spalten: vec![
                Spalte::neu(1, "IdType", 2),
                Spalte::neu(2, "IdIndex", 4),
                Spalte::neu(256, "IdBlob", 11),
            ],
            zeilen: vec![
                vec![
                    (1, vec![1]),
                    (2, 5i32.to_le_bytes().to_vec()),
                    (256, utf16z("Dnscache")),
                ],
                vec![
                    (1, vec![0]),
                    (2, 6i32.to_le_bytes().to_vec()),
                    (
                        256,
                        utf16z("\\device\\harddiskvolume3\\windows\\explorer.exe"),
                    ),
                ],
                vec![
                    (1, vec![3]),
                    (2, 7i32.to_le_bytes().to_vec()),
                    (256, vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]),
                ],
                vec![(1, vec![3]), (2, 8i32.to_le_bytes().to_vec())],
            ],
        };
        let kopf = |extra: Vec<Spalte>| {
            let mut v = vec![
                Spalte::neu(1, "AutoIncId", 4),
                Spalte::neu(2, "TimeStamp", 8),
                Spalte::neu(3, "AppId", 4),
                Spalte::neu(4, "UserId", 4),
            ];
            v.extend(extra);
            v
        };
        // 2026-04-18 08:47:00 UTC als OLE-Datum.
        let ts = (46_130.0f64 + (8.0 * 60.0 + 47.0) / 1440.0)
            .to_bits()
            .to_le_bytes()
            .to_vec();
        let netz = Tabelle {
            name: "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
            spalten: kopf(vec![
                Spalte::neu(5, "BytesSent", 15),
                Spalte::neu(6, "BytesRecvd", 15),
            ]),
            zeilen: vec![
                vec![
                    (1, 1i32.to_le_bytes().to_vec()),
                    (2, ts.clone()),
                    (3, 5i32.to_le_bytes().to_vec()),
                    (4, 7i32.to_le_bytes().to_vec()),
                    (5, 713i64.to_le_bytes().to_vec()),
                    (6, 2022i64.to_le_bytes().to_vec()),
                ],
                vec![
                    (1, 2i32.to_le_bytes().to_vec()),
                    (2, ts.clone()),
                    (3, 6i32.to_le_bytes().to_vec()),
                    (4, 8i32.to_le_bytes().to_vec()),
                    (5, 1i64.to_le_bytes().to_vec()),
                ],
            ],
        };
        let energie = Tabelle {
            name: "{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}",
            spalten: kopf(vec![Spalte::neu(256, "Tag", 10)]),
            zeilen: vec![vec![
                (1, 1i32.to_le_bytes().to_vec()),
                (2, ts),
                (3, 99i32.to_le_bytes().to_vec()),
                (256, utf16z(":v")),
            ]],
        };
        datenbank(&[idmap, netz, energie], zustand)
    }

    fn quelle() -> Quelle<'static> {
        Quelle {
            pfad: "Windows\\System32\\sru\\SRUDB.dat",
            mft_record: 42,
            volume_offset: 0,
            layout: None,
            ohne_image: "test",
            abbildung: crate::schatten::Abbildung::live(),
        }
    }

    #[test]
    fn mini_srudb_auswerten() {
        let data = mini_srudb(3);
        let mut anbieter = HashMap::new();
        anbieter.insert(
            guid_key("{973f5d5c-1d90-4944-be8e-24b94231a174}"),
            "Windows Network Data Usage Monitor".to_string(),
        );
        let mut out = Outcome::default();
        analyze(&data, &quelle(), &anbieter, &mut out);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        assert_eq!(out.findings.len(), 4);

        let a = &out.findings[0].attributes;
        assert_eq!(out.findings[0].name, "Dnscache");
        assert_eq!(a["programm_id_typ"], "1");
        assert_eq!(a["konto"], "S-1-5-18");
        assert_eq!(a["anbieter"], "Windows Network Data Usage Monitor");
        assert_eq!(a["zeitpunkt_utc"], "2026-04-18T08:47:00.0000000Z");
        // Rohwert in Tagen seit 1899-12-30 ergibt dieselbe Zeit.
        let ole: f64 = a["zeitpunkt_ole"].parse().unwrap();
        assert_eq!(((ole - 25_569.0) * 86_400.0).round() as i64, 1_776_502_020);
        assert_eq!(a["BytesSent"], "713");
        assert_eq!(a["BytesRecvd"], "2022");
        assert_eq!(a["mft_record"], "42");
        assert_eq!(a["image_offset_fehlt"], "test");
        let at: usize = a["datei_offset"].parse().unwrap();
        assert_eq!(
            data[at], 6,
            "Datensatz beginnt mit der letzten festen Spalte"
        );

        let b = &out.findings[1].attributes;
        assert_eq!(
            b["programm"],
            "\\device\\harddiskvolume3\\windows\\explorer.exe"
        );
        assert_eq!(b["konto_hinweis"], "IdBlob leer");
        assert!(!b.contains_key("BytesRecvd"));

        // Unbekannter Anbieter, unbekannte AppId, UTF-16 in 1252-Spalte.
        let c = &out.findings[2];
        assert_eq!(c.name, "{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}");
        assert!(!c.attributes.contains_key("anbieter"));
        assert!(!c.attributes.contains_key("programm"));
        assert_eq!(c.attributes["Tag"], "3a0076000000");
        assert_eq!(c.attributes["Tag_als_utf16"], ":v");
        assert!(c.attributes.contains_key("Tag_hinweis"));

        let s = &out.findings[3].attributes;
        assert_eq!(s["art"], "srum_db");
        assert_eq!(s["datensaetze"], "3");
        assert_eq!(s["id_eintraege"], "4");
    }

    #[test]
    fn unsauber_geschlossen_wird_gemeldet() {
        let mut out = Outcome::default();
        analyze(&mini_srudb(2), &quelle(), &HashMap::new(), &mut out);
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].contains("unsauber"));
        assert_eq!(out.findings.len(), 4);
    }

    #[test]
    fn kaputte_daten_ohne_panik() {
        let data = mini_srudb(3);
        for n in [0, 100, 4096, 8192, 20_000, data.len() - 1] {
            fuzz(&data[..n]);
        }
        let mut kaputt = data.clone();
        for i in (0..kaputt.len()).step_by(97) {
            kaputt[i] ^= 0xa5;
        }
        fuzz(&kaputt);
    }

    #[test]
    fn sid_und_text_nach_struktur() {
        assert_eq!(
            decode_blob(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]),
            "S-1-5-18"
        );
        let text: Vec<u8> = "Dnscache\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_blob(&text), "Dnscache");
        assert_eq!(decode_blob(&[0xff]), "ff");
        // Falsche Länge: keine SID.
        assert!(sid(&[1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).is_none());
    }

    #[test]
    fn ole_datum_in_utc() {
        // Rohwert der ersten Zeile von {D10CA2FE-...} aus einer echten
        // SRUDB.dat, von dissect.esedb gleich gelesen.
        let v = Value::DateTime(4_676_572_922_901_150_652);
        assert_eq!(ole_iso(&v).as_deref(), Some("2026-04-18T08:48:00.0000000Z"));
        assert_eq!(ole_iso(&Value::DateTime(f64::NAN.to_bits())), None);
        assert_eq!(ole_iso(&Value::I32(1)), None);
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

    /// Gegen echte SRUDB.dat und SOFTWARE sowie die dissect-Referenz: gleiche
    /// Datensätze je Tabelle, gleiche Ganzzahlwerte, alle Programme und Konten
    /// aufgelöst, Anbieternamen vorhanden, OLE-Zeit passend zu den
    /// FILETIME-Spalten.
    #[test]
    #[ignore = "benötigt STRATUM_ESE_REFERENCE und STRATUM_HIVELOG_REFERENCE"]
    fn dissect_referenz() {
        let ese = std::path::PathBuf::from(std::env::var_os("STRATUM_ESE_REFERENCE").unwrap());
        let hives =
            std::path::PathBuf::from(std::env::var_os("STRATUM_HIVELOG_REFERENCE").unwrap());
        let data = std::fs::read(ese.join("SRUDB.dat")).unwrap();
        let referenz: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ese.join("srudb_referenz.json")).unwrap())
                .unwrap();
        let software = std::fs::read(hives.join("SOFTWARE")).unwrap();
        let anbieter = provider_names(&Hive::parse(&software).unwrap());
        assert!(anbieter.len() >= 8, "{anbieter:?}");
        let quelle = Quelle {
            pfad: "Windows\\System32\\sru\\SRUDB.dat",
            mft_record: 0,
            volume_offset: 0,
            layout: None,
            ohne_image: "test",
            abbildung: crate::schatten::Abbildung::live(),
        };
        let mut out = Outcome::default();
        analyze(&data, &quelle, &anbieter, &mut out);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);

        let mut tabellen = 0;
        let mut werte = 0usize;
        let mut zeiten = 0usize;
        for (name, erwartet) in referenz.as_object().unwrap() {
            if !name.starts_with('{') {
                continue;
            }
            tabellen += 1;
            let funde: Vec<&Finding> = out
                .findings
                .iter()
                .filter(|f| f.attributes.get("tabelle") == Some(name))
                .collect();
            let saetze = erwartet["datensaetze"].as_array().unwrap();
            assert_eq!(funde.len(), saetze.len(), "{name}: Datensätze");
            for (f, satz) in funde.iter().zip(saetze) {
                assert!(f.attributes.contains_key("anbieter"), "{name}");
                assert!(f.attributes.contains_key("zeitpunkt_utc"), "{name}");
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
                if f.attributes.contains_key("AppId") {
                    assert!(f.attributes.contains_key("programm_id_typ"), "{name} {f:?}");
                }
                if f.attributes.contains_key("UserId") {
                    assert!(f.attributes.contains_key("konto_id_typ"), "{name} {f:?}");
                }
                // FILETIME-Spalten liegen höchstens zehn Minuten vor und
                // höchstens eine Minute nach dem OLE-Zeitpunkt.
                let ts = u64::from_str_radix(
                    &satz["TimeStamp"]["hex"]
                        .as_str()
                        .unwrap()
                        .as_bytes()
                        .chunks(2)
                        .rev()
                        .map(|c| std::str::from_utf8(c).unwrap())
                        .collect::<String>(),
                    16,
                )
                .unwrap();
                let ts = ole_filetime(ts).unwrap() as i64;
                for spalte in FILETIME_SPALTEN {
                    let Some(ft) = f.attributes.get(spalte) else {
                        continue;
                    };
                    let ft: i64 = ft.parse().unwrap();
                    if ft > 0 {
                        let diff = (ft - ts) / 10_000_000;
                        assert!((-600..=60).contains(&diff), "{name} {spalte} {diff}");
                        zeiten += 1;
                    }
                }
            }
        }
        assert_eq!(tabellen, 8);
        assert!(werte > 10_000, "{werte}");
        assert!(zeiten > 1_000, "{zeiten}");
        let summe = out
            .findings
            .iter()
            .find(|f| f.attributes.get("art").map(String::as_str) == Some("srum_db"))
            .unwrap();
        assert_eq!(summe.attributes["datensaetze"], "5064");
        assert_eq!(summe.attributes["id_eintraege"], "555");
    }
}
