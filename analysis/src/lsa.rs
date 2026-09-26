//! Domäne „LSA": entschlüsselte LSA-Secrets aus dem SECURITY-Hive.
//!
//! LSA-Secrets enthalten unter anderem Klartext-Passwörter von Dienst- und
//! Autologon-Konten, den DPAPI-Systemschlüssel und `NL$KM`. Die Entschlüsselung
//! liegt im `creds`-Crate; hier werden die Ergebnisse als Funde aufbereitet.
//!
//! Wie bei den SAM-Hashes gilt: gegen echte Hives (secretsdump.py) auf der VM
//! abschliessend verifizieren.

use stratum_creds::{extract_cached_logons, extract_lsa_secrets};
use stratum_registry::Hive;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für LSA-Secrets.
pub struct LsaAnalyzer;

impl Analyzer for LsaAnalyzer {
    fn domain(&self) -> &str {
        "lsa"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            let before = out.findings.len();
            let (Some(system), Some(security)) = (&inst.hives.system, &inst.hives.security) else {
                continue;
            };
            let (system, security) = match (Hive::parse(system), Hive::parse(security)) {
                (Ok(s), Ok(sec)) => (s, sec),
                (Err(e), _) => {
                    out.warnings
                        .push(format!("LSA: SYSTEM-Hive nicht lesbar: {e}"));
                    continue;
                }
                (_, Err(e)) => {
                    out.warnings
                        .push(format!("LSA: SECURITY-Hive nicht lesbar: {e}"));
                    continue;
                }
            };
            match extract_lsa_secrets(&system, &security) {
                Ok(secrets) => {
                    for s in secrets {
                        if s.value.is_empty() {
                            continue;
                        }
                        let (wert, art) = interpret(&s.value);
                        let mut f = Finding::new("lsa", &s.name, "SECURITY\\Policy\\Secrets")
                            .with("wert", wert)
                            .with("darstellung", art)
                            .with("laenge", s.value.len().to_string());
                        // DPAPI_SYSTEM: Version (4), Maschinen- und Benutzerschlüssel
                        // (je 20 Byte). Getrennt ausgeben, wie secretsdump es tut.
                        if s.name == "DPAPI_SYSTEM" && s.value.len() >= 44 {
                            f = f
                                .with("dpapi_machinekey", hex(&s.value[4..24]))
                                .with("dpapi_userkey", hex(&s.value[24..44]));
                        }
                        out.findings.push(f);
                    }
                }
                Err(e) => out.warnings.push(format!("LSA-Secrets: {e}")),
            }

            // Gecachte Domain-Logins (DCC2).
            match extract_cached_logons(&system, &security) {
                Ok(logons) => {
                    for l in logons {
                        out.findings.push(
                            Finding::new("lsa", l.username, "SECURITY\\Cache")
                                .with("art", "dcc2")
                                .with("dcc2_hash", l.dcc2_hex)
                                .with("hinweis", "DCC2, mit hashcat-Modus 2100 angreifbar"),
                        );
                    }
                }
                Err(e) => out.warnings.push(format!("DCC2: {e}")),
            }
            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

/// Obergrenze für die Hex-Darstellung eines Secrets. Übliche Secrets sind
/// deutlich kleiner; die Grenze schützt nur vor manipulierten Hives.
const MAX_HEX_BYTES: usize = 4096;

/// Stellt einen Secret-Wert dar: als UTF-16LE-Text, wenn er lesbar ist, sonst
/// vollständig als Hex.
fn interpret(value: &[u8]) -> (String, &'static str) {
    if let Some(text) = as_utf16_text(value) {
        return (text, "text");
    }
    (hex(&value[..value.len().min(MAX_HEX_BYTES)]), "hex")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn as_utf16_text(value: &[u8]) -> Option<String> {
    if value.len() < 2 || !value.len().is_multiple_of(2) {
        return None;
    }
    let mut units: Vec<u16> = value
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    // Eine Null mitten im Wert spricht für Binärdaten.
    if units.is_empty() || units.contains(&0) {
        return None;
    }
    let text = String::from_utf16(&units).ok()?;
    // Nur druckbares Latin (ASCII bis Latin Extended-A) zählt als Text.
    // Zufällige Bytes ergeben als UTF-16 meist CJK-Zeichen und würden sonst
    // fälschlich als lesbar gelten.
    let lesbar = text
        .chars()
        .all(|c| (' '..='\u{17f}').contains(&c) && !c.is_control());
    lesbar.then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_text_erkannt() {
        let v: Vec<u8> = "Passw0rt!"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let (wert, art) = interpret(&v);
        assert_eq!(art, "text");
        assert_eq!(wert, "Passw0rt!");
    }

    #[test]
    fn zufallsbytes_sind_kein_text() {
        // Frei gewählte Bytes, die als UTF-16 CJK-Zeichen ergeben.
        let v = [0x11, 0x4e, 0x2d, 0x5b, 0x88, 0x6c, 0x3a, 0x7a];
        assert_eq!(interpret(&v).1, "hex");
    }

    #[test]
    fn umlaute_und_nullende_als_text() {
        let mut v: Vec<u8> = "Kennwort-Österreich"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        v.extend_from_slice(&[0, 0]);
        assert_eq!(interpret(&v), ("Kennwort-Österreich".into(), "text"));
    }

    #[test]
    fn langer_wert_vollständig_als_hex() {
        let v = vec![0x98u8; 152];
        let (wert, art) = interpret(&v);
        assert_eq!(art, "hex");
        assert_eq!(wert.len(), 304);
    }

    #[test]
    fn binaer_als_hex() {
        // UTF-16-Units, die Steuerzeichen ergeben -> gilt nicht als Text.
        let v = vec![0x01, 0x00, 0x07, 0x00, 0x1b, 0x00];
        let (wert, art) = interpret(&v);
        assert_eq!(art, "hex");
        assert_eq!(wert, "010007001b00");
    }
}
