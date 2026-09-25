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
                _ => continue,
            };
            match extract_lsa_secrets(&system, &security) {
                Ok(secrets) => {
                    for s in secrets {
                        if s.value.is_empty() {
                            continue;
                        }
                        let (wert, art) = interpret(&s.value);
                        out.findings.push(
                            Finding::new("lsa", s.name, "SECURITY\\Policy\\Secrets")
                                .with("wert", wert)
                                .with("darstellung", art),
                        );
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

/// Stellt einen Secret-Wert dar: als UTF-16LE-Text, wenn er überwiegend lesbar
/// ist, sonst als Hex (auf 64 Byte begrenzt).
fn interpret(value: &[u8]) -> (String, &'static str) {
    if let Some(text) = as_utf16_text(value) {
        return (text, "text");
    }
    let hex: String = value.iter().take(64).map(|b| format!("{b:02x}")).collect();
    (hex, "hex")
}

fn as_utf16_text(value: &[u8]) -> Option<String> {
    if value.len() < 2 || !value.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = value
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    let text = String::from_utf16_lossy(&units);
    let printable = text.chars().filter(|c| !c.is_control()).count();
    // Mindestens drei Viertel druckbar, damit Binaerdaten nicht als Text gelten.
    if printable * 4 >= text.chars().count() * 3 && !text.is_empty() {
        Some(text)
    } else {
        None
    }
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
    fn binaer_als_hex() {
        // UTF-16-Units, die Steuerzeichen ergeben -> gilt nicht als Text.
        let v = vec![0x01, 0x00, 0x07, 0x00, 0x1b, 0x00];
        let (wert, art) = interpret(&v);
        assert_eq!(art, "hex");
        assert_eq!(wert, "010007001b00");
    }
}
