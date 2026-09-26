//! Domäne „DPAPI": entschlüsselt die System-Masterkeys mit `DPAPI_SYSTEM`.
//!
//! System-Masterkeys liegen unter
//! `Windows\System32\Microsoft\Protect\S-1-5-18` und schützen maschinengebundene
//! DPAPI-Geheimnisse (Aufgabenplanung, WLAN, manche Dienst-Zugangsdaten). Sie
//! brauchen kein Benutzerpasswort: der Schlüssel steckt in `DPAPI_SYSTEM` aus
//! dem SECURITY-Hive, den stratum ohnehin ausliest.
//!
//! Der Nutzen ist doppelt. Erstens legt es die Grundlage für maschinengebundene
//! DPAPI-Daten. Zweitens läuft hier genau derselbe Masterkey-Parser und dieselbe
//! Krypto wie beim benutzergebundenen Pfad (Browser-Passwörter), nur mit einem
//! anderen Ausgangsschlüssel. Damit lässt sich die Masterkey-Entschlüsselung
//! ohne geknacktes Passwort byte-genau gegen ein unabhängiges Werkzeug (etwa
//! impacket) prüfen: mit gesetztem `STRATUM_DEBUG` gibt jeder Fund den
//! entschlüsselten Masterkey als Hex aus.

use stratum_creds::{dpapi, extract_lsa_secrets};
use stratum_ntfs::NtfsVolume;
use stratum_registry::Hive;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für die System-Masterkeys.
pub struct DpapiAnalyzer;

impl Analyzer for DpapiAnalyzer {
    fn domain(&self) -> &str {
        "dpapi"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        let debug = std::env::var_os("STRATUM_DEBUG").is_some();

        for inst in &ctx.installs {
            let before = out.findings.len();

            // DPAPI_SYSTEM aus den Hives holen: Maschinen- und Benutzerschlüssel.
            let (Some(system), Some(security)) = (&inst.hives.system, &inst.hives.security) else {
                continue;
            };
            let (Ok(system), Ok(security)) = (Hive::parse(system), Hive::parse(security)) else {
                continue;
            };
            let secrets = match extract_lsa_secrets(&system, &security) {
                Ok(s) => s,
                Err(e) => {
                    out.warnings.push(format!("DPAPI: {e}"));
                    continue;
                }
            };
            let Some(dpapi_system) = secrets.iter().find(|s| s.name == "DPAPI_SYSTEM") else {
                continue;
            };
            if dpapi_system.value.len() < 44 {
                out.warnings
                    .push("DPAPI_SYSTEM zu kurz für Maschinen-/Benutzerschlüssel".into());
                continue;
            }
            let machine: [u8; 20] = dpapi_system.value[4..24].try_into().unwrap();
            let user: [u8; 20] = dpapi_system.value[24..44].try_into().unwrap();

            // Passendes Volume über den Partitionsoffset finden.
            let Some(v) = ctx
                .volumes
                .iter()
                .find(|v| v.target.offset == inst.target.offset)
            else {
                continue;
            };
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings.push(format!(
                        "DPAPI: Offset {} nicht lesbar: {e}",
                        v.target.offset
                    ));
                    continue;
                }
            };

            for e in v.files.iter().filter(|f| is_system_masterkey_path(&f.path)) {
                let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
                    continue;
                };
                let guid = e.path.rsplit('\\').next().unwrap_or_default();

                // Erst mit dem Benutzer-, dann mit dem Maschinenschlüssel.
                let (mk, welcher) = match dpapi::decrypt_system_masterkey(&f.data, &user) {
                    Ok(mk) => (Some(mk), "benutzer"),
                    Err(_) => match dpapi::decrypt_system_masterkey(&f.data, &machine) {
                        Ok(mk) => (Some(mk), "maschine"),
                        Err(_) => (None, ""),
                    },
                };

                let mut fd = Finding::new("dpapi", "System-Masterkey", &e.path)
                    .with("art", "system_masterkey")
                    .with("guid", guid)
                    .with("entschluesselt", if mk.is_some() { "ja" } else { "nein" });
                if let Some(mk) = mk {
                    fd = fd.with("schluessel", welcher);
                    if debug {
                        fd = fd.with("masterkey_hex", hex(&mk));
                    }
                } else {
                    out.warnings.push(format!(
                        "{}: System-Masterkey nicht entschluesselbar",
                        e.path
                    ));
                }
                out.findings.push(fd);
            }

            out.tag_origin(before, &inst.origin);
        }
        out
    }
}

/// Pfad einer System-Masterkey-Datei unter `...\Protect\S-1-5-18` (auch der
/// Unterordner `User`), Dateiname ist eine GUID.
fn is_system_masterkey_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.contains("\\microsoft\\protect\\s-1-5-18") {
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
    b.iter().enumerate().all(|(i, &c)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            c == b'-'
        } else {
            c.is_ascii_hexdigit()
        }
    })
}

/// Bytes als Kleinschreib-Hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_masterkey_pfad_erkannt() {
        assert!(is_system_masterkey_path(
            "Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\\
             1f2e3d4c-5b6a-7089-90ab-cdef01234567"
        ));
        assert!(is_system_masterkey_path(
            "Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\\
             1f2e3d4c-5b6a-7089-90ab-cdef01234567"
        ));
        assert!(!is_system_masterkey_path(
            "Users\\ich\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-1-2-3-1001\\\
             1f2e3d4c-5b6a-7089-90ab-cdef01234567"
        ));
        assert!(!is_system_masterkey_path(
            "Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\Preferred"
        ));
    }

    #[test]
    fn hex_klein() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
