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
use stratum_registry::Hive;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für die System-Masterkeys.
pub struct DpapiAnalyzer;

impl Analyzer for DpapiAnalyzer {
    fn dateibasiert(&self) -> bool {
        true
    }

    fn domain(&self) -> &str {
        "dpapi"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        let debug = std::env::var_os("STRATUM_DEBUG").is_some();
        let mut funde = Vec::new();
        durchlaufen(ctx, None, &mut out.warnings, |m| funde.push(m));
        for m in funde {
            let mut fd = Finding::new("dpapi", "System-Masterkey", &m.pfad)
                .with("art", "system_masterkey")
                .with("guid", &m.guid)
                .with(
                    "entschluesselt",
                    if m.masterkey.is_some() { "ja" } else { "nein" },
                )
                .with("volume_offset", m.volume_offset.to_string())
                .with("mft_record", m.mft_record.to_string());
            if let Some(o) = m.mft_record_offset {
                fd = fd.with("mft_record_offset", o.to_string());
            }
            if let Some(mk) = &m.masterkey {
                fd = fd
                    .with("schluessel", m.schluessel)
                    .with("entschluesselt_mit", m.entschluesselt_mit());
                if debug {
                    fd = fd.with("masterkey_hex", hex(mk));
                }
            } else {
                out.warnings.push(format!(
                    "{}: System-Masterkey nicht entschluesselbar",
                    m.pfad
                ));
            }
            let start = out.findings.len();
            out.findings.push(fd);
            out.tag_origin(start, &m.herkunft);
        }
        out
    }
}

/// Ein System-Masterkey mit Fundstelle und, falls gelungen, dem
/// entschlüsselten Schlüssel.
#[derive(Debug, Clone)]
pub struct SystemMasterkey {
    /// Pfad der Masterkey-Datei im Volume.
    pub pfad: String,
    /// GUID (Dateiname).
    pub guid: String,
    /// Herkunft (`live` oder Schattenkopie).
    pub herkunft: String,
    /// Volume-Offset im Image.
    pub volume_offset: u64,
    /// MFT-Nummer der Datei.
    pub mft_record: u64,
    /// Image-Offset des MFT-Datensatzes, falls bekannt.
    pub mft_record_offset: Option<u64>,
    /// Entschlüsselter Masterkey.
    pub masterkey: Option<Vec<u8>>,
    /// `benutzer` oder `maschine`: welcher Teil von `DPAPI_SYSTEM` passte.
    pub schluessel: &'static str,
}

impl SystemMasterkey {
    /// Klartext, womit entschlüsselt wurde.
    pub fn entschluesselt_mit(&self) -> &'static str {
        match self.schluessel {
            "benutzer" => "DPAPI_SYSTEM, Benutzerschlüssel (LSA-Secret)",
            "maschine" => "DPAPI_SYSTEM, Maschinenschlüssel (LSA-Secret)",
            _ => "",
        }
    }

    /// Masterkey als Hex.
    pub fn masterkey_hex(&self) -> Option<String> {
        self.masterkey.as_deref().map(hex)
    }
}

/// Entschlüsselt gezielt die System-Masterkeys mit dieser GUID, unabhängig
/// vom Debug-Modus. Für den Abruf eines einzelnen Schlüssels auf Anfrage.
pub fn masterkey_abrufen(
    ctx: &AnalysisContext<'_>,
    guid: &str,
    warnungen: &mut Vec<String>,
) -> Vec<SystemMasterkey> {
    let mut treffer = Vec::new();
    durchlaufen(ctx, Some(guid), warnungen, |m| treffer.push(m));
    treffer
}

/// Läuft über alle Installationen (live und Schattenkopien) und ihre
/// System-Masterkeys; mit `nur_guid` nur über diese eine Datei.
fn durchlaufen(
    ctx: &AnalysisContext<'_>,
    nur_guid: Option<&str>,
    warnungen: &mut Vec<String>,
    mut je: impl FnMut(SystemMasterkey),
) {
    for inst in ctx.installs.iter() {
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
                warnungen.push(format!("DPAPI: {e}"));
                continue;
            }
        };
        let Some(dpapi_system) = secrets.iter().find(|s| s.name == "DPAPI_SYSTEM") else {
            continue;
        };
        let (Some(machine), Some(user)) = (
            dpapi_system
                .value
                .get(4..24)
                .and_then(|b| <[u8; 20]>::try_from(b).ok()),
            dpapi_system
                .value
                .get(24..44)
                .and_then(|b| <[u8; 20]>::try_from(b).ok()),
        ) else {
            warnungen.push("DPAPI_SYSTEM zu kurz für Maschinen-/Benutzerschlüssel".into());
            continue;
        };

        // Passendes Volume über den Partitionsoffset finden.
        let Some(v) = ctx
            .volumes
            .iter()
            .find(|v| v.target.offset == inst.target.offset)
        else {
            continue;
        };
        let (mut vol, abbildung) = match ctx.open_volume(v) {
            Ok(x) => x,
            Err(e) => {
                warnungen.push(format!(
                    "DPAPI: Offset {} nicht lesbar: {e}",
                    v.target.offset
                ));
                continue;
            }
        };

        for e in v.files.iter().filter(|f| is_system_masterkey_path(&f.path)) {
            let guid = e.path.rsplit('\\').next().unwrap_or_default();
            if nur_guid.is_some_and(|g| !g.eq_ignore_ascii_case(guid)) {
                continue;
            }
            let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
                continue;
            };
            // Erst mit dem Benutzer-, dann mit dem Maschinenschlüssel.
            let (masterkey, schluessel) = match dpapi::decrypt_system_masterkey(&f.data, &user) {
                Ok(mk) => (Some(mk.to_vec()), "benutzer"),
                Err(_) => match dpapi::decrypt_system_masterkey(&f.data, &machine) {
                    Ok(mk) => (Some(mk.to_vec()), "maschine"),
                    Err(_) => (None, ""),
                },
            };
            je(SystemMasterkey {
                pfad: e.path.clone(),
                guid: guid.to_string(),
                herkunft: inst.origin.clone(),
                volume_offset: v.target.offset,
                mft_record: e.mft_record,
                mft_record_offset: f.meta.record_offset.and_then(|o| abbildung.image(o)),
                masterkey,
                schluessel,
            });
        }
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
