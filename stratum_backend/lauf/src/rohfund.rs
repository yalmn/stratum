//! Einzelnen Rohfund aus einem Report lesen und nachprüfen.
//!
//! Artefakte im Modell verweisen nur mit der Fundkennung auf den Rohfund im
//! Report (`raw_metadata.rohfund_id`). Die Kennung ist ein Inhaltshash; sie
//! wird nach dem Lesen nachgerechnet. Ist der erwartete SHA-256 des Reports
//! bekannt (aus der Datenbank), wird zuerst die ganze Datei dagegen geprüft.
//!
//! Die Fundliste wird beim Lesen durchlaufen, ohne den Report als Baum im
//! Speicher aufzubauen; behalten wird nur der gesuchte Fund.

use std::fmt;
use std::path::Path;

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use stratum_analysis::{assign_ids, Finding};

/// Warum ein Rohfund nicht geliefert werden kann.
#[derive(Debug, thiserror::Error)]
pub enum RohfundFehler {
    /// Datei fehlt oder ist nicht lesbar.
    #[error("Report nicht lesbar: {pfad}: {quelle}")]
    Lesen {
        /// Pfad des Reports.
        pfad: String,
        /// Ursache.
        #[source]
        quelle: std::io::Error,
    },
    /// Der Report hat nicht mehr den erwarteten SHA-256.
    #[error("Report verändert: SHA-256 {ist} statt {erwartet}")]
    Hash {
        /// Gespeicherter Wert.
        erwartet: String,
        /// Nachgerechneter Wert.
        ist: String,
    },
    /// Kein gültiges JSON oder keine lesbare Fundliste.
    #[error("Report nicht auswertbar: {0}")]
    Format(#[from] serde_json::Error),
    /// Kein Fund mit dieser Kennung im Report.
    #[error("kein Fund mit Kennung {0} im Report")]
    NichtImReport(String),
    /// Die Kennung passt nicht zum Inhalt des Funds.
    #[error("Kennung {id} passt nicht zum Inhalt (nachgerechnet {nachgerechnet})")]
    Kennung {
        /// Gesuchte Kennung.
        id: String,
        /// Aus dem Inhalt berechnet.
        nachgerechnet: String,
    },
}

impl RohfundFehler {
    /// Report oder Fund passen nicht mehr zu ihrem Hash.
    pub fn integritaet(&self) -> bool {
        matches!(
            self,
            RohfundFehler::Hash { .. } | RohfundFehler::Kennung { .. }
        )
    }
}

/// Gelesener Rohfund mit dem SHA-256 des Reports, aus dem er stammt.
#[derive(Debug)]
pub struct Rohfund {
    /// Der Fund, wie er im Report steht.
    pub fund: Finding,
    /// SHA-256 der Report-Datei.
    pub report_sha256: String,
}

/// Liest den Fund mit Kennung `id` aus dem Report. Mit `erwartet` muss der
/// SHA-256 der Datei diesem Wert entsprechen.
pub fn lesen(report: &Path, id: &str, erwartet: Option<&str>) -> Result<Rohfund, RohfundFehler> {
    let bytes = std::fs::read(report).map_err(|quelle| RohfundFehler::Lesen {
        pfad: report.display().to_string(),
        quelle,
    })?;
    let report_sha256 = sha256_hex(&bytes);
    if let Some(e) = erwartet {
        if !e.eq_ignore_ascii_case(&report_sha256) {
            return Err(RohfundFehler::Hash {
                erwartet: e.to_string(),
                ist: report_sha256,
            });
        }
    }
    let mut de = serde_json::Deserializer::from_slice(&bytes);
    let fund = Suche { id }
        .deserialize(&mut de)?
        .ok_or_else(|| RohfundFehler::NichtImReport(id.to_string()))?;
    de.end()?;
    // Inhaltsgleiche Funde tragen `-2`, `-3`, …; verglichen wird der Hash.
    let mut nach = [Finding {
        id: String::new(),
        ..fund.clone()
    }];
    assign_ids(&mut nach);
    let basis = id.split('-').next().unwrap_or(id);
    if nach[0].id != basis {
        return Err(RohfundFehler::Kennung {
            id: id.to_string(),
            nachgerechnet: std::mem::take(&mut nach[0].id),
        });
    }
    Ok(Rohfund {
        fund,
        report_sha256,
    })
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Oberste Ebene des Reports: nur `findings` wird angesehen.
struct Suche<'a> {
    id: &'a str,
}

impl<'de> DeserializeSeed<'de> for Suche<'_> {
    type Value = Option<Finding>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Suche<'_> {
    type Value = Option<Finding>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("einen Report als JSON-Objekt")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
        let mut gefunden = None;
        while let Some(k) = m.next_key::<std::borrow::Cow<'de, str>>()? {
            if k == "findings" && gefunden.is_none() {
                gefunden = m.next_value_seed(Liste { id: self.id })?;
            } else {
                m.next_value::<IgnoredAny>()?;
            }
        }
        Ok(gefunden)
    }
}

/// Die Fundliste: jeder Fund wird gelesen, nur der gesuchte behalten.
struct Liste<'a> {
    id: &'a str,
}

impl<'de> DeserializeSeed<'de> for Liste<'_> {
    type Value = Option<Finding>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Liste<'_> {
    type Value = Option<Finding>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("eine Liste von Funden")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
        let mut gefunden = None;
        while let Some(f) = s.next_element::<Finding>()? {
            if gefunden.is_none() && f.id == self.id {
                gefunden = Some(f);
            }
        }
        Ok(gefunden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(dir: &Path, funde: &[Finding]) -> std::path::PathBuf {
        let p = dir.join("report.json");
        let v = serde_json::json!({"version": 1, "findings": funde, "timeline": []});
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        p
    }

    fn funde() -> Vec<Finding> {
        let mut f = vec![
            Finding::new("usb", "Stick", "SYSTEM").with("seriennummer", "123"),
            Finding::new("lsa", "_SC_Dienst", "SECURITY").with("wert", "geheim"),
            Finding::new("usb", "Stick", "SYSTEM").with("seriennummer", "123"),
        ];
        assign_ids(&mut f);
        f
    }

    #[test]
    fn fund_mit_hash_und_kennung() {
        let d = tempfile::tempdir().unwrap();
        let f = funde();
        let p = report(d.path(), &f);
        let sha = sha256_hex(&std::fs::read(&p).unwrap());
        let r = lesen(&p, &f[1].id, Some(&sha.to_uppercase())).unwrap();
        assert_eq!(r.fund.attributes["wert"], "geheim");
        assert_eq!(r.report_sha256, sha);
        // Inhaltsgleicher zweiter Fund mit Zusatz.
        let r = lesen(&p, &f[2].id, None).unwrap();
        assert!(f[2].id.ends_with("-2"));
        assert_eq!(r.fund.id, f[2].id);
        assert!(matches!(
            lesen(&p, "0000000000000000", None),
            Err(RohfundFehler::NichtImReport(_))
        ));
        assert!(matches!(
            lesen(&p, &f[0].id, Some("00")),
            Err(RohfundFehler::Hash { .. })
        ));
        assert!(matches!(
            lesen(&d.path().join("fehlt.json"), &f[0].id, None),
            Err(RohfundFehler::Lesen { .. })
        ));
    }

    #[test]
    fn veraenderter_fund_faellt_auf() {
        let d = tempfile::tempdir().unwrap();
        let mut f = funde();
        f[1].attributes.insert("wert".into(), "anders".into());
        let p = report(d.path(), &f);
        assert!(matches!(
            lesen(&p, &f[1].id, None),
            Err(RohfundFehler::Kennung { .. })
        ));
        std::fs::write(&p, b"{\"findings\": [").unwrap();
        assert!(matches!(
            lesen(&p, &f[1].id, None),
            Err(RohfundFehler::Format(_))
        ));
    }
}
