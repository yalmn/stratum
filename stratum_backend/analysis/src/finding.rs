//! Der einheitliche Fund-Typ über alle Domänen.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ein einzelner Fund (Rohfund). Alle Domänen liefern denselben Typ, damit
/// Report und HTML-Ansicht eine gemeinsame Tabelle bilden können. Im
/// Datenmodell ist er noch keine fachliche Bewertung, sondern Eingabe des
/// Normalizers (siehe [`RawFinding`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stabile, aus dem Inhalt abgeleitete Kennung (siehe [`assign_ids`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Domäne, aus der der Fund stammt (z. B. `"darknet"`, `"zugangsdaten"`).
    pub domain: String,
    /// Kurzbezeichnung des Funds (der Begriff, der Kontoname, ...).
    pub name: String,
    /// Quelle im Image: Dateipfad, falls bekannt, sonst ein Hinweis auf den
    /// rohen Bereich.
    pub source: String,
    /// Absoluter Byte-Offset im Image, falls zutreffend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Weitere Felder je nach Domäne (Kodierung, Kontext, RID, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl Finding {
    /// Neuer Fund mit Domäne, Name und Quelle.
    pub fn new(
        domain: impl Into<String>,
        name: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: String::new(),
            domain: domain.into(),
            name: name.into(),
            source: source.into(),
            offset: None,
            attributes: BTreeMap::new(),
        }
    }

    /// Setzt den Byte-Offset.
    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Fügt ein Attribut hinzu.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// Name des Funds im Sinn des Datenmodells: ein Rohfund, den der Normalizer
/// auf Artefakte, Observationen, Entitäten, Ereignisse und Beziehungen abbildet.
pub type RawFinding = Finding;

/// Vergibt jedem Fund eine aus seinem Inhalt abgeleitete Kennung: die ersten
/// 16 Hexzeichen von SHA-256 über Domäne, Name, Quelle, Offset und Attribute.
/// Dasselbe Image ergibt so in jedem Lauf dieselben Kennungen, unabhängig von
/// der Position im Report. Inhaltsgleiche Funde erhalten in der Reihenfolge
/// ihres Auftretens die Zusätze `-2`, `-3` usw.
pub fn assign_ids(findings: &mut [Finding]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in findings {
        let mut h = Sha256::new();
        let mut feld = |bytes: &[u8]| {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        };
        feld(f.domain.as_bytes());
        feld(f.name.as_bytes());
        feld(f.source.as_bytes());
        match f.offset {
            Some(offset) => feld(&offset.to_le_bytes()),
            None => feld(&[]),
        }
        for (key, value) in &f.attributes {
            feld(key.as_bytes());
            feld(value.as_bytes());
        }
        let digest = h.finalize();
        let base: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        let n = seen.entry(base.clone()).or_insert(0);
        *n += 1;
        f.id = if *n == 1 { base } else { format!("{base}-{n}") };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kennungen_sind_stabil_und_eindeutig() {
        let a = Finding::new("usb", "Stick", "SYSTEM")
            .at(4096)
            .with("serie", "1");
        let b = Finding::new("usb", "Stick", "SYSTEM")
            .at(4096)
            .with("serie", "2");
        let mut erste = vec![a.clone(), b.clone(), a.clone()];
        assign_ids(&mut erste);
        assert_eq!(erste[0].id.len(), 16);
        assert_ne!(erste[0].id, erste[1].id);
        assert_eq!(erste[2].id, format!("{}-2", erste[0].id));
        // Unabhängig von der Position im Report.
        let mut zweite = vec![b, a];
        assign_ids(&mut zweite);
        assert_eq!(zweite[0].id, erste[1].id);
        assert_eq!(zweite[1].id, erste[0].id);
        // Feldgrenzen sind eindeutig: "ab"+"c" ist nicht "a"+"bc".
        let mut x = vec![Finding::new("d", "ab", "c"), Finding::new("d", "a", "bc")];
        assign_ids(&mut x);
        assert_ne!(x[0].id, x[1].id);
    }
}
