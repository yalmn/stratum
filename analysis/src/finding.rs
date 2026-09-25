//! Der einheitliche Fund-Typ über alle Domänen.

use std::collections::BTreeMap;

use serde::Serialize;

/// Ein einzelner Fund. Alle Domänen liefern denselben Typ, damit Report und
/// HTML-Ansicht eine gemeinsame Tabelle bilden können.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Domäne, aus der der Fund stammt (z. B. `"darknet"`, `"zugangsdaten"`).
    pub domain: String,
    /// Kurzbezeichnung des Funds (der Begriff, der Kontoname, ...).
    pub name: String,
    /// Quelle im Image: Dateipfad, falls bekannt, sonst ein Hinweis auf den
    /// rohen Bereich.
    pub source: String,
    /// Absoluter Byte-Offset im Image, falls zutreffend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Weitere Felder je nach Domäne (Kodierung, Kontext, RID, ...).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
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
