//! Die Begriffstabelle, die pro Fall gepflegt wird.

use serde::{Deserialize, Serialize};

/// Fehler beim Laden einer Begriffstabelle.
#[derive(Debug, thiserror::Error)]
pub enum TermTableError {
    /// Die TOML-Datei konnte nicht gelesen werden.
    #[error("Begriffstabelle nicht lesbar: {0}")]
    Read(#[from] std::io::Error),

    /// Die TOML-Datei ist syntaktisch oder strukturell fehlerhaft.
    #[error("Begriffstabelle fehlerhaft: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Standardabstand zwischen zwei Begriffen eines Paares, in Bytes.
pub const DEFAULT_ABSTAND: u64 = 128;
/// Obergrenze für die Zahl der Treffer, ab der abgeschnitten wird.
pub const DEFAULT_MAX_TREFFER: usize = 100_000;
/// Standard-Obergrenze für die Treffer einer einzelnen Kategorie.
pub const DEFAULT_KAT_MAX: usize = 20_000;

/// Eine komplette Begriffstabelle, üblicherweise aus einer TOML-Datei.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TermTable {
    /// Angaben zum Fall.
    pub meta: Meta,
    /// Die Suchkategorien.
    #[serde(default, rename = "kategorie")]
    pub categories: Vec<Category>,
}

/// Kopfdaten der Tabelle.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Meta {
    /// Bezeichnung, z. B. die Fallnummer.
    pub name: String,
    /// Version der Tabelle, damit im Report klar ist, welcher Stand lief.
    #[serde(default)]
    pub version: u32,
    /// Obergrenze für die Gesamtzahl der Treffer.
    #[serde(default = "default_max")]
    pub max_treffer: usize,
}

fn default_max() -> usize {
    DEFAULT_MAX_TREFFER
}

/// Suchmodus einer Kategorie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Modus {
    /// Jeder gefundene Begriff ist ein Treffer.
    #[default]
    Einfach,
    /// Ein Treffer entsteht nur aus einem Begriff der linken und einem der
    /// rechten Seite in geringem Abstand.
    Paar,
}

/// Eine Suchkategorie.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Category {
    /// Kennung, erscheint im Report (z. B. `"zugangsdaten"`, `"darknet"`).
    pub id: String,
    /// Ob die Kategorie durchsucht wird.
    #[serde(default = "default_true")]
    pub aktiv: bool,
    /// Suchmodus.
    #[serde(default)]
    pub modus: Modus,
    /// Begriffe im Modus [`Modus::Einfach`].
    #[serde(default)]
    pub begriffe: Vec<String>,
    /// Linke Seite im Modus [`Modus::Paar`], z. B. Benutzername-Felder.
    #[serde(default)]
    pub links: Vec<String>,
    /// Rechte Seite im Modus [`Modus::Paar`], z. B. Passwort-Felder.
    #[serde(default)]
    pub rechts: Vec<String>,
    /// Höchstabstand zwischen linkem und rechtem Begriff eines Paares, in Bytes.
    #[serde(default = "default_abstand")]
    pub abstand_bytes: u64,
    /// Wenn gesetzt, wird bei einem Treffer auf `.onion` geprüft, ob eine
    /// gültige v3-Onion-Adresse davorsteht. Nur passende Adressen werden
    /// gemeldet.
    #[serde(default)]
    pub onion_pruefung: bool,
    /// Nur ganze Wörter treffen: ein Begriff zählt nur, wenn er nicht in einem
    /// längeren Wort steckt (`rat` nicht in `operator`). Standard: an.
    #[serde(default = "default_true")]
    pub ganzes_wort: bool,
    /// Nur Treffer melden, die in einem zusammenhängenden Stück lesbaren Textes
    /// liegen. Filtert Zufallstreffer in Binärdaten (z. B. Programmcode).
    /// Standard: an.
    #[serde(default = "default_true")]
    pub nur_text: bool,
    /// Obergrenze für die Treffer dieser Kategorie. Verhindert, dass eine laute
    /// Kategorie die Suche für alle anderen abbricht.
    #[serde(default = "default_kat_max")]
    pub max_treffer: usize,
}

fn default_true() -> bool {
    true
}

fn default_abstand() -> u64 {
    DEFAULT_ABSTAND
}

fn default_kat_max() -> usize {
    DEFAULT_KAT_MAX
}

impl TermTable {
    /// Lädt eine Tabelle aus einer TOML-Datei.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, TermTableError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_str(&text)
    }

    /// Liest eine Tabelle aus einem TOML-String.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Self, TermTableError> {
        Ok(toml::from_str(text)?)
    }

    /// Die aktiven Kategorien.
    pub fn active(&self) -> impl Iterator<Item = &Category> {
        self.categories.iter().filter(|c| c.aktiv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabelle_laden() {
        let t = TermTable::from_str(
            r#"
            [meta]
            name = "Fall 1"
            version = 2

            [[kategorie]]
            id = "zugangsdaten"
            modus = "paar"
            links = ["user", "benutzer"]
            rechts = ["pw", "passwort"]
            abstand_bytes = 64

            [[kategorie]]
            id = "darknet"
            begriffe = [".onion", "torrc"]
            onion_pruefung = true

            [[kategorie]]
            id = "aus"
            aktiv = false
            begriffe = ["x"]
            "#,
        )
        .unwrap();

        assert_eq!(t.meta.name, "Fall 1");
        assert_eq!(t.meta.version, 2);
        assert_eq!(t.meta.max_treffer, DEFAULT_MAX_TREFFER);
        assert_eq!(t.categories.len(), 3);
        assert_eq!(t.active().count(), 2);

        let cred = &t.categories[0];
        assert_eq!(cred.modus, Modus::Paar);
        assert_eq!(cred.abstand_bytes, 64);
        assert_eq!(cred.links, ["user", "benutzer"]);

        let dark = &t.categories[1];
        assert_eq!(dark.modus, Modus::Einfach);
        assert!(dark.onion_pruefung);
        assert_eq!(dark.abstand_bytes, DEFAULT_ABSTAND);
    }

    #[test]
    fn fehlerhafte_tabelle() {
        assert!(TermTable::from_str("kein gültiges toml [[[").is_err());
        assert!(TermTable::from_str("[meta]\nversion = 1").is_err());
    }
}
