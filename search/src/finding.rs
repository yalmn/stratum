//! Ergebnisse der Suche.

use serde::Serialize;

/// Kodierung, in der ein Begriff im Image stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// Ein Byte je Zeichen (ASCII bzw. Latin-1).
    Ascii,
    /// Zwei Byte je Zeichen, Little Endian (Windows-Unicode).
    Utf16Le,
}

impl Encoding {
    /// Zahl der Bytes je Zeichen.
    pub fn width(self) -> usize {
        match self {
            Encoding::Ascii => 1,
            Encoding::Utf16Le => 2,
        }
    }
}

/// Art eines Treffers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "art", rename_all = "lowercase")]
pub enum FindingKind {
    /// Ein einzelner Begriff.
    Term {
        /// Der gefundene Begriff.
        begriff: String,
    },
    /// Ein Paar aus einem linken und einem rechten Begriff, z. B. ein
    /// Benutzername-Feld und ein Passwort-Feld in geringem Abstand.
    Paar {
        /// Begriff der linken Seite.
        links: String,
        /// Begriff der rechten Seite.
        rechts: String,
        /// Byte-Abstand zwischen den beiden Fundstellen.
        abstand: u64,
    },
}

/// Ein einzelner Treffer der Suche.
///
/// `offset` ist der absolute Byte-Offset im Image. Damit ist jeder Fund auf
/// seine Quelle zurückführbar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Kategorie aus der Begriffstabelle.
    pub kategorie: String,
    /// Art und Inhalt des Treffers.
    #[serde(flatten)]
    pub kind: FindingKind,
    /// Kodierung der Fundstelle.
    pub kodierung: Encoding,
    /// Absoluter Byte-Offset im Image.
    pub offset: u64,
    /// Lesbarer Ausschnitt um die Fundstelle.
    pub kontext: String,
}
