//! Fehlertypen.

/// Fehler beim Lesen von Schattenkopien.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VssError {
    /// Eine Struktur liegt außerhalb der Daten (verkürztes Image).
    #[error("Offset {0:#x} liegt außerhalb der Daten")]
    Truncated(u64),
    /// Ein Offset liegt außerhalb des Snapshots oder ist nicht darstellbar.
    #[error("Offset {0:#x} außerhalb des gültigen Bereichs")]
    OutOfRange(u64),
    /// Kennung oder Satztyp eines Blocks passen nicht.
    #[error("Block bei {offset:#x}: {reason}")]
    BadBlock {
        /// Offset des Blocks im Volume.
        offset: u64,
        /// Beschreibung.
        reason: &'static str,
    },
    /// Eine Blockkette verweist auf sich selbst oder ist zu lang.
    #[error("Schleife oder zu lange Kette bei {0:#x}")]
    Loop(u64),
    /// Es gibt keinen Store mit diesem Index.
    #[error("kein Store {0}")]
    NoStore(usize),
    /// Der Store hat keine Daten im Volume.
    #[error("Store {0} hat keine Daten im Volume")]
    NoStoreData(usize),
}
