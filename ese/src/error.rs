//! Fehlertypen.

/// Fehler beim Lesen einer ESE-Datenbank.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EseError {
    /// Die Datei ist kleiner als der Dateikopf.
    #[error("Datenbank zu klein: {0} Byte")]
    TooSmall(usize),
    /// Die Signatur 0x89abcdef fehlt.
    #[error("keine ESE-Signatur")]
    BadSignature,
    /// Die Seitengröße im Kopf ist keine der zulässigen Größen.
    #[error("unzulässige Seitengröße {0}")]
    BadPageSize(u32),
    /// Eine Seite liegt außerhalb der Datei.
    #[error("Seite {0} liegt außerhalb der Datei")]
    PageOutOfRange(u32),
    /// Kopf oder Tags einer Seite sind unstimmig.
    #[error("Seite {page}: {reason}")]
    BadPage {
        /// Seitennummer.
        page: u32,
        /// Beschreibung.
        reason: &'static str,
    },
    /// Der Systemkatalog ist nicht lesbar.
    #[error("Systemkatalog: {0}")]
    Catalog(String),
}
