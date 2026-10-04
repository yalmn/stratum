//! Lokale Analysewerkzeuge als begrenzte Connectoren. Evidence wird nicht
//! an Prozesse gegeben; der Aufrufer stellt eine Arbeitskopie bereit.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod http_lab;
pub mod netzwerk;
mod prozess;
pub mod yara;

/// Fehler eines begrenzten Connectors.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorFehler {
    /// Werkzeug oder Arbeitskopie nicht lesbar.
    #[error("Connector: {0}")]
    Io(#[from] std::io::Error),
    /// Regel, Laufzeit oder Ausgabe nicht unterstützt.
    #[error("Connector: {0}")]
    Eingabe(String),
    /// Vom Auftraggeber abgebrochen.
    #[error("Connector abgebrochen")]
    Abgebrochen,
}
