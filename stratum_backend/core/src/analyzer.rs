//! Plugin-Schnittstelle für Artefakt-Analysen.
//!
//! Neue Artefakte werden als eigene Implementierung von [`Analyzer`] in einem
//! separaten Crate umgesetzt, der Kern bleibt dabei unverändert.

use serde::Serialize;

use crate::error::ImageError;
use crate::image::ImageReader;

/// Ein einzelner Fund einer Analyse.
///
/// Jeder Fund muss auf seine Quelle im Image zurückführbar sein.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Name des Analyzers, der den Fund erzeugt hat.
    pub analyzer: String,
    /// Kategorie, z. B. `"registry"` oder `"browser-history"`.
    pub category: String,
    /// Quelle innerhalb des Images, z. B. ein Dateipfad im Dateisystem.
    pub source: String,
    /// Absoluter Byte-Offset im Image, an dem der Fund liegt.
    pub offset: u64,
    /// Kurzbeschreibung des Funds.
    pub summary: String,
}

/// Fehler eines Analyzers.
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    /// Fehler beim Lesen aus dem Image.
    #[error(transparent)]
    Image(#[from] ImageError),

    /// Analyzer-spezifischer Fehler.
    #[error("{0}")]
    Other(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Schnittstelle für alle Analysen.
///
/// `Send + Sync` ist gefordert, damit mehrere Analyzer parallel laufen können.
pub trait Analyzer: Send + Sync {
    /// Führt die Analyse auf dem Image aus.
    fn run(&self, img: &ImageReader) -> Result<Vec<Finding>, AnalyzerError>;
}
