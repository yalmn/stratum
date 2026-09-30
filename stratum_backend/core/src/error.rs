//! Fehlertypen des Image-Layers.

use std::path::PathBuf;

/// Fehler beim Öffnen oder Lesen eines Images.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// Datei konnte nicht geöffnet oder gemappt werden.
    #[error("Image {path} konnte nicht geöffnet werden: {source}")]
    Open {
        /// Pfad des Images.
        path: PathBuf,
        /// Ursprünglicher IO-Fehler.
        #[source]
        source: std::io::Error,
    },

    /// Lesezugriff außerhalb des Images, z. B. weil ein Partitionseintrag
    /// über das Ende eines gekürzten Images hinauszeigt.
    #[error("Lesezugriff außerhalb des Images: offset={offset}, len={len}, image_size={size}")]
    OutOfBounds {
        /// Angefragter Start-Offset in Bytes.
        offset: u64,
        /// Angefragte Länge in Bytes.
        len: u64,
        /// Tatsächliche Imagegröße in Bytes.
        size: u64,
    },
}
