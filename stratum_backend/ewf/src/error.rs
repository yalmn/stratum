//! Fehlertypen.

use std::path::PathBuf;

/// Fehler beim Lesen eines Expert-Witness-Images.
#[derive(Debug, thiserror::Error)]
pub enum EwfError {
    /// Eine Segmentdatei ließ sich nicht öffnen.
    #[error("Segment {path}: {source}")]
    Open {
        /// Pfad der Segmentdatei.
        path: PathBuf,
        /// Ursache.
        source: std::io::Error,
    },
    /// Signatur oder Segmentnummer im Dateikopf passen nicht.
    #[error("Segment {segment}: {reason}")]
    BadHeader {
        /// Segmentnummer (ab 1).
        segment: usize,
        /// Beschreibung.
        reason: String,
    },
    /// Format wird nicht unterstützt (etwa EWF2/Ex01 oder L01).
    #[error("nicht unterstütztes Format: {0}")]
    Unsupported(String),
    /// Eine Sektion ist beschädigt oder unstimmig.
    #[error("Segment {segment}, Offset {offset:#x}: {reason}")]
    BadSection {
        /// Segmentnummer (ab 1).
        segment: usize,
        /// Offset in der Segmentdatei.
        offset: u64,
        /// Beschreibung.
        reason: String,
    },
    /// Ein Chunk ist nicht lesbar (Prüfsumme, Kompression, fehlendes Segment).
    #[error("Chunk {index}: {reason}")]
    BadChunk {
        /// Chunknummer (ab 0).
        index: u64,
        /// Beschreibung.
        reason: String,
    },
    /// Lesebereich außerhalb der Mediengröße.
    #[error("Bereich ab {offset:#x} mit {len} Byte außerhalb der Mediengröße {size}")]
    OutOfRange {
        /// Gewünschter Offset.
        offset: u64,
        /// Gewünschte Länge.
        len: u64,
        /// Mediengröße.
        size: u64,
    },
}
