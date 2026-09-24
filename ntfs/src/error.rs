//! Fehlertypen des NTFS-Zugriffs.

/// Fehler beim Zugriff auf ein NTFS-Volume.
#[derive(Debug, thiserror::Error)]
pub enum NtfsVolumeError {
    /// Der angegebene Bereich liegt außerhalb des Images.
    #[error("Partition [{offset}, +{size}) liegt außerhalb des Images ({image_size} Bytes)")]
    OutOfImage {
        /// Start der Partition im Image.
        offset: u64,
        /// Größe der Partition.
        size: u64,
        /// Größe des Images.
        image_size: u64,
    },

    /// Ein erwarteter Pfad zeigt auf ein Verzeichnis, nicht auf eine Datei.
    #[error("{path} ist ein Verzeichnis, keine Datei")]
    NotAFile {
        /// Der angefragte Pfad.
        path: String,
    },

    /// Ein erwarteter Pfad zeigt auf eine Datei, nicht auf ein Verzeichnis.
    #[error("{path} ist eine Datei, kein Verzeichnis")]
    NotADirectory {
        /// Der angefragte Pfad.
        path: String,
    },

    /// Fehler aus dem darunterliegenden NTFS-Parser.
    #[error(transparent)]
    Ntfs(#[from] ntfs::NtfsError),

    /// IO-Fehler beim Lesen der Datendaten.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
