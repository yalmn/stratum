//! Fehlertypen des NTFS-Zugriffs.

/// Fehler beim Zugriff auf ein NTFS-Volume.
#[derive(Debug, thiserror::Error)]
pub enum NtfsVolumeError {
    /// Der unbenannte Datenstrom der Master File Table fehlt.
    #[error("$MFT hat keinen unbenannten $DATA-Strom")]
    MissingMftData,

    /// Die logische MFT-Größe ist kein Vielfaches der Datensatzgröße.
    #[error("$MFT-Größe {size} ist kein Vielfaches der Datensatzgröße {record_size}")]
    InvalidMftSize {
        /// Logische Größe des `$MFT`-Datenstroms.
        size: u64,
        /// Datensatzgröße aus dem NTFS-Bootsektor.
        record_size: u32,
    },

    /// Die MFT behauptet mehr Datensätze, als sicher verarbeitet werden können.
    #[error("$MFT enthält laut Datenstrom {records} Datensätze, maximal zulässig sind {maximum}")]
    ImplausibleMftRecordCount {
        /// Aus der logischen MFT-Größe abgeleitete Anzahl.
        records: u64,
        /// Aus Partitionsgröße und Schutzgrenze abgeleitete Obergrenze.
        maximum: u64,
    },

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

    /// Fehler beim Lesen einer vom System komprimierten Datei (WOF).
    #[error(transparent)]
    Wof(#[from] crate::wof::WofError),

    /// Fehler beim Entpacken eines NTFS-komprimierten (LZNT1) Datenstroms.
    #[error("LZNT1-Dekompression fehlgeschlagen: {0}")]
    Lznt1(#[from] crate::lznt1::Lznt1Error),
}
