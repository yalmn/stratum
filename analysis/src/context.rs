//! Der gemeinsame, read-only Kontext für alle Analyzer.

use stratum_core::ImageReader;

/// Ein NTFS-Bereich, den die Analyzer untersuchen sollen.
#[derive(Debug, Clone, Copy)]
pub struct NtfsTarget {
    /// Index der Partition in der Tabelle, oder `u32::MAX` wenn per bdp.info
    /// vorgegeben.
    pub index: u32,
    /// Byte-Offset der Partition im Image.
    pub offset: u64,
    /// Länge der Partition in Bytes.
    pub size: u64,
}

/// Gemeinsamer Kontext eines Analyselaufs. Er hält nur geteilte, unveränderliche
/// Daten; veränderliche Zustände (z. B. der Lesecursor eines NTFS-Volumes) legt
/// jeder Analyzer für sich an.
pub struct AnalysisContext<'a> {
    /// Read-only Sicht auf das Image.
    pub img: &'a ImageReader,
    /// Als NTFS erkannte Bereiche.
    pub ntfs_targets: Vec<NtfsTarget>,
}

impl<'a> AnalysisContext<'a> {
    /// Baut einen Kontext aus Image und NTFS-Bereichen.
    pub fn new(img: &'a ImageReader, ntfs_targets: Vec<NtfsTarget>) -> Self {
        Self { img, ntfs_targets }
    }
}
