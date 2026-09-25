//! Der gemeinsame, read-only Kontext für alle Analyzer.

use stratum_core::ImageReader;

use crate::windows::{extract_installs, WindowsInstall};

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
    /// Gefundene Windows-Installationen mit Grunddaten (Hives, Zeitzone,
    /// Rechnername, Konten). Wird von [`AnalysisContext::build`] gefüllt.
    pub installs: Vec<WindowsInstall>,
}

impl<'a> AnalysisContext<'a> {
    /// Kontext ohne Windows-Grunddaten (z. B. für die reine Keyword-Suche und
    /// für Tests).
    pub fn new(img: &'a ImageReader, ntfs_targets: Vec<NtfsTarget>) -> Self {
        Self {
            img,
            ntfs_targets,
            installs: Vec::new(),
        }
    }

    /// Baut den vollständigen Kontext auf: extrahiert je NTFS-Bereich die
    /// Registry-Hives und leitet Zeitzone, Rechnername und Konten ab. Diese
    /// teure Arbeit wird einmal geleistet und von allen Analyzern geteilt.
    pub fn build(img: &'a ImageReader, ntfs_targets: Vec<NtfsTarget>) -> Self {
        let installs = extract_installs(img, &ntfs_targets);
        Self {
            img,
            ntfs_targets,
            installs,
        }
    }
}
