//! Der gemeinsame, read-only Kontext für alle Analyzer.

use stratum_core::ImageReader;

use crate::fsindex::FsIndex;
use crate::windows::{extract_installs, extract_snapshots, WindowsInstall};

/// Vom Untersucher übergebenes Geheimnis, um benutzergebundene DPAPI-Daten
/// (gespeicherte Browser-Passwörter) zu entschlüsseln. Ohne Angabe bleibt es
/// bei der reinen Bestandsaufnahme (Anzahl verschlüsselter Einträge).
#[derive(Debug, Clone)]
pub enum DpapiInput {
    /// Klartextpasswort des Benutzers; der SHA-1 wird selbst gebildet.
    Password(String),
    /// Bereits gebildeter SHA-1 des Passworts (UTF-16LE).
    Sha1([u8; 20]),
    /// Ein bereits entschlüsselter DPAPI-Masterkey (64 Byte).
    Masterkey([u8; 64]),
}

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
    /// Pfad-Index je NTFS-Bereich, den die Analyzer abfragen. Wird von
    /// [`AnalysisContext::build`] gefüllt.
    pub volumes: Vec<FsIndex>,
    /// Auffälligkeiten aus dem Kontext-Aufbau (z. B. nicht indizierbare Bereiche).
    pub warnings: Vec<String>,
    /// Optionales Geheimnis zum Entschlüsseln benutzergebundener DPAPI-Daten.
    pub dpapi: Option<DpapiInput>,
    /// Firefox-Hauptpasswort (leer, falls keins gesetzt ist).
    pub firefox_password: Option<String>,
}

impl<'a> AnalysisContext<'a> {
    /// Kontext ohne Windows-Grunddaten (z. B. für die reine Keyword-Suche und
    /// für Tests).
    pub fn new(img: &'a ImageReader, ntfs_targets: Vec<NtfsTarget>) -> Self {
        Self {
            img,
            ntfs_targets,
            installs: Vec::new(),
            volumes: Vec::new(),
            warnings: Vec::new(),
            dpapi: None,
            firefox_password: None,
        }
    }

    /// Baut den vollständigen Kontext auf: legt je NTFS-Bereich den Pfad-Index an
    /// und extrahiert die Registry-Hives (Zeitzone, Rechnername, Konten). Diese
    /// teure Arbeit wird einmal geleistet und von allen Analyzern geteilt.
    pub fn build(img: &'a ImageReader, ntfs_targets: Vec<NtfsTarget>) -> Self {
        let mut installs = extract_installs(img, &ntfs_targets);
        // Frühere Zustände aus Volume Shadow Copies ergänzen; registry-basierte
        // Analyzer werten sie automatisch mit aus.
        installs.extend(extract_snapshots(img, &ntfs_targets));

        let mut volumes = Vec::new();
        let mut warnings = Vec::new();
        for &target in &ntfs_targets {
            match FsIndex::build(img, target) {
                Ok(idx) => volumes.push(idx),
                Err(e) => warnings.push(format!(
                    "Pfad-Index für Offset {} nicht erstellbar: {e}",
                    target.offset
                )),
            }
        }

        Self {
            img,
            ntfs_targets,
            installs,
            volumes,
            warnings,
            dpapi: None,
            firefox_password: None,
        }
    }
}
