//! Der gemeinsame, read-only Kontext für alle Analyzer.

use std::sync::Arc;

use stratum_core::ImageReader;
use stratum_ntfs::{NtfsVolume, NtfsVolumeError};

use crate::fsindex::{FsIndex, Herkunft};
use crate::schatten::{self, Abbildung, Abweichung, Schatten, VolumeReader};
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
    /// Rechnername, Konten). Wird von [`AnalysisContext::build`] gefüllt und
    /// mit den Snapshot-Kontexten geteilt.
    pub installs: Arc<Vec<WindowsInstall>>,
    /// Pfad-Index je NTFS-Bereich, den die Analyzer abfragen. Wird von
    /// [`AnalysisContext::build`] gefüllt. In einem Snapshot-Kontext nur die
    /// vom Live-Stand abweichenden Dateien dieses Snapshots.
    pub volumes: Vec<FsIndex>,
    /// Schattenkopien je NTFS-Bereich.
    pub schatten: Arc<Vec<Schatten<'a>>>,
    /// Differenz-Indizes aller Snapshots (Herkunft Snapshot).
    pub snapshot_volumes: Vec<FsIndex>,
    /// Dateien, die in einem Snapshot vom Live-Stand abweichen.
    pub abweichungen: Arc<Vec<Abweichung>>,
    /// Je Snapshot: Volume-Offset, Store-Index, Zahl der Dateien.
    pub snapshot_dateien: Vec<(u64, usize, usize)>,
    /// Auffälligkeiten aus dem Kontext-Aufbau (z. B. nicht indizierbare Bereiche).
    pub warnings: Vec<String>,
    /// Optionales Geheimnis zum Entschlüsseln benutzergebundener DPAPI-Daten.
    pub dpapi: Option<DpapiInput>,
    /// Firefox-Hauptpasswort (leer, falls keins gesetzt ist).
    pub firefox_password: Option<String>,
}

impl<'a> AnalysisContext<'a> {
    /// ANSI-Codepage der Windows-Installation auf dem Volume bei `offset`
    /// (Live-System, nicht Schattenkopie), falls bekannt.
    pub fn ansi_codepage(&self, offset: u64) -> Option<&str> {
        self.installs
            .iter()
            .find(|i| i.target.offset == offset && i.origin == "live")
            .and_then(|i| i.ansi_codepage.as_deref())
    }

    /// Kontext ohne Windows-Grunddaten (z. B. für die reine Keyword-Suche und
    /// für Tests).
    pub fn new(img: &'a ImageReader, ntfs_targets: Vec<NtfsTarget>) -> Self {
        Self {
            img,
            ntfs_targets,
            installs: Arc::new(Vec::new()),
            volumes: Vec::new(),
            schatten: Arc::new(Vec::new()),
            snapshot_volumes: Vec::new(),
            abweichungen: Arc::new(Vec::new()),
            snapshot_dateien: Vec::new(),
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
                Ok(idx) => {
                    warnings.extend(
                        idx.warnings
                            .iter()
                            .map(|w| format!("Pfad-Index Offset {}: {w}", target.offset)),
                    );
                    volumes.push(idx);
                }
                Err(e) => warnings.push(format!(
                    "Pfad-Index für Offset {} nicht erstellbar: {e}",
                    target.offset
                )),
            }
        }

        // Schattenkopien: je Snapshot die vom Live-Stand abweichenden Dateien.
        let mut schatten_liste = Vec::new();
        let mut snapshot_volumes = Vec::new();
        let mut abweichungen = Vec::new();
        let mut snapshot_dateien = Vec::new();
        for &target in &ntfs_targets {
            let Some(bereich) = schatten::ImageBereich::new(img, target) else {
                continue;
            };
            let vss = match stratum_vss::Volume::open(bereich) {
                Ok(Some(v)) if v.store_count() > 0 => v,
                Ok(_) => continue,
                Err(e) => {
                    warnings.push(format!(
                        "Schattenkopien Offset {} nicht lesbar: {e}",
                        target.offset
                    ));
                    continue;
                }
            };
            let s = Schatten { target, vss };
            if let Some(live) = volumes
                .iter()
                .find(|v: &&FsIndex| v.target.offset == target.offset)
            {
                for vergleich in schatten::vergleichen(img, &s, live) {
                    if let Herkunft::Snapshot { store, .. } = vergleich.index.herkunft {
                        snapshot_dateien.push((target.offset, store, vergleich.dateien));
                    }
                    warnings.extend(vergleich.warnungen);
                    abweichungen.extend(vergleich.abweichungen);
                    snapshot_volumes.push(vergleich.index);
                }
            }
            schatten_liste.push(s);
        }

        Self {
            img,
            ntfs_targets,
            installs: Arc::new(installs),
            volumes,
            schatten: Arc::new(schatten_liste),
            snapshot_volumes,
            abweichungen: Arc::new(abweichungen),
            snapshot_dateien,
            warnings,
            dpapi: None,
            firefox_password: None,
        }
    }

    /// Öffnet das Volume eines Pfad-Index (live oder Snapshot) und liefert
    /// die Umrechnung der vom NTFS-Parser gemeldeten Offsets in Image-Offsets.
    pub fn open_volume(
        &self,
        v: &FsIndex,
    ) -> Result<(NtfsVolume<VolumeReader<'_>>, Abbildung<'_>), NtfsVolumeError> {
        schatten::open(self.img, &self.schatten, v)
    }

    /// Je Snapshot ein Kontext, dessen Pfad-Index nur die vom Live-Stand
    /// abweichenden Dateien enthält. Hives und Schattenkopien werden geteilt,
    /// nicht kopiert.
    pub fn snapshot_kontexte(&self) -> Vec<(Herkunft, u64, AnalysisContext<'a>)> {
        self.snapshot_volumes
            .iter()
            .filter(|v| !v.files.is_empty())
            .map(|v| {
                (
                    v.herkunft,
                    v.target.offset,
                    AnalysisContext {
                        img: self.img,
                        ntfs_targets: Vec::new(),
                        installs: Arc::clone(&self.installs),
                        volumes: vec![v.clone()],
                        schatten: Arc::clone(&self.schatten),
                        snapshot_volumes: Vec::new(),
                        abweichungen: Arc::new(Vec::new()),
                        snapshot_dateien: Vec::new(),
                        warnings: Vec::new(),
                        dpapi: self.dpapi.clone(),
                        firefox_password: self.firefox_password.clone(),
                    },
                )
            })
            .collect()
    }
}
