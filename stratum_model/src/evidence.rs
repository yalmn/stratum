//! Evidence: ein Beweisobjekt. Es wird nie verändert (Architekturregel 1).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ActorId, CaseId, EvidenceId};

/// Art eines Beweisobjekts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Rohimage eines Datenträgers (dd).
    RawDiskImage,
    /// Expert-Witness-Image (E01).
    E01Image,
    /// Virtuelle Festplatte (VHD/VHDX).
    VhdImage,
    /// Verzeichnis.
    Directory,
    /// Dateisammlung.
    FileCollection,
    /// Netzwerkaufzeichnung.
    Pcap,
    /// Netzwerkflüsse.
    NetworkFlow,
    /// Sammlung von Protokolldateien.
    LogBundle,
    /// Sicherung eines Mobilgeräts.
    MobileBackup,
    /// Abbild eines Android-Geräts.
    AndroidImage,
    /// iOS-Sicherung.
    IosBackup,
    /// Speicherabbild.
    MemoryDump,
    /// Einzelner Registry-Hive.
    RegistryHive,
    /// Datenbank.
    Database,
    /// Export aus einem Cloud-Dienst.
    CloudExport,
    /// Sonstiges.
    Other,
}

/// Ein Beweisobjekt in einem Fall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Technische ID des Imports (UUIDv7).
    pub id: EvidenceId,
    /// Fall.
    pub case_id: CaseId,
    /// Art.
    pub kind: EvidenceKind,
    /// Anzeigename.
    pub name: String,
    /// Ursprünglicher Dateiname.
    pub original_name: Option<String>,
    /// Ablageort (Pfad oder URI).
    pub source_uri: String,
    /// Größe in Byte (bei E01 die Mediengröße).
    pub size: u64,
    /// SHA-256 über die Mediendaten (hex).
    pub sha256: String,
    /// BLAKE3 über die Mediendaten (hex).
    pub blake3: String,
    /// Zeitpunkt der Sicherung, falls bekannt (z. B. aus dem E01-Kopf).
    pub acquired_at: Option<DateTime<Utc>>,
    /// Zeitpunkt des Imports in stratum.
    pub imported_at: DateTime<Utc>,
    /// Importiert von.
    pub imported_by: ActorId,
    /// Sicherungsverfahren bzw. -werkzeug.
    pub acquisition_method: Option<String>,
    /// Nur lesend eingebunden (immer `true` bei stratum).
    pub read_only: bool,
    /// Übergeordnete Evidence (z. B. bei extrahierten Dateien).
    pub parent_evidence_id: Option<EvidenceId>,
    /// Weitere Angaben (z. B. Akquisedaten und Akquise-Hashes eines E01).
    pub metadata: JsonValue,
}
