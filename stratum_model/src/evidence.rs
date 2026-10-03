//! Evidence: ein Beweisobjekt. Es wird nie verändert (Architekturregel 1).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ActorId, CaseId, EvidenceId, EvidenceRelationId};
use crate::provenance::DerivationKind;

/// Art eines Beweisobjekts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
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

/// Wie weit stratum ein Beweisobjekt auswerten kann. Erkennung, erfolgreiche
/// Auswertung und fehlende Schlüssel werden getrennt ausgewiesen; nicht
/// unterstützte Arten werden trotzdem registriert und gehasht.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum EvidenceSupport {
    /// Registriert und gehasht, noch nicht ausgewertet.
    Recognized,
    /// Mindestens ein Analyselauf ist abgeschlossen.
    Analyzed,
    /// Format wird (noch) nicht unterstützt.
    UnsupportedFormat,
    /// Format bekannt, aber verschlüsselt und ohne Schlüssel.
    KeyMissing,
}

/// Ein Beweisobjekt in einem Fall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct Evidence {
    /// Technische ID des Imports (UUIDv7).
    pub id: EvidenceId,
    /// Fall.
    pub case_id: CaseId,
    /// Art.
    pub kind: EvidenceKind,
    /// Anzeigename.
    pub name: String,
    /// System oder Rolle, zu der die Evidence gehört (z. B. „Webserver“).
    pub role: Option<String>,
    /// Ursprünglicher Dateiname.
    pub original_name: Option<String>,
    /// Ablageort (Pfad oder URI).
    pub source_uri: String,
    /// Größe in Byte (bei E01 die Mediengröße).
    // JSON-Zahl; bis 2^53 Byte (8 PiB) exakt.
    #[cfg_attr(feature = "ts", ts(type = "number"))]
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
    /// Stand der Auswertbarkeit.
    pub support: EvidenceSupport,
    /// Übergeordnete Evidence (z. B. bei extrahierten Dateien).
    pub parent_evidence_id: Option<EvidenceId>,
    /// Weitere Angaben (z. B. Akquisedaten und Akquise-Hashes eines E01).
    pub metadata: JsonValue,
}

/// Art der Beziehung zwischen zwei Beweisobjekten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceRelationKind {
    /// Quelle ist aus dem Ziel entstanden (z. B. Rohimage aus einem E01,
    /// entschlüsseltes Image aus dem verschlüsselten).
    DerivedFrom,
    /// Beide stammen vom selben Datenträger oder Gerät.
    SameSource,
    /// Quelle gehört zum Ziel (z. B. USB-Image zum Rechner).
    BelongsTo,
    /// Quelle ist ein Teil des Ziels (z. B. ein Segment).
    PartOf,
}

/// Beziehung zwischen zwei Beweisobjekten desselben Falls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRelation {
    /// ID (UUIDv7).
    pub id: EvidenceRelationId,
    /// Fall.
    pub case_id: CaseId,
    /// Quelle.
    pub source_evidence_id: EvidenceId,
    /// Ziel.
    pub target_evidence_id: EvidenceId,
    /// Art.
    pub kind: EvidenceRelationKind,
    /// Wie die Beziehung entstanden ist (von stratum erkannt oder vom
    /// Analysten gesetzt).
    pub derivation: DerivationKind,
    /// Begründung oder Notiz.
    pub note: Option<String>,
    /// Angelegt am.
    pub created_at: DateTime<Utc>,
    /// Angelegt von, falls ein Analyst sie gesetzt hat.
    pub created_by: Option<ActorId>,
}
