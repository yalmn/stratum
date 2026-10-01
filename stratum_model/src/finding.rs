//! Finding: eine fachliche Bewertung. Nicht jedes Artefakt ist ein Finding,
//! und Vorschläge eines Sprachmodells werden nie automatisch zu einem
//! (Architekturregel 4).
//!
//! Die heutigen Funde der Engine sind in diesem Sinn noch keine Findings,
//! sondern Rohfunde; der Normalizer bildet sie auf Artefakte, Observationen,
//! Entitäten, Ereignisse und Beziehungen ab.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, ArtifactId, CaseId, EntityId, EventId, FindingId};
use crate::provenance::DerivationKind;

/// Fachliche Einordnung. Ein Vorschlag; die Zielarchitektur legt die
/// Kategorien nicht fest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Ausführung von Programmen.
    Execution,
    /// Persistenz (Autostart, Dienste, Aufgaben).
    Persistence,
    /// Zugangsdaten.
    CredentialAccess,
    /// Datenabfluss.
    Exfiltration,
    /// Seitliche Bewegung im Netz.
    LateralMovement,
    /// Verschleierung und Spurenbeseitigung.
    DefenseEvasion,
    /// Benutzeraktivität.
    UserActivity,
    /// Wechseldatenträger.
    RemovableMedia,
    /// Netzwerk.
    Network,
    /// Sonstiges.
    Other,
}

/// Bearbeitungsstand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Neu.
    New,
    /// In Prüfung.
    InReview,
    /// Bestätigt.
    Confirmed,
    /// Verworfen.
    Rejected,
    /// Erledigt.
    Resolved,
}

/// Priorität. Ein Vorschlag; die Zielarchitektur nennt die Stufen nicht.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingPriority {
    /// Niedrig.
    Low,
    /// Mittel.
    Medium,
    /// Hoch.
    High,
    /// Kritisch.
    Critical,
}

/// Bewertung des Sachverhalts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisposition {
    /// Unbekannt.
    Unknown,
    /// Harmlos.
    Benign,
    /// Erwartet.
    Expected,
    /// Verdächtig.
    Suspicious,
    /// Schädlich.
    Malicious,
    /// Relevant.
    Relevant,
    /// Nicht relevant.
    NotRelevant,
}

/// Ein Finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// ID (UUIDv7, da eine Bewertung kein Ableitungsergebnis ist).
    pub id: FindingId,
    /// Fall.
    pub case_id: CaseId,
    /// Titel.
    pub title: String,
    /// Beschreibung.
    pub description: Option<String>,
    /// Einordnung.
    pub category: FindingCategory,
    /// Bearbeitungsstand.
    pub status: FindingStatus,
    /// Priorität.
    pub priority: FindingPriority,
    /// Bewertung.
    pub disposition: FindingDisposition,
    /// Ableitungsstatus.
    pub derivation: DerivationKind,
    /// Beteiligte Entitäten.
    pub entity_refs: Vec<EntityId>,
    /// Beteiligte Ereignisse.
    pub event_refs: Vec<EventId>,
    /// Belegende Artefakte.
    pub artifact_refs: Vec<ArtifactId>,
    /// Angelegt am (Untersuchungszeit).
    pub created_at: DateTime<Utc>,
    /// Angelegt von.
    pub created_by: ActorId,
    /// Zuletzt geändert (Untersuchungszeit).
    pub updated_at: DateTime<Utc>,
}
