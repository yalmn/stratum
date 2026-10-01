//! Fall: eine vollständige Untersuchung.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, CaseId, TagId};

/// Bearbeitungsstand eines Falls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Angelegt.
    New,
    /// In Bearbeitung.
    Active,
    /// In Prüfung.
    Review,
    /// Ruhend.
    Suspended,
    /// Abgeschlossen.
    Closed,
    /// Archiviert.
    Archived,
}

/// Einstufung eines Falls. Die Stufen sind ein Vorschlag; die Zielarchitektur
/// legt sie nicht fest (Grundlage für spätere attributbasierte Rechte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseClassification {
    /// Offen.
    Open,
    /// Intern.
    Internal,
    /// Vertraulich.
    Confidential,
    /// Streng vertraulich.
    StrictlyConfidential,
}

/// Ein Fall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    /// Technische ID (UUIDv7).
    pub id: CaseId,
    /// Menschlich lesbare Fallnummer, z. B. `DFIR-2026-0017`.
    pub case_number: String,
    /// Titel.
    pub title: String,
    /// Beschreibung.
    pub description: Option<String>,
    /// Stand.
    pub status: CaseStatus,
    /// Einstufung.
    pub classification: CaseClassification,
    /// Angelegt am.
    pub created_at: DateTime<Utc>,
    /// Angelegt von.
    pub created_by: ActorId,
    /// Eröffnet am.
    pub opened_at: Option<DateTime<Utc>>,
    /// Geschlossen am.
    pub closed_at: Option<DateTime<Utc>>,
    /// Zeitzone für die Anzeige (Analysezeiten bleiben UTC).
    pub timezone: Option<String>,
    /// Schlagworte.
    pub tags: Vec<TagId>,
}
