//! Fallmerkliste: Analysten-Auswahl und Prüfnotiz, keine Änderung der Quelle.
use crate::{ActorId, CaseId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unterstützte stabile Objektverweise der Merkliste.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookmarkKind {
    /// Datei: Evidence-ID, Volume-Offset und MFT-Datensatz mit | getrennt.
    File,
    /// Normalisiertes Ereignis.
    Event,
    /// Normalisierte Entität.
    Entity,
    /// Gespeicherte Beziehung.
    Relationship,
    /// Artefakt mit unveränderter Herkunft.
    Artifact,
}
impl BookmarkKind {
    /// Name für API und Speicherung.
    pub fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Event => "event",
            Self::Entity => "entity",
            Self::Relationship => "relationship",
            Self::Artifact => "artifact",
        }
    }
}
/// Gemeinsame Auswahl des Falls; Prüfstatus ist eine Analystenangabe.
#[derive(Debug, Serialize)]
pub struct Bookmark {
    /// Verwaltungs-ID, UUIDv7.
    pub id: uuid::Uuid,
    /// Zugehöriger Fall.
    pub case_id: CaseId,
    /// Art des verknüpften Objekts.
    pub kind: BookmarkKind,
    /// Stabile Referenz auf das Quellobjekt.
    pub target: String,
    /// Beim Markieren serverseitig ermittelter Anzeigename, keine Geheimwerte.
    pub title: String,
    /// Begründung oder Arbeitsnotiz des Analysten.
    pub note: String,
    /// Vom Analysten als geprüft markiert, keine Bestätigung eines Befunds.
    pub reviewed: bool,
    /// Zeitpunkt der Aufnahme in Untersuchungszeit.
    pub created_at: DateTime<Utc>,
    /// Letzte Änderung in Untersuchungszeit.
    pub updated_at: DateTime<Utc>,
    /// Letzter Bearbeiter.
    pub updated_by: ActorId,
}
