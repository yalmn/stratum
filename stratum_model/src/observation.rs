//! Observation: ein direkt aus einem Artefakt extrahierter Sachverhalt, noch
//! keine Bewertung.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ArtifactId, CaseId, ObservationId};
use crate::provenance::ParserIdentity;

/// Art einer Observation, z. B. `process_creation` oder `registry_value`.
/// Die Zielarchitektur legt die Arten nicht abschließend fest; sie entstehen
/// mit den Mappern des Normalizers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObservationKind(pub String);

/// Eine Observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Deterministische ID (siehe [`ObservationId::derive`]).
    pub id: ObservationId,
    /// Fall.
    pub case_id: CaseId,
    /// Artefakt, aus dem sie stammt.
    pub artifact_id: ArtifactId,
    /// Art.
    pub kind: ObservationKind,
    /// Felder, wie sie in der Quelle stehen.
    pub fields: JsonValue,
    /// Parser.
    pub parser: ParserIdentity,
    /// Zeitpunkt der Erfassung in stratum (Analysezeit).
    pub observed_at: DateTime<Utc>,
}
