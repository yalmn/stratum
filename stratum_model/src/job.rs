//! Jobs: Aufträge, die ein Worker im Hintergrund ausführt (Analysen und
//! Evidence-Importe). Ein Job läuft im Namen dessen, der ihn angelegt hat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ActorId, AnalysisRunId, CaseId, JobId};

/// Art eines Jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum JobKind {
    /// Analyse einer registrierten Evidence.
    Analysis,
    /// Datei aus dem Fallordner hashen und als Evidence registrieren.
    EvidenceImport,
    /// Lokaler YARA-Scan einer katalogisierten Datei.
    YaraScan,
    /// DNS-/WHOIS-Anreicherung zur Untersuchungszeit.
    NetworkEnrichment,
    /// HTTP-Versuch gegen einen isolierten simulierten Server.
    HttpReplay,
}

/// Stand eines Jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum JobStatus {
    /// Wartet auf einen Worker.
    Queued,
    /// Läuft.
    Running,
    /// Fertig.
    Completed,
    /// Gescheitert.
    Failed,
    /// Abgebrochen.
    Cancelled,
}

/// Ein Job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct Job {
    /// ID (UUIDv7).
    pub id: JobId,
    /// Fall.
    pub case_id: CaseId,
    /// Art.
    pub kind: JobKind,
    /// Stand.
    pub status: JobStatus,
    /// Parameter (bei Analysen: Evidence und Optionen, nie Geheimnisse).
    pub parameters: JsonValue,
    /// Letzter Fortschritt (Phase, erledigt, gesamt, Meldung).
    pub progress: JsonValue,
    /// Angelegt von; der Job läuft in seinem Namen.
    pub created_by: ActorId,
    /// Angelegt am.
    pub created_at: DateTime<Utc>,
    /// Begonnen am.
    pub started_at: Option<DateTime<Utc>>,
    /// Beendet am.
    pub finished_at: Option<DateTime<Utc>>,
    /// Worker, der ihn ausführt bzw. ausgeführt hat.
    pub worker: Option<String>,
    /// Abbruch angefordert.
    pub cancel_requested: bool,
    /// Fehlermeldung.
    pub error: Option<String>,
    /// Zugehöriger Analyselauf.
    pub analysis_run_id: Option<AnalysisRunId>,
    /// Ergebnis (z. B. Report-Pfad und SHA-256).
    pub result: Option<JsonValue>,
}
