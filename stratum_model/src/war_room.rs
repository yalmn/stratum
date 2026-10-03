//! War Room: der operative Verlauf eines Falls als typisierter Strom.
//!
//! Getrennt von der forensischen Timeline (was auf dem System geschah) und
//! vom Audit (was ein Benutzer in stratum getan hat): der War Room zeigt,
//! wie die Untersuchung läuft. Einträge werden nur angehängt, nie geändert;
//! eine Korrektur ist ein neuer Eintrag mit `parent_entry_id`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ActorId, AuditEventId, CaseId, WarRoomEntryId};
use crate::provenance::ObjectRef;

/// Art eines Eintrags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum WarRoomEntryKind {
    /// Nachricht eines Analysten.
    AnalystMessage,
    /// Notiz eines Analysten.
    AnalystNote,
    /// Suche ausgeführt.
    Search,
    /// Ergebnis einer Abfrage.
    QueryResult,
    /// Entität geöffnet.
    EntityOpened,
    /// Artefakt geöffnet.
    ArtifactOpened,
    /// Finding angelegt.
    FindingCreated,
    /// Finding geändert.
    FindingUpdated,
    /// Playbook gestartet.
    PlaybookStarted,
    /// Schritt eines Playbooks.
    PlaybookStep,
    /// Playbook beendet.
    PlaybookCompleted,
    /// Rekonstruktion gestartet.
    ReconstructionStarted,
    /// Replay angefordert.
    ReplayRequest,
    /// Ergebnis eines Replays.
    ReplayResult,
    /// Treffer in Threat Intelligence.
    ThreatIntelMatch,
    /// Ergebnis eines Connectors.
    ConnectorResult,
    /// Frage an ein Sprachmodell.
    AiQuestion,
    /// Antwort eines Sprachmodells (nie automatisch ein Finding).
    AiAnswer,
    /// Datei extrahiert.
    FileExtracted,
    /// Report erzeugt.
    ReportGenerated,
    /// Ereignis des Systems (Job angelegt, Analyse beendet …).
    SystemEvent,
}

/// Ein Eintrag im War Room.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub struct WarRoomEntry {
    /// ID (UUIDv7).
    pub id: WarRoomEntryId,
    /// Fall.
    pub case_id: CaseId,
    /// Zeitpunkt (Untersuchungszeit).
    pub timestamp: DateTime<Utc>,
    /// Wer: Analyst, oder bei Systemereignissen der Auftraggeber des Jobs.
    pub actor: ActorId,
    /// Art.
    pub kind: WarRoomEntryKind,
    /// Verknüpfte Objekte des Modells.
    pub object_refs: Vec<ObjectRef>,
    /// Inhalt (Text, Kennzahlen, Job-ID …).
    #[cfg_attr(feature = "ts", ts(type = "Record<string, unknown>"))]
    pub payload: JsonValue,
    /// Eintrag, auf den sich dieser bezieht.
    pub parent_entry_id: Option<WarRoomEntryId>,
    /// Audit-Ereignis der Handlung; bei Einträgen des Workers leer, sie
    /// verweisen über `payload.job_id` auf den Job.
    pub audit_event_id: Option<AuditEventId>,
}
