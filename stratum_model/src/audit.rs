//! Audit: was welcher Benutzer in stratum getan hat. Getrennt von der
//! forensischen Timeline (was auf dem untersuchten System geschah) und vom
//! War Room (wie die Untersuchung läuft).
//!
//! Die Ereignisse bilden eine Hash-Kette: jeder Hash deckt den Inhalt und
//! den Hash des Vorgängers ab. Eine nachträgliche Änderung, Lücke oder
//! Umstellung fällt beim Nachrechnen auf.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ActorId, AuditEventId, CaseId};

/// Protokollierte Aktion. Auch Lesezugriffe werden festgehalten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditAction {
    /// Anmeldung.
    Login,
    /// Abmeldung.
    Logout,
    /// Konto selbst registriert (wartet auf Freigabe).
    UserRegister,
    /// Konto angelegt (durch einen Superadmin oder bei der Einrichtung).
    UserCreate,
    /// Registrierung freigegeben.
    UserApprove,
    /// Registrierung abgelehnt.
    UserReject,
    /// Konto gesperrt.
    UserDisable,
    /// Kontenliste gelesen.
    UserList,
    /// Superadmin-Recht vergeben oder entzogen.
    SuperadminSet,
    /// Rolle angelegt.
    RoleCreate,
    /// Rolle geändert (Name, Beschreibung, Berechtigungen).
    RoleModify,
    /// Rolle gelöscht.
    RoleDelete,
    /// Rolle an ein Konto vergeben.
    RoleGrant,
    /// Rolle einem Konto entzogen.
    RoleRevoke,
    /// Fall angelegt.
    CaseCreate,
    /// Fallliste gelesen.
    CaseList,
    /// Fall geöffnet.
    CaseOpen,
    /// Fall geschlossen.
    CaseClose,
    /// Evidence registriert.
    EvidenceImport,
    /// Evidence gegen ihren registrierten Hash geprüft.
    EvidenceVerify,
    /// Analyse gestartet.
    AnalysisStart,
    /// Analyse abgeschlossen.
    AnalysisComplete,
    /// Analyse fehlgeschlagen.
    AnalysisFail,
    /// Analyse abgebrochen.
    AnalysisCancel,
    /// Suche ausgeführt.
    SearchRun,
    /// Datei angesehen.
    FileView,
    /// Datei extrahiert.
    FileExtract,
    /// Datei heruntergeladen.
    FileDownload,
    /// Zugangsdaten angesehen.
    CredentialView,
    /// Finding angelegt.
    FindingCreate,
    /// Finding geändert.
    FindingModify,
    /// Beziehung angelegt.
    RelationCreate,
    /// Beziehung entfernt.
    RelationRemove,
    /// Wortliste hochgeladen.
    WordlistUpload,
    /// Playbook gestartet.
    PlaybookStart,
    /// Threat Intel importiert.
    TiImport,
    /// Threat Intel exportiert.
    TiExport,
    /// Rekonstruktion gestartet.
    ReconstructionStart,
    /// Replay angefordert.
    ReplayRequest,
    /// Report erstellt.
    ReportCreate,
    /// Report exportiert.
    ReportExport,
    /// Anfrage an ein Sprachmodell.
    AiQuery,
    /// Antwort eines Sprachmodells.
    AiResponse,
    /// Connector genutzt.
    ConnectorUse,
    /// Audit gelesen.
    AuditView,
    /// Audit-Kette nachgerechnet.
    AuditVerify,
}

/// Ausgang einer Aktion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// Ausgeführt.
    Success,
    /// Abgelehnt (fehlende Berechtigung, falsches Passwort).
    Denied,
    /// Versucht, aber gescheitert.
    Failure,
}

/// Ein Audit-Ereignis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ID (UUIDv7).
    pub id: AuditEventId,
    /// Laufende Nummer, lückenlos ab 1.
    pub sequence: u64,
    /// Handelnder Benutzer oder Dienst.
    pub actor_id: ActorId,
    /// Fall, falls die Aktion einen betrifft.
    pub case_id: Option<CaseId>,
    /// Zeitpunkt der Aktion (Untersuchungszeit, UTC).
    pub timestamp: DateTime<Utc>,
    /// Aktion.
    pub action: AuditAction,
    /// Art des betroffenen Objekts (z. B. `evidence`).
    pub object_type: String,
    /// Betroffenes Objekt.
    pub object_id: Option<String>,
    /// Ausgang.
    pub result: AuditResult,
    /// Weitere Angaben.
    pub details: JsonValue,
    /// Hash des Vorgängers (beim ersten Ereignis 64 Nullen).
    pub previous_hash: Option<String>,
    /// SHA-256 über Vorgänger-Hash, Nummer und Inhalt (hex).
    pub hash: String,
}
