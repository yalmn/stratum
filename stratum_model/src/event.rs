//! Ereignis: ein zeitlich gebundener Vorgang mit beteiligten Entitäten.
//! Die Timeline ist eine Projektion aus Ereignissen, keine eigene
//! Wahrheitsschicht.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{CaseId, EntityId, EventId};
use crate::provenance::DerivationKind;
use crate::time::ForensicTime;

/// Art eines Ereignisses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Prozessstart.
    ProcessStart,
    /// Prozessende.
    ProcessExit,
    /// Anmeldung.
    UserLogon,
    /// Abmeldung.
    UserLogoff,
    /// Datei angelegt.
    FileCreated,
    /// Datei geändert.
    FileModified,
    /// Datei gelöscht.
    FileDeleted,
    /// Datei umbenannt.
    FileRenamed,
    /// Datei zugegriffen.
    FileAccessed,
    /// Registry-Schlüssel angelegt.
    RegistryKeyCreated,
    /// Registry-Schlüssel geändert.
    RegistryKeyModified,
    /// Registry-Wert gesetzt.
    RegistryValueSet,
    /// Netzwerkverbindung.
    NetworkConnection,
    /// DNS-Anfrage.
    DnsQuery,
    /// HTTP-Anfrage.
    HttpRequest,
    /// HTTP-Antwort.
    HttpResponse,
    /// Dienst installiert.
    ServiceInstalled,
    /// Dienst gestartet.
    ServiceStarted,
    /// Geplante Aufgabe angelegt.
    ScheduledTaskCreated,
    /// Geplante Aufgabe ausgeführt.
    ScheduledTaskExecuted,
    /// USB-Gerät verbunden.
    UsbConnected,
    /// USB-Gerät getrennt.
    UsbRemoved,
    /// Besuch einer Webseite.
    BrowserVisit,
    /// Download.
    Download,
    /// Anmeldeversuch.
    AuthenticationAttempt,
    /// Datenbankabfrage.
    DatabaseQuery,
    /// E-Mail gesendet.
    EmailSent,
    /// E-Mail empfangen.
    EmailReceived,
    /// Befehl eingegeben.
    CommandEntered,
    /// Systemstart.
    SystemBoot,
    /// Herunterfahren.
    SystemShutdown,
    /// Eigene Art (Name in den Attributen).
    Custom,
}

/// Ein Ereignis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Deterministische ID (siehe [`EventId::derive`]).
    pub id: EventId,
    /// Fall.
    pub case_id: CaseId,
    /// Art.
    pub kind: EventKind,
    /// Beginn bzw. Zeitpunkt.
    pub occurred_at: Option<ForensicTime>,
    /// Ende, falls es eine Dauer gibt.
    pub ended_at: Option<ForensicTime>,
    /// Weitere Angaben.
    pub attributes: JsonValue,
    /// Ableitungsstatus.
    pub derivation: DerivationKind,
    /// Zeitpunkt der Erfassung in stratum (Analysezeit).
    pub created_at: DateTime<Utc>,
}

/// Rolle einer Entität in einem Ereignis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    /// Handelnder.
    Actor,
    /// Betroffener.
    Subject,
    /// Gegenstand.
    Object,
    /// Benutzer.
    User,
    /// Rechner.
    Host,
    /// Prozess.
    Process,
    /// Elternprozess.
    ParentProcess,
    /// Kindprozess.
    ChildProcess,
    /// Ausführbare Datei.
    Executable,
    /// Quelle.
    Source,
    /// Ziel.
    Destination,
    /// Quell-IP.
    SourceIp,
    /// Ziel-IP.
    DestinationIp,
    /// Datei.
    File,
    /// Registry-Objekt.
    RegistryObject,
    /// Konto.
    Account,
    /// Gerät.
    Device,
    /// Sonstiges.
    Other,
}

/// Beteiligung einer Entität an einem Ereignis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventParticipant {
    /// Ereignis.
    pub event_id: EventId,
    /// Entität.
    pub entity_id: EntityId,
    /// Rolle.
    pub role: ParticipantRole,
}
