//! Artefakt: ein konkretes forensisches Objekt innerhalb einer Evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{ArtifactId, CaseId, EvidenceId};
use crate::provenance::{ParserIdentity, SourceLocator};

/// Art eines Artefakts. Gegenüber der Zielarchitektur ergänzt um Arten, die
/// die Engine heute schon liefert (ESE, USN, Shell Items, Jump Lists,
/// Papierkorb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// MFT-Datensatz.
    NtfsMftRecord,
    /// NTFS-Datenstrom.
    NtfsStream,
    /// Eintrag im USN-Änderungsjournal.
    UsnRecord,
    /// Registry-Schlüssel.
    RegistryKey,
    /// Registry-Wert.
    RegistryValue,
    /// Datensatz eines Ereignisprotokolls.
    EvtxRecord,
    /// Prefetch-Datei.
    PrefetchRecord,
    /// LNK-Datei.
    LnkRecord,
    /// Eintrag einer Jump List.
    JumpListEntry,
    /// Shell Item (ShellBags, LNK-IDList).
    ShellItem,
    /// Eintrag im Papierkorb.
    RecycleBinRecord,
    /// Zeile im Browser-Verlauf.
    BrowserHistoryRow,
    /// Gespeicherte Anmeldung im Browser.
    BrowserLoginRow,
    /// Zeile im PowerShell-Verlauf.
    PowershellHistoryLine,
    /// Datensatz einer ESE-Datenbank (SRUM, WebCache).
    EseRecord,
    /// Netzwerkpaket.
    PcapPacket,
    /// Netzwerkfluss.
    NetworkFlow,
    /// Zeile einer Protokolldatei.
    LogLine,
    /// Zeile einer SQLite-Datenbank.
    SqliteRow,
    /// Datensatz einer mobilen Quelle.
    MobileRecord,
    /// Unbekannt.
    Unknown,
}

/// Ein Artefakt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    /// Deterministische ID (siehe [`ArtifactId::derive`]).
    pub id: ArtifactId,
    /// Fall.
    pub case_id: CaseId,
    /// Evidence.
    pub evidence_id: EvidenceId,
    /// Art.
    pub kind: ArtifactKind,
    /// Fundstelle.
    pub source_locator: SourceLocator,
    /// Parser.
    pub parser: ParserIdentity,
    /// Rohdaten des Parsers (unverändert).
    pub raw_metadata: JsonValue,
    /// Zeitpunkt der Erfassung in stratum (Analysezeit, keine Artefaktzeit).
    pub created_at: DateTime<Utc>,
}
