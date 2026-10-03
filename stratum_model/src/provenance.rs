//! Herkunft: woher eine Information stammt und wie sie entstanden ist.
//!
//! Jedes Objekt über der rohen Evidence trägt einen Ableitungsstatus
//! ([`DerivationKind`]) und mindestens eine Herkunftsangabe
//! ([`ProvenanceRef`]) bis zur Fundstelle ([`SourceLocator`]). So bleibt
//! jeder Schritt von einer Bewertung bis zur Byte-Stelle nachvollziehbar
//! (Architekturregeln 2 und 3).

use serde::{Deserialize, Serialize};

use crate::ids::{
    AnalysisRunId, ArtifactId, CaseId, EntityId, EventId, EvidenceId, FindingId, ObservationId,
    RelationshipId,
};

/// Wie ein Objekt entstanden ist. Beobachtetes und Gefolgertes werden nie
/// gleich behandelt; die Oberfläche zeigt diesen Status immer an.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum DerivationKind {
    /// Direkt in der Evidence beobachtet.
    Observed,
    /// Deterministisch durch einen Parser extrahiert.
    Parsed,
    /// Aus mehreren Datenfeldern berechnet.
    Derived,
    /// Über mehrere Artefakte hinweg zusammengeführt.
    Correlated,
    /// Durch Replay oder eine rekonstruierte Umgebung erzeugt.
    Reconstructed,
    /// Innerhalb einer Simulation entstanden.
    Simulated,
    /// Bewusst von einem Analysten hinzugefügt.
    AnalystAsserted,
    /// Aus einer externen Threat-Intel-Quelle.
    ExternalIntel,
    /// Von einem Sprachmodell vorgeschlagen.
    AiSuggested,
}

impl DerivationKind {
    /// `true` für Status, die nicht unmittelbar aus der Evidence stammen und
    /// deshalb nie als beobachtete Tatsache gelten dürfen.
    pub fn is_interpretation(self) -> bool {
        !matches!(self, Self::Observed | Self::Parsed | Self::Derived)
    }
}

/// Welcher Parser eine Information erzeugt hat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserIdentity {
    /// Name, z. B. `windows.eventlog`.
    pub name: String,
    /// Version des Parsers.
    pub version: String,
    /// Version von stratum (einschließlich Revision).
    pub stratum_version: String,
    /// Hash der Konfiguration, falls eine verwendet wurde.
    pub config_hash: Option<String>,
}

/// Schattenkopie, aus der eine Fundstelle stammt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowCopyRef {
    /// Store-Index (0 = älteste Schattenkopie).
    pub store: usize,
    /// Store-Kennung (GUID).
    pub store_id: Option<String>,
}

/// Typisierte Fundstelle in einer Evidence.
///
/// Gegenüber der Zielarchitektur ergänzt: bei NTFS der Offset im Datenstrom,
/// der physische Image-Offset und die Schattenkopie; eine eigene Variante für
/// ESE-Datenbanken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceLocator {
    /// Bytebereich im Image (bei E01: in den Mediendaten).
    ByteRange {
        /// Offset im Image.
        offset: u64,
        /// Länge, falls bekannt.
        length: Option<u64>,
    },
    /// Datei oder Datenstrom in einem NTFS-Volume.
    Ntfs {
        /// Offset des Volumes im Image.
        volume_offset: u64,
        /// MFT-Datensatznummer.
        mft_record: u64,
        /// Sequenznummer des Datensatzes.
        sequence: Option<u16>,
        /// Name des Datenstroms (`None` = unbenannter Strom).
        stream: Option<String>,
        /// Offset des MFT-Datensatzes im Image.
        record_offset: Option<u64>,
        /// Offset im Datenstrom (Datei-Offset).
        byte_offset: Option<u64>,
        /// Physischer Offset dieser Bytes im Image.
        image_offset: Option<u64>,
        /// Schattenkopie, falls die Stelle nicht aus dem Live-Stand stammt.
        shadow_copy: Option<ShadowCopyRef>,
    },
    /// Schlüssel oder Wert in einem Registry-Hive.
    Registry {
        /// Hive (z. B. Pfad der Hive-Datei).
        hive: String,
        /// Schlüsselpfad.
        key_path: String,
        /// Name des Werts.
        value_name: Option<String>,
        /// Offset der Zelle in der Hive-Datei.
        cell_offset: Option<u64>,
    },
    /// Datensatz in einem Windows-Ereignisprotokoll.
    Evtx {
        /// Pfad der `.evtx`-Datei.
        path: String,
        /// EventRecordID.
        record_id: u64,
    },
    /// Zeile einer Textdatei.
    FileLine {
        /// Pfad.
        path: String,
        /// Zeilennummer (ab 1).
        line: u64,
        /// Offset der Zeile in der Datei.
        byte_offset: Option<u64>,
    },
    /// Paket in einer Netzwerkaufzeichnung.
    Pcap {
        /// Paketnummer.
        packet_number: u64,
        /// Kennung des Datenstroms.
        stream_id: Option<String>,
    },
    /// Zeile einer Datenbank (z. B. SQLite).
    Database {
        /// Pfad der Datenbankdatei.
        path: String,
        /// Tabelle.
        table: String,
        /// Zeilenkennung.
        row_id: Option<String>,
    },
    /// Datensatz einer ESE-Datenbank (SRUM, WebCache).
    Ese {
        /// Pfad der Datenbankdatei.
        path: String,
        /// Tabelle.
        table: String,
        /// Seite.
        page: u32,
        /// Offset des Datensatzes in der Datei.
        byte_offset: u64,
    },
    /// Datensatz einer mobilen Quelle.
    Mobile {
        /// Datenbank.
        database: Option<String>,
        /// Tabelle.
        table: Option<String>,
        /// Datensatzkennung.
        record_id: Option<String>,
    },
}

/// Verweis auf ein Objekt des Modells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
pub enum ObjectRef {
    /// Fall.
    Case(CaseId),
    /// Evidence.
    Evidence(EvidenceId),
    /// Analyselauf.
    AnalysisRun(AnalysisRunId),
    /// Artefakt.
    Artifact(ArtifactId),
    /// Observation.
    Observation(ObservationId),
    /// Entität.
    Entity(EntityId),
    /// Ereignis.
    Event(EventId),
    /// Beziehung.
    Relationship(RelationshipId),
    /// Finding.
    Finding(FindingId),
}

/// Herkunft einer Information bis zur Fundstelle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRef {
    /// Evidence, aus der die Information stammt.
    pub evidence_id: EvidenceId,
    /// Artefakt, falls bekannt.
    pub artifact_id: Option<ArtifactId>,
    /// Observation, falls bekannt.
    pub observation_id: Option<ObservationId>,
    /// Fundstelle.
    pub source_locator: Option<SourceLocator>,
    /// Parser, der die Information erzeugt hat.
    pub parser: Option<ParserIdentity>,
    /// Analyselauf.
    pub analysis_run_id: Option<AnalysisRunId>,
}

/// Rolle einer Herkunftsangabe für ein Objekt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRole {
    /// Hauptquelle.
    Primary,
    /// Stützende Quelle.
    Supporting,
    /// Bestätigende Quelle.
    Corroborating,
    /// Widersprechende Quelle.
    Contradicting,
}

/// Verknüpfung eines Objekts mit einer Herkunftsangabe; ein Objekt kann
/// mehrere haben.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceLink {
    /// Objekt.
    pub object: ObjectRef,
    /// Herkunft.
    pub provenance: ProvenanceRef,
    /// Rolle.
    pub role: ProvenanceRole,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn interpretation_ist_erkennbar() {
        assert!(!DerivationKind::Parsed.is_interpretation());
        assert!(!DerivationKind::Observed.is_interpretation());
        assert!(DerivationKind::Correlated.is_interpretation());
        assert!(DerivationKind::AiSuggested.is_interpretation());
    }

    #[test]
    fn fundstelle_als_json() {
        let l = SourceLocator::Ntfs {
            volume_offset: 122_683_392,
            mft_record: 109_565,
            sequence: Some(2),
            stream: None,
            record_offset: None,
            byte_offset: Some(4096),
            image_offset: Some(5_000_000_000),
            shadow_copy: Some(ShadowCopyRef {
                store: 1,
                store_id: None,
            }),
        };
        let j = serde_json::to_value(&l).unwrap();
        assert_eq!(j["type"], "ntfs");
        assert_eq!(j["mft_record"], 109_565);
        assert_eq!(j["shadow_copy"]["store"], 1);
        assert_eq!(serde_json::from_value::<SourceLocator>(j).unwrap(), l);

        let o = ObjectRef::Entity(EntityId(Uuid::from_u128(7)));
        let j = serde_json::to_value(o).unwrap();
        assert_eq!(j["type"], "entity");
        assert_eq!(serde_json::from_value::<ObjectRef>(j).unwrap(), o);
    }
}
