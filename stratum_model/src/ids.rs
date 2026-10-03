//! Stabile, global eindeutige IDs (Architekturregel 9) und ihre Bildung.
//!
//! Zwei Arten (Entscheidung Z6):
//! - Verwaltungsobjekte (Fall, Evidence-Import, Analyselauf, Finding,
//!   Analyst) erhalten eine UUIDv7 beim Anlegen.
//! - Alles, was aus Evidence abgeleitet wird (Artifact, Observation, Entity,
//!   Event, Relationship), erhält eine deterministische UUIDv5. Gleiche
//!   Eingaben ergeben dieselbe ID, ein erneuter Lauf über dieselbe Evidence
//!   im selben Fall ist damit reproduzierbar (Regel 10). Die Fall-ID gehört
//!   immer zu den Eingaben, damit dasselbe Image in zwei Fällen nicht
//!   dieselben IDs erzeugt.
//!
//! Die Eingaben einer UUIDv5 werden längenpräfixiert verkettet, damit
//! verschiedene Zerlegungen nie denselben Namen ergeben.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Namensraum aller stratum-UUIDv5 (fest, nie ändern: sonst ändern sich alle
/// abgeleiteten IDs).
const NAMESPACE: Uuid = Uuid::from_u128(0x5f3c_2a91_7d4e_4b0a_9c61_8e2d_04b7_a3f5);

/// Bildet eine deterministische UUIDv5 aus einer Objektart und Teilen.
pub fn derived_uuid(art: &str, teile: &[&[u8]]) -> Uuid {
    let mut name = Vec::with_capacity(64);
    for t in std::iter::once(art.as_bytes()).chain(teile.iter().copied()) {
        name.extend_from_slice(&(t.len() as u64).to_le_bytes());
        name.extend_from_slice(t);
    }
    Uuid::new_v5(&NAMESPACE, &name)
}

macro_rules! id_typ {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Die zugrunde liegende UUID.
            pub fn uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

macro_rules! verwaltung {
    ($name:ident) => {
        impl $name {
            /// Neue ID (UUIDv7, zeitlich sortierbar).
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

id_typ!(
    /// Fall.
    CaseId
);
verwaltung!(CaseId);
id_typ!(
    /// Evidence-Import (ein Beweisobjekt in einem Fall).
    EvidenceId
);
verwaltung!(EvidenceId);
id_typ!(
    /// Analyselauf.
    AnalysisRunId
);
verwaltung!(AnalysisRunId);
id_typ!(
    /// Fachliche Bewertung (Finding).
    FindingId
);
verwaltung!(FindingId);
id_typ!(
    /// Person oder Dienst, der in stratum handelt.
    ActorId
);
verwaltung!(ActorId);
id_typ!(
    /// Eintrag im War Room.
    WarRoomEntryId
);
verwaltung!(WarRoomEntryId);

impl ActorId {
    /// Systemkonto der Kommandozeile, solange sie ohne Anmeldung arbeitet.
    /// Fest, damit die Datenbank es anlegen kann (Migration 0004).
    pub fn cli() -> Self {
        Self(derived_uuid("akteur", &[b"stratum-cli"]))
    }

    /// Platzhalter für Aktionen ohne bekannten Benutzer, etwa eine
    /// Anmeldung mit unbekanntem Namen.
    pub fn unbekannt() -> Self {
        Self(derived_uuid("akteur", &[b"unbekannt"]))
    }
}
id_typ!(
    /// Schlagwort.
    TagId
);
verwaltung!(TagId);
id_typ!(
    /// Job (Auftrag für einen Worker).
    JobId
);
verwaltung!(JobId);
id_typ!(
    /// Rolle (frei angelegtes Bündel von Berechtigungen).
    RoleId
);
verwaltung!(RoleId);

impl RoleId {
    /// ID einer mitgelieferten Vorlage, aus ihrem Namen abgeleitet
    /// (Migration 0004 legt die Vorlagen mit genau diesen IDs an).
    pub fn template(name: &str) -> Self {
        Self(derived_uuid("rolle", &[name.as_bytes()]))
    }
}
id_typ!(
    /// Audit-Ereignis.
    AuditEventId
);
verwaltung!(AuditEventId);
id_typ!(
    /// Beziehung zwischen zwei Evidence-Objekten.
    EvidenceRelationId
);
verwaltung!(EvidenceRelationId);

id_typ!(
    /// Forensisches Objekt in einer Evidence (abgeleitet).
    ArtifactId
);
id_typ!(
    /// Direkt extrahierter Sachverhalt (abgeleitet).
    ObservationId
);
id_typ!(
    /// Objekt mit eigener Identität (abgeleitet).
    EntityId
);
id_typ!(
    /// Zeitlich gebundener Vorgang (abgeleitet).
    EventId
);
id_typ!(
    /// Beziehung zwischen zwei Entitäten (abgeleitet).
    RelationshipId
);

impl ArtifactId {
    /// ID eines Artefakts aus Fall, SHA-256 der Evidence (hex) und dem
    /// kanonischen Schlüssel seiner Fundstelle.
    pub fn derive(case: CaseId, evidence_sha256: &str, locator_key: &str) -> Self {
        Self(derived_uuid(
            "artifact",
            &[
                case.0.as_bytes(),
                evidence_sha256.as_bytes(),
                locator_key.as_bytes(),
            ],
        ))
    }
}

impl ObservationId {
    /// ID einer Observation aus ihrem Artefakt und ihrer Art.
    pub fn derive(artifact: ArtifactId, kind: &str) -> Self {
        Self(derived_uuid(
            "observation",
            &[artifact.0.as_bytes(), kind.as_bytes()],
        ))
    }
}

impl EntityId {
    /// ID einer Entität aus Fall, Art und kanonischem Schlüssel.
    pub fn derive(case: CaseId, kind: &str, canonical_key: &str) -> Self {
        Self(derived_uuid(
            "entity",
            &[case.0.as_bytes(), kind.as_bytes(), canonical_key.as_bytes()],
        ))
    }
}

impl EventId {
    /// ID eines Ereignisses aus Fall, Art und einem Schlüssel aus Quelle und
    /// Zeitpunkt.
    pub fn derive(case: CaseId, kind: &str, key: &str) -> Self {
        Self(derived_uuid(
            "event",
            &[case.0.as_bytes(), kind.as_bytes(), key.as_bytes()],
        ))
    }
}

impl RelationshipId {
    /// ID einer Beziehung aus Fall, Art und den beiden Entitäten.
    pub fn derive(case: CaseId, kind: &str, source: EntityId, target: EntityId) -> Self {
        Self(derived_uuid(
            "relationship",
            &[
                case.0.as_bytes(),
                kind.as_bytes(),
                source.0.as_bytes(),
                target.0.as_bytes(),
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn feste_akteure_wie_in_migration_0004() {
        use super::ActorId;
        assert_eq!(
            ActorId::cli().to_string(),
            "90713752-b779-524a-be66-954f05a2e0c3"
        );
        assert_eq!(
            ActorId::unbekannt().to_string(),
            "924f4def-f441-57c7-8284-92be2c4250ad"
        );
    }

    use super::*;

    fn fall() -> CaseId {
        CaseId(Uuid::from_u128(1))
    }

    #[test]
    fn abgeleitete_ids_sind_reproduzierbar() {
        let a = ArtifactId::derive(fall(), "e633f0be", "ntfs:0:42:3");
        assert_eq!(a, ArtifactId::derive(fall(), "e633f0be", "ntfs:0:42:3"));
        assert_eq!(a.0.get_version_num(), 5);
        // Anderer Fall, andere Evidence oder andere Stelle: andere ID.
        assert_ne!(
            a,
            ArtifactId::derive(CaseId(Uuid::from_u128(2)), "e633f0be", "ntfs:0:42:3")
        );
        assert_ne!(a, ArtifactId::derive(fall(), "e633f0bf", "ntfs:0:42:3"));
        assert_ne!(a, ArtifactId::derive(fall(), "e633f0be", "ntfs:0:42:4"));
    }

    #[test]
    fn laengenpraefix_verhindert_mehrdeutigkeit() {
        assert_ne!(
            derived_uuid("x", &[b"ab", b"c"]),
            derived_uuid("x", &[b"a", b"bc"])
        );
        assert_ne!(
            derived_uuid("entity", &[b"a"]),
            derived_uuid("event", &[b"a"])
        );
    }

    #[test]
    fn beziehung_ist_gerichtet() {
        let a = EntityId::derive(fall(), "user_account", "S-1-5-18");
        let b = EntityId::derive(fall(), "host", "WIN-01");
        assert_ne!(
            RelationshipId::derive(fall(), "ACCOUNT_ON", a, b),
            RelationshipId::derive(fall(), "ACCOUNT_ON", b, a)
        );
    }

    #[test]
    fn verwaltungs_ids_sind_v7_und_als_text_serialisiert() {
        let c = CaseId::new();
        assert_eq!(c.0.get_version_num(), 7);
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, format!("\"{c}\""));
        assert_eq!(serde_json::from_str::<CaseId>(&json).unwrap(), c);
    }
}
