//! Gemeinsames Datenmodell von stratum.
//!
//! Der Weg von der Evidence zur Bewertung:
//! Evidence > Artifact > Observation > Entity und Event > Relationship >
//! Correlation > Finding. Jede Stufe trägt ihre Herkunft
//! ([`provenance::ProvenanceRef`]) und, über der rohen Evidence, ihren
//! Ableitungsstatus ([`provenance::DerivationKind`]). Beobachtetes,
//! Gefolgertes und Vorschläge eines Sprachmodells werden nie vermischt.
//!
//! Das Modell besteht nur aus Typen und ihren Regeln (IDs, kanonische
//! Schlüssel, Zeitangaben). Es hängt von keinem Backend-Crate ab und kennt
//! weder Datenbank noch Oberfläche.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod audit;
pub mod case;
pub mod entity;
pub mod event;
pub mod evidence;
pub mod finding;
pub mod ids;
pub mod job;
pub mod observation;
pub mod provenance;
pub mod relationship;
pub mod time;
pub mod user;
pub mod war_room;

pub use artifact::{Artifact, ArtifactKind};
pub use audit::{AuditAction, AuditEvent, AuditResult};
pub use case::{Case, CaseClassification, CaseStatus};
pub use entity::{canonical, Entity, EntityKind};
pub use event::{Event, EventKind, EventParticipant, ParticipantRole};
pub use evidence::{
    Evidence, EvidenceKind, EvidenceRelation, EvidenceRelationKind, EvidenceSupport,
};
pub use finding::{Finding, FindingCategory, FindingDisposition, FindingPriority, FindingStatus};
pub use ids::{
    ActorId, AnalysisRunId, ArtifactId, AuditEventId, CaseId, EntityId, EventId, EvidenceId,
    EvidenceRelationId, FindingId, JobId, ObservationId, RelationshipId, RoleId, TagId,
    WarRoomEntryId,
};
pub use job::{Job, JobKind, JobStatus};
pub use observation::{Observation, ObservationKind};
pub use provenance::{
    DerivationKind, ObjectRef, ParserIdentity, ProvenanceLink, ProvenanceRef, ProvenanceRole,
    ShadowCopyRef, SourceLocator,
};
pub use relationship::{Relationship, RelationshipKind};
pub use time::{ForensicTime, TimePrecision, TimeSemantics};
pub use user::{role_templates, Permission, Role, User, UserKind, UserStatus};
pub use war_room::{WarRoomEntry, WarRoomEntryKind};
