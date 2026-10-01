//! Beziehung: eine längerfristige oder semantische Verbindung zwischen zwei
//! Entitäten. Zeitliche Handlungen (ausgeführt, angelegt, gelöscht) sind
//! Ereignisse; die Oberfläche darf daraus vereinfachte Kanten ableiten.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::{CaseId, EntityId, RelationshipId};
use crate::provenance::DerivationKind;

/// Beziehungsarten (Ontologie der Zielarchitektur), in JSON wie dort in
/// Großbuchstaben, z. B. `SAME_AS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationshipKind {
    /// Identität: dieselbe Entität.
    SameAs,
    /// Identität: möglicherweise dieselbe (unsichere Zusammenführung).
    PossiblySameAs,
    /// Identität: Alias.
    Aliases,
    /// Besitz.
    Owns,
    /// Zugehörigkeit.
    BelongsTo,
    /// Mitgliedschaft.
    MemberOf,
    /// Konto auf einem Rechner.
    AccountOn,
    /// Administrator von.
    AdminOf,
    /// Nutzt.
    Uses,
    /// Enthält.
    Contains,
    /// Hat Datenstrom.
    HasStream,
    /// Hat Hash.
    HasHash,
    /// Signiert von.
    SignedBy,
    /// Liegt auf.
    LocatedOn,
    /// Extrahiert aus.
    ExtractedFrom,
    /// Verweist auf.
    References,
    /// Elternprozess von.
    ParentOf,
    /// Führt aus.
    Executes,
    /// Lädt.
    Loads,
    /// Nutzt Datei.
    UsesFile,
    /// Wird aufgelöst zu.
    ResolvesTo,
    /// Verbindet sich mit.
    ConnectsTo,
    /// Kommuniziert mit.
    CommunicatesWith,
    /// Gehostet auf.
    HostedOn,
    /// Installiert auf.
    InstalledOn,
    /// Läuft auf.
    RunsOn,
    /// Hängt ab von.
    DependsOn,
    /// Passt zu Indikator.
    MatchesIndicator,
    /// Deutet hin auf.
    Indicates,
    /// Zugeschrieben.
    AttributedTo,
    /// Nutzt Schadsoftware.
    UsesMalware,
    /// Nutzt Werkzeug.
    UsesTool,
    /// Zielt auf.
    Targets,
    /// In Bezug zu.
    RelatedTo,
    /// Abgeleitet aus.
    DerivedFrom,
    /// Gestützt durch.
    SupportedBy,
    /// Bestätigt.
    Corroborates,
    /// Widerspricht.
    Contradicts,
    /// Korreliert mit.
    CorrelatedWith,
}

impl RelationshipKind {
    /// Name wie in JSON (für IDs).
    pub fn as_str(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

/// Eine Beziehung.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    /// Deterministische ID aus Fall, Art, Quelle und Ziel.
    pub id: RelationshipId,
    /// Fall.
    pub case_id: CaseId,
    /// Quelle.
    pub source_entity_id: EntityId,
    /// Ziel.
    pub target_entity_id: EntityId,
    /// Art.
    pub kind: RelationshipKind,
    /// Ableitungsstatus.
    pub derivation: DerivationKind,
    /// Gültig ab (Artefaktzeit).
    pub valid_from: Option<DateTime<Utc>>,
    /// Gültig bis (Artefaktzeit).
    pub valid_until: Option<DateTime<Utc>>,
    /// Weitere Angaben.
    pub attributes: JsonValue,
}

impl Relationship {
    /// Beziehung mit ID aus Fall, Art, Quelle und Ziel.
    pub fn new(
        case_id: CaseId,
        kind: RelationshipKind,
        source: EntityId,
        target: EntityId,
        derivation: DerivationKind,
    ) -> Self {
        Self {
            id: RelationshipId::derive(case_id, &kind.as_str(), source, target),
            case_id,
            source_entity_id: source,
            target_entity_id: target,
            kind,
            derivation,
            valid_from: None,
            valid_until: None,
            attributes: JsonValue::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn schreibweise_wie_in_der_ontologie() {
        assert_eq!(
            RelationshipKind::PossiblySameAs.as_str(),
            "POSSIBLY_SAME_AS"
        );
        assert_eq!(RelationshipKind::AccountOn.as_str(), "ACCOUNT_ON");
        let fall = CaseId(Uuid::from_u128(1));
        let r = Relationship::new(
            fall,
            RelationshipKind::HasHash,
            EntityId(Uuid::from_u128(2)),
            EntityId(Uuid::from_u128(3)),
            DerivationKind::Derived,
        );
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["kind"], "HAS_HASH");
        assert_eq!(j["derivation"], "derived");
        assert_eq!(serde_json::from_value::<Relationship>(j).unwrap(), r);
    }
}
