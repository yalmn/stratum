//! Eine vollständige Kette von der Evidence bis zum Finding, wie sie der
//! Normalizer später aus einem EVTX-Datensatz bilden soll: IDs sind
//! reproduzierbar, Herkunft reicht bis zur Byte-Stelle, alles übersteht den
//! Weg über JSON unverändert.

use chrono::DateTime;
use serde_json::json;
use stratum_model::*;
use uuid::Uuid;

const SHA: &str = "e633f0be5fb9ee9a07d44ba5223b786012ce89e9f0024f93d743568e6d052f16";

struct Kette {
    artifact: Artifact,
    observation: Observation,
    benutzer: Entity,
    host: Entity,
    event: Event,
    teilnehmer: Vec<EventParticipant>,
    beziehung: Relationship,
    herkunft: ProvenanceLink,
}

fn kette(fall: CaseId, evidence: EvidenceId) -> Kette {
    let t = DateTime::from_timestamp(1_776_505_484, 0).unwrap();
    let parser = ParserIdentity {
        name: "windows.eventlog".into(),
        version: "1".into(),
        stratum_version: "0.1.0 (777677f)".into(),
        config_hash: None,
    };
    let fundstelle = SourceLocator::Ntfs {
        volume_offset: 122_683_392,
        mft_record: 109_300,
        sequence: Some(1),
        stream: None,
        record_offset: None,
        byte_offset: Some(69_632),
        image_offset: Some(4_812_345_344),
        shadow_copy: None,
    };
    let artifact = Artifact {
        id: ArtifactId::derive(fall, SHA, "ntfs:122683392:109300:69632"),
        case_id: fall,
        evidence_id: evidence,
        kind: ArtifactKind::EvtxRecord,
        source_locator: fundstelle.clone(),
        parser: parser.clone(),
        raw_metadata: json!({"event_id": 4624, "event_record_id": 42812}),
        created_at: t,
    };
    let observation = Observation {
        id: ObservationId::derive(artifact.id, "user_logon"),
        case_id: fall,
        artifact_id: artifact.id,
        kind: ObservationKind("user_logon".into()),
        fields: json!({"TargetUserSid": "S-1-5-21-1-2-3-1001", "LogonType": 2}),
        parser: parser.clone(),
        observed_at: t,
    };
    let benutzer = Entity::new(
        fall,
        EntityKind::UserAccount,
        canonical::windows_user(Some("S-1-5-21-1-2-3-1001"), None, Some("ich")).unwrap(),
        "ich".into(),
        t,
    );
    let host = Entity::new(
        fall,
        EntityKind::Host,
        "host:desktop-g2lnled".into(),
        "DESKTOP-G2LNLED".into(),
        t,
    );
    let zeit =
        ForensicTime::from_filetime(134_209_790_846_680_107, TimeSemantics::EventTime).unwrap();
    let event = Event {
        id: EventId::derive(
            fall,
            "user_logon",
            &format!("evtx:42812:{}", zeit.original.as_deref().unwrap()),
        ),
        case_id: fall,
        kind: EventKind::UserLogon,
        occurred_at: Some(zeit),
        ended_at: None,
        attributes: json!({"logon_type": 2}),
        derivation: DerivationKind::Parsed,
        created_at: t,
    };
    let teilnehmer = vec![
        EventParticipant {
            event_id: event.id,
            entity_id: benutzer.id,
            role: ParticipantRole::User,
        },
        EventParticipant {
            event_id: event.id,
            entity_id: host.id,
            role: ParticipantRole::Host,
        },
    ];
    let beziehung = Relationship::new(
        fall,
        RelationshipKind::AccountOn,
        benutzer.id,
        host.id,
        DerivationKind::Derived,
    );
    let herkunft = ProvenanceLink {
        object: ObjectRef::Event(event.id),
        provenance: ProvenanceRef {
            evidence_id: evidence,
            artifact_id: Some(artifact.id),
            observation_id: Some(observation.id),
            source_locator: Some(fundstelle),
            parser: Some(parser),
            analysis_run_id: None,
        },
        role: ProvenanceRole::Primary,
    };
    Kette {
        artifact,
        observation,
        benutzer,
        host,
        event,
        teilnehmer,
        beziehung,
        herkunft,
    }
}

fn rund<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(x: &T) {
    let j = serde_json::to_string(x).unwrap();
    assert_eq!(&serde_json::from_str::<T>(&j).unwrap(), x);
}

#[test]
fn kette_ist_reproduzierbar_und_rundlaufend() {
    let fall = CaseId(Uuid::from_u128(0x0196_0000_0000_7000_8000_0000_0000_0001));
    // Zwei Importe derselben Evidence in denselben Fall: abgeleitete IDs gleich.
    let a = kette(fall, EvidenceId::new());
    let b = kette(fall, EvidenceId::new());
    assert_eq!(a.artifact.id, b.artifact.id);
    assert_eq!(a.observation.id, b.observation.id);
    assert_eq!(a.benutzer.id, b.benutzer.id);
    assert_eq!(a.event.id, b.event.id);
    assert_eq!(a.beziehung.id, b.beziehung.id);
    // Anderer Fall: andere IDs.
    let c = kette(CaseId::new(), EvidenceId::new());
    assert_ne!(a.artifact.id, c.artifact.id);
    assert_ne!(a.benutzer.id, c.benutzer.id);

    rund(&a.artifact);
    rund(&a.observation);
    rund(&a.benutzer);
    rund(&a.host);
    rund(&a.event);
    rund(&a.teilnehmer);
    rund(&a.beziehung);
    rund(&a.herkunft);

    // Von der Beziehung über das Ereignis bis zur Byte-Stelle.
    assert_eq!(a.herkunft.object, ObjectRef::Event(a.event.id));
    let Some(SourceLocator::Ntfs {
        image_offset,
        byte_offset,
        ..
    }) = &a.herkunft.provenance.source_locator
    else {
        panic!("Fundstelle fehlt");
    };
    assert_eq!(
        (*image_offset, *byte_offset),
        (Some(4_812_345_344), Some(69_632))
    );
    assert!(!a.event.derivation.is_interpretation());
    assert!(DerivationKind::Correlated.is_interpretation());
}

/// Schichtenregel: das Modell hängt von keinem Backend-Crate ab.
#[test]
fn modell_haengt_von_keinem_backend_crate_ab() {
    let toml = include_str!("../Cargo.toml");
    let abhaengigkeiten = toml.split("[dependencies]").nth(1).unwrap_or("");
    assert!(
        !abhaengigkeiten.contains("stratum-"),
        "stratum-model darf keine stratum-Crates einbinden"
    );
}
