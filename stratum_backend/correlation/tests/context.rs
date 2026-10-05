//! Synthetische Quellbytes und negative Kontrollfälle für Kontextzuordnungen.
use stratum_correlation::{evaluate, Trace};
use stratum_model::{
    ArtifactId, CaseId, DerivationKind, EvidenceId, ForensicTime, ParserIdentity, ProvenanceRef,
    SourceLocator, TimePrecision, TimeSemantics,
};
use uuid::Uuid;
fn trace(id: u128, seconds: i64) -> Trace {
    Trace {
        event_id: Uuid::from_u128(id),
        kind: "process_start".into(),
        entity_id: Uuid::from_u128(10),
        entity_kind: "file".into(),
        role: "executable".into(),
        host_id: Uuid::from_u128(20),
        snapshot: None,
        time: ForensicTime::from_unix(seconds, TimeSemantics::EventTime).unwrap(),
        derivation: DerivationKind::Parsed,
        source: ProvenanceRef {
            evidence_id: EvidenceId(Uuid::from_u128(30)),
            artifact_id: Some(ArtifactId(Uuid::from_u128(100 + id))),
            observation_id: None,
            source_locator: Some(SourceLocator::ByteRange {
                offset: id as u64 * 16,
                length: Some(16),
            }),
            parser: Some(ParserIdentity {
                name: format!("fixture-{id}"),
                version: "1".into(),
                stratum_version: "test".into(),
                config_hash: None,
            }),
            analysis_run_id: None,
        },
    }
}
fn run(a: Trace, b: Trace) -> usize {
    evaluate(CaseId(Uuid::from_u128(1)), vec![a, b])
        .matches
        .len()
}
#[test]
fn quellbytes_und_reproduzierbare_zuordnung() {
    let image = b"0000000000000000execution-one!!!execution-two!!!".to_vec();
    let before = image.clone();
    let a = trace(1, 100);
    let b = trace(2, 102);
    let r = evaluate(CaseId(Uuid::from_u128(1)), vec![b.clone(), a.clone()]);
    assert_eq!(r.matches.len(), 1);
    assert_eq!(r.matches[0].derivation, DerivationKind::Correlated);
    for t in &r.matches[0].traces {
        if let Some(SourceLocator::ByteRange {
            offset,
            length: Some(length),
        }) = &t.source.source_locator
        {
            let bytes = &image[*offset as usize..(*offset + length) as usize];
            assert_eq!(
                bytes,
                if *offset == 16 {
                    b"execution-one!!!"
                } else {
                    b"execution-two!!!"
                }
            );
        } else {
            panic!("Quellbereich fehlt");
        }
    }
    assert_eq!(image, before);
    let repeated = evaluate(
        CaseId(Uuid::from_u128(1)),
        vec![a.clone(), b.clone(), a.clone()],
    );
    assert_eq!(repeated.matches.len(), 1);
    assert_eq!(repeated.matches[0].id, r.matches[0].id);
    assert_ne!(
        evaluate(CaseId(Uuid::from_u128(2)), vec![a, b]).matches[0].id,
        r.matches[0].id
    );
}
#[test]
fn kontextgrenzen_verhindern_fehlzuordnung() {
    let a = trace(1, 100);
    for field in [
        "entity",
        "host",
        "evidence",
        "artifact",
        "parser",
        "time",
        "derivation",
        "precision",
        "anchor",
    ] {
        let mut b = trace(2, 102);
        match field {
            "entity" => b.entity_id = Uuid::from_u128(11),
            "host" => b.host_id = Uuid::from_u128(21),
            "evidence" => b.source.evidence_id = EvidenceId(Uuid::from_u128(31)),
            "artifact" => b.source.artifact_id = a.source.artifact_id,
            "parser" => b.source.parser.as_mut().unwrap().name = "fixture-1".into(),
            "time" => b.time.semantics = TimeSemantics::AnalysisTime,
            "derivation" => b.derivation = DerivationKind::Reconstructed,
            "precision" => b.time.precision = TimePrecision::Minute,
            "anchor" => b.source.source_locator = None,
            _ => unreachable!(),
        }
        assert_eq!(run(a.clone(), b), 0, "{field}");
    }
}
#[test]
fn grenze_mit_voller_zeitpräzision() {
    let a = trace(1, 100);
    let mut b = trace(2, 102);
    b.time.utc = "1970-01-01T00:01:42.000000001Z".parse().unwrap();
    assert_eq!(run(a, b), 0);
}
#[test]
fn persistenz_und_netzwerk_nur_im_passenden_kontext() {
    let mut a = trace(1, 100);
    let mut b = trace(2, 200);
    a.entity_kind = "service".into();
    b.entity_kind = "service".into();
    a.kind = "service_installed".into();
    b.kind = "service_started".into();
    assert_eq!(run(a.clone(), b.clone()), 1);
    b.time = ForensicTime::from_unix(99, TimeSemantics::EventTime).unwrap();
    assert_eq!(run(a, b), 0);
    let mut a = trace(1, 100);
    let mut b = trace(2, 400);
    for t in [&mut a, &mut b] {
        t.entity_kind = "process".into();
        t.role = "process".into();
    }
    b.kind = "network_connection".into();
    assert_eq!(run(a.clone(), b.clone()), 1);
    b.time = ForensicTime::from_unix(401, TimeSemantics::EventTime).unwrap();
    assert_eq!(run(a, b), 0);
}
#[test]
fn schattenstände_nicht_vermischen() {
    let mut a = trace(1, 100);
    let mut b = trace(2, 102);
    let locator = |shadow_copy| SourceLocator::Ntfs {
        volume_offset: 0,
        mft_record: 42,
        sequence: None,
        stream: None,
        record_offset: Some(4096),
        byte_offset: None,
        image_offset: None,
        shadow_copy,
    };
    a.source.source_locator = Some(locator(None));
    b.source.source_locator = Some(locator(None));
    assert_eq!(run(a.clone(), b.clone()), 1);
    b.source.source_locator = Some(locator(Some(stratum_model::ShadowCopyRef {
        store: 0,
        store_id: None,
    })));
    assert_eq!(run(a, b), 0);
}
#[test]
fn dichte_daten_erreichen_sichtbare_schutzgrenze() {
    let rows = (1..=1000).map(|n| trace(n, 100)).collect();
    let result = evaluate(CaseId(Uuid::from_u128(1)), rows);
    assert!(result.limited);
    assert_eq!(result.matches.len(), 500);
    let mut rows = Vec::new();
    for n in 1..=1000 {
        let mut t = trace(n, 100);
        t.source.parser.as_mut().unwrap().name = "same-parser".into();
        rows.push(t);
    }
    let result = evaluate(CaseId(Uuid::from_u128(1)), rows);
    assert!(result.limited);
    assert_eq!(result.comparisons, 200000);
    assert!(result.matches.is_empty());
}
