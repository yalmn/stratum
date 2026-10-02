//! Gegen eine echte PostgreSQL, nur mit gesetztem `STRATUM_DB_URL` (etwa
//! `postgres://stratum@127.0.0.1:5432/stratum`), Passwort optional aus der
//! Datei in `STRATUM_DB_PASSWORT_DATEI`.

use stratum_analysis::RawFinding;
use stratum_model::{
    ActorId, Case, CaseClassification, CaseId, DerivationKind, Evidence, EvidenceId, EvidenceKind,
    EvidenceRelation, EvidenceRelationId, EvidenceRelationKind, EvidenceSupport, Finding,
    FindingCategory, FindingDisposition, FindingId, FindingPriority, FindingStatus,
};
use stratum_normalize::{normalisieren, Kontext};
use stratum_store::{Datenbank, LaufAngaben, LaufStand, StoreError};

fn url() -> Option<String> {
    std::env::var("STRATUM_DB_URL").ok()
}

fn kontext() -> Kontext {
    Kontext {
        // Eigener Fall je Testlauf, damit Läufe sich nicht berühren.
        case_id: CaseId(uuid::Uuid::now_v7()),
        evidence_id: EvidenceId(uuid::Uuid::now_v7()),
        evidence_sha256: "a".repeat(64),
        host: Some("TESTRECHNER".into()),
        stratum_version: "test".into(),
        zeitpunkt: chrono::DateTime::from_timestamp(0, 0).unwrap(),
    }
}

fn funde() -> Vec<RawFinding> {
    let mut a = RawFinding::new(
        "eventlog",
        "Anmeldung erfolgreich",
        "Windows\\System32\\winevt\\Logs\\Security.evtx",
    );
    for (k, v) in [
        ("event_id", "4624"),
        ("event_record_id", "1"),
        ("filetime", "134209790846680107"),
        ("anbieter", "Microsoft-Windows-Security-Auditing"),
        ("benutzer", "ich"),
        ("benutzer_sid", "S-1-5-21-1-2-3-1001"),
        ("volume_offset", "122683392"),
        ("mft_record", "39938"),
        ("mft_record_offset", "3384805376"),
        ("datei_offset", "69632"),
    ] {
        a = a.with(k, v);
    }
    a.id = "0123456789abcdef".into();
    let mut b = RawFinding::new(
        "usb",
        "{fff43352-3b0a-11f1-b1a1-806e6f6e6963}",
        "HKCU ich\\MountPoints2",
    )
    .with("art", "mount_point")
    .with("benutzer", "ich")
    .with("hive_offset", "1");
    b.id = "fedcba9876543210".into();
    vec![a, b]
}

fn fall(k: &Kontext) -> Case {
    Case {
        id: k.case_id,
        case_number: format!("TEST-{}", k.case_id),
        title: "Test".into(),
        description: None,
        status: stratum_model::CaseStatus::Active,
        classification: CaseClassification::Internal,
        created_at: k.zeitpunkt,
        created_by: ActorId::new(),
        opened_at: None,
        closed_at: None,
        timezone: None,
        case_folder: Some("/faelle/test".into()),
        tags: Vec::new(),
    }
}

fn evidence(k: &Kontext, id: EvidenceId, sha256: &str, kind: EvidenceKind) -> Evidence {
    Evidence {
        id,
        case_id: k.case_id,
        kind,
        name: "merged.dd".into(),
        role: Some("Arbeitsplatz".into()),
        original_name: None,
        source_uri: "/faelle/test/merged.dd".into(),
        size: 85_899_345_920,
        sha256: sha256.into(),
        blake3: "b".repeat(64),
        acquired_at: None,
        imported_at: k.zeitpunkt,
        imported_by: ActorId::new(),
        acquisition_method: None,
        read_only: true,
        support: EvidenceSupport::Recognized,
        parent_evidence_id: None,
        metadata: serde_json::json!({"bdp_info": "bdp.info"}),
    }
}

fn finding(k: &Kontext, derivation: DerivationKind, m: &stratum_normalize::Modell) -> Finding {
    Finding {
        id: FindingId::new(),
        case_id: k.case_id,
        title: "Anmeldung".into(),
        description: None,
        category: FindingCategory::UserActivity,
        status: FindingStatus::New,
        priority: FindingPriority::Low,
        disposition: FindingDisposition::Unknown,
        derivation,
        entity_refs: Vec::new(),
        event_refs: vec![m.events[0].id],
        artifact_refs: vec![m.artifacts[0].id],
        created_at: k.zeitpunkt,
        created_by: ActorId::new(),
        updated_at: k.zeitpunkt,
    }
}

async fn verbinden() -> Option<Datenbank> {
    let Some(url) = url() else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return None;
    };
    // cargo test läuft im Ordner des Crates; ein relativer Pfad ist wie bei
    // stratum selbst vom Projektverzeichnis aus gemeint.
    let passwort = std::env::var_os("STRATUM_DB_PASSWORT_DATEI").map(|p| {
        let p = std::path::PathBuf::from(p);
        let p = if p.is_relative() {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(p)
        } else {
            p
        };
        std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("Passwortdatei {} nicht lesbar: {e}", p.display()))
            .trim()
            .to_string()
    });
    Some(
        Datenbank::verbinden_mit(&url, passwort.as_deref())
            .await
            .expect("Verbindung"),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn modell_schreiben_und_wiederholen() {
    let Some(db) = verbinden().await else {
        return;
    };
    let k = kontext();
    let m = normalisieren(&funde(), &k);
    let konfiguration = serde_json::json!({"keywords": false});
    let angaben = LaufAngaben {
        started_at: k.zeitpunkt,
        configuration: &konfiguration,
        configuration_hash: Some("c0ffee"),
        model_sha256: Some("abc"),
    };

    assert!(db.fall_anlegen(&fall(&k)).await.unwrap());
    assert!(!db.fall_anlegen(&fall(&k)).await.unwrap());
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    assert!(db.evidence_registrieren(&ev).await.unwrap());
    assert!(!db.evidence_registrieren(&ev).await.unwrap());
    // Gleiche ID mit anderem Inhalt: abgelehnt, nichts verändert.
    let falsch = evidence(
        &k,
        k.evidence_id,
        &"f".repeat(64),
        EvidenceKind::RawDiskImage,
    );
    assert!(matches!(
        db.evidence_registrieren(&falsch).await,
        Err(StoreError::EvidenceAbweichung { .. })
    ));

    let erst = db.modell_speichern(&k, &m, &angaben).await.unwrap();
    assert_eq!(erst.artefakte, m.artifacts.len() as u64);
    assert_eq!(erst.ereignisse, m.events.len() as u64);
    assert_eq!(erst.beteiligungen, m.participants.len() as u64);
    assert_eq!(erst.beziehungen, m.relationships.len() as u64);
    assert_eq!(erst.herkunftsangaben, m.provenance.len() as u64);

    // Zweiter Lauf: dieselben IDs, nichts kommt doppelt hinzu.
    let zweit = db.modell_speichern(&k, &m, &angaben).await.unwrap();
    assert_eq!(zweit.artefakte, 0);
    assert_eq!(zweit.ereignisse, 0);
    assert_eq!(zweit.beteiligungen, 0);
    assert_eq!(zweit.herkunftsangaben, 0);
    let zahlen = db.zaehlen(k.case_id.0).await.unwrap();
    assert!(zahlen.contains(&("event".to_string(), m.events.len() as i64)));

    // Fundstelle der Herkunft entfällt in der Tabelle, die View setzt sie ein.
    let gespeichert: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT p.source_locator FROM provenance p JOIN event e ON e.id = p.object_id \
         WHERE e.case_id = $1 LIMIT 1",
    )
    .bind(k.case_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(gespeichert.is_none());
    let voll: serde_json::Value = sqlx::query_scalar(
        "SELECT p.source_locator FROM provenance_full p JOIN event e ON e.id = p.object_id \
         WHERE e.case_id = $1 LIMIT 1",
    )
    .bind(k.case_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(voll["mft_record"], 39938);

    // Sortierspalte auf die Mikrosekunde (Grenze von timestamptz), die
    // verlustfreie Zeit mit FILETIME-Original steht in occurred_at.
    let (utc, original): (chrono::DateTime<chrono::Utc>, String) = sqlx::query_as(
        "SELECT occurred_utc, occurred_at->>'original' FROM event WHERE case_id = $1 LIMIT 1",
    )
    .bind(k.case_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(utc.to_rfc3339(), "2026-04-18T09:44:44.668011+00:00");
    assert_eq!(original, "134209790846680107");
}

#[tokio::test(flavor = "current_thread")]
async fn lauf_finding_und_evidence_beziehung() {
    let Some(db) = verbinden().await else {
        return;
    };
    let k = kontext();
    let m = normalisieren(&funde(), &k);
    let konfiguration = serde_json::json!({});
    let angaben = LaufAngaben {
        started_at: k.zeitpunkt,
        configuration: &konfiguration,
        configuration_hash: None,
        model_sha256: None,
    };
    db.fall_anlegen(&fall(&k)).await.unwrap();
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    db.evidence_registrieren(&ev).await.unwrap();

    // Ohne registrierte Evidence kein Lauf.
    let mut fremd = kontext();
    fremd.case_id = k.case_id;
    assert!(db.modell_speichern(&fremd, &m, &angaben).await.is_err());

    let g = db.modell_speichern(&k, &m, &angaben).await.unwrap();
    let ende = k.zeitpunkt + chrono::Duration::seconds(5);
    db.lauf_abschliessen(g.lauf_id, LaufStand::Completed, ende, Some("d00d"))
        .await
        .unwrap();
    let (stand, bericht, support): (String, String, String) = sqlx::query_as(
        "SELECT r.status, r.report_sha256, e.support FROM analysis_run r \
         JOIN evidence e ON e.id = r.evidence_id WHERE r.id = $1",
    )
    .bind(g.lauf_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        (stand.as_str(), bericht.as_str(), support.as_str()),
        ("completed", "d00d", "analyzed")
    );
    // Ein abgeschlossener Lauf lässt sich nicht noch einmal beenden.
    assert!(db
        .lauf_abschliessen(g.lauf_id, LaufStand::Failed, ende, None)
        .await
        .is_err());

    // Finding mit Belegen aus diesem Fall.
    db.finding_speichern(&finding(&k, DerivationKind::AnalystAsserted, &m))
        .await
        .unwrap();
    // Beleg aus einem anderen Fall: abgelehnt, nichts geschrieben.
    let mut fremdes = finding(&k, DerivationKind::AnalystAsserted, &m);
    fremdes.event_refs = vec![stratum_model::EventId(uuid::Uuid::now_v7())];
    assert!(matches!(
        db.finding_speichern(&fremdes).await,
        Err(StoreError::FindingBeleg(1))
    ));
    // Vorschlag eines Sprachmodells wird nie von selbst ein Finding.
    assert!(db
        .finding_speichern(&finding(&k, DerivationKind::AiSuggested, &m))
        .await
        .is_err());
    let zahlen = db.zaehlen(k.case_id.0).await.unwrap();
    assert!(zahlen.contains(&("finding".to_string(), 1)));

    // E01 mit denselben Mediendaten: von selbst als gleiche Quelle verknüpft.
    let e01 = evidence(
        &k,
        EvidenceId::new(),
        &k.evidence_sha256,
        EvidenceKind::E01Image,
    );
    db.evidence_registrieren(&e01).await.unwrap();
    let (art, herkunft): (String, String) = sqlx::query_as(
        "SELECT kind, derivation FROM evidence_relation WHERE source_evidence_id = $1 \
         AND target_evidence_id = $2",
    )
    .bind(e01.id.0)
    .bind(k.evidence_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        (art.as_str(), herkunft.as_str()),
        ("SAME_SOURCE", "derived")
    );
    // Zusätzlich vom Analysten: das Rohimage ist aus dem E01 entpackt.
    let r = EvidenceRelation {
        id: EvidenceRelationId::new(),
        case_id: k.case_id,
        source_evidence_id: k.evidence_id,
        target_evidence_id: e01.id,
        kind: EvidenceRelationKind::DerivedFrom,
        derivation: DerivationKind::AnalystAsserted,
        note: Some("mit ewfexport entpackt".into()),
        created_at: k.zeitpunkt,
        created_by: None,
    };
    assert!(db.evidence_beziehung(&r).await.unwrap());
    assert!(!db.evidence_beziehung(&r).await.unwrap());
    // Evidence eines anderen Falls lässt sich nicht verknüpfen.
    let k2 = kontext();
    db.fall_anlegen(&fall(&k2)).await.unwrap();
    let anderer = evidence(&k2, k2.evidence_id, &k2.evidence_sha256, EvidenceKind::Pcap);
    db.evidence_registrieren(&anderer).await.unwrap();
    let quer = EvidenceRelation {
        id: EvidenceRelationId::new(),
        target_evidence_id: anderer.id,
        ..r
    };
    assert!(db.evidence_beziehung(&quer).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn uebernommene_evidence_wird_einmal_vervollstaendigt() {
    let Some(db) = verbinden().await else {
        return;
    };
    let k = kontext();
    db.fall_anlegen(&fall(&k)).await.unwrap();
    // Platzhalter wie aus Migration 0002.
    sqlx::query(
        "INSERT INTO evidence (id, case_id, kind, name, source_uri, sha256, imported_at, \
         support, metadata) VALUES ($1, $2, 'other', 'übernommen', 'unbekannt', $3, now(), \
         'analyzed', '{\"uebernommen\": \"analysis_run\"}')",
    )
    .bind(k.evidence_id.0)
    .bind(k.case_id.0)
    .bind(&k.evidence_sha256)
    .execute(db.pool())
    .await
    .unwrap();
    // Anderer Inhalt unter derselben ID: abgelehnt, Platzhalter bleibt.
    let falsch = evidence(
        &k,
        k.evidence_id,
        &"f".repeat(64),
        EvidenceKind::RawDiskImage,
    );
    assert!(matches!(
        db.evidence_registrieren(&falsch).await,
        Err(StoreError::EvidenceAbweichung { .. })
    ));
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    assert!(!db.evidence_registrieren(&ev).await.unwrap());
    let (art, groesse, support): (String, i64, String) =
        sqlx::query_as("SELECT kind, size, support FROM evidence WHERE id = $1")
            .bind(k.evidence_id.0)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        (art.as_str(), groesse, support.as_str()),
        ("raw_disk_image", 85_899_345_920, "analyzed")
    );
    // Danach unveränderlich wie jede Evidence.
    let anders = Evidence {
        name: "anders".into(),
        ..ev
    };
    db.evidence_registrieren(&anders).await.unwrap();
    let name: String = sqlx::query_scalar("SELECT name FROM evidence WHERE id = $1")
        .bind(k.evidence_id.0)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(name, "merged.dd");
}
