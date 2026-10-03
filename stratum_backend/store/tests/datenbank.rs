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

/// Handelnder Akteur in den Tests: das feste Konto der Kommandozeile.
fn a() -> ActorId {
    ActorId::cli()
}

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
        created_by: ActorId::cli(),
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
        imported_by: ActorId::cli(),
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
        created_by: ActorId::cli(),
        updated_at: k.zeitpunkt,
    }
}

fn passwort() -> Option<String> {
    // cargo test läuft im Ordner des Crates; ein relativer Pfad ist wie bei
    // stratum selbst vom Projektverzeichnis aus gemeint.
    std::env::var_os("STRATUM_DB_PASSWORT_DATEI").map(|p| {
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
    })
}

/// Eigentümer-Verbindung zur Datenbank aus `url` (Migrationen, Trigger-Tests).
async fn eigentuemer(url: &str) -> sqlx::PgConnection {
    use sqlx::Connection as _;
    let mut o: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
    if let Some(p) = passwort() {
        o = o.password(&p);
    }
    sqlx::PgConnection::connect_with(&o).await.unwrap()
}

/// Eigene, frische Datenbank für Tests, die die ganze Audit-Kette prüfen
/// oder absichtlich beschädigen. Liefert Verbindung, URL und Namen.
async fn frische_datenbank() -> Option<(Datenbank, String, String)> {
    use sqlx::Executor as _;
    let url = url()?;
    let name = format!("stratum_test_{}", uuid::Uuid::now_v7().simple());
    let mut o = eigentuemer(&url).await;
    // Name aus einer UUID, kein fremder Text.
    let sql = format!("CREATE DATABASE {name}");
    o.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql)))
        .await
        .unwrap();
    let (basis, _) = url.rsplit_once('/').unwrap();
    let neu = format!("{basis}/{name}");
    let db = Datenbank::verbinden_mit(&neu, passwort().as_deref())
        .await
        .expect("Verbindung");
    Some((db, neu, name))
}

async fn frische_datenbank_entfernen(db: Datenbank, name: &str) {
    use sqlx::Executor as _;
    db.pool().close().await;
    let mut o = eigentuemer(&url().unwrap()).await;
    let sql = format!("DROP DATABASE {name} WITH (FORCE)");
    o.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql)))
        .await
        .unwrap();
}

/// Wegwerf-Datenbank eines Tests; wird beim Verlassen entfernt, auch wenn
/// der Test scheitert. So bleiben in der eigentlichen Datenbank keine
/// Testfälle zurück.
struct Wegwerf {
    db: Datenbank,
    name: String,
}

impl std::ops::Deref for Wegwerf {
    type Target = Datenbank;
    fn deref(&self) -> &Datenbank {
        &self.db
    }
}

impl Drop for Wegwerf {
    fn drop(&mut self) {
        // Eigene Laufzeit in einem eigenen Thread: Drop ist synchron und
        // läuft auch beim Abwickeln nach einem fehlgeschlagenen Test.
        let name = std::mem::take(&mut self.name);
        let _ = std::thread::spawn(move || {
            use sqlx::Executor as _;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut o = eigentuemer(&url().unwrap()).await;
                let sql = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
                o.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql)))
                    .await
                    .unwrap();
            });
        })
        .join();
    }
}

async fn verbinden() -> Option<Wegwerf> {
    let Some((db, _, name)) = frische_datenbank().await else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return None;
    };
    Some(Wegwerf { db, name })
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
        audit_details: serde_json::json!({}),
    };

    assert!(db.fall_anlegen(a(), &fall(&k)).await.unwrap());
    assert!(!db.fall_anlegen(a(), &fall(&k)).await.unwrap());
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    assert!(db.evidence_registrieren(a(), &ev).await.unwrap());
    assert!(!db.evidence_registrieren(a(), &ev).await.unwrap());
    // Gleiche ID mit anderem Inhalt: abgelehnt, nichts verändert.
    let falsch = evidence(
        &k,
        k.evidence_id,
        &"f".repeat(64),
        EvidenceKind::RawDiskImage,
    );
    assert!(matches!(
        db.evidence_registrieren(a(), &falsch).await,
        Err(StoreError::EvidenceAbweichung { .. })
    ));

    let lauf = db.lauf_beginnen(a(), &k, &angaben).await.unwrap();
    let erst = db.modell_speichern(lauf, &m, Some("abc")).await.unwrap();
    assert_eq!(erst.artefakte, m.artifacts.len() as u64);
    assert_eq!(erst.ereignisse, m.events.len() as u64);
    assert_eq!(erst.beteiligungen, m.participants.len() as u64);
    assert_eq!(erst.beziehungen, m.relationships.len() as u64);
    assert_eq!(erst.herkunftsangaben, m.provenance.len() as u64);

    // Zweiter Lauf: dieselben IDs, nichts kommt doppelt hinzu.
    let lauf = db.lauf_beginnen(a(), &k, &angaben).await.unwrap();
    let zweit = db.modell_speichern(lauf, &m, Some("abc")).await.unwrap();
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
        audit_details: serde_json::json!({}),
    };
    db.fall_anlegen(a(), &fall(&k)).await.unwrap();
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    db.evidence_registrieren(a(), &ev).await.unwrap();

    // Ohne registrierte Evidence kein Lauf.
    let mut fremd = kontext();
    fremd.case_id = k.case_id;
    assert!(db.lauf_beginnen(a(), &fremd, &angaben).await.is_err());

    let lauf = db.lauf_beginnen(a(), &k, &angaben).await.unwrap();
    let g = db.modell_speichern(lauf, &m, None).await.unwrap();
    let ende = k.zeitpunkt + chrono::Duration::seconds(5);
    db.lauf_abschliessen(
        a(),
        g.lauf_id,
        LaufStand::Completed,
        ende,
        Some("d00d"),
        None,
    )
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
    // Ein abgeschlossener Lauf lässt sich nicht noch einmal beenden und
    // nimmt nichts mehr an.
    assert!(matches!(
        db.lauf_abschliessen(a(), g.lauf_id, LaufStand::Failed, ende, None, None)
            .await,
        Err(StoreError::LaufNichtAktiv(_))
    ));
    assert!(matches!(
        db.modell_speichern(g.lauf_id, &m, None).await,
        Err(StoreError::LaufNichtAktiv(_))
    ));
    assert!(matches!(
        db.katalog_speichern(g.lauf_id, "[]").await,
        Err(StoreError::LaufNichtAktiv(_))
    ));

    // Finding mit Belegen aus diesem Fall.
    db.finding_speichern(a(), &finding(&k, DerivationKind::AnalystAsserted, &m))
        .await
        .unwrap();
    // Beleg aus einem anderen Fall: abgelehnt, nichts geschrieben.
    let mut fremdes = finding(&k, DerivationKind::AnalystAsserted, &m);
    fremdes.event_refs = vec![stratum_model::EventId(uuid::Uuid::now_v7())];
    assert!(matches!(
        db.finding_speichern(a(), &fremdes).await,
        Err(StoreError::FindingBeleg(1))
    ));
    // Vorschlag eines Sprachmodells wird nie von selbst ein Finding.
    assert!(db
        .finding_speichern(a(), &finding(&k, DerivationKind::AiSuggested, &m))
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
    db.evidence_registrieren(a(), &e01).await.unwrap();
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
    assert!(db.evidence_beziehung(a(), &r).await.unwrap());
    assert!(!db.evidence_beziehung(a(), &r).await.unwrap());
    // Evidence eines anderen Falls lässt sich nicht verknüpfen.
    let k2 = kontext();
    db.fall_anlegen(a(), &fall(&k2)).await.unwrap();
    let anderer = evidence(&k2, k2.evidence_id, &k2.evidence_sha256, EvidenceKind::Pcap);
    db.evidence_registrieren(a(), &anderer).await.unwrap();
    let quer = EvidenceRelation {
        id: EvidenceRelationId::new(),
        target_evidence_id: anderer.id,
        ..r
    };
    assert!(db.evidence_beziehung(a(), &quer).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn uebernommene_evidence_wird_einmal_vervollstaendigt() {
    let Some(db) = verbinden().await else {
        return;
    };
    let k = kontext();
    db.fall_anlegen(a(), &fall(&k)).await.unwrap();
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
        db.evidence_registrieren(a(), &falsch).await,
        Err(StoreError::EvidenceAbweichung { .. })
    ));
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    assert!(!db.evidence_registrieren(a(), &ev).await.unwrap());
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
    db.evidence_registrieren(a(), &anders).await.unwrap();
    let name: String = sqlx::query_scalar("SELECT name FROM evidence WHERE id = $1")
        .bind(k.evidence_id.0)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(name, "merged.dd");
}

/// Zwei Zeilen im Format von `--catalog`, eine davon mit einer Größe, die es
/// in NTFS nicht geben kann.
const KATALOG: &str = r#"[
{"volume_offset":122683392,"mft_record":5,"sequenz":5,"parent_record":5,"typ":"verzeichnis","pfad":"","name":"","si":{"erstellt":"2026-04-18T09:40:47.3257138Z","geaendert":"2026-04-18T09:40:47.3257138Z","mft_geaendert":"2026-04-18T09:40:47.3257138Z","zugriff":"2026-04-18T09:40:47.3257138Z"},"attribute":["versteckt","system"],"hardlinks":1,"mft_record_offset":3343918080},
{"volume_offset":122683392,"mft_record":51283,"sequenz":3,"parent_record":2000,"typ":"datei","pfad":"Windows\\System32\\calc.exe","name":"calc.exe","groesse":49152,"fn":{"erstellt":"2026-04-18T09:41:00.0000001Z"},"streams":[{"name":"WofCompressedData","groesse":20000}],"hardlinks":2,"reparse_tag":"0x80000017","wof":"XPRESS8K","mft_record_offset":3396423680},
{"volume_offset":122683392,"mft_record":77,"parent_record":5,"typ":"datei","pfad":"kaputt","name":"kaputt","groesse":18446744073709551615,"fehler":"Datensatz nicht lesbar"}
]"#;

#[tokio::test(flavor = "current_thread")]
async fn dateikatalog() {
    let Some(db) = verbinden().await else {
        return;
    };
    let k = kontext();
    let konfiguration = serde_json::json!({});
    let angaben = LaufAngaben {
        started_at: k.zeitpunkt,
        configuration: &konfiguration,
        configuration_hash: None,
        audit_details: serde_json::json!({}),
    };
    db.fall_anlegen(a(), &fall(&k)).await.unwrap();
    db.evidence_registrieren(
        a(),
        &evidence(
            &k,
            k.evidence_id,
            &k.evidence_sha256,
            EvidenceKind::RawDiskImage,
        ),
    )
    .await
    .unwrap();
    let lauf = db.lauf_beginnen(a(), &k, &angaben).await.unwrap();
    assert_eq!(db.katalog_speichern(lauf, KATALOG).await.unwrap(), 3);
    assert_eq!(db.katalog_speichern(lauf, KATALOG).await.unwrap(), 0);

    let (verz, zeit, ft, attr, groesse): (bool, String, i64, Vec<String>, Option<i64>) =
        sqlx::query_as(
            "SELECT is_directory, filetime_iso(si_created), si_created, attributes, size \
             FROM file WHERE evidence_id = $1 AND mft_record = 5",
        )
        .bind(k.evidence_id.0)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(verz);
    assert_eq!(zeit, "2026-04-18T09:40:47.3257138Z");
    assert_eq!(ft, 134209788473257138);
    assert_eq!(attr, ["versteckt", "system"]);
    assert_eq!(groesse, None);
    let (pfad, wof, strom): (String, String, i64) = sqlx::query_as(
        "SELECT path, wof, (streams->0->>'groesse')::bigint FROM file \
         WHERE evidence_id = $1 AND mft_record = 51283",
    )
    .bind(k.evidence_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        (pfad.as_str(), wof.as_str(), strom),
        ("Windows\\System32\\calc.exe", "XPRESS8K", 20000)
    );
    let (groesse, fehler): (Option<i64>, String) =
        sqlx::query_as("SELECT size, error FROM file WHERE evidence_id = $1 AND mft_record = 77")
            .bind(k.evidence_id.0)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!((groesse, fehler.as_str()), (None, "Datensatz nicht lesbar"));

    // Späterer Lauf mit Dateiinhalten ergänzt den Hash einmal.
    let mit_hash = KATALOG.replace(
        r#""wof":"XPRESS8K","#,
        r#""wof":"XPRESS8K","sha256":"96b43352","dateityp":"pe","#,
    );
    assert_eq!(db.katalog_speichern(lauf, &mit_hash).await.unwrap(), 0);
    let (hash, typ): (String, String) = sqlx::query_as(
        "SELECT sha256, file_type FROM file WHERE evidence_id = $1 AND mft_record = 51283",
    )
    .bind(k.evidence_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!((hash.as_str(), typ.as_str()), ("96b43352", "pe"));
    let zahlen = db.zaehlen(k.case_id.0).await.unwrap();
    assert!(zahlen.contains(&("file".to_string(), 3)));

    // Kinder eines Verzeichnisses über den Index.
    let kinder: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM file WHERE evidence_id = $1 AND volume_offset = 122683392 \
         AND parent_record = 5 AND mft_record <> 5",
    )
    .bind(k.evidence_id.0)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(kinder, 1);
}

/// Echter Katalog (JSON Lines von `--catalog`) aus `STRATUM_KATALOG_REFERENZ`,
/// in Blöcken wie bei `--db`. Prüft Vollständigkeit und misst die Dauer.
#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn katalog_referenz() {
    let Some(pfad) = std::env::var_os("STRATUM_KATALOG_REFERENZ") else {
        eprintln!("STRATUM_KATALOG_REFERENZ nicht gesetzt, Test übersprungen");
        return;
    };
    let Some(db) = verbinden().await else {
        return;
    };
    let text = std::fs::read_to_string(pfad).unwrap();
    let zeilen: Vec<&str> = text.lines().collect();
    let k = kontext();
    let konfiguration = serde_json::json!({});
    let angaben = LaufAngaben {
        started_at: k.zeitpunkt,
        configuration: &konfiguration,
        configuration_hash: None,
        audit_details: serde_json::json!({}),
    };
    db.fall_anlegen(a(), &fall(&k)).await.unwrap();
    db.evidence_registrieren(
        a(),
        &evidence(
            &k,
            k.evidence_id,
            &k.evidence_sha256,
            EvidenceKind::RawDiskImage,
        ),
    )
    .await
    .unwrap();
    let lauf = db.lauf_beginnen(a(), &k, &angaben).await.unwrap();
    let start = std::time::Instant::now();
    let mut neu = 0;
    let bloecke: Vec<String> = zeilen
        .chunks(16_384)
        .map(|b| format!("[{}]", b.join(",")))
        .collect();
    for block in &bloecke {
        neu += db.katalog_speichern(lauf, block).await.unwrap();
    }
    eprintln!(
        "{} Zeilen, {neu} neu, {:.1} s",
        zeilen.len(),
        start.elapsed().as_secs_f64()
    );
    assert_eq!(neu, zeilen.len() as u64);
    // Jede Zeit kommt als derselbe Text zurück, den der Katalog schrieb.
    for block in &bloecke {
        let falsch: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM jsonb_to_recordset($1::jsonb) AS x(volume_offset bigint, \
             mft_record bigint, parent_record bigint, name text, si jsonb, fn jsonb) \
             JOIN file f ON f.evidence_id = $2 AND f.volume_offset = x.volume_offset \
             AND f.mft_record = x.mft_record AND f.parent_record = x.parent_record \
             AND f.name = x.name \
             WHERE filetime_iso(f.si_created) IS DISTINCT FROM x.si->>'erstellt' \
             OR filetime_iso(f.si_modified) IS DISTINCT FROM x.si->>'geaendert' \
             OR filetime_iso(f.si_mft_modified) IS DISTINCT FROM x.si->>'mft_geaendert' \
             OR filetime_iso(f.si_accessed) IS DISTINCT FROM x.si->>'zugriff' \
             OR filetime_iso(f.fn_created) IS DISTINCT FROM x.fn->>'erstellt' \
             OR filetime_iso(f.fn_modified) IS DISTINCT FROM x.fn->>'geaendert' \
             OR filetime_iso(f.fn_mft_modified) IS DISTINCT FROM x.fn->>'mft_geaendert' \
             OR filetime_iso(f.fn_accessed) IS DISTINCT FROM x.fn->>'zugriff'",
        )
        .bind(block)
        .bind(k.evidence_id.0)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(falsch, 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn filetime_rundlauf() {
    let Some(db) = verbinden().await else {
        return;
    };
    // Grenzwerte: kleinster Wert, Unix-Epoche, fünfstellige Jahre, oberstes
    // Bit gesetzt (in Windows ungültig) und größter Wert.
    for ft in [
        1u64,
        116_444_736_000_000_000,
        134_209_788_473_257_138,
        2_650_467_743_999_999_999,
        (1 << 63) - 1,
        1 << 63,
        u64::MAX,
    ] {
        let iso = stratum_core::time::filetime_to_iso(ft).unwrap();
        let zurueck: String = sqlx::query_scalar("SELECT filetime_iso($1)")
            .bind(ft as i64)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(zurueck, iso);
    }
}

/// Aktionen der Reihe nach im Audit dieser Datenbank.
async fn aktionen(db: &Datenbank) -> Vec<(i64, String, String)> {
    sqlx::query_as("SELECT sequence, action, result FROM audit_event ORDER BY sequence")
        .fetch_all(db.pool())
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn audit_kette_und_rechte() {
    use sqlx::Executor as _;
    let Some((db, url, name)) = frische_datenbank().await else {
        return;
    };
    let k = kontext();
    let konfiguration = serde_json::json!({});
    let angaben = LaufAngaben {
        started_at: k.zeitpunkt,
        configuration: &konfiguration,
        configuration_hash: Some("c0ffee"),
        audit_details: serde_json::json!({"betriebssystem_benutzer": "root"}),
    };
    db.fall_anlegen(a(), &fall(&k)).await.unwrap();
    let ev = evidence(
        &k,
        k.evidence_id,
        &k.evidence_sha256,
        EvidenceKind::RawDiskImage,
    );
    db.evidence_registrieren(a(), &ev).await.unwrap();
    db.evidence_registrieren(a(), &ev).await.unwrap();
    let lauf = db.lauf_beginnen(a(), &k, &angaben).await.unwrap();
    db.lauf_abschliessen(
        a(),
        lauf,
        LaufStand::Completed,
        k.zeitpunkt,
        Some("d00d"),
        Some("/x/report.json"),
    )
    .await
    .unwrap();
    // Abweichender Hash: Aktion scheitert, Prüfung bleibt im Audit.
    let falsch = evidence(
        &k,
        k.evidence_id,
        &"f".repeat(64),
        EvidenceKind::RawDiskImage,
    );
    assert!(db.evidence_registrieren(a(), &falsch).await.is_err());
    let erwartet = [
        "CASE_CREATE",
        "EVIDENCE_IMPORT",
        "EVIDENCE_VERIFY",
        "ANALYSIS_START",
        "ANALYSIS_COMPLETE",
        "REPORT_CREATE",
        "EVIDENCE_VERIFY",
    ];
    let ist = aktionen(&db).await;
    assert_eq!(
        ist.iter().map(|z| z.1.as_str()).collect::<Vec<_>>(),
        erwartet
    );
    assert_eq!(
        ist.iter().map(|z| z.0).collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    assert_eq!(ist[6].2, "failure");
    let start: (String, String) = sqlx::query_as(
        "SELECT details->>'betriebssystem_benutzer', details->>'configuration_hash' \
         FROM audit_event WHERE action = 'ANALYSIS_START'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(start, ("root".to_string(), "c0ffee".to_string()));
    let von: uuid::Uuid = sqlx::query_scalar("SELECT started_by FROM analysis_run WHERE id = $1")
        .bind(lauf.0)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(von, ActorId::cli().0);

    let p = db.audit_pruefen(a()).await.unwrap();
    assert!(p.intakt(), "{:?}", p.fehler);
    assert_eq!(p.ereignisse, 7);

    // Die Anwendung darf nichts löschen und das Audit nicht ändern.
    for sql in [
        "DELETE FROM case_file",
        "DELETE FROM file",
        "UPDATE audit_event SET result = 'success'",
        "DELETE FROM audit_event",
        "UPDATE audit_head SET sequence = 0",
    ] {
        // SQLSTATE 42501: fehlende Berechtigung (unabhängig von der Sprache
        // der Server-Meldungen).
        let fehler = db.pool().execute(sql).await.unwrap_err();
        let code = fehler.as_database_error().and_then(|e| e.code());
        assert_eq!(code.as_deref(), Some("42501"), "{sql}: {fehler}");
    }
    // Auch der Eigentümer kann das Audit nicht ändern, löschen oder leeren.
    let mut o = eigentuemer(&url).await;
    for sql in [
        "UPDATE audit_event SET result = 'success' WHERE sequence = 7",
        "DELETE FROM audit_event WHERE sequence = 8",
        "TRUNCATE audit_event",
    ] {
        let fehler = o.execute(sql).await.unwrap_err().to_string();
        assert!(fehler.contains("unveränderlich"), "{sql}: {fehler}");
    }

    // Mit abgeschaltetem Trigger (nur als Superuser möglich) verändert:
    // das Nachrechnen findet es.
    o.execute("ALTER TABLE audit_event DISABLE TRIGGER audit_kein_aendern")
        .await
        .unwrap();
    o.execute(
        "UPDATE audit_event SET payload = replace(payload, 'failure', 'success'), \
         result = 'success' WHERE sequence = 7",
    )
    .await
    .unwrap();
    let p = db.audit_pruefen(a()).await.unwrap();
    assert!(!p.intakt());
    assert!(
        p.fehler.iter().any(|f| f.contains("Nummer 7: Hash")),
        "{:?}",
        p.fehler
    );
    // Ereignisse am Ende entfernt: der Kopf der Kette verrät es.
    o.execute("DELETE FROM audit_event WHERE sequence >= 8")
        .await
        .unwrap();
    let p = db.audit_pruefen(a()).await.unwrap();
    assert!(
        p.fehler.iter().any(|f| f.contains("Kopf der Kette")),
        "{:?}",
        p.fehler
    );
    drop(o);
    frische_datenbank_entfernen(db, &name).await;
}

#[tokio::test(flavor = "current_thread")]
async fn rollen_registrierung_freigabe() {
    let Some((db, _url, name)) = frische_datenbank().await else {
        return;
    };
    use stratum_model::{role_templates, Permission, RoleId, UserStatus};

    // Mitgelieferte Vorlagen genau wie im Modell.
    let rollen = db.rollen().await.unwrap();
    assert_eq!(rollen.len(), 8);
    for (n, _, rechte) in role_templates() {
        let r = rollen.iter().find(|r| r.name == n).unwrap();
        assert_eq!(r.id, RoleId::template(n));
        let mut soll = rechte.clone();
        soll.sort();
        let mut ist = r.permissions.clone();
        ist.sort();
        assert_eq!(ist, soll, "{n}");
    }
    let analyst = RoleId::template("Analyst");

    // Erste Einrichtung durch die Kommandozeile, danach nicht mehr.
    assert!(matches!(
        db.superadmin_einrichten(a(), "chef", "Chef", "zu-kurz")
            .await,
        Err(StoreError::Passwort(_))
    ));
    let chef = db
        .superadmin_einrichten(a(), "chef", "Chef", "ein langes Passwort")
        .await
        .unwrap();
    assert!(db
        .superadmin_einrichten(a(), "chef2", "Chef", "ein langes Passwort")
        .await
        .is_err());

    // Registrierung: ohne Freigabe keine Anmeldung und keine Rechte.
    let neu = db
        .registrieren("mia", "Mia M.", "noch ein Passwort!")
        .await
        .unwrap();
    assert_eq!(neu.status, UserStatus::Pending);
    assert!(db
        .registrieren("mia", "Doppelt", "noch ein Passwort!")
        .await
        .is_err());
    assert!(db.anmelden("mia", "noch ein Passwort!").await.is_err());
    assert!(db.rechte(neu.id).await.unwrap().is_empty());
    // Nur Superadmins geben frei.
    assert!(db.freigeben(neu.id, neu.id, &[analyst]).await.is_err());
    db.freigeben(chef.id, neu.id, &[analyst]).await.unwrap();
    let mia = db.anmelden("mia", "noch ein Passwort!").await.unwrap();
    assert_eq!(mia.roles, [analyst]);
    assert!(db.berechtigt(mia.id, Permission::FileView).await.unwrap());
    assert!(!db
        .berechtigt(mia.id, Permission::CredentialViewSensitive)
        .await
        .unwrap());
    // Fehlende Berechtigung: abgelehnt und protokolliert.
    let k = kontext();
    let mut f = fall(&k);
    f.created_by = mia.id;
    assert!(matches!(
        db.fall_anlegen(mia.id, &f).await,
        Err(StoreError::Verweigert(_))
    ));

    // Superadmin legt eine eigene Rolle an, ändert und vergibt sie.
    let r = db
        .rolle_anlegen(
            chef.id,
            "Fallführung",
            Some("eigene Rolle"),
            &[Permission::CaseCreate, Permission::CaseView],
        )
        .await
        .unwrap();
    assert!(db
        .rolle_anlegen(chef.id, "Fallführung", None, &[])
        .await
        .is_err());
    assert!(db
        .rolle_anlegen(mia.id, "Eigenbau", None, &[])
        .await
        .is_err());
    db.rolle_aendern(
        chef.id,
        r.id,
        "Fallführung",
        None,
        &[
            Permission::CaseCreate,
            Permission::CaseView,
            Permission::CaseEdit,
        ],
    )
    .await
    .unwrap();
    db.konto_rollen_setzen(chef.id, mia.id, &[analyst, r.id])
        .await
        .unwrap();
    assert!(db.fall_anlegen(mia.id, &f).await.unwrap());
    // Rolle gelöscht: Recht wieder weg.
    db.rolle_loeschen(chef.id, r.id).await.unwrap();
    assert!(!db.berechtigt(mia.id, Permission::CaseCreate).await.unwrap());
    assert_eq!(db.benutzer("mia").await.unwrap().unwrap().roles, [analyst]);

    // Der letzte Superadmin bleibt; mit einem zweiten geht es.
    assert!(db.superadmin_setzen(chef.id, chef.id, false).await.is_err());
    assert!(db.sperren(chef.id, chef.id).await.is_err());
    db.superadmin_setzen(chef.id, mia.id, true).await.unwrap();
    assert!(db
        .berechtigt(mia.id, Permission::CredentialViewSensitive)
        .await
        .unwrap());
    db.sperren(mia.id, chef.id).await.unwrap();
    assert!(db.anmelden("chef", "ein langes Passwort").await.is_err());
    // Ablehnen einer Registrierung; Dienstkonten haben kein Passwort.
    let x = db
        .registrieren("xaver", "X", "zwölf Zeichen!!")
        .await
        .unwrap();
    db.ablehnen(mia.id, x.id).await.unwrap();
    assert!(db.anmelden("xaver", "zwölf Zeichen!!").await.is_err());
    let dienst = db
        .dienstkonto_anlegen(mia.id, "importer", "Import", &[analyst])
        .await
        .unwrap();
    assert!(db.anmelden("importer", "irgendein Passwort").await.is_err());
    assert!(db
        .berechtigt(dienst.id, Permission::FileView)
        .await
        .unwrap());

    let ist: Vec<(String, String)> = aktionen(&db)
        .await
        .into_iter()
        .map(|z| (z.1, z.2))
        .collect();
    let soll = [
        ("USER_CREATE", "success"),
        ("USER_CREATE", "denied"),
        ("USER_REGISTER", "success"),
        ("USER_REGISTER", "denied"),
        ("LOGIN", "denied"),
        ("USER_APPROVE", "denied"),
        ("ROLE_GRANT", "success"),
        ("USER_APPROVE", "success"),
        ("LOGIN", "success"),
        ("CASE_CREATE", "denied"),
        ("ROLE_CREATE", "success"),
        ("ROLE_CREATE", "denied"),
        ("ROLE_MODIFY", "success"),
        ("ROLE_GRANT", "success"),
        ("CASE_CREATE", "success"),
        ("ROLE_DELETE", "success"),
        ("SUPERADMIN_SET", "success"),
        ("USER_DISABLE", "success"),
        ("LOGIN", "denied"),
        ("USER_REGISTER", "success"),
        ("USER_REJECT", "success"),
        ("LOGIN", "denied"),
        ("ROLE_GRANT", "success"),
        ("USER_CREATE", "success"),
        ("LOGIN", "denied"),
    ];
    assert_eq!(
        ist,
        soll.map(|(x, y)| (x.to_string(), y.to_string())).to_vec()
    );
    // Gründe stehen nur im Audit.
    let gruende: Vec<String> = sqlx::query_scalar(
        "SELECT details->>'grund' FROM audit_event \
         WHERE action = 'LOGIN' AND result = 'denied' ORDER BY sequence",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        gruende,
        [
            "nicht_freigegeben",
            "gesperrt",
            "abgelehnt",
            "kein_passwort"
        ]
    );
    let modify: (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT details->'rechte_vorher', details->'rechte' FROM audit_event \
         WHERE action = 'ROLE_MODIFY'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(modify.0, serde_json::json!(["case.create", "case.view"]));
    assert_eq!(
        modify.1,
        serde_json::json!(["case.create", "case.edit", "case.view"])
    );
    // Passwort ändern: eigenes nur mit dem bisherigen, fremdes nur als
    // Superadmin; offene Sitzungen enden.
    let (token, _) = db
        .sitzung_anlegen("mia", "noch ein Passwort!", None)
        .await
        .unwrap();
    assert!(db.sitzung_pruefen(&token).await.unwrap().is_some());
    assert!(matches!(
        db.passwort_aendern(mia.id, "mia", Some("falsch"), "ganz neues Passwort")
            .await,
        Err(StoreError::Verweigert(_))
    ));
    assert!(db
        .passwort_aendern(mia.id, "mia", Some("noch ein Passwort!"), "kurz")
        .await
        .is_err());
    db.passwort_aendern(
        mia.id,
        "mia",
        Some("noch ein Passwort!"),
        "ganz neues Passwort",
    )
    .await
    .unwrap();
    assert!(db.sitzung_pruefen(&token).await.unwrap().is_none());
    assert!(db.anmelden("mia", "noch ein Passwort!").await.is_err());
    db.anmelden("mia", "ganz neues Passwort").await.unwrap();
    // mia ist Superadmin (siehe oben) und darf ein fremdes Passwort setzen.
    db.passwort_aendern(mia.id, "xaver", None, "zurückgesetzt 123")
        .await
        .unwrap();
    assert!(db
        .passwort_aendern(dienst.id, "mia", None, "von einem Dienst!!")
        .await
        .is_err());
    let hash: String =
        sqlx::query_scalar("SELECT password_hash FROM app_user WHERE username = 'chef'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(db.audit_pruefen(a()).await.unwrap().intakt());
    frische_datenbank_entfernen(db, &name).await;
}
