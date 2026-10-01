//! Gegen eine echte PostgreSQL, nur mit gesetztem `STRATUM_DB_URL` (etwa
//! `postgres://stratum@127.0.0.1:5432/stratum`), Passwort optional aus der
//! Datei in `STRATUM_DB_PASSWORT_DATEI`.

use stratum_analysis::RawFinding;
use stratum_model::{CaseId, EvidenceId};
use stratum_normalize::{normalisieren, Kontext};
use stratum_store::Datenbank;

fn url() -> Option<String> {
    std::env::var("STRATUM_DB_URL").ok()
}

fn kontext() -> Kontext {
    Kontext {
        // Eigener Fall je Testlauf, damit Läufe sich nicht berühren.
        case_id: CaseId(uuid::Uuid::now_v7()),
        evidence_id: EvidenceId(uuid::Uuid::now_v7()),
        evidence_sha256: "test".into(),
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

#[tokio::test(flavor = "current_thread")]
async fn modell_schreiben_und_wiederholen() {
    let Some(url) = url() else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return;
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
    let db = Datenbank::verbinden_mit(&url, passwort.as_deref())
        .await
        .expect("Verbindung");
    let k = kontext();
    let m = normalisieren(&funde(), &k);

    let erst = db.modell_speichern(&k, &m, Some("abc")).await.unwrap();
    assert_eq!(erst.artefakte, m.artifacts.len() as u64);
    assert_eq!(erst.ereignisse, m.events.len() as u64);
    assert_eq!(erst.beteiligungen, m.participants.len() as u64);
    assert_eq!(erst.beziehungen, m.relationships.len() as u64);
    assert_eq!(erst.herkunftsangaben, m.provenance.len() as u64);

    // Zweiter Lauf: dieselben IDs, nichts kommt doppelt hinzu.
    let zweit = db.modell_speichern(&k, &m, Some("abc")).await.unwrap();
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
