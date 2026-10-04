//! Worker gegen eine echte PostgreSQL (`STRATUM_DB_URL`, Passwort optional
//! aus `STRATUM_DB_PASSWORT_DATEI`), in einer eigenen, danach gelöschten
//! Datenbank.

use std::path::Path;

use serde_json::json;
use sqlx::{Connection as _, Executor as _};
use stratum_jobs::{AnalyseOptionen, Worker};
use stratum_model::{
    ActorId, Case, CaseClassification, CaseId, CaseStatus, Evidence, EvidenceId, EvidenceKind,
    EvidenceSupport, JobStatus,
};
use stratum_store::Datenbank;

fn passwort() -> Option<String> {
    let p = std::path::PathBuf::from(std::env::var_os("STRATUM_DB_PASSWORT_DATEI")?);
    let p = if p.is_relative() {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
    } else {
        p
    };
    Some(std::fs::read_to_string(p).unwrap().trim().to_string())
}

async fn sql(url: &str, befehl: String) {
    let mut o: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
    if let Some(p) = passwort() {
        o = o.password(&p);
    }
    let mut c = sqlx::PgConnection::connect_with(&o).await.unwrap();
    c.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(befehl)))
        .await
        .unwrap();
}

/// Testdatenbank, beim Verlassen gelöscht (auch bei Fehlschlag).
struct Wegwerf {
    rt: tokio::runtime::Runtime,
    url: String,
    name: String,
}

impl Drop for Wegwerf {
    fn drop(&mut self) {
        let befehl = format!("DROP DATABASE {} WITH (FORCE)", self.name);
        self.rt.block_on(sql(&self.url, befehl));
    }
}

fn evidence(fall: CaseId, datei: &Path, kind: EvidenceKind) -> Evidence {
    let inhalt = std::fs::read(datei).unwrap();
    let h = stratum_core::hash_bytes(&inhalt);
    Evidence {
        id: EvidenceId::new(),
        case_id: fall,
        kind,
        name: datei.file_name().unwrap().to_string_lossy().into(),
        role: None,
        original_name: None,
        source_uri: datei.display().to_string(),
        size: inhalt.len() as u64,
        sha256: h.sha256,
        blake3: h.blake3,
        acquired_at: None,
        imported_at: chrono::Utc::now(),
        imported_by: ActorId::cli(),
        acquisition_method: None,
        read_only: true,
        support: EvidenceSupport::Recognized,
        parent_evidence_id: None,
        metadata: json!({}),
    }
}

#[test]
fn worker_ablauf() {
    let Ok(url) = std::env::var("STRATUM_DB_URL") else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return;
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let name = format!("stratum_test_{}", uuid::Uuid::now_v7().simple());
    rt.block_on(sql(&url, format!("CREATE DATABASE {name}")));
    let (basis, _) = url.rsplit_once('/').unwrap();
    let neu = format!("{basis}/{name}");
    let db = rt
        .block_on(Datenbank::verbinden_mit(&neu, passwort().as_deref()))
        .unwrap();
    let _wegwerf = Wegwerf {
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        url: url.clone(),
        name: name.clone(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let bild = tmp.path().join("leer.dd");
    std::fs::write(&bild, vec![0u8; 1 << 16]).unwrap();
    let text = tmp.path().join("notiz.txt");
    std::fs::write(&text, b"kein Image").unwrap();
    let a = ActorId::cli();
    let fall = Case {
        id: CaseId::new(),
        case_number: "JOB-1".into(),
        title: "Jobs".into(),
        description: None,
        status: CaseStatus::Active,
        classification: CaseClassification::Internal,
        created_at: chrono::Utc::now(),
        created_by: a,
        opened_at: None,
        closed_at: None,
        timezone: None,
        case_folder: None,
        tags: Vec::new(),
    };
    let ev = evidence(fall.id, &bild, EvidenceKind::RawDiskImage);
    let ev_text = evidence(fall.id, &text, EvidenceKind::Other);
    rt.block_on(async {
        db.fall_anlegen(a, &fall).await.unwrap();
        db.evidence_registrieren(a, &ev).await.unwrap();
        db.evidence_registrieren(a, &ev_text).await.unwrap();
    });
    let optionen = serde_json::to_value(AnalyseOptionen {
        katalog: true,
        ..Default::default()
    })
    .unwrap();
    let einreihen = |e: EvidenceId| {
        rt.block_on(db.analyse_einreihen(a, fall.id, e, optionen.clone()))
            .unwrap()
    };
    let lesen = |id| rt.block_on(db.job_lesen(id)).unwrap();
    let ausgabe = tmp.path().join("jobs");
    let worker = Worker::neu(db.clone(), rt.handle().clone(), ausgabe.clone());

    // Ohne Recht: nicht einreihen.
    assert!(rt
        .block_on(db.analyse_einreihen(ActorId::unbekannt(), fall.id, ev.id, json!({})))
        .is_err());

    // Normaler Ablauf.
    let id = einreihen(ev.id);
    assert_eq!(lesen(id).status, JobStatus::Queued);
    assert_eq!(worker.einmal().unwrap(), Some((id, JobStatus::Completed)));
    let job = lesen(id);
    let erg = job.result.unwrap();
    let report = std::fs::read(erg["report"].as_str().unwrap()).unwrap();
    assert_eq!(
        erg["report_sha256"],
        stratum_core::hash_bytes(&report).sha256
    );
    assert!(ausgabe.join(id.to_string()).join("katalog.jsonl").exists());
    let lauf = job.analysis_run_id.unwrap();
    let (stand, von): (String, uuid::Uuid) = rt
        .block_on(
            sqlx::query_as("SELECT status, started_by FROM analysis_run WHERE id = $1")
                .bind(lauf.0)
                .fetch_one(db.pool()),
        )
        .unwrap();
    assert_eq!((stand.as_str(), von), ("completed", a.0));
    assert_eq!(job.progress["phase"], "analyzer");
    let h = &job.progress["phasen"]["hashing"];
    assert_eq!(
        (h["erledigt"].as_u64(), h["gesamt"].as_u64()),
        (Some(1 << 16), Some(1 << 16))
    );
    let an = &job.progress["phasen"]["analyzer"];
    assert_eq!(an["erledigt"], an["gesamt"]);
    for phase in ["hashing", "katalog", "analyzer"] {
        let stand = &job.progress["phasen"][phase];
        assert_eq!(stand["abgeschlossen"], true);
        assert!(stand["dauer_ms"].as_u64().is_some());
    }
    assert!(job.progress["meldung"]
        .as_str()
        .unwrap()
        .contains("Report geschrieben"));
    assert_eq!(worker.einmal().unwrap(), None);

    // Wartend abgebrochen: läuft nie.
    let id = einreihen(ev.id);
    assert_eq!(
        rt.block_on(db.job_abbrechen(a, id)).unwrap(),
        JobStatus::Cancelled
    );
    assert_eq!(worker.einmal().unwrap(), None);
    assert!(rt.block_on(db.job_abbrechen(a, id)).is_err());

    // Laufend abgebrochen: hält an, Lauf als abgebrochen beendet.
    let id = einreihen(ev.id);
    let job = rt.block_on(db.job_holen("test")).unwrap().unwrap();
    assert_eq!(job.id, id);
    assert_eq!(
        rt.block_on(db.job_abbrechen(a, id)).unwrap(),
        JobStatus::Running
    );
    let job = lesen(id);
    assert_eq!(worker.ausfuehren(job).unwrap(), JobStatus::Cancelled);
    let job = lesen(id);
    assert_eq!(job.status, JobStatus::Cancelled);
    if let Some(l) = job.analysis_run_id {
        let stand: String = rt
            .block_on(
                sqlx::query_scalar("SELECT status FROM analysis_run WHERE id = $1")
                    .bind(l.0)
                    .fetch_one(db.pool()),
            )
            .unwrap();
        assert_eq!(stand, "cancelled");
    }

    // Höchstens eine Analyse gleichzeitig; ohne Lebenszeichen verwaist.
    let erster = einreihen(ev.id);
    let zweiter = einreihen(ev.id);
    assert_eq!(rt.block_on(db.job_holen("w1")).unwrap().unwrap().id, erster);
    assert!(rt.block_on(db.job_holen("w2")).unwrap().is_none());
    rt.block_on(
        sqlx::query("UPDATE job SET heartbeat_at = now() - interval '1 hour' WHERE id = $1")
            .bind(erster.0)
            .execute(db.pool()),
    )
    .unwrap();
    assert_eq!(
        rt.block_on(db.job_holen("w2")).unwrap().unwrap().id,
        zweiter
    );
    let alt = lesen(erster);
    assert_eq!(alt.status, JobStatus::Failed);
    assert_eq!(alt.error.as_deref(), Some("Worker ohne Lebenszeichen"));
    rt.block_on(db.job_beenden(zweiter, JobStatus::Failed, Some("Test"), None))
        .unwrap();

    // Keine analysierbare Art: Job scheitert mit Begründung.
    let id = einreihen(ev_text.id);
    assert_eq!(worker.einmal().unwrap(), Some((id, JobStatus::Failed)));
    assert!(lesen(id)
        .error
        .unwrap()
        .contains("kein analysierbares Image"));

    // Liste und Audit.
    let liste = rt.block_on(db.jobs(a, Some(fall.id), 100)).unwrap();
    assert_eq!(liste.len(), 6);
    // Sechs angelegt, einer ohne Recht abgelehnt.
    let anzahl: Vec<(String, i64)> = rt
        .block_on(
            sqlx::query_as(
                "SELECT result, count(*) FROM audit_event WHERE action = 'JOB_CREATE' \
                 GROUP BY result ORDER BY result",
            )
            .fetch_all(db.pool()),
        )
        .unwrap();
    assert_eq!(
        anzahl,
        [("denied".to_string(), 1), ("success".to_string(), 6)]
    );
    assert!(rt.block_on(db.audit_pruefen(a)).unwrap().intakt());
    drop(db);
    rt.shutdown_background();
}
