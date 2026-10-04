//! API gegen eine echte PostgreSQL (`STRATUM_DB_URL`, Passwort optional
//! aus `STRATUM_DB_PASSWORT_DATEI`), in einer eigenen, danach gelöschten
//! Datenbank. Anfragen gehen direkt an den Router, ohne offenen Port.

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use futures_util::StreamExt;
use serde_json::{json, Value};
use sqlx::{Connection as _, Executor as _};
use stratum_model::{ActorId, CaseId, Evidence, EvidenceId, EvidenceKind, EvidenceSupport, RoleId};
use stratum_store::Datenbank;
use tower::ServiceExt;

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

/// Anfrage an den Router; liefert Status, Kopfzeilen und JSON.
async fn anfrage(
    app: &axum::Router,
    methode: &str,
    pfad: &str,
    token: Option<&str>,
    inhalt: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut r = Request::builder().method(methode).uri(pfad);
    if let Some(t) = token {
        r = r.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = match inhalt {
        Some(v) => {
            r = r.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let antwort = app.clone().oneshot(r.body(body).unwrap()).await.unwrap();
    let status = antwort.status();
    let kopf = antwort.headers().clone();
    let bytes = axum::body::to_bytes(antwort.into_body(), 1 << 20)
        .await
        .unwrap();
    let wert = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, kopf, wert)
}

/// Katalog mit Wurzel, einem Verzeichnis und drei Dateien.
const KATALOG: &str = r#"[
{"volume_offset":122683392,"mft_record":5,"parent_record":5,"typ":"verzeichnis","pfad":"","name":""},
{"volume_offset":122683392,"mft_record":100,"parent_record":5,"typ":"verzeichnis","pfad":"Windows","name":"Windows"},
{"volume_offset":122683392,"mft_record":101,"parent_record":5,"typ":"datei","pfad":"a.txt","name":"a.txt","groesse":3},
{"volume_offset":122683392,"mft_record":102,"parent_record":5,"typ":"datei","pfad":"b|c.txt","name":"b|c.txt","groesse":4},
{"volume_offset":122683392,"mft_record":200,"parent_record":100,"typ":"datei","pfad":"Windows\\calc.exe","name":"calc.exe","groesse":49152,"si":{"erstellt":"2026-04-18T09:40:47.3257138Z"}}
]"#;

/// Schreibt ein kleines Modell (zwei Anmeldungen, ein LSA-Secret) samt
/// Katalog als abgeschlossenen Analyselauf in den Fall, den Report mit den
/// Rohfunden nach `ordner`. Liefert den Pfad des Reports.
async fn modell_schreiben(
    db: &Datenbank,
    fall: CaseId,
    ev: &Evidence,
    ordner: &std::path::Path,
) -> std::path::PathBuf {
    use stratum_analysis::RawFinding;
    let anmeldung = |nr: &str, ft: &str| {
        let mut f = RawFinding::new(
            "eventlog",
            "Anmeldung erfolgreich",
            "Windows\\System32\\winevt\\Logs\\Security.evtx",
        );
        for (k, v) in [
            ("event_id", "4624"),
            ("event_record_id", nr),
            ("filetime", ft),
            ("anbieter", "Microsoft-Windows-Security-Auditing"),
            ("benutzer", "ich"),
            ("benutzer_sid", "S-1-5-21-1-2-3-1001"),
            ("volume_offset", "122683392"),
            ("mft_record", "39938"),
            ("mft_record_offset", "3384805376"),
            ("datei_offset", "69632"),
        ] {
            f = f.with(k, v);
        }
        f
    };
    let lsa = RawFinding::new(
        "lsa",
        "_SC_VBoxService",
        "SECURITY\\Policy\\Secrets\\_SC_VBoxService\\CurrVal",
    )
    .with("art", "lsa_secret")
    .with("wert", "Dienstkennwort1")
    .with("laenge", "30")
    .with("hive_offset", "8100");
    let mut funde = vec![
        anmeldung("1", "134209790846680107"),
        anmeldung("2", "134209790946680107"),
        lsa,
    ];
    stratum_analysis::assign_ids(&mut funde);
    let report = ordner.join("report.json");
    let text = serde_json::to_vec_pretty(&json!({"findings": funde})).unwrap();
    std::fs::write(&report, &text).unwrap();
    let report_sha256 = stratum_core::hash_bytes(&text).sha256;
    let k = stratum_normalize::Kontext {
        case_id: fall,
        evidence_id: ev.id,
        evidence_sha256: ev.sha256.clone(),
        host: Some("TESTRECHNER".into()),
        stratum_version: "test".into(),
        zeitpunkt: chrono::Utc::now(),
    };
    let m = stratum_normalize::normalisieren(&funde, &k);
    let konfiguration = json!({});
    let lauf = db
        .lauf_beginnen(
            ActorId::cli(),
            &k,
            &stratum_store::LaufAngaben {
                started_at: chrono::Utc::now(),
                configuration: &konfiguration,
                configuration_hash: None,
                audit_details: json!({}),
            },
        )
        .await
        .unwrap();
    db.modell_speichern(lauf, &m, None).await.unwrap();
    db.katalog_speichern(lauf, KATALOG).await.unwrap();
    db.lauf_abschliessen(
        ActorId::cli(),
        lauf,
        stratum_store::LaufStand::Completed,
        chrono::Utc::now(),
        Some(&report_sha256),
        report.to_str(),
    )
    .await
    .unwrap();
    report
}

async fn anmelden(app: &axum::Router, name: &str, pw: &str) -> String {
    let (s, _, v) = anfrage(
        app,
        "POST",
        "/api/v1/sitzung",
        None,
        Some(json!({"name": name, "passwort": pw})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_ablauf() {
    let Ok(url) = std::env::var("STRATUM_DB_URL") else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return;
    };
    let name = format!("stratum_test_{}", uuid::Uuid::now_v7().simple());
    sql(&url, format!("CREATE DATABASE {name}")).await;
    let (basis, _) = url.rsplit_once('/').unwrap();
    let db = Datenbank::verbinden_mit(&format!("{basis}/{name}"), passwort().as_deref())
        .await
        .unwrap();
    let ergebnis = std::panic::AssertUnwindSafe(ablauf(db.clone()));
    let r = futures_util::FutureExt::catch_unwind(ergebnis).await;
    db.pool().close().await;
    sql(&url, format!("DROP DATABASE {name} WITH (FORCE)")).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

async fn ablauf(db: Datenbank) {
    let cli = ActorId::cli();
    let chef = db
        .superadmin_einrichten(cli, "chef", "Chef", "chef-passwort-123")
        .await
        .unwrap();
    for (n, pw, rolle) in [
        ("mia", "mia-passwort-456", "Forensic Examiner"),
        ("tom", "tom-passwort-789", "Analyst"),
    ] {
        let u = db.registrieren(n, n, pw).await.unwrap();
        db.freigeben(chef.id, u.id, &[RoleId::template(rolle)])
            .await
            .unwrap();
    }
    let app = stratum_server::router(db.clone());

    // Ohne oder mit falscher Anmeldung nichts.
    let (s, _, v) = anfrage(&app, "GET", "/api/v1/ich", None, None).await;
    assert_eq!(
        (s, v["fehler"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("nicht angemeldet"))
    );
    let (s, _, _) = anfrage(
        &app,
        "POST",
        "/api/v1/sitzung",
        None,
        Some(json!({"name": "mia", "passwort": "falsch"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/ich", Some("gibtsnicht"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Anmeldung: Token im Body und als HttpOnly-Cookie.
    let (s, kopf, v) = anfrage(
        &app,
        "POST",
        "/api/v1/sitzung",
        None,
        Some(json!({"name": "chef", "passwort": "chef-passwort-123"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let t_chef = v["token"].as_str().unwrap().to_string();
    assert_eq!(t_chef.len(), 64);
    let cookie = kopf[header::SET_COOKIE].to_str().unwrap();
    assert!(
        cookie.starts_with(&format!("stratum_sitzung={t_chef};")) && cookie.contains("HttpOnly")
    );
    assert_eq!(v["rechte"].as_array().unwrap().len(), 23);
    // Auch über das Cookie.
    let antwort = app
        .clone()
        .oneshot(
            Request::get("/api/v1/ich")
                .header(header::COOKIE, format!("stratum_sitzung={t_chef}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::OK);
    // Anmeldung auch per HTTP-Basic (curl -u), ohne Körper.
    let antwort = app
        .clone()
        .oneshot(
            Request::post("/api/v1/sitzung")
                // tom:tom-passwort-789
                .header(header::AUTHORIZATION, "Basic dG9tOnRvbS1wYXNzd29ydC03ODk=")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::OK);
    // Kaputtes JSON: Fehler im gewohnten Format.
    let antwort = app
        .clone()
        .oneshot(
            Request::post("/api/v1/sitzung")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("kein json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::BAD_REQUEST);
    let v: Value = serde_json::from_slice(
        &axum::body::to_bytes(antwort.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(v["fehler"].as_str().unwrap().contains("HTTP-Basic"));
    let t_mia = anmelden(&app, "mia", "mia-passwort-456").await;
    let t_tom = anmelden(&app, "tom", "tom-passwort-789").await;
    let (_, _, v) = anfrage(&app, "GET", "/api/v1/ich", Some(&t_mia), None).await;
    assert_eq!(v["konto"]["username"], "mia");
    assert!(v["rechte"]
        .as_array()
        .unwrap()
        .contains(&json!("credential.view_sensitive")));

    // Fälle.
    let fall = json!({"nummer": "API-1", "titel": "API-Test"});
    let (s, _, v) = anfrage(
        &app,
        "POST",
        "/api/v1/faelle",
        Some(&t_mia),
        Some(fall.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = anfrage(
        &app,
        "POST",
        "/api/v1/faelle",
        Some(&t_chef),
        Some(fall.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let fall_id = CaseId(v["id"].as_str().unwrap().parse().unwrap());
    let (s, _, _) = anfrage(&app, "POST", "/api/v1/faelle", Some(&t_chef), Some(fall)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let antwort = app
        .clone()
        .oneshot(
            Request::post("/api/v1/faelle")
                .header(header::AUTHORIZATION, format!("Bearer {t_chef}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{\"titel\": 1}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::BAD_REQUEST);
    let (s, _, v) = anfrage(&app, "GET", "/api/v1/faelle", Some(&t_mia), None).await;
    assert_eq!((s, v.as_array().unwrap().len()), (StatusCode::OK, 1));
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/faelle/GIBTSNICHT", Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Evidence (hier direkt registriert; über die API folgt das als Job).
    let tmp = tempfile::tempdir().unwrap();
    let bild = tmp.path().join("leer.dd");
    std::fs::write(&bild, vec![0u8; 1 << 16]).unwrap();
    let h = stratum_core::hash_bytes(&std::fs::read(&bild).unwrap());
    let ev = Evidence {
        id: EvidenceId::new(),
        case_id: fall_id,
        kind: EvidenceKind::RawDiskImage,
        name: "leer.dd".into(),
        role: None,
        original_name: None,
        source_uri: bild.display().to_string(),
        size: 1 << 16,
        sha256: h.sha256,
        blake3: h.blake3,
        acquired_at: None,
        imported_at: chrono::Utc::now(),
        imported_by: cli,
        acquisition_method: None,
        read_only: true,
        support: EvidenceSupport::Recognized,
        parent_evidence_id: None,
        metadata: json!({}),
    };
    db.evidence_registrieren(cli, &ev).await.unwrap();
    let (_, _, v) = anfrage(&app, "GET", "/api/v1/faelle/API-1", Some(&t_mia), None).await;
    assert_eq!(v["evidence"][0]["name"], "leer.dd");

    // Analyse als Job, Fortschritt als Server-Sent Events.
    let analyse = json!({"evidence": "leer.dd", "optionen": {"katalog": true}});
    let (s, _, _) = anfrage(
        &app,
        "POST",
        "/api/v1/faelle/API-1/analysen",
        Some(&t_tom),
        Some(analyse.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = anfrage(
        &app,
        "POST",
        "/api/v1/faelle/API-1/analysen",
        Some(&t_mia),
        Some(analyse),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let job = v["job"].as_str().unwrap().to_string();
    let antwort = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/jobs/{job}/fortschritt"))
                .header(header::AUTHORIZATION, format!("Bearer {t_mia}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::OK);
    assert_eq!(antwort.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut strom = antwort.into_body().into_data_stream();
    let mut text = String::new();
    let erstes = tokio::time::timeout(Duration::from_secs(5), strom.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    text.push_str(&String::from_utf8_lossy(&erstes));
    assert!(
        text.contains("event: stand") && text.contains("\"queued\""),
        "{text}"
    );
    // Ein Worker erledigt den Job; der Strom endet mit „completed“.
    let worker = stratum_jobs::Worker::neu(
        db.clone(),
        tokio::runtime::Handle::current(),
        tmp.path().join("jobs"),
    );
    let w = tokio::task::spawn_blocking(move || worker.einmal().unwrap());
    while let Ok(Some(teil)) = tokio::time::timeout(Duration::from_secs(30), strom.next()).await {
        text.push_str(&String::from_utf8_lossy(&teil.unwrap()));
    }
    assert!(w.await.unwrap().is_some());
    assert!(text.contains("\"completed\""), "{text}");
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/jobs/{job}"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(v["status"], "completed");
    assert!(v["result"]["report_sha256"].is_string());
    let (s, _, _) = anfrage(
        &app,
        "DELETE",
        &format!("/api/v1/jobs/{job}"),
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, _, v) = anfrage(&app, "GET", "/api/v1/jobs?fall=API-1", Some(&t_mia), None).await;
    assert_eq!(v.as_array().unwrap().len(), 1);

    // Evidence-Import als Job, nur aus dem Fallordner.
    let ordner = tmp.path().join("fall2");
    std::fs::create_dir_all(ordner.join("netz")).unwrap();
    let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1];
    pcap.resize(1 << 12, 1);
    std::fs::write(ordner.join("netz/mitschnitt.pcap"), &pcap).unwrap();
    std::fs::write(tmp.path().join("fremd.pcap"), &pcap).unwrap();
    let fall2 =
        json!({"nummer": "API-2", "titel": "Import", "ordner": ordner.display().to_string()});
    let (s, _, _) = anfrage(&app, "POST", "/api/v1/faelle", Some(&t_chef), Some(fall2)).await;
    assert_eq!(s, StatusCode::CREATED);
    let import = |datei: &str| json!({"datei": datei, "rolle": "Router"});
    let pfad = "/api/v1/faelle/API-2/evidence";
    let (s, _, _) = anfrage(
        &app,
        "POST",
        pfad,
        Some(&t_tom),
        Some(import("netz/mitschnitt.pcap")),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = anfrage(
        &app,
        "POST",
        "/api/v1/faelle/API-1/evidence",
        Some(&t_mia),
        Some(import("leer.dd")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        v["fehler"].as_str().unwrap().contains("ohne Fallordner"),
        "{v}"
    );
    for falsch in [
        "../fremd.pcap",
        "fehlt.pcap",
        tmp.path().join("fremd.pcap").to_str().unwrap(),
    ] {
        let (s, _, v) = anfrage(&app, "POST", pfad, Some(&t_mia), Some(import(falsch))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{falsch}: {v}");
    }
    let (s, _, _) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-2/ordner",
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-2/ordner",
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["eintraege"][0]["name"].as_str(),
            v["eintraege"][0]["typ"].as_str()
        ),
        (Some("netz"), Some("dir"))
    );
    let (_, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-2/ordner?pfad=netz",
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(v["eintraege"][0]["name"], "mitschnitt.pcap");
    assert_eq!(v["eintraege"][0]["registriert"], false);
    let (s, _, _) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-2/ordner?pfad=..",
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    for runde in [true, false] {
        let (s, _, v) = anfrage(
            &app,
            "POST",
            pfad,
            Some(&t_mia),
            Some(import("netz/mitschnitt.pcap")),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        let job = v["job"].as_str().unwrap().to_string();
        let worker = stratum_jobs::Worker::neu(
            db.clone(),
            tokio::runtime::Handle::current(),
            tmp.path().join("jobs"),
        );
        let (_, status) = tokio::task::spawn_blocking(move || worker.einmal().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, stratum_model::JobStatus::Completed);
        let (_, _, v) = anfrage(
            &app,
            "GET",
            &format!("/api/v1/jobs/{job}"),
            Some(&t_mia),
            None,
        )
        .await;
        assert_eq!(v["kind"], "evidence_import");
        assert_eq!(v["result"]["kind"], "pcap");
        assert_eq!(v["result"]["neu"], runde);
        assert_eq!(
            v["result"]["sha256"],
            stratum_core::hash_bytes(&pcap).sha256
        );
    }
    let (_, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-2/ordner?pfad=netz",
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(v["eintraege"][0]["registriert"], true);
    let (_, _, v) = anfrage(&app, "GET", "/api/v1/faelle/API-2", Some(&t_mia), None).await;
    let e = &v["evidence"][0];
    assert_eq!(
        (e["name"].as_str(), e["kind"].as_str()),
        (Some("mitschnitt.pcap"), Some("pcap"))
    );
    assert_eq!(
        (e["role"].as_str(), e["support"].as_str()),
        (Some("Router"), Some("unsupported_format"))
    );
    assert_eq!(v["evidence"].as_array().unwrap().len(), 1);

    // Audit: mia hat audit.view nicht, chef als Superadmin schon.
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/audit", Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = anfrage(&app, "GET", "/api/v1/audit?anzahl=500", Some(&t_chef), None).await;
    assert_eq!(s, StatusCode::OK);
    let aktionen: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "LOGIN",
        "CASE_CREATE",
        "JOB_CREATE",
        "ANALYSIS_START",
        "ANALYSIS_COMPLETE",
    ] {
        assert!(aktionen.contains(&a), "{a} fehlt");
    }
    let (_, _, v) = anfrage(&app, "POST", "/api/v1/audit/pruefen", Some(&t_chef), None).await;
    assert_eq!(v["fehler_gesamt"], 0);

    // Ergebnisse: kleines Modell aus Rohfunden in den Fall schreiben.
    let report = modell_schreiben(&db, fall_id, &ev, tmp.path()).await;
    let (s, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-1/zeitachse?anzahl=1",
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["eintraege"].as_array().unwrap().len(), 1);
    let erstes = v["eintraege"][0].clone();
    assert_eq!(erstes["kind"], "user_logon");
    assert!(erstes["participants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "ich"));
    let weiter = v["naechste"].as_str().unwrap().to_string();
    let (_, _, v2) = anfrage(
        &app,
        "GET",
        &format!(
            "/api/v1/faelle/API-1/zeitachse?anzahl=1&nach={}",
            weiter
                .replace('+', "%2B")
                .replace(':', "%3A")
                .replace('|', "%7C")
        ),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(v2["eintraege"].as_array().unwrap().len(), 1);
    assert_ne!(v2["eintraege"][0]["id"], erstes["id"]);
    assert!(v2["eintraege"][0]["occurred_utc"].as_str() >= erstes["occurred_utc"].as_str());
    assert!(v2["naechste"].is_null());
    let (_, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-1/zeitachse?art=gibts_nicht",
        Some(&t_tom),
        None,
    )
    .await;
    assert!(v["eintraege"].as_array().unwrap().is_empty());
    let (_, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-1/zeitachse/arten",
        Some(&t_tom),
        None,
    )
    .await;
    assert!(v
        .as_array()
        .unwrap()
        .contains(&json!({"art": "user_logon", "anzahl": 2})));

    // Entitäten: das Dienstpasswort ist maskiert.
    let (_, _, v) = anfrage(
        &app,
        "GET",
        "/api/v1/faelle/API-1/entitaeten?suche=vbox&art=credential",
        Some(&t_tom),
        None,
    )
    .await;
    let cred = v["eintraege"][0].clone();
    assert_eq!(cred["display_name"], "LSA-Secret _SC_VBoxService");
    assert_eq!(cred["attributes"]["wert"], "[maskiert]");
    let id = cred["id"].as_str().unwrap().to_string();
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/entitaeten/{id}"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(v["entitaet"]["attributes"]["wert"], "[maskiert]");
    assert!(v["beziehungen"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["kind"] == "BELONGS_TO" && b["gegenueber"]["name"] == "VBoxService"));
    // Klartext nur mit credential.view_sensitive (Analyst nicht, Forensic
    // Examiner ja), beides im Audit.
    let (s, _, _) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/entitaeten/{id}?klartext=true"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/entitaeten/{id}?klartext=true"),
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["entitaet"]["attributes"]["wert"], "Dienstkennwort1");
    let cv: Vec<(String, uuid::Uuid)> = sqlx::query_as(
        "SELECT result, actor_id FROM audit_event WHERE action = 'CREDENTIAL_VIEW' ORDER BY sequence",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(cv.len(), 2);
    assert_eq!(cv[0].0, "denied");
    assert_eq!(cv[1].0, "success");
    let (s, _, _) = anfrage(
        &app,
        "GET",
        "/api/v1/entitaeten/01a0fdd9-8410-7011-a689-f51d5bd3b3a5",
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Dateibaum: Volumes, Wurzel seitenweise (erst Verzeichnisse), Unterordner.
    let (s, _, v) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/evidence/{}/volumes", ev.id),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v[0]["volume_offset"], 122683392);
    assert_eq!(
        (v[0]["eintraege"].as_i64(), v[0]["verzeichnisse"].as_i64()),
        (Some(5), Some(2))
    );
    let wurzel = format!("/api/v1/evidence/{}/dateien?volume=122683392", ev.id);
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{wurzel}&anzahl=2"),
        Some(&t_tom),
        None,
    )
    .await;
    let e = v["eintraege"].as_array().unwrap();
    assert_eq!(
        (e[0]["name"].as_str(), e[0]["hat_kinder"].as_bool()),
        (Some("Windows"), Some(true))
    );
    assert_eq!(e[1]["name"], "a.txt");
    assert_eq!(e[1]["hat_kinder"], false);
    let weiter = v["naechste"].as_str().unwrap().replace('|', "%7C");
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{wurzel}&anzahl=2&nach={weiter}"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(v["eintraege"].as_array().unwrap().len(), 1);
    assert_eq!(v["eintraege"][0]["name"], "b|c.txt");
    assert!(v["naechste"].is_null());
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{wurzel}&verzeichnis=100"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(v["eintraege"][0]["path"], "Windows\\calc.exe");
    assert_eq!(
        v["eintraege"][0]["si_created"],
        "2026-04-18T09:40:47.3257138Z"
    );
    let (s, _, _) = anfrage(
        &app,
        "GET",
        &format!("{wurzel}&nach=kaputt"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = anfrage(
        &app,
        "GET",
        "/api/v1/evidence/01a0fdd9-8410-7011-a689-f51d5bd3b3a5/volumes",
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Rohfund aus dem Report, geprüft gegen den Hash in der Datenbank.
    let artefakt = |domain: &'static str| {
        let db = db.clone();
        async move {
            let id: uuid::Uuid = sqlx::query_scalar(
                "SELECT id FROM artifact WHERE raw_metadata->>'domain' = $1 LIMIT 1",
            )
            .bind(domain)
            .fetch_one(db.pool())
            .await
            .unwrap();
            format!("/api/v1/artefakte/{id}/rohfund")
        }
    };
    let lsa = artefakt("lsa").await;
    let (s, _, v) = anfrage(&app, "GET", &lsa, Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["fund"]["attributes"]["wert"], "[maskiert]");
    assert_eq!(v["fund"]["attributes"]["laenge"], "30");
    assert_eq!(
        (v["maskiert"].as_bool(), v["report"]["geprueft"].as_bool()),
        (Some(true), Some(true))
    );
    let (s, _, _) = anfrage(
        &app,
        "GET",
        &format!("{lsa}?klartext=true"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, v) = anfrage(
        &app,
        "GET",
        &format!("{lsa}?klartext=true"),
        Some(&t_mia),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["fund"]["attributes"]["wert"], "Dienstkennwort1");
    let (_, _, v) = anfrage(&app, "GET", &artefakt("eventlog").await, Some(&t_tom), None).await;
    assert_eq!(
        (
            v["maskiert"].as_bool(),
            v["fund"]["attributes"]["event_id"].as_str()
        ),
        (Some(false), Some("4624"))
    );
    // Veränderter Report: 409; fehlender Report: 404. Beides im Audit.
    let mut text = std::fs::read(&report).unwrap();
    text.push(b'\n');
    std::fs::write(&report, &text).unwrap();
    let (s, _, v) = anfrage(&app, "GET", &lsa, Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(
        v["fehler"].as_str().unwrap().contains("Report verändert"),
        "{v}"
    );
    std::fs::remove_file(&report).unwrap();
    let (s, _, _) = anfrage(&app, "GET", &lsa, Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let zaehlung: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT action, result, count(*) FROM audit_event \
         WHERE (action IN ('FILE_VIEW', 'CREDENTIAL_VIEW') AND object_type <> 'case_folder') OR object_type = 'artifact' \
         GROUP BY 1, 2 ORDER BY 1, 2",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        zaehlung,
        [
            ("CREDENTIAL_VIEW".into(), "denied".into(), 2),
            ("CREDENTIAL_VIEW".into(), "success".into(), 2),
            ("DATA_VIEW".into(), "failure".into(), 2),
            ("DATA_VIEW".into(), "success".into(), 3),
            ("FILE_VIEW".into(), "success".into(), 4),
        ]
    );

    // Zeitachse je Evidence und mit Suchtext; Ereignis mit Herkunft.
    let za = "/api/v1/faelle/API-1/zeitachse";
    let laenge = |v: &Value| v["eintraege"].as_array().unwrap().len();
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{za}?evidence={}", ev.id),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(laenge(&v), 2, "{v}");
    let eid = v["eintraege"][0]["id"].as_str().unwrap().to_string();
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{za}?evidence=01a0fdd9-8410-7011-a689-f51d5bd3b3a5"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(laenge(&v), 0);
    let (_, _, v) = anfrage(&app, "GET", &format!("{za}?suche=4624"), Some(&t_tom), None).await;
    assert_eq!(laenge(&v), 2);
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{za}?suche=100%25"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(laenge(&v), 0);
    let (s, _, v) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/ereignisse/{eid}"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ereignis"]["kind"], "user_logon");
    let h = &v["herkunft"][0];
    assert_eq!(h["evidence_name"], "leer.dd");
    assert!(
        h["rohfund_id"].is_string() && h["source_locator"].is_object(),
        "{h}"
    );

    // War Room: Systemeinträge zum Analyse-Job, Notizen, Seiten.
    let wr = "/api/v1/faelle/API-1/warroom";
    let (s, _, v) = anfrage(&app, "GET", wr, Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let ereignisse: Vec<&str> = v["eintraege"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["payload"]["event"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(ereignisse, ["job_finished", "job_queued"]);
    assert_eq!(v["eintraege"][0]["payload"]["status"], "completed");
    assert_eq!(v["eintraege"][0]["object_refs"][0]["type"], "evidence");
    let (s, _, v) = anfrage(
        &app,
        "POST",
        wr,
        Some(&t_tom),
        Some(json!({"text": "  Erste Einschätzung  "})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(
        (v["kind"].as_str(), v["payload"]["text"].as_str()),
        (Some("analyst_note"), Some("Erste Einschätzung"))
    );
    assert!(v["audit_event_id"].is_string());
    let notiz = v["id"].as_str().unwrap().to_string();
    let (s, _, _) = anfrage(
        &app,
        "POST",
        wr,
        Some(&t_tom),
        Some(json!({"text": "x", "art": "system_event"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = anfrage(&app, "POST", wr, Some(&t_tom), Some(json!({"text": "   "}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, v) = anfrage(
        &app,
        "POST",
        wr,
        Some(&t_mia),
        Some(json!({"text": "Bestätigt", "parent": notiz})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let (_, _, v) = anfrage(&app, "GET", &format!("{wr}?anzahl=1"), Some(&t_tom), None).await;
    assert_eq!(v["eintraege"][0]["parent_entry_id"], notiz.as_str());
    assert!(v["eintraege"][0]["actor_name"].is_string());
    let weiter = v["naechste"].as_str().unwrap().to_string();
    let (_, _, v) = anfrage(
        &app,
        "GET",
        &format!("{wr}?anzahl=1&vor={weiter}"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(v["eintraege"][0]["id"], notiz.as_str());
    // Einträge sind unveränderlich, auch für die Anwendungsrolle.
    assert!(sqlx::query("UPDATE war_room_entry SET payload = '{}'")
        .execute(db.pool())
        .await
        .is_err());

    let (s, _, v) = anfrage(
        &app,
        "GET",
        &format!("/api/v1/evidence/{}/dateien/122683392/200", ev.id),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v[0]["name"].as_str(), v[0]["parent_record"].as_i64()),
        (Some("calc.exe"), Some(100))
    );
    // Dateiinhalt: nur Katalogdateien, Verzeichnisse nicht, Export nur mit
    // file.extract. leer.dd enthält kein NTFS, Lesen scheitert deshalb mit 404.
    let datei = |record: i64, was: &str| {
        format!(
            "/api/v1/evidence/{}/dateien/122683392/{record}/{was}",
            ev.id
        )
    };
    let (s, _, v) = anfrage(&app, "GET", &datei(101, "inhalt"), Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(v["fehler"].as_str().unwrap().contains("NTFS"), "{v}");
    let (s, _, _) = anfrage(&app, "GET", &datei(100, "inhalt"), Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = anfrage(&app, "GET", &datei(999, "inhalt"), Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = anfrage(&app, "GET", &datei(101, "export"), Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = anfrage(&app, "GET", &datei(101, "export"), Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = anfrage(&app, "POST", &datei(101, "hash"), Some(&t_tom), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Katalogsuche umfasst das Volume, nicht nur das aktuelle Verzeichnis.
    let suchen = format!("/api/v1/evidence/{}/dateisuche?volume=122683392", ev.id);
    let (status, _, v) = anfrage(
        &app,
        "GET",
        &format!("{suchen}&endung=exe"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["eintraege"].as_array().unwrap().len(), 1);
    assert_eq!(v["eintraege"][0]["name"], "calc.exe");
    let (status, _, v) = anfrage(
        &app,
        "GET",
        &format!("{suchen}&suche=%25"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["eintraege"].as_array().unwrap().is_empty());
    let (status, _, v) = anfrage(
        &app,
        "GET",
        &format!("{suchen}&format=pe"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["eintraege"].as_array().unwrap().is_empty());
    let (status, _, v) = anfrage(
        &app,
        "GET",
        &format!("{suchen}&anzahl=1"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let mut next = v["naechste"].as_str().unwrap().to_string();
    let mut names = vec![v["eintraege"][0]["name"].as_str().unwrap().to_string()];
    loop {
        let encoded: String = next
            .as_bytes()
            .iter()
            .map(|b| format!("%{b:02X}"))
            .collect();
        let (status, _, v) = anfrage(
            &app,
            "GET",
            &format!("{suchen}&anzahl=1&nach={encoded}"),
            Some(&t_tom),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        names.push(v["eintraege"][0]["name"].as_str().unwrap().to_string());
        match v["naechste"].as_str() {
            Some(n) => next = n.to_string(),
            None => break,
        }
    }
    assert_eq!(names.len(), 3);
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 3);
    let (status, _, _) = anfrage(
        &app,
        "GET",
        &format!("{suchen}&nach=kaputt"),
        Some(&t_tom),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = anfrage(&app, "GET", &suchen, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Inhaltssuche: leere Anfrage wird abgelehnt; defektes Image wird als Fehler protokolliert.
    let (status, _, _) = anfrage(
        &app,
        "POST",
        &datei(101, "suche"),
        Some(&t_tom),
        Some(json!({"wort": ""})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = anfrage(
        &app,
        "POST",
        &datei(101, "suche"),
        Some(&t_tom),
        Some(json!({"wort": "Geheimwort"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let result: (String, String) = sqlx::query_as("SELECT result, details::text FROM audit_event WHERE action = 'SEARCH_RUN' ORDER BY sequence DESC LIMIT 1").fetch_one(db.pool()).await.unwrap();
    assert_eq!(result.0, "failure");
    assert!(!result.1.contains("Geheimwort"));
    assert!(result.1.contains("suchtext_sha256"));
    let (status, _, _) = anfrage(&app, "GET", &datei(101, "vorschau"), Some(&t_tom), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Registrierung über die API, Freigabe und Passwortpflicht.
    let lea = json!({"name": "lea", "anzeigename": "Lea L.", "passwort": "lea-passwort-1234"});
    let (s, _, v) = anfrage(&app, "POST", "/api/v1/registrierung", None, Some(lea)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["status"], "pending");
    let (s, _, _) = anfrage(
        &app,
        "POST",
        "/api/v1/sitzung",
        None,
        Some(json!({"name": "lea", "passwort": "lea-passwort-1234"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/konten", Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, _, v) = anfrage(&app, "GET", "/api/v1/konten", Some(&t_chef), None).await;
    let lea_id = v
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["username"] == "lea")
        .map(|k| k["id"].as_str().unwrap().to_string())
        .unwrap();
    let (s, _, v) = anfrage(&app, "GET", "/api/v1/rollen", Some(&t_chef), None).await;
    assert_eq!(s, StatusCode::OK);
    let analyst = v
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Analyst")
        .unwrap()["id"]
        .clone();
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/rollen", Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = anfrage(
        &app,
        "POST",
        &format!("/api/v1/konten/{lea_id}/freigeben"),
        Some(&t_chef),
        Some(json!({"rollen": [analyst]})),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let t_lea = anmelden(&app, "lea", "lea-passwort-1234").await;
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/faelle", Some(&t_lea), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = anfrage(
        &app,
        "POST",
        &format!("/api/v1/konten/{lea_id}/passwort"),
        Some(&t_chef),
        Some(json!({"neu": "vom-chef-gesetzt-1"})),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/faelle", Some(&t_lea), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "alte Sitzung endet");
    let t_lea = anmelden(&app, "lea", "vom-chef-gesetzt-1").await;
    let (s, _, v) = anfrage(&app, "GET", "/api/v1/faelle", Some(&t_lea), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(v["fehler"].as_str().unwrap().contains("Passwort"), "{v}");
    let (_, _, v) = anfrage(&app, "GET", "/api/v1/ich", Some(&t_lea), None).await;
    assert_eq!(v["konto"]["password_change_required"], true);
    let (s, _, _) = anfrage(
        &app,
        "POST",
        "/api/v1/ich/passwort",
        Some(&t_lea),
        Some(json!({"bisher": "falsch-falsch-1", "neu": "lea-eigenes-pw-99"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = anfrage(
        &app,
        "POST",
        "/api/v1/ich/passwort",
        Some(&t_lea),
        Some(json!({"bisher": "vom-chef-gesetzt-1", "neu": "lea-eigenes-pw-99"})),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let t_lea = anmelden(&app, "lea", "lea-eigenes-pw-99").await;
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/faelle", Some(&t_lea), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = anfrage(
        &app,
        "POST",
        &format!("/api/v1/konten/{lea_id}/sperren"),
        Some(&t_chef),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = anfrage(
        &app,
        "POST",
        "/api/v1/sitzung",
        None,
        Some(json!({"name": "lea", "passwort": "lea-eigenes-pw-99"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Weboberfläche: Dateien, sonst index.html; API-Pfade bleiben JSON.
    let gui = tmp.path().join("dist");
    std::fs::create_dir_all(gui.join("assets")).unwrap();
    std::fs::write(
        gui.join("index.html"),
        "<!doctype html><title>stratum</title>",
    )
    .unwrap();
    std::fs::write(gui.join("assets/a.js"), "export {};").unwrap();
    let mit_gui = stratum_server::router_mit_oberflaeche(db.clone(), Some(&gui));
    for (pfad, status, art) in [
        ("/", StatusCode::OK, "text/html"),
        ("/faelle/API-1", StatusCode::OK, "text/html"),
        ("/assets/a.js", StatusCode::OK, "text/javascript"),
        (
            "/api/v1/gibtsnicht",
            StatusCode::NOT_FOUND,
            "application/json",
        ),
        ("/api/v1/ich", StatusCode::UNAUTHORIZED, "application/json"),
    ] {
        let r = mit_gui
            .clone()
            .oneshot(Request::get(pfad).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), status, "{pfad}");
        let typ = r.headers()[header::CONTENT_TYPE].to_str().unwrap();
        assert!(typ.starts_with(art), "{pfad}: {typ}");
        assert!(r.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
    }

    // Abmelden beendet die Sitzung.
    let (s, kopf, _) = anfrage(&app, "DELETE", "/api/v1/sitzung", Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(kopf[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    let (s, _, _) = anfrage(&app, "GET", "/api/v1/ich", Some(&t_mia), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let logout: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_event WHERE action = 'LOGOUT'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(logout, 1);
}
