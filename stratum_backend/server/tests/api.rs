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

/// Schreibt ein kleines Modell (zwei Anmeldungen, ein LSA-Secret) als
/// Analyselauf in den Fall.
async fn modell_schreiben(db: &Datenbank, fall: CaseId, ev: &Evidence) {
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
        f.id = format!("anmeldung{nr}");
        f
    };
    let mut lsa = RawFinding::new(
        "lsa",
        "_SC_VBoxService",
        "SECURITY\\Policy\\Secrets\\_SC_VBoxService\\CurrVal",
    )
    .with("art", "lsa_secret")
    .with("wert", "Dienstkennwort1")
    .with("laenge", "30")
    .with("hive_offset", "8100");
    lsa.id = "lsa1".into();
    let funde = vec![
        anmeldung("1", "134209790846680107"),
        anmeldung("2", "134209790946680107"),
        lsa,
    ];
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
    modell_schreiben(&db, fall_id, &ev).await;
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
