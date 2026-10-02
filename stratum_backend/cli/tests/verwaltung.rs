//! Unterbefehle für Konten, Rollen und Audit. Ohne Datenbank nur Aufbau und
//! Rechtekatalog; mit `STRATUM_DB_URL` der ganze Ablauf in einer eigenen,
//! danach gelöschten Datenbank.

use std::path::Path;
use std::process::{Command, Output};

fn stratum(args: &[&str], db: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_stratum"));
    c.args(args);
    match db {
        Some(url) => c.env("STRATUM_DB_URL", url),
        None => c.env_remove("STRATUM_DB_URL"),
    };
    c.output().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn rechtekatalog_ohne_datenbank() {
    let o = stratum(&["rechte"], None);
    assert!(o.status.success(), "{}", text(&o));
    let t = String::from_utf8(o.stdout).unwrap();
    assert_eq!(t.lines().count(), 23);
    assert!(t.contains("credential.view_sensitive"));
}

#[test]
fn unterbefehl_und_image_schliessen_sich_aus() {
    // Ohne Datenbank scheitert ein verwaltender Befehl verständlich.
    let o = stratum(&["konto", "liste"], None);
    assert!(!o.status.success());
    assert!(text(&o).contains("STRATUM_DB_URL"));
    // Ein Unterbefehl verlangt kein Image, das Image keinen Unterbefehl.
    let o = stratum(&[], None);
    assert!(!o.status.success());
    assert!(text(&o).contains("IMAGE"));
    // Die Unterbefehle sind erreichbar.
    let o = stratum(&["rolle", "--help"], None);
    assert!(o.status.success());
    assert!(text(&o).contains("anlegen"));
}

fn mit<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<&'a str> {
    [a, b].concat()
}

/// Passwort der Datenbank aus `STRATUM_DB_PASSWORT_DATEI`, relative Pfade
/// vom Projektverzeichnis aus (wie bei stratum selbst).
fn db_passwort() -> Option<String> {
    let p = std::path::PathBuf::from(std::env::var_os("STRATUM_DB_PASSWORT_DATEI")?);
    let p = if p.is_relative() {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
    } else {
        p
    };
    Some(
        std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("Passwortdatei {} nicht lesbar: {e}", p.display()))
            .trim()
            .to_string(),
    )
}

fn sql(url: &str, befehl: String) {
    use sqlx::{Connection as _, Executor as _};
    let rt = tokio_rt();
    rt.block_on(async {
        let mut o: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
        if let Some(p) = db_passwort() {
            o = o.password(&p);
        }
        let mut c = sqlx::PgConnection::connect_with(&o).await.unwrap();
        c.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(befehl)))
            .await
            .unwrap();
    });
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn ablauf_mit_datenbank() {
    let Ok(url) = std::env::var("STRATUM_DB_URL") else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return;
    };
    // Die Passwortdatei für die Datenbank kommt wie bei stratum selbst aus
    // der Umgebung; relative Pfade gelten vom Projektverzeichnis aus.
    if let Some(p) = std::env::var_os("STRATUM_DB_PASSWORT_DATEI") {
        let p = std::path::PathBuf::from(p);
        if p.is_relative() {
            std::env::set_current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        }
    }
    let name = format!("stratum_test_{}", uuid::Uuid::now_v7().simple());
    sql(&url, format!("CREATE DATABASE {name}"));
    let (basis, _) = url.rsplit_once('/').unwrap();
    let neu = format!("{basis}/{name}");
    let tmp = tempfile::tempdir().unwrap();
    let chef = tmp.path().join("chef");
    let mia = tmp.path().join("mia");
    std::fs::write(&chef, "chef-passwort-123\n").unwrap();
    std::fs::write(&mia, "mia-passwort-456\n").unwrap();
    let (chef, mia) = (chef.to_str().unwrap(), mia.to_str().unwrap());
    let ok = |args: &[&str]| {
        let o = stratum(args, Some(&neu));
        assert!(o.status.success(), "{args:?}: {}", text(&o));
        String::from_utf8(o.stdout).unwrap()
    };
    let nein = |args: &[&str], meldung: &str| {
        let o = stratum(args, Some(&neu));
        assert!(!o.status.success(), "{args:?} hätte scheitern müssen");
        assert!(text(&o).contains(meldung), "{args:?}: {}", text(&o));
    };
    let als_chef = ["--als", "chef", "--als-passwort-datei", chef];
    let als_mia = ["--als", "mia", "--als-passwort-datei", mia];

    // Ungültiger Name: verständliche Meldung, noch vor Passwort und Datenbank.
    nein(
        &[
            "superadmin",
            "einrichten",
            "NAME",
            "--anzeigename",
            "N",
            "--passwort-datei",
            chef,
        ],
        "etwa name",
    );

    ok(&[
        "superadmin",
        "einrichten",
        "chef",
        "--anzeigename",
        "Chef",
        "--passwort-datei",
        chef,
    ]);
    nein(
        &[
            "superadmin",
            "einrichten",
            "zwei",
            "--anzeigename",
            "Z",
            "--passwort-datei",
            chef,
        ],
        "verweigert",
    );
    ok(&[
        "konto",
        "registrieren",
        "mia",
        "--anzeigename",
        "Mia M.",
        "--passwort-datei",
        mia,
    ]);
    nein(&mit(&["audit", "liste"], &als_mia), "verweigert");
    nein(&["konto", "liste"], "verweigert");
    nein(
        &mit(
            &["konto", "freigeben", "mia", "--rolle", "Gibtsnicht"],
            &als_chef,
        ),
        "keine Rolle Gibtsnicht",
    );
    ok(&mit(
        &["konto", "freigeben", "mia", "--rolle", "Analyst"],
        &als_chef,
    ));
    nein(
        &mit(
            &["rolle", "anlegen", "X", "--recht", "gibt.es.nicht"],
            &als_chef,
        ),
        "keine Berechtigung gibt.es.nicht",
    );
    ok(&mit(
        &[
            "rolle",
            "anlegen",
            "Fallführung",
            "--recht",
            "case.create",
            "--recht",
            "audit.view",
        ],
        &als_chef,
    ));
    ok(&mit(
        &[
            "konto",
            "rollen",
            "mia",
            "--rolle",
            "Analyst",
            "--rolle",
            "Fallführung",
        ],
        &als_chef,
    ));
    let liste = ok(&mit(&["konto", "liste"], &als_chef));
    let zeile = liste.lines().find(|l| l.starts_with("mia ")).unwrap();
    assert!(zeile.contains("active") && zeile.contains("Fallführung") && zeile.contains("Analyst"));
    // Mia darf jetzt das Audit lesen (audit.view aus der eigenen Rolle).
    let json = ok(&mit(
        &["audit", "liste", "--anzahl", "100", "--json"],
        &als_mia,
    ));
    let ereignisse: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    let aktionen: Vec<String> = ereignisse
        .iter()
        .rev()
        .map(|e| {
            format!(
                "{} {} {}",
                e["action"].as_str().unwrap(),
                e["result"].as_str().unwrap(),
                e["akteur"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        aktionen,
        [
            "USER_CREATE success stratum-cli",
            "USER_CREATE denied stratum-cli",
            "USER_REGISTER success mia",
            "LOGIN denied mia",
            "USER_LIST denied stratum-cli",
            "LOGIN success chef",
            "LOGIN success chef",
            "ROLE_GRANT success chef",
            "USER_APPROVE success chef",
            "LOGIN success chef",
            "LOGIN success chef",
            "ROLE_CREATE success chef",
            "LOGIN success chef",
            "ROLE_GRANT success chef",
            "LOGIN success chef",
            "USER_LIST success chef",
            "LOGIN success mia",
        ]
    );
    ok(&mit(&["superadmin", "ernennen", "mia"], &als_chef));
    ok(&mit(&["superadmin", "entziehen", "chef"], &als_mia));
    nein(
        &mit(&["superadmin", "entziehen", "mia"], &als_mia),
        "letzte",
    );
    ok(&mit(&["rolle", "loeschen", "Fallführung"], &als_mia));
    let pruefung = ok(&mit(&["audit", "pruefen"], &als_mia));
    assert!(pruefung.contains("\"fehler_gesamt\": 0"), "{pruefung}");
    let o = stratum(&["--audit-pruefen"], Some(&neu));
    assert!(o.status.success(), "{}", text(&o));
    sql(&url, format!("DROP DATABASE {name} WITH (FORCE)"));
}
