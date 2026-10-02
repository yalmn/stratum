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

/// Eigene Testdatenbank; wird beim Verlassen gelöscht, auch wenn der Test
/// scheitert.
struct Wegwerf {
    url: String,
    name: String,
}

impl Wegwerf {
    fn neu(url: &str) -> Self {
        let name = format!("stratum_test_{}", uuid::Uuid::now_v7().simple());
        sql(url, format!("CREATE DATABASE {name}"));
        Self {
            url: url.to_string(),
            name,
        }
    }
}

impl Drop for Wegwerf {
    fn drop(&mut self) {
        sql(
            &self.url,
            format!("DROP DATABASE {} WITH (FORCE)", self.name),
        );
    }
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
    let wegwerf = Wegwerf::neu(&url);
    let (basis, _) = url.rsplit_once('/').unwrap();
    let neu = format!("{basis}/{}", wegwerf.name);
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
    // Gesperrte Dienstkonten (hier „unbekannt“) nur mit --alle.
    assert!(!liste.lines().any(|l| l.starts_with("unbekannt ")));
    let alle = ok(&mit(&["konto", "liste", "--alle"], &als_chef));
    assert!(alle.lines().any(|l| l.starts_with("unbekannt ")));
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
}

/// stratum nur mit Konfigurationsdatei, ohne Umgebungsvariablen der
/// Datenbank.
fn mit_konfig(args: &[&str], konfig: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stratum"))
        .args(args)
        .env_remove("STRATUM_DB_URL")
        .env_remove("STRATUM_DB_PASSWORT_DATEI")
        .env_remove("STRATUM_KONTO")
        .env("STRATUM_KONFIG", konfig)
        .output()
        .unwrap()
}

#[test]
fn fall_evidence_analyse_mit_konfig() {
    let Ok(url) = std::env::var("STRATUM_DB_URL") else {
        eprintln!("STRATUM_DB_URL nicht gesetzt, Test übersprungen");
        return;
    };
    let wegwerf = Wegwerf::neu(&url);
    let name = &wegwerf.name;
    let (basis, _) = url.rsplit_once('/').unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let mut konfig =
        format!("[jobs]\nausgabe = \"jobs\"\n\n[datenbank]\nurl = \"{basis}/{name}\"\n");
    if let Some(p) = db_passwort() {
        std::fs::write(d.join("dbpw"), p).unwrap();
        // Relativ zur Konfigurationsdatei.
        konfig.push_str("passwort_datei = \"dbpw\"\n");
    }
    let k = d.join("stratum.toml");
    std::fs::write(&k, konfig).unwrap();
    for (n, p) in [
        ("chef", "chef-passwort-123"),
        ("mia", "mia-passwort-456"),
        ("tom", "tom-passwort-789"),
    ] {
        std::fs::write(d.join(n), p).unwrap();
    }
    // Kein Image mit Partitionen: wird als „other“ registriert.
    let bild = d.join("abbild.bin");
    std::fs::write(&bild, vec![0u8; 1 << 20]).unwrap();
    let pf = |n: &str| d.join(n).display().to_string();
    let (chef, mia, tom, bild_s, bericht) = (
        pf("chef"),
        pf("mia"),
        pf("tom"),
        pf("abbild.bin"),
        pf("r.json"),
    );
    let ok = |args: &[&str]| {
        let o = mit_konfig(args, &k);
        assert!(o.status.success(), "{args:?}: {}", text(&o));
        text(&o)
    };
    let als = |n: &'static str, p: &str| -> Vec<String> {
        vec![
            "--als".into(),
            n.into(),
            "--als-passwort-datei".into(),
            p.into(),
        ]
    };
    let mitals = |a: &[&str], b: &[String]| -> Vec<String> {
        a.iter()
            .map(|s| s.to_string())
            .chain(b.iter().cloned())
            .collect()
    };
    let lauf = |v: Vec<String>| {
        let r: Vec<&str> = v.iter().map(String::as_str).collect();
        mit_konfig(&r, &k)
    };

    assert!(ok(&["konfig"]).contains(&format!("{basis}/{name}")));
    ok(&[
        "superadmin",
        "einrichten",
        "chef",
        "--anzeigename",
        "Chef",
        "--passwort-datei",
        &chef,
    ]);
    ok(&[
        "konto",
        "registrieren",
        "mia",
        "--anzeigename",
        "Mia",
        "--passwort-datei",
        &mia,
    ]);
    ok(&[
        "konto",
        "registrieren",
        "tom",
        "--anzeigename",
        "Tom",
        "--passwort-datei",
        &tom,
    ]);
    let o = lauf(mitals(
        &["konto", "freigeben", "mia", "--rolle", "Forensic Examiner"],
        &als("chef", &chef),
    ));
    assert!(o.status.success(), "{}", text(&o));
    let o = lauf(mitals(
        &["konto", "freigeben", "tom", "--rolle", "Analyst"],
        &als("chef", &chef),
    ));
    assert!(o.status.success(), "{}", text(&o));
    let o = lauf(mitals(
        &[
            "fall",
            "neu",
            "F-1",
            "--titel",
            "Test",
            "--ordner",
            d.to_str().unwrap(),
        ],
        &als("chef", &chef),
    ));
    assert!(o.status.success(), "{}", text(&o));
    // Ohne case.create kein Fall.
    let o = lauf(mitals(
        &["fall", "neu", "F-2", "--titel", "x"],
        &als("mia", &mia),
    ));
    assert!(
        !o.status.success() && text(&o).contains("case.create"),
        "{}",
        text(&o)
    );

    let o = lauf(mitals(
        &["evidence", "hinzu", "F-1", &bild_s, "--rolle", "Test"],
        &als("mia", &mia),
    ));
    let t = text(&o);
    assert!(o.status.success(), "{t}");
    assert!(t.contains("(other, unsupported_format)"), "{t}");
    let id = t
        .lines()
        .find_map(|l| l.trim().strip_prefix("ID"))
        .unwrap()
        .trim()
        .to_string();

    // Ohne analysis.start: abgelehnt, bevor das Image gehasht wird.
    let o = lauf(mitals(
        &[&bild_s, "--db", "--fall", "F-1", "-o", &bericht],
        &als("tom", &tom),
    ));
    let t = text(&o);
    assert!(!o.status.success() && t.contains("analysis.start"), "{t}");
    assert!(!t.contains("Integritäts-Hashes"), "{t}");
    assert!(!Path::new(&bericht).exists());

    // Mit Recht: der Lauf nutzt die registrierte Evidence weiter.
    let o = lauf(mitals(
        &[&bild_s, "--db", "--fall", "F-1", "-o", &bericht],
        &als("mia", &mia),
    ));
    assert!(o.status.success(), "{}", text(&o));
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bericht).unwrap()).unwrap();
    assert_eq!(r["modell"]["evidence_id"], id.as_str());
    assert!(r["modell"].get("pfad").is_none());
    let o = lauf(mitals(&["fall", "zeigen", "F-1"], &als("mia", &mia)));
    let t = text(&o);
    assert!(t.contains("Evidence    1") && t.contains(&id), "{t}");

    let o = lauf(mitals(
        &["audit", "liste", "--anzahl", "10", "--json"],
        &als("chef", &chef),
    ));
    assert!(o.status.success(), "{}", text(&o));
    let ereignisse: Vec<serde_json::Value> = serde_json::from_slice(&o.stdout).unwrap();
    let kurz: Vec<String> = ereignisse
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
        kurz,
        [
            "LOGIN success tom",
            "ANALYSIS_START denied tom",
            "LOGIN success mia",
            "EVIDENCE_VERIFY success mia",
            "ANALYSIS_START success mia",
            "ANALYSIS_COMPLETE success mia",
            "REPORT_CREATE success mia",
            "LOGIN success mia",
            "CASE_OPEN success mia",
            "LOGIN success chef",
        ]
    );

    // Job: eingereiht, vom Worker übernommen; eine Datei ohne Partitionen
    // ist kein analysierbares Image, der Job scheitert mit Begründung.
    let o = lauf(mitals(
        &["job", "analyse", "F-1", "abbild.bin"],
        &als("mia", &mia),
    ));
    assert!(o.status.success(), "{}", text(&o));
    let job = String::from_utf8(o.stdout).unwrap().trim().to_string();
    let o = mit_konfig(&["worker", "--einmal"], &k);
    let t = text(&o);
    assert!(
        o.status.success() && t.contains(&format!("Job {job}: failed")),
        "{t}"
    );
    let o = lauf(mitals(
        &["job", "zeigen", &job, "--json"],
        &als("mia", &mia),
    ));
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["status"], "failed");
    assert!(j["error"]
        .as_str()
        .unwrap()
        .contains("kein analysierbares Image"));
    let o = mit_konfig(&["worker", "--einmal"], &k);
    assert!(text(&o).contains("kein Job wartet"));
}
