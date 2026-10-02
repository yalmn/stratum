//! Verbindung zu PostgreSQL für die Kommandozeile: Verbindung aus
//! Umgebung oder `stratum.toml`, Anmeldung und Fallwahl vor einem Lauf, das
//! Nachrechnen des Audits. Was während eines Laufs geschrieben wird, macht
//! `stratum_lauf`.
//!
//! Asynchron nur hier, in einer eigenen Laufzeit; die Analyse bleibt
//! synchron.

use anyhow::{Context, Result};
use serde_json::json;
use stratum_model::{ActorId, CaseId};
use stratum_store::Datenbank;

/// Akteur für Aktionen über die CLI: das feste Systemkonto, solange die
/// Kommandozeile ohne Anmeldung arbeitet. Wer sie aufgerufen hat, steht als
/// Benutzer des Betriebssystems im Audit.
pub fn cli_akteur() -> ActorId {
    ActorId::cli()
}

/// Benutzer des Betriebssystems (bei `sudo` der aufrufende).
pub fn betriebssystem_benutzer() -> Option<String> {
    ["SUDO_USER", "USER", "LOGNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
}

/// Verbindet mit der Datenbank: URL aus `STRATUM_DB_URL` oder
/// `stratum.toml`, Passwort aus der Datei in `STRATUM_DB_PASSWORT_DATEI` oder
/// `stratum.toml`.
pub fn verbinden() -> Result<(tokio::runtime::Runtime, Datenbank)> {
    let k = crate::konfig::konfig()?;
    let url = k.db_url().context(
        "keine Datenbank angegeben: STRATUM_DB_URL setzen oder [datenbank] url in stratum.toml",
    )?;
    // Passwort aus einer Datei (dieselbe, die Docker als Secret nutzt).
    let passwort = match k.db_passwort_datei() {
        Some(p) => Some(
            std::fs::read_to_string(&p)
                .with_context(|| format!("Passwortdatei nicht lesbar: {}", p.to_string_lossy()))?
                .trim()
                .to_string(),
        ),
        None => None,
    };
    // multi_thread mit einem Worker: so treibt auch `Handle::block_on` aus
    // dem synchronen Lauf die Verbindung (bei current_thread täte es das
    // nur innerhalb von `Runtime::block_on`).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .context("Laufzeit für die Datenbank nicht erstellbar")?;
    let db = rt.block_on(Datenbank::verbinden_mit(&url, passwort.as_deref()))?;
    Ok((rt, db))
}

/// Rechnet die Audit-Kette nach (`--audit-pruefen`) und gibt das Ergebnis
/// als JSON aus. Fehler in der Kette führen zu einem Fehler-Exitcode.
pub fn audit_pruefen() -> Result<()> {
    let (rt, db) = verbinden()?;
    audit_pruefen_mit(&rt, &db, cli_akteur())
}

/// Wie [`audit_pruefen`], mit gegebener Verbindung und handelndem Konto.
pub fn audit_pruefen_mit(
    rt: &tokio::runtime::Runtime,
    db: &Datenbank,
    akteur: ActorId,
) -> Result<()> {
    let p = rt.block_on(db.audit_pruefen(akteur))?;
    println!("{}", serde_json::to_string_pretty(&p)?);
    if !p.intakt() {
        anyhow::bail!(
            "Audit-Kette nicht intakt: {} Fehler in {} Ereignissen",
            p.fehler_gesamt,
            p.ereignisse
        );
    }
    eprintln!(
        "[+] Audit-Kette intakt: {} Ereignisse, letzter Hash {}",
        p.ereignisse, p.letzter_hash
    );
    Ok(())
}

/// Verbindung, angemeldetes Konto und gewählter Fall, vor der Analyse
/// hergestellt: ein falsches Passwort oder ein unbekannter Fall fällt so vor
/// dem langen Image-Hash auf.
pub struct Vorbereitet {
    rt: tokio::runtime::Runtime,
    db: Datenbank,
    akteur: ActorId,
    fall: Option<CaseId>,
}

impl Vorbereitet {
    /// Verbindet, meldet `als` an (sonst das Konto aus `stratum.toml`, sonst
    /// das Systemkonto) und löst die Fallnummer auf.
    pub fn herstellen(
        als: Option<&str>,
        als_passwort_datei: Option<&std::path::Path>,
        fall_nummer: Option<&str>,
    ) -> Result<Self> {
        let (rt, db) = verbinden().context("--db")?;
        let akteur = crate::verwaltung::anmelden(&rt, &db, als, als_passwort_datei)?;
        let fall = match fall_nummer {
            Some(n) => Some(rt.block_on(db.fall_id(n))?.with_context(|| {
                format!("kein Fall {n} (anlegen mit: stratum fall neu {n} --titel …)")
            })?),
            None => None,
        };
        // Ohne analysis.start gar nicht erst hashen; die Ablehnung steht im
        // Audit wie bei jeder anderen Aktion.
        rt.block_on(db.verlangen(
            akteur,
            stratum_model::Permission::AnalysisStart,
            stratum_store::AuditEintrag {
                akteur,
                case_id: fall,
                aktion: stratum_model::AuditAction::AnalysisStart,
                objekt_typ: "analysis_run",
                objekt_id: None,
                ergebnis: stratum_model::AuditResult::Denied,
                details: json!({"vorabpruefung": true}),
            },
        ))?;
        Ok(Self {
            rt,
            db,
            akteur,
            fall,
        })
    }
}

impl Vorbereitet {
    /// Ziel für `stratum_lauf`: Verbindung, Konto, Fall und der Benutzer
    /// des Betriebssystems für das Audit. Die Laufzeit bleibt bei `self`.
    pub fn ziel(&self) -> stratum_lauf::DbZiel {
        stratum_lauf::DbZiel {
            handle: self.rt.handle().clone(),
            db: self.db.clone(),
            akteur: self.akteur,
            fall: self.fall,
            audit_details: json!({"betriebssystem_benutzer": betriebssystem_benutzer()}),
        }
    }
}
