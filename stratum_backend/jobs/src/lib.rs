//! Worker für Jobs: holt wartende Aufträge aus PostgreSQL und führt sie aus.
//!
//! Ein Analyse-Job analysiert eine im Fall registrierte Evidence mit
//! [`stratum_lauf::analysieren`], im Namen dessen, der den Job angelegt hat.
//! Ein Import-Job hasht eine Datei aus dem Fallordner und registriert sie
//! als Evidence ([`stratum_lauf::import`]).
//! Fortschritt geht höchstens einmal je Sekunde in die Job-Tabelle; das ist
//! zugleich das Lebenszeichen, und die Antwort sagt, ob abgebrochen werden
//! soll. Report und Seitendateien liegen in `<ausgabe>/<Job-ID>/`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use stratum_lauf::{LaufFehler, Phase, Rueckmeldung};
use stratum_model::{AnalysisRunId, EvidenceId, EvidenceKind, Job, JobId, JobKind, JobStatus};
use stratum_store::{Datenbank, StoreError};

/// Fehler des Workers selbst (nicht eines Jobs; die landen im Job).
#[derive(Debug, thiserror::Error)]
pub enum JobFehler {
    /// Datenbank.
    #[error(transparent)]
    Datenbank(#[from] StoreError),
}

/// Optionen eines Analyse-Jobs. Bewusst ohne Geheimnisse: DPAPI- und
/// Firefox-Passwörter stünden sonst im Klartext in der Datenbank.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalyseOptionen {
    /// Dateikatalog zusätzlich als Datei.
    pub katalog: bool,
    /// SHA-256 und Signaturtyp jeder Datei im Katalog.
    pub datei_hashes: bool,
    /// MFT-Zeitachse als Datei.
    pub mft_timeline: bool,
    /// USN-Journal als Datei.
    pub usn_journal: bool,
    /// Das ganze Image roh nach Begriffen durchsuchen.
    pub raw_sweep: bool,
    /// Die mitgelieferte Begriffsliste nicht verwenden.
    pub ohne_begriffe: bool,
    /// Die bei der Evidence vermerkte bdp.info verwenden (nur diese
    /// Partition).
    pub bdp: bool,
}

/// Parameter eines Import-Jobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportParameter {
    /// Datei, aufgelöst und innerhalb des Fallordners.
    pub datei: PathBuf,
    /// Anzeigename (Standard: Dateiname).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// System oder Rolle, zu der die Evidence gehört.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolle: Option<String>,
    /// Art statt der Erkennung.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub art: Option<EvidenceKind>,
}

#[derive(Deserialize)]
struct AnalyseParameter {
    evidence_id: EvidenceId,
    #[serde(default)]
    optionen: AnalyseOptionen,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct YaraParameter {
    evidence_id: EvidenceId,
    volume: i64,
    mft: i64,
    regeln: String,
    regel_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetzwerkParameter {
    host: String,
    dns: bool,
    whois: bool,
}

/// Ein Worker.
pub struct Worker {
    db: Datenbank,
    handle: tokio::runtime::Handle,
    name: String,
    ausgabe: PathBuf,
}

impl Worker {
    /// Neuer Worker. `handle` muss zu einer Laufzeit mit eigenem Treiber
    /// gehören (`multi_thread`); `ausgabe` ist der Ordner für Reports.
    pub fn neu(db: Datenbank, handle: tokio::runtime::Handle, ausgabe: PathBuf) -> Self {
        let rechner = std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|h| h.trim().to_string())
            })
            .unwrap_or_else(|| "worker".into());
        Self {
            db,
            handle,
            name: format!("{rechner}:{}", std::process::id()),
            ausgabe,
        }
    }

    /// Name des Workers (Rechner und Prozess).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Holt einen Job und führt ihn aus. `None`, wenn keiner wartet oder
    /// schon die Höchstzahl läuft. Blockiert für die Dauer des Jobs; nicht
    /// aus einer asynchronen Aufgabe heraus aufrufen.
    pub fn einmal(&self) -> Result<Option<(JobId, JobStatus)>, JobFehler> {
        let Some(job) = self.handle.block_on(self.db.job_holen(&self.name))? else {
            return Ok(None);
        };
        let id = job.id;
        Ok(Some((id, self.ausfuehren(job)?)))
    }

    /// Führt einen schon geholten (laufenden) Job aus und beendet ihn.
    pub fn ausfuehren(&self, job: Job) -> Result<JobStatus, JobFehler> {
        let r = JobRueckmeldung {
            db: &self.db,
            handle: &self.handle,
            job: job.id,
            abbruch: AtomicBool::new(job.cancel_requested),
            stand: Mutex::new(Stand {
                gesendet: Instant::now() - Duration::from_secs(10),
                fortschritt: json!({}),
                phasenbeginn: std::collections::HashMap::new(),
            }),
        };
        let (status, fehler, ergebnis) = match job.kind {
            JobKind::Analysis => match self.analyse(&job, &r) {
                Ok(e) => (JobStatus::Completed, None, Some(e)),
                Err(LaufFehler::Abgebrochen) => {
                    (JobStatus::Cancelled, Some("abgebrochen".to_string()), None)
                }
                Err(f) => (JobStatus::Failed, Some(fehlerkette(&f)), None),
            },
            JobKind::NetworkEnrichment => match self.netzwerk(&job, &r) {
                Ok(e) => (JobStatus::Completed, None, Some(e)),
                Err(LaufFehler::Abgebrochen) => {
                    (JobStatus::Cancelled, Some("abgebrochen".into()), None)
                }
                Err(f) => (JobStatus::Failed, Some(fehlerkette(&f)), None),
            },
            JobKind::HttpReplay => match self.http_replay(&job, &r) {
                Ok(e) => (JobStatus::Completed, None, Some(e)),
                Err(LaufFehler::Abgebrochen) => {
                    (JobStatus::Cancelled, Some("abgebrochen".into()), None)
                }
                Err(f) => (JobStatus::Failed, Some(fehlerkette(&f)), None),
            },
            JobKind::YaraScan => match self.yara(&job, &r) {
                Ok(e) => (JobStatus::Completed, None, Some(e)),
                Err(LaufFehler::Abgebrochen) => {
                    (JobStatus::Cancelled, Some("abgebrochen".into()), None)
                }
                Err(f) => (JobStatus::Failed, Some(fehlerkette(&f)), None),
            },
            JobKind::EvidenceImport => match self.import(&job, &r) {
                Ok(e) => (JobStatus::Completed, None, Some(e)),
                Err(LaufFehler::Abgebrochen) => {
                    (JobStatus::Cancelled, Some("abgebrochen".to_string()), None)
                }
                Err(f) => (JobStatus::Failed, Some(fehlerkette(&f)), None),
            },
        };
        r.senden(true);
        self.handle.block_on(self.db.job_beenden(
            job.id,
            status,
            fehler.as_deref(),
            ergebnis.as_ref(),
        ))?;
        Ok(status)
    }

    fn netzwerk(&self, job: &Job, r: &JobRueckmeldung<'_>) -> Result<Value, LaufFehler> {
        let p: NetzwerkParameter = serde_json::from_value(job.parameters.clone())?;
        let audit = stratum_store::AuditEintrag {
            akteur: job.created_by,
            case_id: Some(job.case_id),
            aktion: stratum_model::AuditAction::ConnectorUse,
            objekt_typ: "job",
            objekt_id: Some(job.id.to_string()),
            ergebnis: stratum_model::AuditResult::Success,
            details: json!({"connector":"dns-whois-v1", "host":p.host, "dns":p.dns,"whois":p.whois}),
        };
        self.handle.block_on(self.db.verlangen(
            job.created_by,
            stratum_model::Permission::CaseView,
            audit.clone(),
        ))?;
        self.handle.block_on(self.db.verlangen(
            job.created_by,
            stratum_model::Permission::ConnectorUse,
            audit.clone(),
        ))?;
        let zeit = chrono::Utc::now();
        r.meldung("Externe DNS-/WHOIS-Abfragen ausführen");
        let result = stratum_connectors::netzwerk::abfragen(&p.host, p.dns, p.whois, &|| {
            r.abbruch_angefordert()
        });
        let success = result
            .as_ref()
            .is_ok_and(|results| results.iter().all(|r| r.erfolgreich));
        self.handle
            .block_on(self.db.audit(&stratum_store::AuditEintrag {
                ergebnis: if success {
                    stratum_model::AuditResult::Success
                } else {
                    stratum_model::AuditResult::Failure
                },
                ..audit
            }))?;
        let antworten = result.map_err(|e| match e {
            stratum_connectors::ConnectorFehler::Abgebrochen => LaufFehler::Abgebrochen,
            e => LaufFehler::Eingabe(e.to_string()),
        })?;
        Ok(
            json!({"werkzeug":"DNS/WHOIS", "connector":"dns-whois-v1", "host":p.host, "abgefragt_am":zeit, "beendet_am":chrono::Utc::now(), "ableitung":stratum_model::DerivationKind::ExternalIntel, "alle_erfolgreich":success, "antworten":antworten}),
        )
    }

    fn http_replay(&self, job: &Job, r: &JobRueckmeldung<'_>) -> Result<Value, LaufFehler> {
        let p: stratum_model::http_lab::HttpReplayRequest =
            serde_json::from_value(job.parameters.clone())?;
        p.pruefen().map_err(LaufFehler::Eingabe)?;
        let audit = stratum_store::AuditEintrag {
            akteur: job.created_by,
            case_id: Some(job.case_id),
            aktion: stratum_model::AuditAction::ReconstructionStart,
            objekt_typ: "job",
            objekt_id: Some(job.id.to_string()),
            ergebnis: stratum_model::AuditResult::Success,
            details: json!({"connector":"http-offline-v1","network_policy":"none","direction":p.direction,"method":p.method,"source":p.source}),
        };
        for permission in [
            stratum_model::Permission::CaseView,
            stratum_model::Permission::FileView,
            stratum_model::Permission::AnalysisStart,
            stratum_model::Permission::ConnectorUse,
        ] {
            self.handle
                .block_on(self.db.verlangen(job.created_by, permission, audit.clone()))?;
        }
        let started = chrono::Utc::now();
        r.meldung("HTTP-Rekonstruktion im Offline-Lab ausführen");
        self.handle.block_on(self.db.audit(&audit))?;
        let result = stratum_connectors::http_lab::replay(&p, &|| r.abbruch_angefordert());
        self.handle
            .block_on(self.db.audit(&stratum_store::AuditEintrag {
                aktion: stratum_model::AuditAction::ConnectorUse,
                ergebnis: if result.is_ok() {
                    stratum_model::AuditResult::Success
                } else {
                    stratum_model::AuditResult::Failure
                },
                ..audit
            }))?;
        let exchange = result.map_err(|e| match e {
            stratum_connectors::ConnectorFehler::Abgebrochen => LaufFehler::Abgebrochen,
            e => LaufFehler::Eingabe(e.to_string()),
        })?;
        Ok(
            json!({"werkzeug":"HTTP Lab","ableitung":stratum_model::DerivationKind::Reconstructed,"started_at":started,"finished_at":chrono::Utc::now(),"direction":p.direction,"source":p.source,"hypothesis":p.hypothesis,"simulation":true,"lab":exchange}),
        )
    }

    fn yara(&self, job: &Job, r: &JobRueckmeldung<'_>) -> Result<Value, LaufFehler> {
        use stratum_connectors::yara::{regeln_pruefen, scannen, YaraFehler};
        let p: YaraParameter = serde_json::from_value(job.parameters.clone())?;
        self.handle.block_on(self.db.verlangen(
            job.created_by,
            stratum_model::Permission::AnalysisStart,
            stratum_store::AuditEintrag {
                akteur: job.created_by,
                case_id: Some(job.case_id),
                aktion: stratum_model::AuditAction::ConnectorUse,
                objekt_typ: "job",
                objekt_id: Some(job.id.to_string()),
                ergebnis: stratum_model::AuditResult::Success,
                details: json!({"connector":"yara-v1"}),
            },
        ))?;
        regeln_pruefen(&p.regeln).map_err(|e| LaufFehler::Eingabe(e.to_string()))?;
        if stratum_core::hash_bytes(p.regeln.as_bytes()).sha256 != p.regel_sha256 {
            return Err(LaufFehler::Eingabe(
                "Regelhash stimmt nicht mit Auftrag überein".into(),
            ));
        }
        let q = self.handle.block_on(self.db.datei_quelle(
            job.created_by,
            p.evidence_id,
            p.volume,
            p.mft,
            stratum_store::dateien::Zugriff::Suchen,
        ))?;
        if q.fall != job.case_id {
            return Err(LaufFehler::Eingabe(
                "Datei gehört nicht zum Job-Fall".into(),
            ));
        }
        if q.groesse.is_some_and(|size| size > 256 * 1024 * 1024) {
            return Err(LaufFehler::Eingabe(
                "Datei größer als YARA-Limit von 256 MiB".into(),
            ));
        }
        stratum_connectors::yara::bereitschaft(&|| r.abbruch_angefordert()).map_err(
            |e| match e {
                YaraFehler::Abgebrochen => LaufFehler::Abgebrochen,
                e => LaufFehler::Eingabe(e.to_string()),
            },
        )?;
        let dir =
            tempfile::tempdir().map_err(|e| LaufFehler::Eingabe(format!("Arbeitsordner: {e}")))?;
        std::fs::write(dir.path().join("rules.yar"), &p.regeln)
            .map_err(|e| LaufFehler::Eingabe(format!("Regelkopie: {e}")))?;
        let out = std::fs::File::create(dir.path().join("target.bin"))
            .map_err(|e| LaufFehler::Eingabe(format!("Dateikopie: {e}")))?;
        let o = stratum_lauf::datei::DateiOrt {
            image: std::path::Path::new(&q.image),
            bdp: q.bdp.as_deref().map(std::path::Path::new),
            volume_offset: u64::try_from(p.volume)
                .map_err(|_| LaufFehler::Eingabe("Volume ungültig".into()))?,
            mft: u64::try_from(p.mft).map_err(|_| LaufFehler::Eingabe("MFT ungültig".into()))?,
        };
        r.phase_beginn(Phase::Suche);
        r.meldung("Datei für lokalen YARA-Scan bereitstellen");
        let bytes = stratum_lauf::datei::inhalt_kopieren(&o, out, 256 * 1024 * 1024, r)?;
        r.meldung("YARA-Regeln ausführen");
        let ergebnis =
            scannen(dir.path(), bytes, &|| r.abbruch_angefordert()).map_err(|e| match e {
                YaraFehler::Abgebrochen => LaufFehler::Abgebrochen,
                e => LaufFehler::Eingabe(e.to_string()),
            })?;
        r.phase_ende(Phase::Suche);
        Ok(
            json!({"werkzeug":"YARA", "regel_sha256":p.regel_sha256, "quelle":{"evidence":q.evidence,"volume":p.volume,"mft":p.mft,"pfad":q.pfad,"offset_basis":"logical_file"}, "ableitung":stratum_model::DerivationKind::Derived, "bytes":bytes, "ergebnis":ergebnis}),
        )
    }

    fn import(&self, job: &Job, r: &JobRueckmeldung<'_>) -> Result<Value, LaufFehler> {
        let p: ImportParameter = serde_json::from_value(job.parameters.clone())?;
        // Noch einmal prüfen: zwischen Einreihen und Ausführen kann sich
        // der Ordner geändert haben (etwa ein neuer symbolischer Link).
        let ordner = self
            .handle
            .block_on(self.db.fall_ordner(job.case_id))?
            .ok_or_else(|| LaufFehler::Eingabe("Fall ohne Fallordner".into()))?;
        let datei = stratum_lauf::import::im_ordner(&p.datei, std::path::Path::new(&ordner))?;
        let ev = stratum_lauf::import::einlesen(
            &stratum_lauf::import::Einlesen {
                fall: job.case_id,
                datei,
                name: p.name,
                rolle: p.rolle,
                art: p.art,
                akteur: job.created_by,
            },
            r,
        )?;
        let neu = self
            .handle
            .block_on(self.db.evidence_registrieren(job.created_by, &ev))?;
        r.meldung(&format!(
            "[+] Evidence {} {}",
            ev.name,
            if neu {
                "registriert"
            } else {
                "war schon registriert, Hash bestätigt"
            }
        ));
        Ok(json!({
            "evidence_id": ev.id,
            "name": ev.name,
            "kind": ev.kind,
            "support": ev.support,
            "sha256": ev.sha256,
            "blake3": ev.blake3,
            "groesse": ev.size,
            "neu": neu,
        }))
    }

    fn analyse(&self, job: &Job, r: &JobRueckmeldung<'_>) -> Result<Value, LaufFehler> {
        let p: AnalyseParameter = serde_json::from_value(job.parameters.clone())?;
        let ev = self
            .handle
            .block_on(self.db.evidence_lesen(p.evidence_id))?;
        if !matches!(ev.kind, EvidenceKind::RawDiskImage | EvidenceKind::E01Image) {
            return Err(LaufFehler::Eingabe(format!(
                "Evidence {} ({:?}) ist kein analysierbares Image",
                ev.name, ev.kind
            )));
        }
        let ordner = self.ausgabe.join(job.id.to_string());
        std::fs::create_dir_all(&ordner).map_err(|e| LaufFehler::Schritt {
            kontext: format!("Ausgabeordner nicht anlegbar: {}", ordner.display()),
            quelle: Box::new(e),
        })?;
        let o = &p.optionen;
        let bdp = if o.bdp {
            Some(
                ev.metadata
                    .get("bdp_info")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                    .ok_or_else(|| {
                        LaufFehler::Eingabe("bei der Evidence ist keine bdp.info vermerkt".into())
                    })?,
            )
        } else {
            None
        };
        let datei = |n: &str, ja: bool| ja.then(|| ordner.join(n));
        let optionen = stratum_lauf::Optionen {
            image: PathBuf::from(&ev.source_uri),
            bdp,
            hashen: true,
            mitgelieferte_begriffe: !o.ohne_begriffe,
            begriffstabellen: Vec::new(),
            raw_sweep: o.raw_sweep,
            onion_proxy: None,
            dpapi: None,
            firefox_passwort: None,
            katalog: datei("katalog.jsonl", o.katalog),
            datei_hashes: o.datei_hashes,
            mft_timeline: datei("mft_timeline.jsonl", o.mft_timeline),
            usn_journal: datei("usn_journal.jsonl", o.usn_journal),
            modell: None,
            fall_id: None,
            gestartet: chrono::Utc::now(),
        };
        let ziel = stratum_lauf::DbZiel {
            handle: self.handle.clone(),
            db: self.db.clone(),
            akteur: job.created_by,
            fall: Some(job.case_id),
            audit_details: json!({"job_id": job.id, "worker": self.name}),
        };
        let e = stratum_lauf::analysieren(&optionen, Some(ziel), r)?;
        let pfad = ordner.join("report.json");
        let geschrieben = stratum_lauf::report_schreiben(&e.report, &pfad);
        let sha = geschrieben.as_ref().ok().cloned();
        if let Some(s) = e.sitzung {
            s.abschliessen(sha.as_deref(), sha.as_ref().map(|_| pfad.as_path()))?;
        }
        let sha = geschrieben?;
        r.meldung(&format!("[+] Report geschrieben: {}", pfad.display()));
        Ok(json!({
            "ausgabe": ordner.display().to_string(),
            "report": pfad.display().to_string(),
            "report_sha256": sha,
            "funde": e.report.findings.len(),
            "zeitstrahl": e.report.timeline.len(),
            "warnungen": e.report.warnings.len(),
        }))
    }
}

/// Fehler samt Ursachen als eine Zeile.
fn fehlerkette(f: &dyn std::error::Error) -> String {
    let mut t = f.to_string();
    let mut q = f.source();
    while let Some(e) = q {
        t.push_str(": ");
        t.push_str(&e.to_string());
        q = e.source();
    }
    t
}

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Hashing => "hashing",
        Phase::Katalog => "katalog",
        Phase::Analyzer => "analyzer",
        Phase::Suche => "suche",
    }
}

struct Stand {
    gesendet: Instant,
    fortschritt: Value,
    phasenbeginn: std::collections::HashMap<&'static str, Instant>,
}

/// Rückmeldung eines Jobs: schreibt Fortschritt gedrosselt in die
/// Datenbank und merkt sich, ob abgebrochen werden soll.
struct JobRueckmeldung<'a> {
    db: &'a Datenbank,
    handle: &'a tokio::runtime::Handle,
    job: JobId,
    abbruch: AtomicBool,
    stand: Mutex<Stand>,
}

impl JobRueckmeldung<'_> {
    fn aendern(&self, f: impl FnOnce(&mut Value)) {
        let mut s = self.stand.lock().unwrap_or_else(|v| v.into_inner());
        f(&mut s.fortschritt);
    }

    /// Schreibt den Stand, wenn seit dem letzten Mal eine Sekunde vergangen
    /// ist (oder `immer`).
    fn senden(&self, immer: bool) {
        let wert = {
            let mut s = self.stand.lock().unwrap_or_else(|v| v.into_inner());
            if !immer && s.gesendet.elapsed() < Duration::from_secs(1) {
                return;
            }
            s.gesendet = Instant::now();
            s.fortschritt.clone()
        };
        // Ohne Datenbank kein Lebenszeichen; dann lieber abbrechen, statt
        // stundenlang unbemerkt weiterzurechnen.
        let abbruch = self
            .handle
            .block_on(self.db.job_fortschritt(self.job, &wert))
            .unwrap_or(true);
        if abbruch {
            self.abbruch.store(true, Ordering::Relaxed);
        }
    }
}

impl Rueckmeldung for JobRueckmeldung<'_> {
    fn meldung(&self, text: &str) {
        self.aendern(|v| v["meldung"] = json!(text));
        self.senden(false);
    }

    // Stand je Phase (Suche und Analyzer laufen gleichzeitig); `phase` ist
    // die zuletzt begonnene.
    fn fortschritt(&self, phase: Phase, erledigt: u64, gesamt: u64) {
        self.aendern(|v| {
            v["phasen"][phase_name(phase)] = json!({"erledigt": erledigt, "gesamt": gesamt});
        });
        self.senden(false);
    }

    fn phase_beginn(&self, phase: Phase) {
        {
            let mut s = self.stand.lock().unwrap_or_else(|v| v.into_inner());
            s.phasenbeginn.insert(phase_name(phase), Instant::now());
            s.fortschritt["phase"] = json!(phase);
            s.fortschritt["phasen"][phase_name(phase)] = json!({"erledigt": 0, "gesamt": 0});
        }
        self.senden(true);
    }

    fn phase_ende(&self, phase: Phase) {
        {
            let mut s = self.stand.lock().unwrap_or_else(|v| v.into_inner());
            if let Some(beginn) = s.phasenbeginn.remove(phase_name(phase)) {
                let dauer_ms = u64::try_from(beginn.elapsed().as_millis()).unwrap_or(u64::MAX);
                let stand = &mut s.fortschritt["phasen"][phase_name(phase)];
                stand["dauer_ms"] = json!(dauer_ms);
                stand["abgeschlossen"] = json!(true);
            }
        }
        self.senden(true);
    }

    fn lauf_begonnen(&self, lauf: AnalysisRunId) {
        if let Err(e) = self.handle.block_on(self.db.job_lauf(self.job, lauf)) {
            self.aendern(|v| v["meldung"] = json!(format!("Lauf nicht vermerkt: {e}")));
        }
    }

    fn abbruch_angefordert(&self) -> bool {
        self.senden(false);
        self.abbruch.load(Ordering::Relaxed)
    }
}
