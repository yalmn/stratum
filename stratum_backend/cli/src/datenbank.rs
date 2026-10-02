//! Schreiben in PostgreSQL (`--db`): vor der Analyse Fall und Evidence
//! registrieren und den Lauf beginnen, dann Dateikatalog und Modell
//! speichern, nach dem Report den Lauf abschließen.
//!
//! Asynchron nur hier, in einer eigenen Laufzeit; die Analyse bleibt
//! synchron.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use stratum_model::{
    ActorId, Case, CaseClassification, CaseId, CaseStatus, Evidence, EvidenceKind, EvidenceSupport,
};
use stratum_store::{Datenbank, Geschrieben, LaufAngaben, LaufStand};

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
    let rt = tokio::runtime::Builder::new_current_thread()
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

/// Was neben dem Modell in die Datenbank geht.
pub struct Auftrag {
    /// Beginn des Laufs.
    pub gestartet: chrono::DateTime<chrono::Utc>,
    /// Image als Pfad, wie angegeben.
    pub image: std::path::PathBuf,
    /// Format des Images.
    pub format: stratum_core::ImageFormat,
    /// Mediengröße in Byte.
    pub groesse: u64,
    /// Integritäts-Hashes (bei `--db` Pflicht).
    pub hashes: stratum_core::ImageHashes,
    /// Akquisezeit aus dem E01-Kopf.
    pub akquisezeit: Option<chrono::DateTime<chrono::Utc>>,
    /// Weitere Angaben zur Evidence (E01-Kopf, bdp.info).
    pub metadaten: Value,
    /// Konfiguration des Laufs.
    pub konfiguration: Value,
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

    /// Fall aus `--fall`, falls angegeben.
    pub fn fall(&self) -> Option<CaseId> {
        self.fall
    }
}

/// Offene Verbindung mit dem laufenden Analyselauf.
pub struct Sitzung {
    rt: tokio::runtime::Runtime,
    db: Datenbank,
    akteur: ActorId,
    lauf: stratum_model::AnalysisRunId,
    fall_neu: bool,
    evidence_neu: bool,
    dateien: u64,
}

impl Auftrag {
    /// Registriert Fall (falls nicht per `--fall` gewählt) und Evidence und
    /// beginnt den Lauf als das angemeldete Konto.
    pub fn beginnen(&self, v: Vorbereitet, k: &mut stratum_normalize::Kontext) -> Result<Sitzung> {
        let Vorbereitet {
            rt,
            db,
            akteur: a,
            fall: gewaehlt,
        } = v;
        // Im gewählten Fall schon registrierte Evidence mit diesem Hash
        // weiterverwenden (auch wenn sie mit --art anders eingestuft wurde);
        // bei E01 und Rohimage derselben Mediendaten die passende Art.
        if gewaehlt.is_some() {
            let vorhanden = rt.block_on(db.evidence_nach_hash(k.case_id, &self.hashes.sha256))?;
            let passend = |art: EvidenceKind| match self.format {
                stratum_core::ImageFormat::Ewf => art == EvidenceKind::E01Image,
                stratum_core::ImageFormat::Raw => art != EvidenceKind::E01Image,
            };
            if let Some((id, _)) = vorhanden
                .iter()
                .find(|(_, art)| *art == EvidenceKind::RawDiskImage && passend(*art))
                .or_else(|| vorhanden.iter().find(|(_, art)| passend(*art)))
            {
                k.evidence_id = *id;
            }
        }
        let mut fall = self.fall(k);
        fall.created_by = a;
        let mut evidence = self.evidence(k);
        evidence.imported_by = a;
        let konfig_hash =
            stratum_core::hash_bytes(&serde_json::to_vec(&self.konfiguration)?).sha256;
        let angaben = LaufAngaben {
            started_at: self.gestartet,
            configuration: &self.konfiguration,
            configuration_hash: Some(&konfig_hash),
            audit_details: json!({"betriebssystem_benutzer": betriebssystem_benutzer()}),
        };
        let (lauf, fall_neu, evidence_neu) = rt.block_on(async {
            // Ein gewählter Fall besteht schon; anlegen hieße case.create
            // verlangen, das ein Analyst nicht braucht.
            let fall_neu = match gewaehlt {
                Some(_) => false,
                None => db.fall_anlegen(a, &fall).await?,
            };
            let evidence_neu = db.evidence_registrieren(a, &evidence).await?;
            let lauf = db.lauf_beginnen(a, k, &angaben).await?;
            Ok::<_, stratum_store::StoreError>((lauf, fall_neu, evidence_neu))
        })?;
        eprintln!(
            "[+] Datenbank: Fall {}{}, Lauf {lauf}",
            k.case_id,
            if fall_neu { " (neu)" } else { "" }
        );
        Ok(Sitzung {
            rt,
            db,
            akteur: a,
            lauf,
            fall_neu,
            evidence_neu,
            dateien: 0,
        })
    }

    fn dateiname(&self) -> String {
        self.image
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.image.display().to_string())
    }

    /// Fall mit Vorgaben; ein vorhandener Fall bleibt in der Datenbank
    /// unverändert.
    fn fall(&self, k: &stratum_normalize::Kontext) -> Case {
        let titel = match &k.host {
            Some(h) => format!("{h} ({})", self.dateiname()),
            None => self.dateiname(),
        };
        Case {
            id: k.case_id,
            case_number: format!("CLI-{}", k.case_id),
            title: titel,
            description: None,
            status: CaseStatus::Active,
            classification: CaseClassification::Internal,
            created_at: self.gestartet,
            created_by: cli_akteur(),
            opened_at: Some(self.gestartet),
            closed_at: None,
            timezone: None,
            // Der Ordner, in dem das Image liegt, gilt als Fallordner.
            case_folder: std::fs::canonicalize(&self.image)
                .ok()
                .and_then(|p| p.parent().map(|d| d.display().to_string())),
            tags: Vec::new(),
        }
    }

    fn evidence(&self, k: &stratum_normalize::Kontext) -> Evidence {
        Evidence {
            id: k.evidence_id,
            case_id: k.case_id,
            kind: match self.format {
                stratum_core::ImageFormat::Raw => EvidenceKind::RawDiskImage,
                stratum_core::ImageFormat::Ewf => EvidenceKind::E01Image,
            },
            name: self.dateiname(),
            role: None,
            original_name: None,
            source_uri: std::fs::canonicalize(&self.image)
                .unwrap_or_else(|_| self.image.clone())
                .display()
                .to_string(),
            size: self.groesse,
            sha256: self.hashes.sha256.clone(),
            blake3: self.hashes.blake3.clone(),
            acquired_at: self.akquisezeit,
            imported_at: self.gestartet,
            imported_by: cli_akteur(),
            acquisition_method: None,
            read_only: true,
            support: EvidenceSupport::Recognized,
            parent_evidence_id: None,
            metadata: self.metadaten.clone(),
        }
    }
}

impl Sitzung {
    /// Schreibt das Modell in den Lauf.
    pub fn modell(
        &self,
        m: &stratum_normalize::Modell,
        modell_sha256: Option<&str>,
    ) -> Result<Geschrieben> {
        eprintln!("[*] Schreibe Modell in die Datenbank ...");
        let mut g = self
            .rt
            .block_on(self.db.modell_speichern(self.lauf, m, modell_sha256))?;
        g.fall_neu = self.fall_neu;
        g.evidence_neu = self.evidence_neu;
        g.dateien = self.dateien;
        eprintln!(
            "[+] Datenbank: neu {} Artefakte, {} Ereignisse, {} Entitäten, {} Dateien",
            g.artefakte, g.ereignisse, g.entitaeten, g.dateien
        );
        Ok(g)
    }

    /// Schreiber für den Dateikatalog: nimmt JSON Lines an und schreibt sie
    /// blockweise in die Datenbank.
    pub fn katalog(&mut self) -> KatalogSchreiber<'_> {
        KatalogSchreiber {
            sitzung: self,
            puffer: Vec::with_capacity(1 << 22),
            zeilen: 0,
        }
    }

    /// Beendet den Lauf. Bei Erfolg mit dem SHA-256 des Reports.
    pub fn abschliessen(self, report_sha256: Option<&str>) -> Result<()> {
        let stand = if report_sha256.is_some() {
            LaufStand::Completed
        } else {
            LaufStand::Failed
        };
        self.rt
            .block_on(self.db.lauf_abschliessen(
                self.akteur,
                self.lauf,
                stand,
                chrono::Utc::now(),
                report_sha256,
            ))
            .context("Analyselauf in der Datenbank nicht abschließbar")
    }
}

/// Konfiguration des Laufs für die Datenbank. Geheimnisse (Passwörter,
/// Schlüssel) erscheinen nur als Art, nie mit Wert.
pub fn konfiguration(cli_werte: &[(&str, Value)], analyzer: &[&str]) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("analyzer".into(), json!(analyzer));
    for (k, v) in cli_werte {
        m.insert((*k).into(), v.clone());
    }
    Value::Object(m)
}

/// Zeilen je Block beim Schreiben des Katalogs in die Datenbank.
const KATALOG_BLOCK: usize = 16_384;

/// Nimmt den Katalog als JSON Lines entgegen und schreibt ihn in Blöcken
/// von [`KATALOG_BLOCK`] Zeilen in die Datenbank. So liegt nie der ganze
/// Katalog im Speicher.
pub struct KatalogSchreiber<'a> {
    sitzung: &'a mut Sitzung,
    puffer: Vec<u8>,
    zeilen: usize,
}

impl KatalogSchreiber<'_> {
    /// Schreibt alle vollständigen Zeilen im Puffer.
    fn senden(&mut self) -> std::io::Result<()> {
        let Some(ende) = self.puffer.iter().rposition(|b| *b == b'\n') else {
            return Ok(());
        };
        // JSON Lines enthalten keine rohen Zeilenumbrüche (serde maskiert
        // sie), also wird aus jedem Umbruch ein Komma.
        let rest = self.puffer.split_off(ende + 1);
        self.puffer.pop();
        let mut array = Vec::with_capacity(self.puffer.len() + 2);
        array.push(b'[');
        array.extend(
            self.puffer
                .iter()
                .map(|b| if *b == b'\n' { b',' } else { *b }),
        );
        array.push(b']');
        self.puffer = rest;
        self.zeilen = 0;
        let text = String::from_utf8(array)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let s = &mut *self.sitzung;
        let neu =
            s.rt.block_on(s.db.katalog_speichern(s.lauf, &text))
                .map_err(std::io::Error::other)?;
        s.dateien += neu;
        Ok(())
    }
}

impl std::io::Write for KatalogSchreiber<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.puffer.extend_from_slice(buf);
        self.zeilen += buf.iter().filter(|b| **b == b'\n').count();
        if self.zeilen >= KATALOG_BLOCK {
            self.senden()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.senden()
    }
}

/// Schreibt in zwei Ziele zugleich (Katalogdatei und Datenbank).
pub struct Beide<A, B>(pub A, pub B);

impl<A: std::io::Write, B: std::io::Write> std::io::Write for Beide<A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        self.1.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()?;
        self.1.flush()
    }
}
