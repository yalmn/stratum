//! Schreiben in PostgreSQL (`--db`): Fall und Evidence registrieren, Modell
//! als Analyselauf speichern, Lauf nach dem Report abschließen.
//!
//! Asynchron nur hier, in einer eigenen Laufzeit; die Analyse bleibt
//! synchron.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use stratum_model::{
    ids::derived_uuid, ActorId, Case, CaseClassification, CaseStatus, Evidence, EvidenceKind,
    EvidenceSupport,
};
use stratum_store::{Datenbank, Geschrieben, LaufAngaben, LaufStand};

/// Akteur für Aktionen über die CLI, solange es keine Benutzerkonten gibt.
/// Fest, damit die spätere Benutzertabelle ihn übernehmen kann.
pub fn cli_akteur() -> ActorId {
    ActorId(derived_uuid("akteur", &[b"stratum-cli"]))
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

/// Offene Verbindung mit dem laufenden Analyselauf.
pub struct Sitzung {
    rt: tokio::runtime::Runtime,
    db: Datenbank,
    lauf: stratum_model::AnalysisRunId,
}

impl Auftrag {
    /// Registriert Fall und Evidence und schreibt das Modell als Lauf mit
    /// Stand `running`.
    pub fn ausfuehren(
        &self,
        k: &stratum_normalize::Kontext,
        m: &stratum_normalize::Modell,
        modell_sha256: &str,
    ) -> Result<(Sitzung, Geschrieben)> {
        let url = std::env::var("STRATUM_DB_URL")
            .context("--db: Umgebungsvariable STRATUM_DB_URL ist nicht gesetzt")?;
        // Passwort aus einer Datei (dieselbe, die Docker als Secret nutzt).
        let passwort = match std::env::var_os("STRATUM_DB_PASSWORT_DATEI") {
            Some(p) => Some(
                std::fs::read_to_string(&p)
                    .with_context(|| {
                        format!("Passwortdatei nicht lesbar: {}", p.to_string_lossy())
                    })?
                    .trim()
                    .to_string(),
            ),
            None => None,
        };
        eprintln!("[*] Schreibe Modell in die Datenbank ...");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Laufzeit für die Datenbank nicht erstellbar")?;
        let fall = self.fall(k);
        let evidence = self.evidence(k);
        let konfig_hash =
            stratum_core::hash_bytes(&serde_json::to_vec(&self.konfiguration)?).sha256;
        let angaben = LaufAngaben {
            started_at: self.gestartet,
            configuration: &self.konfiguration,
            configuration_hash: Some(&konfig_hash),
            model_sha256: Some(modell_sha256),
        };
        let (db, g) = rt.block_on(async {
            let db = Datenbank::verbinden_mit(&url, passwort.as_deref()).await?;
            let fall_neu = db.fall_anlegen(&fall).await?;
            let evidence_neu = db.evidence_registrieren(&evidence).await?;
            let mut g = db.modell_speichern(k, m, &angaben).await?;
            g.fall_neu = fall_neu;
            g.evidence_neu = evidence_neu;
            Ok::<_, stratum_store::StoreError>((db, g))
        })?;
        eprintln!(
            "[+] Datenbank: Lauf {}, neu {} Artefakte, {} Ereignisse, {} Entitäten",
            g.lauf_id, g.artefakte, g.ereignisse, g.entitaeten
        );
        Ok((
            Sitzung {
                rt,
                db,
                lauf: g.lauf_id,
            },
            g,
        ))
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
    /// Beendet den Lauf. Bei Erfolg mit dem SHA-256 des Reports.
    pub fn abschliessen(self, report_sha256: Option<&str>) -> Result<()> {
        let stand = if report_sha256.is_some() {
            LaufStand::Completed
        } else {
            LaufStand::Failed
        };
        self.rt
            .block_on(self.db.lauf_abschliessen(
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
pub fn konfiguration(
    cli_werte: &[(&str, Value)],
    analyzer: &[Box<dyn stratum_analysis::Analyzer>],
) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "analyzer".into(),
        json!(analyzer.iter().map(|a| a.name()).collect::<Vec<_>>()),
    );
    for (k, v) in cli_werte {
        m.insert((*k).into(), v.clone());
    }
    Value::Object(m)
}
