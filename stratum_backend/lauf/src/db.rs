//! Schreiben in PostgreSQL während eines Laufs: Fall und Evidence
//! registrieren, den Lauf beginnen, Dateikatalog und Modell speichern, den
//! Lauf abschließen.
//!
//! Die Analyse ist synchron; die Datenbank wird über einen `tokio`-Handle
//! angesprochen (`Handle::block_on`). Der Aufrufer stellt die Laufzeit: die
//! Kommandozeile eine eigene, ein Worker seine.

use std::path::Path;

use serde_json::{json, Value};
use stratum_model::{
    ActorId, AnalysisRunId, Case, CaseClassification, CaseId, CaseStatus, Evidence, EvidenceKind,
    EvidenceSupport,
};
use stratum_store::{Datenbank, Geschrieben, LaufAngaben, LaufStand};

use crate::LaufFehler;

/// Wohin und als wer ein Lauf in die Datenbank schreibt.
#[derive(Clone)]
pub struct DbZiel {
    /// Handle einer Laufzeit mit eigenem Treiber (z. B. `multi_thread`);
    /// bei `current_thread` würde `block_on` über den Handle nicht treiben.
    pub handle: tokio::runtime::Handle,
    /// Verbindung.
    pub db: Datenbank,
    /// Handelndes Konto.
    pub akteur: ActorId,
    /// Gewählter, schon bestehender Fall; ohne Angabe wird ein Fall
    /// `CLI-<ID>` aus dem Image-Hash abgeleitet und bei Bedarf angelegt.
    pub fall: Option<CaseId>,
    /// Weitere Angaben für das Audit beim Start (z. B. Benutzer des
    /// Betriebssystems, Job-ID).
    pub audit_details: Value,
}

/// Was neben dem Modell in die Datenbank geht.
pub(crate) struct Auftrag {
    pub gestartet: chrono::DateTime<chrono::Utc>,
    pub image: std::path::PathBuf,
    pub format: stratum_core::ImageFormat,
    pub groesse: u64,
    pub hashes: stratum_core::ImageHashes,
    pub akquisezeit: Option<chrono::DateTime<chrono::Utc>>,
    pub metadaten: Value,
    pub konfiguration: Value,
}

/// Offene Verbindung mit dem laufenden Analyselauf.
pub struct Sitzung {
    ziel: DbZiel,
    lauf: AnalysisRunId,
    fall_neu: bool,
    evidence_neu: bool,
    dateien: u64,
}

impl Auftrag {
    /// Registriert Fall (falls nicht gewählt) und Evidence und beginnt den
    /// Lauf als das Konto des Ziels.
    pub fn beginnen(
        &self,
        ziel: DbZiel,
        k: &mut stratum_normalize::Kontext,
    ) -> Result<Sitzung, LaufFehler> {
        let a = ziel.akteur;
        let db = &ziel.db;
        // Im gewählten Fall schon registrierte Evidence mit diesem Hash
        // weiterverwenden (auch wenn sie mit --art anders eingestuft wurde);
        // bei E01 und Rohimage derselben Mediendaten die passende Art.
        if ziel.fall.is_some() {
            let vorhanden = ziel
                .handle
                .block_on(db.evidence_nach_hash(k.case_id, &self.hashes.sha256))?;
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
            audit_details: ziel.audit_details.clone(),
        };
        let gewaehlt = ziel.fall;
        let (lauf, fall_neu, evidence_neu) = ziel.handle.block_on(async {
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
        Ok(Sitzung {
            ziel,
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
            created_by: ActorId::cli(),
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
            imported_by: ActorId::cli(),
            acquisition_method: None,
            read_only: true,
            support: EvidenceSupport::Recognized,
            parent_evidence_id: None,
            metadata: self.metadaten.clone(),
        }
    }
}

impl Sitzung {
    /// Analyselauf.
    pub fn lauf(&self) -> AnalysisRunId {
        self.lauf
    }

    /// Fall des Laufs.
    pub(crate) fn meldung_begonnen(&self, k: &stratum_normalize::Kontext) -> String {
        format!(
            "[+] Datenbank: Fall {}{}, Lauf {}",
            k.case_id,
            if self.fall_neu { " (neu)" } else { "" },
            self.lauf
        )
    }

    /// Schreibt das Modell in den Lauf.
    pub(crate) fn modell(
        &self,
        m: &stratum_normalize::Modell,
        modell_sha256: Option<&str>,
    ) -> Result<Geschrieben, LaufFehler> {
        let mut g = self.ziel.handle.block_on(self.ziel.db.modell_speichern(
            self.lauf,
            m,
            modell_sha256,
        ))?;
        g.fall_neu = self.fall_neu;
        g.evidence_neu = self.evidence_neu;
        g.dateien = self.dateien;
        Ok(g)
    }

    /// Schreiber für den Dateikatalog: nimmt JSON Lines an und schreibt sie
    /// blockweise in die Datenbank.
    pub(crate) fn katalog(&mut self) -> KatalogSchreiber<'_> {
        KatalogSchreiber {
            sitzung: self,
            puffer: Vec::with_capacity(1 << 22),
            zeilen: 0,
        }
    }

    /// Beendet den Lauf: mit dem SHA-256 des Reports als abgeschlossen,
    /// ohne als fehlgeschlagen. Mit dem Pfad der Report-Datei lassen sich
    /// Rohfunde später über die API abrufen.
    pub fn abschliessen(
        self,
        report_sha256: Option<&str>,
        report_pfad: Option<&Path>,
    ) -> Result<(), LaufFehler> {
        let stand = if report_sha256.is_some() {
            LaufStand::Completed
        } else {
            LaufStand::Failed
        };
        self.beenden(stand, report_sha256, report_pfad)
    }

    /// Beendet den Lauf mit dem gegebenen Stand.
    pub fn beenden(
        self,
        stand: LaufStand,
        report_sha256: Option<&str>,
        report_pfad: Option<&Path>,
    ) -> Result<(), LaufFehler> {
        // Absolut, damit Server und Worker die Datei unabhängig vom
        // Arbeitsverzeichnis finden; Pfade, die kein UTF-8 sind, entfallen.
        let pfad = report_pfad
            .and_then(|p| std::path::absolute(p).ok())
            .and_then(|p| p.to_str().map(String::from));
        self.ziel.handle.block_on(self.ziel.db.lauf_abschliessen(
            self.ziel.akteur,
            self.lauf,
            stand,
            chrono::Utc::now(),
            report_sha256,
            pfad.as_deref(),
        ))?;
        Ok(())
    }
}

/// Zeilen je Block beim Schreiben des Katalogs in die Datenbank.
const KATALOG_BLOCK: usize = 16_384;

/// Nimmt den Katalog als JSON Lines entgegen und schreibt ihn in Blöcken
/// von [`KATALOG_BLOCK`] Zeilen in die Datenbank. So liegt nie der ganze
/// Katalog im Speicher.
pub(crate) struct KatalogSchreiber<'a> {
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
        let neu = s
            .ziel
            .handle
            .block_on(s.ziel.db.katalog_speichern(s.lauf, &text))
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
pub(crate) struct Beide<A, B>(pub A, pub B);

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

/// Konfiguration des Laufs für die Datenbank. Geheimnisse (Passwörter,
/// Schlüssel) erscheinen nur als Art, nie mit Wert.
pub(crate) fn konfiguration(werte: &[(&str, Value)], analyzer: &[&str]) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("analyzer".into(), json!(analyzer));
    for (k, v) in werte {
        m.insert((*k).into(), v.clone());
    }
    Value::Object(m)
}
