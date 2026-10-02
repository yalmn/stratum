//! Ein Analyselauf als Bibliothek: Image öffnen, hashen, Partitionen und
//! NTFS erkennen, Dateikatalog und Zeitachsen schreiben, Analyzer ausführen,
//! auf das Datenmodell abbilden, in die Datenbank schreiben und den Report
//! zusammenstellen.
//!
//! Kommandozeile und Worker rufen dieselbe Funktion [`analysieren`] auf;
//! ein Server ruft nie die Kommandozeile. Wie Meldungen und Fortschritt
//! ankommen und ob abgebrochen werden soll, bestimmt der Aufrufer über
//! [`Rueckmeldung`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bdp;
pub mod db;
pub mod liveness;
pub mod report;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use stratum_analysis::{
    run_all_mit, ActivitiesCacheAnalyzer, AnalysisContext, Analyzer, BamAnalyzer, BrowserAnalyzer,
    DpapiAnalyzer, DpapiInput, EventLogAnalyzer, FilePersistenceAnalyzer, JumpListAnalyzer,
    KeywordAnalyzer, LnkAnalyzer, LsaAnalyzer, NtfsTarget, PersistenceAnalyzer,
    PowerShellHistoryAnalyzer, PrefetchAnalyzer, ProgramExecutionAnalyzer, RecycleBinAnalyzer,
    ShellBagsAnalyzer, SrumAnalyzer, Steuerung, TorAnalyzer, UsbAnalyzer, UserActivityAnalyzer,
    VssAnalyzer, WebCacheAnalyzer, ZoneIdentifierAnalyzer,
};
use stratum_core::{hash_image_abbrechbar, scan_partitions, FsHint, ImageReader, PartitionScheme};
use stratum_search::TermTable;
use stratum_store::LaufStand;

pub use db::{DbZiel, Sitzung};
use report::{
    CatalogInfo, ImageInfo, KeywordInfo, MftTimelineInfo, Report, Tool, UsnJournalInfo,
    WindowsReport,
};

/// Fehler eines Laufs.
#[derive(Debug, thiserror::Error)]
pub enum LaufFehler {
    /// Ein Schritt ist gescheitert; `kontext` sagt, welcher.
    #[error("{kontext}")]
    Schritt {
        /// Was gerade geschah.
        kontext: String,
        /// Ursache.
        #[source]
        quelle: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Eingabe ungültig.
    #[error("{0}")]
    Eingabe(String),
    /// Auf Anforderung abgebrochen.
    #[error("Analyse abgebrochen")]
    Abgebrochen,
    /// Datenbank.
    #[error(transparent)]
    Datenbank(#[from] stratum_store::StoreError),
    /// JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Hängt an einen Fehler den Schritt, in dem er auftrat.
pub trait Kontext<T> {
    /// Fehler mit Kontext versehen.
    fn kontext(self, k: impl FnOnce() -> String) -> Result<T, LaufFehler>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Kontext<T> for Result<T, E> {
    fn kontext(self, k: impl FnOnce() -> String) -> Result<T, LaufFehler> {
        self.map_err(|e| LaufFehler::Schritt {
            kontext: k(),
            quelle: Box::new(e),
        })
    }
}

/// Abschnitt eines Laufs, für Fortschrittsanzeigen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Integritäts-Hash über das Image (Bytes).
    Hashing,
    /// Dateikatalog (Einträge).
    Katalog,
    /// Domänen-Analyzer (fertige Analyzer).
    Analyzer,
    /// Keyword-Suche über das Image (Bytes).
    Suche,
}

/// Wie ein Lauf nach außen berichtet und ob er abbrechen soll.
pub trait Rueckmeldung: Sync {
    /// Eine Meldung wie „[+] 18 Funde …“.
    fn meldung(&self, text: &str);
    /// Eine Phase beginnt.
    fn phase_beginn(&self, _phase: Phase) {}
    /// Fortschritt einer Phase.
    fn fortschritt(&self, phase: Phase, erledigt: u64, gesamt: u64);
    /// Eine Phase ist beendet.
    fn phase_ende(&self, _phase: Phase) {}
    /// Der Lauf ist in der Datenbank begonnen.
    fn lauf_begonnen(&self, _lauf: stratum_model::AnalysisRunId) {}
    /// Ob abgebrochen werden soll. Gefragt wird zwischen den Schritten und
    /// vor jedem Analyzer.
    fn abbruch_angefordert(&self) -> bool {
        false
    }
}

/// Was ein Lauf tun soll.
#[derive(Debug, Clone)]
pub struct Optionen {
    /// Image (Rohimage oder E01).
    pub image: PathBuf,
    /// bdp.info von ForensiCUnlock: legt die Partition fest.
    pub bdp: Option<PathBuf>,
    /// Integritäts-Hashes bilden (Pflicht mit Datenbank).
    pub hashen: bool,
    /// Mitgelieferte Begriffsliste verwenden.
    pub mitgelieferte_begriffe: bool,
    /// Eigene Begriffstabellen (TOML).
    pub begriffstabellen: Vec<PathBuf>,
    /// Das ganze Image roh nach Begriffen durchsuchen.
    pub raw_sweep: bool,
    /// .onion-Adressen über diesen SOCKS5-Proxy prüfen.
    pub onion_proxy: Option<String>,
    /// DPAPI-Eingabe.
    pub dpapi: Option<DpapiInput>,
    /// Firefox-Hauptpasswort.
    pub firefox_passwort: Option<String>,
    /// Dateikatalog als JSON Lines in diese Datei.
    pub katalog: Option<PathBuf>,
    /// Im Katalog SHA-256 und Signaturtyp jeder Datei.
    pub datei_hashes: bool,
    /// MFT-Zeitachse in diese Datei.
    pub mft_timeline: Option<PathBuf>,
    /// USN-Journal in diese Datei.
    pub usn_journal: Option<PathBuf>,
    /// Datenmodell als JSON in diese Datei.
    pub modell: Option<PathBuf>,
    /// Fall-ID für das Modell (sonst aus dem Hash bzw. dem gewählten Fall).
    pub fall_id: Option<uuid::Uuid>,
    /// Beginn des Laufs.
    pub gestartet: chrono::DateTime<chrono::Utc>,
}

/// Ergebnis: der Report und, mit Datenbank, der noch offene Lauf. Der
/// Aufrufer schreibt den Report und schließt den Lauf mit dessen Hash ab.
pub struct Ergebnis {
    /// Report.
    pub report: Report,
    /// Offener Lauf in der Datenbank.
    pub sitzung: Option<Sitzung>,
}

/// Mitgelieferte Standard-Begriffstabelle, in das Programm eingebaut.
pub const DEFAULT_KEYWORDS: &str = include_str!("../../begriffe/strafverfolgung.toml");

/// Legt eine Ausgabedatei an; eine vorhandene wird nie überschrieben.
fn neue_datei(p: &Path, was: &str) -> Result<std::fs::File, LaufFehler> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .kontext(|| format!("{was} nicht anlegbar (existiert bereits?): {}", p.display()))
}

fn abbruch_pruefen(r: &dyn Rueckmeldung) -> Result<(), LaufFehler> {
    if r.abbruch_angefordert() {
        return Err(LaufFehler::Abgebrochen);
    }
    Ok(())
}

/// Führt einen Lauf aus. Mit `db` wird vor der Analyse ein Lauf in der
/// Datenbank begonnen; bricht die Analyse danach ab oder scheitert sie, wird
/// er als abgebrochen bzw. fehlgeschlagen beendet.
pub fn analysieren(
    o: &Optionen,
    db: Option<DbZiel>,
    r: &dyn Rueckmeldung,
) -> Result<Ergebnis, LaufFehler> {
    let mut sitzung = None;
    let ergebnis = ablauf(o, db, r, &mut sitzung);
    match ergebnis {
        Ok(report) => Ok(Ergebnis { report, sitzung }),
        Err(f) => {
            if let Some(s) = sitzung.take() {
                let stand = if matches!(f, LaufFehler::Abgebrochen) {
                    LaufStand::Cancelled
                } else {
                    LaufStand::Failed
                };
                if let Err(e) = s.beenden(stand, None) {
                    r.meldung(&format!("[!] Lauf in der Datenbank nicht beendbar: {e}"));
                }
            }
            Err(f)
        }
    }
}

fn ablauf(
    o: &Optionen,
    db: Option<DbZiel>,
    r: &dyn Rueckmeldung,
    sitzung: &mut Option<Sitzung>,
) -> Result<Report, LaufFehler> {
    if db.is_some() && !o.hashen {
        return Err(LaufFehler::Eingabe(
            "mit Datenbank nur mit Integritäts-Hash".into(),
        ));
    }
    let img = ImageReader::open(&o.image)
        .kontext(|| format!("Image nicht lesbar: {}", o.image.display()))?;

    // Ausgabedateien vor der langen Hash-Phase anlegen, damit ein
    // Namenskonflikt sofort auffällt.
    let catalog_file = match &o.katalog {
        Some(p) => Some((p.clone(), neue_datei(p, "Katalog")?)),
        None => None,
    };
    let modell_file = match &o.modell {
        Some(p) => Some((p.clone(), neue_datei(p, "Modelldatei")?)),
        None => None,
    };
    let mft_timeline_file = match &o.mft_timeline {
        Some(p) => Some((p.clone(), neue_datei(p, "MFT-Zeitachse")?)),
        None => None,
    };
    let usn_file = match &o.usn_journal {
        Some(p) => Some((p.clone(), neue_datei(p, "USN-Zeitachse")?)),
        None => None,
    };
    let fall_id = o.fall_id.or(db.as_ref().and_then(|d| d.fall).map(|c| c.0));

    let mut warnings = Vec::new();

    let hashes = if o.hashen {
        r.phase_beginn(Phase::Hashing);
        let cb = |done| r.fortschritt(Phase::Hashing, done, img.len());
        let cb: stratum_core::Progress = &cb;
        // Bei E01 scheitert der Hash an einem unlesbaren Chunk; ohne
        // vollständigen Hash keine Analyse (sonst ohne Hash).
        let abbruch = || r.abbruch_angefordert();
        let h = hash_image_abbrechbar(&img, Some(cb), &abbruch)
            .kontext(|| "Integritäts-Hash nicht berechenbar (Image beschädigt?)".into())?
            .ok_or(LaufFehler::Abgebrochen)?;
        r.phase_ende(Phase::Hashing);
        r.meldung(&format!(
            "[+] Integritäts-Hashes berechnet ({} Bytes)",
            img.len()
        ));
        Some(h)
    } else {
        None
    };
    abbruch_pruefen(r)?;

    let ewf_info = img.ewf().map(|e| ewf_report(e, hashes.as_ref()));
    if let Some(info) = &ewf_info {
        for (art, stimmt) in [("MD5", info.md5_stimmt), ("SHA-1", info.sha1_stimmt)] {
            if stimmt == Some(false) {
                warnings.push(format!(
                    "Akquise-{art} des E01 stimmt nicht mit den gelesenen Mediendaten überein"
                ));
            }
        }
        warnings.extend(info.warnungen.iter().map(|w| format!("E01: {w}")));
    }

    let partitions = scan_partitions(&img);
    r.meldung(&format!(
        "[+] {} Partition(en) erkannt ({:?})",
        partitions.partitions.len(),
        partitions.scheme
    ));

    let targets = targets_from(&partitions, o.bdp.as_deref())?;
    if targets.is_empty() && partitions.scheme != PartitionScheme::None {
        warnings.push("keine NTFS-Partition gefunden".into());
    }

    // Gemeinsamer Kontext: extrahiert einmalig je NTFS-Bereich die Hives und
    // leitet Zeitzone, Rechnername und Konten ab.
    r.meldung("[*] Lese Registry-Hives und baue Pfad-Index ...");
    let mut ctx = AnalysisContext::build(&img, targets.clone());
    ctx.dpapi = o.dpapi.clone();
    ctx.firefox_password = o.firefox_passwort.clone();
    warnings.extend(ctx.warnings.iter().cloned());
    if let Some(v) = ctx.volumes.first() {
        r.meldung(&format!(
            "[+] Pfad-Index: {} Dateien, {} Verzeichnisse",
            v.files.len(),
            v.directories.len()
        ));
    }
    abbruch_pruefen(r)?;

    // Domänen-Analyzer zusammenstellen: Tor läuft immer, die Keyword-Suche nur
    // bei aktiver Begriffsliste. Schon hier, weil die Datenbank sie als
    // Konfiguration des Laufs festhält.
    let mut analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(TorAnalyzer),
        Box::new(PersistenceAnalyzer),
        Box::new(UsbAnalyzer),
        Box::new(UserActivityAnalyzer),
        Box::new(BrowserAnalyzer),
        Box::new(PrefetchAnalyzer),
        Box::new(EventLogAnalyzer),
        Box::new(VssAnalyzer),
        Box::new(ProgramExecutionAnalyzer),
        Box::new(LsaAnalyzer),
        Box::new(DpapiAnalyzer),
        Box::new(BamAnalyzer),
        Box::new(FilePersistenceAnalyzer),
        Box::new(RecycleBinAnalyzer),
        Box::new(LnkAnalyzer),
        Box::new(JumpListAnalyzer),
        Box::new(PowerShellHistoryAnalyzer),
        Box::new(ZoneIdentifierAnalyzer),
        Box::new(ShellBagsAnalyzer),
        Box::new(ActivitiesCacheAnalyzer),
        Box::new(SrumAnalyzer),
        Box::new(WebCacheAnalyzer),
    ];
    let (keyword_analyzer, keywords) = if !o.mitgelieferte_begriffe && o.begriffstabellen.is_empty()
    {
        (None, None)
    } else {
        let (analyzer, info) =
            build_keyword_analyzer(o.mitgelieferte_begriffe, &o.begriffstabellen)?;
        (Some(analyzer), Some(info))
    };

    let mut kontext = if o.modell.is_some() || db.is_some() {
        Some(kontext_bilden(&img, hashes.as_ref(), fall_id, &ctx))
    } else {
        None
    };

    // Fall, Evidence und Lauf vor der Analyse registrieren; Katalog und
    // Modell gehören dann zu diesem Lauf.
    if let (Some(ziel), Some(h), Some((k, _))) = (db, &hashes, &mut kontext) {
        let mut namen: Vec<&str> = analyzers.iter().map(|a| a.name()).collect();
        if keyword_analyzer.is_some() {
            namen.push("KeywordAnalyzer");
        }
        let auftrag = db::Auftrag {
            gestartet: o.gestartet,
            image: img.path().to_path_buf(),
            format: img.format(),
            groesse: img.len(),
            hashes: h.clone(),
            akquisezeit: img
                .ewf()
                .and_then(|e| e.info().acquired_unix())
                .and_then(|u| chrono::DateTime::from_timestamp(u, 0)),
            metadaten: serde_json::json!({
                "md5": h.md5,
                "sha1": h.sha1,
                "ewf": ewf_info,
                "bdp_info": o.bdp.as_ref().map(|p| p.display().to_string()),
            }),
            konfiguration: db::konfiguration(
                &[
                    ("begriffe", serde_json::json!(keywords)),
                    ("raw_sweep", o.raw_sweep.into()),
                    ("check_onion", o.onion_proxy.is_some().into()),
                    (
                        "bdp_info",
                        serde_json::json!(o.bdp.as_ref().map(|p| p.display().to_string())),
                    ),
                    ("dpapi", serde_json::json!(dpapi_art(o.dpapi.as_ref()))),
                    ("firefox_passwort", o.firefox_passwort.is_some().into()),
                    ("katalog", o.katalog.is_some().into()),
                    ("datei_hashes", o.datei_hashes.into()),
                    ("mft_timeline", o.mft_timeline.is_some().into()),
                    ("usn_journal", o.usn_journal.is_some().into()),
                ],
                &namen,
            ),
        };
        let s = auftrag.beginnen(ziel, k)?;
        r.lauf_begonnen(s.lauf());
        r.meldung(&s.meldung_begonnen(k));
        *sitzung = Some(s);
    }

    // Dateikatalog als JSON Lines in die Datei, in die Datenbank oder beides.
    let catalog = if catalog_file.is_some() || sitzung.is_some() {
        r.meldung("[*] Schreibe Dateikatalog ...");
        r.phase_beginn(Phase::Katalog);
        let progress = |done: u64, total: u64| r.fortschritt(Phase::Katalog, done, total);
        let options = stratum_analysis::CatalogOptions {
            inhalte: o.datei_hashes,
            progress: Some(&progress),
        };
        let mut datei = catalog_file.map(|(path, file)| {
            (
                path,
                std::io::BufWriter::with_capacity(1 << 20, stratum_core::HashingWriter::new(file)),
            )
        });
        let mut dbk = sitzung.as_mut().map(Sitzung::katalog);
        let summary = match (&mut datei, &mut dbk) {
            (Some((_, f)), Some(d)) => {
                stratum_analysis::write_catalog_with(&img, &ctx.volumes, db::Beide(f, d), options)
            }
            (Some((_, f)), None) => {
                stratum_analysis::write_catalog_with(&img, &ctx.volumes, f, options)
            }
            (None, Some(d)) => stratum_analysis::write_catalog_with(&img, &ctx.volumes, d, options),
            (None, None) => unreachable!("Katalog ohne Ziel"),
        }
        .kontext(|| "Dateikatalog nicht schreibbar".into())?;
        drop(dbk);
        r.phase_ende(Phase::Katalog);
        if summary.fehler > 0 {
            warnings.push(format!(
                "Dateikatalog: {} Einträge ohne lesbaren MFT-Datensatz (Feld fehler)",
                summary.fehler
            ));
        }
        match datei {
            Some((path, w)) => {
                let (_, hashes) = w
                    .into_inner()
                    .map_err(|e| e.into_error())
                    .and_then(|h| h.finish())
                    .kontext(|| format!("Katalog nicht abschließbar: {}", path.display()))?;
                r.meldung(&format!(
                    "[+] Dateikatalog: {} Einträge ({} Fehler) in {}",
                    summary.eintraege,
                    summary.fehler,
                    path.display()
                ));
                Some(CatalogInfo {
                    pfad: path.display().to_string(),
                    quelle: stratum_analysis::CATALOG_SOURCE,
                    format: "JSON Lines, ein Eintrag je Zeile, sortiert nach Volume und Pfad",
                    hashes,
                    summary,
                })
            }
            None => {
                r.meldung(&format!(
                    "[+] Dateikatalog: {} Einträge ({} Fehler) in der Datenbank",
                    summary.eintraege, summary.fehler
                ));
                None
            }
        }
    } else {
        None
    };
    abbruch_pruefen(r)?;

    let mft_timeline = match mft_timeline_file {
        Some((path, file)) => {
            r.meldung("[*] Schreibe vollständige MFT-Zeitachse ...");
            let mut writer =
                std::io::BufWriter::with_capacity(1 << 20, stratum_core::HashingWriter::new(file));
            let summary = stratum_analysis::write_mft_timeline(&img, &ctx.volumes, &mut writer)
                .kontext(|| format!("MFT-Zeitachse nicht schreibbar: {}", path.display()))?;
            let (_, hashes) = writer
                .into_inner()
                .map_err(|e| e.into_error())
                .and_then(|h| h.finish())
                .kontext(|| format!("MFT-Zeitachse nicht abschließbar: {}", path.display()))?;
            r.meldung(&format!(
                "[+] MFT-Zeitachse: {} Ereignisse aus {} lesbaren Datensätzen ({} gelöscht, {} Fehler) in {}",
                summary.ereignisse,
                summary.lesbar,
                summary.geloescht,
                summary.fehler,
                path.display()
            ));
            if summary.fehler > 0 {
                warnings.push(format!(
                    "MFT-Zeitachse: {} Datensatzplätze nicht als gültige FILE-Datensätze lesbar",
                    summary.fehler
                ));
            }
            Some(MftTimelineInfo {
                pfad: path.display().to_string(),
                quelle: stratum_analysis::MFT_TIMELINE_SOURCE,
                format: "JSON Lines, ein SI-/FN-MACB-Ereignis je Zeile, je Volume chronologisch sortiert",
                hashes,
                summary,
            })
        }
        None => None,
    };

    let usn_journal = match usn_file {
        Some((path, file)) => {
            r.meldung("[*] Schreibe USN-Änderungsjournal ...");
            let mut writer =
                std::io::BufWriter::with_capacity(1 << 20, stratum_core::HashingWriter::new(file));
            let summary = stratum_analysis::write_usn_journal(&img, &ctx.volumes, &mut writer)
                .kontext(|| format!("USN-Zeitachse nicht schreibbar: {}", path.display()))?;
            let (_, hashes) = writer
                .into_inner()
                .map_err(|error| error.into_error())
                .and_then(|hashing| hashing.finish())
                .kontext(|| format!("USN-Zeitachse nicht abschließbar: {}", path.display()))?;
            r.meldung(&format!(
                "[+] USN-Zeitachse: {} Datensätze aus {} Journal(en), {} Fehler in {}",
                summary.datensaetze,
                summary.journals,
                summary.fehler,
                path.display()
            ));
            if summary.fehler > 0 || summary.abgeschnitten > 0 {
                warnings.push(format!(
                    "USN-Zeitachse: {} unplausible und {} abgeschnittene Datensätze",
                    summary.fehler, summary.abgeschnitten
                ));
            }
            Some(UsnJournalInfo {
                pfad: path.display().to_string(),
                quelle: stratum_analysis::USN_JOURNAL_SOURCE,
                format: "JSON Lines, ein USN_RECORD_V2/V3 je Zeile, in Journalreihenfolge",
                hashes,
                summary,
            })
        }
        None => None,
    };
    abbruch_pruefen(r)?;

    let mut windows = Vec::new();
    for inst in ctx.installs.iter() {
        // Reine Datenpartitionen (kein SYSTEM-Hive) liefern keinen Eintrag; hier
        // erscheinen nur echte Windows-Installationen und Fehlerfaelle.
        if inst.hives.system.is_none() && inst.accounts.is_empty() {
            for w in &inst.warnings {
                warnings.push(format!("Offset {}: {w}", inst.target.offset));
            }
            continue;
        }
        r.meldung(&format!(
            "[+] Windows gefunden: {} Konto(en){}",
            inst.accounts.len(),
            inst.computer_name
                .as_deref()
                .map(|c| format!(", Rechner {c}"))
                .unwrap_or_default()
        ));
        windows.push(WindowsReport {
            origin: inst.origin.clone(),
            partition_index: inst.target.index,
            partition_offset: inst.target.offset,
            computer_name: inst.computer_name.clone(),
            timezone: inst.timezone.clone(),
            accounts: inst.accounts.clone(),
            hives: inst.hive_status.clone(),
            warnings: inst.warnings.clone(),
        });
    }

    // Die Suche meldet ihren Stand in geteilte Zähler; ein begleitender
    // Thread gibt ihn weiter (ihr Rückruf darf nichts Geliehenes halten).
    let suche = keyword_analyzer.is_some();
    let suchstand = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    if let Some(analyzer) = keyword_analyzer {
        let stand = Arc::clone(&suchstand);
        let analyzer =
            analyzer
                .with_raw_sweep(o.raw_sweep)
                .with_progress(Box::new(move |done, total| {
                    stand.0.store(done, Ordering::Relaxed);
                    stand.1.store(total, Ordering::Relaxed);
                }));
        analyzers.push(Box::new(analyzer));
    }

    if suche {
        r.phase_beginn(Phase::Suche);
    }
    r.meldung("[*] Führe Domänen-Analyzer aus ...");
    r.phase_beginn(Phase::Analyzer);
    let abbruch = || r.abbruch_angefordert();
    let fortschritt =
        |fertig: usize, gesamt: usize| r.fortschritt(Phase::Analyzer, fertig as u64, gesamt as u64);
    let analyzer_fertig = AtomicBool::new(false);
    let mut analysis = std::thread::scope(|bereich| {
        if suche {
            bereich.spawn(|| {
                let melden = || {
                    let (d, t) = (
                        suchstand.0.load(Ordering::Relaxed),
                        suchstand.1.load(Ordering::Relaxed),
                    );
                    if t > 0 {
                        r.fortschritt(Phase::Suche, d, t);
                    }
                };
                while !analyzer_fertig.load(Ordering::Relaxed) {
                    melden();
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                melden();
            });
        }
        let a = run_all_mit(
            &ctx,
            &analyzers,
            &Steuerung {
                abbruch: &abbruch,
                fortschritt: &fortschritt,
            },
        );
        analyzer_fertig.store(true, Ordering::Relaxed);
        a
    });
    drop(analyzers);
    if suche {
        r.phase_ende(Phase::Suche);
    }
    r.phase_ende(Phase::Analyzer);
    if analysis.abgebrochen {
        return Err(LaufFehler::Abgebrochen);
    }
    warnings.append(&mut analysis.warnings);
    r.meldung(&format!(
        "[+] {} Funde ueber alle Domänen",
        analysis.findings.len()
    ));

    // Optionale Online-Erreichbarkeitspruefung der gefundenen .onion-Adressen.
    if let Some(proxy) = &o.onion_proxy {
        r.meldung(&format!(
            "[*] Pruefe .onion-Erreichbarkeit ueber {proxy} ..."
        ));
        let mut live = liveness::check_onions(&analysis.findings, proxy);
        r.meldung(&format!("[+] {} .onion-Adresse(n) geprueft", live.len()));
        analysis.findings.append(&mut live);
    }
    abbruch_pruefen(r)?;

    stratum_analysis::assign_ids(&mut analysis.findings);
    let timeline = stratum_analysis::build_timeline(&analysis.findings);
    let modell = match kontext.take() {
        Some(k) => {
            let info = modell_schreiben(modell_file, k, &analysis.findings, sitzung.as_ref(), r)?;
            warnings.extend(info.hinweise.iter().map(|h| format!("Modell: {h}")));
            Some(info)
        }
        None => None,
    };
    r.meldung(&format!(
        "[+] Zeitstrahl mit {} Ereignissen",
        timeline.len()
    ));

    let generated_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(Report {
        tool: Tool::default(),
        generated_unix,
        image: ImageInfo {
            path: img.path().display().to_string(),
            format: match img.format() {
                stratum_core::ImageFormat::Raw => "raw",
                stratum_core::ImageFormat::Ewf => "e01",
            },
            size: img.len(),
            ewf: ewf_info,
            hashes,
        },
        partitions,
        windows,
        analyzers: analysis.analyzers,
        findings: analysis.findings,
        timeline,
        keywords,
        catalog,
        modell,
        mft_timeline,
        usn_journal,
        warnings,
    })
}

/// Report als JSON in eine Datei, daneben `<Datei>.sha256` mit SHA-256 und
/// BLAKE3. Liefert den SHA-256. Eine vorhandene Datei wird ersetzt (wie
/// bisher bei `-o`).
pub fn report_schreiben(report: &Report, pfad: &Path) -> Result<String, LaufFehler> {
    let json = report_json(report)?;
    std::fs::write(pfad, &json)
        .kontext(|| format!("Report nicht schreibbar: {}", pfad.display()))?;
    let hashes = stratum_core::hash_bytes(json.as_bytes());
    let sidecar = {
        let mut s = pfad.as_os_str().to_os_string();
        s.push(".sha256");
        PathBuf::from(s)
    };
    let content = format!("sha256  {}\nblake3  {}\n", hashes.sha256, hashes.blake3);
    std::fs::write(&sidecar, content)
        .kontext(|| format!("Pruefsummen-Datei nicht schreibbar: {}", sidecar.display()))?;
    Ok(hashes.sha256)
}

/// Report als formatiertes JSON.
pub fn report_json(report: &Report) -> Result<String, LaufFehler> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Art der DPAPI-Eingabe für die Laufkonfiguration, ohne den Wert.
fn dpapi_art(d: Option<&DpapiInput>) -> Option<&'static str> {
    match d? {
        DpapiInput::Password(_) => Some("passwort"),
        DpapiInput::Sha1(_) => Some("sha1"),
        DpapiInput::Masterkey(_) => Some("masterkey"),
    }
}

/// Welche Bereiche als NTFS untersucht werden: entweder genau die per
/// bdp.info benannte Partition, oder alle als NTFS erkannten aus dem Scan.
pub fn targets_from(
    partitions: &stratum_core::PartitionTable,
    bdp: Option<&Path>,
) -> Result<Vec<NtfsTarget>, LaufFehler> {
    Ok(match bdp {
        Some(path) => {
            let b = bdp::load(path)?;
            vec![NtfsTarget {
                index: u32::MAX,
                offset: b.offset_bytes,
                size: b.size_bytes,
            }]
        }
        None => partitions
            .partitions
            .iter()
            .filter(|p| p.fs_hint == FsHint::Ntfs || p.typ == stratum_core::PartitionType::Volume)
            .map(|p| NtfsTarget {
                index: p.index,
                offset: p.start_offset,
                size: p.size_bytes,
            })
            .collect(),
    })
}

/// NTFS-Bereiche für die Extraktion, ohne Hashing und Analyse.
pub fn ntfs_targets(img: &ImageReader, bdp: Option<&Path>) -> Result<Vec<NtfsTarget>, LaufFehler> {
    targets_from(&scan_partitions(img), bdp)
}

/// Baut den Keyword-Analyzer aus der mitgelieferten und den eigenen
/// Begriffstabellen und liefert dazu die Angaben für den Report.
pub fn build_keyword_analyzer(
    use_default: bool,
    paths: &[PathBuf],
) -> Result<(KeywordAnalyzer, KeywordInfo), LaufFehler> {
    // Mehrere Tabellen werden zu einer zusammengeführt: alle Kategorien
    // hintereinander, der Name aus den Quellen, die höchste Version. Die
    // mitgelieferte Tabelle kommt zuerst, damit eigene Kategorien folgen.
    let mut names = Vec::new();
    let mut version = 0;
    let mut categories = Vec::new();
    let mut max_treffer = usize::MAX;

    if use_default {
        let table = TermTable::from_str(DEFAULT_KEYWORDS)
            .kontext(|| "eingebaute Begriffstabelle nicht lesbar".into())?;
        names.push(format!("{} (mitgeliefert)", table.meta.name));
        version = version.max(table.meta.version);
        max_treffer = max_treffer.min(table.meta.max_treffer);
        categories.extend(table.categories);
    }

    for path in paths {
        let table = TermTable::load(path)
            .kontext(|| format!("Begriffstabelle nicht lesbar: {}", path.display()))?;
        names.push(table.meta.name);
        version = version.max(table.meta.version);
        max_treffer = max_treffer.min(table.meta.max_treffer);
        categories.extend(table.categories);
    }

    let table = TermTable {
        meta: stratum_search::Meta {
            name: names.join(" + "),
            version,
            max_treffer,
        },
        categories,
    };
    let info = KeywordInfo {
        table_name: table.meta.name.clone(),
        table_version: table.meta.version,
    };
    Ok((KeywordAnalyzer::from_table(&table), info))
}

/// Angaben aus einem E01-Image für den Report, mit Abgleich der bei der
/// Akquise gespeicherten Hashes gegen die gelesenen Mediendaten.
pub fn ewf_report(
    e: &stratum_ewf::EwfImage,
    hashes: Option<&stratum_core::ImageHashes>,
) -> report::EwfInfo {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let gespeichert = e.stored_hashes();
    let info = e.info();
    report::EwfInfo {
        segmente: e
            .segment_paths()
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        chunk_groesse: e.chunk_size(),
        sektor_groesse: e.bytes_per_sector(),
        satz_id: e.set_id().map(|g| hex(&g)),
        akquise_quelle: info.source,
        akquise: info
            .values
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                let name = stratum_ewf::AcquisitionInfo::label(k).unwrap_or(k);
                (name.to_string(), v.clone())
            })
            .collect(),
        akquisezeit_utc: info
            .acquired_unix()
            .and_then(|u| u64::try_from(u + 11_644_473_600).ok())
            .and_then(|s| stratum_core::time::filetime_to_iso(s * 10_000_000)),
        gespeichert_md5: gespeichert.md5.map(|m| hex(&m)),
        gespeichert_sha1: gespeichert.sha1.map(|m| hex(&m)),
        md5_stimmt: gespeichert
            .md5
            .zip(hashes.and_then(|h| h.md5.as_deref()))
            .map(|(g, b)| hex(&g) == b),
        sha1_stimmt: gespeichert
            .sha1
            .zip(hashes.and_then(|h| h.sha1.as_deref()))
            .map(|(g, b)| hex(&g) == b),
        warnungen: e.warnings().to_vec(),
    }
}

/// Evidence-ID aus Fall, SHA-256 und Art, damit dieselbe Datei im selben
/// Fall immer dieselbe ID bekommt (bei `evidence hinzu` wie bei `--db`). E01
/// und Rohimage derselben Mediendaten sind getrennte Evidence; das Rohimage
/// behält die Ableitung von früher.
pub fn evidence_id_ableiten(
    fall: stratum_model::CaseId,
    sha256: &str,
    art: stratum_model::EvidenceKind,
) -> stratum_model::EvidenceId {
    use stratum_model::{ids::derived_uuid, EvidenceKind};
    let teile: Vec<&[u8]> = match art {
        EvidenceKind::RawDiskImage => vec![fall.0.as_bytes(), sha256.as_bytes()],
        EvidenceKind::E01Image => vec![fall.0.as_bytes(), sha256.as_bytes(), b"e01"],
        andere => {
            let name = serde_json::to_value(andere)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            return stratum_model::EvidenceId(derived_uuid(
                "cli-evidence",
                &[fall.0.as_bytes(), sha256.as_bytes(), name.as_bytes()],
            ));
        }
    };
    stratum_model::EvidenceId(derived_uuid("cli-evidence", &teile))
}

/// Kontext für das Datenmodell: Fall- und Evidence-ID, Hash, Rechnername.
/// Dazu Hinweise für den Report.
fn kontext_bilden(
    img: &ImageReader,
    hashes: Option<&stratum_core::ImageHashes>,
    fall_id: Option<uuid::Uuid>,
    ctx: &AnalysisContext<'_>,
) -> (stratum_normalize::Kontext, Vec<String>) {
    use stratum_model::{ids::derived_uuid, CaseId};
    let mut hinweise = Vec::new();
    let evidence_key = match hashes {
        Some(h) => h.sha256.clone(),
        None => {
            hinweise.push(
                "ohne Image-Hash: Ersatzschlüssel aus Pfad und Größe, IDs nur in diesem Lauf belastbar"
                    .to_string(),
            );
            format!("ohne-hash:{}:{}", img.path().display(), img.len())
        }
    };
    let case_id =
        CaseId(fall_id.unwrap_or_else(|| derived_uuid("cli-fall", &[evidence_key.as_bytes()])));
    let evidence_id = evidence_id_ableiten(
        case_id,
        &evidence_key,
        match img.format() {
            stratum_core::ImageFormat::Raw => stratum_model::EvidenceKind::RawDiskImage,
            stratum_core::ImageFormat::Ewf => stratum_model::EvidenceKind::E01Image,
        },
    );
    let tool = Tool::default();
    let k = stratum_normalize::Kontext {
        case_id,
        evidence_id,
        evidence_sha256: evidence_key,
        host: ctx
            .installs
            .iter()
            .find(|i| i.origin == "live")
            .and_then(|i| i.computer_name.clone()),
        stratum_version: format!("{} ({})", tool.version, tool.revision),
        zeitpunkt: chrono::Utc::now(),
    };
    (k, hinweise)
}

/// Bildet die Funde auf das Datenmodell ab und schreibt es als JSON, mit
/// Datenbank zusätzlich in den laufenden Analyselauf.
fn modell_schreiben(
    datei: Option<(PathBuf, std::fs::File)>,
    (mut k, mut hinweise): (stratum_normalize::Kontext, Vec<String>),
    funde: &[stratum_analysis::RawFinding],
    db: Option<&Sitzung>,
    r: &dyn Rueckmeldung,
) -> Result<report::ModellInfo, LaufFehler> {
    // Zeitpunkt der Abbildung, wie vor der Registrierung in der Datenbank.
    k.zeitpunkt = chrono::Utc::now();
    r.meldung("[*] Bilde Funde auf das Datenmodell ab ...");
    let mut m = stratum_normalize::normalisieren(funde, &k);
    let datei_hashes = match &datei {
        Some((path, file)) => {
            let mut w = std::io::BufWriter::new(stratum_core::HashingWriter::new(file));
            serde_json::to_writer(&mut w, &m)
                .kontext(|| format!("Modell nicht schreibbar: {}", path.display()))?;
            let (_, h) = w
                .into_inner()
                .map_err(|e| e.into_error())
                .and_then(|h| h.finish())
                .kontext(|| format!("Modell nicht abschließbar: {}", path.display()))?;
            Some(h)
        }
        None => None,
    };
    let datenbank = match db {
        Some(s) => {
            r.meldung("[*] Schreibe Modell in die Datenbank ...");
            let g = s.modell(&m, datei_hashes.as_ref().map(|h| h.sha256.as_str()))?;
            r.meldung(&format!(
                "[+] Datenbank: neu {} Artefakte, {} Ereignisse, {} Entitäten, {} Dateien",
                g.artefakte, g.ereignisse, g.entitaeten, g.dateien
            ));
            Some(g)
        }
        None => None,
    };
    hinweise.append(&mut m.hinweise);
    r.meldung(&format!(
        "[+] Modell: {} Ereignisse, {} Entitäten, {} Beziehungen{}",
        m.events.len(),
        m.entities.len(),
        m.relationships.len(),
        datei
            .as_ref()
            .map(|(p, _)| format!(" in {}", p.display()))
            .unwrap_or_default()
    ));
    Ok(report::ModellInfo {
        pfad: datei.as_ref().map(|(p, _)| p.display().to_string()),
        format: datei.as_ref().map(|_| "json"),
        hashes: datei_hashes,
        fall_id: k.case_id.to_string(),
        evidence_id: k.evidence_id.to_string(),
        artefakte: m.artifacts.len(),
        observationen: m.observations.len(),
        entitaeten: m.entities.len(),
        ereignisse: m.events.len(),
        beziehungen: m.relationships.len(),
        herkunftsangaben: m.provenance.len(),
        statistik: std::mem::take(&mut m.statistik),
        hinweise,
        datenbank,
    })
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_KEYWORDS;
    use stratum_search::TermTable;

    #[test]
    fn eingebaute_liste_ist_gueltig() {
        let t = TermTable::from_str(DEFAULT_KEYWORDS).expect("Default-Tabelle muss parsen");
        assert_eq!(t.meta.name, "Strafverfolgung");
        assert!(t.categories.len() >= 8);
        // Die Zugangsdaten-Kategorie ist im Paar-Modus.
        let z = t
            .categories
            .iter()
            .find(|c| c.id == "zugangsdaten")
            .unwrap();
        assert_eq!(z.modus, stratum_search::Modus::Paar);
        // Die sensible Kategorie ist leer und abgeschaltet.
        let m = t
            .categories
            .iter()
            .find(|c| c.id == "missbrauchsdarstellung")
            .unwrap();
        assert!(!m.aktiv);
        assert!(m.begriffe.is_empty());
    }
}
