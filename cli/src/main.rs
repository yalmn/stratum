//! stratum: automatisierte, read-only Inhaltsanalyse eines Roh-Images.
//!
//! Der Lauf öffnet das Image ausschließlich lesend, bildet die
//! Integritäts-Hashes, erkennt die Partitionen und wertet jede NTFS-Partition
//! aus (Registry-Eckdaten und lokale Konten). Optional durchsucht er das Image
//! mit einer Begriffstabelle. Das Ergebnis ist ein JSON-Report.

mod bdp;
mod extract;
mod liveness;
mod report;
mod report_html;

use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use stratum_analysis::{
    run_all, ActivitiesCacheAnalyzer, AnalysisContext, Analyzer, BamAnalyzer, BrowserAnalyzer,
    DpapiAnalyzer, DpapiInput, EventLogAnalyzer, FilePersistenceAnalyzer, JumpListAnalyzer,
    KeywordAnalyzer, LnkAnalyzer, LsaAnalyzer, NtfsTarget, PersistenceAnalyzer,
    PowerShellHistoryAnalyzer, PrefetchAnalyzer, ProgramExecutionAnalyzer, RecycleBinAnalyzer,
    ShellBagsAnalyzer, SrumAnalyzer, TorAnalyzer, UsbAnalyzer, UserActivityAnalyzer, VssAnalyzer,
    WebCacheAnalyzer, ZoneIdentifierAnalyzer,
};
use stratum_core::{
    hash_image_with_progress, scan_partitions, FsHint, ImageReader, PartitionScheme,
};
use stratum_search::TermTable;

use report::{
    CatalogInfo, ImageInfo, KeywordInfo, MftTimelineInfo, Report, Tool, UsnJournalInfo,
    WindowsReport,
};

/// Automatisierte, gerichtsverwertbare Inhaltsanalyse eines Roh-Images (read-only).
#[derive(Parser, Debug)]
#[command(
    name = "stratum",
    version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (Revision ",
        env!("STRATUM_REVISION"),
        ", nicht committete Änderungen: ",
        env!("STRATUM_REVISION_GEAENDERT"),
        ")"
    ),
    about
)]
struct Cli {
    /// Pfad zum Roh-Image (z. B. merged.dd).
    image: PathBuf,

    /// Zieldatei für den JSON-Report (Standard: Ausgabe auf stdout).
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Zusätzlich einen übersichtlichen HTML-Report in diese Datei schreiben.
    #[arg(long)]
    html: Option<PathBuf>,

    /// Begriffstabelle(n) (TOML) für die Keyword-Suche. Mehrfach angebbar, die
    /// Tabellen werden zusammengeführt (z. B. eine mitgelieferte und eine
    /// eigene).
    #[arg(short, long)]
    keywords: Vec<PathBuf>,

    /// bdp.info von ForensiCUnlock: legt die zu analysierende Partition fest.
    #[arg(long)]
    bdp: Option<PathBuf>,

    /// Die Integritäts-Hashes nicht berechnen (spart bei großen Images Zeit).
    #[arg(long)]
    no_hash: bool,

    /// Zusätzlich das gesamte Image roh nach Begriffen durchsuchen (findet auch
    /// unallozierte und gelöschte Bereiche, dauert aber deutlich länger).
    #[arg(long)]
    raw_sweep: bool,

    /// Gefundene .onion-Adressen online über Tor auf Erreichbarkeit prüfen.
    /// Verlässt die Offline-Analyse und setzt einen laufenden Tor-Dienst voraus.
    #[arg(long)]
    check_onion: bool,

    /// SOCKS5-Proxy für --check-onion.
    #[arg(long, default_value = "127.0.0.1:9050")]
    tor_proxy: String,

    /// Die mitgelieferte Begriffsliste "Strafverfolgung" nicht verwenden
    /// (dann wird nur gesucht, wenn eine eigene Tabelle mit -k angegeben ist).
    #[arg(long)]
    no_default_keywords: bool,

    /// Eine einzelne Datei aus dem Image extrahieren und beenden, ohne Analyse.
    /// Zwei Werte: der NTFS-Pfad im Image und die Zieldatei.
    /// Beispiel: --dump "Windows/System32/config/SAM" /tmp/SAM
    #[arg(long, num_args = 2, value_names = ["NTFS_PFAD", "ZIEL"])]
    dump: Option<Vec<String>>,

    /// Eine Datei über Volume-Offset und MFT-Nummer extrahieren (Werte z. B. aus
    /// dem Dateikatalog) und beenden. Wie bei --dump entsteht daneben
    /// `<ZIEL>.herkunft.json` mit Quelle und Hashes; nichts wird überschrieben.
    #[arg(long, num_args = 3, value_names = ["VOLUME_OFFSET", "MFT", "ZIEL"])]
    dump_record: Option<Vec<String>>,

    /// Dateikatalog aller Dateien und Verzeichnisse mit Metadaten als JSON Lines
    /// in diese Datei schreiben. Der Report verweist mit Hashes darauf. Eine
    /// vorhandene Datei wird nicht überschrieben.
    #[arg(long, value_name = "DATEI")]
    catalog: Option<PathBuf>,

    /// Im Dateikatalog zusätzlich SHA-256 und Signaturtyp jeder Datei
    /// bestimmen. Liest dafür jede Datei vollständig und dauert entsprechend
    /// lange; die Integrität sichert bereits der Image-Hash.
    #[arg(long, requires = "catalog")]
    datei_hashes: bool,

    /// Vollständige MFT-Zeitachse mit SI-/FN-MACB-Ereignissen als JSON Lines.
    /// Enthält auch lesbare gelöschte Datensätze. Eine vorhandene Datei wird
    /// nicht überschrieben.
    #[arg(long, value_name = "DATEI")]
    mft_timeline: Option<PathBuf>,

    /// NTFS-Änderungsjournal `$UsnJrnl:$J` als JSON Lines schreiben. Spärliche
    /// Bereiche werden übersprungen. Eine vorhandene Datei wird nicht
    /// überschrieben.
    #[arg(long, value_name = "DATEI")]
    usn_journal: Option<PathBuf>,

    /// Klartextpasswort des Benutzers, um gespeicherte Browser-Passwörter
    /// (DPAPI) zu entschlüsseln. Der NT-Hash genügt dafür nicht; das Passwort
    /// wird üblicherweise vorher aus dem NT-Hash geknackt (hashcat/john).
    #[arg(long, value_name = "PASSWORT")]
    dpapi_password: Option<String>,

    /// Statt des Klartextpassworts der vorberechnete SHA-1 (UTF-16LE), hex.
    #[arg(long, value_name = "HEX40")]
    dpapi_sha1: Option<String>,

    /// Statt des Passworts ein bereits entschlüsselter DPAPI-Masterkey (64 Byte,
    /// hex), z. B. aus mimikatz oder impacket.
    #[arg(long, value_name = "HEX128")]
    dpapi_masterkey: Option<String>,

    /// Firefox-Hauptpasswort, um gespeicherte Firefox-Passwörter zu
    /// entschlüsseln. Ohne Angabe wird ein leeres Hauptpasswort angenommen (der
    /// Normalfall).
    #[arg(long, value_name = "PASSWORT")]
    firefox_password: Option<String>,
}

/// Wandelt eine Hex-Zeichenkette fester Länge in Bytes; Fehler mit Kontext.
fn hex_bytes(s: &str, erwartet: usize, name: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() != erwartet * 2 {
        anyhow::bail!(
            "{name}: {} Hex-Zeichen erwartet, {} erhalten",
            erwartet * 2,
            s.len()
        );
    }
    (0..erwartet)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow::anyhow!("{name}: ungültiges Hex"))
        })
        .collect()
}

/// Baut aus den drei sich ausschliessenden DPAPI-Flags die Eingabe.
fn dpapi_from_cli(cli: &Cli) -> Result<Option<DpapiInput>> {
    let gesetzt = [
        cli.dpapi_password.is_some(),
        cli.dpapi_sha1.is_some(),
        cli.dpapi_masterkey.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if gesetzt > 1 {
        anyhow::bail!("--dpapi-password, --dpapi-sha1 und --dpapi-masterkey schliessen sich aus");
    }
    if let Some(p) = &cli.dpapi_password {
        return Ok(Some(DpapiInput::Password(p.clone())));
    }
    if let Some(h) = &cli.dpapi_sha1 {
        let b = hex_bytes(h, 20, "--dpapi-sha1")?;
        return Ok(Some(DpapiInput::Sha1(b.try_into().unwrap())));
    }
    if let Some(m) = &cli.dpapi_masterkey {
        let b = hex_bytes(m, 64, "--dpapi-masterkey")?;
        return Ok(Some(DpapiInput::Masterkey(b.try_into().unwrap())));
    }
    Ok(None)
}

/// Mitgelieferte Standard-Begriffstabelle, in das Programm eingebaut.
const DEFAULT_KEYWORDS: &str = include_str!("../../begriffe/strafverfolgung.toml");

fn main() -> Result<()> {
    let cli = Cli::parse();

    let img = ImageReader::open(&cli.image)
        .with_context(|| format!("Image nicht lesbar: {}", cli.image.display()))?;

    // Schnellmodus: eine Datei extrahieren und beenden (keine Analyse).
    if let Some(d) = &cli.dump {
        let targets = ntfs_targets(&img, cli.bdp.as_deref())?;
        return extract::run(
            &img,
            &targets,
            extract::Selector::Path(&d[0]),
            std::path::Path::new(&d[1]),
        );
    }
    if let Some(d) = &cli.dump_record {
        let volume_offset = d[0]
            .parse()
            .with_context(|| format!("VOLUME_OFFSET ist keine Zahl: {}", d[0]))?;
        let mft = d[1]
            .parse()
            .with_context(|| format!("MFT ist keine Zahl: {}", d[1]))?;
        let targets = ntfs_targets(&img, cli.bdp.as_deref())?;
        return extract::run(
            &img,
            &targets,
            extract::Selector::Record { volume_offset, mft },
            std::path::Path::new(&d[2]),
        );
    }

    // Katalogdatei vor der langen Hash-Phase anlegen, damit ein Namenskonflikt
    // sofort auffällt.
    let catalog_file = match &cli.catalog {
        Some(p) => Some((
            p.clone(),
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)
                .with_context(|| {
                    format!(
                        "Katalog nicht anlegbar (existiert bereits?): {}",
                        p.display()
                    )
                })?,
        )),
        None => None,
    };
    let mft_timeline_file = match &cli.mft_timeline {
        Some(p) => Some((
            p.clone(),
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)
                .with_context(|| {
                    format!(
                        "MFT-Zeitachse nicht anlegbar (existiert bereits?): {}",
                        p.display()
                    )
                })?,
        )),
        None => None,
    };
    let usn_file = match &cli.usn_journal {
        Some(path) => Some((
            path.clone(),
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| {
                    format!(
                        "USN-Zeitachse nicht anlegbar (existiert bereits?): {}",
                        path.display()
                    )
                })?,
        )),
        None => None,
    };

    let mut warnings = Vec::new();

    let hashes = if cli.no_hash {
        None
    } else {
        let pb = bytes_bar(img.len(), "Hashing");
        let cb: stratum_core::Progress = &|done| pb.set_position(done);
        let h = hash_image_with_progress(&img, Some(cb));
        pb.finish_and_clear();
        eprintln!("[+] Integritäts-Hashes berechnet ({} Bytes)", img.len());
        Some(h)
    };

    let partitions = scan_partitions(&img);
    eprintln!(
        "[+] {} Partition(en) erkannt ({:?})",
        partitions.partitions.len(),
        partitions.scheme
    );

    let targets = targets_from(&partitions, cli.bdp.as_deref())?;
    if targets.is_empty() && partitions.scheme != PartitionScheme::None {
        warnings.push("keine NTFS-Partition gefunden".into());
    }

    // Gemeinsamer Kontext: extrahiert einmalig je NTFS-Bereich die Hives und
    // leitet Zeitzone, Rechnername und Konten ab.
    eprintln!("[*] Lese Registry-Hives und baue Pfad-Index ...");
    let dpapi = dpapi_from_cli(&cli)?;
    let mut ctx = AnalysisContext::build(&img, targets.clone());
    ctx.dpapi = dpapi;
    ctx.firefox_password = cli.firefox_password.clone();
    warnings.extend(ctx.warnings.iter().cloned());
    if let Some(v) = ctx.volumes.first() {
        eprintln!(
            "[+] Pfad-Index: {} Dateien, {} Verzeichnisse",
            v.files.len(),
            v.directories.len()
        );
    }

    let catalog = match catalog_file {
        Some((path, file)) => {
            eprintln!("[*] Schreibe Dateikatalog ...");
            let mut w =
                std::io::BufWriter::with_capacity(1 << 20, stratum_core::HashingWriter::new(file));
            let started = std::time::Instant::now();
            let progress = |done: u64, total: u64| {
                eprintln!(
                    "[*] Dateikatalog: {done} von {total} Einträgen ({} s)",
                    started.elapsed().as_secs()
                );
            };
            let summary = stratum_analysis::write_catalog_with(
                &img,
                &ctx.volumes,
                &mut w,
                stratum_analysis::CatalogOptions {
                    inhalte: cli.datei_hashes,
                    progress: Some(&progress),
                },
            )
            .with_context(|| format!("Katalog nicht schreibbar: {}", path.display()))?;
            let (_, hashes) = w
                .into_inner()
                .map_err(|e| e.into_error())
                .and_then(|h| h.finish())
                .with_context(|| format!("Katalog nicht abschließbar: {}", path.display()))?;
            eprintln!(
                "[+] Dateikatalog: {} Einträge ({} Fehler) in {}",
                summary.eintraege,
                summary.fehler,
                path.display()
            );
            if summary.fehler > 0 {
                warnings.push(format!(
                    "Dateikatalog: {} Einträge ohne lesbaren MFT-Datensatz (Feld fehler)",
                    summary.fehler
                ));
            }
            Some(CatalogInfo {
                pfad: path.display().to_string(),
                quelle: stratum_analysis::CATALOG_SOURCE,
                format: "JSON Lines, ein Eintrag je Zeile, sortiert nach Volume und Pfad",
                hashes,
                summary,
            })
        }
        None => None,
    };

    let mft_timeline = match mft_timeline_file {
        Some((path, file)) => {
            eprintln!("[*] Schreibe vollständige MFT-Zeitachse ...");
            let mut writer =
                std::io::BufWriter::with_capacity(1 << 20, stratum_core::HashingWriter::new(file));
            let summary = stratum_analysis::write_mft_timeline(&img, &ctx.volumes, &mut writer)
                .with_context(|| format!("MFT-Zeitachse nicht schreibbar: {}", path.display()))?;
            let (_, hashes) = writer
                .into_inner()
                .map_err(|e| e.into_error())
                .and_then(|h| h.finish())
                .with_context(|| format!("MFT-Zeitachse nicht abschließbar: {}", path.display()))?;
            eprintln!(
                "[+] MFT-Zeitachse: {} Ereignisse aus {} lesbaren Datensätzen ({} gelöscht, {} Fehler) in {}",
                summary.ereignisse,
                summary.lesbar,
                summary.geloescht,
                summary.fehler,
                path.display()
            );
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
            eprintln!("[*] Schreibe USN-Änderungsjournal ...");
            let mut writer =
                std::io::BufWriter::with_capacity(1 << 20, stratum_core::HashingWriter::new(file));
            let summary = stratum_analysis::write_usn_journal(&img, &ctx.volumes, &mut writer)
                .with_context(|| format!("USN-Zeitachse nicht schreibbar: {}", path.display()))?;
            let (_, hashes) = writer
                .into_inner()
                .map_err(|error| error.into_error())
                .and_then(|hashing| hashing.finish())
                .with_context(|| format!("USN-Zeitachse nicht abschließbar: {}", path.display()))?;
            eprintln!(
                "[+] USN-Zeitachse: {} Datensätze aus {} Journal(en), {} Fehler in {}",
                summary.datensaetze,
                summary.journals,
                summary.fehler,
                path.display()
            );
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

    let mut windows = Vec::new();
    for inst in &ctx.installs {
        // Reine Datenpartitionen (kein SYSTEM-Hive) liefern keinen Eintrag; hier
        // erscheinen nur echte Windows-Installationen und Fehlerfaelle.
        if inst.hives.system.is_none() && inst.accounts.is_empty() {
            for w in &inst.warnings {
                warnings.push(format!("Offset {}: {w}", inst.target.offset));
            }
            continue;
        }
        eprintln!(
            "[+] Windows gefunden: {} Konto(en){}",
            inst.accounts.len(),
            inst.computer_name
                .as_deref()
                .map(|c| format!(", Rechner {c}"))
                .unwrap_or_default()
        );
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

    // Domänen-Analyzer zusammenstellen: Tor läuft immer, die Keyword-Suche nur
    // bei aktiver Begriffsliste.
    let use_default = !cli.no_default_keywords;
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

    let mut keyword_bar = None;
    let keywords = if !use_default && cli.keywords.is_empty() {
        None
    } else {
        let (analyzer, info) = build_keyword_analyzer(use_default, &cli.keywords)?;
        let pb = bytes_bar(img.len(), "Suche");
        let bar = pb.clone();
        let analyzer = analyzer
            .with_raw_sweep(cli.raw_sweep)
            .with_progress(Box::new(move |done, total| {
                bar.set_length(total);
                bar.set_position(done);
            }));
        analyzers.push(Box::new(analyzer));
        keyword_bar = Some(pb);
        Some(info)
    };

    eprintln!("[*] Führe Domänen-Analyzer aus ...");
    let mut analysis = run_all(&ctx, &analyzers);
    if let Some(pb) = keyword_bar {
        pb.finish_and_clear();
    }
    warnings.append(&mut analysis.warnings);
    eprintln!("[+] {} Funde ueber alle Domänen", analysis.findings.len());

    // Optionale Online-Erreichbarkeitspruefung der gefundenen .onion-Adressen.
    if cli.check_onion {
        eprintln!(
            "[*] Pruefe .onion-Erreichbarkeit ueber {} ...",
            cli.tor_proxy
        );
        let mut live = liveness::check_onions(&analysis.findings, &cli.tor_proxy);
        eprintln!("[+] {} .onion-Adresse(n) geprueft", live.len());
        analysis.findings.append(&mut live);
    }

    stratum_analysis::assign_ids(&mut analysis.findings);
    let timeline = stratum_analysis::build_timeline(&analysis.findings);
    eprintln!("[+] Zeitstrahl mit {} Ereignissen", timeline.len());

    let generated_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let out = Report {
        tool: Tool::default(),
        generated_unix,
        image: ImageInfo {
            path: img.path().display().to_string(),
            size: img.len(),
            hashes,
        },
        partitions,
        windows,
        analyzers: analysis.analyzers,
        findings: analysis.findings,
        timeline,
        keywords,
        catalog,
        mft_timeline,
        usn_journal,
        warnings,
    };

    if let Some(path) = &cli.html {
        let html = report_html::render(&out);
        std::fs::write(path, html)
            .with_context(|| format!("HTML-Report nicht schreibbar: {}", path.display()))?;
        eprintln!("[+] HTML-Report geschrieben: {}", path.display());
    }

    write_report(&out, cli.out.as_deref())
}

/// Fortschrittsbalken in Bytes. Zeichnet auf stderr und blendet sich aus, wenn
/// stderr kein Terminal ist, damit der JSON-Report auf stdout sauber bleibt.
fn bytes_bar(len: u64, label: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    let tmpl = format!(
        "  {label:<8}[{{bar:40}}] {{bytes}}/{{total_bytes}} ({{bytes_per_sec}}, ETA {{eta}})"
    );
    if let Ok(style) = ProgressStyle::with_template(&tmpl) {
        pb.set_style(style.progress_chars("=>-"));
    }
    pb
}

/// Welche Bereiche als NTFS untersucht werden: entweder genau die per
/// bdp.info benannte Partition, oder alle als NTFS erkannten aus dem Scan.
fn targets_from(
    partitions: &stratum_core::PartitionTable,
    bdp: Option<&std::path::Path>,
) -> Result<Vec<NtfsTarget>> {
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
fn ntfs_targets(img: &ImageReader, bdp: Option<&std::path::Path>) -> Result<Vec<NtfsTarget>> {
    targets_from(&scan_partitions(img), bdp)
}

/// Baut den Keyword-Analyzer aus der mitgelieferten und den eigenen
/// Begriffstabellen und liefert dazu die Angaben für den Report.
fn build_keyword_analyzer(
    use_default: bool,
    paths: &[PathBuf],
) -> Result<(KeywordAnalyzer, KeywordInfo)> {
    // Mehrere Tabellen werden zu einer zusammengeführt: alle Kategorien
    // hintereinander, der Name aus den Quellen, die höchste Version. Die
    // mitgelieferte Tabelle kommt zuerst, damit eigene Kategorien folgen.
    let mut names = Vec::new();
    let mut version = 0;
    let mut categories = Vec::new();
    let mut max_treffer = usize::MAX;

    if use_default {
        let table = TermTable::from_str(DEFAULT_KEYWORDS)
            .context("eingebaute Begriffstabelle nicht lesbar")?;
        names.push(format!("{} (mitgeliefert)", table.meta.name));
        version = version.max(table.meta.version);
        max_treffer = max_treffer.min(table.meta.max_treffer);
        categories.extend(table.categories);
    }

    for path in paths {
        let table = TermTable::load(path)
            .with_context(|| format!("Begriffstabelle nicht lesbar: {}", path.display()))?;
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

fn write_report(report: &Report, out: Option<&std::path::Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("Report nicht serialisierbar")?;
    match out {
        Some(path) => {
            std::fs::write(path, &json)
                .with_context(|| format!("Report nicht schreibbar: {}", path.display()))?;
            eprintln!("Report geschrieben: {}", path.display());
            // Fuer die Beweiskette: Pruefsummen des Reports als Beisatz schreiben.
            let hashes = stratum_core::hash_bytes(json.as_bytes());
            let sidecar = with_extension(path, "sha256");
            let content = format!("sha256  {}\nblake3  {}\n", hashes.sha256, hashes.blake3);
            std::fs::write(&sidecar, content).with_context(|| {
                format!("Pruefsummen-Datei nicht schreibbar: {}", sidecar.display())
            })?;
            eprintln!("[+] Report-SHA-256: {}", hashes.sha256);
            eprintln!("[+] Pruefsummen geschrieben: {}", sidecar.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(json.as_bytes())?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Haengt eine Endung an den Report-Pfad an (report.json -> report.json.sha256).
fn with_extension(path: &std::path::Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
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
