//! stratum: automatisierte, read-only Inhaltsanalyse eines Roh-Images.
//!
//! Der Lauf öffnet das Image ausschließlich lesend, bildet die
//! Integritäts-Hashes, erkennt die Partitionen und wertet jede NTFS-Partition
//! aus (Registry-Eckdaten und lokale Konten). Optional durchsucht er das Image
//! mit einer Begriffstabelle. Das Ergebnis ist ein JSON-Report.

mod bdp;
mod report;
mod report_html;
mod windows;

use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use stratum_analysis::{run_all, AnalysisContext, Analyzer, KeywordAnalyzer, NtfsTarget};
use stratum_core::{
    hash_image_with_progress, scan_partitions, FsHint, ImageReader, PartitionScheme,
};
use stratum_search::TermTable;

use report::{ImageInfo, Report, SearchReport, Tool};

/// Automatisierte, gerichtsverwertbare Inhaltsanalyse eines Roh-Images (read-only).
#[derive(Parser, Debug)]
#[command(name = "stratum", version, about)]
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

    /// Die mitgelieferte Begriffsliste "Strafverfolgung" nicht verwenden
    /// (dann wird nur gesucht, wenn eine eigene Tabelle mit -k angegeben ist).
    #[arg(long)]
    no_default_keywords: bool,
}

/// Mitgelieferte Standard-Begriffstabelle, in das Programm eingebaut.
const DEFAULT_KEYWORDS: &str = include_str!("../../begriffe/strafverfolgung.toml");

fn main() -> Result<()> {
    let cli = Cli::parse();

    let img = ImageReader::open(&cli.image)
        .with_context(|| format!("Image nicht lesbar: {}", cli.image.display()))?;

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

    // Welche Bereiche als NTFS untersucht werden: entweder genau die per
    // bdp.info benannte Partition, oder alle als NTFS erkannten aus dem Scan.
    let targets: Vec<NtfsTarget> = match &cli.bdp {
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
    };
    if targets.is_empty() && partitions.scheme != PartitionScheme::None {
        warnings.push("keine NTFS-Partition gefunden".into());
    }

    let mut windows = Vec::new();
    for t in &targets {
        let (index, offset, size) = (t.index, t.offset, t.size);
        eprintln!("[*] Untersuche NTFS-Partition bei Offset {offset} ...");
        match windows::analyze(&img, index, offset, size) {
            Ok(Some(w)) => {
                eprintln!(
                    "[+] Windows gefunden: {} Konto(en){}",
                    w.accounts.len(),
                    w.computer_name
                        .as_deref()
                        .map(|c| format!(", Rechner {c}"))
                        .unwrap_or_default()
                );
                windows.push(w);
            }
            Ok(None) => eprintln!("    kein Windows auf dieser Partition"),
            Err(e) => warnings.push(format!("Partition {index}: {e:#}")),
        }
    }

    let use_default = !cli.no_default_keywords;
    let search = if !use_default && cli.keywords.is_empty() {
        None
    } else {
        Some(run_search(&img, &targets, use_default, &cli.keywords)?)
    };

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
        search,
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

fn run_search(
    img: &ImageReader,
    targets: &[NtfsTarget],
    use_default: bool,
    paths: &[PathBuf],
) -> Result<SearchReport> {
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
    let table_name = table.meta.name.clone();
    let table_version = table.meta.version;

    // Der Keyword-Analyzer durchsucht das Image blockweise parallel und meldet
    // seinen Fortschritt an einen Byte-Balken.
    let pb = bytes_bar(img.len(), "Suche");
    let bar = pb.clone();
    let analyzer = KeywordAnalyzer::from_table(&table)
        .with_progress(Box::new(move |done| bar.set_position(done)));
    let analyzers: Vec<Box<dyn Analyzer>> = vec![Box::new(analyzer)];
    let ctx = AnalysisContext::new(img, targets.to_vec());

    let result = run_all(&ctx, &analyzers);
    pb.finish_and_clear();
    eprintln!("[+] Keyword-Suche: {} Treffer", result.findings.len());
    Ok(SearchReport {
        table_name,
        table_version,
        findings: result.findings,
        warnings: result.warnings,
    })
}

fn write_report(report: &Report, out: Option<&std::path::Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("Report nicht serialisierbar")?;
    match out {
        Some(path) => {
            std::fs::write(path, json)
                .with_context(|| format!("Report nicht schreibbar: {}", path.display()))?;
            eprintln!("Report geschrieben: {}", path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(json.as_bytes())?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
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
