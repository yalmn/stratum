//! stratum: automatisierte, read-only Inhaltsanalyse eines Roh-Images.
//!
//! Der Lauf öffnet das Image ausschließlich lesend, bildet die
//! Integritäts-Hashes, erkennt die Partitionen und wertet jede NTFS-Partition
//! aus (Registry-Eckdaten und lokale Konten). Optional durchsucht er das Image
//! mit einer Begriffstabelle. Das Ergebnis ist ein JSON-Report.

mod bdp;
mod report;
mod windows;

use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;

use stratum_core::{hash_image, scan_partitions, FsHint, ImageReader, PartitionScheme};
use stratum_search::{SearchEngine, TermTable};

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

    /// Begriffstabelle (TOML) für die Keyword-Suche.
    #[arg(short, long)]
    keywords: Option<PathBuf>,

    /// bdp.info von ForensiCUnlock: legt die zu analysierende Partition fest.
    #[arg(long)]
    bdp: Option<PathBuf>,

    /// Die Integritäts-Hashes nicht berechnen (spart bei großen Images Zeit).
    #[arg(long)]
    no_hash: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let img = ImageReader::open(&cli.image)
        .with_context(|| format!("Image nicht lesbar: {}", cli.image.display()))?;

    let mut warnings = Vec::new();

    let hashes = if cli.no_hash {
        None
    } else {
        Some(hash_image(&img))
    };

    let partitions = scan_partitions(&img);

    // Welche Bereiche als NTFS untersucht werden: entweder genau die per
    // bdp.info benannte Partition, oder alle als NTFS erkannten aus dem Scan.
    let targets = match &cli.bdp {
        Some(path) => {
            let b = bdp::load(path)?;
            vec![(u32::MAX, b.offset_bytes, b.size_bytes)]
        }
        None => partitions
            .partitions
            .iter()
            .filter(|p| p.fs_hint == FsHint::Ntfs || p.typ == stratum_core::PartitionType::Volume)
            .map(|p| (p.index, p.start_offset, p.size_bytes))
            .collect(),
    };
    if targets.is_empty() && partitions.scheme != PartitionScheme::None {
        warnings.push("keine NTFS-Partition gefunden".into());
    }

    let mut windows = Vec::new();
    for (index, offset, size) in targets {
        match windows::analyze(&img, index, offset, size) {
            Ok(Some(w)) => windows.push(w),
            Ok(None) => {}
            Err(e) => warnings.push(format!("Partition {index}: {e:#}")),
        }
    }

    let search = match &cli.keywords {
        Some(path) => Some(run_search(&img, path)?),
        None => None,
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

    write_report(&out, cli.out.as_deref())
}

fn run_search(img: &ImageReader, path: &std::path::Path) -> Result<SearchReport> {
    let table = TermTable::load(path).context("Begriffstabelle nicht lesbar")?;
    let engine = SearchEngine::new(&table);
    let result = engine.run(img.as_slice(), 0);
    Ok(SearchReport {
        table_name: table.meta.name,
        table_version: table.meta.version,
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
