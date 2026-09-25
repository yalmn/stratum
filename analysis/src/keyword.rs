//! Domäne „Keyword-Suche".
//!
//! Standardmäßig gezielt: Es werden nur die allozierten Textdateien aus dem
//! Pfad-Index gelesen und durchsucht (parallel über die Dateiliste). Jeder
//! Treffer trägt den echten Dateipfad und den Offset innerhalb der Datei. Nur
//! wenn kein Pfad-Index vorliegt, fällt der Analyzer auf eine rohe Suche über
//! das gesamte Image zurück.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use stratum_ntfs::NtfsVolume;
use stratum_search::{Encoding, FindingKind, SearchEngine, SearchResult, TermTable};

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Rückmeldung über den Fortschritt: (durchsuchte Bytes, Gesamtbytes).
pub type Progress = Box<dyn Fn(u64, u64) + Sync + Send>;

/// Endungen, die als Klartext gelten und durchsucht werden.
const TEXT_EXTS: &[&str] = &[
    "txt", "log", "csv", "tsv", "ini", "cfg", "conf", "json", "xml", "yaml", "yml", "html", "htm",
    "md", "eml", "vcf", "rtf", "sql", "ps1", "bat", "cmd", "sh", "py", "js", "php", "reg", "url",
    "srt", "sub",
];

/// Globale Obergrenze für die Treffer einer Domäne über alle Dateien hinweg.
const GLOBAL_CAT_CAP: usize = 20_000;

/// Dateien je Arbeitspaket, damit ein NTFS-Volume nicht pro Datei neu geöffnet
/// werden muss.
const CHUNK: usize = 128;

/// Verzeichnisse, die fast nur Programm- und Systemdateien enthalten und das
/// Rauschen der Keyword-Suche erzeugen.
const EXCLUDE_PREFIX: &[&str] = &[
    "windows\\",
    "program files\\",
    "program files (x86)\\",
    "programdata\\",
    "$recycle.bin\\",
    "system volume information\\",
    "msocache\\",
    "perflogs\\",
    "recovery\\",
    "$windows.~bt\\",
    "$windows.~ws\\",
];

/// Beschränkt die datei-gescopte Suche auf mögliche Nutzerinhalte: System- und
/// Programmverzeichnisse sowie `AppData` werden ausgeschlossen (dort liegen fast
/// nur Programm- und Systemdateien). Alles Übrige, insbesondere Nutzerdateien
/// unter `Users\`, bleibt drin. Der optionale Roh-Sweep (`--raw-sweep`) deckt
/// bei Bedarf weiterhin den gesamten Datenträger ab.
fn is_user_content(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    if EXCLUDE_PREFIX.iter().any(|x| p.starts_with(x)) {
        return false;
    }
    !p.contains("\\appdata\\")
}

/// Analyzer für die Keyword-Suche.
pub struct KeywordAnalyzer {
    engine: SearchEngine,
    progress: Option<Progress>,
    raw_sweep: bool,
}

impl KeywordAnalyzer {
    /// Baut den Analyzer aus einer fertigen Such-Engine.
    pub fn new(engine: SearchEngine) -> Self {
        Self {
            engine,
            progress: None,
            raw_sweep: false,
        }
    }

    /// Schaltet zusätzlich die Rohsuche über das gesamte Image ein (findet auch
    /// unallozierte und gelöschte Bereiche, dauert aber deutlich länger).
    pub fn with_raw_sweep(mut self, on: bool) -> Self {
        self.raw_sweep = on;
        self
    }

    /// Baut den Analyzer aus einer Begriffstabelle.
    pub fn from_table(table: &TermTable) -> Self {
        Self::new(SearchEngine::new(table))
    }

    /// Hinterlegt eine Fortschritts-Rückmeldung (durchsuchte Bytes, Gesamtbytes).
    pub fn with_progress(mut self, progress: Progress) -> Self {
        self.progress = Some(progress);
        self
    }

    fn report(&self, done: u64, total: u64) {
        if let Some(p) = &self.progress {
            p(done, total);
        }
    }

    /// Gezielte Suche über die Textdateien des Pfad-Index.
    fn run_files(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let total_bytes: u64 = ctx
            .volumes
            .iter()
            .flat_map(|v| v.by_extension(TEXT_EXTS))
            .filter(|e| is_user_content(&e.path))
            .map(|e| e.size)
            .sum();
        let done = AtomicU64::new(0);

        let mut findings: Vec<Finding> = Vec::new();
        let warnings: Vec<String> = Vec::new();

        for v in &ctx.volumes {
            let entries: Vec<_> = v
                .by_extension(TEXT_EXTS)
                .filter(|e| is_user_content(&e.path))
                .collect();
            let target = v.target;

            let chunk_results: Vec<Vec<Finding>> = entries
                .par_chunks(CHUNK)
                .map(|chunk| {
                    let mut out = Vec::new();
                    let mut vol = match NtfsVolume::open(ctx.img, target.offset, target.size) {
                        Ok(vol) => vol,
                        Err(_) => {
                            // Fortschritt trotzdem weiterzaehlen.
                            let sum: u64 = chunk.iter().map(|e| e.size).sum();
                            let d = done.fetch_add(sum, Ordering::Relaxed) + sum;
                            self.report(d, total_bytes);
                            return out;
                        }
                    };
                    for e in chunk {
                        if let Ok(Some(file)) = vol.read_file_by_record(e.mft_record, &e.path) {
                            let result = self.engine.run(&file.data, 0);
                            map_findings(result, &e.path, Some(e.mft_record), &mut out);
                        }
                        let d = done.fetch_add(e.size, Ordering::Relaxed) + e.size;
                        self.report(d, total_bytes);
                    }
                    out
                })
                .collect();

            for c in chunk_results {
                findings.extend(c);
            }
        }

        self.report(total_bytes, total_bytes);
        Outcome { findings, warnings }
    }

    /// Rohsuche über das gesamte Image (Fallback ohne Pfad-Index).
    fn run_raw(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let total = ctx.img.len();
        let cb = |done: u64| self.report(done, total);
        let cb_ref: &(dyn Fn(u64) + Sync) = &cb;
        let result = self
            .engine
            .run_parallel_with_progress(ctx.img.as_slice(), 0, Some(cb_ref));

        let mut findings = Vec::new();
        map_findings(result, "Image (roh)", None, &mut findings);
        Outcome {
            findings,
            warnings: Vec::new(),
        }
    }
}

impl Analyzer for KeywordAnalyzer {
    fn domain(&self) -> &str {
        "keyword"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        // Ohne Pfad-Index bleibt nur die Rohsuche. Mit Index werden gezielt die
        // Textdateien durchsucht; --raw-sweep haengt zusaetzlich eine Rohsuche
        // über das ganze Image an (unallozierte/gelöschte Bereiche).
        let mut outcome = if ctx.volumes.is_empty() {
            self.run_raw(ctx)
        } else {
            let mut oc = self.run_files(ctx);
            if self.raw_sweep {
                let mut raw = self.run_raw(ctx);
                oc.findings.append(&mut raw.findings);
                oc.warnings.append(&mut raw.warnings);
            }
            oc
        };
        // Kategorie-Obergrenze einmal über alle (Datei + roh) Funde.
        cap_per_domain(&mut outcome.findings, &mut outcome.warnings);
        outcome
    }
}

/// Wandelt die Treffer eines Suchlaufs in Funde mit Quelle um.
fn map_findings(
    result: SearchResult,
    source: &str,
    mft_record: Option<u64>,
    out: &mut Vec<Finding>,
) {
    for f in result.findings {
        let kodierung = match f.kodierung {
            Encoding::Ascii => "ascii",
            Encoding::Utf16Le => "utf16le",
        };
        let (name, art, abstand) = match f.kind {
            FindingKind::Term { begriff } => (begriff, "term", None),
            FindingKind::Paar {
                links,
                rechts,
                abstand,
            } => (format!("{links} / {rechts}"), "paar", Some(abstand)),
        };
        let mut finding = Finding::new(f.kategorie, name, source)
            .at(f.offset)
            .with("art", art)
            .with("kodierung", kodierung)
            .with("kontext", f.kontext);
        if let Some(a) = abstand {
            finding = finding.with("abstand", a.to_string());
        }
        if let Some(rec) = mft_record {
            finding = finding.with("mft_record", rec.to_string());
        }
        out.push(finding);
    }
}

/// Kappt die Treffer je Domäne global (über alle Dateien) und meldet die
/// betroffenen Domänen.
fn cap_per_domain(findings: &mut Vec<Finding>, warnings: &mut Vec<String>) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut capped: HashSet<String> = HashSet::new();
    findings.retain(|f| {
        let c = counts.entry(f.domain.clone()).or_default();
        if *c < GLOBAL_CAT_CAP {
            *c += 1;
            true
        } else {
            capped.insert(f.domain.clone());
            false
        }
    });
    let mut capped: Vec<_> = capped.into_iter().collect();
    capped.sort();
    for d in capped {
        warnings.push(format!(
            "Domäne {d}: globale Grenze {GLOBAL_CAT_CAP} erreicht, weitere Treffer nicht erfasst"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::is_user_content;

    #[test]
    fn scoping_nutzerinhalte() {
        assert!(is_user_content("Users\\ich\\Documents\\notiz.txt"));
        assert!(is_user_content("notiz.txt")); // Wurzeldatei
        assert!(is_user_content("Daten\\brief.docx"));
        // Ausgeschlossen:
        assert!(!is_user_content("Windows\\System32\\x.ini"));
        assert!(!is_user_content("Program Files\\App\\config.json"));
        assert!(!is_user_content("Users\\ich\\AppData\\Local\\Edge\\x.js"));
        assert!(!is_user_content("ProgramData\\Microsoft\\y.xml"));
    }
}
