//! Führt mehrere Analyzer parallel aus.

use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;

use crate::{AnalysisContext, Analyzer, Finding};

/// Gesammeltes Ergebnis aller Analyzer.
#[derive(Debug, Default, Serialize)]
pub struct AnalysisResult {
    /// Alle Funde, nach Domäne und Offset sortiert.
    pub findings: Vec<Finding>,
    /// Auffälligkeiten aus allen Domänen.
    pub warnings: Vec<String>,
    /// Laufstatus je Analyzer in der übergebenen Reihenfolge.
    pub analyzers: Vec<AnalyzerStatus>,
}

/// Was ein einzelner Analyzer geliefert hat. Null Funde heißt nur, dass
/// dieser Analyzer nichts gemeldet hat; wie vollständig er die Quellen lesen
/// konnte, stehen dann in seinen Warnungen.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerStatus {
    /// Name des Analyzers.
    pub name: &'static str,
    /// Domäne seiner Funde.
    pub domain: String,
    /// Anzahl der Funde.
    pub funde: usize,
    /// Anzahl der Warnungen (Quellen nicht oder nur teilweise lesbar u. a.).
    pub warnungen: usize,
    /// Laufzeit in Millisekunden (Untersuchungszeit, keine Artefaktzeit).
    pub dauer_ms: u64,
}

/// Lässt alle Analyzer gleichzeitig auf demselben Kontext laufen.
///
/// Die Analyzer sind untereinander unabhängig; ein einzelner rechenintensiver
/// Analyzer (z. B. die Keyword-Suche) parallelisiert seine Arbeit zusätzlich
/// intern.
pub fn run_all(ctx: &AnalysisContext<'_>, analyzers: &[Box<dyn Analyzer>]) -> AnalysisResult {
    let parts: Vec<(&'static str, String, crate::Outcome, u64)> = analyzers
        .par_iter()
        .map(|a| {
            let start = Instant::now();
            let outcome = a.run(ctx);
            let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            (a.name(), a.domain().to_string(), outcome, ms)
        })
        .collect();

    let mut out = AnalysisResult::default();
    for (name, domain, mut outcome, dauer_ms) in parts {
        out.analyzers.push(AnalyzerStatus {
            name,
            domain: domain.clone(),
            funde: outcome.findings.len(),
            warnungen: outcome.warnings.len(),
            dauer_ms,
        });
        out.findings.append(&mut outcome.findings);
        for w in outcome.warnings {
            out.warnings.push(format!("[{domain}] {w}"));
        }
    }
    out.findings
        .sort_by(|a, b| a.domain.cmp(&b.domain).then(a.offset.cmp(&b.offset)));
    out
}
