//! Führt mehrere Analyzer parallel aus.

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
}

/// Lässt alle Analyzer gleichzeitig auf demselben Kontext laufen.
///
/// Die Analyzer sind untereinander unabhängig; ein einzelner rechenintensiver
/// Analyzer (z. B. die Keyword-Suche) parallelisiert seine Arbeit zusätzlich
/// intern.
pub fn run_all(ctx: &AnalysisContext<'_>, analyzers: &[Box<dyn Analyzer>]) -> AnalysisResult {
    let parts: Vec<(String, crate::Outcome)> = analyzers
        .par_iter()
        .map(|a| (a.domain().to_string(), a.run(ctx)))
        .collect();

    let mut out = AnalysisResult::default();
    for (domain, mut outcome) in parts {
        out.findings.append(&mut outcome.findings);
        for w in outcome.warnings {
            out.warnings.push(format!("[{domain}] {w}"));
        }
    }
    out.findings
        .sort_by(|a, b| a.domain.cmp(&b.domain).then(a.offset.cmp(&b.offset)));
    out
}
