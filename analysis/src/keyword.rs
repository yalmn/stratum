//! Domäne „Keyword-Suche": durchsucht das Image nach den Begriffen der
//! Begriffstabelle und liefert die Treffer als [`Finding`].

use stratum_search::{Encoding, FindingKind, SearchEngine, TermTable};

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für die Keyword-Suche über das rohe Image.
pub struct KeywordAnalyzer {
    engine: SearchEngine,
}

impl KeywordAnalyzer {
    /// Baut den Analyzer aus einer fertigen Such-Engine.
    pub fn new(engine: SearchEngine) -> Self {
        Self { engine }
    }

    /// Baut den Analyzer aus einer Begriffstabelle.
    pub fn from_table(table: &TermTable) -> Self {
        Self::new(SearchEngine::new(table))
    }
}

impl Analyzer for KeywordAnalyzer {
    fn domain(&self) -> &str {
        "keyword"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        // Blockweise parallele Suche über das gesamte Image.
        let result = self.engine.run_parallel(ctx.img.as_slice(), 0);

        let findings = result
            .findings
            .into_iter()
            .map(|f| {
                let kodierung = match f.kodierung {
                    Encoding::Ascii => "ascii",
                    Encoding::Utf16Le => "utf16le",
                };
                let (name, art, extra) = match f.kind {
                    FindingKind::Term { begriff } => (begriff, "term", None),
                    FindingKind::Paar {
                        links,
                        rechts,
                        abstand,
                    } => (format!("{links} / {rechts}"), "paar", Some(abstand)),
                };
                let mut finding = Finding::new(f.kategorie, name, "Image (roh)")
                    .at(f.offset)
                    .with("art", art)
                    .with("kodierung", kodierung)
                    .with("kontext", f.kontext);
                if let Some(abstand) = extra {
                    finding = finding.with("abstand", abstand.to_string());
                }
                finding
            })
            .collect();

        Outcome {
            findings,
            warnings: result.warnings,
        }
    }
}
