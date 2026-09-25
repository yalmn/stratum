//! Domäne „Keyword-Suche": durchsucht das Image nach den Begriffen der
//! Begriffstabelle und liefert die Treffer als [`Finding`].

use stratum_search::{Encoding, FindingKind, SearchEngine, TermTable};

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Rückmeldung über die Zahl bereits durchsuchter Bytes.
pub type Progress = Box<dyn Fn(u64) + Sync + Send>;

/// Analyzer für die Keyword-Suche über das rohe Image.
pub struct KeywordAnalyzer {
    engine: SearchEngine,
    progress: Option<Progress>,
}

impl KeywordAnalyzer {
    /// Baut den Analyzer aus einer fertigen Such-Engine.
    pub fn new(engine: SearchEngine) -> Self {
        Self {
            engine,
            progress: None,
        }
    }

    /// Baut den Analyzer aus einer Begriffstabelle.
    pub fn from_table(table: &TermTable) -> Self {
        Self::new(SearchEngine::new(table))
    }

    /// Hinterlegt eine Fortschritts-Rückmeldung (durchsuchte Bytes).
    pub fn with_progress(mut self, progress: Progress) -> Self {
        self.progress = Some(progress);
        self
    }
}

impl Analyzer for KeywordAnalyzer {
    fn domain(&self) -> &str {
        "keyword"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        // Blockweise parallele Suche über das gesamte Image.
        let progress = self
            .progress
            .as_ref()
            .map(|p| p.as_ref() as &(dyn Fn(u64) + Sync));
        let result = self
            .engine
            .run_parallel_with_progress(ctx.img.as_slice(), 0, progress);

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
