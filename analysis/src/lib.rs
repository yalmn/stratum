//! Domänen-Analyzer und der gemeinsame Kontext, auf dem sie arbeiten.
//!
//! Jede Domäne (Keyword-Suche, Zugangsdaten, Browser, Chat, ...) ist eine
//! Implementierung von [`Analyzer`]. Die teuren Vorarbeiten (Partitionen,
//! NTFS-Volumes, Registry-Hives, Zeitzone) stehen einmalig im
//! [`AnalysisContext`] bereit, damit die Analyzer parallel darauf laufen können,
//! ohne sie erneut zu leisten.
//!
//! Der `Analyzer`-Trait liegt hier und nicht in `core`, weil der Kontext Typen
//! aus den höheren Crates (NTFS, Registry) hält; in `core` ergäbe das einen
//! Abhängigkeitszyklus.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod browser;
mod context;
mod eventlog;
mod finding;
mod fsindex;
mod keyword;
mod lsa;
mod prefetch;
mod programexec;
mod reg;
mod runner;
mod timeline;
mod tor;
mod vss;
mod windows;

#[cfg(test)]
#[path = "../tests/common/builder.rs"]
mod builder;

pub use browser::BrowserAnalyzer;
pub use context::{AnalysisContext, NtfsTarget};
pub use eventlog::EventLogAnalyzer;
pub use finding::Finding;
pub use fsindex::{FileEntry, FsIndex};
pub use keyword::KeywordAnalyzer;
pub use lsa::LsaAnalyzer;
pub use prefetch::PrefetchAnalyzer;
pub use programexec::ProgramExecutionAnalyzer;
pub use reg::{PersistenceAnalyzer, UsbAnalyzer, UserActivityAnalyzer};
pub use runner::{run_all, AnalysisResult};
pub use timeline::{build as build_timeline, TimelineEntry};
pub use tor::TorAnalyzer;
pub use vss::VssAnalyzer;
pub use windows::{extract_snapshots, Hives, TimeZone, WindowsInstall};

/// Ergebnis eines einzelnen Analyzers.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Gefundene Spuren.
    pub findings: Vec<Finding>,
    /// Auffälligkeiten während der Analyse.
    pub warnings: Vec<String>,
}

impl Outcome {
    /// Markiert alle seit `before` hinzugekommenen Funde mit der Herkunft des
    /// Volumes, sofern es sich nicht um das Live-Volume handelt (Nachweis, dass
    /// ein Fund aus einer Schattenkopie stammt).
    fn tag_origin(&mut self, before: usize, origin: &str) {
        if origin == "live" {
            return;
        }
        for f in &mut self.findings[before..] {
            f.attributes
                .insert("volume".to_string(), origin.to_string());
        }
    }
}

/// Eine Analyse-Domäne. Implementierungen müssen `Sync` sein, damit mehrere
/// Analyzer gleichzeitig laufen können.
pub trait Analyzer: Sync {
    /// Kurzname der Domäne, erscheint im Report.
    fn domain(&self) -> &str;

    /// Führt die Analyse auf dem Kontext aus.
    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome;
}
