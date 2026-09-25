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
mod finding;
mod fsindex;
mod keyword;
mod prefetch;
mod reg;
mod runner;
mod tor;
mod windows;

#[cfg(test)]
#[path = "../tests/common/builder.rs"]
mod builder;

pub use browser::BrowserAnalyzer;
pub use context::{AnalysisContext, NtfsTarget};
pub use finding::Finding;
pub use fsindex::{FileEntry, FsIndex};
pub use keyword::KeywordAnalyzer;
pub use prefetch::PrefetchAnalyzer;
pub use reg::{PersistenceAnalyzer, UsbAnalyzer, UserActivityAnalyzer};
pub use runner::{run_all, AnalysisResult};
pub use tor::TorAnalyzer;
pub use windows::{Hives, TimeZone, WindowsInstall};

/// Ergebnis eines einzelnen Analyzers.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Gefundene Spuren.
    pub findings: Vec<Finding>,
    /// Auffälligkeiten während der Analyse.
    pub warnings: Vec<String>,
}

/// Eine Analyse-Domäne. Implementierungen müssen `Sync` sein, damit mehrere
/// Analyzer gleichzeitig laufen können.
pub trait Analyzer: Sync {
    /// Kurzname der Domäne, erscheint im Report.
    fn domain(&self) -> &str;

    /// Führt die Analyse auf dem Kontext aus.
    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome;
}
