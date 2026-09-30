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
mod catalog;
mod context;
mod dpapi;
mod eventlog;
mod filepersist;
mod finding;
mod fsindex;
mod jumplist;
mod keyword;
mod knownfolder;
mod lnk;
mod lsa;
mod mfttimeline;
mod pathrating;
mod powershell;
mod prefetch;
mod programexec;
mod recyclebin;
mod reg;
mod runner;
mod shellbags;
mod shellitem;
mod timeline;
mod tor;
mod usb;
mod usn;
mod vss;
mod windows;
mod zone;

#[cfg(test)]
#[path = "../tests/common/builder.rs"]
mod builder;

pub use browser::BrowserAnalyzer;
pub use catalog::{
    write_catalog, write_catalog_with, CatalogOptions, CatalogProgress, CatalogSummary,
    CATALOG_SOURCE,
};
pub use context::{AnalysisContext, DpapiInput, NtfsTarget};
pub use dpapi::DpapiAnalyzer;
pub use eventlog::EventLogAnalyzer;
pub use filepersist::FilePersistenceAnalyzer;
pub use finding::{assign_ids, Finding};
pub use fsindex::{FileEntry, FsIndex};
pub use jumplist::JumpListAnalyzer;
pub use keyword::KeywordAnalyzer;
pub use lnk::LnkAnalyzer;
pub use lsa::LsaAnalyzer;
pub use mfttimeline::{write_mft_timeline, MftTimelineSummary, MFT_TIMELINE_SOURCE};
pub use powershell::{parse_powershell_history, PowerShellHistoryAnalyzer};
pub use prefetch::PrefetchAnalyzer;
pub use programexec::ProgramExecutionAnalyzer;
pub use recyclebin::RecycleBinAnalyzer;
pub use reg::{BamAnalyzer, PersistenceAnalyzer, UsbAnalyzer, UserActivityAnalyzer};
pub use runner::{run_all, AnalysisResult, AnalyzerStatus};
pub use shellbags::ShellBagsAnalyzer;
pub use timeline::{build as build_timeline, TimelineEntry};
pub use tor::TorAnalyzer;
pub use usn::{write_usn_journal, UsnJournalSummary, USN_JOURNAL_SOURCE};
pub use vss::VssAnalyzer;
pub use windows::{extract_snapshots, HiveStatus, Hives, LogStatus, TimeZone, WindowsInstall};
pub use zone::ZoneIdentifierAnalyzer;

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

    /// Name des Analyzers im Report. Standard ist der Typname ohne Modulpfad.
    fn name(&self) -> &'static str {
        let full = std::any::type_name::<Self>();
        let base = full.split('<').next().unwrap_or(full);
        base.rsplit("::").next().unwrap_or(base)
    }

    /// Führt die Analyse auf dem Kontext aus.
    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome;
}

/// Einstiegspunkte für die Fuzz-Targets. Nicht Teil der stabilen API.
#[doc(hidden)]
pub mod fuzzing {
    /// Prüft USB-Properties unter dem Wurzelschlüssel eines synthetischen Hives.
    pub fn usb_properties(data: &[u8]) {
        if let Ok(hive) = stratum_registry::Hive::parse(data) {
            if let Ok(key) = hive.root() {
                let mut finding = crate::Finding::new("usb", "", "SYSTEM");
                crate::usb::add_times(&key, &mut finding, &mut Vec::new());
            }
        }
    }

    /// Wertet Aufgaben-XML und den Text zusätzlich als Dienstbefehl aus.
    pub fn persistence_text(text: &str) {
        let _ = crate::filepersist::task_actions(text);
        let _ = crate::pathrating::rate_command(text);
    }

    /// Prüft den Shell-Item-Parser (ShellBags, LNK-IDList) mit beliebigen Bytes.
    pub fn shell_items(data: &[u8]) {
        let _ = crate::shellitem::parse_list(data);
        let _ = crate::shellitem::parse_item(data);
        let _ = crate::lnk::parse_lnk(data);
    }

    /// Prüft die Lagebestimmung von EVTX-Datensätzen mit beliebigen Bytes.
    pub fn evtx_records(data: &[u8]) {
        let _ = crate::eventlog::record_index(data);
    }

    /// Prüft den USN-Scanner mit beliebigen Bytes.
    pub fn usn(data: &[u8]) {
        crate::usn::fuzz(data);
    }

    /// Prüft den `Zone.Identifier`-Parser mit beliebigen Bytes.
    pub fn zone_identifier(data: &[u8]) {
        crate::zone::fuzz(data);
    }
}
