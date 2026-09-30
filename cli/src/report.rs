//! Datenstruktur des JSON-Reports.
//!
//! Der Report ist das Bindeglied zu XSOAR: eine stabile, maschinenlesbare
//! Zusammenfassung aller Funde mit ihrer Herkunft (Offset, Quelle).

use serde::Serialize;

use stratum_analysis::{
    AnalyzerStatus, CatalogSummary, Finding, MftTimelineSummary, TimeZone, TimelineEntry,
    UsnJournalSummary,
};
use stratum_core::{ImageHashes, PartitionTable};
use stratum_creds::Account;

/// Der komplette Report eines Laufs.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Angaben zum Werkzeug.
    pub tool: Tool,
    /// Zeitpunkt der Erstellung als Unix-Zeit (Sekunden, UTC). Bewusst als
    /// Zahl, damit die nachgelagerte Schicht die Darstellung wählt.
    pub generated_unix: i64,
    /// Angaben zum untersuchten Image.
    pub image: ImageInfo,
    /// Erkannte Partitionen.
    pub partitions: PartitionTable,
    /// Ergebnisse je Windows-Installation.
    pub windows: Vec<WindowsReport>,
    /// Laufstatus je Analyzer: Funde, Warnungen, Laufzeit.
    pub analyzers: Vec<AnalyzerStatus>,
    /// Funde aller Domänen-Analyzer (Keyword, Tor, ...), mit Domäne, Name und
    /// Pfad.
    pub findings: Vec<Finding>,
    /// Zeitstrahl aller zeitbehafteten Funde (nach Zeit sortiert).
    pub timeline: Vec<TimelineEntry>,
    /// Angaben zur verwendeten Begriffstabelle, falls die Keyword-Suche lief.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<KeywordInfo>,
    /// Verweis auf den Dateikatalog, falls einer geschrieben wurde.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogInfo>,
    /// Verweis auf die vollständige MFT-Zeitachse, falls geschrieben.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mft_timeline: Option<MftTimelineInfo>,
    /// Verweis auf das USN-Änderungsjournal, falls geschrieben.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usn_journal: Option<UsnJournalInfo>,
    /// Übergreifende Hinweise.
    pub warnings: Vec<String>,
}

/// Verweis auf die MFT-Zeitachse mit Hashes und Zählern.
#[derive(Debug, Serialize)]
pub struct MftTimelineInfo {
    /// Pfad der JSON-Lines-Datei.
    pub pfad: String,
    /// Beschreibung der ausgewerteten Quelle.
    pub quelle: &'static str,
    /// Dateiformat und Sortierung.
    pub format: &'static str,
    /// SHA-256 und BLAKE3 über die geschriebene Datei.
    pub hashes: ImageHashes,
    /// Zähler des MFT-Durchlaufs.
    #[serde(flatten)]
    pub summary: MftTimelineSummary,
}

/// Verweis auf die USN-Zeitachse mit Hashes und Zählern.
#[derive(Debug, Serialize)]
pub struct UsnJournalInfo {
    /// Pfad der JSON-Lines-Datei.
    pub pfad: String,
    /// Beschreibung der ausgewerteten Quelle.
    pub quelle: &'static str,
    /// Dateiformat und Reihenfolge.
    pub format: &'static str,
    /// SHA-256 und BLAKE3 über die geschriebene Datei.
    pub hashes: ImageHashes,
    /// Zähler des Journal-Durchlaufs.
    #[serde(flatten)]
    pub summary: UsnJournalSummary,
}

/// Verweis auf den Dateikatalog mit Hashes der geschriebenen Datei.
#[derive(Debug, Serialize)]
pub struct CatalogInfo {
    /// Pfad der Katalogdatei.
    pub pfad: String,
    /// Woraus der Katalog besteht und was fehlt.
    pub quelle: &'static str,
    /// Dateiformat.
    pub format: &'static str,
    /// SHA-256 und BLAKE3 über die geschriebene Datei.
    pub hashes: ImageHashes,
    /// Zähler.
    #[serde(flatten)]
    pub summary: CatalogSummary,
}

/// Angaben zur verwendeten Begriffstabelle.
#[derive(Debug, Serialize)]
pub struct KeywordInfo {
    /// Name der Begriffstabelle(n).
    pub table_name: String,
    /// Höchste Version der verwendeten Tabellen.
    pub table_version: u32,
}

/// Angaben zum Werkzeug.
#[derive(Debug, Serialize)]
pub struct Tool {
    /// Name.
    pub name: &'static str,
    /// Version aus dem Cargo-Manifest.
    pub version: &'static str,
    /// Git-Commit, aus dem das Binary gebaut wurde.
    pub revision: &'static str,
    /// Ob beim Bauen nicht committete Änderungen an versionierten Dateien
    /// vorlagen (`ja`, `nein`, `unbekannt`). Bei `ja` belegt die Revision
    /// allein den Stand nicht.
    pub revision_geaendert: &'static str,
}

impl Default for Tool {
    fn default() -> Self {
        Self {
            name: "stratum",
            version: env!("CARGO_PKG_VERSION"),
            revision: env!("STRATUM_REVISION"),
            revision_geaendert: env!("STRATUM_REVISION_GEAENDERT"),
        }
    }
}

/// Angaben zum Image.
#[derive(Debug, Serialize)]
pub struct ImageInfo {
    /// Pfad, unter dem das Image geöffnet wurde.
    pub path: String,
    /// Größe in Bytes.
    pub size: u64,
    /// Integritäts-Hashes, falls berechnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<ImageHashes>,
}

/// Ergebnisse einer Windows-Installation (einer NTFS-Partition).
#[derive(Debug, Serialize, Default)]
pub struct WindowsReport {
    /// Herkunft des Volumes ("live" oder eine Schattenkopie).
    pub origin: String,
    /// Index der Partition in der Tabelle.
    pub partition_index: u32,
    /// Byte-Offset der Partition im Image.
    pub partition_offset: u64,
    /// Rechnername aus der Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    /// Zeitzone aus der Registry (nicht die Systemzeit des Analyserechners).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<TimeZone>,
    /// Lokale Konten mit NT-Hash.
    pub accounts: Vec<Account>,
    /// Hinweise zu dieser Installation.
    pub warnings: Vec<String>,
}
