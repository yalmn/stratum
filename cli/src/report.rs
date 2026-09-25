//! Datenstruktur des JSON-Reports.
//!
//! Der Report ist das Bindeglied zu XSOAR: eine stabile, maschinenlesbare
//! Zusammenfassung aller Funde mit ihrer Herkunft (Offset, Quelle).

use serde::Serialize;

use stratum_analysis::{Finding, TimeZone};
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
    /// Funde aller Domänen-Analyzer (Keyword, Tor, ...), mit Domäne, Name und
    /// Pfad.
    pub findings: Vec<Finding>,
    /// Angaben zur verwendeten Begriffstabelle, falls die Keyword-Suche lief.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<KeywordInfo>,
    /// Übergreifende Hinweise.
    pub warnings: Vec<String>,
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
}

impl Default for Tool {
    fn default() -> Self {
        Self {
            name: "stratum",
            version: env!("CARGO_PKG_VERSION"),
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
