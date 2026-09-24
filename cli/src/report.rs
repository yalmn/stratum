//! Datenstruktur des JSON-Reports.
//!
//! Der Report ist das Bindeglied zu XSOAR: eine stabile, maschinenlesbare
//! Zusammenfassung aller Funde mit ihrer Herkunft (Offset, Quelle).

use serde::Serialize;

use stratum_core::{ImageHashes, PartitionTable};
use stratum_creds::Account;
use stratum_search::Finding;

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
    /// Ergebnis der Keyword-Suche, falls eine Begriffstabelle geladen wurde.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<SearchReport>,
    /// Übergreifende Hinweise.
    pub warnings: Vec<String>,
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

/// Zeitzone laut Registry.
#[derive(Debug, Serialize)]
pub struct TimeZone {
    /// Name des Zeitzonen-Schlüssels, z. B. "W. Europe Standard Time".
    pub key_name: String,
    /// Aktiver Zeitversatz zu UTC in Minuten (aus ActiveTimeBias).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_bias_minutes: Option<i32>,
}

/// Ergebnis der Keyword-Suche.
#[derive(Debug, Serialize)]
pub struct SearchReport {
    /// Name der verwendeten Begriffstabelle.
    pub table_name: String,
    /// Version der Begriffstabelle.
    pub table_version: u32,
    /// Treffer.
    pub findings: Vec<Finding>,
    /// Hinweise der Suche.
    pub warnings: Vec<String>,
}
