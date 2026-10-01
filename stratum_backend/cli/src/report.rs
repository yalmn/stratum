//! Datenstruktur des JSON-Reports.
//!
//! Der Report ist das Bindeglied zu XSOAR: eine stabile, maschinenlesbare
//! Zusammenfassung aller Funde mit ihrer Herkunft (Offset, Quelle).

use serde::Serialize;

use stratum_analysis::{
    AnalyzerStatus, CatalogSummary, Finding, HiveStatus, MftTimelineSummary, TimeZone,
    TimelineEntry, UsnJournalSummary,
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
    /// Pfad, unter dem das Image geöffnet wurde (bei E01 die erste
    /// Segmentdatei).
    pub path: String,
    /// `raw` oder `e01`.
    pub format: &'static str,
    /// Größe in Bytes (bei E01 die Mediengröße).
    pub size: u64,
    /// Integritäts-Hashes, falls berechnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<ImageHashes>,
    /// Angaben aus einem E01-Image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ewf: Option<EwfInfo>,
}

/// Angaben aus einem E01-Image (Akquise).
#[derive(Debug, Serialize, Default)]
pub struct EwfInfo {
    /// Segmentdateien in Reihenfolge.
    pub segmente: Vec<String>,
    /// Chunkgröße in Byte.
    pub chunk_groesse: u32,
    /// Byte je Sektor.
    pub sektor_groesse: u32,
    /// Kennung des Segmentsatzes, falls gesetzt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satz_id: Option<String>,
    /// Sektion, aus der die Akquisedaten stammen (`header2` oder `header`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub akquise_quelle: Option<&'static str>,
    /// Akquisedaten (Fallnummer, Bearbeiter, Notizen ...), Schlüssel lesbar
    /// benannt, unbekannte Kennungen unverändert.
    pub akquise: std::collections::BTreeMap<String, String>,
    /// Akquisezeit in UTC, wenn als POSIX-Zeit gespeichert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub akquisezeit_utc: Option<String>,
    /// Bei der Akquise gespeicherter MD5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gespeichert_md5: Option<String>,
    /// Bei der Akquise gespeicherter SHA-1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gespeichert_sha1: Option<String>,
    /// MD5 über die gelesenen Mediendaten stimmt mit dem gespeicherten überein.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5_stimmt: Option<bool>,
    /// SHA-1 über die gelesenen Mediendaten stimmt mit dem gespeicherten überein.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1_stimmt: Option<bool>,
    /// Hinweise beim Öffnen.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnungen: Vec<String>,
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
    /// Zustand der Hives und ihrer Transaktionslogs.
    pub hives: Vec<HiveStatus>,
    /// Hinweise zu dieser Installation.
    pub warnings: Vec<String>,
}
