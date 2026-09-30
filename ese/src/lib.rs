//! Nur lesender Parser für ESE-Datenbanken (Extensible Storage Engine, auch
//! JET Blue), wie sie Windows für SRUM, WebCache und andere Artefakte nutzt.
//!
//! Formatgrundlage ist die Beschreibung von libyal/libesedb ("Extensible
//! Storage Engine (ESE) Database File (EDB) format"). Neuere Details, die dort
//! fehlen oder nur angedeutet sind, etwa die reservierten Bits im Tag-Zähler
//! ab Revision 0x122, sind gegen die Referenzbibliothek dissect.esedb und
//! echte Windows-11-Datenbanken geprüft.
//!
//! Der Parser arbeitet auf einem Byte-Slice, liest nur und prüft alle Längen.
//! Beschädigte oder manipulierte Seiten führen zu Fehlern oder werden
//! übersprungen und gezählt, nie zu einer Panik.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod catalog;
mod error;
mod page;
mod record;

pub use catalog::{Column, ColumnType, Table};
pub use error::EseError;
pub use page::{Node, Page, PageFlags};
pub use record::{Record, Value};

/// Größe des Dateikopfs, der in der ersten Seite steht.
const HEADER_MIN: usize = 668;
/// Seitennummer der Wurzel des Systemkatalogs (MSysObjects).
const CATALOG_ROOT: u32 = 4;
/// Obergrenze für Seiten, die ein Baumdurchlauf besucht.
pub const MAX_TREE_PAGES: usize = 1_000_000;

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Angaben aus dem Dateikopf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Formatversion, praktisch immer 0x620.
    pub format_version: u32,
    /// Formatrevision (z. B. 300 bei Windows 11 24H2).
    pub format_revision: u32,
    /// Seitengröße in Byte.
    pub page_size: u32,
    /// Datenbankzustand (2 unsauber beendet, 3 sauber beendet laut libesedb).
    pub state: u32,
    /// Windows-Version, die zuletzt geschrieben hat (Major, Minor, Build).
    pub os_version: (u32, u32, u32),
}

/// Eine geöffnete Datenbank.
#[derive(Debug)]
pub struct Database<'a> {
    data: &'a [u8],
    header: Header,
    tables: Vec<Table>,
    /// Hinweise beim Öffnen (übersprungene Seiten, unbekannte Katalogeinträge).
    warnings: Vec<String>,
}

impl<'a> Database<'a> {
    /// Liest Dateikopf und Systemkatalog.
    pub fn open(data: &'a [u8]) -> Result<Self, EseError> {
        if data.len() < HEADER_MIN {
            return Err(EseError::TooSmall(data.len()));
        }
        if data[4..8] != [0xef, 0xcd, 0xab, 0x89] {
            return Err(EseError::BadSignature);
        }
        let header = Header {
            format_version: u32_at(data, 8).unwrap_or(0),
            format_revision: u32_at(data, 232).unwrap_or(0),
            page_size: u32_at(data, 236).unwrap_or(0),
            state: u32_at(data, 52).unwrap_or(0),
            os_version: (
                u32_at(data, 216).unwrap_or(0),
                u32_at(data, 220).unwrap_or(0),
                u32_at(data, 224).unwrap_or(0),
            ),
        };
        if ![2048, 4096, 8192, 16384, 32768].contains(&header.page_size) {
            return Err(EseError::BadPageSize(header.page_size));
        }
        let mut db = Self {
            data,
            header,
            tables: Vec::new(),
            warnings: Vec::new(),
        };
        let (tables, warnings) = catalog::read(&db)?;
        db.tables = tables;
        db.warnings = warnings;
        Ok(db)
    }

    /// Kopfangaben.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Tabellen laut Systemkatalog.
    pub fn tables(&self) -> &[Table] {
        &self.tables
    }

    /// Tabelle nach Namen (ohne Beachtung der Groß-/Kleinschreibung).
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(name))
    }

    /// Hinweise aus dem Öffnen und dem Katalog.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Kleine Seiten (bis 8 KiB) haben andere Tag- und Datensatzformate.
    pub(crate) fn small_pages(&self) -> bool {
        self.header.page_size <= 8192
    }

    /// Liest eine Seite. Seite n liegt bei (n + 1) × Seitengröße.
    pub fn page(&self, number: u32) -> Result<Page<'a>, EseError> {
        let size = self.header.page_size as usize;
        let start = (number as usize)
            .checked_add(1)
            .and_then(|n| n.checked_mul(size))
            .ok_or(EseError::PageOutOfRange(number))?;
        let buf = self
            .data
            .get(start..start + size)
            .ok_or(EseError::PageOutOfRange(number))?;
        Page::parse(number, start as u64, buf, self.small_pages())
    }

    /// Alle Blattknoten eines B+-Baums ab seiner Wurzelseite, in Baumordnung.
    /// Nicht lesbare Seiten werden übersprungen und in `skipped` gezählt.
    pub fn leaf_nodes(&self, root: u32) -> Result<TreeWalk<'a>, EseError> {
        let mut walk = TreeWalk::default();
        let mut visited = std::collections::HashSet::new();
        self.descend(root, &mut walk, &mut visited, 0)?;
        Ok(walk)
    }

    fn descend(
        &self,
        number: u32,
        walk: &mut TreeWalk<'a>,
        visited: &mut std::collections::HashSet<u32>,
        depth: usize,
    ) -> Result<(), EseError> {
        if depth > 64 || visited.len() >= MAX_TREE_PAGES || !visited.insert(number) {
            walk.skipped += 1;
            return Ok(());
        }
        let page = match self.page(number) {
            Ok(p) => p,
            Err(e) if depth > 0 => {
                walk.skipped += 1;
                walk.errors.push(format!("Seite {number}: {e}"));
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let nodes = page.nodes();
        if page.flags.contains(PageFlags::LEAF) {
            walk.nodes.extend(nodes);
        } else {
            for node in nodes {
                match u32_at(node.data, 0) {
                    Some(child) => self.descend(child, walk, visited, depth + 1)?,
                    None => walk.skipped += 1,
                }
            }
        }
        Ok(())
    }

    /// Datensätze einer Tabelle.
    pub fn records<'d>(&'d self, table: &'d Table) -> Result<Vec<Record<'a, 'd>>, EseError> {
        let walk = self.leaf_nodes(table.fdp)?;
        Ok(walk
            .nodes
            .into_iter()
            .map(|node| Record::new(self, table, node))
            .collect())
    }
}

/// Ergebnis eines Baumdurchlaufs.
#[derive(Debug, Default)]
pub struct TreeWalk<'a> {
    /// Blattknoten in Baumordnung.
    pub nodes: Vec<Node<'a>>,
    /// Übersprungene Seiten oder Verweise.
    pub skipped: usize,
    /// Fehler zu übersprungenen Seiten.
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsinn_wird_abgewiesen() {
        assert_eq!(
            Database::open(&[0; 100]).unwrap_err(),
            EseError::TooSmall(100)
        );
        assert_eq!(
            Database::open(&[0; 8192]).unwrap_err(),
            EseError::BadSignature
        );
        let mut kopf = vec![0u8; 8192];
        kopf[4..8].copy_from_slice(&[0xef, 0xcd, 0xab, 0x89]);
        kopf[236..240].copy_from_slice(&1000u32.to_le_bytes());
        assert_eq!(
            Database::open(&kopf).unwrap_err(),
            EseError::BadPageSize(1000)
        );
        // Gültiger Kopf, aber kein Katalog.
        kopf[236..240].copy_from_slice(&4096u32.to_le_bytes());
        assert!(Database::open(&kopf).is_err());
    }

    #[test]
    fn seiten_tags_ausserhalb_werden_abgewiesen() {
        let mut seite = vec![0u8; 4096];
        seite[34..36].copy_from_slice(&0x0fffu16.to_le_bytes());
        assert!(Page::parse(1, 4096, &seite, true).is_err());
        seite[34..36].copy_from_slice(&0u16.to_le_bytes());
        assert!(Page::parse(1, 4096, &seite, true)
            .unwrap()
            .nodes()
            .is_empty());
    }
}
