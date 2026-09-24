//! Base Block und Zellzugriff.

use crate::error::HiveError;
use crate::key::Key;

/// Größe des Base Blocks. Zell-Offsets zählen ab dem Ende des Base Blocks.
pub(crate) const BASE_BLOCK_SIZE: usize = 4096;

/// Kopfdaten eines Hives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseBlock {
    /// Primäre Sequenznummer.
    pub primary_seq: u32,
    /// Sekundäre Sequenznummer. Weicht sie von der primären ab, wurde der
    /// Hive nicht sauber geschrieben und die Transaktionslogs (`.LOG1`,
    /// `.LOG2`) enthalten möglicherweise neuere Daten.
    pub secondary_seq: u32,
    /// Letzter Schreibzeitpunkt als FILETIME (UTC).
    pub last_written: u64,
    /// Hauptversion, praktisch immer 1.
    pub major: u32,
    /// Nebenversion (3 bis 6).
    pub minor: u32,
    /// Zell-Offset des Wurzelschlüssels.
    pub root_cell: u32,
    /// Größe des Hive-Bin-Bereichs laut Header.
    pub hbins_size: u32,
    /// Dateiname aus dem Header (die letzten Zeichen des Pfads, unter dem
    /// der Hive geladen war).
    pub file_name: String,
    /// Prüfsumme laut Header.
    pub checksum: u32,
    /// Selbst berechnete Prüfsumme.
    pub checksum_calc: u32,
}

impl BaseBlock {
    /// `true`, wenn die Sequenznummern abweichen.
    pub fn is_dirty(&self) -> bool {
        self.primary_seq != self.secondary_seq
    }

    /// `true`, wenn die Prüfsumme stimmt.
    pub fn checksum_ok(&self) -> bool {
        self.checksum == self.checksum_calc
    }
}

/// Ein geöffneter Hive.
#[derive(Debug)]
pub struct Hive<'a> {
    data: &'a [u8],
    base: BaseBlock,
    warnings: Vec<String>,
}

impl<'a> Hive<'a> {
    /// Liest den Base Block und prüft die Signatur.
    ///
    /// Eine falsche Prüfsumme oder ein unsauber geschriebener Hive führen
    /// nicht zum Fehler, sondern zu einem Eintrag in [`Hive::warnings`].
    pub fn parse(data: &'a [u8]) -> Result<Self, HiveError> {
        if data.len() < BASE_BLOCK_SIZE {
            return Err(HiveError::TooSmall(data.len()));
        }
        if &data[..4] != b"regf" {
            return Err(HiveError::BadSignature);
        }

        let name_raw = &data[48..112];
        let base = BaseBlock {
            primary_seq: le_u32(data, 4),
            secondary_seq: le_u32(data, 8),
            last_written: le_u64(data, 12),
            major: le_u32(data, 20),
            minor: le_u32(data, 24),
            root_cell: le_u32(data, 36),
            hbins_size: le_u32(data, 40),
            file_name: decode_utf16(name_raw),
            checksum: le_u32(data, 508),
            checksum_calc: checksum(&data[..508]),
        };

        let mut warnings = Vec::new();
        if base.is_dirty() {
            warnings.push(format!(
                "Hive unsauber geschrieben (Sequenz {} != {}), Transaktionslogs nicht eingespielt",
                base.primary_seq, base.secondary_seq
            ));
        }
        if !base.checksum_ok() {
            warnings.push(format!(
                "Base-Block-Prüfsumme stimmt nicht ({:#010x} statt {:#010x})",
                base.checksum, base.checksum_calc
            ));
        }
        let expected_end = BASE_BLOCK_SIZE as u64 + u64::from(base.hbins_size);
        if expected_end > data.len() as u64 {
            warnings.push(format!(
                "Hive laut Header {expected_end} Bytes groß, vorhanden {} Bytes (gekürzt?)",
                data.len()
            ));
        }

        Ok(Self {
            data,
            base,
            warnings,
        })
    }

    /// Kopfdaten.
    pub fn base_block(&self) -> &BaseBlock {
        &self.base
    }

    /// Auffälligkeiten aus dem Base Block.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Der Wurzelschlüssel.
    pub fn root(&self) -> Result<Key<'_, 'a>, HiveError> {
        Key::read(self, self.base.root_cell)
    }

    /// Öffnet einen Schlüssel relativ zur Wurzel, z. B.
    /// `"Microsoft\\Windows\\CurrentVersion\\Run"`.
    ///
    /// Groß-/Kleinschreibung wird ignoriert. Ein leerer Pfad liefert die
    /// Wurzel. `Ok(None)`, wenn ein Pfadteil nicht existiert.
    pub fn open_key(&self, path: &str) -> Result<Option<Key<'_, 'a>>, HiveError> {
        let mut key = self.root()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match key.subkey(part)? {
                Some(k) => key = k,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// Nutzdaten der Zelle `cell` (ohne das 4-Byte-Größenfeld).
    pub(crate) fn cell(&self, cell: u32) -> Result<&'a [u8], HiveError> {
        let off = BASE_BLOCK_SIZE as u64 + u64::from(cell);
        let bad = HiveError::BadCell { offset: off };
        let start = usize::try_from(off).map_err(|_| bad.clone())?;
        let body = start.checked_add(4).ok_or(bad.clone())?;
        let size_bytes = self.data.get(start..body).ok_or(bad.clone())?;
        let size = i32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]);
        // Negative Größe = belegt, positive = frei. Referenzierte Zellen sollten
        // belegt sein; freie werden trotzdem gelesen, da das bei beschädigten
        // Hives mehr Daten rettet als ein Abbruch.
        let len = size.unsigned_abs() as usize;
        if len < 8 {
            return Err(bad);
        }
        let end = start.checked_add(len).ok_or(bad.clone())?;
        self.data.get(body..end).ok_or(bad)
    }

    /// Wie [`Hive::cell`], prüft zusätzlich die Zwei-Byte-Signatur.
    pub(crate) fn cell_sig(&self, cell: u32, sig: &'static str) -> Result<&'a [u8], HiveError> {
        let c = self.cell(cell)?;
        if &c[..2] != sig.as_bytes() {
            return Err(HiveError::UnexpectedCell {
                offset: file_offset(cell),
                expected: sig,
                found: [c[0], c[1]],
            });
        }
        Ok(c)
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }
}

/// Offset einer Zelle in der Datei (Beginn des Größenfelds).
pub(crate) fn file_offset(cell: u32) -> u64 {
    BASE_BLOCK_SIZE as u64 + u64::from(cell)
}

/// XOR über die ersten 127 Doppelwörter, mit den Sonderfällen aus der
/// Spezifikation.
fn checksum(block: &[u8]) -> u32 {
    let x = block.chunks_exact(4).fold(0u32, |acc, c| {
        acc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]])
    });
    match x {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        x => x,
    }
}

pub(crate) fn decode_utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

// Aufrufer stellen sicher, dass die Bytes vorhanden sind (Längenprüfung der
// Zelle vorab).
pub(crate) fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

pub(crate) fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub(crate) fn le_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;

    #[test]
    fn base_block() {
        let data = HiveBuilder::new().finish_empty_root();
        let h = Hive::parse(&data).unwrap();
        let b = h.base_block();
        assert_eq!(b.major, 1);
        assert_eq!(b.minor, 5);
        assert_eq!(b.file_name, "SYSTEM");
        assert!(b.checksum_ok());
        assert!(!b.is_dirty());
        assert!(h.warnings().is_empty(), "{:?}", h.warnings());
    }

    #[test]
    fn dirty_und_falsche_prüfsumme() {
        let mut data = HiveBuilder::new().finish_empty_root();
        data[8] ^= 1;
        let h = Hive::parse(&data).unwrap();
        assert!(h.base_block().is_dirty());
        assert!(!h.base_block().checksum_ok());
        assert_eq!(h.warnings().len(), 2);
    }

    #[test]
    fn falsche_signatur_und_zu_klein() {
        let mut data = HiveBuilder::new().finish_empty_root();
        assert!(matches!(
            Hive::parse(&data[..100]),
            Err(HiveError::TooSmall(100))
        ));
        data[0] = b'x';
        assert!(matches!(Hive::parse(&data), Err(HiveError::BadSignature)));
    }

    #[test]
    fn gekürzter_hive() {
        let data = HiveBuilder::new().finish_empty_root();
        let h = Hive::parse(&data[..BASE_BLOCK_SIZE]).unwrap();
        assert!(h.warnings().iter().any(|w| w.contains("gekürzt")));
        assert!(matches!(h.root(), Err(HiveError::BadCell { .. })));
    }

    #[test]
    fn zelle_außerhalb() {
        let data = HiveBuilder::new().finish_empty_root();
        let h = Hive::parse(&data).unwrap();
        assert!(h.cell(u32::MAX).is_err());
        assert!(h.cell(u32::MAX - 2).is_err());
    }

    #[test]
    fn prüfsumme_sonderfälle() {
        assert_eq!(checksum(&[0u8; 508]), 1);
        let mut b = [0u8; 508];
        b[..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(checksum(&b), 0xFFFF_FFFE);
    }
}
