//! Werte (vk-Zellen) und ihre Daten.

use std::borrow::Cow;

use crate::error::HiveError;
use crate::hive::{decode_utf16, file_offset, le_u16, le_u32, Hive};

/// Name ist ASCII bzw. Latin-1 statt UTF-16LE.
const VALUE_COMP_NAME: u16 = 0x0001;
/// Gesetztes Bit in der Datenlänge: Daten stehen direkt im Offset-Feld.
const DATA_INLINE: u32 = 0x8000_0000;
/// Ab dieser Länge liegen Daten in Hives ab Version 1.4 als Big Data (`db`).
const BIG_DATA_THRESHOLD: usize = 16344;
/// Feste Länge des vk-Kopfes vor dem Namen.
const VK_HEADER: usize = 20;

/// Datentyp eines Werts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    /// REG_NONE
    None,
    /// REG_SZ
    Sz,
    /// REG_EXPAND_SZ
    ExpandSz,
    /// REG_BINARY
    Binary,
    /// REG_DWORD (Little Endian)
    Dword,
    /// REG_DWORD_BIG_ENDIAN
    DwordBigEndian,
    /// REG_LINK
    Link,
    /// REG_MULTI_SZ
    MultiSz,
    /// REG_QWORD
    Qword,
    /// Anderer Typ, z. B. Ressourcenlisten oder frei vergebene Werte.
    Other(u32),
}

impl From<u32> for ValueType {
    fn from(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            11 => Self::Qword,
            t => Self::Other(t),
        }
    }
}

/// Ein Registry-Wert.
#[derive(Debug, Clone)]
pub struct Value<'a> {
    name: String,
    typ: ValueType,
    data: Cow<'a, [u8]>,
    cell: u32,
}

impl<'a> Value<'a> {
    pub(crate) fn read(hive: &Hive<'a>, cell: u32) -> Result<Self, HiveError> {
        let vk = hive.cell_sig(cell, "vk")?;
        let bad = HiveError::BadCell {
            offset: file_offset(cell),
        };
        if vk.len() < VK_HEADER {
            return Err(bad);
        }
        let name_len = le_u16(vk, 2) as usize;
        let raw_name = vk.get(VK_HEADER..VK_HEADER + name_len).ok_or(bad)?;
        let name = if le_u16(vk, 16) & VALUE_COMP_NAME != 0 {
            raw_name.iter().map(|&b| b as char).collect()
        } else {
            decode_utf16(raw_name)
        };

        let raw_len = le_u32(vk, 4);
        let data_cell = le_u32(vk, 8);
        let typ = ValueType::from(le_u32(vk, 12));
        let data = read_data(hive, cell, vk, raw_len, data_cell)?;

        Ok(Self {
            name,
            typ,
            data,
            cell,
        })
    }

    /// Name des Werts, leer beim Standardwert.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Datentyp.
    pub fn value_type(&self) -> ValueType {
        self.typ
    }

    /// Rohdaten.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Offset der vk-Zelle in der Hive-Datei.
    pub fn file_offset(&self) -> u64 {
        file_offset(self.cell)
    }

    /// Daten als Zeichenkette (UTF-16LE bis zum ersten Nullzeichen), bei
    /// REG_SZ, REG_EXPAND_SZ und REG_LINK.
    pub fn as_string(&self) -> Option<String> {
        match self.typ {
            ValueType::Sz | ValueType::ExpandSz | ValueType::Link => Some(decode_utf16(&self.data)),
            _ => None,
        }
    }

    /// Einzelne Zeichenketten eines REG_MULTI_SZ.
    pub fn as_multi_string(&self) -> Option<Vec<String>> {
        if self.typ != ValueType::MultiSz {
            return None;
        }
        let units: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(
            units
                .split(|&u| u == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
        )
    }

    /// Zahlwert bei REG_DWORD und REG_DWORD_BIG_ENDIAN.
    pub fn as_u32(&self) -> Option<u32> {
        let b: [u8; 4] = self.data.get(..4)?.try_into().ok()?;
        match self.typ {
            ValueType::Dword => Some(u32::from_le_bytes(b)),
            ValueType::DwordBigEndian => Some(u32::from_be_bytes(b)),
            _ => None,
        }
    }

    /// Zahlwert bei REG_QWORD.
    pub fn as_u64(&self) -> Option<u64> {
        if self.typ != ValueType::Qword {
            return None;
        }
        let b: [u8; 8] = self.data.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    }
}

fn read_data<'a>(
    hive: &Hive<'a>,
    cell: u32,
    vk: &'a [u8],
    raw_len: u32,
    data_cell: u32,
) -> Result<Cow<'a, [u8]>, HiveError> {
    let bad_len = HiveError::BadDataLength {
        offset: file_offset(cell),
        len: raw_len,
    };

    if raw_len & DATA_INLINE != 0 {
        let len = (raw_len & !DATA_INLINE) as usize;
        return vk
            .get(8..8 + len)
            .filter(|_| len <= 4)
            .map(Cow::Borrowed)
            .ok_or(bad_len);
    }

    let len = raw_len as usize;
    if len == 0 {
        return Ok(Cow::Borrowed(&[]));
    }
    // Mehr Daten als der ganze Hive groß ist, kann es nicht geben. Das
    // begrenzt auch die Allokation bei Big Data.
    if len > hive.len() {
        return Err(bad_len);
    }

    let c = hive.cell(data_cell)?;
    if len > BIG_DATA_THRESHOLD && hive.base_block().minor >= 4 && c.starts_with(b"db") {
        return read_big_data(hive, data_cell, c, len).map(Cow::Owned);
    }
    c.get(..len).map(Cow::Borrowed).ok_or(bad_len)
}

/// Setzt einen Big-Data-Wert aus seinen Segmenten zusammen. Jedes Segment
/// trägt höchstens [`BIG_DATA_THRESHOLD`] Nutzbytes, der Rest der Zelle ist
/// Auffüllung.
fn read_big_data(
    hive: &Hive<'_>,
    db_cell: u32,
    db: &[u8],
    len: usize,
) -> Result<Vec<u8>, HiveError> {
    let bad = HiveError::BadCell {
        offset: file_offset(db_cell),
    };
    if db.len() < 8 {
        return Err(bad);
    }
    let count = u32::from(le_u16(db, 2));
    let list_cell = le_u32(db, 4);
    let list = hive.cell(list_cell)?;
    let entries = list.get(..count as usize * 4).ok_or(HiveError::BadCount {
        offset: file_offset(list_cell),
        count,
    })?;

    let mut out = Vec::with_capacity(len);
    for e in entries.chunks_exact(4) {
        let seg = hive.cell(le_u32(e, 0))?;
        let take = (len - out.len()).min(BIG_DATA_THRESHOLD).min(seg.len());
        out.extend_from_slice(&seg[..take]);
        if out.len() == len {
            return Ok(out);
        }
    }
    Err(HiveError::BadDataLength {
        offset: file_offset(db_cell),
        len: len as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn hive_with(values: impl FnOnce(&mut HiveBuilder) -> Vec<u32>) -> Vec<u8> {
        let mut b = HiveBuilder::new();
        let v = values(&mut b);
        let root = b.key("ROOT", None, &v);
        b.finish(root)
    }

    #[test]
    fn typen() {
        let data = hive_with(|b| {
            vec![
                b.vk("Dword", 4, &7u32.to_le_bytes()),
                b.vk("BE", 5, &7u32.to_be_bytes()),
                b.vk("Qword", 11, &0x1122_3344_5566_7788u64.to_le_bytes()),
                b.vk("Sz", 1, &utf16z("C:\\Windows")),
                b.vk(
                    "Multi",
                    7,
                    &[utf16z("a"), utf16z("bc"), vec![0, 0]].concat(),
                ),
                b.vk("", 3, &[1, 2, 3]),
            ]
        });
        let h = Hive::parse(&data).unwrap();
        let root = h.root().unwrap();
        assert_eq!(root.values().unwrap().len(), 6);

        assert_eq!(root.value("dword").unwrap().unwrap().as_u32(), Some(7));
        assert_eq!(root.value("BE").unwrap().unwrap().as_u32(), Some(7));
        assert_eq!(
            root.value("Qword").unwrap().unwrap().as_u64(),
            Some(0x1122_3344_5566_7788)
        );
        let sz = root.value("SZ").unwrap().unwrap();
        assert_eq!(sz.as_string().as_deref(), Some("C:\\Windows"));
        assert_eq!(sz.as_u32(), None);
        assert_eq!(
            root.value("Multi").unwrap().unwrap().as_multi_string(),
            Some(vec!["a".to_string(), "bc".to_string()])
        );
        let def = root.value("").unwrap().unwrap();
        assert_eq!(def.data(), &[1, 2, 3]);
        assert_eq!(def.value_type(), ValueType::Binary);
        assert!(root.value("fehlt").unwrap().is_none());
    }

    #[test]
    fn inline_daten() {
        // Werte bis 4 Bytes legt der Builder inline ab.
        let data = hive_with(|b| vec![b.vk("x", 3, &[9, 8])]);
        let h = Hive::parse(&data).unwrap();
        let v = h.root().unwrap().value("x").unwrap().unwrap();
        assert_eq!(v.data(), &[9, 8]);
    }

    #[test]
    fn inline_zu_lang() {
        let mut b = HiveBuilder::new();
        let vk = b.vk("x", 3, &[1]);
        b.patch_u32(vk, 8, DATA_INLINE | 5);
        let root = b.key("ROOT", None, &[vk]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(matches!(
            h.root().unwrap().values(),
            Err(HiveError::BadDataLength { .. })
        ));
    }

    #[test]
    fn big_data() {
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 253) as u8).collect();
        let data = hive_with(|b| vec![b.vk_big("gross", 3, &payload)]);
        let h = Hive::parse(&data).unwrap();
        let v = h.root().unwrap().value("gross").unwrap().unwrap();
        assert_eq!(v.data(), payload.as_slice());
    }

    #[test]
    fn big_data_zu_wenig_segmente() {
        let payload = vec![1u8; 40_000];
        let mut b = HiveBuilder::new();
        let vk = b.vk_big("gross", 3, &payload);
        // Datenlänge größer angeben, als die Segmente hergeben
        b.patch_u32(vk, 8, 60_000);
        let root = b.key("ROOT", None, &[vk]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(matches!(
            h.root().unwrap().values(),
            Err(HiveError::BadDataLength { .. })
        ));
    }

    #[test]
    fn datenlänge_größer_als_hive() {
        let mut b = HiveBuilder::new();
        let vk = b.vk("x", 3, &[1, 2, 3, 4, 5, 6]);
        b.patch_u32(vk, 8, 0x7FFF_FFFF);
        let root = b.key("ROOT", None, &[vk]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(matches!(
            h.root().unwrap().values(),
            Err(HiveError::BadDataLength { .. })
        ));
    }

    #[test]
    fn werteliste_zu_kurz() {
        let mut b = HiveBuilder::new();
        let vk = b.vk("x", 4, &1u32.to_le_bytes());
        let root = b.key("ROOT", None, &[vk]);
        // Anzahl der Werte im nk auf einen absurden Wert setzen
        b.patch_u32(root, 4 + 36, 1_000_000);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(matches!(
            h.root().unwrap().values(),
            Err(HiveError::BadCount {
                count: 1_000_000,
                ..
            })
        ));
    }
}
