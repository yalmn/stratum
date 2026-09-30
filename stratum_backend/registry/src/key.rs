//! Schlüssel (nk-Zellen) und Unterschlüssel-Listen.

use crate::error::HiveError;
use crate::hive::{decode_utf16, file_offset, le_u16, le_u32, le_u64, Hive};
use crate::value::Value;

/// Kennzeichen für "keine Zelle".
const NO_CELL: u32 = 0xFFFF_FFFF;
/// Name ist ASCII bzw. Latin-1 statt UTF-16LE.
const KEY_COMP_NAME: u16 = 0x0020;
/// Feste Länge des nk-Kopfes vor dem Namen.
const NK_HEADER: usize = 76;

/// Ein Registry-Schlüssel.
#[derive(Debug, Clone)]
pub struct Key<'h, 'a> {
    hive: &'h Hive<'a>,
    cell: u32,
    nk: &'a [u8],
    name: String,
}

impl<'h, 'a> Key<'h, 'a> {
    pub(crate) fn read(hive: &'h Hive<'a>, cell: u32) -> Result<Self, HiveError> {
        let nk = hive.cell_sig(cell, "nk")?;
        let name = nk_name(nk).ok_or(HiveError::BadCell {
            offset: file_offset(cell),
        })?;
        Ok(Self {
            hive,
            cell,
            nk,
            name,
        })
    }

    /// Name des Schlüssels.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Letzter Schreibzeitpunkt als FILETIME (UTC).
    pub fn last_written(&self) -> u64 {
        le_u64(self.nk, 4)
    }

    /// Offset der nk-Zelle in der Hive-Datei.
    pub fn file_offset(&self) -> u64 {
        file_offset(self.cell)
    }

    /// Anzahl der Unterschlüssel laut Header.
    pub fn subkey_count(&self) -> u32 {
        le_u32(self.nk, 20)
    }

    /// Der Class-Wert des Schlüssels als Text, falls vorhanden.
    ///
    /// Der Class-Name ist ein selten genutztes Feld. Windows legt darin unter
    /// anderem die Teile des Syskey ab (Schlüssel `JD`, `Skew1`, `GBG`, `Data`
    /// unter `Control\Lsa`), jeweils als UTF-16LE-Hex-Text. Die Daten liegen in
    /// einer eigenen Zelle, auf die der nk-Datensatz verweist.
    pub fn class(&self) -> Result<Option<String>, HiveError> {
        let cell = le_u32(self.nk, 48);
        let len = le_u16(self.nk, 74) as usize;
        if cell == NO_CELL || len == 0 {
            return Ok(None);
        }
        let data = self.hive.cell(cell)?;
        let raw = data.get(..len).ok_or(HiveError::BadCell {
            offset: file_offset(cell),
        })?;
        Ok(Some(decode_utf16(raw)))
    }

    /// Anzahl der Werte laut Header.
    pub fn value_count(&self) -> u32 {
        le_u32(self.nk, 36)
    }

    /// Alle Unterschlüssel in der Reihenfolge der Liste.
    pub fn subkeys(&self) -> Result<Vec<Key<'h, 'a>>, HiveError> {
        self.subkey_cells()?
            .into_iter()
            .map(|c| Key::read(self.hive, c))
            .collect()
    }

    /// Sucht einen direkten Unterschlüssel per Name, ohne Beachtung der
    /// Groß-/Kleinschreibung.
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h, 'a>>, HiveError> {
        for c in self.subkey_cells()? {
            let nk = self.hive.cell_sig(c, "nk")?;
            let Some(n) = nk_name(nk) else { continue };
            if eq_ignore_case(&n, name) {
                return Ok(Some(Key {
                    hive: self.hive,
                    cell: c,
                    nk,
                    name: n,
                }));
            }
        }
        Ok(None)
    }

    /// Alle Werte des Schlüssels.
    pub fn values(&self) -> Result<Vec<Value<'a>>, HiveError> {
        self.value_cells()?
            .map(|c| Value::read(self.hive, c))
            .collect()
    }

    /// Sucht einen Wert per Name, ohne Beachtung der Groß-/Kleinschreibung.
    /// Der Standardwert eines Schlüssels hat den leeren Namen `""`.
    pub fn value(&self, name: &str) -> Result<Option<Value<'a>>, HiveError> {
        for c in self.value_cells()? {
            let v = Value::read(self.hive, c)?;
            if eq_ignore_case(v.name(), name) {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    fn subkey_cells(&self) -> Result<Vec<u32>, HiveError> {
        let list = le_u32(self.nk, 28);
        if self.subkey_count() == 0 || list == NO_CELL {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        collect_list(self.hive, list, 0, &mut out)?;
        Ok(out)
    }

    fn value_cells(&self) -> Result<impl Iterator<Item = u32> + 'a, HiveError> {
        let count = self.value_count();
        let list = le_u32(self.nk, 40);
        let cells: &'a [u8] = if count == 0 || list == NO_CELL {
            &[]
        } else {
            let c = self.hive.cell(list)?;
            let need = (count as usize).checked_mul(4);
            match need {
                Some(n) if n <= c.len() => &c[..n],
                _ => {
                    return Err(HiveError::BadCount {
                        offset: file_offset(list),
                        count,
                    })
                }
            }
        };
        Ok(cells.chunks_exact(4).map(|b| le_u32(b, 0)))
    }
}

/// Sammelt die nk-Offsets aus einer Unterschlüssel-Liste. `ri`-Listen dürfen
/// laut Spezifikation nur auf `lf`, `lh` oder `li` zeigen, also höchstens eine
/// Ebene tief. Das begrenzt auch die Rekursion bei manipulierten Hives.
fn collect_list(
    hive: &Hive<'_>,
    cell: u32,
    depth: u8,
    out: &mut Vec<u32>,
) -> Result<(), HiveError> {
    let c = hive.cell(cell)?;
    let count = u32::from(le_u16(c, 2));
    let (stride, recurse) = match &c[..2] {
        b"lf" | b"lh" => (8, false),
        b"li" => (4, false),
        b"ri" if depth == 0 => (4, true),
        b"ri" => {
            return Err(HiveError::ListTooDeep {
                offset: file_offset(cell),
            })
        }
        _ => {
            return Err(HiveError::UnexpectedCell {
                offset: file_offset(cell),
                expected: "lf/lh/li/ri",
                found: [c[0], c[1]],
            })
        }
    };
    let end = 4 + count as usize * stride;
    let Some(entries) = c.get(4..end) else {
        return Err(HiveError::BadCount {
            offset: file_offset(cell),
            count,
        });
    };
    for e in entries.chunks_exact(stride) {
        let off = le_u32(e, 0);
        if recurse {
            collect_list(hive, off, depth + 1, out)?;
        } else {
            out.push(off);
        }
    }
    Ok(())
}

fn nk_name(nk: &[u8]) -> Option<String> {
    if nk.len() < NK_HEADER {
        return None;
    }
    let len = le_u16(nk, 72) as usize;
    let raw = nk.get(NK_HEADER..NK_HEADER + len)?;
    if le_u16(nk, 2) & KEY_COMP_NAME != 0 {
        Some(raw.iter().map(|&b| b as char).collect())
    } else {
        Some(decode_utf16(raw))
    }
}

/// Namensvergleich ohne Beachtung der Groß-/Kleinschreibung.
///
/// Windows vergleicht mit einer eigenen Großbuchstaben-Tabelle. Für ASCII ist
/// das identisch, für andere Zeichen ist die Unicode-Großschreibung von Rust
/// eine Näherung.
pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;

    #[test]
    fn namen_vergleich() {
        assert!(eq_ignore_case("CurrentControlSet", "currentcontrolset"));
        assert!(eq_ignore_case("Größe", "GRÖSSE"));
        assert!(!eq_ignore_case("Run", "RunOnce"));
    }

    #[test]
    fn listenarten() {
        let mut b = HiveBuilder::new();
        let a = b.key("A", None, &[]);
        let c = b.key("B", None, &[]);
        let d = b.key("C", None, &[]);
        let lf = b.lf(&[a]);
        let li = b.li(&[c, d]);
        let ri = b.ri(&[lf, li]);
        let root = b.key_with_list("ROOT", ri, 3, &[]);
        let data = b.finish(root);

        let h = Hive::parse(&data).unwrap();
        let names: Vec<_> = h
            .root()
            .unwrap()
            .subkeys()
            .unwrap()
            .iter()
            .map(|k| k.name().to_string())
            .collect();
        assert_eq!(names, ["A", "B", "C"]);
    }

    #[test]
    fn ri_in_ri_wird_abgelehnt() {
        let mut b = HiveBuilder::new();
        let a = b.key("A", None, &[]);
        let lf = b.lf(&[a]);
        let inner = b.ri(&[lf]);
        let outer = b.ri(&[inner]);
        let root = b.key_with_list("ROOT", outer, 1, &[]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(matches!(
            h.root().unwrap().subkeys(),
            Err(HiveError::ListTooDeep { .. })
        ));
    }

    #[test]
    fn ri_auf_sich_selbst() {
        // Eine ri-Liste, die auf sich selbst zeigt, darf nicht endlos laufen.
        let mut b = HiveBuilder::new();
        let ri = b.ri(&[0]);
        b.patch_u32(ri, 8, ri);
        let root = b.key_with_list("ROOT", ri, 1, &[]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(h.root().unwrap().subkeys().is_err());
    }

    #[test]
    fn zu_großer_zähler() {
        let mut b = HiveBuilder::new();
        let a = b.key("A", None, &[]);
        let lf = b.lf(&[a]);
        b.patch_u16(lf, 6, 0xFFFF);
        let root = b.key_with_list("ROOT", lf, 1, &[]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        assert!(matches!(
            h.root().unwrap().subkeys(),
            Err(HiveError::BadCount { count: 0xFFFF, .. })
        ));
    }

    #[test]
    fn falscher_zelltyp() {
        let mut b = HiveBuilder::new();
        let a = b.key("A", None, &[]);
        let lf = b.lf(&[a]);
        let root = b.key_with_list("ROOT", lf, 1, &[]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        // Die lf-Liste als Schlüssel lesen
        assert!(matches!(
            Key::read(&h, lf),
            Err(HiveError::UnexpectedCell { expected: "nk", .. })
        ));
    }

    #[test]
    fn class_wert() {
        let mut b = HiveBuilder::new();
        let jd = b.key_with_class("JD", "0011aabb", None, &[]);
        let lf = b.lf(&[jd]);
        let root = b.key_with_list("ROOT", lf, 1, &[]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        let jd = h.open_key("JD").unwrap().unwrap();
        assert_eq!(jd.class().unwrap().as_deref(), Some("0011aabb"));
        // Schlüssel ohne Class liefert None.
        assert_eq!(h.root().unwrap().class().unwrap(), None);
    }

    #[test]
    fn utf16_name() {
        let mut b = HiveBuilder::new();
        let k = b.key_utf16("Übersicht");
        let lf = b.lf(&[k]);
        let root = b.key_with_list("ROOT", lf, 1, &[]);
        let data = b.finish(root);
        let h = Hive::parse(&data).unwrap();
        let k = h.open_key("übersicht").unwrap().unwrap();
        assert_eq!(k.name(), "Übersicht");
    }
}
