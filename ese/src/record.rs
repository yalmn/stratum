//! Datensätze: feste, variable und getaggte Spalten.
//!
//! Aufbau laut libesedb: vier Byte Kopf (letzte feste Spalte, letzte variable
//! Spalte, Ende der festen Daten), feste Werte, Null-Bitmap der festen Spalten,
//! Offsets der variablen Spalten (höchstes Bit = leer), variable Daten, dann
//! das Offset-Array der getaggten Spalten mit deren Daten.

use crate::{u16_at, u32_at, Column, ColumnType, Database, Node, Table};

/// Ein Spaltenwert.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Wahrheitswert.
    Bit(bool),
    /// Vorzeichenlose 8-Bit-Zahl.
    U8(u8),
    /// 16-Bit-Zahl mit Vorzeichen.
    I16(i16),
    /// 16-Bit-Zahl ohne Vorzeichen.
    U16(u16),
    /// 32-Bit-Zahl mit Vorzeichen.
    I32(i32),
    /// 32-Bit-Zahl ohne Vorzeichen.
    U32(u32),
    /// 64-Bit-Zahl mit Vorzeichen (auch Currency).
    I64(i64),
    /// Gleitkommazahl einfacher Genauigkeit.
    F32(f32),
    /// Gleitkommazahl doppelter Genauigkeit.
    F64(f64),
    /// Datum als Rohwert. Je nach Datenbank FILETIME oder OLE-Datum, die
    /// Deutung bleibt dem Aufrufer.
    DateTime(u64),
    /// GUID in üblicher Schreibweise.
    Guid(String),
    /// Text.
    Text(String),
    /// Binärdaten.
    Binary(Vec<u8>),
    /// Getaggter Wert in einer noch nicht ausgewerteten Form (Long Value,
    /// komprimiert oder mehrwertig), mit Flags und Rohbytes.
    Special {
        /// Flags des getaggten Werts (0x02 komprimiert, 0x04 Long Value,
        /// 0x08 mehrwertig, 0x10 zwei Werte).
        flags: u8,
        /// Rohbytes.
        data: Vec<u8>,
    },
}

/// Ein Datensatz einer Tabelle.
#[derive(Debug, Clone)]
pub struct Record<'a, 'd> {
    table: &'d Table,
    small: bool,
    /// Knoten mit Schlüssel, Seite und Dateioffset.
    pub node: Node<'a>,
}

impl<'a, 'd> Record<'a, 'd> {
    pub(crate) fn new(db: &'d Database<'a>, table: &'d Table, node: Node<'a>) -> Self {
        Self {
            table,
            small: db.small_pages(),
            node,
        }
    }

    /// Rohbytes einer Spalte (ohne Deutung) und bei getaggten Spalten deren
    /// Flags. `None` bei fehlendem oder leerem Wert.
    pub fn raw(&self, column: &Column) -> Option<(&'a [u8], u8)> {
        raw_value(
            self.node.data,
            self.small,
            self.node.new_record_format,
            column,
        )
    }

    /// Wert einer Spalte, gedeutet nach ihrem Typ.
    pub fn get(&self, column: &Column) -> Option<Value> {
        let (raw, flags) = self.raw(column)?;
        if flags & 0x1e != 0 {
            return Some(Value::Special {
                flags,
                data: raw.to_vec(),
            });
        }
        Some(decode(column, raw))
    }

    /// Wert einer Spalte nach Namen.
    pub fn get_by_name(&self, name: &str) -> Option<Value> {
        self.get(self.table.column(name)?)
    }
}

/// Rohbytes und Flags einer Spalte in den Daten eines Datensatzes.
pub(crate) fn raw_value<'a>(
    d: &'a [u8],
    small: bool,
    new_record_format: bool,
    column: &Column,
) -> Option<(&'a [u8], u8)> {
    let last_fixed = u16::from(*d.first()?);
    let last_var = u16::from(*d.get(1)?);
    let fixed_end = usize::from(u16_at(d, 2)?);
    if column.id < 128 {
        if column.id > last_fixed {
            return None;
        }
        // Null-Bitmap direkt vor dem Ende der festen Daten.
        let bitmap_len = usize::from(last_fixed).div_ceil(8);
        let bitmap_start = fixed_end.checked_sub(bitmap_len)?;
        let bit = usize::from(column.id - 1);
        if d.get(bitmap_start + bit / 8)? & (1 << (bit % 8)) != 0 {
            return None;
        }
        let start = 4 + column.fixed_offset?;
        return d.get(start..start + column.fixed_size()?).map(|v| (v, 0));
    }
    let var_count = usize::from(last_var.saturating_sub(127));
    let var_data = fixed_end + var_count * 2;
    let var_offset = |i: usize| u16_at(d, fixed_end + i * 2);
    if column.id < 256 {
        if column.id > last_var {
            return None;
        }
        let i = usize::from(column.id - 128);
        let end = var_offset(i)?;
        if end & 0x8000 != 0 {
            return None;
        }
        let start = if i == 0 {
            0
        } else {
            var_offset(i - 1)? & 0x7fff
        };
        return d
            .get(var_data + usize::from(start)..var_data + usize::from(end))
            .map(|v| (v, 0));
    }
    // Getaggte Spalten.
    let tagged = if var_count > 0 {
        var_data + usize::from(var_offset(var_count - 1)? & 0x7fff)
    } else {
        var_data
    };
    if !new_record_format || d.len() < tagged + 4 {
        return None;
    }
    let first = u32_at(d, tagged)?;
    let mask = if small { 0x1fff } else { 0x7fff };
    let count = usize::from(((first >> 16) as u16) & mask) / 4;
    let entry = |i: usize| -> Option<(u16, u16)> {
        let v = u32_at(d, tagged + i * 4)?;
        Some((v as u16, (v >> 16) as u16))
    };
    let index = (0..count).find(|&i| entry(i).is_some_and(|(id, _)| id == column.id))?;
    let (_, raw_off) = entry(index)?;
    let mut start = usize::from(raw_off & mask);
    let end = match index + 1 < count {
        true => usize::from(entry(index + 1)?.1 & mask),
        false => d.len() - tagged,
    };
    // Große Seiten: immer ein Flag-Byte vor dem Wert. Kleine Seiten: nur
    // mit Bit 0x4000; Bit 0x2000 bedeutet leer.
    let extended = !small || raw_off & 0x4000 != 0;
    if small && raw_off & 0x2000 != 0 {
        return None;
    }
    let mut flags = 0u8;
    if extended {
        flags = *d.get(tagged + start)?;
        start += 1;
        if !small && flags & 0x20 != 0 {
            return None;
        }
    }
    d.get(tagged + start..tagged + end.max(start))
        .map(|v| (v, flags))
}

fn decode(column: &Column, raw: &[u8]) -> Value {
    let arr = |n: usize| raw.get(..n);
    match column.column_type {
        ColumnType::Bit => Value::Bit(raw.first().is_some_and(|b| *b != 0)),
        ColumnType::UnsignedByte => raw
            .first()
            .map_or(Value::Binary(Vec::new()), |b| Value::U8(*b)),
        ColumnType::Short => {
            arr(2).map_or(bin(raw), |b| Value::I16(i16::from_le_bytes([b[0], b[1]])))
        }
        ColumnType::UnsignedShort => {
            arr(2).map_or(bin(raw), |b| Value::U16(u16::from_le_bytes([b[0], b[1]])))
        }
        ColumnType::Long => arr(4).map_or(bin(raw), |b| {
            Value::I32(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }),
        ColumnType::UnsignedLong => arr(4).map_or(bin(raw), |b| {
            Value::U32(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }),
        ColumnType::IeeeSingle => arr(4).map_or(bin(raw), |b| {
            Value::F32(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }),
        ColumnType::Currency | ColumnType::LongLong => arr(8).map_or(bin(raw), |b| {
            Value::I64(i64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
        }),
        ColumnType::IeeeDouble => arr(8).map_or(bin(raw), |b| {
            Value::F64(f64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
        }),
        ColumnType::DateTime => arr(8).map_or(bin(raw), |b| {
            Value::DateTime(u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
        }),
        ColumnType::Guid => arr(16).map_or(bin(raw), |g| {
            Value::Guid(format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
                u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
                u16::from_le_bytes([g[4], g[5]]),
                u16::from_le_bytes([g[6], g[7]]),
                g[8],
                g[9],
                g[10..16]
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<String>()
            ))
        }),
        ColumnType::Text | ColumnType::LongText => Value::Text(text(raw, column.codepage)),
        _ => bin(raw),
    }
}

fn bin(raw: &[u8]) -> Value {
    Value::Binary(raw.to_vec())
}

/// Text nach Codepage: 1200 UTF-16LE, sonst ein Byte je Zeichen (1252/ASCII).
fn text(raw: &[u8], codepage: u32) -> String {
    if codepage == 1200 {
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string()
    } else {
        raw.iter()
            .map(|&b| char::from(b))
            .collect::<String>()
            .trim_end_matches('\0')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spalte(id: u16, t: ColumnType, fixed_offset: Option<usize>) -> Column {
        Column {
            id,
            name: format!("c{id}"),
            column_type: t,
            codepage: 1200,
            space: 0,
            fixed_offset,
        }
    }

    /// Datensatz einer kleinen Seite: Spalte 1 (I32) und 2 (I16, NULL),
    /// variable Spalte 128 ("ab" als UTF-16), getaggte Spalten 256 und 257.
    fn datensatz() -> Vec<u8> {
        let mut d = vec![2, 128, 0, 0];
        d.extend_from_slice(&7i32.to_le_bytes());
        d.extend_from_slice(&0i16.to_le_bytes());
        d.push(0b10); // Spalte 2 ist NULL
        let fixed_end = d.len() as u16;
        d[2..4].copy_from_slice(&fixed_end.to_le_bytes());
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(&[b'a', 0, b'b', 0]);
        // Getaggte Spalten: Offsets relativ zum Array, 256 mit Flag-Byte.
        let array = 8u16;
        d.extend_from_slice(&256u16.to_le_bytes());
        d.extend_from_slice(&(array | 0x4000).to_le_bytes());
        d.extend_from_slice(&257u16.to_le_bytes());
        d.extend_from_slice(&(array + 5).to_le_bytes());
        d.push(0x00);
        d.extend_from_slice(&[1, 2, 3, 4]);
        d.extend_from_slice(&[9, 9]);
        d
    }

    #[test]
    fn feste_variable_und_getaggte_spalten() {
        let d = datensatz();
        let c1 = spalte(1, ColumnType::Long, Some(0));
        let c2 = spalte(2, ColumnType::Short, Some(4));
        let c128 = spalte(128, ColumnType::Text, None);
        let c256 = spalte(256, ColumnType::LongBinary, None);
        let c257 = spalte(257, ColumnType::LongBinary, None);
        let wert = |c: &Column| raw_value(&d, true, true, c).map(|(v, _)| decode(c, v));
        assert_eq!(wert(&c1), Some(Value::I32(7)));
        assert_eq!(wert(&c2), None);
        assert_eq!(wert(&c128), Some(Value::Text("ab".into())));
        assert_eq!(
            raw_value(&d, true, true, &c256),
            Some((&[1u8, 2, 3, 4][..], 0))
        );
        assert_eq!(raw_value(&d, true, true, &c257), Some((&[9u8, 9][..], 0)));
        // Ohne neues Datensatzformat keine getaggten Werte.
        assert_eq!(raw_value(&d, true, false, &c256), None);
        assert_eq!(wert(&spalte(300, ColumnType::Long, None)), None);
    }

    #[test]
    fn unsinnige_datensaetze_ohne_panik() {
        let c = [
            spalte(1, ColumnType::Long, Some(0)),
            spalte(130, ColumnType::Text, None),
            spalte(260, ColumnType::LongText, None),
        ];
        let mut state = 99u32;
        for len in 0..200 {
            let d: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (state >> 16) as u8
                })
                .collect();
            for col in &c {
                for small in [true, false] {
                    let _ = raw_value(&d, small, true, col).map(|(v, _)| decode(col, v));
                }
            }
        }
    }
}
