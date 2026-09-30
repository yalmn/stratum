//! Systemkatalog (MSysObjects): Tabellen, Spalten, Long-Value-Bäume.

use crate::{Database, EseError, Record, Value, CATALOG_ROOT};

/// Spaltentyp (JET_COLTYP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    /// Ungültig.
    Nil,
    /// Wahrheitswert.
    Bit,
    /// 8 Bit ohne Vorzeichen.
    UnsignedByte,
    /// 16 Bit mit Vorzeichen.
    Short,
    /// 32 Bit mit Vorzeichen.
    Long,
    /// 64 Bit mit Vorzeichen.
    Currency,
    /// Gleitkomma 32 Bit.
    IeeeSingle,
    /// Gleitkomma 64 Bit.
    IeeeDouble,
    /// Datum (64 Bit).
    DateTime,
    /// Binärdaten bis 255 Byte.
    Binary,
    /// Text bis 255 Byte.
    Text,
    /// Lange Binärdaten.
    LongBinary,
    /// Langer Text.
    LongText,
    /// Veraltet.
    Slv,
    /// 32 Bit ohne Vorzeichen.
    UnsignedLong,
    /// 64 Bit mit Vorzeichen.
    LongLong,
    /// GUID.
    Guid,
    /// 16 Bit ohne Vorzeichen.
    UnsignedShort,
    /// Unbekannter Typwert.
    Unknown(u32),
}

impl ColumnType {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Nil,
            1 => Self::Bit,
            2 => Self::UnsignedByte,
            3 => Self::Short,
            4 => Self::Long,
            5 => Self::Currency,
            6 => Self::IeeeSingle,
            7 => Self::IeeeDouble,
            8 => Self::DateTime,
            9 => Self::Binary,
            10 => Self::Text,
            11 => Self::LongBinary,
            12 => Self::LongText,
            13 => Self::Slv,
            14 => Self::UnsignedLong,
            15 => Self::LongLong,
            16 => Self::Guid,
            17 => Self::UnsignedShort,
            v => Self::Unknown(v),
        }
    }

    /// Feste Größe des Typs, falls er eine hat.
    fn size(self) -> Option<usize> {
        Some(match self {
            Self::Bit | Self::UnsignedByte => 1,
            Self::Short | Self::UnsignedShort => 2,
            Self::Long | Self::UnsignedLong | Self::IeeeSingle => 4,
            Self::Currency | Self::IeeeDouble | Self::DateTime | Self::LongLong => 8,
            Self::Guid => 16,
            _ => return None,
        })
    }
}

/// Eine Spalte.
#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    /// Spalten-ID (1 bis 127 fest, 128 bis 255 variabel, ab 256 getaggt).
    pub id: u16,
    /// Name.
    pub name: String,
    /// Typ.
    pub column_type: ColumnType,
    /// Codepage bei Textspalten (1200 = UTF-16LE).
    pub codepage: u32,
    /// Größe laut Katalog (bei festen Binär-/Textspalten die feste Länge).
    pub space: u32,
    /// Lage fester Spalten im Datensatz, relativ zum Ende des Kopfs.
    pub fixed_offset: Option<usize>,
}

impl Column {
    /// Größe eines festen Werts.
    pub fn fixed_size(&self) -> Option<usize> {
        self.column_type
            .size()
            .or_else(|| usize::try_from(self.space).ok().filter(|&s| s > 0))
    }
}

/// Eine Tabelle.
#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    /// Name.
    pub name: String,
    /// Objekt-ID.
    pub object_id: u32,
    /// Wurzelseite des Datenbaums.
    pub fdp: u32,
    /// Wurzelseite des Long-Value-Baums, falls vorhanden.
    pub long_value_fdp: Option<u32>,
    /// Spalten nach ID sortiert.
    pub columns: Vec<Column>,
}

impl Table {
    /// Spalte nach Namen.
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    /// Spalte nach ID.
    pub fn column_by_id(&self, id: u16) -> Option<&Column> {
        self.columns.iter().find(|c| c.id == id)
    }

    /// Lage der festen Spalten: Summe der Größen aller festen Spalten mit
    /// kleinerer ID.
    fn layout(&mut self) {
        self.columns.sort_by_key(|c| c.id);
        let mut offset = 0usize;
        for c in &mut self.columns {
            if c.id < 128 {
                c.fixed_offset = Some(offset);
                offset += c.fixed_size().unwrap_or(0);
            }
        }
    }
}

fn col(id: u16, name: &str, t: u32) -> Column {
    Column {
        id,
        name: name.into(),
        column_type: ColumnType::from_raw(t),
        codepage: 1252,
        space: 0,
        fixed_offset: None,
    }
}

/// Der Katalog selbst mit seinen fest vorgegebenen Spalten (libesedb, Beispiel
/// "the catalog (data type) definition").
fn catalog_table() -> Table {
    let mut t = Table {
        name: "MSysObjects".into(),
        object_id: 2,
        fdp: CATALOG_ROOT,
        long_value_fdp: None,
        columns: vec![
            col(1, "ObjidTable", 4),
            col(2, "Type", 3),
            col(3, "Id", 4),
            col(4, "ColtypOrPgnoFDP", 4),
            col(5, "SpaceUsage", 4),
            col(6, "Flags", 4),
            col(7, "PagesOrLocale", 4),
            col(8, "RootFlag", 1),
            col(9, "RecordOffset", 3),
            col(10, "LCMapFlags", 4),
            col(11, "KeyMost", 17),
            col(12, "LVChunkMax", 4),
            col(128, "Name", 10),
            col(130, "TemplateTable", 10),
        ],
    };
    t.layout();
    t
}

fn int(v: Option<Value>) -> Option<i64> {
    match v? {
        Value::I16(x) => Some(i64::from(x)),
        Value::U16(x) => Some(i64::from(x)),
        Value::I32(x) => Some(i64::from(x)),
        Value::U32(x) => Some(i64::from(x)),
        _ => None,
    }
}

/// Liest den Katalog. Einträge: Typ 1 Tabelle, 2 Spalte, 3 Index, 4 Long Value.
pub(crate) fn read(db: &Database<'_>) -> Result<(Vec<Table>, Vec<String>), EseError> {
    let catalog = catalog_table();
    let walk = db
        .leaf_nodes(CATALOG_ROOT)
        .map_err(|e| EseError::Catalog(e.to_string()))?;
    let mut warnings: Vec<String> = walk.errors.clone();
    let mut tables: Vec<Table> = Vec::new();
    for node in walk.nodes {
        if node.is_deleted() {
            continue;
        }
        let rec = Record::new(db, &catalog, node);
        let get = |n: &str| int(rec.get_by_name(n));
        let (Some(kind), Some(object)) = (get("Type"), get("ObjidTable")) else {
            warnings.push("Katalogeintrag ohne Typ oder Objekt-ID".into());
            continue;
        };
        let name = match rec.get_by_name("Name") {
            Some(Value::Text(s)) => s,
            _ => String::new(),
        };
        let pgno_or_type = get("ColtypOrPgnoFDP").unwrap_or(0);
        let object = object as u32;
        match kind {
            1 => tables.push(Table {
                name,
                object_id: object,
                fdp: pgno_or_type as u32,
                long_value_fdp: None,
                columns: Vec::new(),
            }),
            2 | 4 => {
                let Some(table) = tables.iter_mut().rev().find(|t| t.object_id == object) else {
                    warnings.push(format!("Katalogeintrag {name} ohne Tabelle {object}"));
                    continue;
                };
                if kind == 4 {
                    table.long_value_fdp = Some(pgno_or_type as u32);
                } else {
                    table.columns.push(Column {
                        id: get("Id").unwrap_or(0) as u16,
                        name,
                        column_type: ColumnType::from_raw(pgno_or_type as u32),
                        codepage: get("PagesOrLocale").unwrap_or(0) as u32,
                        space: get("SpaceUsage").unwrap_or(0) as u32,
                        fixed_offset: None,
                    });
                }
            }
            _ => {}
        }
    }
    for t in &mut tables {
        t.layout();
    }
    if tables.is_empty() {
        return Err(EseError::Catalog("keine Tabellen".into()));
    }
    Ok((tables, warnings))
}
