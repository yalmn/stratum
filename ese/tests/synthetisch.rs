//! Synthetische Mini-Datenbank: Katalog, feste, variable und getaggte Spalten,
//! leere Werte.

#[path = "common/bau.rs"]
mod bau;

use bau::{datenbank, Spalte, Tabelle};
use stratum_ese::{ColumnType, Database, Value};

#[test]
fn mini_datenbank_lesen() {
    let spalten = vec![
        Spalte::neu(1, "Nummer", 4),
        Spalte::neu(2, "Zeit", 8),
        Spalte::neu(3, "Klein", 2),
        Spalte::neu(128, "Name", 10),
        Spalte::neu(129, "Rest", 9),
        Spalte {
            codepage: 1200,
            ..Spalte::neu(256, "Langtext", 12)
        },
        Spalte::neu(257, "Blob", 11),
    ];
    let langtext: Vec<u8> = "Grüße".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let tabelle = Tabelle {
        name: "Probe",
        spalten,
        zeilen: vec![
            vec![
                (1, 7i32.to_le_bytes().to_vec()),
                (2, 1.5f64.to_bits().to_le_bytes().to_vec()),
                (128, b"eins".to_vec()),
                (256, langtext),
                (257, vec![1, 2, 3]),
            ],
            vec![(1, (-1i32).to_le_bytes().to_vec()), (129, vec![0xaa])],
        ],
    };
    let data = datenbank(&[tabelle], 3);
    let db = Database::open(&data).unwrap();
    assert_eq!(db.header().page_size, 4096);
    assert_eq!(db.header().state, 3);
    let t = db.table("probe").unwrap();
    assert_eq!(t.columns.len(), 7);
    assert_eq!(t.column("Langtext").unwrap().codepage, 1200);
    assert_eq!(
        t.column("Blob").unwrap().column_type,
        ColumnType::LongBinary
    );

    let r = db.records(t).unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].get_by_name("Nummer"), Some(Value::I32(7)));
    assert_eq!(
        r[0].get_by_name("Zeit"),
        Some(Value::DateTime(1.5f64.to_bits()))
    );
    assert_eq!(r[0].get_by_name("Klein"), None);
    assert_eq!(r[0].get_by_name("Name"), Some(Value::Text("eins".into())));
    assert_eq!(r[0].get_by_name("Rest"), None);
    assert_eq!(
        r[0].get_by_name("Langtext"),
        Some(Value::Text("Grüße".into()))
    );
    assert_eq!(r[0].get_by_name("Blob"), Some(Value::Binary(vec![1, 2, 3])));

    assert_eq!(r[1].get_by_name("Nummer"), Some(Value::I32(-1)));
    assert_eq!(r[1].get_by_name("Name"), None);
    assert_eq!(r[1].get_by_name("Rest"), Some(Value::Binary(vec![0xaa])));
    assert_eq!(r[1].get_by_name("Blob"), None);
    // Datei-Offset zeigt auf die Datensatzdaten.
    let n = &r[1].node;
    let at = n.file_offset as usize;
    assert_eq!(&data[at..at + n.data.len()], n.data);
}
