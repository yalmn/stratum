//! Vergleich mit dissect.esedb auf echten Windows-11-Datenbanken.
//!
//! Die Referenz-JSON erzeugt ein kleines Skript mit dissect.esedb: je Tabelle
//! Spalten und für jeden Datensatz die Rohbytes jeder Spalte (hex), bei Long
//! Values, komprimierten und mehrwertigen Spalten nur deren Flags.

use serde_json::Value as Json;
use stratum_ese::{Database, Value};

fn vergleiche(db_datei: &str, json_datei: &str) {
    let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_ESE_REFERENCE").unwrap());
    let data = std::fs::read(dir.join(db_datei)).unwrap();
    let referenz: Json =
        serde_json::from_slice(&std::fs::read(dir.join(json_datei)).unwrap()).unwrap();
    let db = Database::open(&data).unwrap();
    let mut werte = 0usize;
    for (name, erwartet) in referenz.as_object().unwrap() {
        // Doppelte Tabellennamen sind in der Referenz nicht eindeutig.
        if db.tables().iter().filter(|t| &t.name == name).count() != 1 {
            continue;
        }
        let table = db.table(name).unwrap();
        let spalten = erwartet["spalten"].as_array().unwrap();
        assert_eq!(table.columns.len(), spalten.len(), "{name}: Spaltenzahl");
        for s in spalten {
            let c = table
                .column(s["name"].as_str().unwrap())
                .unwrap_or_else(|| panic!("{name}: Spalte {s} fehlt"));
            assert_eq!(
                u64::from(c.id),
                s["id"].as_u64().unwrap(),
                "{name}.{}",
                c.name
            );
        }
        let records = db.records(table).unwrap();
        let sollsaetze = erwartet["datensaetze"].as_array().unwrap();
        assert_eq!(records.len(), sollsaetze.len(), "{name}: Datensätze");
        for (i, (rec, soll)) in records.iter().zip(sollsaetze).enumerate() {
            for c in &table.columns {
                let sollwert = &soll[&c.name];
                let ist = rec.get(c);
                match (sollwert.get("hex"), sollwert.get("spezial"), &ist) {
                    (Some(hex), _, _) => {
                        let (raw, _) = rec
                            .raw(c)
                            .unwrap_or_else(|| panic!("{name}[{i}].{} fehlt", c.name));
                        let raw: String = raw.iter().map(|b| format!("{b:02x}")).collect();
                        assert_eq!(&raw, hex.as_str().unwrap(), "{name}[{i}].{}", c.name);
                    }
                    (None, Some(f), Some(Value::Special { flags, .. })) => {
                        assert_eq!(
                            u64::from(*flags),
                            f.as_u64().unwrap(),
                            "{name}[{i}].{}",
                            c.name
                        );
                    }
                    (None, None, None) => {}
                    _ => panic!(
                        "{name}[{i}].{}: erwartet {sollwert}, gelesen {ist:?}",
                        c.name
                    ),
                }
                werte += 1;
            }
        }
    }
    eprintln!("{db_datei}: {werte} Werte verglichen");
    assert!(werte > 0);
}

#[test]
#[ignore = "benötigt STRATUM_ESE_REFERENCE mit Datenbanken und dissect-Referenz"]
fn srudb_wie_dissect() {
    vergleiche("SRUDB.dat", "srudb_referenz.json");
}

#[test]
#[ignore = "benötigt STRATUM_ESE_REFERENCE mit Datenbanken und dissect-Referenz"]
fn webcache_wie_dissect() {
    vergleiche("WebCacheV01.dat", "webcache_referenz.json");
}
