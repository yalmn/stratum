//! Zeitpunkte aus den Geräte-Properties eines USBSTOR-Eintrags.

use stratum_registry::{HiveError, Key, Value, ValueType};

use crate::Finding;

const PROPERTY_SET: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";
// Microsoft devpkey.h: IDs 100 bis 103, jeweils DEVPROP_TYPE_FILETIME.
const PROPERTIES: [(&str, &str); 4] = [
    ("0064", "installation"),
    ("0065", "erste_installation"),
    ("0066", "letzte_verbindung"),
    ("0067", "letztes_trennen"),
];
// Im SYSTEM-Hive gespeicherter Geräte-Property-Typ (FILETIME = 0x10).
const FILETIME_TYPE: ValueType = ValueType::Other(0xffff0010);

fn property_set<'h, 'a>(instance: &Key<'h, 'a>) -> Result<Option<Key<'h, 'a>>, HiveError> {
    match instance.subkey("Properties")? {
        Some(properties) => properties.subkey(PROPERTY_SET),
        None => Ok(None),
    }
}

fn filetime(value: &Value<'_>) -> Result<u64, &'static str> {
    if value.value_type() != FILETIME_TYPE {
        return Err("unerwarteter Geräte-Property-Typ, erwartet 0xffff0010");
    }
    let bytes: [u8; 8] = value
        .data()
        .try_into()
        .map_err(|_| "FILETIME muss genau 8 Byte enthalten")?;
    let ft = u64::from_le_bytes(bytes);
    // FILETIME-Konvertierung nach SYSTEMTIME erlaubt kein gesetztes höchstes Bit.
    if ft > i64::MAX as u64 {
        return Err("FILETIME außerhalb des Windows-Zeitbereichs");
    }
    Ok(ft)
}

pub(crate) fn add_times(instance: &Key<'_, '_>, finding: &mut Finding, warnings: &mut Vec<String>) {
    let properties = property_set(instance);
    for (id, field) in PROPERTIES {
        let source = format!("{}\\Properties\\{PROPERTY_SET}\\{id}", finding.source);
        finding
            .attributes
            .insert(format!("{field}_quelle"), format!("{source}\\(Standard)"));
        let result = match &properties {
            Ok(Some(key)) => key.subkey(id).map_err(|e| e.to_string()),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        };
        let mut status = "nicht_vorhanden";
        let parsed = result.and_then(|key| {
            let Some(key) = key else { return Ok(None) };
            finding.attributes.insert(
                format!("{field}_key_hive_offset"),
                key.file_offset().to_string(),
            );
            let value = key
                .value("")
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "Standardwert fehlt".to_string())?;
            finding.attributes.insert(
                format!("{field}_hive_offset"),
                value.file_offset().to_string(),
            );
            filetime(&value).map(Some).map_err(str::to_string)
        });
        match parsed {
            Ok(Some(ft)) => {
                finding
                    .attributes
                    .insert(format!("{field}_filetime"), ft.to_string());
                if let Some(utc) = stratum_core::time::filetime_to_iso(ft) {
                    status = "vorhanden";
                    finding.attributes.insert(format!("{field}_utc"), utc);
                    let ticks = i128::from(ft) - 116_444_736_000_000_000i128;
                    finding.attributes.insert(
                        format!("{field}_unix"),
                        ticks.div_euclid(10_000_000).to_string(),
                    );
                } else {
                    status = "nicht_gesetzt";
                }
            }
            Ok(None) => {}
            Err(error) => {
                status = "nicht_lesbar";
                warnings.push(format!("USB-Zeitpunkt {source}: {error}"));
            }
        }
        finding
            .attributes
            .insert(format!("{field}_status"), status.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::HiveBuilder;

    fn parse(typ: u32, data: &[u8]) -> Result<u64, &'static str> {
        let mut builder = HiveBuilder::new();
        let value = builder.vk("", typ, data);
        let root = builder.key("ROOT", None, &[value]);
        let bytes = builder.finish(root);
        let hive = stratum_registry::Hive::parse(&bytes).unwrap();
        filetime(&hive.root().unwrap().value("").unwrap().unwrap())
    }

    #[test]
    fn typ_länge_und_grenzwerte() {
        for length in [0, 1, 4, 7, 9, 16] {
            assert!(parse(0xffff0010, &vec![0; length]).is_err());
        }
        for typ in [0, 1, 3, 4, 11, 0xffff0012] {
            assert!(parse(typ, &132_539_328_000_000_000u64.to_le_bytes()).is_err());
        }
        for ft in [0, 1, 132_539_328_000_000_001, i64::MAX as u64] {
            assert_eq!(parse(0xffff0010, &ft.to_le_bytes()), Ok(ft));
        }
        assert!(parse(0xffff0010, &u64::MAX.to_le_bytes()).is_err());
    }
}
