//! Akquisedaten aus den Sektionen `header2` (UTF-16) und `header` (8 Bit).
//!
//! Beide enthalten zlib-komprimierten Text. Die Kategorie `main` besteht aus
//! einer Zeile mit Kennungen und einer Zeile mit Werten, jeweils durch
//! Tabulatoren getrennt.

/// Akquisedaten als Paare aus Kennung und Wert, in der gespeicherten
/// Reihenfolge. Die Bedeutung der Kennungen folgt der libewf-Beschreibung.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcquisitionInfo {
    /// Kennung und Wert, z. B. `("c", "Fall-42")`.
    pub values: Vec<(String, String)>,
    /// Sektion, aus der die Werte stammen (`header2` oder `header`).
    pub source: Option<&'static str>,
}

impl AcquisitionInfo {
    /// Wert zu einer Kennung, leere Werte als `None`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// Bezeichnung einer Kennung im Report.
    pub fn label(key: &str) -> Option<&'static str> {
        Some(match key {
            "a" => "beschreibung",
            "c" => "fallnummer",
            "n" => "beweisnummer",
            "e" => "bearbeiter",
            "t" => "notizen",
            "md" => "modell",
            "sn" => "seriennummer",
            "l" => "geraetebezeichnung",
            "av" => "programmversion",
            "ov" => "plattform",
            "m" => "akquisezeit",
            "u" => "systemzeit",
            "r" => "kompression",
            _ => return None,
        })
    }

    /// Akquisezeit als Unix-Sekunden, wenn der Wert eine reine Zahl ist
    /// (POSIX-Zeit, wie in `header2` und bei linen). Die EnCase-Form
    /// „2002 3 4 10 19 59“ in `header` enthält keine Zeitzone und wird nicht
    /// umgerechnet.
    pub fn acquired_unix(&self) -> Option<i64> {
        let m = self.get("m")?;
        if !m.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        m.parse().ok()
    }
}

/// Text aus einer `header2`-Sektion (UTF-16 mit BOM).
pub(crate) fn decode_utf16(raw: &[u8]) -> Option<String> {
    let (bom, rest) = (raw.get(..2)?, &raw[2..]);
    let le = match bom {
        [0xff, 0xfe] => true,
        [0xfe, 0xff] => false,
        _ => return None,
    };
    let units: Vec<u16> = rest
        .chunks_exact(2)
        .map(|c| {
            if le {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Text aus einer `header`-Sektion; die Codepage ist nicht angegeben, Bytes
/// werden als Latin-1 gelesen.
pub(crate) fn decode_8bit(raw: &[u8]) -> String {
    raw.iter().map(|&b| char::from(b)).collect()
}

/// Kennungen und Werte der Kategorie `main`.
pub(crate) fn parse(text: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end_matches('\r')).collect();
    let Some(i) = lines.iter().position(|l| *l == "main") else {
        return Vec::new();
    };
    let (Some(keys), Some(vals)) = (lines.get(i + 1), lines.get(i + 2)) else {
        return Vec::new();
    };
    keys.split('\t')
        .zip(vals.split('\t').chain(std::iter::repeat("")))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kategorie_main() {
        let text = "1\nmain\nc\tn\ta\te\tt\tm\n42\tE-7\tTest\tPrüfer\t\t1142163845\n\n";
        let info = AcquisitionInfo {
            values: parse(text),
            source: Some("header"),
        };
        assert_eq!(info.get("c"), Some("42"));
        assert_eq!(info.get("e"), Some("Prüfer"));
        assert_eq!(info.get("t"), None);
        assert_eq!(info.acquired_unix(), Some(1_142_163_845));
        assert!(parse("ohne kategorie").is_empty());
    }

    #[test]
    fn utf16_mit_bom() {
        let mut le = vec![0xff, 0xfe];
        le.extend("äö".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_utf16(&le).as_deref(), Some("äö"));
        let mut be = vec![0xfe, 0xff];
        be.extend("x".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode_utf16(&be).as_deref(), Some("x"));
        assert_eq!(decode_utf16(b"ab"), None);
    }

    #[test]
    fn encase_datum_wird_nicht_umgerechnet() {
        let info = AcquisitionInfo {
            values: vec![("m".into(), "2002 3 4 10 19 59".into())],
            source: Some("header"),
        };
        assert_eq!(info.acquired_unix(), None);
    }
}
