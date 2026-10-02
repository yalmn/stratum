//! Einlesen der `bdp.info`, die ForensiCUnlock neben der `merged.dd` ablegt.
//!
//! Die Datei nennt die Lage der entschlüsselten Partition. Format (Key=Wert je
//! Zeile), erzeugt von ForensiCUnlock:
//!
//! ```text
//! slot=2
//! start=239616
//! end=1023999
//! length=784384
//! sector_size=512
//! offset_bytes=122683392
//! ```

use std::path::Path;

use crate::{Kontext, LaufFehler};

/// Lage der entschlüsselten Partition im Image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bdp {
    /// Byte-Offset der Partition im Image.
    pub offset_bytes: u64,
    /// Länge der Partition in Bytes.
    pub size_bytes: u64,
}

/// Liest eine `bdp.info` ein.
pub fn load(path: &Path) -> Result<Bdp, LaufFehler> {
    let text = std::fs::read_to_string(path)
        .kontext(|| format!("bdp.info nicht lesbar: {}", path.display()))?;
    parse(&text).map_err(|f| {
        LaufFehler::Eingabe(format!("bdp.info unvollständig: {}: {f}", path.display()))
    })
}

fn parse(text: &str) -> Result<Bdp, &'static str> {
    let mut offset_bytes = None;
    let mut length = None;
    let mut sector_size = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "offset_bytes" => offset_bytes = value.parse::<u64>().ok(),
            "length" => length = value.parse::<u64>().ok(),
            "sector_size" => sector_size = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    let offset_bytes = offset_bytes.ok_or("offset_bytes fehlt")?;
    let (l, s) = length
        .zip(sector_size)
        .ok_or("length oder sector_size fehlt")?;
    let size_bytes = l
        .checked_mul(s)
        .ok_or("length mal sector_size läuft über")?;
    Ok(Bdp {
        offset_bytes,
        size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parst_bdp() {
        let text = "slot=2\nstart=239616\nend=1023999\nlength=784384\nsector_size=512\noffset_bytes=122683392\n";
        let b = parse(text).unwrap();
        assert_eq!(b.offset_bytes, 122_683_392);
        assert_eq!(b.size_bytes, 784_384 * 512);
    }

    #[test]
    fn fehlende_felder() {
        assert!(parse("slot=1\n").is_err());
    }

    #[test]
    fn ueberlauf_ohne_panik() {
        let t = "offset_bytes=0\nlength=18446744073709551615\nsector_size=512\n";
        assert!(parse(t).is_err());
    }
}
