//! Gemeinsame Bausteine der Analyzer auf ESE-Datenbanken (SRUM, WebCache):
//! Datei samt Ablage im Image lesen, Herkunft je Datensatz, Werte darstellen.

use stratum_core::time::filetime_to_iso;
use stratum_ese::{Column, Node, Record, Value};
use stratum_ntfs::{DataStreamLayout, NtfsVolume, NtfsVolumeError};

use crate::fsindex::FileEntry;
use crate::{Finding, Outcome};

/// Obergrenze für Binärwerte im Fund; längere werden gekürzt und ihre Länge
/// angegeben.
const MAX_BINAER: usize = 4096;

/// Herkunft einer Datenbankdatei im Image.
pub(crate) struct Quelle<'a> {
    pub pfad: &'a str,
    pub mft_record: u64,
    pub volume_offset: u64,
    pub layout: Option<&'a DataStreamLayout>,
    /// Grund, falls ein Datei-Offset keinem Image-Offset zugeordnet wird.
    pub ohne_image: &'static str,
}

impl<'a> Quelle<'a> {
    /// Quelle ohne bekannte Ablage (Tests, Fuzzing).
    pub fn ohne_ablage(pfad: &'a str, ohne_image: &'static str) -> Self {
        Self {
            pfad,
            mft_record: 0,
            volume_offset: 0,
            layout: None,
            ohne_image,
        }
    }

    /// Physischer Image-Offset zu einem Offset in der Datei.
    pub fn image_offset(&self, datei_offset: u64) -> Option<u64> {
        self.layout?.runs.iter().find_map(|run| {
            let rel = datei_offset.checked_sub(run.logical_offset)?;
            (rel < run.length).then_some(run.image_offset? + rel)
        })
    }

    /// Hängt Seite, Datei- und Image-Offset eines Datensatzes an den Fund.
    pub fn herkunft(&self, mut f: Finding, node: &Node<'_>) -> Finding {
        f = f
            .with("seite", node.page.to_string())
            .with("datei_offset", node.file_offset.to_string())
            .with("mft_record", self.mft_record.to_string())
            .with("volume_offset", self.volume_offset.to_string());
        f = match self.image_offset(node.file_offset) {
            Some(image) => f.at(image),
            None => f.with("image_offset_fehlt", self.ohne_image),
        };
        if node.is_deleted() {
            f = f.with("geloescht_markiert", "ja");
        }
        f
    }
}

/// Inhalt und Ablage einer Datei. Fehler landen als Warnung in `out`.
pub(crate) fn lesen<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    entry: &FileEntry,
    out: &mut Outcome,
) -> Option<(Vec<u8>, Option<DataStreamLayout>, &'static str)> {
    let data = match vol.read_file_by_record(entry.mft_record, &entry.path) {
        Ok(Some(f)) => f.data,
        Ok(None) => return None,
        Err(e) => {
            out.warnings
                .push(format!("{}: nicht lesbar: {e}", entry.path));
            return None;
        }
    };
    // Ablage im Image, damit jeder Datensatz einen physischen Offset erhält
    // (wie bei den Ereignisprotokollen).
    let (layout, ohne_image) = match vol.data_stream_layout(&entry.path, "") {
        Ok(layout) => (layout, "ablage_unbekannt"),
        Err(NtfsVolumeError::CompressedDataStream { .. }) => (None, "datei_ntfs_komprimiert"),
        Err(e) => {
            out.warnings
                .push(format!("{}: Ablage nicht bestimmbar: {e}", entry.path));
            (None, "ablage_nicht_lesbar")
        }
    };
    Some((data, layout, ohne_image))
}

/// Warnungen beim Öffnen und ein unsauberer Datenbankzustand.
pub(crate) fn zustand_melden(db: &stratum_ese::Database<'_>, pfad: &str, out: &mut Outcome) {
    for w in db.warnings() {
        out.warnings.push(format!("{pfad}: {w}"));
    }
    if db.header().state == 2 {
        out.warnings.push(format!(
            "{pfad}: Datenbank unsauber geschlossen; Änderungen aus den Logdateien sind nicht eingespielt"
        ));
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn utf16(b: &[u8]) -> Option<String> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units)
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
}

/// Wert als Text. Binärwerte als Hex (gekürzt, siehe [`spalte`]), Long
/// Values, komprimierte und mehrwertige Spalten als `nicht_ausgewertet`.
pub(crate) fn render(v: &Value) -> String {
    match v {
        Value::Bit(b) => b.to_string(),
        Value::U8(x) => x.to_string(),
        Value::I16(x) => x.to_string(),
        Value::U16(x) => x.to_string(),
        Value::I32(x) => x.to_string(),
        Value::U32(x) => x.to_string(),
        Value::I64(x) => x.to_string(),
        Value::F32(x) => x.to_string(),
        Value::F64(x) => x.to_string(),
        Value::DateTime(x) => x.to_string(),
        Value::Guid(g) => g.clone(),
        Value::Text(t) => t.clone(),
        Value::Binary(b) => hex(&b[..b.len().min(MAX_BINAER)]),
        Value::Special { flags, data } => format!(
            "nicht_ausgewertet(flags {flags:#04x}): {}",
            hex(&data[..data.len().min(64)])
        ),
    }
}

/// Hängt eine Spalte ohne besondere Deutung an. Textspalten, die laut Katalog
/// nicht UTF-16 sind, aber Nullbytes enthalten, bleiben als Hex erhalten; die
/// UTF-16-Lesart steht getrennt und gekennzeichnet daneben.
pub(crate) fn spalte(mut f: Finding, rec: &Record<'_, '_>, c: &Column, v: &Value) -> Finding {
    if let (Value::Text(t), Some((raw, _))) = (v, rec.raw(c)) {
        if c.codepage != 1200 && t.contains('\0') {
            f = f.with(&c.name, hex(raw)).with(
                format!("{}_hinweis", c.name),
                format!(
                    "Codepage laut Katalog {}, Inhalt mit Nullbytes; Wert als Hex",
                    c.codepage
                ),
            );
            if let Some(u) = utf16(raw) {
                f = f.with(format!("{}_als_utf16", c.name), u);
            }
            return f;
        }
    }
    if let Value::Binary(b) = v {
        if b.len() > MAX_BINAER {
            f = f.with(format!("{}_laenge", c.name), b.len().to_string());
        }
    }
    f.with(&c.name, render(v))
}

/// FILETIME-Spalte: Rohwert und, falls gesetzt und nicht der Höchstwert
/// („kein Ablauf“), zusätzlich `<Spalte>_utc`.
pub(crate) fn filetime(mut f: Finding, name: &str, v: &Value) -> Finding {
    f = f.with(name, render(v));
    if let Value::I64(ft) = v {
        if *ft != i64::MAX {
            if let Some(iso) = u64::try_from(*ft).ok().and_then(filetime_to_iso) {
                f = f.with(format!("{name}_utc"), iso);
            }
        }
    }
    f
}

/// Benutzername aus einem Pfad unter `Users\<Name>\`.
pub(crate) fn benutzer_aus_pfad(path: &str) -> Option<String> {
    let teile: Vec<&str> = path.split('\\').collect();
    teile
        .iter()
        .position(|p| p.eq_ignore_ascii_case("Users"))
        .and_then(|i| teile.get(i + 1))
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_ohne_null_und_hoechstwert() {
        let f = filetime(Finding::new("t", "", "q"), "X", &Value::I64(0));
        assert!(!f.attributes.contains_key("X_utc"));
        let f = filetime(Finding::new("t", "", "q"), "X", &Value::I64(i64::MAX));
        assert!(!f.attributes.contains_key("X_utc"));
        let f = filetime(
            Finding::new("t", "", "q"),
            "X",
            &Value::I64(134_209_771_526_006_675),
        );
        assert_eq!(f.attributes["X_utc"], "2026-04-18T09:12:32.6006675Z");
    }

    #[test]
    fn benutzer_nur_unter_users() {
        assert_eq!(
            benutzer_aus_pfad("Users\\ich\\AppData\\x.dat").as_deref(),
            Some("ich")
        );
        assert_eq!(benutzer_aus_pfad("Windows\\x.dat"), None);
    }
}
