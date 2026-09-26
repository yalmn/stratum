//! Dateibasierte Persistenz: geplante Aufgaben und Autostart-Ordner.
//!
//! Anders als die Registry-Autostarts liegen diese Artefakte als Dateien im
//! Dateisystem: die XML-Beschreibungen der geplanten Aufgaben unter
//! `Windows\System32\Tasks` und die Verknüpfungen in den Autostart-Ordnern der
//! Benutzer und des Systems. Der Analyzer liest sie über den Pfad-Index.

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, FsIndex, Outcome};

/// Analyzer für geplante Aufgaben und Autostart-Ordner.
pub struct FilePersistenceAnalyzer;

impl Analyzer for FilePersistenceAnalyzer {
    fn domain(&self) -> &str {
        "persistence"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };
            scheduled_tasks(&mut vol, v, &mut out);
            startup_folders(&mut vol, v, &mut out);
        }
        out
    }
}

/// Liest die XML-Dateien unter `Windows\System32\Tasks` und meldet je Aufgabe
/// den auszuführenden Befehl.
fn scheduled_tasks<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    let prefix = "Windows\\System32\\Tasks";
    let dateien: Vec<_> = v
        .under(prefix)
        .filter(|e| e.size > 0 && e.size < 1_000_000)
        .cloned()
        .collect();
    for e in dateien {
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let text = decode_text(&f.data);
        // Nur echte Aufgaben-XML auswerten.
        if !text.contains("<Task") {
            continue;
        }
        let command = tag(&text, "Command");
        let arguments = tag(&text, "Arguments");
        let author = tag(&text, "Author");
        let user = tag(&text, "UserId");
        // Der Aufgabenname ist der Pfad unter Tasks.
        let name = e.path.strip_prefix(prefix).unwrap_or(&e.path);
        let name = name.trim_start_matches('\\');

        let befehl = match (&command, &arguments) {
            (Some(c), Some(a)) => format!("{c} {a}"),
            (Some(c), None) => c.clone(),
            _ => String::new(),
        };
        let mut fd = Finding::new("persistence", name, &e.path)
            .with("ort", "Aufgabe")
            .with("befehl", befehl);
        if let Some(a) = author {
            fd = fd.with("autor", a);
        }
        if let Some(u) = user {
            fd = fd.with("benutzer", u);
        }
        out.findings.push(fd);
    }
}

/// Meldet die Einträge in den Autostart-Ordnern der Benutzer und des Systems.
fn startup_folders<R: std::io::Read + std::io::Seek>(
    _vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    // Endet ein Pfad auf einen Autostart-Ordner (mit einer Datei darin)?
    let marker = "\\start menu\\programs\\startup\\";
    for e in &v.files {
        let lower = e.path.to_ascii_lowercase();
        let Some(pos) = lower.find(marker) else {
            continue;
        };
        // Nur direkte Einträge im Ordner, keine tieferen Unterordner.
        let rest = &e.path[pos + marker.len()..];
        if rest.is_empty() || rest.contains('\\') {
            continue;
        }
        if rest.eq_ignore_ascii_case("desktop.ini") {
            continue;
        }
        out.findings
            .push(Finding::new("persistence", rest, &e.path).with("ort", "Autostart-Ordner"));
    }
}

/// Dekodiert einen Text als UTF-16LE (mit BOM) oder sonst als UTF-8 (verlustarm).
fn decode_text(data: &[u8]) -> String {
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0xfe {
        let units: Vec<u16> = data[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(data).into_owned()
    }
}

/// Extrahiert den Textinhalt des ersten `<tag>...</tag>` (ohne Namensraum-Präfix).
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let inhalt = xml[start..end].trim();
    if inhalt.is_empty() {
        None
    } else {
        Some(inhalt.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_extrahiert_inhalt() {
        let xml = "<Task><Actions><Exec><Command>C:\\evil.exe</Command>\
                   <Arguments>-x</Arguments></Exec></Actions></Task>";
        assert_eq!(tag(xml, "Command").as_deref(), Some("C:\\evil.exe"));
        assert_eq!(tag(xml, "Arguments").as_deref(), Some("-x"));
        assert_eq!(tag(xml, "Author"), None);
    }

    #[test]
    fn decode_utf16_mit_bom() {
        let mut d = vec![0xff, 0xfe];
        d.extend("ab".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_text(&d), "ab");
        assert_eq!(decode_text(b"hallo"), "hallo");
    }
}
