//! PSReadLine-Verlauf: gespeicherte Eingaben mit Dateiposition, ohne erfundene Ausführungszeiten.
//!
//! Die physische Zeilenfolge bleibt erhalten. Ein Verlaufseintrag allein beweist
//! weder eine Ausführung noch deren Erfolg. Mehrzeilige Eingaben werden hier
//! nicht zu einem vermeintlich sicher rekonstruierten Befehl zusammengefügt.

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINES: usize = 50_000;
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Liest PSReadLine-Verlaufsdateien gezielt über den vorhandenen NTFS-Index.
pub struct PowerShellHistoryAnalyzer;

impl Analyzer for PowerShellHistoryAnalyzer {
    fn domain(&self) -> &str {
        "powershell"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            let candidates: Vec<_> = v.files.iter().filter(|e| history_path(&e.path)).collect();
            if candidates.is_empty() {
                continue;
            }
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("PowerShell, Volume {}: {e}", v.target.offset));
                    continue;
                }
            };
            for e in candidates {
                if e.size > MAX_FILE_BYTES as u64 {
                    out.warnings
                        .push(format!("{}: Verlauf über 16 MiB, nicht gelesen", e.path));
                    continue;
                }
                let f = match vol.read_file_by_record(e.mft_record, &e.path) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        out.warnings
                            .push(format!("{}: indizierte Datei nicht lesbar", e.path));
                        continue;
                    }
                    Err(err) => {
                        out.warnings.push(format!("{}: {err}", e.path));
                        continue;
                    }
                };
                let mut parsed = parse_powershell_history(&f.data, &e.path);
                for finding in &mut parsed.findings {
                    finding
                        .attributes
                        .insert("mft_record".into(), e.mft_record.to_string());
                    finding
                        .attributes
                        .insert("volume_offset".into(), v.target.offset.to_string());
                    if let Some(offset) = f.meta.record_offset {
                        finding
                            .attributes
                            .insert("mft_record_offset".into(), offset.to_string());
                    }
                }
                out.findings.extend(parsed.findings);
                out.warnings.extend(parsed.warnings);
            }
        }
        out
    }
}

fn history_path(path: &str) -> bool {
    let path = path.replace('/', "\\").to_ascii_lowercase();
    let name = path.rsplit('\\').next().unwrap_or("");
    name == "consolehost_history.txt"
        || (path.contains("\\psreadline\\") && name.ends_with("_history.txt"))
}

/// Liest physische UTF-8-Verlaufszeilen mit originalen Byte-Offsets innerhalb
/// der Datei. Ungültige Kodierung und Größenbegrenzungen werden gemeldet.
/// `Finding::offset` bleibt leer, da Dateioffsets keine physischen Image-Offsets sind.
pub fn parse_powershell_history(data: &[u8], source: &str) -> Outcome {
    let mut out = Outcome::default();
    if data.len() > MAX_FILE_BYTES {
        out.warnings
            .push(format!("{source}: Verlauf über 16 MiB, nicht ausgewertet"));
        return out;
    }
    let start = if data.starts_with(b"\xef\xbb\xbf") {
        3
    } else {
        0
    };
    if std::str::from_utf8(&data[start..]).is_err() {
        out.warnings.push(format!(
            "{source}: kein gültiger UTF-8-Verlauf, nicht ausgewertet"
        ));
        return out;
    }
    let normalized = source.replace('/', "\\");
    let parts: Vec<_> = normalized.split('\\').collect();
    let user = parts
        .windows(2)
        .find(|p| p[0].eq_ignore_ascii_case("Users"))
        .map(|p| p[1]);
    let mut offset = start;
    for (index, raw) in data[start..].split_inclusive(|b| *b == b'\n').enumerate() {
        if index >= MAX_LINES {
            out.warnings.push(format!(
                "{source}: nach {MAX_LINES} physischen Zeilen abgebrochen"
            ));
            break;
        }
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() > MAX_LINE_BYTES {
            out.warnings.push(format!(
                "{source}: Zeile {} über 64 KiB, übersprungen",
                index + 1
            ));
        } else if let Ok(text) = std::str::from_utf8(line) {
            if !text.trim().is_empty() {
                let mut f =
                    Finding::new("powershell", format!("Verlaufszeile {}", index + 1), source)
                        .with("art", "psreadline_zeile")
                        .with("eingabe", text)
                        .with("zeile", (index + 1).to_string())
                        .with("datei_offset", offset.to_string())
                        .with("datei_laenge", line.len().to_string())
                        .with(
                            "fortsetzung",
                            if text.ends_with('`') { "ja" } else { "nein" },
                        )
                        .with("zeitstatus", "im Verlauf nicht gespeichert")
                        .with("ausfuehrungsstatus", "durch Verlauf allein nicht belegt");
                if let Some(user) = user {
                    f = f.with("profil", user);
                }
                out.findings.push(f);
            }
        }
        offset += raw.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn originalpositionen_und_mehrzeilige_eingaben() {
        let data = "\u{feff}Get-Date\r\n\r\nWrite-Output `\n 'Grüße'".as_bytes();
        let result = parse_powershell_history(data, "Users\\alice\\ConsoleHost_history.txt");
        assert!(result.warnings.is_empty());
        assert_eq!(result.findings.len(), 3);
        for f in &result.findings {
            let start: usize = f.attributes["datei_offset"].parse().unwrap();
            let len: usize = f.attributes["datei_laenge"].parse().unwrap();
            assert_eq!(
                &data[start..start + len],
                f.attributes["eingabe"].as_bytes()
            );
            assert!(f.offset.is_none());
            assert_eq!(f.attributes["profil"], "alice");
        }
        assert_eq!(result.findings[1].attributes["zeile"], "3");
        assert_eq!(result.findings[1].attributes["fortsetzung"], "ja");
        assert!(crate::build_timeline(&result.findings).is_empty());
    }

    #[test]
    fn grenzen_und_kodierung() {
        assert!(!parse_powershell_history(&[0xff, 0xfe], "x")
            .warnings
            .is_empty());
        assert!(parse_powershell_history(b"", "x").findings.is_empty());
        let mut data = vec![b'x'; MAX_LINE_BYTES + 1];
        data.extend_from_slice(b"\nGet-Date");
        let result = parse_powershell_history(&data, "x");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.warnings.len(), 1);
        let result = parse_powershell_history(&b"x\n".repeat(MAX_LINES + 1), "x");
        assert_eq!(result.findings.len(), MAX_LINES);
        assert_eq!(result.warnings.len(), 1);
        assert!(
            !parse_powershell_history(&vec![b'x'; MAX_FILE_BYTES + 1], "x")
                .warnings
                .is_empty()
        );
    }

    #[test]
    fn gezielte_dateiauswahl() {
        assert!(history_path("Users\\a\\ConsoleHost_history.txt"));
        assert!(history_path(
            "Users/a/PSReadLine/Visual Studio Code Host_history.txt"
        ));
        assert!(!history_path("Users\\a\\browser_history.txt"));
        assert!(!history_path("Users\\a\\ConsoleHost_history.txt.exe"));
    }
}
