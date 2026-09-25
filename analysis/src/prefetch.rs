//! Domäne „Prefetch": Belege für ausgeführte Programme aus `Windows\Prefetch`.
//!
//! Jede `.pf`-Datei belegt, dass das zugehörige Programm ausgeführt wurde. Der
//! Programmname steht im Dateinamen (`PROG.EXE-<HASH>.pf`), die Ausführungszeit
//! grob im Änderungszeitpunkt der Datei.
//!
//! Zum Dateiformat: Ab Windows 10 sind die `.pf` mit MAM (LZXPRESS Huffman)
//! komprimiert. Ein eigener Dekompressor für den komprimierten Inhalt
//! (Ausführungszähler, exakte Laufzeiten) ist noch nicht umgesetzt; solche
//! Dateien werden als komprimiert gekennzeichnet. Unkomprimierte SCCA-Dateien
//! (Windows 7 und älter) liefern zusätzlich den intern gespeicherten
//! Programmnamen.

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für Prefetch-Dateien.
pub struct PrefetchAnalyzer;

impl Analyzer for PrefetchAnalyzer {
    fn domain(&self) -> &str {
        "prefetch"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();

        for v in &ctx.volumes {
            let entries: Vec<_> = v
                .by_extension(&["pf"])
                .filter(|e| e.path.to_ascii_lowercase().contains("prefetch"))
                .collect();
            if entries.is_empty() {
                continue;
            }
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };

            for e in entries {
                let name = filename(&e.path);
                let programm = executable_from_pf(name).unwrap_or_else(|| name.to_string());

                let mut finding = Finding::new("prefetch", programm, &e.path)
                    .with("art", "ausfuehrung")
                    .with("prefetch_datei", name);

                if let Ok(Some(file)) = vol.read_file_by_record(e.mft_record, &e.path) {
                    if let Some(u) = filetime_to_unix(file.meta.modified) {
                        finding = finding.with("letzte_aenderung_unix", u.to_string());
                    }
                    match format(&file.data) {
                        Format::Mam => {
                            finding = finding
                                .with("format", "MAM (komprimiert)")
                                .with("hinweis", "Inhalt nicht geparst, Dekompressor folgt");
                        }
                        Format::Scca => {
                            finding = finding.with("format", "SCCA");
                            if let Some(intern) = scca_internal_name(&file.data) {
                                finding = finding.with("interner_name", intern);
                            }
                        }
                        Format::Unknown => {
                            finding = finding.with("format", "unbekannt");
                        }
                    }
                }
                out.findings.push(finding);
            }
        }
        out
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Format {
    /// MAM-komprimiert (Windows 10/11).
    Mam,
    /// Unkomprimiert (Windows 7 und älter).
    Scca,
    /// Weder das eine noch das andere.
    Unknown,
}

/// Erkennt das Prefetch-Format an der Signatur.
fn format(data: &[u8]) -> Format {
    if data.len() >= 4 && &data[..3] == b"MAM" {
        Format::Mam
    } else if data.len() >= 8 && &data[4..8] == b"SCCA" {
        Format::Scca
    } else {
        Format::Unknown
    }
}

/// Der intern gespeicherte Programmname aus einer unkomprimierten SCCA-Datei
/// (UTF-16LE ab Offset 0x10, bis zu 60 Zeichen).
fn scca_internal_name(data: &[u8]) -> Option<String> {
    let raw = data.get(0x10..0x10 + 60)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

/// Letzter Pfadteil.
fn filename(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// Programmname aus einem Prefetch-Dateinamen: `NOTEPAD.EXE-D8414F97.pf` ->
/// `NOTEPAD.EXE`. Gibt `None`, wenn der Name nicht dem Muster entspricht.
fn executable_from_pf(name: &str) -> Option<String> {
    let stem = name
        .strip_suffix(".pf")
        .or_else(|| name.strip_suffix(".PF"))?;
    let dash = stem.rfind('-')?;
    let (exe, hash) = stem.split_at(dash);
    let hash = &hash[1..];
    // Der Hash ist 7 bis 8 Hex-Ziffern.
    if exe.is_empty() || hash.len() < 7 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(exe.to_string())
}

/// FILETIME (100-ns seit 1601) -> Unix-Sekunden, `None` vor 1970.
fn filetime_to_unix(ft: u64) -> Option<i64> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let t = ft.checked_sub(EPOCH_DIFF)?;
    Some((t / 10_000_000) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programmname_aus_pf() {
        assert_eq!(
            executable_from_pf("NOTEPAD.EXE-D8414F97.pf").as_deref(),
            Some("NOTEPAD.EXE")
        );
        assert_eq!(
            executable_from_pf("cmd.exe-0a1b2c3d4.pf").as_deref(),
            Some("cmd.exe")
        );
        // Kein gueltiges Muster.
        assert_eq!(executable_from_pf("layout.ini"), None);
        assert_eq!(executable_from_pf("readme.pf"), None);
    }

    #[test]
    fn format_erkennung() {
        assert_eq!(format(b"MAM\x04\x00\x00\x00\x00"), Format::Mam);
        let mut scca = vec![0u8; 16];
        scca[4..8].copy_from_slice(b"SCCA");
        assert_eq!(format(&scca), Format::Scca);
        assert_eq!(format(b"xxxx"), Format::Unknown);
    }

    #[test]
    fn scca_name_ausgelesen() {
        let mut data = vec![0u8; 0x10 + 60];
        data[4..8].copy_from_slice(b"SCCA");
        let name: Vec<u8> = "CMD.EXE"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        data[0x10..0x10 + name.len()].copy_from_slice(&name);
        assert_eq!(scca_internal_name(&data).as_deref(), Some("CMD.EXE"));
    }

    #[test]
    fn filetime_umrechnung() {
        // 2021-01-01T00:00:00Z
        assert_eq!(
            filetime_to_unix(132_539_328_000_000_000),
            Some(1_609_459_200)
        );
        assert_eq!(filetime_to_unix(0), None);
    }
}
