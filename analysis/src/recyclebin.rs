//! Papierkorb: gelöschte Dateien aus den `$I`-Metadaten.
//!
//! Ab Windows Vista liegt je gelöschter Datei im Papierkorb ein Paar: `$R...`
//! enthält den Inhalt, `$I...` die Metadaten (Originalpfad, Originalgröße,
//! Löschzeitpunkt). Dieser Analyzer liest die `$I`-Dateien unter
//! `\$Recycle.Bin\<SID>` über den Pfad-Index.

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, FsIndex, Outcome};

/// Analyzer für den Papierkorb.
pub struct RecycleBinAnalyzer;

impl Analyzer for RecycleBinAnalyzer {
    fn domain(&self) -> &str {
        "papierkorb"
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
            recycle(&mut vol, v, &mut out);
        }
        out
    }
}

fn recycle<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    let dateien: Vec<_> = v
        .under("$Recycle.Bin")
        .filter(|e| {
            e.path
                .rsplit('\\')
                .next()
                .map(|n| n.starts_with("$I"))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    for e in dateien {
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let Some(info) = parse_i(&f.data) else {
            out.warnings
                .push(format!("{}: $I-Metadaten unlesbar", e.path));
            continue;
        };
        // Die SID steht als Ordner direkt unter $Recycle.Bin.
        let sid = e
            .path
            .split('\\')
            .nth(1)
            .filter(|s| s.starts_with("S-1-"))
            .unwrap_or("");
        let mut fd = Finding::new("papierkorb", &info.original_path, &e.path)
            .with("art", "geloeschte_datei")
            .with("originalgroesse", info.size.to_string());
        if !sid.is_empty() {
            fd = fd.with("sid", sid);
        }
        if let Some(z) = info.deleted_unix {
            fd = fd.with("geloescht_unix", z.to_string());
        }
        out.findings.push(fd);
    }
}

/// Ausgewertete `$I`-Metadaten.
struct RecycledInfo {
    original_path: String,
    size: u64,
    deleted_unix: Option<i64>,
}

/// Liest eine `$I`-Metadatendatei (Windows Vista bis 11).
fn parse_i(data: &[u8]) -> Option<RecycledInfo> {
    let version = u64::from_le_bytes(data.get(0..8)?.try_into().ok()?);
    let size = u64::from_le_bytes(data.get(8..16)?.try_into().ok()?);
    let ft = u64::from_le_bytes(data.get(16..24)?.try_into().ok()?);
    let deleted_unix = if ft == 0 {
        None
    } else {
        stratum_registry::filetime_to_unix(ft).map(|(s, _)| s)
    };

    let original_path = match version {
        1 => {
            // Fester Pfad von 260 UTF-16-Zeichen ab Offset 24.
            let raw = data
                .get(24..24 + 520)
                .unwrap_or(&data[24.min(data.len())..]);
            utf16z(raw)
        }
        2 => {
            // Längenpräfix (Zeichen inkl. Null) ab Offset 24, dann der Pfad.
            let len = u32::from_le_bytes(data.get(24..28)?.try_into().ok()?) as usize;
            let bytes = len.checked_mul(2)?;
            let raw = data.get(28..28 + bytes)?;
            utf16z(raw)
        }
        _ => return None,
    };
    if original_path.is_empty() {
        return None;
    }
    Some(RecycledInfo {
        original_path,
        size,
        deleted_unix,
    })
}

/// UTF-16LE bis zur ersten Null.
fn utf16z(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn parse_version2() {
        let mut d = Vec::new();
        d.extend_from_slice(&2u64.to_le_bytes()); // Version
        d.extend_from_slice(&12345u64.to_le_bytes()); // Groesse
        d.extend_from_slice(&(133_800_000_000_000_000u64).to_le_bytes()); // FILETIME ~2025
        let path = "C:\\Users\\ich\\geheim.docx";
        let chars = path.encode_utf16().count() as u32 + 1;
        d.extend_from_slice(&chars.to_le_bytes());
        d.extend_from_slice(&utf16(path));
        d.extend_from_slice(&[0, 0]);
        let info = parse_i(&d).unwrap();
        assert_eq!(info.original_path, path);
        assert_eq!(info.size, 12345);
        assert!(info.deleted_unix.unwrap() > 1_700_000_000);
    }

    #[test]
    fn parse_version1_fester_pfad() {
        let mut d = Vec::new();
        d.extend_from_slice(&1u64.to_le_bytes());
        d.extend_from_slice(&99u64.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes()); // keine Zeit
        let path = "D:\\x\\y.txt";
        let mut p = utf16(path);
        p.resize(520, 0);
        d.extend_from_slice(&p);
        let info = parse_i(&d).unwrap();
        assert_eq!(info.original_path, path);
        assert_eq!(info.deleted_unix, None);
    }
}
