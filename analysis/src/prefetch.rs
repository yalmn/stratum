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
                    match scca_body(&file.data) {
                        Body::Scca(body, label) => {
                            finding = finding.with("format", label);
                            if let Some(intern) = scca_internal_name(&body) {
                                finding = finding.with("interner_name", intern);
                            }
                            if let Some(info) = scca_run_info(&body) {
                                if let Some(count) = info.run_count {
                                    finding =
                                        finding.with("ausfuehrungszaehler", count.to_string());
                                }
                                if let Some(last) = info.last_run_unix {
                                    finding =
                                        finding.with("letzte_ausfuehrung_unix", last.to_string());
                                }
                                if info.run_times > 0 {
                                    finding = finding
                                        .with("erfasste_laufzeiten", info.run_times.to_string());
                                }
                            }
                        }
                        Body::MamFailed => {
                            finding = finding.with("format", "MAM (Dekompression fehlgeschlagen)");
                        }
                        Body::Unknown => {
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

/// Der SCCA-Inhalt einer Prefetch-Datei, ggf. entpackt.
enum Body {
    /// Entpackter oder unkomprimierter SCCA-Inhalt mit Format-Bezeichnung.
    Scca(Vec<u8>, &'static str),
    /// MAM-Signatur erkannt, aber Dekompression schlug fehl.
    MamFailed,
    /// Kein bekanntes Prefetch-Format.
    Unknown,
}

/// Liefert den SCCA-Inhalt: bei MAM (Windows 10/11) wird er per LZXPRESS-Huffman
/// entpackt, unkomprimierte SCCA-Dateien werden direkt übernommen.
fn scca_body(data: &[u8]) -> Body {
    if data.len() >= 8 && &data[..3] == b"MAM" {
        // Bytes 4..8: unkomprimierte Größe. Ab Byte 8 der komprimierte Strom.
        let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        // Größe gegen einen plausiblen Rahmen begrenzen (Schutz vor
        // manipulierten Headern).
        let size = size.min(16 * 1024 * 1024);
        match xpress_huffman::decompress(&data[8..], size) {
            Ok(body) if body.len() >= 8 && &body[4..8] == b"SCCA" => {
                Body::Scca(body, "MAM (entpackt)")
            }
            _ => Body::MamFailed,
        }
    } else if data.len() >= 8 && &data[4..8] == b"SCCA" {
        Body::Scca(data.to_vec(), "SCCA")
    } else {
        Body::Unknown
    }
}

/// Ausführungsdaten aus der File-Information-Sektion.
struct RunInfo {
    run_count: Option<u32>,
    last_run_unix: Option<i64>,
    run_times: u32,
}

/// Liest Ausführungszähler und Laufzeiten aus dem SCCA-Inhalt. Die Offsets
/// haengen von der Formatversion ab (libscca). Unplausible Werte werden
/// verworfen, damit bei einer Variantenabweichung kein Fehlwert entsteht.
fn scca_run_info(body: &[u8]) -> Option<RunInfo> {
    let version = u32::from_le_bytes(body.get(0..4)?.try_into().ok()?);
    // Zahl der Laufzeiten und Offset des Zaehlers je Version.
    let (times, count_off) = match version {
        23 => (1usize, 0x98usize),
        26 => (8, 0xD0),
        30 => (8, 0xD0),
        31 => (8, 0xC8),
        _ => return None,
    };
    const LAST_RUN: usize = 0x80;

    let mut last_run_unix = None;
    let mut valid_times = 0u32;
    for i in 0..times {
        let off = LAST_RUN + i * 8;
        let Some(raw) = body.get(off..off + 8) else {
            break;
        };
        let ft = u64::from_le_bytes(raw.try_into().unwrap());
        if let Some(u) = plausible_time(ft) {
            valid_times += 1;
            last_run_unix = Some(last_run_unix.map_or(u, |cur: i64| cur.max(u)));
        }
    }

    let run_count = body
        .get(count_off..count_off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .filter(|&c| (1..=1_000_000).contains(&c));

    Some(RunInfo {
        run_count,
        last_run_unix,
        run_times: valid_times,
    })
}

/// FILETIME -> Unix-Sekunden, aber nur wenn der Zeitpunkt zwischen 2000 und 2100
/// liegt (sonst vermutlich falscher Offset).
fn plausible_time(ft: u64) -> Option<i64> {
    let u = filetime_to_unix(ft)?;
    (946_684_800..=4_102_444_800).contains(&u).then_some(u)
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
    fn scca_body_erkennung() {
        // Unkomprimiert.
        let mut scca = vec![0u8; 16];
        scca[4..8].copy_from_slice(b"SCCA");
        assert!(matches!(scca_body(&scca), Body::Scca(_, "SCCA")));
        // Kein Prefetch.
        assert!(matches!(scca_body(b"xxxxxxxx"), Body::Unknown));
        // MAM mit unbrauchbarem Strom -> Dekompression scheitert.
        assert!(matches!(
            scca_body(b"MAM\x04\x08\x00\x00\x00\xff\xff"),
            Body::MamFailed
        ));
    }

    #[test]
    fn run_info_version_30() {
        // Version 30: 8 Laufzeiten ab 0x80, Zaehler bei 0xD0.
        let mut body = vec![0u8; 0xE0];
        body[0..4].copy_from_slice(&30u32.to_le_bytes());
        body[4..8].copy_from_slice(b"SCCA");
        // Eine plausible Laufzeit (2021-01-01) an erster Stelle.
        body[0x80..0x88].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        body[0xD0..0xD4].copy_from_slice(&7u32.to_le_bytes());
        let info = scca_run_info(&body).unwrap();
        assert_eq!(info.run_count, Some(7));
        assert_eq!(info.last_run_unix, Some(1_609_459_200));
        assert_eq!(info.run_times, 1);
    }

    #[test]
    fn run_info_verwirft_unplausibles() {
        let mut body = vec![0u8; 0xE0];
        body[0..4].copy_from_slice(&30u32.to_le_bytes());
        // Laufzeit 0 und absurder Zaehler -> beide verworfen.
        body[0xD0..0xD4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        let info = scca_run_info(&body).unwrap();
        assert_eq!(info.run_count, None);
        assert_eq!(info.last_run_unix, None);
        assert_eq!(info.run_times, 0);
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
