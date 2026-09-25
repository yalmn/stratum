//! Domäne „Programmausführung": Belege dafür, dass Programme existierten oder
//! ausgeführt wurden, aus Amcache und Shimcache (AppCompatCache).
//!
//! Beide ergänzen Prefetch: Amcache (`Amcache.hve`) verzeichnet installierte und
//! ausgeführte Programme mit Pfad und Zeitpunkt, Shimcache (im SYSTEM-Hive)
//! listet Programme, die dem Kompatibilitäts-Cache bekannt wurden.

use stratum_registry::Hive;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für Amcache und Shimcache.
pub struct ProgramExecutionAnalyzer;

impl Analyzer for ProgramExecutionAnalyzer {
    fn domain(&self) -> &str {
        "programmausfuehrung"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for inst in &ctx.installs {
            if let Some(bytes) = &inst.hives.amcache {
                match Hive::parse(bytes) {
                    Ok(hive) => amcache(&hive, &mut out),
                    Err(e) => out.warnings.push(format!("Amcache nicht lesbar: {e}")),
                }
            }
            if let Some(bytes) = &inst.hives.system {
                match Hive::parse(bytes) {
                    Ok(hive) => shimcache(&hive, &mut out),
                    Err(e) => out
                        .warnings
                        .push(format!("SYSTEM (Shimcache) nicht lesbar: {e}")),
                }
            }
        }
        out
    }
}

/// Amcache: `Root\InventoryApplicationFile` (Windows 10/11). Jeder Unterschlüssel
/// ist ein Programm mit Pfad und Zeitpunkt.
fn amcache(hive: &Hive, out: &mut Outcome) {
    let Ok(Some(root)) = hive.open_key("Root\\InventoryApplicationFile") else {
        return;
    };
    let Ok(entries) = root.subkeys() else { return };
    for e in entries {
        let path = e
            .value("LowerCaseLongPath")
            .ok()
            .flatten()
            .and_then(|v| v.as_string());
        let Some(path) = path else { continue };
        let mut f =
            Finding::new("programmausfuehrung", path.clone(), path).with("quelle", "amcache");
        if let Some(u) = filetime_to_unix(e.last_written()) {
            f = f.with("registriert_unix", u.to_string());
        }
        if let Some(sha1) = e.value("FileId").ok().flatten().and_then(|v| v.as_string()) {
            // FileId ist der SHA-1 mit vier führenden Nullen.
            let sha1 = sha1.trim_start_matches('0');
            if !sha1.is_empty() {
                f = f.with("sha1", sha1.to_string());
            }
        }
        out.findings.push(f);
    }
}

/// Shimcache: `...\Control\Session Manager\AppCompatCache` Wert `AppCompatCache`
/// (Windows-10-Format mit `10ts`-Einträgen).
fn shimcache(system: &Hive, out: &mut Outcome) {
    let cs = current_control_set(system);
    let path = format!("{cs}\\Control\\Session Manager\\AppCompatCache");
    let Ok(Some(key)) = system.open_key(&path) else {
        return;
    };
    let Ok(Some(value)) = key.value("AppCompatCache") else {
        return;
    };
    for (prog, ft) in parse_shimcache_win10(value.data()) {
        let mut f =
            Finding::new("programmausfuehrung", prog.clone(), prog).with("quelle", "shimcache");
        if let Some(u) = ft.and_then(filetime_to_unix) {
            f = f.with("letzte_aenderung_unix", u.to_string());
        }
        out.findings.push(f);
    }
}

/// Parst das Windows-10-Shimcache-Format (`10ts`-Einträge). Liefert je Eintrag
/// den Pfad und die letzte Änderungszeit als FILETIME. Defensiv: bei jeder
/// Unstimmigkeit bricht das Parsen ab, statt Müll zu liefern.
fn parse_shimcache_win10(blob: &[u8]) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    if blob.len() < 4 {
        return out;
    }
    let header_size = le32(blob, 0) as usize;
    // Plausibler Header (Win10 = 0x34) und innerhalb des Blobs.
    if header_size < 4 || header_size > blob.len() {
        return out;
    }
    let mut pos = header_size;
    while pos + 12 <= blob.len() {
        if &blob[pos..pos + 4] != b"10ts" {
            break;
        }
        let cell_size = le32(blob, pos + 8) as usize;
        let path_len = le16(blob, pos + 12) as usize;
        let path_start = pos + 14;
        let Some(path_raw) = blob.get(path_start..path_start + path_len) else {
            break;
        };
        let path = utf16(path_raw);
        // Nach dem Pfad folgt die FILETIME der letzten Änderung.
        let ft = blob
            .get(path_start + path_len..path_start + path_len + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
        if !path.is_empty() {
            out.push((path, ft));
        }
        // Naechster Eintrag: cell_size zaehlt ab Offset pos+12.
        let next = pos + 12 + cell_size;
        if next <= pos || out.len() > 100_000 {
            break;
        }
        pos = next;
    }
    out
}

fn current_control_set(system: &Hive) -> String {
    let n = system
        .open_key("Select")
        .ok()
        .flatten()
        .and_then(|k| k.value("Current").ok().flatten())
        .and_then(|v| v.as_u32())
        .unwrap_or(1);
    format!("ControlSet{n:03}")
}

fn utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn filetime_to_unix(ft: u64) -> Option<i64> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let t = ft.checked_sub(EPOCH_DIFF)?;
    Some((t / 10_000_000) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn shimcache_win10_eintrag() {
        let path = utf16le("C:\\Windows\\notepad.exe");
        let mut blob = Vec::new();
        // Header (0x34 Bytes), Inhalt egal.
        blob.extend_from_slice(&0x34u32.to_le_bytes());
        blob.resize(0x34, 0);
        // Ein 10ts-Eintrag.
        let ft: u64 = 132_539_328_000_000_000; // 2021-01-01
        let mut entry = Vec::new();
        entry.extend_from_slice(b"10ts");
        entry.extend_from_slice(&0u32.to_le_bytes()); // unbekannt
                                                      // cell_size: ab Offset +12, also path_len(2) + path + ft(8) + datalen(4)
        let cell_size = 2 + path.len() + 8 + 4;
        entry.extend_from_slice(&(cell_size as u32).to_le_bytes());
        entry.extend_from_slice(&(path.len() as u16).to_le_bytes());
        entry.extend_from_slice(&path);
        entry.extend_from_slice(&ft.to_le_bytes());
        entry.extend_from_slice(&0u32.to_le_bytes()); // datalen
        blob.extend_from_slice(&entry);

        let parsed = parse_shimcache_win10(&blob);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, "C:\\Windows\\notepad.exe");
        assert_eq!(parsed[0].1.and_then(filetime_to_unix), Some(1_609_459_200));
    }

    #[test]
    fn shimcache_müll_bricht_ab() {
        // Kein 10ts nach dem Header -> keine Eintraege, kein Panic.
        let mut blob = 0x34u32.to_le_bytes().to_vec();
        blob.resize(0x34 + 16, 0xAB);
        assert!(parse_shimcache_win10(&blob).is_empty());
        // Zu kurz.
        assert!(parse_shimcache_win10(&[0, 0]).is_empty());
    }
}
