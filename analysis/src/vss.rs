//! Domäne „VSS": erkennt und listet Volume Shadow Copies (Schattenkopien).
//!
//! Schattenkopien enthalten frühere Zustände des Dateisystems und sind
//! forensisch sehr wertvoll (gelöschte oder veränderte Dateien). Dieser
//! Analyzer meldet, welche Schattenkopien vorhanden sind und wann sie angelegt
//! wurden.
//!
//! Das vollständige Wiederherstellen einer Schattenkopie (jeden Snapshot als
//! zusätzliches Volume behandeln und die Datei-Analyzer erneut darauf laufen
//! lassen) ist ein grösserer, eigener Ausbauschritt und hier noch nicht
//! umgesetzt.

use std::io::Cursor;

use vshadow::VssVolume;

use stratum_core::Guid;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für Volume Shadow Copies.
pub struct VssAnalyzer;

impl Analyzer for VssAnalyzer {
    fn domain(&self) -> &str {
        "vss"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        let data = ctx.img.as_slice();

        for target in &ctx.ntfs_targets {
            let start = target.offset as usize;
            let end = match start.checked_add(target.size as usize) {
                Some(e) if e <= data.len() => e,
                _ => continue,
            };
            let mut cursor = Cursor::new(&data[start..end]);

            // Kein VSS-Katalog vorhanden -> kein Fehler, nur keine Funde.
            let Ok(vss) = VssVolume::new(&mut cursor) else {
                continue;
            };
            let count = vss.store_count();
            if count == 0 {
                continue;
            }

            for i in 0..count {
                let Ok(info) = vss.store_info(i) else {
                    continue;
                };
                let mut f = Finding::new(
                    "vss",
                    format!("Schattenkopie {}", Guid(info.store_id)),
                    format!("Offset {}", target.offset),
                )
                .with("nummer", (i + 1).to_string())
                .with("volume_groesse", info.volume_size.to_string())
                .with("sequenz", info.sequence.to_string());
                if let Some(u) = filetime_to_unix(info.creation_time) {
                    f = f.with("erstellt_unix", u.to_string());
                }
                out.findings.push(f);
            }
        }
        out
    }
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
    fn filetime_umrechnung() {
        assert_eq!(
            filetime_to_unix(132_539_328_000_000_000),
            Some(1_609_459_200)
        );
        assert_eq!(filetime_to_unix(0), None);
    }

    #[test]
    fn guid_darstellung() {
        let g = Guid([
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ]);
        assert_eq!(g.to_string(), "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    }
}
