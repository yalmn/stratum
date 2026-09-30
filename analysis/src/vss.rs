//! Domäne „VSS": erkennt und listet Volume Shadow Copies (Schattenkopien).
//!
//! Gelesen mit dem eigenen Parser (Crate `stratum-vss`), blockweise gegen
//! libvshadow geprüft. Je Schattenkopie ein Fund mit Kennungen, Zeitpunkt,
//! Attributen und Zahl der Blockdeskriptoren. Die Nummer (`VSS#n`) zählt nach
//! Erstellungszeit, 1 ist die älteste.

use stratum_core::time::filetime_to_iso;
use stratum_vss::{guid, Volume};

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
            let vss = match Volume::open(&data[start..end]) {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) => {
                    out.warnings.push(format!(
                        "Offset {}: Schattenkopien nicht lesbar: {e}",
                        target.offset
                    ));
                    continue;
                }
            };
            for w in vss.warnings() {
                out.warnings.push(format!("Offset {}: {w}", target.offset));
            }
            for info in vss.stores() {
                let mut f = Finding::new(
                    "vss",
                    format!("Schattenkopie {}", guid(&info.id)),
                    format!("Offset {}", target.offset),
                )
                .with("nummer", (info.index + 1).to_string())
                .with("store_id", guid(&info.id))
                .with("volume_groesse", info.volume_size.to_string())
                .with("sequenz", info.sequence.to_string())
                .with("blockdeskriptoren", info.block_descriptors.to_string())
                .with("vss_version", vss.version().to_string())
                .with("volume_offset", target.offset.to_string());
                if let Some(u) = filetime_to_unix(info.creation_time) {
                    f = f.with("erstellt_unix", u.to_string());
                }
                if let Some(iso) = filetime_to_iso(info.creation_time) {
                    f = f.with("erstellt_utc", iso);
                }
                if let Some(id) = &info.copy_id {
                    f = f.with("schattenkopie_id", guid(id));
                }
                if let Some(id) = &info.copy_set_id {
                    f = f.with("satz_id", guid(id));
                }
                if let Some(a) = info.attribute_flags {
                    f = f.with("attribute", format!("{a:#010x}"));
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
}
