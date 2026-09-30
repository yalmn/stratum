//! Domäne „VSS": erkennt und listet Volume Shadow Copies (Schattenkopien).
//!
//! Gelesen mit dem eigenen Parser (Crate `stratum-vss`), blockweise gegen
//! libvshadow geprüft. Je Schattenkopie ein Fund mit Kennungen, Zeitpunkt,
//! Attributen und Zahl der Blockdeskriptoren. Die Nummer (`VSS#n`) zählt nach
//! Erstellungszeit, 1 ist die älteste.
//!
//! Dazu je Datei, die in einem Snapshot vom Live-Stand abweicht, ein Fund
//! (`art` = `vss_datei`): nur im Snapshot vorhanden, Inhalt abweichend oder
//! nicht prüfbar, mit Metadaten aus Snapshot und Live-Stand. Der Image-Offset
//! zeigt auf den MFT-Datensatz im Snapshot, aufgelöst über den Store.

use stratum_core::time::filetime_to_iso;
use stratum_ntfs::RecordInfo;
use stratum_vss::{guid, Location, Volume};

use crate::schatten::Abweichung;
use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Obergrenze für Abgleich-Funde.
const MAX_ABGLEICH: usize = 200_000;

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
                if let Some((_, _, n)) = ctx
                    .snapshot_dateien
                    .iter()
                    .find(|(o, s, _)| *o == target.offset && *s == info.index)
                {
                    let zahl = |st: &str| {
                        ctx.abweichungen
                            .iter()
                            .filter(|a| {
                                a.volume_offset == target.offset
                                    && a.store == info.index
                                    && a.status.name() == st
                            })
                            .count()
                            .to_string()
                    };
                    f = f
                        .with("dateien_im_snapshot", n.to_string())
                        .with("nur_im_snapshot", zahl("nur_im_snapshot"))
                        .with("inhalt_abweichend", zahl("inhalt_abweichend"))
                        .with("nicht_pruefbar", zahl("nicht_pruefbar"));
                }
                out.findings.push(f);
            }
        }
        for (i, a) in ctx.abweichungen.iter().enumerate() {
            if i >= MAX_ABGLEICH {
                out.warnings.push(format!(
                    "{} weitere abweichende Dateien in Schattenkopien nicht einzeln gemeldet",
                    ctx.abweichungen.len() - MAX_ABGLEICH
                ));
                break;
            }
            let mut f = abgleich(a);
            let vss = ctx
                .schatten
                .iter()
                .find(|s| s.target.offset == a.volume_offset);
            let record = a.snapshot.as_ref().and_then(|i| i.record_offset);
            if let (Some(s), Some(r)) = (vss, record) {
                if let Ok((Location::Volume { offset, .. }, _)) = s.vss.locate(a.store, r) {
                    f = f.at(a.volume_offset + offset);
                }
            }
            out.findings.push(f);
        }
        out
    }
}

fn zeiten(mut f: Finding, praefix: &str, info: &RecordInfo) -> Finding {
    if let Some(t) = info.si_times {
        for (name, ft) in [
            ("erstellt", t.created),
            ("geaendert", t.modified),
            ("mft_geaendert", t.mft_modified),
            ("zugriff", t.accessed),
        ] {
            if let Some(iso) = filetime_to_iso(ft) {
                f = f.with(format!("{praefix}{name}_utc"), iso);
            }
        }
    }
    if let Some(g) = info.data_size {
        f = f.with(format!("{praefix}groesse"), g.to_string());
    }
    f.with(format!("{praefix}sequenz"), info.sequence.to_string())
}

/// Fund zu einer abweichenden Datei.
fn abgleich(a: &Abweichung) -> Finding {
    let e = &a.eintrag;
    let name = e.path.rsplit('\\').next().unwrap_or(&e.path);
    let mut f = Finding::new("vss", name, &e.path)
        .with("art", "vss_datei")
        .with("status", a.status.name())
        .with("herkunft", format!("VSS#{}", a.store + 1))
        .with("vss_volume_offset", a.volume_offset.to_string())
        .with("mft_record", e.mft_record.to_string())
        .with("parent_record", e.parent_record.to_string());
    if let Some(i) = &a.snapshot {
        f = zeiten(f, "", i);
    }
    if let Some(i) = &a.live {
        f = zeiten(f, "live_", i).with("live_mft_record", i.mft_record.to_string());
    }
    if let Some(h) = &a.hinweis {
        f = f.with("hinweis", h);
    }
    if e.path.starts_with('$') {
        f = f.with("ntfs_metadatei", "ja");
    }
    f
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
