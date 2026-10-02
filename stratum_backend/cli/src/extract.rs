//! Gezielte Extraktion einer einzelnen Datei mit Herkunftsnachweis.
//!
//! Neben die Zieldatei wird `<ZIEL>.herkunft.json` geschrieben: Quelle im Image,
//! Hashes des extrahierten Inhalts, Zeitstempel der Datei (Artefaktzeit) und
//! der Zeitpunkt der Extraktion (Untersuchungszeit), klar getrennt. Vorhandene
//! Dateien werden nie überschrieben.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use stratum_analysis::NtfsTarget;
use stratum_core::time::filetime_to_iso;
use stratum_core::{HashingWriter, ImageReader};
use stratum_ntfs::NtfsVolume;

use stratum_lauf::report::Tool;

/// Welche Datei extrahiert werden soll.
pub enum Selector<'a> {
    /// NTFS-Pfad, gesucht in allen Zielbereichen.
    Path(&'a str),
    /// MFT-Datensatz in dem Volume, das bei diesem Offset beginnt.
    Record {
        /// Byte-Offset des Volumes im Image.
        volume_offset: u64,
        /// MFT-Datensatznummer.
        mft: u64,
    },
}

#[derive(Serialize)]
struct Herkunft<'a> {
    werkzeug: Tool,
    image: ImageRef<'a>,
    quelle: Quelle<'a>,
    inhalt: Inhalt,
    artefaktzeiten_si: Zeiten,
    untersuchung: Untersuchung<'a>,
}

#[derive(Serialize)]
struct ImageRef<'a> {
    pfad: String,
    groesse: u64,
    hinweis: &'a str,
}

#[derive(Serialize)]
struct Quelle<'a> {
    volume_offset: u64,
    mft_record: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mft_record_offset: Option<u64>,
    #[serde(skip_serializing_if = "str::is_empty")]
    pfad: &'a str,
    strom: String,
}

#[derive(Serialize)]
struct Inhalt {
    groesse_strom: u64,
    geschrieben: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    gueltige_laenge: Option<u64>,
    sha256: String,
    blake3: String,
}

#[derive(Serialize)]
struct Zeiten {
    erstellt: Option<String>,
    geaendert: Option<String>,
    mft_geaendert: Option<String>,
    zugriff: Option<String>,
}

#[derive(Serialize)]
struct Untersuchung<'a> {
    extrahiert_utc: Option<String>,
    ziel: &'a str,
}

/// Sucht die Datei, schreibt Inhalt und Herkunftsnachweis.
///
/// Der Inhalt wird blockweise gestreamt und dabei gehasht, es gibt also keine
/// Größengrenze. Nur NTFS- und WOF-komprimierte Dateien werden im Speicher
/// entpackt und sind auf [`stratum_ntfs::MAX_FILE_SIZE`] begrenzt; darüber gibt
/// es einen Fehler statt einer gekürzten Datei.
pub fn run(img: &ImageReader, targets: &[NtfsTarget], sel: Selector, out: &Path) -> Result<()> {
    let sidecar = sidecar_path(out);
    for p in [out, sidecar.as_path()] {
        if p.exists() {
            anyhow::bail!(
                "{} existiert bereits, wird nicht überschrieben",
                p.display()
            );
        }
    }

    let (volume_offset, mut vol, mft, path) = find(img, targets, &sel)?;
    let mut writer = HashingWriter::new(BufWriter::with_capacity(1 << 20, create_new(out)?));
    let prefetch = |offset: u64, len: u64| img.prefetch(offset, len);
    let written = vol
        .write_file_by_record(mft, path, &prefetch, &mut writer)
        .map_err(anyhow::Error::from)
        .and_then(|meta| meta.with_context(|| format!("MFT-Datensatz {mft} hat keinen Inhalt")))
        .and_then(|meta| Ok((meta, writer.finish()?)));
    let (meta, hashes) = match written {
        Ok((meta, (_, hashes))) => (meta, hashes),
        Err(error) => {
            // Nur die eben selbst angelegte, unvollständige Zieldatei entfernen,
            // damit kein halber Inhalt wie ein Beweisstück aussieht.
            let _ = std::fs::remove_file(out);
            return Err(error.context(format!("Extraktion von MFT {mft} fehlgeschlagen")));
        }
    };

    let ziel = out.display().to_string();
    let herkunft = Herkunft {
        werkzeug: Tool::default(),
        image: ImageRef {
            pfad: img.path().display().to_string(),
            groesse: img.len(),
            hinweis: "Image-Hash steht im Report des Analyselaufs; hier nicht erneut berechnet",
        },
        quelle: Quelle {
            volume_offset,
            mft_record: meta.mft_record,
            mft_record_offset: meta.record_offset,
            pfad: &meta.path,
            strom: match meta.wof {
                Some(format) => format!(
                    "{} entpackt ({format}), Größe laut unbenanntem $DATA",
                    stratum_ntfs::wof::WOF_STREAM
                ),
                None => "$DATA (unbenannt)".to_string(),
            },
        },
        inhalt: Inhalt {
            groesse_strom: meta.size,
            geschrieben: hashes.bytes,
            gueltige_laenge: meta.valid_size,
            sha256: hashes.sha256,
            blake3: hashes.blake3,
        },
        artefaktzeiten_si: Zeiten {
            erstellt: filetime_to_iso(meta.created),
            geaendert: filetime_to_iso(meta.modified),
            mft_geaendert: filetime_to_iso(meta.mft_modified),
            zugriff: filetime_to_iso(meta.accessed),
        },
        untersuchung: Untersuchung {
            extrahiert_utc: now_filetime().and_then(filetime_to_iso),
            ziel: &ziel,
        },
    };
    let json = serde_json::to_vec_pretty(&herkunft).context("Herkunft nicht serialisierbar")?;
    create_new(&sidecar)?
        .write_all(&json)
        .with_context(|| format!("Herkunftsdatei nicht schreibbar: {}", sidecar.display()))?;

    eprintln!(
        "[+] {} Bytes geschrieben: {} (Volume {}, MFT {}), Herkunft: {}",
        hashes.bytes,
        out.display(),
        volume_offset,
        meta.mft_record,
        sidecar.display()
    );
    eprintln!("[+] SHA-256 {}", herkunft.inhalt.sha256);
    Ok(())
}

type Found<'a> = (u64, NtfsVolume<stratum_core::ImageCursor<'a>>, u64, &'a str);

fn find<'a>(img: &'a ImageReader, targets: &[NtfsTarget], sel: &Selector<'a>) -> Result<Found<'a>> {
    match *sel {
        Selector::Path(path) => {
            for t in targets {
                let Ok(mut vol) = NtfsVolume::open(img, t.offset, t.size) else {
                    continue;
                };
                if let Ok(Some(mft)) = vol.record_of(path) {
                    return Ok((t.offset, vol, mft, path));
                }
            }
            anyhow::bail!("Datei '{path}' in keiner NTFS-Partition gefunden")
        }
        Selector::Record { volume_offset, mft } => {
            let t = targets
                .iter()
                .find(|t| t.offset == volume_offset)
                .with_context(|| {
                    let bekannt: Vec<String> =
                        targets.iter().map(|t| t.offset.to_string()).collect();
                    format!(
                        "kein NTFS-Volume bei Offset {volume_offset} (bekannt: {})",
                        bekannt.join(", ")
                    )
                })?;
            let vol = NtfsVolume::open(img, t.offset, t.size)
                .with_context(|| format!("Volume bei Offset {volume_offset} nicht lesbar"))?;
            Ok((volume_offset, vol, mft, ""))
        }
    }
}

fn create_new(p: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .with_context(|| format!("{} nicht anlegbar (existiert sie bereits?)", p.display()))
}

fn sidecar_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_owned();
    s.push(".herkunft.json");
    PathBuf::from(s)
}

/// Aktuelle Systemzeit als FILETIME. Das ist die Untersuchungszeit, nie eine
/// Zeit aus dem Image.
fn now_filetime() -> Option<u64> {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let ticks = u64::try_from(d.as_nanos() / 100).ok()?;
    ticks.checked_add(116_444_736_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begleitdatei_und_zeit() {
        assert_eq!(
            sidecar_path(Path::new("/tmp/SAM")),
            PathBuf::from("/tmp/SAM.herkunft.json")
        );
        let iso = now_filetime().and_then(filetime_to_iso).unwrap();
        assert!(iso.starts_with("20") && iso.ends_with('Z'));
    }
}
