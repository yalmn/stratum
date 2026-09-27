//! Gezielte Extraktion einer einzelnen Datei mit Herkunftsnachweis.
//!
//! Neben die Zieldatei wird `<ZIEL>.herkunft.json` geschrieben: Quelle im Image,
//! Hashes des extrahierten Inhalts, Zeitstempel der Datei (Artefaktzeit) und
//! der Zeitpunkt der Extraktion (Untersuchungszeit), klar getrennt. Vorhandene
//! Dateien werden nie überschrieben.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use stratum_analysis::NtfsTarget;
use stratum_core::time::filetime_to_iso;
use stratum_core::{hash_bytes, ImageHashes, ImageReader};
use stratum_ntfs::{FileData, NtfsVolume};

use crate::report::Tool;

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
    abgeschnitten: bool,
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

    let (volume_offset, file) = find(img, targets, &sel)?;
    let hashes: ImageHashes = hash_bytes(&file.data);
    let abgeschnitten = (file.data.len() as u64) < file.meta.size;

    create_new(out)?
        .write_all(&file.data)
        .with_context(|| format!("Zieldatei nicht schreibbar: {}", out.display()))?;

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
            mft_record: file.meta.mft_record,
            mft_record_offset: file.meta.record_offset,
            pfad: &file.meta.path,
            strom: match file.meta.wof {
                Some(format) => format!(
                    "{} entpackt ({format}), Größe laut unbenanntem $DATA",
                    stratum_ntfs::wof::WOF_STREAM
                ),
                None => "$DATA (unbenannt)".to_string(),
            },
        },
        inhalt: Inhalt {
            groesse_strom: file.meta.size,
            geschrieben: hashes.bytes,
            abgeschnitten,
            sha256: hashes.sha256,
            blake3: hashes.blake3,
        },
        artefaktzeiten_si: Zeiten {
            erstellt: filetime_to_iso(file.meta.created),
            geaendert: filetime_to_iso(file.meta.modified),
            mft_geaendert: filetime_to_iso(file.meta.mft_modified),
            zugriff: filetime_to_iso(file.meta.accessed),
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
        file.data.len(),
        out.display(),
        volume_offset,
        file.meta.mft_record,
        sidecar.display()
    );
    if abgeschnitten {
        eprintln!(
            "[!] Datei ist {} Bytes groß, extrahiert wurden nur {} Bytes (Obergrenze {} Bytes)",
            file.meta.size,
            file.data.len(),
            stratum_ntfs::MAX_FILE_SIZE
        );
    }
    Ok(())
}

fn find(img: &ImageReader, targets: &[NtfsTarget], sel: &Selector) -> Result<(u64, FileData)> {
    match *sel {
        Selector::Path(path) => {
            for t in targets {
                let Ok(mut vol) = NtfsVolume::open(img, t.offset, t.size) else {
                    continue;
                };
                if let Ok(Some(file)) = vol.read_file(path) {
                    return Ok((t.offset, file));
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
            let mut vol = NtfsVolume::open(img, t.offset, t.size)
                .with_context(|| format!("Volume bei Offset {volume_offset} nicht lesbar"))?;
            let file = vol
                .read_file_by_record(mft, "")
                .with_context(|| format!("MFT-Datensatz {mft} nicht lesbar"))?
                .with_context(|| format!("MFT-Datensatz {mft} hat keinen Inhalt"))?;
            Ok((volume_offset, file))
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
