//! Einzelne Dateien aus dem Image lesen: Ausschnitt (Hex-Ansicht), Hash
//! oder vollständiger Inhalt (Export). Das Image wird nur lesend geöffnet;
//! die Datei ist über Volume-Offset und MFT-Datensatz bestimmt, wie im
//! Dateikatalog.

use std::io::Write;
use std::path::Path;

use stratum_analysis::NtfsTarget;
use stratum_core::{HashingWriter, ImageReader};
use stratum_ntfs::NtfsVolume;

use crate::{ntfs_targets, Kontext, LaufFehler};

/// Höchstens so viele Bytes liefert ein Ausschnitt.
pub const FENSTER_MAX: u64 = 64 * 1024;

/// Welche Datei: Image, gegebenenfalls bdp.info, Volume und Datensatz.
#[derive(Debug, Clone)]
pub struct DateiOrt<'a> {
    /// Pfad des Images (Rohimage oder E01).
    pub image: &'a Path,
    /// bdp.info, falls das Volume nur damit gefunden wird.
    pub bdp: Option<&'a Path>,
    /// Byte-Offset des Volumes im Image.
    pub volume_offset: u64,
    /// MFT-Datensatznummer.
    pub mft: u64,
}

/// Ergebnis eines vollständigen Lesens.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DateiHashes {
    /// Gelesene Bytes.
    pub bytes: u64,
    /// SHA-256 (hex).
    pub sha256: String,
    /// BLAKE3 (hex).
    pub blake3: String,
    /// Größe laut Datenstrom.
    pub groesse: u64,
    /// Gültige Datenlänge, falls kleiner als die Größe.
    pub gueltige_laenge: Option<u64>,
    /// WOF-Verfahren, falls entpackt.
    pub wof: Option<&'static str>,
}

fn ziel(targets: &[NtfsTarget], offset: u64) -> Option<NtfsTarget> {
    targets.iter().find(|t| t.offset == offset).cloned()
}

/// Öffnet das Image und das Volume; ohne Treffer in der Partitionssuche
/// wird die bdp.info versucht.
fn oeffnen<'a>(
    img: &'a ImageReader,
    o: &DateiOrt<'_>,
) -> Result<NtfsVolume<stratum_core::ImageCursor<'a>>, LaufFehler> {
    let mut t = ziel(&ntfs_targets(img, None)?, o.volume_offset);
    if t.is_none() {
        if let Some(b) = o.bdp {
            t = ziel(&ntfs_targets(img, Some(b))?, o.volume_offset);
        }
    }
    let t = t.ok_or_else(|| {
        LaufFehler::Eingabe(format!("kein NTFS-Volume bei Offset {}", o.volume_offset))
    })?;
    NtfsVolume::open(img, t.offset, t.size)
        .kontext(|| format!("NTFS-Volume bei {} nicht lesbar", t.offset))
}

/// Prüft, dass Image und Volume lesbar sind, ohne die Datei zu lesen.
pub fn pruefen(o: &DateiOrt<'_>) -> Result<(), LaufFehler> {
    let img = ImageReader::open(o.image)
        .kontext(|| format!("Image nicht lesbar: {}", o.image.display()))?;
    oeffnen(&img, o).map(|_| ())
}

/// Schreibt den Inhalt der Datei nach `out` und liefert die Hashes.
pub fn schreiben<W: Write>(o: &DateiOrt<'_>, out: W) -> Result<(W, DateiHashes), LaufFehler> {
    let img = ImageReader::open(o.image)
        .kontext(|| format!("Image nicht lesbar: {}", o.image.display()))?;
    let mut vol = oeffnen(&img, o)?;
    let mut w = HashingWriter::new(out);
    let prefetch = |offset: u64, len: u64| img.prefetch(offset, len);
    let meta = vol
        .write_file_by_record(o.mft, "", &prefetch, &mut w)
        .kontext(|| format!("MFT-Datensatz {} nicht lesbar", o.mft))?
        .ok_or_else(|| LaufFehler::Eingabe(format!("MFT-Datensatz {} hat keinen Inhalt", o.mft)))?;
    let (out, h) = w.finish().kontext(|| "Schreiben fehlgeschlagen".into())?;
    Ok((
        out,
        DateiHashes {
            bytes: h.bytes,
            sha256: h.sha256,
            blake3: h.blake3,
            groesse: meta.size,
            gueltige_laenge: meta.valid_size,
            wof: meta.wof,
        },
    ))
}

/// Liefert höchstens [`FENSTER_MAX`] Bytes ab `offset`. Gelesen wird ab dem
/// Anfang der Datei; nach dem Fenster bricht das Lesen ab.
pub fn ausschnitt(o: &DateiOrt<'_>, offset: u64, laenge: u64) -> Result<Vec<u8>, LaufFehler> {
    let laenge = laenge.min(FENSTER_MAX);
    let img = ImageReader::open(o.image)
        .kontext(|| format!("Image nicht lesbar: {}", o.image.display()))?;
    let mut vol = oeffnen(&img, o)?;
    let mut f = Fenster {
        von: offset,
        bis: offset.saturating_add(laenge),
        pos: 0,
        daten: Vec::with_capacity(laenge as usize),
    };
    let prefetch = |offset: u64, len: u64| img.prefetch(offset, len);
    match vol.write_file_by_record(o.mft, "", &prefetch, &mut f) {
        Ok(_) => Ok(f.daten),
        // Das Fenster ist voll: gewollter Abbruch.
        Err(_) if f.pos >= f.bis => Ok(f.daten),
        Err(e) => Err(LaufFehler::Schritt {
            kontext: format!("MFT-Datensatz {} nicht lesbar", o.mft),
            quelle: Box::new(e),
        }),
    }
}

/// Behält nur die Bytes im Bereich `von..bis` und meldet danach einen Fehler,
/// damit das Lesen nicht bis zum Dateiende weiterläuft.
struct Fenster {
    von: u64,
    bis: u64,
    pos: u64,
    daten: Vec<u8>,
}

impl Write for Fenster {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.pos >= self.bis {
            return Err(std::io::Error::other("Fenster voll"));
        }
        let anfang = self.pos;
        let ende = anfang + buf.len() as u64;
        if ende > self.von {
            let a = self.von.saturating_sub(anfang) as usize;
            let b = (self.bis.min(ende) - anfang) as usize;
            self.daten.extend_from_slice(&buf[a..b]);
        }
        self.pos = ende;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fenster_schneidet_und_bricht_ab() {
        let mut f = Fenster {
            von: 5,
            bis: 12,
            pos: 0,
            daten: Vec::new(),
        };
        f.write_all(b"0123").unwrap();
        f.write_all(b"456789").unwrap();
        f.write_all(b"abcdef").unwrap();
        assert_eq!(f.daten, b"56789ab");
        assert!(f.write_all(b"x").is_err());
    }
}
