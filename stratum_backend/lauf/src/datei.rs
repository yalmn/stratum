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

/// Kopiert höchstens `limit` Bytes einer Datei ohne Hashing in eine Arbeitskopie.
/// Teilkopien werden bei Fehler oder Abbruch nicht als Ergebnis zurückgegeben.
pub fn inhalt_kopieren<W: Write>(
    o: &DateiOrt<'_>,
    out: W,
    limit: u64,
    r: &dyn crate::Rueckmeldung,
) -> Result<u64, LaufFehler> {
    struct Begrenzt<'a, W> {
        out: W,
        limit: u64,
        bytes: u64,
        r: &'a dyn crate::Rueckmeldung,
    }
    impl<W: Write> Write for Begrenzt<'_, W> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.r.abbruch_angefordert() {
                return Err(std::io::Error::other("abgebrochen"));
            }
            if bytes.len() as u64 > self.limit.saturating_sub(self.bytes) {
                return Err(std::io::Error::other("Datei größer als Scanlimit"));
            }
            let n = self.out.write(bytes)?;
            self.bytes += n as u64;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.out.flush()
        }
    }
    let img =
        ImageReader::open(o.image).kontext(|| "Image für Arbeitskopie nicht lesbar".into())?;
    let mut vol = oeffnen(&img, o)?;
    let mut writer = Begrenzt {
        out,
        limit,
        bytes: 0,
        r,
    };
    let result = vol.write_file_by_record(
        o.mft,
        "",
        &|offset, len| img.prefetch(offset, len),
        &mut writer,
    );
    if r.abbruch_angefordert() {
        return Err(LaufFehler::Abgebrochen);
    }
    result
        .kontext(|| "Arbeitskopie nicht vollständig lesbar".into())?
        .ok_or_else(|| LaufFehler::Eingabe("Datei ohne lesbaren Inhalt".into()))?;
    writer
        .flush()
        .kontext(|| "Arbeitskopie nicht schreibbar".into())?;
    Ok(writer.bytes)
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
    fenster_lesen(o, offset, laenge.min(FENSTER_MAX))
}

/// Vollständige Vorschau bis 8 MiB; größere Dateien werden abgelehnt.
pub fn vorschau(o: &DateiOrt<'_>, groesse: u64) -> Result<Vec<u8>, LaufFehler> {
    if groesse > 8 * 1024 * 1024 {
        return Err(LaufFehler::Eingabe("Vorschau auf 8 MiB begrenzt".into()));
    }
    fenster_lesen(o, 0, groesse.saturating_add(1))
}

fn fenster_lesen(o: &DateiOrt<'_>, offset: u64, laenge: u64) -> Result<Vec<u8>, LaufFehler> {
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

/// Höchstens 256 MiB je interaktiver Inhaltssuche.
pub const SUCHE_MAX: u64 = 256 * 1024 * 1024;

/// Ein wörtlicher Treffer im logischen Dateiinhalt, kein physischer Image-Offset.
#[derive(Debug, serde::Serialize)]
pub struct WortTreffer {
    /// Byte-Offset ab Dateianfang.
    pub offset: u64,
    /// UTF-8 oder UTF-16LE.
    pub kodierung: &'static str,
}

/// Suchumfang und Treffer; eine begrenzte Suche ist ausdrücklich unvollständig.
#[derive(Debug, serde::Serialize)]
pub struct WortSuche {
    /// Treffer, höchstens 500.
    pub treffer: Vec<WortTreffer>,
    /// Tatsächlich geprüfte Bytes.
    pub gelesen: u64,
    /// Das Dateiende wurde ohne Begrenzung erreicht.
    pub vollstaendig: bool,
}

struct Muster {
    bytes: Vec<u8>,
    rueck: Vec<usize>,
    stand: usize,
    kodierung: &'static str,
}

impl Muster {
    fn neu(bytes: Vec<u8>, kodierung: &'static str) -> Self {
        let mut rueck = vec![0; bytes.len()];
        let mut j = 0;
        for i in 1..bytes.len() {
            while j > 0 && bytes[i] != bytes[j] {
                j = rueck[j - 1];
            }
            if bytes[i] == bytes[j] {
                j += 1;
            }
            rueck[i] = j;
        }
        Self {
            bytes,
            rueck,
            stand: 0,
            kodierung,
        }
    }

    fn byte(&mut self, b: u8) -> bool {
        while self.stand > 0 && b != self.bytes[self.stand] {
            self.stand = self.rueck[self.stand - 1];
        }
        if b == self.bytes[self.stand] {
            self.stand += 1;
        }
        if self.stand == self.bytes.len() {
            self.stand = self.rueck[self.stand - 1];
            true
        } else {
            false
        }
    }
}

struct WortScanner {
    muster: [Muster; 2],
    ergebnis: WortSuche,
    gestoppt: bool,
}

impl WortScanner {
    fn neu(wort: &str) -> Result<Self, LaufFehler> {
        if wort.is_empty() || wort.len() > 1024 {
            return Err(LaufFehler::Eingabe(
                "Suchtext muss 1 bis 1024 UTF-8-Bytes lang sein".into(),
            ));
        }
        let utf16 = wort.encode_utf16().flat_map(u16::to_le_bytes).collect();
        Ok(Self {
            muster: [
                Muster::neu(wort.as_bytes().to_vec(), "UTF-8"),
                Muster::neu(utf16, "UTF-16LE"),
            ],
            ergebnis: WortSuche {
                treffer: Vec::new(),
                gelesen: 0,
                vollstaendig: false,
            },
            gestoppt: false,
        })
    }
}

impl Write for WortScanner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for &b in buf {
            if self.ergebnis.gelesen >= SUCHE_MAX || self.ergebnis.treffer.len() >= 500 {
                self.gestoppt = true;
                return Err(std::io::Error::other("Suchgrenze erreicht"));
            }
            self.ergebnis.gelesen += 1;
            for m in &mut self.muster {
                if m.byte(b) {
                    if self.ergebnis.treffer.len() == 500 {
                        self.gestoppt = true;
                        return Err(std::io::Error::other("Suchgrenze erreicht"));
                    }
                    self.ergebnis.treffer.push(WortTreffer {
                        offset: self.ergebnis.gelesen - m.bytes.len() as u64,
                        kodierung: m.kodierung,
                    });
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Sucht wörtlich und mit Beachtung der Groß-/Kleinschreibung in UTF-8 und
/// UTF-16LE. Der Scanner behält nur Muster und Treffer, auch über Blockgrenzen.
pub fn wort_suchen(o: &DateiOrt<'_>, wort: &str) -> Result<WortSuche, LaufFehler> {
    let mut scanner = WortScanner::neu(wort)?;
    let img = ImageReader::open(o.image).kontext(|| "Image nicht lesbar".into())?;
    let mut vol = oeffnen(&img, o)?;
    let prefetch = |offset: u64, len: u64| img.prefetch(offset, len);
    match vol.write_file_by_record(o.mft, "", &prefetch, &mut scanner) {
        Ok(Some(_)) => scanner.ergebnis.vollstaendig = true,
        Ok(None) => {
            return Err(LaufFehler::Eingabe(
                "Datei hat keinen lesbaren Datenstrom".into(),
            ))
        }
        Err(_) if scanner.gestoppt => (),
        Err(e) => {
            return Err(LaufFehler::Schritt {
                kontext: "Dateisuche fehlgeschlagen".into(),
                quelle: Box::new(e),
            })
        }
    }
    Ok(scanner.ergebnis)
}

/// Sucht syntaktisch gültige IP-Literale, höchstens 256 MiB und 500 Treffer.
/// Die Fundstellen sind logische Datei-Offsets, keine Netzwerkbeobachtungen.
pub fn ips_suchen(o: &DateiOrt<'_>) -> Result<stratum_search::ip::IpSuche, LaufFehler> {
    let mut scanner = stratum_search::ip::IpScanner::neu(SUCHE_MAX);
    let img = ImageReader::open(o.image).kontext(|| "Image nicht lesbar".into())?;
    let mut vol = oeffnen(&img, o)?;
    let prefetch = |offset: u64, len: u64| img.prefetch(offset, len);
    let ende = match vol.write_file_by_record(o.mft, "", &prefetch, &mut scanner) {
        Ok(Some(_)) => true,
        Ok(None) => {
            return Err(LaufFehler::Eingabe(
                "Datei hat keinen lesbaren Datenstrom".into(),
            ))
        }
        Err(_) if scanner.begrenzt() => false,
        Err(e) => {
            return Err(LaufFehler::Schritt {
                kontext: "IP-Suche fehlgeschlagen".into(),
                quelle: Box::new(e),
            })
        }
    };
    Ok(scanner.abschliessen(ende))
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
    fn wortsuche_unicode_ueber_blockgrenzen() {
        let mut s = WortScanner::neu("Grüße").unwrap();
        let mut bytes = b"prefix ".to_vec();
        bytes.extend_from_slice("Grüße".as_bytes());
        bytes.extend_from_slice(b" xx ");
        let utf16_offset = bytes.len() as u64;
        bytes.extend("Grüße".encode_utf16().flat_map(u16::to_le_bytes));
        for chunk in bytes.chunks(1) {
            s.write_all(chunk).unwrap();
        }
        assert_eq!(s.ergebnis.treffer.len(), 2);
        assert_eq!(s.ergebnis.treffer[0].offset, 7);
        assert_eq!(s.ergebnis.treffer[0].kodierung, "UTF-8");
        assert_eq!(s.ergebnis.treffer[1].offset, utf16_offset);
        assert_eq!(s.ergebnis.treffer[1].kodierung, "UTF-16LE");
    }

    #[test]
    fn wortsuche_ueberlappung_und_grenzen() {
        let mut s = WortScanner::neu("aba").unwrap();
        s.write_all(b"ababa").unwrap();
        assert_eq!(
            s.ergebnis
                .treffer
                .iter()
                .map(|t| t.offset)
                .collect::<Vec<_>>(),
            [0, 2]
        );
        assert!(WortScanner::neu("").is_err());
        assert!(WortScanner::neu(&"a".repeat(1025)).is_err());
        let mut s = WortScanner::neu("a").unwrap();
        assert!(s.write_all(&vec![b'a'; 501]).is_err());
        assert_eq!(s.ergebnis.treffer.len(), 500);
        assert!(s.gestoppt);
        let mut s = WortScanner::neu("z").unwrap();
        s.ergebnis.gelesen = SUCHE_MAX - 1;
        assert!(s.write_all(b"xy").is_err());
        assert_eq!(s.ergebnis.gelesen, SUCHE_MAX);
    }

    #[test]
    fn wortsuche_entspricht_unabhaengiger_fenstersuche() {
        let text = b"abacabababcabababacaba";
        for word in ["a", "aba", "abab", "abac", "x"] {
            let expected: Vec<u64> = text
                .windows(word.len())
                .enumerate()
                .filter(|(_, b)| *b == word.as_bytes())
                .map(|(i, _)| i as u64)
                .collect();
            for size in 1..=text.len() {
                let mut s = WortScanner::neu(word).unwrap();
                for chunk in text.chunks(size) {
                    s.write_all(chunk).unwrap();
                }
                assert_eq!(
                    s.ergebnis
                        .treffer
                        .iter()
                        .map(|t| t.offset)
                        .collect::<Vec<_>>(),
                    expected
                );
            }
        }
    }

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
