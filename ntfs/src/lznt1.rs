//! LZNT1-Dekompression, die Windows-Standardkompression fuer NTFS-Dateien.
//!
//! NTFS legt einen komprimierten `$DATA`-Strom in Kompressionseinheiten zu je
//! 16 Clustern ab. Innerhalb einer Einheit liegen die Daten als Folge von
//! Chunks vor; die durch die Kompression eingesparten Cluster erscheinen als
//! spaerliche Datenlaeufe. Diese Datei entpackt den Chunk-Strom einer Einheit.
//! Das Zusammensetzen der Einheiten (spaerliche Fuellung, unkomprimiert
//! abgelegte Einheiten) erledigt der Aufrufer in `read_data`.
//!
//! Format: Der Strom besteht aus Chunks mit 2-Byte-Kopf (little-endian). Bit 15
//! zeigt an, ob der Chunk komprimiert ist; die Bits 0..12 tragen die Laenge der
//! Chunk-Daten minus eins. Ein Kopf von 0 beendet den Strom. Ein komprimierter
//! Chunk besteht aus Tag-Gruppen: ein Tag-Byte, danach acht Elemente. Ist das
//! zugehoerige Bit 0, folgt ein Literal-Byte; ist es 1, folgt ein 2-Byte-Tupel
//! (Rueckverweis). Die Aufteilung des Tupels in Abstand und Laenge passt sich
//! an die Zahl der im aktuellen Chunk bereits erzeugten Bytes an.
//!
//! Der Parser verarbeitet nicht vertrauenswuerdige Daten und laeuft daher
//! defensiv: er greift nie ausserhalb der Grenzen zu und meldet Fehler ueber
//! `Result`, statt zu panicken.

/// Anzahl der Elemente je Tag-Gruppe.
const TAG_GRUPPE: usize = 8;
/// Anfaengliche Bitbreite fuer den Laengenteil eines Rueckverweis-Tupels.
const START_SPLIT: u32 = 12;
/// Anfaengliche Schwelle fuer die Anpassung der Bitbreite.
const START_SCHWELLE: usize = 16;
/// Maske fuer die Chunk-Laenge (untere 12 Bit des Kopfes).
const KOPF_LAENGE_MASKE: u16 = 0x0FFF;
/// Bit im Kopf, das einen komprimierten Chunk kennzeichnet.
const KOPF_KOMPRIMIERT: u16 = 0x8000;

/// Fehler beim Entpacken eines LZNT1-Chunk-Stroms.
#[derive(Debug, thiserror::Error)]
pub enum Lznt1Error {
    /// Eingabe endet mitten in einem Kopf oder Chunk.
    #[error("unerwartetes Ende der komprimierten Daten")]
    UnerwartetesEnde,
    /// Ein Rueckverweis zeigt vor den Beginn der bisher erzeugten Ausgabe.
    #[error("ungueltiger Rueckverweis (Abstand groesser als Ausgabe)")]
    UngueltigerAbstand,
}

/// Entpackt einen LZNT1-Chunk-Strom und haengt das Ergebnis an `out` an.
///
/// `input` sind die tatsaechlich belegten (komprimierten) Bytes einer
/// Kompressionseinheit. Der Strom endet am ersten Null-Kopf oder am Ende der
/// Eingabe.
pub fn decompress(input: &[u8], out: &mut Vec<u8>) -> Result<(), Lznt1Error> {
    let mut pos = 0usize;
    let end = input.len();

    while pos < end {
        // Ein einzelnes verbleibendes Null-Byte markiert das Ende.
        if pos + 1 == end && input[pos] == 0 {
            break;
        }
        if pos + 2 > end {
            return Err(Lznt1Error::UnerwartetesEnde);
        }
        let kopf = u16::from_le_bytes([input[pos], input[pos + 1]]);
        pos += 2;
        if kopf == 0 {
            break;
        }
        let laenge = ((kopf & KOPF_LAENGE_MASKE) + 1) as usize;
        let komprimiert = (kopf & KOPF_KOMPRIMIERT) != 0;
        if pos + laenge > end {
            return Err(Lznt1Error::UnerwartetesEnde);
        }
        let chunk = &input[pos..pos + laenge];
        if komprimiert {
            entpacke_chunk(chunk, out)?;
        } else {
            out.extend_from_slice(chunk);
        }
        pos += laenge;
    }
    Ok(())
}

/// Entpackt einen einzelnen komprimierten Chunk (bis zu 4096 Ausgabe-Bytes).
fn entpacke_chunk(input: &[u8], out: &mut Vec<u8>) -> Result<(), Lznt1Error> {
    let mut pos = 0usize;
    let end = input.len();
    let chunk_start = out.len();

    let mut split = START_SPLIT;
    let mut maske = (1usize << split) - 1;
    let mut schwelle = START_SCHWELLE;

    while pos < end {
        let tag = input[pos];
        pos += 1;

        for i in 0..TAG_GRUPPE {
            if pos >= end {
                // Zulaessiges Ende innerhalb einer Tag-Gruppe.
                return Ok(());
            }
            let ist_verweis = (tag >> i) & 1 != 0;
            if ist_verweis {
                if pos + 2 > end {
                    return Err(Lznt1Error::UnerwartetesEnde);
                }
                let tupel = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
                pos += 2;
                let laenge = (tupel & maske) + 3;
                let abstand = (tupel >> split) + 1;
                kopiere_verweis(out, chunk_start, abstand, laenge)?;
            } else {
                out.push(input[pos]);
                pos += 1;
            }

            // Bitbreite an die bereits im Chunk erzeugte Byte-Zahl anpassen.
            let im_chunk = out.len() - chunk_start;
            while im_chunk > schwelle {
                if split > 0 {
                    split -= 1;
                    maske = (1usize << split) - 1;
                }
                schwelle <<= 1;
            }
        }
    }
    Ok(())
}

/// Kopiert einen Rueckverweis aus der bereits erzeugten Ausgabe. Der Abstand
/// bezieht sich auf das Ende der Ausgabe; ueberlappende Bereiche sind erlaubt
/// (Lauflaengen-Effekt bei Abstand 1).
fn kopiere_verweis(
    out: &mut Vec<u8>,
    chunk_start: usize,
    abstand: usize,
    laenge: usize,
) -> Result<(), Lznt1Error> {
    if abstand == 0 || abstand > out.len() - chunk_start {
        return Err(Lznt1Error::UngueltigerAbstand);
    }
    let quelle = out.len() - abstand;
    out.reserve(laenge);
    if abstand == 1 {
        let byte = out[out.len() - 1];
        out.resize(out.len() + laenge, byte);
    } else {
        for k in 0..laenge {
            let b = out[quelle + k];
            out.push(b);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unkomprimierter_chunk_wird_kopiert() {
        // Kopf 0x3005: Bit 15 = 0 (unkomprimiert), Laenge = 5+1 = 6.
        let mut stream = vec![0x05, 0x30];
        stream.extend_from_slice(b"hallo!");
        let mut out = Vec::new();
        decompress(&stream, &mut out).unwrap();
        assert_eq!(out, b"hallo!");
    }

    #[test]
    fn rueckverweis_erzeugt_lauflaenge() {
        // Ein Literal 'a', danach ein Rueckverweis Abstand 1 Laenge 3 -> "aaaa".
        // Tag: Bit0=0 (Literal), Bit1=1 (Verweis) => 0b0000_0010 = 0x02.
        // Tupel 0x0000 bei split=12: abstand=(0>>12)+1=1, laenge=(0&0xFFF)+3=3.
        // Chunk-Daten: [tag, 'a', tupel_lo, tupel_hi] = [0x02, 0x61, 0x00, 0x00].
        // Kopf 0xB003: Bit15=1 (komprimiert), Laenge = 3+1 = 4.
        let stream = [0x03, 0xB0, 0x02, 0x61, 0x00, 0x00];
        let mut out = Vec::new();
        decompress(&stream, &mut out).unwrap();
        assert_eq!(out, b"aaaa");
    }

    #[test]
    fn reiner_literal_chunk() {
        // Tag 0x00 -> acht Literale; wir liefern nur vier und enden vorzeitig.
        // Kopf 0xB004: komprimiert, Laenge = 4+1 = 5 (tag + 4 Literale).
        let stream = [0x04, 0xB0, 0x00, b'A', b'B', b'C', b'D'];
        let mut out = Vec::new();
        decompress(&stream, &mut out).unwrap();
        assert_eq!(out, b"ABCD");
    }

    #[test]
    fn null_kopf_beendet_strom() {
        let stream = [0x00, 0x00];
        let mut out = Vec::new();
        decompress(&stream, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ungueltiger_abstand_meldet_fehler() {
        // Verweis als erstes Element ohne vorherige Ausgabe -> Fehler.
        // Tag 0x01 (Bit0=1 Verweis), Tupel 0x0000 -> abstand 1, aber Ausgabe leer.
        let stream = [0x03, 0xB0, 0x01, 0x00, 0x00];
        let mut out = Vec::new();
        assert!(decompress(&stream, &mut out).is_err());
    }
}
