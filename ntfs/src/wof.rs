//! Windows Overlay Filter (WOF): vom System komprimierte Dateien.
//!
//! Windows (CompactOS, `compact /exe`) legt den Inhalt solcher Dateien
//! komprimiert im benannten Strom `WofCompressedData` ab. Der unbenannte
//! `$DATA`-Strom behält nur die logische Größe und ist sonst leer, ein Reparse
//! Point mit dem Tag `IO_REPARSE_TAG_WOF` verweist auf das Verfahren.
//!
//! Aufbau des Reparse-Puffers nach Microsoft (`WOF_EXTERNAL_INFO`,
//! `FILE_PROVIDER_EXTERNAL_INFO_V1`). Aufbau des Datenstroms nach der
//! Referenzimplementierung ntfs-3g-system-compression: Die Chunks liegen
//! hintereinander, davor eine Tabelle mit dem Offset jedes Chunks außer dem
//! ersten, gezählt ab dem Tabellenende; 4 Byte je Eintrag, 8 Byte ab einer
//! unkomprimierten Größe über `u32::MAX`. Ein Chunk, dessen gespeicherte Größe
//! seiner Originalgröße entspricht, liegt unkomprimiert vor.

/// Reparse-Tag des Windows Overlay Filters.
pub const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;

/// Name des Stroms mit den komprimierten Daten.
pub const WOF_STREAM: &str = "WofCompressedData";

/// Kompressionsverfahren einer WOF-Datei.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WofFormat {
    /// XPRESS-Huffman mit 4-KiB-Chunks.
    Xpress4k,
    /// LZX mit 32-KiB-Chunks.
    Lzx,
    /// XPRESS-Huffman mit 8-KiB-Chunks.
    Xpress8k,
    /// XPRESS-Huffman mit 16-KiB-Chunks.
    Xpress16k,
}

impl WofFormat {
    fn from_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::Xpress4k),
            1 => Some(Self::Lzx),
            2 => Some(Self::Xpress8k),
            3 => Some(Self::Xpress16k),
            _ => None,
        }
    }

    /// Unkomprimierte Größe eines Chunks.
    pub fn chunk_size(self) -> usize {
        match self {
            Self::Xpress4k => 4096,
            Self::Xpress8k => 8192,
            Self::Xpress16k => 16384,
            Self::Lzx => 32768,
        }
    }

    /// Bezeichnung für Reports.
    pub fn name(self) -> &'static str {
        match self {
            Self::Xpress4k => "XPRESS4K",
            Self::Lzx => "LZX",
            Self::Xpress8k => "XPRESS8K",
            Self::Xpress16k => "XPRESS16K",
        }
    }
}

/// Fehler beim Lesen einer WOF-Datei.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WofError {
    /// Reparse-Puffer zu kurz oder mit unbekannter Version.
    #[error("WOF-Reparse-Puffer ungültig: {0}")]
    InvalidReparse(&'static str),
    /// Der Inhalt liegt in einer externen WIM-Datei, nicht im Volume.
    #[error("WOF mit WIM-Provider: Inhalt liegt in einer externen WIM-Datei")]
    WimProvider,
    /// Unbekannter Provider.
    #[error("WOF mit unbekanntem Provider {0}")]
    UnknownProvider(u32),
    /// Unbekanntes Kompressionsverfahren.
    #[error("WOF mit unbekanntem Kompressionsverfahren {0}")]
    UnknownFormat(u32),
    /// Verfahren erkannt, aber nicht umgesetzt.
    #[error("WOF-Kompression {0} wird nicht unterstützt")]
    Unsupported(&'static str),
    /// Chunk-Tabelle oder Chunk-Grenzen passen nicht zum Strom.
    #[error("WofCompressedData beschädigt: {0}")]
    Corrupt(&'static str),
    /// Ein Chunk ließ sich nicht entpacken.
    #[error("WOF-Chunk {chunk} nicht entpackbar: {reason}")]
    Chunk {
        /// Nummer des Chunks.
        chunk: usize,
        /// Grund laut Dekompressor.
        reason: String,
    },
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// XPRESS-Huffman entpacken ([MS-XCA] 2.2.4).
///
/// `xpress-huffman` 0.1.3 beendet die Dekodierung, sobald die Leseposition das
/// Ende der Eingabe erreicht, obwohl dann noch Bits im Puffer stehen. Endet der
/// komprimierte Strom genau mit dem letzten Symbol, fehlt dadurch das letzte
/// Byte. Ein paar angehängte Nullbytes lassen die Schleife weiterlaufen; die
/// Ausgabe endet trotzdem genau bei `size`, das Anhängsel wird nie ausgegeben.
pub fn xpress_decompress(data: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let mut padded = Vec::with_capacity(data.len() + 8);
    padded.extend_from_slice(data);
    padded.extend_from_slice(&[0u8; 8]);
    let out = xpress_huffman::decompress(&padded, size).map_err(|e| e.to_string())?;
    if out.len() == size {
        Ok(out)
    } else {
        Err(format!("{} statt {} Byte", out.len(), size))
    }
}

/// Wertet den Inhalt eines `$REPARSE_POINT`-Attributs aus. `Ok(None)` heißt:
/// kein WOF-Reparse-Point. Nur der Provider „FILE“ liegt vollständig im Volume.
pub fn parse_reparse(data: &[u8]) -> Result<Option<WofFormat>, WofError> {
    let Some(tag) = le32(data, 0) else {
        return Ok(None);
    };
    if tag != IO_REPARSE_TAG_WOF {
        return Ok(None);
    }
    // REPARSE_DATA_BUFFER: Tag (4), Länge (2), reserviert (2), danach die Daten.
    let (Some(wof_version), Some(provider)) = (le32(data, 8), le32(data, 12)) else {
        return Err(WofError::InvalidReparse("zu kurz"));
    };
    if wof_version != 1 {
        return Err(WofError::InvalidReparse("unbekannte WOF-Version"));
    }
    match provider {
        2 => {}
        1 => return Err(WofError::WimProvider),
        other => return Err(WofError::UnknownProvider(other)),
    }
    let (Some(file_version), Some(format)) = (le32(data, 16), le32(data, 20)) else {
        return Err(WofError::InvalidReparse("zu kurz"));
    };
    if file_version != 1 {
        return Err(WofError::InvalidReparse("unbekannte Provider-Version"));
    }
    WofFormat::from_id(format)
        .map(Some)
        .ok_or(WofError::UnknownFormat(format))
}

/// Entpackt `WofCompressedData` zur ursprünglichen Datei. Höchstens `limit`
/// Byte werden erzeugt; ist die Datei größer, endet das Ergebnis dort.
pub fn decompress(
    stream: &[u8],
    format: WofFormat,
    uncompressed_size: u64,
    limit: usize,
) -> Result<Vec<u8>, WofError> {
    if format == WofFormat::Lzx {
        return Err(WofError::Unsupported(format.name()));
    }
    let chunk_size = format.chunk_size() as u64;
    let num_chunks = uncompressed_size.div_ceil(chunk_size);
    if num_chunks == 0 {
        return Ok(Vec::new());
    }
    let entry = if uncompressed_size > u64::from(u32::MAX) {
        8
    } else {
        4
    };
    let table_len = (num_chunks - 1)
        .checked_mul(entry)
        .filter(|&l| l <= stream.len() as u64)
        .ok_or(WofError::Corrupt("Chunk-Tabelle länger als der Strom"))?
        as usize;
    let data = &stream[table_len..];

    let offset = |i: u64| -> u64 {
        if i == 0 {
            return 0;
        }
        let at = ((i - 1) * entry) as usize;
        let raw = &stream[at..at + entry as usize];
        let mut buf = [0u8; 8];
        buf[..raw.len()].copy_from_slice(raw);
        u64::from_le_bytes(buf)
    };

    let wanted = uncompressed_size.min(limit as u64) as usize;
    // Vorab nur begrenzt reservieren, die Größe stammt aus dem Image.
    let mut out = Vec::with_capacity(wanted.min(stream.len().saturating_mul(8)));
    let mut i = 0u64;
    while out.len() < wanted {
        let start = offset(i);
        let end = if i + 1 < num_chunks {
            offset(i + 1)
        } else {
            data.len() as u64
        };
        if start > end || end > data.len() as u64 {
            return Err(WofError::Corrupt("Chunk-Grenzen außerhalb des Stroms"));
        }
        let original = chunk_size.min(uncompressed_size - i * chunk_size) as usize;
        let stored = &data[start as usize..end as usize];
        if stored.len() > original {
            return Err(WofError::Corrupt("Chunk größer als seine Originalgröße"));
        }
        if stored.len() == original {
            out.extend_from_slice(stored);
        } else {
            let chunk = xpress_decompress(stored, original).map_err(|reason| WofError::Chunk {
                chunk: i as usize,
                reason,
            })?;
            out.extend_from_slice(&chunk);
        }
        i += 1;
    }
    out.truncate(wanted);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reparse(provider: u32, format: u32) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&IO_REPARSE_TAG_WOF.to_le_bytes());
        d.extend_from_slice(&16u16.to_le_bytes());
        d.extend_from_slice(&[0, 0]);
        for v in [1, provider, 1, format] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d
    }

    #[test]
    fn reparse_puffer() {
        // Echter Puffer aus einem Windows-11-System (XPRESS8K).
        let echt = [
            0x17, 0, 0, 0x80, 0x10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0,
        ];
        assert_eq!(parse_reparse(&echt), Ok(Some(WofFormat::Xpress8k)));
        assert_eq!(parse_reparse(&reparse(2, 0)), Ok(Some(WofFormat::Xpress4k)));
        assert_eq!(parse_reparse(&reparse(2, 1)), Ok(Some(WofFormat::Lzx)));
        assert_eq!(parse_reparse(&reparse(1, 0)), Err(WofError::WimProvider));
        assert_eq!(
            parse_reparse(&reparse(7, 0)),
            Err(WofError::UnknownProvider(7))
        );
        assert_eq!(
            parse_reparse(&reparse(2, 9)),
            Err(WofError::UnknownFormat(9))
        );
        assert_eq!(parse_reparse(&0xA000_0003u32.to_le_bytes()), Ok(None));
        assert_eq!(parse_reparse(&[]), Ok(None));
        assert!(parse_reparse(&echt[..10]).is_err());
    }

    /// Strom aus unkomprimiert gespeicherten Chunks.
    fn stored_stream(data: &[u8], chunk: usize) -> Vec<u8> {
        let chunks: Vec<&[u8]> = data.chunks(chunk).collect();
        let mut table = Vec::new();
        let mut pos = 0u32;
        for c in &chunks[..chunks.len() - 1] {
            pos += c.len() as u32;
            table.extend_from_slice(&pos.to_le_bytes());
        }
        let mut s = table;
        for c in chunks {
            s.extend_from_slice(c);
        }
        s
    }

    #[test]
    fn unkomprimierte_chunks_und_grenzen() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let s = stored_stream(&data, 8192);
        let out = decompress(&s, WofFormat::Xpress8k, data.len() as u64, usize::MAX).unwrap();
        assert_eq!(out, data);
        // Begrenzung liefert den Anfang.
        let out = decompress(&s, WofFormat::Xpress8k, data.len() as u64, 9000).unwrap();
        assert_eq!(out, &data[..9000]);
        // Leere Datei.
        assert_eq!(decompress(&[], WofFormat::Xpress4k, 0, 10), Ok(Vec::new()));
        // LZX wird ausdrücklich abgelehnt.
        assert_eq!(
            decompress(&s, WofFormat::Lzx, data.len() as u64, usize::MAX),
            Err(WofError::Unsupported("LZX"))
        );
    }

    #[test]
    fn beschaedigte_stroeme() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 7) as u8).collect();
        let good = stored_stream(&data, 8192);
        // Tabelle länger als der Strom.
        assert!(decompress(&good[..4], WofFormat::Xpress8k, 1 << 30, usize::MAX).is_err());
        // Offset hinter dem Strom.
        let mut bad = good.clone();
        bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decompress(&bad, WofFormat::Xpress8k, data.len() as u64, usize::MAX).is_err());
        // Offsets rückwärts.
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(decompress(&bad, WofFormat::Xpress8k, data.len() as u64, usize::MAX).is_err());
        // Letzter Chunk zu lang.
        let mut bad = good.clone();
        bad.push(0);
        assert!(decompress(&bad, WofFormat::Xpress8k, data.len() as u64, usize::MAX).is_err());
        // Kaputter komprimierter Chunk: Fehler statt Panik.
        let mut bad = good.clone();
        bad.truncate(bad.len() - 100);
        assert!(decompress(&bad, WofFormat::Xpress8k, data.len() as u64, usize::MAX).is_err());
        // Riesige angebliche Größe bei winzigem Strom.
        assert!(decompress(&[1, 2, 3], WofFormat::Xpress4k, u64::MAX, usize::MAX).is_err());
    }

    /// Selbst gebauter XPRESS-Strom: alle 256 Literale mit 8-Bit-Codes, der Code
    /// eines Literals ist dann sein Wert. Jedes 16-Bit-Wort (Little Endian, höchstes
    /// Bit zuerst) trägt zwei Literale; der Strom endet genau mit dem letzten Symbol.
    fn literal_stream(data: &[u8]) -> Vec<u8> {
        let mut s = vec![0x88u8; 128];
        s.extend_from_slice(&[0u8; 128]);
        for pair in data.chunks(2) {
            let word = (u16::from(pair[0]) << 8) | u16::from(*pair.get(1).unwrap_or(&0));
            s.extend_from_slice(&word.to_le_bytes());
        }
        s
    }

    #[test]
    fn xpress_letztes_symbol_am_eingabeende() {
        let data = b"stratum-wof-test";
        let s = literal_stream(data);
        assert_eq!(xpress_decompress(&s, data.len()).unwrap(), data);
        // Ohne Auffüllung verliert xpress-huffman 0.1.3 hier Bytes am Ende.
        let roh = xpress_huffman::decompress(&s, data.len()).unwrap_or_default();
        assert!(
            roh.len() < data.len(),
            "Fehler der Crate behoben? {}",
            roh.len()
        );
        // Über WOF: Chunk 0 komprimiert (zwei Symbole „A“ und „B“ mit je 1 Bit,
        // 4096 Bit enden genau am Eingabeende), Chunk 1 roh gespeichert.
        let full: Vec<u8> = (0..4096u32)
            .map(|i| if (i * 7 + i / 5) % 3 == 0 { b'B' } else { b'A' })
            .collect();
        let mut s0 = vec![0u8; 256];
        s0[32] = 0x10; // Symbol 65 („A“), oberes Nibble: Länge 1
        s0[33] = 0x01; // Symbol 66 („B“), unteres Nibble: Länge 1
        for bits in full.chunks(16) {
            let word = bits
                .iter()
                .fold(0u16, |w, &c| (w << 1) | u16::from(c == b'B'));
            s0.extend_from_slice(&word.to_le_bytes());
        }
        let rest = [7u8; 4096];
        let mut stream = Vec::new();
        stream.extend_from_slice(&(s0.len() as u32).to_le_bytes());
        stream.extend_from_slice(&s0);
        stream.extend_from_slice(&rest);
        let out = decompress(&stream, WofFormat::Xpress4k, 8192, usize::MAX).unwrap();
        assert_eq!(&out[..4096], &full[..]);
        assert_eq!(&out[4096..], &rest[..]);
    }
}
