//! Nur lesender Zugriff auf Expert-Witness-Images (EWF-E01, auch SMART S01).
//!
//! Formatgrundlage ist die Beschreibung von libyal/libewf („Expert Witness
//! Compression Format (EWF)“). Geprüft gegen libewf (`ewfexport`, `ewfinfo`)
//! an EnCase 1/5/6/7, FTK Imager, linen und mehrteiligen Images.
//!
//! Die Segmentdateien werden nur lesend eingebunden. Die Medien-Daten liegen
//! in Chunks (Standard 32 KiB), einzeln zlib-komprimiert oder roh mit
//! Adler-32-Prüfsumme. Jeder Chunk wird beim Lesen geprüft; ein Fehler wird
//! gemeldet, nie stillschweigend mit Nullen gefüllt. Entpackte Chunks liegen
//! in einem kleinen Zwischenspeicher.
//!
//! Nicht unterstützt und als solches gemeldet: EWF2 (`.Ex01`, `.Lx01`) und
//! logische Images (`.L01`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cache;
mod error;
mod header;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use stratum_mmap::ReadOnlyMap;

pub use error::EwfError;
pub use header::AcquisitionInfo;

use cache::ChunkCache;

/// Signatur von EWF-E01 und SMART.
const SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
/// Signatur logischer Images (L01), nicht unterstützt.
const SIGNATURE_LOGICAL: &[u8; 8] = b"LVF\x09\x0d\x0a\xff\x00";
/// Größe von Dateikopf und Sektionsdeskriptor.
const FILE_HEADER: usize = 13;
const DESCRIPTOR: usize = 76;
/// Schutz gegen Sektionsketten ohne Ende.
const MAX_SECTIONS: usize = 1 << 20;
/// Größte zulässige Chunkgröße (32.768 Sektoren zu 512 Byte laut Beschreibung).
const MAX_CHUNK: u64 = 32_768 * 512;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Daten einer Segmentdatei.
#[derive(Debug)]
enum SegmentData {
    Map(ReadOnlyMap),
    Bytes(Vec<u8>),
}

impl SegmentData {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Map(m) => m.as_slice(),
            Self::Bytes(b) => b,
        }
    }
}

#[derive(Debug)]
struct Segment {
    path: Option<PathBuf>,
    data: SegmentData,
}

/// Lage eines Chunks in einer Segmentdatei.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLocation {
    /// Segment (ab 0).
    pub segment: usize,
    /// Beginn der gespeicherten Daten in der Segmentdatei.
    pub offset: u64,
    /// Gespeicherte Länge (komprimiert bzw. Daten plus Prüfsumme).
    pub stored_len: u64,
    /// zlib-komprimiert.
    pub compressed: bool,
}

/// Bei der Akquise gespeicherte Hashes der Mediendaten.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredHashes {
    /// MD5 aus `hash` oder `digest`.
    pub md5: Option<[u8; 16]>,
    /// SHA-1 aus `digest`.
    pub sha1: Option<[u8; 20]>,
}

/// Geometrie aus der Sektion `volume` bzw. `disk`.
#[derive(Debug, Clone, Copy, Default)]
struct Geometry {
    chunk_count: u64,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
    set_id: Option<[u8; 16]>,
}

/// Sektion einer Segmentdatei.
#[derive(Debug, Clone)]
struct Section {
    kind: String,
    start: u64,
    /// Ende: Beginn der nächsten Sektion, sonst Beginn plus Größe.
    end: u64,
}

/// Ein geöffnetes Expert-Witness-Image.
#[derive(Debug)]
pub struct EwfImage {
    segments: Vec<Segment>,
    chunks: Vec<ChunkLocation>,
    chunk_size: u32,
    bytes_per_sector: u32,
    media_size: u64,
    set_id: Option<[u8; 16]>,
    info: AcquisitionInfo,
    hashes: StoredHashes,
    warnings: Vec<String>,
    cache: ChunkCache,
}

impl EwfImage {
    /// Öffnet ein Image über die erste Segmentdatei (`.E01`, `.e01`, `.s01`).
    /// Weitere Segmente werden nach der Namensregel gesucht (E02 bis E99,
    /// dann EAA bis ZZZ).
    pub fn open(first: &Path) -> Result<Self, EwfError> {
        let mut segments = Vec::new();
        for n in 1.. {
            let path = if n == 1 {
                first.to_path_buf()
            } else {
                match segment_path(first, n) {
                    Some(p) if p.exists() => p,
                    _ => break,
                }
            };
            let map = ReadOnlyMap::open(&path).map_err(|source| EwfError::Open {
                path: path.clone(),
                source,
            })?;
            segments.push(Segment {
                path: Some(path),
                data: SegmentData::Map(map),
            });
        }
        Self::build(segments)
    }

    /// Image aus Segmenten im Speicher (Tests, Fuzzing).
    pub fn from_bytes(segments: Vec<Vec<u8>>) -> Result<Self, EwfError> {
        Self::build(
            segments
                .into_iter()
                .map(|b| Segment {
                    path: None,
                    data: SegmentData::Bytes(b),
                })
                .collect(),
        )
    }

    fn build(segments: Vec<Segment>) -> Result<Self, EwfError> {
        if segments.is_empty() {
            return Err(EwfError::Unsupported("keine Segmentdatei".into()));
        }
        let mut geometry: Option<Geometry> = None;
        let mut info = AcquisitionInfo::default();
        let mut header8 = None;
        let mut hashes = StoredHashes::default();
        let mut chunks = Vec::new();
        let mut warnings = Vec::new();

        for (i, seg) in segments.iter().enumerate() {
            let data = seg.data.as_slice();
            check_file_header(data, i + 1)?;
            let sections = read_sections(data, i + 1)?;
            // Eine Tabelle mit beschädigtem Kopf wird durch ihre Kopie
            // (`table2`) ersetzt.
            let mut table_kaputt = false;
            for (si, s) in sections.iter().enumerate() {
                let body = &data[(s.start as usize + DESCRIPTOR).min(data.len())
                    ..(s.end as usize).min(data.len())];
                match s.kind.as_str() {
                    "header2" if info.source.is_none() => {
                        if let Some(text) = inflate_all(body).and_then(|t| header::decode_utf16(&t))
                        {
                            info.values = header::parse(&text);
                            info.source = Some("header2");
                        }
                    }
                    "header" if header8.is_none() => {
                        header8 = inflate_all(body).map(|t| header::decode_8bit(&t));
                    }
                    "volume" | "disk" if geometry.is_none() => {
                        let (g, pruef_ok) = read_geometry(body, i + 1, s.start)?;
                        if !pruef_ok {
                            warnings.push(format!(
                                "Segment {}: Prüfsumme der Sektion {} stimmt nicht",
                                i + 1,
                                s.kind
                            ));
                        }
                        geometry = Some(g);
                    }
                    "table" => match read_table(data, &sections, si, i) {
                        Ok(t) => {
                            table_kaputt = false;
                            chunks.extend(t);
                        }
                        Err(e) => {
                            table_kaputt = true;
                            warnings.push(format!("{e}; versuche table2"));
                        }
                    },
                    "table2" if table_kaputt => {
                        chunks.extend(read_table(data, &sections, si, i)?);
                        table_kaputt = false;
                    }
                    "hash" if hashes.md5.is_none() => {
                        hashes.md5 = nonzero16(body);
                    }
                    "digest" => {
                        hashes.md5 = nonzero16(body).or(hashes.md5);
                        hashes.sha1 = body
                            .get(16..36)
                            .and_then(|b| b.try_into().ok())
                            .filter(|b: &[u8; 20]| b.iter().any(|x| *x != 0));
                    }
                    _ => {}
                }
            }
            if table_kaputt {
                return Err(EwfError::BadSection {
                    segment: i + 1,
                    offset: 0,
                    reason: "Tabelle und Kopie table2 unlesbar".into(),
                });
            }
        }
        if info.source.is_none() {
            if let Some(text) = header8 {
                info.values = header::parse(&text);
                info.source = Some("header");
            }
        }
        let g = geometry.ok_or_else(|| EwfError::BadSection {
            segment: 1,
            offset: 0,
            reason: "keine Sektion volume oder disk".into(),
        })?;
        let chunk_size = u64::from(g.sectors_per_chunk) * u64::from(g.bytes_per_sector);
        if chunk_size == 0 || chunk_size > MAX_CHUNK {
            return Err(EwfError::Unsupported(format!(
                "Chunkgröße {chunk_size} Byte"
            )));
        }
        let media_size = g
            .sector_count
            .checked_mul(u64::from(g.bytes_per_sector))
            .ok_or_else(|| EwfError::Unsupported("Mediengröße überläuft".into()))?;
        let noetig = media_size.div_ceil(chunk_size);
        if chunks.len() as u64 != g.chunk_count || (chunks.len() as u64) < noetig {
            warnings.push(format!(
                "{} Chunks in den Tabellen, laut Volume {}, für die Mediengröße nötig {}",
                chunks.len(),
                g.chunk_count,
                noetig
            ));
        }
        Ok(Self {
            segments,
            chunks,
            chunk_size: chunk_size as u32,
            bytes_per_sector: g.bytes_per_sector,
            media_size,
            set_id: g.set_id,
            info,
            hashes,
            warnings,
            cache: ChunkCache::new(),
        })
    }

    /// Größe der Mediendaten in Byte.
    pub fn media_size(&self) -> u64 {
        self.media_size
    }

    /// Größe eines Chunks in Byte.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Byte je Sektor.
    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Anzahl der Chunks laut Tabellen.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Lage eines Chunks in den Segmentdateien.
    pub fn chunk_location(&self, index: usize) -> Option<ChunkLocation> {
        self.chunks.get(index).copied()
    }

    /// Pfade der Segmentdateien in Reihenfolge.
    pub fn segment_paths(&self) -> Vec<&Path> {
        self.segments
            .iter()
            .filter_map(|s| s.path.as_deref())
            .collect()
    }

    /// Kennung des Segmentsatzes aus der Sektion `volume`, falls gesetzt.
    pub fn set_id(&self) -> Option<[u8; 16]> {
        self.set_id
    }

    /// Akquisedaten.
    pub fn info(&self) -> &AcquisitionInfo {
        &self.info
    }

    /// Bei der Akquise gespeicherte Hashes.
    pub fn stored_hashes(&self) -> &StoredHashes {
        &self.hashes
    }

    /// Hinweise beim Öffnen.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Entpackter, geprüfter Inhalt eines Chunks (beim letzten Chunk nur der
    /// Teil innerhalb der Mediengröße).
    pub fn chunk(&self, index: u64) -> Result<Arc<[u8]>, EwfError> {
        if let Some(c) = self.cache.get(index) {
            return Ok(c);
        }
        let data = self.read_chunk(index)?;
        let data: Arc<[u8]> = data.into();
        self.cache.put(index, Arc::clone(&data));
        Ok(data)
    }

    fn read_chunk(&self, index: u64) -> Result<Vec<u8>, EwfError> {
        let fehler = |reason: String| EwfError::BadChunk { index, reason };
        let loc = usize::try_from(index)
            .ok()
            .and_then(|i| self.chunks.get(i))
            .ok_or_else(|| fehler("nicht in den Tabellen (Segment fehlt?)".into()))?;
        let cs = u64::from(self.chunk_size);
        let want = cs.min(self.media_size.saturating_sub(index * cs)) as usize;
        let seg = self.segments[loc.segment].data.as_slice();
        let raw = seg
            .get(loc.offset as usize..(loc.offset + loc.stored_len) as usize)
            .ok_or_else(|| fehler("außerhalb der Segmentdatei".into()))?;
        if loc.compressed {
            let mut out = vec![0u8; cs as usize];
            let n = miniz_oxide::inflate::decompress_slice_iter_to_slice(
                &mut out,
                std::iter::once(raw),
                true,
                false,
            )
            .map_err(|e| fehler(format!("zlib: {e:?}")))?;
            if n < want {
                return Err(fehler(format!("entpackt {n} statt {want} Byte")));
            }
            out.truncate(want);
            Ok(out)
        } else {
            let daten = raw
                .get(..want)
                .ok_or_else(|| fehler("roher Chunk zu kurz".into()))?;
            let pruef = raw
                .get(want..want + 4)
                .and_then(|b| u32_at(b, 0))
                .ok_or_else(|| fehler("Prüfsumme fehlt".into()))?;
            if adler2::adler32_slice(daten) != pruef {
                return Err(fehler("Adler-32 stimmt nicht".into()));
            }
            Ok(daten.to_vec())
        }
    }

    /// Liest `buf.len()` Byte ab `offset` der Mediendaten.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), EwfError> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|&e| e <= self.media_size)
            .ok_or(EwfError::OutOfRange {
                offset,
                len: buf.len() as u64,
                size: self.media_size,
            })?;
        let cs = u64::from(self.chunk_size);
        let mut pos = offset;
        while pos < end {
            let index = pos / cs;
            let chunk = self.chunk(index)?;
            let im_chunk = (pos - index * cs) as usize;
            let n = ((end - pos) as usize).min(chunk.len() - im_chunk);
            let ziel = (pos - offset) as usize;
            buf[ziel..ziel + n].copy_from_slice(&chunk[im_chunk..im_chunk + n]);
            pos += n as u64;
        }
        Ok(())
    }
}

/// Pfad des Segments `n` (ab 1) nach der EWF-Namensregel.
pub fn segment_path(first: &Path, n: u32) -> Option<PathBuf> {
    let ext = first.extension()?.to_str()?;
    let neu = segment_extension(ext, n)?;
    Some(first.with_extension(neu))
}

/// Endung des Segments `n` zu einer ersten Endung wie `E01` oder `s01`.
pub fn segment_extension(first: &str, n: u32) -> Option<String> {
    let b = first.as_bytes();
    if b.len() != 3 || &b[1..] != b"01" || !b[0].is_ascii_alphabetic() || n == 0 {
        return None;
    }
    let gross = b[0].is_ascii_uppercase();
    let basis = if gross { b'A' } else { b'a' };
    if n < 100 {
        return Some(format!("{}{n:02}", b[0] as char));
    }
    let k = n - 100;
    let c0 = u32::from(b[0] - basis) + k / (26 * 26);
    if c0 >= 26 {
        return None;
    }
    let buchstabe = |x: u32| (basis + x as u8) as char;
    Some(format!(
        "{}{}{}",
        buchstabe(c0),
        buchstabe((k / 26) % 26),
        buchstabe(k % 26)
    ))
}

fn check_file_header(data: &[u8], segment: usize) -> Result<(), EwfError> {
    let kopf = data.get(..FILE_HEADER).ok_or_else(|| EwfError::BadHeader {
        segment,
        reason: "Datei kürzer als der Dateikopf".into(),
    })?;
    if &kopf[..8] == SIGNATURE_LOGICAL {
        return Err(EwfError::Unsupported("logisches Image (L01)".into()));
    }
    if &kopf[..8] != SIGNATURE {
        let ewf2 = kopf.starts_with(b"EVF2") || kopf.starts_with(b"LEF2");
        return Err(if ewf2 {
            EwfError::Unsupported("EWF2 (Ex01/Lx01)".into())
        } else {
            EwfError::BadHeader {
                segment,
                reason: "keine EWF-Signatur".into(),
            }
        });
    }
    let nummer = u16::from_le_bytes([kopf[9], kopf[10]]) as usize;
    if nummer != segment {
        return Err(EwfError::BadHeader {
            segment,
            reason: format!("Segmentnummer {nummer} im Dateikopf"),
        });
    }
    Ok(())
}

/// Sektionen einer Segmentdatei in Kettenreihenfolge.
fn read_sections(data: &[u8], segment: usize) -> Result<Vec<Section>, EwfError> {
    let mut out: Vec<Section> = Vec::new();
    let mut off = FILE_HEADER as u64;
    let len = data.len() as u64;
    loop {
        let fehler = |reason: &str| EwfError::BadSection {
            segment,
            offset: off,
            reason: reason.into(),
        };
        if out.len() >= MAX_SECTIONS {
            return Err(fehler("zu viele Sektionen"));
        }
        let d = data
            .get(off as usize..off as usize + DESCRIPTOR)
            .ok_or_else(|| fehler("Sektionsdeskriptor außerhalb der Datei"))?;
        if adler2::adler32_slice(&d[..72]) != u32_at(d, 72).unwrap_or(0) {
            return Err(fehler("Prüfsumme des Sektionsdeskriptors stimmt nicht"));
        }
        let kind: String = d[..16]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| char::from(b))
            .collect();
        let next = u64_at(d, 16).unwrap_or(0);
        let size = u64_at(d, 24).unwrap_or(0);
        let ende_kette = kind == "done" || kind == "next" || next == off;
        let end = if next > off {
            next
        } else {
            off.saturating_add(size.max(DESCRIPTOR as u64))
        }
        .min(len);
        out.push(Section {
            kind,
            start: off,
            end,
        });
        if ende_kette {
            break;
        }
        if next <= off || next >= len {
            return Err(fehler("Verweis auf die nächste Sektion unstimmig"));
        }
        off = next;
    }
    Ok(out)
}

/// Geometrie aus `volume`/`disk`: 1052 Byte (EnCase 2 bis 7, FTK, linen)
/// oder 94 Byte (EWF-Grundformat, EnCase 1, SMART; Sektorzahl dort 32 Bit).
/// Zweiter Wert: Adler-32 der Sektion stimmt.
fn read_geometry(body: &[u8], segment: usize, offset: u64) -> Result<(Geometry, bool), EwfError> {
    let fehler = || EwfError::BadSection {
        segment,
        offset,
        reason: format!("Sektion volume mit {} Byte zu kurz", body.len()),
    };
    let gross = body.len() >= 1052;
    let (pruef_ende, sektoren) = if gross {
        (1048, u64_at(body, 16).ok_or_else(fehler)?)
    } else if body.len() >= 94 {
        (90, u64::from(u32_at(body, 16).ok_or_else(fehler)?))
    } else {
        return Err(fehler());
    };
    let pruef_ok =
        adler2::adler32_slice(&body[..pruef_ende]) == u32_at(body, pruef_ende).unwrap_or(0);
    let set_id: Option<[u8; 16]> = if gross {
        body.get(64..80)
            .and_then(|b| b.try_into().ok())
            .filter(|b: &[u8; 16]| b.iter().any(|x| *x != 0))
    } else {
        None
    };
    Ok((
        Geometry {
            chunk_count: u64::from(u32_at(body, 4).ok_or_else(fehler)?),
            sectors_per_chunk: u32_at(body, 8).ok_or_else(fehler)?,
            bytes_per_sector: u32_at(body, 12).ok_or_else(fehler)?,
            sector_count: sektoren,
            set_id,
        },
        pruef_ok,
    ))
}

/// Chunks einer `table`- oder `table2`-Sektion. Offsets sind relativ zum
/// Basisoffset im Tabellenkopf (EnCase 6 und neuer, sonst 0 = Dateianfang);
/// das gesetzte oberste Bit kennzeichnet Kompression. Ein Chunk endet am
/// nächsten Eintrag, der letzte am Ende der Sektion, in der er liegt.
fn read_table(
    data: &[u8],
    sections: &[Section],
    si: usize,
    segment: usize,
) -> Result<Vec<ChunkLocation>, EwfError> {
    let s = &sections[si];
    let fehler = |reason: String| EwfError::BadSection {
        segment: segment + 1,
        offset: s.start,
        reason,
    };
    let body = data
        .get(s.start as usize + DESCRIPTOR..s.end as usize)
        .ok_or_else(|| fehler("Tabelle außerhalb der Datei".into()))?;
    let kopf = body
        .get(..24)
        .ok_or_else(|| fehler("Tabellenkopf fehlt".into()))?;
    if adler2::adler32_slice(&kopf[..20]) != u32_at(kopf, 20).unwrap_or(0) {
        return Err(fehler("Prüfsumme des Tabellenkopfs stimmt nicht".into()));
    }
    let anzahl = u32_at(kopf, 0).unwrap_or(0) as usize;
    let basis = u64_at(kopf, 8).unwrap_or(0);
    let eintraege = body
        .get(24..24 + anzahl * 4)
        .ok_or_else(|| fehler(format!("{anzahl} Einträge passen nicht in die Sektion")))?;
    let roh: Vec<(u64, bool)> = eintraege
        .chunks_exact(4)
        .map(|e| {
            let v = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
            (basis + u64::from(v & 0x7fff_ffff), v & 0x8000_0000 != 0)
        })
        .collect();
    let mut out = Vec::with_capacity(roh.len());
    for (i, &(start, compressed)) in roh.iter().enumerate() {
        let end = match roh.get(i + 1) {
            Some(&(n, _)) => n,
            None => sections
                .iter()
                .find(|x| x.start <= start && start < x.end)
                .map(|x| x.end)
                .ok_or_else(|| fehler(format!("Chunk bei {start:#x} in keiner Sektion")))?,
        };
        if end <= start || end > data.len() as u64 {
            return Err(fehler(format!(
                "Chunk {i} unstimmig ({start:#x} bis {end:#x})"
            )));
        }
        out.push(ChunkLocation {
            segment,
            offset: start,
            stored_len: end - start,
            compressed,
        });
    }
    Ok(out)
}

/// Vollständig entpackter zlib-Inhalt (für die kleinen Header-Sektionen).
fn inflate_all(raw: &[u8]) -> Option<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(raw, 16 << 20).ok()
}

fn nonzero16(body: &[u8]) -> Option<[u8; 16]> {
    body.get(..16)
        .and_then(|b| b.try_into().ok())
        .filter(|b: &[u8; 16]| b.iter().any(|x| *x != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmentnamen() {
        assert_eq!(segment_extension("E01", 2).as_deref(), Some("E02"));
        assert_eq!(segment_extension("E01", 99).as_deref(), Some("E99"));
        assert_eq!(segment_extension("E01", 100).as_deref(), Some("EAA"));
        assert_eq!(segment_extension("E01", 125).as_deref(), Some("EAZ"));
        assert_eq!(segment_extension("E01", 126).as_deref(), Some("EBA"));
        assert_eq!(
            segment_extension("E01", 100 + 26 * 26).as_deref(),
            Some("FAA")
        );
        assert_eq!(segment_extension("e01", 100).as_deref(), Some("eaa"));
        assert_eq!(segment_extension("s01", 3).as_deref(), Some("s03"));
        assert_eq!(
            segment_extension("E01", 100 + 22 * 26 * 26).as_deref(),
            None
        );
        assert_eq!(segment_extension("dd", 2), None);
        assert_eq!(
            segment_path(Path::new("/x/bild.E01"), 3),
            Some(PathBuf::from("/x/bild.E03"))
        );
    }

    #[test]
    fn unsinn_wird_abgewiesen() {
        assert!(matches!(
            EwfImage::from_bytes(vec![vec![0; 10]]),
            Err(EwfError::BadHeader { .. })
        ));
        let mut l01 = b"LVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00".to_vec();
        l01.resize(200, 0);
        assert!(matches!(
            EwfImage::from_bytes(vec![l01]),
            Err(EwfError::Unsupported(_))
        ));
        let mut falsche_nummer = SIGNATURE.to_vec();
        falsche_nummer.extend([1, 2, 0, 0, 0]);
        assert!(matches!(
            EwfImage::from_bytes(vec![falsche_nummer]),
            Err(EwfError::BadHeader { .. })
        ));
        assert!(EwfImage::from_bytes(Vec::new()).is_err());
    }
}
