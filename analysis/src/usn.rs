//! Streaming-Auswertung des NTFS-Änderungsjournals `$UsnJrnl:$J`.

use std::io::{Error, ErrorKind, Write};

use serde::Serialize;
use stratum_core::time::filetime_to_iso;
use stratum_core::ImageReader;
use stratum_ntfs::NtfsVolume;

use crate::FsIndex;

/// Quelle des Änderungsjournals im NTFS-Systemverzeichnis.
pub const USN_JOURNAL_SOURCE: &str = "$Extend\\$UsnJrnl:$J";

const JOURNAL_PATH: &str = "$Extend\\$UsnJrnl";
const JOURNAL_STREAM: &str = "$J";
const CHUNK_SIZE: u64 = 4 * 1024 * 1024;
const MAX_RECORD_SIZE: usize = 64 * 1024;

/// Zusammenfassung einer geschriebenen USN-Zeitachse.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsnJournalSummary {
    /// NTFS-Volumes mit vorhandenem Änderungsjournal.
    pub journals: u64,
    /// NTFS-Volumes ohne `$UsnJrnl:$J`.
    pub ohne_journal: u64,
    /// Logische Länge der ausgewerteten Journale.
    pub logische_bytes: u64,
    /// Tatsächlich gelesene, physisch belegte Bytes.
    pub belegte_bytes: u64,
    /// Geschriebene USN-Datensätze.
    pub datensaetze: u64,
    /// Datensätze im Format USN_RECORD_V2.
    pub version_2: u64,
    /// Datensätze im Format USN_RECORD_V3.
    pub version_3: u64,
    /// Datensätze mit unbekannter Hauptversion.
    pub unbekannte_version: u64,
    /// Beschädigte oder unplausible Datensatzköpfe.
    pub fehler: u64,
    /// Unvollständiger Datensatz am Ende eines belegten Bereichs.
    pub abgeschnitten: u64,
    /// Datensätze mit `FILE_CREATE`.
    pub erstellt: u64,
    /// Datensätze mit `FILE_DELETE`.
    pub geloescht: u64,
    /// Datensätze mit `RENAME_OLD_NAME`.
    pub umbenannt_alt: u64,
    /// Datensätze mit `RENAME_NEW_NAME`.
    pub umbenannt_neu: u64,
    /// Volume-Offsets mit vorhandenem Journal.
    pub volumes: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct EventLine {
    volume_offset: u64,
    stream_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_offset: Option<u64>,
    record_length: u32,
    version_major: u16,
    version_minor: u16,
    dateireferenz: String,
    elternreferenz: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mft_record: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequenz: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eltern_mft_record: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eltern_sequenz: Option<u16>,
    usn: i64,
    filetime: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    zeit_utc: Option<String>,
    reason: u32,
    gruende: Vec<&'static str>,
    unbekannte_reason_bits: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    name: String,
    quelle: &'static str,
}

struct ParsedRecord {
    line: EventLine,
}

/// Schreibt alle lesbaren V2- und V3-Datensätze aus `$UsnJrnl:$J` als JSON
/// Lines in ihrer Reihenfolge im Journal.
///
/// Spärliche Bereiche werden nicht materialisiert. Jeder ausgegebene
/// Datensatz trägt seinen logischen Stromoffset und, bei nicht-residenten
/// Journalen, den absoluten Byte-Offset seiner Quelle im Image.
pub fn write_usn_journal<W: Write>(
    img: &ImageReader,
    volumes: &[FsIndex],
    mut out: W,
) -> std::io::Result<UsnJournalSummary> {
    let mut summary = UsnJournalSummary::default();
    for index in volumes {
        let target = index.target;
        let mut volume = NtfsVolume::open(img, target.offset, target.size).map_err(invalid_data)?;
        let Some(layout) = volume
            .data_stream_layout(JOURNAL_PATH, JOURNAL_STREAM)
            .map_err(invalid_data)?
        else {
            summary.ohne_journal += 1;
            continue;
        };
        summary.journals += 1;
        summary.logische_bytes = summary.logische_bytes.saturating_add(layout.logical_size);
        summary.belegte_bytes = summary.belegte_bytes.saturating_add(layout.allocated_size);
        summary.volumes.push(target.offset);

        let mut scanner = Scanner::new(&mut out, &mut summary, target.offset);
        if let Some(data) = layout.resident {
            scanner.feed(0, layout.resident_image_offset, &data)?;
        } else {
            for run in layout.runs {
                let Some(image_offset) = run.image_offset else {
                    scanner.gap(run.logical_offset.saturating_add(run.length));
                    continue;
                };
                let mut done = 0u64;
                while done < run.length {
                    let take = CHUNK_SIZE.min(run.length - done);
                    let take_usize = usize::try_from(take)
                        .map_err(|_| Error::new(ErrorKind::InvalidData, "USN-Lauf zu groß"))?;
                    let source = image_offset.checked_add(done).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "USN-Image-Offset überläuft")
                    })?;
                    let data = img.read_at(source, take_usize).map_err(Error::other)?;
                    scanner.feed(run.logical_offset + done, Some(source), data)?;
                    done += take;
                }
            }
        }
        scanner.finish();
    }
    out.flush()?;
    Ok(summary)
}

fn invalid_data(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::InvalidData, error.to_string())
}

struct Pending {
    data: Vec<u8>,
    expected: Option<usize>,
    logical_offset: u64,
    image_offset: Option<u64>,
    next_logical: u64,
}

struct Scanner<'a, W: Write> {
    out: &'a mut W,
    summary: &'a mut UsnJournalSummary,
    volume_offset: u64,
    pending: Option<Pending>,
}

impl<'a, W: Write> Scanner<'a, W> {
    fn new(out: &'a mut W, summary: &'a mut UsnJournalSummary, volume_offset: u64) -> Self {
        Self {
            out,
            summary,
            volume_offset,
            pending: None,
        }
    }

    fn gap(&mut self, next_logical: u64) {
        if self.pending.take().is_some() {
            self.summary.abgeschnitten += 1;
        }
        let _ = next_logical;
    }

    fn finish(&mut self) {
        if self.pending.take().is_some() {
            self.summary.abgeschnitten += 1;
        }
    }

    fn feed(
        &mut self,
        logical_offset: u64,
        image_offset: Option<u64>,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut used = 0usize;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.next_logical != logical_offset)
        {
            self.pending = None;
            self.summary.abgeschnitten += 1;
        }
        if let Some(mut pending) = self.pending.take() {
            if pending.expected.is_none() {
                let take = (8 - pending.data.len()).min(data.len());
                pending.data.extend_from_slice(&data[..take]);
                pending.next_logical += take as u64;
                used += take;
                if pending.data.len() == 8 {
                    pending.expected = plausible_header(&pending.data);
                    if pending.expected.is_none() {
                        self.summary.fehler += 1;
                    }
                }
            }
            if let Some(expected) = pending.expected {
                let take = (expected - pending.data.len()).min(data.len() - used);
                pending.data.extend_from_slice(&data[used..used + take]);
                pending.next_logical += take as u64;
                used += take;
                if pending.data.len() == expected {
                    self.write_record(&pending.data, pending.logical_offset, pending.image_offset)?;
                } else {
                    self.pending = Some(pending);
                    return Ok(());
                }
            }
        }

        while used < data.len() {
            let remaining = &data[used..];
            if remaining.len() < 8 {
                self.pending = Some(Pending {
                    data: remaining.to_vec(),
                    expected: None,
                    logical_offset: logical_offset + used as u64,
                    image_offset: image_offset.map(|offset| offset + used as u64),
                    next_logical: logical_offset + data.len() as u64,
                });
                break;
            }
            let length = match plausible_header(remaining) {
                Some(length) => length,
                None => {
                    if remaining[..8].iter().any(|byte| *byte != 0) {
                        self.summary.fehler += 1;
                    }
                    used += 8;
                    continue;
                }
            };
            if length > remaining.len() {
                self.pending = Some(Pending {
                    data: remaining.to_vec(),
                    expected: Some(length),
                    logical_offset: logical_offset + used as u64,
                    image_offset: image_offset.map(|offset| offset + used as u64),
                    next_logical: logical_offset + data.len() as u64,
                });
                break;
            }
            self.write_record(
                &remaining[..length],
                logical_offset + used as u64,
                image_offset.map(|offset| offset + used as u64),
            )?;
            used += length;
        }
        Ok(())
    }

    fn write_record(
        &mut self,
        bytes: &[u8],
        logical_offset: u64,
        image_offset: Option<u64>,
    ) -> std::io::Result<()> {
        match parse_record(bytes, self.volume_offset, logical_offset, image_offset) {
            Ok(parsed) => {
                if parsed.line.reason & 0x0000_0100 != 0 {
                    self.summary.erstellt += 1;
                }
                if parsed.line.reason & 0x0000_0200 != 0 {
                    self.summary.geloescht += 1;
                }
                if parsed.line.reason & 0x0000_1000 != 0 {
                    self.summary.umbenannt_alt += 1;
                }
                if parsed.line.reason & 0x0000_2000 != 0 {
                    self.summary.umbenannt_neu += 1;
                }
                match parsed.line.version_major {
                    2 => self.summary.version_2 += 1,
                    3 => self.summary.version_3 += 1,
                    _ => self.summary.unbekannte_version += 1,
                }
                serde_json::to_writer(&mut self.out, &parsed.line).map_err(Error::other)?;
                self.out.write_all(b"\n")?;
                self.summary.datensaetze += 1;
            }
            Err(ParseError::Unsupported) => self.summary.unbekannte_version += 1,
            Err(ParseError::Invalid) => self.summary.fehler += 1,
        }
        Ok(())
    }
}

fn plausible_header(bytes: &[u8]) -> Option<usize> {
    let length = read_u32(bytes, 0)? as usize;
    if !(8..=MAX_RECORD_SIZE).contains(&length) || !length.is_multiple_of(8) {
        return None;
    }
    Some(length)
}

#[derive(Debug)]
enum ParseError {
    Invalid,
    Unsupported,
}

fn parse_record(
    bytes: &[u8],
    volume_offset: u64,
    stream_offset: u64,
    image_offset: Option<u64>,
) -> Result<ParsedRecord, ParseError> {
    let record_length = read_u32(bytes, 0).ok_or(ParseError::Invalid)?;
    if record_length as usize != bytes.len() {
        return Err(ParseError::Invalid);
    }
    let major = read_u16(bytes, 4).ok_or(ParseError::Invalid)?;
    let minor = read_u16(bytes, 6).ok_or(ParseError::Invalid)?;
    let (file_ref, parent_ref, base) = match major {
        2 if bytes.len() >= 60 => (
            Reference::V2(read_u64(bytes, 8).ok_or(ParseError::Invalid)?),
            Reference::V2(read_u64(bytes, 16).ok_or(ParseError::Invalid)?),
            24,
        ),
        3 if bytes.len() >= 76 => (
            Reference::V3(read_array_16(bytes, 8).ok_or(ParseError::Invalid)?),
            Reference::V3(read_array_16(bytes, 24).ok_or(ParseError::Invalid)?),
            40,
        ),
        2 | 3 => return Err(ParseError::Invalid),
        _ => return Err(ParseError::Unsupported),
    };
    let usn = read_i64(bytes, base).ok_or(ParseError::Invalid)?;
    let filetime = read_i64(bytes, base + 8).ok_or(ParseError::Invalid)?;
    let reason = read_u32(bytes, base + 16).ok_or(ParseError::Invalid)?;
    let source_info = read_u32(bytes, base + 20).ok_or(ParseError::Invalid)?;
    let security_id = read_u32(bytes, base + 24).ok_or(ParseError::Invalid)?;
    let file_attributes = read_u32(bytes, base + 28).ok_or(ParseError::Invalid)?;
    let name_length = read_u16(bytes, base + 32).ok_or(ParseError::Invalid)? as usize;
    let name_offset = read_u16(bytes, base + 34).ok_or(ParseError::Invalid)? as usize;
    if !name_length.is_multiple_of(2) {
        return Err(ParseError::Invalid);
    }
    let name_end = name_offset
        .checked_add(name_length)
        .filter(|end| *end <= bytes.len())
        .ok_or(ParseError::Invalid)?;
    let name = String::from_utf16_lossy(
        &bytes[name_offset..name_end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    let (reasons, known) = reason_names(reason);
    let (mft_record, sequence) = file_ref.v2_parts();
    let (parent_record, parent_sequence) = parent_ref.v2_parts();
    Ok(ParsedRecord {
        line: EventLine {
            volume_offset,
            stream_offset,
            image_offset,
            record_length,
            version_major: major,
            version_minor: minor,
            dateireferenz: file_ref.text(),
            elternreferenz: parent_ref.text(),
            mft_record,
            sequenz: sequence,
            eltern_mft_record: parent_record,
            eltern_sequenz: parent_sequence,
            usn,
            filetime,
            zeit_utc: u64::try_from(filetime).ok().and_then(filetime_to_iso),
            reason,
            gruende: reasons,
            unbekannte_reason_bits: reason & !known,
            source_info,
            security_id,
            file_attributes,
            name,
            quelle: USN_JOURNAL_SOURCE,
        },
    })
}

enum Reference {
    V2(u64),
    V3([u8; 16]),
}

impl Reference {
    fn text(&self) -> String {
        match self {
            Self::V2(value) => format!("{value:016x}"),
            Self::V3(value) => value.iter().map(|byte| format!("{byte:02x}")).collect(),
        }
    }

    fn v2_parts(&self) -> (Option<u64>, Option<u16>) {
        match self {
            Self::V2(value) => (
                Some(value & 0x0000_ffff_ffff_ffff),
                Some((value >> 48) as u16),
            ),
            Self::V3(_) => (None, None),
        }
    }
}

fn reason_names(reason: u32) -> (Vec<&'static str>, u32) {
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0001, "DATA_OVERWRITE"),
        (0x0000_0002, "DATA_EXTEND"),
        (0x0000_0004, "DATA_TRUNCATION"),
        (0x0000_0010, "NAMED_DATA_OVERWRITE"),
        (0x0000_0020, "NAMED_DATA_EXTEND"),
        (0x0000_0040, "NAMED_DATA_TRUNCATION"),
        (0x0000_0100, "FILE_CREATE"),
        (0x0000_0200, "FILE_DELETE"),
        (0x0000_0400, "EA_CHANGE"),
        (0x0000_0800, "SECURITY_CHANGE"),
        (0x0000_1000, "RENAME_OLD_NAME"),
        (0x0000_2000, "RENAME_NEW_NAME"),
        (0x0000_4000, "INDEXABLE_CHANGE"),
        (0x0000_8000, "BASIC_INFO_CHANGE"),
        (0x0001_0000, "HARD_LINK_CHANGE"),
        (0x0002_0000, "COMPRESSION_CHANGE"),
        (0x0004_0000, "ENCRYPTION_CHANGE"),
        (0x0008_0000, "OBJECT_ID_CHANGE"),
        (0x0010_0000, "REPARSE_POINT_CHANGE"),
        (0x0020_0000, "STREAM_CHANGE"),
        (0x0040_0000, "TRANSACTED_CHANGE"),
        (0x0080_0000, "INTEGRITY_CHANGE"),
        (0x8000_0000, "CLOSE"),
    ];
    let mut names = Vec::new();
    let mut known = 0u32;
    for &(flag, name) in FLAGS {
        if reason & flag != 0 {
            names.push(name);
            known |= flag;
        }
    }
    (names, known)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_i64(data: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_array_16(data: &[u8], offset: usize) -> Option<[u8; 16]> {
    data.get(offset..offset + 16)?.try_into().ok()
}

pub(crate) fn fuzz(data: &[u8]) {
    let mut output = std::io::sink();
    let mut summary = UsnJournalSummary::default();
    let mut scanner = Scanner::new(&mut output, &mut summary, 0);
    let _ = scanner.feed(0, Some(0), data);
    scanner.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(name: &str, reason: u32) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let raw_len = 60 + utf16.len() * 2;
        let length = raw_len.div_ceil(8) * 8;
        let mut data = vec![0u8; length];
        data[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        data[8..16].copy_from_slice(&((7u64 << 48) | 42).to_le_bytes());
        data[16..24].copy_from_slice(&((3u64 << 48) | 5).to_le_bytes());
        data[24..32].copy_from_slice(&1234i64.to_le_bytes());
        data[32..40].copy_from_slice(&133_700_000_000_000_000i64.to_le_bytes());
        data[40..44].copy_from_slice(&reason.to_le_bytes());
        data[56..58].copy_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
        data[58..60].copy_from_slice(&60u16.to_le_bytes());
        for (index, value) in utf16.into_iter().enumerate() {
            let start = 60 + index * 2;
            data[start..start + 2].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    fn v3(name: &str) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let raw_len = 76 + utf16.len() * 2;
        let length = raw_len.div_ceil(8) * 8;
        let mut data = vec![0u8; length];
        data[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        data[8..24].copy_from_slice(&[0x11; 16]);
        data[24..40].copy_from_slice(&[0x22; 16]);
        data[40..48].copy_from_slice(&99i64.to_le_bytes());
        data[48..56].copy_from_slice(&133_700_000_000_000_000i64.to_le_bytes());
        data[56..60].copy_from_slice(&0x2000u32.to_le_bytes());
        data[72..74].copy_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
        data[74..76].copy_from_slice(&76u16.to_le_bytes());
        for (index, value) in utf16.into_iter().enumerate() {
            let start = 76 + index * 2;
            data[start..start + 2].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    #[test]
    fn v2_felder_und_gruende() {
        let bytes = v2("alt.txt", 0x8000_1100);
        let parsed = parse_record(&bytes, 4096, 8192, Some(12_288)).unwrap();
        assert_eq!(parsed.line.mft_record, Some(42));
        assert_eq!(parsed.line.sequenz, Some(7));
        assert_eq!(parsed.line.eltern_mft_record, Some(5));
        assert_eq!(parsed.line.name, "alt.txt");
        assert_eq!(parsed.line.image_offset, Some(12_288));
        assert_eq!(
            parsed.line.gruende,
            vec!["FILE_CREATE", "RENAME_OLD_NAME", "CLOSE"]
        );
    }

    #[test]
    fn scanner_verbindet_chunkgrenze() {
        let record = v2("grenze.txt", 0x200);
        let mut output = Vec::new();
        let mut summary = UsnJournalSummary::default();
        let mut scanner = Scanner::new(&mut output, &mut summary, 0);
        scanner.feed(100, Some(1000), &record[..17]).unwrap();
        scanner.feed(117, Some(2000), &record[17..]).unwrap();
        scanner.finish();
        assert_eq!(summary.datensaetze, 1);
        assert_eq!(summary.geloescht, 1);
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["stream_offset"], 100);
        assert_eq!(json["image_offset"], 1000);
    }

    #[test]
    fn v3_behaelt_128_bit_referenzen() {
        let bytes = v3("neu.txt");
        let parsed = parse_record(&bytes, 0, 0, Some(4096)).unwrap();
        assert_eq!(parsed.line.version_major, 3);
        assert_eq!(parsed.line.dateireferenz, "11".repeat(16));
        assert_eq!(parsed.line.elternreferenz, "22".repeat(16));
        assert_eq!(parsed.line.mft_record, None);
        assert_eq!(parsed.line.name, "neu.txt");
        assert_eq!(parsed.line.gruende, vec!["RENAME_NEW_NAME"]);
    }

    #[test]
    fn unplausible_laengen_werden_abgewiesen() {
        assert!(plausible_header(&[0; 8]).is_none());
        let mut data = v2("x", 1);
        data[0..4].copy_from_slice(&7u32.to_le_bytes());
        assert!(plausible_header(&data).is_none());
    }
}
