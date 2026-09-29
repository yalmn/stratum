//! Herkunftsangaben aus dem benannten NTFS-Strom `Zone.Identifier`.
//!
//! Der Strom ist einfacher Text mit dem Abschnitt `[ZoneTransfer]`. Er belegt
//! eine gespeicherte Zonenzuordnung und gegebenenfalls die dort hinterlegten
//! URLs. Er belegt weder einen erfolgreichen Download noch die spätere
//! Ausführung der Datei.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use stratum_core::hash_bytes;
use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, FileEntry, Finding, Outcome};

const STREAM_NAME: &str = "Zone.Identifier";
const MAX_STREAM_SIZE: u64 = 64 * 1024;
const MAX_LINES: usize = 256;
const MAX_LINE_BYTES: usize = 8192;
const MAX_FINDINGS: usize = 100_000;
const MAX_WARNINGS: usize = 100;
/// Dateien je paralleler Arbeitseinheit.
const TASK: usize = 512;

/// Analyzer für die von Windows gespeicherte Herkunftszone einer Datei.
pub struct ZoneIdentifierAnalyzer;

impl Analyzer for ZoneIdentifierAnalyzer {
    fn domain(&self) -> &str {
        "dateiherkunft"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        let mut suppressed = 0usize;
        for index in &ctx.volumes {
            let (offset, size) = (index.target.offset, index.target.size);
            if let Err(error) = NtfsVolume::open(ctx.img, offset, size) {
                push_warning(
                    &mut out,
                    &mut suppressed,
                    format!("Volume {offset} nicht lesbar: {error}"),
                );
                continue;
            }
            // Jeder Datensatz wird einmal gelesen; die Blöcke laufen parallel,
            // die Reihenfolge der Ergebnisse bleibt die des Pfad-Index.
            let found = AtomicUsize::new(out.findings.len());
            let results: Vec<Vec<Inspected>> = index
                .files
                .par_chunks(TASK)
                .map_init(
                    || NtfsVolume::open(ctx.img, offset, size).ok(),
                    |volume, chunk| {
                        let Some(volume) = volume else {
                            return Vec::new();
                        };
                        let mut results = Vec::new();
                        for entry in chunk {
                            if found.load(Ordering::Relaxed) > MAX_FINDINGS {
                                break;
                            }
                            let result = inspect(volume, offset, entry);
                            if result.0.is_some() {
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                            if result.0.is_some() || !result.1.is_empty() {
                                results.push(result);
                            }
                        }
                        results
                    },
                )
                .collect();
            for (finding, warnings) in results.into_iter().flatten() {
                for warning in warnings {
                    push_warning(&mut out, &mut suppressed, warning);
                }
                if let Some(finding) = finding {
                    if out.findings.len() >= MAX_FINDINGS {
                        push_warning(
                            &mut out,
                            &mut suppressed,
                            format!("Grenze von {MAX_FINDINGS} Zone.Identifier-Funden erreicht"),
                        );
                        return out;
                    }
                    out.findings.push(finding);
                }
            }
        }
        if suppressed > 0 {
            out.warnings.push(format!(
                "{suppressed} weitere Zone.Identifier-Hinweise nicht einzeln aufgeführt"
            ));
        }
        out
    }
}

/// Ergebnis für eine Datei: Fund (falls ein `Zone.Identifier` existiert) und Hinweise.
type Inspected = (Option<Finding>, Vec<String>);

/// Prüft eine Datei auf einen `Zone.Identifier`-Strom und wertet ihn aus.
fn inspect<R: std::io::Read + std::io::Seek>(
    volume: &mut NtfsVolume<R>,
    volume_offset: u64,
    entry: &FileEntry,
) -> Inspected {
    let Ok(info) = volume.record_info(entry.mft_record, Some(entry.parent_record)) else {
        return (None, Vec::new());
    };
    let Some(stream) = info
        .streams
        .iter()
        .find(|stream| stream.name.eq_ignore_ascii_case(STREAM_NAME))
    else {
        return (None, Vec::new());
    };
    let source = format!("{}:{}:$DATA", entry.path, stream.name);
    let Some(record_offset) = info.record_offset else {
        return (
            None,
            vec![format!("{source}: MFT-Datensatzoffset nicht bestimmbar")],
        );
    };
    let finding = Finding::new(
        "dateiherkunft",
        entry.path.rsplit('\\').next().unwrap_or(&entry.path),
        &source,
    )
    .at(record_offset)
    .with("art", "zone_identifier")
    .with("dateipfad", &entry.path)
    .with("strom", &stream.name)
    .with("strom_groesse", stream.size.to_string())
    .with("mft_record", entry.mft_record.to_string())
    .with("volume_offset", volume_offset.to_string())
    .with("mft_record_offset", record_offset.to_string())
    .with("offset_art", "MFT-Datensatz als Quellenanker")
    .with(
        "aussage",
        "gespeicherte Herkunftszone; Download und Ausführung dadurch nicht belegt",
    );
    if stream.size > MAX_STREAM_SIZE {
        return (
            Some(finding.with("auswertung_status", "zu_gross")),
            vec![format!(
                "{source}: {} Bytes, Grenze {MAX_STREAM_SIZE}, nicht gelesen",
                stream.size
            )],
        );
    }
    let data = match volume.read_stream_by_record(entry.mft_record, &entry.path, &stream.name) {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                Some(finding.with("auswertung_status", "nicht_lesbar")),
                vec![format!("{source}: Strom nicht mehr lesbar")],
            );
        }
        Err(error) => {
            return (
                Some(finding.with("auswertung_status", "nicht_lesbar")),
                vec![format!("{source}: {error}")],
            );
        }
    };
    let hashes = hash_bytes(&data.data);
    let finding = finding
        .with("strom_sha256", hashes.sha256)
        .with("strom_blake3", hashes.blake3)
        .with("gelesene_bytes", hashes.bytes.to_string());
    match parse(&data.data) {
        Ok(parsed) => {
            let mut finding = add_fields(finding, &parsed);
            if !parsed.hinweise.is_empty() {
                finding = finding.with("parser_hinweise", parsed.hinweise.join("; "));
            }
            (
                Some(finding.with("auswertung_status", "gelesen")),
                Vec::new(),
            )
        }
        Err(error) => (
            Some(
                finding
                    .with("auswertung_status", "format_nicht_lesbar")
                    .with("parser_fehler", &error),
            ),
            vec![format!("{source}: {error}")],
        ),
    }
}

fn push_warning(out: &mut Outcome, suppressed: &mut usize, warning: String) {
    if out.warnings.len() < MAX_WARNINGS {
        out.warnings.push(warning);
    } else {
        *suppressed += 1;
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedZone {
    fields: BTreeMap<String, String>,
    weitere_felder: Vec<String>,
    hinweise: Vec<String>,
    kodierung: &'static str,
}

fn parse(data: &[u8]) -> Result<ParsedZone, String> {
    let (text, kodierung) = decode(data)?;
    if text.contains('\0') {
        return Err("Strom enthält Nullzeichen".into());
    }
    let mut fields = BTreeMap::new();
    let mut weitere_felder = Vec::new();
    let mut hinweise = Vec::new();
    let mut in_zone_transfer = false;
    let mut found_section = false;
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_LINES {
            return Err(format!("mehr als {MAX_LINES} Zeilen"));
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(format!(
                "Zeile {} länger als {MAX_LINE_BYTES} Byte",
                index + 1
            ));
        }
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_zone_transfer = section.eq_ignore_ascii_case("ZoneTransfer");
            found_section |= in_zone_transfer;
            continue;
        }
        if !in_zone_transfer {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            hinweise.push(format!("Zeile {} ohne Gleichheitszeichen", index + 1));
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            hinweise.push(format!("Zeile {} ohne Feldname", index + 1));
            continue;
        }
        let normalized = key.to_ascii_lowercase();
        if fields.contains_key(&normalized) {
            hinweise.push(format!("Feld {key} mehrfach vorhanden"));
            continue;
        }
        let value = value.trim().to_string();
        if !is_known_field(&normalized) {
            weitere_felder.push(format!("{key}={value}"));
        }
        fields.insert(normalized, value);
    }
    if !found_section {
        return Err("Abschnitt [ZoneTransfer] fehlt".into());
    }
    if fields
        .get("zoneid")
        .is_some_and(|value| value.parse::<u32>().is_err())
    {
        hinweise.push("ZoneId ist keine vorzeichenlose Ganzzahl".into());
    }
    Ok(ParsedZone {
        fields,
        weitere_felder,
        hinweise,
        kodierung,
    })
}

fn decode(data: &[u8]) -> Result<(String, &'static str), String> {
    if let Some(data) = data.strip_prefix(b"\xff\xfe") {
        if !data.len().is_multiple_of(2) {
            return Err("UTF-16LE-Strom mit ungerader Bytelänge".into());
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();
        return String::from_utf16(&units)
            .map(|text| (text, "UTF-16LE"))
            .map_err(|_| "ungültiges UTF-16LE".into());
    }
    if let Some(data) = data.strip_prefix(b"\xfe\xff") {
        if !data.len().is_multiple_of(2) {
            return Err("UTF-16BE-Strom mit ungerader Bytelänge".into());
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .collect();
        return String::from_utf16(&units)
            .map(|text| (text, "UTF-16BE"))
            .map_err(|_| "ungültiges UTF-16BE".into());
    }
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    std::str::from_utf8(data)
        .map(|text| (text.to_string(), "UTF-8"))
        .map_err(|_| "Strom ist weder gültiges UTF-8 noch UTF-16 mit BOM".into())
}

fn is_known_field(key: &str) -> bool {
    matches!(
        key,
        "zoneid" | "hosturl" | "referrerurl" | "lastwriterpackagefamilyname" | "appdefinedzoneid"
    )
}

fn add_fields(mut finding: Finding, parsed: &ParsedZone) -> Finding {
    finding = finding.with("kodierung", parsed.kodierung);
    for (source, target) in [
        ("zoneid", "zone_id"),
        ("hosturl", "host_url"),
        ("referrerurl", "referrer_url"),
        (
            "lastwriterpackagefamilyname",
            "last_writer_package_family_name",
        ),
        ("appdefinedzoneid", "app_defined_zone_id"),
    ] {
        if let Some(value) = parsed.fields.get(source) {
            finding = finding.with(target, value);
        }
    }
    if let Some(zone) = parsed
        .fields
        .get("zoneid")
        .and_then(|value| value.parse::<u32>().ok())
        .and_then(zone_name)
    {
        finding = finding.with("zone_name", zone);
    }
    if !parsed.weitere_felder.is_empty() {
        finding = finding.with("weitere_felder", parsed.weitere_felder.join(", "));
    }
    finding
}

fn zone_name(zone: u32) -> Option<&'static str> {
    match zone {
        0 => Some("lokaler_computer"),
        1 => Some("intranet"),
        2 => Some("vertrauenswürdig"),
        3 => Some("internet"),
        4 => Some("nicht_vertrauenswürdig"),
        _ => None,
    }
}

pub(crate) fn fuzz(data: &[u8]) {
    let _ = parse(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liest_zone_und_urls() {
        let parsed = parse(
            b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/start\r\nHostUrl=https://example.test/datei.exe\r\nX-Test=roh\r\n",
        )
        .unwrap();
        assert_eq!(parsed.fields["zoneid"], "3");
        assert_eq!(parsed.fields["hosturl"], "https://example.test/datei.exe");
        assert_eq!(parsed.weitere_felder, vec!["X-Test=roh"]);
        assert_eq!(parsed.kodierung, "UTF-8");
        assert_eq!(zone_name(3), Some("internet"));
    }

    #[test]
    fn liest_utf16_und_store_felder() {
        let text = "[ZoneTransfer]\r\nZoneId=2\r\nLastWriterPackageFamilyName=Paket_123\r\nAppDefinedZoneId=7\r\n";
        let mut data = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.fields["lastwriterpackagefamilyname"], "Paket_123");
        assert_eq!(parsed.fields["appdefinedzoneid"], "7");
        assert_eq!(parsed.kodierung, "UTF-16LE");
    }

    #[test]
    fn formatfehler_werden_nicht_erraten() {
        assert!(parse(b"ZoneId=3").is_err());
        assert!(parse(&[0xff, 0xfe, 0x41]).is_err());
        let parsed = parse(b"[ZoneTransfer]\nZoneId=3\nZoneId=4\nkaputt").unwrap();
        assert_eq!(parsed.fields["zoneid"], "3");
        assert_eq!(parsed.hinweise.len(), 2);
        assert_eq!(zone_name(999), None);
        assert!(parse(b"[ZoneTransfer]\nZoneId=3\0").is_err());
        let parsed = parse(b"[ZoneTransfer]\nZoneId=unbekannt").unwrap();
        assert_eq!(parsed.hinweise.len(), 1);
    }
}
