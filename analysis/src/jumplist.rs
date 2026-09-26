//! Jump Lists: zuletzt genutzte Dateien und Aufgaben je Anwendung.
//!
//! Windows legt je Anwendung eine Jump-List an. Es gibt zwei Formen:
//!
//! - `*.automaticDestinations-ms`: eine OLE-Verbunddatei (CFBF), deren Streams
//!   jeweils eine eingebettete Verknüpfung (LNK) sind.
//! - `*.customDestinations-ms`: eine Folge von LNK-Strukturen mit einem kleinen
//!   Kopf.
//!
//! Der Dateiname (ohne Endung) ist die Anwendungskennung (AppID). Aus den
//! eingebetteten Verknüpfungen werden Zielpfad, Zeitstempel und Datenträger-
//! Seriennummer gelesen (siehe [`crate::lnk`]).

use stratum_ntfs::NtfsVolume;

use crate::lnk::{parse_lnk, Lnk};
use crate::{AnalysisContext, Analyzer, Finding, FsIndex, Outcome};

/// Analyzer für Jump Lists.
pub struct JumpListAnalyzer;

impl Analyzer for JumpListAnalyzer {
    fn domain(&self) -> &str {
        "useraktivitaet"
    }

    fn run(&self, ctx: &AnalysisContext<'_>) -> Outcome {
        let mut out = Outcome::default();
        for v in &ctx.volumes {
            let mut vol = match NtfsVolume::open(ctx.img, v.target.offset, v.target.size) {
                Ok(vol) => vol,
                Err(e) => {
                    out.warnings
                        .push(format!("Offset {} nicht lesbar: {e}", v.target.offset));
                    continue;
                }
            };
            automatic(&mut vol, v, &mut out);
            custom(&mut vol, v, &mut out);
        }
        out
    }
}

fn automatic<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    let dateien: Vec<_> = v
        .by_extension(&["automaticdestinations-ms"])
        .filter(|e| e.size > 0 && e.size < 20_000_000)
        .cloned()
        .collect();
    for e in dateien {
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let benutzer = benutzer_aus_pfad(&e.path);
        let appid = appid_aus_pfad(&e.path);
        let Some(streams) = read_cfbf_streams(&f.data) else {
            out.warnings.push(format!("{}: CFBF nicht lesbar", e.path));
            continue;
        };
        for (name, bytes) in streams {
            // Der DestList-Stream ist Metadaten, kein LNK.
            if name.eq_ignore_ascii_case("DestList") {
                continue;
            }
            if let Some(link) = parse_lnk(&bytes) {
                out.findings
                    .push(lnk_finding(&link, &e.path, &benutzer, &appid, Some(&name)));
            }
        }
    }
}

fn custom<R: std::io::Read + std::io::Seek>(
    vol: &mut NtfsVolume<R>,
    v: &FsIndex,
    out: &mut Outcome,
) {
    let dateien: Vec<_> = v
        .by_extension(&["customdestinations-ms"])
        .filter(|e| e.size > 0 && e.size < 20_000_000)
        .cloned()
        .collect();
    for e in dateien {
        let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
            continue;
        };
        let benutzer = benutzer_aus_pfad(&e.path);
        let appid = appid_aus_pfad(&e.path);
        for lnk in split_embedded_lnks(&f.data) {
            if let Some(link) = parse_lnk(lnk) {
                out.findings
                    .push(lnk_finding(&link, &e.path, &benutzer, &appid, None));
            }
        }
    }
}

/// Baut einen Fund aus einer eingebetteten Verknüpfung.
fn lnk_finding(
    link: &Lnk,
    source: &str,
    benutzer: &str,
    appid: &str,
    stream: Option<&str>,
) -> Finding {
    let name = if link.target_path.is_empty() {
        format!("Jump-List {appid}")
    } else {
        link.target_path.clone()
    };
    let mut fd = Finding::new("useraktivitaet", name, source).with("art", "jumplist");
    if !benutzer.is_empty() {
        fd = fd.with("benutzer", benutzer);
    }
    if !appid.is_empty() {
        fd = fd.with("appid", appid);
    }
    if let Some(s) = stream {
        fd = fd.with("stream", s);
    }
    if !link.target_path.is_empty() {
        fd = fd.with("zielpfad", link.target_path.clone());
    }
    if let Some(s) = link.drive_serial {
        fd = fd.with("laufwerk_seriennummer", format!("{s:08x}"));
    }
    if link.file_size > 0 {
        fd = fd.with("zielgroesse", link.file_size.to_string());
    }
    for (k, t) in [
        ("ziel_erstellt_unix", link.created),
        ("ziel_geaendert_unix", link.modified),
        ("ziel_zugriff_unix", link.accessed),
    ] {
        if let Some(z) = t {
            fd = fd.with(k, z.to_string());
        }
    }
    fd
}

fn benutzer_aus_pfad(path: &str) -> String {
    let parts: Vec<&str> = path.split('\\').collect();
    for (i, p) in parts.iter().enumerate() {
        if p.eq_ignore_ascii_case("Users") {
            if let Some(name) = parts.get(i + 1) {
                return name.to_string();
            }
        }
    }
    String::new()
}

fn appid_aus_pfad(path: &str) -> String {
    let file = path.rsplit('\\').next().unwrap_or(path);
    file.split('.').next().unwrap_or(file).to_string()
}

/// Zerlegt eine CustomDestinations-Datei in ihre eingebetteten LNK-Strukturen,
/// indem nach der Shell-Link-Signatur (HeaderSize 0x4C + Link-CLSID) gesucht wird.
fn split_embedded_lnks(data: &[u8]) -> Vec<&[u8]> {
    const SIG: [u8; 20] = [
        0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    let mut starts = Vec::new();
    let mut i = 0;
    while i + SIG.len() <= data.len() {
        if data[i..i + SIG.len()] == SIG {
            starts.push(i);
            i += SIG.len();
        } else {
            i += 1;
        }
    }
    let mut out = Vec::new();
    for (idx, &s) in starts.iter().enumerate() {
        let end = starts.get(idx + 1).copied().unwrap_or(data.len());
        out.push(&data[s..end]);
    }
    out
}

// --- Minimaler CFBF-Leser (OLE Compound Binary File Format) ---

const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;

/// Liest die benannten Streams einer CFBF-Datei. `None`, wenn die Signatur
/// fehlt oder der Kopf unstimmig ist. Defensiv gegen fehlerhafte Strukturen.
fn read_cfbf_streams(data: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    if data.len() < 512 || data[..8] != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return None;
    }
    let u16at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
    let u32at = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);

    let sector_shift = u16at(30);
    if !(9..=16).contains(&sector_shift) {
        return None;
    }
    let sector_size = 1usize << sector_shift;
    let mini_shift = u16at(32);
    if !(4..=12).contains(&mini_shift) {
        return None;
    }
    let mini_size = 1usize << mini_shift;
    let num_fat = u32at(44) as usize;
    let first_dir = u32at(48);
    let mini_cutoff = u32at(56) as usize;
    let first_mini_fat = u32at(60);
    let num_mini_fat = u32at(64) as usize;
    let first_difat = u32at(68);
    let num_difat = u32at(72) as usize;

    // Byte-Bereich eines Sektors (Sektor 0 beginnt nach dem Kopf-Sektor).
    let sector = |n: u32| -> Option<&[u8]> {
        let start = sector_size.checked_add((n as usize).checked_mul(sector_size)?)?;
        data.get(start..start + sector_size)
    };

    // DIFAT einsammeln: 109 Einträge im Kopf, dann ggf. weitere DIFAT-Sektoren.
    let mut difat: Vec<u32> = (0..109).map(|i| u32at(76 + i * 4)).collect();
    let mut next = first_difat;
    let per = sector_size / 4;
    let mut guard = 0;
    while num_difat > 0 && next != ENDOFCHAIN && next != FREESECT && guard <= num_difat {
        let s = sector(next)?;
        for i in 0..per - 1 {
            difat.push(u32::from_le_bytes([
                s[i * 4],
                s[i * 4 + 1],
                s[i * 4 + 2],
                s[i * 4 + 3],
            ]));
        }
        next = u32::from_le_bytes([
            s[(per - 1) * 4],
            s[(per - 1) * 4 + 1],
            s[(per - 1) * 4 + 2],
            s[(per - 1) * 4 + 3],
        ]);
        guard += 1;
    }
    difat.truncate(num_fat.max(1) * per);

    // FAT aufbauen.
    let mut fat: Vec<u32> = Vec::new();
    for &fs in difat.iter().take(num_fat) {
        if fs == FREESECT || fs == ENDOFCHAIN {
            continue;
        }
        let Some(s) = sector(fs) else { continue };
        for i in 0..per {
            fat.push(u32::from_le_bytes([
                s[i * 4],
                s[i * 4 + 1],
                s[i * 4 + 2],
                s[i * 4 + 3],
            ]));
        }
    }
    if fat.is_empty() {
        return None;
    }

    // Sektorkette entlang der FAT einsammeln.
    let chain = |start: u32| -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = start;
        let mut seen = 0;
        while cur != ENDOFCHAIN && cur != FREESECT && (cur as usize) < fat.len() {
            let Some(s) = sector(cur) else { break };
            out.extend_from_slice(s);
            cur = fat[cur as usize];
            seen += 1;
            if seen > fat.len() {
                break; // Schutz vor Zyklen
            }
        }
        out
    };

    // Verzeichnis lesen.
    let dir = chain(first_dir);
    let mut root_start = 0u32;
    let mut root_size = 0u64;
    let mut streams: Vec<(String, u32, u64)> = Vec::new();
    for entry in dir.chunks_exact(128) {
        let name_len = u16::from_le_bytes([entry[64], entry[65]]) as usize;
        let typ = entry[66];
        if typ == 0 || name_len < 2 {
            continue;
        }
        let name = utf16_name(&entry[..name_len.min(64)]);
        let start = u32::from_le_bytes([entry[116], entry[117], entry[118], entry[119]]);
        let mut size = u64::from_le_bytes([
            entry[120], entry[121], entry[122], entry[123], entry[124], entry[125], entry[126],
            entry[127],
        ]);
        if sector_shift == 9 {
            size &= 0xFFFF_FFFF; // v3: nur die unteren 32 Bit sind gültig
        }
        match typ {
            5 => {
                root_start = start;
                root_size = size;
            }
            2 => streams.push((name, start, size)),
            _ => {}
        }
    }

    // Mini-Stream (Container der kleinen Streams) und Mini-FAT.
    let mini_stream = {
        let mut m = chain(root_start);
        m.truncate(root_size as usize);
        m
    };
    let mini_fat_bytes = chain(first_mini_fat);
    let _ = num_mini_fat;
    let mini_fat: Vec<u32> = mini_fat_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // Streams auslesen.
    let mut out = Vec::new();
    for (name, start, size) in streams {
        let bytes = if (size as usize) >= mini_cutoff {
            let mut b = chain(start);
            b.truncate(size as usize);
            b
        } else {
            // Über die Mini-FAT im Mini-Stream.
            let mut b = Vec::new();
            let mut cur = start;
            let mut seen = 0;
            while cur != ENDOFCHAIN && cur != FREESECT && (cur as usize) < mini_fat.len() {
                let off = (cur as usize) * mini_size;
                let Some(chunk) = mini_stream.get(off..off + mini_size) else {
                    break;
                };
                b.extend_from_slice(chunk);
                cur = mini_fat[cur as usize];
                seen += 1;
                if seen > mini_fat.len() {
                    break;
                }
            }
            b.truncate(size as usize);
            b
        };
        out.push((name, bytes));
    }
    Some(out)
}

/// UTF-16LE-Name eines Verzeichniseintrags (ohne die abschliessende Null).
fn utf16_name(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appid_und_benutzer() {
        let p = "Users\\ich\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\\
                 AutomaticDestinations\\5f7b5f1e01b83767.automaticDestinations-ms";
        assert_eq!(benutzer_aus_pfad(p), "ich");
        assert_eq!(appid_aus_pfad(p), "5f7b5f1e01b83767");
    }

    #[test]
    fn embedded_lnks_getrennt() {
        // Zwei minimale LNK-Koepfe hintereinander (nur Signatur + Rest).
        let mut sig = vec![
            0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
        ];
        sig.resize(76, 0);
        let mut data = vec![0u8; 8]; // kleiner Kopf davor
        data.extend_from_slice(&sig);
        data.extend_from_slice(&sig);
        let parts = split_embedded_lnks(&data);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 76);
    }

    #[test]
    fn kein_cfbf() {
        assert!(read_cfbf_streams(b"nicht ole").is_none());
    }
}
