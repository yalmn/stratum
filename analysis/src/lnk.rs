//! Verknüpfungen (`.lnk`) aus dem `Recent`-Ordner der Benutzer.
//!
//! Windows legt beim Öffnen einer Datei eine Verknüpfung im `Recent`-Ordner an.
//! Sie enthält den Zielpfad, die Zeitstempel des Ziels (angelegt, geändert,
//! zugegriffen), die Zielgröße und die Seriennummer des Datenträgers, auf dem
//! das Ziel lag, also auch von inzwischen entfernten Wechseldatenträgern.
//!
//! Der Parser folgt dem Shell-Link-Format (MS-SHLLINK) und liest defensiv: er
//! prüft alle Längen und bricht bei fehlerhaften Daten sauber ab.

use stratum_ntfs::NtfsVolume;

use crate::{AnalysisContext, Analyzer, Finding, Outcome};

/// Analyzer für `.lnk`-Verknüpfungen im Recent-Ordner.
pub struct LnkAnalyzer;

impl Analyzer for LnkAnalyzer {
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
            let dateien: Vec<_> = v
                .by_extension(&["lnk"])
                .filter(|e| e.path.to_ascii_lowercase().contains("\\recent\\"))
                .filter(|e| e.size > 0 && e.size < 1_000_000)
                .cloned()
                .collect();
            for e in dateien {
                let Ok(Some(f)) = vol.read_file_by_record(e.mft_record, &e.path) else {
                    continue;
                };
                let Some(link) = parse_lnk(&f.data) else {
                    continue;
                };
                let benutzer = benutzer_aus_pfad(&e.path);
                let name = if link.target_path.is_empty() {
                    e.path.rsplit('\\').next().unwrap_or(&e.path).to_string()
                } else {
                    link.target_path.clone()
                };
                let mut fd = Finding::new("useraktivitaet", name, &e.path).with("art", "lnk");
                if !benutzer.is_empty() {
                    fd = fd.with("benutzer", benutzer);
                }
                if !link.target_path.is_empty() {
                    fd = fd.with("zielpfad", link.target_path.as_str());
                }
                if let Some(s) = link.drive_serial {
                    fd = fd.with("laufwerk_seriennummer", format!("{s:08x}"));
                }
                if link.file_size > 0 {
                    fd = fd.with("zielgroesse", link.file_size.to_string());
                }
                out.findings.push(with_target_times(fd, &link));
            }
        }
        out
    }
}

/// 1980-01-01 00:00 UTC, Beginn der DOS-Zeitrechnung.
const DOS_EPOCH_UTC: i64 = 315_532_800;

/// Erkennt die DOS-Epoche in Ortszeit (UTC-12 bis UTC+14, Versatz in
/// Viertelstunden). Windows trägt sie ein, wenn das Ziel keine eigene Zeit hat,
/// etwa bei der Wurzel eines FAT-Laufwerks.
fn is_dos_epoch_placeholder(unix: i64) -> bool {
    let diff = unix - DOS_EPOCH_UTC;
    (-14 * 3600..=12 * 3600).contains(&diff) && diff % 900 == 0
}

/// Ergänzt die Zielzeiten. Platzhalter der DOS-Epoche bleiben als Rohwert
/// erhalten, landen aber nicht unter den Zeitschlüsseln der Timeline.
pub(crate) fn with_target_times(mut fd: Finding, link: &Lnk) -> Finding {
    let mut placeholder = false;
    for (k, t) in [
        ("ziel_erstellt", link.created),
        ("ziel_geaendert", link.modified),
        ("ziel_zugriff", link.accessed),
    ] {
        let Some(z) = t else { continue };
        if is_dos_epoch_placeholder(z) {
            placeholder = true;
            fd = fd.with(format!("{k}_platzhalter_unix"), z.to_string());
        } else {
            fd = fd.with(format!("{k}_unix"), z.to_string());
        }
    }
    if placeholder {
        fd = fd.with(
            "ziel_zeiten_hinweis",
            "DOS-Epoche 1980-01-01 00:00 Ortszeit, keine echte Zeitangabe des Ziels",
        );
    }
    fd
}

/// Der Benutzername aus einem Pfad `Users\<name>\...`.
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

/// Ausgewertete Verknüpfung.
#[derive(Default)]
pub(crate) struct Lnk {
    pub(crate) target_path: String,
    pub(crate) drive_serial: Option<u32>,
    pub(crate) file_size: u32,
    pub(crate) created: Option<i64>,
    pub(crate) modified: Option<i64>,
    pub(crate) accessed: Option<i64>,
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn ft(b: &[u8], at: usize) -> Option<i64> {
    let raw = b.get(at..at + 8)?;
    let v = u64::from_le_bytes(raw.try_into().ok()?);
    if v == 0 {
        return None;
    }
    stratum_registry::filetime_to_unix(v).map(|(s, _)| s)
}

/// Liest eine ANSI- bzw. UTF-16LE-Zeichenkette bis zur Null ab `off`.
fn cstr(b: &[u8], off: usize, unicode: bool) -> String {
    if unicode {
        let units: Vec<u16> = b
            .get(off..)
            .unwrap_or(&[])
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let bytes: Vec<u8> = b
            .get(off..)
            .unwrap_or(&[])
            .iter()
            .copied()
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Parst eine Shell-Link-Datei (MS-SHLLINK). `None` bei ungültigem Header.
pub(crate) fn parse_lnk(data: &[u8]) -> Option<Lnk> {
    // ShellLinkHeader: 76 Byte, HeaderSize == 0x4C.
    if le_u32(data, 0)? != 0x4C || data.len() < 76 {
        return None;
    }
    let flags = le_u32(data, 20)?;
    let mut link = Lnk {
        created: ft(data, 28),
        accessed: ft(data, 36),
        modified: ft(data, 44),
        file_size: le_u32(data, 52).unwrap_or(0),
        ..Default::default()
    };

    let mut off = 76usize;
    // HasLinkTargetIDList (Bit 0): IDList überspringen.
    if flags & 0x1 != 0 {
        let idlist_size = data.get(off..off + 2)?;
        let n = u16::from_le_bytes([idlist_size[0], idlist_size[1]]) as usize;
        off = off.checked_add(2 + n)?;
    }
    // HasLinkInfo (Bit 1): den LinkInfo-Block auswerten.
    if flags & 0x2 != 0 {
        parse_link_info(data.get(off..)?, &mut link);
    }
    Some(link)
}

/// Wertet den LinkInfo-Block aus (VolumeID mit Seriennummer und lokaler Pfad).
fn parse_link_info(li: &[u8], link: &mut Lnk) {
    let Some(header_size) = le_u32(li, 4) else {
        return;
    };
    let Some(li_flags) = le_u32(li, 8) else {
        return;
    };
    let vol_off = le_u32(li, 12).unwrap_or(0) as usize;
    let base_off = le_u32(li, 16).unwrap_or(0) as usize;

    // VolumeIDAndLocalBasePath (Bit 0).
    if li_flags & 0x1 != 0 {
        if vol_off != 0 {
            // VolumeID: Size(4), DriveType(4), DriveSerialNumber(4).
            if let Some(serial) = le_u32(li, vol_off + 8) {
                link.drive_serial = Some(serial);
            }
        }
        // Bevorzugt den Unicode-Pfad, falls der Header ihn ausweist.
        let uni_base_off = if header_size >= 0x24 {
            le_u32(li, 28).unwrap_or(0) as usize
        } else {
            0
        };
        let path = if uni_base_off != 0 {
            cstr(li, uni_base_off, true)
        } else if base_off != 0 {
            cstr(li, base_off, false)
        } else {
            String::new()
        };
        link.target_path = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ft_bytes(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    #[test]
    fn benutzer_erkannt() {
        assert_eq!(
            benutzer_aus_pfad("Users\\ich\\AppData\\Roaming\\...\\Recent\\x.lnk"),
            "ich"
        );
        assert_eq!(benutzer_aus_pfad("Windows\\x"), "");
    }

    #[test]
    fn parst_header_und_pfad() {
        let mut d = vec![0u8; 76];
        d[0] = 0x4C; // HeaderSize
        d[20..24].copy_from_slice(&0x2u32.to_le_bytes()); // nur HasLinkInfo
        d[28..36].copy_from_slice(&ft_bytes(133_800_000_000_000_000)); // erstellt ~2025
        d[52..56].copy_from_slice(&4096u32.to_le_bytes()); // Groesse

        // LinkInfo ab Offset 76.
        let base = "C:\\Users\\ich\\geheim.docx\0";
        let header_size = 0x1Cu32; // ohne Unicode-Offsets
        let vol_off = 28u32; // VolumeID direkt hinter dem Kopf
        let base_off = vol_off + 20; // hinter der VolumeID
        let mut li = Vec::new();
        li.extend_from_slice(&0u32.to_le_bytes()); // LinkInfoSize (egal)
        li.extend_from_slice(&header_size.to_le_bytes());
        li.extend_from_slice(&1u32.to_le_bytes()); // Flags: VolumeIDAndLocalBasePath
        li.extend_from_slice(&vol_off.to_le_bytes());
        li.extend_from_slice(&base_off.to_le_bytes());
        li.extend_from_slice(&0u32.to_le_bytes()); // CNR-Offset
        li.extend_from_slice(&0u32.to_le_bytes()); // Suffix-Offset
                                                   // VolumeID (20 Byte): Size, DriveType, Serial, LabelOffset, +Rest
        while li.len() < 76 + vol_off as usize - 76 {
            li.push(0);
        }
        // vol_off ist relativ zum LinkInfo-Anfang; hier steht li schon an 28.
        li.resize(vol_off as usize, 0);
        li.extend_from_slice(&20u32.to_le_bytes()); // VolumeIDSize
        li.extend_from_slice(&3u32.to_le_bytes()); // DriveType
        li.extend_from_slice(&0xABCD1234u32.to_le_bytes()); // Serial
        li.extend_from_slice(&16u32.to_le_bytes()); // VolumeLabelOffset
        li.extend_from_slice(&0u32.to_le_bytes()); // Rest
        li.resize(base_off as usize, 0);
        li.extend_from_slice(base.as_bytes());

        d.extend_from_slice(&li);
        let link = parse_lnk(&d).unwrap();
        assert_eq!(link.target_path, "C:\\Users\\ich\\geheim.docx");
        assert_eq!(link.drive_serial, Some(0xABCD1234));
        assert_eq!(link.file_size, 4096);
        assert!(link.created.unwrap() > 1_700_000_000);
    }

    #[test]
    fn dos_epoche_ist_kein_zeitpunkt() {
        // Echter Wert aus einem USB-Laufwerk-LNK (UTC+2).
        assert!(is_dos_epoch_placeholder(315_525_600));
        assert!(is_dos_epoch_placeholder(DOS_EPOCH_UTC));
        assert!(!is_dos_epoch_placeholder(DOS_EPOCH_UTC + 61));
        assert!(!is_dos_epoch_placeholder(1_700_000_000));
        let link = Lnk {
            created: Some(315_525_600),
            modified: Some(1_700_000_000),
            ..Lnk::default()
        };
        let f = with_target_times(Finding::new("useraktivitaet", "x", "q"), &link);
        assert_eq!(f.attributes["ziel_erstellt_platzhalter_unix"], "315525600");
        assert!(!f.attributes.contains_key("ziel_erstellt_unix"));
        assert_eq!(f.attributes["ziel_geaendert_unix"], "1700000000");
        let tl = crate::build_timeline(&[f]);
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].unix, 1_700_000_000);
    }
}
