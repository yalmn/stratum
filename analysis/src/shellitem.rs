//! Shell Items (SHITEMID) und Shell-Item-Listen, wie sie in ShellBags,
//! LNK-Dateien und Jump Lists stehen.
//!
//! Formatgrundlage: libyal/libfwsi, "Windows Shell Item format". Microsoft
//! dokumentiert das Format nicht vollständig. Gegen echte Windows-11-Daten
//! geprüft sind: Stammordner (0x1f), Laufwerk (0x2f), Datei- und Ordnereinträge
//! (0x31, 0x32, 0x36) mit Erweiterungsblock 0xbeef0004 in Version 9 (Name,
//! MFT-Referenz stimmen mit dem Dateisystem überein, FAT-Zeiten sind UTC),
//! Delegate-Einträge (0x74, "CFSF"), Systemsteuerungs-Kategorie (0x01) und
//! -Element (0x71). Nur nach der Beschreibung umgesetzt, ohne Testdaten:
//! Netzwerkorte (0x40 bis 0x4f) und 0xbeef0004 in den Versionen 3, 7 und 8.
//! Alles andere wird als `unbekannt` mit Rohbytes ausgegeben, nicht gedeutet.

use stratum_core::time::filetime_to_iso;

/// Höchstzahl ausgewerteter Einträge einer Liste (Schutz vor Endlosdaten).
const MAX_ITEMS: usize = 64;

/// Ein ausgewerteter Shell Item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ShellItem {
    /// Klassentyp (Byte 2).
    pub typ: u8,
    /// Art: `stammordner`, `laufwerk`, `ordner`, `datei`, `dateieintrag`,
    /// `netzwerk`, `systemsteuerung_kategorie`, `systemsteuerung_element`
    /// oder `unbekannt`.
    pub art: &'static str,
    /// Namensteil für den Pfad, falls im Eintrag selbst enthalten.
    pub name: Option<String>,
    /// Kurzname (8.3), wenn er vom langen Namen abweicht.
    pub kurzname: Option<String>,
    /// GUID (Stammordner, Laufwerk ohne Namen, Systemsteuerung, Delegate).
    pub guid: Option<String>,
    /// Sortierindex eines Stammordners.
    pub sortierindex: Option<u8>,
    /// Systemsteuerungs-Kategorie (Nummer).
    pub kategorie: Option<u32>,
    /// Dateigröße laut Eintrag (32 Bit).
    pub groesse: Option<u32>,
    /// Änderungszeit (FAT, UTC).
    pub geaendert: Option<FatTime>,
    /// Erstellzeit (FAT, UTC) aus 0xbeef0004.
    pub erstellt: Option<FatTime>,
    /// Zugriffszeit (FAT, UTC) aus 0xbeef0004.
    pub zugriff: Option<FatTime>,
    /// MFT-Datensatz und Sequenz aus 0xbeef0004.
    pub mft: Option<(u64, u16)>,
    /// Version des Erweiterungsblocks 0xbeef0004.
    pub erweiterung_version: Option<u16>,
    /// Rohbytes (höchstens 64) bei unbekannten Einträgen.
    pub roh: Option<String>,
    /// Lesbare Zeichenfolge aus einem unbekannten Eintrag, ohne Deutung.
    pub zeichenkette: Option<String>,
}

/// FAT-Zeitstempel (Datum in den unteren, Uhrzeit in den oberen 16 Bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FatTime(pub u32);

impl FatTime {
    fn from_raw(raw: u32) -> Option<Self> {
        (raw != 0).then_some(Self(raw))
    }

    /// Unix-Sekunden, `None` bei ungültigem Datum oder ungültiger Uhrzeit.
    pub fn unix(self) -> Option<i64> {
        let (d, t) = (self.0 & 0xffff, self.0 >> 16);
        let (year, month, day) = (1980 + i64::from(d >> 9), (d >> 5) & 15, d & 31);
        let (hour, minute, second) = (t >> 11, (t >> 5) & 63, (t & 31) * 2);
        if !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Some(days * 86_400 + i64::from(hour * 3600 + minute * 60 + second))
    }

    /// ISO 8601 in UTC.
    pub fn iso(self) -> Option<String> {
        let unix = self.unix()?;
        let ft = u64::try_from(unix + 11_644_473_600).ok()? * 10_000_000;
        filetime_to_iso(ft)
    }
}

/// Tage seit 1970-01-01 für ein Datum im gregorianischen Kalender.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// GUID in üblicher Schreibweise (erste drei Felder little-endian).
pub(crate) fn guid(b: &[u8]) -> Option<String> {
    let g = b.get(..16)?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10..]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    ))
}

fn ascii_z(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b[..end].iter().map(|&c| char::from(c)).collect()
}

/// UTF-16LE bis zum Nullzeichen; liefert auch die gelesene Länge in Byte.
fn utf16_z(b: &[u8]) -> (String, usize) {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    (String::from_utf16_lossy(&units), units.len() * 2 + 2)
}

fn hex(b: &[u8]) -> String {
    b.iter().take(64).map(|x| format!("{x:02x}")).collect()
}

/// Längste lesbare ASCII-Folge (mindestens drei Zeichen).
fn printable(b: &[u8]) -> Option<String> {
    b.split(|c| !(0x20..0x7f).contains(c))
        .filter(|s| s.len() >= 3)
        .max_by_key(|s| s.len())
        .map(|s| String::from_utf8_lossy(s).into_owned())
}

/// Zerlegt eine Shell-Item-Liste (jeder Eintrag mit eigener Größe, Ende bei
/// Größe 0 oder am Ende der Daten). Liefert Offset und Eintrag.
pub(crate) fn parse_list(data: &[u8]) -> Vec<(usize, ShellItem)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while out.len() < MAX_ITEMS {
        let Some(size) = u16_at(data, pos).map(usize::from) else {
            break;
        };
        if size < 3 {
            break;
        }
        let Some(item) = data.get(pos..pos + size) else {
            break;
        };
        out.push((pos, parse_item(item)));
        pos += size;
    }
    out
}

/// Wertet einen einzelnen Shell Item aus. `item` beginnt mit dem Größenfeld.
/// Liefert nie einen Fehler; nicht deutbare Einträge sind `unbekannt`.
pub(crate) fn parse_item(item: &[u8]) -> ShellItem {
    let size = u16_at(item, 0).map_or(0, usize::from).min(item.len());
    let item = &item[..size];
    let typ = item.get(2).copied().unwrap_or(0);
    let mut s = ShellItem {
        typ,
        art: "unbekannt",
        ..Default::default()
    };
    if item.len() >= 12 && &item[6..10] == b"CFSF" {
        delegate(item, &mut s);
    } else if typ == 0x1f {
        root(item, &mut s);
    } else if typ & 0x70 == 0x20 {
        volume(item, &mut s);
    } else if typ & 0x70 == 0x30 {
        file_entry(item, item, &mut s);
    } else if typ & 0x70 == 0x40 {
        network(item, &mut s);
    } else if typ == 0x71 && item.len() >= 30 {
        s.art = "systemsteuerung_element";
        s.guid = guid(&item[14..30]);
    } else if typ == 0x01 && u32_at(item, 4) == Some(0x39de_2184) {
        s.art = "systemsteuerung_kategorie";
        s.kategorie = u32_at(item, 8);
        s.name = s
            .kategorie
            .and_then(control_panel_category)
            .map(str::to_string);
    }
    if s.art == "unbekannt" {
        s.roh = Some(hex(item));
        s.zeichenkette = printable(item.get(3..).unwrap_or(&[]));
    }
    s
}

/// Stammordner: Sortierindex und Ordner-GUID. Ist der Eintrag länger, muss
/// dort ein Erweiterungsblock (0xbeef....) folgen, sonst ist es eine andere,
/// nicht beschriebene Form von 0x1f.
fn root(item: &[u8], s: &mut ShellItem) {
    if item.len() < 20 {
        return;
    }
    if item.len() > 22 && u16_at(item, 26) != Some(0xbeef) {
        return;
    }
    s.art = "stammordner";
    s.sortierindex = Some(item[3]);
    s.guid = guid(&item[4..20]);
}

fn volume(item: &[u8], s: &mut ShellItem) {
    s.art = "laufwerk";
    if s.typ & 0x01 != 0 {
        s.name = Some(ascii_z(item.get(3..23).unwrap_or(&[])));
    } else {
        s.guid = item.get(4..20).and_then(guid);
    }
}

/// Datei- oder Ordnereintrag. `fields` enthält Größe, Zeit und Primärnamen,
/// `whole` den ganzen Eintrag mit den Erweiterungsblöcken (bei Delegates
/// unterschiedlich).
fn file_entry(fields: &[u8], whole: &[u8], s: &mut ShellItem) {
    let typ = fields.get(2).copied().unwrap_or(0);
    s.art = if typ & 0x01 != 0 {
        "ordner"
    } else if typ & 0x02 != 0 {
        "datei"
    } else {
        "dateieintrag"
    };
    s.groesse = u32_at(fields, 4);
    s.geaendert = u32_at(fields, 8).and_then(FatTime::from_raw);
    let primaer = match fields.get(14..) {
        Some(rest) if typ & 0x04 != 0 => utf16_z(rest).0,
        Some(rest) => ascii_z(rest),
        None => String::new(),
    };
    let ext = beef0004(whole);
    let lang = ext.as_ref().and_then(|e| e.name.clone());
    if let Some(e) = ext {
        s.erstellt = e.erstellt;
        s.zugriff = e.zugriff;
        s.mft = e.mft;
        s.erweiterung_version = Some(e.version);
    }
    match lang.filter(|l| !l.is_empty()) {
        Some(l) => {
            if !primaer.is_empty() && !primaer.eq_ignore_ascii_case(&l) {
                s.kurzname = Some(primaer);
            }
            s.name = Some(l);
        }
        None if !primaer.is_empty() => s.name = Some(primaer),
        None => {}
    }
}

struct Beef0004 {
    version: u16,
    erstellt: Option<FatTime>,
    zugriff: Option<FatTime>,
    mft: Option<(u64, u16)>,
    name: Option<String>,
}

/// Erweiterungsblock 0xbeef0004. Seine Lage steht in den letzten zwei Byte des
/// Eintrags (Offset des ersten Erweiterungsblocks).
fn beef0004(item: &[u8]) -> Option<Beef0004> {
    let first = usize::from(u16_at(item, item.len().checked_sub(2)?)?);
    let block = item.get(first..item.len() - 2)?;
    let size = usize::from(u16_at(block, 0)?);
    if u32_at(block, 4)? != 0xbeef_0004 || size < 20 || size > block.len() + 2 {
        return None;
    }
    let block = &block[..size.min(block.len())];
    let version = u16_at(block, 2)?;
    // Lage des langen Namens je Version (libfwsi); Version 9 gegen echte
    // Daten geprüft.
    let name_at = match version {
        3 => 20,
        7 => 38,
        8 => 42,
        v if v >= 9 => 46,
        _ => return None,
    };
    let mft = (version >= 7)
        .then(|| {
            u32_at(block, 20)
                .zip(u16_at(block, 24))
                .zip(u16_at(block, 26))
        })
        .flatten()
        .map(|((lo, hi), seq)| (u64::from(lo) | (u64::from(hi) << 32), seq))
        .filter(|&(record, _)| record != 0);
    Some(Beef0004 {
        version,
        erstellt: u32_at(block, 8).and_then(FatTime::from_raw),
        zugriff: u32_at(block, 12).and_then(FatTime::from_raw),
        mft,
        name: block.get(name_at..).map(|b| utf16_z(b).0),
    })
}

/// Delegate-Eintrag: eingebetteter Dateieintrag nach der Kennung `CFSF`, danach
/// Delegate-Klasse und Ordner-GUID, dahinter die Erweiterungsblöcke.
fn delegate(item: &[u8], s: &mut ShellItem) {
    let inner_size = usize::from(u16_at(item, 4).unwrap_or(0));
    let Some(inner) = item.get(10..6 + inner_size) else {
        return;
    };
    file_entry(inner, item, s);
    s.guid = item.get(6 + inner_size + 16..).and_then(guid);
}

/// Netzwerkort; nur nach der Formatbeschreibung, ohne Testdaten.
fn network(item: &[u8], s: &mut ShellItem) {
    s.art = "netzwerk";
    let name = ascii_z(item.get(5..).unwrap_or(&[]));
    if !name.is_empty() {
        s.name = Some(name);
    }
}

/// Kategorien der Systemsteuerung laut libfwsi.
fn control_panel_category(n: u32) -> Option<&'static str> {
    Some(match n {
        0 => "All Control Panel Items",
        1 => "Appearance and Personalization",
        2 => "Hardware and Sound",
        3 => "Network and Internet",
        4 => "Sounds, Speech, and Audio Devices",
        5 => "System and Security",
        6 => "Clock, Language, and Region",
        7 => "Ease of Access",
        8 => "Programs",
        9 => "User Accounts",
        10 => "Security Center",
        11 => "Mobile PC",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// Ordnereintrag mit Erweiterungsblock 0xbeef0004 Version 9, aufgebaut wie
    /// die geprüften Windows-11-Einträge.
    fn ordner(kurz: &str, lang: &str, mft: u64, seq: u16) -> Vec<u8> {
        let mut item = vec![0, 0, 0x31, 0];
        item.extend_from_slice(&0u32.to_le_bytes());
        item.extend_from_slice(&0x3ad1_5881u32.to_le_bytes());
        item.extend_from_slice(&0x10u16.to_le_bytes());
        item.extend_from_slice(kurz.as_bytes());
        item.push(0);
        if item.len() % 2 == 1 {
            item.push(0);
        }
        let start = item.len();
        let mut ext = vec![0, 0, 9, 0, 0x04, 0, 0xef, 0xbe];
        ext.extend_from_slice(&0x3ad1_5881u32.to_le_bytes());
        ext.extend_from_slice(&0x3ad1_5881u32.to_le_bytes());
        ext.extend_from_slice(&[0x2e, 0, 0, 0]);
        ext.extend_from_slice(&(mft as u32).to_le_bytes());
        ext.extend_from_slice(&((mft >> 32) as u16).to_le_bytes());
        ext.extend_from_slice(&seq.to_le_bytes());
        ext.extend_from_slice(&[0; 8]);
        ext.extend_from_slice(&[0; 2 + 4 + 4]);
        assert_eq!(ext.len(), 46);
        ext.extend_from_slice(&utf16z(lang));
        ext.extend_from_slice(&(start as u16).to_le_bytes());
        let ext_len = ext.len() as u16;
        ext[..2].copy_from_slice(&ext_len.to_le_bytes());
        item.extend_from_slice(&ext);
        let len = item.len() as u16;
        item[..2].copy_from_slice(&len.to_le_bytes());
        item
    }

    #[test]
    fn fat_zeit_ist_utc_und_prueft_bereiche() {
        let t = FatTime(0x3ad1_5881);
        assert_eq!(t.unix(), Some(1_711_956_154));
        assert_eq!(t.iso().as_deref(), Some("2024-04-01T07:22:34.0000000Z"));
        assert_eq!(FatTime(0x0000_0021 | (0xffff << 16)).unix(), None);
        assert_eq!(FatTime(1 << 16).unix(), None);
    }

    #[test]
    fn ordner_mit_langem_namen_und_mft_referenz() {
        let s = parse_item(&ordner("PROGRA~2", "Program Files (x86)", 3176, 1));
        assert_eq!(s.art, "ordner");
        assert_eq!(s.name.as_deref(), Some("Program Files (x86)"));
        assert_eq!(s.kurzname.as_deref(), Some("PROGRA~2"));
        assert_eq!(s.mft, Some((3176, 1)));
        assert_eq!(s.erweiterung_version, Some(9));
        assert_eq!(s.geaendert.and_then(FatTime::unix), Some(1_711_956_154));
        assert_eq!(s.erstellt, s.geaendert);
    }

    #[test]
    fn stammordner_laufwerk_und_systemsteuerung() {
        let mut root = vec![0x14, 0, 0x1f, 0x50];
        root.extend_from_slice(&[
            0xe0, 0x4f, 0xd0, 0x20, 0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00, 0x2b, 0x30,
            0x30, 0x9d,
        ]);
        let s = parse_item(&root);
        assert_eq!(s.art, "stammordner");
        assert_eq!(
            s.guid.as_deref(),
            Some("20d04fe0-3aea-1069-a2d8-08002b30309d")
        );
        assert_eq!(s.sortierindex, Some(0x50));

        let mut vol = vec![0x19, 0, 0x2f];
        vol.extend_from_slice(b"C:\\");
        vol.resize(25, 0);
        assert_eq!(parse_item(&vol).name.as_deref(), Some("C:\\"));

        let kat = [0x0c, 0, 0x01, 0, 0x84, 0x21, 0xde, 0x39, 5, 0, 0, 0];
        let s = parse_item(&kat);
        assert_eq!(s.art, "systemsteuerung_kategorie");
        assert_eq!(s.name.as_deref(), Some("System and Security"));
    }

    #[test]
    fn delegate_mit_eingebettetem_ordner() {
        let inneres = [
            0x16, 0, 0x31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0, b'A', b'p', b'p', b'D', b'a', b't',
            b'a', 0,
        ];
        let mut item = vec![0, 0, 0x74, 0];
        item.extend_from_slice(&((4 + inneres.len()) as u16).to_le_bytes());
        item.extend_from_slice(b"CFSF");
        item.extend_from_slice(&inneres);
        item.extend_from_slice(&[0x11; 16]);
        item.extend_from_slice(&[
            0xc5, 0xcd, 0xfa, 0xdf, 0x9f, 0x67, 0x56, 0x41, 0x89, 0x47, 0xc5, 0xc7, 0x6b, 0xc0,
            0xb6, 0x7f,
        ]);
        let len = item.len() as u16;
        item[..2].copy_from_slice(&len.to_le_bytes());
        let s = parse_item(&item);
        assert_eq!(s.art, "ordner");
        assert_eq!(s.name.as_deref(), Some("AppData"));
        assert_eq!(
            s.guid.as_deref(),
            Some("dffacdc5-679f-4156-8947-c5c76bc0b67f")
        );
    }

    #[test]
    fn unbekanntes_und_unsinn_ohne_panik() {
        let mut item = vec![
            0x55, 0, 0x1f, 0, 0x2f, 0, 0x10, 0xb7, 0xa6, 0xf5, 0x19, 0, 0x2f,
        ];
        item.extend_from_slice(b"L:\\");
        item.resize(0x55, 0);
        let s = parse_item(&item);
        assert_eq!(s.art, "unbekannt");
        assert_eq!(s.zeichenkette.as_deref(), Some("/L:\\"));
        assert!(s.roh.is_some());
        let mut state = 7u32;
        for _ in 0..2000 {
            let daten: Vec<u8> = (0..300)
                .map(|_| {
                    state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (state >> 16) as u8
                })
                .collect();
            let _ = parse_list(&daten);
            let _ = parse_item(&daten);
        }
        assert!(parse_list(&[0x02, 0x00]).is_empty());
    }

    /// Gegen echte LNK-Dateien: der Pfad aus der IDList muss dem LinkInfo-Pfad
    /// entsprechen, wo beide vorhanden sind.
    #[test]
    #[ignore = "benötigt STRATUM_SHELLITEM_REFERENCE mit LNK-Dateien"]
    fn lnk_referenz() {
        let dir =
            std::path::PathBuf::from(std::env::var_os("STRATUM_SHELLITEM_REFERENCE").unwrap());
        let mut verglichen = 0;
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) != Some("lnk") {
                continue;
            }
            let data = std::fs::read(&p).unwrap();
            let mut link = crate::lnk::parse_lnk(&data).unwrap();
            // Codepage des Testimages laut Registry (ACP).
            link.decode_ansi(Some("1252"));
            let f = crate::lnk::with_target_times(crate::Finding::new("t", "t", "t"), &link);
            let idl = f.attributes.get("idlist_pfad");
            eprintln!(
                "{:?}: LinkInfo {:?} IDList {:?}",
                p.file_name().unwrap(),
                link.target_path,
                idl
            );
            if let (false, Some(idl)) = (link.target_path.is_empty(), idl) {
                let ziel = link.target_path.trim_end_matches('\\').to_lowercase();
                // Beginnt die IDList mit einem Stammordner (etwa dem Profil),
                // muss der Rest das Ende des LinkInfo-Pfads sein.
                let idl = idl.to_lowercase();
                match idl.strip_prefix('{').and_then(|r| r.split_once("}\\")) {
                    Some((_, rest)) => assert!(ziel.ends_with(&format!("\\{rest}")), "{p:?}"),
                    None => assert_eq!(idl, ziel, "{p:?}"),
                }
                verglichen += 1;
            }
        }
        assert!(verglichen >= 4);
    }
}
