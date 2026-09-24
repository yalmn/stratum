//! Erkennung von Partitionstabellen (MBR und GPT) und Dateisystem-Hinweisen.
//!
//! Alle Werte stammen aus nicht vertrauenswürdigen Images. Jeder Zugriff ist
//! längengeprüft, Rechnungen laufen mit `checked_*`. Auffälligkeiten (falsche
//! CRC, Einträge über das Imageende hinaus usw.) führen nicht zum Abbruch,
//! sondern landen in [`PartitionTable::warnings`].

use std::fmt;

use serde::{Serialize, Serializer};

use crate::image::{slice_at, ImageReader};

/// Sektorgröße für MBR-Adressierung.
const MBR_SECTOR: u32 = 512;
/// Sektorgrößen, unter denen nach einem GPT-Header gesucht wird.
const GPT_SECTOR_SIZES: [u32; 2] = [512, 4096];
/// Obergrenze für das gesamte GPT-Eintragsarray. Die Spezifikation fordert
/// mindestens 16 KiB, üblich sind 128 Einträge zu je 128 Bytes. Größere Werte
/// sind praktisch nur bei manipulierten Headern zu erwarten.
const GPT_MAX_ARRAY: u64 = 4 * 1024 * 1024;
/// Mindestgröße eines GPT-Headers laut Spezifikation.
const GPT_HEADER_MIN: usize = 92;

/// Art der gefundenen Partitionierung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PartitionScheme {
    /// Klassischer Master Boot Record.
    Mbr,
    /// GUID Partition Table.
    Gpt,
    /// Keine Partitionstabelle, das Image beginnt direkt mit einem
    /// Dateisystem (z. B. Abbild eines einzelnen Volumes).
    Volume,
    /// Nichts erkannt.
    None,
}

/// GUID im GPT-Format (die ersten drei Felder Little Endian).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// `true`, wenn alle Bytes 0 sind (unbenutzter GPT-Eintrag).
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Guid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Typkennung einer Partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "scheme", content = "id", rename_all = "lowercase")]
pub enum PartitionType {
    /// MBR-Typbyte.
    Mbr(u8),
    /// GPT-Typ-GUID.
    Gpt(Guid),
    /// Pseudo-Partition für ein Image ohne Partitionstabelle.
    Volume,
}

impl PartitionType {
    /// Lesbare Bezeichnung bekannter Typen, sonst `"unbekannt"`.
    pub fn description(&self) -> &'static str {
        match self {
            PartitionType::Mbr(t) => match t {
                0x01 => "FAT12",
                0x04 | 0x06 | 0x0E => "FAT16",
                0x05 | 0x0F | 0x85 => "Extended",
                0x07 => "NTFS/exFAT/HPFS",
                0x0B | 0x0C => "FAT32",
                0x27 => "Windows RE (versteckt)",
                0x82 => "Linux Swap",
                0x83 => "Linux",
                0x8E => "Linux LVM",
                0xEE => "GPT Protective",
                0xEF => "EFI System",
                _ => "unbekannt",
            },
            PartitionType::Gpt(g) => match g.to_string().as_str() {
                "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
                "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft Reserved",
                "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data",
                "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows Recovery",
                "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux Filesystem",
                "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux Swap",
                _ => "unbekannt",
            },
            PartitionType::Volume => "Volume ohne Partitionstabelle",
        }
    }

    fn is_mbr_extended(&self) -> bool {
        matches!(self, PartitionType::Mbr(0x05 | 0x0F | 0x85))
    }
}

/// Dateisystem-Hinweis aus der Signatur im ersten Sektor der Partition.
///
/// Das ist nur ein Hinweis anhand weniger Bytes, keine Validierung des
/// Dateisystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FsHint {
    /// OEM-ID `"NTFS    "`.
    Ntfs,
    /// FAT12/16/32.
    Fat,
    /// OEM-ID `"EXFAT   "`.
    ExFat,
    /// OEM-ID `"ReFS"`.
    Refs,
    /// OEM-ID `"-FVE-FS-"`: BitLocker-verschlüsseltes Volume.
    BitLocker,
    /// Signatur nicht erkannt.
    Unknown,
    /// Der Startsektor liegt außerhalb des Images.
    OutOfImage,
}

/// Eine erkannte Partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partition {
    /// Position in der Tabelle (MBR 0..=3, GPT Eintragsnummer).
    pub index: u32,
    /// Typkennung.
    pub typ: PartitionType,
    /// Lesbare Typbezeichnung.
    pub type_name: &'static str,
    /// Startsektor.
    pub start_lba: u64,
    /// Länge in Sektoren.
    pub size_sectors: u64,
    /// Sektorgröße, mit der `start_lba` und `size_sectors` gerechnet sind.
    pub sector_size: u32,
    /// Absoluter Byte-Offset des Partitionsbeginns im Image.
    pub start_offset: u64,
    /// Länge in Bytes.
    pub size_bytes: u64,
    /// Byte-Offset des Tabelleneintrags im Image, aus dem die Partition
    /// gelesen wurde.
    pub entry_offset: u64,
    /// Partitionsname (nur GPT).
    pub name: Option<String>,
    /// Hinweis auf das enthaltene Dateisystem.
    pub fs_hint: FsHint,
}

/// Ergebnis der Partitionserkennung.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartitionTable {
    /// Erkannte Partitionierung.
    pub scheme: PartitionScheme,
    /// Gefundene Partitionen in Tabellenreihenfolge.
    pub partitions: Vec<Partition>,
    /// Auffälligkeiten, die beim Parsen aufgefallen sind.
    pub warnings: Vec<String>,
}

/// Erkennt die Partitionierung eines Images.
pub fn scan_partitions(img: &ImageReader) -> PartitionTable {
    scan_bytes(img.as_slice())
}

/// Erkennt die Partitionierung eines Images, das als Byte-Slice vorliegt.
///
/// Arbeitet nur auf `&[u8]` und ist damit direkt als Fuzz-Target nutzbar.
pub fn scan_bytes(data: &[u8]) -> PartitionTable {
    let mut warnings = Vec::new();
    let image_len = data.len() as u64;

    let Some(lba0) = slice_at(data, 0, MBR_SECTOR as usize) else {
        warnings.push(format!("Image kleiner als ein Sektor ({image_len} Bytes)"));
        return PartitionTable {
            scheme: PartitionScheme::None,
            partitions: Vec::new(),
            warnings,
        };
    };

    // Ein Volume-Bootsektor trägt ebenfalls 0x55AA, deshalb vor dem MBR prüfen.
    let fs = detect_fs(lba0);
    if fs != FsHint::Unknown {
        return PartitionTable {
            scheme: PartitionScheme::Volume,
            partitions: vec![Partition {
                index: 0,
                typ: PartitionType::Volume,
                type_name: PartitionType::Volume.description(),
                start_lba: 0,
                size_sectors: image_len / u64::from(MBR_SECTOR),
                sector_size: MBR_SECTOR,
                start_offset: 0,
                size_bytes: image_len,
                entry_offset: 0,
                name: None,
                fs_hint: fs,
            }],
            warnings,
        };
    }

    if lba0[510..512] != [0x55, 0xAA] {
        warnings.push("keine MBR-Signatur 0x55AA an Offset 510".into());
        return PartitionTable {
            scheme: PartitionScheme::None,
            partitions: Vec::new(),
            warnings,
        };
    }

    let mbr = parse_mbr(data, lba0, &mut warnings);

    if mbr.iter().any(|p| p.typ == PartitionType::Mbr(0xEE)) {
        match parse_gpt(data, &mut warnings) {
            Some(partitions) => {
                return PartitionTable {
                    scheme: PartitionScheme::Gpt,
                    partitions,
                    warnings,
                }
            }
            None => warnings.push(
                "Protective MBR vorhanden, aber kein gültiger GPT-Header; verwende MBR-Einträge"
                    .into(),
            ),
        }
    }

    PartitionTable {
        scheme: PartitionScheme::Mbr,
        partitions: mbr,
        warnings,
    }
}

fn parse_mbr(data: &[u8], lba0: &[u8], warnings: &mut Vec<String>) -> Vec<Partition> {
    let mut out = Vec::with_capacity(4);
    for i in 0..4u32 {
        let off = 446 + 16 * i as usize;
        let e = &lba0[off..off + 16];
        let status = e[0];
        let typ = PartitionType::Mbr(e[4]);
        let start = u64::from(le_u32(e, 8));
        let sectors = u64::from(le_u32(e, 12));

        if e[4] == 0 {
            continue;
        }
        if status != 0x00 && status != 0x80 {
            warnings.push(format!(
                "MBR-Eintrag {i}: ungewöhnliches Statusbyte 0x{status:02X}"
            ));
        }
        if sectors == 0 {
            warnings.push(format!("MBR-Eintrag {i}: Länge 0, übersprungen"));
            continue;
        }
        if typ.is_mbr_extended() {
            warnings.push(format!(
                "MBR-Eintrag {i}: erweiterte Partition, logische Laufwerke werden noch nicht ausgewertet"
            ));
        }

        if let Some(p) = build_partition(
            data, i, typ, start, sectors, MBR_SECTOR, off as u64, None, warnings,
        ) {
            out.push(p);
        }
    }
    out
}

fn parse_gpt(data: &[u8], warnings: &mut Vec<String>) -> Option<Vec<Partition>> {
    let (ss, hdr_off) = GPT_SECTOR_SIZES.iter().find_map(|&ss| {
        let off = u64::from(ss);
        (slice_at(data, off, 8)? == b"EFI PART").then_some((ss, off))
    })?;

    let hdr = slice_at(data, hdr_off, GPT_HEADER_MIN)?;
    let header_size = le_u32(hdr, 12) as usize;
    if header_size < GPT_HEADER_MIN || header_size > ss as usize {
        warnings.push(format!("GPT: ungültige Headergröße {header_size}"));
        return None;
    }
    let full_hdr = slice_at(data, hdr_off, header_size)?;
    let stored_crc = le_u32(hdr, 16);
    let mut crc = crc32fast::Hasher::new();
    crc.update(&full_hdr[..16]);
    crc.update(&[0; 4]);
    crc.update(&full_hdr[20..]);
    if crc.finalize() != stored_crc {
        warnings.push(format!(
            "GPT: Header-CRC32 stimmt nicht (Offset {hdr_off}), Header möglicherweise manipuliert"
        ));
    }

    let entries_lba = le_u64(hdr, 72);
    let count = le_u32(hdr, 80);
    let entry_size = le_u32(hdr, 84);
    let entries_crc = le_u32(hdr, 88);

    if entry_size < 128 || !entry_size.is_power_of_two() {
        warnings.push(format!("GPT: ungültige Eintragsgröße {entry_size}"));
        return None;
    }
    let array_len = u64::from(count) * u64::from(entry_size);
    if array_len > GPT_MAX_ARRAY {
        warnings.push(format!(
            "GPT: Eintragsarray mit {array_len} Bytes überschreitet Limit von {GPT_MAX_ARRAY}"
        ));
        return None;
    }
    let Some(array_off) = entries_lba.checked_mul(u64::from(ss)) else {
        warnings.push(format!("GPT: Eintrags-LBA {entries_lba} ungültig"));
        return None;
    };
    // array_len <= GPT_MAX_ARRAY, passt also sicher in usize.
    let Some(array) = slice_at(data, array_off, array_len as usize) else {
        warnings.push(format!(
            "GPT: Eintragsarray (Offset {array_off}, {array_len} Bytes) liegt außerhalb des Images"
        ));
        return None;
    };
    if crc32fast::hash(array) != entries_crc {
        warnings.push("GPT: CRC32 des Eintragsarrays stimmt nicht".into());
    }

    let mut out = Vec::new();
    for (i, e) in array.chunks_exact(entry_size as usize).enumerate() {
        let mut g = [0u8; 16];
        g.copy_from_slice(&e[..16]);
        let guid = Guid(g);
        if guid.is_zero() {
            continue;
        }
        // i < count <= u32::MAX
        let idx = i as u32;
        let first = le_u64(e, 32);
        let last = le_u64(e, 40);
        if last < first {
            warnings.push(format!(
                "GPT-Eintrag {idx}: letzte LBA {last} vor erster LBA {first}, übersprungen"
            ));
            continue;
        }
        let entry_offset = array_off + (i as u64) * u64::from(entry_size);
        let name = utf16_name(&e[56..128]);
        let sectors = (last - first).saturating_add(1);
        if let Some(p) = build_partition(
            data,
            idx,
            PartitionType::Gpt(guid),
            first,
            sectors,
            ss,
            entry_offset,
            Some(name),
            warnings,
        ) {
            out.push(p);
        }
    }
    Some(out)
}

#[allow(clippy::too_many_arguments)]
fn build_partition(
    data: &[u8],
    index: u32,
    typ: PartitionType,
    start_lba: u64,
    size_sectors: u64,
    sector_size: u32,
    entry_offset: u64,
    name: Option<String>,
    warnings: &mut Vec<String>,
) -> Option<Partition> {
    let ss = u64::from(sector_size);
    let (Some(start_offset), Some(size_bytes)) =
        (start_lba.checked_mul(ss), size_sectors.checked_mul(ss))
    else {
        warnings.push(format!(
            "Partition {index}: Start {start_lba} / Länge {size_sectors} Sektoren läuft über, übersprungen"
        ));
        return None;
    };

    let image_len = data.len() as u64;
    let fs_hint = match slice_at(data, start_offset, sector_size as usize) {
        Some(boot) => detect_fs(boot),
        None => FsHint::OutOfImage,
    };
    if start_offset
        .checked_add(size_bytes)
        .is_none_or(|end| end > image_len)
    {
        warnings.push(format!(
            "Partition {index}: reicht über das Imageende ({image_len} Bytes) hinaus, Image evtl. gekürzt"
        ));
    }

    Some(Partition {
        index,
        typ,
        type_name: typ.description(),
        start_lba,
        size_sectors,
        sector_size,
        start_offset,
        size_bytes,
        entry_offset,
        name,
        fs_hint,
    })
}

/// Bestimmt anhand des Bootsektors einen Dateisystem-Hinweis.
fn detect_fs(boot: &[u8]) -> FsHint {
    match boot.get(3..11) {
        Some(b"NTFS    ") => return FsHint::Ntfs,
        Some(b"EXFAT   ") => return FsHint::ExFat,
        Some(b"-FVE-FS-") => return FsHint::BitLocker,
        Some(b"ReFS\0\0\0\0") => return FsHint::Refs,
        _ => {}
    }
    // FAT hat keine feste OEM-ID, daher Dateisystem-Typfeld plus Bootsignatur.
    let signed = boot.get(510..512) == Some(&[0x55, 0xAA]);
    let fat32 = boot.get(82..87) == Some(b"FAT32");
    let fat16 = boot.get(54..57) == Some(b"FAT");
    if signed && (fat32 || fat16) {
        return FsHint::Fat;
    }
    FsHint::Unknown
}

fn utf16_name(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

// Aufrufer garantieren über slice_at bzw. feste Arraygrößen, dass `off + 4`
// bzw. `off + 8` innerhalb von `b` liegt.
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const SS: usize = 512;

    /// Schreibt einen NTFS-Bootsektor an `lba`.
    pub(crate) fn put_ntfs_boot(img: &mut [u8], lba: usize) {
        let s = &mut img[lba * SS..(lba + 1) * SS];
        s[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        s[3..11].copy_from_slice(b"NTFS    ");
        s[510] = 0x55;
        s[511] = 0xAA;
    }

    pub(crate) fn put_mbr_entry(
        img: &mut [u8],
        i: usize,
        status: u8,
        typ: u8,
        start: u32,
        len: u32,
    ) {
        let e = &mut img[446 + 16 * i..446 + 16 * (i + 1)];
        e[0] = status;
        e[4] = typ;
        e[8..12].copy_from_slice(&start.to_le_bytes());
        e[12..16].copy_from_slice(&len.to_le_bytes());
    }

    /// Synthetisches Image: MBR mit NTFS-Partition (LBA 2, 4 Sektoren) und
    /// Linux-Partition (LBA 6, 2 Sektoren). Gesamt 8 Sektoren.
    pub(crate) fn synthetic_mbr() -> Vec<u8> {
        let mut img = vec![0u8; 8 * SS];
        put_mbr_entry(&mut img, 0, 0x80, 0x07, 2, 4);
        put_mbr_entry(&mut img, 1, 0x00, 0x83, 6, 2);
        img[510] = 0x55;
        img[511] = 0xAA;
        put_ntfs_boot(&mut img, 2);
        img
    }

    #[test]
    fn mbr_mit_ntfs() {
        let t = scan_bytes(&synthetic_mbr());
        assert_eq!(t.scheme, PartitionScheme::Mbr);
        assert!(t.warnings.is_empty(), "{:?}", t.warnings);
        assert_eq!(t.partitions.len(), 2);

        let p = &t.partitions[0];
        assert_eq!(p.index, 0);
        assert_eq!(p.typ, PartitionType::Mbr(0x07));
        assert_eq!(p.start_lba, 2);
        assert_eq!(p.size_sectors, 4);
        assert_eq!(p.start_offset, 1024);
        assert_eq!(p.size_bytes, 2048);
        assert_eq!(p.entry_offset, 446);
        assert_eq!(p.fs_hint, FsHint::Ntfs);

        let p = &t.partitions[1];
        assert_eq!(p.typ, PartitionType::Mbr(0x83));
        assert_eq!(p.entry_offset, 462);
        assert_eq!(p.fs_hint, FsHint::Unknown);
    }

    #[test]
    fn ohne_signatur() {
        let mut img = synthetic_mbr();
        img[511] = 0;
        let t = scan_bytes(&img);
        assert_eq!(t.scheme, PartitionScheme::None);
        assert!(t.partitions.is_empty());
        assert_eq!(t.warnings.len(), 1);
    }

    #[test]
    fn zu_kleines_image() {
        let t = scan_bytes(&[0u8; 100]);
        assert_eq!(t.scheme, PartitionScheme::None);
        assert!(!t.warnings.is_empty());
    }

    #[test]
    fn partition_hinter_imageende() {
        let mut img = synthetic_mbr();
        put_mbr_entry(&mut img, 2, 0x00, 0x07, u32::MAX, u32::MAX);
        let t = scan_bytes(&img);
        let p = &t.partitions[2];
        assert_eq!(p.fs_hint, FsHint::OutOfImage);
        assert_eq!(p.start_offset, u64::from(u32::MAX) * 512);
        assert!(t.warnings.iter().any(|w| w.contains("Imageende")));
    }

    #[test]
    fn leere_und_ungewöhnliche_einträge() {
        let mut img = synthetic_mbr();
        put_mbr_entry(&mut img, 2, 0x00, 0x07, 1, 0);
        put_mbr_entry(&mut img, 3, 0x12, 0x0F, 7, 1);
        let t = scan_bytes(&img);
        assert_eq!(t.partitions.len(), 3);
        assert!(t.warnings.iter().any(|w| w.contains("Länge 0")));
        assert!(t.warnings.iter().any(|w| w.contains("Statusbyte 0x12")));
        assert!(t.warnings.iter().any(|w| w.contains("erweiterte")));
    }

    #[test]
    fn volume_ohne_tabelle() {
        let mut img = vec![0u8; 4 * SS];
        put_ntfs_boot(&mut img, 0);
        let t = scan_bytes(&img);
        assert_eq!(t.scheme, PartitionScheme::Volume);
        assert_eq!(t.partitions.len(), 1);
        assert_eq!(t.partitions[0].fs_hint, FsHint::Ntfs);
        assert_eq!(t.partitions[0].size_bytes, 4 * SS as u64);
    }

    #[test]
    fn fs_signaturen() {
        let mut s = vec![0u8; SS];
        s[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(detect_fs(&s), FsHint::BitLocker);
        s[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(detect_fs(&s), FsHint::ExFat);
        s[3..11].copy_from_slice(b"ReFS\0\0\0\0");
        assert_eq!(detect_fs(&s), FsHint::Refs);

        let mut s = vec![0u8; SS];
        s[82..90].copy_from_slice(b"FAT32   ");
        assert_eq!(detect_fs(&s), FsHint::Unknown, "ohne 0x55AA kein FAT");
        s[510] = 0x55;
        s[511] = 0xAA;
        assert_eq!(detect_fs(&s), FsHint::Fat);
        assert_eq!(detect_fs(&s[..10]), FsHint::Unknown);
    }

    /// Baut ein GPT-Image mit 512-Byte-Sektoren: Protective MBR, Header an
    /// LBA 1, 4 Einträge à 128 Bytes ab LBA 2, Basic-Data-Partition auf LBA 4..=7
    /// mit NTFS-Bootsektor.
    fn synthetic_gpt() -> Vec<u8> {
        let mut img = vec![0u8; 10 * SS];
        put_mbr_entry(&mut img, 0, 0x00, 0xEE, 1, 9);
        img[510] = 0x55;
        img[511] = 0xAA;

        // Basic Data GUID EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 in On-Disk-Form.
        let basic = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
            0x99, 0xC7,
        ];
        let e = &mut img[2 * SS..2 * SS + 128];
        e[..16].copy_from_slice(&basic);
        e[16] = 1; // Unique GUID, beliebig
        e[32..40].copy_from_slice(&4u64.to_le_bytes());
        e[40..48].copy_from_slice(&7u64.to_le_bytes());
        for (i, c) in "Daten".encode_utf16().enumerate() {
            e[56 + 2 * i..58 + 2 * i].copy_from_slice(&c.to_le_bytes());
        }
        let array_crc = crc32fast::hash(&img[2 * SS..2 * SS + 4 * 128]);

        let h = &mut img[SS..SS + 92];
        h[..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&1u64.to_le_bytes());
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&4u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let hdr_crc = crc32fast::hash(h);
        h[16..20].copy_from_slice(&hdr_crc.to_le_bytes());

        put_ntfs_boot(&mut img, 4);
        img
    }

    #[test]
    fn gpt_mit_ntfs() {
        let t = scan_bytes(&synthetic_gpt());
        assert_eq!(t.scheme, PartitionScheme::Gpt);
        assert!(t.warnings.is_empty(), "{:?}", t.warnings);
        assert_eq!(t.partitions.len(), 1);
        let p = &t.partitions[0];
        assert_eq!(p.type_name, "Microsoft Basic Data");
        assert_eq!(
            p.typ,
            PartitionType::Gpt(Guid([
                0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
                0x99, 0xC7
            ]))
        );
        assert_eq!(p.start_lba, 4);
        assert_eq!(p.size_sectors, 4);
        assert_eq!(p.entry_offset, 1024);
        assert_eq!(p.name.as_deref(), Some("Daten"));
        assert_eq!(p.fs_hint, FsHint::Ntfs);
    }

    #[test]
    fn gpt_crc_fehler_wird_gemeldet() {
        let mut img = synthetic_gpt();
        img[SS + 24] ^= 0xFF; // Header verändern
        img[2 * SS + 16] ^= 0xFF; // Eintrag verändern
        let t = scan_bytes(&img);
        assert_eq!(t.scheme, PartitionScheme::Gpt);
        assert_eq!(t.partitions.len(), 1);
        assert!(t.warnings.iter().any(|w| w.contains("Header-CRC32")));
        assert!(t.warnings.iter().any(|w| w.contains("Eintragsarrays")));
    }

    #[test]
    fn gpt_mit_absurder_eintragsanzahl() {
        let mut img = synthetic_gpt();
        img[SS + 80..SS + 84].copy_from_slice(&u32::MAX.to_le_bytes());
        let t = scan_bytes(&img);
        // Fällt auf den Protective-MBR-Eintrag zurück, ohne zu allokieren.
        assert_eq!(t.scheme, PartitionScheme::Mbr);
        assert!(t.warnings.iter().any(|w| w.contains("Limit")));
    }

    #[test]
    fn guid_format() {
        let g = Guid([
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ]);
        assert_eq!(g.to_string(), "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
        assert_eq!(PartitionType::Gpt(g).description(), "EFI System");
    }

    #[test]
    fn zufallsdaten_ohne_panic() {
        // Einfacher deterministischer Generator, damit der Test reproduzierbar ist.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for len in [0usize, 1, 511, 512, 513, 1024, 4096, 8192] {
            for _ in 0..200 {
                let mut buf = vec![0u8; len];
                for b in &mut buf {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = x as u8;
                }
                if len >= 512 {
                    buf[510] = 0x55;
                    buf[511] = 0xAA;
                    buf[446 + 4] = 0xEE;
                }
                if len >= 1024 {
                    buf[512..520].copy_from_slice(b"EFI PART");
                }
                let _ = scan_bytes(&buf);
            }
        }
    }
}
