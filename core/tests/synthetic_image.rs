//! Durchstich gegen ein synthetisches Mini-Image auf der Platte:
//! öffnen, hashen, Partitionen erkennen, Bootsektor lesen.

use std::io::Write;

use stratum_core::{hash_image, scan_partitions, FsHint, ImageReader, PartitionScheme};

const SS: usize = 512;

fn build_image() -> Vec<u8> {
    let mut img = vec![0u8; 16 * SS];
    // MBR-Eintrag 0: NTFS, aktiv, LBA 2, 8 Sektoren
    let e = &mut img[446..462];
    e[0] = 0x80;
    e[4] = 0x07;
    e[8..12].copy_from_slice(&2u32.to_le_bytes());
    e[12..16].copy_from_slice(&8u32.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    let boot = &mut img[2 * SS..3 * SS];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[510] = 0x55;
    boot[511] = 0xAA;
    img
}

#[test]
fn durchstich() {
    let data = build_image();
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let img = ImageReader::open(f.path()).unwrap();
    assert_eq!(img.len(), data.len() as u64);

    let h = hash_image(&img);
    assert_eq!(h.bytes, data.len() as u64);
    assert_eq!(h.sha256.len(), 64);
    assert_eq!(h.blake3, blake3::hash(&data).to_hex().to_string());

    let t = scan_partitions(&img);
    assert_eq!(t.scheme, PartitionScheme::Mbr);
    assert_eq!(t.partitions.len(), 1);
    let p = &t.partitions[0];
    assert_eq!(p.fs_hint, FsHint::Ntfs);

    let boot = img.read_at(p.start_offset, SS).unwrap();
    assert_eq!(&boot[3..11], b"NTFS    ");
    assert!(img.read_at(img.len() - 1, 2).is_err());
}
