//! Dateiinhalt, Vorschau und Wortsuche an einem synthetischen NTFS, ohne Mount.
use std::process::Command;
use stratum_core::ImageReader;
use stratum_lauf::datei::{ausschnitt, vorschau, wort_suchen, DateiOrt};
use stratum_ntfs::NtfsVolume;

#[test]
#[ignore = "benötigt mkntfs und ntfscp auf der Linux-VM"]
fn dateiinhalt_suche_und_vorschau() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("mini.ntfs");
    let source = dir.path().join("inhalt.txt");
    let mut bytes = vec![b'x'; 4094];
    bytes.extend_from_slice("Grüße".as_bytes());
    bytes.extend_from_slice(b" padding ");
    let utf16_offset = bytes.len() as u64;
    bytes.extend("Grüße".encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&source, &bytes).unwrap();
    std::fs::write(&image, vec![0u8; 16 * 1024 * 1024]).unwrap();
    assert!(Command::new("mkntfs")
        .args(["-F", "-Q"])
        .arg(&image)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ntfscp")
        .arg(&image)
        .arg(&source)
        .arg("inhalt.txt")
        .status()
        .unwrap()
        .success());
    let before = std::fs::read(&image).unwrap();
    let img = ImageReader::open(&image).unwrap();
    let mut vol = NtfsVolume::open(&img, 0, before.len() as u64).unwrap();
    let record = vol
        .read_file("inhalt.txt")
        .unwrap()
        .unwrap()
        .meta
        .mft_record;
    let o = DateiOrt {
        image: &image,
        bdp: None,
        volume_offset: 0,
        mft: record,
    };
    let result = wort_suchen(&o, "Grüße").unwrap();
    assert!(result.vollstaendig);
    assert_eq!(result.gelesen, bytes.len() as u64);
    assert_eq!(
        result.treffer.iter().map(|t| t.offset).collect::<Vec<_>>(),
        [4094, utf16_offset]
    );
    assert_eq!(ausschnitt(&o, 4094, 7).unwrap(), "Grüße".as_bytes());
    assert_eq!(vorschau(&o, bytes.len() as u64).unwrap(), bytes);
    assert!(vorschau(&o, 8 * 1024 * 1024 + 1).is_err());
    assert_eq!(std::fs::read(&image).unwrap(), before);
}
