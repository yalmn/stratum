//! Kleines synthetisches Image (siehe `fixtures/README.md`), ohne externe
//! Daten: rohe und komprimierte Chunks, unvollständiger letzter Chunk,
//! Akquise-MD5 und Akquisedaten.

use md5::Md5;
use sha2::{Digest, Sha256};
use stratum_ewf::EwfImage;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bild() -> EwfImage {
    let pfad = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/klein.E01");
    EwfImage::open(&pfad).unwrap()
}

#[test]
fn inhalt_und_hashes() {
    let img = bild();
    assert!(img.warnings().is_empty(), "{:?}", img.warnings());
    assert_eq!(img.media_size(), 135_680);
    assert_eq!(img.chunk_size(), 32_768);
    assert_eq!(img.chunk_count(), 5);
    let roh: Vec<bool> = (0..5)
        .map(|i| !img.chunk_location(i).unwrap().compressed)
        .collect();
    assert_eq!(roh, [true, true, true, false, false]);

    let mut alles = vec![0u8; img.media_size() as usize];
    img.read_at(0, &mut alles).unwrap();
    // SHA-256 der Rohdaten, aus denen das Image erzeugt wurde.
    assert_eq!(
        hex(&Sha256::digest(&alles)),
        "b15c14c2a93def1ad9b5aa5b4133f946b4b17d48bcef528a4e4829115ee64db0"
    );
    assert_eq!(
        hex(&Md5::digest(&alles)),
        "c6bcf4f05097cc2e30cca678a24919a7"
    );
    assert_eq!(
        img.stored_hashes().md5.map(|m| hex(&m)).as_deref(),
        Some("c6bcf4f05097cc2e30cca678a24919a7")
    );
    assert_eq!(&alles[3 * 32_768..4 * 32_768], &[0u8; 32_768][..]);
    assert!(alles[4 * 32_768..].starts_with(b"stratum E01 Fixture "));

    // Lesen über Chunkgrenzen und am Ende.
    let mut b = [0u8; 10];
    img.read_at(32_768 - 5, &mut b).unwrap();
    assert_eq!(b, alles[32_768 - 5..32_768 + 5]);
    img.read_at(135_670, &mut b).unwrap();
    assert!(img.read_at(135_671, &mut b).is_err());
}

#[test]
fn akquisedaten() {
    let img = bild();
    let i = img.info();
    assert_eq!(i.source, Some("header2"));
    assert_eq!(i.get("c"), Some("Fixture"));
    assert_eq!(i.get("e"), Some("stratum"));
    assert_eq!(i.get("t"), Some("synthetisch"));
    assert!(i.acquired_unix().is_some());
}
