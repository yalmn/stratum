//! Vergleich mit libewf: dfvfs-Testdaten (`ext2.E01`, mehrteilig
//! `ext2.split.E01/E02`) und mit `ewfacquire` 20230212 aus `vss.raw`
//! erzeugte Varianten (EnCase 1/5/6/7, FTK Imager, linen 6, ohne Kompression
//! in vier Segmenten, 128 Sektoren je Chunk). Erwartet werden der SHA-256
//! der Mediendaten (aus `ewfexport` bzw. dem Rohimage), der gespeicherte
//! Akquise-MD5 und bei den eigenen Varianten die Akquisedaten.

use md5::Md5;
use sha2::{Digest, Sha256};
use stratum_ewf::EwfImage;

const VSS: &str = "e633f0be5fb9ee9a07d44ba5223b786012ce89e9f0024f93d743568e6d052f16";
const EXT2: &str = "a6c2f0e39afe6c6ab432ca5465349fcefe8dc944398e97b2d957d3f89dbb5d80";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn pruefen(datei: &str, sha256: &str, segmente: usize) -> EwfImage {
    let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_EWF_REFERENCE").unwrap());
    let img = EwfImage::open(&dir.join(datei)).unwrap_or_else(|e| panic!("{datei}: {e}"));
    assert!(img.warnings().is_empty(), "{datei}: {:?}", img.warnings());
    assert_eq!(img.segment_paths().len(), segmente, "{datei}");
    let mut sha = Sha256::new();
    let mut md5 = Md5::new();
    // Ungerade Stückgröße, damit Lesevorgänge über Chunkgrenzen gehen.
    let mut buf = vec![0u8; 100_003];
    let mut pos = 0u64;
    while pos < img.media_size() {
        let n = (img.media_size() - pos).min(buf.len() as u64) as usize;
        img.read_at(pos, &mut buf[..n]).unwrap();
        sha.update(&buf[..n]);
        md5.update(&buf[..n]);
        pos += n as u64;
    }
    assert_eq!(hex(&sha.finalize()), sha256, "{datei}");
    let md5 = md5.finalize();
    assert_eq!(
        img.stored_hashes().md5.map(|m| hex(&m)),
        Some(hex(&md5)),
        "{datei}: Akquise-MD5"
    );
    img
}

#[test]
#[ignore = "benötigt STRATUM_EWF_REFERENCE mit den Testimages"]
fn wie_libewf() {
    pruefen("ext2.E01", EXT2, 1);
    pruefen("ext2.split.E01", EXT2, 2);
    for (datei, segmente) in [
        ("vss_e6best.E01", 1),
        ("vss_e6none.E01", 4),
        ("vss_e6fast_b128.E01", 1),
        ("vss_e5.E01", 1),
        ("vss_e7.E01", 1),
        ("vss_ftk.E01", 1),
        ("vss_linen6.E01", 1),
        ("vss_ewf.e01", 4),
    ] {
        let img = pruefen(datei, VSS, segmente);
        let i = img.info();
        assert_eq!(i.get("c"), Some("Fall-42"), "{datei}");
        assert_eq!(i.get("e"), Some("Pruefer"), "{datei}");
        assert_eq!(i.get("n"), Some("E-7"), "{datei}");
        if i.source == Some("header2") {
            assert_eq!(i.get("t"), Some("Notiz äöü"), "{datei}");
        }
    }
}

/// Ein verfälschtes Byte in einem rohen (Adler-32) und einem komprimierten
/// (zlib) Chunk führt zu einem Lesefehler genau dieses Chunks.
#[test]
#[ignore = "benötigt STRATUM_EWF_REFERENCE mit den Testimages"]
fn beschaedigte_chunks_werden_erkannt() {
    let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_EWF_REFERENCE").unwrap());
    for datei in ["vss_e6none.E01", "vss_e6best.E01"] {
        let pfad = dir.join(datei);
        let gut = EwfImage::open(&pfad).unwrap();
        let loc = gut.chunk_location(3).unwrap();
        let mut segmente: Vec<Vec<u8>> = gut
            .segment_paths()
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        let at = (loc.offset + loc.stored_len / 2) as usize;
        segmente[loc.segment][at] ^= 0x40;
        let kaputt = EwfImage::from_bytes(segmente).unwrap();
        let cs = u64::from(kaputt.chunk_size());
        let mut b = vec![0u8; cs as usize];
        assert!(kaputt.read_at(2 * cs, &mut b).is_ok(), "{datei}: Chunk 2");
        let fehler = kaputt.read_at(3 * cs, &mut b).unwrap_err().to_string();
        assert!(fehler.starts_with("Chunk 3"), "{datei}: {fehler}");
        assert!(kaputt.read_at(4 * cs, &mut b).is_ok(), "{datei}: Chunk 4");
    }
}
