//! Vergleich mit libvshadow am öffentlichen Testimage `vss.raw` aus dfvfs
//! (zwei Stores). Die Referenz-JSON enthält je Store den SHA-256 über den
//! ganzen Snapshot und die ersten 16 Hexzeichen des SHA-256 jedes
//! 16-KiB-Blocks.

use sha2::{Digest, Sha256};
use stratum_vss::{guid, Volume, BLOCK_SIZE};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
#[ignore = "benötigt STRATUM_VSS_REFERENCE mit vss.raw und vss_referenz.json"]
fn wie_libvshadow() {
    let dir = std::path::PathBuf::from(std::env::var_os("STRATUM_VSS_REFERENCE").unwrap());
    let data = std::fs::read(dir.join("vss.raw")).unwrap();
    let referenz: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("vss_referenz.json")).unwrap()).unwrap();
    let vol = Volume::open(&data).unwrap().expect("VSS erwartet");
    assert!(vol.warnings().is_empty(), "{:?}", vol.warnings());
    let stores = referenz["stores"].as_array().unwrap();
    assert_eq!(vol.store_count(), stores.len());
    for (info, r) in vol.stores().into_iter().zip(stores) {
        assert_eq!(guid(&info.id), r["id"].as_str().unwrap());
        assert_eq!(info.volume_size, r["volume_groesse"].as_u64().unwrap());
        assert_eq!(
            info.block_descriptors as u64,
            r["bloecke"].as_u64().unwrap()
        );
        let mut h = Sha256::new();
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        let bloecke = r["block_sha"].as_array().unwrap();
        let mut abweichend = Vec::new();
        let mut pos = 0u64;
        for (n, erwartet) in bloecke.iter().enumerate() {
            let len = BLOCK_SIZE.min(info.volume_size - pos) as usize;
            vol.read_at(info.index, pos, &mut buf[..len]).unwrap();
            h.update(&buf[..len]);
            if hex(&Sha256::digest(&buf[..len]))[..16] != *erwartet.as_str().unwrap() {
                abweichend.push(n);
            }
            pos += len as u64;
        }
        assert!(
            abweichend.is_empty(),
            "Store {}: {abweichend:?}",
            info.index
        );
        assert_eq!(hex(&h.finalize()), r["sha256"].as_str().unwrap());

        // Dasselbe über Read mit ungerader Lesegröße.
        let mut rd = vol.reader(info.index).unwrap();
        let mut h = Sha256::new();
        let mut stueck = vec![0u8; 7777];
        loop {
            let n = std::io::Read::read(&mut rd, &mut stueck).unwrap();
            if n == 0 {
                break;
            }
            h.update(&stueck[..n]);
        }
        assert_eq!(hex(&h.finalize()), r["sha256"].as_str().unwrap());
    }
}
