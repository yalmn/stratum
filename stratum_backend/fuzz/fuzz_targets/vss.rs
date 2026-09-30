#![no_main]

use libfuzzer_sys::fuzz_target;

// Beliebige Bytes als Volume: Kopf, Katalog, Blocklisten und Lesepfad.
fuzz_target!(|data: &[u8]| {
    if let Ok(Some(vol)) = stratum_vss::Volume::open(data) {
        let mut buf = [0u8; 0x8000];
        for s in 0..vol.store_count() {
            let _ = vol.read_at(s, 0, &mut buf);
            let _ = vol.read_at(s, 0x3ff0, &mut buf[..64]);
        }
    }
});
