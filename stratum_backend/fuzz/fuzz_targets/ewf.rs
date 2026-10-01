#![no_main]

use libfuzzer_sys::fuzz_target;

// Beliebige Bytes als einzelne Segmentdatei: Sektionen, Tabellen, Chunks.
fuzz_target!(|data: &[u8]| {
    if let Ok(img) = stratum_ewf::EwfImage::from_bytes(vec![data.to_vec()]) {
        let mut buf = vec![0u8; 70_000];
        let n = img.media_size().min(buf.len() as u64) as usize;
        let _ = img.read_at(0, &mut buf[..n]);
    }
});
