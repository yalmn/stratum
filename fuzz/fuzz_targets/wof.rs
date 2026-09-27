#![no_main]
use libfuzzer_sys::fuzz_target;
use stratum_ntfs::wof::{decompress, parse_reparse, WofFormat};

// Reparse-Puffer und WofCompressedData stammen aus nicht vertrauenswürdigen
// Images: weder Panik noch unbegrenzter Speicher.
fuzz_target!(|data: &[u8]| {
    let _ = parse_reparse(data);
    if data.len() < 5 {
        return;
    }
    let format = match data[0] % 4 {
        0 => WofFormat::Xpress4k,
        1 => WofFormat::Lzx,
        2 => WofFormat::Xpress8k,
        _ => WofFormat::Xpress16k,
    };
    let size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
    let _ = decompress(&data[5..], format, size, 1 << 20);
});
