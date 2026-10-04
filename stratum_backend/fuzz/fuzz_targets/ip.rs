#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
fuzz_target!(|data: &[u8]| {
    let mut scanner = stratum_search::ip::IpScanner::neu(1024 * 1024);
    for block in data.chunks(17) {
        if scanner.write_all(block).is_err() { break; }
    }
    let complete = !scanner.begrenzt();
    let result = scanner.abschliessen(complete);
    assert!(result.treffer.len() <= 500);
    assert!(result.gelesen <= data.len() as u64);
    for hit in result.treffer {
        let expected = if hit.kodierung == "ASCII" { hit.original.as_bytes().to_vec() }
            else { hit.original.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        assert_eq!(data.get(hit.offset as usize..(hit.offset + hit.laenge) as usize), Some(expected.as_slice()));
    }
});
