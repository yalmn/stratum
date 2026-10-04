#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(hits) = stratum_connectors::yara::ausgabe_lesen(s, 256 * 1024 * 1024) {
            assert!(hits.len() <= 500);
            for hit in hits { for value in hit.strings { assert!(value.offset.checked_add(value.gespeicherte_laenge).is_some_and(|end|end <= 256 * 1024 * 1024)); } }
        }
        let _ = stratum_connectors::netzwerk::host_eingabe(s);
    }
});
