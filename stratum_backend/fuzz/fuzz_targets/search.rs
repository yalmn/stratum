#![no_main]

use libfuzzer_sys::fuzz_target;
use stratum_search::{SearchEngine, TermTable};

fuzz_target!(|data: &[u8]| {
    // Feste Tabelle mit allen Modi, damit der Fuzzer die Byte-Suche trifft.
    let table = TermTable::from_str(
        r#"
        [meta]
        name = "fuzz"
        max_treffer = 5000
        [[kategorie]]
        id = "z"
        modus = "paar"
        links = ["user", "un"]
        rechts = ["pw", "pass"]
        abstand_bytes = 64
        [[kategorie]]
        id = "d"
        begriffe = [".onion", "torrc"]
        onion_pruefung = true
        "#,
    )
    .unwrap();
    let engine = SearchEngine::new(&table);
    let _ = engine.run(data, 0);
});
