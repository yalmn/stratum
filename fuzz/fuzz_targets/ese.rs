#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(db) = stratum_ese::Database::open(data) else {
        return;
    };
    for table in db.tables() {
        let Ok(records) = db.records(table) else {
            continue;
        };
        for record in records.iter().take(1000) {
            for column in &table.columns {
                let _ = record.get(column);
            }
        }
    }
});
