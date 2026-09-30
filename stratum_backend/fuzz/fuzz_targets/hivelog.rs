#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Erste Hälfte als Hive, zweite als Transaktionslog.
    let (hive, log) = data.split_at(data.len() / 2);
    let log = stratum_registry::TransactionLog::parse(log);
    let _ = stratum_registry::recover(hive, &[log]);
});
