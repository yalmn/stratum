#![no_main]

use libfuzzer_sys::fuzz_target;
use stratum_registry::{Hive, Key};

/// Läuft begrenzt durch den Baum. Die Grenzen gehören zum Fuzz-Target, nicht
/// zum Parser: ein Hive darf Zyklen enthalten, das Durchlaufen muss der
/// Aufrufer begrenzen.
fn walk(key: &Key<'_, '_>, depth: u32, budget: &mut u32) {
    if depth > 16 || *budget == 0 {
        return;
    }
    *budget -= 1;
    if let Ok(values) = key.values() {
        for v in values {
            let _ = (v.as_string(), v.as_multi_string(), v.as_u32(), v.as_u64());
        }
    }
    if let Ok(subkeys) = key.subkeys() {
        for k in subkeys {
            walk(&k, depth + 1, budget);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(hive) = Hive::parse(data) else { return };
    if let Ok(root) = hive.root() {
        let mut budget = 10_000;
        walk(&root, 0, &mut budget);
    }
    let _ = hive.open_key("Select");
    let _ = hive.open_key("ControlSet001\\Control\\TimeZoneInformation");
});
