#![no_main]

use libfuzzer_sys::fuzz_target;
use stratum_ntfs::NtfsVolume;

// Der NTFS-Parser liest nicht vertrauenswürdige Images. Hier wird geprüft,
// dass beliebige Bytes weder Panic noch Endlosschleife auslösen.
fuzz_target!(|data: &[u8]| {
    let Ok(mut vol) = NtfsVolume::from_bytes(data) else {
        return;
    };
    let _ = vol.read_file("Windows/System32/config/SYSTEM");
    let _ = vol.exists("Users");
    let _ = vol.list_dir("");
});
