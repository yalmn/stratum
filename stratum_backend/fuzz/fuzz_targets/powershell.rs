#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = stratum_analysis::parse_powershell_history(data, "ConsoleHost_history.txt");
});
