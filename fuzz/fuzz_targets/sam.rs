#![no_main]

use libfuzzer_sys::fuzz_target;
use stratum_creds::{hashed_bootkey, user_hash};

// Die F- und V-Strukturen stammen aus einem nicht vertrauenswuerdigen Hive.
// Die Offset-Arithmetik darf auf keiner Eingabe paniken.
fuzz_target!(|data: &[u8]| {
    let key = [0u8; 16];
    let _ = hashed_bootkey(data, &key);
    let _ = user_hash(data, 500, &key);
});
