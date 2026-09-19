#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Fuzz ring name validation and pattern matching
        for line in text.lines() {
            let _ = git_agecrypt::git::validate_ring_name(line.trim());
        }
    }
});
