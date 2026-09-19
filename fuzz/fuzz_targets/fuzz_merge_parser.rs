#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz semantic merge conflict parser with arbitrary byte sequences
    let _ = git_agecrypt::merge::find_semantic_conflicts(data, "fuzz_input.env");
});
