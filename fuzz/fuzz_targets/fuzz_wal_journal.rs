#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = git_agecrypt::format::parse_and_validate_lock_journal(text);
        let _ = git_agecrypt::format::parse_format_file_content(text);
        let _ = git_agecrypt::format::parse_and_validate_repo_pub(text);
        let _ = git_agecrypt::format::validate_wrapped_key_envelope(text);
    }
});
