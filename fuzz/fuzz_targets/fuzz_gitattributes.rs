#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = git_agecrypt::format::parse_gitattributes_rules(text);
        for line in text.lines() {
            let _ = git_agecrypt::git::validate_ring_name(line.trim());
            let _ = git_agecrypt::git::is_shell_safe_repo_path(line.trim());
        }
    }
});
