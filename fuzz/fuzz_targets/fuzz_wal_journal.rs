#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Fuzz recovery journal log lines
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(op) = parts.first() {
                match *op {
                    "BEGIN" | "RENAME" | "COMMIT" | "ROLLBACK" => {
                        let _ = parts.get(1);
                    }
                    _ => {}
                }
            }
        }
    }
});
