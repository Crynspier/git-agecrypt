#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Fuzz age stream header parsing and decryption fail-closed behavior
    let mut reader = Cursor::new(data);
    let id = age::x25519::Identity::generate();
    if let Ok(decryptor) = age::Decryptor::new(&mut reader) {
        let _ = decryptor.decrypt(std::iter::once(&id as &dyn age::Identity));
    }
});
