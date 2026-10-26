# Format Version 1 Golden & Migration Fixtures

This directory contains pinned Format Version 1 test vectors verified by [`tests/test_format_and_recovery_fixtures.rs`](../../test_format_and_recovery_fixtures.rs).

- `format`: Explicit Format Version 1 marker (`1\n`).
- `repo.pub`: Pinned v1 master public key (`age1...`).
- `identity.txt`: Test-only collaborator X25519 private key used to unwrap `recipient_x25519.age`.
- `recipient_x25519.age`: Pinned v1 ASCII-armored wrapped master key envelope with `# public-key:` header.
- `secret.env.age`: Pinned v1 binary `age` ciphertext encrypted under the master key in `recipient_x25519.age`.

**Policy:** Never regenerate or mutate these v1 fixture files when making future changes; they enforce long-term backward compatibility across `v0.6.x` and `v1.x`.
