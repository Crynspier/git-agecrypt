# Contributing to git-agecrypt

Thank you for your interest in improving `git-agecrypt`!

## Development Setup

`git-agecrypt` requires Rust 1.88.0 or later (Rust 2024 edition):

```bash
# Clone the repository
git clone https://github.com/Crynspier/git-agecrypt.git
cd git-agecrypt

# Build in debug mode
cargo build
```

## Running Tests

The test suite includes unit tests and comprehensive end-to-end integration tests. During normal development, use the split commands below rather than the broad all-targets invocation, which is reserved as the final comprehensive gate:

```bash
# Unit tests and binary test targets
cargo test --workspace --locked --lib --bins

# Integration tests (run each integration binary concurrently on Windows)
powershell -ExecutionPolicy Bypass -File ./scripts/run-integration-tests.ps1 -MaxParallel 4

# Re-run a focused integration test with output
cargo test --workspace --locked --test test_generative_shadow_state_machine -- --nocapture
```

For the coverage-guided fuzz targets, install `cargo-fuzz` separately and run them on demand from the repository root:

```bash
cargo fuzz run fuzz_age_ciphertext -- -runs=10000
cargo fuzz run fuzz_wal_journal -- -runs=10000
cargo fuzz run fuzz_merge_parser -- -runs=10000
cargo fuzz run fuzz_gitattributes -- -runs=10000
```

Record the target, seed/options, toolchain, commit, and result for release evidence.

## Code Quality Standards

Before opening a pull request, ensure your changes satisfy the project's automated verification gates:

```bash
# 1. Format check
cargo fmt --check

# 2. Strict linter check (zero warnings)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Release build check
cargo build --release
```

## Pull Requests

1. Keep commits focused and atomic.
2. Include tests for any bug fixes or new features.
3. Update relevant documentation in `README.md` if CLI arguments or behaviors change.
