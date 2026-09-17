# Contributing to git-agecrypt

Thank you for your interest in improving `git-agecrypt`!

## Development Setup

`git-agecrypt` requires a standard Rust toolchain (Rust 1.74+):

```bash
# Clone the repository
git clone https://github.com/Crynspier/git-agecrypt.git
cd git-agecrypt

# Build in debug mode
cargo build
```

## Running Tests

The test suite includes both unit tests and comprehensive end-to-end integration tests:

```bash
# Run all tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture
```

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
