# Security Policy & Vulnerability Reporting

## Supported Versions

| Format Version | Supported | Notes |
| :--- | :--- | :--- |
| Format Version `1` (Latest release) | :white_check_mark: Yes | Recommended for all deployments. |
| Earlier releases | :x: No | Upgrade to the latest release (100% format-compatible with existing Format Version `1` repositories). |

For upgrade, rollback, and clean-room disaster recovery instructions, see [`docs/operations.md`](docs/operations.md).

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report suspected vulnerabilities privately via **[GitHub Private Vulnerability Reporting (Security Advisories)](https://github.com/Crynspier/git-agecrypt/security/advisories/new)**.

### What to Include in a Report
- The `git-agecrypt --version` and platform/OS (`Linux`, `macOS`, `Windows`).
- A minimal reproduction script or repository fixture demonstrating the issue.
- Which security boundary or invariant is affected (see [`docs/security-model.md`](docs/security-model.md) and [`docs/security-review-package.md`](docs/security-review-package.md)).

---

## External Security Review & Audit Status

`git-agecrypt` has not yet undergone a paid third-party cryptographic audit.
- All symmetric and asymmetric cryptography is delegated directly to the upstream [`age`](https://crates.io/crates/age) crate (`X25519`, `ssh-ed25519`, `ssh-rsa`, `ChaCha20-Poly1305` STREAM) and RustCrypto (`sha2`, `hmac`).
- A comprehensive **[External Security Review Readiness Package](docs/security-review-package.md)** documents the complete trust model, key hierarchy, data-flow diagrams, every `unsafe` block and OS syscall in the codebase, crash/durability invariants, and priority review questions.
