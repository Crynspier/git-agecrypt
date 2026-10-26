# Release Process, Provenance, and Verification Guide

This document defines the release engineering pipeline, artifact verification instructions, reproducible build guidelines, and support/upgrade policy for `git-agecrypt`.

---

## 1. Supported Platforms and Release Artifacts

Every tagged release (`v*`) built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) produces prebuilt binaries and archives after passing the full test suite (`release-gate`):

| Target Triple | Operating System / Architecture | Archive Name | Checksum File |
| :--- | :--- | :--- | :--- |
| `x86_64-unknown-linux-gnu` | Linux x86_64 | `git-agecrypt-linux-x86_64.tar.gz` | `git-agecrypt-linux-x86_64.tar.gz.sha256` |
| `x86_64-apple-darwin` | macOS Intel (x86_64) | `git-agecrypt-macos-x86_64.tar.gz` | `git-agecrypt-macos-x86_64.tar.gz.sha256` |
| `aarch64-apple-darwin` | macOS Apple Silicon (ARM64) | `git-agecrypt-macos-aarch64.tar.gz` | `git-agecrypt-macos-aarch64.tar.gz.sha256` |
| `x86_64-pc-windows-msvc` | Windows x86_64 (MSVC) | `git-agecrypt-windows-x86_64.zip` | `git-agecrypt-windows-x86_64.zip.sha256` |

Each release also publishes **GitHub Artifact Build Provenance Attestations** (`actions/attest-build-provenance` / SLSA build provenance signed via Sigstore Fulcio).

---

## 2. Verifying Release Checksums and Provenance Attestations

### 2.1 Verifying SHA-256 Checksums
Download your platform archive and its `.sha256` file from the [GitHub Releases](https://github.com/Crynspier/git-agecrypt/releases) page, then run:

- **Linux:**
  ```bash
  sha256sum --check git-agecrypt-linux-x86_64.tar.gz.sha256
  ```
- **macOS:**
  ```bash
  shasum -a 256 --check git-agecrypt-macos-aarch64.tar.gz.sha256
  ```
- **Windows (PowerShell):**
  ```powershell
  $expected = (Get-Content .\git-agecrypt-windows-x86_64.zip.sha256).Split(' ')[0].Trim()
  $actual = (Get-FileHash .\git-agecrypt-windows-x86_64.zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "SHA-256 mismatch!" } else { "SHA-256 verified: $actual" }
  ```

### 2.2 Verifying GitHub Build Provenance Attestations (`gh attestation verify`)
Using the [GitHub CLI (`gh` >= 2.49.0)](https://cli.github.com/):

```bash
gh attestation verify git-agecrypt-linux-x86_64.tar.gz \
  --repo Crynspier/git-agecrypt
```

This cryptographically verifies the Sigstore bundle against the repository's GitHub Actions workflow identity and commit SHA.

---

## 3. Building Reproducibly from Locked Source

To build from source with exact dependency pinning (`Cargo.lock`):

```bash
git clone https://github.com/Crynspier/git-agecrypt.git
cd git-agecrypt
git checkout v<VERSION>

# Build with locked dependencies
cargo build --release --locked

# Or install directly via Cargo
cargo install --path . --locked
```

---

## 4. Pre-Release Checklist and Quality Gates

Before tagging any release, maintainers MUST verify:
1. `cargo fmt --all -- --check` passes with zero diffs.
2. `cargo clippy --workspace --all-targets --locked -- -D warnings` passes with zero warnings.
3. `cargo test --locked --workspace` passes across Linux, macOS, and Windows.
4. `cargo deny check advisories bans licenses sources` passes in CI.
5. Golden format fixtures and migration fixtures (`tests/test_format_and_recovery_fixtures.rs`) pass without modification to historical v1 fixtures.
6. All action references in `.github/workflows/*.yml` and `examples/github-actions/*.yml` are pinned to full 40-character commit SHAs.
