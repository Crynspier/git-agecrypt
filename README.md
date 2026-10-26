# `git-agecrypt`

[![CI](https://github.com/Crynspier/git-agecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Crynspier/git-agecrypt/actions/workflows/ci.yml)
[![Release](https://github.com/Crynspier/git-agecrypt/actions/workflows/release.yml/badge.svg)](https://github.com/Crynspier/git-agecrypt/actions/workflows/release.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Transparent, GPG-free Git file encryption powered by [`age`](https://age-encryption.org/) and existing SSH keys.**

`git-agecrypt` encrypts sensitive files (`*.secret.env`, `secrets/**`, certificates, configuration files) transparently inside Git repositories using Git's native `clean`, `smudge`, `textconv`, and 3-way `merge` drivers. Files stay decrypted in your local working tree while unlocked, and are guaranteed to be stored as binary **age v1** (`X25519` + `ChaCha20-Poly1305`) ciphertext in the Git index, commit history, and remote servers.

![git-agecrypt Architecture and Trust Boundary Diagram](docs/architecture.svg)

---

## Why `git-agecrypt`?

| Capability | `git-agecrypt` | `git-crypt` | `sops` |
| :--- | :--- | :--- | :--- |
| **Cryptographic Backend** | Modern `age` v1 (`X25519` + `ChaCha20-Poly1305`) | Legacy GPG keyring (`gpg`) or symmetric key | `age`, PGP, Cloud KMS |
| **Uses Existing SSH Keys (`id_ed25519` / `id_rsa`)** | Yes (native `age-ssh`) | No | Via `ssh-to-age` conversion |
| **Transparent Git Working Tree (`clean`/`smudge`)** | Yes (any text or binary file) | Yes | No (manual edit/decrypt wrapper) |
| **Key Revocation & Rotation (`rekey` + `rewrap`)** | Built-in (`git-agecrypt rekey` & `rewrap`) | Not built-in | Manual `sops updatekeys` |
| **Scoped Multi-Ring Isolation (`--ring prod`)** | Built-in per-environment rings | Symmetric key files only | File-level `.sops.yaml` rules |
| **3-Way Encrypted Merge Driver (`merge`)** | Built-in with semantic key=value conflict warnings | Binary conflict | No native Git merge driver |
| **Crash-Safe Lock Journal & Recovery (`inspect`)** | OS-locked WAL journal (`recovery.lock` + `lock.journal`) | None | N/A |
| **Server-Side `pre-receive` & CI Enforcement** | Built-in (`check --pre-receive` & `--commit-range`) | External scripts | External scripts |

---

## 60-Second Quickstart

```bash
# 1. Initialize git-agecrypt in your Git repository (creates .gitattributes, repo.pub, and hooks)
git-agecrypt init

# 2. Enroll a teammate or CI runner using an age or SSH public key (or --github <username>)
git-agecrypt add-recipient -i ~/.ssh/id_ed25519.pub -n alice

# 3. Create a secret file matching .gitattributes and commit normally
mkdir -p secrets
echo "DATABASE_URL=postgres://app:supersecret@db.internal:5432/prod" > secrets/app.secret.env
git add .gitattributes .git-agecrypt secrets/app.secret.env
git commit -m "feat: add encrypted application secrets"

# 4. Verify that the blob stored in Git is age v1 ciphertext (never plaintext!)
git show HEAD:secrets/app.secret.env | head -c 21
# -> age-encryption.org/v1

# 5. Lock the working tree when done (or unlock on a fresh clone with `git-agecrypt unlock`)
git-agecrypt lock
git-agecrypt unlock ~/.ssh/id_ed25519
```

---

## Installation & Verification

### 1. Prebuilt Release Binaries (Linux, macOS, Windows)
Download the archive for your platform (`git-agecrypt-linux-x86_64.tar.gz`, `git-agecrypt-macos-x86_64.tar.gz`, `git-agecrypt-macos-aarch64.tar.gz`, or `git-agecrypt-windows-x86_64.zip`) and its `.sha256` checksum file from [GitHub Releases](https://github.com/Crynspier/git-agecrypt/releases), then verify its integrity and provenance:

```bash
# Verify SHA-256 checksum (Linux / macOS)
shasum -a 256 --check git-agecrypt-linux-x86_64.tar.gz.sha256

# Verify GitHub Sigstore build provenance attestation
gh attestation verify git-agecrypt-linux-x86_64.tar.gz \
  --repo Crynspier/git-agecrypt
```

### 2. Build from Source with Cargo
```bash
cargo install --locked git-agecrypt
# Or from a local checkout:
cargo install --path . --locked
```

---

## Core Workflows & CLI Reference

| Command | Description |
| :--- | :--- |
| `git-agecrypt init [--ring <RING>] [--ai-shield]` | Initialize repository or named ring, configure `.git/config` drivers, and install safeguard hooks. |
| `git-agecrypt add-recipient (-i <KEY> \| --github <USER>) [-n <NAME>] [--ring <RING>]` | Enroll an `age1...` or SSH public key (`ssh-ed25519` / `ssh-rsa`) as a recipient. |
| `git-agecrypt remove-recipient <NAME> [--ring <RING>]` | Remove a recipient envelope from `.git-agecrypt/keys/`. |
| `git-agecrypt list-recipients [--ring <RING>]` | List enrolled recipient envelopes and public key prefixes. |
| `git-agecrypt rekey [-f] [--ring <RING>]` | Rotate the ring's master key, re-wrap for remaining recipients, and re-encrypt working tree secrets. |
| `git-agecrypt rewrap (<PATH>... \| --all) [-i <KEY>] [-f]` | Re-encrypt historical or cherry-picked ciphertexts under the current active master key. |
| `git-agecrypt unlock [<KEY_FILE> \| -] [-f] [--ring <RING>]` | Unwrap the master key using your private key and decrypt tracked secrets across worktrees. |
| `git-agecrypt lock [-f] [--ring <RING>]` | Transactionally wipe local `repo.key` and replace working tree secrets with ciphertext. |
| `git-agecrypt status` | Show lock status, active public key, tracked `.gitattributes` patterns, and configured rings. |
| `git-agecrypt inspect [--format text\|json] [--ring <RING>]` | Read-only diagnostic report of format version, recipient envelopes, key state, and recovery actions. |
| `git-agecrypt export-age <FILE> -r <RECIPIENT> -o <OUT_FILE> [--ring <RING>] [-i <KEY>] [-y]` | Export a tracked secret to a standalone standard `age` file without writing plaintext to stdout. |
| `git-agecrypt check [--pre-push \| --pre-receive \| --commit-range <RANGE>] [--report-only]` | Verify staged files, outgoing pushes, incoming server refs, or CI commit ranges against plaintext leaks. |
| `git-agecrypt run [-e <ENV_FILE>] [--ring <RING>] [--fd] -- <CMD> [ARGS...]` | Run a subprocess with decrypted `.env` secrets injected (supports Linux `memfd_create` via `--fd`). |
| `git-agecrypt shield [--check]` | Synchronize tracked secret patterns into `.cursorignore`, `.claudeignore`, `.aiderignore`, and `.aiignore`. |
| `git-agecrypt migrate-from-git-crypt [-i <KEY>]` | Migrate `.gitattributes` rules and tracked secrets from `git-crypt` to `git-agecrypt`. |

---

## Security Posture & Limitations

- **Evidence-Bounded Claims:** `git-agecrypt` has not yet undergone a paid third-party cryptographic audit. All cryptographic operations use the upstream [`age`](https://crates.io/crates/age) crate (`X25519`, `ChaCha20-Poly1305`) and RustCrypto [`sha2`](https://crates.io/crates/sha2) / [`hmac`](https://crates.io/crates/hmac). See [`docs/security-review-package.md`](docs/security-review-package.md) for the complete `unsafe`/syscall inventory and threat model.
- **Git History Immutability:** Removing a collaborator (`remove-recipient` + `rekey`) prevents them from decrypting *future* commits, but cannot erase their access to historical commits they already cloned. Always rotate actual external credentials when offboarding.
- **Server-Side Enforcement Recommended:** Client-side Git hooks can be skipped with `--no-verify`. Production repositories should enable the reference server-side `pre-receive` hook ([`examples/hooks/pre-receive`](examples/hooks/pre-receive)) or GitHub Action workflow ([`examples/github-actions/agecrypt-verify.yml`](examples/github-actions/agecrypt-verify.yml)).
- **Clean-Room Recovery Without `git-agecrypt`:** Because Format Version 1 uses standard `age` v1 files, you can recover any secret using only `git` and the standard `age` CLI (`grep -v '^#' .git-agecrypt/keys/<you>.age | age -d -i <your_key> > repo.key && git show HEAD:<secret> | age -d -i repo.key`).

---

## Documentation Index

- **[Format Specification (v1)](docs/format-spec.md)** — Normative on-disk and in-Git format specification, compatibility policy, and recovery rules.
- **[Operations & Disaster Recovery Guide](docs/operations.md)** — Onboarding, offboarding, multi-ring isolation, upgrades, `inspect`, `export-age`, and clean-room recovery.
- **[Server & CI Enforcement Guide](docs/server-enforcement.md)** — Deploying bare-repository `pre-receive` hooks and GitHub Actions verification.
- **[Internals & Locking Architecture](docs/internals.md)** — Envelope encryption, convergence cache, shared-state mutation table, and WAL lock transactions.
- **[Security Model & Threat Boundaries](docs/security-model.md)** — Threat actors, platform mitigations, and residual risks.
- **[External Security Review Package](docs/security-review-package.md)** — Data-flow diagrams, complete `unsafe`/syscall inventory, and auditor focus areas.
- **[Specification Guarantees](docs/spec-guarantees.md)** — Formal operational invariants and failure-mode guarantees.
- **[Verification Matrix](docs/verification-matrix.md)** — Mapping of security invariants to automated unit, integration, crash, concurrency, and fuzz tests.
- **[Release Process & Provenance](docs/release-process.md)** — Checksum verification, Sigstore build provenance attestations, and reproducible builds.

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
