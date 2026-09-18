# git-agecrypt

Transparent client-side Git encryption using [age](https://age-encryption.org/v1), SSH keys, and hardware tokens.

[![CI](https://github.com/Crynspier/git-agecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Crynspier/git-agecrypt/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

---

`git-agecrypt` provides transparent file encryption and decryption for Git repositories using Git's native filter drivers (`clean`, `smudge`, `diff`, and `merge`).

Files remain unencrypted cleartext in your local working directory so your editor, linters, and compiler can access them normally. When files are committed or pushed to a remote repository, they are automatically encrypted into authenticated `age` ciphertexts. Collaborators without an enrolled private key see only encrypted data.

It is designed as a modern replacement for `git-crypt`, substituting GPG and OpenSSL dependencies with the `age` format (X25519, ChaCha20-Poly1305), standard SSH Ed25519 or RSA keys, and native Age hardware plugins (YubiKey, Apple Secure Enclave, TPM).

---

## Contents

- [Architecture](#architecture)
- [Features](#features)
- [How It Compares](#how-it-compares)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [CI / CD Integration](#ci--cd-integration)
- [Migration from git-crypt](#migration-from-git-crypt)
- [CLI Reference](#cli-reference)
- [Documentation & Deep Dives](#documentation--deep-dives)
- [Minimum Supported Versions](#minimum-supported-versions)
- [License](#license)

---

## Architecture

### Transparent Filter Pipeline

```text
Working Tree                 Git Index & Staging              Remote (GitHub, etc.)
(Cleartext on disk)          (Local object store)             (Encrypted ciphertext)

+------------------+         +------------------+             +------------------+
|  secrets.env     | git add | age-encryption/v1|  git push   | age-encryption/v1|
|  PASS=secret     |-------->| [authenticated]  |------------>| [authenticated]  |
+------------------+  clean  +------------------+             +------------------+
         ^                            |
         |        git checkout        |
         +----------------------------+
                     smudge
```

### Key Management

`git-agecrypt` uses a two-tier key envelope:

1. **Repository Master Key:** A 256-bit symmetric key that encrypts all secret files in the repository.
2. **Recipient Envelopes (`.git-agecrypt/keys/<name>.age`):** The master key is encrypted individually for each authorized team member using their SSH public key (`~/.ssh/id_ed25519.pub`, `~/.ssh/id_rsa.pub`), native `age` identity, or hardware token recipient.

When a team member rotates the master key via `git-agecrypt rekey`, collaborators re-synchronize transparently on `git pull` using their local SSH identity.

---

## Features

- **No GPG required:** Uses standard SSH keys (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`), native `age` keys, or hardware tokens via Age plugins. No GPG daemon, keyrings, or pinentry prompts.
- **Hardware token & Age plugin support:** Seamlessly enroll YubiKeys (`age-plugin-yubikey`), Apple Secure Enclave (`age-plugin-se`), and TPM tokens (`age-plugin-tpm`) via standard Age plugin recipients (`age1yubikey1...`, `age1se1...`).
- **Runtime secret injection:** Execute child commands with in-memory decrypted environment variables (`git-agecrypt run -- <cmd>`) without writing cleartext `.env` files to disk.
- **In-memory clean fast-path:** Small secrets and config files (< 1 MiB) are spooled and encrypted entirely in RAM with zero temporary disk file I/O. Memory buffers are cryptographically zeroized on drop.
- **Zero memory bloat on large files ($O(1)$ RAM):** Streams larger than 1 MiB automatically spill to disk, processing files in 64 KiB chunks; multi-gigabyte archives or database dumps never exhaust system memory.
- **Deterministic HMAC ciphertext cache:** Prevents phantom `git diff` churn caused by random encryption nonces, using keyed HMAC-SHA256 digests over plaintext payloads.
- **Semantic merge conflict detection:** 3-way merge driver detects conflicting duplicate key definitions on concurrent branch edits to `.env` and configuration files and emits actionable warnings.
- **GitHub user key enrollment:** Add team members directly by GitHub username (`git-agecrypt add-recipient --github <user>`).
- **Safe locked clones:** Cloning without a configured key succeeds cleanly (exit code 0). Files remain encrypted on disk until unlocked.
- **Transactional lock with WAL:** `git-agecrypt lock` re-smudges files on disk to encrypted ciphertext with write-ahead logging, guaranteeing recovery if interrupted.
- **Automated 3-way merge driver:** Decrypts conflicting branches, performs line-based 3-way merging, re-encrypts the result, and protects binary secrets from corruption.
- **Worktree native:** A single unlock operates across all linked Git worktrees via `--git-common-dir`.
- **Safeguard hooks:** Pre-commit and pre-push hooks inspect staged blobs in the Git index (`:0:<path>`) to block accidental cleartext leaks or commits encrypted under revoked keys.
- **Untracked secret leak scanner:** Pre-commit safeguard scans all staged files and aborts commits if untracked files matching secret heuristics (e.g. `.env`, private keys) are staged in plaintext.
- **AI and IDE shielding:** Synchronizes ignore rules across `.cursorignore`, `.claudeignore`, `.aiderignore`, and `.aiignore` so local LLM indexers never ingest unencrypted working-tree secrets.
- **Headless CI/CD friendly:** Unlocks from stdin (`echo "$KEY" | git-agecrypt unlock -`) with zero daemon processes.
- **Standalone binary:** Pure Rust with zero external dynamic library dependencies (no OpenSSL DLLs).

---

## How It Compares

| Aspect | `git-agecrypt` | `git-crypt` | Mozilla `sops` |
|---|---|---|---|
| **Working Tree State** | Transparent cleartext or ephemeral runtime injection (`git-agecrypt run`) | Transparent cleartext on disk | Encrypted on disk (manual CLI edit) |
| **Cryptography** | `age` (X25519, ChaCha20-Poly1305) | GPG (OpenPGP) / AES-CTR | Age, PGP, AWS KMS, GCP KMS, Vault |
| **Identity Mechanism** | SSH keys (`id_ed25519`), Age keys, or Age plugins (YubiKey, Apple SE, TPM) | GPG keyring / Symmetric key | Cloud KMS or GPG/Age |
| **Nonce Handling** | Keyed HMAC cache (zero phantom diffs) | Deterministic IV (from SHA-1 HMAC) | N/A (whole file encryption) |
| **Locked Clone Behavior** | Passes ciphertext through (exit 0) | Fails checkout (exit 128) | N/A |
| **Binary Dependencies** | Pure Rust static binary (~4.8 MB) | C++ linking OpenSSL | Go binary |
| **3-Way Merge Driver** | Built-in (with semantic conflict warnings) | None (manual conflict resolution) | None |

---

## Installation

### Pre-Compiled Binaries

Download pre-compiled standalone binaries from the [GitHub Releases](https://github.com/Crynspier/git-agecrypt/releases) page:

- **Linux:** `git-agecrypt-linux-x86_64.tar.gz` (x86_64)
- **macOS:** `git-agecrypt-macos-aarch64.tar.gz` (Apple Silicon M-series), `git-agecrypt-macos-x86_64.tar.gz` (Intel)
- **Windows:** `git-agecrypt-windows-x86_64.zip` (`git-agecrypt.exe`)

Extract the binary and place it in your system `PATH` (e.g. `/usr/local/bin` on Unix, or `C:\Program Files\Git\usr\bin` on Windows).

### Building From Source

Requires Rust 1.85 or later (Rust 2024 edition):

```bash
git clone https://github.com/Crynspier/git-agecrypt.git
cd git-agecrypt
cargo install --path .
```

Or build a release binary directly:

```bash
cargo build --release
# Binary is located at target/release/git-agecrypt (or target/release/git-agecrypt.exe)
```

Verify installation:

```bash
git-agecrypt --version
```

---

## Quickstart

### 1. Initialize a Repository

Inside any Git repository:

```bash
cd my-project
git-agecrypt init
```

This:
- Generates a new 256-bit symmetric repository master key.
- Enrolls your local SSH key (`~/.ssh/id_ed25519.pub` or `~/.ssh/id_rsa.pub`).
- Configures Git filter and diff drivers in `.git/config`.
- Installs non-destructive safeguard hooks (`pre-commit`, `pre-merge-commit`, `pre-push`).

### 2. Configure Files to Encrypt

Specify files in `.gitattributes`. Always include `-text` to prevent Git from converting CRLF/LF line endings on encrypted payloads:

```gitattributes
# Secrets and environment configs
*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text
.env.production filter=agecrypt diff=agecrypt merge=agecrypt -text
secrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text
```

Commit the configuration:

```bash
git add .gitattributes .git-agecrypt/
git commit -m "Initialize git-agecrypt configuration"
```

### 3. Add Collaborators

Enroll teammates using their public key file, public key string, or GitHub username:

```bash
# From an SSH public key file
git-agecrypt add-recipient -i ~/.ssh/id_ed25519.pub --name alice

# Directly from GitHub
git-agecrypt add-recipient --github octocat --name octocat

# From a key string
git-agecrypt add-recipient -i "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." --name bob

# Hardware token recipient via Age plugin (e.g. YubiKey or Apple Secure Enclave)
git-agecrypt add-recipient -i "age1yubikey1..." --name yubikey-alice

# List enrolled recipients
git-agecrypt list-recipients
```

Commit the new recipient wrappers:

```bash
git add .git-agecrypt/keys/
git commit -m "Add Alice and Bob to repository recipients"
git push
```

### 4. Daily Workflow

No special commands are needed for daily development:

```bash
# Edit your secret file normally
echo "DATABASE_URL=postgres://app:secret@localhost/db" > secrets/app.secret.env

# git add transparently runs the clean filter (encrypts to age container)
git add secrets/app.secret.env

# Commit and push normally
git commit -m "Update database connection string"
git push
```

To view cleartext diffs:

```bash
git diff secrets/app.secret.env
```

To verify the staged blob is encrypted:

```bash
git cat-file -p HEAD:secrets/app.secret.env
```

### 5. Locking and Unlocking

**Unlock a fresh clone:**

```bash
# Auto-detects ~/.ssh/id_ed25519 and ~/.ssh/id_rsa
git-agecrypt unlock

# Or provide a specific key path
git-agecrypt unlock ~/.ssh/custom_key

# Or supply key from stdin (for CI/CD)
echo "$DEPLOY_KEY" | git-agecrypt unlock -
```

**Lock the working tree (re-encrypt files on disk):**

```bash
git-agecrypt lock
```

Files on disk are replaced with their encrypted `.age` ciphertexts, and cached credentials in `.git/` are cleared.

### 6. Ephemeral Runtime Secret Injection (`run`)

To execute applications or tests without keeping unencrypted secrets on disk, use `git-agecrypt run`:

```bash
# Decrypt repository .env in memory and inject into child process environment
git-agecrypt run -- cargo run

# Run a server or script with specific encrypted env file
git-agecrypt run -e production.secret.env -- node server.js

# Run automated tests with injected environment secrets
git-agecrypt run -- npm test
```

Secrets are decrypted entirely in RAM, injected into the child process environment, and immediately zeroized upon exit without creating temporary cleartext files on disk.

### 7. Offboarding and Key Rotation

When a collaborator leaves:

```bash
# 1. Remove the recipient key
git-agecrypt remove-recipient bob

# 2. Rotate the master key and re-encrypt all working tree secrets
git-agecrypt rekey

# 3. Commit the rotated configuration
git add .git-agecrypt
git commit -m "Rotate master key and remove bob"
git push
```

The offboarded developer cannot decrypt any subsequent commits.

### 8. Resolving Historical Branches (`rewrap`)

When cherry-picking or merging an older commit created under a previous master key:

```bash
# Rewrap a specific file under the current active key
git-agecrypt rewrap secrets/app.secret.env

# Or rewrap all tracked historical secrets
git-agecrypt rewrap --all
```

---

## CI / CD Integration

`git-agecrypt` runs headlessly without background daemons:

### GitHub Actions

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Option A: Download standalone pre-compiled release binary
      - name: Install git-agecrypt
        run: |
          curl -sSL https://github.com/Crynspier/git-agecrypt/releases/latest/download/git-agecrypt-linux-x86_64.tar.gz | tar -xz
          sudo mv git-agecrypt /usr/local/bin/

      # Option B (if Rust toolchain is already installed):
      # - run: cargo install --git https://github.com/Crynspier/git-agecrypt.git

      - name: Unlock Secrets
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
        run: echo "$DEPLOY_KEY" | git-agecrypt unlock -

      - name: Run Tests
        run: cargo test
```

---

## Migration from `git-crypt`

To migrate a repository currently using `git-crypt`:

```bash
# 1. Ensure the repository is unlocked with git-crypt
git-crypt unlock

# 2. Run automated migration
git-agecrypt migrate-from-git-crypt -i ~/.ssh/id_ed25519.pub

# 3. Review and commit changes
git add .gitattributes .git-agecrypt/
git commit -m "Migrate from git-crypt to git-agecrypt"
```

---

## CLI Reference

| Command | Options | Description |
|---|---|---|
| `init` | `[--gitattributes], [--ai-shield]` | Initialize master key, enroll current SSH key, configure Git filters, and install hooks. |
| `add-recipient` | `-i, --identity <KEY>`, `--github <USER>`, `-n, --name <NAME>` | Enroll a new recipient public key. |
| `remove-recipient` | `<NAME>` | Remove an enrolled recipient. |
| `list-recipients` | *(none)* | Display all enrolled recipients in alphabetical order. |
| `unlock` | `[KEY_FILE]`, `-f, --force` | Decrypt master key and smudge secret files on disk. |
| `lock` | `-f, --force` | Re-smudge disk files to ciphertext and remove cached master key. |
| `rekey` | `-f, --force` | Rotate the master key and re-encrypt all tracked secret files. |
| `rewrap` | `[PATH]...`, `-a, --all`, `-i, --identity <KEY>`, `-f, --force` | Re-encrypt historical ciphertexts under the active master key. |
| `status` | *(none)* | Display repository status, active key fingerprint, and tracked files. |
| `shield` | `[--check]` | Synchronize AI agent and IDE ignore files (`.cursorignore`, `.claudeignore`, `.aiderignore`, `.aiignore`). |
| `install-hooks` | *(none)* | Install or update safeguard hooks (`pre-commit`, `pre-merge-commit`, `pre-push`). |
| `check` | `[--pre-push], [--allow-untracked-secrets]` | Validate staged files or outgoing commits against unencrypted or untracked secret leaks. |
| `clean` | `[PATH]` | Git clean filter (streams stdin plaintext to stdout ciphertext). |
| `smudge` | `[PATH]` | Git smudge filter (streams stdin ciphertext to stdout plaintext). |
| `textconv` | `<PATH>` | Git diff driver (decrypts target for cleartext diffs). |
| `merge` | `<O> <A> <B> [L] [P]` | Git 3-way merge driver. |
| `run` | `[-e, --env-file <PATH>] -- <COMMAND>...` | Execute child process with in-memory decrypted secrets injected into environment variables. |
| `migrate-from-git-crypt` | `-i, --identity <KEY>` | Convert an existing git-crypt repository. |

---

## Documentation & Deep Dives

Comprehensive specifications and architecture guides are available in the [`docs/`](docs/) directory:

- **[Security Model & Threat Analysis](docs/security-model.md):**
  Detailed threat model, cryptographic primitives (ChaCha20-Poly1305, X25519, HMAC caching), POSIX permissions (`0o700`/`0o600`), crash durability (`sync_all`), Merkle DAG forward-secrecy vs historical revocation, runtime secret injection boundaries, and enterprise server-side `pre-receive` hook enforcement.

- **[Internal Architecture & Driver Mechanics](docs/internals.md):**
  In-depth breakdown of the Git filter lifecycle (`clean`, `smudge`, `textconv`, `merge`), two-tier spooling architecture (RAM < 1 MiB with `zeroize`, disk >= 1 MiB inside `.git/git-agecrypt/spool/`), stage-0 index deduplication, cache validation, and the 3-way semantic merge driver conflict algorithms.

---

## Minimum Supported Versions

- **Rust:** 1.85.0+ (Rust 2024 edition)
- **Git:** 2.25.0+ (recommended for `--pathspec-from-file` and `-z` null-delimited plumbing)

---

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
