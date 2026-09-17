# git-agecrypt

Transparent client-side Git encryption using [age](https://age-encryption.org/v1) and SSH keys.

[![CI](https://github.com/Crynspier/git-agecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Crynspier/git-agecrypt/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust 1.74+](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)

---

`git-agecrypt` provides transparent file encryption and decryption for Git repositories using Git's native filter drivers (`clean`, `smudge`, `diff`, and `merge`).

Files remain unencrypted cleartext in your local working directory so your editor, linters, and compiler can access them normally. When files are committed or pushed to a remote repository, they are automatically encrypted into authenticated `age` ciphertexts. Collaborators without an enrolled private key see only encrypted data.

It is designed as a modern replacement for `git-crypt`, substituting GPG and OpenSSL dependencies with the `age` format (X25519, ChaCha20-Poly1305) and standard SSH Ed25519 or RSA keys.

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
- [Security Model & Caveats](#security-model)
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
2. **Recipient Envelopes (`.git-agecrypt/keys/<name>.age`):** The master key is encrypted individually for each authorized team member using their SSH public key (`~/.ssh/id_ed25519.pub`, `~/.ssh/id_rsa.pub`) or native `age` identity.

When a team member rotates the master key via `git-agecrypt rekey`, collaborators re-synchronize transparently on `git pull` using their local SSH identity.

---

## Features

- **No GPG required:** Uses standard SSH keys (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`) or native `age` keys. No GPG daemon, keyrings, or pinentry prompts.
- **GitHub user key enrollment:** Add team members directly by GitHub username (`git-agecrypt add-recipient --github <user>`).
- **Deterministic HMAC ciphertext cache:** Prevents phantom `git diff` churn caused by random encryption nonces, using keyed HMAC-SHA256 digests over plaintext payloads.
- **Zero memory bloat ($O(1)$ RAM):** Streaming architecture processes files in 64 KiB chunks; large archives and database dumps never buffer entirely in memory.
- **Safe locked clones:** Cloning without a configured key succeeds cleanly (exit code 0). Files remain encrypted on disk until unlocked.
- **Transactional lock with WAL:** `git-agecrypt lock` re-smudges files on disk to encrypted ciphertext with write-ahead logging, guaranteeing recovery if interrupted.
- **Automated 3-way merge driver:** Decrypts conflicting branches, performs line-based 3-way merging, re-encrypts the result, and protects binary secrets from corruption.
- **Worktree native:** A single unlock operates across all linked Git worktrees via `--git-common-dir`.
- **Safeguard hooks:** Pre-commit and pre-push hooks inspect staged blobs in the Git index (`:0:<path>`) to block accidental cleartext leaks or commits encrypted under revoked keys.
- **Headless CI/CD friendly:** Unlocks from stdin (`echo "$KEY" | git-agecrypt unlock -`) with zero daemon processes.
- **Standalone binary:** Pure Rust with zero external dynamic library dependencies (no OpenSSL DLLs).

---

## How It Compares

| Aspect | `git-agecrypt` | `git-crypt` | Mozilla `sops` |
|---|---|---|---|
| **Working Tree State** | Transparent cleartext on disk | Transparent cleartext on disk | Encrypted on disk (manual CLI edit) |
| **Cryptography** | `age` (X25519, ChaCha20-Poly1305) | GPG (OpenPGP) / AES-CTR | Age, PGP, AWS KMS, GCP KMS, Vault |
| **Identity Mechanism** | SSH keys (`id_ed25519`) or Age | GPG keyring / Symmetric key | Cloud KMS or GPG/Age |
| **Nonce Handling** | Keyed HMAC cache (zero phantom diffs) | Deterministic IV (from SHA-1 HMAC) | N/A (whole file encryption) |
| **Locked Clone Behavior** | Passes ciphertext through (exit 0) | Fails checkout (exit 128) | N/A |
| **Binary Dependencies** | Pure Rust static binary (~4.5 MB) | C++ linking OpenSSL | Go binary |
| **3-Way Merge Driver** | Built-in | None (manual conflict resolution) | None |

---

## Installation

### Pre-Compiled Binaries

Download pre-compiled standalone binaries from the [GitHub Releases](https://github.com/Crynspier/git-agecrypt/releases) page:

- **Linux:** `git-agecrypt-linux-x86_64.tar.gz` (x86_64)
- **macOS:** `git-agecrypt-macos-aarch64.tar.gz` (Apple Silicon M-series), `git-agecrypt-macos-x86_64.tar.gz` (Intel)
- **Windows:** `git-agecrypt-windows-x86_64.zip` (`git-agecrypt.exe`)

Extract the binary and place it in your system `PATH` (e.g. `/usr/local/bin` on Unix, or `C:\Program Files\Git\usr\bin` on Windows).

### Building From Source

Requires Rust 1.74 or later:

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

### 6. Offboarding and Key Rotation

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

### 7. Resolving Historical Branches (`rewrap`)

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
| `init` | `[--gitattributes]` | Initialize master key, enroll current SSH key, configure Git filters, and install hooks. |
| `add-recipient` | `-i, --identity <KEY>`, `--github <USER>`, `-n, --name <NAME>` | Enroll a new recipient public key. |
| `remove-recipient` | `<NAME>` | Remove an enrolled recipient. |
| `list-recipients` | *(none)* | Display all enrolled recipients in alphabetical order. |
| `unlock` | `[KEY_FILE]`, `-f, --force` | Decrypt master key and smudge secret files on disk. |
| `lock` | `-f, --force` | Re-smudge disk files to ciphertext and remove cached master key. |
| `rekey` | `-f, --force` | Rotate the master key and re-encrypt all tracked secret files. |
| `rewrap` | `[PATH]...`, `-a, --all`, `-i, --identity <KEY>`, `-f, --force` | Re-encrypt historical ciphertexts under the active master key. |
| `status` | *(none)* | Display repository status, active key fingerprint, and tracked files. |
| `install-hooks` | *(none)* | Install or update safeguard hooks (`pre-commit`, `pre-merge-commit`, `pre-push`). |
| `check` | `[--pre-push]` | Validate staged files or outgoing commits against unencrypted leaks. |
| `clean` | `[PATH]` | Git clean filter (streams stdin plaintext to stdout ciphertext). |
| `smudge` | `[PATH]` | Git smudge filter (streams stdin ciphertext to stdout plaintext). |
| `textconv` | `<PATH>` | Git diff driver (decrypts target for cleartext diffs). |
| `merge` | `<O> <A> <B> [L] [P]` | Git 3-way merge driver. |
| `migrate-from-git-crypt` | `-i, --identity <KEY>` | Convert an existing git-crypt repository. |

---

## Security Model

### Cryptographic Foundation

- **Payload Encryption:** ChaCha20-Poly1305 AEAD (RFC 8439) in 64 KiB streaming chunks.
- **Key Exchange:** X25519 ECDH (RFC 7748) and Ed25519-to-X25519 point conversion (RFC 8032).
- **Deterministic Ciphertext Caching:** Cache lookup keys are derived using `HMAC-SHA256(master_key, plaintext)`. The cache key cannot be precomputed without the master key, protecting low-entropy secrets from dictionary or rainbow-table attacks.
- **Payload Authentication:** Any bit manipulation of ciphertext headers or chunks fails Poly1305 AEAD authentication immediately, preventing silent corruption.
- **Partial Hunk Staging:** `git add -p` is blocked by safeguard hooks because Git's interactive hunk applier bypasses clean filter drivers.

### Caveats & Inherited Risks

Like all repository-level transparent encryption systems (including `git-crypt`), `git-agecrypt` operates within Git's architecture and carries specific inherited trade-offs:

1. **Git Metadata is Unencrypted:**
   Git stores commit logs, authors, timestamps, filenames, and directory trees in the clear. An unauthorized party with read access to the remote repository can see which secret files exist, when they were modified, and their approximate file size (within Age's 64 KiB chunk boundary). For strict regulatory environments where file paths or metadata must remain confidential, dedicated secret managers (such as HashiCorp Vault or AWS Secrets Manager) or envelope tools like Mozilla `sops` are recommended.

2. **Client-Side Filter Reliance:**
   Transparent Git filters execute on developers' local machines. If a developer runs `git commit --no-verify`, client-side pre-commit hooks are bypassed. If a developer clones a repository on a machine lacking `git-agecrypt` and stages a secret file, unencrypted files could theoretically be committed.

### Server-Side Enforcement (Enterprise Guard)

To eliminate client-side filter reliance across team environments, configure a server-side `pre-receive` hook (or repository push rule) on your Git host (GitHub Enterprise, GitLab, Gitea, or bare Git servers). This guarantees that any push containing an unencrypted secret is rejected by the server, regardless of client configuration:

```bash
#!/usr/bin/env bash
# Server-side pre-receive hook: rejects pushes containing unencrypted secrets
set -euo pipefail

while read -r oldrev newrev refname; do
    if [ "$newrev" = "0000000000000000000000000000000000000000" ]; then
        continue # Branch deletion
    fi

    revs=$([ "$oldrev" = "0000000000000000000000000000000000000000" ] && echo "$newrev" || echo "$oldrev..$newrev")

    for commit in $(git rev-list "$revs"); do
        for path in $(git diff-tree -r --name-only --no-commit-id "$commit"); do
            if git check-attr filter -- "$path" | grep -q 'filter: agecrypt'; then
                header=$(git cat-file -p "$commit:$path" | head -n 1 || true)
                if [[ ! "$header" =~ ^age-encryption\.org/v1 ]]; then
                    echo "===============================================================" >&2
                    echo "PUSH REJECTED BY SERVER PRE-RECEIVE HOOK" >&2
                    echo "Commit $commit contains UNENCRYPTED secret: $path" >&2
                    echo "Please configure git-agecrypt locally and re-commit." >&2
                    echo "===============================================================" >&2
                    exit 1
                fi
            fi
        done
    done
done
```

---

## Minimum Supported Versions

- **Rust:** 1.74.0+
- **Git:** 2.25.0+ (recommended for `--pathspec-from-file` and `-z` null-delimited plumbing)

---

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
