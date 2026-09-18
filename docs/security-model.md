# Security Model and Threat Analysis

`git-agecrypt` provides transparent, client-side, authenticated encryption for secret files stored within Git repositories. This document outlines the formal threat model, cryptographic design, operating system boundaries, and architectural invariants implemented by `git-agecrypt`.

---

## 1. Threat Model & Trust Boundaries

### 1.1 What `git-agecrypt` Defends Against

- **Untrusted Remote Hosting:** Remote Git hosts (GitHub, GitLab, Bitbucket, cloud infrastructure, or bare Git servers) only receive authenticated `age` ciphertexts. Compromise or subpoena of the remote Git host exposes zero plaintext secrets.
- **Passive and Active Network Interception:** Repository pushes, pulls, and clones transfer ciphertext payloads. Man-in-the-middle (MITM) adversaries cannot decrypt or inject forged secrets due to ChaCha20-Poly1305 AEAD authentication.
- **Unauthorized Clones and Forking:** Public or unintended access to repository clones leaves secret files in their encrypted state. Without an enrolled private key, files cannot be decrypted.
- **Local AI Agent and IDE Indexer Leakage:** Local coding assistants and IDE indexing processes scan the working directory. Through `git-agecrypt shield`, ignore patterns are synchronized into `.cursorignore`, `.claudeignore`, `.aiderignore`, and `.aiignore`, preventing local language models from ingesting transparently decrypted secrets into context windows.
- **Accidental Cleartext Staging:** The built-in safeguard hook suite (`pre-commit`, `pre-merge-commit`, `pre-push`) and `git-agecrypt check` inspect index blobs (`:0:<path>`) prior to commit or push, preventing unencrypted secrets or untracked sensitive files (e.g. unmatched `.env`, private keys) from escaping into the Git object database.
- **Ciphertext Header Tampering & Interactive Staging Corruption:** Running interactive patch staging (`git add -p`) on encrypted files or tampering with ciphertext chunks is detected by `git-agecrypt check`, blocking commits that contain corrupted `age` payloads.

### 1.2 What `git-agecrypt` Does NOT Defend Against

- **Compromised Developer Endpoints:** An adversary with root or user-level execution on a developer's unlocked machine can access working-tree cleartext, inspect process memory, or read local SSH private keys.
- **Git Metadata and Traffic Analysis:** Git commit metadata (commit messages, authors, timestamps, file names, directory hierarchies, and commit DAG structure) is not encrypted. Secret file sizes are observable to within `age`'s 64 KiB chunk boundary.
- **Malicious Collaborators During Active Tenure:** Any team member with an enrolled recipient key possesses mathematical access to the repository master key and can decrypt secrets tracked under that key.
- **Bypassing Local Hooks (`--no-verify`):** Client-side Git hooks execute locally. A developer executing `git commit --no-verify` on a machine without `git-agecrypt` configured can commit unencrypted files unless server-side enforcement is active.

---

## 2. Cryptographic Architecture

### 2.1 Cryptographic Primitives

- **Payload Encryption:** ChaCha20-Poly1305 AEAD (RFC 8439) with 64 KiB streaming chunking as defined in the [age specification](https://age-encryption.org/v1).
- **Key Exchange:** X25519 ECDH (RFC 7748) and Ed25519-to-X25519 point conversion (RFC 8032) for native SSH keys.
- **Hardware Tokens & Age Plugins:** Direct support for hardware security keys via Age plugins (`age-plugin-yubikey`, `age-plugin-se`, `age-plugin-tpm`).
- **Key Derivation & Deterministic Caching:** HMAC-SHA256 (RFC 2104) keyed with the 256-bit repository master key to compute deduplication cache keys.

### 2.2 Two-Tier Key Envelope Architecture

`git-agecrypt` separates secret data encryption from recipient identity management:

1. **Repository Master Key:** A 256-bit symmetric cryptographic key generated at repository initialization (`git-agecrypt init`). All file payloads in the repository are encrypted directly with this key.
2. **Recipient Envelopes:** The master key is wrapped individually for each authorized team member into `.git-agecrypt/keys/<recipient>.age`. Each envelope is encrypted against the recipient's public key (SSH public key, native `age` identity, or hardware token).

This separation ensures that adding or removing recipients does not require re-encrypting the entire repository's files.

### 2.3 Keyed Deterministic HMAC Caching

Standard `age` encryption generates fresh random nonces for every payload, which would produce non-deterministic ciphertexts on every `git add`, causing phantom `git diff` churn.

To solve this securely:
- `git-agecrypt` computes a cache key using `HMAC-SHA256(master_key, plaintext)`.
- Because the HMAC uses the secret master key as its cryptographic key, an external attacker cannot precompute rainbow tables or dictionary attacks against secret payloads.
- If a matching ciphertext exists in `.git/git-agecrypt/cache/`, `git-agecrypt` verifies that the cached file has a valid `age` header structure. If valid, it reuses the ciphertext. If invalid or corrupted, the entry is unlinked and a clean re-encryption is performed.

---

## 3. Git Invariants and Plumbing Integrity

### 3.1 The Working-Tree vs Object Database Invariant

`git-agecrypt` strictly enforces the core invariant:
$$\text{Working tree} = \text{Plaintext} \iff \text{Git index / Object database} = \text{Ciphertext}$$

- **Clean Filter:** Transforms plaintext standard input into `age-encryption.org/v1` authenticated ciphertext standard output during staging (`git add`).
- **Smudge Filter:** Transforms `age` ciphertext standard input into plaintext standard output during checkout (`git checkout`, `git switch`). If the repository is locked or keys are unavailable, the smudge filter passes the ciphertext through intact with exit code `0`, preventing Git checkout failures.
- **Git Index Stages (1, 2, 3):** During merge conflicts, unmerged stages in the index remain 100% encrypted ciphertext. Plaintext is never placed into index stages.
- **Textconv Driver:** Decrypts ciphertext on the fly for read-only tools (`git diff`, `git log -p`) without modifying files on disk.

### 3.2 Corrupted Staged Ciphertext Detection

Git's interactive patch mode (`git add -p`) splits diffs into hunks and attempts to apply them to the index. Because `age` headers begin with human-readable ASCII lines followed by binary payload blocks, partial staging can create corrupted `age` containers.

`git-agecrypt check` inspects the header of every staged secret file in index stage 0. If a staged file contains a corrupted or invalid `age` header, the commit is strictly aborted with actionable instructions.

---

## 4. Filesystem Security, Permissions, and Durability

### 4.1 Strict POSIX Permissions

On Unix systems, `git-agecrypt` enforces strict POSIX file permissions on all local state directories and sensitive files:
- State directories (`.git/git-agecrypt/`, `.git/git-agecrypt/cache/`, `.git/git-agecrypt/spool/`): `0o700` (`rwx------`)
- Master key files and journals: `0o600` (`rw-------`)

This prevents unauthorized access from other local users sharing the same machine.

### 4.2 Colocated Spool Directory

When processing streams larger than 1 MiB, temporary spill files are stored within `.git/git-agecrypt/spool/` rather than the system-wide `/tmp` directory. This ensures:
- Spill data remains on the same filesystem and partition as the Git repository, enabling atomic rename operations.
- Spill files inherit repository directory access permissions and avoid shared multi-tenant temporary locations.

### 4.3 Crash Durability & Physical Disk Synchronization

To prevent data loss or corrupted key files from sudden system reboots or power loss:
- Key files, journals, and cache files are written to atomic temporary files (`NamedTempFile`).
- Before atomically persisting the file into its destination, `git-agecrypt` executes `sync_all()` (`fsync`), ensuring data and metadata are physically written to durable storage before the directory entry is updated.

### 4.4 Transactional Locking with Write-Ahead Logging (WAL)

The `git-agecrypt lock` command re-smudges cleartext files on disk back into ciphertext. To prevent partial state if interrupted:
- A write-ahead journal (`.git/git-agecrypt/lock.journal`) is written and flushed prior to modifying disk files.
- If an operation is interrupted, the journal guarantees deterministic recovery on the next command execution.

---

## 5. Merkle DAG Immutability & Key Rotation

### 5.1 Historical Revocation vs Forward Secrecy

Git repositories are Merkle DAGs; all commit objects are immutable and content-addressed.

When an employee is offboarded:
1. Their recipient envelope is removed: `git-agecrypt remove-recipient <name>`
2. The repository master key is rotated: `git-agecrypt rekey`

**Important Security Reality:**
- `git-agecrypt rekey` rotates the master key and re-encrypts all current working tree files forward.
- It intentionally does **not** rewrite historical Git commits.
- A former collaborator who possessed the previous master key retains the ability to decrypt historical commits created during their tenure (from local clones or repository backups).
- If historical secrets must be invalidated, change the secrets at the source (e.g. rotate API keys, database credentials, or certificates).

### 5.2 Historical Branch Integration (`rewrap`)

When cherry-picking, rebasing, or merging historical branches encrypted under older master keys, `git-agecrypt rewrap` allows decrypting the legacy ciphertext using the historical key and re-encrypting under the active master key, preserving Git workflow flexibility.

---

## 6. Runtime Secret Injection (`git-agecrypt run`)

The `git-agecrypt run` command decrypts secret environment files in memory and injects them directly into child process environment variables without writing cleartext files to disk.

### 6.1 Process Memory & `/proc` Boundaries

When executing commands using `run`, consider the operating system process boundary:
- **Process Memory & `/proc` Inspection:** On Linux systems, any process running under the same user ID (UID) or possessing `PTRACE_MODE_READ` capability can inspect `/proc/<pid>/environ`. Run untrusted or multi-tenant processes under isolated service accounts.
- **Child Process Inheritance:** Environment variables are inherited by child processes spawned by the target command. Ensure build tools, test runners, or scripts do not echo environment variables to CI logs.
- **Core Dumps:** Prevent memory-mapped secrets from being written to disk on unexpected crashes by setting `ulimit -c 0` or disabling kernel core dumps (`fs.suid_dumpable = 0`).
- **Cryptographic Memory Zeroization:** All in-memory buffers holding decrypted plaintext are zeroized using the `zeroize` crate immediately when dropped.

---

## 7. Server-Side Enforcement (Enterprise Gateway)

To eliminate reliance on client-side hooks across distributed teams, deploy a server-side `pre-receive` hook on your central Git server (GitHub Enterprise, GitLab, Gitea, or bare Git). The hook verifies that every file with `filter=agecrypt` is committed as valid `age` ciphertext:

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
