# `git-agecrypt` Format Specification (Version 1)

**Status:** Normative Specification (Format Version `1`)

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Format Version Numbers and Compatibility Rules

### 1.1 Format Version Identifier
- The current repository and local-state format version is integer **`1`** (`FORMAT_VERSION = 1`).
- A repository MAY explicitly declare its format version in `.git-agecrypt/format` (and per-ring in `.git-agecrypt/rings/<ring>/format`) or via a `# format-version: 1` header comment in `repo.pub`, `.git-agecrypt/keys/*.age`, or `.git/git-agecrypt/lock.journal`.
- If `.git-agecrypt/format` is absent, a compliant reader MUST treat the repository as **implicit Format Version `1`** for backward compatibility with repositories initialized before explicit format markers were introduced.

### 1.2 Explicit Format Marker File Syntax (`.git-agecrypt/format`)
- When present, `.git-agecrypt/format` (and `.git-agecrypt/rings/<ring>/format` or `.git/git-agecrypt/format`) MUST be a UTF-8 text file containing either:
  - A single unsigned integer line: `1`
  - Or a key-value directive line: `format-version: 1`
- Blank lines and lines beginning with `#` (after trimming leading whitespace) MUST be ignored as comments.
- Multiple version directives in the same file, non-integer version strings (e.g., `v2`, `invalid`), or empty format files without a version directive MUST be rejected as malformed.

### 1.3 Forward/Backward Compatibility and Fail-Closed Policy
- **Fail-Closed on Unknown Versions:** Any reader or writer encountering a format version `!= 1` in `.git-agecrypt/format`, `.git-agecrypt/rings/<ring>/format`, `.git/git-agecrypt/format`, `repo.pub`, `keys/*.age`, or `lock.journal` MUST abort the operation immediately with a descriptive error diagnostic. Implementations MUST NOT silently ignore unknown versions or overwrite higher-version metadata.
- **Symlink & Reparse Point Prohibition:** No file or directory inside `.git-agecrypt/` or `.git/git-agecrypt/` MAY be a symbolic link, NTFS junction, or Win32 reparse point. Implementations MUST verify `symlink_metadata` / `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT` and fail closed on any symlink or reparse point.

---

## 2. Committed Repository Metadata Structure (`.git-agecrypt/`)

Committed cryptographic metadata resides at the root of the Git working tree under `.git-agecrypt/`:

```text
.git-agecrypt/
├── format                        # OPTIONAL explicit format version marker ("1\n")
├── repo.pub                      # Default ring public X25519 master key ("age1...\n")
├── keys/
│   └── <recipient_name>.age      # Default ring wrapped master key envelopes
└── rings/                        # OPTIONAL multi-ring isolation directory
    └── <ring_name>/
        ├── format                # OPTIONAL ring format version marker ("1\n")
        ├── repo.pub              # Ring-specific public X25519 master key
        └── keys/
            └── <recipient_name>.age
```

- Implementations inspecting `.git-agecrypt/` via `git-agecrypt inspect` MUST flag any unrecognized top-level files or directories outside `{format, repo.pub, keys, rings}` as unsupported metadata entries.

---

## 3. Master Public Key Format (`repo.pub`)

- Path: `.git-agecrypt/repo.pub` (default ring) or `.git-agecrypt/rings/<ring>/repo.pub` (scoped ring).
- Encoding: UTF-8 text with LF (`\n`) or CRLF (`\r\n`) line endings.
- Grammar:
  1. Zero or more optional comment lines starting with `#` (including `# format-version: 1`).
  2. Exactly one Bech32-encoded `age` X25519 public key line matching `age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}` (as defined by the [age specification v1](https://age-encryption.org/v1)).
- Validation requirements:
  - A file with zero recipient lines, more than one recipient line, or a non-X25519 recipient (such as an `ssh-ed25519` key placed directly in `repo.pub`) MUST be rejected.

---

## 4. Wrapped Master Key Envelopes (`.git-agecrypt/keys/<name>.age`)

Each enrolled collaborator or CI identity receives an individual wrapped copy of the ring's symmetric/master identity (`AGE-SECRET-KEY-1...`) under `.git-agecrypt/keys/<name>.age` (or `.git-agecrypt/rings/<ring>/keys/<name>.age`).

### 4.1 Recipient Filename Grammar
- `<name>` MUST be a plain filename without path separators (`/`, `\`), parent traversal segments (`.` or `..`), or ASCII control characters (`0x00..=0x1F`, `0x7F`).
- Enrolled labels are normalized to lowercase ASCII `[a-z0-9_.-]` with `.age` extension.
- If a new recipient's normalized filename collides case-insensitively with an existing `.age` file that wraps for a different public key, `add-recipient` appends a 4-byte (8-hex-char) SHA-256 suffix (`<label>_<sha256_prefix8>.age`) to prevent clobbering on case-insensitive filesystems (Windows NTFS, macOS APFS).

### 4.2 Envelope Structure and Header Metadata
A valid `.age` recipient envelope is an UTF-8 text file consisting of:
1. **Header comment block** (before `-----BEGIN AGE ENCRYPTED FILE-----`):
   - **REQUIRED:** `# public-key: <recipient_string>` where `<recipient_string>` is a valid `age1...`, `ssh-ed25519 ...`, or `ssh-rsa ...` public key string. This header enables non-interactive `git-agecrypt rekey` to re-wrap a newly rotated master key for all active recipients without requiring their private keys.
   - **OPTIONAL:** `# format-version: 1`.
   - Any unknown `# <field>: <value>` header directive MUST be flagged as unsupported by strict validators.
2. **ASCII-Armored `age` v1 Ciphertext Block:**
   - Begins with `-----BEGIN AGE ENCRYPTED FILE-----` and ends with `-----END AGE ENCRYPTED FILE-----` (PEM-style base64 armor per the `age` v1 specification).
   - The decrypted payload of this `age` ciphertext MUST be the trimmed ASCII Bech32 string of the ring's master secret key (`AGE-SECRET-KEY-1...`).

```text
# public-key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...
-----END AGE ENCRYPTED FILE-----
```

---

## 5. Multi-Ring Layout and Naming Grammar

Scoped encryption rings isolate cryptographic domains within a single Git repository so that a recipient unlocked for ring `dev` cannot decrypt secrets governed by ring `prod`.

### 5.1 Ring Naming Rules (`validate_ring_name`)
Every named ring `<ring>` MUST satisfy all of the following invariants:
1. **Length:** `1 <= len <= 64` bytes.
2. **Character Set:** First character MUST be ASCII alphanumeric (`[a-zA-Z0-9]`). Subsequent characters MUST be in `[a-zA-Z0-9_.-]`.
3. **Reserved Identifiers:** MUST NOT equal `"default"`, `"."`, or `".."`.
4. **Windows Device Names:** Case-insensitively (ignoring extensions after `.`), MUST NOT match any reserved Win32 device name: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`.
5. **Case-Collision Prohibition:** A repository MUST NOT contain two rings whose names differ only in ASCII letter case (e.g., `Prod` and `prod`).

---

## 6. `.gitattributes` Filter, Diff, and Merge Mapping

Tracked secrets are designated via standard Git attributes in `.gitattributes`:

- **Default Ring:**
  ```gitattributes
  secrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text
  *.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text
  ```
- **Named Ring (`<ring>`):**
  ```gitattributes
  secrets/prod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text
  ```
- **Binary Safety (`-text`):** Rules SHOULD include `-text` (or `binary`) so Git never applies CRLF line-ending translation to binary `age` ciphertexts.
- **No Filter Chaining:** A pattern MUST NOT combine `filter=agecrypt*` with `filter=lfs` or another Git filter driver.
- **Shell-Safe Tracked Paths:** Because Git expands `%f`, `%O`, `%A`, `%B`, and `%P` in filter/merge driver commands via `sh -c` without shell escaping, any repository-relative secret path containing `"`, `` ` ``, `$`, `\`, or ASCII control characters (`0x00..=0x1F`, `0x7F`) MUST be rejected at commit and pre-receive time.

---

## 7. Local Untracked State Layout (`.git/git-agecrypt/`)

All local machine state resides inside the repository's shared Git common directory (`git rev-parse --git-common-dir`, typically `.git/git-agecrypt/`), shared across all linked Git worktrees:

```text
<git-common-dir>/git-agecrypt/
├── recovery.lock                 # OS-level exclusive coordination lock (flock / LockFileEx)
├── lock.journal                  # Write-Ahead Log (WAL) during transactional lock
├── refresh.lock                  # Short-lived advisory auto-refresh coordination file
├── repo.key                      # Unwrapped active master key for default ring (mode 0600 / user-only ACL)
├── repo.key.locking              # Staged master key during in-flight default-ring lock transaction
├── cache/
│   └── <sha256(repo.pub)[..16]>/
│       └── <hmac_sha256_hex>.age # Deterministic clean-filter convergence cache
├── spool/                        # Restricted temporary spool directory (mode 0700)
├── merge-spool/                  # Restricted temporary directory for 3-way plaintext merge inputs
└── rings/
    └── <ring_name>/
        ├── refresh.lock
        ├── repo.key
        ├── repo.key.locking
        └── cache/
            └── <sha256(ring_repo.pub)[..16]>/
                └── <hmac_sha256_hex>.age
```

---

## 8. `repo.key` and `repo.key.locking` Lifecycle

1. **Format:** `repo.key` contains the single-line Bech32 age secret key `AGE-SECRET-KEY-1...` corresponding to the ring's `repo.pub`.
2. **Permissions & Atomic Write (`save_local_master_key_for_ring`):**
   - Created in `<state_dir>/repo.key.tmp.<pid>.<nonce>` using `openat(..., O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)` on Unix or `FILE_FLAG_OPEN_REPARSE_POINT` + `icacls /inheritance:r /grant:r <USER>:(R,W)` on Windows *before* any key bytes are written.
   - Flushed and `sync_all()`'d to disk.
   - Atomically renamed onto `repo.key` (`rename(2)` on Unix; `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` on Windows) followed by parent directory `sync_dir`.
3. **Transactional Lock Lifecycle (`repo.key.locking`):**
   - During `git-agecrypt lock`, after `lock.journal` is written and synced, `repo.key` is atomically renamed to `repo.key.locking`.
   - While `repo.key` is absent, `git checkout-index -f -u` runs across all linked worktrees; the `smudge` filter sees no `repo.key` and writes raw `age` ciphertext to the working tree.
   - Once all worktrees succeed, `repo.key.locking` and `lock.journal` are unlinked and the directory is synced.

---

## 9. `lock.journal` Write-Ahead Log Syntax and Replay Rules

### 9.1 Syntax
- Path: `<git-common-dir>/git-agecrypt/lock.journal`.
- Encoding: UTF-8 text, LF-delimited lines.
- Optional first-line header: `# format-version: 1`.
- Each record line MUST consist of two non-empty fields separated by a single ASCII horizontal tab (`\t`, `0x09`) and contain no NUL (`\0`) bytes:
  ```text
  <worktree_root_path>\t<repo_relative_secret_path>
  ```

### 9.2 Crash Recovery & Replay Rules (`recover_interrupted_transaction`)
Startup recovery executes under the exclusive `recovery.lock` guard:
1. **`repo.key.locking` exists AND `repo.key` exists:**
   - The previous lock or unlock completed; `repo.key.locking` and `lock.journal` are stale markers and MUST be deleted.
2. **`repo.key.locking` exists AND `repo.key` does NOT exist:**
   - An in-flight `lock` transaction was interrupted (e.g., `SIGKILL`, power loss, `Ctrl+C`).
   - `repo.key.locking` MUST be renamed back to `repo.key` and synced.
   - If `lock.journal` exists, it is parsed and validated (`parse_and_validate_lock_journal`). Every listed `<worktree_root_path>\t<repo_relative_secret_path>` whose working-tree file is either a `0`-byte truncated file (with a non-empty staged blob) or raw `age` ciphertext is removed and re-checked out (`git checkout-index -f -u -- <rel_path>`) so the `smudge` filter restores plaintext. Uncommitted plaintext edits in the working tree are NEVER overwritten.
   - `lock.journal` is removed ONLY after every recorded entry has been successfully recovered.
3. **`repo.key.locking` does NOT exist AND `lock.journal` exists:**
   - First, `lock.journal` syntax is validated; if malformed, recovery MUST fail closed and retain the journal.
   - If `repo.key` exists (crash occurred after journal creation but before `repo.key -> repo.key.locking` rename), the uncommitted `lock.journal` is safely removed.
   - If `repo.key` does NOT exist, the state is ambiguous; recovery MUST fail closed with an error and retain `lock.journal` for inspection (`git-agecrypt inspect`).

---

## 10. Ciphertext Cache Key Derivation and Invalidation

Because `age` encryption is randomized (generating a fresh ephemeral X25519 key and payload nonce on every invocation), Git's `clean` filter requires deterministic convergence so unchanged plaintext files do not appear perpetually modified to `git status` or `git add`.

1. **Two-Tier Convergence:**
   - **Primary (Index-First):** During `git-agecrypt clean <path>`, if the Git staging index (`:0:<path>`) already contains a valid `age` ciphertext blob that decrypts under the active ring master key to bytes identical to the incoming stdin plaintext, `clean` emits the exact staged ciphertext blob.
   - **Secondary (Local HMAC Cache):**
     - Cache namespace directory: `<state_dir>/cache/<hex(SHA256(trim(repo.pub)))[0..16]>/`.
     - Cache entry filename: `<hex(HMAC_SHA256(key = trim(repo.key), msg = plaintext))>.age`.
     - On cache hit, the cached `.age` file is verified by decrypting it with the active master key and comparing the plaintext byte-for-byte before emitting.
2. **Invalidation:**
   - Rotating a ring's master key (`rekey`) changes `repo.pub`, automatically selecting a new `<hex(SHA256(repo.pub))[0..16]>` namespace and purging the old `cache/` directory.
   - Locking a ring (`lock`) purges `<state_dir>/cache/`.

---

## 11. Canonical Blob Format in Git Object Storage

Every secret blob stored in the Git index or object database on a path governed by `filter=agecrypt` (or `filter=agecrypt-<ring>`) MUST be a binary (non-armored) **age v1** file:
- First 22 bytes MUST equal `age-encryption.org/v1\n`.
- Followed by one or more recipient stanzas (`-> X25519 <ephemeral_share>`), header MAC (`--- <header_mac>\n`), and STREAM-encrypted ChaCha20-Poly1305 payload chunks.
- Exceptions:
  - Git symbolic links (`mode 120000`) store the link target path in plaintext and are passed through unmodified.
  - Git submodule gitlinks (`mode 160000`) store commit OIDs and are not filtered.
  - 0-byte empty files pass through as 0-byte blobs.

---

## 12. Compatibility and Deprecation Policy

1. **Backward Compatibility within Format Version 1:** All Format Version 1 compatible releases of `git-agecrypt` MUST read and write Format Version 1 repositories without manual migration.
2. **Explicit Versioned Upgrades:** Any future format revision (`FORMAT_VERSION >= 2`) MUST require an explicit `git-agecrypt migrate-format` command and MUST write `.git-agecrypt/format` with the new integer version.
3. **Standard `age` Escape Hatch:** Because committed secret blobs are standard binary `age` v1 files and `.git-agecrypt/keys/*.age` envelopes are standard ASCII-armored `age` v1 files wrapping a standard `AGE-SECRET-KEY-1...` identity, any Format Version 1 repository can be recovered using only the upstream `age` CLI without `git-agecrypt` installed (or exported via `git-agecrypt export-age`).
