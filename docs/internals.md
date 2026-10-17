# Internal Architecture & Implementation Details

This document covers the internal design, runtime lifecycle, streaming buffers, and merge algorithms implemented in `git-agecrypt`.

---

## 1. Git Filter Driver Lifecycle

Git integrates with `git-agecrypt` using custom filter and diff drivers configured in `.git/config` and applied via `.gitattributes`.

```text
+--------------------------------------------------------------------------------+
|                                Git Worktree                                    |
|                                                                                |
|  [ Working Tree (Plaintext) ]                                                  |
|        |                  ^                                                    |
|     git add          git checkout / git switch                                 |
|        |                  |                                                    |
|        v                  |                                                    |
|  +-------------+   +---------------+                                           |
|  | clean       |   | smudge        |                                           |
|  | driver      |   | driver        |                                           |
|  +-------------+   +---------------+                                           |
|        |                  ^                                                    |
|        v                  |                                                    |
|  [ Git Index (Ciphertext) ]                                                    |
|        |                                                                       |
|     git commit                                                                 |
|        |                                                                       |
|        v                                                                       |
|  [ Git Object DB (.git/objects) (Authenticated age ciphertext) ]               |
|        |                                                                       |
|        +------> git diff / git log -p ------> [ textconv driver ]              |
|        |                                                                       |
|        +------> git merge (concurrent edit) -> [ 3-way merge driver ]          |
+--------------------------------------------------------------------------------+
```

### 1.1 The `clean` Filter

The `clean` filter converts cleartext from standard input into authenticated `age` ciphertext on standard output when files are staged (`git add`).

**Execution Pipeline:**
1. **Repository & Key Verification:** Reads the unlocked repository key from `.git/git-agecrypt/repo.key`. If the key is missing or locked, `clean` aborts with an error to prevent committing unencrypted data.
2. **Two-Tier Ingest:** The incoming stream from `stdin` is read into memory up to 1 MiB. If the stream exceeds 1 MiB, the stream spool uses the host temporary-file facility.
3. **Stage-0 Index Deduplication:** If the target path is provided, `git-agecrypt` inspects the existing blob at `:0:<path>` in the Git index. If the existing index blob decrypts to identical plaintext, the existing ciphertext is reused directly, producing bitwise-identical commits without re-encryption overhead.
4. **Keyed HMAC Cache Check:** Computes an HMAC-SHA256 digest of the plaintext using the master key. If a matching ciphertext exists in `.git/git-agecrypt/cache/<hmac>`, the cached header is validated (`is_age_ciphertext`). If valid, the cached ciphertext is emitted.
5. **Streaming Encryption:** On a cache miss, the plaintext is encrypted into an `age-encryption.org/v1` container using ChaCha20-Poly1305 in 64 KiB chunks. The result is written to `stdout`, and atomically cached with `sync_all()`.

### 1.2 The `smudge` Filter

The `smudge` filter converts ciphertext from standard input into cleartext on standard output during checkout or switch operations (`git checkout`, `git switch`, `git reset`).

**Execution Pipeline:**
1. **Pass-Through on Locked Repositories:** If the repository is locked or no enrolled key is present, `smudge` is designed to stream standard input directly to standard output with exit code `0`. This allows the encrypted payload to remain checked out, subject to other Git and filesystem errors.
2. **Decryption:** If unlocked, the `age` container is decrypted using the master key. Small files are decrypted in RAM; files larger than 1 MiB are streamed through disk spools in 64 KiB chunks.

### 1.3 The `textconv` Driver

Configured for `git diff` and `git log -p`:
- Git passes the target ciphertext file path as an argument.
- `git-agecrypt textconv <path>` decrypts the file and writes cleartext to `stdout`.
- Diffs appear naturally in terminals and GUIs as standard plaintext diffs while the underlying repository objects remain encrypted.

---

## 2. Two-Tier Spooling & Memory Management

`git-agecrypt` uses separate in-memory and temporary-file paths for small and large inputs. Exact resource usage depends on the age and I/O layers:

| Tier | Payload Size | Storage Medium | Zeroization | Memory Footprint |
|---|---|---|---|---|
| **Tier 1 (RAM)** | $< 1\text{ MiB}$ | Heap buffer (`Zeroizing<Vec<u8>>`) | Automatic on `drop` | $O(N)$ up to 1 MiB |
| **Tier 2 (Temporary Spool)** | $\ge 1\text{ MiB}$ | Host temporary-file facility | Removed on close when cleanup succeeds | Bounded, implementation-dependent memory |

### 2.1 Tier 1: In-Memory Fast Path

For inputs below the 1 MiB threshold on the in-memory path:
- The implementation does not intentionally create a temporary spool file.
- The primary spool buffer uses Rust's `zeroize` crate on deallocation; this does not guarantee that every intermediate or operating-system copy is wiped.

### 2.2 Tier 2: Bounded Streaming for Large Files

For datasets, database dumps, archives, or binary blobs $\ge 1\text{ MiB}$:
- The stream spool is created through the host temporary-file facility; it is not currently forced into `.git/git-agecrypt/spool/`.
- Encryption and decryption use the implementation's streaming buffers; exact memory usage depends on the age and I/O layers.
- The design avoids loading the complete file into one application buffer, but this document does not promise a fixed peak-memory figure.

---

## 3. Deterministic HMAC Caching & Index Deduplication

### 3.1 Eliminating Phantom Diffs

Because `age` uses randomized nonces, re-encrypting identical plaintext normally yields different ciphertexts. In Git, this would cause `git diff` to show modified binary files even when no content changed.

`git-agecrypt` eliminates phantom diffs through a two-level deduplication strategy:

```text
[ Plaintext Ingest ]
        |
        v
[ Stage 0 Index Check ] -------- Match found? --------> [ Emit Existing Blob ]
        | No
        v
[ Keyed HMAC Cache Check ] ----- Valid Hit? ----------> [ Emit Cached Blob ]
        | Miss / Invalid
        v
[ age Encryption Engine ] ----> [ Atomic Cache Write (sync_all) ] ----> [ Emit New Ciphertext ]
```

1. **Stage 0 Index Deduplication:** Prior to encryption, `git-agecrypt` checks `:0:<path>` in the Git index. If that blob decrypts to the current plaintext, the exact existing ciphertext is reused.
2. **Keyed HMAC Cache:** If the index entry is unavailable or different, `git-agecrypt` computes `HMAC-SHA256(master_key, plaintext)`. The digest addresses the cache file at `.git/git-agecrypt/cache/<fingerprint>/<digest>`.
3. **Cryptographic Cache Authentication:** When a cache hit candidate is discovered, `git-agecrypt` does NOT simply trust the file structure. It decrypts the cached ciphertext in RAM using the active master identity and verifies that `HMAC-SHA256(master_key, decrypted_bytes) == digest`. If the HMAC matches and decryption succeeds, the ciphertext is safely emitted.
4. **Automatic Eviction & Fail-Closed Fallback:** If the candidate cache file has been tampered with, originates from a foreign key epoch, or contains bit flips, `git-agecrypt` automatically removes the corrupted entry (`fs::remove_file`) and falls back to a clean encryption of the genuine working tree file.
5. **Key Epoch Cache Purging:** During `git-agecrypt rekey`, all cached ciphertexts across `.git/git-agecrypt/cache/` are immediately purged to prevent ciphertext reuse across different master key generations.

---

## 4. 3-Way Semantic Merge Driver

When two developers modify an encrypted file concurrently on different branches, Git invokes the custom merge driver configured in `.gitattributes`:

$$\text{merge driver invocation: } \texttt{git-agecrypt merge <\%O> <\%A> <\%B> [\%L] [\%P]}$$

- `%O`: Ancestor / Base version (encrypted)
- `%A`: Current branch / "Ours" (encrypted)
- `%B`: Other branch / "Theirs" (encrypted)
- `%L`: Conflict marker length (default: 7)
- `%P`: Target file path

### 4.1 Execution Sequence

1. **Decryption:** `%O`, `%A`, and `%B` are decrypted into temporary cleartext files managed by the host temporary-file facility.
2. **Binary Detection:** If any decrypted version contains null bytes (`0x00`), the file is treated as binary. Clean 3-way line merging is aborted; a conflict is declared immediately to protect binary data from corruption.
3. **Git 3-Way Merge:** Executes `git merge-file -L <our> -L <base> -L <their> <tmp_A> <tmp_O> <tmp_B>`.
4. **Semantic Key Analysis:** If merging `.env` or key-value configuration files, `git-agecrypt` scans the merged output for conflicting assignments or duplicate keys and emits diagnostic warnings.
5. **False-Merge Prevention:**
   - If `git merge-file` exited with code `> 0` or conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) exist in the output:
     - The output is sanitized to prevent double carriage-return (`\r\r\n`) issues on Windows.
     - The conflicting cleartext with visible conflict markers is re-encrypted back into `%A`.
     - `sync_all()` is executed to ensure durability.
     - The merge driver exits with non-zero status (`exit(1)`), ensuring Git pauses the merge and developers see the exact conflict in their editor.
6. **Clean Merge:** If there are no conflicts, the clean merged text is re-encrypted into `%A`, `sync_all()` is called, and the merge driver exits with code `0`.

---

## 5. Safeguard Hook Architecture

`git-agecrypt install-hooks` installs non-destructive Git hooks that inspect staged files prior to commit and push:

### 5.1 Pre-Commit & Pre-Merge-Commit

1. **Staged Blob Inspection:** Inspects every staged file in the index matching encrypted attributes. Confirms each staged blob starts with the valid `age-encryption.org/v1` header.
2. **Corrupted Ciphertext Guard:** Detects partial `git add -p` staging artifacts or corrupted ciphertext containers and halts the commit.
3. **Untracked Secret Heuristic Scanner:** Inspects staged files that are *not* configured with `filter=agecrypt`. If any staged file matches high-entropy secret patterns, `.env` conventions, or private key headers (`BEGIN ... PRIVATE KEY`), the commit is blocked to prevent accidental plaintext exposure.

### 5.2 Pre-Push

1. **Outgoing Commit Validation:** Scans the revision range `origin/branch..HEAD` to verify that every commit about to leave the local repository has all sensitive files properly encrypted.
2. **Key Epoch Verification:** Verifies that all outgoing encrypted files are decryptable with the currently active master key, preventing developers from pushing commits encrypted under outdated or revoked keys.

---

## 6. Scoped Recipient Rings Architecture

`git-agecrypt` supports partitioned recipient access domains known as **Scoped Recipient Rings**.

### 6.1 Directory & State Hierarchy

```text
Repository Root
├── .gitattributes
├── .git-agecrypt/
│   ├── keys/                         # Default ring recipient envelopes
│   │   ├── alice.age
│   │   └── bob.age
│   ├── repo.pub                      # Default ring public identity
│   └── rings/
│       ├── prod/                     # Scoped ring "prod"
│       │   ├── keys/
│       │   │   └── ops_lead.age
│       │   └── repo.pub
│       └── dev/                      # Scoped ring "dev"
│           ├── keys/
│           │   └── team.age
│           └── repo.pub
└── .git/
    └── git-agecrypt/
        ├── repo.key                  # Ephemeral unlocked default master key
        ├── cache/                    # HMAC ciphertext cache
        ├── spool/                    # Auxiliary local state and cleanup area
        └── rings/
            ├── prod/
            │   └── repo.key          # Ephemeral unlocked prod master key
            └── dev/
                └── repo.key          # Ephemeral unlocked dev master key
```

### 6.2 Driver Binding & Filter Routing

Scoped rings bind Git filters through `.gitattributes`:
- `*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text` routes to the default ring.
- `secrets/prod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text` routes to ring `prod`.

When `git-agecrypt clean %f --ring prod` or `git-agecrypt smudge %f --ring prod` executes:
1. It queries `.git/git-agecrypt/rings/prod/repo.key`.
2. If unlocked, it decrypts/encrypts using the `prod` master key.
3. If locked, `smudge` safely passes ciphertext through without breaking Git checkout or branch switching.
4. During pre-commit and pre-push validation, `git-agecrypt check` dynamically inspects each staged file's assigned filter attribute and validates ciphertext against that specific ring's key epoch.

### 6.3 Ring Identifier Validation Grammar

To prevent directory traversal attacks, arbitrary file overwrites, and platform-specific device name collisions, all ring identifiers supplied via `--ring <name>` or parsed from `.gitattributes` (`filter=agecrypt-<name>`) must strictly satisfy the following validation rules:

1. **Length:** Between 1 and 64 characters.
2. **Grammar Whitelist:** Must begin with an alphanumeric character (`[a-zA-Z0-9]`), followed optionally by alphanumeric characters, underscores (`_`), dots (`.`), or hyphens (`-`).
3. **Disallowed Characters:** Forward slashes (`/`), backslashes (`\`), spaces, null bytes, and non-printable control characters are strictly rejected.
4. **Parent Traversal Prevention:** Sequences such as `..`, `.`, or paths containing path separators are immediately rejected before performing any filesystem operations.
5. **Reserved Device Protection:** Rejects reserved Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`, `LPT1` through `LPT9`) regardless of file extension or letter casing.

---

## 7. Anonymous In-Memory Secret Passing (`memfd_create`)

To avoid intentionally placing decrypted environment variables in `/proc/<pid>/environ` on Linux hosts:

### 7.1 Linux Kernel In-Memory File Descriptors

When `git-agecrypt run --fd -- <cmd>` is executed on Linux:
1. **Syscall Invocation:** `git-agecrypt` invokes `libc::syscall(SYS_memfd_create, name, MFD_CLOEXEC)`. The `MFD_CLOEXEC` flag guarantees that the descriptor will not leak into unrelated forks or subprocesses spawned by the parent.
2. **Anonymous RAM Allocation:** The Linux kernel allocates an anonymous, RAM-backed file descriptor that has no path on the physical filesystem.
3. **Decryption & Spooling:** The encrypted `.env` file is decrypted in RAM and written into the file descriptor.
4. **File Offset Rewind:** The file position is rewound to 0 (`lseek(fd, 0, SEEK_SET)`).
5. **Child Process Descriptor Transfer:** In `Command::pre_exec` before executing the child command via `execve`, the `FD_CLOEXEC` flag is cleared (`fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC)`) exclusively for the target child process.
6. **FD Exposure:** The descriptor number is injected into the child's environment as `GIT_AGECRYPT_ENV_FD=<fd>`. Child processes can read secrets via `/dev/fd/<fd>` or `open("/proc/self/fd/<fd>", O_RDONLY)`.
7. **Descriptor Lifetime:** When the parent and child close the descriptor, the kernel releases the anonymous file. This avoids an application-created pathname, but does not establish that plaintext can never be paged, captured, or written by the operating system.
8. **Fail-Closed on Non-Linux Hosts:** On operating systems lacking anonymous RAM descriptors (Windows, macOS), `run --fd` strictly fails closed by default. Users must explicitly supply `--allow-env-fallback` to permit falling back to standard in-memory environment variable injection.

---

## 8. Crash Durability & Directory Synchronization

To reduce filesystem metadata inconsistency after interruption or a crash:

1. **Atomic Temporary Replacement:** Key, journal, and merge-target writes generally use uniquely named temporary files and replacement within the target filesystem. Stream spools and some fallback paths use the host temporary-file facility instead.
2. **File Content Sync:** Critical replacement paths call `sync_all()` (`fsync`) before replacement. This asks the operating system to flush file data and metadata; it is not a universal proof of physical-media persistence.
3. **Directory Entry Sync (`sync_dir`):** POSIX replacement paths also attempt to synchronize the containing directory. Windows behavior and filesystem guarantees differ by platform.
4. **Error Handling:** Security-critical write, replacement, and recovery errors are propagated. Auxiliary cache cleanup and some cleanup synchronization are intentionally best effort.

---

## 9. Generative State Machine & Combinatorial DAG Verification

The repository includes generative randomized state-machine harnesses, including [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs), powered by seeded PRNGs (`rand_chacha::ChaCha8Rng`):

1. **State Space Exploration:** The harness executes a default 100-step pseudorandom sequential run, with configurable depth, including `EditSecret`, `GitAdd`, `GitCommit`, `GitCreateBranch`, `GitSwitchBranch`, `GitStashPush`, `GitStashPop`, `GitRepack`, `AgecryptLock`, `AgecryptUnlock`, and `AgecryptRekey`.
2. **Shadow State Model:** Tracks expected plaintext and encrypted status in memory and checks the invariants implemented by the harness at each transition.
3. **Forensic Canary Validation:** Injects unique canary tokens into secrets and checks selected packfile/loose-object scenarios for plaintext canary presence; this does not cover every Git operation or misconfiguration.
4. **Combinatorial DAG Testing:** Separate tests exercise multi-ring and multi-generation branch divergence, merges, and credential synchronization ([`tests/test_combinatorial_rings_generations.rs`](../tests/test_combinatorial_rings_generations.rs)).

---

## 10. Filesystem Boundary Validation & Platform Hardening

1. **Symlink & Reparse Point Protection:** To defend against arbitrary file overwrite or credential redirection attacks via symlink swapping (TOCTOU), `ensure_not_symlink_or_reparse` validates that `.git/git-agecrypt/repo.key`, `.git-agecrypt/keys/`, and state directories are genuine physical directories and files.
2. **Case-Insensitive Collision Prevention:** On case-insensitive filesystems (Windows NTFS, macOS APFS), `check_ring_case_collision` prevents ring collisions (e.g. creating `PROD` when `prod` already exists).
3. **Linux Kernel Memory Lockdown:** When passing secrets via `run --fd`, child processes execute `libc::prctl(PR_SET_DUMPABLE, 0)` in `pre_exec` to prevent unauthorized memory attachment via `ptrace` or core dump generation.



