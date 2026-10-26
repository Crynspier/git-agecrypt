# `git-agecrypt` Internals & Cryptographic Architecture

This document provides a technical deep-dive into the internal architecture, cryptographic design, shared-state locking invariants, convergence caching, and crash-consistency mechanisms of `git-agecrypt`.

For the normative on-disk and in-Git wire format specification, see [`docs/format-spec.md`](format-spec.md). For the external security review package and complete `unsafe`/syscall inventory, see [`docs/security-review-package.md`](security-review-package.md).

---

## 1. Envelope Encryption Architecture

`git-agecrypt` implements a **two-tier envelope encryption architecture** to avoid O(N) ciphertext bloat and enable instant recipient onboarding without re-encrypting historical Git blobs:

```text
+-------------------------------------------------------------------+
| 1. Collaborator Private Key (SSH Ed25519 / RSA or age X25519)      |
+-------------------------------------------------------------------+
                                  |
                                  | Decrypts (.git-agecrypt/keys/<user>.age)
                                  v
+-------------------------------------------------------------------+
| 2. Repository Master Key (256-bit age X25519 Identity)            |
|    - Public Key:  .git-agecrypt/repo.pub (Committed)              |
|    - Secret Key:  .git/git-agecrypt/repo.key (Untracked, 0600)    |
+-------------------------------------------------------------------+
                                  |
                                  | Encrypts / Decrypts (clean / smudge / merge)
                                  v
+-------------------------------------------------------------------+
| 3. Tracked Secret Files (e.g., secrets/prod.env)                  |
|    - Working Tree: Plaintext (when unlocked)                      |
|    - Git Index/DB: age-encryption.org/v1 Binary Ciphertext        |
+-------------------------------------------------------------------+
```

### Why Envelope Encryption?
1. **Constant-Size Blobs:** Encrypting a file directly to 50 team members in `age` adds 50 recipient stanzas to every encrypted file header. Envelope encryption encrypts each secret file to **one** recipient (`.git-agecrypt/repo.pub`), keeping headers compact regardless of team size.
2. **Zero-Churn Onboarding:** Adding a new collaborator (`git-agecrypt add-recipient`) only creates a ~300-byte `.git-agecrypt/keys/<name>.age` file wrapping the master key. No tracked secret files need to be re-encrypted or modified.
3. **Scoped Rings (`--ring <NAME>`):** Each ring maintains its own isolated `repo.pub`, `keys/*.age`, and local `repo.key`, providing cryptographic domain separation across environments (`dev`, `staging`, `prod`).

---

## 2. Shared-State Mutation Path Inventory & Locking Contract

Every command or internal helper that mutates repository-wide local state (`.git/git-agecrypt/`), committed key metadata (`.git-agecrypt/`), working-tree secret files, or `.git/config` is coordinated by the OS-level exclusive lock `recovery.lock` (`GitRepo::acquire_recovery_lock`).

| Command / Operation | Shared State Read | Shared State Mutated | Lock Acquired | Hold Scope (Start -> End) | Failure / Rollback Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `startup recovery` (`recover_interrupted_transaction`) | `repo.key.locking`, `repo.key`, `lock.journal`, `refresh.lock` | `repo.key`, `repo.key.locking`, `lock.journal`, worktree secret files, orphaned `.tmp` files | `recovery.lock` (OS exclusive via `flock` / `LockFileEx`) | Acquired before inspecting `repo.key.locking` or `lock.journal`; held until journal replay and tmp sweep complete. | Retains `lock.journal` if replay fails or if journal is malformed/ambiguous. |
| `init` (`cmd_init`) | `repo.pub`, `repo.key`, `.gitattributes` | `.git-agecrypt/repo.pub`, `.git-agecrypt/keys/initial_user.age`, `.git/git-agecrypt/repo.key`, `.git/config`, `.git/hooks/*`, AI shield files | `recovery.lock` | Acquired once at start of `cmd_init` (including atomic startup recovery) and held until hooks and AI shield files finish writing. | Atomic temp-file write + rename for `repo.key`; fails closed on unsupported format version. |
| `add-recipient` (`cmd_add_recipient`) | `repo.key`, `repo.pub`, `.git-agecrypt/keys/*.age` | `.git-agecrypt/keys/<label>.age` | `recovery.lock` | Acquired before reading `repo.key` and held until all new `.age` recipient envelopes are written. | Disambiguates case-insensitive key collisions with a SHA-256 suffix; never clobbers existing keys. |
| `remove-recipient` (`cmd_remove_recipient`) | `.git-agecrypt/keys/*.age` | Unlinks `.git-agecrypt/keys/<label>.age` | `recovery.lock` | Acquired before scanning `keys/` and held until recipient file removal completes. | Rejects path traversal/control characters; fails if recipient does not exist. |
| `rekey` (`cmd_rekey`) | `repo.key`, `keys/*.age`, worktree dirty status | `keys/*.age`, `repo.pub`, `repo.key`, `cache/`, Git index (`git add --renormalize`) | `recovery.lock` | Acquired before dirty-tree validation and held continuously through key rotation, `repo.key` replacement, cache purge, and index renormalization. | Aborts before mutation if non-secret files are dirty (unless `--force`) or if zero valid recipients exist. |
| `rewrap` (`cmd_rewrap`) | `repo.key`, `keys/*.age`, Git history commits, tracked secret files | Working-tree secret files (via atomic temp persist), Git index (`git add`) | `recovery.lock` | Acquired before reading `repo.key` and held across historical key discovery, file decryption, atomic persistence, and staging. | Preserves read-only permissions via `ReadonlyGuard`; aborts on unstaged plaintext edits unless `--force`. |
| `unlock` (`cmd_unlock`) | `keys/*.age`, user private key, worktree dirty status | `repo.key`, tracked secret files across all linked worktrees (`git checkout-index`) | `recovery.lock` | Acquired before reading `keys/*.age` and held through `save_local_master_key_for_ring` and `refresh_all_worktrees_for_ring`. | Atomic `repo.key` replacement; skips dirty secret files unless `--force`. |
| `lock` (`cmd_lock`) | `repo.key`, worktree dirty/reachability status, active Git op markers | `lock.journal`, `repo.key` -> `repo.key.locking`, worktree secret files, `cache/` | `recovery.lock` | Acquired before checking active Git ops / dirty files / unreachable worktrees and held until `repo.key.locking`, `lock.journal`, and `cache/` are removed. | Full WAL rollback (`repo.key.locking` -> `repo.key` + `replay_lock_journal_or_selective`) on any error or crash. |
| `migrate-from-git-crypt` (`cmd_migrate`) | `.gitattributes`, `.git-crypt` | `.gitattributes`, `.git-agecrypt/`, `repo.key`, `.git/config`, Git index | `recovery.lock` | Single `RecoveryLockGuard` held across `.gitattributes` update, `cmd_init_locked`, `cmd_add_recipient_locked`, and `git add --renormalize`. | Fails closed if `.gitattributes` is missing or format is unsupported. |
| `shield` / `install-hooks` | `.gitattributes`, `.git/hooks/*` | `.cursorignore`, `.claudeignore`, `.aiderignore`, `.aiignore` / `.git/hooks/*` | `recovery.lock` | Acquired at command start and held until ignore files or hook scripts are written. | Preserves existing user content outside managed blocks. |
| `smudge` / `textconv` / `merge` auto-refresh (`try_auto_refresh_master_key_for_ring`) | `repo.pub`, `repo.key`, `keys/*.age`, default SSH/age keys | `refresh.lock`, `repo.key` | `refresh.lock` (advisory wait-and-adopt) + `recovery.lock` (around `save_local_master_key_for_ring`) | `refresh.lock` coordinates parallel filter workers; `recovery.lock` serializes the actual `repo.key` atomic write against concurrent CLI commands. | If `refresh.lock` times out (5s), degrades safely to existing key state without racing. |

### `recovery.lock` Hardening Invariants
1. **OS-Managed Exclusive File Lock:** Uses `fs2::FileExt::try_lock_exclusive` (`flock(LOCK_EX | LOCK_NB)` on Unix, `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)` on Windows) in a bounded retry loop (`DEFAULT_RECOVERY_LOCK_TIMEOUT_MS = 30_000`, configurable via `GIT_AGECRYPT_LOCK_TIMEOUT_MS`).
2. **Zero Heuristic Stale Lock Breaking:** `recovery.lock` is never deleted or broken based on PID or mtime heuristics. When a holding process terminates or crashes (`SIGKILL` / `TerminateProcess`), the operating system kernel releases the file handle lock automatically.
3. **Coordination-Path Replacement Protection:**
   - On Windows, `recovery.lock` is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE` (omitting `FILE_SHARE_DELETE`), preventing any process from unlinking or renaming `recovery.lock` while a handle is open.
   - On Unix, `recovery.lock` is opened via `openat(..., O_NOFOLLOW | O_CLOEXEC)` and, after `try_lock_exclusive()` succeeds, its file descriptor `(st_dev, st_ino)` is verified against `symlink_metadata(lock_path)`. If the path was unlinked or replaced while waiting, the stale descriptor is unlocked and acquisition retries on the live path.

---

## 3. Convergence & Idempotency (Defeating the "Phantom Modified" Bug)

`age` encryption is randomized: encrypting the same plaintext twice produces two completely different ciphertexts due to ephemeral X25519 keys and random nonces. In a naive Git `clean` filter, running `git status` or `git add` causes Git to re-invoke `clean`, see a new ciphertext SHA-1, and mark unmodified files as perpetually `modified`.

`git-agecrypt` achieves **100% deterministic convergence** via a two-tier lookup in `crypto::clean_stream`:

### Tier 1: Index-First Inspection (Primary — Works on Fresh Clones)
1. When `git-agecrypt clean "%f"` runs, it fetches the currently staged blob from the Git index (`git cat-file blob :0:<path>`, capped at 512 MiB).
2. It attempts to decrypt the staged blob in-memory using the local master key (`repo.key`).
3. If the decrypted staged blob matches the incoming `stdin` plaintext byte-for-byte (verified via SHA-256 and length), `clean` outputs the **exact existing staged ciphertext bytes** from the index.

### Tier 2: HMAC-Keyed Local Ciphertext Cache (Secondary)
1. Plaintext is hashed using `HMAC-SHA256(key = repo.key, message = plaintext)`.
2. The cache directory `.git/git-agecrypt/cache/<sha256(repo.pub)[0..16]>/` is queried for `<hmac_hex>.age`.
3. **Cryptographic Poisoning Verification:** On a cache hit, `clean` decrypts the cached `.age` file with the active master key and verifies that the resulting plaintext matches the incoming `stdin` SHA-256 hash and length before emitting it.
4. **LRU Bounds:** When the cache directory exceeds 256 files, the oldest 64 entries by modification time are evicted.

---

## 4. Bounded Streaming & O(1) Memory Spool (`SpoolBuffer`)

To support both tiny `.env` files and multi-gigabyte database dumps without exhausting RAM:
- Payloads `<= 8 MiB` (`IN_MEMORY_SPOOL_LIMIT`) are buffered in a `Zeroizing<Vec<u8>>` in RAM and scrubbed on drop.
- Payloads `> 8 MiB` automatically spill over to an anonymous, automatically unlinked `tempfile::tempfile()` on disk.

---

## 5. Crash-Consistent Lock Transactions (Write-Ahead Log)

Locking a repository (`git-agecrypt lock`) must remove `repo.key` and replace plaintext secrets across all linked worktrees with ciphertext. If interrupted mid-operation by `SIGKILL` or power loss, a naive implementation leaves `repo.key` deleted while some worktree files are 0-byte truncated or half-smudged.

`GitRepo::transactional_lock_for_ring` guarantees atomic recovery via a 4-phase protocol under `recovery.lock`:
1. **Preflight Validation:** Verifies no active Git rebase/merge/cherry-pick/bisect is in progress, no tracked secret files have uncommitted changes, all linked worktrees are reachable, and no tracked secret file is held open exclusively by another process.
2. **Write-Ahead Log (`lock.journal`):** Writes every target `<worktree>\t<rel_path>` to `.git/git-agecrypt/lock.journal`, calls `sync_all()`, and syncs the parent directory.
3. **Key Staging (`repo.key.locking`):** Atomically renames `repo.key` -> `repo.key.locking` and syncs the state directory.
4. **Worktree Refresh & Commit:** Checkouts all tracked secret files as ciphertext across all worktrees, then removes `repo.key.locking` and `lock.journal`. If any step fails or crashes, `acquire_recovery_lock()` on the next invocation restores `repo.key` and selectively re-smudges only the files recorded in `lock.journal`.
