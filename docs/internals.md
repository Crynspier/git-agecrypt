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
1. **Repository & Key Verification:** Reads the master key from `.git/git-agecrypt/master.key`. If the key is missing or locked, `clean` aborts with an error to prevent committing unencrypted data.
2. **Two-Tier Ingest:** The incoming stream from `stdin` is read into memory up to 1 MiB. If the stream exceeds 1 MiB, it spills into `.git/git-agecrypt/spool/`.
3. **Stage-0 Index Deduplication:** If the target path is provided, `git-agecrypt` inspects the existing blob at `:0:<path>` in the Git index. If the existing index blob decrypts to identical plaintext, the existing ciphertext is reused directly, producing bitwise-identical commits without re-encryption overhead.
4. **Keyed HMAC Cache Check:** Computes an HMAC-SHA256 digest of the plaintext using the master key. If a matching ciphertext exists in `.git/git-agecrypt/cache/<hmac>`, the cached header is validated (`is_age_ciphertext`). If valid, the cached ciphertext is emitted.
5. **Streaming Encryption:** On a cache miss, the plaintext is encrypted into an `age-encryption.org/v1` container using ChaCha20-Poly1305 in 64 KiB chunks. The result is written to `stdout`, and atomically cached with `sync_all()`.

### 1.2 The `smudge` Filter

The `smudge` filter converts ciphertext from standard input into cleartext on standard output during checkout or switch operations (`git checkout`, `git switch`, `git reset`).

**Execution Pipeline:**
1. **Pass-Through on Locked Repositories:** If the repository is locked or no enrolled key is present, `smudge` streams standard input directly to standard output with exit code `0`. This ensures that cloning a repository or switching branches never causes Git to fail with fatal errors.
2. **Decryption:** If unlocked, the `age` container is decrypted using the master key. Small files are decrypted in RAM; files larger than 1 MiB are streamed through disk spools in 64 KiB chunks.

### 1.3 The `textconv` Driver

Configured for `git diff` and `git log -p`:
- Git passes the target ciphertext file path as an argument.
- `git-agecrypt textconv <path>` decrypts the file and writes cleartext to `stdout`.
- Diffs appear naturally in terminals and GUIs as standard plaintext diffs while the underlying repository objects remain encrypted.

---

## 2. Two-Tier Spooling & Memory Management

`git-agecrypt` enforces strict resource boundaries to support both tiny environment configs and multi-gigabyte files efficiently:

| Tier | Payload Size | Storage Medium | Zeroization | Memory Footprint |
|---|---|---|---|---|
| **Tier 1 (RAM)** | $< 1\text{ MiB}$ | Heap buffer (`Zeroizing<Vec<u8>>`) | Automatic on `drop` | $O(N)$ up to 1 MiB |
| **Tier 2 (Disk Spool)** | $\ge 1\text{ MiB}$ | `.git/git-agecrypt/spool/` | Unlinked on close | $O(1)$ RAM (64 KiB chunk buffer) |

### 2.1 Tier 1: In-Memory Fast Path

Secrets and configuration files are almost universally under 1 MiB. For these files:
- Zero temporary disk files are created.
- Buffers use Rust's `zeroize` crate to guarantee memory is wiped with zeroes when deallocated, preventing secret remanence in process memory.

### 2.2 Tier 2: Bounded Streaming for Large Files

For datasets, database dumps, archives, or binary blobs $\ge 1\text{ MiB}$:
- Data spills directly into an anonymous temporary file inside `.git/git-agecrypt/spool/`.
- Encryption and decryption operate in 64 KiB streaming chunks (`STREAM_CHUNK_SIZE`).
- Peak memory usage remains bounded to approximately 128 KiB regardless of whether the file is 10 MiB or 50 GiB.

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
2. **Keyed HMAC Cache:** If the index entry is unavailable or different, `git-agecrypt` computes `HMAC-SHA256(master_key, plaintext)`. The digest addresses the cache file at `.git/git-agecrypt/cache/<digest>`.
3. **Cache Validation & Invalidation:** When a cache hit occurs, `git-agecrypt` performs a lightweight check on the header (`is_age_ciphertext`). If a cached file was truncated or corrupted, it is automatically unlinked and treated as a cache miss, ensuring corrupted data is never emitted into the Git index.

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

1. **Decryption:** `%O`, `%A`, and `%B` are decrypted into temporary cleartext files inside `.git/git-agecrypt/spool/`.
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
