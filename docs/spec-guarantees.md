# Specification: Cryptographic Security Guarantees & Threat Model

This document formally specifies the cryptographic and architectural guarantees of `git-agecrypt`.

---

## 1. Historical Access & Revocation Semantics

When a collaborator is removed from an encryption ring via `git-agecrypt remove-recipient <name>` followed by `git-agecrypt rekey`:

1. **Forward Secrecy for New Commits ($G_{n+1}$):**
   - A brand new 256-bit symmetric master key is generated.
   - The master key is wrapped exclusively for the remaining authorized recipients.
   - The previous symmetric master key is purged from the local cache and working tree.
   - Any ciphertext generated after the rekey epoch ($G_{n+1}$) **cannot be decrypted** by the revoked party, even if they retain their private key.

2. **Historical Commits ($G_0 \dots G_n$):**
   - Git is an immutable append-only directed acyclic graph (DAG). Past commit trees retain objects encrypted under previous epoch keys ($G_n$).
   - A revoked recipient who possessed access during epoch $G_n$ can decrypt historical commits from that epoch if they retained their epoch $G_n$ credentials.
   - If historical confidentiality is required after offboarding, the repository history must be rewritten using `git-filter-repo` and all historical blobs re-encrypted.

3. **New Collaborator Access:**
   - A collaborator added at epoch $G_{n+1}$ can decrypt all commits created in $G_{n+1}$ or later.
   - They **cannot** decrypt historical commits from prior epochs ($G_0 \dots G_n$) unless the repository administrator exports and wraps the historical keys for them.

---

## 2. In-Flight Durability & Crash Consistency (WAL)

`git-agecrypt` guarantees **crash consistency** under arbitrary process termination (`SIGKILL`, power failure, hardware faults):

- **Atomic Key Staging:** Master keys are staged via `repo.key.tmp.<pid>` with `fsync()`, directory sync, and atomic rename.
- **Write-Ahead Log (WAL):** The locking transaction records all staged secret targets in `lock.journal` with `sync_all()` before modifying the key store.
- **Self-Healing Recovery:** Any subsequent invocation (`status`, `lock`, `unlock`, etc.) triggers `recover_interrupted_transaction()`. The repository deterministically recovers either the **Old Valid State** or the **New Valid State**.
- **No Corrupted Half-States:** Secret files are never left in a partially decrypted or corrupted state.

---

## 3. Cache Security Model

`git-agecrypt` employs deterministic clean/smudge caching to prevent Git phantom diffs:

- **HMAC Addressing:** Cache entries are keyed by $\text{HMAC-SHA256}_{K_{\text{master}}}(\text{plaintext})$.
- **Generational Purging:** On every `rekey`, the cache for that ring is purged, ensuring that stale generation ciphertexts are never re-emitted into the Git object store.
- **Integrity Validation:** Every cache read validates the HMAC before reuse. Corrupted or tampered entries are immediately detected, purged, and re-encrypted from source.

---

## 4. `run --fd` Process Isolation Boundary

When executing commands via `git-agecrypt run -- <cmd>`:

- **Zero Disk Exposure:** Decrypted secrets are never written to disk, swap, or temporary files.
- **Zero Environment Leakage:** Secrets are not passed in `argv` or inherited environment variables where other local users might inspect them via `ps` or `/proc/<pid>/cmdline`.
- **Memory Dumpable Lockdown:** On Linux, child processes have `libc::prctl(PR_SET_DUMPABLE, 0)` set in `pre_exec`, preventing sibling processes under the same UID from reading memory via `/proc/<pid>/mem` or attaching debuggers via `ptrace`.
- **Descriptor Reclaim:** Secrets are delivered over anonymous file descriptors (or `memfd_create`) which are automatically reclaimed by the kernel upon child process termination.

---

## 5. Hardware Token Fail-Closed Boundary

- Missing, corrupted, unresponsive, or disconnected hardware tokens result in immediate **fail-closed termination**.
- `git-agecrypt` will **never** fallback to plaintext, fallback to an untrusted secondary credential, or emit unencrypted secrets into Git streams.
