# Specification: Cryptographic Security Guarantees & Threat Model

This document records the cryptographic and architectural properties that `git-agecrypt` implements, together with their operational limits and verification boundaries.

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

`git-agecrypt` is designed to provide crash consistency when a process terminates unexpectedly. The automated suites cover process termination and selected fault-injection cases; physical power-loss behavior remains filesystem- and host-specific:

- **Atomic Key Staging:** Master keys are staged via `repo.key.tmp.<pid>` with `fsync()`, directory sync, and atomic rename.
- **Write-Ahead Log (WAL):** The locking transaction records all staged secret targets in `lock.journal` with `sync_all()` before modifying the key store.
- **Self-Healing Recovery:** Any subsequent invocation (`status`, `lock`, `unlock`, etc.) triggers `recover_interrupted_transaction()`. The repository deterministically recovers either the **Old Valid State** or the **New Valid State**.
- **No Silent Half-States:** Recovery rejects incomplete or inconsistent metadata instead of treating it as successful state. The guarantees depend on the filesystem primitives available on the host.

---

## 3. Cache Security Model

`git-agecrypt` employs deterministic clean/smudge caching to prevent Git phantom diffs:

- **HMAC Addressing:** Cache entries are keyed by $\text{HMAC-SHA256}_{K_{\text{master}}}(\text{plaintext})$.
- **Generational Purging:** On every `rekey`, the cache for that ring is purged, ensuring that stale generation ciphertexts are never re-emitted into the Git object store.
- **Integrity Validation:** Every cache read validates the HMAC before reuse. Corrupted or tampered entries are immediately detected, purged, and re-encrypted from source.

---

## 4. `run --fd` Process Isolation Boundary

When executing commands via `git-agecrypt run --fd -- <cmd>`:

- **No Application Temporary-File Exposure:** The `--fd` path does not intentionally write decrypted secrets to application temporary files. The operating system may still page or capture process memory; that is outside this tool's guarantee.
- **Zero Environment Leakage:** Secrets are not passed in `argv` or inherited environment variables where other local users might inspect them via `ps` or `/proc/<pid>/cmdline`.
- **Memory Dumpability Reduction:** On Linux, the child setup applies `libc::prctl(PR_SET_DUMPABLE, 0)` in `pre_exec`, reducing some same-user `/proc` and `ptrace` inspection paths. This does not prevent all memory capture, paging, or access by an authorized child.
- **Descriptor Reclaim:** Linux secrets are delivered through an anonymous descriptor that is closed and reclaimed according to normal process/file-descriptor lifetime rules.

---

## 5. Hardware Token Fail-Closed Boundary

- Missing, corrupted, unresponsive, or disconnected hardware tokens result in immediate **fail-closed termination**.
- `git-agecrypt` will **never** fallback to plaintext, fallback to an untrusted secondary credential, or emit unencrypted secrets into Git streams.

---

## 6. Verification Boundary

The guarantees above are implementation claims, not a promise that every operating-system primitive is available everywhere. The evidence currently maintained in this repository maps them as follows; test results do not by themselves establish a published release or universal platform coverage:

| Guarantee | Implementation evidence | Verification boundary |
|---|---|---|
| Historical revocation | Epoch-specific recipient wrapping and cache purge | New epochs exclude revoked recipients; old Git objects remain decryptable to recipients who held the old epoch key |
| Crash consistency | WAL, staged writes, fsync/sync-all, atomic rename, recovery sweep | SIGKILL/TerminateProcess and torn-write suites; dm-flakey is Linux/root-gated |
| Cache integrity | HMAC-addressed entries with validation and generation purge | Corruption, race, and rekey tests; a cache hit is never trusted without authentication |
| `run --fd` isolation | Linux `memfd_create`, dumpability lockdown, descriptor lifecycle cleanup | Linux gets anonymous descriptors; Windows/macOS fail closed unless `--allow-env-fallback` is explicitly requested |
| Hardware-token failure handling | Age plugin protocol errors are propagated without plaintext fallback | Missing, malformed, slow, and disconnected plugins are failure cases, not supported recovery paths |

The project does not claim protection against plaintext already copied by an authorized process, historical Git objects retained by a formerly authorized recipient, compromised hosts, or operating systems that cannot provide the requested kernel isolation primitive. Those are explicit limitations rather than silent best-effort behavior.
