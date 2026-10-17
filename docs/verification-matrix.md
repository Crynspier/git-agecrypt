# Verification and Invariant Mapping Matrix

This document maps the implemented verification suites and documented invariants to their source files. Entries describe test coverage; they do not claim exhaustive coverage of every operating-system or filesystem behavior.

---

## 1. Verification Matrix

| # | Critique Domain | Architectural Implementation | Primary Automated Test Suite | Coverage Confidence |
|---|---|---|---|---|
| **#1** | Real SIGKILL / crash-point injection | 25 in-flight crash hooks (`GIT_AGECRYPT_CRASH_POINT`) terminating via `SIGKILL` / `TerminateProcess`, covering lock, unlock, rekey, merge, cache, clean, and spool paths | [`tests/test_sigkill_crash_injection.rs`](../tests/test_sigkill_crash_injection.rs) | Deterministic |
| **#2** | Expanded randomized Git state machine | Generative state machine with 40 operation types and a default 100-step run, covering history manipulation (merge, rebase, cherry-pick, revert, reset), index manipulation (partial staging, unstage), filesystem changes (create, modify, delete, rename, binary, Unicode), and repository operations (stash, branch, tag, repack, GC). Ops logged before execution; exact replay via `GIT_AGECRYPT_REPLAY`; automated ddmin failure-shrinking via subprocess oracle (`GIT_AGECRYPT_SHRINK`) producing a minimal `<log>.min` reproducer | [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) | Generative + Shrinkable |
| **#3** | In-memory shadow model tracking rings | `ShadowModel` reference engine tracking rings, generations, recipients, lock states, per-branch file state, and commit snapshots | [`tests/common/shadow_model.rs`](../tests/common/shadow_model.rs), [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) | Generative |
| **#4** | Random ring × generation × Git DAG | Generative DAG branching, independent ring rekeys, cross-ring merges, per-recipient access matrix verification | [`tests/test_generative_ring_dag.rs`](../tests/test_generative_ring_dag.rs) | Generative |
| **#5** | Real mixed-operation concurrency | Concurrent clean/smudge/lock/unlock/rekey/status threads racing against each other | [`tests/test_advanced_cache_races.rs`](../tests/test_advanced_cache_races.rs), [`tests/test_mixed_concurrency_stress.rs`](../tests/test_mixed_concurrency_stress.rs) | Generative |
| **#6** | TOCTOU filesystem elimination | Descriptor-pinned `openat(..., O_NOFOLLOW)` (Unix) and `FILE_FLAG_OPEN_REPARSE_POINT` (Windows) | [`src/git.rs`](../src/git.rs), [`tests/test_toctou_racing.rs`](../tests/test_toctou_racing.rs) | Deterministic |
| **#7** | Hostile-process `/proc` testing for `run --fd` | Real child secret consumption with `/proc/<pid>/status` Dumpable verification on Linux | [`tests/test_hostile_proc_snooping.rs`](../tests/test_hostile_proc_snooping.rs) | Deterministic |
| **#8** | FD lifetime and process crash bounds | Child exit codes (0, 42), crash handling, early close, and descriptor cleanup | [`tests/test_fd_lifecycle_crash.rs`](../tests/test_fd_lifecycle_crash.rs) | Deterministic |
| **#9** | On-demand coverage-guided fuzzing | Local/on-demand parser fuzzing using the repository fuzz targets | [`fuzz/fuzz_targets/`](../fuzz/fuzz_targets/) | On-demand |
| **#10** | Permanent regression corpus | Byte-level regression corpus runner in standard CI | [`tests/regressions/`](../tests/regressions/), [`tests/test_regression_corpus.rs`](../tests/test_regression_corpus.rs) | Continuous |
| **#11** | Power-loss & crash durability testing | Write → fsync → rename → crash → restart verification across the implemented crash points, concurrency × crash injection, per-file torn-write audits (every audited file must be absent / complete-old / complete-new), and an optional dm-flakey block-layer experiment on Linux with root and device-mapper support | [`tests/test_sigkill_crash_injection.rs`](../tests/test_sigkill_crash_injection.rs), [`tests/test_durability.rs`](../tests/test_durability.rs), [`tests/test_concurrency_crash_matrix.rs`](../tests/test_concurrency_crash_matrix.rs), [`tests/test_power_loss_durability.rs`](../tests/test_power_loss_durability.rs) | Deterministic + environment-gated |
| **#12** | Large-file interrupted streaming | 4 MiB stream killed in-flight with recursive forensic canary disk sweeps | [`tests/test_large_file_crash_spool.rs`](../tests/test_large_file_crash_spool.rs) | Deterministic |
| **#13** | Strict 3-tier submodule hierarchy | Strict parent → child → grandchild hierarchy testing with assertion rigor | [`tests/test_strict_submodules_matrix.rs`](../tests/test_strict_submodules_matrix.rs) | Deterministic |
| **#14** | Expanded 3-way merge matrix | 18-case merge matrix: non-overlapping, comments, quotes, JSON, conflict markers | [`tests/test_deep_merge_matrix_expanded.rs`](../tests/test_deep_merge_matrix_expanded.rs) | Deterministic |
| **#15** | Historical revocation semantics | Alice, Bob, Charlie multi-generation epoch access control | [`tests/test_historical_revocation_epochs.rs`](../tests/test_historical_revocation_epochs.rs) | Deterministic |
| **#16** | Hardware-token failure matrix | Missing, corrupt, truncated, and empty identity streams fail closed; age-plugin IPC failure injection (missing binary, rogue executable, exit-1, garbage output, silent success, torn stanza, slow token) fails closed with no canary plaintext observed in the tested outputs and clean recovery | [`tests/test_hardware_token_failure_matrix.rs`](../tests/test_hardware_token_failure_matrix.rs), [`tests/test_plugin_failure_injection.rs`](../tests/test_plugin_failure_injection.rs) | Deterministic |
| **#17** | Memory-hygiene under crash & errors | Forensic canary sweeps and tested checks for canary retention in selected crash/error artifacts | [`tests/test_large_file_crash_spool.rs`](../tests/test_large_file_crash_spool.rs), [`tests/test_memory_hygiene.rs`](../tests/test_memory_hygiene.rs) | Deterministic |
| **#18** | Performance benchmarking | Crypto micro-benches (spool/clean/smudge at 1 KiB / 100 KiB / 1 MiB / 4 MiB) and end-to-end CLI benches (clean, bulk clean ×20, lock, unlock, rekey, status) with sanity ceilings, machine-readable JSON output (`GIT_AGECRYPT_BENCH_JSON`), and opt-in baseline regression checks (`GIT_AGECRYPT_BENCH_CHECK` vs `benches/baseline.json`) | [`benches/bench_main.rs`](../benches/bench_main.rs), [`benches/baseline.json`](../benches/baseline.json) | Opt-in |
| **#19** | Cross-platform adversarial testing | Active symlink and junction racing on NTFS and POSIX | [`tests/test_toctou_racing.rs`](../tests/test_toctou_racing.rs), [`tests/test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) | Deterministic |
| **#20** | Advanced cache race testing | Cache hit × rekey races with explicit error checking, atomic persistence, and cache corruption recovery | [`tests/test_advanced_cache_races.rs`](../tests/test_advanced_cache_races.rs) | Generative |
| **#21** | Expanded invariant framework | Continuous evaluation of Invariants A through G after every operation | [`tests/common/invariants.rs`](../tests/common/invariants.rs) | Continuous |
| **#22** | Configurable random-run depth | Seedable PRNG (`GIT_AGECRYPT_SEED`) with configurable operation count (`GIT_AGECRYPT_OPS`) | [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) | Generative |
| **#23** | Documentation & specification tightening | Maintained documentation of security model, threat boundaries, and revocation limits | [`docs/spec-guarantees.md`](spec-guarantees.md) | Reviewed with changes |
| **#24** | Dependency & unsafe hardening | Source comments document the reviewed `unsafe` blocks for `openat`, `TerminateProcess`, and `prctl` | [`src/git.rs`](../src/git.rs), [`src/main.rs`](../src/main.rs) | Source-reviewed + CI |
| **#25** | CI matrix and deep verification | CI performs formatting, linting, workspace tests, benchmark compilation, and platform smoke builds; fuzzing, benchmark execution, and selected deep experiments remain explicitly invoked locally or by an operator | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`tests/`](../tests/), [`fuzz/`](../fuzz/) | CI + opt-in |
| **#26** | Concurrency × crash injection | Races state-changing operations against crash points, then recovers | [`tests/test_concurrency_crash_matrix.rs`](../tests/test_concurrency_crash_matrix.rs) | Generative |
| **#27** | FD inheritance boundaries | Verifies secret FD availability across fork/exec boundaries | [`tests/test_run_fd_inheritance.rs`](../tests/test_run_fd_inheritance.rs) | Deterministic |

---

## 2. Invariants A through G Verification Mapping

- **Invariant A (Working Tree Plaintext ⟺ Git Objects Ciphertext):** Verified continuously across [`test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs), [`test_stateful_random_harness.rs`](../tests/test_stateful_random_harness.rs), and [`test_deep_merge_matrix_expanded.rs`](../tests/test_deep_merge_matrix_expanded.rs).
- **Invariant B (Crash Durability & Fail-Closed Flush):** Exercised across the 25 crash points listed in [`test_sigkill_crash_injection.rs`](../tests/test_sigkill_crash_injection.rs), plus the durability and concurrency matrices. These tests do not establish universal physical power-loss durability.
- **Invariant C (Cross-Ring Isolation):** Verified by [`test_generative_ring_dag.rs`](../tests/test_generative_ring_dag.rs) and [`test_scoped_rings.rs`](../tests/test_scoped_rings.rs).
- **Invariant D (Path Traversal & Device Name Safety):** Verified by [`test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) and [`test_filesystem_security.rs`](../tests/test_filesystem_security.rs).
- **Invariant E (Zero-Plaintext Memory Hygiene):** Verified by [`test_memory_hygiene.rs`](../tests/test_memory_hygiene.rs), [`test_run_fd_isolation.rs`](../tests/test_run_fd_isolation.rs), and [`test_run_fd_inheritance.rs`](../tests/test_run_fd_inheritance.rs).
- **Invariant F (Idempotent Git State Machine):** Verified by [`test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) and [`test_stateful_git.rs`](../tests/test_stateful_git.rs).
- **Invariant G (Zero Plaintext Canary Leaks):** Verified by [`test_large_file_crash_spool.rs`](../tests/test_large_file_crash_spool.rs), [`test_forensic_canary_sweeps.rs`](../tests/test_forensic_canary_sweeps.rs), and continuous state machine sweeps.

---

## 3. Additional Verification Infrastructure

The repository includes the following generative, adversarial, and durability verification infrastructure:

### 3.1 Exact Replay + ddmin Failure-Shrinking (Generative State Machine)

- Every operation drawn by `test_deep_generative_shadow_model_state_machine` is serialized to a hex-encoded, `|`-delimited ops log (`GIT_AGECRYPT_OPS_LOG`) **before** execution, so a crash mid-run still leaves a complete replayable prefix.
- `test_replay_ops_log` re-executes a recorded log bit-for-bit when `GIT_AGECRYPT_REPLAY=<path>` is set — no RNG involved, fully deterministic.
- `test_ddmin_shrink_real_failure` implements a classic ddmin algorithm: candidate subsequences of the failing ops log are executed in a fresh subprocess (`replay_subprocess_fails` oracle), shrinking the failure to a minimal reproducer written to `<log>.min`. Gated on `GIT_AGECRYPT_SHRINK`.
- `test_ddmin_shrinker_selftest` validates the shrinker machinery itself using a synthetic ordered-subsequence failure trigger (`GIT_AGECRYPT_FAIL_IF_EXEC_SEQ`), proving ddmin eliminates unrelated noise ops.
- Replay and shrinking are available through the generative state-machine test's environment-controlled modes; they are run on demand.

### 3.2 age-plugin / Hardware-Token Failure Injection

- [`tests/test_plugin_failure_injection.rs`](../tests/test_plugin_failure_injection.rs) exercises the age plugin protocol (`AGE-PLUGIN-FOOBAR-1QVHULF`) with real plugin binary resolution (`which`, PATHEXT-aware, cross-platform mock scripts: POSIX `sh` + Windows `.bat`).
- Matrix: missing plugin binary, rogue executable (the git-agecrypt binary itself renamed as the plugin), plugin exits 1, garbage stdout, silent success (empty response), torn stanza (partial `-> file-key` line), slow token (multi-second delay).
- Fail-closed assertions: non-zero exit, byte-identical ciphertext pre/post failure, no canary plaintext in stdout/stderr, no dangling `.tmp` / `.locking` artifacts, and a subsequent operation with the plugin removed must recover cleanly.

### 3.3 Power-Loss Durability (Torn-Write Audit + dm-flakey)

- [`tests/test_power_loss_durability.rs`](../tests/test_power_loss_durability.rs):
  - `test_power_loss_torn_write_audit`: kills the CLI at the 20 write-side crash points currently listed by the test, then recursively audits selected state files (public keys, armored `.age` identities, `repo.key`, tracked secrets) classifying each as absent / complete-old / complete-new. Followed by a recovery status sweep and idempotent retry with exact-plaintext checks.
  - `test_dm_flakey_true_power_loss` (Linux + root + device-mapper only): builds a loop-backed dm-flakey device with ext4, crashes the CLI at `after_unwrap_key`, cuts power at the block layer (flakey error target), remounts, and verifies recovery. Skips cleanly on non-Linux / non-root.
- The torn-write audit is cross-platform. The dm-flakey test is Linux/root-gated and must be run on a host that provides device-mapper support; the standard CI workflow does not claim to run it.

### 3.4 Benchmark Suite v2

- [`benches/bench_main.rs`](../benches/bench_main.rs): crypto micro-benches (spool / clean / smudge at 1 KiB, 100 KiB, 1 MiB, 4 MiB) plus end-to-end CLI benches (clean, bulk clean ×20 files, lock, unlock, rekey, status) with per-benchmark sanity ceilings.
- Machine-readable output via `GIT_AGECRYPT_BENCH_JSON=1` (optional `GIT_AGECRYPT_BENCH_OUT=<path>`); opt-in regression gate via `GIT_AGECRYPT_BENCH_CHECK=1` comparing against committed [`benches/baseline.json`](../benches/baseline.json) with 3× tolerance.
- Performance benchmarks are opt-in and produce local Criterion output; no benchmark result is treated as a release claim without a recorded run.

