# High-Assurance Verification & Invariant Mapping Matrix (v0.5.0)

This document provides the exhaustive, bi-directional verification matrix mapping every architectural invariant and critique item to its concrete implementation and automated test suites in `git-agecrypt`.

---

## 1. Critique Items Verification Matrix (v0.5.0)

| # | Critique Domain | Architectural Implementation | Primary Automated Test Suite |
|---|---|---|---|
| **#1** | Real SIGKILL / crash-point injection | 14 in-flight crash hooks (`GIT_AGECRYPT_CRASH_POINT`) terminating via `SIGKILL` / `TerminateProcess` | [`tests/test_sigkill_crash_injection.rs`](../tests/test_sigkill_crash_injection.rs) |
| **#2** | Expanded randomized Git state machine | 24-operation generative state machine testing branches, stashes, rebases, and commits | [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) |
| **#3** | In-memory shadow model tracking rings | `ShadowModel` reference engine tracking rings, generations, recipients, and lock states | [`tests/common/shadow_model.rs`](../tests/common/shadow_model.rs), [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) |
| **#4** | Random ring $\times$ generation $\times$ Git DAG | Generative DAG branching, independent ring rekeys, and cross-ring merges | [`tests/test_generative_ring_dag.rs`](../tests/test_generative_ring_dag.rs) |
| **#5** | Real mixed-operation concurrency | Concurrent clean/smudge threads racing against active rekeys and cache updates | [`tests/test_advanced_cache_races.rs`](../tests/test_advanced_cache_races.rs), [`tests/test_mixed_concurrency_stress.rs`](../tests/test_mixed_concurrency_stress.rs) |
| **#6** | TOCTOU filesystem elimination | Descriptor-pinned `openat(..., O_NOFOLLOW)` (Unix) and `FILE_FLAG_OPEN_REPARSE_POINT` (Windows) | [`src/git.rs`](../src/git.rs), [`tests/test_toctou_racing.rs`](../tests/test_toctou_racing.rs) |
| **#7** | Hostile-process `/proc` testing for `run --fd` | Real child secret consumption with concurrent `/proc/<pid>/mem` and `ptrace` inspection | [`tests/test_hostile_proc_snooping.rs`](../tests/test_hostile_proc_snooping.rs) |
| **#8** | FD lifetime and process crash bounds | Child exit codes (0, 42), crash handling, early close, and descriptor cleanup | [`tests/test_fd_lifecycle_crash.rs`](../tests/test_fd_lifecycle_crash.rs) |
| **#9** | Continuous coverage-guided fuzzing | Dedicated GitHub Actions nightly workflow for continuous parser fuzzing | [`.github/workflows/nightly-fuzz.yml`](../.github/workflows/nightly-fuzz.yml) |
| **#10** | Permanent regression corpus | Byte-level regression corpus runner in standard CI | [`tests/regressions/`](../tests/regressions/), [`tests/test_regression_corpus.rs`](../tests/test_regression_corpus.rs) |
| **#11** | Power-loss & crash durability testing | Write $\to$ fsync $\to$ rename $\to$ crash $\to$ restart verification across 14 state boundaries | [`tests/test_sigkill_crash_injection.rs`](../tests/test_sigkill_crash_injection.rs), [`tests/test_durability.rs`](../tests/test_durability.rs) |
| **#12** | Large-file interrupted streaming | 4 MiB stream killed in-flight with recursive forensic canary disk sweeps | [`tests/test_large_file_crash_spool.rs`](../tests/test_large_file_crash_spool.rs) |
| **#13** | Strict 3-tier submodule hierarchy | Strict parent $\to$ child $\to$ grandchild hierarchy testing with assertion rigor | [`tests/test_strict_submodules_matrix.rs`](../tests/test_strict_submodules_matrix.rs) |
| **#14** | Expanded 3-way merge matrix | 18-case merge matrix: non-overlapping, comments, quotes, JSON, conflict markers | [`tests/test_deep_merge_matrix_expanded.rs`](../tests/test_deep_merge_matrix_expanded.rs) |
| **#15** | Historical revocation semantics | Alice, Bob, Charlie multi-generation epoch access and forward-secrecy proofs | [`tests/test_historical_revocation_epochs.rs`](../tests/test_historical_revocation_epochs.rs) |
| **#16** | Hardware-token failure matrix | Missing, corrupt, truncated, and empty identity streams fail closed | [`tests/test_hardware_token_failure_matrix.rs`](../tests/test_hardware_token_failure_matrix.rs) |
| **#17** | Memory-hygiene under crash & errors | Forensic canary sweeps and zero secret retention in core dumps / crash files | [`tests/test_large_file_crash_spool.rs`](../tests/test_large_file_crash_spool.rs), [`tests/test_memory_hygiene.rs`](../tests/test_memory_hygiene.rs) |
| **#18** | Performance benchmarking | Throughput (MB/s) and latency microbenchmarks across payload sizes | [`benches/bench_main.rs`](../benches/bench_main.rs) |
| **#19** | Cross-platform adversarial testing | Active symlink and junction racing on NTFS and POSIX | [`tests/test_toctou_racing.rs`](../tests/test_toctou_racing.rs), [`tests/test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) |
| **#20** | Advanced cache race testing | Cache hit $\times$ rekey races, atomic persistence, and cache corruption recovery | [`tests/test_advanced_cache_races.rs`](../tests/test_advanced_cache_races.rs) |
| **#21** | Expanded invariant framework | Continuous evaluation of Invariants A through G after every operation | [`tests/common/invariants.rs`](../tests/common/invariants.rs) |
| **#22** | Configurable random-run depth | Seedable PRNG (`GIT_AGECRYPT_SEED`) with configurable operation count (`GIT_AGECRYPT_OPS`) | [`tests/test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) |
| **#23** | Documentation & specification tightening | Formal specification of security model, threat boundaries, and revocation guarantees | [`docs/spec-guarantees.md`](spec-guarantees.md) |
| **#24** | Dependency & unsafe hardening | Documented `unsafe` blocks for `openat`, `TerminateProcess`, and `prctl` | [`src/git.rs`](../src/git.rs), [`src/main.rs`](../src/main.rs) |
| **#25** | CI matrix & nightly automation | Multi-OS testing matrix + dedicated nightly deep fuzz workflow | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.github/workflows/nightly-fuzz.yml`](../.github/workflows/nightly-fuzz.yml) |

---

## 2. Invariants A through G Verification Mapping

- **Invariant A (Working Tree Plaintext $\iff$ Git Objects Ciphertext):** Verified continuously across [`test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs), [`test_stateful_random_harness.rs`](../tests/test_stateful_random_harness.rs), and [`test_deep_merge_matrix_expanded.rs`](../tests/test_deep_merge_matrix_expanded.rs).
- **Invariant B (Crash Durability & Fail-Closed Flush):** Verified across all 14 crash points in [`test_sigkill_crash_injection.rs`](../tests/test_sigkill_crash_injection.rs) and [`test_durability.rs`](../tests/test_durability.rs).
- **Invariant C (Cross-Ring Isolation):** Verified by [`test_generative_ring_dag.rs`](../tests/test_generative_ring_dag.rs) and [`test_scoped_rings.rs`](../tests/test_scoped_rings.rs).
- **Invariant D (Path Traversal & Device Name Safety):** Verified by [`test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) and [`test_filesystem_security.rs`](../tests/test_filesystem_security.rs).
- **Invariant E (Zero-Plaintext Memory Hygiene):** Verified by [`test_memory_hygiene.rs`](../tests/test_memory_hygiene.rs) and [`test_run_fd_isolation.rs`](../tests/test_run_fd_isolation.rs).
- **Invariant F (Idempotent Git State Machine):** Verified by [`test_generative_shadow_state_machine.rs`](../tests/test_generative_shadow_state_machine.rs) and [`test_stateful_git.rs`](../tests/test_stateful_git.rs).
- **Invariant G (Zero Plaintext Canary Leaks):** Verified by [`test_large_file_crash_spool.rs`](../tests/test_large_file_crash_spool.rs), [`test_forensic_canary_sweeps.rs`](../tests/test_forensic_canary_sweeps.rs), and continuous state machine sweeps.
