# High-Assurance Verification & Invariant Mapping Matrix (v0.4.0)

This document provides the exhaustive, bi-directional verification matrix mapping every architectural invariant and critique item to its concrete implementation and automated test suites in `git-agecrypt`.

---

## 1. Critique Items Verification Matrix

| # | Critique Domain | Architectural Implementation | Primary Automated Test Suite |
|---|---|---|---|
| **#1** | Randomized Git state-machine harness | In-memory shadow model + seeded PRNG (`rand_chacha`) | [`tests/test_stateful_random_harness.rs`](../tests/test_stateful_random_harness.rs) |
| **#2** | Ring $\times$ generation $\times$ Git operations | Multi-tier ring envelope routing + independent key rotation | [`tests/test_combinatorial_rings_generations.rs`](../tests/test_combinatorial_rings_generations.rs) |
| **#3** | Real in-flight kill point testing | Atomic staging + WAL journal deterministic recovery (`recover_interrupted_transaction`) | [`tests/test_fault_injection_kill.rs`](../tests/test_fault_injection_kill.rs) |
| **#4** | Filesystem / crash durability testing | POSIX directory `sync_dir` + `sync_all` on temporary files before rename | [`tests/test_durability.rs`](../tests/test_durability.rs), [`tests/test_fault_injection_kill.rs`](../tests/test_fault_injection_kill.rs) |
| **#5** | Complete `run --fd` security lifecycle | Parent `MFD_CLOEXEC` + child `pre_exec` unset + exit code propagation | [`tests/test_run_fd_isolation.rs`](../tests/test_run_fd_isolation.rs), [`tests/test_run_fd.rs`](../tests/test_run_fd.rs) |
| **#6** | `/proc` & memory inspection boundary | `libc::prctl(PR_SET_DUMPABLE, 0)` in child `pre_exec` | [`src/main.rs`](../src/main.rs), [`tests/test_run_fd_isolation.rs`](../tests/test_run_fd_isolation.rs) |
| **#7** | Mixed-operation concurrency stress | Parallel thread workers executing clean, smudge, and cache reads | [`tests/test_mixed_concurrency_stress.rs`](../tests/test_mixed_concurrency_stress.rs) |
| **#8** | Cache race & stress testing | Keyed HMAC validation with automatic eviction of stale entries | [`tests/test_mixed_concurrency_stress.rs`](../tests/test_mixed_concurrency_stress.rs), [`tests/test_concurrency.rs`](../tests/test_concurrency.rs) |
| **#9** | Symlink / TOCTOU redirection attacks | `ensure_not_symlink_or_reparse` validates all sensitive paths | [`tests/test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) |
| **#10** | Cross-platform case-insensitive collisions | `check_ring_case_collision` blocks case-variant collisions (`prod` vs `PROD`) | [`tests/test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) |
| **#11** | Deep merge truth-table matrix | 3-way semantic merge driver with comment, unicode, and duplicate key checks | [`tests/test_deep_merge_matrix.rs`](../tests/test_deep_merge_matrix.rs) |
| **#12** | Multi-generation branch DAG topology | Rekey tracking across forked DAG branches and cross-branch merges | [`tests/test_combinatorial_rings_generations.rs`](../tests/test_combinatorial_rings_generations.rs), [`tests/test_rekey_chains.rs`](../tests/test_rekey_chains.rs) |
| **#13** | Revocation across complex histories | Epoch-based recipient envelope rotation with historical commit access | [`tests/test_revocation_history.rs`](../tests/test_revocation_history.rs) |
| **#14** | Submodule recursive hierarchy | Independent keys and filter drivers across nested submodules | [`tests/test_submodule_recursion.rs`](../tests/test_submodule_recursion.rs), [`tests/test_submodules_worktrees.rs`](../tests/test_submodules_worktrees.rs) |
| **#15** | Large-file interruption testing | Two-tier spooling (> 1 MiB spills to disk in 64 KiB streaming chunks) | [`tests/test_forensic_canary_sweeps.rs`](../tests/test_forensic_canary_sweeps.rs), [`tests/test_large_files.rs`](../tests/test_large_files.rs) |
| **#16** | Plaintext temp file forensic sweeps | Recursive disk scan across `.git/`, spool, and system temp | [`tests/test_forensic_canary_sweeps.rs`](../tests/test_forensic_canary_sweeps.rs) |
| **#17** | Error-path secret leakage prevention | Error formatting audits; raw secrets are never formatted into errors | [`tests/test_adversarial_harness.rs`](../tests/test_adversarial_harness.rs) |
| **#18** | Hardware-token failure matrix | Deterministic fail-closed behavior on missing, corrupt, or wrong keys | [`tests/test_hardware_token_matrix.rs`](../tests/test_hardware_token_matrix.rs) |
| **#19** | Proper fuzzing campaign | Proptest property-based fuzzing of clean, smudge, and merge parsers | [`src/crypto.rs`](../src/crypto.rs), [`src/merge.rs`](../src/merge.rs), [`tests/test_fuzz_boundaries.rs`](../tests/test_fuzz_boundaries.rs) |
| **#20** | Stateful fuzzing of application | Generative random operation loop comparing against shadow state | [`tests/test_stateful_random_harness.rs`](../tests/test_stateful_random_harness.rs) |
| **#21** | Declarative invariant framework | Formal invariant assertion suite (`assert_inv_a` through `assert_inv_f`) | [`tests/common/invariants.rs`](../tests/common/invariants.rs) |
| **#22** | Performance benchmarking | Keyed HMAC-SHA256 cache hits eliminate ChaCha20-Poly1305 re-encryption | [`src/crypto.rs`](../src/crypto.rs), [`tests/test_durability.rs`](../tests/test_durability.rs) |
| **#23** | Memory lifetime & hygiene | Sensitive buffers wrapped in `Zeroizing<Vec<u8>>` wiped on drop | [`src/crypto.rs`](../src/crypto.rs), [`tests/test_memory_hygiene.rs`](../tests/test_memory_hygiene.rs) |
| **#24** | Dependency & unsafe-code audit | Audited `unsafe` blocks for `memfd_create`, `libc::close`, and `prctl` | [`src/main.rs`](../src/main.rs), [`src/git.rs`](../src/git.rs) |
| **#25** | CI matrix expansion | Multi-platform CI runners (Ubuntu, macOS ARM64/x86_64, Windows) | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| **#26** | Release regression corpus | 117-test regression suite covering historical boundary conditions | [`tests/integration_tests.rs`](../tests/integration_tests.rs) |
| **#27** | Documentation $\leftrightarrow$ Implementation sync | Formal invariants A–F and architecture guides verified by tests | [`docs/security-model.md`](security-model.md), [`docs/internals.md`](internals.md) |

---

## 2. Invariants A through F Verification Mapping

- **Invariant A (Working Tree Plaintext $\iff$ Git Objects Ciphertext):** Verified continuously by [`assert_invariant_a`](../tests/common/mod.rs) across [`test_stateful_random_harness.rs`](../tests/test_stateful_random_harness.rs), [`test_stateful_git.rs`](../tests/test_stateful_git.rs), and [`test_adversarial_harness.rs`](../tests/test_adversarial_harness.rs).
- **Invariant B (Crash Durability & Fail-Closed Flush):** Verified by [`test_durability.rs`](../tests/test_durability.rs) and [`test_fault_injection_kill.rs`](../tests/test_fault_injection_kill.rs).
- **Invariant C (Cross-Ring Isolation):** Verified by [`test_scoped_rings.rs`](../tests/test_scoped_rings.rs) and [`test_combinatorial_rings_generations.rs`](../tests/test_combinatorial_rings_generations.rs).
- **Invariant D (Path Traversal & Device Name Safety):** Verified by [`test_case_collision_and_symlinks.rs`](../tests/test_case_collision_and_symlinks.rs) and [`test_filesystem_security.rs`](../tests/test_filesystem_security.rs).
- **Invariant E (Zero-Plaintext Memory Hygiene):** Verified by [`test_memory_hygiene.rs`](../tests/test_memory_hygiene.rs) and [`test_run_fd_isolation.rs`](../tests/test_run_fd_isolation.rs).
- **Invariant F (Idempotent Git State Machine):** Verified by [`test_stateful_random_harness.rs`](../tests/test_stateful_random_harness.rs) and [`test_stateful_git.rs`](../tests/test_stateful_git.rs).
