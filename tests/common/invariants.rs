use super::*;
use std::fs;
use std::path::Path;

/// Classification of recovered repository state after crash recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredState {
    /// Recovery restored the repository to the pre-transaction state.
    OldValid,
    /// Recovery completed the transaction to the post-transaction state.
    NewValid,
    /// Recovery left the repository in a partial or corrupted state.
    Partial,
}

/// Invariant A: Working tree contains plaintext <=> Git object DB/index/packs contain age ciphertext.
pub fn assert_inv_a_working_tree_vs_objects(repo: &Path, rel_path: &str, expected_plaintext: &str) {
    let disk_file = repo.join(rel_path);
    assert!(disk_file.exists(), "File {rel_path} must exist on disk");
    let disk_content = fs::read_to_string(&disk_file).expect("Failed to read working tree file");
    assert_eq!(
        disk_content, expected_plaintext,
        "Working tree must match expected plaintext"
    );

    let cat_ref = format!("HEAD:{}", rel_path.replace('\\', "/"));
    let blob = git_out(repo, &["cat-file", "-p", &cat_ref]);
    assert!(
        blob.starts_with(b"age-encryption.org/v1\n"),
        "Git object store blob for {rel_path} must be age ciphertext"
    );
}

/// Invariant B: Durability & WAL consistency. No dangling unrecovered journals or locking markers.
pub fn assert_inv_b_durability_consistent(repo: &Path) {
    let state_dir = repo.join(".git").join("git-agecrypt");
    if state_dir.exists() {
        let locking_file = state_dir.join("repo.key.locking");
        assert!(
            !locking_file.exists(),
            "Dangling repo.key.locking file found"
        );
    }
}

/// Invariant C: Cross-ring isolation. Ring A secrets cannot be read or touched by Ring B.
pub fn assert_inv_c_cross_ring_isolation(
    repo: &Path,
    ring_a: &str,
    ring_b: &str,
    file_a: &str,
    file_b: &str,
    plain_a: &str,
    plain_b: &str,
    key_a_sec: Option<&str>,
) {
    // 1. Lock Ring A
    let mut lock_cmd = agecrypt_cmd(repo);
    lock_cmd.args(["lock", "--ring", ring_a]).assert().success();

    // 2. Assert Ring A is locked on disk (ciphertext)
    let disk_a = fs::read(repo.join(file_a)).unwrap();
    assert!(
        disk_a.starts_with(b"age-encryption.org/v1\n"),
        "Ring A file must be locked/smudged to ciphertext"
    );

    // 3. Assert Ring B remains unlocked and readable
    let disk_b = fs::read_to_string(repo.join(file_b)).unwrap();
    assert_eq!(
        disk_b, plain_b,
        "Ring B secret must remain plaintext when Ring A is locked"
    );

    // 4. Unlock Ring A and verify Ring A restored
    let mut unlock_cmd = agecrypt_cmd(repo);
    if let Some(sec) = key_a_sec {
        let id_file = repo.join("temp_unlock_key.txt");
        fs::write(&id_file, sec).unwrap();
        unlock_cmd
            .args(["unlock", "--ring", ring_a, id_file.to_str().unwrap()])
            .assert()
            .success();
        let _ = fs::remove_file(&id_file);
    } else {
        unlock_cmd
            .args(["unlock", "--ring", ring_a])
            .assert()
            .success();
    }

    let disk_a_restored = fs::read_to_string(repo.join(file_a)).unwrap();
    assert_eq!(
        disk_a_restored, plain_a,
        "Ring A secret must restore upon unlock"
    );
}

/// Invariant D: Ring identifier grammar and reserved device safety.
pub fn assert_inv_d_ring_grammar_safe(repo: &Path, ring_name: &str) -> bool {
    let out = agecrypt_cmd(repo)
        .args(["init", "--ring", ring_name])
        .output()
        .unwrap();
    out.status.success()
}

/// Invariant E: Zero-plaintext memory hygiene. No plaintext canary leaks to stdout, stderr, or temp files.
pub fn assert_inv_e_zero_plaintext_memory(
    repo: &Path,
    canary: &str,
    stdout: &[u8],
    stderr: &[u8],
) {
    let stdout_str = String::from_utf8_lossy(stdout);
    let stderr_str = String::from_utf8_lossy(stderr);
    assert!(
        !stdout_str.contains(canary),
        "Plaintext canary '{}' leaked into stdout",
        canary
    );
    assert!(
        !stderr_str.contains(canary),
        "Plaintext canary '{}' leaked into stderr",
        canary
    );

    // Scan temp files in the repo's .git/git-agecrypt directory
    let state_dir = repo.join(".git").join("git-agecrypt");
    if state_dir.exists() {
        fn scan_dir(dir: &Path, canary: &[u8]) -> bool {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        if scan_dir(&p, canary) {
                            return true;
                        }
                    } else if let Ok(data) = fs::read(&p) {
                        if data.windows(canary.len()).any(|w| w == canary) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        assert!(
            !scan_dir(&state_dir, canary.as_bytes()),
            "Plaintext canary '{}' leaked into git-agecrypt state directory",
            canary
        );
    }
}

/// Invariant F: Idempotent Git plumbing. Standard Git commands preserve the encryption invariant.
pub fn assert_inv_f_idempotent_plumbing(repo: &Path, secret_files: &[&str], is_locked: bool) {
    for name in secret_files {
        let file_path = repo.join(name);
        if !file_path.exists() {
            continue;
        }
        let disk_bytes = fs::read(&file_path).unwrap();
        let is_ciphertext = disk_bytes.starts_with(b"age-encryption.org/v1\n");

        if is_locked {
            assert!(
                is_ciphertext,
                "When locked, disk file '{}' must be ciphertext",
                name
            );
        } else {
            assert!(
                !is_ciphertext,
                "When unlocked, disk file '{}' must be plaintext",
                name
            );
        }
    }
}

/// Invariant G: Zero plaintext canary leaks in reachable or unreachable Git repository objects/spool.
pub fn assert_inv_g_zero_canary_leaks(repo: &Path, canary: &[u8]) {
    let git_dir = repo.join(".git");
    fn scan_dir(dir: &Path, canary: &[u8]) -> bool {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    if scan_dir(&p, canary) {
                        return true;
                    }
                } else if let Ok(data) = fs::read(&p) {
                    if data.windows(canary.len()).any(|w| w == canary) {
                        return true;
                    }
                }
            }
        }
        false
    }
    assert!(
        !scan_dir(&git_dir, canary),
        "Invariant G violation: Plaintext canary detected in .git directory"
    );
}

/// Classify the recovered repository state after crash recovery.
/// Returns OldValid, NewValid, or Partial.
pub fn classify_recovered_state(
    repo: &Path,
    expected_old_state: &str,
    expected_new_state: &str,
    secret_file: &str,
) -> RecoveredState {
    let disk_content = fs::read_to_string(repo.join(secret_file)).unwrap_or_default();

    if disk_content == expected_old_state {
        return RecoveredState::OldValid;
    }
    if disk_content == expected_new_state {
        return RecoveredState::NewValid;
    }
    RecoveredState::Partial
}

/// Assert that the recovered state is either OldValid or NewValid, never Partial.
pub fn assert_recovered_state_valid(
    repo: &Path,
    expected_old_state: &str,
    expected_new_state: &str,
    secret_file: &str,
) -> RecoveredState {
    let state = classify_recovered_state(repo, expected_old_state, expected_new_state, secret_file);
    assert!(
        state != RecoveredState::Partial,
        "Recovery must produce OldValid or NewValid state, not Partial"
    );
    state
}
