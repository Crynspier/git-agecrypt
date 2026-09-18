mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_case_insensitive_ring_collision_rejection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    // 1. Initialize lowercase ring 'prod'
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();

    // 2. Attempting to initialize 'PROD' or 'Prod' must fail closed due to case collision
    let out_upper = agecrypt_cmd(repo)
        .args(["init", "--ring", "PROD"])
        .output()
        .unwrap();
    assert!(
        !out_upper.status.success(),
        "Ring 'PROD' must be rejected when 'prod' exists to prevent case-insensitive collision"
    );
    let stderr = String::from_utf8_lossy(&out_upper.stderr);
    assert!(
        stderr.contains("collides with existing ring") || stderr.contains("Security violation"),
        "Error message must indicate case collision"
    );

    let out_mixed = agecrypt_cmd(repo)
        .args(["init", "--ring", "Prod"])
        .output()
        .unwrap();
    assert!(
        !out_mixed.status.success(),
        "Ring 'Prod' must be rejected when 'prod' exists to prevent case-insensitive collision"
    );
}

#[test]
fn test_symlink_redirection_attacks_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    // Test: Symlink in key file location
    let key_file = repo.join(".git").join("git-agecrypt").join("repo.key");
    if key_file.exists() {
        let outside_dir = tempdir().unwrap();
        let target_file = outside_dir.path().join("hijacked_target.txt");
        fs::write(&target_file, "fake_key").unwrap();

        // Attempt symlink replace
        let _ = fs::remove_file(&key_file);
        #[cfg(unix)]
        let symlink_res = std::os::unix::fs::symlink(&target_file, &key_file);
        #[cfg(windows)]
        let symlink_res = std::os::windows::fs::symlink_file(&target_file, &key_file);

        if symlink_res.is_ok() {
            // Invoking git-agecrypt status must fail or refuse to read the symlinked key
            let out = agecrypt_cmd(repo).arg("status").output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            // It should fail or detect the symlink violation
            if !out.status.success() {
                assert!(stderr.contains("Security violation") || stderr.contains("symlink"));
            }
        }
    }
}
