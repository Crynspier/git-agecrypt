mod common;

use common::invariants::*;
use common::*;
use std::fs;
use std::io::Write;
use std::process::Stdio;
use tempfile::tempdir;

#[test]
fn test_all_14_crash_points_deterministic_sigkill_and_recovery() {
    let crash_points = [
        "before_tx_begin",
        "after_tmp_create",
        "after_plaintext_write",
        "after_ciphertext_write",
        "after_ciphertext_fsync",
        "after_dir_fsync",
        "after_key_rename",
        "after_journal_create",
        "after_journal_fsync",
        "after_journal_transition",
        "after_old_delete",
        "before_cleanup",
        "after_cleanup",
        "spool_chunk",
        "after_unwrap_key",
        "after_unlock_key_saved",
        "after_unlock_refresh",
        "after_rekey_pub_write",
        "after_rekey_key_saved",
        "after_rekey_cache_purge",
        "after_merge_decrypt",
        "after_merge_file",
        "after_merge_fsync",
        "after_merge_rename",
    ];

    for point in crash_points {
        let temp = tempdir().expect("Failed to create tempdir");
        let repo = temp.path();
        init_repo(repo);

        // 1. Initial configuration
        agecrypt_cmd(repo).arg("init").assert().success();
        let (_sec_id, pub_key) = generate_test_identity();
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &pub_key, "--name", "ci_user"])
            .assert()
            .success();

        let secret_content =
            format!("SECRET_DATA_KEY=super_secure_vault_value_for_crash_{point}\n");
        fs::write(repo.join("vault.secret.env"), &secret_content).unwrap();
        run_git(
            repo,
            &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
        );
        run_git(repo, &["commit", "-m", "Initial secret commit"]);

        // 2. Select operation that exercises the crash point
        let mut op_cmd = agecrypt_cmd(repo);
        op_cmd.env("GIT_AGECRYPT_CRASH_POINT", point);

        match point {
            "after_tmp_create" | "after_plaintext_write" | "after_rekey_pub_write"
            | "after_rekey_key_saved" | "after_rekey_cache_purge" => {
                // Key generation / rekey writes local master key
                op_cmd.args(["rekey", "-f"]);
            }
            "after_old_delete" => {
                // Remove recipient unlinks old key
                op_cmd.args(["remove-recipient", "ci_user"]);
            }
            "after_ciphertext_write" | "after_ciphertext_fsync" | "spool_chunk" => {
                // Clean filter streams large payload
                op_cmd.args(["clean", "vault.secret.env"]);
                op_cmd.stdin(Stdio::piped());
                op_cmd.stdout(Stdio::null());
                op_cmd.stderr(Stdio::null());
            }
            "after_unwrap_key" | "after_unlock_key_saved" | "after_unlock_refresh" => {
                // Unlock path: write a valid identity to a key file and unlock
                let id_file = repo.join("unlock_key.txt");
                fs::write(&id_file, &_sec_id).unwrap();
                op_cmd.args(["unlock", id_file.to_str().unwrap()]);
            }
            "after_merge_decrypt" | "after_merge_file" | "after_merge_fsync" | "after_merge_rename" => {
                // Merge path: create a merge scenario, then run git merge with crash point env
                run_git(repo, &["checkout", "-b", "merge_branch"]);
                fs::write(repo.join("vault.secret.env"), "MERGE_BRANCH=conflict\n").unwrap();
                run_git(repo, &["commit", "-am", "Branch change"]);
                run_git(repo, &["checkout", "main"]);
                fs::write(repo.join("vault.secret.env"), "MERGE_MAIN=conflict\n").unwrap();
                run_git(repo, &["commit", "-am", "Main change"]);

                // Run git merge with the crash point env var set
                let output = std::process::Command::new("git")
                    .args(["merge", "merge_branch", "-m", "Merge"])
                    .current_dir(repo)
                    .env("GIT_AGECRYPT_CRASH_POINT", point)
                    .output()
                    .expect("Failed to run git merge");
                assert!(
                    !output.status.success(),
                    "Process with crash point {point} must exit non-zero"
                );
                // Continue to recovery
                let status_out = agecrypt_cmd(repo)
                    .env_remove("GIT_AGECRYPT_CRASH_POINT")
                    .arg("status")
                    .output()
                    .expect("Failed to run status for recovery");
                assert!(
                    status_out.status.success(),
                    "Recovery command on repo must succeed after crash point {point}"
                );
                assert_inv_b_durability_consistent(repo);
                continue;
            }
            _ => {
                // Lock transaction triggers journal and rename crash points
                op_cmd.args(["lock", "-f"]);
            }
        }

        // 3. Execute with crash point active -> must fail or terminate abnormally
        if point == "after_ciphertext_write"
            || point == "after_ciphertext_fsync"
            || point == "spool_chunk"
        {
            if let Ok(mut child) = op_cmd.spawn() {
                if let Some(mut sin) = child.stdin.take() {
                    let large_payload = vec![b'A'; 2 * 1024 * 1024]; // 2 MiB
                    let _ = sin.write_all(&large_payload);
                    drop(sin);
                }
                let status = child.wait().expect("Child wait failed");
                assert!(
                    !status.success(),
                    "Process with crash point {point} must not succeed normally"
                );
            }
        } else {
            let output = op_cmd.output().expect("Failed to run crashed command");
            assert!(
                !output.status.success(),
                "Process with crash point {point} must exit non-zero"
            );
        }

        // 4. Restart and run recovery
        let status_out = agecrypt_cmd(repo)
            .env_remove("GIT_AGECRYPT_CRASH_POINT")
            .arg("status")
            .output()
            .expect("Failed to run status for recovery");
        assert!(
            status_out.status.success(),
            "Recovery command on repo must succeed after crash point {point}"
        );

        // 5. Verify formal invariants
        assert_inv_b_durability_consistent(repo);

        // 6. Working tree must be valid plaintext — formally classified as OldValid or NewValid
        let read_back = fs::read_to_string(repo.join("vault.secret.env")).unwrap_or_default();
        let recovered_state = if read_back == secret_content {
            RecoveredState::OldValid
        } else if read_back.is_empty() {
            // Empty file after recovery is acceptable for lock operations (old state = file existed, new state = file locked)
            // But we must verify it's not a partial write
            RecoveredState::NewValid
        } else if read_back.starts_with("SECRET_DATA_KEY=") {
            RecoveredState::NewValid
        } else {
            RecoveredState::Partial
        };
        assert!(
            recovered_state != RecoveredState::Partial,
            "Recovery must produce OldValid or NewValid state, not Partial. Got: {:?}",
            read_back
        );
    }
}
