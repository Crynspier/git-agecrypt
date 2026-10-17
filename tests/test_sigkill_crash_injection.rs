mod common;

use common::invariants::*;
use common::*;
use std::fs;
use std::io::Write;
use std::process::{ExitStatus, Stdio};
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

fn assert_crash_termination(status: ExitStatus, point: &str) {
    assert!(
        !status.success(),
        "Process with crash point {point} must fail"
    );

    #[cfg(unix)]
    assert_eq!(
        status.signal(),
        Some(9),
        "Crash point {point} must terminate with SIGKILL"
    );

    #[cfg(windows)]
    assert_eq!(
        status.code(),
        Some(137),
        "Crash point {point} must terminate with the configured Windows exit code"
    );
}

#[test]
fn test_all_24_crash_points_deterministic_sigkill_and_recovery() {
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
            "after_tmp_create"
            | "after_plaintext_write"
            | "after_rekey_pub_write"
            | "after_rekey_key_saved"
            | "after_rekey_cache_purge" => {
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
            "after_merge_decrypt"
            | "after_merge_file"
            | "after_merge_fsync"
            | "after_merge_rename" => {
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
                    .env("GIT_AGECRYPT_CRASH_HOOKS_ARMED", "1")
                    .output()
                    .expect("Failed to run git merge");
                assert!(
                    !output.status.success(),
                    "Merge crash point {point} must not complete successfully"
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
            let mut child = op_cmd.spawn().expect("Failed to spawn crashed command");
            if let Some(mut sin) = child.stdin.take() {
                let large_payload = vec![b'A'; 2 * 1024 * 1024]; // 2 MiB
                let _ = sin.write_all(&large_payload);
                drop(sin);
            }
            let status = child.wait().expect("Child wait failed");
            assert_crash_termination(status, point);
        } else {
            let output = op_cmd.output().expect("Failed to run crashed command");
            assert_crash_termination(output.status, point);
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

        // 6. Recover the exact plaintext and reject partial or truncated state.
        // Re-materialize the committed blob through the normal smudge path before
        // asserting bytes; this also proves the Git object remains decryptable.
        if point != "after_old_delete" {
            run_git(repo, &["checkout", "HEAD", "--", "vault.secret.env"]);
        }
        if point != "after_old_delete" {
            let recovery_id = repo.join("recovery_key.txt");
            fs::write(&recovery_id, &_sec_id).unwrap();
            agecrypt_cmd(repo)
                .args(["unlock", recovery_id.to_str().unwrap()])
                .env_remove("GIT_AGECRYPT_CRASH_POINT")
                .assert()
                .success();
            run_git(repo, &["checkout", "HEAD", "--", "vault.secret.env"]);
        }
        let state =
            classify_recovered_state(repo, &secret_content, &secret_content, "vault.secret.env");
        if state == RecoveredState::Partial {
            let data = fs::read(repo.join("vault.secret.env")).unwrap();
            let is_complete_ciphertext = data.starts_with(b"age-encryption.org/v1\n")
                && data.windows(4).any(|window| window == b"--- ");
            assert!(
                is_complete_ciphertext
                    && matches!(
                        point,
                        "after_tmp_create"
                            | "after_plaintext_write"
                            | "after_rekey_pub_write"
                            | "after_rekey_key_saved"
                            | "after_rekey_cache_purge"
                    ),
                "Recovery produced partial state for crash point {point}: {data:?}"
            );
        } else {
            assert_eq!(
                state,
                RecoveredState::OldValid,
                "Recovery must restore the exact original plaintext for {point}"
            );
        }
    }
}
