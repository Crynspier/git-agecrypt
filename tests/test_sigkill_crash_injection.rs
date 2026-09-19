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
            "after_tmp_create" | "after_plaintext_write" => {
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

        // 6. Working tree must be valid plaintext
        let read_back = fs::read_to_string(repo.join("vault.secret.env")).unwrap_or_default();
        assert!(
            read_back == secret_content
                || read_back.is_empty()
                || read_back.starts_with("SECRET_DATA_KEY="),
            "Working tree secret after recovery must not be corrupted: got '{read_back}'"
        );
    }
}
