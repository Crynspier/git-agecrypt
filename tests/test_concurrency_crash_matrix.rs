mod common;

use common::invariants::*;
use common::*;
use std::fs;
use std::io::Write;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

/// Concurrency + crash injection: races state-changing operations against crash points.
/// Catches bugs where a race plus partially written state plus recovery interact badly.
#[test]
fn test_concurrency_crash_injection_matrix() {
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

    // Each crash point uses an isolated repository, so run the matrix in
    // parallel. This keeps the test's coverage while avoiding a long serial
    // wall-clock delay from repeatedly starting Git and git-agecrypt.
    thread::scope(|scope| {
        for point in crash_points {
            scope.spawn(move || {
                let temp = tempdir().expect("Failed to create tempdir");
                let repo_arc = Arc::new(temp.path().to_path_buf());
                let repo = repo_arc.as_path();
                init_repo(repo);

                agecrypt_cmd(repo).arg("init").assert().success();
                let (_sec_id, pub_key) = generate_test_identity();
                agecrypt_cmd(repo)
                    .args(["add-recipient", "-i", &pub_key, "--name", "crash_user"])
                    .assert()
                    .success();

                fs::write(
                    repo.join(".gitattributes"),
                    "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
                )
                .unwrap();

                let secret_content = format!("CRASH_CONCURRENT_SECRET=value_for_{point}\n");
                fs::write(repo.join("vault.secret.env"), &secret_content).unwrap();
                run_git(
                    repo,
                    &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
                );
                run_git(repo, &["commit", "-m", "Initial commit"]);

                // Track the two state-changing workers instead of sleeping for a fixed
                // interval. The old two-second delay was paid once per crash point even
                // after both workers had already exited, making this test look hung in
                // the full integration suite.
                let active_workers = Arc::new(AtomicUsize::new(2));
                let mut handles = Vec::new();

                // Worker 1: clean filter (may hit spool_chunk or ciphertext crash points)
                let repo_clone = Arc::clone(&repo_arc);
                let active = Arc::clone(&active_workers);
                let point_owned = point.to_string();
                let handle = thread::spawn(move || {
                    let r = repo_clone.as_path();
                    let mut clean = agecrypt_cmd(r);
                    clean.env("GIT_AGECRYPT_CRASH_POINT", &point_owned);
                    clean.args(["clean", "vault.secret.env"]);
                    clean.stdin(Stdio::piped());
                    clean.stdout(Stdio::null());
                    clean.stderr(Stdio::null());
                    if let Ok(mut child) = clean.spawn() {
                        if let Some(mut sin) = child.stdin.take() {
                            let payload = vec![b'A'; 2 * 1024 * 1024]; // 2 MiB
                            let _ = sin.write_all(&payload);
                            drop(sin);
                        }
                        let _ = child.wait();
                    }
                    active.fetch_sub(1, Ordering::Release);
                });
                handles.push(handle);

                // Worker 2: lock operation (may hit journal crash points)
                let repo_clone = Arc::clone(&repo_arc);
                let active = Arc::clone(&active_workers);
                let point_owned = point.to_string();
                let handle = thread::spawn(move || {
                    let r = repo_clone.as_path();
                    let mut lock = agecrypt_cmd(r);
                    lock.env("GIT_AGECRYPT_CRASH_POINT", &point_owned);
                    lock.args(["lock", "-f"]);
                    let _ = lock.output();
                    active.fetch_sub(1, Ordering::Release);
                });
                handles.push(handle);

                // Worker 3: status checks (read-only, should trigger recovery)
                let repo_clone = Arc::clone(&repo_arc);
                let active = Arc::clone(&active_workers);
                let handle = thread::spawn(move || {
                    let r = repo_clone.as_path();
                    while active.load(Ordering::Acquire) != 0 {
                        let _ = agecrypt_cmd(r).arg("status").output();
                        thread::sleep(Duration::from_millis(10));
                    }
                });
                handles.push(handle);

                for h in handles {
                    let _ = h.join();
                }

                // Recovery: run status to trigger recover_interrupted_transaction
                let recovery = agecrypt_cmd(repo)
                    .env_remove("GIT_AGECRYPT_CRASH_POINT")
                    .arg("status")
                    .output()
                    .expect("Failed to run recovery");

                // Verify repository is in a consistent state (not partial)
                assert!(
                    recovery.status.success(),
                    "Recovery must succeed after crash point {point}"
                );

                assert_inv_b_durability_consistent(repo);

                // Verify no plaintext canary leaks
                assert_inv_g_zero_canary_leaks(repo, b"CRASH_CONCURRENT_SECRET");
            });
        }
    });
}
