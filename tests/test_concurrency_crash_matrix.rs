mod common;

use common::invariants::*;
use common::*;
use std::fs;
use std::io::Write;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

    for point in crash_points {
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

        let stop_flag = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        // Worker 1: clean filter (may hit spool_chunk or ciphertext crash points)
        let repo_clone = Arc::clone(&repo_arc);
        let stop = Arc::clone(&stop_flag);
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
            stop.store(true, Ordering::Relaxed);
        });
        handles.push(handle);

        // Worker 2: lock operation (may hit journal crash points)
        let repo_clone = Arc::clone(&repo_arc);
        let stop = Arc::clone(&stop_flag);
        let point_owned = point.to_string();
        let handle = thread::spawn(move || {
            let r = repo_clone.as_path();
            let mut lock = agecrypt_cmd(r);
            lock.env("GIT_AGECRYPT_CRASH_POINT", &point_owned);
            lock.args(["lock", "-f"]);
            let _ = lock.output();
            stop.store(true, Ordering::Relaxed);
        });
        handles.push(handle);

        // Worker 3: status checks (read-only, should trigger recovery)
        let repo_clone = Arc::clone(&repo_arc);
        let stop = Arc::clone(&stop_flag);
        let handle = thread::spawn(move || {
            let r = repo_clone.as_path();
            while !stop.load(Ordering::Relaxed) {
                let _ = agecrypt_cmd(r).arg("status").output();
                thread::sleep(Duration::from_millis(10));
            }
        });
        handles.push(handle);

        // Wait for crash to happen
        thread::sleep(Duration::from_secs(2));
        stop_flag.store(true, Ordering::Relaxed);

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
    }
}
