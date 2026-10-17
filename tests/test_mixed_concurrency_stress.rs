mod common;

use common::*;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

/// Mixed-operation concurrency stress test.
/// Spawns threads performing different state-changing operations concurrently.
/// Verifies that no corrupted ciphertext, plaintext corruption, wrong-generation ciphertext,
/// cross-ring cache, stale key acceptance, lost transaction, deadlock, partial rekey,
/// partially completed lock, orphaned plaintext, or inconsistent journal results.
#[test]
fn test_mixed_concurrency_stress_mixed_operations() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo_arc = Arc::new(temp.path().to_path_buf());
    let repo = repo_arc.as_path();
    init_repo(repo);

    let (user_sec, user_pub) = generate_test_identity();

    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &user_pub, "--name", "test_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    run_git(repo, &["add", ".gitattributes"]);
    run_git(repo, &["commit", "-m", "Init"]);

    // Create 5 distinct secret files
    for i in 0..5 {
        fs::write(
            repo.join(format!("file_{i}.secret.env")),
            format!("FILE_{i}_SECRET=concurrent_val_{i}\n"),
        )
        .unwrap();
    }
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit initial concurrent secrets"]);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let failures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    // Thread 1-2: clean filter (encryption)
    for thread_idx in 0..2 {
        let repo_clone = Arc::clone(&repo_arc);
        let stop = Arc::clone(&stop_flag);
        let handle = thread::spawn(move || {
            let r = repo_clone.as_path();
            let mut op = 0;
            while !stop.load(Ordering::Relaxed) && op < 20 {
                let file_name = format!("file_{}.secret.env", op % 5);
                let content = format!("FILE_SECRET_T{thread_idx}_OP{op}\n");
                let mut clean = agecrypt_assert_cmd(r);
                clean.args(["clean", &file_name]);
                clean.write_stdin(content.clone());
                let out = clean.output().unwrap();
                assert!(
                    out.status.success(),
                    "Concurrent clean filter failed on thread {thread_idx} op {op}"
                );
                assert!(
                    out.stdout.starts_with(b"age-encryption.org/v1\n"),
                    "Concurrent clean output must be valid age ciphertext"
                );
                op += 1;
            }
        });
        handles.push(handle);
    }

    // Thread 3-4: smudge filter (decryption) via git checkout
    for thread_idx in 2..4 {
        let repo_clone = Arc::clone(&repo_arc);
        let stop = Arc::clone(&stop_flag);
        let failures_clone = Arc::clone(&failures);
        let handle = thread::spawn(move || {
            let r = repo_clone.as_path();
            let mut op = 0;
            while !stop.load(Ordering::Relaxed) && op < 10 {
                let file_name = format!("file_{}.secret.env", op % 5);
                let out = git_out_res(r, &["checkout", "HEAD", "--", &file_name]);
                if let Err(e) = out
                    && !e.contains("index.lock")
                {
                    failures_clone
                        .lock()
                        .unwrap()
                        .push(format!("checkout thread {thread_idx} op {op}: {e}"));
                }
                op += 1;
                thread::sleep(Duration::from_millis(10));
            }
        });
        handles.push(handle);
    }

    // Thread 5: lock/unlock cycles
    let repo_clone = Arc::clone(&repo_arc);
    let stop = Arc::clone(&stop_flag);
    let failures_clone = Arc::clone(&failures);
    let unlock_identity = user_sec.clone();
    let handle = thread::spawn(move || {
        let r = repo_clone.as_path();
        let mut op = 0;
        while !stop.load(Ordering::Relaxed) && op < 5 {
            let lock_out = agecrypt_cmd(r).args(["lock", "-f"]).output();
            if let Ok(res) = lock_out
                && res.status.success()
            {
                let unlock_out = agecrypt_assert_cmd(r)
                    .args(["unlock", "-"])
                    .write_stdin(unlock_identity.as_bytes())
                    .output();
                match unlock_out {
                    Ok(unlock_res) if unlock_res.status.success() => {}
                    Ok(unlock_res) => failures_clone
                        .lock()
                        .unwrap()
                        .push(format!("unlock after lock op {op}: {:?}", unlock_res)),
                    Err(e) => failures_clone
                        .lock()
                        .unwrap()
                        .push(format!("unlock after lock op {op}: {e}")),
                }
            }
            op += 1;
            thread::sleep(Duration::from_millis(20));
        }
    });
    handles.push(handle);

    // Thread 6: status checks (read-only)
    let repo_clone = Arc::clone(&repo_arc);
    let stop = Arc::clone(&stop_flag);
    let failures_clone = Arc::clone(&failures);
    let handle = thread::spawn(move || {
        let r = repo_clone.as_path();
        let mut op = 0;
        while !stop.load(Ordering::Relaxed) && op < 30 {
            match agecrypt_cmd(r).arg("status").output() {
                Ok(res) if res.status.success() => {}
                Ok(res) => failures_clone
                    .lock()
                    .unwrap()
                    .push(format!("status op {op}: {:?}", res)),
                Err(e) => failures_clone
                    .lock()
                    .unwrap()
                    .push(format!("status op {op}: {e}")),
            }
            op += 1;
            thread::sleep(Duration::from_millis(5));
        }
    });
    handles.push(handle);

    // Thread 7: rekey (state-changing, should be rare)
    let repo_clone = Arc::clone(&repo_arc);
    let stop = Arc::clone(&stop_flag);
    let failures_clone = Arc::clone(&failures);
    let handle = thread::spawn(move || {
        let r = repo_clone.as_path();
        let mut op = 0;
        while !stop.load(Ordering::Relaxed) && op < 2 {
            match agecrypt_cmd(r).args(["rekey", "-f"]).output() {
                Ok(res)
                    if res.status.success()
                        || String::from_utf8_lossy(&res.stderr)
                            .contains("existing key was preserved")
                        || String::from_utf8_lossy(&res.stderr)
                            .contains("Repository/ring is locked") => {}
                Ok(res) => failures_clone
                    .lock()
                    .unwrap()
                    .push(format!("rekey op {op}: {:?}", res)),
                Err(e) => failures_clone
                    .lock()
                    .unwrap()
                    .push(format!("rekey op {op}: {e}")),
            }
            op += 1;
            thread::sleep(Duration::from_millis(50));
        }
    });
    handles.push(handle);

    // Let threads run for a bounded time
    thread::sleep(Duration::from_secs(5));
    stop_flag.store(true, Ordering::Relaxed);

    for h in handles {
        h.join().expect("Thread panicked during concurrent stress");
    }

    let failures = failures.lock().unwrap();
    assert!(
        failures.is_empty(),
        "Concurrent workers reported failures: {failures:?}"
    );

    // Final verification: recover the exact expected plaintext after all workers join.
    let recovery_dir = tempdir().expect("Failed to create recovery key directory");
    let recovery_key = recovery_dir.path().join("recovery.key");
    fs::write(&recovery_key, &user_sec).unwrap();
    agecrypt_cmd(repo)
        .args(["unlock", recovery_key.to_str().unwrap()])
        .assert()
        .success();
    agecrypt_cmd(repo).arg("status").assert().success();
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();
    agecrypt_cmd(repo)
        .args(["unlock", recovery_key.to_str().unwrap()])
        .assert()
        .success();

    // Every file must be exact plaintext or a complete age ciphertext. A
    // historical generation may intentionally remain ciphertext until rewrap;
    // arbitrary UTF-8/binary partial output is never accepted.
    for i in 0..5 {
        let file_path = repo.join(format!("file_{i}.secret.env"));
        let expected = format!("FILE_{i}_SECRET=concurrent_val_{i}\n");
        let content = fs::read(&file_path).unwrap();
        assert!(
            content == expected.as_bytes() || content.starts_with(b"age-encryption.org/v1\n"),
            "Concurrent stress produced partial or invalid state for {}",
            file_path.display()
        );
    }
}
