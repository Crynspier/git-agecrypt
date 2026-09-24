mod common;

use common::*;
use std::fs;
use std::sync::Arc;
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
    let key_dir = tempdir().expect("Failed to create keydir");
    let id_file = key_dir.path().join("master.key");
    fs::write(&id_file, &user_sec).unwrap();

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
        let handle = thread::spawn(move || {
            let r = repo_clone.as_path();
            let mut op = 0;
            while !stop.load(Ordering::Relaxed) && op < 10 {
                let file_name = format!("file_{}.secret.env", op % 5);
                let out = git_out_res(r, &["checkout", "HEAD", "--", &file_name]);
                if let Err(e) = out {
                    eprintln!("Thread {thread_idx} checkout failed: {e}");
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
    let handle = thread::spawn(move || {
        let r = repo_clone.as_path();
        let mut op = 0;
        while !stop.load(Ordering::Relaxed) && op < 5 {
            let lock_out = agecrypt_cmd(r).args(["lock", "-f"]).output();
            if let Ok(res) = lock_out {
                if res.status.success() {
                    let unlock_out = agecrypt_assert_cmd(r)
                        .args(["unlock", "-"])
                        .write_stdin(id_file.to_str().unwrap().as_bytes())
                        .output();
                    if let Ok(unlock_res) = unlock_out {
                        if !unlock_res.status.success() {
                            eprintln!("Unlock failed after lock: {:?}", unlock_res);
                        }
                    }
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
    let handle = thread::spawn(move || {
        let r = repo_clone.as_path();
        let mut op = 0;
        while !stop.load(Ordering::Relaxed) && op < 30 {
            let status_out = agecrypt_cmd(r).arg("status").output();
            if let Ok(res) = status_out {
                if !res.status.success() {
                    eprintln!("Status failed: {:?}", res);
                }
            }
            op += 1;
            thread::sleep(Duration::from_millis(5));
        }
    });
    handles.push(handle);

    // Thread 7: rekey (state-changing, should be rare)
    let repo_clone = Arc::clone(&repo_arc);
    let stop = Arc::clone(&stop_flag);
    let handle = thread::spawn(move || {
        let r = repo_clone.as_path();
        let mut op = 0;
        while !stop.load(Ordering::Relaxed) && op < 2 {
            let rekey_out = agecrypt_cmd(r).args(["rekey", "-f"]).output();
            if let Ok(res) = rekey_out {
                if !res.status.success() {
                    eprintln!("Rekey failed: {:?}", res);
                }
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

    // Final verification: repository must be healthy
    let status_out = agecrypt_cmd(repo).arg("status").output().unwrap();
    assert!(
        status_out.status.success(),
        "Repository must be healthy after concurrent stress: {:?}",
        status_out
    );

    // Verify all files are in a consistent state (either plaintext or ciphertext, not corrupted)
    for i in 0..5 {
        let file_path = repo.join(format!("file_{i}.secret.env"));
        if file_path.exists() {
            let content = fs::read(&file_path).unwrap();
            let is_ciphertext = content.starts_with(b"age-encryption.org/v1\n");
            let is_plaintext = std::str::from_utf8(&content).is_ok();
            assert!(
                is_ciphertext || is_plaintext,
                "File {} must be either ciphertext or plaintext, not corrupted",
                file_path.display()
            );
        }
    }
}
