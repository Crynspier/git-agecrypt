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

#[test]
fn test_cache_hit_versus_rekey_race_and_corruption_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "cache_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    let secret_data = "SHARED_CACHE_SECRET=cache_race_secret_payload_12345\n";
    fs::write(repo.join("cached.secret.env"), secret_data).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "cached.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial cached secret commit"]);

    let repo_path = repo.to_path_buf();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_flag);

    // Worker thread 1: Repeatedly clean/smudge cached secret stream
    let clean_worker = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            let mut cmd = agecrypt_cmd(&repo_path);
            cmd.args(["clean", "cached.secret.env"]);
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            if let Ok(mut child) = cmd.spawn() {
                if let Some(mut sin) = child.stdin.take() {
                    let _ = sin.write_all(secret_data.as_bytes());
                }
                let _ = child.wait();
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    // Worker thread 2: Concurrently rotate master key (rekey)
    for i in 0..3 {
        let rekey_out = agecrypt_cmd(repo).args(["rekey", "-f"]).output();
        if let Ok(res) = rekey_out {
            assert!(
                res.status.success(),
                "Rekey must succeed even under concurrent clean load (iteration {})",
                i
            );
        }
        thread::sleep(Duration::from_millis(15));
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = clean_worker.join();

    // Invariant B check after concurrent races
    assert_inv_b_durability_consistent(repo);

    // Test cache corruption detection and recovery
    let cache_dir = repo.join(".git").join("git-agecrypt").join("cache");
    if cache_dir.exists() {
        if let Ok(entries) = fs::read_dir(&cache_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("age") {
                    // Corrupt cache file by writing invalid bytes
                    fs::write(&p, b"CORRUPTED_CACHE_CIPHERTEXT_HEADER").unwrap();
                    break;
                }
            }
        }

        // Clean filter encountering corrupted cache must detect, purge bad entry, and re-encrypt cleanly
        let mut clean_cmd = agecrypt_cmd(repo);
        clean_cmd.args(["clean", "cached.secret.env"]);
        clean_cmd.stdin(Stdio::piped());
        clean_cmd.stdout(Stdio::piped());
        let mut child = clean_cmd.spawn().unwrap();
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(secret_data.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "Clean filter must recover from corrupted cache file and succeed"
        );
        assert!(
            out.stdout.starts_with(b"age-encryption.org/v1\n"),
            "Output must be valid age ciphertext"
        );
    }
}
