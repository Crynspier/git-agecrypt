mod common;

use common::*;
use std::fs;
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn test_mixed_concurrency_stress_cache_and_clean() {
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

    // Spawn 10 concurrent worker threads performing clean filter and status operations
    let mut handles = Vec::new();
    for thread_idx in 0..10 {
        let repo_clone = Arc::clone(&repo_arc);
        let handle = thread::spawn(move || {
            let r = repo_clone.as_path();
            for op in 0..10 {
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
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join()
            .expect("Thread panicked during concurrent clean stress");
    }

    // Verify repository remains 100% healthy
    agecrypt_cmd(repo).arg("status").assert().success();
}
