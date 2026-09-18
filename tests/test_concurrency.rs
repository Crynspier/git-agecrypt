mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use std::io::Write;
use std::process::Stdio;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;

#[test]
fn test_concurrent_clean_cache_race() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_plain = b"CONCURRENT_SECRET_PAYLOAD_TEST=race_condition_proof_456\nPORT=8080\n";
    let thread_count = 8;
    let barrier = Arc::new(Barrier::new(thread_count));
    let repo_path = repo.to_path_buf();

    let mut handles = Vec::new();
    for i in 0..thread_count {
        let b = Arc::clone(&barrier);
        let r = repo_path.clone();
        let payload = secret_plain.to_vec();

        handles.push(thread::spawn(move || {
            b.wait();
            let mut cmd = agecrypt_cmd(&r);
            let mut child = cmd
                .arg("clean")
                .arg(format!("test_{i}.secret.env"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to spawn clean");

            child.stdin.as_mut().unwrap().write_all(&payload).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "Clean command failed in thread {i}");
            out.stdout
        }));
    }

    let mut ciphertexts = Vec::new();
    for handle in handles {
        let cipher = handle.join().expect("Thread panicked");
        assert!(
            cipher.starts_with(b"age-encryption.org/v1\n"),
            "Output must be valid age ciphertext"
        );
        ciphertexts.push(cipher);
    }

    // Every ciphertext produced by the concurrent clean commands must decrypt to the original plaintext
    for (i, cipher) in ciphertexts.iter().enumerate() {
        let mut smudge_cmd = agecrypt_cmd(repo);
        let mut child = smudge_cmd
            .arg("smudge")
            .arg(format!("test_{i}.secret.env"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        child.stdin.as_mut().unwrap().write_all(cipher).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, secret_plain);
    }
}

#[test]
fn test_concurrent_smudge_threads() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_plain = b"SHARED_SECRET_FOR_SMUDGE_CONCURRENCY=true\n";
    let mut clean_cmd = agecrypt_cmd(repo);
    let mut child = clean_cmd
        .arg("clean")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(secret_plain)
        .unwrap();
    let clean_out = child.wait_with_output().unwrap();
    let ciphertext = clean_out.stdout;

    let thread_count = 8;
    let barrier = Arc::new(Barrier::new(thread_count));
    let repo_path = repo.to_path_buf();

    let mut handles = Vec::new();
    for i in 0..thread_count {
        let b = Arc::clone(&barrier);
        let r = repo_path.clone();
        let cipher = ciphertext.clone();

        handles.push(thread::spawn(move || {
            b.wait();
            let mut cmd = agecrypt_cmd(&r);
            let mut child = cmd
                .arg("smudge")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to spawn smudge");

            child.stdin.as_mut().unwrap().write_all(&cipher).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "Smudge command failed in thread {i}");
            out.stdout
        }));
    }

    for handle in handles {
        let decrypted = handle.join().expect("Thread panicked");
        assert_eq!(decrypted, secret_plain);
    }
}

#[test]
fn test_refresh_lock_breaks_on_dead_pid() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let state_dir = repo.join(".git").join("git-agecrypt");
    let refresh_lock = state_dir.join("refresh.lock");

    // Create a stale lock file with an unreachable dead PID (e.g. 999999)
    fs::write(&refresh_lock, "999999\n").unwrap();

    // Set lock mtime to 1 hour ago
    let one_hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    filetime::set_file_mtime(&refresh_lock, one_hour_ago).unwrap();

    // Run status command: should automatically sweep and clear stale dead PID lock
    agecrypt_cmd(repo).arg("status").assert().success();

    assert!(
        !refresh_lock.exists(),
        "Stale lock must have been cleaned up"
    );
}
