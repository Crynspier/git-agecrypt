mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_large_file_streaming_roundtrip() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    // 4 MiB payload exceeding the 1 MiB in-memory spool threshold
    let secret_file = repo.join("large_dataset.secret.env");
    let chunk = "LARGE_STREAMING_SECRET_CHUNK_0123456789abcdef\n";
    let repeat_count = (4 * 1024 * 1024) / chunk.len();
    let payload = chunk.repeat(repeat_count);

    fs::write(&secret_file, &payload).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit 4 MiB secret"]);

    // Verify git object contains age ciphertext
    let blob = git_out(repo, &["cat-file", "blob", ":large_dataset.secret.env"]);
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));

    // Verify spool directory is clean
    let spool_dir = repo.join(".git").join("git-agecrypt").join("spool");
    if spool_dir.exists() {
        let count = fs::read_dir(&spool_dir).map(|e| e.count()).unwrap_or(0);
        assert_eq!(count, 0, "Spool directory must have 0 lingering temp files");
    }

    // Checkout and verify decrypted data matches exact payload
    run_git(
        repo,
        &["checkout", "HEAD", "--", "large_dataset.secret.env"],
    );
    let read_back = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(read_back.len(), payload.len());
    assert_eq!(read_back, payload);
}

#[test]
fn test_large_file_lock_and_unlock() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "user"]);
    add_cmd.assert().success();

    let secret_file = repo.join("big.secret.env");
    let chunk = "KEY_VALUE_LINE_ABCDEF_0123456789\n";
    let repeat_count = (2 * 1024 * 1024) / chunk.len();
    let payload = chunk.repeat(repeat_count);
    fs::write(&secret_file, &payload).unwrap();

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit 2 MiB secret"]);

    // Lock repository
    agecrypt_cmd(repo).arg("lock").assert().success();
    let locked_bytes = fs::read(&secret_file).unwrap();
    assert!(locked_bytes.starts_with(b"age-encryption.org/v1\n"));

    // Unlock repository
    let id_file = repo.join("user.key");
    fs::write(&id_file, &secret_key).unwrap();
    let mut unlock_cmd = agecrypt_cmd(repo);
    unlock_cmd
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();
    let _ = fs::remove_file(&id_file);

    let restored = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(restored.len(), payload.len());
    assert_eq!(restored, payload);
}
