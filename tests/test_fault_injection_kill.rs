mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_in_flight_termination_and_crash_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    let (user_sec, user_pub) = generate_test_identity();
    let key_dir = tempdir().expect("Failed to create keydir");
    let id_file = key_dir.path().join("test_user.key");
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

    let secret_file = repo.join("service.secret.env");
    fs::write(&secret_file, "CRITICAL_KEY=super_secret_payload\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Initial commit of critical secret"]);

    // 1. Simulate process kill during lock transaction:
    // Create a dangling .git/git-agecrypt/repo.key.locking file and corrupted lock.journal
    let state_dir = repo.join(".git").join("git-agecrypt");
    fs::create_dir_all(&state_dir).unwrap();

    let locking_file = state_dir.join("repo.key.locking");
    let key_file = state_dir.join("repo.key");

    // Move repo.key to repo.key.locking (as happens at the start of cmd_lock)
    if key_file.exists() {
        fs::rename(&key_file, &locking_file).unwrap();
    } else {
        fs::write(&locking_file, &user_sec).unwrap();
    }

    // Write a corrupted/interrupted WAL journal
    let journal_file = state_dir.join("lock.journal");
    fs::write(
        &journal_file,
        "service.secret.env\nINCOMPLETE_WRITE_TRUNCATED",
    )
    .unwrap();

    // 2. Invoke git-agecrypt status:
    // This triggers `recover_interrupted_transaction`, which detects repo.key.locking without repo.key,
    // restores repo.key, and recovers repository state cleanly.
    agecrypt_cmd(repo).arg("status").assert().success();

    // Verify repo.key was restored
    assert!(
        key_file.exists(),
        "Crash recovery must restore repo.key from interrupted transaction"
    );

    // 3. Verify normal locking and unlocking work after crash recovery
    agecrypt_cmd(repo).arg("lock").assert().success();
    let locked_bytes = fs::read(&secret_file).unwrap();
    assert!(
        locked_bytes.starts_with(b"age-encryption.org/v1\n"),
        "Service secret must lock cleanly after crash recovery"
    );

    agecrypt_cmd(repo)
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        "CRITICAL_KEY=super_secret_payload\n",
        "Service secret must restore exact plaintext upon unlock"
    );
}
