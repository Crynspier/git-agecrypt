mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_wal_corruption_deterministic_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("data.secret.env");
    fs::write(&secret_file, "SECRET=wal_recovery_test\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // Simulate crash during lock with corrupted WAL journal
    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");
    fs::rename(&key_file, &locking_file).unwrap();

    let journal_file = state_dir.join("lock.journal");
    fs::write(&journal_file, b"corrupt_garbage_without_tabs\x00\xff\xfe\n").unwrap();

    // Run status: triggers recover_interrupted_transaction
    agecrypt_cmd(repo).arg("status").assert().success();

    // Verify master key was safely restored and journal cleaned
    assert!(key_file.exists());
    assert!(!locking_file.exists());
    assert!(!journal_file.exists());
}

#[test]
fn test_wal_journal_recovers_across_clock_jumps() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("database.secret.env");
    let original_content = "DB_PASS=ProductionSecure123\n";
    fs::write(&secret_file, original_content).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit secret"]);

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");
    let journal_file = state_dir.join("lock.journal");

    // Simulate crash during lock:
    // 1. Stage repo.key -> repo.key.locking
    fs::rename(&key_file, &locking_file).unwrap();

    // 2. Write WAL journal recording target secret
    fs::write(
        &journal_file,
        format!("{}\tdatabase.secret.env\n", repo.display()),
    )
    .unwrap();

    // 3. Truncate database.secret.env to 0 bytes (interrupted checkout-index)
    fs::write(&secret_file, b"").unwrap();
    assert_eq!(fs::metadata(&secret_file).unwrap().len(), 0);

    // 4. Set mtime to 1 hour in the past (simulating machine sleep or clock drift)
    let one_hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    filetime::set_file_mtime(&secret_file, one_hour_ago).unwrap();

    // Run status command: discover() runs recover_interrupted_transaction()
    agecrypt_cmd(repo).arg("status").assert().success();

    // Master key must be recovered
    assert!(key_file.exists());
    assert!(!locking_file.exists());
    assert!(!journal_file.exists());

    // File content must be safely restored to original plaintext
    let restored_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(restored_content, original_content);
}

#[test]
fn test_interrupted_lock_split_brain_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file_a = repo.join("alpha.secret.env");
    let secret_file_b = repo.join("beta.secret.env");
    fs::write(&secret_file_a, "ALPHA=original\n").unwrap();
    fs::write(&secret_file_b, "BETA=original\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit two secrets"]);

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");
    let journal_file = state_dir.join("lock.journal");

    fs::rename(&key_file, &locking_file).unwrap();
    fs::write(
        &journal_file,
        format!(
            "{}\talpha.secret.env\n{}\tbeta.secret.env\n",
            repo.display(),
            repo.display()
        ),
    )
    .unwrap();

    // alpha was encrypted before crash, beta was untouched
    run_git(repo, &["checkout-index", "-f", "alpha.secret.env"]);

    // Run status to trigger auto-recovery
    agecrypt_cmd(repo).arg("status").assert().success();

    // Both files must be readable plaintext
    assert_eq!(
        fs::read_to_string(&secret_file_a).unwrap(),
        "ALPHA=original\n"
    );
    assert_eq!(
        fs::read_to_string(&secret_file_b).unwrap(),
        "BETA=original\n"
    );
    assert!(key_file.exists());
    assert!(!locking_file.exists());
}

#[test]
fn test_half_written_repo_key_fails_closed() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let key_path = repo.join(".git").join("git-agecrypt").join("repo.key");
    // Truncate repo.key to corrupt partial bytes
    fs::write(&key_path, "AGE-SECRET-KEY-1CORRUPTEDPARTIAL").unwrap();

    // Status or smudge must fail closed, rejecting invalid key
    let mut cmd = agecrypt_cmd(repo);
    cmd.arg("status");
    let assert = cmd.assert();
    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_lower = stdout.to_lowercase();
    assert!(
        stderr.contains("corrupt")
            || stderr.contains("invalid")
            || stdout_lower.contains("locked")
            || stdout_lower.contains("no (locked)"),
        "Must safely report locked or reject corrupt key: stderr={stderr}, stdout={stdout}"
    );
}

#[test]
fn test_half_written_cache_entry_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("test.secret.env");
    fs::write(&secret_file, "CANARY_SECRET=val123\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // Find the cache directory
    let cache_parent = repo.join(".git").join("git-agecrypt").join("cache");
    if cache_parent.exists() {
        for entry in fs::read_dir(&cache_parent).unwrap().flatten() {
            if entry.path().is_dir() {
                for file in fs::read_dir(entry.path()).unwrap().flatten() {
                    // Corrupt cache file by truncating to 10 bytes
                    let _ = fs::write(file.path(), b"TRUNCATED!");
                }
            }
        }
    }

    // Checking out or diffing should cleanly detect corrupted cache hit and recover
    run_git(repo, &["checkout", "HEAD", "--", "test.secret.env"]);
    let content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(content, "CANARY_SECRET=val123\n");
}

#[test]
fn test_spool_canary_zero_plaintext_remnants() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("spool.secret.env");
    let canary = "SECRET_CANARY_SPOOL_TEST_PAYLOAD_999";
    fs::write(&secret_file, format!("CANARY={canary}\n")).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit canary"]);

    let spool_dir = repo.join(".git").join("git-agecrypt").join("spool");
    if spool_dir.exists() {
        // Any temporary spool files created during add/commit must have been swept or zeroed
        for entry in fs::read_dir(&spool_dir).unwrap().flatten() {
            let data = fs::read(entry.path()).unwrap_or_default();
            let text = String::from_utf8_lossy(&data);
            assert!(
                !text.contains(canary),
                "Spool directory contained plaintext canary: {}",
                entry.path().display()
            );
        }
    }
}
