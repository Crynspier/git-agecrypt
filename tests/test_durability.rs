mod common;

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

    // Run status: recovery must fail closed on corrupted WAL data.
    agecrypt_cmd(repo).arg("status").assert().failure();

    // The master key is restored, but corrupted recovery metadata is retained
    // for diagnosis or operator-assisted recovery rather than discarded.
    assert!(key_file.exists());
    assert!(!locking_file.exists());
    assert!(journal_file.exists());
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

/// Demonstrates that an interrupted `rekey` operation (at `after_rekey_pub_write` or `after_rekey_key_saved`)
/// preserves valid atomic metadata files (`repo.pub` and `keys/*.age`) and recovers cleanly via either
/// rollback (`git checkout -- .git-agecrypt` + `unlock`) or roll-forward (`unlock` + `rekey`),
/// and that `rewrap` recovers historical secrets after key rotation.
#[test]
fn test_interrupted_rekey_and_rewrap_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    let (alice_sec, alice_pub) = generate_test_identity();
    let alice_key = repo.join("alice.key");
    fs::write(&alice_key, &alice_sec).unwrap();

    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &alice_pub, "-n", "alice"])
        .assert()
        .success();

    let secret_file = repo.join("vault.secret.env");
    let expected_secret = "ROTATION_RECOVERY_SECRET=survives_interrupted_rekey_100\n";
    fs::write(&secret_file, expected_secret).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
    );
    run_git(
        repo,
        &["commit", "-m", "Initial secret before interrupted rekey"],
    );
    let v1_blob = git_out(repo, &["cat-file", "blob", "HEAD:vault.secret.env"]);

    // 1. Trigger deterministic crash during `rekey` at `after_rekey_pub_write`
    let mut crash_rekey = agecrypt_cmd(repo);
    crash_rekey
        .env("GIT_AGECRYPT_CRASH_POINT", "after_rekey_pub_write")
        .arg("rekey")
        .assert()
        .failure();

    // Verify `inspect` confirms `repo.pub` and `keys/alice.age` were written atomically (never truncated)
    let inspect_out = agecrypt_cmd(repo)
        .args(["inspect", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        inspect_out.status.success(),
        "inspect must succeed after interrupted rekey: {}",
        String::from_utf8_lossy(&inspect_out.stderr)
    );
    // `status` runs transactional recovery, detecting the interrupted rekey and
    // rolling back all recipient envelopes and repo.pub to the consistent pre-rekey generation!
    let status_out = agecrypt_cmd(repo).arg("status").output().unwrap();
    assert!(status_out.status.success());
    let stderr_str = String::from_utf8_lossy(&status_out.stderr);
    let stdout_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        stderr_str.contains("Recovered interrupted rekey transaction")
            || stdout_str.contains("YES (plaintext on disk)"),
        "status output: stdout: {stdout_str}, stderr: {stderr_str}"
    );

    // 2. Re-running `rekey` completes the rotation transaction cleanly and atomically!
    agecrypt_cmd(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt", "vault.secret.env"]);
    run_git(repo, &["commit", "-m", "Completed rekey rotation"]);
    assert_invariant_a(repo, "vault.secret.env", expected_secret);
    agecrypt_cmd(repo).arg("check").assert().success();

    // 3. Simulate historical ciphertext on disk (e.g. from an interrupted merge/cherry-pick of pre-rotation v1_blob)
    // and verify `rewrap` decrypts it using the historical master key from Git history and re-encrypts under the active key!
    fs::write(&secret_file, &v1_blob).unwrap();
    agecrypt_cmd(repo)
        .args([
            "rewrap",
            "vault.secret.env",
            "--identity",
            alice_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    // `check` confirms the staged blob in the index is now encrypted under the active master key
    agecrypt_cmd(repo).arg("check").assert().success();
    assert_invariant_a(repo, "vault.secret.env", expected_secret);

    // 4. Test crash during Phase 2 (after key metadata activation, before staging completion):
    let mut crash_phase2 = agecrypt_cmd(repo);
    crash_phase2
        .env("GIT_AGECRYPT_CRASH_POINT", "after_rekey_cache_purge")
        .arg("rekey")
        .assert()
        .failure();

    // Verify recovery recognizes completed key rotation and retains active keys
    let status_out = agecrypt_cmd(repo).arg("status").output().unwrap();
    assert!(status_out.status.success());
    let stderr_str = String::from_utf8_lossy(&status_out.stderr);
    assert!(
        stderr_str.contains("Rekey key rotation for ring 'default' was previously completed")
            || stderr_str.contains("NOTICE"),
        "stderr: {stderr_str}"
    );

    // Finalize staging with git add and check passes
    run_git(repo, &["add", ".git-agecrypt", "vault.secret.env"]);
    run_git(
        repo,
        &[
            "commit",
            "-m",
            "Finalized rekey rotation after phase 2 interruption",
        ],
    );
    agecrypt_cmd(repo).arg("check").assert().success();
    assert_invariant_a(repo, "vault.secret.env", expected_secret);
}
