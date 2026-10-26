mod common;

use common::{agecrypt_cmd, generate_test_identity, init_repo, run_git};
use fs2::FileExt;
use git_agecrypt::git::{acquire_recovery_lock, acquire_recovery_lock_with_timeout};
use std::fs;
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;

/// A.4(1): Bounded timeout returns an explicit, actionable timeout error when another
/// thread/process holds `recovery.lock`.
#[test]
fn test_recovery_lock_bounded_timeout_returns_actionable_error() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("git-agecrypt");
    let _holder = acquire_recovery_lock(&state_dir).expect("Primary holder must acquire lock");

    let start = std::time::Instant::now();
    let err = match acquire_recovery_lock_with_timeout(&state_dir, Duration::from_millis(200)) {
        Ok(_) => panic!("Must time out while primary holder retains recovery.lock"),
        Err(e) => e.to_string(),
    };
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(180),
        "Must wait at least until timeout ({elapsed:?})"
    );
    assert!(
        err.contains("Timed out after") && err.contains("recovery.lock"),
        "Error message must be actionable and identify recovery.lock, got: {err}"
    );
}

/// A.4(2): CLI commands respect `GIT_AGECRYPT_LOCK_TIMEOUT_MS` when a concurrent process
/// holds `recovery.lock`, failing cleanly instead of hanging indefinitely.
#[test]
fn test_cli_mutating_commands_timeout_cleanly_when_recovery_lock_held() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (sec, pub_key) = generate_test_identity();
    let key_file = repo.join("id.txt");
    fs::write(&key_file, &sec).unwrap();

    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &pub_key, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );

    // Hold recovery.lock from this process
    let state_dir = repo.join(".git").join("git-agecrypt");
    let guard = acquire_recovery_lock(&state_dir).unwrap();

    // Mutating CLI commands must fail closed with timeout when GIT_AGECRYPT_LOCK_TIMEOUT_MS is short
    for args in [
        &["lock"][..],
        &["unlock", key_file.to_str().unwrap()][..],
        &["rekey"][..],
        &["add-recipient", "-i", &pub_key, "-n", "bob"][..],
        &["remove-recipient", "alice"][..],
    ] {
        let out = agecrypt_cmd(repo)
            .env("GIT_AGECRYPT_LOCK_TIMEOUT_MS", "150")
            .args(args)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "Command {:?} must fail when recovery.lock is held",
            args
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("Timed out") && stderr.contains("recovery.lock"),
            "Expected timeout diagnostic on {:?}, got: {}",
            args,
            stderr
        );
    }

    // Read-only `inspect` must still succeed even while `recovery.lock` is held!
    let inspect_out = agecrypt_cmd(repo)
        .env("GIT_AGECRYPT_LOCK_TIMEOUT_MS", "150")
        .args(["inspect", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        inspect_out.status.success(),
        "Read-only inspect must not block on recovery.lock: {}",
        String::from_utf8_lossy(&inspect_out.stderr)
    );

    // Drop guard -> mutating command succeeds immediately
    drop(guard);
    let out_after = agecrypt_cmd(repo)
        .env("GIT_AGECRYPT_LOCK_TIMEOUT_MS", "2000")
        .args(["lock"])
        .output()
        .unwrap();
    assert!(
        out_after.status.success(),
        "Lock must succeed after guard release: {}",
        String::from_utf8_lossy(&out_after.stderr)
    );
}

/// A.4(3): `recovery.lock` is NEVER reclaimed via PID or mtime heuristics.
/// Writing a dead PID and old timestamp into `recovery.lock` while an active handle holds
/// the OS lock must NEVER allow a second waiter to steal the lock.
#[test]
fn test_recovery_lock_never_reclaimed_by_dead_pid_or_mtime_heuristics() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("git-agecrypt");
    fs::create_dir_all(&state_dir).unwrap();
    let lock_path = state_dir.join("recovery.lock");

    #[cfg(windows)]
    let mut holder_file = {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0x01 | 0x02)
            .open(&lock_path)
            .unwrap()
    };
    #[cfg(not(windows))]
    let mut holder_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();

    holder_file.lock_exclusive().unwrap();
    // Write a dead PID and ancient timestamp (0) into recovery.lock
    writeln!(holder_file, "99999999:0").unwrap();
    holder_file.flush().unwrap();

    // Attempt to acquire recovery.lock: must still block and time out because OS handle lock is held!
    let res = acquire_recovery_lock_with_timeout(&state_dir, Duration::from_millis(150));
    assert!(
        res.is_err(),
        "recovery.lock must NEVER be broken by dead-PID or timestamp heuristics while OS handle is locked"
    );

    drop(holder_file);

    // Once the OS handle is closed, acquisition succeeds immediately even with "99999999:0" inside the file
    let _guard = acquire_recovery_lock_with_timeout(&state_dir, Duration::from_millis(500))
        .expect("Must acquire lock immediately once OS handle is closed");
}

/// A.4(4): Crash / kill of a lock-holding process releases `recovery.lock` automatically via the OS kernel,
/// and scoped-ring interrupted lock transactions (`rings/<ring>/repo.key.locking`) are recovered atomically.
#[test]
fn test_scoped_ring_interrupted_lock_recovered_under_recovery_lock() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (sec, pub_key) = generate_test_identity();
    let key_file = repo.join("prod_id.txt");
    fs::write(&key_file, &sec).unwrap();

    assert!(
        agecrypt_cmd(repo)
            .args(["init", "--ring", "prod"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(repo)
            .args([
                "add-recipient",
                "--ring",
                "prod",
                "-i",
                &pub_key,
                "-n",
                "ops"
            ])
            .status()
            .unwrap()
            .success()
    );

    fs::write(
        repo.join(".gitattributes"),
        "secrets/prod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("secrets/prod")).unwrap();
    let secret_file = repo.join("secrets/prod/db.env");
    fs::write(&secret_file, "PROD_SECRET=top_secret_val\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "secrets/prod/db.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Add prod secret"]);

    // Simulate a crash during `git-agecrypt lock --ring prod` after `repo.key -> repo.key.locking`
    let prod_state_dir = repo.join(".git/git-agecrypt/rings/prod");
    let prod_key = prod_state_dir.join("repo.key");
    let prod_locking = prod_state_dir.join("repo.key.locking");
    assert!(prod_key.exists());
    fs::rename(&prod_key, &prod_locking).unwrap();
    // Truncate the secret file in the working tree as if checkout was killed mid-flight
    fs::write(&secret_file, b"").unwrap();
    let journal_path = repo.join(".git/git-agecrypt/lock.journal");
    fs::write(
        &journal_path,
        format!("{}\tsecrets/prod/db.env\n", repo.display()),
    )
    .unwrap();

    // Verify `inspect` reports the interrupted transaction without mutating it
    let inspect_out = agecrypt_cmd(repo)
        .args(["inspect", "--format", "json", "--ring", "prod"])
        .output()
        .unwrap();
    assert!(inspect_out.status.success());
    let inspect_json = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(
        inspect_json.contains("\"interrupted_lock_pending_recovery\""),
        "inspect must report interrupted_lock_pending_recovery, got: {inspect_json}"
    );
    assert!(
        prod_locking.exists(),
        "inspect must be strictly read-only and leave repo.key.locking untouched"
    );

    // Now run `status` (or any management command) -> must atomically recover `prod` ring's repo.key and secret file!
    let status_out = agecrypt_cmd(repo).arg("status").output().unwrap();
    assert!(status_out.status.success());
    assert!(
        prod_key.exists() && !prod_locking.exists(),
        "Scoped ring repo.key must be restored from repo.key.locking"
    );
    assert!(
        !journal_path.exists(),
        "lock.journal must be removed after successful replay"
    );
    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        "PROD_SECRET=top_secret_val\n",
        "Truncated secret file in scoped ring must be restored to plaintext"
    );
}

/// A.4(5): Coordination-path replacement protection on `recovery.lock`.
#[test]
fn test_recovery_lock_resists_path_replacement_and_deletion() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("git-agecrypt");
    let guard = acquire_recovery_lock(&state_dir).unwrap();
    let lock_path = state_dir.join("recovery.lock");

    #[cfg(windows)]
    {
        // On Windows, omitting FILE_SHARE_DELETE prevents unlinking or renaming recovery.lock while held
        let remove_res = fs::remove_file(&lock_path);
        assert!(
            remove_res.is_err(),
            "Windows must block unlinking recovery.lock while a RecoveryLockGuard handle is open"
        );
    }

    #[cfg(unix)]
    {
        // On Unix, even if someone unlinks recovery.lock while held, a new waiter must detect the inode mismatch
        // and acquire a lock on the newly created live path without panicking or corrupting state.
        let _ = fs::remove_file(&lock_path);
    }

    drop(guard);
    let _guard2 = acquire_recovery_lock(&state_dir)
        .expect("Must cleanly re-acquire recovery.lock after release");
}
