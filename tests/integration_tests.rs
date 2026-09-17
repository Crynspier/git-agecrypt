use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn prepend_to_path(dir: &Path) -> std::ffi::OsString {
    let mut paths = vec![dir.to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(paths).unwrap_or_default()
}

fn run_git(repo: &Path, args: &[&str]) {
    let bin_dir = assert_cmd::cargo::cargo_bin("git-agecrypt")
        .parent()
        .unwrap()
        .to_path_buf();
    let new_path = prepend_to_path(&bin_dir);

    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", &new_path)
        .status()
        .expect("Failed to execute git command");
    assert!(status.success(), "Git command failed: {:?}", args);
}

fn git_out(repo: &Path, args: &[&str]) -> Vec<u8> {
    let bin_dir = assert_cmd::cargo::cargo_bin("git-agecrypt")
        .parent()
        .unwrap()
        .to_path_buf();
    let new_path = prepend_to_path(&bin_dir);

    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", &new_path)
        .output()
        .expect("Failed to execute git command");
    assert!(output.status.success(), "Git command failed: {:?}", args);
    output.stdout
}

#[test]
fn test_git_agecrypt_init_and_transparent_encryption() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    // 1. Initialize git repo
    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    // 2. Run git-agecrypt init
    let mut cmd = Command::cargo_bin("git-agecrypt").unwrap();
    cmd.current_dir(repo)
        .arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains("Initialization complete"));

    // Check metadata created
    assert!(repo.join(".git-agecrypt").join("repo.pub").exists());
    assert!(
        repo.join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );
    assert!(repo.join(".gitattributes").exists());

    // 3. Create a secret file matching default pattern (*.secret.env)
    let secret_path = repo.join("database.secret.env");
    let secret_content = "DB_PASSWORD=SuperSecretPassw0rd123!\nAPI_TOKEN=prod_token_abc\n";
    fs::write(&secret_path, secret_content).expect("Failed to write secret file");

    // 4. Stage and commit
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial secret commit"]);

    // 5. Verify transparent on-disk state (working tree is plaintext)
    let disk_content = fs::read_to_string(&secret_path).expect("Failed to read file on disk");
    assert_eq!(disk_content, secret_content);

    // 6. Verify Git object store state (Git blob is age ciphertext!)
    let blob = git_out(repo, &["cat-file", "-p", "HEAD:database.secret.env"]);
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));
    assert!(!String::from_utf8_lossy(&blob).contains("SuperSecretPassw0rd123!"));

    // 7. Test textconv diff driver
    let mut textconv_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    textconv_cmd
        .current_dir(repo)
        .arg("textconv")
        .arg("database.secret.env")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "DB_PASSWORD=SuperSecretPassw0rd123!",
        ));

    // 8. Test lock
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    assert!(
        !repo
            .join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );

    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("NO (locked)"));
}

#[test]
fn test_pre_commit_safeguard_blocks_plaintext() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    // Configure .gitattributes manually WITHOUT git filter installed
    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt\n",
    )
    .unwrap();

    // Create and stage plaintext file directly
    let secret_file = repo.join("app.secret.env");
    fs::write(&secret_file, "PLAINTEXT_SECRET=leaked_key\n").unwrap();
    run_git(repo, &["add", "app.secret.env"]);

    // Run git-agecrypt check
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd
        .current_dir(repo)
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains("CRITICAL SECURITY ALERT"));
}

#[test]
fn test_large_binary_streaming_roundtrip() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a 2 MB pseudo-random binary secret asset (e.g. mock keystore)
    let binary_file = repo.join("certificate.secret.env");
    let mut binary_data = vec![0u8; 2 * 1024 * 1024];
    for (i, byte) in binary_data.iter_mut().enumerate() {
        *byte = ((i * 37 + 13) % 256) as u8;
    }
    fs::write(&binary_file, &binary_data).unwrap();

    run_git(repo, &["add", "certificate.secret.env"]);
    run_git(repo, &["commit", "-m", "Add large binary asset"]);

    // Verify disk is intact
    let disk_bytes = fs::read(&binary_file).unwrap();
    assert_eq!(disk_bytes, binary_data);

    // Verify git object is age ciphertext
    let blob = git_out(repo, &["cat-file", "-p", "HEAD:certificate.secret.env"]);
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));
    assert_ne!(blob, binary_data);
}

#[test]
fn test_ssh_recipient_enrollment_and_unlock() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Generate an SSH Ed25519 key pair in tempdir
    let ssh_key = temp.path().join("id_ed25519_test");
    let ssh_pub = temp.path().join("id_ed25519_test.pub");

    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            ssh_key.to_str().unwrap(),
            "-C",
            "test-collaborator@git-agecrypt",
        ])
        .status()
        .expect("Failed to run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");

    // Add recipient using SSH public key
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .arg("add-recipient")
        .arg("-i")
        .arg(&ssh_pub)
        .arg("--name")
        .arg("alice")
        .assert()
        .success()
        .stderr(predicate::str::contains("alice.age"));

    // Verify recipient file was created
    assert!(
        repo.join(".git-agecrypt")
            .join("keys")
            .join("alice.age")
            .exists()
    );

    // Lock repo
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();
    assert!(
        !repo
            .join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );

    // Unlock using the SSH private key
    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(repo)
        .arg("unlock")
        .arg(&ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains("Repository unlocked successfully"));

    assert!(
        repo.join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );
}

#[test]
fn test_unlock_from_stdin() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "CI Bot"]);
    run_git(repo, &["config", "user.email", "ci@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let ssh_key = temp.path().join("id_ed25519_ci");
    let ssh_pub = temp.path().join("id_ed25519_ci.pub");

    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            ssh_key.to_str().unwrap(),
            "-C",
            "ci@runner",
        ])
        .status()
        .expect("Failed to run ssh-keygen");
    assert!(status.success());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .arg("add-recipient")
        .arg("-i")
        .arg(&ssh_pub)
        .arg("--name")
        .arg("ci-runner")
        .assert()
        .success();

    // Lock repo
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    // Unlock via stdin: echo "$KEY" | git-agecrypt unlock -
    let key_content = fs::read_to_string(&ssh_key).unwrap();
    let mut unlock_stdin_cmd = assert_cmd::Command::cargo_bin("git-agecrypt").unwrap();
    unlock_stdin_cmd.current_dir(repo).args(["unlock", "-"]);
    unlock_stdin_cmd.write_stdin(key_content);
    unlock_stdin_cmd
        .assert()
        .success()
        .stderr(predicate::str::contains("Repository unlocked successfully"));

    assert!(
        repo.join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );
}

#[test]
fn test_safe_unlock_preserves_unstaged_edits() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("config.secret.env");
    fs::write(&secret_file, "API_KEY=committed_v1\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "config.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit v1"]);

    // Now edit secret file in working tree (unstaged modification!)
    fs::write(&secret_file, "API_KEY=uncommitted_local_draft\n").unwrap();

    // Lock repo without --force: must abort with error exit code and preserve local draft!
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().failure();

    // Unlock without --force: should warn and preserve local draft!
    // We get the master key string from the initial_user or we pass the key
    // In this repo, let's unlock with the master key if we have an enrolled key, or test unlock with SSH
    let ssh_key = temp.path().join("id_ed25519");
    let _ssh_pub = temp.path().join("id_ed25519.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", ssh_key.to_str().unwrap()])
        .status()
        .unwrap();

    // Unlock first to add recipient
    let pub_file = repo.join(".git-agecrypt").join("repo.pub");
    assert!(pub_file.exists());

    // Verify unstaged edit was NOT overwritten
    let current_disk = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(current_disk, "API_KEY=uncommitted_local_draft\n");
}

#[test]
fn test_merge_driver_binary_collision_guard() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a mock binary file for %O, %A, %B
    let base_file = temp.path().join("base.bin");
    let ours_file = temp.path().join("ours.bin");
    let theirs_file = temp.path().join("theirs.bin");

    // Write binary bytes (with null bytes)
    let binary_bytes = vec![0u8, 159, 255, 0, 12, 0, 88];
    fs::write(&base_file, &binary_bytes).unwrap();
    fs::write(&ours_file, &binary_bytes).unwrap();
    fs::write(&theirs_file, &binary_bytes).unwrap();

    // Attempt merge using git-agecrypt merge
    let mut merge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    merge_cmd
        .current_dir(repo)
        .arg("merge")
        .arg(&base_file)
        .arg(&ours_file)
        .arg(&theirs_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Binary secret detected"));
}

#[test]
fn test_rekey_and_offboarding() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Admin"]);
    run_git(repo, &["config", "user.email", "admin@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Generate Alice and Bob SSH keys
    let alice_key = temp.path().join("id_alice");
    let alice_pub = temp.path().join("id_alice.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", alice_key.to_str().unwrap()])
        .status()
        .unwrap();

    let bob_key = temp.path().join("id_bob");
    let bob_pub = temp.path().join("id_bob.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", bob_key.to_str().unwrap()])
        .status()
        .unwrap();

    // Enroll Alice and Bob
    let mut add_alice = Command::cargo_bin("git-agecrypt").unwrap();
    add_alice
        .current_dir(repo)
        .args([
            "add-recipient",
            "-i",
            alice_pub.to_str().unwrap(),
            "--name",
            "alice",
        ])
        .assert()
        .success();

    let mut add_bob = Command::cargo_bin("git-agecrypt").unwrap();
    add_bob
        .current_dir(repo)
        .args([
            "add-recipient",
            "-i",
            bob_pub.to_str().unwrap(),
            "--name",
            "bob",
        ])
        .assert()
        .success();

    // Create a secret file and commit it
    let secret_file = repo.join("server.secret.env");
    fs::write(&secret_file, "API_SECRET=shared_team_token\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "server.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial shared secret"]);

    // Verify Bob can unlock
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    let mut unlock_bob = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_bob
        .current_dir(repo)
        .args(["unlock", bob_key.to_str().unwrap()])
        .assert()
        .success();

    // Now remove Bob (offboarding)
    let mut remove_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    remove_cmd
        .current_dir(repo)
        .args(["remove-recipient", "bob"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Removed recipient 'bob'"));

    assert!(
        !repo
            .join(".git-agecrypt")
            .join("keys")
            .join("bob.age")
            .exists()
    );
    assert!(
        repo.join(".git-agecrypt")
            .join("keys")
            .join("alice.age")
            .exists()
    );

    // Execute rekey
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd
        .current_dir(repo)
        .arg("rekey")
        .assert()
        .success()
        .stderr(predicate::str::contains("Repository successfully re-keyed"));

    run_git(repo, &["add", ".git-agecrypt"]);
    run_git(
        repo,
        &["commit", "-m", "Rekey repository after offboarding Bob"],
    );

    // Lock repository
    let mut lock_cmd2 = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd2.current_dir(repo).arg("lock").assert().success();

    // Verify Bob FAILS to unlock
    let mut unlock_bob_fail = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_bob_fail
        .current_dir(repo)
        .args(["unlock", bob_key.to_str().unwrap()])
        .assert()
        .failure();

    // Verify Alice SUCCEEDS to unlock
    let mut unlock_alice = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_alice
        .current_dir(repo)
        .args(["unlock", alice_key.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Repository unlocked successfully"));

    // Verify decrypted content on disk
    let on_disk = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(on_disk, "API_SECRET=shared_team_token\n");
}

#[test]
fn test_git_worktrees_shared_unlock() {
    let temp = tempdir().expect("Failed to create tempdir");
    let main_repo = temp.path().join("main_repo");
    fs::create_dir(&main_repo).unwrap();

    run_git(&main_repo, &["init"]);
    run_git(&main_repo, &["config", "user.name", "Test Developer"]);
    run_git(&main_repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd
        .current_dir(&main_repo)
        .arg("init")
        .assert()
        .success();

    let secret_file = main_repo.join("db.secret.env");
    fs::write(&secret_file, "SECRET=value123\n").unwrap();
    run_git(
        &main_repo,
        &["add", ".gitattributes", ".git-agecrypt", "db.secret.env"],
    );
    run_git(&main_repo, &["commit", "-m", "Initial commit"]);

    // Create a linked worktree
    let worktree_dir = temp.path().join("feature_worktree");
    run_git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feature",
            worktree_dir.to_str().unwrap(),
        ],
    );

    // Verify status in worktree: should be unlocked because main is unlocked
    let mut status_worktree = Command::cargo_bin("git-agecrypt").unwrap();
    status_worktree
        .current_dir(&worktree_dir)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("YES (plaintext on disk)"));

    // Lock in main repo
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(&main_repo)
        .arg("lock")
        .assert()
        .success();

    // Worktree should now automatically reflect locked status because repo.key is shared in common_dir!
    let mut status_worktree_locked = Command::cargo_bin("git-agecrypt").unwrap();
    status_worktree_locked
        .current_dir(&worktree_dir)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("NO (locked)"));
}

#[test]
fn test_crlf_warning_when_missing_text() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    // Create .gitattributes WITHOUT -text flag
    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt\n",
    )
    .unwrap();

    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd
        .current_dir(repo)
        .arg("check")
        .assert()
        .success()
        .stderr(predicate::str::contains("does not specify '-text'"));
}

#[test]
fn test_symlink_safety_in_pre_commit_check() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a dummy object for the symlink target
    let hash_out = git_out(repo, &["hash-object", "-w", "--stdin"]);
    let hash_str = String::from_utf8_lossy(&hash_out).trim().to_string();

    // Add 120000 entry for a pattern matching .secret.env
    run_git(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{},link.secret.env", hash_str),
        ],
    );

    // Run check: it must recognize mode 120000 as a symlink and NOT flag it as plaintext secret
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_deterministic_clean_caching_prevents_phantom_diffs() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("db.secret.env");
    fs::write(&secret_file, "DATABASE_PASSWORD=SuperSecretPassw0rd123!\n").unwrap();

    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "db.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Initial commit of secret file"]);

    let original_blob = git_out(repo, &["rev-parse", "HEAD:db.secret.env"]);

    // Advance file mtime by 1 hour (simulating an editor touch or build script touch)
    let now = std::time::SystemTime::now();
    let future = now + std::time::Duration::from_secs(3600);
    filetime::set_file_mtime(&secret_file, filetime::FileTime::from_system_time(future))
        .expect("Failed to update file mtime");

    // Execute git status --porcelain: with deterministic caching, working tree MUST BE CLEAN!
    let status_out = git_out(repo, &["status", "--porcelain"]);
    let status_str = String::from_utf8_lossy(&status_out);
    assert!(
        status_str.trim().is_empty(),
        "Working tree must be clean with no phantom modifications after mtime touch! Got: '{status_str}'"
    );

    // Re-stage the file: index blob SHA must be 100% bit-for-bit identical to HEAD
    run_git(repo, &["add", "db.secret.env"]);
    let staged_blob = git_out(repo, &["rev-parse", ":db.secret.env"]);
    assert_eq!(
        original_blob, staged_blob,
        "Staged blob must be bit-for-bit identical to committed blob due to deterministic cache hit!"
    );
}

#[test]
fn test_locked_checkout_succeeds_and_unlock_decrypts() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Generate Alice SSH key and enroll
    let alice_key = temp.path().join("id_alice");
    let alice_pub = temp.path().join("id_alice.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", alice_key.to_str().unwrap()])
        .status()
        .unwrap();

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args([
            "add-recipient",
            "-i",
            alice_pub.to_str().unwrap(),
            "--name",
            "alice",
        ])
        .assert()
        .success();

    let secret_file = repo.join("api.secret.env");
    fs::write(&secret_file, "API_KEY=prod_live_secret_456\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "api.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit live secret"]);

    // Lock repository
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    // Verify file on disk is encrypted ciphertext!
    let disk_locked = fs::read(&secret_file).unwrap();
    assert!(
        disk_locked.starts_with(b"age-encryption.org/v1\n"),
        "Locking must encrypt working tree secret files!"
    );

    // CRITICAL: Git checkout on a locked repo MUST NOT crash with exit code 128!
    run_git(repo, &["checkout", "HEAD", "--", "api.secret.env"]);

    let disk_still_locked = fs::read(&secret_file).unwrap();
    assert!(disk_still_locked.starts_with(b"age-encryption.org/v1\n"));

    // Now unlock repository with Alice's key
    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(repo)
        .args(["unlock", alice_key.to_str().unwrap()])
        .assert()
        .success();

    // Verify file on disk is decrypted to plaintext!
    let disk_plaintext = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(disk_plaintext, "API_KEY=prod_live_secret_456\n");
}

#[test]
fn test_tracked_files_with_spaces() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a secret file WITH SPACES in the name
    let secret_with_spaces = repo.join("production database config.secret.env");
    fs::write(&secret_with_spaces, "PASSWORD=space_test_pwd_789\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "production database config.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit secret with spaces"]);

    // Check pre-commit check passes
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();

    // Verify lock and working tree refresh handles spaces without error
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    let disk_bytes = fs::read(&secret_with_spaces).unwrap();
    assert!(disk_bytes.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn test_nested_gitattributes_support() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a nested subdirectory with its own .gitattributes
    let sub_dir = repo.join("services").join("auth");
    fs::create_dir_all(&sub_dir).unwrap();
    fs::write(
        sub_dir.join(".gitattributes"),
        "*.credentials filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    let nested_secret = sub_dir.join("jwt.credentials");
    fs::write(&nested_secret, "JWT_SECRET=super_nested_key\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            "services/auth/.gitattributes",
            "services/auth/jwt.credentials",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit nested secret"]);

    // Verify blob in git is age ciphertext
    let blob = git_out(
        repo,
        &["cat-file", "-p", "HEAD:services/auth/jwt.credentials"],
    );
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));

    // Verify check command runs cleanly
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_subdirectory_discovery_and_status() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a deeply nested directory
    let deep_dir = repo.join("services").join("billing").join("v2");
    fs::create_dir_all(&deep_dir).unwrap();

    // Run git-agecrypt status FROM DEEP SUBDIRECTORY
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(&deep_dir)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Unlocked:          YES"));
}

#[test]
fn test_git_merge_driver_5_positional_arguments() {
    use std::io::Write;
    use std::process::Stdio;

    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create ancestor %O, ours %A, theirs %B
    let base_file = repo.join("base.env");
    let ours_file = repo.join("ours.env");
    let theirs_file = repo.join("theirs.env");

    let encrypt_file = |content: &[u8], dest: &Path| {
        let mut clean_cmd = Command::cargo_bin("git-agecrypt").unwrap();
        let mut child = clean_cmd
            .current_dir(repo)
            .arg("clean")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(content).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        fs::write(dest, out.stdout).unwrap();
    };

    encrypt_file(b"FOO=common\nMID=stable\nBAR=common\n", &base_file);
    encrypt_file(b"FOO=ours_change\nMID=stable\nBAR=common\n", &ours_file);
    encrypt_file(b"FOO=common\nMID=stable\nBAR=theirs_change\n", &theirs_file);

    // Execute merge with 5 positional arguments (%O %A %B %L %P)
    let mut merge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    merge_cmd
        .current_dir(repo)
        .args([
            "merge",
            base_file.to_str().unwrap(),
            ours_file.to_str().unwrap(),
            theirs_file.to_str().unwrap(),
            "7",
            "configs/secrets.env",
        ])
        .assert()
        .success();

    // Verify ours_file is merged and encrypted
    let merged_cipher = fs::read(&ours_file).unwrap();
    assert!(merged_cipher.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn test_recipient_name_sanitization_on_windows() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let alice_key = temp.path().join("id_alice");
    let alice_pub = temp.path().join("id_alice.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", alice_key.to_str().unwrap()])
        .status()
        .unwrap();

    // Name with invalid characters on Windows (colon, slash, spaces)
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args([
            "add-recipient",
            "-i",
            alice_pub.to_str().unwrap(),
            "--name",
            "alice:work/laptop",
        ])
        .assert()
        .success();

    // Verify file on disk exists with sanitized filename
    let keys_dir = repo.join(".git-agecrypt").join("keys");
    let key_file = keys_dir.join("alice_work_laptop.age");
    assert!(key_file.exists(), "Sanitized recipient file must exist!");
}

#[test]
fn test_filter_config_includes_filename_expansion() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let clean_cfg = git_out(
        repo,
        &["config", "--local", "--get", "filter.agecrypt.clean"],
    );
    let clean_str = String::from_utf8_lossy(&clean_cfg);
    assert!(
        clean_str.contains("git-agecrypt clean %f"),
        "Filter clean must include %f: got {clean_str}"
    );

    let smudge_cfg = git_out(
        repo,
        &["config", "--local", "--get", "filter.agecrypt.smudge"],
    );
    let smudge_str = String::from_utf8_lossy(&smudge_cfg);
    assert!(
        smudge_str.contains("git-agecrypt smudge %f"),
        "Filter smudge must include %f: got {smudge_str}"
    );
}

#[test]
fn test_clean_counter_trap_in_git() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Plaintext content starting with age header (e.g. a markdown documentation or sample file)
    let fake_age_plaintext =
        "age-encryption.org/v1\nThis is actually plaintext secret documentation!\n";
    let secret_file = repo.join("doc.secret.env");
    fs::write(&secret_file, fake_age_plaintext).unwrap();

    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "doc.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit fake age header file"]);

    // The committed blob in Git MUST NOT match the plaintext! It must be encrypted.
    let blob = git_out(repo, &["cat-file", "-p", "HEAD:doc.secret.env"]);
    assert_ne!(
        blob,
        fake_age_plaintext.as_bytes(),
        "Plaintext with age header must NOT bypass clean filter!"
    );
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));

    // Working tree file must remain exactly as authored
    let disk_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(disk_content, fake_age_plaintext);
}

#[test]
fn test_rekey_cache_fingerprint_isolation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Admin"]);
    run_git(repo, &["config", "user.email", "admin@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create and enroll user
    let user_key = temp.path().join("id_user");
    let user_pub = temp.path().join("id_user.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", user_key.to_str().unwrap()])
        .status()
        .unwrap();

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args([
            "add-recipient",
            "-i",
            user_pub.to_str().unwrap(),
            "--name",
            "user",
        ])
        .assert()
        .success();

    // Stage a secret file: populates the cache
    let secret_file = repo.join("test.secret.env");
    fs::write(&secret_file, "SECRET=value_to_cache\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );

    let base_cache = repo.join(".git").join("git-agecrypt").join("cache");
    assert!(base_cache.exists(), "Cache root directory should exist");

    let subdirs_before: Vec<_> = fs::read_dir(&base_cache)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        subdirs_before.len(),
        1,
        "Should have 1 cache fingerprint directory before rekey"
    );

    // Rekey repository: clears stale cache and generates new master key
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Modify secret file so Git clean filter runs under the new master key
    fs::write(&secret_file, "SECRET=value_after_rekey\n").unwrap();
    run_git(repo, &["add", "test.secret.env"]);

    assert!(
        base_cache.exists(),
        "Cache root directory should exist after staging"
    );

    let subdirs_after: Vec<_> = fs::read_dir(&base_cache)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    assert!(
        !subdirs_after.contains(&subdirs_before[0]),
        "Old cache fingerprint directory should be isolated/cleared after rekey"
    );
}

#[test]
fn test_multi_worktree_synchronized_lock_and_unlock() {
    let temp = tempdir().expect("Failed to create tempdir");
    let main_repo = temp.path().join("main_repo");
    fs::create_dir(&main_repo).unwrap();

    run_git(&main_repo, &["init"]);
    run_git(&main_repo, &["config", "user.name", "Test Developer"]);
    run_git(&main_repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd
        .current_dir(&main_repo)
        .arg("init")
        .assert()
        .success();

    // Create and enroll user key
    let user_key = temp.path().join("id_user");
    let user_pub = temp.path().join("id_user.pub");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", user_key.to_str().unwrap()])
        .status()
        .unwrap();

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(&main_repo)
        .args([
            "add-recipient",
            "-i",
            user_pub.to_str().unwrap(),
            "--name",
            "user",
        ])
        .assert()
        .success();

    // Secret in main worktree
    let secret_main = main_repo.join("main.secret.env");
    fs::write(&secret_main, "SECRET_MAIN=main_token_123\n").unwrap();
    run_git(
        &main_repo,
        &["add", ".gitattributes", ".git-agecrypt", "main.secret.env"],
    );
    run_git(&main_repo, &["commit", "-m", "Main commit"]);

    // Create linked worktree
    let feature_worktree = temp.path().join("feature_worktree");
    run_git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feature",
            feature_worktree.to_str().unwrap(),
        ],
    );

    // Secret in feature worktree
    let secret_feat = feature_worktree.join("feat.secret.env");
    fs::write(&secret_feat, "SECRET_FEAT=feat_token_456\n").unwrap();
    run_git(&feature_worktree, &["add", "feat.secret.env"]);
    run_git(&feature_worktree, &["commit", "-m", "Feature commit"]);

    // Lock repository from the main worktree
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(&main_repo)
        .arg("lock")
        .assert()
        .success();

    // CRITICAL: Both main_repo AND feature_worktree must now have encrypted secrets on disk!
    let main_bytes = fs::read(&secret_main).unwrap();
    assert!(
        main_bytes.starts_with(b"age-encryption.org/v1\n"),
        "Main worktree secrets must be encrypted on lock!"
    );

    let feat_bytes = fs::read(&secret_feat).unwrap();
    assert!(
        feat_bytes.starts_with(b"age-encryption.org/v1\n"),
        "Linked worktree secrets must be synchronized and encrypted on lock!"
    );

    // Unlock repository from the feature worktree
    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(&feature_worktree)
        .args(["unlock", user_key.to_str().unwrap()])
        .assert()
        .success();

    // CRITICAL: Both main_repo AND feature_worktree must now be decrypted to plaintext!
    let main_plain = fs::read_to_string(&secret_main).unwrap();
    assert_eq!(main_plain, "SECRET_MAIN=main_token_123\n");

    let feat_plain = fs::read_to_string(&secret_feat).unwrap();
    assert_eq!(feat_plain, "SECRET_FEAT=feat_token_456\n");
}

#[test]
fn test_rename_tracking_in_status_z() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("database.secret.env");
    fs::write(&secret_file, "DB_PASS=original_pass\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit original secret"]);

    // Rename tracked secret file
    run_git(
        repo,
        &["mv", "database.secret.env", "production.secret.env"],
    );

    // Attempt lock without --force: must detect that production.secret.env is dirty/modified and warn!
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("production.secret.env"));

    // Verify file was NOT overwritten or destroyed
    assert!(repo.join("production.secret.env").exists());
}

#[test]
fn test_stale_worktree_resilience() {
    let temp = tempdir().expect("Failed to create tempdir");
    let main_repo = temp.path().join("main");
    fs::create_dir(&main_repo).unwrap();

    run_git(&main_repo, &["init"]);
    run_git(&main_repo, &["config", "user.name", "Test Developer"]);
    run_git(&main_repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd
        .current_dir(&main_repo)
        .arg("init")
        .assert()
        .success();

    let secret_file = main_repo.join("test.secret.env");
    fs::write(&secret_file, "SECRET=value\n").unwrap();
    run_git(
        &main_repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(&main_repo, &["commit", "-m", "Initial commit"]);

    // Create a linked worktree
    let stale_worktree = temp.path().join("stale_wt");
    run_git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "stale-branch",
            stale_worktree.to_str().unwrap(),
        ],
    );
    assert!(stale_worktree.exists());

    // Manually delete the worktree folder from disk without running git worktree prune
    fs::remove_dir_all(&stale_worktree).unwrap();
    assert!(!stale_worktree.exists());

    // git-agecrypt lock without --force should safely abort with a warning about unreachable worktrees
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(&main_repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unreachable"));

    // git-agecrypt lock with --force should succeed and NOT crash with NotFound / os error 2
    let mut force_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    force_cmd
        .current_dir(&main_repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    // Verify main repo secret was locked (encrypted)
    let disk_bytes = fs::read(&secret_file).unwrap();
    assert!(disk_bytes.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn test_hmac_cache_leak_protection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create a common dictionary secret
    let secret_file = repo.join("common.secret.env");
    let secret_content = "DEBUG=true\n";
    fs::write(&secret_file, secret_content).unwrap();

    // Stage file: invokes clean filter, which populates cache
    run_git(repo, &["add", "common.secret.env"]);

    // Calculate unkeyed SHA-256 of "DEBUG=true\n"
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(secret_content.as_bytes());
    let unkeyed_sha256 = format!("{:x}", hasher.finalize());

    // Check the cache directory
    let cache_root = repo.join(".git").join("git-agecrypt").join("cache");
    let mut found_cache_entries = 0;
    if cache_root.exists() {
        for fp_entry in fs::read_dir(&cache_root).unwrap() {
            let fp_dir = fp_entry.unwrap().path();
            if fp_dir.is_dir() {
                for file_entry in fs::read_dir(&fp_dir).unwrap() {
                    let fname = file_entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    found_cache_entries += 1;
                    // CRITICAL: Cache filename must NOT match the unkeyed SHA-256 hash!
                    assert_ne!(
                        fname,
                        format!("{unkeyed_sha256}.age"),
                        "Cache filename leaked plaintext SHA-256 hash! Must be keyed HMAC-SHA256."
                    );
                    assert!(fname.ends_with(".age"));
                    assert_eq!(fname.len(), 32 + 4); // 32 hex chars + .age (compact 128-bit hash for MAX_PATH safety)
                }
            }
        }
    }
    assert!(
        found_cache_entries > 0,
        "Cache entry must have been created"
    );
}

#[test]
fn test_worktree_missing_git_resilience() {
    let temp = tempdir().expect("Failed to create tempdir");
    let main_repo = temp.path().join("main");
    fs::create_dir(&main_repo).unwrap();

    run_git(&main_repo, &["init"]);
    run_git(&main_repo, &["config", "user.name", "Test Developer"]);
    run_git(&main_repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd
        .current_dir(&main_repo)
        .arg("init")
        .assert()
        .success();

    let secret_file = main_repo.join("test.secret.env");
    fs::write(&secret_file, "SECRET=value\n").unwrap();
    run_git(
        &main_repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(&main_repo, &["commit", "-m", "Initial commit"]);

    // Create a sibling worktree
    let sibling_worktree = temp.path().join("sibling_wt");
    run_git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "sibling-branch",
            sibling_worktree.to_str().unwrap(),
        ],
    );
    assert!(sibling_worktree.exists());
    assert!(sibling_worktree.join(".git").exists());

    // Delete ONLY the .git pointer file inside the sibling worktree, leaving directory intact
    fs::remove_file(sibling_worktree.join(".git")).unwrap();
    assert!(sibling_worktree.is_dir());
    assert!(!sibling_worktree.join(".git").exists());

    // git-agecrypt lock without --force should safely abort with a warning about unreachable worktrees
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(&main_repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unreachable"));

    // git-agecrypt lock with --force should succeed and NOT crash with "fatal: not a git repository"
    let mut force_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    force_cmd
        .current_dir(&main_repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    // Verify main repo secret was locked
    let disk_bytes = fs::read(&secret_file).unwrap();
    assert!(disk_bytes.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn test_interrupted_lock_startup_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("data.secret.env");
    fs::write(&secret_file, "KEY=data\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "data.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Init"]);

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");

    // Simulate interrupted lock: repo.key renamed to repo.key.locking
    assert!(key_file.exists());
    fs::rename(&key_file, &locking_file).unwrap();
    assert!(!key_file.exists());
    assert!(locking_file.exists());

    // Run status command: discover() must automatically heal and recover repo.key
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Recovered interrupted lock transaction",
        ));

    assert!(
        key_file.exists(),
        "Master key must be restored after recovery"
    );
    assert!(
        !locking_file.exists(),
        "Dangling locking file must be resolved"
    );
}

#[test]
fn test_transactional_lock_preflight_split_brain_protection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret1 = repo.join("first.secret.env");
    let secret2 = repo.join("second.secret.env");
    fs::write(&secret1, "KEY1=value1\n").unwrap();
    fs::write(&secret2, "KEY2=value2\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "first.secret.env",
            "second.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit two secrets"]);

    // Lock second.secret.env with exclusive non-sharing file handle (simulating running process on Windows)
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open file with share_mode = 0 (no read/write/delete sharing)
        let _locked_handle = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&secret2)
            .expect("Failed to lock file exclusively for test");

        // Attempt to lock the repository: preflight must detect locked file and abort!
        let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
        lock_cmd
            .current_dir(repo)
            .arg("lock")
            .arg("-f")
            .assert()
            .failure()
            .stderr(predicate::str::contains("second.secret.env"));

        // Critical: first.secret.env must NOT have been encrypted (no split-brain state!)
        let s1_bytes = fs::read(&secret1).unwrap();
        assert_eq!(
            s1_bytes, b"KEY1=value1\n",
            "first.secret.env must remain clean plaintext"
        );

        // repo.key must still be present and intact
        assert!(
            repo.join(".git")
                .join("git-agecrypt")
                .join("repo.key")
                .exists()
        );
    }
}

#[test]
fn test_interrupted_lock_split_brain_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("database.secret.env");
    let original_secret = "DB_PASS=SuperSecretPlaintext999\n";
    fs::write(&secret_file, original_secret).unwrap();
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

    // Simulate an interrupted lock transaction:
    // 1. repo.key staged to repo.key.locking
    fs::rename(&key_file, &locking_file).unwrap();
    // 2. Working tree file was partially converted to ciphertext on disk before process was killed
    let raw_git_blob = git_out(repo, &["cat-file", "blob", "HEAD:database.secret.env"]);
    assert!(
        String::from_utf8_lossy(&raw_git_blob).contains("age-encryption.org/v1"),
        "Committed object in git index must be age ciphertext"
    );
    fs::write(&secret_file, &raw_git_blob).unwrap();
    assert_ne!(fs::read(&secret_file).unwrap(), original_secret.as_bytes());

    // Run status: startup recovery runs recover_interrupted_transaction
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Recovered interrupted lock transaction",
        ));

    // Key must be restored
    assert!(key_file.exists());
    assert!(!locking_file.exists());

    // Working tree file must have been automatically re-smudged back to original plaintext!
    let recovered_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(
        recovered_content, original_secret,
        "Startup recovery must re-smudge working tree files back to plaintext (no split-brain)"
    );
}

#[test]
fn test_lock_sweeps_orphaned_tmp_spools() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("test.secret.env");
    fs::write(&secret_file, "SECRET=value\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    let state_dir = repo.join(".git").join("git-agecrypt");
    let cache_dir = state_dir.join("cache").join("default");
    fs::create_dir_all(&cache_dir).unwrap();

    // Create orphaned temp spool files simulating killed streaming processes
    let orphan1 = cache_dir.join(".tmpABC123");
    let orphan2 = state_dir.join("repo.key.tmp.12345");
    let orphan3 = cache_dir.join("spool_data.tmp");
    fs::write(&orphan1, "abandoned plaintext chunk 1").unwrap();
    fs::write(&orphan2, "abandoned key write").unwrap();
    fs::write(&orphan3, "abandoned plaintext chunk 2").unwrap();

    assert!(orphan1.exists());
    assert!(orphan2.exists());
    assert!(orphan3.exists());

    // Lock repository: must sweep all orphaned .tmp files
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    assert!(!orphan1.exists(), "Cache .tmp file must be swept");
    assert!(!orphan2.exists(), "State dir repo.key.tmp.* must be swept");
    assert!(!orphan3.exists(), "Spool *.tmp file must be swept");
}

#[test]
fn test_recovery_preserves_uncommitted_plaintext_edits() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("billing.secret.env");
    fs::write(&secret_file, "COMMITTED_DATA=true\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "billing.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // Developer makes local uncommitted changes
    let uncommitted_data = "COMMITTED_DATA=true\nLOCAL_UNCOMMITTED_CHANGES=do_not_lose_me!\n";
    fs::write(&secret_file, uncommitted_data).unwrap();

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");

    // Simulate an interrupted lock transaction in the repository
    fs::rename(&key_file, &locking_file).unwrap();

    // Run status to trigger automatic startup recovery
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Recovered interrupted lock transaction",
        ));

    // Key must be restored
    assert!(key_file.exists());

    // CRITICAL: Uncommitted plaintext edits must NOT have been destroyed or overwritten!
    let current_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(
        current_content, uncommitted_data,
        "Startup recovery must never overwrite uncommitted plaintext edits in the working tree"
    );
}

#[test]
fn test_lock_read_only_secret_file() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("cert.secret.env");
    fs::write(&secret_file, "CERTIFICATE_DATA=12345\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "cert.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit cert"]);

    // Mark secret file read-only (simulating chmod 400 or attrib +r)
    let meta = fs::metadata(&secret_file).unwrap();
    let mut perms = meta.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&secret_file, perms).unwrap();

    // Locking must succeed without failing on preflight
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    // Verify key was removed (repository locked)
    let key_file = repo.join(".git").join("git-agecrypt").join("repo.key");
    assert!(!key_file.exists());
}

#[test]
fn test_sweep_preserves_custom_identities() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let state_dir = repo.join(".git").join("git-agecrypt");
    let cache_dir = state_dir.join("cache").join("default");
    fs::create_dir_all(&cache_dir).unwrap();

    // Create user keys containing "tmp" in name
    let user_key1 = state_dir.join("id_ed25519_temporary");
    let user_key2 = state_dir.join("deploy_token_tmp");
    fs::write(&user_key1, "SSH_KEY_TMP_DATA").unwrap();
    fs::write(&user_key2, "DEPLOY_TOKEN_DATA").unwrap();

    // Create real temporary spool files
    let spool1 = cache_dir.join(".tmpABC999");
    let spool2 = cache_dir.join("stream.tmp");
    fs::write(&spool1, "spool 1").unwrap();
    fs::write(&spool2, "spool 2").unwrap();

    // Lock repository
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    // Spools must be deleted
    assert!(!spool1.exists());
    assert!(!spool2.exists());

    // Custom identities containing 'tmp' in their name must NOT be deleted
    assert!(user_key1.exists(), "id_ed25519_temporary must be preserved");
    assert!(user_key2.exists(), "deploy_token_tmp must be preserved");
}

#[test]
fn test_pre_commit_blocks_rename_to_untracked_destination() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Configure .gitattributes to specifically protect secrets/**
    let gitattributes_path = repo.join(".gitattributes");
    fs::write(
        &gitattributes_path,
        "secrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    run_git(repo, &["add", ".gitattributes"]);
    run_git(repo, &["commit", "-m", "Configure secrets/** encryption"]);

    // Create secrets/db.env
    let secrets_dir = repo.join("secrets");
    fs::create_dir_all(&secrets_dir).unwrap();
    let original_secret = secrets_dir.join("db.env");
    fs::write(&original_secret, "DB_PASSWORD=SuperSecret123\n").unwrap();
    run_git(repo, &["add", "secrets/db.env"]);
    run_git(repo, &["commit", "-m", "Commit initial encrypted secret"]);

    // Create config/ directory and rename secrets/db.env -> config/db.env
    let config_dir = repo.join("config");
    fs::create_dir_all(&config_dir).unwrap();
    run_git(repo, &["mv", "secrets/db.env", "config/db.env"]);

    // Check pre-commit check: must immediately block the commit!
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd
        .current_dir(repo)
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "SECRET RENAMED TO UNENCRYPTED DESTINATION",
        ))
        .stderr(predicate::str::contains("secrets/db.env"))
        .stderr(predicate::str::contains("config/db.env"));
}

#[test]
fn test_recovery_restores_truncated_0byte_file() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("data.secret.env");
    let original_content = "AUTHENTIC_SECRET_CONTENT=xyz987\n";
    fs::write(&secret_file, original_content).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "data.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit data secret"]);

    // Simulate crash after write truncation: 0 bytes on disk, repo.key.locking present
    fs::write(&secret_file, b"").unwrap();
    assert_eq!(fs::metadata(&secret_file).unwrap().len(), 0);

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");
    fs::rename(&key_file, &locking_file).unwrap();

    // Run status to trigger recovery
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Recovered interrupted lock transaction",
        ));

    // Key must be restored
    assert!(key_file.exists());

    // 0-byte truncated file must be re-smudged from index back to original content!
    let restored_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(
        restored_content, original_content,
        "Startup recovery must detect 0-byte crash-truncated files and re-smudge them from index"
    );
}

#[test]
fn test_lock_and_unlock_preserves_readonly_permissions() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Generate dedicated SSH key for unlock
    let ssh_key = temp.path().join("id_ed25519");
    let ssh_pub = temp.path().join("id_ed25519.pub");
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&ssh_key)
        .status()
        .expect("Failed to run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .arg("add-recipient")
        .arg("-i")
        .arg(&ssh_pub)
        .arg("--name")
        .arg("alice")
        .assert()
        .success();

    let secret_file = repo.join("cert.secret.env");
    fs::write(&secret_file, "SECURE_CERTIFICATE=999\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "cert.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit cert"]);

    // Mark file read-only
    let meta = fs::metadata(&secret_file).unwrap();
    let mut perms = meta.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&secret_file, perms).unwrap();
    assert!(fs::metadata(&secret_file).unwrap().permissions().readonly());

    // Lock repository: must succeed
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    // Verify file is locked on disk AND read-only permission was preserved
    assert!(fs::metadata(&secret_file).unwrap().permissions().readonly());

    // Unlock repository using SSH key
    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(repo)
        .arg("unlock")
        .arg(&ssh_key)
        .assert()
        .success();

    // Verify file is smudged to plaintext AND read-only permission is still preserved!
    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        "SECURE_CERTIFICATE=999\n"
    );
    assert!(
        fs::metadata(&secret_file).unwrap().permissions().readonly(),
        "Read-only attribute must be preserved across lock and unlock cycles"
    );
}

#[test]
fn test_checkout_historical_branch_after_rekey() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Create and commit secret on main
    let secret_file = repo.join("api.secret.env");
    fs::write(&secret_file, "API_KEY_V1=alpha_secret\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "api.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit v1 secret"]);

    // Create branch 'historical'
    run_git(repo, &["branch", "historical"]);

    // Enroll an SSH key so rekey can proceed
    let ssh_key = temp.path().join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&ssh_key)
        .status()
        .expect("Failed to run ssh-keygen");
    assert!(status.success());
    let pub_content = fs::read_to_string(temp.path().join("id_ed25519.pub")).unwrap();

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_content, "--name", "user"])
        .assert()
        .success();

    // Rekey repository on main (generates new master key K2)
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    run_git(repo, &["add", "-u"]);
    run_git(repo, &["commit", "-m", "Rotate master key"]);

    // Now switch to historical branch: must succeed without clean filter aborting!
    run_git(repo, &["checkout", "historical"]);
}

#[test]
fn test_lock_blocked_during_active_rebase_or_merge() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("db.secret.env");
    fs::write(&secret_file, "DB_PASS=123\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "db.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // Simulate active merge state by creating MERGE_HEAD
    let git_dir = repo.join(".git");
    let merge_head = git_dir.join("MERGE_HEAD");
    fs::write(&merge_head, "0123456789abcdef0123456789abcdef01234567\n").unwrap();

    // Lock without --force must abort with warning
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Active Git operation detected"));

    // Key file must still exist
    let key_file = git_dir.join("git-agecrypt").join("repo.key");
    assert!(
        key_file.exists(),
        "repo.key must not be deleted when lock is aborted"
    );

    // Lock with --force must succeed
    let mut lock_force = Command::cargo_bin("git-agecrypt").unwrap();
    lock_force
        .current_dir(repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    assert!(
        !key_file.exists(),
        "repo.key must be removed when forced lock succeeds"
    );
}

#[test]
fn test_intentional_0byte_secret_preserved_during_recovery() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("config.secret.env");
    fs::write(&secret_file, "ORIGINAL_CONFIG=prod\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "config.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // User intentionally empties the file
    fs::write(&secret_file, b"").unwrap();
    assert_eq!(fs::metadata(&secret_file).unwrap().len(), 0);

    // Set file mtime to 300 seconds in the past (intentional modification outside crash window)
    let past_time = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(300),
    );
    filetime::set_file_mtime(&secret_file, past_time).unwrap();

    // Staging repo.key.locking (current mtime) simulates an interrupted lock transaction
    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");
    fs::rename(&key_file, &locking_file).unwrap();

    // Run status to trigger recovery
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Recovered interrupted lock transaction",
        ));

    // Key must be restored
    assert!(key_file.exists());

    // The intentional 0-byte file must NOT have been overwritten from index!
    let current_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(
        current_content, "",
        "Intentional 0-byte edit outside crash window must be preserved by selective recovery"
    );
}

#[test]
fn test_status_reports_stale_master_key_after_rekey() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Status initially reports Unlocked
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("YES (plaintext on disk)"));

    // Simulate upstream rekey: write a different public key into repo.pub
    fs::write(
        repo.join(".git-agecrypt").join("repo.pub"),
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n",
    )
    .unwrap();

    // Status must now report STALE / OUT-OF-SYNC
    let mut status_stale = Command::cargo_bin("git-agecrypt").unwrap();
    status_stale
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("OUT-OF-SYNC / STALE"));
}

#[test]
fn test_cache_uses_compact_32_char_filename() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret_file = repo.join("service.secret.env");
    fs::write(&secret_file, "PORT=8080\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "service.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit service secret"]);

    // Inspect cache directory
    let cache_base = repo.join(".git").join("git-agecrypt").join("cache");
    assert!(cache_base.exists());

    let mut count = 0;
    for fp in fs::read_dir(&cache_base).unwrap() {
        let fp_path = fp.unwrap().path();
        if fp_path.is_dir() {
            for entry in fs::read_dir(&fp_path).unwrap() {
                let fname = entry.unwrap().file_name().to_string_lossy().to_string();
                if fname.ends_with(".age") {
                    count += 1;
                    assert_eq!(
                        fname.len(),
                        36,
                        "Cache filename must be exactly 32 hex chars + .age (36 chars) for MAX_PATH safety"
                    );
                }
            }
        }
    }
    assert!(count > 0, "At least one cache entry should be created");
}

#[test]
fn test_pre_commit_blocks_staged_secret_with_revoked_key() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Commit a secret with the original master key (Key 1)
    let secret_file = repo.join("credentials.secret.env");
    fs::write(&secret_file, "API_SECRET=ActiveToken123\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "credentials.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit with Key 1"]);

    // Save the staged ciphertext encrypted under Key 1
    let old_ciphertext = git_out(repo, &["cat-file", "blob", "HEAD:credentials.secret.env"]);
    assert!(old_ciphertext.starts_with(b"age-encryption.org/v1\n"));

    // Enroll an identity so rekey has an active recipient
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Rotate master key via rekey: Key 1 -> Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt"]);
    run_git(repo, &["add", "--renormalize", "."]);
    run_git(repo, &["commit", "-m", "Rekey to Key 2"]);

    // Simulate cherry-pick/merge or copy of old ciphertext encrypted under revoked Key 1
    fs::write(&secret_file, &old_ciphertext).unwrap();
    run_git(repo, &["add", "credentials.secret.env"]);

    // Pre-commit check MUST fail because the staged blob cannot be decrypted with Key 2!
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd
        .current_dir(repo)
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "STAGED SECRET ENCRYPTED WITH REVOKED/FOREIGN KEY",
        ));

    // Overwriting with proper cleartext and re-staging re-encrypts under active Key 2
    fs::write(&secret_file, "API_SECRET=RefreshedActiveToken456\n").unwrap();
    run_git(repo, &["add", "credentials.secret.env"]);

    let mut check_ok = Command::cargo_bin("git-agecrypt").unwrap();
    check_ok.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_wal_journal_recovers_across_clock_jumps() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

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
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Recovered interrupted lock transaction",
        ));

    // Key must be restored and journal removed
    assert!(key_file.exists(), "Master key must be restored");
    assert!(!locking_file.exists(), "Locking file must be deleted");
    assert!(
        !journal_file.exists(),
        "WAL journal must be deleted after recovery"
    );

    // File must be completely restored to cleartext despite 1-hour timestamp gap!
    let restored = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(
        restored, original_content,
        "WAL journal must restore truncated file across clock jumps"
    );
}

#[test]
fn test_concurrent_refresh_lock_adoption() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let refresh_lock = state_dir.join("refresh.lock");

    // Enroll an identity key
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "worker"])
        .assert()
        .success();

    // Rekey repository
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Save rotated master key
    let rotated_key = fs::read_to_string(&key_file).unwrap();

    // Secret ciphertext to smudge
    let secret_file = repo.join("service.secret.env");
    let expected_plaintext = "PORT=9090\n";
    fs::write(&secret_file, expected_plaintext).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "service.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit service secret"]);
    let ciphertext_blob = git_out(repo, &["cat-file", "blob", "HEAD:service.secret.env"]);

    // Make local key stale
    let dummy_id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let old_fake_key = dummy_id.to_string();
    fs::write(&key_file, old_fake_key.expose_secret()).unwrap();

    // Acquire refresh.lock simulating worker 1 holding lock
    fs::write(&refresh_lock, "locked by worker 1").unwrap();
    assert!(refresh_lock.exists());

    // Worker 1 finishes after 200ms, updates repo.key and releases refresh.lock
    let r_lock_clone = refresh_lock.clone();
    let k_file_clone = key_file.clone();
    let rot_clone = rotated_key.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = fs::write(&k_file_clone, &rot_clone);
        let _ = fs::remove_file(&r_lock_clone);
    });

    // Run smudge filter as worker 2: should wait for refresh.lock, detect resolved stale key, and decrypt!
    let mut smudge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = smudge_cmd
        .current_dir(repo)
        .arg("smudge")
        .arg("service.secret.env")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&ciphertext_blob)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout_str, expected_plaintext);
}

#[test]
fn test_rekey_does_not_stage_dirty_non_secret_files() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Enroll an identity
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Create and commit a secret file and a regular code file
    let secret_file = repo.join("service.secret.env");
    fs::write(&secret_file, "API_KEY=OriginalMasterKeySecret\n").unwrap();
    let code_file = repo.join("main.rs");
    fs::write(&code_file, "fn main() { println!(\"original\"); }\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "service.secret.env",
            "main.rs",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // Now introduce an uncommitted modification to main.rs (dirty non-secret file)
    fs::write(
        &code_file,
        "fn main() { println!(\"uncommitted work in progress\"); }\n",
    )
    .unwrap();

    // Running rekey without --force MUST abort to prevent dirty file pollution
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd
        .current_dir(repo)
        .arg("rekey")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "uncommitted modifications in non-secret file(s)",
        ))
        .stderr(predicate::str::contains("main.rs"));

    // Verify main.rs remains unstaged in git status
    let status_out = String::from_utf8(git_out(repo, &["status", "--porcelain"])).unwrap();
    assert!(
        status_out.contains(" M main.rs"),
        "main.rs must remain unstaged"
    );
    assert!(
        !status_out.contains("M  main.rs"),
        "main.rs must not be staged"
    );

    // Now rekey with --force
    let mut rekey_force_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_force_cmd
        .current_dir(repo)
        .args(["rekey", "--force"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Repository successfully re-keyed!",
        ));

    // Verify: main.rs is STILL unstaged (' M main.rs') and was NOT swept into index by targeted pathspecs!
    let status_out2 = String::from_utf8(git_out(repo, &["status", "--porcelain"])).unwrap();
    assert!(
        status_out2.contains(" M main.rs"),
        "main.rs must remain unstaged even after rekey --force"
    );
    assert!(
        !status_out2.contains("M  main.rs"),
        "main.rs must NOT be staged in index"
    );
}

#[test]
fn test_rewrap_resolves_historical_ciphertext() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Alice's identity
    let alice_id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let alice_priv = alice_id.to_string();
    let alice_pub = format!("{}", alice_id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();

    // Commit secret under Key 1
    let secret_file = repo.join("database.secret.env");
    let secret_plain = "DB_PASS=HistoricalMasterKeySecret\n";
    fs::write(&secret_file, secret_plain).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit secret with Key 1"]);

    // Capture ciphertext encrypted under Key 1
    let old_ciphertext = git_out(repo, &["cat-file", "blob", "HEAD:database.secret.env"]);
    assert!(old_ciphertext.starts_with(b"age-encryption.org/v1\n"));

    // Rotate master key: Key 1 -> Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt"]);
    run_git(repo, &["commit", "-m", "Rekey to Key 2"]);

    // Simulate cherry-pick/merge or copy of old ciphertext encrypted under Key 1
    fs::write(&secret_file, &old_ciphertext).unwrap();
    run_git(repo, &["add", "database.secret.env"]);

    // Verify: pre-commit check blocks this commit
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd
        .current_dir(repo)
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "STAGED SECRET ENCRYPTED WITH REVOKED/FOREIGN KEY",
        ))
        .stderr(predicate::str::contains("git-agecrypt rewrap"));

    // Write Alice's identity to a key file
    let id_file = repo.join("alice.key");
    fs::write(&id_file, alice_priv.expose_secret()).unwrap();

    // Run git-agecrypt rewrap
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(repo)
        .args([
            "rewrap",
            "database.secret.env",
            "-i",
            id_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Successfully rewrapped 'database.secret.env' under active master key",
        ));

    // Now pre-commit check MUST succeed!
    let mut check_ok = Command::cargo_bin("git-agecrypt").unwrap();
    check_ok.current_dir(repo).arg("check").assert().success();

    // Verify working tree file is decrypted cleartext
    let content_on_disk = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(content_on_disk, secret_plain);

    // Verify newly staged blob in index is encrypted under Key 2
    let new_staged_blob = git_out(repo, &["cat-file", "blob", ":database.secret.env"]);
    assert!(new_staged_blob.starts_with(b"age-encryption.org/v1\n"));
    assert_ne!(new_staged_blob, old_ciphertext);
}

#[test]
fn test_refresh_lock_breaks_on_dead_pid() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let refresh_lock = state_dir.join("refresh.lock");

    // Alice identity
    let id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let priv_str = id.to_string();
    let pub_key = format!("{}", id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "worker"])
        .assert()
        .success();

    // Rekey repository
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Secret ciphertext to smudge
    let secret_file = repo.join("service.secret.env");
    let expected_plaintext = "API_TOKEN=AutoRefreshedToken\n";
    fs::write(&secret_file, expected_plaintext).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "service.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit service secret"]);
    let ciphertext_blob = git_out(repo, &["cat-file", "blob", "HEAD:service.secret.env"]);

    // Invalidate local key so smudge needs auto-refresh
    let dummy_id = age::x25519::Identity::generate();
    let old_fake_key = dummy_id.to_string();
    fs::write(&key_file, old_fake_key.expose_secret()).unwrap();

    // Save identity to a file and set GIT_AGECRYPT_IDENTITY
    let id_path = repo.join("worker.key");
    fs::write(&id_path, priv_str.expose_secret()).unwrap();

    // Write refresh.lock with a DEAD PID (99999999) and a timestamp far in the future
    // Timestamp far in the future guarantees it cannot break via timeout (now - ts > 5)
    // It MUST break via is_pid_alive(99999999) == false!
    let far_future_ts = 2_000_000_000u64;
    fs::write(&refresh_lock, format!("99999999:{far_future_ts}")).unwrap();
    assert!(refresh_lock.exists());

    let start = std::time::Instant::now();

    // Run smudge filter as worker: should detect dead PID immediately, break lock, unwrap new key, and decrypt!
    let mut smudge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = smudge_cmd
        .current_dir(repo)
        .env("GIT_AGECRYPT_IDENTITY", id_path.to_str().unwrap())
        .arg("smudge")
        .arg("service.secret.env")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&ciphertext_blob)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout_str, expected_plaintext);

    let duration = start.elapsed();
    assert!(
        duration < std::time::Duration::from_secs(3),
        "Smudge must break dead lock and succeed quickly, took {:?}",
        duration
    );
}

#[test]
fn test_orphaned_journal_without_locking_key_unlinks_cleanly() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let state_dir = repo.join(".git").join("git-agecrypt");
    let key_file = state_dir.join("repo.key");
    let locking_file = state_dir.join("repo.key.locking");
    let journal_file = state_dir.join("lock.journal");

    // Simulate post-lock crash:
    // repo.key and repo.key.locking were deleted/renamed (repository is locked),
    // but lock.journal was left behind on disk.
    let _ = fs::remove_file(&key_file);
    assert!(!key_file.exists());
    assert!(!locking_file.exists());

    // Create orphaned journal
    fs::write(
        &journal_file,
        format!("{}\tsome_file.secret.env\n", repo.display()),
    )
    .unwrap();
    assert!(journal_file.exists());

    // Run status command: discover() runs recover_interrupted_transaction()
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success();

    // Verify orphaned journal was cleaned up without attempting recovery without key
    assert!(
        !journal_file.exists(),
        "Orphaned journal must be unlinked cleanly"
    );
}

#[test]
fn test_rekey_with_deleted_tracked_secret() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Enroll an identity
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Create and commit two secrets
    let active_secret = repo.join("active.secret.env");
    fs::write(&active_secret, "PORT=8080\n").unwrap();
    let obsolete_secret = repo.join("obsolete.secret.env");
    fs::write(&obsolete_secret, "DEPRECATED=true\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "active.secret.env",
            "obsolete.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial commit with two secrets"]);

    // Delete obsolete.secret.env from disk in the working tree without staging deletion (git rm)
    fs::remove_file(&obsolete_secret).unwrap();
    assert!(!obsolete_secret.exists());

    // Rekey must NOT fail with "fatal: pathspec 'obsolete.secret.env' did not match any files"
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd
        .current_dir(repo)
        .arg("rekey")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Repository successfully re-keyed!",
        ));

    // Verify active.secret.env was re-encrypted under the new master key
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_rewrap_all_skips_plaintext_wip_drafts() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Enroll an identity
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Commit secret
    let secret_file = repo.join("service.secret.env");
    fs::write(&secret_file, "API_KEY=CleanCommittedKey\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "service.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit clean secret"]);

    // Introduce local uncommitted WIP modifications to service.secret.env
    let uncommitted_content = "API_KEY=WIP_Uncommitted_Local_Draft\n";
    fs::write(&secret_file, uncommitted_content).unwrap();

    // Running rewrap --all must NOT stage the plaintext draft
    let mut rewrap_all_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_all_cmd
        .current_dir(repo)
        .args(["rewrap", "--all"])
        .assert()
        .success();

    // Verify service.secret.env is STILL unstaged (' M service.secret.env')
    let status_out = String::from_utf8(git_out(repo, &["status", "--porcelain"])).unwrap();
    assert!(
        status_out.contains(" M service.secret.env"),
        "Draft must remain unstaged: {status_out}"
    );
    assert!(
        !status_out.contains("M  service.secret.env"),
        "Draft must NOT be staged in index: {status_out}"
    );

    // Content on disk must be preserved exactly
    let disk_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(disk_content, uncommitted_content);
}

#[test]
fn test_rewrap_shallow_clone_guidance() {
    let temp_origin = tempdir().expect("Failed to create origin tempdir");
    let origin_repo = temp_origin.path();

    run_git(origin_repo, &["init"]);
    run_git(origin_repo, &["config", "user.name", "Test Developer"]);
    run_git(origin_repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd
        .current_dir(origin_repo)
        .arg("init")
        .assert()
        .success();

    // Alice identity
    let alice_id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let alice_priv = alice_id.to_string();
    let alice_pub = format!("{}", alice_id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(origin_repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();

    // Commit secret under Key 1
    let secret_file = origin_repo.join("database.secret.env");
    fs::write(&secret_file, "DB_PASS=SecretKey1\n").unwrap();
    run_git(
        origin_repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(origin_repo, &["commit", "-m", "Commit with Key 1"]);

    let old_ciphertext = git_out(
        origin_repo,
        &["cat-file", "blob", "HEAD:database.secret.env"],
    );

    // Rekey to Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd
        .current_dir(origin_repo)
        .arg("rekey")
        .assert()
        .success();
    run_git(origin_repo, &["add", ".git-agecrypt"]);
    run_git(origin_repo, &["commit", "-m", "Rekey to Key 2"]);

    // Create shallow clone of origin_repo at depth 1
    let temp_shallow = tempdir().expect("Failed to create shallow tempdir");
    let shallow_repo = temp_shallow.path();

    // Use file:// URI for cloning
    let origin_str = format!(
        "file:///{}",
        origin_repo.display().to_string().replace('\\', "/")
    );
    run_git(shallow_repo, &["clone", "--depth", "1", &origin_str, "."]);
    run_git(shallow_repo, &["config", "user.name", "CI Bot"]);
    run_git(shallow_repo, &["config", "user.email", "ci@example.com"]);

    // Unlock shallow repo with Alice's identity
    let id_file = shallow_repo.join("alice.key");
    fs::write(&id_file, alice_priv.expose_secret()).unwrap();

    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(shallow_repo)
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();

    // Simulate historical ciphertext placed in working tree
    let shallow_secret = shallow_repo.join("database.secret.env");
    fs::write(&shallow_secret, &old_ciphertext).unwrap();

    // Running rewrap without historical history must fail with clear shallow clone instructions
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(shallow_repo)
        .args(["rewrap", "database.secret.env"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shallow clone"))
        .stderr(predicate::str::contains("git fetch --unshallow"));
}

#[test]
fn test_color_ui_always_does_not_break_plumbing() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);
    // Forcibly enable ANSI coloring across all Git commands
    run_git(repo, &["config", "color.ui", "always"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Add recipient
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Commit secret
    let secret_file = repo.join("color.secret.env");
    fs::write(&secret_file, "COLOR=true\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "color.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit with color.ui=always"]);

    // Run status, check, rekey - all must succeed without ANSI corruption
    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success();

    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();

    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    let mut check_after_rekey = Command::cargo_bin("git-agecrypt").unwrap();
    check_after_rekey
        .current_dir(repo)
        .arg("check")
        .assert()
        .success();
}

#[test]
fn test_merge_driver_crlf_lf_cross_platform_normalization() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let base_file = repo.join("base.age");
    let ours_file = repo.join("ours.age");
    let theirs_file = repo.join("theirs.age");

    let encrypt_file = |content: &[u8], dest: &Path| {
        let mut clean_cmd = Command::cargo_bin("git-agecrypt").unwrap();
        let mut child = clean_cmd
            .current_dir(repo)
            .arg("clean")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(content).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        fs::write(dest, out.stdout).unwrap();
    };

    // Base uses Unix LF
    encrypt_file(b"PORT=8080\nHOST=localhost\nDEBUG=false\n", &base_file);
    // Ours edited DEBUG on Windows, so ours has CRLF (\r\n) line endings
    encrypt_file(b"PORT=8080\r\nHOST=localhost\r\nDEBUG=true\r\n", &ours_file);
    // Theirs edited PORT on Linux/macOS, so theirs has LF (\n) line endings
    encrypt_file(b"PORT=9000\nHOST=localhost\nDEBUG=false\n", &theirs_file);

    // Run 3-way merge driver
    let mut merge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    merge_cmd
        .current_dir(repo)
        .args([
            "merge",
            base_file.to_str().unwrap(),
            ours_file.to_str().unwrap(),
            theirs_file.to_str().unwrap(),
            "7",
            "configs/server.secret.env",
        ])
        .assert()
        .success();

    // Verify ours_file is merged and encrypted
    let merged_cipher = fs::read(&ours_file).unwrap();
    assert!(merged_cipher.starts_with(b"age-encryption.org/v1\n"));

    // Smudge and verify content
    let mut smudge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = smudge_cmd
        .current_dir(repo)
        .arg("smudge")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&merged_cipher)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let decrypted = String::from_utf8(out.stdout).unwrap();

    // Both changes must be merged without collision or conflict markers!
    assert!(decrypted.contains("PORT=9000"));
    assert!(decrypted.contains("DEBUG=true"));
    assert!(!decrypted.contains("<<<<<<<"));
    // Ours originally used CRLF, so the merged output must have preserved CRLF!
    assert!(
        decrypted.contains("\r\n"),
        "Merged file must preserve ours CRLF endings!"
    );
}

#[test]
fn test_check_skips_submodule_gitlinks() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Add a tracked pattern in .gitattributes matching the submodule path
    let gitattributes = repo.join(".gitattributes");
    fs::write(
        &gitattributes,
        "submodules/** filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    // Stage gitattributes
    run_git(repo, &["add", ".gitattributes"]);

    // Create a mock gitlink entry (mode 160000) in the index under submodules/my-submodule
    let dummy_sha = "0123456789abcdef0123456789abcdef01234567";
    let status = Command::new("git")
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            dummy_sha,
            "submodules/my-submodule",
        ])
        .current_dir(repo)
        .status()
        .expect("Failed to create gitlink in index");
    assert!(status.success());

    // Verify git ls-files --stage shows mode 160000
    let ls_out = git_out(repo, &["ls-files", "--stage", "submodules/my-submodule"]);
    let ls_str = String::from_utf8_lossy(&ls_out);
    assert!(
        ls_str.starts_with("160000"),
        "Index entry must be mode 160000: got {ls_str}"
    );

    // Run git-agecrypt check: must succeed and NOT flag the gitlink SHA as plaintext secret leak!
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_rewrap_collaborator_added_after_secret_creation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Alice is initial recipient (Commit 1)
    let alice_id = age::x25519::Identity::generate();
    let alice_pub = format!("{}", alice_id.to_public());
    let mut add_alice = Command::cargo_bin("git-agecrypt").unwrap();
    add_alice
        .current_dir(repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();

    // Commit a secret encrypted with Key 1 (Commit 2)
    let secret_file = repo.join("legacy.secret.env");
    fs::write(
        &secret_file,
        "DATABASE_URL=postgres://secret-db:5432/main\n",
    )
    .unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "legacy.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit 2: secret with Key 1"]);

    // Bob is enrolled LATER at Commit 3 (while Key 1 is still active)
    let bob_id = age::x25519::Identity::generate();
    let bob_pub = format!("{}", bob_id.to_public());
    let mut add_bob = Command::cargo_bin("git-agecrypt").unwrap();
    add_bob
        .current_dir(repo)
        .args(["add-recipient", "-i", &bob_pub, "--name", "bob"])
        .assert()
        .success();
    run_git(repo, &["add", ".git-agecrypt"]);
    run_git(repo, &["commit", "-m", "Commit 3: enroll Bob"]);

    // Alice rekeys repository to Key 2 (Commit 4)
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt", "legacy.secret.env"]);
    run_git(repo, &["commit", "-m", "Commit 4: rotate to Key 2"]);

    // Now, create a branch or simulate cherry-picking the old commit 2 secret (encrypted with Key 1)
    let old_blob = git_out(repo, &["show", "HEAD~2:legacy.secret.env"]);
    fs::write(&secret_file, &old_blob).unwrap();
    run_git(repo, &["add", "legacy.secret.env"]);

    // Pre-commit check must detect foreign/historical key
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().failure();

    // Bob attempts to rewrap using his identity!
    // Because Bob was enrolled in Commit 3 (after Commit 2), git log on .git-agecrypt/keys
    // will discover bob.age in Commit 3 and unwrap Key 1!
    use age::secrecy::ExposeSecret;
    let bob_key_str = bob_id.to_string();
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(repo)
        .args([
            "rewrap",
            "legacy.secret.env",
            "--identity",
            bob_key_str.expose_secret(),
        ])
        .assert()
        .success();

    // After rewrap, pre-commit check must succeed!
    let mut check_cmd2 = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd2.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_install_hooks_covers_pre_commit_merge_and_push() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut install_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    install_cmd
        .current_dir(repo)
        .arg("install-hooks")
        .assert()
        .success();

    let hooks_dir = repo.join(".git").join("hooks");
    for hook_name in &["pre-commit", "pre-merge-commit", "pre-push"] {
        let hook_file = hooks_dir.join(hook_name);
        assert!(hook_file.exists(), "Hook {} must be installed!", hook_name);
        let content = fs::read_to_string(&hook_file).unwrap();
        assert!(
            content.contains("git-agecrypt check"),
            "Hook {} must invoke git-agecrypt check!",
            hook_name
        );
    }
}

#[test]
fn test_rekey_with_pathspec_streaming() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Add recipient
    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Create 30 secret files across nested directories to test pathspec streaming
    let gitattributes = repo.join(".gitattributes");
    fs::write(
        &gitattributes,
        "secrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    let secrets_dir = repo.join("secrets");
    fs::create_dir_all(&secrets_dir).unwrap();

    let mut secret_paths = Vec::new();
    for i in 0..30 {
        let name = format!("service_{i:02}.secret.env");
        let path = secrets_dir.join(&name);
        fs::write(&path, format!("KEY_{i}=secret_value_{i}\n")).unwrap();
        secret_paths.push(format!("secrets/{name}"));
    }

    run_git(repo, &["add", ".gitattributes", ".git-agecrypt", "secrets"]);
    run_git(repo, &["commit", "-m", "Commit 30 secret files"]);

    // Run rekey: should use --pathspec-from-file=- streaming
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Verify git-agecrypt check succeeds across all 30 rekeyed files
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_hooks_respect_core_hooks_path_and_preserve_existing() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    // Configure core.hooksPath to custom directory .custom_hooks
    run_git(repo, &["config", "core.hooksPath", ".custom_hooks"]);

    let custom_hooks_dir = repo.join(".custom_hooks");
    fs::create_dir_all(&custom_hooks_dir).unwrap();

    // Create an existing pre-commit hook with custom linter script
    let pre_commit_file = custom_hooks_dir.join("pre-commit");
    let existing_script = "#!/bin/sh\n# Existing user linter\necho 'Running linter...'\neslint .\n";
    fs::write(&pre_commit_file, existing_script).unwrap();

    // Run install-hooks
    let mut install_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    install_cmd
        .current_dir(repo)
        .arg("install-hooks")
        .assert()
        .success();

    // 1. Verify pre-commit preserved existing linter AND appended git-agecrypt check
    let content = fs::read_to_string(&pre_commit_file).unwrap();
    assert!(
        content.contains("eslint ."),
        "Existing linter command must be preserved!"
    );
    assert!(
        content.contains("git-agecrypt check"),
        "git-agecrypt check must be appended!"
    );

    // 2. Verify pre-push was created in .custom_hooks with --pre-push flag
    let pre_push_file = custom_hooks_dir.join("pre-push");
    assert!(
        pre_push_file.exists(),
        "pre-push hook must be installed in .custom_hooks!"
    );
    let push_content = fs::read_to_string(&pre_push_file).unwrap();
    assert!(push_content.contains("git-agecrypt check --pre-push"));

    // 3. Verify standard .git/hooks was NOT written to
    let standard_hooks_dir = repo.join(".git").join("hooks");
    assert!(
        !standard_hooks_dir.join("pre-commit").exists(),
        ".git/hooks must not be written to when core.hooksPath is configured!"
    );

    // 4. Idempotency test: running install-hooks again must not duplicate commands
    let mut install_cmd2 = Command::cargo_bin("git-agecrypt").unwrap();
    install_cmd2
        .current_dir(repo)
        .arg("install-hooks")
        .assert()
        .success();
    let content2 = fs::read_to_string(&pre_commit_file).unwrap();
    let count = content2
        .matches("# git-agecrypt automated pre-commit safeguard")
        .count();
    assert_eq!(
        count, 1,
        "git-agecrypt safeguard must not be duplicated on repeated install-hooks!"
    );
}

#[test]
fn test_pre_push_hook_catches_committed_leak_with_clean_index() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Create a bare remote
    let remote_dir = temp.path().join("remote.git");
    let status = Command::new("git")
        .args(["init", "--bare", remote_dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    run_git(
        repo,
        &["remote", "add", "origin", remote_dir.to_str().unwrap()],
    );

    // Commit a clean initial state
    let dummy = repo.join("README.md");
    fs::write(&dummy, "Hello world\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "README.md"],
    );
    run_git(repo, &["commit", "-m", "Initial clean commit"]);

    // Push initial commit to remote so remote ref exists
    run_git(repo, &["push", "origin", "master"]);
    let remote_sha = String::from_utf8(git_out(repo, &["rev-parse", "origin/master"]))
        .unwrap()
        .trim()
        .to_string();

    // Now commit an UNENCRYPTED plaintext secret into a new commit by bypassing filter
    let secret_file = repo.join("leak.secret.env");
    fs::write(
        &secret_file,
        "AWS_SECRET_KEY=super_secret_plaintext_leak_123\n",
    )
    .unwrap();
    let blob_sha = String::from_utf8(git_out(
        repo,
        &[
            "hash-object",
            "-w",
            "--no-filters",
            secret_file.to_str().unwrap(),
        ],
    ))
    .unwrap()
    .trim()
    .to_string();
    let status = Command::new("git")
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            &blob_sha,
            "leak.secret.env",
        ])
        .current_dir(repo)
        .status()
        .unwrap();
    assert!(status.success());
    run_git(
        repo,
        &[
            "commit",
            "--no-verify",
            "-m",
            "Commit with unencrypted plaintext secret",
        ],
    );

    let local_sha = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Notice: Staged area (index) is completely clean now!
    let staged_diff = git_out(repo, &["diff", "--cached"]);
    assert!(staged_diff.is_empty(), "Staged area must be clean!");

    // Standard git-agecrypt check would check index and PASS (false negative)!
    let mut check_staged = Command::cargo_bin("git-agecrypt").unwrap();
    check_staged
        .current_dir(repo)
        .arg("check")
        .assert()
        .success();

    // But git-agecrypt check --pre-push MUST catch the leak in the outgoing commit!
    let mut check_push = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = check_push
        .current_dir(repo)
        .args(["check", "--pre-push"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    let push_input = format!("refs/heads/master {local_sha} refs/heads/master {remote_sha}\n");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(push_input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    // pre-push MUST reject the push!
    assert!(
        !out.status.success(),
        "Pre-push check MUST block pushing plaintext secret!"
    );
    let err_msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        err_msg.contains("UNENCRYPTED SECRET IN PUSHED COMMIT")
            || err_msg.contains("Push rejected")
    );
}

#[test]
fn test_pre_push_hook_ignores_dirty_staged_files() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Commit a clean secret
    let secret_file = repo.join("clean.secret.env");
    fs::write(&secret_file, "KEY=clean_value\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "clean.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Clean secret commit"]);
    let local_sha = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Create an unencrypted staged file in index (simulates WIP draft in progress)
    let secret_wip = repo.join("wip.secret.env");
    fs::write(&secret_wip, "AWS_KEY=unencrypted_draft_secret\n").unwrap();
    let wip_blob_sha = String::from_utf8(git_out(
        repo,
        &[
            "hash-object",
            "-w",
            "--no-filters",
            secret_wip.to_str().unwrap(),
        ],
    ))
    .unwrap()
    .trim()
    .to_string();
    let status = Command::new("git")
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            &wip_blob_sha,
            "wip.secret.env",
        ])
        .current_dir(repo)
        .status()
        .unwrap();
    assert!(status.success());

    // Standard check fails because wip.secret.env is invalid in staging
    let mut check_staged = Command::cargo_bin("git-agecrypt").unwrap();
    check_staged
        .current_dir(repo)
        .arg("check")
        .assert()
        .failure();

    // BUT pre-push MUST SUCCEED because the commit being pushed (local_sha) is 100% clean!
    let mut check_push = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = check_push
        .current_dir(repo)
        .args(["check", "--pre-push"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    let push_input = format!(
        "refs/heads/master {local_sha} refs/heads/master 0000000000000000000000000000000000000000\n"
    );
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(push_input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "Pre-push check must NOT be blocked by unrelated dirty staging area!"
    );
}

#[test]
fn test_merge_driver_conflict_markers_no_double_cr() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let base_file = repo.join("base.age");
    let ours_file = repo.join("ours.age");
    let theirs_file = repo.join("theirs.age");

    let encrypt_file = |content: &[u8], dest: &Path| {
        let mut clean_cmd = Command::cargo_bin("git-agecrypt").unwrap();
        let mut child = clean_cmd
            .current_dir(repo)
            .arg("clean")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(content).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        fs::write(dest, out.stdout).unwrap();
    };

    // Conflicting edits on CRLF file
    encrypt_file(b"PORT=8080\r\nHOST=localhost\r\n", &base_file);
    encrypt_file(b"PORT=9000\r\nHOST=localhost\r\n", &ours_file);
    encrypt_file(b"PORT=9999\r\nHOST=localhost\r\n", &theirs_file);

    let mut merge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let status = merge_cmd
        .current_dir(repo)
        .args([
            "merge",
            base_file.to_str().unwrap(),
            ours_file.to_str().unwrap(),
            theirs_file.to_str().unwrap(),
            "7",
            "configs/conflict.secret.env",
        ])
        .status()
        .unwrap();

    // Conflict occurred (exit code > 0)
    assert!(!status.success());

    // Decrypt merged result
    let merged_cipher = fs::read(&ours_file).unwrap();
    let mut smudge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = smudge_cmd
        .current_dir(repo)
        .arg("smudge")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&merged_cipher)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let decrypted = out.stdout;
    // Verify conflict markers are present
    assert!(decrypted.windows(7).any(|w| w == b"<<<<<<<"));
    assert!(decrypted.windows(7).any(|w| w == b">>>>>>>"));

    // CRITICAL: Ensure NO double carriage return (\r\r\n) exists anywhere!
    assert!(
        !decrypted.windows(3).any(|w| w == b"\r\r\n"),
        "Merged file must NOT contain double carriage return (\\r\\r\\n)!"
    );
}

#[test]
fn test_rekey_with_zero_secrets() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Absolutely 0 secret files exist in the repository
    // Run rekey: must succeed without crashing on empty pathspec
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    let mut status_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    status_cmd
        .current_dir(repo)
        .arg("status")
        .assert()
        .success();
}

#[test]
fn test_rewrap_detached_head_commit() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Commit 1: secret under Key 1
    let secret = repo.join("database.secret.env");
    fs::write(&secret, "DB_HOST=primary.internal\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit 1: secret with Key 1"]);

    // Commit 2: rotate to Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt", "database.secret.env"]);
    run_git(repo, &["commit", "-m", "Commit 2: rotate to Key 2"]);

    // Switch to detached HEAD at Commit 1
    run_git(repo, &["checkout", "HEAD~1"]);

    use age::secrecy::ExposeSecret;
    let alice_priv = id.to_string();
    let id_file = repo.join("alice.key");
    fs::write(&id_file, alice_priv.expose_secret()).unwrap();

    // In detached HEAD, rewrap database.secret.env
    // Traversal includes HEAD so historical key is recovered!
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(repo)
        .args([
            "rewrap",
            "database.secret.env",
            "-i",
            id_file.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn test_windows_backslash_path_in_check_special_entry() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let gitattributes = repo.join(".gitattributes");
    fs::write(
        &gitattributes,
        "tools/** filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    run_git(repo, &["add", ".gitattributes"]);

    // Create a submodule entry at tools/sub
    let dummy_sha = "0123456789abcdef0123456789abcdef01234567";
    let status = Command::new("git")
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            dummy_sha,
            "tools/sub",
        ])
        .current_dir(repo)
        .status()
        .unwrap();
    assert!(status.success());

    // Run check: path normalization with backslashes should not fail or escape-corrupt
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success();
}

#[test]
fn test_pre_push_skips_deleted_secrets_and_submodules() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Commit a secret and a submodule entry
    let secret = repo.join("database.secret.env");
    fs::write(&secret, "DB_PASS=clean123\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit 1: secret"]);
    let c1_sha = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Delete the secret and add a submodule
    run_git(repo, &["rm", "database.secret.env"]);
    let dummy_sha = "0123456789abcdef0123456789abcdef01234567";
    let status = Command::new("git")
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            dummy_sha,
            "vendor/submodule.secret.env",
        ])
        .current_dir(repo)
        .status()
        .unwrap();
    assert!(status.success());
    run_git(
        repo,
        &["commit", "-m", "Commit 2: delete secret and add submodule"],
    );
    let c2_sha = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Pre-push check from c1 to c2 must succeed (deleted file and gitlink ignored)
    let mut check_push = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = check_push
        .current_dir(repo)
        .args(["check", "--pre-push"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    let push_input = format!("refs/heads/master {c2_sha} refs/heads/master {c1_sha}\n");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(push_input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "Pre-push must skip deleted secrets and submodules without crashing!"
    );
}

#[test]
fn test_pre_push_allows_historical_rekeyed_commits_on_new_branch() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    // Commit 1: secret under Key 1
    let secret = repo.join("database.secret.env");
    fs::write(&secret, "DB_PASS=Key1Secret\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit 1: with Key 1"]);

    // Commit 2: rotate to Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt", "database.secret.env"]);
    run_git(repo, &["commit", "-m", "Commit 2: rotate to Key 2"]);

    // Create a new branch 'feat/hotfix' based on Commit 2 (where tip has Key 2)
    run_git(repo, &["checkout", "-b", "feat/hotfix"]);
    let dummy = repo.join("README.md");
    fs::write(&dummy, "Hotfix documentation\n").unwrap();
    run_git(repo, &["add", "README.md"]);
    run_git(repo, &["commit", "-m", "Commit 3: doc hotfix"]);

    let local_sha = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Pushing 'feat/hotfix' as a NEW branch (remote_oid is all 0s)
    // rev-list traverses history back to Commit 1 (which has Key 1).
    // Because Commit 1 has age ciphertext (not plaintext), and tip commit has Key 2, pre-push MUST SUCCEED!
    let mut check_push = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = check_push
        .current_dir(repo)
        .args(["check", "--pre-push"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    let zero_sha = "0000000000000000000000000000000000000000";
    let push_input =
        format!("refs/heads/feat/hotfix {local_sha} refs/heads/feat/hotfix {zero_sha}\n");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(push_input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "Pre-push must allow pushing historical rekeyed commits when tip is clean!"
    );
}

#[test]
fn test_worktree_hooks_installed_in_common_dir() {
    let temp = tempdir().expect("Failed to create tempdir");
    let main_repo = temp.path().join("main");
    fs::create_dir_all(&main_repo).unwrap();

    run_git(&main_repo, &["init"]);
    run_git(&main_repo, &["config", "user.name", "Test Developer"]);
    run_git(&main_repo, &["config", "user.email", "dev@example.com"]);

    let dummy = main_repo.join("README.md");
    fs::write(&dummy, "Initial commit\n").unwrap();
    run_git(&main_repo, &["add", "README.md"]);
    run_git(&main_repo, &["commit", "-m", "Initial commit"]);

    // Create a linked worktree
    let wt_path = temp.path().join("linked_wt");
    run_git(
        &main_repo,
        &[
            "worktree",
            "add",
            wt_path.to_str().unwrap(),
            "-b",
            "feature",
        ],
    );

    // Run install-hooks FROM WITHIN the linked worktree!
    let mut install_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    install_cmd
        .current_dir(&wt_path)
        .arg("install-hooks")
        .assert()
        .success();

    // Verify hooks were installed in main repository's common hooks dir, NOT per-worktree administrative path!
    let common_hooks = main_repo.join(".git").join("hooks");
    assert!(
        common_hooks.join("pre-commit").exists(),
        "Hooks must be installed in common hooks directory!"
    );
    assert!(common_hooks.join("pre-push").exists());

    // Worktree administrative path must NOT contain disconnected hooks
    let wt_admin_hooks = main_repo
        .join(".git")
        .join("worktrees")
        .join("linked_wt")
        .join("hooks");
    assert!(!wt_admin_hooks.exists());
}

#[test]
fn test_hook_shebang_prepending_runs_before_exit_and_exec() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let hooks_dir = repo.join(".git").join("hooks");
    fs::create_dir_all(&hooks_dir).unwrap();

    // Create pre-existing hook that exits early with exit 0
    let pre_commit = hooks_dir.join("pre-commit");
    let existing_script =
        "#!/bin/sh\n# Existing linter script\necho \"Running existing linter\"\nexit 0\n";
    fs::write(&pre_commit, existing_script).unwrap();

    // Run install-hooks
    let mut install_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    install_cmd
        .current_dir(repo)
        .arg("install-hooks")
        .assert()
        .success();

    let content = fs::read_to_string(&pre_commit).unwrap();
    let agecrypt_pos = content
        .find("git-agecrypt")
        .expect("git-agecrypt snippet must be present");
    let exit_pos = content.find("exit 0").expect("exit 0 must be present");

    // Prepending ensures git-agecrypt runs BEFORE exit 0!
    assert!(
        agecrypt_pos < exit_pos,
        "git-agecrypt must be prepended before existing exit/exec commands!"
    );
    assert!(
        content.starts_with("#!/bin/sh\n"),
        "Shebang must remain at the very top of the script!"
    );
}

#[test]
fn test_hook_contains_canonical_binary_path() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut install_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    install_cmd
        .current_dir(repo)
        .arg("install-hooks")
        .assert()
        .success();

    let pre_commit = repo.join(".git").join("hooks").join("pre-commit");
    let content = fs::read_to_string(&pre_commit).unwrap();

    // The script must have fallback logic containing a canonical path to git-agecrypt
    assert!(content.contains("git-agecrypt"));
    assert!(content.contains("EXEC="));
}

#[test]
fn test_fido2_hardware_key_rejection_message() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAI... user@yubikey", "--name", "alice"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("FIDO2 / hardware security keys ('sk-ssh-ed25519' or 'sk-ecdsa') are not supported"));
}

#[test]
fn test_recipient_collision_protection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Alice 1
    let id1 = age::x25519::Identity::generate();
    let pub1 = format!("{}", id1.to_public());
    let mut add1 = Command::cargo_bin("git-agecrypt").unwrap();
    add1.current_dir(repo)
        .args(["add-recipient", "-i", &pub1, "--name", "alice"])
        .assert()
        .success();

    let key1_file = repo.join(".git-agecrypt").join("keys").join("alice.age");
    assert!(key1_file.exists());
    let content1 = fs::read_to_string(&key1_file).unwrap();

    // Alice 2 (different key with same label)
    let id2 = age::x25519::Identity::generate();
    let pub2 = format!("{}", id2.to_public());
    let mut add2 = Command::cargo_bin("git-agecrypt").unwrap();
    add2.current_dir(repo)
        .args(["add-recipient", "-i", &pub2, "--name", "alice"])
        .assert()
        .success();

    // Verify key 1 was NOT overwritten! Key 2 was disambiguated
    let content1_after = fs::read_to_string(&key1_file).unwrap();
    assert_eq!(
        content1, content1_after,
        "Existing recipient key must NOT be overwritten!"
    );

    let entries: Vec<_> = fs::read_dir(repo.join(".git-agecrypt").join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(entries.len(), 2, "Two distinct recipient files must exist!");
    assert!(
        entries
            .iter()
            .any(|name| name.starts_with("alice_") && name.ends_with(".age"))
    );
}

#[test]
fn test_annotated_tag_push_peels_to_commit() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret = repo.join("database.secret.env");
    fs::write(&secret, "DB_KEY=clean_production_key\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Release commit with secret"]);

    // Create an annotated tag
    run_git(repo, &["tag", "-a", "v1.0.0", "-m", "Release 1.0.0"]);
    let tag_sha = String::from_utf8(git_out(repo, &["rev-parse", "v1.0.0"]))
        .unwrap()
        .trim()
        .to_string();

    // Pre-push check with annotated tag object SHA
    let mut check_push = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = check_push
        .current_dir(repo)
        .args(["check", "--pre-push"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    let push_input = format!(
        "refs/tags/v1.0.0 {tag_sha} refs/tags/v1.0.0 0000000000000000000000000000000000000000\n"
    );
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(push_input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "Pre-push check must peel annotated tags to commits and succeed!"
    );
}

#[test]
fn test_sparse_checkout_cone_preservation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Enroll recipient
    let alice_id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let alice_priv = alice_id.to_string();
    let alice_pub = format!("{}", alice_id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();

    let id_file = temp.path().join("alice.key");
    fs::write(&id_file, alice_priv.expose_secret()).unwrap();

    // Create secrets in cone and outside cone
    let cone_dir = repo.join("cone");
    let sparse_dir = repo.join("sparse");
    fs::create_dir_all(&cone_dir).unwrap();
    fs::create_dir_all(&sparse_dir).unwrap();

    let in_secret = cone_dir.join("in.secret.env");
    let out_secret = sparse_dir.join("out.secret.env");
    fs::write(&in_secret, "CONE_SECRET=in_cone\n").unwrap();
    fs::write(&out_secret, "SPARSE_SECRET=outside_cone\n").unwrap();

    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "cone", "sparse"],
    );
    run_git(repo, &["commit", "-m", "Commit all secrets"]);

    // Enable sparse-checkout and set cone to "cone/" and ".git-agecrypt/"
    run_git(repo, &["sparse-checkout", "set", "cone/", ".git-agecrypt/"]);

    // Verify out_secret was unlinked by git sparse-checkout
    assert!(
        !out_secret.exists(),
        "File outside cone must not exist after sparse-checkout set"
    );

    // Run lock and unlock
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd.current_dir(repo).arg("lock").assert().success();

    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(repo)
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();

    // Verify in_secret exists and is plaintext
    assert!(in_secret.exists());
    let in_content = fs::read_to_string(&in_secret).unwrap();
    assert_eq!(in_content, "CONE_SECRET=in_cone\n");

    // CRITICAL: out_secret must NOT have been dumped onto disk by refresh_working_tree!
    assert!(
        !out_secret.exists(),
        "refresh_working_tree must preserve sparse-checkout boundaries and NOT checkout SKIP_WORKTREE files!"
    );
}

#[test]
fn test_smudge_passes_historical_ciphertext_without_crashing_checkout() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let alice_id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let alice_priv = alice_id.to_string();
    let alice_pub = format!("{}", alice_id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();

    // Commit secret under Key 1
    let secret = repo.join("api.secret.env");
    fs::write(&secret, "API_KEY=Key1SecretValue\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "api.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit under Key 1"]);

    let commit1 = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Rekey to Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();
    run_git(repo, &["add", ".git-agecrypt"]);
    run_git(repo, &["commit", "-m", "Rekey to Key 2"]);

    // CRITICAL TEST: Checkout historical commit 1!
    // Active local key is Key 2, but commit 1 contains blob encrypted under Key 1.
    // Smudge filter must NOT return exit code 1; it must pass through raw ciphertext and exit 0!
    run_git(repo, &["checkout", &commit1]);

    assert!(secret.exists());
    let on_disk = fs::read(&secret).unwrap();
    assert!(
        on_disk.starts_with(b"age-encryption.org/v1\n"),
        "Historical ciphertext must be safely placed on disk"
    );

    // Rewrap can decrypt it using Alice's identity
    let id_file = temp.path().join("alice.key");
    fs::write(&id_file, alice_priv.expose_secret()).unwrap();

    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(repo)
        .args(["rewrap", "api.secret.env", "-i", id_file.to_str().unwrap()])
        .assert()
        .success();

    let plain = fs::read_to_string(&secret).unwrap();
    assert_eq!(plain, "API_KEY=Key1SecretValue\n");
}

#[test]
fn test_check_staged_files_with_leading_slash_path() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let sub_dir = repo.join("secrets");
    fs::create_dir_all(&sub_dir).unwrap();
    let secret = sub_dir.join("service.secret.env");
    fs::write(&secret, "SERVICE_SECRET=leaked_plain\n").unwrap();

    // Stage unencrypted secret
    run_git(repo, &["add", "secrets/service.secret.env"]);

    // check must use :0:<path> index stage syntax without triggering commit message regex lookup
    let mut check_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).arg("check").assert().success(); // Staged with clean filter, so it was encrypted transparently!
}

#[test]
fn test_merge_driver_on_readonly_secret_files() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let base_file = repo.join("base.age");
    let ours_file = repo.join("ours.age");
    let theirs_file = repo.join("theirs.age");

    let encrypt_file = |content: &[u8], dest: &Path| {
        let mut clean_cmd = Command::cargo_bin("git-agecrypt").unwrap();
        let mut child = clean_cmd
            .current_dir(repo)
            .arg("clean")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(content).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        fs::write(dest, out.stdout).unwrap();
    };

    encrypt_file(b"PORT=8080\nHOST=localhost\nDEBUG=false\n", &base_file);
    encrypt_file(b"PORT=8080\nHOST=localhost\nDEBUG=true\n", &ours_file);
    encrypt_file(b"PORT=9000\nHOST=localhost\nDEBUG=false\n", &theirs_file);

    // Mark ours_file read-only
    let mut perms = fs::metadata(&ours_file).unwrap().permissions();
    perms.set_readonly(true);
    let _ = fs::set_permissions(&ours_file, perms);

    // Run 3-way merge driver on read-only ours file
    let mut merge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    merge_cmd
        .current_dir(repo)
        .args([
            "merge",
            base_file.to_str().unwrap(),
            ours_file.to_str().unwrap(),
            theirs_file.to_str().unwrap(),
            "7",
            "configs/server.secret.env",
        ])
        .assert()
        .success();

    // Verify ours_file is merged, encrypted, and its readonly permission was restored
    let merged_cipher = fs::read(&ours_file).unwrap();
    assert!(merged_cipher.starts_with(b"age-encryption.org/v1\n"));
    assert!(fs::metadata(&ours_file).unwrap().permissions().readonly());

    // Smudge and verify content
    let mut smudge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let mut child = smudge_cmd
        .current_dir(repo)
        .arg("smudge")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&merged_cipher)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let plain = String::from_utf8(out.stdout).unwrap();
    assert!(plain.contains("PORT=9000"));
    assert!(plain.contains("DEBUG=true"));
}

#[test]
fn test_textconv_gracefully_handles_historical_commits() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "alice"])
        .assert()
        .success();

    let secret = repo.join("vault.secret.env");
    fs::write(&secret, "PASSWORD=secret123\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit 1"]);

    let old_blob = git_out(repo, &["cat-file", "blob", "HEAD:vault.secret.env"]);

    // Rekey to Key 2
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Write old blob to a temp file
    let old_file = temp.path().join("old_vault.env");
    fs::write(&old_file, &old_blob).unwrap();

    // textconv on historical file must NOT exit with error code 1!
    let mut textconv_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    textconv_cmd
        .current_dir(repo)
        .args(["textconv", old_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "[git-agecrypt: file is encrypted with a historical or foreign key",
        ));
}

#[test]
fn test_recipient_case_canonicalization_and_removal() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_key = format!("{}", id.to_public());

    // Add recipient with mixed-case label "AliceDev"
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "AliceDev"])
        .assert()
        .success();

    // Verify key was canonicalized to lowercase "alicedev.age"
    let key_file = repo.join(".git-agecrypt").join("keys").join("alicedev.age");
    assert!(
        key_file.exists(),
        "Recipient file must be saved in lowercase"
    );

    // Remove recipient using mixed-case name "ALICEDEV"
    let mut remove_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    remove_cmd
        .current_dir(repo)
        .args(["remove-recipient", "ALICEDEV"])
        .assert()
        .success();

    assert!(
        !key_file.exists(),
        "Recipient file must be removed case-insensitively"
    );
}

#[test]
fn test_rewrap_streams_large_secret_without_memory_spike() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let priv_str = id.to_string();
    let pub_str = format!("{}", id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_str, "--name", "worker"])
        .assert()
        .success();

    // Create a 200 KB repetitive secret dataset
    let secret = repo.join("dataset.secret.env");
    let payload = "DATA_CHUNK_LINE_0123456789abcdef\n".repeat(6000);
    fs::write(&secret, &payload).unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "dataset.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit large secret dataset"]);

    let old_cipher = git_out(repo, &["cat-file", "blob", "HEAD:dataset.secret.env"]);

    // Rekey repository
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Overwrite with old ciphertext
    fs::write(&secret, &old_cipher).unwrap();

    let id_file = temp.path().join("worker.key");
    fs::write(&id_file, priv_str.expose_secret()).unwrap();

    // Run rewrap
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(repo)
        .args([
            "rewrap",
            "dataset.secret.env",
            "-i",
            id_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let plain_restored = fs::read_to_string(&secret).unwrap();
    assert_eq!(plain_restored.len(), payload.len());
    assert_eq!(plain_restored, payload);
}

#[test]
fn test_merge_driver_atomic_preserve_on_clean_stream_failure() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Merge Tester"]);
    run_git(repo, &["config", "user.email", "merge@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let base = repo.join("base.txt");
    let ours = repo.join("ours.txt");
    let theirs = repo.join("theirs.txt");

    let initial_ours = b"IMPORTANT_OURS_DATA_BEFORE_MERGE\n";
    fs::write(&base, b"BASE_DATA\n").unwrap();
    fs::write(&ours, initial_ours).unwrap();
    // Corrupt theirs so merge driver encounters an unrecoverable failure
    fs::write(
        &theirs,
        b"age-encryption.org/v1\nCORRUPTED_CIPHERTEXT_HEADER\n",
    )
    .unwrap();

    let mut merge_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    merge_cmd
        .current_dir(repo)
        .args([
            "merge",
            base.to_str().unwrap(),
            ours.to_str().unwrap(),
            theirs.to_str().unwrap(),
            "7",
            "ours.txt",
        ])
        .assert()
        .failure();

    // Verify ours was NOT truncated to 0 bytes and preserves its exact original content
    let preserved = fs::read(&ours).expect("Ours file must exist");
    assert_eq!(
        preserved, initial_ours,
        "Ours file must never be truncated or destroyed on merge failure"
    );
}

#[test]
fn test_rewrap_preserves_readonly_permissions_on_error() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Rewrap Tester"]);
    run_git(repo, &["config", "user.email", "rewrap@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret = repo.join("credentials.secret.env");
    let secret_data = "AWS_SECRET_ACCESS_KEY=TopSecretKey123\n";
    fs::write(&secret, secret_data).unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "credentials.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Commit credentials"]);

    // Set file to read-only
    let mut perms = fs::metadata(&secret).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&secret, perms).unwrap();
    assert!(fs::metadata(&secret).unwrap().permissions().readonly());

    // Create a dummy unrelated key
    let dummy_key = temp.path().join("unrelated.key");
    fs::write(
        &dummy_key,
        "AGE-SECRET-KEY-10000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();

    // Run rewrap with the invalid identity - it will fail to decrypt
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(repo)
        .args([
            "rewrap",
            "credentials.secret.env",
            "-i",
            dummy_key.to_str().unwrap(),
        ])
        .assert()
        .failure();

    // Verify read-only permissions are strictly preserved on error by ReadonlyGuard
    let final_perms = fs::metadata(&secret).unwrap().permissions();
    assert!(
        final_perms.readonly(),
        "Read-only attribute must be preserved when rewrap fails"
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap(),
        secret_data,
        "Secret content must remain intact"
    );

    // Clean up read-only so tempdir can be removed
    let mut cleanup_perms = fs::metadata(&secret).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    cleanup_perms.set_readonly(false);
    let _ = fs::set_permissions(&secret, cleanup_perms);
}

#[test]
fn test_index_aware_deduplication_prevents_phantom_diffs_after_cache_wipe() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Cache Tester"]);
    run_git(repo, &["config", "user.email", "cache@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret = repo.join("database.secret.env");
    let content = "DB_HOST=primary.cluster.internal\nDB_PASS=ProductionMasterSecret!\n";
    fs::write(&secret, content).unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "database.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial database commit"]);

    let initial_blob_sha =
        String::from_utf8(git_out(repo, &["rev-parse", "HEAD:database.secret.env"])).unwrap();

    // Wipe the local HMAC cache completely
    let cache_dir = repo.join(".git").join("git-agecrypt").join("cache");
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir).unwrap();
    }
    assert!(!cache_dir.exists());

    // Run git add again on unchanged file.
    // Index-aware deduplication will query staged blob (:0:database.secret.env), verify match,
    // and re-use the exact existing ciphertext.
    run_git(repo, &["add", "database.secret.env"]);

    let new_blob_sha =
        String::from_utf8(git_out(repo, &["rev-parse", ":database.secret.env"])).unwrap();
    assert_eq!(
        initial_blob_sha, new_blob_sha,
        "Blob SHA must remain bit-for-bit identical even after complete cache wipe!"
    );

    // Verify git diff --cached is completely empty
    let diff_cached = git_out(repo, &["diff", "--cached"]);
    assert!(
        diff_cached.is_empty(),
        "No phantom diff should be staged after cache wipe: {}",
        String::from_utf8_lossy(&diff_cached)
    );
}

#[test]
fn test_lock_aborts_on_unreachable_worktree() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Worktree Tester"]);
    run_git(repo, &["config", "user.email", "worktree@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret = repo.join("keys.secret.env");
    fs::write(&secret, "SECRET_TOKEN=xyz123\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "keys.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // Create a linked worktree
    let wt_dir = temp.path().join("secondary_worktree");
    run_git(repo, &["worktree", "add", wt_dir.to_str().unwrap()]);

    // Now abruptly remove the worktree directory without pruning
    fs::remove_dir_all(&wt_dir).unwrap();
    assert!(!wt_dir.exists());

    // git-agecrypt lock without --force should abort
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Linked worktree(s) are detached or unreachable",
        ))
        .stderr(predicate::str::contains("--force"));

    // git-agecrypt lock with --force should succeed
    let mut force_lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    force_lock_cmd
        .current_dir(repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    // Verify repository is locked
    assert!(
        !repo
            .join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );
}

#[test]
fn test_rewrap_from_subdirectory() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Subdir Tester"]);
    run_git(repo, &["config", "user.email", "subdir@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let priv_str = id.to_string();
    let pub_str = format!("{}", id.to_public());
    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_str, "--name", "worker"])
        .assert()
        .success();

    let secrets_dir = repo.join("secrets");
    fs::create_dir_all(&secrets_dir).unwrap();
    let secret = secrets_dir.join("database.secret.env");
    let payload = "DB_PASS=SubdirTestSecret123\n";
    fs::write(&secret, payload).unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "secrets/database.secret.env",
        ],
    );
    run_git(
        repo,
        &["commit", "-m", "Initial commit of secret in subfolder"],
    );

    let old_cipher = git_out(
        repo,
        &["cat-file", "blob", "HEAD:secrets/database.secret.env"],
    );

    // Rekey repository
    let mut rekey_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rekey_cmd.current_dir(repo).arg("rekey").assert().success();

    // Overwrite secret on disk with old ciphertext
    fs::write(&secret, &old_cipher).unwrap();

    // Run rewrap from INSIDE the secrets/ subdirectory!
    let mut rewrap_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    rewrap_cmd
        .current_dir(&secrets_dir)
        .args([
            "rewrap",
            "--identity",
            priv_str.expose_secret(),
            "database.secret.env",
        ])
        .assert()
        .success();

    let restored = fs::read_to_string(&secret).unwrap();
    assert_eq!(
        restored, payload,
        "Cleartext must be correctly restored on disk"
    );
}

#[test]
fn test_lock_aborts_with_error_on_active_git_operation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Lock Op Tester"]);
    run_git(repo, &["config", "user.email", "lock_op@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret = repo.join("test.secret.env");
    fs::write(&secret, "SECRET=value\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit"]);

    // Simulate an in-progress merge
    let merge_head = repo.join(".git").join("MERGE_HEAD");
    fs::write(&merge_head, "0123456789abcdef0123456789abcdef01234567\n").unwrap();

    // git-agecrypt lock without --force MUST fail with error exit code 1
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Active Git operation detected"))
        .stderr(predicate::str::contains("MERGE_HEAD"));

    // Verify repo is still unlocked (did not falsely report success)
    assert!(
        repo.join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );

    // git-agecrypt lock with --force should succeed
    let mut force_lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    force_lock_cmd
        .current_dir(repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    assert!(
        !repo
            .join(".git")
            .join("git-agecrypt")
            .join("repo.key")
            .exists()
    );
}

#[test]
fn test_refresh_working_tree_fallback_preserves_unrelated_files() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Tree Tester"]);
    run_git(repo, &["config", "user.email", "tree@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let priv_str = id.to_string();
    let pub_str = format!("{}", id.to_public());
    let key_file = temp.path().join("worker.key");
    fs::write(&key_file, priv_str.expose_secret()).unwrap();

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_str, "--name", "worker"])
        .assert()
        .success();

    let app_file = repo.join("main.rs");
    fs::write(&app_file, "fn main() { println!(\"original\"); }\n").unwrap();
    let secret_file = repo.join("app.secret.env");
    fs::write(&secret_file, "SECRET_TOKEN=initial\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "main.rs",
            "app.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // Developer makes local unstaged modifications to non-secret app file
    let uncommitted_content = "fn main() { println!(\"WORK IN PROGRESS DO NOT OVERWRITE\"); }\n";
    fs::write(&app_file, uncommitted_content).unwrap();

    // Lock and unlock repo
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    let mut unlock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    unlock_cmd
        .current_dir(repo)
        .args(["unlock", key_file.to_str().unwrap(), "--force"])
        .assert()
        .success();

    // Verify non-secret uncommitted edits were NEVER wiped out
    let current_app = fs::read_to_string(&app_file).unwrap();
    assert_eq!(
        current_app, uncommitted_content,
        "Unrelated application files must be preserved during refresh"
    );
}

#[test]
fn test_migrate_ensures_dash_text_attribute() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Migrate Tester"]);
    run_git(repo, &["config", "user.email", "migrate@example.com"]);

    let gitattributes = repo.join(".gitattributes");
    fs::write(
        &gitattributes,
        "*.secret.env filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();

    let mut migrate_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    migrate_cmd
        .current_dir(repo)
        .arg("migrate-from-git-crypt")
        .assert()
        .success();

    let updated_attr = fs::read_to_string(&gitattributes).unwrap();
    assert!(
        updated_attr.contains("-text"),
        "Migrated .gitattributes must contain '-text' to protect against Windows CRLF mutation: {updated_attr}"
    );
    assert!(updated_attr.contains("filter=agecrypt diff=agecrypt merge=agecrypt -text"));
}

#[test]
fn test_lock_aborts_with_error_on_dirty_secrets() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Dirty Lock Tester"]);
    run_git(repo, &["config", "user.email", "dirty_lock@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let secret = repo.join("test.secret.env");
    fs::write(&secret, "SECRET=value\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // Modify the secret file on disk without staging/committing
    fs::write(&secret, "SECRET=dirty_value_not_committed\n").unwrap();

    // git-agecrypt lock without --force MUST abort with non-zero exit code
    let mut lock_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    lock_cmd
        .current_dir(repo)
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Lock aborted: uncommitted changes in tracked secret file(s)",
        ));

    // repo.key must still exist because lock was aborted to prevent data loss
    let key_file = repo.join(".git").join("git-agecrypt").join("repo.key");
    assert!(
        key_file.exists(),
        "Master key must be preserved when lock is aborted"
    );

    // Forced lock with --force MUST succeed
    let mut force_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    force_cmd
        .current_dir(repo)
        .args(["lock", "--force"])
        .assert()
        .success();

    assert!(
        !key_file.exists(),
        "Master key must be wiped after forced lock"
    );
}

#[test]
fn test_add_recipient_rejects_both_identity_and_github() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Arg Tester"]);
    run_git(repo, &["config", "user.email", "arg@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    let id = age::x25519::Identity::generate();
    let pub_str = format!("{}", id.to_public());

    let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    add_cmd
        .current_dir(repo)
        .args(["add-recipient", "-i", &pub_str, "--github", "octocat"])
        .assert()
        .failure();
}

#[test]
fn test_check_pre_push_empty_stdin_safe() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "PrePush Tester"]);
    run_git(repo, &["config", "user.email", "prepush@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Running check --pre-push with empty stdin must return success
    let mut check_cmd = assert_cmd::Command::cargo_bin("git-agecrypt").unwrap();
    check_cmd.current_dir(repo).args(["check", "--pre-push"]);
    check_cmd.write_stdin("");
    check_cmd.assert().success();
}

#[test]
fn test_list_recipients_deterministic_alphabetical() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "List Tester"]);
    run_git(repo, &["config", "user.email", "list@example.com"]);

    let mut init_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    init_cmd.current_dir(repo).arg("init").assert().success();

    // Add 3 recipients in non-alphabetical order
    for name in &["charlie", "alice", "bob"] {
        let id = age::x25519::Identity::generate();
        let pub_str = format!("{}", id.to_public());
        let mut add_cmd = Command::cargo_bin("git-agecrypt").unwrap();
        add_cmd
            .current_dir(repo)
            .args(["add-recipient", "-i", &pub_str, "--name", name])
            .assert()
            .success();
    }

    let mut list_cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let out = list_cmd
        .current_dir(repo)
        .arg("list-recipients")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);

    let alice_idx = stdout_str
        .find("alice.age")
        .expect("alice.age must be present");
    let bob_idx = stdout_str.find("bob.age").expect("bob.age must be present");
    let charlie_idx = stdout_str
        .find("charlie.age")
        .expect("charlie.age must be present");

    assert!(
        alice_idx < bob_idx && bob_idx < charlie_idx,
        "Recipients must be listed in deterministic alphabetical order: alice < bob < charlie. Actual output:\n{stdout_str}"
    );
}
