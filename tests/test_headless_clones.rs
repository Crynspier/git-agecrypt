mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_locked_clone_checkout_to_unlock_lifecycle() {
    let temp = tempdir().expect("Failed to create tempdir");
    let origin_repo = temp.path().join("origin");
    fs::create_dir(&origin_repo).unwrap();
    init_repo(&origin_repo);

    agecrypt_cmd(&origin_repo).arg("init").assert().success();

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(&origin_repo);
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "bob"]);
    add_cmd.assert().success();

    let secret_file = origin_repo.join("production.secret.env");
    let secret_plain = "PROD_API_KEY=live_secure_token_777\n";
    fs::write(&secret_file, secret_plain).unwrap();
    run_git(&origin_repo, &["add", "."]);
    run_git(&origin_repo, &["commit", "-m", "Commit prod secret"]);

    // Clone origin repo to fresh destination
    let clone_repo = temp.path().join("clone");
    let origin_url = origin_repo.to_str().unwrap().replace('\\', "/");
    let clone_dest = clone_repo.to_str().unwrap().replace('\\', "/");
    run_git(
        temp.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "clone",
            &origin_url,
            &clone_dest,
        ],
    );

    // In clone repo: filters are not installed initially or key is missing
    let clone_secret = clone_repo.join("production.secret.env");
    assert!(clone_secret.exists());

    // Without key, the secret in working tree is age ciphertext
    let clone_bytes = fs::read(&clone_secret).unwrap();
    assert!(
        clone_bytes.starts_with(b"age-encryption.org/v1\n"),
        "Fresh clone without keys must check out ciphertext (fail closed)"
    );

    // Initialize/configure filters in clone
    agecrypt_cmd(&clone_repo).arg("init").assert().success();

    // Verify status reports locked
    let mut status_cmd = agecrypt_cmd(&clone_repo);
    let assert = status_cmd.arg("status").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.to_lowercase().contains("no (locked)"));

    // Unlock using Bob's key file
    let id_file = clone_repo.join("bob.key");
    fs::write(&id_file, &secret_key).unwrap();
    let mut unlock_cmd = agecrypt_cmd(&clone_repo);
    unlock_cmd
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();
    let _ = fs::remove_file(&id_file);

    // After unlock, working tree file must be plaintext!
    let decrypted = fs::read_to_string(&clone_secret).unwrap();
    assert_eq!(decrypted, secret_plain);
}

#[test]
fn test_non_interactive_headless_ci_fails_closed() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("test.secret.env");
    fs::write(&secret_file, "SECRET=value\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // Lock repository
    agecrypt_cmd(repo).arg("lock").assert().success();

    // Calling unlock without key argument in non-interactive CI must exit immediately with code 1
    let mut unlock_cmd = agecrypt_cmd(repo);
    unlock_cmd.env("CI", "true");
    let assert = unlock_cmd.arg("unlock").assert().failure().code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("No private keys found") || stderr.contains("Specify a key"));

    // Calling run on locked repository in CI must fail closed immediately with code 1
    let mut run_cmd = agecrypt_cmd(repo);
    run_cmd.env("CI", "true");
    #[cfg(windows)]
    run_cmd.args(["run", "--", "cmd.exe", "/c", "echo should_never_run"]);
    #[cfg(not(windows))]
    run_cmd.args(["run", "--", "sh", "-c", "echo should_never_run"]);

    let run_assert = run_cmd.assert().failure().code(1);
    let run_err = String::from_utf8_lossy(&run_assert.get_output().stderr);
    assert!(run_err.contains("repository is locked"));
}
