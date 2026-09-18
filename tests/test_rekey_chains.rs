mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_5_generation_key_rotation_lifecycle() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (alice_sec, alice_pub) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &alice_pub, "--name", "alice"]);
    add_cmd.env("GIT_AGECRYPT_IDENTITY", &alice_sec);
    add_cmd.assert().success();

    let secret_file = repo.join("vault.secret.env");

    // Loop through 5 generations (G0 to G4)
    for generation in 0..5 {
        let content = format!("GENERATION={generation}\nPAYLOAD=secret_state_{generation}\n");
        fs::write(&secret_file, &content).unwrap();
        run_git(repo, &["add", "."]);
        run_git(repo, &["commit", "-m", &format!("Commit Gen {generation}")]);

        // Verify working tree is plaintext
        assert_eq!(fs::read_to_string(&secret_file).unwrap(), content);

        // Rekey for next generation if generation < 4
        if generation < 4 {
            let mut rekey_cmd = agecrypt_cmd(repo);
            rekey_cmd.args(["rekey", "--force"]);
            rekey_cmd.env("GIT_AGECRYPT_IDENTITY", &alice_sec);
            rekey_cmd.assert().success();
        }

        // Verify git object contains valid age ciphertext
        let blob = git_out(repo, &["cat-file", "blob", ":vault.secret.env"]);
        assert!(
            blob.starts_with(b"age-encryption.org/v1\n"),
            "Git index blob must be valid age ciphertext at Gen {generation}"
        );
    }
}

#[test]
fn test_rekey_revocation_isolation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (alice_sec, alice_pub) = generate_test_identity();
    let (bob_sec, bob_pub) = generate_test_identity();

    // Enroll Alice and Bob
    let mut add_a = agecrypt_cmd(repo);
    add_a.args(["add-recipient", "-i", &alice_pub, "--name", "alice"]);
    add_a.assert().success();

    let mut add_b = agecrypt_cmd(repo);
    add_b.args(["add-recipient", "-i", &bob_pub, "--name", "bob"]);
    add_b.assert().success();

    let secret_file = repo.join("creds.secret.env");
    fs::write(&secret_file, "SHARED_SECRET=g0_value\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit Gen 0"]);

    // Remove Bob
    let mut rm_b = agecrypt_cmd(repo);
    rm_b.args(["remove-recipient", "bob"]);
    rm_b.assert().success();

    // Rekey to G1
    let mut rekey_cmd = agecrypt_cmd(repo);
    rekey_cmd.args(["rekey", "--force"]);
    rekey_cmd.env("GIT_AGECRYPT_IDENTITY", &alice_sec);
    rekey_cmd.assert().success();

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit Gen 1 rekey"]);

    // Lock the repo
    agecrypt_cmd(repo).arg("lock").assert().success();
    let locked_bytes = fs::read(&secret_file).unwrap();
    assert!(locked_bytes.starts_with(b"age-encryption.org/v1\n"));

    // Attempt to unlock with revoked Bob: MUST fail closed
    let id_bob = repo.join("bob_key.txt");
    fs::write(&id_bob, &bob_sec).unwrap();
    let mut unlock_bob = agecrypt_cmd(repo);
    unlock_bob.args(["unlock", id_bob.to_str().unwrap()]);
    unlock_bob.assert().failure();
    let _ = fs::remove_file(&id_bob);

    // Unlock with active Alice: MUST succeed
    let id_alice = repo.join("alice_key.txt");
    fs::write(&id_alice, &alice_sec).unwrap();
    let mut unlock_alice = agecrypt_cmd(repo);
    unlock_alice.args(["unlock", id_alice.to_str().unwrap()]);
    unlock_alice.assert().success();
    let _ = fs::remove_file(&id_alice);

    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        "SHARED_SECRET=g0_value\n"
    );
}

#[test]
fn test_historical_branch_cherry_pick_across_rekey() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (alice_sec, alice_pub) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &alice_pub, "--name", "alice"]);
    add_cmd.assert().success();

    let secret_file = repo.join("feature.secret.env");
    fs::write(&secret_file, "FEATURE=gen0_base\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Base Gen 0 commit"]);

    // Create old feature branch at Gen 0
    run_git(repo, &["checkout", "-b", "old-branch"]);
    fs::write(&secret_file, "FEATURE=gen0_feature_modification\n").unwrap();
    run_git(repo, &["commit", "-am", "Old feature commit"]);
    let old_commit = String::from_utf8_lossy(&git_out(repo, &["rev-parse", "HEAD"]))
        .trim()
        .to_string();

    // Switch back to main and rekey to Gen 1
    run_git(repo, &["checkout", "main"]);
    let mut rekey_cmd = agecrypt_cmd(repo);
    rekey_cmd.args(["rekey", "--force"]);
    rekey_cmd.env("GIT_AGECRYPT_IDENTITY", &alice_sec);
    rekey_cmd.assert().success();

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Rotate key to Gen 1"]);

    // 1. Checkout old historical branch: must succeed without crashing clean/smudge
    run_git(repo, &["checkout", "old-branch"]);
    // 2. Checkout main branch: must succeed
    run_git(repo, &["checkout", "main"]);

    // 3. Obtain old ciphertext from old-branch commit
    let old_ciphertext = git_out(
        repo,
        &[
            "cat-file",
            "blob",
            &format!("{old_commit}:feature.secret.env"),
        ],
    );
    assert!(old_ciphertext.starts_with(b"age-encryption.org/v1\n"));

    // Write old ciphertext to working tree and stage it
    fs::write(&secret_file, &old_ciphertext).unwrap();
    run_git(repo, &["add", "feature.secret.env"]);

    // Check pre-commit blocks the historical key and instructs to rewrap
    let mut check_cmd = agecrypt_cmd(repo);
    let check_assert = check_cmd.arg("check").assert().failure();
    let check_err = String::from_utf8_lossy(&check_assert.get_output().stderr);
    assert!(check_err.contains("REVOKED/FOREIGN KEY") || check_err.contains("rewrap"));

    // Run rewrap using Alice's identity
    let id_file = repo.join("alice.key");
    fs::write(&id_file, &alice_sec).unwrap();
    let mut rewrap_cmd = agecrypt_cmd(repo);
    rewrap_cmd
        .args([
            "rewrap",
            "feature.secret.env",
            "-i",
            id_file.to_str().unwrap(),
        ])
        .assert()
        .success();
    let _ = fs::remove_file(&id_file);

    // After rewrap, pre-commit check must pass
    agecrypt_cmd(repo).arg("check").assert().success();

    // Working tree file must be cleartext
    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        "FEATURE=gen0_feature_modification\n"
    );

    // New blob staged under Key 2
    let blob = git_out(repo, &["cat-file", "blob", ":feature.secret.env"]);
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));
    assert_ne!(blob, old_ciphertext);
}
