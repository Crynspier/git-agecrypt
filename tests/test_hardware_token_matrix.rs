mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_hardware_token_failure_modes_fail_closed() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    let key_dir = tempdir().expect("Failed to create key dir");
    let (alice_sec, alice_pub) = generate_test_identity();
    let alice_pub_file = key_dir.path().join("alice.pub");
    fs::write(&alice_pub_file, &alice_pub).unwrap();
    let alice_sec_file = key_dir.path().join("alice.key");
    fs::write(&alice_sec_file, &alice_sec).unwrap();

    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args([
            "add-recipient",
            "-i",
            alice_pub_file.to_str().unwrap(),
            "--name",
            "alice",
        ])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(repo.join("token.secret.env"), "TOKEN_VAL=hardware_bound\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit token secret"]);

    // Lock repository
    agecrypt_cmd(repo).arg("lock").assert().success();

    // 1. Attempt unlock with non-existent token key file
    let fake_key = key_dir.path().join("non_existent_token.key");
    let out_missing = agecrypt_cmd(repo)
        .args(["unlock", fake_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out_missing.status.success(),
        "Missing hardware token or key file must fail closed"
    );

    // 2. Attempt unlock with corrupted / truncated age identity
    let corrupt_key = key_dir.path().join("corrupt_token.key");
    fs::write(
        &corrupt_key,
        "AGE-SECRET-KEY-1CORRUPTED_TRUNCATED_BAD_PAYLOAD",
    )
    .unwrap();
    let out_corrupt = agecrypt_cmd(repo)
        .args(["unlock", corrupt_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out_corrupt.status.success(),
        "Corrupted identity format must fail closed"
    );

    // 3. Attempt unlock with wrong key (different X25519 identity)
    let (wrong_sec, _) = generate_test_identity();
    let wrong_key_file = key_dir.path().join("wrong_token.key");
    fs::write(&wrong_key_file, &wrong_sec).unwrap();
    let out_wrong = agecrypt_cmd(repo)
        .args(["unlock", wrong_key_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out_wrong.status.success(),
        "Wrong identity must fail closed without decrypting"
    );

    // Verify file remains locked ciphertext
    assert!(
        fs::read(repo.join("token.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n"),
        "Secret file must remain encrypted ciphertext upon token failures"
    );

    // 4. Successful unlock with alice_sec_file
    let out_valid = agecrypt_cmd(repo)
        .args(["unlock", alice_sec_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out_valid.status.success(), "Valid identity must unlock");
    assert_eq!(
        fs::read_to_string(repo.join("token.secret.env")).unwrap(),
        "TOKEN_VAL=hardware_bound\n"
    );
}
