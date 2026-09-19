mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_hardware_token_failure_fail_closed_matrix() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "token_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        repo.join("token.secret.env"),
        "SECRET_TOKEN_DATA=hardware_protected_12345\n",
    )
    .unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "token.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Token secret commit"]);

    // Lock repository to put it in encrypted state
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();

    // 1. Missing identity file
    let missing_path = repo.join("non_existent_token.key");
    let out_missing = agecrypt_cmd(repo)
        .args(["unlock", missing_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out_missing.status.success(),
        "Unlock must fail closed when identity file is missing"
    );

    // 2. Corrupt / truncated identity
    let corrupt_path = repo.join("corrupt_token.key");
    fs::write(&corrupt_path, "AGE-SECRET-KEY-1TRUNCATED_BAD_DATA").unwrap();
    let out_corrupt = agecrypt_cmd(repo)
        .args(["unlock", corrupt_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out_corrupt.status.success(),
        "Unlock must fail closed on corrupted token identity"
    );

    // 3. Malformed SSH private key header
    let malformed_path = repo.join("malformed_ssh.key");
    fs::write(
        &malformed_path,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nINVALID_BASE64_GARBAGE\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    let out_malformed = agecrypt_cmd(repo)
        .args(["unlock", malformed_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out_malformed.status.success(),
        "Unlock must fail closed on malformed SSH key"
    );

    // 4. Empty identity via stdin
    let out_empty = agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(b"")
        .output()
        .unwrap();
    assert!(
        !out_empty.status.success(),
        "Unlock must fail closed when empty identity passed"
    );

    // 5. Valid identity unlocks cleanly
    let out_valid = agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(sec_id.as_bytes())
        .output()
        .unwrap();
    assert!(
        out_valid.status.success(),
        "Valid identity must unlock repository successfully"
    );

    let content = fs::read_to_string(repo.join("token.secret.env")).unwrap();
    assert_eq!(
        content, "SECRET_TOKEN_DATA=hardware_protected_12345\n",
        "Secret content must match after valid unlock"
    );
}
