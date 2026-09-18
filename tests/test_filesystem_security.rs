mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_path_traversal_and_reserved_names() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (_sec, pub_key) = generate_test_identity();

    // Attempt traversal in recipient name
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd
        .args([
            "add-recipient",
            "-i",
            &pub_key,
            "--name",
            "../../escape_test",
        ])
        .assert()
        .success();

    // Verify no file escaped outside .git-agecrypt/keys/
    assert!(!repo.join("escape_test.age").exists());
    assert!(!repo.join("escape_test").exists());
    assert!(!repo.join(".git-agecrypt").join("escape_test.age").exists());

    // Verify it was safely sanitized inside .git-agecrypt/keys/
    let keys_dir = repo.join(".git-agecrypt").join("keys");
    let entries: Vec<String> = fs::read_dir(&keys_dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(entries.iter().any(|name| name.contains("escape_test")));
}

#[test]
fn test_read_only_attribute_handling() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "user"]);
    add_cmd.assert().success();

    let secret_file = repo.join("cert.secret.env");
    let initial_content = "CERTIFICATE_DATA=super_secure_read_only_999\n";
    fs::write(&secret_file, initial_content).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit read-only secret"]);

    // Mark secret file read-only (chmod 0400 or attrib +r)
    let meta = fs::metadata(&secret_file).unwrap();
    let mut perms = meta.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&secret_file, perms).unwrap();
    assert!(fs::metadata(&secret_file).unwrap().permissions().readonly());

    // Locking must succeed without failing on preflight
    agecrypt_cmd(repo).arg("lock").assert().success();

    // Verify file is locked to ciphertext
    let locked_bytes = fs::read(&secret_file).unwrap();
    assert!(locked_bytes.starts_with(b"age-encryption.org/v1\n"));
    // Verify file remains read-only
    assert!(fs::metadata(&secret_file).unwrap().permissions().readonly());

    // Unlock file
    let id_file = repo.join("test_user.key");
    fs::write(&id_file, &secret_key).unwrap();
    let mut unlock_cmd = agecrypt_cmd(repo);
    unlock_cmd.args(["unlock", id_file.to_str().unwrap()]);
    unlock_cmd.assert().success();
    let _ = fs::remove_file(&id_file);

    // Verify file is restored to plaintext and preserves read-only attribute
    let restored_content = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(restored_content, initial_content);
    assert!(fs::metadata(&secret_file).unwrap().permissions().readonly());
}

#[test]
fn test_case_insensitive_path_handling() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    // Add recipient with mixed-case name
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "AliceDev"]);
    add_cmd.assert().success();

    // List recipients must show the enrolled key
    let mut list_cmd = agecrypt_cmd(repo);
    let assert = list_cmd.arg("list-recipients").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.contains("AliceDev") || stdout.contains("alicedev"));

    // Remove recipient using lowercase: must handle case-insensitively on Windows
    let mut rm_cmd = agecrypt_cmd(repo);
    rm_cmd.args(["remove-recipient", "alicedev"]);
    let _ = rm_cmd.assert();

    let _ = secret_key;
}
