mod common;

use common::*;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_secret_scrubbing_on_errors() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_canary = "SUPER_SECRET_HYGIENE_CANARY_TOKEN_999888";
    let env_content = format!("SECRET={secret_canary}\nINVALID_LINE_NO_EQUALS\n");
    let secret_file = repo.join("test.secret.env");
    fs::write(&secret_file, &env_content).unwrap();

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit test secret"]);

    // Lock repository
    agecrypt_cmd(repo).arg("lock").assert().success();

    // Trigger run failure on locked repo without identity
    let mut run_cmd = agecrypt_cmd(repo);
    #[cfg(windows)]
    run_cmd.args(["run", "--", "cmd.exe", "/c", "echo test"]);
    #[cfg(not(windows))]
    run_cmd.args(["run", "--", "sh", "-c", "echo test"]);

    let assert = run_cmd.assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);

    // CANARY must NEVER leak into stdout or stderr
    assert!(
        !stderr.contains(secret_canary),
        "Secret canary leaked into stderr during error: {stderr}"
    );
    assert!(
        !stdout.contains(secret_canary),
        "Secret canary leaked into stdout during error: {stdout}"
    );
}

#[test]
fn test_hmac_cache_key_leak_protection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_content = "DEBUG=true\n";
    let secret_file = repo.join("common.secret.env");
    fs::write(&secret_file, secret_content).unwrap();

    run_git(repo, &["add", "common.secret.env"]);

    // Unkeyed SHA-256 of "DEBUG=true\n"
    let mut hasher = Sha256::new();
    hasher.update(secret_content.as_bytes());
    let unkeyed_sha256 = format!("{:x}", hasher.finalize());

    let cache_root = repo.join(".git").join("git-agecrypt").join("cache");
    let mut found_cache_entries = 0;
    if cache_root.exists() {
        for fp_entry in fs::read_dir(&cache_root).unwrap().flatten() {
            if fp_entry.path().is_dir() {
                for file_entry in fs::read_dir(fp_entry.path()).unwrap().flatten() {
                    let fname = file_entry.file_name().to_string_lossy().to_string();
                    found_cache_entries += 1;
                    // Cache filename must NOT match the unkeyed SHA-256 hash!
                    assert_ne!(
                        fname,
                        format!("{unkeyed_sha256}.age"),
                        "Cache filename leaked plaintext SHA-256 hash! Must be keyed HMAC-SHA256."
                    );
                    assert!(fname.ends_with(".age"));
                    assert_eq!(fname.len(), 32 + 4);
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
fn test_git_diff_patch_never_exposes_cleartext_secret() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let canary = "SECRET_DIFF_CANARY_VALUE_XYZ123";
    let secret_file = repo.join("app.secret.env");
    fs::write(&secret_file, format!("API_SECRET={canary}\n")).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // Check git diff --cached or git diff HEAD
    let diff_output = git_out(repo, &["diff", "HEAD"]);
    let diff_str = String::from_utf8_lossy(&diff_output);
    assert!(
        !diff_str.contains(canary),
        "Git diff must never expose cleartext canary: {diff_str}"
    );
}
