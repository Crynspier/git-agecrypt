#![allow(unused)]

pub mod invariants;
pub mod shadow_model;

pub use assert_cmd::prelude::*;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub fn bin_dir() -> PathBuf {
    assert_cmd::cargo::cargo_bin("git-agecrypt")
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn prepend_to_path(dir: &Path) -> OsString {
    let mut paths = vec![dir.to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(paths).unwrap_or_default()
}

pub fn agecrypt_cmd(repo: &Path) -> Command {
    let mut cmd = Command::cargo_bin("git-agecrypt").unwrap();
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);
    cmd.current_dir(repo).env("PATH", &new_path);
    cmd
}

pub fn agecrypt_assert_cmd(repo: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("git-agecrypt").unwrap();
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);
    cmd.current_dir(repo).env("PATH", &new_path);
    cmd
}

pub fn run_git(repo: &Path, args: &[&str]) {
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);

    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", &new_path)
        .status()
        .unwrap_or_else(|e| panic!("Failed to execute git {:?}: {}", args, e));
    assert!(status.success(), "Git command failed: {:?}", args);
}

pub fn git_out(repo: &Path, args: &[&str]) -> Vec<u8> {
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);

    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", &new_path)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute git {:?}: {}", args, e));
    assert!(output.status.success(), "Git command failed: {:?}", args);
    output.stdout
}

pub fn run_git_output(repo: &Path, args: &[&str]) -> Output {
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);

    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", &new_path)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute git {:?}: {}", args, e))
}

pub fn git_out_res(repo: &Path, args: &[&str]) -> std::result::Result<Vec<u8>, String> {
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);

    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", &new_path)
        .output()
        .map_err(|e| format!("Failed to execute git {:?}: {}", args, e))?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn init_repo(repo: &Path) {
    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.name", "Test Developer"]);
    run_git(repo, &["config", "user.email", "dev@example.com"]);
    let _ = run_git_output(repo, &["branch", "-M", "main"]);
}

/// Generates a test X25519 identity keypair (secret_key, public_key)
pub fn generate_test_identity() -> (String, String) {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    let secret = id.to_string();
    let public = id.to_public().to_string();
    (secret.expose_secret().to_string(), public)
}

/// Invariant A: Working tree contains plaintext <=> Git object DB/index/packs contain age ciphertext.
pub fn assert_invariant_a(repo: &Path, secret_rel_path: &str, expected_plaintext: &str) {
    let disk_file = repo.join(secret_rel_path);
    assert!(
        disk_file.exists(),
        "File {} must exist on disk",
        secret_rel_path
    );
    let disk_content = fs::read_to_string(&disk_file).expect("Failed to read working tree file");
    assert_eq!(
        disk_content, expected_plaintext,
        "Working tree must contain exact plaintext"
    );

    let cat_ref = format!("HEAD:{}", secret_rel_path.replace('\\', "/"));
    let blob = git_out(repo, &["cat-file", "-p", &cat_ref]);
    assert!(
        blob.starts_with(b"age-encryption.org/v1\n"),
        "Git object store blob must be authenticated age ciphertext"
    );
    let blob_str = String::from_utf8_lossy(&blob);
    assert!(
        !blob_str.contains(expected_plaintext),
        "Git object store blob must NEVER contain plaintext secrets"
    );
}

/// Invariant C: Cross-ring isolation. Ring A secrets cannot be read or touched by Ring B.
#[allow(clippy::too_many_arguments)]
pub fn assert_invariant_c(
    repo: &Path,
    ring_a: &str,
    _ring_b: &str,
    file_a: &str,
    file_b: &str,
    plain_a: &str,
    plain_b: &str,
    key_a_sec: Option<&str>,
) {
    // 1. Lock Ring A
    let mut lock_cmd = agecrypt_cmd(repo);
    lock_cmd.args(["lock", "--ring", ring_a]).assert().success();

    // 2. Assert Ring A is locked on disk (ciphertext)
    let disk_a = fs::read(repo.join(file_a)).unwrap();
    assert!(
        disk_a.starts_with(b"age-encryption.org/v1\n"),
        "Ring A file must be locked/smudged to ciphertext"
    );

    // 3. Assert Ring B remains unlocked and readable
    let disk_b = fs::read_to_string(repo.join(file_b)).unwrap();
    assert_eq!(
        disk_b, plain_b,
        "Ring B secret must remain plaintext when Ring A is locked"
    );

    // 4. Unlock Ring A and verify Ring A restored
    let mut unlock_cmd = agecrypt_cmd(repo);
    if let Some(sec) = key_a_sec {
        let id_file = repo.join("temp_unlock_key.txt");
        fs::write(&id_file, sec).unwrap();
        unlock_cmd
            .args(["unlock", "--ring", ring_a, id_file.to_str().unwrap()])
            .assert()
            .success();
        let _ = fs::remove_file(&id_file);
    } else {
        unlock_cmd
            .args(["unlock", "--ring", ring_a])
            .assert()
            .success();
    }

    let disk_a_restored = fs::read_to_string(repo.join(file_a)).unwrap();
    assert_eq!(
        disk_a_restored, plain_a,
        "Ring A secret must restore upon unlock"
    );
}

/// Verifies that zero plaintext canaries exist inside any object (loose or packed) in the Git object database.
pub fn assert_no_plaintext_in_git_objects(repo: &Path, canaries: &[&str]) {
    let all_objects_output = git_out(repo, &["cat-file", "--batch-check", "--batch-all-objects"]);
    let all_objects_str = String::from_utf8_lossy(&all_objects_output);
    for line in all_objects_str.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(sha) = parts.first() {
            let obj_content = git_out(repo, &["cat-file", "-p", sha]);
            let obj_str = String::from_utf8_lossy(&obj_content);
            for canary in canaries {
                assert!(
                    !obj_str.contains(canary),
                    "Plaintext canary '{}' found inside Git object {}! Plaintext leaked into object database.",
                    canary,
                    sha
                );
            }
        }
    }
}
