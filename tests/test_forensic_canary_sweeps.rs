mod common;

use common::*;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_forensic_canary_sweep_large_files() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    let (user_sec, user_pub) = generate_test_identity();
    let key_dir = tempdir().expect("Failed to create keydir");
    let id_file = key_dir.path().join("master.key");
    fs::write(&id_file, &user_sec).unwrap();

    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &user_pub, "--name", "test_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.bin filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    // Generate a 2 MiB payload with embedded unique forensic canaries
    let canary_id = format!(
        "CANARY_FORENSIC_{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut large_secret = Vec::with_capacity(2 * 1024 * 1024);
    for chunk_idx in 0..2048 {
        large_secret.extend_from_slice(format!("{canary_id}_CHUNK_{chunk_idx:04}\n").as_bytes());
        large_secret.resize(large_secret.len() + 900, b'X');
    }

    let secret_file = repo.join("large.secret.bin");
    fs::write(&secret_file, &large_secret).unwrap();

    // Stage and commit large file
    run_git(repo, &["add", "."]);
    run_git(
        repo,
        &["commit", "-m", "Commit 2 MiB secret with forensic canaries"],
    );

    // Lock working tree
    agecrypt_cmd(repo).arg("lock").assert().success();

    // FORENSIC SCAN 1: Spool and temporary directories
    let spool_dir = repo.join(".git").join("git-agecrypt").join("spool");
    if spool_dir.exists() {
        assert_canary_absent_in_directory(&spool_dir, canary_id.as_bytes());
    }

    // FORENSIC SCAN 2: Git Object Store
    let canary_chunk = format!("{canary_id}_CHUNK_0001");
    assert_no_plaintext_in_git_objects(repo, &[&canary_chunk]);

    // Unlock and verify restored content
    agecrypt_cmd(repo)
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();

    let restored = fs::read(&secret_file).unwrap();
    assert_eq!(
        restored.len(),
        large_secret.len(),
        "Restored file size must match"
    );
    assert_eq!(
        restored, large_secret,
        "Restored file content must match exactly"
    );
}

fn assert_canary_absent_in_directory(dir: &Path, canary_bytes: &[u8]) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(bytes) = fs::read(&p) {
                    assert!(
                        !bytes.windows(canary_bytes.len()).any(|w| w == canary_bytes),
                        "Forensic violation: unencrypted canary found in temporary disk file '{}'",
                        p.display()
                    );
                }
            } else if p.is_dir() {
                assert_canary_absent_in_directory(&p, canary_bytes);
            }
        }
    }
}
