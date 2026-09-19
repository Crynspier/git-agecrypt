mod common;

use common::invariants::*;
use common::*;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use tempfile::tempdir;

fn recursively_scan_for_canary(dir: &Path, canary: &[u8]) -> Vec<String> {
    let mut leaks = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                leaks.extend(recursively_scan_for_canary(&p, canary));
            } else if let Ok(data) = fs::read(&p) {
                if data.windows(canary.len()).any(|window| window == canary) {
                    leaks.push(p.display().to_string());
                }
            }
        }
    }
    leaks
}

#[test]
fn test_large_file_streaming_crash_and_forensic_canary_sweep() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "canary_user"])
        .assert()
        .success();

    let canary_token = b"SUPER_SENSITIVE_IN_FLIGHT_CANARY_TOKEN_999";
    let mut large_stream = Vec::with_capacity(4 * 1024 * 1024);
    while large_stream.len() < 4 * 1024 * 1024 {
        large_stream.extend_from_slice(b"CHUNK_FILLER_DATA_BEFORE_CANARY_");
        large_stream.extend_from_slice(canary_token);
        large_stream.extend_from_slice(b"\n");
    }

    // Attempt clean filter streaming with spool_chunk crash point active
    let mut clean_cmd = agecrypt_cmd(repo);
    clean_cmd.env("GIT_AGECRYPT_CRASH_POINT", "spool_chunk");
    clean_cmd.args(["clean", "large.secret.bin"]);
    clean_cmd.stdin(Stdio::piped());
    clean_cmd.stdout(Stdio::null());
    clean_cmd.stderr(Stdio::null());

    let mut child = clean_cmd.spawn().expect("Failed to spawn clean filter");
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(&large_stream);
        drop(sin);
    }
    let status = child.wait().expect("Failed to wait on child");
    assert!(
        !status.success(),
        "Clean filter must crash/terminate on spool_chunk crash point"
    );

    // Run recovery on repo
    agecrypt_cmd(repo).arg("status").assert().success();

    // Invariant B: Durability & WAL consistency
    assert_inv_b_durability_consistent(repo);

    // Forensic canary sweep across .git/ directory
    let git_dir = repo.join(".git");
    let leaks = recursively_scan_for_canary(&git_dir, canary_token);
    assert!(
        leaks.is_empty(),
        "Zero plaintext canary leaks must exist in .git/ after crashed stream: found leaks in {:?}",
        leaks
    );
}
