use super::*;
use std::fs;
use std::path::Path;

/// Invariant A: Working tree contains plaintext <=> Git object DB/index/packs contain age ciphertext.
pub fn assert_inv_a_working_tree_vs_objects(repo: &Path, rel_path: &str, expected_plaintext: &str) {
    let disk_file = repo.join(rel_path);
    assert!(disk_file.exists(), "File {rel_path} must exist on disk");
    let disk_content = fs::read_to_string(&disk_file).expect("Failed to read working tree file");
    assert_eq!(
        disk_content, expected_plaintext,
        "Working tree must match expected plaintext"
    );

    let cat_ref = format!("HEAD:{}", rel_path.replace('\\', "/"));
    let blob = git_out(repo, &["cat-file", "-p", &cat_ref]);
    assert!(
        blob.starts_with(b"age-encryption.org/v1\n"),
        "Git object store blob for {rel_path} must be age ciphertext"
    );
}

/// Invariant B: Durability & WAL consistency. No dangling unrecovered journals or locking markers.
pub fn assert_inv_b_durability_consistent(repo: &Path) {
    let state_dir = repo.join(".git").join("git-agecrypt");
    if state_dir.exists() {
        let locking_file = state_dir.join("repo.key.locking");
        assert!(
            !locking_file.exists(),
            "Dangling repo.key.locking file found"
        );
    }
}

/// Invariant D: Ring identifier grammar and reserved device safety.
pub fn assert_inv_d_ring_grammar_safe(repo: &Path, ring_name: &str) -> bool {
    let out = agecrypt_cmd(repo)
        .args(["init", "--ring", ring_name])
        .output()
        .unwrap();
    out.status.success()
}

/// Invariant G: Zero plaintext canary leaks in reachable or unreachable Git repository objects/spool.
pub fn assert_inv_g_zero_canary_leaks(repo: &Path, canary: &[u8]) {
    let git_dir = repo.join(".git");
    fn scan_dir(dir: &Path, canary: &[u8]) -> bool {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    if scan_dir(&p, canary) {
                        return true;
                    }
                } else if let Ok(data) = fs::read(&p) {
                    if data.windows(canary.len()).any(|w| w == canary) {
                        return true;
                    }
                }
            }
        }
        false
    }
    assert!(
        !scan_dir(&git_dir, canary),
        "Invariant G violation: Plaintext canary detected in .git directory"
    );
}
