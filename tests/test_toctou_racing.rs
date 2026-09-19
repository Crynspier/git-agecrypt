mod common;

use common::*;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_toctou_racing_symlink_swap_rejection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "victim_user"])
        .assert()
        .success();

    let target_canary_dir = tempdir().expect("Failed to create target tempdir");
    let target_canary_file = target_canary_dir.path().join("unauthorized_leak.txt");
    fs::write(&target_canary_file, "ORIGINAL_UNAUTHORIZED_TARGET").unwrap();

    let victim_file = repo.join(".git").join("git-agecrypt").join("repo.key");

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_flag);
    let victim_clone = victim_file.clone();
    let _target_clone = target_canary_file.clone();

    // Spawn an aggressive attacker thread continuously toggling between a real file and a symlink
    let attacker_handle = thread::spawn(move || {
        let mut count = 0;
        while !stop_clone.load(Ordering::Relaxed) && count < 200 {
            // Attempt to create symlink/junction if permissions allow
            #[cfg(unix)]
            {
                let _ = fs::remove_file(&victim_clone);
                let _ = std::os::unix::fs::symlink(&_target_clone, &victim_clone);
                thread::sleep(Duration::from_millis(2));
                let _ = fs::remove_file(&victim_clone);
                let _ = fs::write(&victim_clone, "LEGITIMATE_KEY_REPLACEMENT");
            }
            #[cfg(windows)]
            {
                // On Windows without developer mode, symlink creation may require elevated privileges,
                // so we test rapid rename/swap between legitimate and decoy file paths
                let decoy = victim_clone.with_extension("decoy");
                let _ = fs::write(&decoy, "DECOY_UNTRUSTED_CONTENT");
                let _ = fs::rename(&decoy, &victim_clone);
                thread::sleep(Duration::from_millis(2));
            }
            count += 1;
        }
    });

    // Victim repeatedly executes operations
    for _ in 0..10 {
        let out = agecrypt_cmd(repo).arg("status").output();
        if let Ok(res) = out {
            // Must either succeed on real repo or fail closed with security error,
            // but the target canary file must NEVER be overwritten with secret data!
            let _ = res;
        }
        thread::sleep(Duration::from_millis(5));
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = attacker_handle.join();

    // Verify the unauthorized destination was untouched
    let target_content = fs::read_to_string(&target_canary_file).unwrap();
    assert_eq!(
        target_content, "ORIGINAL_UNAUTHORIZED_TARGET",
        "Target file must NEVER be overwritten by a TOCTOU symlink race attack!"
    );
}
