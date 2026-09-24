//! Power-loss durability testing.
//!
//! Two layers:
//! 1. `test_power_loss_torn_write_audit` (cross-platform): kills git-agecrypt at every
//!    write-side crash point (SIGKILL/TerminateProcess) and audits EVERY file in the repo
//!    and the local state dir for torn/partial writes. A file is only ever allowed to be
//!    absent, complete-old, or complete-new. The crashed operation is then retried to prove
//!    idempotent recovery, and (where applicable) secrets must decrypt to exact plaintext.
//! 2. `test_dm_flakey_true_power_loss` (Linux + root + device-mapper only): runs the repo
//!    on a dm-flakey block device, cuts "power" at the block layer mid-transaction,
//!    force-remounts, and verifies recovery. Skips cleanly when unavailable.

mod common;

use common::invariants::*;
use common::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::tempdir;

/// A file whose write was interrupted must never be a truncated/garbled version of
/// itself. Returns a description of the violation, if any.
fn classify_file_violation(path: &Path, rel: &str, plaintext_canary: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // Transient transaction artifacts are allowed to exist pre-recovery; they are
    // audited for cleanup AFTER recovery instead.
    if name.contains(".tmp") || name == "repo.key.locking" || name == "lock.journal" {
        return None;
    }

    if name.ends_with(".pub") {
        // Public key files: every non-empty line is a complete age recipient or comment.
        let text = String::from_utf8_lossy(&data);
        if text.trim().is_empty() {
            return Some(format!("{rel}: empty public key file"));
        }
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with("age1") && !line.starts_with('#') {
                return Some(format!("{rel}: torn public key file, bad line: {line:?}"));
            }
        }
        return None;
    }

    if name.ends_with(".age") {
        let norm_rel = rel.replace('\\', "/");
        if norm_rel.contains("/cache/") {
            // Binary ciphertext cache entries (clean-filter dedup cache). Writes are
            // atomic (NamedTempFile + sync_all + rename), so presence implies a
            // complete entry; the age magic header verifies it is not a partial
            // rename artifact. Full integrity is additionally HMAC-authenticated
            // by the cache reader on lookup.
            if !data.starts_with(b"age-encryption.org/v1") {
                return Some(format!("{rel}: torn binary cache entry (bad age magic)"));
            }
            return None;
        }
        // Wrapped recipient keys: armored age file must be COMPLETE (header+footer).
        let text = String::from_utf8_lossy(&data);
        let complete = text.contains("-----BEGIN AGE ENCRYPTED FILE-----")
            && text.contains("-----END AGE ENCRYPTED FILE-----");
        if !complete {
            return Some(format!(
                "{rel}: torn armored key file (missing header/footer)"
            ));
        }
        return None;
    }

    if name == "repo.key" {
        // Local master key: must be complete (non-empty, plausible key material).
        if data.len() < 10 {
            return Some(format!(
                "{rel}: torn local master key ({} bytes)",
                data.len()
            ));
        }
        return None;
    }

    if name.ends_with(".secret.env") {
        // Working-tree secrets: exact plaintext, complete armored ciphertext, or
        // binary-header ciphertext (binary completeness is proven by post-recovery
        // decryption). Anything else (e.g. truncated armor) is a torn write.
        if data == plaintext_canary.as_bytes() {
            return None;
        }
        let text = String::from_utf8_lossy(&data);
        if text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
            if !text.contains("-----END AGE ENCRYPTED FILE-----") {
                return Some(format!(
                    "{rel}: truncated armored ciphertext in working tree"
                ));
            }
            return None;
        }
        if data.starts_with(b"age-encryption.org/v1\n") {
            return None;
        }
        if !data.is_empty() && data != plaintext_canary.as_bytes() {
            return Some(format!(
                "{rel}: working tree secret is neither complete plaintext nor complete ciphertext"
            ));
        }
        return None;
    }

    None
}

/// Recursively audits the whole repo (working tree + state dirs) for torn files.
fn audit_no_torn_files(repo: &Path, plaintext_canary: &str) {
    let mut violations = Vec::new();
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .flatten()
        {
            let path = entry.path();
            let rel = path
                .strip_prefix(repo)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                if path == repo.join(".git") {
                    // Only descend into .git/git-agecrypt (git's own object store has its
                    // own durability discipline); audit git-agecrypt state + working tree.
                    let state = path.join("git-agecrypt");
                    if state.exists() {
                        stack.push(state);
                    }
                    continue;
                }
                stack.push(path);
            } else if ft.is_file()
                && let Some(v) = classify_file_violation(&path, &rel, plaintext_canary)
            {
                violations.push(v);
            }
        }
    }
    assert!(
        violations.is_empty(),
        "torn-write violations:\n{}",
        violations.join("\n")
    );
}

/// Asserts no transient transaction artifacts remain in the local state dir.
fn assert_no_transient_artifacts(repo: &Path, ctx: &str) {
    let state_dir = repo.join(".git").join("git-agecrypt");
    if !state_dir.exists() {
        return;
    }
    for entry in fs::read_dir(&state_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.contains(".tmp") && name != "repo.key.locking" && name != "lock.journal",
            "{ctx}: transient artifact survived recovery: {name}"
        );
    }
}
/// Sets up a repo with one committed, unlocked secret. Returns (guard, repo, sec_id, plaintext).
fn setup_unlocked_repo() -> (tempfile::TempDir, PathBuf, String, String) {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path().to_path_buf();
    init_repo(&repo);

    agecrypt_cmd(&repo).arg("init").assert().success();
    let (sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(&repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "ci_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    let plaintext = "POWER_LOSS_CANARY=super_secure_vault_value\n".to_string();
    fs::write(repo.join("vault.secret.env"), &plaintext).unwrap();
    run_git(
        &repo,
        &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
    );
    run_git(&repo, &["commit", "-m", "Initial secret commit"]);

    (temp, repo, sec_id, plaintext)
}

/// Runs `git-agecrypt status` (recovery sweep) and asserts success.
fn run_recovery_status(repo: &Path, point: &str) {
    let out = agecrypt_cmd(repo)
        .env_remove("GIT_AGECRYPT_CRASH_POINT")
        .arg("status")
        .output()
        .expect("Failed to run status for recovery");
    assert!(
        out.status.success(),
        "recovery status must succeed after crash point {point}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
/// Cross-platform torn-write audit: kill at every write-side crash point, verify no file
/// is left partially written, then prove recovery is complete and idempotent.
#[test]
fn test_power_loss_torn_write_audit() {
    let crash_points = [
        "before_tx_begin",
        "after_tmp_create",
        "after_plaintext_write",
        "after_ciphertext_write",
        "after_ciphertext_fsync",
        "after_dir_fsync",
        "after_key_rename",
        "after_journal_create",
        "after_journal_fsync",
        "after_journal_transition",
        "after_old_delete",
        "before_cleanup",
        "after_cleanup",
        "spool_chunk",
        "after_unwrap_key",
        "after_unlock_key_saved",
        "after_unlock_refresh",
        "after_rekey_pub_write",
        "after_rekey_key_saved",
        "after_rekey_cache_purge",
    ];

    for point in crash_points {
        let (_temp, repo, sec_id, plaintext) = setup_unlocked_repo();
        let id_file = repo.join("unlock_key.txt");
        fs::write(&id_file, &sec_id).unwrap();

        let mut op_cmd = agecrypt_cmd(&repo);
        op_cmd.env("GIT_AGECRYPT_CRASH_POINT", point);

        let clean_point = matches!(
            point,
            "after_ciphertext_write" | "after_ciphertext_fsync" | "spool_chunk"
        );
        let unlock_point = matches!(
            point,
            "after_unwrap_key" | "after_unlock_key_saved" | "after_unlock_refresh"
        );
        let rekey_point = matches!(
            point,
            "after_tmp_create"
                | "after_plaintext_write"
                | "after_rekey_pub_write"
                | "after_rekey_key_saved"
                | "after_rekey_cache_purge"
        );

        // Trigger the crash.
        if clean_point {
            op_cmd.args(["clean", "vault.secret.env"]);
            op_cmd.stdin(Stdio::piped());
            op_cmd.stdout(Stdio::null());
            op_cmd.stderr(Stdio::null());
            let mut child = op_cmd.spawn().expect("spawn clean");
            if let Some(mut sin) = child.stdin.take() {
                let payload = vec![b'A'; 2 * 1024 * 1024];
                let _ = sin.write_all(&payload);
            }
            let status = child.wait().expect("wait clean");
            assert!(!status.success(), "{point}: crashed clean must not succeed");
        } else {
            match point {
                _ if unlock_point => {
                    op_cmd.args(["unlock", id_file.to_str().unwrap()]);
                }
                _ if rekey_point => {
                    op_cmd.args(["rekey", "-f"]);
                }
                "after_old_delete" => {
                    op_cmd.args(["remove-recipient", "ci_user"]);
                }
                _ => {
                    op_cmd.args(["lock", "-f"]);
                }
            }
            let out = op_cmd.output().expect("run crashed op");
            assert!(
                !out.status.success(),
                "{point}: crashed op must exit non-zero"
            );
        }

        // LAYER 1: no torn writes anywhere (pre-recovery audit).
        audit_no_torn_files(&repo, &plaintext);

        // LAYER 2: recovery sweep succeeds and leaves no transient artifacts.
        run_recovery_status(&repo, point);
        assert_no_transient_artifacts(&repo, point);
        assert_inv_b_durability_consistent(&repo);
        // LAYER 3: idempotent retry of the crashed operation must succeed (or be
        // harmlessly complete already), and secrets must decrypt to exact plaintext.
        if clean_point {
            let out = agecrypt_cmd(&repo)
                .args(["clean", "vault.secret.env"])
                .output()
                .expect("retry clean");
            assert!(out.status.success(), "{point}: retried clean must succeed");
            assert!(
                !out.stdout.is_empty(),
                "{point}: retried clean must emit complete ciphertext"
            );
        } else if unlock_point {
            agecrypt_cmd(&repo)
                .args(["unlock", id_file.to_str().unwrap()])
                .assert()
                .success();
            let disk = fs::read_to_string(repo.join("vault.secret.env")).unwrap();
            assert_eq!(
                disk, plaintext,
                "{point}: unlock retry must restore exact plaintext"
            );
        } else if rekey_point {
            agecrypt_cmd(&repo).args(["rekey", "-f"]).assert().success();
        } else if point == "after_old_delete" {
            // Delete already happened pre-crash; re-adding the recipient must succeed.
            let (_, pub2) = generate_test_identity();
            agecrypt_cmd(&repo)
                .args(["add-recipient", "-i", &pub2, "--name", "ci_user"])
                .assert()
                .success();
        } else {
            // lock-transaction points: retry lock, then full decryptability proof.
            agecrypt_cmd(&repo).args(["lock", "-f"]).assert().success();
            agecrypt_cmd(&repo)
                .args(["unlock", id_file.to_str().unwrap()])
                .assert()
                .success();
            let disk = fs::read_to_string(repo.join("vault.secret.env")).unwrap();
            assert_eq!(
                disk, plaintext,
                "{point}: post-crash unlock must restore exact plaintext"
            );
        }

        // Final structural audit after recovery.
        audit_no_torn_files(&repo, &plaintext);
        assert_no_transient_artifacts(&repo, point);
    }
}
// ---------------------------------------------------------------------------
// True power-loss emulation via device-mapper flakey target (Linux + root only).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod dm_flakey {
    use super::*;
    use std::process::Command;

    fn have_cmd(cmd: &str) -> bool {
        Command::new("sh")
            .args(["-c", &format!("command -v {cmd} >/dev/null 2>&1")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn is_root() -> bool {
        Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }

    fn run(argv: &[&str]) -> Result<String, String> {
        let out = Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| format!("{}: spawn: {e}", argv[0]))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(format!(
                "{}: exit {}: {}",
                argv.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    /// Best-effort cleanup of the block-device stack on drop (including panics).
    struct PowerCutGuard {
        dm_name: String,
        loop_dev: String,
        mnt: PathBuf,
    }

    impl Drop for PowerCutGuard {
        fn drop(&mut self) {
            let _ = run(&["umount", "-f", "-l", &self.mnt.to_string_lossy()]);
            let _ = run(&["dmsetup", "remove", "-f", &self.dm_name]);
            let _ = run(&["losetup", "-d", &self.loop_dev]);
        }
    }

    /// Builds a live repo on a flakey device, crashes mid-unlock, cuts power at the block
    /// layer, remounts, and verifies full recoverability. Skips cleanly when the
    /// environment lacks root/device-mapper support.
    pub fn run() {
        if !is_root() || !have_cmd("dmsetup") || !have_cmd("losetup") || !have_cmd("mkfs.ext4") {
            eprintln!("dm-flakey power-loss test requires Linux root + device-mapper; skipping");
            return;
        }

        let temp = tempdir().expect("tempdir");
        let img = temp.path().join("disk.img");
        let mnt = temp.path().join("mnt");
        fs::create_dir_all(&mnt).unwrap();

        // 64 MiB backing image.
        let f = fs::File::create(&img).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        drop(f);

        let loop_dev = match run(&["losetup", "-f", "--show", &img.to_string_lossy()]) {
            Ok(dev) => dev,
            Err(e) => {
                eprintln!("losetup unavailable ({e}); skipping dm-flakey test");
                return;
            }
        };
        let dm_name = format!("gaflakey{}", std::process::id());
        let sectors = "131072"; // 64 MiB / 512
        let guard = PowerCutGuard {
            dm_name: dm_name.clone(),
            loop_dev: loop_dev.clone(),
            mnt: mnt.clone(),
        };

        run(&[
            "dmsetup",
            "create",
            &dm_name,
            "--table",
            &format!("0 {sectors} flakey {loop_dev} 0 0 0"),
        ])
        .expect("dmsetup create flakey");
        run(&["mkfs.ext4", "-q", &format!("/dev/mapper/{dm_name}")]).expect("mkfs.ext4");
        run(&[
            "mount",
            &format!("/dev/mapper/{dm_name}"),
            &mnt.to_string_lossy(),
        ])
        .expect("mount flakey");

        // Build a working repo on the flakey filesystem.
        let repo = mnt.join("repo");
        fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        agecrypt_cmd(&repo).arg("init").assert().success();
        let (sec_id, pub_key) = generate_test_identity();
        agecrypt_cmd(&repo)
            .args(["add-recipient", "-i", &pub_key, "--name", "power_user"])
            .assert()
            .success();
        fs::write(
            repo.join(".gitattributes"),
            "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
        )
        .unwrap();
        let plaintext = "POWER_CUT_CANARY=flakey_block_layer\n".to_string();
        fs::write(repo.join("vault.secret.env"), &plaintext).unwrap();
        run_git(
            &repo,
            &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
        );
        run_git(&repo, &["commit", "-m", "secret"]);
        // Establish a locked baseline so unlock runs a real transaction.
        agecrypt_cmd(&repo).args(["lock", "-f"]).assert().success();
        let id_file = repo.join("unlock_key.txt");
        fs::write(&id_file, &sec_id).unwrap();

        // Crash mid-transaction (after key unwrap, before key save + refresh).
        let out = agecrypt_cmd(&repo)
            .args(["unlock", id_file.to_str().unwrap()])
            .env("GIT_AGECRYPT_CRASH_POINT", "after_unwrap_key")
            .output()
            .expect("crashed unlock");
        assert!(
            !out.status.success(),
            "crash point must terminate the process"
        );

        // TRUE POWER CUT: drop all in-flight writes at the block layer, kill the fs.
        run(&["dmsetup", "suspend", &dm_name]).expect("dm suspend");
        run(&[
            "dmsetup",
            "load",
            &dm_name,
            "--table",
            &format!("0 {sectors} error"),
        ])
        .expect("dm load error target");
        run(&["dmsetup", "resume", &dm_name]).expect("dm resume error");
        run(&["umount", "-f", &mnt.to_string_lossy()]).expect("force unmount (no sync)");
        run(&["dmsetup", "remove", "-f", &dm_name]).expect("dm remove");

        // Reattach the surviving disk image and remount (ext4 replays its journal).
        run(&[
            "dmsetup",
            "create",
            &dm_name,
            "--table",
            &format!("0 {sectors} flakey {loop_dev} 0 0 0"),
        ])
        .expect("dm recreate");
        run(&[
            "mount",
            &format!("/dev/mapper/{dm_name}"),
            &mnt.to_string_lossy(),
        ])
        .expect("remount after power loss");

        // POST-POWER-LOSS RECOVERY: repo must be coherent and recoverable.
        audit_no_torn_files(&repo, &plaintext);
        run_recovery_status(&repo, "dm-flakey");
        assert_no_transient_artifacts(&repo, "dm-flakey");
        assert_inv_b_durability_consistent(&repo);

        // Idempotent retry: unlock must complete and restore exact plaintext.
        let retry = agecrypt_cmd(&repo)
            .args(["unlock", id_file.to_str().unwrap()])
            .output()
            .expect("post-power-loss unlock");
        assert!(
            retry.status.success(),
            "post-power-loss unlock must succeed: {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        let disk = fs::read_to_string(repo.join("vault.secret.env")).unwrap();
        assert_eq!(
            disk, plaintext,
            "post-power-loss unlock must restore exact plaintext"
        );

        drop(guard);
    }
}

#[test]
fn test_dm_flakey_true_power_loss() {
    #[cfg(target_os = "linux")]
    dm_flakey::run();
    #[cfg(not(target_os = "linux"))]
    println!("dm-flakey power-loss test is Linux-only; skipping on this platform");
}
