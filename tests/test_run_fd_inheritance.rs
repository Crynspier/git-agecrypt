mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

/// Test FD inheritance across process boundaries.
/// Verifies that the secret FD is available exactly where intended and nowhere else.
#[test]
fn test_run_fd_inheritance_boundaries() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "fd_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt -text\n",
    )
    .unwrap();

    let secret_content = "INHERITANCE_SECRET=fd_test_value_12345\n";
    fs::write(repo.join("app.secret.env"), secret_content).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // On Linux, test FD inheritance through fork/exec
    #[cfg(target_os = "linux")]
    {
        // Test 1: Direct child can read FD from offset 0 and sees GIT_AGECRYPT_ENV_FD and GIT_AGECRYPT_ENV_FILE
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--fd",
            "--",
            "sh",
            "-c",
            "test -n \"$GIT_AGECRYPT_ENV_FD\" && test \"$GIT_AGECRYPT_ENV_FILE\" = \"/dev/fd/$GIT_AGECRYPT_ENV_FD\" && cat /dev/fd/$GIT_AGECRYPT_ENV_FD",
        ]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "Direct child must read FD");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("INHERITANCE_SECRET=fd_test_value_12345"),
            "Direct child must receive secret via FD from byte offset 0"
        );

        // Test 2: Verify GIT_AGECRYPT_ENV_FD is backed by memfd_create (`memfd:git_agecrypt_env`)
        // and no internal git-agecrypt file descriptors (such as `recovery.lock`, `repo.key`, or
        // duplicate memfds) are leaked across exec into the child process.
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--fd",
            "--",
            "sh",
            "-c",
            "for f in /proc/self/fd/*; do fd=$(basename \"$f\"); target=$(readlink \"$f\" 2>/dev/null || true); if [ -n \"$target\" ]; then echo \"FD:$fd:$target\"; fi; done",
        ]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "FD enumeration must succeed");
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let fd_entries: Vec<&str> = stdout_str
            .lines()
            .filter(|l| l.starts_with("FD:"))
            .collect();
        let memfd_entries: Vec<&&str> = fd_entries
            .iter()
            .filter(|l| l.contains("git_agecrypt_env"))
            .collect();
        assert_eq!(
            memfd_entries.len(),
            1,
            "Exactly one memfd (GIT_AGECRYPT_ENV_FD) may be open in child process: {:?}",
            fd_entries
        );
        for entry in &fd_entries {
            assert!(
                !entry.contains("recovery.lock")
                    && !entry.contains("repo.key")
                    && !entry.contains("lock.journal"),
                "Internal git-agecrypt file descriptor leaked into child process: {entry}"
            );
        }

        // Test 3: Verify PR_SET_DUMPABLE=0 is preserved across exec when spawning git-agecrypt test-dumpable
        let dump_out_file = repo.join("fd_dumpable_state.txt");
        let bin_path = assert_cmd::cargo::cargo_bin!("git-agecrypt");
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--fd",
            "--",
            bin_path.to_str().unwrap(),
            "__test-dumpable",
            "--output",
            dump_out_file.to_str().unwrap(),
        ]);
        cmd.assert().success();
        let dumpable_val = fs::read_to_string(&dump_out_file).unwrap();
        assert_eq!(
            dumpable_val.trim(),
            "0",
            "PR_GET_DUMPABLE must be 0 in child process under run --fd"
        );

        // Test 4: Child that forks without exec should inherit FD
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--fd",
            "--",
            "sh",
            "-c",
            "cat /dev/fd/$GIT_AGECRYPT_ENV_FD & wait",
        ]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "Forked child must read FD");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("INHERITANCE_SECRET"),
            "Forked child (no exec) must inherit FD"
        );
    }

    // On non-Linux, --fd fails closed without --allow-env-fallback
    #[cfg(not(target_os = "linux"))]
    {
        let mut cmd = agecrypt_cmd(repo);
        cmd.args(["run", "--fd", "--", "sh", "-c", "echo test"]);
        cmd.assert().failure().code(1);
    }
}

/// Test that secrets are not leaked through environment variables when --fd is used.
#[test]
fn test_run_fd_no_env_leakage() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "env_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt -text\n",
    )
    .unwrap();

    let secret_content = "ENV_LEAK_SECRET=must_not_appear_in_env\n";
    fs::write(repo.join("app.secret.env"), secret_content).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit secret"]);

    #[cfg(target_os = "linux")]
    {
        // Run with --fd and check that the secret is NOT in the child's environment
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--fd",
            "--",
            "sh",
            "-c",
            "env | grep ENV_LEAK_SECRET || echo ENV_CLEAN",
        ]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "env check must succeed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("ENV_CLEAN"),
            "Secret must NOT appear in environment when --fd is used: {}",
            stdout
        );
    }
}
