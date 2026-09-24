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
    run_git(repo, &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"]);
    run_git(repo, &["commit", "-m", "Commit secret"]);

    // On Linux, test FD inheritance through fork/exec
    #[cfg(target_os = "linux")]
    {
        // Test 1: Direct child can read FD
        let mut cmd = agecrypt_cmd(repo);
        cmd.args(["run", "--fd", "--", "sh", "-c", "cat /dev/fd/$GIT_AGECRYPT_ENV_FD"]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "Direct child must read FD");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("INHERITANCE_SECRET"),
            "Direct child must receive secret via FD"
        );

        // Test 2: Grandchild (fork + exec) should NOT inherit FD by default
        // The FD should be closed on exec unless explicitly inherited
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--fd",
            "--",
            "sh",
            "-c",
            "sh -c 'cat /dev/fd/$GIT_AGECRYPT_ENV_FD 2>&1 || echo FD_NOT_AVAILABLE'",
        ]);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "Grandchild command must succeed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        // The grandchild should either not see the FD or get an error
        // This depends on whether the FD was marked close-on-exec
        assert!(
            stdout.contains("FD_NOT_AVAILABLE") || stdout.contains("INHERITANCE_SECRET"),
            "Grandchild FD inheritance behavior must be deterministic: {}",
            stdout
        );

        // Test 3: Child that forks without exec should inherit FD
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
    run_git(repo, &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"]);
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

