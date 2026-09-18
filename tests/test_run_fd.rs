mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_run_command_basic_env_injection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt -text\n",
    )
    .unwrap();
    let env_content = "API_KEY=super_secret_12345\nDB_PASS=vault_p@ssw0rd!#\nUNICODE_SECRET=🔒🔑✨\nEMPTY_VAL=\nEQUALS_VAL=a=b=c=d\n";
    fs::write(repo.join("app.secret.env"), env_content).unwrap();

    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit secret env"]);

    // Run command checking that environment variables are injected into child
    #[cfg(windows)]
    {
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--",
            "cmd.exe",
            "/c",
            "echo API_KEY=%API_KEY% DB_PASS=%DB_PASS% EQUALS=%EQUALS_VAL%",
        ]);
        let assert = cmd.assert().success();
        let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
        assert!(stdout.contains("API_KEY=super_secret_12345"));
        assert!(stdout.contains("DB_PASS=vault_p@ssw0rd!#"));
        assert!(stdout.contains("EQUALS=a=b=c=d"));
    }

    #[cfg(not(windows))]
    {
        let mut cmd = agecrypt_cmd(repo);
        cmd.args([
            "run",
            "--",
            "sh",
            "-c",
            "echo API_KEY=$API_KEY DB_PASS=$DB_PASS EQUALS=$EQUALS_VAL",
        ]);
        let assert = cmd.assert().success();
        let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
        assert!(stdout.contains("API_KEY=super_secret_12345"));
        assert!(stdout.contains("DB_PASS=vault_p@ssw0rd!#"));
        assert!(stdout.contains("EQUALS=a=b=c=d"));
    }
}

#[test]
fn test_run_fd_fail_closed_on_unsupported_platforms() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt -text\n",
    )
    .unwrap();
    fs::write(repo.join("test.secret.env"), "SECRET=val\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Initial commit"]);

    #[cfg(not(target_os = "linux"))]
    {
        // On Windows and macOS: --fd without --allow-env-fallback MUST fail closed with exit code 1
        let mut cmd = agecrypt_cmd(repo);
        #[cfg(windows)]
        cmd.args([
            "run",
            "--fd",
            "--",
            "cmd.exe",
            "/c",
            "echo should_never_run",
        ]);
        #[cfg(not(windows))]
        cmd.args(["run", "--fd", "--", "sh", "-c", "echo should_never_run"]);

        let assert = cmd.assert().failure().code(1);
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
        assert!(
            stderr.contains("--allow-env-fallback")
                || stderr.contains("Linux anonymous memfd support"),
            "Error must guide the user to --allow-env-fallback: {stderr}"
        );

        // With --allow-env-fallback, it must print the notice and successfully inject variables
        let mut fallback_cmd = agecrypt_cmd(repo);
        #[cfg(windows)]
        fallback_cmd.args([
            "run",
            "--fd",
            "--allow-env-fallback",
            "--",
            "cmd.exe",
            "/c",
            "echo SECRET=%SECRET%",
        ]);
        #[cfg(not(windows))]
        fallback_cmd.args([
            "run",
            "--fd",
            "--allow-env-fallback",
            "--",
            "sh",
            "-c",
            "echo SECRET=$SECRET",
        ]);

        let assert_ok = fallback_cmd.assert().success();
        let stderr_ok = String::from_utf8_lossy(&assert_ok.get_output().stderr);
        let stdout_ok = String::from_utf8_lossy(&assert_ok.get_output().stdout);
        assert!(
            stderr_ok.contains("[NOTICE]"),
            "Notice must be emitted: {stderr_ok}"
        );
        assert!(
            stdout_ok.contains("SECRET=val"),
            "Secret must be injected: {stdout_ok}"
        );
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux: --fd must deliver secrets via memfd and set GIT_AGECRYPT_ENV_FD
        let mut cmd = agecrypt_cmd(repo);
        cmd.args(["run", "--fd", "--", "sh", "-c", "echo FD=$GIT_AGECRYPT_ENV_FD FILE=$GIT_AGECRYPT_ENV_FILE && cat /dev/fd/$GIT_AGECRYPT_ENV_FD"]);
        let assert = cmd.assert().success();
        let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
        assert!(
            stdout.contains("SECRET=val"),
            "Must read secret from fd: {stdout}"
        );
    }
}

#[test]
fn test_run_exit_code_propagation_and_fail_closed() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt -text\n",
    )
    .unwrap();
    fs::write(repo.join("test.secret.env"), "SECRET=val\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "test.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit test"]);

    // Test child process exiting with custom exit code (42)
    #[cfg(windows)]
    {
        let mut cmd = agecrypt_cmd(repo);
        cmd.args(["run", "--", "cmd.exe", "/c", "exit 42"]);
        cmd.assert().failure().code(42);
    }

    #[cfg(not(windows))]
    {
        let mut cmd = agecrypt_cmd(repo);
        cmd.args(["run", "--", "sh", "-c", "exit 42"]);
        cmd.assert().failure().code(42);
    }

    // Test fail closed if locked: secret files cannot be decrypted
    agecrypt_cmd(repo).arg("lock").assert().success();
    let mut locked_cmd = agecrypt_cmd(repo);
    #[cfg(windows)]
    locked_cmd.args(["run", "--", "cmd.exe", "/c", "echo fail"]);
    #[cfg(not(windows))]
    locked_cmd.args(["run", "--", "sh", "-c", "echo fail"]);

    // When locked, files on disk are ciphertext, so git-agecrypt run must fail closed with exit code 1
    let assert_locked = locked_cmd.assert().failure().code(1);
    let stderr_locked = String::from_utf8_lossy(&assert_locked.get_output().stderr);
    assert!(stderr_locked.contains("repository is locked"));
}
