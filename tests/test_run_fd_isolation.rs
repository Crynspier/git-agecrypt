mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_run_fd_child_lifecycle_and_exit_propagation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    fs::write(
        repo.join("app.secret.env"),
        "DATABASE_PORT=9999\nAPI_TOKEN=secret_token_val\n",
    )
    .unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit app secret"]);

    // 1. Successful execution and variable injection
    let mut run_cmd = agecrypt_cmd(repo);
    run_cmd.args([
        "run",
        "-e",
        "app.secret.env",
        "--allow-env-fallback",
        "--fd",
        "--",
    ]);
    #[cfg(windows)]
    run_cmd.args(["cmd", "/C", "exit 0"]);
    #[cfg(not(windows))]
    run_cmd.args(["true"]);
    run_cmd.assert().success();

    // 2. Non-zero exit code propagation from child
    let mut run_fail = agecrypt_cmd(repo);
    run_fail.args([
        "run",
        "-e",
        "app.secret.env",
        "--allow-env-fallback",
        "--fd",
        "--",
    ]);
    #[cfg(windows)]
    run_fail.args(["cmd", "/C", "exit 42"]);
    #[cfg(not(windows))]
    run_fail.args(["sh", "-c", "exit 42"]);
    let out = run_fail.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(42),
        "Child exit code 42 must propagate directly to parent"
    );

    // 3. Fail-closed without allow-env-fallback on non-Linux
    #[cfg(not(target_os = "linux"))]
    {
        let mut run_no_fallback = agecrypt_cmd(repo);
        run_no_fallback.args(["run", "-e", "app.secret.env", "--fd", "--"]);
        #[cfg(windows)]
        run_no_fallback.args(["cmd", "/C", "exit 0"]);
        #[cfg(not(windows))]
        run_no_fallback.args(["true"]);
        run_no_fallback.assert().failure();
    }
}
