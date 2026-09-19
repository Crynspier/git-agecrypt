mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_run_fd_lifecycle_and_exit_code_propagation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "lifecycle_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(repo.join("conf.secret.env"), "LIFECYCLE_VAL=active\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "conf.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Lifecycle secret commit"]);

    // 1. Normal child exit 0
    #[cfg(windows)]
    let exit_0_cmd = ["cmd.exe", "/c", "exit 0"];
    #[cfg(not(windows))]
    let exit_0_cmd = ["sh", "-c", "exit 0"];

    let mut run_0 = agecrypt_cmd(repo);
    run_0.arg("run").arg("--").args(exit_0_cmd);
    run_0.assert().success();

    // 2. Child exit code 42 must propagate exactly to parent
    #[cfg(windows)]
    let exit_42_cmd = ["cmd.exe", "/c", "exit 42"];
    #[cfg(not(windows))]
    let exit_42_cmd = ["sh", "-c", "exit 42"];

    let mut run_42 = agecrypt_cmd(repo);
    run_42.arg("run").arg("--").args(exit_42_cmd);
    let output_42 = run_42.output().unwrap();
    assert_eq!(
        output_42.status.code(),
        Some(42),
        "Parent process must accurately propagate child exit code 42"
    );

    // 3. Child never reads FD and exits immediately
    #[cfg(windows)]
    let no_read_cmd = ["cmd.exe", "/c", "echo child_done"];
    #[cfg(not(windows))]
    let no_read_cmd = ["sh", "-c", "echo child_done"];

    let mut run_no_read = agecrypt_cmd(repo);
    run_no_read.arg("run").arg("--").args(no_read_cmd);
    run_no_read.assert().success();
}
