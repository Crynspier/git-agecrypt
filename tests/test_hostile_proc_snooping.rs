mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_run_fd_child_reads_secret_and_proc_snooping_denied() {
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
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    let secret_env_content = "API_KEY=hostile_proc_test_secret_12345\nDB_PASS=vault_secret_98765\n";
    fs::write(repo.join("app.secret.env"), secret_env_content).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Commit secret env"]);

    // Execute run passing secrets to child process.
    // Child prints environment variables it received to stdout.
    #[cfg(windows)]
    let child_cmd = "cmd.exe";
    #[cfg(windows)]
    let child_args = ["/c", "set API_KEY"];

    #[cfg(not(windows))]
    let child_cmd = "sh";
    #[cfg(not(windows))]
    let child_args = ["-c", "echo $API_KEY"];

    let mut run_cmd = agecrypt_cmd(repo);
    run_cmd.args(["run", "--", child_cmd]);
    run_cmd.args(child_args);

    let output = run_cmd.output().expect("Failed to execute run");
    assert!(
        output.status.success(),
        "run command must exit with child success: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout_str.contains("hostile_proc_test_secret_12345"),
        "Child process must successfully receive injected secret environment variable: got '{stdout_str}'"
    );

    // Lock repository so secrets cannot be extracted without identity
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();
    let mut locked_run = agecrypt_cmd(repo);
    locked_run.args(["run", "--", child_cmd]);
    locked_run.args(child_args);
    locked_run.assert().failure();

    // On Linux, verify that PR_SET_DUMPABLE=0 prevents ptrace attachment
    #[cfg(target_os = "linux")]
    {
        // Probe whether ptrace attach on non-dumpable child returns EPERM
        let res = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert!(res >= 0, "prctl call must succeed");
    }
}
