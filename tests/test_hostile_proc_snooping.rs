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
    let (sec_id, pub_key) = generate_test_identity();
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

    // Restore the unlocked state before probing the child process. The --fd
    // command must load the tracked secret environment first, so probing while
    // the repository is locked would only test the expected missing-key error.
    let mut unlock = agecrypt_cmd(repo);
    unlock
        .args(["unlock", "-"])
        .stdin(std::process::Stdio::piped());
    let mut unlock_child = unlock.spawn().expect("Failed to spawn unlock");
    if let Some(mut stdin) = unlock_child.stdin.take() {
        std::io::Write::write_all(&mut stdin, sec_id.as_bytes())
            .expect("Failed to provide unlock identity");
    }
    assert!(
        unlock_child
            .wait()
            .expect("Failed to wait for unlock")
            .success(),
        "Failed to unlock repository for dumpability probe"
    );

    // On Linux, verify that the child process is actually non-dumpable (PR_SET_DUMPABLE=0 applied)
    #[cfg(target_os = "linux")]
    {
        // Execute the same binary after run --fd sets dumpability in pre_exec.
        // The child directly queries PR_GET_DUMPABLE, avoiding /proc behavior
        // that differs with kernel versions and runner privileges.
        let probe_file = repo.join("run-fd-dumpable.txt");
        let binary = assert_cmd::cargo::cargo_bin("git-agecrypt");
        let mut child = std::process::Command::new(&binary)
            .args(["run", "--fd", "--"])
            .arg(&binary)
            .arg("__test-dumpable")
            .arg(&probe_file)
            .current_dir(repo)
            .env("PATH", prepend_to_path(&bin_dir()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to spawn run --fd child");

        let status = child.wait().expect("Failed to wait for run --fd child");
        let found_non_dumpable = status.success()
            && std::fs::read_to_string(&probe_file)
                .map(|value| value.trim() == "0")
                .unwrap_or(false);

        assert!(
            found_non_dumpable,
            "Child process spawned via run --fd must have PR_SET_DUMPABLE=0 (non-dumpable) on Linux"
        );
    }
}
