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

    // On Linux, verify that the child process is actually non-dumpable (PR_SET_DUMPABLE=0 applied)
    #[cfg(target_os = "linux")]
    {
        // Spawn a child via run --fd and verify that the child's process memory
        // cannot be opened. Modern Linux kernels no longer expose a Dumpable field
        // in /proc/<pid>/status; denying /proc/<pid>/mem is the direct observable
        // effect of PR_SET_DUMPABLE=0 that this test is intended to protect.
        let pid_file = repo.join("run-fd-child.pid");
        let child_script = "echo $$ > \"$GIT_AGECRYPT_TEST_PID_FILE\"; sleep 5";
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("git-agecrypt"))
            .args(["run", "--fd", "--", "sh", "-c", child_script])
            .current_dir(repo)
            .env("PATH", prepend_to_path(&bin_dir()))
            .env("GIT_AGECRYPT_TEST_PID_FILE", &pid_file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to spawn run --fd child");

        let child_pid = (0..20).find_map(|_| {
            std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|pid| pid.trim().parse::<u32>().ok())
                .or_else(|| {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    None
                })
        });
        let found_non_dumpable = child_pid.is_some_and(|pid| {
            std::fs::OpenOptions::new()
                .read(true)
                .open(format!("/proc/{pid}/mem"))
                .is_err()
        });

        let _ = child.kill();
        let _ = child.wait();

        assert!(
            found_non_dumpable,
            "Child process spawned via run --fd must have PR_SET_DUMPABLE=0 (non-dumpable) on Linux"
        );
    }
}
