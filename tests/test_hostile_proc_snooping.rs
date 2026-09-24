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
        use std::io::Read as _;
        // Spawn a child via run --fd and check /proc/<pid>/status for Dumpable flag
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("git-agecrypt"))
            .args(["run", "--fd", "--", "sh", "-c", "sleep 5"])
            .current_dir(repo)
            .env("PATH", prepend_to_path(&bin_dir()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to spawn run --fd child");

        // Give the child a moment to start
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Find the grandchild shell process (the actual child of git-agecrypt)
        // Check the git-agecrypt child's children via /proc
        let parent_pid = child.id();
        let mut found_non_dumpable = false;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let stat_path = format!("/proc/{}/stat", pid);
                    if let Ok(stat) = std::fs::read_to_string(&stat_path) {
                        // ppid is field 4 in /proc/<pid>/stat
                        let parts: Vec<&str> = stat.split_whitespace().collect();
                        if parts.len() > 3 {
                            if let Ok(ppid) = parts[3].parse::<u32>() {
                                if ppid == parent_pid {
                                    // Found the child process; check its dumpable flag
                                    let status_path = format!("/proc/{}/status", pid);
                                    if let Ok(status) = std::fs::read_to_string(&status_path) {
                                        for line in status.lines() {
                                            if line.starts_with("Dumpable:") {
                                                let val = line.trim_start_matches("Dumpable:").trim();
                                                if val == "0" {
                                                    found_non_dumpable = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let _ = child.kill();
        let _ = child.wait();

        assert!(
            found_non_dumpable,
            "Child process spawned via run --fd must have PR_SET_DUMPABLE=0 (non-dumpable) on Linux"
        );
    }
}
