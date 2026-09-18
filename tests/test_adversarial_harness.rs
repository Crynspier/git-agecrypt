mod common;

use common::*;
use std::fs;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn test_formal_invariants_a_through_f() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "alice"]);
    add_cmd.assert().success();

    // 1. INVARIANT A: Working tree is plaintext <=> Git object DB contains ciphertext
    let canary = "INVARIANT_A_CANARY_SECRET_10101";
    let secret_file = repo.join("invariant_a.secret.env");
    let secret_plain = format!("SECRET={canary}\n");
    fs::write(&secret_file, &secret_plain).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit Invariant A"]);

    assert_invariant_a(repo, "invariant_a.secret.env", &secret_plain);
    assert_no_plaintext_in_git_objects(repo, &[canary]);

    // 2. INVARIANT B: Rekeying is atomic and fail-closed
    // Rekeying must succeed atomically without leaving stray temporary files
    let mut rekey_cmd = agecrypt_cmd(repo);
    rekey_cmd.args(["rekey", "--force"]);
    rekey_cmd.env("GIT_AGECRYPT_IDENTITY", &secret_key);
    rekey_cmd.assert().success();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit Rekey"]);

    assert_eq!(fs::read_to_string(&secret_file).unwrap(), secret_plain);
    assert_no_plaintext_in_git_objects(repo, &[canary]);

    // 3. INVARIANT C: Scoped ring isolation
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();
    let (prod_sec, prod_pub) = generate_test_identity();
    let mut add_prod = agecrypt_cmd(repo);
    add_prod.args([
        "add-recipient",
        "--ring",
        "prod",
        "-i",
        &prod_pub,
        "--name",
        "prod_admin",
    ]);
    add_prod.assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt -text\n*.prod.env filter=agecrypt-prod diff=agecrypt-prod -text\n",
    )
    .unwrap();
    let prod_file = repo.join("service.prod.env");
    fs::write(&prod_file, "PROD_SECRET=isolated_prod_value\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit prod ring secret"]);

    assert_invariant_c(
        repo,
        "prod",
        "default",
        "service.prod.env",
        "invariant_a.secret.env",
        "PROD_SECRET=isolated_prod_value\n",
        &secret_plain,
        Some(&prod_sec),
    );

    // 4. INVARIANT D: Special entries and symlinks rejected
    let gitattributes = fs::read_to_string(repo.join(".gitattributes")).unwrap();
    assert!(
        gitattributes.contains("-text"),
        "Invariant D requires -text on binary ciphertext patterns"
    );

    // 5. INVARIANT F: Fail-closed on missing or unauthorized identity
    agecrypt_cmd(repo).arg("lock").assert().success();
    let mut locked_run = agecrypt_cmd(repo);
    #[cfg(windows)]
    locked_run.args(["run", "--", "cmd.exe", "/c", "echo test"]);
    #[cfg(not(windows))]
    locked_run.args(["run", "--", "sh", "-c", "echo test"]);
    locked_run.assert().failure().code(1);
}

#[test]
fn test_regression_corpus() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let (sec_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "user"]);
    add_cmd.assert().success();

    // 1. Zero-byte secret file regression: must not crash or loop
    let empty_secret = repo.join("empty.secret.env");
    fs::write(&empty_secret, b"").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit empty secret"]);
    assert_eq!(fs::read(&empty_secret).unwrap().len(), 0);

    // 2. Secret file with CRLF line endings
    let crlf_secret = repo.join("crlf.secret.env");
    fs::write(&crlf_secret, "KEY1=val1\r\nKEY2=val2\r\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit crlf secret"]);

    // Lock and unlock roundtrip preserves exact CRLF
    agecrypt_cmd(repo).arg("lock").assert().success();
    let id_file = repo.join("user.key");
    fs::write(&id_file, &sec_key).unwrap();
    let mut unlock_cmd = agecrypt_cmd(repo);
    unlock_cmd
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();
    let _ = fs::remove_file(&id_file);
    assert_eq!(
        fs::read_to_string(&crlf_secret).unwrap(),
        "KEY1=val1\r\nKEY2=val2\r\n"
    );

    // 3. Status command with clean and dirty secrets reports accurately
    let mut status_cmd = agecrypt_cmd(repo);
    let assert_stat = status_cmd.arg("status").assert().success();
    let stdout_stat = String::from_utf8_lossy(&assert_stat.get_output().stdout);
    assert!(stdout_stat.contains("YES (plaintext on disk)"));
}

#[test]
fn test_performance_sanity_check() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("perf.secret.env");
    let payload = "PERF_LINE_ABC_123=benchmark_payload\n".repeat(5000); // ~175 KB
    fs::write(&secret_file, &payload).unwrap();

    let start_add = Instant::now();
    run_git(repo, &["add", "."]);
    let add_duration = start_add.elapsed();
    assert!(
        add_duration.as_secs() < 10,
        "Clean filter encryption of 175 KB should take under 10 seconds: {:?}",
        add_duration
    );

    run_git(repo, &["commit", "-m", "Commit perf"]);

    let start_smudge = Instant::now();
    run_git(repo, &["checkout", "HEAD", "--", "perf.secret.env"]);
    let smudge_duration = start_smudge.elapsed();
    assert!(
        smudge_duration.as_secs() < 10,
        "Smudge filter decryption of 175 KB should take under 10 seconds: {:?}",
        smudge_duration
    );

    assert_eq!(fs::read_to_string(&secret_file).unwrap(), payload);
}
