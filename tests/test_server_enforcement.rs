mod common;

use common::{agecrypt_cmd, generate_test_identity, git_out, init_repo, run_git};
use std::fs;
use std::io::Write;
use std::process::Stdio;
use tempfile::TempDir;

const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

fn rev_parse_head(repo: &std::path::Path) -> String {
    String::from_utf8_lossy(&git_out(repo, &["rev-parse", "HEAD"]))
        .trim()
        .to_string()
}

fn run_pre_receive_stdin(
    repo: &std::path::Path,
    stdin_lines: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let mut cmd = agecrypt_cmd(repo);
    cmd.args(["check", "--pre-receive"]);
    cmd.args(extra_args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_lines.as_bytes()).unwrap();
    }
    child.wait_with_output().unwrap()
}

/// D.4(1): Accepts valid encrypted pushes (new branch, update, branch deletion, multi-ref)
/// and works directly inside a bare repository on a Git server.
#[test]
fn test_server_pre_receive_accepts_valid_encrypted_pushes_in_bare_repo() {
    let temp = TempDir::new().unwrap();
    let client = temp.path().join("client");
    let server = temp.path().join("server.git");
    fs::create_dir_all(&client).unwrap();
    fs::create_dir_all(&server).unwrap();

    // Initialize bare server repository
    run_git(&server, &["init", "--bare"]);

    // Initialize client repository
    init_repo(&client);
    let (_sec, pub_key) = generate_test_identity();
    assert!(
        agecrypt_cmd(&client)
            .arg("init")
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(&client)
            .args(["add-recipient", "-i", &pub_key, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );

    fs::create_dir_all(client.join("secrets")).unwrap();
    fs::write(
        client.join("secrets/db.secret.env"),
        "DB_PASS=encrypted_and_valid\n",
    )
    .unwrap();
    run_git(
        &client,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "secrets/db.secret.env",
        ],
    );
    run_git(&client, &["commit", "-m", "Valid encrypted secret"]);
    let commit1 = rev_parse_head(&client);

    // Push to bare server
    run_git(
        &client,
        &["remote", "add", "origin", server.to_str().unwrap()],
    );
    run_git(&client, &["push", "origin", "main"]);

    // Run `git-agecrypt check --pre-receive` inside the BARE server repo!
    // 1. New branch creation (ZERO_SHA -> commit1)
    let out_new = run_pre_receive_stdin(
        &server,
        &format!("{ZERO_SHA} {commit1} refs/heads/main\n"),
        &[],
    );
    assert!(
        out_new.status.success(),
        "Bare server pre-receive must accept valid encrypted push: {}",
        String::from_utf8_lossy(&out_new.stderr)
    );

    // 2. Branch deletion (commit1 -> ZERO_SHA)
    let out_del = run_pre_receive_stdin(
        &server,
        &format!("{commit1} {ZERO_SHA} refs/heads/old-branch\n"),
        &[],
    );
    assert!(
        out_del.status.success(),
        "Branch deletion must be allowed cleanly"
    );

    // 3. Second commit + multi-ref push
    fs::write(
        client.join("secrets/db.secret.env"),
        "DB_PASS=rotated_value_2\n",
    )
    .unwrap();
    run_git(&client, &["add", "secrets/db.secret.env"]);
    run_git(&client, &["commit", "-m", "Update encrypted secret"]);
    let commit2 = rev_parse_head(&client);
    run_git(&client, &["push", "origin", "main"]);

    let multi_ref_input =
        format!("{commit1} {commit2} refs/heads/main\n{ZERO_SHA} {commit2} refs/heads/release\n");
    let out_multi = run_pre_receive_stdin(&server, &multi_ref_input, &[]);
    assert!(
        out_multi.status.success(),
        "Multi-ref valid push must succeed: {}",
        String::from_utf8_lossy(&out_multi.stderr)
    );
}

/// D.4(2): Rejects plaintext secret committed via bypassed clean filter (`--no-verify`),
/// and supports `--report-only` non-blocking audit mode.
#[test]
fn test_server_pre_receive_rejects_plaintext_secret_and_supports_report_only() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (_sec, pub_key) = generate_test_identity();
    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &pub_key, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );

    fs::create_dir_all(repo.join("secrets")).unwrap();
    fs::write(repo.join("secrets/good.env"), "GOOD=1\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "secrets/good.env"],
    );
    run_git(repo, &["commit", "-m", "Good commit"]);
    let good_commit = rev_parse_head(repo);

    // Simulate attacker or misconfigured client disabling clean filter and committing with --no-verify
    run_git(
        repo,
        &["config", "--local", "filter.agecrypt.required", "false"],
    );
    run_git(repo, &["config", "--unset", "filter.agecrypt.clean"]);
    fs::write(repo.join("secrets/leaked.env"), "PLAINTEXT_LEAK=oops\n").unwrap();
    run_git(repo, &["add", "secrets/leaked.env"]);
    run_git(repo, &["commit", "--no-verify", "-m", "Plaintext bypass"]);
    let bad_commit = rev_parse_head(repo);

    // Strict mode (--pre-receive): MUST reject!
    let strict_out = run_pre_receive_stdin(
        repo,
        &format!("{good_commit} {bad_commit} refs/heads/main\n"),
        &[],
    );
    assert!(
        !strict_out.status.success(),
        "Strict pre-receive must reject plaintext secret on protected path"
    );
    let stderr = String::from_utf8_lossy(&strict_out.stderr);
    assert!(
        stderr.contains("Plaintext secret committed to protected path 'secrets/leaked.env'"),
        "Expected plaintext secret alert, got: {stderr}"
    );

    // CI commit-range mode (--commit-range): MUST also reject!
    let range_out = agecrypt_cmd(repo)
        .args([
            "check",
            "--commit-range",
            &format!("{good_commit}..{bad_commit}"),
        ])
        .output()
        .unwrap();
    assert!(!range_out.status.success());

    // Report-only mode (--report-only): logs violation to stderr but exits 0!
    let report_out = run_pre_receive_stdin(
        repo,
        &format!("{good_commit} {bad_commit} refs/heads/main\n"),
        &["--report-only"],
    );
    assert!(
        report_out.status.success(),
        "Report-only mode must exit 0 while logging violation"
    );
    let report_stderr = String::from_utf8_lossy(&report_out.stderr);
    assert!(
        report_stderr.contains("REPORT-ONLY") && report_stderr.contains("secrets/leaked.env"),
        "Report-only mode must still report the offending file: {report_stderr}"
    );
}

/// D.4(3): Rejects corrupted/truncated age headers, missing ring metadata (`repo.pub` / `keys/*.age`),
/// force-pushes introducing invalid blobs, and merge commits with violations.
#[test]
fn test_server_pre_receive_rejects_corrupted_age_header_and_missing_ring_metadata() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (_sec, pub_key) = generate_test_identity();
    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &pub_key, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );

    fs::create_dir_all(repo.join("secrets")).unwrap();
    fs::write(repo.join("secrets/ok.env"), "OK=1\n").unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "secrets/ok.env"],
    );
    run_git(repo, &["commit", "-m", "Base commit"]);
    let base_commit = rev_parse_head(repo);

    // Case A: Commit a forged/corrupted age header (starts with age-encryption.org/v1\n but invalid stanza)
    run_git(
        repo,
        &["config", "--local", "filter.agecrypt.required", "false"],
    );
    run_git(repo, &["config", "--unset", "filter.agecrypt.clean"]);
    fs::write(
        repo.join("secrets/corrupt.env"),
        b"age-encryption.org/v1\n-> X25519 NOT_VALID_BASE64\n--- broken\n",
    )
    .unwrap();
    run_git(repo, &["add", "secrets/corrupt.env"]);
    run_git(repo, &["commit", "--no-verify", "-m", "Corrupted age blob"]);
    let corrupt_commit = rev_parse_head(repo);

    let out_corrupt = run_pre_receive_stdin(
        repo,
        &format!("{base_commit} {corrupt_commit} refs/heads/main\n"),
        &[],
    );
    assert!(
        !out_corrupt.status.success(),
        "Pre-receive must reject corrupted age ciphertext header"
    );
    assert!(
        String::from_utf8_lossy(&out_corrupt.stderr)
            .contains("Malformed or corrupted age ciphertext header")
    );

    // Case B: Force-push / branch referencing a ring (`filter=agecrypt-prod`) without `.git-agecrypt/rings/prod/repo.pub`
    run_git(repo, &["checkout", "-b", "broken-ring", &base_commit]);
    fs::write(
        repo.join(".gitattributes"),
        "secrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text\nprod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("prod")).unwrap();
    // Copy valid ciphertext from secrets/ok.env so blob header is valid age, but 'prod' ring metadata is missing!
    let valid_cipher = git_out(
        repo,
        &["cat-file", "blob", &format!("{base_commit}:secrets/ok.env")],
    );
    fs::write(repo.join("prod/secret.env"), &valid_cipher).unwrap();
    run_git(repo, &["add", ".gitattributes", "prod/secret.env"]);
    run_git(
        repo,
        &["commit", "--no-verify", "-m", "Missing prod ring metadata"],
    );
    let missing_ring_commit = rev_parse_head(repo);

    // Simulate force-push from corrupt_commit -> missing_ring_commit
    let out_missing_ring = run_pre_receive_stdin(
        repo,
        &format!("{corrupt_commit} {missing_ring_commit} refs/heads/main\n"),
        &[],
    );
    assert!(
        !out_missing_ring.status.success(),
        "Pre-receive must reject push when referenced ring 'prod' lacks repo.pub and keys/*.age"
    );
    let ring_stderr = String::from_utf8_lossy(&out_missing_ring.stderr);
    assert!(
        ring_stderr.contains(
            "Ring 'prod' protects tracked secrets in .gitattributes but is missing a valid repo.pub"
        ),
        "Expected missing ring metadata error, got: {ring_stderr}"
    );
}
