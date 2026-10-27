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

fn run_pre_push_stdin(repo: &std::path::Path, stdin_lines: &str) -> std::process::Output {
    let mut cmd = agecrypt_cmd(repo);
    cmd.args(["check", "--pre-push"]);
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
    run_git(&client, &["push", "--no-verify", "origin", "main"]);

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

/// Encryption boundary & historical key rejection across unusual staging (`git update-index --cacheinfo`),
/// unprotected secret renames, merge commits, rebases, nested `.gitattributes`, and multi-ring rotation.
#[test]
fn test_encryption_boundary_and_historical_key_rejection_matrix() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (alice_sec, alice_pub) = generate_test_identity();
    let (bob_sec, bob_pub) = generate_test_identity();
    let alice_key = repo.join("alice.key");
    fs::write(&alice_key, &alice_sec).unwrap();
    let _ = bob_sec;

    // Initialize default ring and 'prod' ring
    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["init", "--ring", "prod"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &alice_pub, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &bob_pub, "-n", "bob"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(repo)
            .args([
                "add-recipient",
                "--ring",
                "prod",
                "-i",
                &alice_pub,
                "-n",
                "alice"
            ])
            .status()
            .unwrap()
            .success()
    );

    // Root .gitattributes + nested services/billing/.gitattributes
    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\nsecrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text\nprod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("services/billing")).unwrap();
    fs::write(
        repo.join("services/billing/.gitattributes"),
        "*.billing.key filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    fs::create_dir_all(repo.join("secrets")).unwrap();
    fs::create_dir_all(repo.join("prod")).unwrap();
    fs::write(repo.join("secrets/main.env"), "MAIN_SECRET=v1\n").unwrap();
    fs::write(repo.join("prod/api.env"), "PROD_SECRET=v1\n").unwrap();
    fs::write(
        repo.join("services/billing/stripe.billing.key"),
        "STRIPE_KEY=v1\n",
    )
    .unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            "services/billing/.gitattributes",
            ".git-agecrypt",
            "secrets/main.env",
            "prod/api.env",
            "services/billing/stripe.billing.key",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial multi-ring commit"]);
    let v1_commit = rev_parse_head(repo);

    // Save v1 ciphertext blobs for historical replay tests
    let old_default_blob = git_out(repo, &["cat-file", "blob", "HEAD:secrets/main.env"]);
    let old_prod_blob = git_out(repo, &["cat-file", "blob", "HEAD:prod/api.env"]);

    // 1. Unusual plumbing staging (`git hash-object -w` + `git update-index --cacheinfo` bypassing clean filter)
    let mut hash_cmd = std::process::Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash_cmd
        .stdin
        .take()
        .unwrap()
        .write_all(b"BYPASSED_FILTER_PLAINTEXT=leaked\n")
        .unwrap();
    let plain_oid = String::from_utf8_lossy(&hash_cmd.wait_with_output().unwrap().stdout)
        .trim()
        .to_string();

    run_git(
        repo,
        &[
            "update-index",
            "--cacheinfo",
            &format!("100644,{plain_oid},secrets/main.env"),
        ],
    );
    let check_plumbing = agecrypt_cmd(repo).arg("check").output().unwrap();
    assert!(
        !check_plumbing.status.success(),
        "check must reject plaintext blob injected directly into index via update-index --cacheinfo"
    );
    run_git(repo, &["reset", "--hard", "HEAD"]);

    // 2. Unprotected secret rename (`git mv secrets/main.env public_notes.txt`)
    run_git(repo, &["mv", "secrets/main.env", "public_notes.txt"]);
    let check_rename = agecrypt_cmd(repo).arg("check").output().unwrap();
    assert!(
        !check_rename.status.success(),
        "check must reject renaming a tracked secret to an unprotected path"
    );
    assert!(
        String::from_utf8_lossy(&check_rename.stderr)
            .contains("SECRET RENAMED TO UNENCRYPTED DESTINATION")
    );
    run_git(repo, &["reset", "--hard", "HEAD"]);

    // 3. Rotate BOTH default ring and 'prod' ring master keys (revoking Bob on default ring)
    assert!(
        agecrypt_cmd(repo)
            .args(["remove-recipient", "bob"])
            .status()
            .unwrap()
            .success()
    );
    assert!(agecrypt_cmd(repo).arg("rekey").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["rekey", "--ring", "prod"])
            .status()
            .unwrap()
            .success()
    );
    run_git(
        repo,
        &[
            "add",
            ".git-agecrypt",
            "secrets/main.env",
            "prod/api.env",
            "services/billing/stripe.billing.key",
        ],
    );
    run_git(repo, &["commit", "-m", "Rotate default and prod keys"]);
    let v2_commit = rev_parse_head(repo);

    // 4. Historical key rejection on default ring AND named 'prod' ring:
    // Inject pre-rotation v1 ciphertext into index for `prod/api.env`
    let mut hash_old_prod = std::process::Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash_old_prod
        .stdin
        .take()
        .unwrap()
        .write_all(&old_prod_blob)
        .unwrap();
    let old_prod_oid = String::from_utf8_lossy(&hash_old_prod.wait_with_output().unwrap().stdout)
        .trim()
        .to_string();

    run_git(
        repo,
        &[
            "update-index",
            "--cacheinfo",
            &format!("100644,{old_prod_oid},prod/api.env"),
        ],
    );
    let check_old_prod = agecrypt_cmd(repo).arg("check").output().unwrap();
    assert!(
        !check_old_prod.status.success(),
        "check must reject staged blob encrypted under historical/revoked 'prod' ring key"
    );
    assert!(
        String::from_utf8_lossy(&check_old_prod.stderr)
            .contains("STAGED SECRET ENCRYPTED WITH REVOKED/FOREIGN KEY")
    );
    run_git(repo, &["reset", "--hard", "HEAD"]);

    // 5. Commit historical default-ring ciphertext with --no-verify (simulating a bad cherry-pick/merge/rebase)
    // and verify that BOTH `check --pre-push` AND `check --commit-range` reject it!
    let mut hash_old_def = std::process::Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash_old_def
        .stdin
        .take()
        .unwrap()
        .write_all(&old_default_blob)
        .unwrap();
    let old_def_oid = String::from_utf8_lossy(&hash_old_def.wait_with_output().unwrap().stdout)
        .trim()
        .to_string();

    run_git(
        repo,
        &[
            "update-index",
            "--cacheinfo",
            &format!("100644,{old_def_oid},secrets/main.env"),
        ],
    );
    run_git(
        repo,
        &[
            "commit",
            "--no-verify",
            "-m",
            "Reintroduce revoked v1 ciphertext",
        ],
    );
    let bad_hist_commit = rev_parse_head(repo);

    // 5a. `check --pre-push` rejects pushing tip containing historical key ciphertext
    let pre_push_out = run_pre_push_stdin(
        repo,
        &format!("refs/heads/main {bad_hist_commit} refs/heads/main {v2_commit}\n"),
    );
    assert!(
        !pre_push_out.status.success(),
        "check --pre-push must reject tip commit containing historical/revoked key ciphertext"
    );
    assert!(
        String::from_utf8_lossy(&pre_push_out.stderr)
            .contains("SECRET ENCRYPTED WITH REVOKED/HISTORICAL KEY")
    );

    // 5b. `check --commit-range` rejects tip commit containing historical key ciphertext when unlocked
    let range_hist_out = agecrypt_cmd(repo)
        .args([
            "check",
            "--commit-range",
            &format!("{v2_commit}..{bad_hist_commit}"),
        ])
        .output()
        .unwrap();
    assert!(
        !range_hist_out.status.success(),
        "check --commit-range must reject historical/revoked key ciphertext in tip tree"
    );
    assert!(
        String::from_utf8_lossy(&range_hist_out.stderr)
            .contains("encrypted under a historical or foreign key")
    );

    // 6. Nested `.gitattributes` enforcement in `--commit-range` and `--pre-receive`
    run_git(repo, &["reset", "--hard", &v2_commit]);
    run_git(
        repo,
        &["config", "--local", "filter.agecrypt.required", "false"],
    );
    run_git(repo, &["config", "--unset", "filter.agecrypt.clean"]);
    fs::write(
        repo.join("services/billing/stripe.billing.key"),
        "PLAINTEXT_NESTED_ATTR_LEAK=1\n",
    )
    .unwrap();
    run_git(repo, &["add", "services/billing/stripe.billing.key"]);
    run_git(
        repo,
        &[
            "commit",
            "--no-verify",
            "-m",
            "Leak in nested .gitattributes path",
        ],
    );
    let nested_leak_commit = rev_parse_head(repo);

    let nested_pre_receive = run_pre_receive_stdin(
        repo,
        &format!("{v2_commit} {nested_leak_commit} refs/heads/main\n"),
        &[],
    );
    assert!(
        !nested_pre_receive.status.success(),
        "pre-receive must enforce rules defined in nested subdirectory .gitattributes"
    );
    assert!(
        String::from_utf8_lossy(&nested_pre_receive.stderr)
            .contains("services/billing/stripe.billing.key")
    );
    let _ = v1_commit;
}

#[test]
fn test_server_pre_receive_rejects_intermediate_commit_leak() {
    let temp = TempDir::new().unwrap();
    let client = temp.path().join("client");
    let server = temp.path().join("server.git");
    fs::create_dir_all(&client).unwrap();
    fs::create_dir_all(&server).unwrap();

    run_git(&server, &["init", "--bare"]);
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
        "DB_PASS=initial_encrypted_secret\n",
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
    run_git(&client, &["commit", "-m", "Commit 1 (clean)"]);
    let commit1 = rev_parse_head(&client);

    // Commit 2 (intermediate): inject a plaintext leak into secrets/db.secret.env
    let mut hash_plain = std::process::Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(&client)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash_plain
        .stdin
        .take()
        .unwrap()
        .write_all(b"PLAINTEXT_LEAKED_INTERMEDIATE_SECRET=compromised\n")
        .unwrap();
    let plain_oid = String::from_utf8_lossy(&hash_plain.wait_with_output().unwrap().stdout)
        .trim()
        .to_string();

    run_git(
        &client,
        &[
            "update-index",
            "--cacheinfo",
            &format!("100644,{plain_oid},secrets/db.secret.env"),
        ],
    );
    run_git(
        &client,
        &[
            "commit",
            "--no-verify",
            "-m",
            "Commit 2 (intermediate leak)",
        ],
    );
    let commit2 = rev_parse_head(&client);

    // Commit 3 (tip): delete or re-encrypt the file so tip tree looks clean
    run_git(&client, &["rm", "-f", "secrets/db.secret.env"]);
    run_git(&client, &["commit", "-m", "Commit 3 (tip cleaned)"]);
    let commit3 = rev_parse_head(&client);

    // Push all commits to bare server
    run_git(
        &client,
        &["remote", "add", "origin", server.to_str().unwrap()],
    );
    run_git(&client, &["push", "--no-verify", "origin", "main"]);

    // Test check --pre-receive on the range commit1..commit3
    let out = run_pre_receive_stdin(
        &server,
        &format!("{commit1} {commit3} refs/heads/main\n"),
        &[],
    );

    // Must reject because intermediate commit2 contained plaintext leak
    assert!(
        !out.status.success(),
        "pre-receive must reject push when intermediate commit contains plaintext secret"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Plaintext secret committed") || stderr.contains(&commit2),
        "stderr must identify leak in commit2: {stderr}"
    );
}

#[test]
fn test_gitattributes_escaped_whitespace_and_directory_boundary() {
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

    // Attributes with escaped space and recursive wildcard prefix
    fs::write(
        repo.join(".gitattributes"),
        "secret\\ file.env filter=agecrypt diff=agecrypt merge=agecrypt -text\nconfig/prod/** filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    fs::create_dir_all(repo.join("config/prod")).unwrap();
    fs::create_dir_all(repo.join("config/production")).unwrap();

    // 1. config/production/notes.txt is NOT in config/prod/** -> should not be flagged as unencrypted protected secret
    fs::write(
        repo.join("config/production/notes.txt"),
        "Public documentation notes\n",
    )
    .unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "config/production/notes.txt",
        ],
    );
    let check_prod_sibling = agecrypt_cmd(repo).arg("check").output().unwrap();
    assert!(
        check_prod_sibling.status.success(),
        "config/production should not match config/prod/**: {}",
        String::from_utf8_lossy(&check_prod_sibling.stderr)
    );

    // 2. secret file.env has escaped space in .gitattributes -> must be recognized as protected!
    let mut hash_plain = std::process::Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash_plain
        .stdin
        .take()
        .unwrap()
        .write_all(b"UNENCRYPTED_ESCAPED_SPACE_SECRET=1\n")
        .unwrap();
    let plain_oid = String::from_utf8_lossy(&hash_plain.wait_with_output().unwrap().stdout)
        .trim()
        .to_string();

    run_git(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("100644,{plain_oid},secret file.env"),
        ],
    );

    let check_escaped = agecrypt_cmd(repo).arg("check").output().unwrap();
    assert!(
        !check_escaped.status.success(),
        "check must reject unencrypted secret in path with escaped space"
    );
    let stderr = String::from_utf8_lossy(&check_escaped.stderr);
    assert!(
        stderr.contains("secret file.env"),
        "stderr must mention secret file.env: {stderr}"
    );
}
