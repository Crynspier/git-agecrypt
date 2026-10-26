mod common;

use common::{agecrypt_cmd, assert_invariant_a, generate_test_identity, init_repo, run_git};
use git_agecrypt::format::{
    FORMAT_VERSION, parse_and_validate_lock_journal, parse_and_validate_repo_pub,
    parse_format_file_content, standalone_recover_secret_bytes, validate_wrapped_key_envelope,
};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use tempfile::TempDir;

/// B.3(1) & G.3: Golden Format Version 1 fixture validation and clean-room recovery
/// using ONLY standard `age` primitives without any `.git/git-agecrypt` state.
#[test]
fn test_golden_v1_fixture_and_clean_room_recovery() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    let fmt_content = fs::read_to_string(fixture_dir.join("format")).unwrap();
    assert_eq!(
        parse_format_file_content(&fmt_content).unwrap(),
        FORMAT_VERSION
    );

    let repo_pub_content = fs::read_to_string(fixture_dir.join("repo.pub")).unwrap();
    let (pub_key, ver) = parse_and_validate_repo_pub(&repo_pub_content).unwrap();
    assert!(pub_key.starts_with("age1"));
    assert_eq!(ver, Some(1));

    let envelope_content = fs::read_to_string(fixture_dir.join("recipient_x25519.age")).unwrap();
    let (rec_pub, rec_ver) = validate_wrapped_key_envelope(&envelope_content).unwrap();
    assert!(rec_pub.starts_with("age1"));
    assert_eq!(rec_ver, Some(1));

    let user_id_bytes = fs::read(fixture_dir.join("identity.txt")).unwrap();
    let secret_ciphertext = fs::read(fixture_dir.join("secret.env.age")).unwrap();

    // Clean-room recovery using only standard `age` primitives:
    let recovered =
        standalone_recover_secret_bytes(&envelope_content, &user_id_bytes, &secret_ciphertext)
            .expect("Clean-room recovery of golden v1 fixture must succeed");

    assert_eq!(
        String::from_utf8(recovered).unwrap(),
        "GOLDEN_V1_SECRET=stable_format_v1_verified\n"
    );
}

/// External `age` CLI interoperability and clean-room disaster recovery:
/// When the external `age` binary is installed (enforced in CI via `GIT_AGECRYPT_REQUIRE_AGE_CLI=1`),
/// verifies that an operator can recover repository secrets and exported `.age` files using ONLY
/// standard `git` + external `age -d` CLI without invoking `git-agecrypt` for decryption.
#[test]
fn test_external_age_cli_clean_room_interoperability() {
    let require_age_cli = std::env::var("GIT_AGECRYPT_REQUIRE_AGE_CLI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let age_version = Command::new("age").arg("--version").output();
    let age_available = matches!(age_version, Ok(ref out) if out.status.success());
    if !age_available {
        assert!(
            !require_age_cli,
            "GIT_AGECRYPT_REQUIRE_AGE_CLI=1 is set, but external 'age' CLI binary was not found on PATH"
        );
        return;
    }

    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (alice_sec, alice_pub) = generate_test_identity();
    let (auditor_sec, auditor_pub) = generate_test_identity();
    let alice_key_file = repo.join("alice_identity.txt");
    let auditor_key_file = repo.join("auditor_identity.txt");
    fs::write(&alice_key_file, format!("{alice_sec}\n")).unwrap();
    fs::write(&auditor_key_file, format!("{auditor_sec}\n")).unwrap();

    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &alice_pub, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );

    fs::create_dir_all(repo.join("secrets")).unwrap();
    let expected_secret = "CLEAN_ROOM_AGE_CLI_SECRET=verified_with_external_age_binary_42\n";
    fs::write(repo.join("secrets/prod.secret.env"), expected_secret).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "secrets/prod.secret.env",
        ],
    );
    run_git(
        repo,
        &["commit", "-m", "Add secret for external age CLI test"],
    );

    // Step 1: Unwrap `.git-agecrypt/keys/alice.age` using the external `age -d` binary
    let unwrap_out = Command::new("age")
        .args([
            "-d",
            "-i",
            alice_key_file.to_str().unwrap(),
            repo.join(".git-agecrypt/keys/alice.age").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute external age CLI");
    assert!(
        unwrap_out.status.success(),
        "External `age -d` failed to unwrap .git-agecrypt/keys/alice.age: {}",
        String::from_utf8_lossy(&unwrap_out.stderr)
    );
    let recovered_master_key = String::from_utf8(unwrap_out.stdout).unwrap();
    assert!(
        recovered_master_key.trim().starts_with("AGE-SECRET-KEY-1"),
        "Unwrapped master key must be a standard AGE-SECRET-KEY-1 identity"
    );
    let master_key_file = repo.join("recovered_master.key");
    fs::write(
        &master_key_file,
        format!("{}\n", recovered_master_key.trim()),
    )
    .unwrap();

    // Step 2: Extract raw ciphertext blob from Git (`git cat-file blob HEAD:secrets/prod.secret.env`)
    // and decrypt it with external `age -d -i recovered_master.key`
    let raw_blob_path = repo.join("raw_blob.age");
    let raw_blob = common::git_out(repo, &["cat-file", "blob", "HEAD:secrets/prod.secret.env"]);
    fs::write(&raw_blob_path, &raw_blob).unwrap();

    let decrypt_blob_out = Command::new("age")
        .args([
            "-d",
            "-i",
            master_key_file.to_str().unwrap(),
            raw_blob_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute external age CLI on blob");
    assert!(
        decrypt_blob_out.status.success(),
        "External `age -d` failed to decrypt Git ciphertext blob: {}",
        String::from_utf8_lossy(&decrypt_blob_out.stderr)
    );
    assert_eq!(
        String::from_utf8(decrypt_blob_out.stdout).unwrap(),
        expected_secret
    );

    // Step 3: Export secret with `git-agecrypt export-age` and decrypt with external `age -d`
    let exported_age_path = repo.join("exported_for_auditor.age");
    assert!(
        agecrypt_cmd(repo)
            .args([
                "export-age",
                "secrets/prod.secret.env",
                "--recipient",
                &auditor_pub,
                "--output",
                exported_age_path.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );

    let decrypt_export_out = Command::new("age")
        .args([
            "-d",
            "-i",
            auditor_key_file.to_str().unwrap(),
            exported_age_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute external age CLI on exported file");
    assert!(
        decrypt_export_out.status.success(),
        "External `age -d` failed to decrypt export-age output: {}",
        String::from_utf8_lossy(&decrypt_export_out.stderr)
    );
    assert_eq!(
        String::from_utf8(decrypt_export_out.stdout).unwrap(),
        expected_secret
    );
}

/// B.3(2)-(8): Fail-closed behavior on unsupported format versions, malformed `repo.pub`,
/// corrupted `keys/*.age` envelopes, and corrupted `lock.journal`.
#[test]
fn test_fail_closed_on_unsupported_format_and_corrupted_metadata() {
    // 1. Format version parser rejects unknown versions and non-numeric strings
    assert!(parse_format_file_content("1\n").is_ok());
    assert!(parse_format_file_content("# comment\nformat-version: 1\n").is_ok());
    assert!(
        parse_format_file_content("2\n")
            .unwrap_err()
            .to_string()
            .contains("Unsupported git-agecrypt repository format version 2")
    );
    assert!(
        parse_format_file_content("99\n")
            .unwrap_err()
            .to_string()
            .contains("Unsupported git-agecrypt repository format version 99")
    );
    assert!(parse_format_file_content("v2\n").is_err());
    assert!(parse_format_file_content("").is_err());

    // 2. repo.pub parser rejects empty, multiple recipients, non-age1 keys, or future format-version header
    assert!(parse_and_validate_repo_pub("").is_err());
    assert!(parse_and_validate_repo_pub("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test").is_err());
    assert!(
        parse_and_validate_repo_pub(
            "# format-version: 2\nage1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"
        )
        .unwrap_err()
        .to_string()
        .contains("Unsupported repo.pub format version 2")
    );

    // 3. Recipient envelope validator rejects missing # public-key:, truncated armor, or unknown header fields
    assert!(
        validate_wrapped_key_envelope(
            "-----BEGIN AGE ENCRYPTED FILE-----\nabc\n-----END AGE ENCRYPTED FILE-----\n"
        )
        .is_err()
    );
    assert!(
        validate_wrapped_key_envelope(
            "# public-key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n# format-version: 2\n-----BEGIN AGE ENCRYPTED FILE-----\nabc\n-----END AGE ENCRYPTED FILE-----\n"
        )
        .unwrap_err()
        .to_string()
        .contains("Unsupported recipient envelope format version 2")
    );

    // 4. lock.journal validator rejects missing tab, empty fields, NUL bytes, or unsupported format-version
    assert!(parse_and_validate_lock_journal("/wt\tsecrets/a.env\n").is_ok());
    assert!(parse_and_validate_lock_journal("# format-version: 1\n/wt\tsecrets/a.env\n").is_ok());
    assert!(parse_and_validate_lock_journal("no_tab_separator\n").is_err());
    assert!(parse_and_validate_lock_journal("/wt\t\n").is_err());
    assert!(parse_and_validate_lock_journal("/wt\tsecrets/a\0b.env\n").is_err());
    assert!(
        parse_and_validate_lock_journal("# format-version: 3\n/wt\tsecrets/a.env\n")
            .unwrap_err()
            .to_string()
            .contains("Unsupported lock.journal format version 3")
    );

    // 5. End-to-end repository fail-closed check when .git-agecrypt/format is version 2
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);
    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());

    fs::write(repo.join(".git-agecrypt/format"), "2\n").unwrap();

    for cmd_args in [
        &["status"][..],
        &["lock"][..],
        &["rekey"][..],
        &["list-recipients"][..],
        &["inspect"][..],
    ] {
        let out = agecrypt_cmd(repo).args(cmd_args).output().unwrap();
        assert!(
            !out.status.success(),
            "Command {:?} must fail closed when .git-agecrypt/format is 2",
            cmd_args
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("Unsupported") && combined.contains("format version"),
            "Expected unsupported format diagnostic on {:?}, got: {}",
            cmd_args,
            combined
        );
    }
}

/// B.4 & B.5: `git-agecrypt inspect` (text and JSON) and `git-agecrypt export-age`
/// interoperability with standard `age` decryption.
#[test]
fn test_inspect_and_export_age_interoperability() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();
    init_repo(repo);

    let (alice_sec, alice_pub) = generate_test_identity();
    let (auditor_sec, auditor_pub) = generate_test_identity();
    let alice_key_file = repo.join("alice.key");
    fs::write(&alice_key_file, &alice_sec).unwrap();

    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &alice_pub, "-n", "alice"])
            .status()
            .unwrap()
            .success()
    );

    fs::create_dir_all(repo.join("secrets")).unwrap();
    let secret_path = repo.join("secrets/service.secret.env");
    let secret_content = "API_TOKEN=age_export_interop_secret_98765\n";
    fs::write(&secret_path, secret_content).unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "secrets/service.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Add service secret"]);
    assert_invariant_a(repo, "secrets/service.secret.env", secret_content);

    // 1. Run `git-agecrypt inspect --format text` and `--format json`
    let text_out = agecrypt_cmd(repo)
        .args(["inspect", "--format", "text"])
        .output()
        .unwrap();
    assert!(text_out.status.success());
    let text_str = String::from_utf8_lossy(&text_out.stdout);
    assert!(text_str.contains("Format version:    1 (source: implicit-v1, supported: true)"));
    assert!(text_str.contains("alice [x25519]"));
    assert!(text_str.contains("secrets/service.secret.env: worktree=plaintext, index=ciphertext"));

    let json_out = agecrypt_cmd(repo)
        .args(["inspect", "--format", "json"])
        .output()
        .unwrap();
    assert!(json_out.status.success());
    let json_str = String::from_utf8_lossy(&json_out.stdout);
    assert!(json_str.contains("\"format_version\": 1"));
    assert!(json_str.contains("\"supported\": true"));
    assert!(json_str.contains("\"status\": \"clean\""));
    assert!(json_str.contains("\"worktree_state\": \"plaintext\""));
    assert!(json_str.contains("\"index_state\": \"ciphertext\""));

    // 2. Export while unlocked using `git-agecrypt export-age`
    let exported_unlocked = repo.join("exported_unlocked.age");
    let exp_out = agecrypt_cmd(repo)
        .args([
            "export-age",
            "secrets/service.secret.env",
            "--recipient",
            &auditor_pub,
            "--output",
            exported_unlocked.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        exp_out.status.success(),
        "export-age failed: {}",
        String::from_utf8_lossy(&exp_out.stderr)
    );
    assert!(
        exp_out.stdout.is_empty(),
        "export-age must NEVER print plaintext or key material to stdout"
    );

    // Refuses to overwrite existing file without --yes
    let exp_overwrite_fail = agecrypt_cmd(repo)
        .args([
            "export-age",
            "secrets/service.secret.env",
            "--recipient",
            &auditor_pub,
            "--output",
            exported_unlocked.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!exp_overwrite_fail.status.success());

    // 3. Lock the repository and export while locked using `--identity` and `--yes`
    assert!(agecrypt_cmd(repo).arg("lock").status().unwrap().success());
    let exp_locked_out = agecrypt_cmd(repo)
        .args([
            "export-age",
            "secrets/service.secret.env",
            "--recipient",
            &auditor_pub,
            "--output",
            exported_unlocked.to_str().unwrap(),
            "--identity",
            alice_key_file.to_str().unwrap(),
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(
        exp_locked_out.status.success(),
        "export-age from locked repo failed: {}",
        String::from_utf8_lossy(&exp_locked_out.stderr)
    );
    assert!(exp_locked_out.stdout.is_empty());

    // 4. Decrypt the exported .age file using standard upstream `age` crate directly
    let exported_bytes = fs::read(&exported_unlocked).unwrap();
    let auditor_id = age::x25519::Identity::from_str(&auditor_sec).unwrap();
    let decryptor = age::Decryptor::new(&exported_bytes[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&auditor_id as &dyn age::Identity))
        .unwrap();
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted).unwrap();
    assert_eq!(decrypted, secret_content);
}

/// G.1 & G.2: Historical migration and upgrade fixture test (simulating an implicit-v1
/// repository created prior to v0.6.0 with multiple rings, key rotation, and historical
/// branches, then upgrading to v0.6.0 and restoring secrets from a fresh clone).
#[test]
fn test_upgrade_and_migration_across_implicit_v1_and_rekey_history() {
    let temp = TempDir::new().unwrap();
    let origin = temp.path().join("origin");
    fs::create_dir_all(&origin).unwrap();
    let repo = origin.as_path();
    init_repo(repo);

    let (alice_sec, alice_pub) = generate_test_identity();
    let (bob_sec, bob_pub) = generate_test_identity();
    let alice_key = temp.path().join("alice.txt");
    let bob_key = temp.path().join("bob.txt");
    fs::write(&alice_key, &alice_sec).unwrap();
    fs::write(&bob_key, &bob_sec).unwrap();

    // Initialize default and 'prod' rings (implicit v1: no .git-agecrypt/format file)
    assert!(agecrypt_cmd(repo).arg("init").status().unwrap().success());
    assert!(
        agecrypt_cmd(repo)
            .args(["init", "--ring", "prod"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!repo.join(".git-agecrypt/format").exists());

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
                "alice",
            ])
            .status()
            .unwrap()
            .success()
    );

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\nsecrets/prod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("secrets/prod")).unwrap();
    fs::write(repo.join("app.secret.env"), "V1_VAL=initial\n").unwrap();
    fs::write(repo.join("secrets/prod/db.env"), "PROD_DB=initial_prod\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "app.secret.env",
            "secrets/prod/db.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial v1 secrets"]);

    // Offboard bob and rotate default ring master key
    assert!(
        agecrypt_cmd(repo)
            .args(["remove-recipient", "bob"])
            .status()
            .unwrap()
            .success()
    );
    assert!(agecrypt_cmd(repo).arg("rekey").status().unwrap().success());
    run_git(repo, &["add", ".git-agecrypt", "app.secret.env"]);
    run_git(
        repo,
        &["commit", "-m", "Rotate master key after offboarding bob"],
    );

    // Write explicit v1 format marker (.git-agecrypt/format = 1) and verify full compatibility
    fs::write(repo.join(".git-agecrypt/format"), "1\n").unwrap();
    run_git(repo, &["add", ".git-agecrypt/format"]);
    run_git(repo, &["commit", "-m", "Add explicit v1 format file"]);

    let inspect_out = agecrypt_cmd(repo)
        .args(["inspect", "--format", "json"])
        .output()
        .unwrap();
    assert!(inspect_out.status.success());
    let inspect_json = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(inspect_json.contains("\"format_source\": \"explicit-file\""));
    assert!(inspect_json.contains("\"supported\": true"));

    // Verify fresh-clone restoration for authorized recipient (Alice) vs revoked recipient (Bob)
    let fresh_clone = temp.path().join("fresh_clone");
    run_git(
        temp.path(),
        &[
            "clone",
            origin.to_str().unwrap(),
            fresh_clone.to_str().unwrap(),
        ],
    );
    // In a fresh clone before init/unlock, files on disk are raw age ciphertexts
    assert!(
        fs::read(fresh_clone.join("app.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    assert!(
        fs::read(fresh_clone.join("secrets/prod/db.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );

    // Configure git filters in the fresh clone (`init`)
    assert!(
        agecrypt_cmd(&fresh_clone)
            .arg("init")
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(&fresh_clone)
            .args(["init", "--ring", "prod"])
            .status()
            .unwrap()
            .success()
    );

    // Revoked recipient Bob CANNOT unlock the rotated repository in the fresh clone
    assert!(
        !agecrypt_cmd(&fresh_clone)
            .args(["unlock", bob_key.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    // Authorized recipient Alice unlocks both default and 'prod' rings in the fresh clone and restores all secrets
    assert!(
        agecrypt_cmd(&fresh_clone)
            .args(["unlock", alice_key.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        agecrypt_cmd(&fresh_clone)
            .args(["unlock", "--ring", "prod", alice_key.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    assert_eq!(
        fs::read_to_string(fresh_clone.join("app.secret.env")).unwrap(),
        "V1_VAL=initial\n"
    );
    assert_eq!(
        fs::read_to_string(fresh_clone.join("secrets/prod/db.env")).unwrap(),
        "PROD_DB=initial_prod\n"
    );
}
