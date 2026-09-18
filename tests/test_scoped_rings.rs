mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_ring_name_validation_grammar() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // Initializing default ring
    let mut cmd = agecrypt_cmd(repo);
    cmd.arg("init").assert().success();

    // Valid ring names: alphanumeric, underscore, dot, hyphen, up to 64 chars
    let valid_rings = [
        "prod",
        "dev",
        "staging-01",
        "test.ring",
        "ring_2",
        "A",
        "a0123456789_.-Z",
    ];
    for ring in valid_rings {
        let mut c = agecrypt_cmd(repo);
        c.args(["init", "--ring", ring]).assert().success();
    }

    // Invalid ring names that MUST fail validation closed
    let invalid_rings = [
        "",                       // empty
        "default",                // reserved word (omitting flag designates default)
        ".",                      // dot traversal
        "..",                     // dot-dot traversal
        "../evil",                // path traversal
        "prod/secrets",           // slash
        "prod\\secrets",          // backslash
        "prod ring",              // space
        "prod;rm -rf /",          // shell command injection
        "prod'--",                // SQL / quote injection
        "prod\"test",             // double quote
        "-start-with-hyphen",     // starts with non-alphanumeric
        "_start-with-underscore", // starts with non-alphanumeric
        ".start-with-dot",        // starts with non-alphanumeric
        "CON",                    // Windows reserved device name
        "prn",                    // Windows reserved device name (case-insensitive)
        "AUX",                    // Windows reserved device name
        "nul",                    // Windows reserved device name
        "COM1",                   // Windows reserved serial port
        "LPT1",                   // Windows reserved parallel port
        "NUL.txt",                // Windows reserved with extension
        "this_ring_name_is_far_too_long_and_exceeds_sixty_four_characters_limit_by_far_exceeding_grammar", // > 64 chars
    ];

    for ring in invalid_rings {
        let mut c = agecrypt_cmd(repo);
        c.arg("init");
        c.arg(format!("--ring={ring}"));
        c.assert().failure();
    }
}

#[test]
fn test_scoped_rings_isolation_and_locking() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // 1. Initialize default, prod, and dev rings
    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["init", "--ring", "dev"])
        .assert()
        .success();

    // Enroll explicit test recipients for rings
    let (def_sec, def_pub) = generate_test_identity();
    let def_key_file = repo.join("def_user.key");
    fs::write(&def_key_file, &def_sec).unwrap();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &def_pub])
        .assert()
        .success();

    let (prod_sec, prod_pub) = generate_test_identity();
    let prod_key_file = repo.join("prod_user.key");
    fs::write(&prod_key_file, &prod_sec).unwrap();
    agecrypt_cmd(repo)
        .args(["add-recipient", "--ring", "prod", "-i", &prod_pub])
        .assert()
        .success();

    // 2. Configure .gitattributes with distinct rings
    let gitattrs = r#"# Ring-specific attribute mappings
default.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text
prod.secret.env filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text
dev.secret.env filter=agecrypt-dev diff=agecrypt-dev merge=agecrypt-dev -text
"#;
    fs::write(repo.join(".gitattributes"), gitattrs).unwrap();

    let def_plain = "DEFAULT_SECRET=top_default_value\n";
    let prod_plain = "PROD_SECRET=top_prod_value\n";
    let dev_plain = "DEV_SECRET=top_dev_value\n";

    fs::write(repo.join("default.secret.env"), def_plain).unwrap();
    fs::write(repo.join("prod.secret.env"), prod_plain).unwrap();
    fs::write(repo.join("dev.secret.env"), dev_plain).unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "default.secret.env",
            "prod.secret.env",
            "dev.secret.env",
        ],
    );
    run_git(
        repo,
        &[
            "commit",
            "-m",
            "Commit secrets across default, prod, dev rings",
        ],
    );

    // 3. Verify Invariant A across all three rings
    assert_invariant_a(repo, "default.secret.env", def_plain);
    assert_invariant_a(repo, "prod.secret.env", prod_plain);
    assert_invariant_a(repo, "dev.secret.env", dev_plain);

    // 4. Verify Invariant C: Lock 'prod' ring only
    agecrypt_cmd(repo)
        .args(["lock", "--ring", "prod"])
        .assert()
        .success();

    // 'prod' file must now be ciphertext on disk
    let prod_disk = fs::read(repo.join("prod.secret.env")).unwrap();
    assert!(prod_disk.starts_with(b"age-encryption.org/v1\n"));

    // 'default' and 'dev' files must remain plaintext on disk
    let def_disk = fs::read_to_string(repo.join("default.secret.env")).unwrap();
    assert_eq!(def_disk, def_plain);
    let dev_disk = fs::read_to_string(repo.join("dev.secret.env")).unwrap();
    assert_eq!(dev_disk, dev_plain);

    // 5. Lock 'default' ring: prod is locked, default is locked, dev remains plaintext
    agecrypt_cmd(repo).arg("lock").assert().success();
    let def_disk_locked = fs::read(repo.join("default.secret.env")).unwrap();
    assert!(def_disk_locked.starts_with(b"age-encryption.org/v1\n"));
    let dev_disk_unlocked = fs::read_to_string(repo.join("dev.secret.env")).unwrap();
    assert_eq!(dev_disk_unlocked, dev_plain);

    // 6. Unlock 'prod' ring: prod becomes plaintext, default remains locked
    let mut unlock_cmd = agecrypt_cmd(repo);
    unlock_cmd
        .args(["unlock", &prod_key_file.to_string_lossy(), "--ring", "prod"])
        .assert()
        .success();
    let prod_restored = fs::read_to_string(repo.join("prod.secret.env")).unwrap();
    assert_eq!(prod_restored, prod_plain);
    let def_still_locked = fs::read(repo.join("default.secret.env")).unwrap();
    assert!(def_still_locked.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn test_branch_switch_cross_ring_attributes() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();

    // Branch A: file assigned to default ring
    fs::write(
        repo.join(".gitattributes"),
        "shared.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    let val_branch_a = "SHARED_KEY=branch_a_default_secret\n";
    fs::write(repo.join("shared.secret.env"), val_branch_a).unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "shared.secret.env",
        ],
    );
    run_git(
        repo,
        &["commit", "-m", "Commit on branch A with default ring"],
    );

    // Create and switch to Branch B: reassign shared.secret.env to prod ring
    run_git(repo, &["checkout", "-b", "branch-prod"]);
    fs::write(
        repo.join(".gitattributes"),
        "shared.secret.env filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n",
    )
    .unwrap();
    let val_branch_b = "SHARED_KEY=branch_b_prod_secret\n";
    fs::write(repo.join("shared.secret.env"), val_branch_b).unwrap();
    run_git(repo, &["add", ".gitattributes", "shared.secret.env"]);
    run_git(repo, &["commit", "-m", "Commit on branch B with prod ring"]);

    // Switch back to master (branch A)
    run_git(repo, &["checkout", "main"]);
    let read_master = fs::read_to_string(repo.join("shared.secret.env")).unwrap();
    assert_eq!(read_master, val_branch_a);

    // Switch to branch-prod
    run_git(repo, &["checkout", "branch-prod"]);
    let read_prod = fs::read_to_string(repo.join("shared.secret.env")).unwrap();
    assert_eq!(read_prod, val_branch_b);
}

#[test]
fn test_rekey_and_rings_combinatorial_isolation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // Initialize default and prod rings
    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();

    fs::write(repo.join(".gitattributes"), "def.secret.env filter=agecrypt diff=agecrypt -text\nprod.secret.env filter=agecrypt-prod diff=agecrypt-prod -text\n").unwrap();
    fs::write(repo.join("def.secret.env"), "DEFAULT_VAL=gen0\n").unwrap();
    fs::write(repo.join("prod.secret.env"), "PROD_VAL=gen0\n").unwrap();
    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "def.secret.env",
            "prod.secret.env",
        ],
    );

    let (prod_sec, prod_pub) = generate_test_identity();
    let prod_key_file = repo.join("prod_user.key");
    fs::write(&prod_key_file, &prod_sec).unwrap();
    agecrypt_cmd(repo)
        .args(["add-recipient", "--ring", "prod", "-i", &prod_pub])
        .assert()
        .success();
    run_git(repo, &["add", ".git-agecrypt"]);
    run_git(repo, &["commit", "-m", "Enroll recipient for prod ring"]);

    // Rekey prod ring ONLY to Gen 1
    agecrypt_cmd(repo)
        .args(["rekey", "--ring", "prod", "-f"])
        .assert()
        .success();
    run_git(repo, &["commit", "-a", "-m", "Rekey prod to Gen 1"]);

    // Verify both are still plaintext in working tree
    assert_eq!(
        fs::read_to_string(repo.join("def.secret.env")).unwrap(),
        "DEFAULT_VAL=gen0\n"
    );
    assert_eq!(
        fs::read_to_string(repo.join("prod.secret.env")).unwrap(),
        "PROD_VAL=gen0\n"
    );

    // Edit both files and commit
    fs::write(repo.join("def.secret.env"), "DEFAULT_VAL=gen0_updated\n").unwrap();
    fs::write(repo.join("prod.secret.env"), "PROD_VAL=gen1_updated\n").unwrap();
    run_git(repo, &["add", "def.secret.env", "prod.secret.env"]);
    run_git(repo, &["commit", "-m", "Update files after prod rekey"]);

    // Lock prod: prod becomes ciphertext, default remains plaintext
    agecrypt_cmd(repo)
        .args(["lock", "--ring", "prod"])
        .assert()
        .success();
    assert!(
        fs::read(repo.join("prod.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    assert_eq!(
        fs::read_to_string(repo.join("def.secret.env")).unwrap(),
        "DEFAULT_VAL=gen0_updated\n"
    );

    // Unlock prod using enrolled key: restored
    agecrypt_cmd(repo)
        .args(["unlock", &prod_key_file.to_string_lossy(), "--ring", "prod"])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("prod.secret.env")).unwrap(),
        "PROD_VAL=gen1_updated\n"
    );
}
