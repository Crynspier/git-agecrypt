mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_combinatorial_rings_generations_dag() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // 1. Initial Identities for 3 rings: default, prod, dev (Generation 0)
    let (def_sec_0, def_pub_0) = generate_test_identity();
    let (prod_sec_0, prod_pub_0) = generate_test_identity();
    let (dev_sec_0, dev_pub_0) = generate_test_identity();

    let key_dir = tempdir().expect("Failed to create keydir");
    let def_key_0 = key_dir.path().join("def_0.key");
    let prod_key_0 = key_dir.path().join("prod_0.key");
    let dev_key_0 = key_dir.path().join("dev_0.key");
    fs::write(&def_key_0, &def_sec_0).unwrap();
    fs::write(&prod_key_0, &prod_sec_0).unwrap();
    fs::write(&dev_key_0, &dev_sec_0).unwrap();

    // Initialize Default ring (G0)
    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &def_pub_0, "--name", "def_0"])
        .assert()
        .success();

    // Initialize Prod ring (G0)
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "--ring", "prod", "-i", &prod_pub_0])
        .assert()
        .success();

    // Initialize Dev ring (G0)
    agecrypt_cmd(repo)
        .args(["init", "--ring", "dev"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "--ring", "dev", "-i", &dev_pub_0])
        .assert()
        .success();

    // Configure .gitattributes to route secrets to their respective rings
    let gitattributes = "\
def.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text
prod.secret.env filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text
dev.secret.env filter=agecrypt-dev diff=agecrypt-dev merge=agecrypt-dev -text
";
    fs::write(repo.join(".gitattributes"), gitattributes).unwrap();
    run_git(repo, &["add", ".gitattributes"]);
    run_git(
        repo,
        &["commit", "-m", "Configure ring routing in .gitattributes"],
    );

    // Commit G0 secrets across all 3 rings
    fs::write(repo.join("def.secret.env"), "DEFAULT_SECRET=val_def_g0\n").unwrap();
    fs::write(repo.join("prod.secret.env"), "PROD_SECRET=val_prod_g0\n").unwrap();
    fs::write(repo.join("dev.secret.env"), "DEV_SECRET=val_dev_g0\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(
        repo,
        &[
            "commit",
            "-m",
            "Commit G0 secrets across default, prod, dev",
        ],
    );

    // 2. Create Branch A from G0
    run_git(repo, &["checkout", "-b", "branch-a"]);
    fs::write(
        repo.join("prod.secret.env"),
        "PROD_SECRET=val_prod_branch_a\n",
    )
    .unwrap();
    run_git(repo, &["add", "prod.secret.env"]);
    run_git(repo, &["commit", "-m", "Branch A updates prod secret"]);

    // 3. On main: Rekey Prod Ring to Generation 1 (leaving default at G0, dev at G0)
    run_git(repo, &["checkout", "main"]);
    let (prod_sec_1, prod_pub_1) = generate_test_identity();
    let prod_key_1 = key_dir.path().join("prod_1.key");
    fs::write(&prod_key_1, &prod_sec_1).unwrap();
    agecrypt_cmd(repo)
        .args(["add-recipient", "--ring", "prod", "-i", &prod_pub_1])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["rekey", "--ring", "prod", "-f"])
        .assert()
        .success();

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Main rekeys prod ring to G1"]);

    // 4. Create Branch B from G1 state
    run_git(repo, &["checkout", "-b", "branch-b"]);
    // On Branch B: Rekey Default Ring to Generation 1
    let (def_sec_1, def_pub_1) = generate_test_identity();
    let def_key_1 = key_dir.path().join("def_1.key");
    fs::write(&def_key_1, &def_sec_1).unwrap();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &def_pub_1])
        .assert()
        .success();
    agecrypt_cmd(repo).args(["rekey", "-f"]).assert().success();

    fs::write(
        repo.join("def.secret.env"),
        "DEFAULT_SECRET=val_def_branch_b_g1\n",
    )
    .unwrap();
    run_git(repo, &["add", "."]);
    run_git(
        repo,
        &[
            "commit",
            "-m",
            "Branch B rekeys default to G1 and updates def secret",
        ],
    );

    // 5. Switch back to main and merge Branch B
    run_git(repo, &["checkout", "main"]);
    let merge_out = run_git_output(
        repo,
        &["merge", "branch-b", "-m", "Merge branch-b into main"],
    );
    assert!(
        merge_out.status.success(),
        "Merge branch-b must succeed cleanly"
    );

    // 6. Verify cross-ring independent resolution:
    // Lock all rings (default, prod, dev)
    agecrypt_cmd(repo).arg("lock").assert().success();
    agecrypt_cmd(repo)
        .args(["lock", "--ring", "prod"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["lock", "--ring", "dev"])
        .assert()
        .success();

    // Verify all 3 files are ciphertext
    assert!(
        fs::read(repo.join("def.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    assert!(
        fs::read(repo.join("prod.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    assert!(
        fs::read(repo.join("dev.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );

    // Unlock Default using G1 key
    agecrypt_cmd(repo)
        .args(["unlock", def_key_1.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("def.secret.env")).unwrap(),
        "DEFAULT_SECRET=val_def_branch_b_g1\n"
    );
    // Prod and Dev must remain locked
    assert!(
        fs::read(repo.join("prod.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    assert!(
        fs::read(repo.join("dev.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );

    // Unlock Prod using G1 key
    agecrypt_cmd(repo)
        .args(["unlock", "--ring", "prod", prod_key_1.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("prod.secret.env")).unwrap(),
        "PROD_SECRET=val_prod_g0\n"
    );
    // Dev must remain locked
    assert!(
        fs::read(repo.join("dev.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );

    // Unlock Dev using G0 key
    agecrypt_cmd(repo)
        .args(["unlock", "--ring", "dev", dev_key_0.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("dev.secret.env")).unwrap(),
        "DEV_SECRET=val_dev_g0\n"
    );

    // Verify zero plaintext canaries exist in Git objects
    assert_no_plaintext_in_git_objects(
        repo,
        &[
            "val_def_branch_b_g1",
            "val_prod_g0",
            "val_dev_g0",
            "val_prod_branch_a",
        ],
    );
}
