mod common;

use common::invariants::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_generative_ring_x_generation_dag_matrix() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // 1. Initialize default ring and custom prod ring
    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["init", "--ring", "prod"])
        .assert()
        .success();

    let (_def_sec, def_pub) = generate_test_identity();
    let (_prod_sec, prod_pub) = generate_test_identity();

    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &def_pub, "--name", "def_user"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args([
            "add-recipient",
            "-i",
            &prod_pub,
            "--name",
            "prod_user",
            "--ring",
            "prod",
        ])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n*.prod.secret.env filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n",
    )
    .unwrap();

    fs::write(repo.join("common.secret.env"), "DEFAULT_VAL=100\n").unwrap();
    fs::write(repo.join("app.prod.secret.env"), "PROD_VAL=200\n").unwrap();

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "common.secret.env",
            "app.prod.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Epoch 0 commit across rings"]);

    // 2. Branch A: Rekey prod ring to Generation 1
    run_git(repo, &["checkout", "-b", "branch-a"]);
    agecrypt_cmd(repo)
        .args(["rekey", "-f", "--ring", "prod"])
        .assert()
        .success();
    fs::write(repo.join("app.prod.secret.env"), "PROD_VAL=201\n").unwrap();
    run_git(repo, &["commit", "-am", "Rekey prod to Gen 1 on branch A"]);

    // 3. Branch B: Rekey default ring to Generation 1
    run_git(repo, &["checkout", "main"]);
    run_git(repo, &["checkout", "-b", "branch-b"]);
    agecrypt_cmd(repo).args(["rekey", "-f"]).assert().success();
    fs::write(repo.join("common.secret.env"), "DEFAULT_VAL=101\n").unwrap();
    run_git(
        repo,
        &["commit", "-am", "Rekey default to Gen 1 on branch B"],
    );

    // 4. Merge Branch A into Branch B
    let merge_res = git_out_res(
        repo,
        &["merge", "branch-a", "-m", "Merge A into B across rings"],
    );
    assert!(
        merge_res.is_ok(),
        "Merging divergent multi-ring key rotation branches must succeed: {:?}",
        merge_res.err()
    );

    // 5. Verify Invariants: both default and prod maintain their independent secrets
    assert_eq!(
        fs::read_to_string(repo.join("common.secret.env")).unwrap(),
        "DEFAULT_VAL=101\n"
    );
    assert_eq!(
        fs::read_to_string(repo.join("app.prod.secret.env")).unwrap(),
        "PROD_VAL=201\n"
    );

    // Verify Invariant B
    assert_inv_b_durability_consistent(repo);
}
