mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_revocation_across_complex_histories() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // Generation 0: Alice + Bob
    let (alice_sec, alice_pub) = generate_test_identity();
    let (bob_sec, bob_pub) = generate_test_identity();
    let (charlie_sec, charlie_pub) = generate_test_identity();

    let key_dir = tempdir().expect("Failed to create keydir");
    let alice_key_file = key_dir.path().join("alice.key");
    let bob_key_file = key_dir.path().join("bob.key");
    let charlie_key_file = key_dir.path().join("charlie.key");
    fs::write(&alice_key_file, &alice_sec).unwrap();
    fs::write(&bob_key_file, &bob_sec).unwrap();
    fs::write(&charlie_key_file, &charlie_sec).unwrap();

    // Alice initializes repository (G0)
    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();

    // Alice enrolls Bob (G0)
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &bob_pub, "--name", "bob"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    run_git(repo, &["add", "."]);
    run_git(
        repo,
        &["commit", "-m", "Init repo with Alice and Bob at G0"],
    );

    // Bob commits a secret during his active tenure (G0)
    fs::write(
        repo.join("project.secret.env"),
        "PROJECT_SECRET=authored_by_bob_g0\n",
    )
    .unwrap();
    run_git(repo, &["add", "project.secret.env"]);
    run_git(repo, &["commit", "-m", "Bob commits secret at G0"]);
    let g0_commit = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Epoch 1: Bob leaves company. Alice removes Bob and rekeys to G1
    agecrypt_cmd(repo)
        .args(["remove-recipient", "bob"])
        .assert()
        .success();
    agecrypt_cmd(repo).args(["rekey", "-f"]).assert().success();

    fs::write(
        repo.join("project.secret.env"),
        "PROJECT_SECRET=updated_by_alice_g1\n",
    )
    .unwrap();
    run_git(repo, &["add", "."]);
    run_git(
        repo,
        &[
            "commit",
            "-m",
            "Alice removes Bob, rekeys to G1, updates secret",
        ],
    );
    let g1_commit = String::from_utf8(git_out(repo, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();

    // Epoch 2: Charlie joins. Alice enrolls Charlie (G1/G2)
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &charlie_pub, "--name", "charlie"])
        .assert()
        .success();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Alice enrolls Charlie"]);

    // VERIFICATION 1: Bob CANNOT unlock current working tree (G1/G2)
    agecrypt_cmd(repo).arg("lock").assert().success();
    let bob_unlock = agecrypt_cmd(repo)
        .args(["unlock", bob_key_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !bob_unlock.status.success()
            || !fs::read_to_string(repo.join("project.secret.env"))
                .unwrap()
                .contains("updated_by_alice_g1"),
        "Bob must NOT be able to decrypt G1/G2 current state"
    );

    // VERIFICATION 2: Charlie CAN unlock current working tree
    agecrypt_cmd(repo)
        .args(["unlock", charlie_key_file.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("project.secret.env")).unwrap(),
        "PROJECT_SECRET=updated_by_alice_g1\n",
        "Charlie must be able to unlock current working tree"
    );

    // VERIFICATION 3: Alice CAN unlock current working tree
    agecrypt_cmd(repo).arg("lock").assert().success();
    agecrypt_cmd(repo)
        .args(["unlock", alice_key_file.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("project.secret.env")).unwrap(),
        "PROJECT_SECRET=updated_by_alice_g1\n",
        "Alice must be able to unlock current working tree"
    );

    // VERIFICATION 4: Historical Merkle DAG semantics
    // Bob checks out historical commit G0 created during his tenure:
    // Git allows checking out historical commit, and textconv or historical envelope can decrypt G0.
    let g0_blob = git_out(
        repo,
        &["cat-file", "-p", &format!("{g0_commit}:project.secret.env")],
    );
    assert!(
        g0_blob.starts_with(b"age-encryption.org/v1\n"),
        "G0 commit in Git object database is authenticated ciphertext"
    );

    let g1_blob = git_out(
        repo,
        &["cat-file", "-p", &format!("{g1_commit}:project.secret.env")],
    );
    assert!(
        g1_blob.starts_with(b"age-encryption.org/v1\n"),
        "G1 commit in Git object database is authenticated ciphertext"
    );
}
