mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_explicit_historical_revocation_epochs() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    // Generate identities for Alice, Bob, Charlie
    let (alice_sec, alice_pub) = generate_test_identity();
    let (bob_sec, bob_pub) = generate_test_identity();
    let (charlie_sec, charlie_pub) = generate_test_identity();

    // 1. Epoch G0: Alice + Bob
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &alice_pub, "--name", "alice"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &bob_pub, "--name", "bob"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    let secret_g0 = "EPOCH_G0_SECRET=super_secret_for_alice_and_bob\n";
    fs::write(repo.join("vault.secret.env"), secret_g0).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "vault.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Epoch G0 commit"]);
    let g0_commit = git_out(repo, &["rev-parse", "HEAD"]);
    let g0_commit_str = String::from_utf8_lossy(&g0_commit).trim().to_string();

    // 2. Epoch G1: Revoke Bob, Add Charlie, Rekey
    agecrypt_cmd(repo)
        .args(["remove-recipient", "bob"])
        .assert()
        .success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &charlie_pub, "--name", "charlie"])
        .assert()
        .success();
    agecrypt_cmd(repo).args(["rekey", "-f"]).assert().success();

    let secret_g1 = "EPOCH_G1_SECRET=top_secret_for_alice_and_charlie_only\n";
    fs::write(repo.join("vault.secret.env"), secret_g1).unwrap();
    run_git(repo, &["add", ".git-agecrypt", "vault.secret.env"]);
    run_git(repo, &["commit", "-m", "Epoch G1 commit"]);

    // Lock repository to test unwrap / smudge capabilities of each party
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();

    // Proof 1: Alice unlocks current G1 state successfully
    agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(alice_sec.as_bytes())
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("vault.secret.env")).unwrap(),
        secret_g1
    );

    // Lock again
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();

    // Proof 2: Charlie unlocks current G1 state successfully
    agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(charlie_sec.as_bytes())
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(repo.join("vault.secret.env")).unwrap(),
        secret_g1
    );

    // Lock again
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();

    // Proof 3: Revoked Bob FAILS to unlock current G1 state
    let bob_unlock = agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(bob_sec.as_bytes())
        .output()
        .expect("Unlock execution");
    assert!(
        !bob_unlock.status.success(),
        "Revoked recipient Bob must fail to unlock post-revocation G1 state"
    );

    // Proof 4: Checkout historical G0 commit. Bob retained key can unlock historical G0 state
    run_git(repo, &["checkout", &g0_commit_str]);
    let bob_hist_unlock = agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(bob_sec.as_bytes())
        .output()
        .expect("Historical unlock");
    assert!(
        bob_hist_unlock.status.success(),
        "Bob with retained G0 key must be able to unlock historical G0 commit where he was an authorized recipient"
    );
    assert_eq!(
        fs::read_to_string(repo.join("vault.secret.env")).unwrap(),
        secret_g0
    );

    // Lock again
    agecrypt_cmd(repo).args(["lock", "-f"]).assert().success();

    // Proof 5: Charlie (added in G1) CANNOT unlock historical G0 commit without historical credentials
    let charlie_hist_unlock = agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(charlie_sec.as_bytes())
        .output()
        .expect("Historical unlock for Charlie");
    assert!(
        !charlie_hist_unlock.status.success(),
        "Charlie who was only added in G1 cannot unlock historical G0 commits"
    );

    // Return to main branch
    run_git(repo, &["checkout", "main"]);
}
