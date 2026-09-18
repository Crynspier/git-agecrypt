mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_porcelain_state_machine_and_canary_scan() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("service.secret.env");
    let canary = "SUPER_SECRET_CANARY_STATEFUL_123456";
    fs::write(&secret_file, format!("CANARY_KEY={canary}\n")).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Initial commit"]);

    // Invariant A verification: Working tree has plaintext, Git object DB has ciphertext
    let expected1 = format!("CANARY_KEY={canary}\n");
    assert_invariant_a(repo, "service.secret.env", &expected1);

    // 1. Commit --amend
    let expected_amended = format!("CANARY_KEY={canary}_AMENDED\n");
    fs::write(&secret_file, &expected_amended).unwrap();
    run_git(repo, &["add", "service.secret.env"]);
    run_git(repo, &["commit", "--amend", "-m", "Commit amended"]);
    assert_invariant_a(repo, "service.secret.env", &expected_amended);

    // 2. Git branch & checkout
    run_git(repo, &["checkout", "-b", "feature-branch"]);
    let expected_feature = format!("CANARY_KEY={canary}_FEATURE\n");
    fs::write(&secret_file, &expected_feature).unwrap();
    run_git(repo, &["add", "service.secret.env"]);
    run_git(repo, &["commit", "-m", "Feature commit"]);
    assert_invariant_a(repo, "service.secret.env", &expected_feature);

    // 3. Git stash push & pop
    fs::write(&secret_file, format!("CANARY_KEY={canary}_STASHED\n")).unwrap();
    run_git(repo, &["stash", "push", "-m", "wip stash"]);
    assert_eq!(fs::read_to_string(&secret_file).unwrap(), expected_feature);
    run_git(repo, &["stash", "pop"]);
    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        format!("CANARY_KEY={canary}_STASHED\n")
    );

    // 4. Git restore
    run_git(repo, &["restore", "service.secret.env"]);
    assert_eq!(fs::read_to_string(&secret_file).unwrap(), expected_feature);

    // 5. Git rebase onto main
    run_git(repo, &["checkout", "main"]);
    run_git(repo, &["rebase", "feature-branch"]);
    assert_eq!(fs::read_to_string(&secret_file).unwrap(), expected_feature);

    // 6. Git repack / gc to create packfiles and verify packfile canary scan
    run_git(repo, &["repack", "-a", "-d"]);
    let amended_str = format!("{canary}_AMENDED");
    let feature_str = format!("{canary}_FEATURE");
    let stashed_str = format!("{canary}_STASHED");
    assert_no_plaintext_in_git_objects(repo, &[canary, &amended_str, &feature_str, &stashed_str]);
}

#[test]
fn test_sparse_checkout_cone_preservation() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    // Create secrets inside and outside cone directory
    let dir_a = repo.join("service-a");
    let dir_b = repo.join("service-b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    let secret_a = dir_a.join("api.secret.env");
    let secret_b = dir_b.join("api.secret.env");
    fs::write(&secret_a, "SERVICE_A=secret_value_a\n").unwrap();
    fs::write(&secret_b, "SERVICE_B=secret_value_b\n").unwrap();

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit services"]);

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(repo);
    add_cmd.args(["add-recipient", "-i", &pub_key]);
    add_cmd.env("GIT_AGECRYPT_IDENTITY", &secret_key);
    add_cmd.assert().success();

    // Initialize sparse-checkout cone
    let git_ver_out = run_git_output(repo, &["version"]);
    let git_ver_str = String::from_utf8_lossy(&git_ver_out.stdout);
    if git_ver_str.contains("git version") {
        let sc_init = run_git_output(repo, &["sparse-checkout", "init", "--cone"]);
        if sc_init.status.success() {
            let sc_set = run_git_output(repo, &["sparse-checkout", "set", "service-a"]);
            if sc_set.status.success() {
                assert!(secret_a.exists());
                assert_eq!(
                    fs::read_to_string(&secret_a).unwrap(),
                    "SERVICE_A=secret_value_a\n"
                );

                // Lock and unlock within sparse cone
                agecrypt_cmd(repo).arg("lock").assert().success();
                let locked_bytes = fs::read(&secret_a).unwrap();
                assert!(locked_bytes.starts_with(b"age-encryption.org/v1\n"));

                let id_file = repo.join("test_identity.txt");
                fs::write(&id_file, &secret_key).unwrap();
                let mut unlock_cmd = agecrypt_cmd(repo);
                unlock_cmd.args(["unlock", id_file.to_str().unwrap()]);
                unlock_cmd.assert().success();
                let _ = fs::remove_file(&id_file);
                assert_eq!(
                    fs::read_to_string(&secret_a).unwrap(),
                    "SERVICE_A=secret_value_a\n"
                );

                // Disable sparse checkout cleanly
                let _ = run_git_output(repo, &["sparse-checkout", "disable"]);
            }
        }
    }
}

#[test]
fn test_branch_divergence_and_cherry_pick() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let file1 = repo.join("common.secret.env");
    fs::write(&file1, "COMMON=initial\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Base commit"]);

    // Create branch topic
    run_git(repo, &["checkout", "-b", "topic"]);
    let file2 = repo.join("topic.secret.env");
    fs::write(&file2, "TOPIC_SECRET=val_topic\n").unwrap();
    run_git(repo, &["add", "topic.secret.env"]);
    run_git(repo, &["commit", "-m", "Topic commit"]);

    let topic_commit = String::from_utf8_lossy(&git_out(repo, &["rev-parse", "HEAD"]))
        .trim()
        .to_string();

    // Switch back to main
    run_git(repo, &["checkout", "main"]);
    assert!(!file2.exists());

    // Cherry-pick topic commit onto main
    run_git(repo, &["cherry-pick", &topic_commit]);
    assert!(file2.exists());
    assert_eq!(
        fs::read_to_string(&file2).unwrap(),
        "TOPIC_SECRET=val_topic\n"
    );

    // Verify index contains strictly ciphertext
    let blob = git_out(repo, &["cat-file", "blob", ":topic.secret.env"]);
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));
    assert!(!String::from_utf8_lossy(&blob).contains("val_topic"));
}
