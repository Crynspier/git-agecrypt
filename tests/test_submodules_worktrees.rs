mod common;

use assert_cmd::prelude::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_multi_worktree_synchronized_lock_and_unlock() {
    let temp = tempdir().expect("Failed to create tempdir");
    let main_repo = temp.path().join("main_repo");
    fs::create_dir(&main_repo).unwrap();
    init_repo(&main_repo);

    agecrypt_cmd(&main_repo).arg("init").assert().success();

    let (secret_key, pub_key) = generate_test_identity();
    let mut add_cmd = agecrypt_cmd(&main_repo);
    add_cmd.args(["add-recipient", "-i", &pub_key, "--name", "user"]);
    add_cmd.assert().success();

    // Secret in main worktree
    let secret_main = main_repo.join("main.secret.env");
    fs::write(&secret_main, "SECRET_MAIN=main_token_123\n").unwrap();
    run_git(
        &main_repo,
        &["add", ".gitattributes", ".git-agecrypt", "main.secret.env"],
    );
    run_git(&main_repo, &["commit", "-m", "Main commit"]);

    // Create linked worktree
    let feature_worktree = temp.path().join("feature_worktree");
    run_git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feature",
            feature_worktree.to_str().unwrap(),
        ],
    );

    // Secret in feature worktree
    let secret_feat = feature_worktree.join("feat.secret.env");
    fs::write(&secret_feat, "SECRET_FEAT=feat_token_456\n").unwrap();
    run_git(&feature_worktree, &["add", "feat.secret.env"]);
    run_git(&feature_worktree, &["commit", "-m", "Feature commit"]);

    // Lock repository from the main worktree
    let mut lock_cmd = agecrypt_cmd(&main_repo);
    lock_cmd.arg("lock").assert().success();

    // CRITICAL: Both main_repo AND feature_worktree must now have encrypted secrets on disk!
    let main_bytes = fs::read(&secret_main).unwrap();
    assert!(
        main_bytes.starts_with(b"age-encryption.org/v1\n"),
        "Main worktree secrets must be encrypted on lock!"
    );

    let feat_bytes = fs::read(&secret_feat).unwrap();
    assert!(
        feat_bytes.starts_with(b"age-encryption.org/v1\n"),
        "Linked worktree secrets must be synchronized and encrypted on lock!"
    );

    // Unlock repository from the feature worktree
    let id_file = feature_worktree.join("user.key");
    fs::write(&id_file, &secret_key).unwrap();
    let mut unlock_cmd = agecrypt_cmd(&feature_worktree);
    unlock_cmd
        .args(["unlock", id_file.to_str().unwrap()])
        .assert()
        .success();
    let _ = fs::remove_file(&id_file);

    // CRITICAL: Both main_repo AND feature_worktree must now be decrypted to plaintext!
    let main_plain = fs::read_to_string(&secret_main).unwrap();
    assert_eq!(main_plain, "SECRET_MAIN=main_token_123\n");

    let feat_plain = fs::read_to_string(&secret_feat).unwrap();
    assert_eq!(feat_plain, "SECRET_FEAT=feat_token_456\n");
}

#[test]
fn test_submodule_independent_encryption_keys() {
    let temp = tempdir().expect("Failed to create tempdir");
    let parent_repo = temp.path().join("parent");
    let sub_repo = temp.path().join("submodule_src");
    fs::create_dir(&parent_repo).unwrap();
    fs::create_dir(&sub_repo).unwrap();

    init_repo(&parent_repo);
    init_repo(&sub_repo);

    agecrypt_cmd(&parent_repo).arg("init").assert().success();
    agecrypt_cmd(&sub_repo).arg("init").assert().success();

    // Verify parent and submodule have distinct master keys
    let parent_pub =
        fs::read_to_string(parent_repo.join(".git-agecrypt").join("repo.pub")).unwrap();
    let sub_pub = fs::read_to_string(sub_repo.join(".git-agecrypt").join("repo.pub")).unwrap();
    assert_ne!(
        parent_pub.trim(),
        sub_pub.trim(),
        "Parent and submodule must have independent master keys"
    );

    // Add submodule into parent
    let sub_dest = parent_repo.join("vendor").join("sub");
    fs::create_dir_all(parent_repo.join("vendor")).unwrap();
    let sub_url = sub_repo.to_str().unwrap().replace('\\', "/");
    let sub_dest_str = sub_dest.to_str().unwrap().replace('\\', "/");

    let out = run_git_output(
        &parent_repo,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &sub_url,
            &sub_dest_str,
        ],
    );
    if out.status.success() {
        // Run git-agecrypt check on parent: must pass and not flag gitlinks as secrets
        agecrypt_cmd(&parent_repo).arg("check").assert().success();
    }
}
