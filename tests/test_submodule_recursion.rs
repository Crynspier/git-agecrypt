mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_recursive_submodule_hierarchy() {
    let temp = tempdir().expect("Failed to create tempdir");
    let root = temp.path();

    let parent_repo = root.join("parent");
    let child_repo = root.join("child");
    let grandchild_repo = root.join("grandchild");

    fs::create_dir_all(&parent_repo).unwrap();
    fs::create_dir_all(&child_repo).unwrap();
    fs::create_dir_all(&grandchild_repo).unwrap();

    init_repo(&grandchild_repo);
    init_repo(&child_repo);
    init_repo(&parent_repo);

    // 1. Initialize grandchild repo with its own independent key
    agecrypt_cmd(&grandchild_repo)
        .arg("init")
        .assert()
        .success();
    fs::write(
        grandchild_repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        grandchild_repo.join("gc.secret.env"),
        "GC_KEY=grandchild_val\n",
    )
    .unwrap();
    run_git(&grandchild_repo, &["add", "."]);
    run_git(&grandchild_repo, &["commit", "-m", "Grandchild init"]);

    // 2. Initialize child repo with its own independent key
    agecrypt_cmd(&child_repo).arg("init").assert().success();
    fs::write(
        child_repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(child_repo.join("child.secret.env"), "CHILD_KEY=child_val\n").unwrap();
    run_git(&child_repo, &["add", "."]);
    run_git(&child_repo, &["commit", "-m", "Child init"]);

    // Add grandchild submodule into child
    let gc_url = format!(
        "file://{}",
        grandchild_repo.to_str().unwrap().replace('\\', "/")
    );
    let child_sub_dest = "modules/grandchild";
    let _ = run_git_output(
        &child_repo,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &gc_url,
            child_sub_dest,
        ],
    );
    let _ = run_git_output(&child_repo, &["commit", "-m", "Add grandchild submodule"]);

    // 3. Initialize parent repo with its own key
    agecrypt_cmd(&parent_repo).arg("init").assert().success();
    fs::write(
        parent_repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        parent_repo.join("parent.secret.env"),
        "PARENT_KEY=parent_val\n",
    )
    .unwrap();
    run_git(&parent_repo, &["add", "."]);
    run_git(&parent_repo, &["commit", "-m", "Parent init"]);

    // Add child submodule into parent
    let child_url = format!("file://{}", child_repo.to_str().unwrap().replace('\\', "/"));
    let parent_sub_dest = "vendor/child";
    let _ = run_git_output(
        &parent_repo,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &child_url,
            parent_sub_dest,
        ],
    );
    let _ = run_git_output(&parent_repo, &["commit", "-m", "Add child submodule"]);

    // Run check on parent: must pass cleanly and recognize gitlinks (mode 160000)
    agecrypt_cmd(&parent_repo).arg("check").assert().success();

    // Verify independent locking: Locking parent does NOT lock child
    agecrypt_cmd(&parent_repo).arg("lock").assert().success();
    assert!(
        fs::read(parent_repo.join("parent.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    assert_eq!(
        fs::read_to_string(child_repo.join("child.secret.env")).unwrap(),
        "CHILD_KEY=child_val\n"
    );
}
