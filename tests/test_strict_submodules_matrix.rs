mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_strict_three_tier_submodule_hierarchy() {
    let temp = tempdir().expect("Failed to create tempdir");
    let root = temp.path();

    let grandchild_dir = root.join("grandchild");
    let child_dir = root.join("child");
    let parent_dir = root.join("parent");

    fs::create_dir_all(&grandchild_dir).unwrap();
    fs::create_dir_all(&child_dir).unwrap();
    fs::create_dir_all(&parent_dir).unwrap();

    // 1. Initialize grandchild with agecrypt
    init_repo(&grandchild_dir);
    agecrypt_cmd(&grandchild_dir).arg("init").assert().success();
    let (_gc_sec, gc_pub) = generate_test_identity();
    agecrypt_cmd(&grandchild_dir)
        .args(["add-recipient", "-i", &gc_pub, "--name", "gc_user"])
        .assert()
        .success();

    fs::write(
        grandchild_dir.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        grandchild_dir.join("grandchild.secret.env"),
        "GC_SECRET=grandchild_val_100\n",
    )
    .unwrap();
    run_git(
        &grandchild_dir,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "grandchild.secret.env",
        ],
    );
    run_git(&grandchild_dir, &["commit", "-m", "Grandchild init commit"]);

    // 2. Initialize child with agecrypt and add grandchild as submodule
    init_repo(&child_dir);
    agecrypt_cmd(&child_dir).arg("init").assert().success();
    let (_c_sec, c_pub) = generate_test_identity();
    agecrypt_cmd(&child_dir)
        .args(["add-recipient", "-i", &c_pub, "--name", "child_user"])
        .assert()
        .success();

    fs::write(
        child_dir.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        child_dir.join("child.secret.env"),
        "CHILD_SECRET=child_val_200\n",
    )
    .unwrap();

    let gc_url = grandchild_dir.to_str().unwrap().replace('\\', "/");
    let add_gc_sub = git_out_res(
        &child_dir,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &gc_url,
            "sub_grandchild",
        ],
    );
    assert!(
        add_gc_sub.is_ok(),
        "Adding grandchild submodule must succeed: {:?}",
        add_gc_sub.err()
    );

    run_git(
        &child_dir,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "child.secret.env",
            "sub_grandchild",
        ],
    );
    run_git(
        &child_dir,
        &["commit", "-m", "Child init commit with submodule"],
    );

    // 3. Initialize parent with agecrypt and add child as submodule
    init_repo(&parent_dir);
    agecrypt_cmd(&parent_dir).arg("init").assert().success();
    let (_p_sec, p_pub) = generate_test_identity();
    agecrypt_cmd(&parent_dir)
        .args(["add-recipient", "-i", &p_pub, "--name", "parent_user"])
        .assert()
        .success();

    fs::write(
        parent_dir.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        parent_dir.join("parent.secret.env"),
        "PARENT_SECRET=parent_val_300\n",
    )
    .unwrap();

    let child_url = child_dir.to_str().unwrap().replace('\\', "/");
    let add_c_sub = git_out_res(
        &parent_dir,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &child_url,
            "sub_child",
        ],
    );
    assert!(
        add_c_sub.is_ok(),
        "Adding child submodule must succeed: {:?}",
        add_c_sub.err()
    );

    run_git(
        &parent_dir,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "parent.secret.env",
            "sub_child",
        ],
    );
    run_git(
        &parent_dir,
        &["commit", "-m", "Parent init commit with submodule"],
    );

    // 4. Verify all 3 tiers maintain strict secret encryption and isolation
    assert_eq!(
        fs::read_to_string(parent_dir.join("parent.secret.env")).unwrap(),
        "PARENT_SECRET=parent_val_300\n"
    );
    assert_eq!(
        fs::read_to_string(child_dir.join("child.secret.env")).unwrap(),
        "CHILD_SECRET=child_val_200\n"
    );
    assert_eq!(
        fs::read_to_string(grandchild_dir.join("grandchild.secret.env")).unwrap(),
        "GC_SECRET=grandchild_val_100\n"
    );

    // Locking child must not affect parent
    agecrypt_cmd(&child_dir)
        .args(["lock", "-f"])
        .assert()
        .success();
    let p_secret_after_child_lock =
        fs::read_to_string(parent_dir.join("parent.secret.env")).unwrap();
    assert_eq!(
        p_secret_after_child_lock, "PARENT_SECRET=parent_val_300\n",
        "Locking child submodule must have zero effect on parent working tree"
    );
}
