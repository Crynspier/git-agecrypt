mod common;

use common::invariants::*;
use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_expanded_3way_merge_matrix_18_cases() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();
    let (_sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "merge_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    // 1. Non-overlapping edits & comments across distinct sections
    let base_content = "# Base configuration\nAPP_NAME=agecrypt\nPORT=3000\nCONFIG_JSON='{\"timeout\": 10}'\n# Middle Section\nDATABASE_URL=postgres://localhost:5432/db\nCACHE_DRIVER=redis\n# Bottom Section\nFEATURE_FLAG=false\nUNICODE_SECRET=🔒\n";
    fs::write(repo.join("app.secret.env"), base_content).unwrap();
    run_git(
        repo,
        &["add", ".gitattributes", ".git-agecrypt", "app.secret.env"],
    );
    run_git(repo, &["commit", "-m", "Base commit"]);

    // Branch A: modifies PORT and CONFIG_JSON (top section), adds comments
    run_git(repo, &["checkout", "-b", "branch-a"]);
    let branch_a_content = "# Base configuration\nAPP_NAME=agecrypt\nPORT=8080 # changed port\nCONFIG_JSON='{\"timeout\": 30}'\n# Middle Section\nDATABASE_URL=postgres://localhost:5432/db\nCACHE_DRIVER=redis\n# Bottom Section\nFEATURE_FLAG=false\nUNICODE_SECRET=🔒\n";
    fs::write(repo.join("app.secret.env"), branch_a_content).unwrap();
    run_git(repo, &["commit", "-am", "Branch A updates"]);

    // Branch B: modifies FEATURE_FLAG and UNICODE_SECRET (bottom section), non-overlapping with branch A
    run_git(repo, &["checkout", "main"]);
    run_git(repo, &["checkout", "-b", "branch-b"]);
    let branch_b_content = "# Base configuration\nAPP_NAME=agecrypt\nPORT=3000\nCONFIG_JSON='{\"timeout\": 10}'\n# Middle Section\nDATABASE_URL=postgres://localhost:5432/db\nCACHE_DRIVER=redis\n# Bottom Section\nFEATURE_FLAG=true # enabled feature\nUNICODE_SECRET=🔒🔑✨\n";
    fs::write(repo.join("app.secret.env"), branch_b_content).unwrap();
    run_git(repo, &["commit", "-am", "Branch B updates"]);

    // Merge Branch A into Branch B -> Must auto-merge cleanly without conflicts!
    let merge_res = git_out_res(repo, &["merge", "branch-a", "-m", "Merge branch A into B"]);
    assert!(
        merge_res.is_ok(),
        "Non-overlapping edits and comments must auto-merge cleanly: {:?}",
        merge_res.err()
    );

    let merged_file = fs::read_to_string(repo.join("app.secret.env")).unwrap();
    assert!(merged_file.contains("PORT=8080"));
    assert!(merged_file.contains("FEATURE_FLAG=true"));
    assert!(merged_file.contains("CONFIG_JSON='{\"timeout\": 30}'"));
    assert!(merged_file.contains("UNICODE_SECRET=🔒🔑✨"));

    // Invariant A holds after merge commit
    assert_inv_a_working_tree_vs_objects(repo, "app.secret.env", &merged_file);

    // 2. Direct same-key collision (conflict detection)
    run_git(repo, &["checkout", "-b", "conflict-side-1"]);
    fs::write(repo.join("app.secret.env"), "PORT=9001\n").unwrap();
    run_git(repo, &["commit", "-am", "Side 1 change"]);

    run_git(repo, &["checkout", "branch-b"]);
    run_git(repo, &["checkout", "-b", "conflict-side-2"]);
    fs::write(repo.join("app.secret.env"), "PORT=9002\n").unwrap();
    run_git(repo, &["commit", "-am", "Side 2 change"]);

    let conflict_merge = git_out_res(repo, &["merge", "conflict-side-1"]);
    assert!(
        conflict_merge.is_err(),
        "Direct overlapping edits must trigger merge conflict"
    );

    let conflict_content = fs::read_to_string(repo.join("app.secret.env")).unwrap();
    assert!(
        conflict_content.contains("<<<<<<<") && conflict_content.contains(">>>>>>>"),
        "Conflicted secret file must contain standard Git conflict markers: got '{conflict_content}'"
    );
    run_git(repo, &["merge", "--abort"]);
}
