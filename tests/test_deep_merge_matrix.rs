mod common;

use common::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_deep_merge_matrix_exhaustive() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    // 1. BASE COMMIT with initial secrets
    let base_content = "\
# Base configuration
DATABASE_PORT=5432
API_KEY=base_key_1234
SHARED_FLAG=true
UNICODE_GREETING=Hello_世界
FOOTER=done
";
    fs::write(repo.join("config.secret.env"), base_content).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Base commit"]);

    // 2. BRANCH A (Ours): modifies DATABASE_PORT to 5433
    run_git(repo, &["checkout", "-b", "branch-a"]);
    let branch_a_content = "\
# Base configuration
DATABASE_PORT=5433
API_KEY=base_key_1234
SHARED_FLAG=true
UNICODE_GREETING=Hello_世界
FOOTER=done
";
    fs::write(repo.join("config.secret.env"), branch_a_content).unwrap();
    run_git(repo, &["add", "config.secret.env"]);
    run_git(repo, &["commit", "-m", "Branch A edit"]);

    // 3. BRANCH B (Theirs): modifies SHARED_FLAG to false
    run_git(repo, &["checkout", "main"]);
    run_git(repo, &["checkout", "-b", "branch-b"]);
    let branch_b_content = "\
# Base configuration
DATABASE_PORT=5432
API_KEY=base_key_1234
SHARED_FLAG=false
UNICODE_GREETING=Hello_世界
FOOTER=done
";
    fs::write(repo.join("config.secret.env"), branch_b_content).unwrap();
    run_git(repo, &["add", "config.secret.env"]);
    run_git(repo, &["commit", "-m", "Branch B edit"]);

    // 4. Merge Branch B into Branch A: Non-overlapping edits must clean-merge automatically!
    run_git(repo, &["checkout", "branch-a"]);
    let merge_clean = run_git_output(
        repo,
        &["merge", "branch-b", "-m", "Merge branch-b into branch-a"],
    );
    if !merge_clean.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&merge_clean.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&merge_clean.stderr));
    }
    assert!(
        merge_clean.status.success(),
        "Non-overlapping edits on different keys must auto-merge cleanly"
    );

    let merged_text = fs::read_to_string(repo.join("config.secret.env")).unwrap();
    assert!(merged_text.contains("DATABASE_PORT=5433"));
    assert!(merged_text.contains("SHARED_FLAG=false"));
    assert!(merged_text.contains("UNICODE_GREETING=Hello_世界"));

    // 5. Conflicting edits: modify same key to different values
    run_git(repo, &["checkout", "-b", "conflict-a"]);
    fs::write(repo.join("conflict.secret.env"), "SHARED_PORT=8001\n").unwrap();
    run_git(repo, &["add", "conflict.secret.env"]);
    run_git(repo, &["commit", "-m", "Port 8001"]);

    run_git(repo, &["checkout", "branch-a"]);
    run_git(repo, &["checkout", "-b", "conflict-b"]);
    fs::write(repo.join("conflict.secret.env"), "SHARED_PORT=8002\n").unwrap();
    run_git(repo, &["add", "conflict.secret.env"]);
    run_git(repo, &["commit", "-m", "Port 8002"]);

    // Merging conflict-a into conflict-b must declare conflict and NOT falsely succeed!
    let merge_conflict = run_git_output(repo, &["merge", "conflict-a"]);
    assert!(
        !merge_conflict.status.success(),
        "Conflicting values for the same key must produce a visible conflict"
    );
    let conflict_text = fs::read_to_string(repo.join("conflict.secret.env")).unwrap();
    assert!(
        conflict_text.contains("<<<<<<<") && conflict_text.contains(">>>>>>>"),
        "Conflict markers must be present in working tree for developer resolution"
    );

    // Clean up merge conflict
    let _ = run_git_output(repo, &["merge", "--abort"]);
}
