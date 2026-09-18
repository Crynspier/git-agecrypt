mod common;

use common::*;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use tempfile::tempdir;

fn encrypt_buffer(repo: &Path, content: &[u8]) -> Vec<u8> {
    let mut clean_cmd = agecrypt_cmd(repo);
    let mut child = clean_cmd
        .arg("clean")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clean");
    child.stdin.as_mut().unwrap().write_all(content).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "Clean command failed to encrypt");
    out.stdout
}

fn decrypt_buffer(repo: &Path, ciphertext: &[u8]) -> Vec<u8> {
    let mut smudge_cmd = agecrypt_cmd(repo);
    let mut child = smudge_cmd
        .arg("smudge")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn smudge");
    child.stdin.as_mut().unwrap().write_all(ciphertext).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "Smudge command failed to decrypt");
    out.stdout
}

#[test]
fn test_merge_driver_clean_3way_merge_disjoint_keys() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_file = repo.join("matrix.secret.env");
    let base_content = "VAR_A=base_a\nVAR_B=base_b\nVAR_C=base_c\n";
    fs::write(&secret_file, base_content).unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Base matrix commit"]);

    // Branch 1: edits VAR_A
    run_git(repo, &["checkout", "-b", "branch-edit-a"]);
    fs::write(
        &secret_file,
        "VAR_A=modified_a\nVAR_B=base_b\nVAR_C=base_c\n",
    )
    .unwrap();
    run_git(repo, &["commit", "-am", "Edit A"]);

    // Branch 2: edits VAR_C from main
    run_git(repo, &["checkout", "main"]);
    run_git(repo, &["checkout", "-b", "branch-edit-c"]);
    fs::write(
        &secret_file,
        "VAR_A=base_a\nVAR_B=base_b\nVAR_C=modified_c\n",
    )
    .unwrap();
    run_git(repo, &["commit", "-am", "Edit C"]);

    // Merge branch-edit-a into branch-edit-c: disjoint line edits should merge cleanly with 0 exit code!
    let merge_res = run_git_output(repo, &["merge", "branch-edit-a"]);
    assert!(
        merge_res.status.success(),
        "Disjoint 3-way merge should succeed cleanly"
    );

    let merged_text = fs::read_to_string(&secret_file).unwrap();
    assert!(merged_text.contains("VAR_A=modified_a"));
    assert!(merged_text.contains("VAR_B=base_b"));
    assert!(merged_text.contains("VAR_C=modified_c"));

    // Verify index blob is valid age ciphertext
    let blob = git_out(repo, &["cat-file", "blob", ":matrix.secret.env"]);
    assert!(blob.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn test_merge_driver_semantic_conflict_detection() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let base_file = repo.join("base.age");
    let ours_file = repo.join("ours.age");
    let theirs_file = repo.join("theirs.age");

    // Conflicting edits on CRLF file
    fs::write(
        &base_file,
        encrypt_buffer(repo, b"PORT=8080\r\nHOST=localhost\r\n"),
    )
    .unwrap();
    fs::write(
        &ours_file,
        encrypt_buffer(repo, b"PORT=9000\r\nHOST=localhost\r\n"),
    )
    .unwrap();
    fs::write(
        &theirs_file,
        encrypt_buffer(repo, b"PORT=9999\r\nHOST=localhost\r\n"),
    )
    .unwrap();

    let mut merge_cmd = agecrypt_cmd(repo);
    let status = merge_cmd
        .args([
            "merge",
            base_file.to_str().unwrap(),
            ours_file.to_str().unwrap(),
            theirs_file.to_str().unwrap(),
            "7",
            "configs/conflict.secret.env",
        ])
        .status()
        .unwrap();

    // Conflict occurred (exit code > 0)
    assert!(!status.success());

    // Decrypt merged result
    let merged_cipher = fs::read(&ours_file).unwrap();
    let decrypted = decrypt_buffer(repo, &merged_cipher);

    // Verify conflict markers are present
    assert!(decrypted.windows(7).any(|w| w == b"<<<<<<<"));
    assert!(decrypted.windows(7).any(|w| w == b">>>>>>>"));

    // CRITICAL: Ensure NO double carriage return (\r\r\n) exists anywhere!
    assert!(
        !decrypted.windows(3).any(|w| w == b"\r\r\n"),
        "Merged conflict output must NOT contain double carriage returns (\\r\\r\\n)!"
    );
}

#[test]
fn test_merge_driver_crlf_lf_cross_platform_normalization() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let base_file = repo.join("base.age");
    let ours_file = repo.join("ours.age");
    let theirs_file = repo.join("theirs.age");

    // Base uses Unix LF
    fs::write(
        &base_file,
        encrypt_buffer(repo, b"PORT=8080\nHOST=localhost\nDEBUG=false\n"),
    )
    .unwrap();
    // Ours edited DEBUG on Windows, so ours has CRLF (\r\n) line endings
    fs::write(
        &ours_file,
        encrypt_buffer(repo, b"PORT=8080\r\nHOST=localhost\r\nDEBUG=true\r\n"),
    )
    .unwrap();
    // Theirs edited PORT on Linux/macOS, so theirs has LF (\n) line endings
    fs::write(
        &theirs_file,
        encrypt_buffer(repo, b"PORT=9000\nHOST=localhost\nDEBUG=false\n"),
    )
    .unwrap();

    // Run 3-way merge driver
    let mut merge_cmd = agecrypt_cmd(repo);
    merge_cmd
        .args([
            "merge",
            base_file.to_str().unwrap(),
            ours_file.to_str().unwrap(),
            theirs_file.to_str().unwrap(),
            "7",
            "configs/server.secret.env",
        ])
        .assert()
        .success();

    // Verify ours_file is merged and encrypted
    let merged_cipher = fs::read(&ours_file).unwrap();
    assert!(merged_cipher.starts_with(b"age-encryption.org/v1\n"));

    let decrypted_bytes = decrypt_buffer(repo, &merged_cipher);
    let decrypted = String::from_utf8(decrypted_bytes).unwrap();

    // Both changes must be merged without collision or conflict markers!
    assert!(decrypted.contains("PORT=9000"));
    assert!(decrypted.contains("DEBUG=true"));
    assert!(!decrypted.contains("<<<<<<<"));
    // Ours originally used CRLF, so the merged output must preserve CRLF!
    assert!(
        decrypted.contains("\r\n"),
        "Merged file must preserve ours CRLF endings!"
    );
}

#[test]
fn test_merge_driver_rejects_unresolved_conflict_markers() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let base = repo.join("base.txt");
    let ours = repo.join("ours.txt");
    let theirs = repo.join("theirs.txt");

    fs::write(&base, "PORT=3000\n").unwrap();
    fs::write(&ours, "PORT=8080\n").unwrap();
    fs::write(&theirs, "PORT=9090\n").unwrap();

    let mut merge_cmd = agecrypt_cmd(repo);
    let assert = merge_cmd
        .args([
            "merge",
            base.to_str().unwrap(),
            ours.to_str().unwrap(),
            theirs.to_str().unwrap(),
            "7",
            "ours.txt",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("Visible merge conflict"));

    // Verify ours was encrypted with visible conflict markers
    let merged_bytes = fs::read(&ours).unwrap();
    assert!(merged_bytes.starts_with(b"age-encryption.org/v1\n"));
}
