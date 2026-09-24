//! Hardware-token / age-plugin failure injection.
//!
//! Exercises the full age-plugin IPC failure surface (as used by hardware tokens such as
//! YubiKey via age-plugin-yubikey) by installing a mock `age-plugin-foobar` executable on
//! PATH that fails in controlled ways, and asserting git-agecrypt always fails CLOSED:
//! unlock must error out, the working tree must remain ciphertext, no key material may be
//! persisted, and no plaintext may leak to stdout/stderr.

mod common;

use common::*;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

/// Valid default plugin identity for a plugin named "foobar" (empty data segment,
/// bech32 HRP `age-plugin-foobar-`). Constant taken from the age crate's own test suite,
/// so it is guaranteed to parse as a plugin identity.
const FOOBAR_PLUGIN_IDENTITY: &str = "AGE-PLUGIN-FOOBAR-1QVHULF";

const CANARY: &str = "PLUGIN_FAIL_CANARY_TOKEN_VALUE";

/// Sets up a locked repository containing one committed secret, plus a plugin identity
/// file. Returns (tempdir guard, repo path, real secret identity).
fn setup_locked_repo() -> (tempfile::TempDir, std::path::PathBuf, String) {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path().to_path_buf();
    init_repo(&repo);

    agecrypt_cmd(&repo).arg("init").assert().success();
    let (sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(&repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "token_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    fs::write(
        repo.join("token.secret.env"),
        format!("{CANARY}=hardware_protected\n"),
    )
    .unwrap();
    run_git(
        &repo,
        &["add", ".gitattributes", ".git-agecrypt", "token.secret.env"],
    );
    run_git(&repo, &["commit", "-m", "Token secret commit"]);

    agecrypt_cmd(&repo).args(["lock", "-f"]).assert().success();

    // Sanity: the secret is ciphertext at rest before we attempt anything.
    let disk = fs::read(repo.join("token.secret.env")).unwrap();
    assert!(
        disk.starts_with(b"age-encryption.org/v1\n"),
        "precondition: secret must be locked ciphertext"
    );

    fs::write(
        repo.join("plugin_identity.txt"),
        format!("{FOOBAR_PLUGIN_IDENTITY}\n"),
    )
    .unwrap();

    (temp, repo, sec_id)
}

/// Asserts the fail-closed contract after a failed plugin-mediated unlock attempt.
fn assert_fail_closed(
    repo: &Path,
    ciphertext_before: &[u8],
    out: &std::process::Output,
    ctx: &str,
) {
    assert!(
        !out.status.success(),
        "{ctx}: unlock must FAIL when the hardware token / plugin is unavailable or broken"
    );

    // Working tree secret must be byte-for-byte unchanged (still ciphertext).
    let disk = fs::read(repo.join("token.secret.env")).unwrap();
    assert_eq!(
        disk, ciphertext_before,
        "{ctx}: working tree secret must remain untouched ciphertext after failed unlock"
    );

    // No plaintext may leak to stdout/stderr.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains(CANARY),
        "{ctx}: plaintext canary leaked to stdout"
    );
    assert!(
        !stderr.contains(CANARY),
        "{ctx}: plaintext canary leaked to stderr"
    );

    // No dangling temp/locking artifacts in the local state dir.
    let state_dir = repo.join(".git").join("git-agecrypt");
    if state_dir.exists() {
        for entry in fs::read_dir(&state_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.contains(".tmp") && !name.ends_with(".locking"),
                "{ctx}: dangling transient artifact left in state dir: {name}"
            );
        }
    }
}

/// Asserts the repository is still fully functional after a failed plugin attempt:
/// a subsequent unlock with the real identity must succeed and restore plaintext.
fn assert_recovery(repo: &Path, sec_id: &str, ctx: &str) {
    let out = agecrypt_assert_cmd(repo)
        .args(["unlock", "-"])
        .write_stdin(sec_id.as_bytes())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{ctx}: recovery unlock with real identity must succeed"
    );
    let disk = fs::read_to_string(repo.join("token.secret.env")).unwrap();
    assert_eq!(
        disk,
        format!("{CANARY}=hardware_protected\n"),
        "{ctx}: recovery unlock must restore exact plaintext"
    );
}
/// Builds a PATH value with the plugin dir and the git-agecrypt bin dir prepended.
fn plugin_path_env(plugin_dir: &Path) -> OsString {
    let mut paths = vec![plugin_dir.to_path_buf(), bin_dir()];
    if let Some(cur) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&cur));
    }
    std::env::join_paths(paths).unwrap_or_default()
}

/// Writes the mock plugin script. Modes:
/// - `exit1`:   exits 1 immediately (token removed / PIN rejected).
/// - `garbage`: prints a non-stanza line and exits 0 (protocol desync).
/// - `empty`:   exits 0 with no output (silent success / crashed UI helper).
/// - `partial`: writes a truncated stanza, then closes stdout (torn IPC stream).
/// - `slow`:    sleeps 2s then fails (slow token confirmation timeout).
#[cfg(unix)]
fn write_mock_plugin_script(plugin_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let script = r#"#!/bin/sh
case "$MOCKFAIL_MODE" in
  exit1)   exit 1 ;;
  garbage) echo "THIS_IS_NOT_A_STANZA $$"; exit 0 ;;
  empty)   exit 0 ;;
  partial) printf -- '-> partial-stanza'; exit 0 ;;
  slow)    sleep 2; exit 1 ;;
  *)       exit 2 ;;
esac
"#;
    let path = plugin_dir.join("age-plugin-foobar");
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
}

#[cfg(windows)]
fn write_mock_plugin_script(plugin_dir: &Path) {
    let script = "@echo off\r\n\
if \"%MOCKFAIL_MODE%\"==\"exit1\" exit /b 1\r\n\
if \"%MOCKFAIL_MODE%\"==\"garbage\" goto garbage\r\n\
if \"%MOCKFAIL_MODE%\"==\"empty\" exit /b 0\r\n\
if \"%MOCKFAIL_MODE%\"==\"partial\" goto partial\r\n\
if \"%MOCKFAIL_MODE%\"==\"slow\" goto slow\r\n\
exit /b 2\r\n\
:garbage\r\n\
echo THIS_IS_NOT_A_STANZA\r\n\
exit /b 0\r\n\
:partial\r\n\
<nul set /p \"=-> partial-stanza\"\r\n\
exit /b 0\r\n\
:slow\r\n\
timeout /t 2 /nobreak >nul\r\n\
exit /b 1\r\n";
    fs::write(plugin_dir.join("age-plugin-foobar.bat"), script).unwrap();
}

/// Installs a copy of the git-agecrypt binary as `age-plugin-foobar`: a real executable
/// that speaks no plugin protocol (prints CLI usage noise, exits non-zero).
fn write_rogue_exe_plugin(plugin_dir: &Path) {
    let src = assert_cmd::cargo::cargo_bin("git-agecrypt");
    let name = if cfg!(windows) {
        "age-plugin-foobar.exe"
    } else {
        "age-plugin-foobar"
    };
    fs::copy(&src, plugin_dir.join(name)).expect("Failed to install rogue plugin exe");
}

#[test]
fn test_plugin_binary_missing_fails_closed() {
    let (_temp, repo, sec_id) = setup_locked_repo();
    let ciphertext_before = fs::read(repo.join("token.secret.env")).unwrap();

    // No age-plugin-foobar exists anywhere on PATH: mirrors "token unplugged".
    let out = agecrypt_cmd(&repo)
        .args(["unlock", "plugin_identity.txt"])
        .output()
        .unwrap();

    assert_fail_closed(&repo, &ciphertext_before, &out, "missing plugin binary");
    assert_recovery(&repo, &sec_id, "missing plugin binary");
}

#[test]
fn test_plugin_rogue_executable_fails_closed() {
    let (_temp, repo, sec_id) = setup_locked_repo();
    let ciphertext_before = fs::read(repo.join("token.secret.env")).unwrap();

    let plugin_dir = repo.join("pluginbin_rogue");
    fs::create_dir_all(&plugin_dir).unwrap();
    write_rogue_exe_plugin(&plugin_dir);

    let out = agecrypt_cmd(&repo)
        .args(["unlock", "plugin_identity.txt"])
        .env("PATH", plugin_path_env(&plugin_dir))
        .output()
        .unwrap();

    assert_fail_closed(&repo, &ciphertext_before, &out, "rogue plugin executable");
    assert_recovery(&repo, &sec_id, "rogue plugin executable");
}

#[test]
fn test_plugin_ipc_failure_matrix() {
    for mode in ["exit1", "garbage", "empty", "partial", "slow"] {
        let (_temp, repo, sec_id) = setup_locked_repo();
        let ciphertext_before = fs::read(repo.join("token.secret.env")).unwrap();

        let plugin_dir = repo.join(format!("pluginbin_{mode}"));
        fs::create_dir_all(&plugin_dir).unwrap();
        write_mock_plugin_script(&plugin_dir);

        let out = agecrypt_cmd(&repo)
            .args(["unlock", "plugin_identity.txt"])
            .env("PATH", plugin_path_env(&plugin_dir))
            .env("MOCKFAIL_MODE", mode)
            .output()
            .unwrap();

        assert_fail_closed(
            &repo,
            &ciphertext_before,
            &out,
            &format!("plugin mode {mode}"),
        );
        assert_recovery(&repo, &sec_id, &format!("plugin mode {mode}"));
    }
}
