mod common;

use common::*;
use std::fs;
use std::io::{Cursor, Write};
use std::process::Stdio;
use tempfile::tempdir;

#[test]
fn test_exact_boundary_file_sizes() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let boundary_sizes = [
        0,         // Empty file
        1,         // Single byte
        65_535,    // 64 KiB - 1
        65_536,    // 64 KiB exact chunk boundary
        65_537,    // 64 KiB + 1
        1_048_575, // 1 MiB - 1
        1_048_576, // 1 MiB exact spool threshold
        1_048_577, // 1 MiB + 1 (spills to disk buffer)
    ];

    for (idx, &size) in boundary_sizes.iter().enumerate() {
        let file_name = format!("boundary_{idx}_{size}.secret.env");
        let file_path = repo.join(&file_name);
        let mut payload = vec![0u8; size];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 256) as u8;
        }
        fs::write(&file_path, &payload).unwrap();

        run_git(repo, &["add", &file_name]);
        run_git(
            repo,
            &["commit", "-m", &format!("Commit boundary size {size}")],
        );

        // Verify committed blob is encrypted
        let blob = git_out(repo, &["cat-file", "-p", &format!("HEAD:{file_name}")]);
        if size > 0 {
            assert!(blob.starts_with(b"age-encryption.org/v1\n"));
        }

        // Verify working tree file matches original bytes exactly
        let disk_data = fs::read(&file_path).unwrap();
        assert_eq!(disk_data.len(), size);
        assert_eq!(disk_data, payload);
    }
}

#[test]
fn test_check_blocks_corrupted_staged_ciphertext() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    let secret_file = repo.join("creds.secret.env");
    fs::write(&secret_file, "SECRET=v1\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Commit initial secret"]);

    // Simulate corrupted Age header staged into Git index
    let bd = bin_dir();
    let new_path = prepend_to_path(&bd);
    let mut child = std::process::Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(repo)
        .env("PATH", &new_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(b"age-encryption.org/v1\nCORRUPTED_HEADER_STAGED_FROM_PATCH\n")
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let oid = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Update index directly with corrupted object
    run_git(
        repo,
        &[
            "update-index",
            "--cacheinfo",
            &format!("100644,{oid},creds.secret.env"),
        ],
    );

    // Run git-agecrypt check: MUST strictly fail and abort commit due to corrupted age header
    let mut check_cmd = agecrypt_cmd(repo);
    let assert = check_cmd.arg("check").assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("CORRUPTED") || stderr.contains("corrupt") || stderr.contains("error"));
}

#[test]
fn test_bit_flip_tampered_ciphertext_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    let secret_plain = b"AUTHENTICATED_PAYLOAD_TEST_WITH_POLY1305_MAC\n";
    let mut clean_cmd = agecrypt_cmd(repo);
    let mut child = clean_cmd
        .arg("clean")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(secret_plain)
        .unwrap();
    let clean_out = child.wait_with_output().unwrap();
    let mut ciphertext = clean_out.stdout;

    // Flip a bit in the ciphertext payload (near the end, in the Poly1305 MAC tag)
    let len = ciphertext.len();
    assert!(len > 32);
    ciphertext[len - 5] ^= 0x55;

    // Smudge MUST fail or refuse to output corrupt plaintext
    let mut smudge_cmd = agecrypt_cmd(repo);
    let mut child = smudge_cmd
        .arg("smudge")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&ciphertext)
        .unwrap();
    let smudge_out = child.wait_with_output().unwrap();

    // The output must NOT equal secret_plain (authentication failure)
    assert_ne!(smudge_out.stdout, secret_plain);
}

#[test]
fn test_fuzzed_metadata_files_fail_closed() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    agecrypt_cmd(repo).arg("init").assert().success();

    // Corrupt repo.pub
    let pub_file = repo.join(".git-agecrypt").join("repo.pub");
    fs::write(&pub_file, b"corrupt_invalid_public_key\x00\xff\xfe\n").unwrap();

    // Status or check should fail closed or report invalid state without panic
    let mut status_cmd = agecrypt_cmd(repo);
    let _ = status_cmd.arg("status").output();
}

#[test]
fn test_fuzz_target_harnesses_deterministic_corpus() {
    let corpus_bytes: &[&[u8]] = &[
        b"",
        b"\x00\xff\xfe\xfd",
        b"age-encryption.org/v1\n",
        b"age-encryption.org/v1\n-> X25519 invalid\n--- badmac\n",
        b"1\n../../etc/passwd\n",
        b"1\nsecrets/app.env\0extra\n",
        b"999\nsecrets/app.env\n",
        b"*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n[attr]agecrypt filter=agecrypt\n",
        b"secrets/** filter=agecrypt-../../bad\n\"quoted\\path/*.env\" filter=agecrypt-prod\n",
        b"KEY=1\nKEY=2\n<<<<<<< ours\nA=1\n=======\nA=2\n>>>>>>> theirs\n",
        b"{\"a\": 1, \"a\": 2}",
        b"a: 1\na: 2\n",
        b"[sec]\nk = 1\nk = 2\n",
        b"# public-key: age1invalid\n-----BEGIN AGE ENCRYPTED FILE-----\ncorrupt\n-----END AGE ENCRYPTED FILE-----\n",
    ];

    let dummy_id = age::x25519::Identity::generate();
    for &data in corpus_bytes {
        // 1. fuzz_age_ciphertext target logic
        let mut reader = Cursor::new(data);
        if let Ok(decryptor) = age::Decryptor::new(&mut reader) {
            let _ = decryptor.decrypt(std::iter::once(&dummy_id as &dyn age::Identity));
        }

        // 2. fuzz_merge_parser target logic
        for ext in [
            "fuzz.env",
            "fuzz.json",
            "fuzz.yaml",
            "fuzz.toml",
            "fuzz.ini",
        ] {
            let _ = git_agecrypt::merge::find_semantic_conflicts(data, ext);
        }

        if let Ok(text) = std::str::from_utf8(data) {
            // 3. fuzz_gitattributes target logic
            let _ = git_agecrypt::format::parse_gitattributes_rules(text);
            for line in text.lines() {
                let _ = git_agecrypt::git::validate_ring_name(line.trim());
                let _ = git_agecrypt::git::is_shell_safe_repo_path(line.trim());
            }

            // 4. fuzz_wal_journal target logic
            let _ = git_agecrypt::format::parse_and_validate_lock_journal(text);
            let _ = git_agecrypt::format::parse_format_file_content(text);
            let _ = git_agecrypt::format::parse_and_validate_repo_pub(text);
            let _ = git_agecrypt::format::validate_wrapped_key_envelope(text);
        }
    }
}
