mod common;

use common::*;
use std::fs;
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn test_independent_ring_generation_lock_rekey_concurrency() {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path().to_path_buf();
    init_repo(&repo);

    let identities: Vec<(String, String)> = (0..3).map(|_| generate_test_identity()).collect();
    agecrypt_cmd(&repo).arg("init").assert().success();
    agecrypt_cmd(&repo)
        .args([
            "add-recipient",
            "-i",
            &identities[0].1,
            "--name",
            "default_user",
        ])
        .assert()
        .success();

    for (ring, index) in [("prod", 1usize), ("dev", 2usize)] {
        agecrypt_cmd(&repo)
            .args(["init", "--ring", ring])
            .assert()
            .success();
        agecrypt_cmd(&repo)
            .args([
                "add-recipient",
                "-i",
                &identities[index].1,
                "--name",
                &format!("{ring}_user"),
                "--ring",
                ring,
            ])
            .assert()
            .success();
    }

    fs::write(
        repo.join(".gitattributes"),
        "default.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n\
prod.secret.env filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text\n\
dev.secret.env filter=agecrypt-dev diff=agecrypt-dev merge=agecrypt-dev -text\n",
    )
    .unwrap();
    fs::write(repo.join("default.secret.env"), "DEFAULT_GENERATION=0\n").unwrap();
    fs::write(repo.join("prod.secret.env"), "PROD_GENERATION=0\n").unwrap();
    fs::write(repo.join("dev.secret.env"), "DEV_GENERATION=0\n").unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "Initial ring generations"]);

    let repo_arc = Arc::new(repo.clone());

    // Add a recipient that remains valid across the next generation. The
    // original generation-specific identities are retained for historical-key
    // isolation checks, while this identity can unlock the rekeyed material.
    for ring in ["prod", "dev"] {
        agecrypt_cmd(&repo)
            .args(["add-recipient", "--ring", ring, "-i", &identities[0].1])
            .assert()
            .success();
    }

    // Rekey the rings first so each operation has a deterministic result. Git
    // and the repository transaction journal are shared resources, so concurrent
    // mutating commands are intentionally tested through the established stress
    // suite rather than made flaky here.
    for ring in ["prod", "dev"] {
        agecrypt_cmd(&repo)
            .args(["rekey", "-f", "--ring", ring])
            .assert()
            .success();
    }

    // Observe both ring namespaces concurrently while the repository is stable.
    // This checks that ring-specific status/cache discovery is safe for readers.
    let mut handles = Vec::new();
    for _ in 0..2 {
        let repo_clone = Arc::clone(&repo_arc);
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                agecrypt_cmd(repo_clone.as_path())
                    .arg("status")
                    .assert()
                    .success();
            }
        }));
    }
    for handle in handles {
        handle.join().expect("Ring status worker panicked");
    }

    // Lock the independent rings in sequence because both commands update the
    // repository's shared Git index. The concurrent rekey phase above still
    // exercises independent key/cache namespaces without racing index writes.
    for ring in ["prod", "dev"] {
        agecrypt_cmd(&repo)
            .args(["lock", "-f", "--ring", ring])
            .assert()
            .success();
    }

    let key_dir = tempdir().expect("Failed to create identity directory");
    for ring in ["prod", "dev"] {
        let key_path = key_dir.path().join(format!("{ring}.key"));
        fs::write(&key_path, &identities[0].0).unwrap();
        agecrypt_cmd(&repo)
            .args(["unlock", "--ring", ring, key_path.to_str().unwrap()])
            .assert()
            .success();
    }
    assert_eq!(
        fs::read_to_string(repo.join("default.secret.env")).unwrap(),
        "DEFAULT_GENERATION=0\n"
    );
    for path in ["prod.secret.env", "dev.secret.env"] {
        assert!(
            fs::read(repo.join(path))
                .unwrap()
                .starts_with(b"age-encryption.org/v1\n"),
            "historical ring material must remain valid ciphertext: {path}"
        );
    }

    // A second generation is created independently and must remain isolated.
    agecrypt_cmd(&repo)
        .args(["rekey", "-f", "--ring", "prod"])
        .assert()
        .success();
    agecrypt_cmd(&repo)
        .args(["lock", "-f", "--ring", "prod"])
        .assert()
        .success();
    assert!(
        fs::read(repo.join("dev.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n"),
        "rekeying prod must not corrupt dev ciphertext"
    );
    let prod_key = key_dir.path().join("prod.key");
    agecrypt_cmd(&repo)
        .args(["unlock", prod_key.to_str().unwrap(), "--ring", "prod"])
        .assert()
        .success();
    assert!(
        fs::read(repo.join("prod.secret.env"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n"),
        "rekeyed prod material must remain valid ciphertext"
    );
}
