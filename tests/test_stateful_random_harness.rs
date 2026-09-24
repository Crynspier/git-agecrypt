mod common;

use common::*;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[derive(Debug, Clone)]
enum Operation {
    EditSecret(usize, String),
    GitAdd(usize),
    GitCommit(String),
    GitCreateBranch(String),
    GitSwitchBranch(String),
    GitStashPush,
    GitStashPop,
    GitRepack,
    AgecryptLock,
    AgecryptUnlock,
    AgecryptRekey,
}

#[test]
fn test_stateful_random_git_state_machine() {
    // M9: hard-fail on an unparsable seed instead of silently collapsing distinct
    // CI matrix legs onto the default seed.
    let seed: u64 = match std::env::var("GIT_AGECRYPT_SEED") {
        Ok(s) => s
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("GIT_AGECRYPT_SEED must be a decimal u64 (got '{s}')")),
        Err(_) => 0x4242_1337_CAFE_BABE,
    };

    println!("Starting stateful randomized harness with seed: 0x{seed:016X}");
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    let (user_sec, user_pub) = generate_test_identity();
    let key_dir = tempdir().expect("Failed to create keydir");
    let id_file = key_dir.path().join("test_user.key");
    fs::write(&id_file, &user_sec).unwrap();

    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &user_pub, "--name", "test_user"])
        .assert()
        .success();

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    run_git(repo, &["add", ".gitattributes"]);
    run_git(repo, &["commit", "-m", "Configure gitattributes"]);

    let secret_filenames = ["app.secret.env", "db.secret.env", "api.secret.env"];

    let mut shadow_files: HashMap<String, String> = HashMap::new();
    for name in &secret_filenames {
        let initial_content = format!("{name}_INITIAL=seed_{seed}\n");
        fs::write(repo.join(name), &initial_content).unwrap();
        shadow_files.insert(name.to_string(), initial_content);
    }
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Initial secrets commit"]);

    let mut branches = vec!["main".to_string()];
    let mut _current_branch = "main".to_string();
    let mut is_locked = false;
    let mut has_stash = false;
    let mut operation_history: Vec<(usize, Operation)> = Vec::new();

    let num_operations = 100;
    for op_idx in 0..num_operations {
        let op_choice = rng.gen_range(0..11);
        let op = match op_choice {
            0 => {
                let file_idx = rng.gen_range(0..secret_filenames.len());
                let new_line = format!("RANDOM_VAL_{op_idx}={}\n", rng.gen_range(1000..9999));
                Operation::EditSecret(file_idx, new_line)
            }
            1 => {
                let file_idx = rng.gen_range(0..secret_filenames.len());
                Operation::GitAdd(file_idx)
            }
            2 => {
                let msg = format!("Random commit at step {op_idx}");
                Operation::GitCommit(msg)
            }
            3 => {
                let branch_name = format!("branch_{op_idx}");
                Operation::GitCreateBranch(branch_name)
            }
            4 => {
                let target_branch = branches[rng.gen_range(0..branches.len())].clone();
                Operation::GitSwitchBranch(target_branch)
            }
            5 => Operation::GitStashPush,
            6 => Operation::GitStashPop,
            7 => Operation::GitRepack,
            8 => Operation::AgecryptLock,
            9 => Operation::AgecryptUnlock,
            _ => Operation::AgecryptRekey,
        };

        operation_history.push((op_idx, op.clone()));
        println!("Step {op_idx}: {op:?}");

        match &op {
            Operation::EditSecret(idx, content) => {
                if !is_locked {
                    let name = secret_filenames[*idx];
                    let file_path = repo.join(name);
                    let mut current = shadow_files.get(name).cloned().unwrap_or_default();
                    current.push_str(content);
                    fs::write(&file_path, &current).unwrap();
                    shadow_files.insert(name.to_string(), current);
                }
            }
            Operation::GitAdd(idx) => {
                let name = secret_filenames[*idx];
                let _ = run_git_output(repo, &["add", name]);
            }
            Operation::GitCommit(msg) => {
                let _ = run_git_output(repo, &["commit", "-m", msg]);
            }
            Operation::GitCreateBranch(b_name) => {
                let out = run_git_output(repo, &["branch", b_name]);
                if out.status.success() && !branches.contains(b_name) {
                    branches.push(b_name.clone());
                }
            }
            Operation::GitSwitchBranch(b_name) => {
                let out = run_git_output(repo, &["checkout", b_name]);
                if out.status.success() {
                    _current_branch = b_name.clone();
                    if !is_locked {
                        // Re-synchronize credentials in case checked-out branch has a different key generation
                        let _ = agecrypt_cmd(repo)
                            .args(["unlock", id_file.to_str().unwrap()])
                            .output();
                    }
                    for name in &secret_filenames {
                        let disk_path = repo.join(name);
                        if disk_path.exists() {
                            if let Ok(c) = fs::read_to_string(&disk_path) {
                                if !c.starts_with("age-encryption.org/v1\n") {
                                    shadow_files.insert(name.to_string(), c);
                                }
                            }
                        }
                    }
                }
            }
            Operation::GitStashPush => {
                if !is_locked {
                    let out = run_git_output(repo, &["stash", "push", "-m", "stateful stash"]);
                    if out.status.success() {
                        has_stash = true;
                    }
                }
            }
            Operation::GitStashPop => {
                if has_stash && !is_locked {
                    let out = run_git_output(repo, &["stash", "pop"]);
                    if out.status.success() {
                        has_stash = false;
                    } else {
                        // Conflict during stash pop: reset to HEAD and drop stash to maintain clean working tree
                        let _ = run_git_output(repo, &["reset", "--hard", "HEAD"]);
                        let _ = run_git_output(repo, &["stash", "drop"]);
                        has_stash = false;
                    }
                    for name in &secret_filenames {
                        let disk_path = repo.join(name);
                        if disk_path.exists() {
                            if let Ok(c) = fs::read_to_string(&disk_path) {
                                if !c.starts_with("age-encryption.org/v1\n") {
                                    shadow_files.insert(name.to_string(), c);
                                }
                            }
                        }
                    }
                }
            }
            Operation::GitRepack => {
                let _ = run_git_output(repo, &["repack", "-a", "-d"]);
            }
            Operation::AgecryptLock => {
                let out = agecrypt_cmd(repo).arg("lock").output().unwrap();
                if out.status.success() {
                    is_locked = true;
                }
            }
            Operation::AgecryptUnlock => {
                let mut unlock = agecrypt_cmd(repo);
                unlock.args(["unlock", id_file.to_str().unwrap()]);
                let out = unlock.output().unwrap();
                if out.status.success() {
                    is_locked = false;
                    for name in &secret_filenames {
                        let disk_path = repo.join(name);
                        if disk_path.exists() {
                            if let Ok(c) = fs::read_to_string(&disk_path) {
                                if !c.starts_with("age-encryption.org/v1\n") {
                                    shadow_files.insert(name.to_string(), c);
                                }
                            }
                        }
                    }
                }
            }
            Operation::AgecryptRekey => {
                if !is_locked {
                    let out = agecrypt_cmd(repo).args(["rekey", "-f"]).output().unwrap();
                    if out.status.success() {
                        let _ = run_git_output(repo, &["add", ".git-agecrypt"]);
                        let _ =
                            run_git_output(repo, &["commit", "-m", "Rotate repository master key"]);
                    }
                }
            }
        }

        // CONTINUOUS INVARIANT VERIFICATION
        assert_invariants_at_step(
            repo,
            &secret_filenames,
            &shadow_files,
            is_locked,
            op_idx,
            seed,
        );
    }

    println!("Successfully completed {num_operations} randomized state transitions!");
}

fn assert_invariants_at_step(
    repo: &Path,
    secret_files: &[&str],
    shadow_files: &HashMap<String, String>,
    is_locked: bool,
    step_idx: usize,
    seed: u64,
) {
    for name in secret_files {
        let file_path = repo.join(name);
        if !file_path.exists() {
            continue;
        }

        let disk_bytes = fs::read(&file_path).unwrap();
        let is_ciphertext = disk_bytes.starts_with(b"age-encryption.org/v1\n");

        if is_locked {
            assert!(
                is_ciphertext,
                "[Seed 0x{seed:016X}, Step {step_idx}] When locked, disk file '{name}' must be ciphertext"
            );
        } else {
            assert!(
                !is_ciphertext,
                "[Seed 0x{seed:016X}, Step {step_idx}] When unlocked, disk file '{name}' must be plaintext"
            );
            if let Err(e) = std::str::from_utf8(&disk_bytes) {
                panic!(
                    "[Seed 0x{seed:016X}, Step {step_idx}] Plaintext file '{name}' must be valid UTF-8 text (len: {}, err: {e}, bytes: {:?})",
                    disk_bytes.len(),
                    &disk_bytes[..disk_bytes.len().min(100)]
                );
            }
        }
    }

    // Git object store must NEVER hold plaintext (check every 10 steps and at the end)
    if step_idx % 10 == 0 || step_idx == 99 {
        let mut canaries = Vec::new();
        for content in shadow_files.values() {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("RANDOM_VAL_") {
                    canaries.push(trimmed);
                }
            }
        }
        if !canaries.is_empty() {
            assert_no_plaintext_in_git_objects(repo, &canaries);
        }
    }
}
