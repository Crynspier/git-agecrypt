mod common;

use common::invariants::*;
use common::shadow_model::*;
use common::*;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_deep_generative_shadow_model_state_machine() {
    let seed: u64 = std::env::var("GIT_AGECRYPT_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xDEAD_BEEF_CAFE_1234);

    let op_count: usize = std::env::var("GIT_AGECRYPT_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    let mut shadow = ShadowModel::new();

    // 1. Initial configuration
    agecrypt_cmd(repo).arg("init").assert().success();
    let (sec_id, pub_key) = generate_test_identity();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &pub_key, "--name", "shadow_user"])
        .assert()
        .success();
    shadow.add_recipient("default", "shadow_user");

    fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();

    let initial_files = ["api.secret.env", "db.secret.env", "app.secret.env"];
    for (i, f) in initial_files.iter().enumerate() {
        let content = format!("SECRET_KEY_{i}=initial_val_{i}\n");
        fs::write(repo.join(f), &content).unwrap();
        shadow.update_file(&repo.join(f), &content);
    }

    run_git(
        repo,
        &[
            "add",
            ".gitattributes",
            ".git-agecrypt",
            "api.secret.env",
            "db.secret.env",
            "app.secret.env",
        ],
    );
    run_git(repo, &["commit", "-m", "Initial secret commit"]);

    let rings = ["default", "prod", "dev"];
    let canary_token = b"SHADOW_STATE_CANARY_CHECK";

    // 2. State Machine Transition Loop
    for step in 0..op_count {
        let action_type = rng.gen_range(0..10);

        match action_type {
            0 => {
                // Edit Secret
                let file_idx = rng.gen_range(0..initial_files.len());
                let file_name = initial_files[file_idx];
                let new_val = format!(
                    "SECRET_KEY_{file_idx}=val_step_{step}_{}\n",
                    rng.gen_range(1000..9999)
                );
                fs::write(repo.join(file_name), &new_val).unwrap();
                shadow.update_file(&repo.join(file_name), &new_val);
            }
            1 => {
                // Git Add
                let file_idx = rng.gen_range(0..initial_files.len());
                let file_name = initial_files[file_idx];
                run_git(repo, &["add", file_name]);
            }
            2 => {
                // Git Commit
                let commit_msg = format!("Commit at step {step}");
                let _ = git_out_res(repo, &["commit", "-am", &commit_msg]);
            }
            3 => {
                // Create / Switch Branch
                let branch_name = format!("branch_{}", rng.gen_range(1..5));
                if !shadow.branches.contains(&branch_name) {
                    let _ = git_out_res(repo, &["branch", &branch_name]);
                    shadow.branches.insert(branch_name.clone());
                }
                let switch_res = git_out_res(repo, &["checkout", &branch_name]);
                if switch_res.is_ok() {
                    shadow.current_branch = branch_name;
                }
            }
            4 => {
                // Switch back to main
                let _ = git_out_res(repo, &["checkout", "main"]);
                shadow.current_branch = "main".to_string();
            }
            5 => {
                // Init Ring
                let ring_idx = rng.gen_range(1..rings.len());
                let ring_name = rings[ring_idx];
                let init_out = agecrypt_cmd(repo)
                    .args(["init", "--ring", ring_name])
                    .output();
                if let Ok(res) = init_out {
                    if res.status.success() {
                        shadow.add_ring(ring_name);
                    }
                }
            }
            6 => {
                // Lock Ring
                let ring_idx = rng.gen_range(0..rings.len());
                let ring_name = rings[ring_idx];
                let lock_out = agecrypt_cmd(repo)
                    .args(["lock", "-f", "--ring", ring_name])
                    .output();
                if let Ok(res) = lock_out {
                    if res.status.success() {
                        shadow.set_locked(ring_name, true);
                    }
                }
            }
            7 => {
                // Unlock Ring
                let ring_idx = rng.gen_range(0..rings.len());
                let ring_name = rings[ring_idx];
                let unlock_out = agecrypt_assert_cmd(repo)
                    .args(["unlock", "-", "--ring", ring_name])
                    .write_stdin(sec_id.as_bytes())
                    .output();
                if let Ok(res) = unlock_out {
                    if res.status.success() {
                        shadow.set_locked(ring_name, false);
                    }
                }
            }
            8 => {
                // Stash Push & Pop
                let _ = git_out_res(repo, &["stash"]);
                let pop_res = git_out_res(repo, &["stash", "pop"]);
                if pop_res.is_err() {
                    let _ = git_out_res(repo, &["reset", "--hard", "HEAD"]);
                    let _ = git_out_res(repo, &["stash", "drop"]);
                }
            }
            _ => {
                // Rekey
                let rekey_res = agecrypt_cmd(repo).args(["rekey", "-f"]).output();
                if let Ok(res) = rekey_res {
                    if res.status.success() {
                        shadow.rekey_ring("default");
                    }
                }
            }
        }

        // Invariant checks at each transition step
        assert_inv_b_durability_consistent(repo);
        assert_inv_g_zero_canary_leaks(repo, canary_token);
    }

    // Final shadow state validation
    shadow.verify_state(repo);
}
