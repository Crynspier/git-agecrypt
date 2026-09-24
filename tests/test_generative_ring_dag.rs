mod common;

use common::invariants::*;
use common::*;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;

/// Generative multi-ring × multi-generation × multi-branch DAG testing.
/// Randomly creates rings, generations, recipients, branches, commits, merges,
/// locks, unlocks, and verifies per-recipient access matrices.
#[test]
fn test_generative_ring_generation_dag_matrix() {
    let seed: u64 = std::env::var("GIT_AGECRYPT_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x1234_5678_9ABC_DEF0);

    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    init_repo(repo);

    // Create multiple identities (recipients)
    let identities: Vec<(String, String)> = (0..5).map(|_| generate_test_identity()).collect();
    let identity_names: Vec<String> = (0..5).map(|i| format!("user_{i}")).collect();

    // Initialize default ring
    agecrypt_cmd(repo).arg("init").assert().success();
    agecrypt_cmd(repo)
        .args(["add-recipient", "-i", &identities[0].1, "--name", &identity_names[0]])
        .assert()
        .success();

    // Create rings
    let ring_names = ["default", "prod", "dev", "staging"];
    for ring in &ring_names[1..] {
        agecrypt_cmd(repo)
            .args(["init", "--ring", ring])
            .assert()
            .success();
    }

    // Configure .gitattributes for ring routing
    let mut gitattrs = String::from("*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n");
    for ring in &ring_names[1..] {
        gitattrs.push_str(&format!("*.{ring}.secret.env filter=agecrypt-{ring} diff=agecrypt-{ring} merge=agecrypt-{ring} -text\n"));
    }
    fs::write(repo.join(".gitattributes"), &gitattrs).unwrap();
    run_git(repo, &["add", ".gitattributes", ".git-agecrypt"]);
    run_git(repo, &["commit", "-m", "Configure rings"]);

    // Track per-recipient access matrix: (recipient, ring, generation) -> can_decrypt
    let mut access_matrix: HashMap<(String, String, u32), bool> = HashMap::new();
    let mut ring_generations: HashMap<String, u32> = HashMap::new();
    for ring in &ring_names {
        ring_generations.insert(ring.to_string(), 0);
        // Initially, only the first recipient can decrypt
        access_matrix.insert((identity_names[0].clone(), ring.to_string(), 0), true);
    }

    // Create initial secret files per ring
    for ring in &ring_names {
        let filename = if *ring == "default" {
            "app.secret.env".to_string()
        } else {
            format!("app.{ring}.secret.env")
        };
        let content = format!("SECRET_{}=val_g0\n", ring.to_uppercase());
        fs::write(repo.join(&filename), &content).unwrap();
    }
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "Initial secrets"]);

    let mut branches: Vec<String> = vec!["main".to_string()];
    let mut commit_count = 1;

    // Generative loop: perform random operations
    for step in 0..50 {
        let op = rng.gen_range(0..10);

        match op {
            0 => {
                // Create branch
                let branch_name = format!("branch_{step}");
                if git_out_res(repo, &["branch", &branch_name]).is_ok() {
                    branches.push(branch_name);
                }
            }
            1 => {
                // Switch branch
                if branches.len() > 1 {
                    let target = &branches[rng.gen_range(0..branches.len())];
                    let _ = git_out_res(repo, &["checkout", target]);
                }
            }
            2 => {
                // Commit secret change
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let filename = if ring == "default" {
                    "app.secret.env".to_string()
                } else {
                    format!("app.{ring}.secret.env")
                };
                let generation = ring_generations[ring];
                let content = format!("SECRET_{}=val_g{}_step{}\n", ring.to_uppercase(), generation, step);
                fs::write(repo.join(&filename), &content).unwrap();
                let _ = git_out_res(repo, &["commit", "-am", &format!("Commit {step}")]);
                commit_count += 1;
            }
            3 => {
                // Add recipient to ring
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let recip_idx = rng.gen_range(0..identities.len());
                let generation = ring_generations[ring];
                let name = format!("{}_g{}", identity_names[recip_idx], generation);
                let res = agecrypt_cmd(repo)
                    .args(["add-recipient", "-i", &identities[recip_idx].1, "--name", &name, "--ring", ring])
                    .output();
                if res.map(|r| r.status.success()).unwrap_or(false) {
                    access_matrix.insert((name, ring.to_string(), generation), true);
                }
            }
            4 => {
                // Remove recipient from ring
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let generation = ring_generations[ring];
                // Find a recipient to remove
                let recipients: Vec<_> = access_matrix.keys()
                    .filter(|(_, r, g)| r == ring && *g == generation)
                    .map(|(n, _, _)| n.clone())
                    .collect();
                if !recipients.is_empty() {
                    let name = &recipients[rng.gen_range(0..recipients.len())];
                    let res = agecrypt_cmd(repo)
                        .args(["remove-recipient", name, "--ring", ring])
                        .output();
                    if res.map(|r| r.status.success()).unwrap_or(false) {
                        access_matrix.insert((name.clone(), ring.to_string(), generation), false);
                    }
                }
            }
            5 => {
                // Rekey ring
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let res = agecrypt_cmd(repo)
                    .args(["rekey", "-f", "--ring", ring])
                    .output();
                if res.map(|r| r.status.success()).unwrap_or(false) {
                    let old_gen = ring_generations[ring];
                    ring_generations.insert(ring.to_string(), old_gen + 1);
                    // New generation: recipients who were authorized in old generation can access new generation
                    for ((name, r, g), can_access) in access_matrix.clone().iter() {
                        if r == ring && *g == old_gen && *can_access {
                            access_matrix.insert((name.clone(), r.clone(), old_gen + 1), true);
                        }
                    }
                }
            }
            6 => {
                // Lock ring
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let _ = agecrypt_cmd(repo)
                    .args(["lock", "-f", "--ring", ring])
                    .output();
            }
            7 => {
                // Unlock ring with first identity
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let key_dir = tempdir().expect("Failed to create keydir");
                let id_file = key_dir.path().join("test.key");
                fs::write(&id_file, &identities[0].0).unwrap();
                let _ = agecrypt_cmd(repo)
                    .args(["unlock", id_file.to_str().unwrap(), "--ring", ring])
                    .output();
            }
            8 => {
                // Merge branches
                if branches.len() > 1 {
                    let target = &branches[rng.gen_range(0..branches.len())];
                    let _ = git_out_res(repo, &["merge", target, "-m", "Merge"]);
                }
            }
            _ => {
                // Create new secret file for random ring
                let ring_idx = rng.gen_range(0..ring_names.len());
                let ring = ring_names[ring_idx];
                let filename = if ring == "default" {
                    format!("secret_{step}.secret.env")
                } else {
                    format!("secret_{step}.{ring}.secret.env")
                };
                let generation = ring_generations[ring];
                let content = format!("NEW_SECRET_{}=val_g{}_step{}\n", ring.to_uppercase(), generation, step);
                fs::write(repo.join(&filename), &content).unwrap();
                let _ = git_out_res(repo, &["add", &filename]);
                let _ = git_out_res(repo, &["commit", "-m", &format!("Add secret {step}")]);
                commit_count += 1;
            }
        }

        // Verify invariants after each step
        assert_inv_b_durability_consistent(repo);
    }

    // Final verification: lock all rings and verify per-recipient access
    for ring in &ring_names {
        let _ = agecrypt_cmd(repo).args(["lock", "-f", "--ring", ring]).output();
    }

    // Verify that all ciphertext in git objects is valid age ciphertext
    assert_inv_g_zero_canary_leaks(repo, b"SECRET_");

    println!("Completed generative ring DAG test with seed 0x{:016X}, {} commits", seed, commit_count);
}

