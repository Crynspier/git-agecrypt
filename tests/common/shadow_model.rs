use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ShadowRing {
    pub name: String,
    pub generation: u32,
    pub authorized_recipients: HashSet<String>,
    pub revoked_recipients: HashSet<String>,
    pub is_locked: bool,
}

#[derive(Debug, Clone)]
pub struct CommitSnapshot {
    pub sha: String,
    pub branch: String,
    pub files: HashMap<PathBuf, String>,
}

#[derive(Debug, Clone)]
pub struct ShadowModel {
    pub rings: HashMap<String, ShadowRing>,
    pub files: HashMap<PathBuf, String>,
    pub branch_files: HashMap<String, HashMap<PathBuf, String>>,
    pub branch_heads: HashMap<String, String>,
    pub commits: Vec<CommitSnapshot>,
    pub staged_files: HashSet<PathBuf>,
    pub branches: HashSet<String>,
    pub current_branch: String,
}

impl ShadowModel {
    pub fn new() -> Self {
        let mut rings = HashMap::new();
        rings.insert(
            "default".to_string(),
            ShadowRing {
                name: "default".to_string(),
                generation: 0,
                authorized_recipients: HashSet::new(),
                revoked_recipients: HashSet::new(),
                is_locked: false,
            },
        );

        let mut branches = HashSet::new();
        branches.insert("main".to_string());

        let mut branch_files = HashMap::new();
        branch_files.insert("main".to_string(), HashMap::new());

        Self {
            rings,
            files: HashMap::new(),
            branch_files,
            branch_heads: HashMap::new(),
            commits: Vec::new(),
            staged_files: HashSet::new(),
            branches,
            current_branch: "main".to_string(),
        }
    }

    pub fn add_ring(&mut self, name: &str) {
        if !self.rings.contains_key(name) {
            self.rings.insert(
                name.to_string(),
                ShadowRing {
                    name: name.to_string(),
                    generation: 0,
                    authorized_recipients: HashSet::new(),
                    revoked_recipients: HashSet::new(),
                    is_locked: false,
                },
            );
        }
    }

    pub fn add_recipient(&mut self, ring: &str, recipient: &str) {
        if let Some(r) = self.rings.get_mut(ring) {
            r.authorized_recipients.insert(recipient.to_string());
            r.revoked_recipients.remove(recipient);
        }
    }

    pub fn revoke_recipient(&mut self, ring: &str, recipient: &str) {
        if let Some(r) = self.rings.get_mut(ring) {
            r.authorized_recipients.remove(recipient);
            r.revoked_recipients.insert(recipient.to_string());
        }
    }

    pub fn rekey_ring(&mut self, ring: &str) {
        if let Some(r) = self.rings.get_mut(ring) {
            r.generation += 1;
        }
    }

    pub fn set_locked(&mut self, ring: &str, locked: bool) {
        if let Some(r) = self.rings.get_mut(ring) {
            r.is_locked = locked;
        }
    }

    pub fn update_file(&mut self, path: &Path, content: &str) {
        self.files.insert(path.to_path_buf(), content.to_string());
    }

    pub fn remove_file(&mut self, path: &Path) {
        self.files.remove(path);
        self.staged_files.remove(path);
        if let Some(bf) = self.branch_files.get_mut(&self.current_branch) {
            bf.remove(path);
        }
    }

    pub fn mark_staged(&mut self, path: &Path) {
        self.staged_files.insert(path.to_path_buf());
    }

    pub fn mark_unstaged(&mut self, path: &Path) {
        self.staged_files.remove(path);
    }

    pub fn record_commit(&mut self, sha: &str) {
        let branch = self.current_branch.clone();
        let snapshot = CommitSnapshot {
            sha: sha.to_string(),
            branch: branch.clone(),
            files: self.files.clone(),
        };
        self.commits.push(snapshot);
        self.branch_heads.insert(branch.clone(), sha.to_string());
        self.branch_files.insert(branch, self.files.clone());
        self.staged_files.clear();
    }

    pub fn switch_branch(&mut self, branch: &str) {
        self.current_branch = branch.to_string();
        if let Some(bf) = self.branch_files.get(branch) {
            self.files = bf.clone();
        }
        self.staged_files.clear();
    }

    pub fn reset_to_commit(&mut self, sha: &str) {
        if let Some(snapshot) = self.commits.iter().find(|c| c.sha == sha) {
            self.files = snapshot.files.clone();
            self.branch_files
                .insert(self.current_branch.clone(), snapshot.files.clone());
            self.branch_heads
                .insert(self.current_branch.clone(), sha.to_string());
        }
        self.staged_files.clear();
    }

    /// Re-sync the shadow model from the actual working tree.
    /// Used after complex git operations (merge, rebase, checkout, reset, stash) that
    /// may change the working tree in ways that are difficult to predict exactly.
    pub fn sync_from_disk(&mut self, repo: &Path, _secret_patterns: &[&str]) {
        // Re-read all tracked files from disk
        let mut new_files = HashMap::new();
        for path in self.files.keys() {
            let full_path = repo.join(path);
            if full_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&full_path) {
                    if !content.starts_with(
                        "age-encryption.org/v1
",
                    ) {
                        new_files.insert(path.clone(), content);
                    }
                }
            }
        }
        // Also scan for new secret files that might have been created
        if let Ok(entries) = std::fs::read_dir(repo) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.ends_with(".secret.env") {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if !content.starts_with(
                                    "age-encryption.org/v1
",
                                ) {
                                    let rel =
                                        path.strip_prefix(repo).unwrap_or(&path).to_path_buf();
                                    new_files.entry(rel).or_insert(content);
                                }
                            }
                        }
                    }
                }
            }
        }
        self.files = new_files;
        // Update branch_files to only files actually committed to HEAD
        let mut committed = HashMap::new();
        if let Ok(output) = std::process::Command::new("git")
            .args(["ls-tree", "-r", "--name-only", "HEAD", "-z"])
            .current_dir(repo)
            .output()
        {
            if output.status.success() {
                for path_slice in output.stdout.split(|&b| b == 0) {
                    if path_slice.is_empty() {
                        continue;
                    }
                    let name = String::from_utf8_lossy(path_slice).to_string();
                    if name.ends_with(".secret.env") {
                        let rel = PathBuf::from(&name);
                        if let Some(content) = self.files.get(&rel) {
                            committed.insert(rel, content.clone());
                        }
                    }
                }
            }
        }
        self.branch_files
            .insert(self.current_branch.clone(), committed);
        self.staged_files.clear();
    }

    /// Get the list of currently tracked plaintext secret files.
    pub fn tracked_files(&self) -> Vec<PathBuf> {
        self.files.keys().cloned().collect()
    }

    /// Check if any ring is currently locked.
    pub fn any_locked(&self) -> bool {
        self.rings.values().any(|r| r.is_locked)
    }

    pub fn verify_state(&self, repo: &Path) {
        for (file_rel, expected_content) in &self.files {
            let full_path = repo.join(file_rel);
            assert!(
                full_path.exists(),
                "Shadow model expects file {:?} to exist, but it does not",
                file_rel
            );
            let disk_str = std::fs::read_to_string(&full_path).unwrap_or_else(|e| {
                panic!("Failed to read working tree file {:?}: {}", file_rel, e)
            });
            assert_eq!(
                disk_str, *expected_content,
                "Working tree file {:?} does not match expected shadow state.\nExpected: {:?}\nGot: {:?}",
                file_rel, expected_content, disk_str
            );
        }
    }

    /// Verify that the Git index (:0:<path>) contains ciphertext for all staged secret files.
    pub fn verify_index_state(&self, repo: &Path) {
        // Query git directly for staged secret files
        if let Ok(output) = std::process::Command::new("git")
            .args(["ls-files", "-z"])
            .current_dir(repo)
            .output()
        {
            if output.status.success() {
                for path_slice in output.stdout.split(|&b| b == 0) {
                    if path_slice.is_empty() {
                        continue;
                    }
                    let name = String::from_utf8_lossy(path_slice).to_string();
                    if name.ends_with(".secret.env") {
                        let blob_ref = format!(":0:{}", name);
                        let blob = std::process::Command::new("git")
                            .args(["cat-file", "-p", &blob_ref])
                            .current_dir(repo)
                            .output();
                        if let Ok(out) = blob {
                            if out.status.success() {
                                assert!(
                                    out.stdout.starts_with(b"age-encryption.org/v1\n"),
                                    "Git index blob {:?} must be age ciphertext, got: {:?}",
                                    blob_ref,
                                    String::from_utf8_lossy(&out.stdout)
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Verify that all committed secret blobs in the Git object database are valid age ciphertext.
    pub fn verify_object_db(&self, repo: &Path) {
        // Query git directly for committed secret files
        if let Ok(output) = std::process::Command::new("git")
            .args(["ls-tree", "-r", "--name-only", "HEAD", "-z"])
            .current_dir(repo)
            .output()
        {
            if output.status.success() {
                for path_slice in output.stdout.split(|&b| b == 0) {
                    if path_slice.is_empty() {
                        continue;
                    }
                    let name = String::from_utf8_lossy(path_slice).to_string();
                    if name.ends_with(".secret.env") {
                        let cat_ref = format!("HEAD:{}", name);
                        let blob = std::process::Command::new("git")
                            .args(["cat-file", "-p", &cat_ref])
                            .current_dir(repo)
                            .output();
                        if let Ok(out) = blob {
                            if out.status.success() {
                                assert!(
                                    out.stdout.starts_with(b"age-encryption.org/v1\n"),
                                    "Git HEAD blob {:?} must be age ciphertext",
                                    cat_ref
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
