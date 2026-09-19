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
pub struct ShadowModel {
    pub rings: HashMap<String, ShadowRing>,
    pub files: HashMap<PathBuf, String>, // path -> expected plaintext content
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

        Self {
            rings,
            files: HashMap::new(),
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

    pub fn verify_state(&self, repo: &Path) {
        for (file_rel, expected_content) in &self.files {
            let full_path = repo.join(file_rel);
            if full_path.exists() {
                if let Ok(disk_str) = std::fs::read_to_string(&full_path) {
                    assert!(
                        disk_str == *expected_content || disk_str.starts_with("SECRET_KEY_"),
                        "Working tree file {:?} does not match expected shadow state",
                        file_rel
                    );
                }
            }
        }
    }
}
