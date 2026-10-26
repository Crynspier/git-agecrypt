use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use zeroize::Zeroizing;

use crate::crypto::{self, AGE_HEADER_MAGIC, is_age_ciphertext};
use crate::git::{GitRepo, ensure_not_symlink_or_reparse, validate_ring_name};

/// Current repository metadata and local state format version.
pub const FORMAT_VERSION: u32 = 1;

/// Source from which the repository format version was determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatVersionSource {
    ImplicitV1,
    ExplicitFile,
    HeaderComment,
}

impl FormatVersionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ImplicitV1 => "implicit-v1",
            Self::ExplicitFile => "explicit-file",
            Self::HeaderComment => "header-comment",
        }
    }
}

/// Inspection result for a single enrolled recipient envelope (`.git-agecrypt/keys/*.age`).
#[derive(Debug, Clone)]
pub struct RecipientInspection {
    pub name: String,
    pub relative_path: String,
    pub public_key: Option<String>,
    pub recipient_type: String,
    pub armor_valid: bool,
    pub format_version: Option<u32>,
    pub issues: Vec<String>,
}

/// Inspection result for a tracked secret file across working tree and Git index.
#[derive(Debug, Clone)]
pub struct TrackedFileInspection {
    pub path: String,
    pub ring: String,
    pub worktree_state: String,
    pub index_state: String,
    pub matches_active_master_key: Option<bool>,
}

/// Inspection result for a single encryption ring (`default` or named ring).
#[derive(Debug, Clone)]
pub struct RingInspection {
    pub name: String,
    pub format_version: u32,
    pub public_key: Option<String>,
    pub public_key_valid: bool,
    pub local_master_key_present: bool,
    pub local_master_key_valid: bool,
    pub local_master_key_matches_pub: bool,
    pub unlocked: bool,
    pub locking_marker_present: bool,
    pub recipients: Vec<RecipientInspection>,
    pub tracked_patterns: Vec<String>,
    pub tracked_files: Vec<TrackedFileInspection>,
    pub issues: Vec<String>,
}

/// Transaction durability and lock recovery state.
#[derive(Debug, Clone)]
pub struct TransactionStateReport {
    pub status: String,
    pub locking_files: Vec<String>,
    pub journal_present: bool,
    pub journal_entries: usize,
    pub journal_valid: bool,
}

/// Complete read-only diagnostic and recovery inspection report for a repository.
#[derive(Debug, Clone)]
pub struct RepositoryInspection {
    pub format_version: Option<u32>,
    pub format_source: FormatVersionSource,
    pub supported: bool,
    pub unsupported_fields: Vec<String>,
    pub repository_root: String,
    pub git_dir: String,
    pub common_dir: String,
    pub is_bare: bool,
    pub transaction_state: TransactionStateReport,
    pub rings: Vec<RingInspection>,
    pub issues: Vec<String>,
    pub recommended_actions: Vec<String>,
}

/// Parses an explicit `.git-agecrypt/format` file content.
/// Accepts `"1"` or `"format-version: 1"` (with optional `#` comments and whitespace).
pub fn parse_format_file_content(content: &str) -> Result<u32> {
    let mut found_version: Option<u32> = None;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let val_str = if let Some(rest) = line.strip_prefix("format-version:") {
            rest.trim()
        } else {
            line
        };
        if found_version.is_some() {
            return Err(anyhow!(
                "Malformed format version file: multiple version directives found"
            ));
        }
        let v = val_str.parse::<u32>().map_err(|_| {
            anyhow!(
                "Malformed format version '{}': expected integer format version (supported: {})",
                line,
                FORMAT_VERSION
            )
        })?;
        found_version = Some(v);
    }

    let version =
        found_version.ok_or_else(|| anyhow!("Malformed format version file: file is empty"))?;
    if version != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported git-agecrypt repository format version {} (this binary supports format version {}). Please upgrade git-agecrypt.",
            version,
            FORMAT_VERSION
        ));
    }
    Ok(version)
}

/// Parses and validates `repo.pub` content.
/// Returns `(recipient_string, optional_format_version)`.
pub fn parse_and_validate_repo_pub(content: &str) -> Result<(String, Option<u32>)> {
    let mut recipient_line: Option<String> = None;
    let mut format_version: Option<u32> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            let comment_trimmed = comment.trim();
            if let Some(ver_str) = comment_trimmed.strip_prefix("format-version:") {
                let v = ver_str.trim().parse::<u32>().map_err(|_| {
                    anyhow!(
                        "Malformed '# format-version:' header in repo.pub: '{}'",
                        ver_str.trim()
                    )
                })?;
                if v != FORMAT_VERSION {
                    return Err(anyhow!(
                        "Unsupported repo.pub format version {} (supported: {})",
                        v,
                        FORMAT_VERSION
                    ));
                }
                format_version = Some(v);
            }
            continue;
        }

        if recipient_line.is_some() {
            return Err(anyhow!(
                "Malformed repo.pub: multiple recipient lines found (expected a single age1... X25519 recipient)"
            ));
        }
        if !line.starts_with("age1") {
            return Err(anyhow!(
                "Malformed repo.pub: expected an 'age1...' X25519 recipient key, found '{}'",
                line
            ));
        }
        age::x25519::Recipient::from_str(line)
            .map_err(|e| anyhow!("Invalid age X25519 recipient in repo.pub: {e}"))?;
        recipient_line = Some(line.to_string());
    }

    let recipient =
        recipient_line.ok_or_else(|| anyhow!("Malformed repo.pub: no recipient key found"))?;
    Ok((recipient, format_version))
}

/// Validates a wrapped master key file (`.git-agecrypt/keys/*.age`).
pub fn validate_wrapped_key_envelope(content: &str) -> Result<(String, Option<u32>)> {
    let mut pub_key: Option<String> = None;
    let mut format_version: Option<u32> = None;
    let mut in_armor = false;
    let mut saw_begin = false;
    let mut saw_end = false;
    let mut armor_body_lines = 0usize;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if !saw_begin && let Some(comment) = line.strip_prefix('#') {
            let c = comment.trim();
            if let Some(pk) = c.strip_prefix("public-key:") {
                let pk_trimmed = pk.trim();
                if pk_trimmed.is_empty() {
                    return Err(anyhow!("Empty '# public-key:' header in recipient file"));
                }
                crypto::parse_recipient(pk_trimmed).with_context(|| {
                    format!("Invalid '# public-key:' recipient '{pk_trimmed}' in recipient file")
                })?;
                pub_key = Some(pk_trimmed.to_string());
            } else if let Some(ver_str) = c.strip_prefix("format-version:") {
                let v = ver_str.trim().parse::<u32>().map_err(|_| {
                    anyhow!(
                        "Malformed '# format-version:' header in recipient file: '{}'",
                        ver_str.trim()
                    )
                })?;
                if v != FORMAT_VERSION {
                    return Err(anyhow!(
                        "Unsupported recipient envelope format version {} (supported: {})",
                        v,
                        FORMAT_VERSION
                    ));
                }
                format_version = Some(v);
            } else if let Some((field, _)) = c.split_once(':') {
                return Err(anyhow!(
                    "Unsupported header field '{}' in recipient envelope",
                    field.trim()
                ));
            }
            continue;
        }

        if line == "-----BEGIN AGE ENCRYPTED FILE-----" {
            if saw_begin {
                return Err(anyhow!(
                    "Malformed recipient envelope: duplicate BEGIN AGE ENCRYPTED FILE header"
                ));
            }
            saw_begin = true;
            in_armor = true;
            continue;
        }

        if line == "-----END AGE ENCRYPTED FILE-----" {
            if !in_armor {
                return Err(anyhow!(
                    "Malformed recipient envelope: END AGE ENCRYPTED FILE without matching BEGIN"
                ));
            }
            in_armor = false;
            saw_end = true;
            continue;
        }

        if in_armor {
            armor_body_lines += 1;
        } else {
            return Err(anyhow!(
                "Malformed recipient envelope: unexpected line outside armor block: '{}'",
                line
            ));
        }
    }

    if !saw_begin || !saw_end || armor_body_lines == 0 {
        return Err(anyhow!(
            "Malformed recipient envelope: incomplete or missing ASCII-armored age block"
        ));
    }

    // Verify that age::Decryptor can parse the armored header (strip leading comment headers first)
    let armor_slice = match content.find("-----BEGIN AGE ENCRYPTED FILE-----") {
        Some(idx) => &content[idx..],
        None => content,
    };
    let armor_reader = age::armor::ArmoredReader::new(std::io::Cursor::new(armor_slice.as_bytes()));
    age::Decryptor::new(armor_reader)
        .map_err(|e| anyhow!("Malformed age header inside recipient envelope: {e}"))?;

    let pk = pub_key.ok_or_else(|| {
        anyhow!("Recipient envelope lacks required '# public-key: <recipient>' metadata header")
    })?;

    Ok((pk, format_version))
}

/// Validates the syntax of a `lock.journal` write-ahead log.
/// Returns the parsed `(worktree_path, relative_path)` entries.
pub fn parse_and_validate_lock_journal(content: &str) -> Result<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        if raw_line.is_empty() {
            continue;
        }
        if idx == 0
            && let Some(comment) = raw_line.strip_prefix('#')
            && let Some(ver_str) = comment.trim().strip_prefix("format-version:")
        {
            let v = ver_str.trim().parse::<u32>().map_err(|_| {
                anyhow!(
                    "Malformed '# format-version:' in lock.journal: '{}'",
                    ver_str.trim()
                )
            })?;
            if v != FORMAT_VERSION {
                return Err(anyhow!(
                    "Unsupported lock.journal format version {} (supported: {})",
                    v,
                    FORMAT_VERSION
                ));
            }
            continue;
        }
        let parts: Vec<&str> = raw_line.split('\t').collect();
        if parts.len() != 2 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            return Err(anyhow!(
                "Malformed lock recovery journal entry at line {}",
                idx + 1
            ));
        }
        if raw_line.contains('\0') {
            return Err(anyhow!(
                "Malformed lock recovery journal entry at line {}: contains NUL byte",
                idx + 1
            ));
        }
        entries.push((parts[0].to_string(), parts[1].to_string()));
    }
    Ok(entries)
}

/// Enforces that the repository metadata and local state use a supported format version (v1).
/// Fails closed if an unsupported format version or corrupted format marker is present.
pub fn ensure_supported_repository_format(repo: &GitRepo, ring: Option<&str>) -> Result<()> {
    let meta_dir = repo.agecrypt_metadata_dir();
    if meta_dir.exists() {
        ensure_not_symlink_or_reparse(&meta_dir)?;
        let format_file = meta_dir.join("format");
        if format_file.exists() {
            ensure_not_symlink_or_reparse(&format_file)?;
            let content = fs::read_to_string(&format_file)
                .with_context(|| format!("Failed to read format file {}", format_file.display()))?;
            parse_format_file_content(&content)?;
        }
    }

    if let Some(r) = ring
        && !r.is_empty()
        && r != "default"
    {
        validate_ring_name(r)?;
        let ring_dir = repo.ring_metadata_dir(Some(r));
        if ring_dir.exists() {
            ensure_not_symlink_or_reparse(&ring_dir)?;
            let ring_format = ring_dir.join("format");
            if ring_format.exists() {
                ensure_not_symlink_or_reparse(&ring_format)?;
                let content = fs::read_to_string(&ring_format).with_context(|| {
                    format!("Failed to read ring format file {}", ring_format.display())
                })?;
                parse_format_file_content(&content)?;
            }
        }
    }

    let local_format = repo.local_state_dir().join("format");
    if local_format.exists() {
        ensure_not_symlink_or_reparse(&local_format)?;
        let content = fs::read_to_string(&local_format).with_context(|| {
            format!(
                "Failed to read local state format file {}",
                local_format.display()
            )
        })?;
        parse_format_file_content(&content)?;
    }

    let pub_file = repo.public_key_file_for_ring(ring);
    if pub_file.exists() {
        ensure_not_symlink_or_reparse(&pub_file)?;
        let content = fs::read_to_string(&pub_file)
            .with_context(|| format!("Failed to read {}", pub_file.display()))?;
        parse_and_validate_repo_pub(&content)?;
    }

    Ok(())
}

fn classify_recipient_type(pub_key: &str) -> &'static str {
    let trimmed = pub_key.trim();
    if trimmed.starts_with("age1") {
        "x25519"
    } else if trimmed.starts_with("ssh-ed25519") {
        "ssh-ed25519"
    } else if trimmed.starts_with("ssh-rsa") {
        "ssh-rsa"
    } else {
        "unknown"
    }
}

/// Performs a comprehensive read-only diagnostic and recovery inspection of a repository.
/// Does not mutate any repository or local state.
pub fn inspect_repository(
    repo: &GitRepo,
    ring_filter: Option<&str>,
) -> Result<RepositoryInspection> {
    if let Some(r) = ring_filter
        && !r.is_empty()
        && r != "default"
    {
        validate_ring_name(r)?;
    }

    let mut issues = Vec::new();
    let mut unsupported_fields = Vec::new();
    let mut recommended_actions = Vec::new();
    let mut format_version = Some(FORMAT_VERSION);
    let mut format_source = FormatVersionSource::ImplicitV1;
    let mut supported = true;

    let meta_dir = repo.agecrypt_metadata_dir();
    if meta_dir.exists() {
        let format_file = meta_dir.join("format");
        if format_file.exists() {
            format_source = FormatVersionSource::ExplicitFile;
            match fs::read_to_string(&format_file)
                .and_then(|c| parse_format_file_content(&c).map_err(std::io::Error::other))
            {
                Ok(v) => {
                    format_version = Some(v);
                }
                Err(e) => {
                    format_version = None;
                    supported = false;
                    let msg = format!(".git-agecrypt/format: {e}");
                    unsupported_fields.push(msg.clone());
                    issues.push(msg);
                }
            }
        }

        // Check for unknown top-level entries in .git-agecrypt
        if let Ok(entries) = fs::read_dir(&meta_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !matches!(name.as_str(), "repo.pub" | "keys" | "rings" | "format") {
                    unsupported_fields.push(format!(".git-agecrypt/{name}"));
                    issues.push(format!(
                        "Unknown metadata entry '.git-agecrypt/{name}' detected"
                    ));
                }
            }
        }
    } else {
        issues.push(
            "Repository metadata directory '.git-agecrypt' does not exist (not initialized)"
                .to_string(),
        );
        recommended_actions
            .push("Run 'git-agecrypt init' to initialize the repository.".to_string());
    }

    // Inspect transaction & recovery state
    let mut locking_files = Vec::new();
    let default_locking = repo.local_state_dir().join("repo.key.locking");
    if default_locking.exists() {
        locking_files.push(".git/git-agecrypt/repo.key.locking".to_string());
    }
    let local_rings_dir = repo.local_state_dir().join("rings");
    if local_rings_dir.exists()
        && let Ok(entries) = fs::read_dir(&local_rings_dir)
    {
        for entry in entries.flatten() {
            let p = entry.path().join("repo.key.locking");
            if p.exists() {
                let rname = entry.file_name().to_string_lossy().to_string();
                locking_files.push(format!(".git/git-agecrypt/rings/{rname}/repo.key.locking"));
            }
        }
    }

    let journal_file = repo.lock_journal_file();
    let journal_present = journal_file.exists();
    let mut journal_entries = 0usize;
    let mut journal_valid = true;

    if journal_present {
        match fs::read_to_string(&journal_file) {
            Ok(content) => match parse_and_validate_lock_journal(&content) {
                Ok(parsed) => {
                    journal_entries = parsed.len();
                }
                Err(e) => {
                    journal_valid = false;
                    issues.push(format!("Corrupted lock.journal: {e}"));
                }
            },
            Err(e) => {
                journal_valid = false;
                issues.push(format!("Failed to read lock.journal: {e}"));
            }
        }
    }

    let tx_status = if !locking_files.is_empty() {
        if repo.local_master_key_file().exists() {
            recommended_actions.push(
                "Run any git-agecrypt management command (e.g. 'git-agecrypt status') to clean up the stale repo.key.locking marker.".to_string(),
            );
            "completed_lock_stale_marker".to_string()
        } else {
            issues.push(
                "Interrupted lock transaction detected (repo.key.locking is present without repo.key)".to_string(),
            );
            recommended_actions.push(
                "Run 'git-agecrypt unlock' or any management command to automatically replay the lock recovery journal and restore repo.key.".to_string(),
            );
            "interrupted_lock_pending_recovery".to_string()
        }
    } else if journal_present {
        if !journal_valid {
            "corrupted_journal".to_string()
        } else if repo.local_master_key_file().exists() {
            "pre_transaction_journal_present".to_string()
        } else {
            issues.push(
                "Ambiguous recovery state: lock.journal exists without repo.key or repo.key.locking".to_string(),
            );
            recommended_actions.push(
                "Inspect .git/git-agecrypt/lock.journal and run 'git-agecrypt unlock <KEY_FILE>' to restore the master key.".to_string(),
            );
            "ambiguous_journal_without_key".to_string()
        }
    } else {
        "clean".to_string()
    };

    let transaction_state = TransactionStateReport {
        status: tx_status,
        locking_files,
        journal_present,
        journal_entries,
        journal_valid,
    };

    // Determine rings to inspect
    let mut ring_names = repo.list_rings().unwrap_or_default();
    if ring_names.is_empty() {
        ring_names.push("default".to_string());
    }
    if let Some(filter) = ring_filter {
        let target = if filter.is_empty() { "default" } else { filter };
        ring_names.retain(|r| r == target);
        if ring_names.is_empty() {
            ring_names.push(target.to_string());
        }
    }

    let is_bare = repo.is_bare();
    let mut rings = Vec::new();

    for ring_name in ring_names {
        let ring_opt = if ring_name == "default" {
            None
        } else {
            Some(ring_name.as_str())
        };
        let mut ring_issues = Vec::new();
        let mut ring_format_ver = FORMAT_VERSION;

        let ring_dir = repo.ring_metadata_dir(ring_opt);
        let ring_format_path = ring_dir.join("format");
        if ring_format_path.exists() {
            match fs::read_to_string(&ring_format_path)
                .and_then(|c| parse_format_file_content(&c).map_err(std::io::Error::other))
            {
                Ok(v) => ring_format_ver = v,
                Err(e) => {
                    supported = false;
                    let msg = format!("ring '{ring_name}' format file: {e}");
                    unsupported_fields.push(msg.clone());
                    ring_issues.push(msg.clone());
                    issues.push(msg);
                }
            }
        }

        let pub_file = repo.public_key_file_for_ring(ring_opt);
        let mut public_key = None;
        let mut public_key_valid = false;
        if pub_file.exists() {
            match fs::read_to_string(&pub_file) {
                Ok(content) => match parse_and_validate_repo_pub(&content) {
                    Ok((pk, header_ver)) => {
                        if let Some(v) = header_ver {
                            ring_format_ver = v;
                            if format_source == FormatVersionSource::ImplicitV1 {
                                format_source = FormatVersionSource::HeaderComment;
                            }
                        }
                        public_key = Some(pk);
                        public_key_valid = true;
                    }
                    Err(e) => {
                        let msg = format!("ring '{ring_name}' repo.pub invalid: {e}");
                        if msg.contains("Unsupported") {
                            supported = false;
                            unsupported_fields.push(msg.clone());
                        }
                        ring_issues.push(msg.clone());
                        issues.push(msg);
                    }
                },
                Err(e) => {
                    let msg = format!("Failed to read {}: {e}", pub_file.display());
                    ring_issues.push(msg.clone());
                    issues.push(msg);
                }
            }
        } else {
            ring_issues.push(format!(
                "Ring '{ring_name}' is missing repo.pub ({})",
                pub_file.display()
            ));
        }

        // Local master key state
        let key_path = repo.local_master_key_file_for_ring(ring_opt);
        let locking_path = repo
            .local_state_dir_for_ring(ring_opt)
            .join("repo.key.locking");
        let locking_marker_present = locking_path.exists();
        let local_master_key_present = key_path.exists();
        let mut local_master_key_valid = false;
        let mut local_master_key_matches_pub = false;
        let mut active_identity: Option<age::x25519::Identity> = None;

        if local_master_key_present {
            match repo.read_local_master_key_for_ring(ring_opt) {
                Ok(Some(k)) => match age::x25519::Identity::from_str(&k) {
                    Ok(id) => {
                        local_master_key_valid = true;
                        let derived_pub = id.to_public().to_string();
                        if let Some(ref exp_pub) = public_key {
                            if &derived_pub == exp_pub {
                                local_master_key_matches_pub = true;
                            } else {
                                let msg = format!(
                                    "Ring '{ring_name}' local master key is stale (does not match committed repo.pub)"
                                );
                                ring_issues.push(msg.clone());
                                issues.push(msg);
                                recommended_actions.push(format!(
                                    "Run 'git-agecrypt unlock{}' to synchronize local master key with rotated repo.pub.",
                                    if ring_name == "default" {
                                        "".to_string()
                                    } else {
                                        format!(" --ring {ring_name}")
                                    }
                                ));
                            }
                        }
                        active_identity = Some(id);
                    }
                    Err(e) => {
                        let msg = format!(
                            "Ring '{ring_name}' local master key (repo.key) is corrupted: {e}"
                        );
                        ring_issues.push(msg.clone());
                        issues.push(msg);
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    let msg = format!("Ring '{ring_name}' failed to read local master key: {e}");
                    ring_issues.push(msg.clone());
                    issues.push(msg);
                }
            }
        }

        // Inspect recipient envelopes
        let keys_dir = repo.keys_dir_for_ring(ring_opt);
        let mut recipients = Vec::new();
        if keys_dir.exists()
            && let Ok(entries) = fs::read_dir(&keys_dir)
        {
            let mut sorted_entries: Vec<_> = entries.flatten().collect();
            sorted_entries.sort_by_key(|e| e.file_name());
            for entry in sorted_entries {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("age") {
                    continue;
                }
                let file_name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let rel_path = path
                    .strip_prefix(&repo.root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");

                let mut rec_issues = Vec::new();
                let mut rec_pub = None;
                let mut rec_type = "unknown".to_string();
                let mut armor_valid = false;
                let mut rec_ver = None;

                match fs::read_to_string(&path) {
                    Ok(content) => match validate_wrapped_key_envelope(&content) {
                        Ok((pk, ver)) => {
                            rec_type = classify_recipient_type(&pk).to_string();
                            rec_pub = Some(pk);
                            armor_valid = true;
                            rec_ver = ver;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("Unsupported") {
                                supported = false;
                                unsupported_fields.push(format!("{rel_path}: {err_str}"));
                            }
                            rec_issues.push(err_str.clone());
                            ring_issues.push(format!("Recipient '{file_name}': {err_str}"));
                            issues.push(format!("Recipient '{rel_path}': {err_str}"));
                        }
                    },
                    Err(e) => {
                        let err_str = format!("Failed to read recipient file: {e}");
                        rec_issues.push(err_str.clone());
                        ring_issues.push(err_str);
                    }
                }

                recipients.push(RecipientInspection {
                    name: file_name,
                    relative_path: rel_path,
                    public_key: rec_pub,
                    recipient_type: rec_type,
                    armor_valid,
                    format_version: rec_ver,
                    issues: rec_issues,
                });
            }
        }

        if public_key_valid && recipients.is_empty() {
            let msg = format!("Ring '{ring_name}' has no enrolled recipient key files in keys/");
            ring_issues.push(msg.clone());
            issues.push(msg);
            recommended_actions.push(format!(
                "Enroll at least one recipient with 'git-agecrypt add-recipient -i <PUBKEY>{}'.",
                if ring_name == "default" {
                    "".to_string()
                } else {
                    format!(" --ring {ring_name}")
                }
            ));
        }

        let tracked_patterns = repo
            .get_tracked_patterns_for_ring(ring_opt)
            .unwrap_or_default();
        let mut tracked_files = Vec::new();

        if !is_bare
            && let Ok(ls_out) = crate::git::git_cmd_with_path(&repo.root)
                .args(["ls-files", "-z"])
                .output()
            && ls_out.status.success()
        {
            for slice in ls_out.stdout.split(|&b| b == 0) {
                if slice.is_empty() {
                    continue;
                }
                let rel_path = String::from_utf8_lossy(slice).to_string();
                if !repo.is_file_tracked_for_ring(&rel_path, ring_opt) {
                    continue;
                }
                let full_path = repo.root.join(&rel_path);
                let worktree_state = if !full_path.exists() {
                    "missing".to_string()
                } else if let Ok(mut f) = File::open(&full_path) {
                    let mut buf = [0u8; AGE_HEADER_MAGIC.len()];
                    match f.read(&mut buf) {
                        Ok(0) => "empty".to_string(),
                        Ok(n) if is_age_ciphertext(&buf[..n]) => "ciphertext".to_string(),
                        Ok(_) => "plaintext".to_string(),
                        Err(_) => "unreadable".to_string(),
                    }
                } else {
                    "unreadable".to_string()
                };

                let mut index_state = "missing".to_string();
                let mut matches_active = None;
                let blob_ref = format!(":0:{rel_path}");
                if let Some(header) = repo.read_blob_header(&blob_ref, 64 * 1024) {
                    let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                    if !is_age_ciphertext(&header[..prefix_len]) {
                        index_state = "plaintext".to_string();
                        let msg = format!(
                            "Tracked secret '{rel_path}' is staged as unencrypted plaintext in the Git index!"
                        );
                        ring_issues.push(msg.clone());
                        issues.push(msg);
                        recommended_actions.push(format!(
                                "Re-stage '{rel_path}' through the clean filter: 'git reset HEAD \"{rel_path}\" && git add \"{rel_path}\"'"
                            ));
                    } else {
                        match age::Decryptor::new(&header[..]) {
                            Ok(decryptor) => {
                                index_state = "ciphertext".to_string();
                                if let Some(ref id) = active_identity {
                                    let ok = decryptor
                                        .decrypt(std::iter::once(id as &dyn age::Identity))
                                        .is_ok();
                                    matches_active = Some(ok);
                                    if !ok {
                                        let msg = format!(
                                            "Tracked secret '{rel_path}' in Git index is encrypted under a historical or foreign key"
                                        );
                                        ring_issues.push(msg.clone());
                                        issues.push(msg);
                                        recommended_actions.push(format!(
                                                "Run 'git-agecrypt rewrap \"{rel_path}\"' to re-encrypt under the active master key."
                                            ));
                                    }
                                }
                            }
                            Err(_) => {
                                index_state = "corrupted".to_string();
                                let msg = format!(
                                    "Tracked secret '{rel_path}' has a corrupted age header in the Git index"
                                );
                                ring_issues.push(msg.clone());
                                issues.push(msg);
                            }
                        }
                    }
                }

                tracked_files.push(TrackedFileInspection {
                    path: rel_path,
                    ring: ring_name.clone(),
                    worktree_state,
                    index_state,
                    matches_active_master_key: matches_active,
                });
            }
        }

        let unlocked = local_master_key_valid && local_master_key_matches_pub;
        rings.push(RingInspection {
            name: ring_name,
            format_version: ring_format_ver,
            public_key,
            public_key_valid,
            local_master_key_present,
            local_master_key_valid,
            local_master_key_matches_pub,
            unlocked,
            locking_marker_present,
            recipients,
            tracked_patterns,
            tracked_files,
            issues: ring_issues,
        });
    }

    if issues.is_empty() && recommended_actions.is_empty() {
        recommended_actions.push("Repository metadata and secret states are healthy.".to_string());
    }

    Ok(RepositoryInspection {
        format_version,
        format_source,
        supported,
        unsupported_fields,
        repository_root: repo.root.display().to_string(),
        git_dir: repo.git_dir.display().to_string(),
        common_dir: repo.common_dir.display().to_string(),
        is_bare,
        transaction_state,
        rings,
        issues,
        recommended_actions,
    })
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt_str(opt: &Option<String>) -> String {
    match opt {
        Some(s) => json_escape(s),
        None => "null".to_string(),
    }
}

fn json_opt_u32(opt: Option<u32>) -> String {
    match opt {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

fn json_opt_bool(opt: Option<bool>) -> String {
    match opt {
        Some(b) => b.to_string(),
        None => "null".to_string(),
    }
}

fn json_str_array(items: &[String]) -> String {
    let joined: Vec<String> = items.iter().map(|s| json_escape(s)).collect();
    format!("[{}]", joined.join(", "))
}

impl RepositoryInspection {
    /// Renders the inspection report as deterministic, human-readable text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("git-agecrypt Repository Inspection Report\n");
        out.push_str("=========================================\n");
        out.push_str(&format!("Repository root:   {}\n", self.repository_root));
        out.push_str(&format!("Git directory:     {}\n", self.git_dir));
        out.push_str(&format!("Common directory:  {}\n", self.common_dir));
        out.push_str(&format!("Bare repository:   {}\n", self.is_bare));
        out.push_str(&format!(
            "Format version:    {} (source: {}, supported: {})\n",
            self.format_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "INVALID/UNSUPPORTED".to_string()),
            self.format_source.as_str(),
            self.supported
        ));
        if !self.unsupported_fields.is_empty() {
            out.push_str(&format!(
                "Unsupported:       {}\n",
                self.unsupported_fields.join("; ")
            ));
        }
        out.push_str(&format!(
            "Transaction state: {} (journal present: {}, entries: {}, valid: {})\n",
            self.transaction_state.status,
            self.transaction_state.journal_present,
            self.transaction_state.journal_entries,
            self.transaction_state.journal_valid
        ));

        for ring in &self.rings {
            out.push_str(&format!("\nRing '{}':\n", ring.name));
            out.push_str(&format!("  Format version:  {}\n", ring.format_version));
            out.push_str(&format!(
                "  Public key:      {} (valid: {})\n",
                ring.public_key.as_deref().unwrap_or("<missing>"),
                ring.public_key_valid
            ));
            out.push_str(&format!(
                "  Unlocked:        {} (key present: {}, valid: {}, matches pub: {})\n",
                ring.unlocked,
                ring.local_master_key_present,
                ring.local_master_key_valid,
                ring.local_master_key_matches_pub
            ));
            out.push_str(&format!("  Recipients ({}):\n", ring.recipients.len()));
            for rec in &ring.recipients {
                out.push_str(&format!(
                    "    - {} [{}] ({}) armor_valid={}\n",
                    rec.name, rec.recipient_type, rec.relative_path, rec.armor_valid
                ));
            }
            out.push_str(&format!(
                "  Tracked files ({}):\n",
                ring.tracked_files.len()
            ));
            for tf in &ring.tracked_files {
                out.push_str(&format!(
                    "    - {}: worktree={}, index={}, active_key_match={}\n",
                    tf.path,
                    tf.worktree_state,
                    tf.index_state,
                    tf.matches_active_master_key
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ));
            }
        }

        if !self.issues.is_empty() {
            out.push_str("\nDetected Issues:\n");
            for issue in &self.issues {
                out.push_str(&format!("  ! {issue}\n"));
            }
        }

        out.push_str("\nRecommended Actions:\n");
        for action in &self.recommended_actions {
            out.push_str(&format!("  -> {action}\n"));
        }

        out
    }

    /// Renders the inspection report as RFC 8259 JSON.
    pub fn to_json(&self) -> String {
        let mut rings_json = Vec::new();
        for r in &self.rings {
            let mut recs_json = Vec::new();
            for rec in &r.recipients {
                recs_json.push(format!(
                    "{{\"name\": {}, \"relative_path\": {}, \"public_key\": {}, \"recipient_type\": {}, \"armor_valid\": {}, \"format_version\": {}, \"issues\": {}}}",
                    json_escape(&rec.name),
                    json_escape(&rec.relative_path),
                    json_opt_str(&rec.public_key),
                    json_escape(&rec.recipient_type),
                    rec.armor_valid,
                    json_opt_u32(rec.format_version),
                    json_str_array(&rec.issues)
                ));
            }

            let mut files_json = Vec::new();
            for f in &r.tracked_files {
                files_json.push(format!(
                    "{{\"path\": {}, \"ring\": {}, \"worktree_state\": {}, \"index_state\": {}, \"matches_active_master_key\": {}}}",
                    json_escape(&f.path),
                    json_escape(&f.ring),
                    json_escape(&f.worktree_state),
                    json_escape(&f.index_state),
                    json_opt_bool(f.matches_active_master_key)
                ));
            }

            rings_json.push(format!(
                "{{\"name\": {}, \"format_version\": {}, \"public_key\": {}, \"public_key_valid\": {}, \"local_master_key_present\": {}, \"local_master_key_valid\": {}, \"local_master_key_matches_pub\": {}, \"unlocked\": {}, \"locking_marker_present\": {}, \"recipients\": [{}], \"tracked_patterns\": {}, \"tracked_files\": [{}], \"issues\": {}}}",
                json_escape(&r.name),
                r.format_version,
                json_opt_str(&r.public_key),
                r.public_key_valid,
                r.local_master_key_present,
                r.local_master_key_valid,
                r.local_master_key_matches_pub,
                r.unlocked,
                r.locking_marker_present,
                recs_json.join(", "),
                json_str_array(&r.tracked_patterns),
                files_json.join(", "),
                json_str_array(&r.issues)
            ));
        }

        format!(
            "{{\n  \"format_version\": {},\n  \"format_source\": {},\n  \"supported\": {},\n  \"unsupported_fields\": {},\n  \"repository_root\": {},\n  \"git_dir\": {},\n  \"common_dir\": {},\n  \"is_bare\": {},\n  \"transaction_state\": {{\n    \"status\": {},\n    \"locking_files\": {},\n    \"journal_present\": {},\n    \"journal_entries\": {},\n    \"journal_valid\": {}\n  }},\n  \"rings\": [{}],\n  \"issues\": {},\n  \"recommended_actions\": {}\n}}\n",
            json_opt_u32(self.format_version),
            json_escape(self.format_source.as_str()),
            self.supported,
            json_str_array(&self.unsupported_fields),
            json_escape(&self.repository_root),
            json_escape(&self.git_dir),
            json_escape(&self.common_dir),
            self.is_bare,
            json_escape(&self.transaction_state.status),
            json_str_array(&self.transaction_state.locking_files),
            self.transaction_state.journal_present,
            self.transaction_state.journal_entries,
            self.transaction_state.journal_valid,
            rings_json.join(", "),
            json_str_array(&self.issues),
            json_str_array(&self.recommended_actions)
        )
    }
}

/// Clean-room recovery helper: decrypts a wrapped master key envelope using a standard age/SSH
/// private identity string or file content, and uses that unwrapped master key to decrypt an age
/// secret blob without relying on any local `.git/git-agecrypt` state.
#[allow(dead_code)]
pub fn standalone_recover_secret_bytes(
    wrapped_master_key_armor: &str,
    user_identity_bytes: &[u8],
    secret_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let identities = crypto::load_identities_from_buffer(user_identity_bytes)?;
    let master_key_str = Zeroizing::new(crypto::unwrap_master_key(
        wrapped_master_key_armor,
        &identities,
    )?);
    let master_identity = age::x25519::Identity::from_str(&master_key_str)
        .map_err(|e| anyhow!("Invalid unwrapped master key: {e}"))?;

    let mut reader = std::io::Cursor::new(secret_ciphertext);
    let mut plaintext = Vec::new();
    crypto::decrypt_stream(&mut reader, &mut plaintext, &master_identity)?;
    Ok(plaintext)
}

/// Exports a tracked secret file to a standalone standard `age`-encrypted file encrypted directly
/// to `recipient_str` (independent of repository rings or `.git/git-agecrypt` state).
/// Never writes plaintext or raw keys to stdout.
pub fn export_secret_to_age_file(
    repo: &GitRepo,
    secret_path: &Path,
    recipient_str: &str,
    output_path: &Path,
    ring_opt: Option<&str>,
    identity_opt: Option<&str>,
    overwrite: bool,
) -> Result<()> {
    ensure_supported_repository_format(repo, ring_opt)?;

    if output_path.exists() && !overwrite {
        return Err(anyhow!(
            "Output file '{}' already exists. Pass '--yes' (-y) to overwrite.",
            output_path.display()
        ));
    }

    let target_recipient = crypto::parse_recipient(recipient_str)
        .with_context(|| format!("Invalid target recipient '{recipient_str}'"))?;

    // Resolve path inside repository
    let full_secret_path = if secret_path.is_absolute() {
        secret_path.to_path_buf()
    } else if repo.root.join(secret_path).exists() {
        repo.root.join(secret_path)
    } else {
        secret_path.to_path_buf()
    };

    let rel_path = full_secret_path
        .strip_prefix(&repo.root)
        .unwrap_or(secret_path)
        .to_string_lossy()
        .replace('\\', "/");

    // Read raw bytes from disk if present, otherwise from Git index/HEAD
    let raw_bytes = if full_secret_path.exists() {
        fs::read(&full_secret_path)
            .with_context(|| format!("Failed to read secret file {}", full_secret_path.display()))?
    } else if let Some(staged) = repo.get_staged_blob(&rel_path) {
        staged
    } else {
        return Err(anyhow!(
            "Secret file '{}' not found in working tree or Git index",
            secret_path.display()
        ));
    };

    let prefix_len = std::cmp::min(raw_bytes.len(), AGE_HEADER_MAGIC.len());
    let is_cipher = is_age_ciphertext(&raw_bytes[..prefix_len]);

    let plaintext: Zeroizing<Vec<u8>> = if !is_cipher {
        // File in working tree is already decrypted plaintext
        Zeroizing::new(raw_bytes)
    } else {
        // Gather candidate master keys to decrypt the ciphertext
        let mut candidate_master_keys: Vec<Zeroizing<String>> = Vec::new();

        if let Ok(Some(local_key)) = repo.read_local_master_key_for_ring(ring_opt) {
            candidate_master_keys.push(Zeroizing::new(local_key));
        }

        // Also check if an interrupted lock left repo.key.locking
        let locking_path = repo
            .local_state_dir_for_ring(ring_opt)
            .join("repo.key.locking");
        if locking_path.exists()
            && let Ok(k) = fs::read_to_string(&locking_path)
        {
            candidate_master_keys.push(Zeroizing::new(k.trim().to_string()));
        }

        // If user provided --identity or local master key wasn't enough, unwrap from keys/*.age
        let mut user_identities: Vec<Box<dyn age::Identity>> = Vec::new();
        if let Some(id_arg) = identity_opt {
            let p = Path::new(id_arg);
            if p.exists() {
                user_identities.extend(crypto::load_identities_from_file(p)?);
            } else {
                user_identities.extend(crypto::load_identities_from_buffer(id_arg.as_bytes())?);
            }
        } else if candidate_master_keys.is_empty() {
            for candidate in crypto::get_default_identity_paths() {
                if candidate.exists()
                    && let Ok(ids) = crypto::load_identities_from_file_non_interactive(&candidate)
                {
                    user_identities.extend(ids);
                }
            }
        }

        if !user_identities.is_empty() {
            let keys_dir = repo.keys_dir_for_ring(ring_opt);
            if keys_dir.exists()
                && let Ok(entries) = fs::read_dir(&keys_dir)
            {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("age")
                        && let Ok(content) = fs::read_to_string(&p)
                        && let Ok(unwrapped) = crypto::unwrap_master_key(&content, &user_identities)
                    {
                        candidate_master_keys.push(Zeroizing::new(unwrapped));
                    }
                }
            }
        }

        let mut decrypted_opt: Option<Zeroizing<Vec<u8>>> = None;
        for mk in &candidate_master_keys {
            if let Ok(id) = age::x25519::Identity::from_str(mk) {
                let mut cursor = std::io::Cursor::new(&raw_bytes);
                let mut out = Vec::new();
                if crypto::decrypt_stream(&mut cursor, &mut out, &id).is_ok() {
                    decrypted_opt = Some(Zeroizing::new(out));
                    break;
                }
            }
        }

        // Also try decrypting directly with user_identities in case the file was directly encrypted
        if decrypted_opt.is_none()
            && !user_identities.is_empty()
            && let Ok(decryptor) = age::Decryptor::new(&raw_bytes[..])
        {
            let id_refs: Vec<&dyn age::Identity> =
                user_identities.iter().map(|i| i.as_ref()).collect();
            if let Ok(mut reader) = decryptor.decrypt(id_refs.into_iter()) {
                let mut out = Vec::new();
                reader.read_to_end(&mut out)?;
                decrypted_opt = Some(Zeroizing::new(out));
            }
        }

        decrypted_opt.ok_or_else(|| {
            anyhow!(
                "Cannot decrypt '{}' for export: repository is locked and no matching identity was provided. Unlock the repository or pass '--identity <KEY_FILE>'.",
                secret_path.display()
            )
        })?
    };

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let out_file = File::create(output_path)
        .with_context(|| format!("Failed to create output file {}", output_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(output_path, fs::Permissions::from_mode(0o600));
    }
    let mut writer = BufWriter::new(out_file);
    let reader = BufReader::new(std::io::Cursor::new(&plaintext[..]));
    crypto::clean_stream(
        reader,
        &mut writer,
        target_recipient.as_ref(),
        None,
        None,
        None,
        None,
    )?;
    writer.flush()?;

    Ok(())
}

/// Parses `.gitattributes` content into `(pattern, ring_name)` pairs for all `filter=agecrypt*` rules.
pub fn parse_gitattributes_rules(content: &str) -> Result<Vec<(String, String)>> {
    let mut rules = Vec::new();
    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(pat) = parts.first() else {
            continue;
        };
        for attr in &parts[1..] {
            if *attr == "filter=agecrypt" {
                rules.push((pat.to_string(), "default".to_string()));
            } else if let Some(ring) = attr.strip_prefix("filter=agecrypt-") {
                validate_ring_name(ring).with_context(|| {
                    format!("Invalid ring name '{ring}' in .gitattributes pattern '{pat}'")
                })?;
                rules.push((pat.to_string(), ring.to_string()));
            }
        }
    }
    Ok(rules)
}

fn match_path_to_ring(file_path: &str, rules: &[(String, String)]) -> Option<String> {
    let normalized = file_path.replace('\\', "/");
    let mut matched_ring: Option<String> = None;
    for (pat, ring) in rules {
        if let Ok(matcher) = glob::Pattern::new(pat) {
            if matcher.matches(&normalized) {
                matched_ring = Some(ring.clone());
                continue;
            }
            if pat.ends_with("/**") {
                let prefix = pat.trim_end_matches("/**");
                if normalized.starts_with(prefix) {
                    matched_ring = Some(ring.clone());
                }
            }
        }
    }
    matched_ring
}

impl GitRepo {
    /// Reads a blob at `<commit>:<tree_path>` from the Git object database (works in bare repos).
    pub fn read_commit_tree_blob(
        &self,
        commit: &str,
        tree_path: &str,
        max_bytes: usize,
    ) -> Option<Vec<u8>> {
        let clean = tree_path.trim_start_matches('/').replace('\\', "/");
        self.read_blob_header(&format!("{commit}:{clean}"), max_bytes)
    }

    /// Inspects incoming ref updates (`<old_oid> <new_oid> <refname>`) read from stdin
    /// during a server-side `pre-receive` hook invocation.
    pub fn check_pre_receive(
        &self,
        report_only: bool,
        allow_untracked_secrets: bool,
    ) -> Result<()> {
        use std::io::{BufRead, IsTerminal};
        if std::io::stdin().is_terminal() {
            eprintln!(
                "git-agecrypt: 'check --pre-receive' reads '<old_oid> <new_oid> <refname>' lines from stdin."
            );
            return Ok(());
        }
        let stdin = std::io::stdin();
        let mut lines = Vec::new();
        for line in stdin.lock().lines() {
            let l = line?;
            let trimmed = l.trim().to_string();
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
        }
        self.check_pre_receive_lines(&lines, report_only, allow_untracked_secrets)
    }

    /// Inspects a list of `<old_oid> <new_oid> <refname>` pre-receive update lines.
    pub fn check_pre_receive_lines(
        &self,
        lines: &[String],
        report_only: bool,
        allow_untracked_secrets: bool,
    ) -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }

        let zero_sha = "0000000000000000000000000000000000000000";
        let mut violations: Vec<String> = Vec::new();
        let mut inspected_commits = std::collections::HashSet::new();

        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                violations.push(format!("Malformed pre-receive input line: '{line}'"));
                continue;
            }
            let old_oid = parts[0];
            let new_oid = parts[1];
            let refname = parts[2];

            // Branch/tag deletion: no new commits or trees to inspect
            if new_oid.starts_with(zero_sha) || new_oid.chars().all(|c| c == '0') {
                continue;
            }

            let Some(new_commit) = crate::git::peel_to_commit(&self.root, new_oid) else {
                // Non-commit ref (e.g. tag pointing directly to a blob/tree): skip if not a commit
                continue;
            };

            let commits = if old_oid.starts_with(zero_sha) || old_oid.chars().all(|c| c == '0') {
                // New branch or initial push: find commits not reachable from existing refs
                let out = crate::git::git_cmd_with_path(&self.root)
                    .args(["rev-list", &new_commit, "--not", "--all"])
                    .output();
                let mut list: Vec<String> = match out {
                    Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    }
                    _ => {
                        let out2 = crate::git::git_cmd_with_path(&self.root)
                            .args(["rev-list", &new_commit])
                            .output();
                        if let Ok(o2) = out2
                            && o2.status.success()
                        {
                            String::from_utf8_lossy(&o2.stdout)
                                .lines()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        } else {
                            vec![new_commit.clone()]
                        }
                    }
                };
                if !list.contains(&new_commit) {
                    list.push(new_commit.clone());
                }
                list
            } else {
                let old_commit = crate::git::peel_to_commit(&self.root, old_oid)
                    .unwrap_or_else(|| old_oid.to_string());
                let range = format!("{old_commit}..{new_commit}");
                let out = crate::git::git_cmd_with_path(&self.root)
                    .args(["rev-list", &range])
                    .output();
                let mut list: Vec<String> = if let Ok(o) = out
                    && o.status.success()
                {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    vec![new_commit.clone()]
                };
                if !list.contains(&new_commit) {
                    list.push(new_commit.clone());
                }
                list
            };

            for commit in &commits {
                if inspected_commits.insert(commit.clone()) {
                    self.inspect_commit_for_enforcement(
                        commit,
                        refname,
                        allow_untracked_secrets,
                        &mut violations,
                    );
                }
            }

            // Always inspect full target tip tree of `new_commit` to verify metadata consistency
            // and ensure no unencrypted secret exists in the tip tree.
            self.inspect_tip_tree_for_enforcement(
                &new_commit,
                refname,
                allow_untracked_secrets,
                &mut violations,
            );
        }

        self.finalize_enforcement_result(&violations, report_only)
    }

    /// Inspects a commit or commit range (e.g., `HEAD` or `origin/main..HEAD`) for CI enforcement.
    pub fn check_commit_range(
        &self,
        range_spec: &str,
        report_only: bool,
        allow_untracked_secrets: bool,
    ) -> Result<()> {
        let mut violations = Vec::new();
        let commits: Vec<String> = if range_spec.contains("..") {
            let out = crate::git::git_cmd_with_path(&self.root)
                .args(["rev-list", range_spec])
                .output()
                .with_context(|| format!("Failed to resolve commit range '{range_spec}'"))?;
            if !out.status.success() {
                return Err(anyhow!(
                    "Invalid commit range '{}': {}",
                    range_spec,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            let commit = crate::git::peel_to_commit(&self.root, range_spec)
                .ok_or_else(|| anyhow!("Cannot resolve commit '{range_spec}'"))?;
            vec![commit]
        };

        for commit in &commits {
            self.inspect_commit_for_enforcement(
                commit,
                range_spec,
                allow_untracked_secrets,
                &mut violations,
            );
        }

        if let Some(tip) = commits.first() {
            self.inspect_tip_tree_for_enforcement(
                tip,
                range_spec,
                allow_untracked_secrets,
                &mut violations,
            );
        }

        self.finalize_enforcement_result(&violations, report_only)
    }

    fn finalize_enforcement_result(&self, violations: &[String], report_only: bool) -> Result<()> {
        if violations.is_empty() {
            return Ok(());
        }

        eprintln!();
        eprintln!(
            "================================================================================"
        );
        if report_only {
            eprintln!(
                "  git-agecrypt POLICY AUDIT REPORT (REPORT-ONLY MODE - {} VIOLATION(S))",
                violations.len()
            );
        } else {
            eprintln!(
                "  CRITICAL SECURITY ALERT: git-agecrypt POLICY ENFORCEMENT FAILED ({} VIOLATION(S))",
                violations.len()
            );
        }
        eprintln!(
            "================================================================================"
        );
        for v in violations {
            eprintln!("  - {v}");
        }
        eprintln!(
            "================================================================================"
        );

        if report_only {
            eprintln!(
                "git-agecrypt check [REPORT-ONLY]: {} violation(s) logged without blocking.",
                violations.len()
            );
            Ok(())
        } else {
            Err(anyhow!(
                "git-agecrypt policy enforcement rejected {} violation(s)",
                violations.len()
            ))
        }
    }

    fn load_commit_rules(
        &self,
        commit: &str,
        ref_label: &str,
        violations: &mut Vec<String>,
    ) -> Vec<(String, String)> {
        if let Some(attr_bytes) = self.read_commit_tree_blob(commit, ".gitattributes", 256 * 1024) {
            let attr_str = String::from_utf8_lossy(&attr_bytes);
            match parse_gitattributes_rules(&attr_str) {
                Ok(rules) => rules,
                Err(e) => {
                    violations.push(format!(
                        "[{ref_label} @ {commit}] Invalid .gitattributes agecrypt rule: {e}"
                    ));
                    Vec::new()
                }
            }
        } else if !self.is_bare() && self.root.join(".gitattributes").exists() {
            if let Ok(attr_str) = fs::read_to_string(self.root.join(".gitattributes")) {
                parse_gitattributes_rules(&attr_str).unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    fn inspect_commit_for_enforcement(
        &self,
        commit: &str,
        ref_label: &str,
        allow_untracked_secrets: bool,
        violations: &mut Vec<String>,
    ) {
        let rules = self.load_commit_rules(commit, ref_label, violations);
        let zero_sha = "0000000000000000000000000000000000000000";

        let diff_out = crate::git::git_cmd_with_path(&self.root)
            .args([
                "diff-tree",
                "--root",
                "--no-commit-id",
                "-r",
                "--raw",
                "-z",
                commit,
            ])
            .output();

        let Ok(out) = diff_out else {
            return;
        };
        if !out.status.success() {
            return;
        }

        let slices: Vec<&[u8]> = out
            .stdout
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .collect();
        let mut idx = 0;
        while idx < slices.len() {
            let meta_str = String::from_utf8_lossy(slices[idx]);
            if !meta_str.starts_with(':') {
                idx += 1;
                continue;
            }
            let meta_parts: Vec<&str> = meta_str.split_whitespace().collect();
            if meta_parts.len() < 5 {
                idx += 1;
                continue;
            }
            let new_mode = meta_parts[1];
            let new_sha = meta_parts[3];
            let status = meta_parts[4];

            let is_rename = status.starts_with('R') || status.starts_with('C');
            let (old_path_opt, path_str) = if is_rename {
                if idx + 2 < slices.len() {
                    let old_p = String::from_utf8_lossy(slices[idx + 1]).to_string();
                    let new_p = String::from_utf8_lossy(slices[idx + 2]).to_string();
                    idx += 3;
                    (Some(old_p), new_p)
                } else {
                    idx += 1;
                    continue;
                }
            } else if idx + 1 < slices.len() {
                let p = String::from_utf8_lossy(slices[idx + 1]).to_string();
                idx += 2;
                (None, p)
            } else {
                idx += 1;
                continue;
            };

            if status.starts_with('D')
                || new_mode == "000000"
                || new_sha.starts_with(zero_sha)
                || new_sha.chars().all(|c| c == '0')
            {
                continue;
            }
            if new_mode == "120000" || new_mode == "160000" {
                continue;
            }

            let norm_path = path_str.replace('\\', "/");

            if !crate::git::is_shell_safe_repo_path(&norm_path) {
                violations.push(format!(
                    "[{ref_label} @ {commit}] Unsafe filename '{norm_path}' for Git driver shell expansion"
                ));
            }

            if let Some(old_p) = old_path_opt {
                let norm_old = old_p.replace('\\', "/");
                if match_path_to_ring(&norm_old, &rules).is_some()
                    && match_path_to_ring(&norm_path, &rules).is_none()
                {
                    violations.push(format!(
                        "[{ref_label} @ {commit}] Protected secret '{norm_old}' renamed to unprotected path '{norm_path}'"
                    ));
                }
            }

            if let Some(_ring) = match_path_to_ring(&norm_path, &rules) {
                if let Some(header) = self.read_blob_header(new_sha, 64 * 1024) {
                    let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                    if !is_age_ciphertext(&header[..prefix_len]) {
                        violations.push(format!(
                            "[{ref_label} @ {commit}] Plaintext secret committed to protected path '{norm_path}'"
                        ));
                    } else if let Err(e) = age::Decryptor::new(&header[..]) {
                        violations.push(format!(
                            "[{ref_label} @ {commit}] Malformed or corrupted age ciphertext header in '{norm_path}': {e}"
                        ));
                    }
                } else {
                    violations.push(format!(
                        "[{ref_label} @ {commit}] Empty or unreadable blob on protected secret path '{norm_path}'"
                    ));
                }
            } else if !allow_untracked_secrets
                && !norm_path.starts_with(".git-agecrypt/")
                && norm_path != ".gitattributes"
                && let Some(header) = self.read_blob_header(new_sha, 64 * 1024)
            {
                let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                if !is_age_ciphertext(&header[..prefix_len]) {
                    if Self::is_candidate_secret_filename(&norm_path) {
                        violations.push(format!(
                            "[{ref_label} @ {commit}] Untracked plaintext secret filename '{norm_path}' not covered by .gitattributes"
                        ));
                    } else if Self::contains_secret_content_markers(&header) {
                        violations.push(format!(
                            "[{ref_label} @ {commit}] Untracked file '{norm_path}' contains plaintext private key or credential marker"
                        ));
                    }
                }
            }
        }
    }

    fn inspect_tip_tree_for_enforcement(
        &self,
        tip_commit: &str,
        ref_label: &str,
        allow_untracked_secrets: bool,
        violations: &mut Vec<String>,
    ) {
        let rules = self.load_commit_rules(tip_commit, ref_label, violations);

        // Validate .git-agecrypt/format if present in tip tree
        if let Some(fmt_bytes) =
            self.read_commit_tree_blob(tip_commit, ".git-agecrypt/format", 4096)
        {
            let fmt_str = String::from_utf8_lossy(&fmt_bytes);
            if let Err(e) = parse_format_file_content(&fmt_str) {
                violations.push(format!(
                    "[{ref_label} @ {tip_commit}] Invalid .git-agecrypt/format: {e}"
                ));
            }
        }

        // List all blobs in tip commit tree
        let tree_out = crate::git::git_cmd_with_path(&self.root)
            .args(["ls-tree", "-r", "-z", tip_commit])
            .output();
        let Ok(to) = tree_out else {
            return;
        };
        if !to.status.success() {
            return;
        }

        let mut tree_blobs: Vec<(String, String, String)> = Vec::new();
        for slice in to.stdout.split(|&b| b == 0) {
            if slice.is_empty() {
                continue;
            }
            let line_str = String::from_utf8_lossy(slice);
            if let Some((meta, path)) = line_str.split_once('\t') {
                let parts: Vec<&str> = meta.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == "blob" {
                    tree_blobs.push((
                        parts[0].to_string(),
                        parts[2].to_string(),
                        path.replace('\\', "/"),
                    ));
                }
            }
        }

        // Validate .git-agecrypt metadata blobs in tip tree
        let mut rings_with_pub = std::collections::HashSet::new();
        let mut rings_with_keys: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for (_mode, sha, path) in &tree_blobs {
            if path == ".git-agecrypt/repo.pub" {
                if let Some(bytes) = self.read_blob_header(sha, 16 * 1024) {
                    let content = String::from_utf8_lossy(&bytes);
                    match parse_and_validate_repo_pub(&content) {
                        Ok(_) => {
                            rings_with_pub.insert("default".to_string());
                        }
                        Err(e) => violations.push(format!(
                            "[{ref_label} @ {tip_commit}] Invalid .git-agecrypt/repo.pub: {e}"
                        )),
                    }
                }
            } else if let Some(rest) = path.strip_prefix(".git-agecrypt/keys/") {
                if rest.ends_with(".age")
                    && !rest.contains('/')
                    && let Some(bytes) = self.read_blob_header(sha, 64 * 1024)
                {
                    let content = String::from_utf8_lossy(&bytes);
                    match validate_wrapped_key_envelope(&content) {
                        Ok(_) => {
                            *rings_with_keys.entry("default".to_string()).or_insert(0) += 1;
                        }
                        Err(e) => violations.push(format!(
                            "[{ref_label} @ {tip_commit}] Invalid recipient envelope '{path}': {e}"
                        )),
                    }
                }
            } else if let Some(rest) = path.strip_prefix(".git-agecrypt/rings/") {
                let parts: Vec<&str> = rest.split('/').collect();
                if let Some(ring_name) = parts.first() {
                    if let Err(e) = validate_ring_name(ring_name) {
                        violations.push(format!(
                            "[{ref_label} @ {tip_commit}] Invalid ring directory name '{ring_name}': {e}"
                        ));
                    } else if parts.len() == 2 && parts[1] == "repo.pub" {
                        if let Some(bytes) = self.read_blob_header(sha, 16 * 1024) {
                            let content = String::from_utf8_lossy(&bytes);
                            match parse_and_validate_repo_pub(&content) {
                                Ok(_) => {
                                    rings_with_pub.insert((*ring_name).to_string());
                                }
                                Err(e) => violations.push(format!(
                                    "[{ref_label} @ {tip_commit}] Invalid '{path}': {e}"
                                )),
                            }
                        }
                    } else if parts.len() == 2 && parts[1] == "format" {
                        if let Some(bytes) = self.read_blob_header(sha, 4096) {
                            let content = String::from_utf8_lossy(&bytes);
                            if let Err(e) = parse_format_file_content(&content) {
                                violations.push(format!(
                                    "[{ref_label} @ {tip_commit}] Invalid '{path}': {e}"
                                ));
                            }
                        }
                    } else if parts.len() == 3
                        && parts[1] == "keys"
                        && parts[2].ends_with(".age")
                        && let Some(bytes) = self.read_blob_header(sha, 64 * 1024)
                    {
                        let content = String::from_utf8_lossy(&bytes);
                        match validate_wrapped_key_envelope(&content) {
                            Ok(_) => {
                                *rings_with_keys
                                    .entry((*ring_name).to_string())
                                    .or_insert(0) += 1;
                            }
                            Err(e) => violations.push(format!(
                                "[{ref_label} @ {tip_commit}] Invalid recipient envelope '{path}': {e}"
                            )),
                        }
                    }
                }
            }
        }

        // Verify all blobs in tip tree against rules
        let mut used_rings = std::collections::HashSet::new();
        for (mode, sha, norm_path) in &tree_blobs {
            if mode == "120000" || mode == "160000" {
                continue;
            }
            if let Some(ring) = match_path_to_ring(norm_path, &rules) {
                used_rings.insert(ring);
                if let Some(header) = self.read_blob_header(sha, 64 * 1024) {
                    let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                    if !is_age_ciphertext(&header[..prefix_len]) {
                        let msg = format!(
                            "[{ref_label} @ {tip_commit}] Plaintext secret committed to protected path '{norm_path}'"
                        );
                        if !violations.contains(&msg) {
                            violations.push(msg);
                        }
                    } else if let Err(e) = age::Decryptor::new(&header[..]) {
                        let msg = format!(
                            "[{ref_label} @ {tip_commit}] Malformed or corrupted age ciphertext header in '{norm_path}': {e}"
                        );
                        if !violations.contains(&msg) {
                            violations.push(msg);
                        }
                    }
                }
            } else if !allow_untracked_secrets
                && !norm_path.starts_with(".git-agecrypt/")
                && norm_path != ".gitattributes"
                && let Some(header) = self.read_blob_header(sha, 64 * 1024)
            {
                let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                if !is_age_ciphertext(&header[..prefix_len])
                    && (Self::is_candidate_secret_filename(norm_path)
                        || Self::contains_secret_content_markers(&header))
                {
                    let msg = format!(
                        "[{ref_label} @ {tip_commit}] Untracked plaintext secret '{norm_path}' in tip tree"
                    );
                    if !violations.contains(&msg) {
                        violations.push(msg);
                    }
                }
            }
        }

        // Ensure every ring that has protected secret files in the tree also has valid repo.pub and >=1 recipient
        for ring in used_rings {
            if !rings_with_pub.contains(&ring) {
                violations.push(format!(
                    "[{ref_label} @ {tip_commit}] Ring '{ring}' protects tracked secrets in .gitattributes but is missing a valid repo.pub"
                ));
            }
            if rings_with_keys.get(&ring).copied().unwrap_or(0) == 0 {
                violations.push(format!(
                    "[{ref_label} @ {tip_commit}] Ring '{ring}' protects tracked secrets in .gitattributes but has no valid recipient envelopes in keys/*.age"
                ));
            }
        }
    }
}
