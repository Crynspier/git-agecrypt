use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Delimiter markers for managing git-agecrypt patterns in AI ignore files
pub const SHIELD_BEGIN_MARKER: &str = "# --- BEGIN git-agecrypt AI SHIELD ---";
pub const SHIELD_END_MARKER: &str = "# --- END git-agecrypt AI SHIELD ---";
pub const SHIELD_COMMENT: &str = "# Patterns synchronized from .gitattributes to block AI indexers from reading unencrypted secrets";

/// The list of target AI agent and IDE ignore files maintained by git-agecrypt
pub const AI_IGNORE_TARGETS: &[&str] = &[
    ".cursorignore", // Cursor IDE native indexer
    ".claudeignore", // Anthropic Claude Code CLI
    ".aiderignore",  // Aider AI assistant (for GPT-4o, Claude, Grok)
    ".aiignore",     // Universal community standard for multi-model coding agents
];

/// Generates the content of the git-agecrypt AI shield block for given patterns
pub fn generate_shield_block(patterns: &[String]) -> String {
    let mut block = String::new();
    block.push_str(SHIELD_BEGIN_MARKER);
    block.push('\n');
    block.push_str(SHIELD_COMMENT);
    block.push('\n');
    for pattern in patterns {
        block.push_str(pattern);
        block.push('\n');
    }
    block.push_str(SHIELD_END_MARKER);
    block.push('\n');
    block
}

/// Synchronizes a single ignore file with the given tracked patterns,
/// preserving any user rules defined outside the delimited markers.
pub fn sync_single_ignore_file(file_path: &Path, patterns: &[String]) -> Result<bool> {
    let new_block = generate_shield_block(patterns);

    let existing_content = if file_path.exists() {
        fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?
    } else {
        String::new()
    };

    let updated_content = if let Some(start_idx) = existing_content.find(SHIELD_BEGIN_MARKER) {
        if let Some(end_offset) = existing_content[start_idx..].find(SHIELD_END_MARKER) {
            let end_idx = start_idx + end_offset + SHIELD_END_MARKER.len();
            // Include trailing newline if present after end marker
            let end_idx_with_nl = if end_idx < existing_content.len()
                && existing_content[end_idx..].starts_with('\n')
            {
                end_idx + 1
            } else if end_idx + 1 < existing_content.len()
                && existing_content[end_idx..].starts_with("\r\n")
            {
                end_idx + 2
            } else {
                end_idx
            };

            let mut out = String::new();
            out.push_str(&existing_content[..start_idx]);
            out.push_str(&new_block);
            out.push_str(&existing_content[end_idx_with_nl..]);
            out
        } else {
            // Malformed end marker: append fresh block
            let mut out = existing_content.clone();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&new_block);
            out
        }
    } else {
        let mut out = existing_content.clone();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&new_block);
        out
    };

    if existing_content == updated_content {
        return Ok(false); // No changes needed
    }

    fs::write(file_path, updated_content)
        .with_context(|| format!("Failed to write {}", file_path.display()))?;
    Ok(true)
}

/// Checks whether a single ignore file contains the expected shield block.
pub fn is_single_ignore_file_synced(file_path: &Path, patterns: &[String]) -> Result<bool> {
    if !file_path.exists() {
        return Ok(patterns.is_empty());
    }

    let existing_content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read {}", file_path.display()))?;

    let start_idx = match existing_content.find(SHIELD_BEGIN_MARKER) {
        Some(idx) => idx,
        None => return Ok(patterns.is_empty()),
    };

    let end_offset = match existing_content[start_idx..].find(SHIELD_END_MARKER) {
        Some(offset) => offset,
        None => return Ok(false),
    };

    let block = &existing_content[start_idx..start_idx + end_offset + SHIELD_END_MARKER.len()];

    // Verify all patterns are present inside the block
    for pat in patterns {
        if !block.lines().any(|line| line.trim() == pat.trim()) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Synchronizes supported AI ignore files in the repository root.
/// If `create_missing` is true, all target ignore files are created if they do not exist.
/// If `create_missing` is false, only existing ignore files are updated.
pub fn sync_ai_shields(
    repo_root: &Path,
    patterns: &[String],
    create_missing: bool,
) -> Result<Vec<PathBuf>> {
    let mut updated_files = Vec::new();

    for target_name in AI_IGNORE_TARGETS {
        let target_path = repo_root.join(target_name);
        if target_path.exists() || create_missing {
            let changed = sync_single_ignore_file(&target_path, patterns)?;
            if changed {
                updated_files.push(target_path);
            }
        }
    }

    Ok(updated_files)
}

/// Checks whether existing or all supported AI ignore files in the repository root are synchronized.
pub fn check_ai_shields(repo_root: &Path, patterns: &[String]) -> Result<bool> {
    let mut any_checked = false;
    for target_name in AI_IGNORE_TARGETS {
        let target_path = repo_root.join(target_name);
        if target_path.exists() {
            any_checked = true;
            if !is_single_ignore_file_synced(&target_path, patterns)? {
                return Ok(false);
            }
        }
    }
    if !any_checked && !patterns.is_empty() {
        return Ok(false);
    }
    Ok(true)
}
