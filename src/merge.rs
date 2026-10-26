use anyhow::{Context, Result, anyhow};
use content_inspector::ContentType;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;

use crate::crypto::{clean_stream, smudge_stream};

/// Maximum supported secret file size for automatic 3-way text merging (32 MiB).
/// Secrets exceeding this limit are refused to prevent unbounded memory and process stalls.
pub const MAX_TEXT_MERGE_FILE_SIZE: u64 = 32 * 1024 * 1024;

/// Detects binary content by streaming through the file in 64 KiB chunks.
/// Inspects the whole file to prevent smuggling binary payloads past the text-only guard (H1)
/// while guaranteeing O(1) memory usage.
pub fn is_file_binary(path: &Path) -> Result<bool> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if content_inspector::inspect(&buf[..n]) == ContentType::BINARY {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Detects whether a text file begins with CRLF line breaks.
fn detect_crlf(path: &Path) -> Result<bool> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut buf = [0u8; 64 * 1024];
    let n = reader.read(&mut buf)?;
    Ok(buf[..n].windows(2).any(|w| w == b"\r\n"))
}

/// Normalizes CRLF (\r\n) to LF (\n) in-place with bounded memory.
fn strip_cr_in_place(path: &Path) -> Result<()> {
    let data = fs::read(path)?;
    if !data.contains(&b'\r') {
        return Ok(());
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev_cr = false;
    for &b in &data {
        if prev_cr {
            if b == b'\n' {
                out.push(b'\n');
                prev_cr = false;
                continue;
            } else {
                out.push(b'\r');
                prev_cr = false;
            }
        }
        if b == b'\r' {
            prev_cr = true;
        } else {
            out.push(b);
        }
    }
    if prev_cr {
        out.push(b'\r');
    }
    fs::write(path, &out)?;
    Ok(())
}

/// Converts LF (\n) to CRLF (\r\n) in-place with bounded memory.
fn convert_lf_to_crlf_in_place(path: &Path) -> Result<()> {
    let data = fs::read(path)?;
    let mut out = Vec::with_capacity(data.len() + data.len() / 20);
    for &b in &data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    fs::write(path, &out)?;
    Ok(())
}

/// Checks whether a text file contains Git conflict markers in streaming fashion.
pub fn file_contains_conflict_markers(path: &Path) -> Result<bool> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut has_start = false;
    let mut has_sep = false;
    let mut has_end = false;
    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("<<<<<<< ") {
            has_start = true;
        } else if trimmed == "=======" {
            has_sep = true;
        } else if trimmed.starts_with(">>>>>>> ") {
            has_end = true;
        }
        if has_start && has_sep && has_end {
            return Ok(true);
        }
    }
    Ok(has_start && has_sep && has_end)
}

/// Decrypts a file (or copies if plaintext) to a temporary file via streaming.
/// When `temp_dir` is provided, the file is created inside the repository's restricted
/// spool directory rather than the shared (often world-readable) system temp dir (C1).
fn decrypt_to_temp(
    path: &Path,
    identity: &dyn age::Identity,
    temp_dir: Option<&Path>,
) -> Result<NamedTempFile> {
    let mut temp_file = match temp_dir {
        Some(dir) => {
            fs::create_dir_all(dir).context("Failed to create merge temp directory")?;
            NamedTempFile::new_in(dir)
        }
        None => NamedTempFile::new(),
    }
    .context("Failed to create temporary file for merge")?;
    if !path.exists() || fs::metadata(path)?.len() == 0 {
        // Empty or non-existent file: leave temp file empty
        return Ok(temp_file);
    }

    let input = File::open(path).with_context(|| {
        format!(
            "Failed to open file for merge decryption: {}",
            path.display()
        )
    })?;

    let mut reader = BufReader::new(input);
    {
        let mut writer = BufWriter::new(&mut temp_file);
        smudge_stream(&mut reader, &mut writer, Some(identity), None, None)
            .with_context(|| format!("Failed to decrypt merge participant: {}", path.display()))?;
        writer.flush()?;
    }

    Ok(temp_file)
}

/// Executes a 3-way merge on encrypted files %O (base), %A (ours), %B (theirs).
/// The merged result is re-encrypted back into %A.
/// Returns the exit code of `git merge-file` (0 on clean merge, >0 if conflicts marked).
#[allow(clippy::too_many_arguments)]
pub fn run_3way_merge(
    base: &Path,
    ours: &Path,
    theirs: &Path,
    marker_size: Option<usize>,
    file_path: &str,
    identity: &dyn age::Identity,
    recipient: &dyn age::Recipient,
    temp_dir: Option<&Path>,
) -> Result<i32> {
    // 1. Decrypt all 3 versions to temporary files
    let temp_base = decrypt_to_temp(base, identity, temp_dir)?;
    let temp_ours = decrypt_to_temp(ours, identity, temp_dir)?;
    let temp_theirs = decrypt_to_temp(theirs, identity, temp_dir)?;

    // 2. Resource & binary collision guards:
    let base_len = fs::metadata(temp_base.path())?.len();
    let ours_len = fs::metadata(temp_ours.path())?.len();
    let theirs_len = fs::metadata(temp_theirs.path())?.len();

    if base_len > MAX_TEXT_MERGE_FILE_SIZE
        || ours_len > MAX_TEXT_MERGE_FILE_SIZE
        || theirs_len > MAX_TEXT_MERGE_FILE_SIZE
    {
        eprintln!(
            "git-agecrypt [ERROR]: Secret file '{file_path}' exceeds maximum text merge limit of 32 MiB. \
             Automatic 3-way text merging cannot be performed on very large files without risking memory exhaustion. \
             Please resolve collision manually."
        );
        return Err(anyhow!(
            "File '{file_path}' too large for 3-way text merge (> 32 MiB): resolve collision manually"
        ));
    }

    if is_file_binary(temp_ours.path())?
        || is_file_binary(temp_theirs.path())?
        || is_file_binary(temp_base.path())?
    {
        eprintln!(
            "git-agecrypt [ERROR]: Binary secret detected for '{file_path}'. \
             Automatic 3-way text merging cannot be performed on binary files without corruption."
        );
        return Err(anyhow!(
            "Binary conflict on '{file_path}': resolve collision manually"
        ));
    }

    // Line-ending normalization: on -text secret files, Windows (\r\n) and Unix (\n) line breaks
    // cause git merge-file to falsely flag entire files as conflicting.
    // Detect whether our working copy (%A) uses CRLF, normalize all three to LF for the merge,
    // and restore CRLF if %A originally used CRLF. All normalization streams via disk to guarantee O(1) RAM.
    let ours_uses_crlf = detect_crlf(temp_ours.path())?;
    strip_cr_in_place(temp_base.path())?;
    strip_cr_in_place(temp_ours.path())?;
    strip_cr_in_place(temp_theirs.path())?;

    let base_has_markers = file_contains_conflict_markers(temp_base.path())?;

    // 3. Run git merge-file on the decrypted temporary files
    crate::git::crash_point("after_merge_decrypt");

    let merge_dir = match ours.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut cmd = crate::git::git_cmd_with_path(merge_dir);
    cmd.args(["-c", "color.ui=false"]);
    cmd.arg("merge-file");

    if let Some(ms) = marker_size {
        cmd.args(["--marker-size", &ms.to_string()]);
    }

    cmd.args(["-L", "HEAD (ours)"]);
    cmd.args(["-L", "base (ancestor)"]);
    cmd.args(["-L", "incoming (theirs)"]);

    // git merge-file modifies temp_ours in place
    cmd.arg(temp_ours.path());
    cmd.arg(temp_base.path());
    cmd.arg(temp_theirs.path());

    let status = cmd.status().context("Failed to execute 'git merge-file'")?;
    let exit_code = status.code().unwrap_or(1);

    crate::git::crash_point("after_merge_file");

    // Line-ending canonicalization: git merge-file on Windows writes conflict markers with \r\n,
    // which can cause double-CR (\r\r\n) or mixed line endings when %A used LF.
    // Strip all \r before \n to canonicalize to pure LF first, then conditionally convert to CRLF if %A used CRLF.
    strip_cr_in_place(temp_ours.path())?;
    if ours_uses_crlf {
        convert_lf_to_crlf_in_place(temp_ours.path())?;
    }

    // 4. Determine final merge status:
    // A false merge is worse than a visible conflict.
    // If git merge-file encountered conflicts OR conflict markers were introduced,
    // force a visible conflict (exit code >= 1).
    let merged_has_markers = file_contains_conflict_markers(temp_ours.path())?;

    let final_exit_code = if exit_code != 0 {
        exit_code
    } else if merged_has_markers && !base_has_markers {
        eprintln!(
            "git-agecrypt merge [CONFLICT]: Unresolved conflict markers detected in '{file_path}'. Forcing merge conflict."
        );
        1
    } else {
        0
    };

    if final_exit_code == 0 {
        check_semantic_conflicts_file(temp_ours.path(), file_path);
    } else {
        eprintln!(
            "git-agecrypt merge [CONFLICT]: Visible merge conflict in '{file_path}' (exit code {final_exit_code})."
        );
    }

    // 5. Re-encrypt the merged result in temp_ours atomically into the target `ours` (%A)
    {
        let orig_readonly = fs::metadata(ours)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false);

        let temp_dir_for_target = match ours.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let mut temp_target = NamedTempFile::new_in(temp_dir_for_target)
            .context("Failed to create temporary file for re-encrypting merge output")?;

        let input = File::open(temp_ours.path())
            .context("Failed to open merged temporary file for re-encryption")?;
        let mut reader = BufReader::new(input);
        {
            let mut writer = BufWriter::new(&mut temp_target);
            clean_stream(
                &mut reader,
                &mut writer,
                recipient,
                None,
                Some(identity),
                None,
                None,
            )
            .context("Failed to re-encrypt merged file into git target")?;
            writer
                .flush()
                .context("Failed to flush encrypted merge output")?;
        }

        struct MergeReadonlyGuard<'a>(&'a Path);
        impl<'a> Drop for MergeReadonlyGuard<'a> {
            fn drop(&mut self) {
                if self.0.exists()
                    && let Ok(mut perms) = fs::metadata(self.0).map(|m| m.permissions())
                {
                    perms.set_readonly(true);
                    let _ = fs::set_permissions(self.0, perms);
                }
            }
        }

        let _readonly_guard = if orig_readonly {
            if let Ok(mut perms) = fs::metadata(ours).map(|m| m.permissions()) {
                crate::git::set_permissions_writable(&mut perms);
                let _ = fs::set_permissions(ours, perms);
            }
            Some(MergeReadonlyGuard(ours))
        } else {
            None
        };

        // Request file synchronization before atomic rename; propagate failures on this critical path.
        temp_target.as_file().sync_all()?;
        crate::git::crash_point("after_merge_fsync");

        // Atomically replace `ours` with retry for antivirus software on Windows
        let mut to_persist = temp_target;
        let mut replaced = false;
        let mut last_err = None;
        for attempt in 0..5 {
            match to_persist.persist(ours) {
                Ok(_) => {
                    replaced = true;
                    break;
                }
                Err(e) => {
                    last_err = Some(e.error);
                    to_persist = e.file;
                    std::thread::sleep(std::time::Duration::from_millis(10 * (1 << attempt)));
                }
            }
        }

        if !replaced {
            let err_msg = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown error".to_string());
            return Err(anyhow!(
                "Failed to replace merge target '{}': {}",
                ours.display(),
                err_msg
            ));
        }

        crate::git::crash_point("after_merge_rename");
    }

    Ok(final_exit_code)
}

/// Checks whether a byte buffer contains standard Git 3-way conflict markers.
pub fn contains_conflict_markers(content: &[u8]) -> bool {
    let lines = content.split(|&b| b == b'\n');
    let mut has_start = false;
    let mut has_sep = false;
    let mut has_end = false;
    for line in lines {
        let trimmed = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.starts_with(b"<<<<<<< ") {
            has_start = true;
        } else if trimmed == b"=======" {
            has_sep = true;
        } else if trimmed.starts_with(b">>>>>>> ") {
            has_end = true;
        }
    }
    has_start && has_sep && has_end
}

#[derive(Debug, PartialEq, Eq)]
pub struct SemanticConflict {
    pub key: String,
    pub prev_line: usize,
    pub curr_line: usize,
    pub prev_val: String,
    pub curr_val: String,
}

/// Detects duplicate conflicting key definitions in merged key-value or .env files.
/// Gracefully handles multiline quoted strings and trailing comments.
pub fn find_semantic_conflicts(content: &[u8], file_path: &str) -> Vec<SemanticConflict> {
    let lower_path = file_path.to_lowercase();
    let is_key_val = lower_path.ends_with(".env")
        || lower_path.contains(".env.")
        || lower_path.ends_with(".conf")
        || lower_path.ends_with(".ini")
        || lower_path.ends_with(".properties");

    if !is_key_val {
        return Vec::new();
    }

    let mut conflicts = Vec::new();
    if let Ok(text) = std::str::from_utf8(content) {
        let mut seen_keys: std::collections::HashMap<String, (usize, String)> =
            std::collections::HashMap::new();
        let mut in_multiline: Option<(String, usize, char, String)> = None;

        for (line_idx, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();

            if let Some((key, start_line, quote_char, mut acc)) = in_multiline.take() {
                if let Some(idx) = line.find(quote_char) {
                    acc.push('\n');
                    acc.push_str(&line[..idx]);
                    if let Some((prev_line, prev_val)) = seen_keys.get(&key) {
                        if prev_val != &acc {
                            conflicts.push(SemanticConflict {
                                key: key.clone(),
                                prev_line: *prev_line,
                                curr_line: start_line + 1,
                                prev_val: prev_val.clone(),
                                curr_val: acc.clone(),
                            });
                        }
                    } else {
                        seen_keys.insert(key, (start_line + 1, acc));
                    }
                } else {
                    acc.push('\n');
                    acc.push_str(line);
                    in_multiline = Some((key, start_line, quote_char, acc));
                }
                continue;
            }

            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let effective = if let Some(stripped) = line.strip_prefix("export ") {
                stripped.trim()
            } else {
                line
            };

            if let Some((k, v)) = effective.split_once('=') {
                let key = k.trim().to_string();
                let val_raw = v.trim();

                if (val_raw.starts_with('"') || val_raw.starts_with('\''))
                    && val_raw.len() >= 2
                    && val_raw.ends_with(val_raw.chars().next().unwrap())
                {
                    let val = val_raw[1..val_raw.len() - 1].to_string();
                    if let Some((prev_line, prev_val)) = seen_keys.get(&key) {
                        if prev_val != &val {
                            conflicts.push(SemanticConflict {
                                key: key.clone(),
                                prev_line: *prev_line,
                                curr_line: line_idx + 1,
                                prev_val: prev_val.clone(),
                                curr_val: val,
                            });
                        }
                    } else {
                        seen_keys.insert(key, (line_idx + 1, val));
                    }
                } else if (val_raw.starts_with('"') || val_raw.starts_with('\''))
                    && (val_raw.len() == 1 || !val_raw.ends_with(val_raw.chars().next().unwrap()))
                {
                    let quote_char = val_raw.chars().next().unwrap();
                    in_multiline = Some((key, line_idx, quote_char, val_raw[1..].to_string()));
                } else {
                    let val = if let Some(idx) = val_raw.find('#') {
                        val_raw[..idx].trim().to_string()
                    } else {
                        val_raw.to_string()
                    };

                    if let Some((prev_line, prev_val)) = seen_keys.get(&key) {
                        if prev_val != &val {
                            conflicts.push(SemanticConflict {
                                key: key.clone(),
                                prev_line: *prev_line,
                                curr_line: line_idx + 1,
                                prev_val: prev_val.clone(),
                                curr_val: val,
                            });
                        }
                    } else {
                        seen_keys.insert(key, (line_idx + 1, val));
                    }
                }
            }
        }
    }
    conflicts
}

fn check_semantic_conflicts_file(path: &Path, file_path: &str) {
    let lower_path = file_path.to_lowercase();
    let is_key_val = lower_path.ends_with(".env")
        || lower_path.contains(".env.")
        || lower_path.ends_with(".conf")
        || lower_path.ends_with(".ini")
        || lower_path.ends_with(".properties");

    if !is_key_val {
        return;
    }

    if let Ok(meta) = fs::metadata(path)
        && meta.len() > 2 * 1024 * 1024
    {
        return;
    }

    if let Ok(content) = fs::read(path) {
        let conflicts = find_semantic_conflicts(&content, file_path);
        if !conflicts.is_empty() {
            eprintln!(
                "git-agecrypt merge [WARNING]: Potential semantic conflict detected in '{file_path}':"
            );
            for c in &conflicts {
                eprintln!(
                    "  Key '{}' defined multiple times with conflicting values:\n    line {}: {}\n    line {}: {}",
                    c.key, c.prev_line, c.prev_val, c.curr_line, c.curr_val
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_semantic_conflicts() {
        let content = b"# Database settings\nPORT=3000\nexport HOST=localhost\n# Concurrent branch added another PORT\nPORT=8080\n";
        let conflicts = find_semantic_conflicts(content, ".env");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].key, "PORT");
        assert_eq!(conflicts[0].prev_line, 2);
        assert_eq!(conflicts[0].curr_line, 5);
        assert_eq!(conflicts[0].prev_val, "3000");
        assert_eq!(conflicts[0].curr_val, "8080");

        // Same value duplicate is not a conflict
        let identical = b"API_KEY=xyz\nAPI_KEY=xyz\n";
        assert!(find_semantic_conflicts(identical, ".env").is_empty());

        // Non-key-val file is skipped
        let ignored = find_semantic_conflicts(content, "data.json");
        assert!(ignored.is_empty());
    }

    #[test]
    fn test_contains_conflict_markers() {
        let clean = b"KEY1=val1\nKEY2=val2\n";
        assert!(!contains_conflict_markers(clean));

        let conflict =
            b"<<<<<<< HEAD (ours)\nKEY1=val1\n=======\nKEY1=val2\n>>>>>>> incoming (theirs)\n";
        assert!(contains_conflict_markers(conflict));

        // Incomplete markers (missing separator or closing) should not trigger
        let incomplete = b"<<<<<<< HEAD (ours)\nKEY1=val1\n";
        assert!(!contains_conflict_markers(incomplete));
    }

    #[test]
    fn test_multiline_and_comment_semantic_conflicts() {
        let multiline_doc = b"CERT=\"line1\nline2\"\nCERT=\"diff1\ndiff2\"\n";
        let conflicts = find_semantic_conflicts(multiline_doc, ".env");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].key, "CERT");

        let comments_doc = b"TOKEN=abc # trailing comment\nTOKEN=def # another comment\n";
        let c2 = find_semantic_conflicts(comments_doc, ".env");
        assert_eq!(c2.len(), 1);
        assert_eq!(c2[0].key, "TOKEN");
        assert_eq!(c2[0].prev_val, "abc");
        assert_eq!(c2[0].curr_val, "def");
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]

        #[test]
        fn proptest_find_semantic_conflicts_never_panics(content in proptest::collection::vec(proptest::num::u8::ANY, 0..8192)) {
            let _ = find_semantic_conflicts(&content, ".env");
            let _ = find_semantic_conflicts(&content, "app.conf");
            let _ = find_semantic_conflicts(&content, "other.json");
        }
    }
}
