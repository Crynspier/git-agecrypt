use anyhow::{Context, Result, anyhow};
use content_inspector::ContentType;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;

use crate::crypto::{clean_stream, smudge_stream};

/// Inspects the beginning of a file to check if it contains binary data.
pub fn is_file_binary(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; 8192];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(content_inspector::inspect(&buf) == ContentType::BINARY)
}

/// Decrypts a file (or copies if plaintext) to a temporary file via streaming.
fn decrypt_to_temp(path: &Path, identity: &dyn age::Identity) -> Result<NamedTempFile> {
    let mut temp_file =
        NamedTempFile::new().context("Failed to create temporary file for merge")?;
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
pub fn run_3way_merge(
    base: &Path,
    ours: &Path,
    theirs: &Path,
    marker_size: Option<usize>,
    file_path: &str,
    identity: &dyn age::Identity,
    recipient: &dyn age::Recipient,
) -> Result<i32> {
    // 1. Decrypt all 3 versions to temporary files
    let temp_base = decrypt_to_temp(base, identity)?;
    let temp_ours = decrypt_to_temp(ours, identity)?;
    let temp_theirs = decrypt_to_temp(theirs, identity)?;

    // 2. Binary collision guard: do not attempt text 3-way merge on binary assets!
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
    // and restore CRLF if %A originally used CRLF.
    let ours_bytes = fs::read(temp_ours.path())?;
    let ours_uses_crlf = ours_bytes.windows(2).any(|w| w == b"\r\n");

    let strip_cr = |data: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for i in 0..data.len() {
            if data[i] == b'\r' && i + 1 < data.len() && data[i + 1] == b'\n' {
                continue;
            }
            out.push(data[i]);
        }
        out
    };

    let base_bytes = fs::read(temp_base.path())?;
    let theirs_bytes = fs::read(temp_theirs.path())?;

    fs::write(temp_base.path(), strip_cr(&base_bytes))?;
    fs::write(temp_ours.path(), strip_cr(&ours_bytes))?;
    fs::write(temp_theirs.path(), strip_cr(&theirs_bytes))?;

    // 3. Run git merge-file on the decrypted temporary files
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

    // Line-ending canonicalization: git merge-file on Windows writes conflict markers with \r\n,
    // which can cause double-CR (\r\r\n) or mixed line endings when %A used LF.
    // Strip all \r before \n to canonicalize to pure LF first, then conditionally convert to CRLF if %A used CRLF.
    let merged_bytes = fs::read(temp_ours.path())?;
    let lf_bytes = strip_cr(&merged_bytes);
    if ours_uses_crlf {
        let mut crlf_bytes = Vec::with_capacity(lf_bytes.len() + lf_bytes.len() / 20);
        for b in lf_bytes {
            if b == b'\n' {
                crlf_bytes.push(b'\r');
            }
            crlf_bytes.push(b);
        }
        fs::write(temp_ours.path(), crlf_bytes)?;
    } else {
        fs::write(temp_ours.path(), lf_bytes)?;
    }

    // 4. Re-encrypt the merged result in temp_ours atomically into the target `ours` (%A)
    {
        let orig_readonly = fs::metadata(ours)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false);

        let merged_input = File::open(temp_ours.path())
            .context("Failed to open merged temporary file for re-encryption")?;
        let mut temp_target = NamedTempFile::new_in(merge_dir).with_context(|| {
            format!(
                "Failed to create temporary output for merge: {}",
                ours.display()
            )
        })?;

        let mut reader = BufReader::new(merged_input);
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
    }

    Ok(exit_code)
}
