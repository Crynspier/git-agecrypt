use anyhow::{Context, Result, anyhow};
use glob::Pattern;
use sha2::Digest;
use std::fs::{self, File};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use crate::crypto::{AGE_HEADER_MAGIC, is_age_ciphertext};

/// Normalizes Windows paths to extended-length prefix (`\\?\`) when approaching MAX_PATH (260 chars).
/// Resolves relative paths to absolute paths first, and ensures all path separators are strictly backslashes (`\`)
/// because the Win32 verbatim `\\?\` prefix explicitly disables kernel path normalization and rejects forward slashes
/// or relative segments ('.' and '..') with ERROR_INVALID_NAME.
#[cfg(windows)]
pub fn ensure_extended_path(path: &Path) -> PathBuf {
    let abs_path = if path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    let s = abs_path.to_string_lossy().replace('/', "\\");
    if s.len() >= 240 && !s.starts_with(r"\\?\") {
        if let Ok(canonical) = fs::canonicalize(&abs_path) {
            let canon_str = canonical.to_string_lossy().replace('/', "\\");
            return PathBuf::from(canon_str);
        }
        if let Some(parent) = abs_path.parent()
            && let Ok(canon_parent) = fs::canonicalize(parent)
            && let Some(file_name) = abs_path.file_name()
        {
            let combined = canon_parent.join(file_name);
            let comb_str = combined.to_string_lossy().replace('/', "\\");
            return PathBuf::from(comb_str);
        }
        if let Some(stripped) = s.strip_prefix(r"\\") {
            return PathBuf::from(format!(r"\\?\UNC\{stripped}"));
        } else if s.chars().nth(1) == Some(':') {
            return PathBuf::from(format!(r"\\?\{s}"));
        }
    }
    PathBuf::from(s)
}

#[cfg(not(windows))]
pub fn ensure_extended_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// Cross-platform helper to safely make a file writable by its owner without setting group/world write bits on Unix.
#[inline]
pub fn set_permissions_writable(perms: &mut fs::Permissions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = perms.mode();
        perms.set_mode(mode | 0o200);
    }
    #[cfg(not(unix))]
    {
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
    }
}

/// Checks whether a process with the given PID is currently alive on the system.
#[cfg(windows)]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    const ERROR_ACCESS_DENIED: u32 = 5;

    unsafe {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(
                dwDesiredAccess: u32,
                bInheritHandle: i32,
                dwProcessId: u32,
            ) -> *mut std::ffi::c_void;
            fn GetExitCodeProcess(hProcess: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
            fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
            fn GetLastError() -> u32;
        }
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let err = GetLastError();
            // If access is denied, the process exists and is alive under an elevated/foreign token
            return err == ERROR_ACCESS_DENIED;
        }
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        ok != 0 && exit_code == STILL_ACTIVE
    }
}

#[cfg(not(windows))]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    unsafe {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        kill(pid as i32, 0) == 0
    }
}

/// Helper to construct a Git `Command` with the current executable's directory prepended to PATH.
/// This ensures Git filter drivers (clean, smudge, merge) can locate `git-agecrypt` when Git is spawned internally.
/// Also injects `-c color.ui=false` globally to prevent ANSI escape sequences from corrupting output parsing.
pub fn git_cmd_with_path<P: AsRef<Path>>(cwd: P) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd);
    cmd.args(["-c", "color.ui=false"]);
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let current_path = std::env::var("PATH").unwrap_or_default();
        let extra = if let Some(parent) = dir.parent() {
            format!("{};{};{}", dir.display(), parent.display(), current_path)
        } else {
            format!("{};{}", dir.display(), current_path)
        };
        cmd.env("PATH", extra);
    }
    cmd
}

/// Helper to peel any Git reference or annotated tag object to its underlying commit hash.
pub fn peel_to_commit(root: &Path, oid: &str) -> Option<String> {
    let out = git_cmd_with_path(root)
        .args(["rev-parse", "--verify", &format!("{oid}^{{commit}}")])
        .output();
    if let Ok(o) = out
        && o.status.success()
    {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

/// Helper to execute a Git command with retry upon index.lock contention.
pub fn run_git_cmd_with_index_retry(
    root: &Path,
    args: &[&str],
    max_retries: usize,
) -> io::Result<std::process::Output> {
    let mut attempts = 0;
    loop {
        let output = git_cmd_with_path(root).args(args).output()?;
        if output.status.success() {
            return Ok(output);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("index.lock") && attempts < max_retries {
            attempts += 1;
            std::thread::sleep(std::time::Duration::from_millis(50 * attempts as u64));
            continue;
        }
        return Ok(output);
    }
}

pub struct GitRepo {
    pub root: PathBuf,
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
}

impl GitRepo {
    /// Discovers the enclosing Git repository, git directory, and common directory (supporting worktrees).
    pub fn discover() -> Result<Self> {
        let output = Command::new("git")
            .args([
                "-c",
                "color.ui=false",
                "rev-parse",
                "--show-toplevel",
                "--git-dir",
                "--git-common-dir",
            ])
            .output()
            .map_err(|e| anyhow!("Failed to execute git command: {e}. Is git installed?"))?;

        if !output.status.success() {
            return Err(anyhow!("Not inside a Git repository"));
        }

        let text = String::from_utf8(output.stdout)?;
        let mut lines = text.lines();
        let root_str = lines
            .next()
            .ok_or_else(|| anyhow!("Failed to obtain repository root"))?;
        let git_dir_str = lines
            .next()
            .ok_or_else(|| anyhow!("Failed to obtain git directory"))?;
        let common_dir_str = lines.next().unwrap_or(git_dir_str);

        let root = PathBuf::from(root_str.trim());
        let cwd = std::env::current_dir().unwrap_or_else(|_| root.clone());

        let git_dir_path = PathBuf::from(git_dir_str.trim());
        let git_dir = if git_dir_path.is_absolute() {
            git_dir_path
        } else {
            cwd.join(git_dir_path)
        };

        let common_dir_path = PathBuf::from(common_dir_str.trim());
        let common_dir = if common_dir_path.is_absolute() {
            common_dir_path
        } else {
            cwd.join(common_dir_path)
        };

        Ok(Self {
            root,
            git_dir,
            common_dir,
        })
    }

    /// Checks whether this repository is a shallow clone (e.g. created with `--depth 1`).
    pub fn is_shallow(&self) -> bool {
        let out = git_cmd_with_path(&self.root)
            .args(["rev-parse", "--is-shallow-repository"])
            .output();
        if let Ok(o) = out
            && o.status.success()
        {
            return String::from_utf8_lossy(&o.stdout).trim() == "true";
        }
        self.git_dir.join("shallow").exists()
    }

    /// Path to the committed `.git-agecrypt` directory.
    pub fn agecrypt_metadata_dir(&self) -> PathBuf {
        self.root.join(".git-agecrypt")
    }

    /// Path to the committed public key file (`.git-agecrypt/repo.pub`).
    pub fn public_key_file(&self) -> PathBuf {
        self.agecrypt_metadata_dir().join("repo.pub")
    }

    /// Path to the committed recipient keys directory (`.git-agecrypt/keys/`).
    pub fn keys_dir(&self) -> PathBuf {
        self.agecrypt_metadata_dir().join("keys")
    }

    /// Path to local untracked cache directory in the common git dir (shared across worktrees).
    pub fn local_state_dir(&self) -> PathBuf {
        self.common_dir.join("git-agecrypt")
    }

    /// Path to local untracked master key (`repo.key`).
    pub fn local_master_key_file(&self) -> PathBuf {
        self.local_state_dir().join("repo.key")
    }

    /// Path to local untracked ciphertext cache directory in the common git dir.
    /// Namespaced by the repository master public key to guarantee that rotating
    /// keys (rekeying) immediately invalidates and isolates all previous cached ciphertexts.
    pub fn cache_dir(&self) -> PathBuf {
        let base_cache = self.local_state_dir().join("cache");
        let dir = if let Ok(pub_key) = fs::read_to_string(self.public_key_file()) {
            let digest = sha2::Sha256::digest(pub_key.trim().as_bytes());
            let hash_hex = format!("{:x}", digest);
            base_cache.join(&hash_hex[..16])
        } else {
            base_cache.join("default")
        };
        ensure_extended_path(&dir)
    }

    /// Purges all cached ciphertexts (e.g. during rekey or lock) and sweeps temp files.
    pub fn clear_cache(&self) -> Result<()> {
        let base_cache = self.local_state_dir().join("cache");
        if base_cache.exists() {
            fs::remove_dir_all(&base_cache)?;
        }
        self.sweep_orphaned_tmp_files();
        Ok(())
    }

    /// Checks if the repository is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.local_master_key_file().exists()
    }

    /// Path to the write-ahead log (WAL) journal file for lock operations.
    pub fn lock_journal_file(&self) -> PathBuf {
        self.local_state_dir().join("lock.journal")
    }

    /// Atomically stores the master secret key in `.git/git-agecrypt/repo.key`.
    pub fn save_local_master_key(&self, secret_key: &str) -> Result<()> {
        let state_dir = self.local_state_dir();
        fs::create_dir_all(&state_dir)?;

        let temp_path = state_dir.join(format!("repo.key.tmp.{}", std::process::id()));
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(secret_key.trim().as_bytes())?;
            file.flush()?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o600);
                fs::set_permissions(&temp_path, perms)?;
            }

            #[cfg(windows)]
            {
                if let Ok(user) = std::env::var("USERNAME")
                    && !user.is_empty()
                {
                    let path_str = temp_path.to_string_lossy().replace('/', "\\");
                    let grant_arg = format!("{user}:(R,W)");
                    let _ = Command::new("icacls")
                        .arg(&path_str)
                        .arg("/inheritance:r")
                        .arg("/grant:r")
                        .arg(&grant_arg)
                        .output();
                }
            }
        }

        let dest = self.local_master_key_file();

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let from_wide: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let to_wide: Vec<u16> = dest.as_os_str().encode_wide().chain(Some(0)).collect();
            const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
            const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn MoveFileExW(
                    lpExistingFileName: *const u16,
                    lpNewFileName: *const u16,
                    dwFlags: u32,
                ) -> i32;
            }

            let mut success = false;
            for _ in 0..5 {
                let ret = unsafe {
                    MoveFileExW(
                        from_wide.as_ptr(),
                        to_wide.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                    )
                };
                if ret != 0 {
                    success = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !success {
                let _ = fs::remove_file(&dest);
                fs::rename(&temp_path, &dest)?;
            }
        }

        #[cfg(not(windows))]
        {
            fs::rename(&temp_path, &dest)?;
        }
        Ok(())
    }

    /// Removes local master key, locking the repository.
    #[allow(dead_code)]
    pub fn lock(&self) -> Result<()> {
        let key_file = self.local_master_key_file();
        if key_file.exists() {
            fs::remove_file(key_file)?;
        }
        Ok(())
    }

    /// Checks for and resolves any dangling or interrupted lock transactions on startup.
    ///
    /// If repo.key.locking exists:
    /// - If repo.key already exists, the transaction succeeded and locking_file is stale: delete it.
    /// - If repo.key does not exist, lock was interrupted (Ctrl+C, crash, SIGKILL): restore repo.key
    ///   AND selectively re-smudge any files recorded in WAL lock.journal (or raw ciphertexts/truncated 0-byte files).
    ///   Uncommitted plaintext modifications in any linked worktree are never overwritten.
    ///
    /// Also sweeps any orphaned temporary spool files left in .git/git-agecrypt/.
    pub fn recover_interrupted_transaction(&self) {
        let locking_file = self.local_state_dir().join("repo.key.locking");
        let journal_file = self.lock_journal_file();

        if locking_file.exists() {
            let key_file = self.local_master_key_file();
            if key_file.exists() {
                let _ = fs::remove_file(&locking_file);
                if journal_file.exists() {
                    let _ = fs::remove_file(&journal_file);
                }
            } else {
                let lock_mtime = fs::metadata(&locking_file).and_then(|m| m.modified()).ok();
                if fs::rename(&locking_file, &key_file).is_ok() {
                    eprintln!(
                        "git-agecrypt [WARNING]: Recovered interrupted lock transaction. Master key has been restored."
                    );
                    // Replay recovery from WAL journal if present, or fallback to selective scan
                    let _ = self.replay_lock_journal_or_selective(lock_mtime);
                }
            }
        } else if journal_file.exists() {
            let _ = fs::remove_file(&journal_file);
        }

        // Clean up stale refresh.lock if older than 10s
        let refresh_lock = self.local_state_dir().join("refresh.lock");
        if refresh_lock.exists()
            && let Ok(meta) = fs::metadata(&refresh_lock)
            && let Ok(mtime) = meta.modified()
            && let Ok(age) = mtime.elapsed()
            && age > std::time::Duration::from_secs(10)
        {
            let _ = fs::remove_file(&refresh_lock);
        }

        self.sweep_orphaned_tmp_files();
    }

    /// Replays recovery for an interrupted lock transaction using the WAL journal (`lock.journal`),
    /// restoring any truncated (0-byte) or partially smudged (age ciphertext) secret files back to cleartext.
    /// If no journal exists (e.g. legacy transaction), falls back to scanning worktrees selectively.
    pub fn replay_lock_journal_or_selective(
        &self,
        lock_mtime: Option<std::time::SystemTime>,
    ) -> Result<()> {
        let journal_file = self.lock_journal_file();
        if journal_file.exists() {
            if let Ok(content) = fs::read_to_string(&journal_file) {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() == 2 {
                        let wt_path = PathBuf::from(parts[0]);
                        let rel_path = parts[1];
                        let full_path = wt_path.join(rel_path);
                        if full_path.exists() {
                            let repo_for_wt = GitRepo {
                                root: wt_path.clone(),
                                git_dir: self.git_dir.clone(),
                                common_dir: self.common_dir.clone(),
                            };

                            let is_empty = fs::metadata(&full_path)
                                .map(|m| m.len() == 0)
                                .unwrap_or(false);
                            let should_resmudge = if is_empty {
                                repo_for_wt.is_staged_blob_non_empty(rel_path)
                            } else if let Ok(mut f) = File::open(&full_path) {
                                let mut prefix = [0u8; AGE_HEADER_MAGIC.len()];
                                if let Ok(n) = f.read(&mut prefix) {
                                    is_age_ciphertext(&prefix[..n])
                                } else {
                                    false
                                }
                            } else {
                                false
                            };

                            if should_resmudge {
                                let orig_readonly = fs::metadata(&full_path)
                                    .map(|m| m.permissions().readonly())
                                    .unwrap_or(false);

                                if orig_readonly && let Ok(meta) = fs::metadata(&full_path) {
                                    let mut perms = meta.permissions();
                                    set_permissions_writable(&mut perms);
                                    let _ = fs::set_permissions(&full_path, perms);
                                }

                                let _ = fs::remove_file(&full_path);
                                let _ = git_cmd_with_path(&wt_path)
                                    .args(["checkout-index", "-f", "-u", "--", rel_path])
                                    .status();

                                if orig_readonly
                                    && full_path.exists()
                                    && let Ok(meta) = fs::metadata(&full_path)
                                {
                                    let mut perms = meta.permissions();
                                    perms.set_readonly(true);
                                    let _ = fs::set_permissions(&full_path, perms);
                                }
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_file(&journal_file);
            Ok(())
        } else {
            self.recover_worktrees_selective(lock_mtime)
        }
    }

    /// Selectively re-smudges only working tree files that currently contain raw Age ciphertext on disk.
    /// Does NOT touch plaintext files, ensuring uncommitted local modifications are never overwritten.
    /// 0-byte truncated files are only recovered if their modification timestamp aligns with the lock transaction (<= 60s).
    pub fn recover_worktrees_selective(
        &self,
        lock_mtime: Option<std::time::SystemTime>,
    ) -> Result<()> {
        let worktrees = self.list_worktrees()?;
        for wt in worktrees {
            if !wt.join(".git").exists() {
                continue;
            }
            let repo_for_wt = GitRepo {
                root: wt.clone(),
                git_dir: self.git_dir.clone(),
                common_dir: self.common_dir.clone(),
            };
            let ls_out = git_cmd_with_path(&wt).args(["ls-files", "-z"]).output();
            if let Ok(out) = ls_out {
                for path_slice in out.stdout.split(|&b| b == 0) {
                    if !path_slice.is_empty() {
                        let rel_path = String::from_utf8_lossy(path_slice);
                        if repo_for_wt.is_file_tracked(&rel_path) {
                            let full_path = wt.join(&*rel_path);
                            if full_path.exists() {
                                let is_empty = fs::metadata(&full_path)
                                    .map(|m| m.len() == 0)
                                    .unwrap_or(false);
                                let should_resmudge = if is_empty {
                                    // 0-byte truncated file from interrupted checkout:
                                    // Verify that file modification is temporally correlated with the lock transaction (within 60s).
                                    // Intentional user modifications made outside the transaction window are preserved!
                                    let file_mtime =
                                        fs::metadata(&full_path).and_then(|m| m.modified()).ok();
                                    let within_crash_window = match (file_mtime, lock_mtime) {
                                        (Some(f_time), Some(l_time)) => {
                                            let diff = if f_time >= l_time {
                                                f_time.duration_since(l_time).unwrap_or_default()
                                            } else {
                                                l_time.duration_since(f_time).unwrap_or_default()
                                            };
                                            diff.as_secs() <= 60
                                        }
                                        _ => true,
                                    };

                                    within_crash_window
                                        && repo_for_wt.is_staged_blob_non_empty(&rel_path)
                                } else if let Ok(mut f) = File::open(&full_path) {
                                    let mut prefix = [0u8; AGE_HEADER_MAGIC.len()];
                                    if let Ok(n) = f.read(&mut prefix) {
                                        is_age_ciphertext(&prefix[..n])
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if should_resmudge {
                                    let orig_readonly = fs::metadata(&full_path)
                                        .map(|m| m.permissions().readonly())
                                        .unwrap_or(false);

                                    if orig_readonly && let Ok(meta) = fs::metadata(&full_path) {
                                        let mut perms = meta.permissions();
                                        set_permissions_writable(&mut perms);
                                        let _ = fs::set_permissions(&full_path, perms);
                                    }

                                    let _ = fs::remove_file(&full_path);
                                    let _ = git_cmd_with_path(&wt)
                                        .args(["checkout-index", "-f", "-u", "--", &*rel_path])
                                        .status();

                                    if orig_readonly
                                        && full_path.exists()
                                        && let Ok(meta) = fs::metadata(&full_path)
                                    {
                                        let mut perms = meta.permissions();
                                        perms.set_readonly(true);
                                        let _ = fs::set_permissions(&full_path, perms);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Checks whether the staged blob in Git index for `rel_path` has non-zero length.
    pub fn is_staged_blob_non_empty(&self, rel_path: &str) -> bool {
        let output = git_cmd_with_path(&self.root)
            .args(["cat-file", "-s", &format!(":{rel_path}")])
            .output();
        if let Ok(out) = output
            && out.status.success()
        {
            let size_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(size) = size_str.trim().parse::<u64>() {
                return size > 0;
            }
        }
        false
    }

    /// Fetches the raw staged blob from the Git index for `rel_path` (:0:<clean_path>) if present.
    pub fn get_staged_blob(&self, rel_path: &str) -> Option<Vec<u8>> {
        let clean_path = rel_path.trim_start_matches('/').trim_start_matches('\\');
        let out = git_cmd_with_path(&self.root)
            .args(["cat-file", "blob", &format!(":0:{clean_path}")])
            .output()
            .ok()?;
        if out.status.success() && !out.stdout.is_empty() {
            Some(out.stdout)
        } else {
            None
        }
    }

    /// Reads up to `max_bytes` of a blob from Git object database or staging index without buffering the whole file.
    pub fn read_blob_header(&self, target: &str, max_bytes: usize) -> Option<Vec<u8>> {
        let clean_target = if let Some(stripped) = target.strip_prefix(":0:") {
            let path = stripped.trim_start_matches('/').trim_start_matches('\\');
            format!(":0:{path}")
        } else {
            target.to_string()
        };

        let mut child = git_cmd_with_path(&self.root)
            .args(["cat-file", "blob", &clean_target])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        let mut buf = Vec::with_capacity(max_bytes.min(65536));
        if let Some(mut stdout) = child.stdout.take() {
            let mut limited = (&mut stdout).take(max_bytes as u64);
            let _ = limited.read_to_end(&mut buf);
        }
        let _ = child.kill();
        let _ = child.wait();

        if !buf.is_empty() { Some(buf) } else { None }
    }

    /// Returns any registered linked worktrees whose directory or .git reference is unreachable/detached.
    pub fn get_unreachable_worktrees(&self) -> Result<Vec<PathBuf>> {
        let worktrees = self.list_all_registered_worktrees()?;
        let mut unreachable = Vec::new();
        for wt in worktrees {
            if !wt.exists() || !wt.join(".git").exists() {
                unreachable.push(wt);
            }
        }
        Ok(unreachable)
    }

    /// Recursively scans .git/git-agecrypt/ and removes any abandoned temporary spool files
    /// (e.g. .tmp*, *tmp*, *.tmp) while strictly preserving persistent files (repo.key, *.age, *.pub).
    pub fn sweep_orphaned_tmp_files(&self) {
        let state_dir = self.local_state_dir();
        sweep_tmp_recursive(&state_dir);
    }

    /// Verifies that all tracked secret files across all active worktrees can be replaced during checkout.
    /// Fails fast before any files are modified if an application or background process holds an exclusive sharing lock.
    /// Read-only secrets (e.g. 0400 or attrib +r) are supported without permanent permission mutations.
    pub fn preflight_check_writable(&self) -> Result<()> {
        let worktrees = self.list_worktrees()?;
        for wt in worktrees {
            if !wt.join(".git").exists() {
                continue;
            }
            let repo_for_wt = GitRepo {
                root: wt.clone(),
                git_dir: self.git_dir.clone(),
                common_dir: self.common_dir.clone(),
            };
            let ls_out = git_cmd_with_path(&wt).args(["ls-files", "-z"]).output();

            if let Ok(out) = ls_out {
                for path_slice in out.stdout.split(|&b| b == 0) {
                    if !path_slice.is_empty() {
                        let rel_path = String::from_utf8_lossy(path_slice);
                        if repo_for_wt.is_file_tracked(&rel_path) {
                            let full_path = wt.join(&*rel_path);
                            if full_path.exists() {
                                let meta = fs::metadata(&full_path).ok();
                                let is_readonly = meta
                                    .as_ref()
                                    .map(|m| m.permissions().readonly())
                                    .unwrap_or(false);

                                #[cfg(windows)]
                                {
                                    if is_readonly {
                                        if let Some(m) = meta {
                                            let orig = m.permissions();
                                            let mut temp = orig.clone();
                                            set_permissions_writable(&mut temp);
                                            if fs::set_permissions(&full_path, temp).is_ok() {
                                                let _ = fs::set_permissions(&full_path, orig);
                                            } else {
                                                return Err(anyhow!(
                                                    "Tracked secret file '{}' in worktree '{}' has read-only permissions that cannot be toggled.",
                                                    rel_path,
                                                    wt.display()
                                                ));
                                            }
                                        }
                                    } else {
                                        match fs::OpenOptions::new().write(true).open(&full_path) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                if err.raw_os_error() == Some(32) {
                                                    return Err(anyhow!(
                                                        "Tracked secret file '{}' in worktree '{}' is locked by another process (sharing violation). \
                                                         Please close any application holding this file open before locking.",
                                                        rel_path,
                                                        wt.display()
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }

                                #[cfg(not(windows))]
                                {
                                    if is_readonly {
                                        if let Some(parent) = full_path.parent() {
                                            if let Ok(parent_meta) = fs::metadata(parent) {
                                                if parent_meta.permissions().readonly() {
                                                    return Err(anyhow!(
                                                        "Parent directory of read-only secret file '{}' in worktree '{}' is not writable.",
                                                        rel_path,
                                                        wt.display()
                                                    ));
                                                }
                                            }
                                        }
                                    } else {
                                        match fs::OpenOptions::new().write(true).open(&full_path) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                return Err(anyhow!(
                                                    "Tracked secret file '{}' in worktree '{}' cannot be written to ({}). \
                                                     Please close any application or process holding this file open before locking.",
                                                    rel_path,
                                                    wt.display(),
                                                    err
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Executes a closure during lock, rolling back `repo.key` and re-smudging files if the operation fails.
    /// Atomically stages `repo.key` -> `repo.key.locking`.
    /// If `f()` succeeds: removes `repo.key.locking` and `lock.journal`.
    /// If `f()` fails: restores `repo.key.locking` -> `repo.key` AND replays recovery from `lock.journal`.
    pub fn transactional_lock<F: FnOnce() -> Result<()>>(&self, f: F) -> Result<()> {
        let key_file = self.local_master_key_file();
        if !key_file.exists() {
            return f();
        }

        // 1. Preflight check: ensure all secret files across all worktrees can be written to
        self.preflight_check_writable()
            .context("Aborting lock due to locked file(s)")?;

        // 2. Write-Ahead Log (WAL): Record all target secret files across all worktrees into lock.journal
        let journal_file = self.lock_journal_file();
        let mut journal_content = String::new();
        if let Ok(worktrees) = self.list_worktrees() {
            for wt in worktrees {
                if !wt.join(".git").exists() {
                    continue;
                }
                let repo_for_wt = GitRepo {
                    root: wt.clone(),
                    git_dir: self.git_dir.clone(),
                    common_dir: self.common_dir.clone(),
                };
                if let Ok(out) = git_cmd_with_path(&wt).args(["ls-files", "-z"]).output() {
                    for path_slice in out.stdout.split(|&b| b == 0) {
                        if !path_slice.is_empty() {
                            let rel_path = String::from_utf8_lossy(path_slice);
                            if repo_for_wt.is_file_tracked(&rel_path) {
                                journal_content.push_str(&format!(
                                    "{}\t{}\n",
                                    wt.display(),
                                    rel_path
                                ));
                            }
                        }
                    }
                }
            }
        }

        if let Ok(mut jf) = File::create(&journal_file) {
            let _ = jf.write_all(journal_content.as_bytes());
            let _ = jf.sync_all();
        }

        let locking_file = self.local_state_dir().join("repo.key.locking");
        if locking_file.exists() {
            let _ = fs::remove_file(&locking_file);
        }
        fs::rename(&key_file, &locking_file).context("Failed to stage master key for locking")?;

        match f() {
            Ok(()) => {
                if locking_file.exists() {
                    let _ = fs::remove_file(&locking_file);
                }
                if journal_file.exists() {
                    let _ = fs::remove_file(&journal_file);
                }
                Ok(())
            }
            Err(err) => {
                // Rollback: restore master key AND replay recovery from journal
                if locking_file.exists() {
                    let lock_mtime = fs::metadata(&locking_file).and_then(|m| m.modified()).ok();
                    let _ = fs::rename(&locking_file, &key_file);
                    let _ = self.replay_lock_journal_or_selective(lock_mtime);
                }
                Err(err)
            }
        }
    }

    /// Reads the stored local master key if present.
    pub fn read_local_master_key(&self) -> Result<Option<String>> {
        let key_file = self.local_master_key_file();
        if !key_file.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(key_file)?;
        Ok(Some(content.trim().to_string()))
    }

    /// Checks if the locally saved master key is stale relative to the committed `.git-agecrypt/repo.pub`.
    /// This happens when an upstream teammate re-keyed the repository and the current user pulled changes.
    pub fn is_local_master_key_stale(&self) -> Result<bool> {
        let pub_file = self.public_key_file();
        if !pub_file.exists() {
            return Ok(false);
        }
        let Some(key_str) = self.read_local_master_key()? else {
            return Ok(false);
        };
        let pub_content = fs::read_to_string(&pub_file)?;
        let expected_recipient = pub_content.trim();
        if expected_recipient.is_empty() {
            return Ok(false);
        }

        if let Ok(identity) = age::x25519::Identity::from_str(&key_str) {
            let actual_recipient = format!("{}", identity.to_public());
            if actual_recipient != expected_recipient {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Attempts to automatically synchronize and unwrap a rotated master key from `.git-agecrypt/keys/*.age`
    /// using standard SSH/age identity keys on the local system.
    /// Uses an advisory file lock (`refresh.lock`) with wait-and-adopt polling to prevent race conditions
    /// between parallel smudge workers (`checkout.workers > 1`), and runs strictly non-interactively.
    pub fn try_auto_refresh_master_key(&self) -> Result<Option<String>> {
        let keys_dir = self.keys_dir();
        if !keys_dir.exists() {
            return Ok(None);
        }

        // Fast-path: check if another worker already refreshed the key
        if !self.is_local_master_key_stale().unwrap_or(true) {
            return self.read_local_master_key();
        }

        let state_dir = self.local_state_dir();
        let _ = fs::create_dir_all(&state_dir);
        let lock_path = state_dir.join("refresh.lock");
        let start = std::time::Instant::now();
        let mut _guard = None;

        // Acquire advisory lock with wait-and-adopt protocol for parallel smudge workers
        while start.elapsed() < std::time::Duration::from_secs(5) {
            if !self.is_local_master_key_stale().unwrap_or(true) {
                return self.read_local_master_key();
            }

            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    let pid = std::process::id();
                    let now_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let _ = write!(file, "{pid}:{now_ts}");
                    let _ = file.flush();

                    struct LockGuard(PathBuf);
                    impl Drop for LockGuard {
                        fn drop(&mut self) {
                            let _ = fs::remove_file(&self.0);
                        }
                    }
                    _guard = Some(LockGuard(lock_path.clone()));
                    drop(file);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Check PID liveness and timestamp to break stale or abandoned locks immediately
                    let mut is_stale = false;
                    if let Ok(content) = fs::read_to_string(&lock_path) {
                        let parts: Vec<&str> = content.trim().split(':').collect();
                        if let Some(pid_str) = parts.first()
                            && let Ok(pid) = pid_str.parse::<u32>()
                            && !is_pid_alive(pid)
                        {
                            is_stale = true;
                        }
                        if !is_stale
                            && parts.len() >= 2
                            && let Ok(ts) = parts[1].parse::<u64>()
                        {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            if now.saturating_sub(ts) > 5 {
                                is_stale = true;
                            }
                        }
                    } else if let Ok(meta) = fs::metadata(&lock_path)
                        && let Ok(mtime) = meta.modified()
                        && let Ok(age) = mtime.elapsed()
                        && age > std::time::Duration::from_secs(5)
                    {
                        is_stale = true;
                    }

                    if is_stale {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }

                    std::thread::sleep(std::time::Duration::from_millis(30));
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(30));
                }
            }
        }

        // Check again after acquiring or timing out
        if !self.is_local_master_key_stale().unwrap_or(true) {
            return self.read_local_master_key();
        }

        // Only use non-interactive loader so we never touch stdin or prompt in background filter!
        let candidates = crate::crypto::get_default_identity_paths();
        let mut identities = Vec::new();
        for candidate in candidates {
            if candidate.exists()
                && let Ok(ids) =
                    crate::crypto::load_identities_from_file_non_interactive(&candidate)
            {
                identities.extend(ids);
            }
        }

        if identities.is_empty() {
            return Ok(None);
        }

        let expected_pub = if let Ok(pub_content) = fs::read_to_string(self.public_key_file()) {
            let trimmed = pub_content.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        } else {
            None
        };

        let entries = fs::read_dir(&keys_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age")
                && let Ok(content) = fs::read_to_string(&path)
                && let Ok(master_key) = crate::crypto::unwrap_master_key(&content, &identities)
            {
                if let Some(ref exp) = expected_pub
                    && let Ok(id) = age::x25519::Identity::from_str(&master_key)
                    && format!("{}", id.to_public()) != *exp
                {
                    continue;
                }
                self.save_local_master_key(&master_key)?;
                return Ok(Some(master_key));
            }
        }
        Ok(None)
    }

    /// Detects if an active Git operation (rebase, merge, cherry-pick, revert, bisect) is in progress
    /// in this repository or any linked worktree.
    pub fn check_active_git_operations(&self) -> Result<Option<String>> {
        let worktrees = self.list_worktrees()?;
        for wt in worktrees {
            let wt_git_dir = if wt.join(".git").is_dir() {
                wt.join(".git")
            } else if wt.join(".git").is_file() {
                if let Ok(content) = fs::read_to_string(wt.join(".git")) {
                    if let Some(gitdir_str) = content.trim().strip_prefix("gitdir:") {
                        let gd_path = PathBuf::from(gitdir_str.trim());
                        if gd_path.is_absolute() {
                            gd_path
                        } else {
                            wt.join(gd_path)
                        }
                    } else {
                        self.git_dir.clone()
                    }
                } else {
                    self.git_dir.clone()
                }
            } else {
                self.git_dir.clone()
            };

            let dirs_to_check = [&wt_git_dir, &self.git_dir, &self.common_dir];
            for d in dirs_to_check {
                if d.join("rebase-merge").exists() {
                    return Ok(Some(
                        "interactive rebase in progress (rebase-merge)".to_string(),
                    ));
                }
                if d.join("rebase-apply").exists() {
                    return Ok(Some(
                        "rebase / apply in progress (rebase-apply)".to_string(),
                    ));
                }
                if d.join("MERGE_HEAD").exists() {
                    return Ok(Some("merge in progress (MERGE_HEAD)".to_string()));
                }
                if d.join("CHERRY_PICK_HEAD").exists() {
                    return Ok(Some(
                        "cherry-pick in progress (CHERRY_PICK_HEAD)".to_string(),
                    ));
                }
                if d.join("REVERT_HEAD").exists() {
                    return Ok(Some("revert in progress (REVERT_HEAD)".to_string()));
                }
                if d.join("BISECT_LOG").exists() {
                    return Ok(Some("bisect in progress (BISECT_LOG)".to_string()));
                }
            }
        }
        Ok(None)
    }

    /// Configures the git filter, diff, and merge drivers in local `.git/config`.
    pub fn configure_git_filters(&self) -> Result<()> {
        let configs = [
            ("filter.agecrypt.clean", "git-agecrypt clean %f"),
            ("filter.agecrypt.smudge", "git-agecrypt smudge %f"),
            ("filter.agecrypt.required", "true"),
            ("diff.agecrypt.textconv", "git-agecrypt textconv"),
            (
                "merge.agecrypt.driver",
                "git-agecrypt merge \"%O\" \"%A\" \"%B\" %L \"%P\"",
            ),
            ("merge.agecrypt.name", "git-agecrypt 3-way merge driver"),
        ];

        for (key, val) in configs {
            let status = git_cmd_with_path(&self.root)
                .args(["config", "--local", key, val])
                .status()
                .with_context(|| format!("Failed to set git config '{key}'"))?;

            if !status.success() {
                return Err(anyhow!("Failed to set git config: {key} = {val}"));
            }
        }
        Ok(())
    }

    /// Resolves the Git hooks directory, respecting `core.hooksPath` configuration.
    pub fn hooks_dir(&self) -> PathBuf {
        let out = git_cmd_with_path(&self.root)
            .args(["config", "--get", "core.hooksPath"])
            .output();
        if let Ok(o) = out
            && o.status.success()
        {
            let path_str = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !path_str.is_empty() {
                let p = PathBuf::from(path_str);
                if p.is_absolute() {
                    return p;
                } else {
                    return self.root.join(p);
                }
            }
        }
        self.common_dir.join("hooks")
    }

    /// Installs safeguard hooks (pre-commit, pre-merge-commit, pre-push), respecting `core.hooksPath`
    /// and preserving any existing user hook scripts.
    pub fn install_pre_commit_hook(&self) -> Result<()> {
        let hooks_dir = self.hooks_dir();
        fs::create_dir_all(&hooks_dir)?;

        let current_exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| {
                let s = p.to_string_lossy();
                let clean = s.strip_prefix(r"\\?\").unwrap_or(&s);
                clean.replace('\\', "/")
            })
            .unwrap_or_default();

        let hook_configs = [
            ("pre-commit", "check"),
            ("pre-merge-commit", "check"),
            ("pre-push", "check --pre-push"),
        ];

        for (name, args) in &hook_configs {
            let hook_path = hooks_dir.join(name);
            let snippet = format!(
                "# git-agecrypt automated {name} safeguard: git-agecrypt {args}\n\
                 if command -v git-agecrypt >/dev/null 2>&1; then\n\
                     EXEC=\"git-agecrypt\"\n\
                 elif [ -n \"{current_exe}\" ] && [ -x \"{current_exe}\" ]; then\n\
                     EXEC=\"{current_exe}\"\n\
                 elif [ -f \"$HOME/.cargo/bin/git-agecrypt\" ]; then\n\
                     EXEC=\"$HOME/.cargo/bin/git-agecrypt\"\n\
                 else\n\
                     EXEC=\"git-agecrypt\"\n\
                 fi\n\
                 \"$EXEC\" {args} || exit 1\n"
            );

            if hook_path.exists() {
                let existing_content = fs::read_to_string(&hook_path).unwrap_or_default();
                if !existing_content.contains("git-agecrypt") {
                    let shebang_end = if existing_content.starts_with("#!") {
                        existing_content.find('\n').map(|i| i + 1).unwrap_or(0)
                    } else {
                        0
                    };
                    let mut updated = String::new();
                    updated.push_str(&existing_content[..shebang_end]);
                    if shebang_end > 0 && !updated.ends_with('\n') {
                        updated.push('\n');
                    }
                    updated.push_str(&snippet);
                    if !snippet.ends_with('\n') {
                        updated.push('\n');
                    }
                    updated.push_str(&existing_content[shebang_end..]);
                    fs::write(&hook_path, updated)?;
                }
            } else {
                let full_script = format!("#!/bin/sh\n{snippet}");
                fs::write(&hook_path, full_script)?;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o755);
                let _ = fs::set_permissions(&hook_path, perms);
            }
        }

        Ok(())
    }

    /// Reads patterns configured for agecrypt from `.gitattributes`.
    /// Reads patterns configured for agecrypt from `.gitattributes` and validates attributes.
    pub fn get_tracked_patterns(&self) -> Result<Vec<String>> {
        let gitattributes_path = self.root.join(".gitattributes");
        if !gitattributes_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&gitattributes_path)?;
        let mut patterns = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains("filter=agecrypt") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if let Some(pat) = parts.first() {
                    patterns.push(pat.to_string());

                    // Check for conflicting filter drivers (e.g. filter=lfs)
                    if trimmed.contains("filter=lfs") {
                        eprintln!(
                            "git-agecrypt [WARNING]: Pattern '{pat}' in .gitattributes specifies both 'filter=agecrypt' and 'filter=lfs'. \
                             Git does not support filter chaining; one driver will silently override the other!"
                        );
                    }

                    // Check for missing -text binary flag
                    if !trimmed.contains("-text") && !trimmed.contains("binary") {
                        eprintln!(
                            "git-agecrypt [WARNING]: Pattern '{pat}' in .gitattributes does not specify '-text'. \
                             Add '-text' to ensure Git never corrupts binary Age ciphertexts with Windows CRLF conversion."
                        );
                    }
                }
            }
        }

        Ok(patterns)
    }

    /// Checks if a file path matches any tracked agecrypt pattern.
    pub fn matches_tracked_pattern(&self, file_path: &str, patterns: &[String]) -> bool {
        let normalized = file_path.replace('\\', "/");
        for pat in patterns {
            if let Ok(matcher) = Pattern::new(pat) {
                if matcher.matches(&normalized) {
                    return true;
                }
                // Handle patterns like "secrets/**" matching "secrets/sub/file.env"
                if pat.ends_with("/**") {
                    let prefix = pat.trim_end_matches("/**");
                    if normalized.starts_with(prefix) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Checks whether Git assigns the `agecrypt` filter to a file path.
    /// Uses `git check-attr filter -- <path>` for native multi-level attribute resolution,
    /// with a fallback to `matches_tracked_pattern`.
    pub fn is_file_tracked(&self, file_path: &str) -> bool {
        let normalized = file_path.replace('\\', "/");
        let output = git_cmd_with_path(&self.root)
            .args(["check-attr", "filter", "--", &normalized])
            .output();

        if let Ok(out) = output
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            // Output format: "<path>: filter: agecrypt"
            if text.contains(": filter: agecrypt") {
                return true;
            }
        }

        // Fallback: check root .gitattributes patterns
        if let Ok(patterns) = self.get_tracked_patterns() {
            return self.matches_tracked_pattern(&normalized, &patterns);
        }
        false
    }

    /// Checks if a staged file is a symlink (mode 120000) or submodule/gitlink (mode 160000) in Git index.
    fn is_staged_special_entry(&self, path_str: &str) -> bool {
        let norm_path = path_str.replace('\\', "/");
        let output = git_cmd_with_path(&self.root)
            .args(["ls-files", "--stage", "--", &norm_path])
            .output();

        if let Ok(out) = output
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(mode) = text.split_whitespace().next() {
                return mode == "120000" || mode == "160000";
            }
        }
        false
    }

    /// Inspects staged blobs to ensure no unencrypted secrets are committed.
    /// Used by `git-agecrypt check` and the pre-commit hook.
    pub fn check_staged_files(&self) -> Result<()> {
        let patterns = self.get_tracked_patterns()?;
        if patterns.is_empty() {
            return Ok(());
        }

        let mut diff_cmd = git_cmd_with_path(&self.root);
        diff_cmd.args(["diff", "--cached", "--name-status", "-z"]);
        let output = match diff_cmd.output() {
            Ok(out) if out.status.success() => out,
            _ => {
                // Universal fallback for unborn HEAD or older Git versions: diff against empty tree hash
                let mut fallback_cmd = git_cmd_with_path(&self.root);
                fallback_cmd.args([
                    "diff-index",
                    "--cached",
                    "--name-status",
                    "-z",
                    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                ]);
                fallback_cmd
                    .output()
                    .context("Failed to list staged files")?
            }
        };

        let raw_slices: Vec<&[u8]> = output
            .stdout
            .split(|&b| b == 0)
            .filter(|slice| !slice.is_empty())
            .collect();

        let mut paths_to_check = Vec::new();
        let mut unprotected_renames = Vec::new();

        let mut i = 0;
        while i < raw_slices.len() {
            let status = String::from_utf8_lossy(raw_slices[i]);
            if status.starts_with('R') || status.starts_with('C') {
                if i + 2 < raw_slices.len() {
                    let old_path = String::from_utf8_lossy(raw_slices[i + 1]).to_string();
                    let new_path = String::from_utf8_lossy(raw_slices[i + 2]).to_string();

                    // Security check: if the source path was an encrypted secret, the destination
                    // MUST ALSO have encryption rules configured in .gitattributes!
                    if self.is_file_tracked(&old_path) && !self.is_file_tracked(&new_path) {
                        unprotected_renames.push((old_path, new_path.clone()));
                    }

                    paths_to_check.push(new_path);
                    i += 3;
                    continue;
                }
            } else if status.starts_with('D') {
                i += 2;
                continue;
            } else {
                if i + 1 < raw_slices.len() {
                    let path = String::from_utf8_lossy(raw_slices[i + 1]).to_string();
                    paths_to_check.push(path);
                    i += 2;
                    continue;
                }
            }
            i += 1;
        }

        if !unprotected_renames.is_empty() {
            eprintln!();
            eprintln!(
                "================================================================================"
            );
            eprintln!("  CRITICAL SECURITY ALERT: SECRET RENAMED TO UNENCRYPTED DESTINATION!");
            eprintln!(
                "================================================================================"
            );
            eprintln!("The following tracked secret(s) were renamed to path(s) that are NOT");
            eprintln!("configured for encryption in .gitattributes:");
            for (old_p, new_p) in &unprotected_renames {
                eprintln!("  - '{old_p}' -> '{new_p}'");
            }
            eprintln!();
            eprintln!(
                "Git will not invoke the encryption filter for untracked paths, causing future"
            );
            eprintln!("edits to be staged and committed as unencrypted plaintext!");
            eprintln!();
            eprintln!("To fix:");
            eprintln!("  1. Add an encryption rule for the destination in .gitattributes, e.g.:");
            for (_, new_p) in &unprotected_renames {
                eprintln!(
                    "     echo \"{new_p} filter=agecrypt diff=agecrypt merge=agecrypt -text\" >> .gitattributes"
                );
            }
            eprintln!("     git add .gitattributes");
            eprintln!("  2. Re-stage the files to trigger encryption:");
            for (_, new_p) in &unprotected_renames {
                eprintln!("     git reset HEAD \"{new_p}\" && git add \"{new_p}\"");
            }
            eprintln!(
                "================================================================================"
            );
            return Err(anyhow!(
                "Commit aborted: secret renamed to unencrypted destination"
            ));
        }

        let mut leaked_files = Vec::new();
        let mut foreign_key_files = Vec::new();

        let master_identity = if let Ok(Some(k)) = self.read_local_master_key() {
            age::x25519::Identity::from_str(&k).ok()
        } else {
            None
        };

        for path_str in paths_to_check {
            if self.is_file_tracked(&path_str) {
                // Symlink / gitlink guard: Symlinks (mode 120000) contain target path string,
                // and submodules (mode 160000) contain commit hashes, not secret payloads
                if self.is_staged_special_entry(&path_str) {
                    continue;
                }

                // Fetch the staged blob header from git object index without full file buffering
                let norm_path = path_str.replace('\\', "/");
                let clean_path = norm_path.trim_start_matches('/');
                let blob_ref = format!(":0:{clean_path}");
                if let Some(header) = self.read_blob_header(&blob_ref, 64 * 1024) {
                    let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                    let prefix = &header[..prefix_len];
                    if !is_age_ciphertext(prefix) {
                        leaked_files.push(path_str);
                    } else if let Some(ref id) = master_identity {
                        // Forward-secrecy verification: verify staged ciphertext can be unwrapped with active master key!
                        if let Ok(decryptor) = age::Decryptor::new(&header[..])
                            && let Err(age::DecryptError::NoMatchingKeys) =
                                decryptor.decrypt(std::iter::once(id as &dyn age::Identity))
                        {
                            foreign_key_files.push(path_str);
                        }
                    }
                }
            }
        }

        if !leaked_files.is_empty() {
            eprintln!();
            eprintln!(
                "================================================================================"
            );
            eprintln!("  CRITICAL SECURITY ALERT: UNENCRYPTED SECRETS STAGED FOR COMMIT!");
            eprintln!(
                "================================================================================"
            );
            eprintln!("The following tracked secret file(s) are staged as plaintext in Git:");
            for f in &leaked_files {
                eprintln!("  - {f}");
            }
            eprintln!();
            eprintln!("Possible reasons:");
            eprintln!(
                "  1. 'filter.agecrypt.clean' is not installed or configured in .git/config."
            );
            eprintln!("  2. Files were staged before git-agecrypt was initialized.");
            eprintln!(
                "  3. 'git add -p' (interactive patch staging) was used. Git's internal 'apply --cached' bypasses clean filters."
            );
            eprintln!();
            eprintln!("To fix:");
            eprintln!("  git-agecrypt init");
            eprintln!("  git reset HEAD <files> && git add <files>");
            eprintln!(
                "================================================================================"
            );
            return Err(anyhow!("Commit aborted: unencrypted secrets detected"));
        }

        if !foreign_key_files.is_empty() {
            eprintln!();
            eprintln!(
                "================================================================================"
            );
            eprintln!(
                "  CRITICAL SECURITY ALERT: STAGED SECRET ENCRYPTED WITH REVOKED/FOREIGN KEY!"
            );
            eprintln!(
                "================================================================================"
            );
            eprintln!(
                "The following staged secret(s) are encrypted under a revoked or unknown key"
            );
            eprintln!("that does not match the repository's active master key:");
            for f in &foreign_key_files {
                eprintln!("  - {f}");
            }
            eprintln!();
            eprintln!("This typically happens when cherry-picking, merging an un-rekeyed branch,");
            eprintln!("or copying ciphertext blobs created prior to a key rotation (rekey).");
            eprintln!(
                "Committing these blobs would allow former collaborators who possess the revoked"
            );
            eprintln!("key to decrypt newly committed repository history!");
            eprintln!();
            eprintln!("To fix:");
            eprintln!("  1. Re-encrypt the historical secret under your active master key:");
            for f in &foreign_key_files {
                eprintln!("     git-agecrypt rewrap \"{f}\"");
            }
            eprintln!("  2. Or if you have the cleartext, overwrite the file and re-stage:");
            for f in &foreign_key_files {
                eprintln!("     git add \"{f}\"");
            }
            eprintln!(
                "================================================================================"
            );
            return Err(anyhow!(
                "Commit aborted: staged blob encrypted with revoked/foreign key"
            ));
        }

        Ok(())
    }

    /// Inspects commits being pushed during a `pre-push` hook invocation.
    /// Reads `<local_ref> <local_oid> <remote_ref> <remote_oid>` from stdin.
    pub fn check_pushed_commits(&self) -> Result<()> {
        if io::stdin().is_terminal() {
            eprintln!(
                "git-agecrypt: 'check --pre-push' is intended to be called by Git's pre-push hook via stdin."
            );
            eprintln!("No push refs received (interactive terminal detected).");
            return Ok(());
        }

        let stdin = io::stdin();
        let mut lines = Vec::new();
        for line in stdin.lock().lines() {
            let l = line?;
            let trimmed = l.trim().to_string();
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
        }

        if lines.is_empty() {
            return Ok(());
        }

        let patterns = self.get_tracked_patterns()?;
        if patterns.is_empty() {
            return Ok(());
        }

        let master_identity = if let Ok(Some(k)) = self.read_local_master_key() {
            age::x25519::Identity::from_str(&k).ok()
        } else {
            None
        };

        let zero_sha = "0000000000000000000000000000000000000000";
        let mut inspected_blobs = std::collections::HashSet::new();

        for line in &lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let _local_ref = parts[0];
            let local_oid = parts[1];
            let _remote_ref = parts[2];
            let remote_oid = parts[3];

            // Branch deletion: no commits being pushed
            if local_oid.starts_with(zero_sha) || local_oid.chars().all(|c| c == '0') {
                continue;
            }

            // Peel any annotated tag to its underlying commit
            let local_commit =
                peel_to_commit(&self.root, local_oid).unwrap_or_else(|| local_oid.to_string());
            let remote_commit =
                peel_to_commit(&self.root, remote_oid).unwrap_or_else(|| remote_oid.to_string());

            // Determine commit list
            let commits =
                if remote_commit.starts_with(zero_sha) || remote_commit.chars().all(|c| c == '0') {
                    // New remote ref: find commits in local_commit not in any remotes
                    let out = git_cmd_with_path(&self.root)
                        .args(["rev-list", &local_commit, "--not", "--remotes"])
                        .output();
                    match out {
                        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                            String::from_utf8_lossy(&o.stdout)
                                .lines()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                        }
                        _ => {
                            // Fallback: list all commits on local_commit
                            let out2 = git_cmd_with_path(&self.root)
                                .args(["rev-list", &local_commit, "-n", "100"])
                                .output();
                            if let Ok(o2) = out2 {
                                String::from_utf8_lossy(&o2.stdout)
                                    .lines()
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect::<Vec<_>>()
                            } else {
                                vec![local_commit.clone()]
                            }
                        }
                    }
                } else {
                    // Updating existing remote ref: commits between remote_commit and local_commit
                    let range = format!("{remote_commit}..{local_commit}");
                    let out = git_cmd_with_path(&self.root)
                        .args(["rev-list", &range])
                        .output();
                    if let Ok(o) = out {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    } else {
                        vec![local_commit.clone()]
                    }
                };

            for commit in &commits {
                // List files touched in this commit with raw modes and SHAs
                let diff_out = git_cmd_with_path(&self.root)
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

                if let Ok(out) = diff_out
                    && out.status.success()
                {
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
                        let path_str = if is_rename {
                            if idx + 2 < slices.len() {
                                let p = String::from_utf8_lossy(slices[idx + 2]).to_string();
                                idx += 3;
                                p
                            } else {
                                idx += 1;
                                continue;
                            }
                        } else {
                            if idx + 1 < slices.len() {
                                let p = String::from_utf8_lossy(slices[idx + 1]).to_string();
                                idx += 2;
                                p
                            } else {
                                idx += 1;
                                continue;
                            }
                        };

                        // Skip deletions
                        if status.starts_with('D')
                            || new_mode == "000000"
                            || new_sha.starts_with(zero_sha)
                            || new_sha.chars().all(|c| c == '0')
                        {
                            continue;
                        }
                        // Ignore symlinks (120000) and gitlinks/submodules (160000)
                        if new_mode == "120000" || new_mode == "160000" {
                            continue;
                        }

                        let norm_path = path_str.replace('\\', "/");
                        if !self.is_file_tracked(&norm_path) {
                            continue;
                        }

                        if inspected_blobs.contains(new_sha) {
                            continue;
                        }

                        // Fetch blob header directly by SHA to verify it is NOT unencrypted plaintext
                        if let Some(header) = self.read_blob_header(new_sha, 64 * 1024) {
                            let prefix_len = std::cmp::min(header.len(), AGE_HEADER_MAGIC.len());
                            let prefix = &header[..prefix_len];
                            if !is_age_ciphertext(prefix) {
                                eprintln!();
                                eprintln!(
                                    "================================================================================"
                                );
                                eprintln!(
                                    "  CRITICAL SECURITY ALERT: UNENCRYPTED SECRET IN PUSHED COMMIT!"
                                );
                                eprintln!(
                                    "================================================================================"
                                );
                                eprintln!(
                                    "Commit '{commit}' contains unencrypted secret: '{norm_path}'"
                                );
                                eprintln!(
                                    "Refusing to push plaintext secret to remote repository!"
                                );
                                eprintln!(
                                    "================================================================================"
                                );
                                return Err(anyhow!(
                                    "Push rejected: unencrypted secret in commit '{commit}': '{norm_path}'"
                                ));
                            }
                            inspected_blobs.insert(new_sha.to_string());
                        }
                    }
                }
            }

            // Verify that all tracked secrets present in the target tip commit can be decrypted with active master key
            if let Some(ref id) = master_identity {
                let tree_out = git_cmd_with_path(&self.root)
                    .args(["ls-tree", "-r", "-z", &local_commit])
                    .output();
                if let Ok(to) = tree_out
                    && to.status.success()
                {
                    for slice in to.stdout.split(|&b| b == 0) {
                        if slice.is_empty() {
                            continue;
                        }
                        let line_str = String::from_utf8_lossy(slice);
                        if let Some((meta, path)) = line_str.split_once('\t') {
                            let parts: Vec<&str> = meta.split_whitespace().collect();
                            if parts.len() >= 3 && parts[1] == "blob" {
                                if parts[0] == "120000" {
                                    // Symlinks contain target path text, not secret payloads
                                    continue;
                                }
                                let sha = parts[2];
                                let norm_path = path.replace('\\', "/");
                                if self.is_file_tracked(&norm_path)
                                    && let Some(header) = self.read_blob_header(sha, 64 * 1024)
                                    && let Ok(decryptor) = age::Decryptor::new(&header[..])
                                    && let Err(age::DecryptError::NoMatchingKeys) =
                                        decryptor.decrypt(std::iter::once(id as &dyn age::Identity))
                                {
                                    eprintln!();
                                    eprintln!(
                                        "================================================================================"
                                    );
                                    eprintln!(
                                        "  CRITICAL SECURITY ALERT: SECRET ENCRYPTED WITH REVOKED/HISTORICAL KEY!"
                                    );
                                    eprintln!(
                                        "================================================================================"
                                    );
                                    eprintln!(
                                        "Target branch tip '{local_commit}' contains a secret encrypted under a revoked or historical key: '{norm_path}'"
                                    );
                                    eprintln!(
                                        "Run 'git-agecrypt rewrap {norm_path}' to re-encrypt under the active master key before pushing."
                                    );
                                    eprintln!(
                                        "================================================================================"
                                    );
                                    return Err(anyhow!(
                                        "Push rejected: secret in tip commit '{local_commit}' encrypted under revoked key: '{norm_path}'"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns a list of tracked secret files that currently have unstaged/uncommitted changes.
    pub fn get_dirty_tracked_files(&self) -> Result<Vec<String>> {
        let patterns = self.get_tracked_patterns()?;
        if patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Check git status --porcelain -z to handle spaces and renames robustly
        let status_out = git_cmd_with_path(&self.root)
            .args(["status", "--porcelain", "-z"])
            .output()
            .context("Failed to check git status")?;

        let mut dirty_secrets = Vec::new();
        let bytes = &status_out.stdout;
        let mut idx = 0;
        while idx < bytes.len() {
            let next_null = bytes[idx..].iter().position(|&b| b == 0);
            let end = match next_null {
                Some(pos) => idx + pos,
                None => bytes.len(),
            };
            let entry_slice = &bytes[idx..end];
            idx = end + 1;

            if entry_slice.len() > 3 {
                let is_rename = entry_slice.starts_with(b"R") || entry_slice.starts_with(b"C");
                let path_bytes = &entry_slice[3..];
                let file_path = String::from_utf8_lossy(path_bytes).to_string();

                if is_rename {
                    // In git status --porcelain -z, rename entries are:
                    // R  <new_path>\0<old_path>\0
                    // Read the second token: old_path
                    let orig_null = bytes[idx..].iter().position(|&b| b == 0);
                    let orig_end = match orig_null {
                        Some(pos) => idx + pos,
                        None => bytes.len(),
                    };
                    let orig_path = String::from_utf8_lossy(&bytes[idx..orig_end]).to_string();
                    idx = orig_end + 1;

                    // If EITHER the new destination path or the original path is a tracked secret, record it!
                    if self.is_file_tracked(&file_path) {
                        dirty_secrets.push(file_path);
                    }
                    if self.is_file_tracked(&orig_path) {
                        dirty_secrets.push(orig_path);
                    }
                } else if self.is_file_tracked(&file_path) {
                    dirty_secrets.push(file_path);
                }
            }
        }
        Ok(dirty_secrets)
    }

    /// Returns a list of tracked NON-SECRET files that currently have unstaged/uncommitted changes.
    /// Used by `cmd_rekey` to prevent accidentally staging and committing developer WIP code.
    pub fn get_dirty_non_secret_files(&self) -> Result<Vec<String>> {
        let status_out = git_cmd_with_path(&self.root)
            .args(["status", "--porcelain", "-z"])
            .output()
            .context("Failed to check git status")?;

        let is_agecrypt_meta = |p: &str| {
            let norm = p.replace('\\', "/");
            norm == ".gitattributes"
                || norm.ends_with("/.gitattributes")
                || norm == ".gitignore"
                || norm.ends_with("/.gitignore")
                || norm == ".git-agecrypt"
                || norm.starts_with(".git-agecrypt/")
                || norm.starts_with(".git/")
        };

        let mut dirty_non_secrets = Vec::new();
        let bytes = &status_out.stdout;
        let mut idx = 0;
        while idx < bytes.len() {
            let next_null = bytes[idx..].iter().position(|&b| b == 0);
            let end = match next_null {
                Some(pos) => idx + pos,
                None => bytes.len(),
            };
            let entry_slice = &bytes[idx..end];
            idx = end + 1;

            if entry_slice.len() > 3 {
                let status_code = &entry_slice[0..2];
                // Skip untracked (??) and ignored (!!) files
                if status_code == b"??" || status_code == b"!!" {
                    continue;
                }

                let is_rename = status_code.starts_with(b"R") || status_code.starts_with(b"C");
                let path_bytes = &entry_slice[3..];
                let file_path = String::from_utf8_lossy(path_bytes).to_string();

                if is_rename {
                    let orig_null = bytes[idx..].iter().position(|&b| b == 0);
                    let orig_end = match orig_null {
                        Some(pos) => idx + pos,
                        None => bytes.len(),
                    };
                    let orig_path = String::from_utf8_lossy(&bytes[idx..orig_end]).to_string();
                    idx = orig_end + 1;

                    if !is_agecrypt_meta(&file_path) && !self.is_file_tracked(&file_path) {
                        dirty_non_secrets.push(file_path);
                    }
                    if !is_agecrypt_meta(&orig_path) && !self.is_file_tracked(&orig_path) {
                        dirty_non_secrets.push(orig_path);
                    }
                } else if !is_agecrypt_meta(&file_path) && !self.is_file_tracked(&file_path) {
                    dirty_non_secrets.push(file_path);
                }
            }
        }
        Ok(dirty_non_secrets)
    }

    /// Refreshes the working tree non-destructively by default.
    /// Checks for unstaged changes before touching files.
    pub fn refresh_working_tree(&self, force: bool) -> Result<()> {
        let dirty_secrets = self.get_dirty_tracked_files()?;

        if !dirty_secrets.is_empty() && !force {
            eprintln!(
                "git-agecrypt [WARNING]: Uncommitted (staged or unstaged) changes detected in tracked secret file(s):"
            );
            for f in &dirty_secrets {
                eprintln!("  - {f}");
            }
            eprintln!(
                "Skipping automatic checkout to protect your uncommitted edits.\n\
                 Run command with '--force' (-f) if you explicitly wish to overwrite working tree modifications."
            );
            return Ok(());
        }

        // List all tracked files with index status flags (-t) to detect SKIP_WORKTREE (sparse checkouts)
        let ls_out = git_cmd_with_path(&self.root)
            .args(["ls-files", "-t", "-z"])
            .output();

        let mut readonly_paths = Vec::new();
        let mut files_to_checkout = Vec::new();

        if let Ok(out) = ls_out {
            for path_slice in out.stdout.split(|&b| b == 0) {
                if !path_slice.is_empty() {
                    let entry_str = String::from_utf8_lossy(path_slice);
                    let (flag, rel_path) = if let Some(space_idx) = entry_str.find(' ') {
                        let f = entry_str[..space_idx].chars().next().unwrap_or(' ');
                        (f, &entry_str[space_idx + 1..])
                    } else {
                        (' ', entry_str.as_ref())
                    };

                    // Skip sparse-checkout files that have SKIP_WORKTREE set ('S' or 's')
                    if flag == 'S' || flag == 's' {
                        continue;
                    }

                    if self.is_file_tracked(rel_path) {
                        let full_path = self.root.join(rel_path);
                        if full_path.exists() {
                            if let Ok(meta) = fs::metadata(&full_path)
                                && meta.permissions().readonly()
                            {
                                readonly_paths.push(full_path.clone());
                                let mut perms = meta.permissions();
                                set_permissions_writable(&mut perms);
                                let _ = fs::set_permissions(&full_path, perms);
                            }
                            let _ = fs::remove_file(&full_path);
                        }
                        files_to_checkout.push(rel_path.to_string());
                    }
                }
            }
        }

        if !files_to_checkout.is_empty() {
            // Run git checkout-index using --stdin -z to force smudge through filter without touching sparse files
            let mut checkout_cmd = git_cmd_with_path(&self.root);
            checkout_cmd.args(["checkout-index", "-f", "-u", "-z", "--stdin"]);
            checkout_cmd.stdin(Stdio::piped());
            let mut child = checkout_cmd
                .spawn()
                .context("Failed to spawn git checkout-index")?;

            if let Some(mut stdin) = child.stdin.take() {
                for f in &files_to_checkout {
                    let _ = stdin.write_all(f.as_bytes());
                    let _ = stdin.write_all(&[0]);
                }
            }

            let status = child
                .wait()
                .context("Failed to refresh working tree with git checkout-index")?;

            if !status.success() {
                // Fallback: checkout strictly the target secret files (never '.'!) to protect unrelated files
                for chunk in files_to_checkout.chunks(50) {
                    let mut fallback_cmd = git_cmd_with_path(&self.root);
                    fallback_cmd.arg("checkout").arg("HEAD").arg("--");
                    for f in chunk {
                        fallback_cmd.arg(f);
                    }
                    let _ = fallback_cmd.status();
                }
            }
        }

        // Re-apply read-only permissions for files that were originally marked read-only
        for full_path in readonly_paths {
            if full_path.exists()
                && let Ok(meta) = fs::metadata(&full_path)
            {
                let mut perms = meta.permissions();
                perms.set_readonly(true);
                let _ = fs::set_permissions(&full_path, perms);
            }
        }

        Ok(())
    }

    /// Discovers all registered worktrees linked to this repository using `git worktree list --porcelain`.
    pub fn list_all_registered_worktrees(&self) -> Result<Vec<PathBuf>> {
        let output = git_cmd_with_path(&self.root)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .context("Failed to list git worktrees")?;

        if !output.status.success() {
            return Ok(vec![self.root.clone()]);
        }

        let mut worktrees = Vec::new();
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(path_str) = line.strip_prefix("worktree ") {
                let trimmed = path_str.trim();
                if !trimmed.is_empty() {
                    worktrees.push(PathBuf::from(trimmed));
                }
            }
        }

        if worktrees.is_empty() {
            worktrees.push(self.root.clone());
        }

        Ok(worktrees)
    }

    /// Discovers all active worktrees linked to this repository.
    /// Filters out stale or unreachable worktree records whose directories or .git references no longer exist on disk.
    pub fn list_worktrees(&self) -> Result<Vec<PathBuf>> {
        let registered = self.list_all_registered_worktrees()?;
        let active: Vec<PathBuf> = registered
            .into_iter()
            .filter(|p| p.join(".git").exists())
            .collect();

        if active.is_empty() {
            Ok(vec![self.root.clone()])
        } else {
            Ok(active)
        }
    }

    /// Checks all worktrees for dirty tracked secret files.
    /// Returns a list of (worktree_path, dirty_files) for any worktree with unstaged modifications.
    pub fn get_dirty_files_across_worktrees(&self) -> Result<Vec<(PathBuf, Vec<String>)>> {
        let worktrees = self.list_worktrees()?;
        let mut results = Vec::new();

        for wt in worktrees {
            if !wt.join(".git").exists() {
                continue;
            }
            let repo_for_wt = GitRepo {
                root: wt.clone(),
                git_dir: self.git_dir.clone(),
                common_dir: self.common_dir.clone(),
            };
            let dirty = repo_for_wt.get_dirty_tracked_files()?;
            if !dirty.is_empty() {
                results.push((wt, dirty));
            }
        }

        Ok(results)
    }

    /// Refreshes the working tree across all linked worktrees.
    pub fn refresh_all_worktrees(&self, force: bool) -> Result<()> {
        let dirty_across = self.get_dirty_files_across_worktrees()?;
        if !dirty_across.is_empty() && !force {
            eprintln!(
                "git-agecrypt [WARNING]: Uncommitted (staged or unstaged) changes detected in tracked secret file(s):"
            );
            for (wt, files) in &dirty_across {
                eprintln!("  In worktree {}:", wt.display());
                for f in files {
                    eprintln!("    - {f}");
                }
            }
            eprintln!(
                "Skipping automatic checkout across worktrees to protect your uncommitted edits.\n\
                 Run command with '--force' (-f) if you explicitly wish to overwrite working tree modifications."
            );
            return Ok(());
        }

        let worktrees = self.list_worktrees()?;
        for wt in worktrees {
            if !wt.join(".git").exists() {
                continue;
            }
            let repo_for_wt = GitRepo {
                root: wt,
                git_dir: self.git_dir.clone(),
                common_dir: self.common_dir.clone(),
            };
            repo_for_wt.refresh_working_tree(force)?;
        }

        Ok(())
    }
}

/// Recursively scans `dir` and removes any abandoned temporary spool files
/// (e.g. .tmp*, *tmp*, *.tmp) while strictly preserving persistent files (repo.key, *.age, *.pub).
fn sweep_tmp_recursive(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                sweep_tmp_recursive(&path);
            } else if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                let lower = file_name.to_lowercase();
                let is_spool = lower.starts_with(".tmp")
                    || lower.starts_with("tmp.")
                    || lower.ends_with(".tmp")
                    || lower.starts_with("repo.key.tmp.");
                if is_spool
                    && !lower.ends_with(".age")
                    && !lower.ends_with(".key")
                    && !lower.ends_with(".pub")
                    && lower != "repo.key"
                {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_extended_path_slash_normalization() {
        #[cfg(windows)]
        {
            let p = Path::new(
                "C:/very/long/path/with/forward/slashes/that/needs/normalization/and/is/approaching/the/win32/maximum/path/length/limit/which/is/260/characters/in/length/and/requires/extended/path/prefixing/with/question/mark/prefix/so/that/it/does/not/fail/with/invalid/name",
            );
            let extended = ensure_extended_path(p);
            let s = extended.to_string_lossy();
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                assert!(
                    !stripped.contains('/'),
                    "Win32 extended path must never contain forward slashes: {s}"
                );
                assert!(s.contains('\\'));
            }
        }
    }

    #[test]
    fn test_ensure_extended_path_resolves_relative_paths() {
        #[cfg(windows)]
        {
            let rel = Path::new("some/relative/long/path/for/win32/extended/path/testing");
            let extended = ensure_extended_path(rel);
            let s = extended.to_string_lossy();
            assert!(
                !s.contains('/'),
                "Win32 path must never contain forward slashes: {s}"
            );
            assert!(
                extended.is_absolute(),
                "ensure_extended_path must always return an absolute path: {s}"
            );
        }
    }

    #[test]
    fn test_is_pid_alive() {
        let my_pid = std::process::id();
        assert!(is_pid_alive(my_pid), "Current process must be alive");
        assert!(!is_pid_alive(99999999), "PID 99999999 must not be alive");
    }

    #[test]
    fn test_ensure_extended_path_unc_formatting() {
        #[cfg(windows)]
        {
            let long_unc = format!(r"\\nas\share\projects\{}", "sub/".repeat(60));
            let extended = ensure_extended_path(Path::new(&long_unc));
            let s = extended.to_string_lossy();
            assert!(
                s.starts_with(r"\\?\UNC\nas\share\projects\"),
                "UNC path must be formatted as \\\\?\\UNC\\: {s}"
            );
            assert!(
                !s.contains('/'),
                "UNC path must not contain forward slashes: {s}"
            );
        }
    }
}
