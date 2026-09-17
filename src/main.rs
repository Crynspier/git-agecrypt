mod cli;
mod crypto;
mod git;
mod github;
mod merge;

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow};
use clap::Parser;

use cli::{Cli, Commands};
use git::GitRepo;

fn main() {
    // Strict stderr discipline: Panics must NEVER print to stdout to avoid corrupting git streams!
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("git-agecrypt fatal panic: {panic_info}");
    }));

    // Intercept SIGINT/Ctrl+C to terminate cleanly. Any interrupted lock transaction
    // will be deterministically recovered on the next command via GitRepo::recover_interrupted_transaction,
    // avoiding multithreaded Windows sharing violations (ERROR_SHARING_VIOLATION).
    let _ = ctrlc::set_handler(move || {
        process::exit(130);
    });

    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        if is_broken_pipe(&err) {
            // Pager exited early (e.g. less or git diff terminated). Silently exit 0.
            process::exit(0);
        }
        eprintln!("git-agecrypt [ERROR]: {err:?}");
        process::exit(1);
    }
}

/// Detects whether an error chain was caused by a BrokenPipe (e.g. downstream pager closed).
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return true;
        }
    }
    false
}

fn run(cli: Cli) -> Result<()> {
    // For non-filter management commands, recover any interrupted lock transaction
    match &cli.command {
        Commands::Clean { .. }
        | Commands::Smudge { .. }
        | Commands::Textconv { .. }
        | Commands::Merge { .. } => {}
        _ => {
            if let Ok(repo) = GitRepo::discover() {
                repo.recover_interrupted_transaction();
            }
        }
    }

    match cli.command {
        Commands::Init { gitattributes } => cmd_init(gitattributes),
        Commands::AddRecipient {
            identity,
            github,
            name,
        } => cmd_add_recipient(identity.as_deref(), github.as_deref(), name.as_deref()),
        Commands::RemoveRecipient { name } => cmd_remove_recipient(&name),
        Commands::ListRecipients => cmd_list_recipients(),
        Commands::Rekey { force } => cmd_rekey(force),
        Commands::Rewrap {
            paths,
            all,
            identity,
            force,
        } => cmd_rewrap(&paths, all, identity.as_deref(), force),
        Commands::Unlock { key_file, force } => cmd_unlock(key_file.as_deref(), force),
        Commands::Lock { force } => cmd_lock(force),
        Commands::Status => cmd_status(),
        Commands::InstallHooks => cmd_install_hooks(),
        Commands::Check { pre_push } => cmd_check(pre_push),
        Commands::Clean { file_path } => cmd_clean(file_path.as_deref()),
        Commands::Smudge { file_path } => cmd_smudge(file_path.as_deref()),
        Commands::Textconv { file } => cmd_textconv(&file),
        Commands::Merge {
            base,
            ours,
            theirs,
            marker_size,
            file_path,
        } => cmd_merge(&base, &ours, &theirs, marker_size, file_path.as_deref()),
        Commands::MigrateFromGitCrypt { identity } => cmd_migrate(identity.as_deref()),
    }
}

fn cmd_init(create_gitattributes: bool) -> Result<()> {
    let repo = GitRepo::discover()?;
    eprintln!("Initializing git-agecrypt in {}", repo.root.display());

    if repo.root.join(".git-crypt").exists() {
        eprintln!(
            "git-agecrypt: Notice: Existing .git-crypt directory found. To migrate an existing git-crypt repository, run 'git-agecrypt migrate-from-git-crypt'."
        );
    }

    let _meta_dir = repo.agecrypt_metadata_dir();
    let keys_dir = repo.keys_dir();
    fs::create_dir_all(&keys_dir)?;

    let pub_file = repo.public_key_file();
    let _master_identity = if pub_file.exists() && repo.is_unlocked() {
        eprintln!("Repository already initialized. Re-configuring git filters...");
        let key_str = repo
            .read_local_master_key()?
            .ok_or_else(|| anyhow!("Failed to read local master key"))?;
        age::x25519::Identity::from_str(&key_str).map_err(|e| anyhow!("{e}"))?
    } else {
        let (identity, recipient) = crypto::generate_master_identity();
        fs::write(&pub_file, format!("{}\n", recipient))?;
        repo.save_local_master_key(identity.to_string().expose_secret())?;
        eprintln!("Generated new 256-bit repository master key.");
        eprintln!("Public key saved to .git-agecrypt/repo.pub: {recipient}");

        // Auto-enroll default SSH key if present
        if let Some(ssh_pub) = find_default_ssh_public_key()
            && let Ok(recipient_box) = crypto::parse_recipient(&ssh_pub)
        {
            let wrapped = crypto::wrap_master_key_with_metadata(
                identity.to_string().expose_secret(),
                recipient_box.as_ref(),
                &ssh_pub,
            )?;
            let initial_key_file = keys_dir.join("initial_user.age");
            fs::write(initial_key_file, wrapped)?;
            eprintln!("Automatically enrolled your local SSH public key as a recipient.");
        }
        identity
    };

    // Configure git config filters
    repo.configure_git_filters()?;
    eprintln!("Configured git filter, diff, and merge drivers in .git/config.");

    // Install pre-commit, pre-merge-commit, and pre-push hooks
    repo.install_pre_commit_hook()?;
    eprintln!(
        "Installed safeguard hooks into .git/hooks/ (pre-commit, pre-merge-commit, pre-push)."
    );

    // Create default .gitattributes template if requested (with -text binary attribute)
    if create_gitattributes {
        let gitattributes_path = repo.root.join(".gitattributes");
        if !gitattributes_path.exists() {
            let template = r#"# git-agecrypt tracked secrets (binary ciphertext, no CRLF conversion)
*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text
secrets/** filter=agecrypt diff=agecrypt merge=agecrypt -text
"#;
            fs::write(&gitattributes_path, template)?;
            eprintln!("Created default .gitattributes template (with -text binary safety flag).");
        }
    }

    eprintln!(
        "Initialization complete! Files matching .gitattributes will be transparently encrypted on commit."
    );
    Ok(())
}

fn cmd_add_recipient(
    identity: Option<&str>,
    github: Option<&str>,
    name: Option<&str>,
) -> Result<()> {
    if identity.is_some() && github.is_some() {
        return Err(anyhow!(
            "Cannot specify both --identity (-i) and --github simultaneously. Choose one recipient source."
        ));
    }

    let repo = GitRepo::discover()?;
    let master_key = repo.read_local_master_key()?.ok_or_else(|| {
        anyhow!(
            "Repository is locked. You must run 'git-agecrypt unlock' before adding recipients."
        )
    })?;

    let mut keys_to_add: Vec<(String, String)> = Vec::new();

    if let Some(user) = github {
        eprintln!("Fetching SSH public keys from GitHub for user '{user}'...");
        let keys = github::fetch_github_keys(user)?;
        for (i, key) in keys.into_iter().enumerate() {
            let label = if let Some(n) = name {
                if i == 0 {
                    n.to_string()
                } else {
                    format!("{n}-{i}")
                }
            } else {
                format!("github-{user}-{i}")
            };
            keys_to_add.push((label, key));
        }
    } else if let Some(id_str) = identity {
        let path = Path::new(id_str);
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let label = name.map(|s| s.to_string()).unwrap_or_else(|| {
                path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            });
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    let sub_label = if i == 0 {
                        label.clone()
                    } else {
                        format!("{label}-{i}")
                    };
                    keys_to_add.push((sub_label, trimmed.to_string()));
                }
            }
        } else {
            let label = name.map(|s| s.to_string()).unwrap_or_else(|| {
                let digest = sha2::Sha256::digest(id_str.as_bytes());
                format!("recipient-{}", &hex_digest(&digest)[..8])
            });
            keys_to_add.push((label, id_str.to_string()));
        }
    } else {
        return Err(anyhow!(
            "Must provide either --identity (-i) or --github <user>"
        ));
    }

    let keys_dir = repo.keys_dir();
    fs::create_dir_all(&keys_dir)?;

    for (label, key_str) in keys_to_add {
        let recipient = crypto::parse_recipient(&key_str)?;
        let wrapped =
            crypto::wrap_master_key_with_metadata(&master_key, recipient.as_ref(), &key_str)?;
        let safe_filename: String = label
            .to_ascii_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let mut filename = format!("{safe_filename}.age");
        let mut dest = keys_dir.join(&filename);

        // Check for existing recipient file case-insensitively
        let existing_file = if let Ok(entries) = fs::read_dir(&keys_dir) {
            entries
                .filter_map(|e| e.ok())
                .find(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&filename)
                })
                .map(|e| e.path())
        } else {
            None
        };

        if let Some(existing_path) = existing_file
            && let Ok(existing_content) = fs::read_to_string(&existing_path)
            && let Some(existing_pk) = crypto::extract_recipient_public_key(&existing_content)
            && existing_pk.trim() != key_str.trim()
        {
            // Key collision with a different public key: disambiguate with short hash to avoid silent clobbering
            use sha2::Digest;
            let hash_bytes = sha2::Sha256::digest(key_str.as_bytes());
            let hash_hex: String = hash_bytes[..4].iter().map(|b| format!("{b:02x}")).collect();
            let disambiguated = format!("{safe_filename}_{hash_hex}.age");
            eprintln!(
                "git-agecrypt add-recipient [WARNING]: Recipient '{safe_filename}.age' already exists with a different public key.\n\
                             Enrolling as '{disambiguated}' to prevent key clobbering."
            );
            filename = disambiguated;
            dest = keys_dir.join(&filename);
        }

        fs::write(&dest, wrapped)?;
        eprintln!("Enrolled recipient '{label}' -> .git-agecrypt/keys/{filename}");
    }

    eprintln!("Remember to commit .git-agecrypt/keys/ to share access with team members.");
    Ok(())
}

fn cmd_remove_recipient(name: &str) -> Result<()> {
    let repo = GitRepo::discover()?;
    let keys_dir = repo.keys_dir();
    let label = name.trim_end_matches(".age");
    let target_name = format!("{label}.age");

    let actual_key_file = if keys_dir.join(&target_name).exists() {
        Some(keys_dir.join(&target_name))
    } else if let Ok(entries) = fs::read_dir(&keys_dir) {
        entries
            .filter_map(|e| e.ok())
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&target_name)
            })
            .map(|e| e.path())
    } else {
        None
    };

    let Some(key_file) = actual_key_file else {
        return Err(anyhow!(
            "Recipient file '{label}.age' not found in {}",
            keys_dir.display()
        ));
    };

    fs::remove_file(&key_file)
        .with_context(|| format!("Failed to remove recipient file: {}", key_file.display()))?;

    eprintln!("Removed recipient '{label}' ({})", key_file.display());
    eprintln!();
    eprintln!("IMPORTANT NOTICE: Offboarding a collaborator requires cycling the master key!");
    eprintln!(
        "Deleting their recipient file prevents them from unlocking future re-keyed commits,"
    );
    eprintln!("but they still possess the current symmetric master key.");
    eprintln!(
        "Run 'git-agecrypt rekey' now to generate a new master key and re-encrypt all secrets."
    );
    Ok(())
}

fn cmd_list_recipients() -> Result<()> {
    let repo = GitRepo::discover()?;
    let keys_dir = repo.keys_dir();
    if !keys_dir.exists() {
        eprintln!("No recipients directory found.");
        return Ok(());
    }

    let mut entries: Vec<_> = fs::read_dir(&keys_dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    let mut count = 0;
    println!("Enrolled recipients in {}:", keys_dir.display());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("age") {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            let size = entry.metadata()?.len();
            let content = fs::read_to_string(&path).unwrap_or_default();
            let pub_info = crypto::extract_recipient_public_key(&content)
                .map(|k| {
                    let truncated: String = k.chars().take(30).collect();
                    if k.chars().count() > 30 {
                        format!(" [{truncated}...]")
                    } else {
                        format!(" [{truncated}]")
                    }
                })
                .unwrap_or_default();
            println!("  * {} ({} bytes){}", filename, size, pub_info);
            count += 1;
        }
    }

    if count == 0 {
        println!("  (No recipient keys found)");
    }
    Ok(())
}

fn cmd_rekey(force: bool) -> Result<()> {
    let repo = GitRepo::discover()?;
    if !repo.is_unlocked() {
        return Err(anyhow!(
            "Repository is locked. You must run 'git-agecrypt unlock' before rekeying."
        ));
    }

    // Safety check: ensure no uncommitted non-secret application files exist unless --force is used
    let dirty_non_secrets = repo.get_dirty_non_secret_files()?;
    if !dirty_non_secrets.is_empty() && !force {
        eprintln!();
        eprintln!(
            "git-agecrypt [WARNING]: Working tree has uncommitted modifications in non-secret file(s):"
        );
        for f in &dirty_non_secrets {
            eprintln!("  - {f}");
        }
        eprintln!();
        eprintln!(
            "Rekeying now risks bundling your unreviewed work-in-progress code into the security key-rotation commit."
        );
        eprintln!(
            "Please commit or stash your modifications before rekeying, or run with '--force' (-f) to proceed anyway."
        );
        return Err(anyhow!(
            "Rekey aborted: uncommitted modifications in non-secret files"
        ));
    }

    let keys_dir = repo.keys_dir();
    if !keys_dir.exists() {
        return Err(anyhow!(
            "Keys directory not found in {}",
            keys_dir.display()
        ));
    }

    eprintln!("Starting repository rekeying (rotating symmetric master key)...");

    // 1. Discover all existing active recipients
    let entries = fs::read_dir(&keys_dir)?;
    let mut recipients_to_rekey: Vec<(PathBuf, String, Box<dyn age::Recipient + Send + 'static>)> =
        Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("age") {
            let content = fs::read_to_string(&path)?;
            if let Some(pub_str) = crypto::extract_recipient_public_key(&content) {
                if let Ok(recipient) = crypto::parse_recipient(&pub_str) {
                    recipients_to_rekey.push((path, pub_str, recipient));
                } else {
                    eprintln!(
                        "git-agecrypt [WARNING]: Failed to parse public key in {}",
                        path.display()
                    );
                }
            } else {
                eprintln!(
                    "git-agecrypt [WARNING]: Recipient file {} lacks public-key comment header. Skipping.",
                    path.display()
                );
            }
        }
    }

    if recipients_to_rekey.is_empty() {
        return Err(anyhow!(
            "No valid recipients with recoverable public keys found in {}. \
             Cannot rotate master key without at least one recipient.",
            keys_dir.display()
        ));
    }

    // 2. Generate brand new master identity
    let (new_identity, new_recipient) = crypto::generate_master_identity();
    let new_secret_str = new_identity.to_string();

    // 3. Re-wrap new master key for all remaining recipients
    for (path, pub_str, recipient) in &recipients_to_rekey {
        let new_wrapped = crypto::wrap_master_key_with_metadata(
            new_secret_str.expose_secret(),
            recipient.as_ref(),
            pub_str,
        )?;
        fs::write(path, new_wrapped)?;
        let name_display = path
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default();
        eprintln!("  * Re-wrapped key for {name_display}");
    }

    // 4. Update .git-agecrypt/repo.pub
    let pub_file = repo.public_key_file();
    fs::write(&pub_file, format!("{}\n", new_recipient))?;

    // 5. Update local master key in common git dir atomically and clear stale cache
    repo.save_local_master_key(new_secret_str.expose_secret())?;
    let _ = repo.clear_cache();

    // 6. Re-stage strictly tracked secret files using targeted pathspecs (never '.'!)
    let ls_out = git::git_cmd_with_path(&repo.root)
        .args(["ls-files", "-z"])
        .output()
        .context("Failed to list tracked files")?;

    let mut secret_files = Vec::new();
    for slice in ls_out.stdout.split(|&b: &u8| b == 0) {
        if !slice.is_empty() {
            let rel_str = String::from_utf8_lossy(slice).to_string();
            if repo.is_file_tracked(&rel_str) && repo.root.join(&rel_str).is_file() {
                secret_files.push(rel_str);
            }
        }
    }

    if !secret_files.is_empty() {
        eprintln!("Re-encrypting working tree secrets with the new master key...");
        let mut streamed_ok = false;
        for attempt in 1..=3 {
            let child = git::git_cmd_with_path(&repo.root)
                .args([
                    "add",
                    "--renormalize",
                    "--pathspec-from-file=-",
                    "--pathspec-file-nul",
                ])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            match child {
                Ok(mut c) => {
                    if let Some(mut stdin) = c.stdin.take() {
                        for f in &secret_files {
                            let _ = stdin.write_all(f.as_bytes());
                            let _ = stdin.write_all(b"\0");
                        }
                    }
                    if let Ok(out) = c.wait_with_output() {
                        if out.status.success() {
                            streamed_ok = true;
                            break;
                        }
                        let err = String::from_utf8_lossy(&out.stderr);
                        if err.contains("index.lock") && attempt < 3 {
                            std::thread::sleep(std::time::Duration::from_millis(
                                50 * attempt as u64,
                            ));
                            continue;
                        }
                    }
                }
                Err(_) => break,
            }
        }

        if !streamed_ok {
            // Fallback for older git versions or environments without pathspec-from-file support:
            // small command-line batches respecting Windows 8,191/32,767 character limits
            let mut current_batch: Vec<&str> = Vec::new();
            let mut current_len = 0;
            for f in &secret_files {
                if current_len + f.len() > 8000 && !current_batch.is_empty() {
                    let mut args = vec!["add", "--renormalize", "--"];
                    args.extend(current_batch.iter());
                    let _ = git::run_git_cmd_with_index_retry(&repo.root, &args, 3);
                    current_batch.clear();
                    current_len = 0;
                }
                current_batch.push(f);
                current_len += f.len() + 1;
            }
            if !current_batch.is_empty() {
                let mut args = vec!["add", "--renormalize", "--"];
                args.extend(current_batch.iter());
                let _ = git::run_git_cmd_with_index_retry(&repo.root, &args, 3);
            }
        }
    }

    eprintln!();
    eprintln!("Repository successfully re-keyed!");
    eprintln!(
        "Rotated master key and re-wrapped for {} active recipient(s).",
        recipients_to_rekey.len()
    );
    eprintln!("To finalize and commit the rotation:");
    eprintln!("  git add .git-agecrypt");
    eprintln!("  git commit -m 'Rotate repository master key (rekey)'");
    Ok(())
}

/// RAII guard that ensures read-only filesystem attributes are restored on drop
/// even if operations fail or exit early with `?`.
struct ReadonlyGuard {
    path: PathBuf,
}

impl Drop for ReadonlyGuard {
    fn drop(&mut self) {
        if self.path.exists()
            && let Ok(mut perms) = fs::metadata(&self.path).map(|m| m.permissions())
        {
            perms.set_readonly(true);
            let _ = fs::set_permissions(&self.path, perms);
        }
    }
}

fn cmd_rewrap(paths: &[PathBuf], all: bool, identity_opt: Option<&str>, force: bool) -> Result<()> {
    let repo = GitRepo::discover()?;

    let master_key_str = repo.read_local_master_key()?.ok_or_else(|| {
        anyhow!("Repository is locked. Run 'git-agecrypt unlock' before rewrapping.")
    })?;
    let active_id = age::x25519::Identity::from_str(&master_key_str).map_err(|e| anyhow!("{e}"))?;

    if paths.is_empty() && !all {
        return Err(anyhow!(
            "No files specified. Provide file paths to rewrap, or pass '--all' (-a) to scan all tracked secret files."
        ));
    }

    let mut target_rel_paths = Vec::new();

    if all {
        let ls_out = git::git_cmd_with_path(&repo.root)
            .args(["ls-files", "-z"])
            .output()
            .context("Failed to list repository files")?;

        for slice in ls_out.stdout.split(|&b: &u8| b == 0) {
            if !slice.is_empty() {
                let rel_str = String::from_utf8_lossy(slice).to_string();
                if repo.is_file_tracked(&rel_str) {
                    target_rel_paths.push(rel_str);
                }
            }
        }
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| repo.root.clone());
        let canon_root = fs::canonicalize(&repo.root).unwrap_or_else(|_| repo.root.clone());
        for p in paths {
            let abs_p = if p.is_absolute() {
                p.clone()
            } else {
                cwd.join(p)
            };
            let canon_abs = fs::canonicalize(&abs_p).unwrap_or_else(|_| abs_p.clone());
            let rel = match canon_abs.strip_prefix(&canon_root) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => match abs_p.strip_prefix(&repo.root) {
                    Ok(r) => r.to_string_lossy().replace('\\', "/"),
                    Err(_) => p.to_string_lossy().replace('\\', "/"),
                },
            };
            target_rel_paths.push(rel);
        }
    }

    if target_rel_paths.is_empty() {
        eprintln!("No tracked secret files found to rewrap.");
        return Ok(());
    }

    // Gather candidate identities to decrypt historical ciphertext
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    identities.push(Box::new(active_id.clone()));

    if let Some(id_str) = identity_opt {
        let p = Path::new(id_str);
        if p.exists() {
            let ids = crypto::load_identities_from_file(p)?;
            identities.extend(ids);
        } else if let Ok(id) = age::x25519::Identity::from_str(id_str) {
            identities.push(Box::new(id));
        }
    }

    // Default SSH/age system keys
    let default_paths = crypto::get_default_identity_paths();
    for candidate in default_paths {
        if candidate.exists()
            && let Ok(ids) = crypto::load_identities_from_file_non_interactive(&candidate)
        {
            identities.extend(ids);
        }
    }

    // Also attempt to unwrap any historical master keys from .git-agecrypt/keys/*.age
    let keys_dir = repo.keys_dir();
    if keys_dir.exists()
        && let Ok(entries) = fs::read_dir(&keys_dir)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("age")
                && let Ok(content) = fs::read_to_string(&p)
                && let Ok(hist_master) = crypto::unwrap_master_key(&content, &identities)
                && let Ok(hist_id) = age::x25519::Identity::from_str(&hist_master)
            {
                identities.push(Box::new(hist_id));
            }
        }
    }

    // Also discover historical master keys across Git commits (rekey history)
    let log_cmd = git::git_cmd_with_path(&repo.root)
        .args([
            "log",
            "HEAD",
            "--all",
            "--name-only",
            "--format=commit:%H",
            "--",
            ".git-agecrypt/keys",
        ])
        .output();

    if let Ok(out) = log_cmd
        && out.status.success()
    {
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let mut current_commit = String::new();
        for line in stdout_str.lines() {
            let trimmed = line.trim();
            if let Some(h) = trimmed.strip_prefix("commit:") {
                current_commit = h.to_string();
            } else if trimmed.ends_with(".age") && !current_commit.is_empty() {
                let cat_cmd = git::git_cmd_with_path(&repo.root)
                    .args([
                        "cat-file",
                        "blob",
                        &format!("{}:{}", current_commit, trimmed),
                    ])
                    .output();
                if let Ok(cat_out) = cat_cmd
                    && cat_out.status.success()
                {
                    let content = String::from_utf8_lossy(&cat_out.stdout);
                    if let Ok(hist_master) = crypto::unwrap_master_key(&content, &identities)
                        && let Ok(hist_id) = age::x25519::Identity::from_str(&hist_master)
                    {
                        identities.push(Box::new(hist_id));
                    }
                }
            }
        }
    }

    let mut rewrapped_count = 0;

    for rel_path in &target_rel_paths {
        let full_path = repo.root.join(rel_path);
        if !full_path.exists() {
            eprintln!(
                "git-agecrypt rewrap [WARNING]: File '{}' not found on disk. Skipping.",
                rel_path
            );
            continue;
        }

        let raw_bytes = fs::read(&full_path)?;
        let prefix_len = std::cmp::min(raw_bytes.len(), crypto::AGE_HEADER_MAGIC.len());
        let is_cipher = crypto::is_age_ciphertext(&raw_bytes[..prefix_len]);

        if is_cipher {
            let decryptor = match age::Decryptor::new(&raw_bytes[..]) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!(
                        "git-agecrypt rewrap [WARNING]: '{}' could not be parsed as Age ciphertext: {e}",
                        rel_path
                    );
                    continue;
                }
            };

            // Test if already decryptable with active master key
            let is_already_active =
                match decryptor.decrypt(std::iter::once(&active_id as &dyn age::Identity)) {
                    Ok(_) => true,
                    Err(age::DecryptError::NoMatchingKeys) => false,
                    Err(_) => false,
                };

            if is_already_active {
                if !all {
                    eprintln!(
                        "'{}' is already encrypted under active master key. Staging...",
                        rel_path
                    );
                    let _ = git::git_cmd_with_path(&repo.root)
                        .args(["add", rel_path])
                        .status();
                }
                continue;
            }

            // Historical or foreign ciphertext: decrypt using gathered identities
            let id_refs: Vec<&dyn age::Identity> =
                identities.iter().map(|id| id.as_ref()).collect();
            let decryptor2 = age::Decryptor::new(&raw_bytes[..])
                .map_err(|e| anyhow!("Failed to parse age ciphertext in '{}': {e}", rel_path))?;

            let mut reader = match decryptor2.decrypt(id_refs.into_iter()) {
                Ok(r) => r,
                Err(e) => {
                    if repo.is_shallow() {
                        return Err(anyhow!(
                            "Cannot decrypt historical ciphertext in '{rel_path}' ({e}).\n\
                             Repository is a shallow clone (commit history is truncated).\n\
                             Historical rewrap requires commit history on shallow clones to discover rotated master keys.\n\
                             Run 'git fetch --unshallow' or configure 'fetch-depth: 0' in CI,\n\
                             or specify the historical decryption key directly via '--identity <KEY>'."
                        ));
                    }
                    return Err(anyhow!(
                        "Cannot decrypt historical ciphertext in '{}' ({}).\n\
                         Specify the decryption private key or historical master key via '--identity <KEY>'.",
                        rel_path,
                        e
                    ));
                }
            };

            // Stream decrypted plaintext into a temporary file in target parent dir for O(1) memory
            // and guaranteed same-filesystem affinity (preventing EXDEV on Docker / multi-mount setups).
            let parent_dir = match full_path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            let mut temp_dest = tempfile::NamedTempFile::new_in(parent_dir)?;
            io::copy(&mut reader, &mut temp_dest)?;
            temp_dest.flush()?;

            // Handle read-only permissions if present via RAII guard
            let orig_readonly = fs::metadata(&full_path)
                .map(|m| m.permissions().readonly())
                .unwrap_or(false);
            let _readonly_guard = if orig_readonly {
                if let Ok(mut perms) = fs::metadata(&full_path).map(|m| m.permissions()) {
                    git::set_permissions_writable(&mut perms);
                    let _ = fs::set_permissions(&full_path, perms);
                }
                Some(ReadonlyGuard {
                    path: full_path.clone(),
                })
            } else {
                None
            };

            // Atomically replace with exponential backoff for antivirus software on Windows
            let mut to_persist = temp_dest;
            let mut persisted = false;
            let mut last_err = None;
            for attempt in 0..5 {
                match to_persist.persist(&full_path) {
                    Ok(_) => {
                        persisted = true;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e.error);
                        to_persist = e.file;
                        std::thread::sleep(std::time::Duration::from_millis(10 * (1 << attempt)));
                    }
                }
            }
            if !persisted {
                let err_msg = last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown error".to_string());
                return Err(anyhow!(
                    "Failed to replace '{}': {}",
                    full_path.display(),
                    err_msg
                ));
            }

            // Stage with git add: Git triggers clean_stream, which encrypts with active master key!
            let status = git::git_cmd_with_path(&repo.root)
                .args(["add", rel_path])
                .status()
                .with_context(|| format!("Failed to stage rewrapped file '{rel_path}'"))?;

            // Explicitly drop guard here (restoring read-only attribute) before checking status
            drop(_readonly_guard);

            if status.success() {
                eprintln!(
                    "Successfully rewrapped '{}' under active master key.",
                    rel_path
                );
                rewrapped_count += 1;
            } else {
                return Err(anyhow!("Failed to re-stage '{}'", rel_path));
            }
        } else {
            if all {
                // In --all mode, skip files that are already plaintext on disk.
                // This protects uncommitted working-tree edits and WIP drafts from being prematurely staged!
                continue;
            }

            // User explicitly requested this path: check for uncommitted working-tree edits
            let status_out = git::git_cmd_with_path(&repo.root)
                .args(["status", "--porcelain", "-z", "--", rel_path])
                .output();
            if let Ok(st) = status_out
                && !st.stdout.is_empty()
                && !force
            {
                let entry = &st.stdout;
                if entry.len() >= 2 && entry[1] == b'M' {
                    eprintln!(
                        "git-agecrypt rewrap [WARNING]: File '{}' has unstaged local modifications in working tree.",
                        rel_path
                    );
                    eprintln!("Staging now would bundle your working-tree edits into the index.");
                    eprintln!(
                        "Run with '--force' (-f) to proceed with staging, or commit your edits first."
                    );
                    return Err(anyhow!(
                        "Rewrap aborted: uncommitted local modifications in '{rel_path}'"
                    ));
                }
            }

            // Plaintext on disk: stage it so clean filter encrypts it with active master key
            let status = git::git_cmd_with_path(&repo.root)
                .args(["add", rel_path])
                .status()
                .with_context(|| format!("Failed to stage file '{rel_path}'"))?;

            if status.success() {
                eprintln!("Staged plaintext '{}' under active master key.", rel_path);
                rewrapped_count += 1;
            }
        }
    }

    eprintln!();
    eprintln!(
        "Rewrapped and staged {} file(s) under the active master key.",
        rewrapped_count
    );
    eprintln!("Files are now verified and ready to commit.");
    Ok(())
}

fn cmd_unlock(key_file: Option<&str>, force: bool) -> Result<()> {
    let repo = GitRepo::discover()?;
    let keys_dir = repo.keys_dir();
    if !keys_dir.exists() {
        return Err(anyhow!(
            "Repository does not have .git-agecrypt/keys directory"
        ));
    }

    // 1. Gather identities
    let mut identities = Vec::new();

    if let Some(path_str) = key_file {
        if path_str == "-" {
            eprintln!("Reading private key identity from standard input...");
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            let ids = crypto::load_identities_from_buffer(&buf)?;
            identities.extend(ids);
        } else {
            let path = Path::new(path_str);
            eprintln!("Loading private key identity from {}...", path.display());
            let ids = crypto::load_identities_from_file(path)?;
            identities.extend(ids);
        }
    } else {
        // Probe default SSH and age locations
        let candidates = crypto::get_default_identity_paths();
        for candidate in candidates {
            if candidate.exists()
                && let Ok(ids) = crypto::load_identities_from_file(&candidate)
            {
                identities.extend(ids);
            }
        }
    }

    if identities.is_empty() {
        return Err(anyhow!(
            "No private keys found. Specify a key with 'git-agecrypt unlock <KEY_FILE>' \
             or pass key via stdin: 'echo \"$KEY\" | git-agecrypt unlock -'"
        ));
    }

    // 2. Iterate through all .git-agecrypt/keys/*.age and attempt unwrapping
    let entries = fs::read_dir(&keys_dir)?;
    let mut unwrapped_key: Option<String> = None;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("age") {
            let content = fs::read_to_string(&path)?;
            if let Ok(key) = crypto::unwrap_master_key(&content, &identities) {
                unwrapped_key = Some(key);
                let name_display = path
                    .file_name()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_default();
                eprintln!("Successfully unlocked using recipient key {name_display}");
                break;
            }
        }
    }

    let master_key = unwrapped_key.ok_or_else(|| {
        anyhow!("None of the provided private keys match any recipient in .git-agecrypt/keys/")
    })?;

    // 3. Atomically save unwrapped master key
    repo.save_local_master_key(&master_key)?;

    // 4. Safe checkout / refresh working trees across all linked worktrees
    repo.refresh_all_worktrees(force)?;

    eprintln!(
        "Repository unlocked successfully. Tracked secrets are now decrypted in your working tree."
    );
    Ok(())
}

fn cmd_lock(force: bool) -> Result<()> {
    let repo = GitRepo::discover()?;

    if let Some(op) = repo.check_active_git_operations()?
        && !force
    {
        eprintln!("git-agecrypt [WARNING]: Active Git operation detected: {op}.");
        eprintln!(
            "Locking now will corrupt Git's working state and risk committing double-encrypted secrets."
        );
        eprintln!(
            "Please finish or abort the operation (e.g. 'git rebase --abort' / 'git merge --abort') \
                 or run with '--force' (-f) to lock anyway."
        );
        return Err(anyhow!(
            "Lock aborted: active Git operation in progress: {op}"
        ));
    }

    let dirty_across = repo.get_dirty_files_across_worktrees()?;
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
        eprintln!("Aborting lock to prevent data loss. Run with '--force' (-f) to lock anyway.");
        return Err(anyhow!(
            "Lock aborted: uncommitted changes in tracked secret file(s)"
        ));
    }

    let unreachable_wts = repo.get_unreachable_worktrees()?;
    if !unreachable_wts.is_empty() && !force {
        eprintln!("git-agecrypt [WARNING]: Linked worktree(s) are detached or unreachable:");
        for wt in &unreachable_wts {
            eprintln!("  - {}", wt.display());
        }
        eprintln!(
            "Plaintext secrets on detached storage devices cannot be re-smudged to ciphertext.\n\
             Locking now would leave plaintext secrets exposed on those media while removing local keys.\n\
             Run with '--force' (-f) to lock anyway, or run 'git worktree prune' if the worktree was deleted."
        );
        return Err(anyhow!(
            "Aborting lock due to unreachable linked worktree(s)"
        ));
    }

    // Cleanliness and uncommitted edits across all worktrees were already strictly validated above.
    // Pass force=true to refresh_all_worktrees so that re-checking git status while repo.key is staged
    // does not falsely trigger dirty detection due to racy git timestamp cache differences.
    repo.transactional_lock(|| repo.refresh_all_worktrees(true))?;
    let _ = repo.clear_cache();
    eprintln!("Repository locked across all linked worktrees. Local credentials removed.");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let repo = GitRepo::discover()?;
    println!("git-agecrypt Status:");
    println!("  Repository root:   {}", repo.root.display());

    let is_stale = repo.is_local_master_key_stale().unwrap_or(false);
    let unlocked_str = if is_stale {
        "OUT-OF-SYNC / STALE (Master key was rotated upstream. Run 'git-agecrypt unlock' to synchronize.)"
    } else if repo.is_unlocked() {
        "YES (plaintext on disk)"
    } else {
        "NO (locked)"
    };
    println!("  Unlocked:          {}", unlocked_str);

    let pub_file = repo.public_key_file();
    if pub_file.exists() {
        let pub_key = fs::read_to_string(pub_file)?;
        println!("  Public Recipient:  {}", pub_key.trim());
    } else {
        println!("  Public Recipient:  Not initialized (run 'git-agecrypt init')");
    }

    let patterns = repo.get_tracked_patterns()?;
    println!(
        "  Tracked patterns:  {}",
        if patterns.is_empty() {
            "(none in .gitattributes)".to_string()
        } else {
            patterns.join(", ")
        }
    );

    let keys_dir = repo.keys_dir();
    let recipient_count = if keys_dir.exists() {
        fs::read_dir(&keys_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("age"))
            .count()
    } else {
        0
    };
    println!("  Enrolled keys:     {}", recipient_count);

    Ok(())
}

fn cmd_install_hooks() -> Result<()> {
    let repo = GitRepo::discover()?;
    repo.install_pre_commit_hook()?;
    eprintln!("Safeguard hooks (pre-commit, pre-merge-commit, pre-push) successfully installed.");
    Ok(())
}

fn cmd_check(pre_push: bool) -> Result<()> {
    let repo = GitRepo::discover()?;
    if pre_push {
        repo.check_pushed_commits()?;
    } else {
        repo.check_staged_files()?;
    }
    Ok(())
}

fn cmd_clean(file_path: Option<&str>) -> Result<()> {
    // Git clean filter: reads stdin, writes stdout.
    // ALL LOGGING MUST BE ON STDERR.
    let repo = GitRepo::discover().context("git-agecrypt clean: failed to discover git repo")?;

    // If file_path is provided, verify whether it is a symlink on disk.
    // Git pipes symlink target text through clean filter; symlink targets MUST NOT be encrypted!
    if let Some(path_str) = file_path {
        let target_path = repo.root.join(path_str);
        if let Ok(meta) = fs::symlink_metadata(&target_path)
            && meta.file_type().is_symlink()
        {
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut reader = BufReader::new(stdin.lock());
            let mut writer = BufWriter::new(stdout.lock());
            io::copy(&mut reader, &mut writer)?;
            writer.flush()?;
            return Ok(());
        }
    }

    let pub_file = repo.public_key_file();
    if !pub_file.exists() {
        return Err(anyhow!(
            "git-agecrypt clean: .git-agecrypt/repo.pub not found. Run 'git-agecrypt init'"
        ));
    }

    let pub_key_str = fs::read_to_string(pub_file)?;
    let recipient = crypto::parse_recipient(&pub_key_str)?;

    let master_key_opt = repo.read_local_master_key()?;
    let identity_opt: Option<age::x25519::Identity> = if let Some(ref key_str) = master_key_opt {
        age::x25519::Identity::from_str(key_str).ok()
    } else {
        None
    };

    let stdin = io::stdin();
    let stdout = io::stdout();

    let reader = BufReader::new(stdin.lock());
    let writer = BufWriter::new(stdout.lock());
    let cache_dir = repo.cache_dir();
    let cache_key = master_key_opt.as_deref().map(|s| s.as_bytes());
    let staged_blob = if let Some(path_str) = file_path {
        repo.get_staged_blob(path_str)
    } else {
        None
    };

    if let Err(err) = crypto::clean_stream(
        reader,
        writer,
        recipient.as_ref(),
        Some(&cache_dir),
        identity_opt.as_ref().map(|id| id as &dyn age::Identity),
        cache_key,
        staged_blob.as_deref(),
    ) {
        if is_broken_pipe(&err) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

fn cmd_smudge(file_path: Option<&str>) -> Result<()> {
    // Git smudge filter: reads stdin, writes stdout.
    // ALL LOGGING MUST BE ON STDERR.
    let repo = GitRepo::discover().context("git-agecrypt smudge: failed to discover git repo")?;

    let is_stale = repo.is_local_master_key_stale().unwrap_or(false);
    let master_key_opt = if is_stale {
        // Master key was rotated upstream! Attempt automatic transparent re-unlock
        if let Ok(Some(new_key)) = repo.try_auto_refresh_master_key() {
            eprintln!(
                "git-agecrypt smudge: Upstream master key was rotated; automatically synchronized credentials."
            );
            Some(new_key)
        } else {
            eprintln!(
                "git-agecrypt smudge [WARNING]: Local master key is stale because repository was rekeyed upstream. \
                 Run 'git-agecrypt unlock' with your private key to decrypt files."
            );
            // Stale key cannot decrypt new ciphertexts; treat as locked so ciphertext passes through without crashing checkout
            None
        }
    } else {
        repo.read_local_master_key()?
    };

    let identity_opt: Option<age::x25519::Identity> = if let Some(ref key_str) = master_key_opt {
        age::x25519::Identity::from_str(key_str).ok()
    } else {
        None
    };

    let stdin = io::stdin();
    let stdout = io::stdout();

    let reader = BufReader::new(stdin.lock());
    let writer = BufWriter::new(stdout.lock());
    let cache_dir = repo.cache_dir();
    let cache_key = master_key_opt.as_deref().map(|s| s.as_bytes());

    if let Err(err) = crypto::smudge_stream(
        reader,
        writer,
        identity_opt.as_ref().map(|id| id as &dyn age::Identity),
        Some(&cache_dir),
        cache_key,
    ) {
        if is_broken_pipe(&err) {
            return Ok(());
        }
        if let Some(p) = file_path {
            eprintln!("git-agecrypt smudge [ERROR] for file '{p}': {err}");
        }
        return Err(err);
    }
    Ok(())
}

fn cmd_textconv(file: &Path) -> Result<()> {
    let repo = GitRepo::discover()?;
    let key_opt = if repo.is_local_master_key_stale().unwrap_or(false) {
        if let Ok(Some(new_key)) = repo.try_auto_refresh_master_key() {
            Some(new_key)
        } else {
            repo.read_local_master_key()?
        }
    } else {
        repo.read_local_master_key()?
    };

    let target_file = if file.exists() {
        file.to_path_buf()
    } else if repo.root.join(file).exists() {
        repo.root.join(file)
    } else {
        file.to_path_buf()
    };

    if !target_file.exists() {
        return Ok(());
    }

    let input = File::open(&target_file)?;
    let mut reader = BufReader::new(input);
    let mut prefix = [0u8; 22];
    let n = reader.read(&mut prefix)?;

    if !crypto::is_age_ciphertext(&prefix[..n]) {
        // Plaintext file
        let mut full_file = File::open(file)?;
        if let Err(err) = io::copy(&mut full_file, &mut io::stdout()) {
            if err.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(err.into());
        }
        return Ok(());
    }

    // Ciphertext
    if let Some(key_str) = key_opt
        && let Ok(identity) = age::x25519::Identity::from_str(&key_str)
    {
        let file_again = File::open(file)?;
        let mut stream_reader = BufReader::new(file_again);
        let mut out = io::stdout();
        if let Err(err) = crypto::decrypt_stream(&mut stream_reader, &mut out, &identity) {
            if is_broken_pipe(&err) {
                return Ok(());
            }
            println!(
                "[git-agecrypt: file is encrypted with a historical or foreign key. Run 'git-agecrypt rewrap' to view diff]"
            );
            return Ok(());
        }
        return Ok(());
    }

    println!("[git-agecrypt: file is encrypted. Run 'git-agecrypt unlock' to view diff]");
    Ok(())
}

fn cmd_merge(
    base: &Path,
    ours: &Path,
    theirs: &Path,
    marker_size: Option<usize>,
    file_path: Option<&str>,
) -> Result<()> {
    let repo = GitRepo::discover()?;
    let key_str = if repo.is_local_master_key_stale().unwrap_or(false) {
        if let Ok(Some(new_key)) = repo.try_auto_refresh_master_key() {
            new_key
        } else {
            repo.read_local_master_key()?.ok_or_else(|| {
                anyhow!("Repository is locked. Cannot execute 3-way merge on encrypted files. Run 'git-agecrypt unlock' first.")
            })?
        }
    } else {
        repo.read_local_master_key()?.ok_or_else(|| {
            anyhow!("Repository is locked. Cannot execute 3-way merge on encrypted files. Run 'git-agecrypt unlock' first.")
        })?
    };

    let identity = age::x25519::Identity::from_str(&key_str).map_err(|e| anyhow!("{e}"))?;
    let pub_file = repo.public_key_file();
    let pub_key_str = fs::read_to_string(pub_file)?;
    let recipient = crypto::parse_recipient(&pub_key_str)?;

    let exit_code = merge::run_3way_merge(
        base,
        ours,
        theirs,
        marker_size,
        file_path.unwrap_or("unknown"),
        &identity,
        recipient.as_ref(),
    )?;

    if exit_code != 0 {
        process::exit(exit_code);
    }

    Ok(())
}

fn cmd_migrate(identity: Option<&str>) -> Result<()> {
    let repo = GitRepo::discover()?;
    eprintln!("Checking repository for git-crypt migration...");

    let gitattributes_path = repo.root.join(".gitattributes");
    if !gitattributes_path.exists() {
        return Err(anyhow!("No .gitattributes found in repository"));
    }

    let attr_content = fs::read_to_string(&gitattributes_path)?;
    if !attr_content.contains("filter=git-crypt") {
        eprintln!("No 'filter=git-crypt' patterns found in .gitattributes.");
    }

    let updated_attr = attr_content
        .replace(
            "filter=git-crypt diff=git-crypt",
            "filter=agecrypt diff=agecrypt merge=agecrypt -text",
        )
        .replace(
            "filter=git-crypt",
            "filter=agecrypt diff=agecrypt merge=agecrypt -text",
        );

    fs::write(&gitattributes_path, updated_attr)?;
    eprintln!("Updated .gitattributes: migrated filter=git-crypt -> filter=agecrypt");

    // Run init
    cmd_init(false)?;

    if let Some(id) = identity {
        cmd_add_recipient(Some(id), None, Some("migration-recipient"))?;
    }

    // Renormalize git index so clean filter is invoked on existing files
    eprintln!(
        "Renormalizing index so Git recompiles all tracked files through git-agecrypt clean..."
    );
    let _ = git::git_cmd_with_path(&repo.root)
        .args(["add", "--renormalize", "."])
        .status();

    eprintln!();
    eprintln!("Migration setup complete!");
    eprintln!("To finalize migration, re-stage your encrypted files and commit:");
    eprintln!("  git add .gitattributes .git-agecrypt");
    eprintln!("  git add -u");
    eprintln!("  git commit -m 'Migrate secrets encryption from git-crypt to git-agecrypt'");

    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

use sha2::Digest;

fn find_default_ssh_public_key() -> Option<String> {
    let home = dirs::home_dir()?;
    let candidates = [
        home.join(".ssh").join("id_ed25519.pub"),
        home.join(".ssh").join("id_rsa.pub"),
    ];

    for path in candidates {
        if path.exists()
            && let Ok(content) = fs::read_to_string(&path)
        {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}
