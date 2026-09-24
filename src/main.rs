mod cli;
mod crypto;
mod git;
mod github;
mod merge;
mod shield;

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

fn validate_ring_arg(ring: Option<&str>) -> Result<Option<&str>> {
    match ring {
        None => Ok(None),
        Some(r) => {
            crate::git::validate_ring_name(r)?;
            Ok(Some(r))
        }
    }
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
        Commands::Init {
            gitattributes,
            ai_shield,
            ring,
        } => cmd_init(gitattributes, ai_shield, ring.as_deref()),
        Commands::AddRecipient {
            identity,
            github,
            name,
            ring,
        } => cmd_add_recipient(
            identity.as_deref(),
            github.as_deref(),
            name.as_deref(),
            ring.as_deref(),
        ),
        Commands::RemoveRecipient { name, ring } => cmd_remove_recipient(&name, ring.as_deref()),
        Commands::ListRecipients { ring } => cmd_list_recipients(ring.as_deref()),
        Commands::Rekey { force, ring } => cmd_rekey(force, ring.as_deref()),
        Commands::Rewrap {
            paths,
            all,
            identity,
            force,
        } => cmd_rewrap(&paths, all, identity.as_deref(), force),
        Commands::Unlock {
            key_file,
            force,
            ring,
        } => cmd_unlock(key_file.as_deref(), force, ring.as_deref()),
        Commands::Lock { force, ring } => cmd_lock(force, ring.as_deref()),
        Commands::Status => cmd_status(),
        Commands::Shield { check } => cmd_shield(check),
        Commands::InstallHooks => cmd_install_hooks(),
        Commands::Check {
            pre_push,
            allow_untracked_secrets,
        } => cmd_check(pre_push, allow_untracked_secrets),
        Commands::Clean { file_path, ring } => cmd_clean(file_path.as_deref(), ring.as_deref()),
        Commands::Smudge { file_path, ring } => cmd_smudge(file_path.as_deref(), ring.as_deref()),
        Commands::Textconv { file, ring } => cmd_textconv(&file, ring.as_deref()),
        Commands::Merge {
            base,
            ours,
            theirs,
            marker_size,
            file_path,
            ring,
        } => cmd_merge(
            &base,
            &ours,
            &theirs,
            marker_size,
            file_path.as_deref(),
            ring.as_deref(),
        ),
        Commands::MigrateFromGitCrypt { identity } => cmd_migrate(identity.as_deref()),
        Commands::Run {
            env_file,
            ring,
            fd,
            allow_env_fallback,
            command,
        } => cmd_run(
            env_file.as_deref(),
            ring.as_deref(),
            fd,
            allow_env_fallback,
            &command,
        ),
    }
}

fn cmd_init(create_gitattributes: bool, ai_shield: bool, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let is_default_ring = matches!(ring_opt, None | Some("default") | Some(""));

    if is_default_ring {
        eprintln!("Initializing git-agecrypt in {}", repo.root.display());
        if repo.root.join(".git-crypt").exists() {
            eprintln!(
                "git-agecrypt: Notice: Existing .git-crypt directory found. To migrate an existing git-crypt repository, run 'git-agecrypt migrate-from-git-crypt'."
            );
        }
    } else {
        let r = ring_opt.unwrap();
        repo.check_ring_case_collision(r)?;
        eprintln!(
            "Initializing git-agecrypt ring '{}' in {}",
            r,
            repo.root.display()
        );
    }

    let keys_dir = repo.keys_dir_for_ring(ring_opt);
    fs::create_dir_all(&keys_dir)?;

    let pub_file = repo.public_key_file_for_ring(ring_opt);
    if pub_file.exists() {
        if repo.is_unlocked_for_ring(ring_opt) {
            if is_default_ring {
                eprintln!("Repository already initialized. Re-configuring git filters...");
            } else {
                eprintln!("Ring already initialized. Re-configuring git filters...");
            }
        } else if is_default_ring {
            eprintln!(
                "Repository is initialized but locked. Configured git filters. Run 'git-agecrypt unlock' to decrypt."
            );
        } else {
            eprintln!(
                "Ring is initialized but locked. Configured git filters. Run 'git-agecrypt unlock --ring {}' to decrypt.",
                ring_opt.unwrap()
            );
        }
    } else {
        let (identity, recipient) = crypto::generate_master_identity();
        if let Some(parent) = pub_file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&pub_file, format!("{}\n", recipient))?;
        repo.save_local_master_key_for_ring(identity.to_string().expose_secret(), ring_opt)?;
        if is_default_ring {
            eprintln!("Generated new 256-bit repository master key.");
            eprintln!("Public key saved to .git-agecrypt/repo.pub: {recipient}");
        } else {
            eprintln!(
                "Generated new 256-bit repository master key for ring '{}'.",
                ring_opt.unwrap()
            );
            eprintln!("Public key saved to {}: {recipient}", pub_file.display());
        }

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
    }

    // Configure git config filters
    repo.configure_git_filters_for_ring(ring_opt)?;
    if is_default_ring {
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
                eprintln!(
                    "Created default .gitattributes template (with -text binary safety flag)."
                );
            }
        }

        // Synchronize AI agent and IDE ignore files (.cursorignore, .claudeignore, .aiderignore, .aiignore)
        let tracked_patterns = repo.get_tracked_patterns()?;
        if !tracked_patterns.is_empty() {
            let updated = shield::sync_ai_shields(&repo.root, &tracked_patterns, ai_shield)?;
            if !updated.is_empty() {
                eprintln!(
                    "Synchronized AI agent and IDE ignore files (.cursorignore, .claudeignore, .aiderignore, .aiignore)."
                );
            }
        }
    } else {
        let r = ring_opt.unwrap();
        eprintln!("Configured git filter, diff, and merge drivers for ring '{r}' in .git/config.");
        eprintln!();
        eprintln!("Add rules to .gitattributes for this ring:");
        eprintln!(
            "  secrets/{r}/** filter=agecrypt-{r} diff=agecrypt-{r} merge=agecrypt-{r} -text"
        );
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
    ring_opt: Option<&str>,
) -> Result<()> {
    if identity.is_some() && github.is_some() {
        return Err(anyhow!(
            "Cannot specify both --identity (-i) and --github simultaneously. Choose one recipient source."
        ));
    }

    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let master_key = repo.read_local_master_key_for_ring(ring_opt)?.ok_or_else(|| {
        anyhow!(
            "Repository/ring is locked. You must run 'git-agecrypt unlock' before adding recipients."
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

    let keys_dir = repo.keys_dir_for_ring(ring_opt);
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
        let is_default = matches!(ring_opt, None | Some("default") | Some(""));
        if is_default {
            eprintln!("Enrolled recipient '{label}' -> .git-agecrypt/keys/{filename}");
        } else {
            eprintln!(
                "Enrolled recipient '{label}' in ring '{}' -> {}",
                ring_opt.unwrap(),
                dest.display()
            );
        }
    }

    let is_default = matches!(ring_opt, None | Some("default") | Some(""));
    if is_default {
        eprintln!("Remember to commit .git-agecrypt/keys/ to share access with team members.");
    } else {
        eprintln!(
            "Remember to commit {} to share access with team members.",
            keys_dir.display()
        );
    }
    Ok(())
}

fn cmd_remove_recipient(name: &str, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let keys_dir = repo.keys_dir_for_ring(ring_opt);
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
    git::crash_point("after_old_delete");

    eprintln!("Removed recipient '{label}' ({})", key_file.display());
    eprintln!();
    eprintln!("IMPORTANT NOTICE: Offboarding a collaborator requires cycling the master key!");
    eprintln!(
        "Deleting their recipient file prevents them from unlocking future re-keyed commits,"
    );
    eprintln!("but they still possess the current symmetric master key.");
    let rekey_cmd = match ring_opt {
        Some(r) if r != "default" && !r.is_empty() => format!("git-agecrypt rekey --ring {r}"),
        _ => "git-agecrypt rekey".to_string(),
    };
    eprintln!("Run '{rekey_cmd}' now to generate a new master key and re-encrypt all secrets.");
    Ok(())
}

fn cmd_list_recipients(ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let keys_dir = repo.keys_dir_for_ring(ring_opt);
    if !keys_dir.exists() {
        eprintln!("No recipients directory found in {}.", keys_dir.display());
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

fn cmd_rekey(force: bool, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    if !repo.is_unlocked_for_ring(ring_opt) {
        return Err(anyhow!(
            "Repository/ring is locked. You must run 'git-agecrypt unlock' before rekeying."
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

    let keys_dir = repo.keys_dir_for_ring(ring_opt);
    if !keys_dir.exists() {
        return Err(anyhow!(
            "Keys directory not found in {}",
            keys_dir.display()
        ));
    }

    let ring_label = ring_opt.unwrap_or("default");
    eprintln!(
        "Starting repository rekeying for ring '{ring_label}' (rotating symmetric master key)..."
    );

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

    // 4. Update repo.pub
    let pub_file = repo.public_key_file_for_ring(ring_opt);
    if let Some(parent) = pub_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pub_file, format!("{}\n", new_recipient))?;

    git::crash_point("after_rekey_pub_write");

    // 5. Update local master key in common git dir atomically and clear stale cache
    repo.save_local_master_key_for_ring(new_secret_str.expose_secret(), ring_opt)?;
    git::crash_point("after_rekey_key_saved");
    repo.clear_cache_for_ring(ring_opt, true)?;
    git::crash_point("after_rekey_cache_purge");
    git::crash_point("after_old_delete");

    // 6. Re-stage strictly tracked secret files using targeted pathspecs (never '.'!)
    let ls_out = git::git_cmd_with_path(&repo.root)
        .args(["ls-files", "-z"])
        .output()
        .context("Failed to list tracked files")?;

    let mut secret_files = Vec::new();
    for slice in ls_out.stdout.split(|&b: &u8| b == 0) {
        if !slice.is_empty() {
            let rel_str = String::from_utf8_lossy(slice).to_string();
            if repo.is_file_tracked_for_ring(&rel_str, ring_opt)
                && repo.root.join(&rel_str).is_file()
            {
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
    let commit_path = match ring_opt {
        Some(r) if r != "default" && !r.is_empty() => format!(".git-agecrypt/rings/{r}"),
        _ => ".git-agecrypt".to_string(),
    };
    eprintln!("To finalize and commit the rotation:");
    eprintln!("  git add {commit_path}");
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

fn cmd_unlock(key_file: Option<&str>, force: bool, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let keys_dir = repo.keys_dir_for_ring(ring_opt);
    if !keys_dir.exists() {
        return Err(anyhow!(
            "Repository does not have {} directory",
            keys_dir.display()
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

    // 2. Iterate through all keys/*.age and attempt unwrapping
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
        anyhow!(
            "None of the provided private keys match any recipient in {}",
            keys_dir.display()
        )
    })?;

    git::crash_point("after_unwrap_key");

    // 3. Atomically save unwrapped master key
    repo.save_local_master_key_for_ring(&master_key, ring_opt)?;

    git::crash_point("after_unlock_key_saved");

    // 4. Safe checkout / refresh working trees across all linked worktrees
    if ring_opt.is_none() {
        repo.refresh_all_worktrees(force)?;
    } else {
        repo.refresh_all_worktrees_for_ring(force, ring_opt)?;
    }

    git::crash_point("after_unlock_refresh");

    let is_default = matches!(ring_opt, None | Some("default") | Some(""));
    if is_default {
        eprintln!(
            "Repository unlocked successfully. Tracked secrets are now decrypted in your working tree."
        );
    } else {
        eprintln!(
            "Repository ring '{}' unlocked successfully. Tracked secrets are now decrypted in your working tree.",
            ring_opt.unwrap()
        );
    }
    Ok(())
}

fn cmd_lock(force: bool, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
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

    let dirty_across = repo.get_dirty_files_across_worktrees_for_ring(ring_opt)?;
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
    if let Some(r) = ring_opt {
        repo.transactional_lock_for_ring(Some(r), || {
            repo.refresh_all_worktrees_for_ring(true, Some(r))
        })?;
        repo.clear_cache_for_ring(Some(r), false)?;
        eprintln!("Ring '{r}' locked across all linked worktrees. Local credentials removed.");
    } else {
        repo.transactional_lock_for_ring(None, || repo.refresh_all_worktrees_for_ring(true, None))?;
        let _ = repo.clear_cache();
        eprintln!(
            "Repository (default ring) locked across all linked worktrees. Local credentials removed."
        );
    }
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

    if let Ok(rings) = repo.list_rings()
        && !rings.is_empty()
    {
        println!("  Configured rings:  {}", rings.join(", "));
    }

    Ok(())
}

fn cmd_shield(check: bool) -> Result<()> {
    let repo = GitRepo::discover()?;
    let patterns = repo.get_tracked_patterns()?;
    if check {
        let synced = shield::check_ai_shields(&repo.root, &patterns)?;
        if synced {
            println!("AI agent and IDE ignore files are synchronized with .gitattributes.");
            Ok(())
        } else {
            eprintln!(
                "git-agecrypt shield: AI ignore files are NOT synchronized with .gitattributes."
            );
            eprintln!("Run 'git-agecrypt shield' to synchronize.");
            std::process::exit(1);
        }
    } else {
        let updated = shield::sync_ai_shields(&repo.root, &patterns, true)?;
        if updated.is_empty() {
            println!("AI agent and IDE ignore files are already up to date.");
        } else {
            println!(
                "Successfully synchronized {} AI ignore file(s):",
                updated.len()
            );
            for p in updated {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                println!("  - {name}");
            }
        }
        Ok(())
    }
}

fn cmd_install_hooks() -> Result<()> {
    let repo = GitRepo::discover()?;
    repo.install_pre_commit_hook()?;
    eprintln!("Safeguard hooks (pre-commit, pre-merge-commit, pre-push) successfully installed.");
    Ok(())
}

fn cmd_check(pre_push: bool, allow_untracked_secrets: bool) -> Result<()> {
    let repo = GitRepo::discover()?;
    if pre_push {
        repo.check_pushed_commits()?;
    } else {
        repo.check_staged_files(allow_untracked_secrets)?;
    }
    Ok(())
}

fn cmd_clean(file_path: Option<&str>, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
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

    let pub_file = repo.public_key_file_for_ring(ring_opt);
    if !pub_file.exists() {
        return Err(anyhow!(
            "git-agecrypt clean: public key file not found: {}. Run 'git-agecrypt init'",
            pub_file.display()
        ));
    }

    let pub_key_str = fs::read_to_string(&pub_file)?;
    let recipient = crypto::parse_recipient(&pub_key_str)?;

    let master_key_opt = repo.read_local_master_key_for_ring(ring_opt)?;
    let identity_opt: Option<age::x25519::Identity> = if let Some(ref key_str) = master_key_opt {
        age::x25519::Identity::from_str(key_str).ok()
    } else {
        None
    };

    let stdin = io::stdin();
    let stdout = io::stdout();

    let reader = BufReader::new(stdin.lock());
    let writer = BufWriter::new(stdout.lock());
    let cache_dir = repo.cache_dir_for_ring(ring_opt);
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

fn cmd_smudge(file_path: Option<&str>, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    // Git smudge filter: reads stdin, writes stdout.
    // ALL LOGGING MUST BE ON STDERR.
    let repo = GitRepo::discover().context("git-agecrypt smudge: failed to discover git repo")?;

    let is_stale = repo
        .is_local_master_key_stale_for_ring(ring_opt)
        .unwrap_or(false);
    let master_key_opt = if is_stale {
        // Master key was rotated upstream! Attempt automatic transparent re-unlock
        if let Ok(Some(new_key)) = repo.try_auto_refresh_master_key_for_ring(ring_opt) {
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
        repo.read_local_master_key_for_ring(ring_opt)?
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
    let cache_dir = repo.cache_dir_for_ring(ring_opt);
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

fn cmd_textconv(file: &Path, ring_opt: Option<&str>) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let key_opt = if repo
        .is_local_master_key_stale_for_ring(ring_opt)
        .unwrap_or(false)
    {
        if let Ok(Some(new_key)) = repo.try_auto_refresh_master_key_for_ring(ring_opt) {
            Some(new_key)
        } else {
            repo.read_local_master_key_for_ring(ring_opt)?
        }
    } else {
        repo.read_local_master_key_for_ring(ring_opt)?
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
    ring_opt: Option<&str>,
) -> Result<()> {
    let ring_opt = validate_ring_arg(ring_opt)?;
    let repo = GitRepo::discover()?;
    let key_str = if repo
        .is_local_master_key_stale_for_ring(ring_opt)
        .unwrap_or(false)
    {
        if let Ok(Some(new_key)) = repo.try_auto_refresh_master_key_for_ring(ring_opt) {
            new_key
        } else {
            repo.read_local_master_key_for_ring(ring_opt)?.ok_or_else(|| {
                anyhow!("Repository is locked. Cannot execute 3-way merge on encrypted files. Run 'git-agecrypt unlock' first.")
            })?
        }
    } else {
        repo.read_local_master_key_for_ring(ring_opt)?.ok_or_else(|| {
            anyhow!("Repository is locked. Cannot execute 3-way merge on encrypted files. Run 'git-agecrypt unlock' first.")
        })?
    };

    let identity = age::x25519::Identity::from_str(&key_str).map_err(|e| anyhow!("{e}"))?;
    let pub_file = repo.public_key_file_for_ring(ring_opt);
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
    cmd_init(false, false, None)?;

    if let Some(id) = identity {
        cmd_add_recipient(Some(id), None, Some("migration-recipient"), None)?;
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

#[cfg(target_os = "linux")]
fn pass_via_memfd(
    env_vars: &std::collections::HashMap<String, String>,
    command: &[String],
) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;

    let mut content = String::new();
    for (k, v) in env_vars {
        content.push_str(&format!("{k}={v}\n"));
    }

    let name = CString::new("git_agecrypt_env")?;
    let fd =
        unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), libc::MFD_CLOEXEC) } as i32;
    if fd < 0 {
        return Err(anyhow!(
            "memfd_create failed: {}",
            io::Error::last_os_error()
        ));
    }

    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(content.as_bytes())?;
    file.flush()?;
    use std::io::Seek;
    file.seek(io::SeekFrom::Start(0))?;

    let raw_fd_val = std::mem::ManuallyDrop::new(file).as_raw_fd();

    let mut child = process::Command::new(&command[0]);
    child.args(&command[1..]);
    child.env("GIT_AGECRYPT_ENV_FD", raw_fd_val.to_string());
    child.env("GIT_AGECRYPT_ENV_FILE", format!("/dev/fd/{raw_fd_val}"));

    unsafe {
        child.pre_exec(move || {
            let flags = libc::fcntl(raw_fd_val, libc::F_GETFD);
            if flags >= 0 {
                let _ = libc::fcntl(raw_fd_val, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            // Block unprivileged same-UID /proc/<pid>/fd inspection and ptrace attachment
            let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0);
            Ok(())
        });
    }

    let status = child
        .status()
        .with_context(|| format!("Failed to execute command '{}'", command[0]))?;
    unsafe {
        libc::close(raw_fd_val);
    }
    process::exit(status.code().unwrap_or(1));
}

#[cfg(not(target_os = "linux"))]
fn pass_via_memfd(
    _env_vars: &std::collections::HashMap<String, String>,
    _command: &[String],
    allow_env_fallback: bool,
) -> Result<()> {
    if !allow_env_fallback {
        return Err(anyhow!(
            "git-agecrypt run [ERROR]: --fd requires Linux anonymous memfd support (SYS_memfd_create). Anonymous in-memory file descriptors are not natively supported on this platform. To explicitly allow falling back to standard process environment injection, re-run with --allow-env-fallback."
        ));
    }
    eprintln!(
        "git-agecrypt run [NOTICE]: In-memory anonymous file descriptor passing (--fd / memfd_create) is only supported on Linux. Falling back to standard child process environment variable injection because --allow-env-fallback was specified."
    );
    Ok(())
}

fn cmd_run(
    env_file_opt: Option<&Path>,
    ring_opt: Option<&str>,
    fd_flag: bool,
    allow_env_fallback: bool,
    command: &[String],
) -> Result<()> {
    let _ = allow_env_fallback;
    let ring_opt = validate_ring_arg(ring_opt)?;
    if command.is_empty() {
        return Err(anyhow!("No command specified to run"));
    }

    let repo = GitRepo::discover()?;

    let files_to_read: Vec<PathBuf> = if let Some(ef) = env_file_opt {
        let full = if ef.is_absolute() {
            ef.to_path_buf()
        } else {
            std::env::current_dir()?.join(ef)
        };
        if !full.exists() {
            return Err(anyhow!(
                "Specified env file '{}' does not exist",
                ef.display()
            ));
        }
        vec![full]
    } else {
        let mut env_files = Vec::new();
        if let Some(r) = ring_opt {
            let ring_env = repo.root.join(format!(".env.{r}"));
            if ring_env.exists() {
                env_files.push(ring_env);
            }
            let ring_dir_env = repo.root.join(format!("secrets/{r}/.env"));
            if ring_dir_env.exists() && !env_files.contains(&ring_dir_env) {
                env_files.push(ring_dir_env);
            }
        }
        let default_env = repo.root.join(".env");
        if default_env.exists() && !env_files.contains(&default_env) {
            env_files.push(default_env);
        }
        if let Ok(out) = git::git_cmd_with_path(&repo.root)
            .args(["ls-files"])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let rel = line.trim();
                    if rel.is_empty() {
                        continue;
                    }
                    let lower = rel.to_lowercase();
                    if (lower.ends_with(".env")
                        || lower.contains(".env.")
                        || lower.ends_with(".secret.env"))
                        && repo.is_file_tracked_for_ring(rel, ring_opt)
                    {
                        let candidate = repo.root.join(rel);
                        if candidate.exists()
                            && candidate.is_file()
                            && !env_files.contains(&candidate)
                        {
                            env_files.push(candidate);
                        }
                    }
                }
            }
        }
        if let Ok(patterns) = repo.get_tracked_patterns_for_ring(ring_opt) {
            for pat in patterns {
                let lower = pat.to_lowercase();
                if lower.ends_with(".env")
                    || lower.contains(".env.")
                    || lower.ends_with(".secret.env")
                {
                    let candidate = repo.root.join(&pat);
                    if candidate.exists() && candidate.is_file() && !env_files.contains(&candidate)
                    {
                        env_files.push(candidate);
                    }
                }
            }
        }
        if env_files.is_empty() {
            let cwd_env = std::env::current_dir()?.join(".env");
            if cwd_env.exists() {
                env_files.push(cwd_env);
            }
        }
        if env_files.is_empty() {
            return Err(anyhow!(
                "No .env file found in repository root or current directory. Specify one with -e/--env-file."
            ));
        }
        env_files
    };

    let mut master_key_opt: Option<String> = None;
    let mut env_vars = std::collections::HashMap::new();

    for path in files_to_read {
        let bytes = fs::read(&path)
            .with_context(|| format!("Failed to read secret env file: {}", path.display()))?;

        let prefix_len = std::cmp::min(bytes.len(), crypto::AGE_HEADER_MAGIC.len());
        let plaintext = if crypto::is_age_ciphertext(&bytes[..prefix_len]) {
            if master_key_opt.is_none() {
                if let Ok(Some(key)) = repo.read_local_master_key_for_ring(ring_opt) {
                    master_key_opt = Some(key);
                } else if let Ok(Some(key)) = repo.try_auto_refresh_master_key_for_ring(ring_opt) {
                    master_key_opt = Some(key);
                } else {
                    let keys_dir = repo.keys_dir_for_ring(ring_opt);
                    if keys_dir.exists() {
                        let mut identities = Vec::new();
                        for candidate in crypto::get_default_identity_paths() {
                            if candidate.exists()
                                && let Ok(ids) =
                                    crypto::load_identities_from_file_non_interactive(&candidate)
                            {
                                identities.extend(ids);
                            }
                        }
                        if !identities.is_empty() {
                            if let Ok(entries) = fs::read_dir(&keys_dir) {
                                for entry in entries.flatten() {
                                    let key_path = entry.path();
                                    if key_path.extension().and_then(|s| s.to_str()) == Some("age")
                                    {
                                        if let Ok(content) = fs::read_to_string(&key_path) {
                                            if let Ok(key) =
                                                crypto::unwrap_master_key(&content, &identities)
                                            {
                                                master_key_opt = Some(key);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if master_key_opt.is_none() {
                        return Err(anyhow!(
                            "File '{}' is encrypted with git-agecrypt, but repository is locked and no valid identity was found.\n\
                             Run 'git-agecrypt unlock' first or provide an unlocked identity.",
                            path.display()
                        ));
                    }
                }
            }

            let master_key = master_key_opt.as_ref().unwrap();
            let id = age::x25519::Identity::from_str(master_key)
                .map_err(|e| anyhow!("Invalid master key identity: {e}"))?;
            let decryptor = age::Decryptor::new(&bytes[..]).map_err(|e| {
                anyhow!(
                    "Failed to parse age ciphertext for '{}': {e}",
                    path.display()
                )
            })?;
            let mut reader = decryptor
                .decrypt(std::iter::once(&id as &dyn age::Identity))
                .map_err(|e| anyhow!("Failed to decrypt secret file '{}': {e}", path.display()))?;
            let mut decrypted_str = String::new();
            reader.read_to_string(&mut decrypted_str)?;
            decrypted_str
        } else {
            String::from_utf8(bytes)
                .with_context(|| format!("File '{}' is not valid UTF-8 text", path.display()))?
        };

        for line in plaintext.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let candidate = if let Some(stripped) = trimmed.strip_prefix("export ") {
                stripped.trim()
            } else {
                trimmed
            };
            if let Some((k, v)) = candidate.split_once('=') {
                let k = k.trim().to_string();
                let mut v = v.trim().to_string();
                if ((v.starts_with('"') && v.ends_with('"'))
                    || (v.starts_with('\'') && v.ends_with('\'')))
                    && v.len() >= 2
                {
                    v = v[1..v.len() - 1].to_string();
                }
                if !k.is_empty() {
                    env_vars.insert(k, v);
                }
            }
        }
    }

    if fd_flag {
        #[cfg(target_os = "linux")]
        {
            return pass_via_memfd(&env_vars, command);
        }
        #[cfg(not(target_os = "linux"))]
        {
            pass_via_memfd(&env_vars, command, allow_env_fallback)?;
        }
    }

    let mut child = process::Command::new(&command[0]);
    child.args(&command[1..]);
    for (k, v) in env_vars {
        child.env(k, v);
    }

    let status = child
        .status()
        .with_context(|| format!("Failed to execute command '{}'", command[0]))?;
    process::exit(status.code().unwrap_or(1));
}
