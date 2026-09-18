use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "git-agecrypt",
    version,
    about = "Modern, GPG-free Git secrets filter using age encryption and SSH keys",
    long_about = "Enables transparent encryption and decryption of repository files using Git's native clean, smudge, and merge filter drivers with the age specification and SSH keys."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize git-agecrypt in the current Git repository
    Init {
        /// Automatically create a default .gitattributes template if none exists
        #[arg(long, default_value_t = true)]
        gitattributes: bool,

        /// Automatically generate AI agent and IDE ignore files (.cursorignore, .claudeignore, etc.)
        #[arg(long)]
        ai_shield: bool,
    },

    /// Add an age or SSH public key recipient
    AddRecipient {
        /// Recipient public key (e.g. 'age1...' or 'ssh-ed25519 ...') or path to public key file
        #[arg(short, long, conflicts_with = "github")]
        identity: Option<String>,

        /// GitHub username to fetch SSH public keys from (https://github.com/<username>.keys)
        #[arg(long, conflicts_with = "identity")]
        github: Option<String>,

        /// Optional name/label for the recipient key file
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Remove an enrolled recipient public key file (.git-agecrypt/keys/<NAME>.age)
    RemoveRecipient {
        /// Name of the recipient file to remove (with or without .age extension)
        name: String,
    },

    /// List all enrolled recipient public keys
    ListRecipients,

    /// Rotate repository master key and re-encrypt all working tree secrets (team offboarding)
    Rekey {
        /// Force rekey even if uncommitted non-secret working tree edits exist
        #[arg(short, long)]
        force: bool,
    },

    /// Unlock repository secrets using an SSH or Age private key
    Unlock {
        /// Path to private key file, or '-' to read from standard input
        #[arg(value_name = "KEY_FILE")]
        key_file: Option<String>,

        /// Overwrite unstaged changes in working tree during checkout
        #[arg(short, long)]
        force: bool,
    },

    /// Lock the repository, wiping credentials and encrypting files in the working tree
    Lock {
        /// Overwrite unstaged changes in working tree during lock
        #[arg(short, long)]
        force: bool,
    },

    /// Display git-agecrypt status, lock state, recipients, and tracked files
    Status,

    /// Synchronize AI agent and IDE ignore files (.cursorignore, .claudeignore, .aiderignore, .aiignore) with .gitattributes
    Shield {
        /// Check whether AI shield ignore files are synchronized without modifying disk
        #[arg(long)]
        check: bool,
    },

    /// Install automated pre-commit safeguard hook into .git/hooks/pre-commit
    InstallHooks,

    /// Inspect staged files or outgoing commits to prevent plaintext secret leaks
    Check {
        /// Inspect outgoing commits passed via stdin by git pre-push hook
        #[arg(long)]
        pre_push: bool,

        /// Allow untracked files matching secret heuristics to be committed as plaintext
        #[arg(long)]
        allow_untracked_secrets: bool,
    },

    /// Git clean filter driver (reads plaintext stdin -> writes age ciphertext stdout)
    Clean {
        /// Optional relative path of the file being filtered (%f)
        file_path: Option<String>,
    },

    /// Git smudge filter driver (reads age ciphertext stdin -> writes plaintext stdout)
    Smudge {
        /// Optional relative path of the file being filtered (%f)
        file_path: Option<String>,
    },

    /// Git diff textconv driver (decrypts target file for git diff)
    Textconv {
        /// File path to decrypt for diff
        file: PathBuf,
    },

    /// Git 3-way merge driver (%O %A %B %L %P)
    Merge {
        /// Base / ancestor version (%O)
        base: PathBuf,
        /// Current / ours version (%A)
        ours: PathBuf,
        /// Incoming / theirs version (%B)
        theirs: PathBuf,
        /// Conflict marker size (%L)
        marker_size: Option<usize>,
        /// Relative path of file being merged (%P)
        file_path: Option<String>,
    },

    /// Re-encrypt historical or foreign secrets under the active master key (resolves historical merge/cherry-pick deadlocks)
    Rewrap {
        /// File path(s) to rewrap under the active master key
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,

        /// Rewrap all tracked secret files that currently contain foreign or historical ciphertexts
        #[arg(short, long)]
        all: bool,

        /// Optional path to private key identity or master key to decrypt historical ciphertext
        #[arg(short, long)]
        identity: Option<String>,

        /// Force rewrapping even if uncommitted working-tree edits exist
        #[arg(short, long)]
        force: bool,
    },

    /// Migrate an existing git-crypt repository to git-agecrypt
    MigrateFromGitCrypt {
        /// Optional identity/public key for the initial git-agecrypt recipient
        #[arg(short, long)]
        identity: Option<String>,
    },

    /// Execute a command with decrypted secrets injected into the process environment
    Run {
        /// Specific secret env file to load (defaults to all tracked .env / *.secret.env files)
        #[arg(short, long)]
        env_file: Option<PathBuf>,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}
