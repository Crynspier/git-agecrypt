//! Generative shadow-model state machine with exact replay and ddmin failure shrinking.
//!
//! Modes:
//! - Generation (default test): drives a seeded RNG to apply random operations while a
//!   shadow model tracks expected state. Every drawn operation is appended to an ops log
//!   (`GIT_AGECRYPT_OPS_LOG`, default: `%TEMP%/git-agecrypt-ops-<pid>-<seed>.log`).
//! - Replay (`test_replay_ops_log`, gated on `GIT_AGECRYPT_REPLAY=<file>`): re-executes a
//!   recorded ops log exactly; operations whose preconditions no longer hold are skipped.
//! - Shrinking (`test_ddmin_shrink_real_failure`, gated on `GIT_AGECRYPT_SHRINK=<file>`):
//!   delta-debugging (ddmin) over the ops log to produce a minimal failing sequence.
//! - Shrinker self-test (`test_ddmin_shrinker_selftest`): validates the replay + ddmin
//!   machinery end-to-end with a synthetic contiguous-subsequence failure trigger
//!   (`GIT_AGECRYPT_FAIL_IF_EXEC_SEQ`).

mod common;

use common::invariants::*;
use common::shadow_model::*;
use common::*;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;

/// Operation types for the generative state machine.
/// Every variant is fully self-contained (all parameters carried inline) so a recorded
/// operation log can be replayed exactly, without the original RNG stream.
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Operation {
    EditSecret(usize, String),
    CreateSecret(String, String),
    DeleteSecret(usize),
    RenameSecret(usize, String),
    CreateBinary(String, Vec<u8>),
    CreateUnicode(String, String),
    GitAdd(usize),
    GitAddAll,
    GitAddPartial(usize, String),
    GitUnstage(usize),
    GitCommit(String),
    GitCommitAmend(String),
    GitMerge(String),
    GitRebase(String),
    GitCherryPick(String),
    GitRevert(String),
    GitResetSoft(String),
    GitResetMixed(String),
    GitResetHard(String),
    GitRestore(usize),
    GitCheckout(String),
    GitSwitch(String),
    GitCreateBranch(String),
    GitDeleteBranch(String),
    GitCreateTag(String),
    GitStashPush,
    GitStashPop,
    GitStashApply,
    GitRepack,
    GitGc,
    GitWorktreeAdd(String),
    GitWorktreeRemove(String),
    AgecryptInitRing(String),
    AgecryptLock(String),
    AgecryptUnlock(String),
    AgecryptRekey(String),
    AgecryptAddRecipient(String, String, String),
    AgecryptRemoveRecipient(String, String),
}
impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::EditSecret(i, _) => write!(f, "EditSecret({})", i),
            Operation::CreateSecret(n, _) => write!(f, "CreateSecret({})", n),
            Operation::DeleteSecret(i) => write!(f, "DeleteSecret({})", i),
            Operation::RenameSecret(i, n) => write!(f, "RenameSecret({}, {})", i, n),
            Operation::CreateBinary(n, _) => write!(f, "CreateBinary({})", n),
            Operation::CreateUnicode(n, _) => write!(f, "CreateUnicode({})", n),
            Operation::GitAdd(i) => write!(f, "GitAdd({})", i),
            Operation::GitAddAll => write!(f, "GitAddAll"),
            Operation::GitAddPartial(i, _) => write!(f, "GitAddPartial({})", i),
            Operation::GitUnstage(i) => write!(f, "GitUnstage({})", i),
            Operation::GitCommit(m) => write!(f, "GitCommit({})", m),
            Operation::GitCommitAmend(m) => write!(f, "GitCommitAmend({})", m),
            Operation::GitMerge(b) => write!(f, "GitMerge({})", b),
            Operation::GitRebase(b) => write!(f, "GitRebase({})", b),
            Operation::GitCherryPick(c) => write!(f, "GitCherryPick({})", c),
            Operation::GitRevert(c) => write!(f, "GitRevert({})", c),
            Operation::GitResetSoft(c) => write!(f, "GitResetSoft({})", c),
            Operation::GitResetMixed(c) => write!(f, "GitResetMixed({})", c),
            Operation::GitResetHard(c) => write!(f, "GitResetHard({})", c),
            Operation::GitRestore(i) => write!(f, "GitRestore({})", i),
            Operation::GitCheckout(b) => write!(f, "GitCheckout({})", b),
            Operation::GitSwitch(b) => write!(f, "GitSwitch({})", b),
            Operation::GitCreateBranch(b) => write!(f, "GitCreateBranch({})", b),
            Operation::GitDeleteBranch(b) => write!(f, "GitDeleteBranch({})", b),
            Operation::GitCreateTag(t) => write!(f, "GitCreateTag({})", t),
            Operation::GitStashPush => write!(f, "GitStashPush"),
            Operation::GitStashPop => write!(f, "GitStashPop"),
            Operation::GitStashApply => write!(f, "GitStashApply"),
            Operation::GitRepack => write!(f, "GitRepack"),
            Operation::GitGc => write!(f, "GitGc"),
            Operation::GitWorktreeAdd(p) => write!(f, "GitWorktreeAdd({})", p),
            Operation::GitWorktreeRemove(p) => write!(f, "GitWorktreeRemove({})", p),
            Operation::AgecryptInitRing(r) => write!(f, "AgecryptInitRing({})", r),
            Operation::AgecryptLock(r) => write!(f, "AgecryptLock({})", r),
            Operation::AgecryptUnlock(r) => write!(f, "AgecryptUnlock({})", r),
            Operation::AgecryptRekey(r) => write!(f, "AgecryptRekey({})", r),
            Operation::AgecryptAddRecipient(r, n, _) => {
                write!(f, "AgecryptAddRecipient({}, {})", r, n)
            }
            Operation::AgecryptRemoveRecipient(r, n) => {
                write!(f, "AgecryptRemoveRecipient({}, {})", r, n)
            }
        }
    }
}
/// Short variant name used for synthetic failure triggers and shrink reporting.
fn op_short_name(op: &Operation) -> &'static str {
    match op {
        Operation::EditSecret(..) => "EditSecret",
        Operation::CreateSecret(..) => "CreateSecret",
        Operation::DeleteSecret(..) => "DeleteSecret",
        Operation::RenameSecret(..) => "RenameSecret",
        Operation::CreateBinary(..) => "CreateBinary",
        Operation::CreateUnicode(..) => "CreateUnicode",
        Operation::GitAdd(..) => "GitAdd",
        Operation::GitAddAll => "GitAddAll",
        Operation::GitAddPartial(..) => "GitAddPartial",
        Operation::GitUnstage(..) => "GitUnstage",
        Operation::GitCommit(..) => "GitCommit",
        Operation::GitCommitAmend(..) => "GitCommitAmend",
        Operation::GitMerge(..) => "GitMerge",
        Operation::GitRebase(..) => "GitRebase",
        Operation::GitCherryPick(..) => "GitCherryPick",
        Operation::GitRevert(..) => "GitRevert",
        Operation::GitResetSoft(..) => "GitResetSoft",
        Operation::GitResetMixed(..) => "GitResetMixed",
        Operation::GitResetHard(..) => "GitResetHard",
        Operation::GitRestore(..) => "GitRestore",
        Operation::GitCheckout(..) => "GitCheckout",
        Operation::GitSwitch(..) => "GitSwitch",
        Operation::GitCreateBranch(..) => "GitCreateBranch",
        Operation::GitDeleteBranch(..) => "GitDeleteBranch",
        Operation::GitCreateTag(..) => "GitCreateTag",
        Operation::GitStashPush => "GitStashPush",
        Operation::GitStashPop => "GitStashPop",
        Operation::GitStashApply => "GitStashApply",
        Operation::GitRepack => "GitRepack",
        Operation::GitGc => "GitGc",
        Operation::GitWorktreeAdd(..) => "GitWorktreeAdd",
        Operation::GitWorktreeRemove(..) => "GitWorktreeRemove",
        Operation::AgecryptInitRing(..) => "AgecryptInitRing",
        Operation::AgecryptLock(..) => "AgecryptLock",
        Operation::AgecryptUnlock(..) => "AgecryptUnlock",
        Operation::AgecryptRekey(..) => "AgecryptRekey",
        Operation::AgecryptAddRecipient(..) => "AgecryptAddRecipient",
        Operation::AgecryptRemoveRecipient(..) => "AgecryptRemoveRecipient",
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct OperationStep {
    step: usize,
    operation: Operation,
    success: bool,
    error: Option<String>,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
/// Serializes an operation to a single log line. All payload fields are hex-encoded so
/// the `|` separator can never appear inside a field and lines stay single-line safe.
fn op_to_line(op: &Operation) -> String {
    use Operation::*;
    let h = |b: &[u8]| hex_encode(b);
    match op {
        EditSecret(i, c) => format!("EditSecret|{i}|{}", h(c.as_bytes())),
        CreateSecret(n, c) => format!("CreateSecret|{}|{}", h(n.as_bytes()), h(c.as_bytes())),
        DeleteSecret(i) => format!("DeleteSecret|{i}"),
        RenameSecret(i, n) => format!("RenameSecret|{i}|{}", h(n.as_bytes())),
        CreateBinary(n, d) => format!("CreateBinary|{}|{}", h(n.as_bytes()), h(d)),
        CreateUnicode(n, c) => format!("CreateUnicode|{}|{}", h(n.as_bytes()), h(c.as_bytes())),
        GitAdd(i) => format!("GitAdd|{i}"),
        GitAddAll => "GitAddAll".to_string(),
        GitAddPartial(i, c) => format!("GitAddPartial|{i}|{}", h(c.as_bytes())),
        GitUnstage(i) => format!("GitUnstage|{i}"),
        GitCommit(m) => format!("GitCommit|{}", h(m.as_bytes())),
        GitCommitAmend(m) => format!("GitCommitAmend|{}", h(m.as_bytes())),
        GitMerge(b) => format!("GitMerge|{}", h(b.as_bytes())),
        GitRebase(b) => format!("GitRebase|{}", h(b.as_bytes())),
        GitCherryPick(c) => format!("GitCherryPick|{}", h(c.as_bytes())),
        GitRevert(c) => format!("GitRevert|{}", h(c.as_bytes())),
        GitResetSoft(c) => format!("GitResetSoft|{}", h(c.as_bytes())),
        GitResetMixed(c) => format!("GitResetMixed|{}", h(c.as_bytes())),
        GitResetHard(c) => format!("GitResetHard|{}", h(c.as_bytes())),
        GitRestore(i) => format!("GitRestore|{i}"),
        GitCheckout(b) => format!("GitCheckout|{}", h(b.as_bytes())),
        GitSwitch(b) => format!("GitSwitch|{}", h(b.as_bytes())),
        GitCreateBranch(b) => format!("GitCreateBranch|{}", h(b.as_bytes())),
        GitDeleteBranch(b) => format!("GitDeleteBranch|{}", h(b.as_bytes())),
        GitCreateTag(t) => format!("GitCreateTag|{}", h(t.as_bytes())),
        GitStashPush => "GitStashPush".to_string(),
        GitStashPop => "GitStashPop".to_string(),
        GitStashApply => "GitStashApply".to_string(),
        GitRepack => "GitRepack".to_string(),
        GitGc => "GitGc".to_string(),
        GitWorktreeAdd(p) => format!("GitWorktreeAdd|{}", h(p.as_bytes())),
        GitWorktreeRemove(p) => format!("GitWorktreeRemove|{}", h(p.as_bytes())),
        AgecryptInitRing(r) => format!("AgecryptInitRing|{}", h(r.as_bytes())),
        AgecryptLock(r) => format!("AgecryptLock|{}", h(r.as_bytes())),
        AgecryptUnlock(r) => format!("AgecryptUnlock|{}", h(r.as_bytes())),
        AgecryptRekey(r) => format!("AgecryptRekey|{}", h(r.as_bytes())),
        AgecryptAddRecipient(r, n, p) => format!(
            "AgecryptAddRecipient|{}|{}|{}",
            h(r.as_bytes()),
            h(n.as_bytes()),
            h(p.as_bytes())
        ),
        AgecryptRemoveRecipient(r, n) => {
            format!(
                "AgecryptRemoveRecipient|{}|{}",
                h(r.as_bytes()),
                h(n.as_bytes())
            )
        }
    }
}

/// Parses one log line back into an operation. Returns None for malformed lines.
fn op_from_line(line: &str) -> Option<Operation> {
    use Operation::*;
    let parts: Vec<&str> = line.split('|').collect();
    let hex_s = |i: usize| -> Option<String> { String::from_utf8(hex_decode(parts.get(i)?)?).ok() };
    let idx = |i: usize| -> Option<usize> { parts.get(i)?.parse().ok() };
    Some(match *parts.first()? {
        "EditSecret" => EditSecret(idx(1)?, hex_s(2)?),
        "CreateSecret" => CreateSecret(hex_s(1)?, hex_s(2)?),
        "DeleteSecret" => DeleteSecret(idx(1)?),
        "RenameSecret" => RenameSecret(idx(1)?, hex_s(2)?),
        "CreateBinary" => CreateBinary(hex_s(1)?, hex_decode(parts.get(2)?)?),
        "CreateUnicode" => CreateUnicode(hex_s(1)?, hex_s(2)?),
        "GitAdd" => GitAdd(idx(1)?),
        "GitAddAll" => GitAddAll,
        "GitAddPartial" => GitAddPartial(idx(1)?, hex_s(2)?),
        "GitUnstage" => GitUnstage(idx(1)?),
        "GitCommit" => GitCommit(hex_s(1)?),
        "GitCommitAmend" => GitCommitAmend(hex_s(1)?),
        "GitMerge" => GitMerge(hex_s(1)?),
        "GitRebase" => GitRebase(hex_s(1)?),
        "GitCherryPick" => GitCherryPick(hex_s(1)?),
        "GitRevert" => GitRevert(hex_s(1)?),
        "GitResetSoft" => GitResetSoft(hex_s(1)?),
        "GitResetMixed" => GitResetMixed(hex_s(1)?),
        "GitResetHard" => GitResetHard(hex_s(1)?),
        "GitRestore" => GitRestore(idx(1)?),
        "GitCheckout" => GitCheckout(hex_s(1)?),
        "GitSwitch" => GitSwitch(hex_s(1)?),
        "GitCreateBranch" => GitCreateBranch(hex_s(1)?),
        "GitDeleteBranch" => GitDeleteBranch(hex_s(1)?),
        "GitCreateTag" => GitCreateTag(hex_s(1)?),
        "GitStashPush" => GitStashPush,
        "GitStashPop" => GitStashPop,
        "GitStashApply" => GitStashApply,
        "GitRepack" => GitRepack,
        "GitGc" => GitGc,
        "GitWorktreeAdd" => GitWorktreeAdd(hex_s(1)?),
        "GitWorktreeRemove" => GitWorktreeRemove(hex_s(1)?),
        "AgecryptInitRing" => AgecryptInitRing(hex_s(1)?),
        "AgecryptLock" => AgecryptLock(hex_s(1)?),
        "AgecryptUnlock" => AgecryptUnlock(hex_s(1)?),
        "AgecryptRekey" => AgecryptRekey(hex_s(1)?),
        "AgecryptAddRecipient" => AgecryptAddRecipient(hex_s(1)?, hex_s(2)?, hex_s(3)?),
        "AgecryptRemoveRecipient" => AgecryptRemoveRecipient(hex_s(1)?, hex_s(2)?),
        _ => return None,
    })
}
/// Mutable harness state shared by generation, replay, and shrinking.
struct Harness {
    repo: PathBuf,
    shadow: ShadowModel,
    all_files: Vec<String>,
    branch_files: HashMap<String, Vec<String>>,
    commit_shas: Vec<String>,
    sec_id: String,
}

impl Harness {
    /// Builds the canonical initial repository state (identical for generation and replay).
    fn setup(repo: &Path) -> Harness {
        init_repo(repo);

        agecrypt_cmd(repo).arg("init").assert().success();
        let (sec_id, pub_key) = generate_test_identity();
        agecrypt_cmd(repo)
            .args(["add-recipient", "-i", &pub_key, "--name", "shadow_user"])
            .assert()
            .success();

        let mut shadow = ShadowModel::new();
        shadow.add_recipient("default", "shadow_user");

        fs::write(
            repo.join(".gitattributes"),
            "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
        )
        .unwrap();

        let initial_files = ["api.secret.env", "db.secret.env", "app.secret.env"];
        let all_files: Vec<String> = initial_files.iter().map(|s| s.to_string()).collect();

        for (i, f) in initial_files.iter().enumerate() {
            let content = format!("SECRET_KEY_{i}=initial_val_{i}\n");
            fs::write(repo.join(f), &content).unwrap();
            shadow.update_file(&PathBuf::from(f), &content);
        }

        run_git(
            repo,
            &[
                "add",
                ".gitattributes",
                ".git-agecrypt",
                "api.secret.env",
                "db.secret.env",
                "app.secret.env",
            ],
        );
        run_git(repo, &["commit", "-m", "Initial secret commit"]);
        if let Ok(sha_out) = git_out_res(repo, &["rev-parse", "HEAD"]) {
            let sha = String::from_utf8_lossy(&sha_out).trim().to_string();
            shadow.record_commit(&sha);
        }

        let mut branch_files: HashMap<String, Vec<String>> = HashMap::new();
        branch_files.insert("main".to_string(), all_files.clone());

        // Deterministic ordering guard: HashSet iteration order is process-random, so all
        // branch/recipient draws sort before indexing (see sorted_branches) to keep seeds
        // and replays reproducible. all_files itself is a Vec and already deterministic.

        Harness {
            repo: repo.to_path_buf(),
            shadow,
            all_files,
            branch_files,
            commit_shas: Vec::new(),
            sec_id,
        }
    }
}

/// Returns true if `rev` resolves to an existing object in the repo's object database.
fn git_obj_exists(repo: &Path, rev: &str) -> bool {
    git_out_res(repo, &["cat-file", "-e", rev]).is_ok()
}

/// Sorted list of known branches (deterministic draw order; HashSet order is random).
fn sorted_branches(h: &Harness) -> Vec<String> {
    let mut bs: Vec<String> = h.shadow.branches.iter().cloned().collect();
    bs.sort();
    bs
}
/// Executes one fully-specified operation against the live repository and the shadow model.
/// Returns (success, error). Operations whose preconditions do not hold in the current
/// state (e.g. referencing a file removed by log minimization) are skipped and reported
/// as (false, Some("skipped: ...")).
fn execute_op(h: &mut Harness, op: &Operation) -> (bool, Option<String>) {
    use Operation::*;
    let repo = h.repo.clone();
    let sync = |h: &mut Harness| h.shadow.sync_from_disk(&repo, &[".secret.env"]);
    match op {
        EditSecret(i, val) => {
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            let file_name = h.all_files[*i].clone();
            fs::write(repo.join(&file_name), val).unwrap();
            h.shadow.update_file(&PathBuf::from(&file_name), val);
            (true, None)
        }
        CreateSecret(name, content) | CreateUnicode(name, content) => {
            fs::write(repo.join(name), content).unwrap();
            h.shadow.update_file(&PathBuf::from(name), content);
            if !h.all_files.contains(name) {
                h.all_files.push(name.clone());
            }
            (true, None)
        }
        DeleteSecret(i) => {
            if h.all_files.len() <= 1 {
                return (false, Some("skipped: no files to delete".to_string()));
            }
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            let file_name = h.all_files.remove(*i);
            let _ = fs::remove_file(repo.join(&file_name));
            h.shadow.remove_file(&PathBuf::from(&file_name));
            (true, None)
        }
        RenameSecret(i, new_name) => {
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            if h.all_files.contains(new_name) {
                return (
                    false,
                    Some("skipped: rename target already tracked".to_string()),
                );
            }
            let old_name = h.all_files[*i].clone();
            let content = fs::read_to_string(repo.join(&old_name)).unwrap_or_default();
            let _ = fs::rename(repo.join(&old_name), repo.join(new_name));
            h.all_files[*i] = new_name.clone();
            h.shadow.remove_file(&PathBuf::from(&old_name));
            h.shadow.update_file(&PathBuf::from(new_name), &content);
            (true, None)
        }
        CreateBinary(name, data) => {
            // Binary fixtures are intentionally not tracked in the (String-based) shadow
            // model; they exercise the filter pipeline on disk only.
            fs::write(repo.join(name), data).unwrap();
            (true, None)
        }
        GitAdd(i) => {
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            let name = h.all_files[*i].clone();
            run_git(&repo, &["add", &name]);
            (true, None)
        }
        GitAddAll => {
            run_git(&repo, &["add", "."]);
            (true, None)
        }
        GitAddPartial(i, content) => {
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            let name = h.all_files[*i].clone();
            fs::write(repo.join(&name), content).unwrap();
            run_git(&repo, &["add", &name]);
            h.shadow.update_file(&PathBuf::from(&name), content);
            (true, None)
        }
        GitUnstage(i) => {
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            let name = h.all_files[*i].clone();
            let _ = git_out_res(&repo, &["reset", "HEAD", "--", &name]);
            (true, None)
        }
        GitCommit(msg) => {
            let res = git_out_res(&repo, &["commit", "-am", msg]);
            if let Ok(sha_out) = git_out_res(&repo, &["rev-parse", "HEAD"]) {
                let sha = String::from_utf8_lossy(&sha_out).trim().to_string();
                h.commit_shas.push(sha);
            }
            let commit_ok = res.is_ok();
            if commit_ok && let Ok(sha_out) = git_out_res(&repo, &["rev-parse", "HEAD"]) {
                let sha = String::from_utf8_lossy(&sha_out).trim().to_string();
                h.shadow.record_commit(&sha);
            }
            (commit_ok, res.err())
        }
        GitCommitAmend(msg) => {
            let res = git_out_res(&repo, &["commit", "--amend", "-m", msg]);
            (res.is_ok(), res.err())
        }
        GitMerge(branch) => {
            if !h.shadow.branches.contains(branch) {
                return (false, Some(format!("skipped: branch {branch} not known")));
            }
            let res = git_out_res(&repo, &["merge", branch, "-m", "Merge"]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitRebase(branch) => {
            if !h.shadow.branches.contains(branch) {
                return (false, Some(format!("skipped: branch {branch} not known")));
            }
            let res = git_out_res(&repo, &["rebase", branch]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitCherryPick(sha) => {
            if !git_obj_exists(&repo, sha) {
                return (false, Some(format!("skipped: commit {sha} not found")));
            }
            let res = git_out_res(&repo, &["cherry-pick", sha]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitRevert(sha) => {
            if !git_obj_exists(&repo, sha) {
                return (false, Some(format!("skipped: commit {sha} not found")));
            }
            let res = git_out_res(&repo, &["revert", "--no-edit", sha]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitResetSoft(sha) => {
            if !git_obj_exists(&repo, sha) {
                return (false, Some(format!("skipped: commit {sha} not found")));
            }
            let res = git_out_res(&repo, &["reset", "--soft", sha]);
            if res.is_ok() {
                h.shadow.reset_to_commit(sha);
            }
            (res.is_ok(), res.err())
        }
        GitResetMixed(sha) => {
            if !git_obj_exists(&repo, sha) {
                return (false, Some(format!("skipped: commit {sha} not found")));
            }
            let res = git_out_res(&repo, &["reset", "--mixed", sha]);
            if res.is_ok() {
                h.shadow.reset_to_commit(sha);
            }
            (res.is_ok(), res.err())
        }
        GitResetHard(sha) => {
            if !git_obj_exists(&repo, sha) {
                return (false, Some(format!("skipped: commit {sha} not found")));
            }
            let res = git_out_res(&repo, &["reset", "--hard", sha]);
            sync(h);
            if res.is_ok() {
                h.shadow.reset_to_commit(sha);
            }
            (res.is_ok(), res.err())
        }
        GitRestore(i) => {
            if *i >= h.all_files.len() {
                return (false, Some(format!("skipped: file index {i} out of range")));
            }
            let name = h.all_files[*i].clone();
            let res = git_out_res(&repo, &["restore", &name]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitCheckout(branch) => {
            if !h.shadow.branches.contains(branch) {
                return (false, Some(format!("skipped: branch {branch} not known")));
            }
            let res = git_out_res(&repo, &["checkout", branch]);
            sync(h);
            if res.is_ok() {
                h.shadow.switch_branch(branch);
            }
            (res.is_ok(), res.err())
        }
        GitSwitch(branch) => {
            if !h.shadow.branches.contains(branch) {
                return (false, Some(format!("skipped: branch {branch} not known")));
            }
            let res = git_out_res(&repo, &["switch", branch]);
            sync(h);
            if res.is_ok() {
                h.shadow.switch_branch(branch);
            }
            (res.is_ok(), res.err())
        }
        GitCreateBranch(branch) => {
            let res = git_out_res(&repo, &["branch", branch]);
            if res.is_ok() {
                h.shadow.branches.insert(branch.clone());
                h.branch_files.insert(branch.clone(), h.all_files.clone());
            }
            (res.is_ok(), res.err())
        }
        GitDeleteBranch(branch) => {
            if branch == "main" || !h.shadow.branches.contains(branch) {
                return (
                    false,
                    Some(format!("skipped: branch {branch} not deletable")),
                );
            }
            let res = git_out_res(&repo, &["branch", "-D", branch]);
            if res.is_ok() {
                h.shadow.branches.remove(branch);
                h.branch_files.remove(branch);
            }
            (res.is_ok(), res.err())
        }
        GitCreateTag(tag) => {
            let res = git_out_res(&repo, &["tag", tag]);
            (res.is_ok(), res.err())
        }
        GitStashPush => {
            let res = git_out_res(&repo, &["stash", "push", "-m", "stash"]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitStashPop => {
            let res = git_out_res(&repo, &["stash", "pop"]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitStashApply => {
            let res = git_out_res(&repo, &["stash", "apply"]);
            sync(h);
            (res.is_ok(), res.err())
        }
        GitRepack => {
            let res = git_out_res(&repo, &["repack", "-a", "-d"]);
            (res.is_ok(), res.err())
        }
        GitGc => {
            let res = git_out_res(&repo, &["gc"]);
            (res.is_ok(), res.err())
        }
        GitWorktreeAdd(_) | GitWorktreeRemove(_) => {
            // Worktree operations are disabled in the generative harness (embedded repos
            // are slow and problematic); they only appear in logs for completeness.
            (false, Some("skipped: worktree ops disabled".to_string()))
        }
        AgecryptInitRing(ring) => {
            if ring == "default" {
                return (
                    false,
                    Some("skipped: default ring always exists".to_string()),
                );
            }
            let res = agecrypt_cmd(&repo).args(["init", "--ring", ring]).output();
            let success = res.map(|r| r.status.success()).unwrap_or(false);
            if success {
                h.shadow.add_ring(ring);
            }
            (success, None)
        }
        AgecryptLock(ring) => {
            let res = agecrypt_cmd(&repo)
                .args(["lock", "-f", "--ring", ring])
                .output();
            let success = res.map(|r| r.status.success()).unwrap_or(false);
            if success {
                h.shadow.set_locked(ring, true);
            }
            sync(h);
            (success, None)
        }
        AgecryptUnlock(ring) => {
            let res = agecrypt_assert_cmd(&repo)
                .args(["unlock", "-", "--ring", ring])
                .write_stdin(h.sec_id.as_bytes())
                .output();
            let success = res.map(|r| r.status.success()).unwrap_or(false);
            if success {
                h.shadow.set_locked(ring, false);
            }
            sync(h);
            (success, None)
        }
        AgecryptRekey(ring) => {
            let res = agecrypt_cmd(&repo)
                .args(["rekey", "-f", "--ring", ring])
                .output();
            let success = res.map(|r| r.status.success()).unwrap_or(false);
            if success {
                h.shadow.rekey_ring(ring);
            }
            sync(h);
            (success, None)
        }
        AgecryptAddRecipient(ring, name, new_pub) => {
            let res = agecrypt_cmd(&repo)
                .args([
                    "add-recipient",
                    "-i",
                    new_pub,
                    "--name",
                    name,
                    "--ring",
                    ring,
                ])
                .output();
            let success = res.map(|r| r.status.success()).unwrap_or(false);
            if success {
                h.shadow.add_recipient(ring, name);
            }
            (success, None)
        }
        AgecryptRemoveRecipient(ring, name) => {
            if !h.shadow.rings.contains_key(ring) {
                return (false, Some(format!("skipped: ring {ring} not found")));
            }
            let res = agecrypt_cmd(&repo)
                .args(["remove-recipient", name, "--ring", ring])
                .output();
            let success = res.map(|r| r.status.success()).unwrap_or(false);
            if success {
                h.shadow.revoke_recipient(ring, name);
            }
            (success, None)
        }
    }
}
/// Draws the next operation from the seeded RNG. The draw sequence per step is identical
/// to the historical harness so seeds keep their meaning; branch and recipient selection
/// sorts first because HashSet iteration order is process-random.
fn draw_op(step: usize, action_type: u32, rng: &mut ChaCha8Rng, h: &Harness) -> Operation {
    use Operation::*;
    let rings = ["default", "prod", "dev"];
    match action_type {
        0 => {
            let file_idx = rng.gen_range(0..h.all_files.len());
            let new_val = format!(
                "SECRET_KEY_{file_idx}=val_step_{step}_{}\n",
                rng.gen_range(1000..9999)
            );
            EditSecret(file_idx, new_val)
        }
        1 => {
            let new_name = format!("secret_{step}.secret.env");
            let content = format!("NEW_SECRET_{step}=val_{}\n", rng.gen_range(1000..9999));
            CreateSecret(new_name, content)
        }
        2 => {
            if h.all_files.len() > 1 {
                DeleteSecret(rng.gen_range(0..h.all_files.len()))
            } else {
                DeleteSecret(0)
            }
        }
        3 => {
            if !h.all_files.is_empty() {
                let file_idx = rng.gen_range(0..h.all_files.len());
                RenameSecret(file_idx, format!("renamed_{step}.secret.env"))
            } else {
                RenameSecret(0, "none".to_string())
            }
        }
        4 => {
            let bin_name = format!("binary_{step}.secret.env");
            let mut bin_data = vec![0u8; 256];
            rng.fill(&mut bin_data[..]);
            CreateBinary(bin_name, bin_data)
        }
        5 => {
            let unicode_name = format!("secret_\u{1F512}_{step}.secret.env");
            let content = format!("UNICODE_SECRET_{step}=val\n");
            CreateUnicode(unicode_name, content)
        }
        6 => {
            if !h.all_files.is_empty() {
                GitAdd(rng.gen_range(0..h.all_files.len()))
            } else {
                GitAdd(0)
            }
        }
        7 => GitAddAll,
        8 => {
            if !h.all_files.is_empty() {
                let file_idx = rng.gen_range(0..h.all_files.len());
                GitAddPartial(file_idx, format!("PARTIAL_{step}=staged\n"))
            } else {
                GitAddPartial(0, String::new())
            }
        }
        9 => {
            if !h.all_files.is_empty() {
                GitUnstage(rng.gen_range(0..h.all_files.len()))
            } else {
                GitUnstage(0)
            }
        }
        10 => GitCommit(format!("Commit at step {step}")),
        11 => GitCommitAmend(format!("Amended commit at step {step}")),
        12 => {
            if h.shadow.branches.len() > 1 {
                let bs = sorted_branches(h);
                GitMerge(bs[rng.gen_range(0..bs.len())].clone())
            } else {
                GitMerge("none".to_string())
            }
        }
        13 => {
            if h.shadow.branches.len() > 1 {
                let bs = sorted_branches(h);
                GitRebase(bs[rng.gen_range(0..bs.len())].clone())
            } else {
                GitRebase("none".to_string())
            }
        }
        14 => {
            if !h.commit_shas.is_empty() {
                GitCherryPick(h.commit_shas[rng.gen_range(0..h.commit_shas.len())].clone())
            } else {
                GitCherryPick("none".to_string())
            }
        }
        15 => {
            if !h.commit_shas.is_empty() {
                GitRevert(h.commit_shas[rng.gen_range(0..h.commit_shas.len())].clone())
            } else {
                GitRevert("none".to_string())
            }
        }
        16 => {
            if !h.commit_shas.is_empty() {
                GitResetSoft(h.commit_shas[rng.gen_range(0..h.commit_shas.len())].clone())
            } else {
                GitResetSoft("none".to_string())
            }
        }
        17 => {
            if !h.commit_shas.is_empty() {
                GitResetMixed(h.commit_shas[rng.gen_range(0..h.commit_shas.len())].clone())
            } else {
                GitResetMixed("none".to_string())
            }
        }
        18 => {
            if !h.commit_shas.is_empty() {
                GitResetHard(h.commit_shas[rng.gen_range(0..h.commit_shas.len())].clone())
            } else {
                GitResetHard("none".to_string())
            }
        }
        19 => {
            if !h.all_files.is_empty() {
                GitRestore(rng.gen_range(0..h.all_files.len()))
            } else {
                GitRestore(0)
            }
        }
        20 => {
            if h.shadow.branches.len() > 1 {
                let bs = sorted_branches(h);
                GitCheckout(bs[rng.gen_range(0..bs.len())].clone())
            } else {
                GitCheckout("main".to_string())
            }
        }
        21 => {
            if h.shadow.branches.len() > 1 {
                let bs = sorted_branches(h);
                GitSwitch(bs[rng.gen_range(0..bs.len())].clone())
            } else {
                GitSwitch("main".to_string())
            }
        }
        22 => GitCreateBranch(format!("branch_{step}")),
        23 => {
            let mut bs: Vec<String> = h
                .shadow
                .branches
                .iter()
                .filter(|b| *b != "main")
                .cloned()
                .collect();
            bs.sort();
            if h.shadow.branches.len() > 1 && !bs.is_empty() {
                GitDeleteBranch(bs[rng.gen_range(0..bs.len())].clone())
            } else {
                GitDeleteBranch("none".to_string())
            }
        }
        24 => GitCreateTag(format!("tag_{step}")),
        25 => GitStashPush,
        26 => GitStashPop,
        27 => GitStashApply,
        28 => GitRepack,
        29 => GitGc,
        // 30/31 were worktree operations; they fall back to plain edits by design.
        30 | 31 => {
            let file_idx = rng.gen_range(0..h.all_files.len());
            EditSecret(file_idx, format!("SECRET_KEY_{file_idx}=val_step_{step}\n"))
        }
        32 => {
            let ring_idx = rng.gen_range(1..rings.len());
            AgecryptInitRing(rings[ring_idx].to_string())
        }
        33 => {
            let ring_idx = rng.gen_range(0..rings.len());
            AgecryptLock(rings[ring_idx].to_string())
        }
        34 => {
            let ring_idx = rng.gen_range(0..rings.len());
            AgecryptUnlock(rings[ring_idx].to_string())
        }
        35 => {
            let ring_idx = rng.gen_range(0..rings.len());
            AgecryptRekey(rings[ring_idx].to_string())
        }
        36 => {
            let ring_idx = rng.gen_range(0..rings.len());
            // NOTE: generate_test_identity() draws from the OS RNG, not the seeded stream,
            // so pure-seed reruns differ in the generated public key. The ops log records
            // the concrete key, making log replay (and shrinking) exact regardless.
            let (_, new_pub) = generate_test_identity();
            AgecryptAddRecipient(rings[ring_idx].to_string(), format!("user_{step}"), new_pub)
        }
        37 => {
            let ring_idx = rng.gen_range(0..rings.len());
            let ring_name = rings[ring_idx].to_string();
            // Deterministic pick: lexicographically smallest authorized recipient.
            let target = h
                .shadow
                .rings
                .get(&ring_name)
                .and_then(|r| r.authorized_recipients.iter().min().cloned())
                .unwrap_or_else(|| "none".to_string());
            AgecryptRemoveRecipient(ring_name, target)
        }
        _ => {
            let file_idx = rng.gen_range(0..h.all_files.len());
            EditSecret(file_idx, format!("SECRET_KEY_{file_idx}=val_step_{step}\n"))
        }
    }
}
/// Per-step invariant bundle shared by generation and full-fidelity replay.
fn check_invariants(repo: &Path, h: &Harness, step: usize, canary: &[u8]) {
    assert_inv_b_durability_consistent(repo);
    assert_inv_g_zero_canary_leaks(repo, canary);
    if step % 10 == 0 {
        h.shadow.verify_state(repo);
        h.shadow.verify_index_state(repo);
        h.shadow.verify_object_db(repo);
    }
}

fn final_verification(repo: &Path, h: &Harness) {
    h.shadow.verify_state(repo);
    h.shadow.verify_index_state(repo);
    h.shadow.verify_object_db(repo);
}

fn default_ops_log_path(seed: u64) -> PathBuf {
    std::env::temp_dir().join(format!(
        "git-agecrypt-ops-{}-{seed:016x}.log",
        std::process::id()
    ))
}

#[test]
fn test_deep_generative_shadow_model_state_machine() {
    // M9: hard-fail on an unparsable seed instead of silently collapsing distinct
    // CI matrix legs onto the default seed.
    let seed: u64 = match std::env::var("GIT_AGECRYPT_SEED") {
        Ok(s) => s
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("GIT_AGECRYPT_SEED must be a decimal u64 (got '{s}')")),
        Err(_) => 0xDEAD_BEEF_CAFE_1234,
    };

    let op_count: usize = std::env::var("GIT_AGECRYPT_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let log_path = std::env::var("GIT_AGECRYPT_OPS_LOG")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_ops_log_path(seed));
    let mut log = fs::File::create(&log_path).expect("Failed to create ops log");
    writeln!(
        log,
        "# git-agecrypt generative ops log seed=0x{seed:016X} ops={op_count}"
    )
    .unwrap();
    log.flush().unwrap();

    println!(
        "Starting generative state machine with seed: 0x{:016X}, ops: {}",
        seed, op_count
    );
    println!("Ops log: {}", log_path.display());
    println!(
        "To replay:  GIT_AGECRYPT_REPLAY=\"{}\" cargo test --test test_generative_shadow_state_machine -- --exact test_replay_ops_log --nocapture",
        log_path.display()
    );
    println!(
        "To shrink:  GIT_AGECRYPT_SHRINK=\"{}\" cargo test --test test_generative_shadow_state_machine -- --exact test_ddmin_shrink_real_failure --nocapture",
        log_path.display()
    );

    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    let mut h = Harness::setup(repo);

    let canary_token = b"SHADOW_STATE_CANARY_CHECK";
    let mut operation_history: Vec<OperationStep> = Vec::new();

    // State Machine Transition Loop
    for step in 0..op_count {
        let action_type = rng.gen_range(0..40);
        let op = draw_op(step, action_type, &mut rng, &h);

        // Log BEFORE execution so a panicking/crashing op is still captured for replay.
        writeln!(log, "{}", op_to_line(&op)).unwrap();
        log.flush().unwrap();

        let (success, error) = execute_op(&mut h, &op);

        operation_history.push(OperationStep {
            step,
            operation: op.clone(),
            success,
            error,
        });

        check_invariants(repo, &h, step, canary_token);
    }

    final_verification(repo, &h);

    println!(
        "Completed {} operations with seed 0x{:016X} (ops log: {})",
        op_count,
        seed,
        log_path.display()
    );
}
/// Executes a recorded operation log against a fresh canonical repository.
/// `fail_if_seq` (short op names) triggers a deliberate panic when the executed
/// (non-skipped) operations contain it as an ordered subsequence — used to validate
/// the shrinking machinery deterministically.
/// `fast` skips invariant checks (only valid for synthetic-trigger shrink runs).
fn run_replay_ops(ops: &[Operation], fail_if_seq: Option<Vec<String>>, fast: bool) {
    let temp = tempdir().expect("Failed to create tempdir");
    let repo = temp.path();
    let mut h = Harness::setup(repo);
    let canary_token = b"SHADOW_STATE_CANARY_CHECK";

    let mut executed: Vec<String> = Vec::new();
    for (step, op) in ops.iter().enumerate() {
        let (_success, error) = execute_op(&mut h, op);
        let skipped = error
            .as_deref()
            .map(|e| e.starts_with("skipped:"))
            .unwrap_or(false);
        if !skipped {
            executed.push(op_short_name(op).to_string());
        }
        if !fast {
            check_invariants(repo, &h, step, canary_token);
        }
    }
    if !fast {
        final_verification(repo, &h);
    }

    if let Some(seq) = fail_if_seq
        && !seq.is_empty()
        && contains_subsequence(&executed, &seq)
    {
        panic!(
            "GIT_AGECRYPT_FAIL_IF_EXEC_SEQ synthetic failure triggered: executed sequence contains {:?} as ordered subsequence",
            seq
        );
    }
}

/// Ordered (not necessarily contiguous) subsequence check.
fn contains_subsequence(haystack: &[String], needle: &[String]) -> bool {
    let mut it = haystack.iter();
    needle.iter().all(|n| it.any(|h| h == n))
}

/// Loads an ops log file into concrete operations (skips comments/blank lines).
fn load_ops_log(path: &str) -> Vec<Operation> {
    let content = fs::read_to_string(path).expect("Failed to read ops log");
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, l)| {
            op_from_line(l)
                .unwrap_or_else(|| panic!("invalid op at {} line {}: {}", path, i + 1, l))
        })
        .collect()
}

#[test]
fn test_replay_ops_log() {
    let path = match std::env::var("GIT_AGECRYPT_REPLAY") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            println!("GIT_AGECRYPT_REPLAY not set; replay test inert");
            return;
        }
    };
    let ops = load_ops_log(&path);
    let fail_seq = std::env::var("GIT_AGECRYPT_FAIL_IF_EXEC_SEQ")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        });
    let fast = std::env::var("GIT_AGECRYPT_FAST_REPLAY").is_ok();
    println!("Replaying {} operations from {}", ops.len(), path);
    run_replay_ops(&ops, fail_seq, fast);
    println!("Replay of {} operations completed", ops.len());
}
/// Re-runs `test_replay_ops_log` in a fresh subprocess against the given ops lines.
/// Returns true when the replay FAILS (exit non-zero or timeout) — i.e. "interesting"
/// in delta-debugging terms.
fn replay_subprocess_fails(
    ops_lines: &[String],
    extra_env: &[(&str, &str)],
    timeout: Duration,
) -> bool {
    let dir = tempdir().expect("Failed to create shrink workspace");
    let file = dir.path().join("ops.log");
    let mut body = ops_lines.join("\n");
    body.push('\n');
    fs::write(&file, body).expect("Failed to write candidate ops log");

    let exe = std::env::current_exe().expect("Failed to locate current test binary");
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        "test_replay_ops_log",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("GIT_AGECRYPT_REPLAY", &file)
    // The nested run must never recurse into generation or shrinking paths.
    .env_remove("GIT_AGECRYPT_SEED")
    .env_remove("GIT_AGECRYPT_OPS")
    .env_remove("GIT_AGECRYPT_OPS_LOG")
    .env_remove("GIT_AGECRYPT_SHRINK")
    .env_remove("GIT_AGECRYPT_CRASH_POINT")
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("Failed to spawn replay subprocess");
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("Failed to poll replay subprocess") {
            Some(status) => return !status.success(),
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // A hang is a failure mode too: treat as interesting.
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Classic ddmin (Zeller & Hildebrandt): minimizes `ops` subject to `interesting`.
/// Returns a 1-minimal failing subsequence (removing any single op makes it pass).
fn ddmin(mut ops: Vec<String>, mut interesting: impl FnMut(&[String]) -> bool) -> Vec<String> {
    let mut n = 2;
    while ops.len() >= 2 {
        let chunk = ops.len().div_ceil(n);
        let mut reduced = false;

        // Phase 1: try removing each chunk (complement reduction).
        let mut i = 0;
        while i < ops.len() {
            let end = (i + chunk).min(ops.len());
            let mut candidate = ops[..i].to_vec();
            candidate.extend_from_slice(&ops[end..]);
            if !candidate.is_empty() && interesting(&candidate) {
                ops = candidate;
                n = (n - 1).max(2);
                reduced = true;
                break;
            }
            i = end;
        }
        if reduced {
            continue;
        }

        // Phase 2: try keeping each chunk alone.
        let mut i = 0;
        while i < ops.len() {
            let end = (i + chunk).min(ops.len());
            let candidate = ops[i..end].to_vec();
            if !candidate.is_empty() && interesting(&candidate) {
                ops = candidate;
                n = 2;
                reduced = true;
                break;
            }
            i = end;
        }
        if reduced {
            continue;
        }

        if n >= ops.len() {
            break;
        }
        n = (n * 2).min(ops.len());
    }
    ops
}
/// End-to-end validation of the replay + ddmin machinery: a synthetic ops log that only
/// "fails" (via GIT_AGECRYPT_FAIL_IF_EXEC_SEQ) when GitStashPush is followed (in executed
/// order) by GitStashPop must shrink to exactly that pair, with all noise ops removed.
#[test]
fn test_ddmin_shrinker_selftest() {
    // Never run inside a replay subprocess.
    if std::env::var("GIT_AGECRYPT_REPLAY").is_ok() {
        return;
    }

    #[allow(clippy::useless_vec)] // fixed shrink-oracle scenario; array-vs-vec churn not worth it
    let ops = vec![
        Operation::EditSecret(0, "SHRINK_NOISE_A=1\n".to_string()),
        Operation::GitStashPush,
        Operation::EditSecret(1, "SHRINK_NOISE_B=2\n".to_string()),
        Operation::GitStashPop,
        Operation::EditSecret(2, "SHRINK_NOISE_C=3\n".to_string()),
    ];
    let lines: Vec<String> = ops.iter().map(op_to_line).collect();
    let env: &[(&str, &str)] = &[
        ("GIT_AGECRYPT_FAIL_IF_EXEC_SEQ", "GitStashPush,GitStashPop"),
        ("GIT_AGECRYPT_FAST_REPLAY", "1"),
    ];
    let timeout = Duration::from_secs(120);

    assert!(
        replay_subprocess_fails(&lines, env, timeout),
        "sanity: the full synthetic sequence must trigger the synthetic failure"
    );
    assert!(
        !replay_subprocess_fails(&lines[..3], env, timeout),
        "sanity: a prefix without GitStashPop must not trigger"
    );

    let shrunk = ddmin(lines.clone(), |cand| {
        replay_subprocess_fails(cand, env, timeout)
    });

    println!(
        "ddmin self-test shrunk {} ops to {}:",
        lines.len(),
        shrunk.len()
    );
    for l in &shrunk {
        println!("  {l}");
    }

    assert!(
        replay_subprocess_fails(&shrunk, env, timeout),
        "shrunk sequence must still reproduce the failure"
    );
    assert!(
        shrunk.len() == 2,
        "ddmin must isolate exactly [GitStashPush, GitStashPop], got {} ops: {:?}",
        shrunk.len(),
        shrunk
    );
    assert!(shrunk[0].starts_with("GitStashPush"));
    assert!(shrunk[1].starts_with("GitStashPop"));
}

/// Shrinks a real failing ops log to a 1-minimal reproducer.
/// Usage: GIT_AGECRYPT_SHRINK=<ops.log> cargo test --test test_generative_shadow_state_machine \
///          -- --exact test_ddmin_shrink_real_failure --nocapture
/// Writes the minimal sequence to <ops.log>.min and prints it.
#[test]
fn test_ddmin_shrink_real_failure() {
    let path = match std::env::var("GIT_AGECRYPT_SHRINK") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            println!("GIT_AGECRYPT_SHRINK not set; real-failure shrinker inert");
            return;
        }
    };
    let lines: Vec<String> = fs::read_to_string(&path)
        .expect("Failed to read ops log to shrink")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    println!("Loaded {} operations from {}", lines.len(), path);

    let timeout = Duration::from_secs(600);
    assert!(
        replay_subprocess_fails(&lines, &[], timeout),
        "The provided ops log does not reproduce a failure; nothing to shrink"
    );

    let shrunk = ddmin(lines.clone(), |cand| {
        replay_subprocess_fails(cand, &[], timeout)
    });

    let out_path = format!("{path}.min");
    let mut body = shrunk.join("\n");
    body.push('\n');
    fs::write(&out_path, &body).expect("Failed to write minimized ops log");

    println!(
        "Minimal failing sequence: {} ops (was {}), written to {}",
        shrunk.len(),
        lines.len(),
        out_path
    );
    for l in &shrunk {
        println!("  {l}");
    }
    assert!(
        replay_subprocess_fails(&shrunk, &[], timeout),
        "minimized sequence must still reproduce the failure"
    );
}
