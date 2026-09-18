use anyhow::{Context, Result, anyhow};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const AGE_HEADER_MAGIC: &[u8] = b"age-encryption.org/v1\n";

/// Truncates HMAC-SHA256 digest to 16 bytes (32 hex characters = 128 bits).
/// Provides 2^128 collision resistance (astronomically safe for local cache)
/// while reclaiming 32 path characters to prevent Windows MAX_PATH overflows.
pub fn format_cache_hash(mac_bytes: &[u8]) -> String {
    mac_bytes[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Computes a keyed HMAC-SHA256 cache filename using the master key.
/// This prevents dictionary attacks or rainbow tables on low-entropy secrets in the cache.
#[cfg(test)]
pub fn compute_cache_filename(key: &[u8], plaintext: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any size");
    mac.update(plaintext);
    format_cache_hash(&mac.finalize().into_bytes())
}

/// Generates a new random X25519 identity for the repository.
pub fn generate_master_identity() -> (age::x25519::Identity, age::x25519::Recipient) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

/// Checks if a byte slice begins with the standard age magic header.
pub fn is_age_ciphertext(prefix: &[u8]) -> bool {
    prefix.starts_with(AGE_HEADER_MAGIC)
}

/// Parses an age or SSH recipient string into an age Recipient.
/// Supports:
/// - Age public keys: `age1...`
/// - OpenSSH public keys: `ssh-ed25519 AAAA...` or `ssh-rsa AAAA...`
pub fn parse_recipient(s: &str) -> Result<Box<dyn age::Recipient + Send + 'static>> {
    let s = s.trim();
    if s.starts_with("sk-") {
        return Err(anyhow!(
            "FIDO2 / hardware security keys ('sk-ssh-ed25519' or 'sk-ecdsa') are not supported by the age encryption format. Please use a standard ed25519 key ('ssh-ed25519'), native age key ('age1...'), or age plugin ('age1yubikey1...')."
        ));
    }

    let mut guard = age::cli_common::StdinGuard::new(false);
    let mut recipients =
        age::cli_common::read_recipients(vec![s.to_string()], vec![], vec![], None, &mut guard)
            .map_err(|e| anyhow!("Failed to parse recipient '{s}': {e}"))?;

    if let Some(r) = recipients.pop() {
        Ok(r)
    } else {
        Err(anyhow!("No valid recipient parsed from '{s}'"))
    }
}

/// Wraps (encrypts) the master key string for a given recipient and returns ASCII armor.
pub fn wrap_master_key(master_key_str: &str, recipient: &dyn age::Recipient) -> Result<String> {
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))
        .map_err(|e| anyhow!("Failed to initialize encryptor for recipient: {e}"))?;
    let mut armored_output = Vec::new();
    {
        let armor_writer = age::armor::ArmoredWriter::wrap_output(
            &mut armored_output,
            age::armor::Format::AsciiArmor,
        )?;
        let mut writer = encryptor.wrap_output(armor_writer)?;
        writer.write_all(master_key_str.as_bytes())?;
        writer.finish()?.finish()?;
    }
    String::from_utf8(armored_output).context("Armored output is not valid UTF-8")
}

/// Wraps the master key and prefixes with a comment header containing the recipient's public key.
/// This enables automatic key rotation (rekey) when collaborators are offboarded.
pub fn wrap_master_key_with_metadata(
    master_key_str: &str,
    recipient: &dyn age::Recipient,
    public_key_str: &str,
) -> Result<String> {
    let armored = wrap_master_key(master_key_str, recipient)?;
    Ok(format!(
        "# public-key: {}\n{}",
        public_key_str.trim(),
        armored
    ))
}

/// Extracts the public key string from the comment preamble of a wrapped key file.
pub fn extract_recipient_public_key(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("# public-key:") {
            let key = rest.trim();
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
        if let Some(rest) = trimmed.strip_prefix("# recipient:") {
            let key = rest.trim();
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
    }
    None
}

/// Loads identities from a byte buffer (supports OpenSSH private keys and age secret keys).
pub fn load_identities_from_buffer(buf: &[u8]) -> Result<Vec<Box<dyn age::Identity>>> {
    load_identities_from_buffer_internal(buf, false)
}

/// Loads identities from a byte buffer without interactive prompts.
pub fn load_identities_from_buffer_non_interactive(
    buf: &[u8],
) -> Result<Vec<Box<dyn age::Identity>>> {
    load_identities_from_buffer_internal(buf, true)
}

fn load_identities_from_buffer_internal(
    buf: &[u8],
    non_interactive: bool,
) -> Result<Vec<Box<dyn age::Identity>>> {
    // 1. Try parsing as an SSH private key (e.g. OpenSSH Ed25519 or RSA)
    if let Ok(ssh_id) = age::ssh::Identity::from_buffer(Cursor::new(buf), None) {
        match ssh_id {
            age::ssh::Identity::Unsupported(k) => {
                return Err(anyhow!("Unsupported SSH key format: {k:?}"));
            }
            valid_ssh_id => {
                let boxed: Box<dyn age::Identity> = if non_interactive {
                    Box::new(valid_ssh_id.with_callbacks(NonInteractiveCallbacks))
                } else {
                    Box::new(valid_ssh_id.with_callbacks(AgecryptCallbacks))
                };
                return Ok(vec![boxed]);
            }
        }
    }

    // 2. Try parsing as standard age IdentityFile
    if let Ok(id_file) = age::IdentityFile::from_buffer(buf)
        && let Ok(identities) = id_file.into_identities()
        && !identities.is_empty()
    {
        let boxed: Vec<Box<dyn age::Identity>> = identities
            .into_iter()
            .map(|id| -> Box<dyn age::Identity> { id })
            .collect();
        return Ok(boxed);
    }

    Err(anyhow!(
        "Could not parse identity: expected either an OpenSSH private key or an age secret key"
    ))
}

/// Loads identities from a file on disk (supports age identity files and OpenSSH private keys).
pub fn load_identities_from_file(path: &Path) -> Result<Vec<Box<dyn age::Identity>>> {
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read identity file: {}", path.display()))?;
    load_identities_from_buffer(&data)
        .with_context(|| format!("Failed to parse identity file: {}", path.display()))
}

/// Loads identities from a file on disk without interactive prompts (for background/smudge operations).
pub fn load_identities_from_file_non_interactive(
    path: &Path,
) -> Result<Vec<Box<dyn age::Identity>>> {
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read identity file: {}", path.display()))?;
    load_identities_from_buffer_non_interactive(&data)
        .with_context(|| format!("Failed to parse identity file: {}", path.display()))
}

/// Unwraps (decrypts) an armored master key string using one of the provided identities.
pub fn unwrap_master_key(
    armored_ciphertext: &str,
    identities: &[Box<dyn age::Identity>],
) -> Result<String> {
    let armor_start = armored_ciphertext
        .find("-----BEGIN AGE ENCRYPTED FILE-----")
        .unwrap_or(0);
    let armor_slice = &armored_ciphertext[armor_start..];

    let armor_reader = age::armor::ArmoredReader::new(Cursor::new(armor_slice.as_bytes()));
    let decryptor = age::Decryptor::new(armor_reader)
        .map_err(|e| anyhow!("Failed to initialize decryptor: {e}"))?;

    if decryptor.is_scrypt() {
        return Err(anyhow!("Wrapped key unexpectedly requires a passphrase"));
    }

    let id_refs: Vec<&dyn age::Identity> = identities.iter().map(|id| id.as_ref()).collect();
    let mut reader = decryptor
        .decrypt(id_refs.into_iter())
        .map_err(|e| anyhow!("Decryption failed with provided identities: {e}"))?;

    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext)?;
    Ok(plaintext)
}

/// Returns standard default paths where SSH private keys and age identities typically reside.
pub fn get_default_identity_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(p) = std::env::var("GIT_AGECRYPT_IDENTITY").or_else(|_| std::env::var("AGE_IDENTITY"))
    {
        paths.push(PathBuf::from(p));
    }
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".ssh").join("id_ed25519"));
        paths.push(home.join(".ssh").join("id_rsa"));
        paths.push(home.join(".ssh").join("id_ecdsa"));
    }
    if let Some(config) = dirs::config_dir() {
        paths.push(config.join("age").join("keys.txt"));
    }
    paths
}

type PeekStream<R> = io::Chain<Cursor<Vec<u8>>, R>;

/// Helper to peek up to N bytes from an input reader without consuming them from the resulting stream.
fn peek_prefix<R: Read>(mut input: R, len: usize) -> io::Result<(Vec<u8>, PeekStream<R>)> {
    let mut buf = vec![0u8; len];
    let mut bytes_read = 0;
    while bytes_read < len {
        let n = input.read(&mut buf[bytes_read..])?;
        if n == 0 {
            break;
        }
        bytes_read += n;
    }
    buf.truncate(bytes_read);
    let prefix = buf.clone();
    let chained = Cursor::new(buf).chain(input);
    Ok((prefix, chained))
}

/// Git `clean` filter:
/// Reads stream `input` and writes to `output`.
/// If `input` is ALREADY an age ciphertext, passes through without re-encrypting.
/// If `input` is plaintext:
///   - Checks `cache_dir` for a matching SHA-256 ciphertext cache entry.
///   - If cached, outputs the exact cached ciphertext (eliminating phantom git diffs).
///   - If not cached, encrypts with `recipient`, outputs to `output`, and caches it.
#[derive(Clone)]
struct AgecryptCallbacks;

impl age::Callbacks for AgecryptCallbacks {
    fn display_message(&self, msg: &str) {
        eprintln!("{msg}");
    }

    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretBox<str>> {
        if let Ok(pass) =
            std::env::var("GIT_AGECRYPT_PASSPHRASE").or_else(|_| std::env::var("AGE_PASSPHRASE"))
        {
            return Some(age::secrecy::SecretBox::new(pass.into_boxed_str()));
        }

        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            eprintln!(
                "git-agecrypt [ERROR]: SSH key requires a passphrase ({description}), but running in a non-interactive environment (no TTY).\n\
                 Set the passphrase in GIT_AGECRYPT_PASSPHRASE or AGE_PASSPHRASE environment variable."
            );
            return None;
        }

        let ui = age::cli_common::UiCallbacks;
        ui.request_passphrase(description)
    }
}

/// Strictly non-interactive callbacks for background/smudge filters.
/// Never prompts, never reads from stdin or TTY; only checks environment variables.
#[derive(Clone)]
pub struct NonInteractiveCallbacks;

impl age::Callbacks for NonInteractiveCallbacks {
    fn display_message(&self, _msg: &str) {}

    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<age::secrecy::SecretBox<str>> {
        if let Ok(pass) =
            std::env::var("GIT_AGECRYPT_PASSPHRASE").or_else(|_| std::env::var("AGE_PASSPHRASE"))
        {
            return Some(age::secrecy::SecretBox::new(pass.into_boxed_str()));
        }
        None
    }
}

/// Evicts the oldest entries from `cache_dir` if entry count or total size exceeds limits.
/// Limits: `max_entries` (e.g. 500) and `max_bytes` (e.g. 100 MB).
pub fn prune_cache_if_needed(cache_dir: &Path, max_entries: usize, max_bytes: u64) -> Result<()> {
    if !cache_dir.exists() {
        return Ok(());
    }

    let mut entries = Vec::new();
    let mut total_size = 0u64;

    for entry in fs::read_dir(cache_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("age")
            && let Ok(meta) = entry.metadata()
        {
            let size = meta.len();
            let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            total_size += size;
            entries.push((path, size, mtime));
        }
    }

    if entries.len() <= max_entries && total_size <= max_bytes {
        return Ok(());
    }

    // Sort oldest first (ascending mtime) -> Least Recently Used (LRU)
    entries.sort_by_key(|&(_, _, mtime)| mtime);

    let mut current_count = entries.len();
    let mut current_size = total_size;

    for (path, size, _) in entries {
        if current_count <= max_entries && current_size <= max_bytes {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            current_count = current_count.saturating_sub(1);
            current_size = current_size.saturating_sub(size);
        }
    }

    Ok(())
}

const IN_MEMORY_SPOOL_LIMIT: usize = 1024 * 1024; // 1 MiB

/// Staging buffer for clean filter and probe streams.
/// Holds data in memory (zeroized on drop) for typical secret files (<= 1 MiB)
/// to eliminate temporary disk file I/O, seamlessly spilling to a NamedTempFile
/// only for files exceeding 1 MiB to guarantee bounded O(1) RAM usage.
pub enum SpoolBuffer {
    Memory(Vec<u8>),
    Disk(tempfile::NamedTempFile),
}

impl Drop for SpoolBuffer {
    fn drop(&mut self) {
        if let SpoolBuffer::Memory(bytes) = self {
            bytes.zeroize();
        }
    }
}

impl SpoolBuffer {
    pub fn reader(&self) -> Result<Box<dyn Read + '_>> {
        match self {
            SpoolBuffer::Memory(bytes) => Ok(Box::new(Cursor::new(bytes.as_slice()))),
            SpoolBuffer::Disk(file) => {
                let f = File::open(file.path())?;
                Ok(Box::new(f))
            }
        }
    }

    #[cfg(test)]
    pub fn is_in_memory(&self) -> bool {
        matches!(self, SpoolBuffer::Memory(_))
    }
}

/// Spools a stream into memory (or temporary file if > 1 MiB) while optionally updating an HMAC digest.
pub fn spool_stream<R: Read>(
    mut stream: R,
    cache_dir: Option<&Path>,
    mut mac_opt: Option<HmacSha256>,
) -> Result<(SpoolBuffer, Option<String>)> {
    let mut mem_buf = Vec::new();
    let mut disk_file: Option<tempfile::NamedTempFile> = None;
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if let Some(ref mut mac) = mac_opt {
            mac.update(&buf[..n]);
        }

        if let Some(ref mut df) = disk_file {
            df.write_all(&buf[..n])?;
        } else if mem_buf.len() + n <= IN_MEMORY_SPOOL_LIMIT {
            mem_buf.extend_from_slice(&buf[..n]);
        } else {
            let mut df = if let Some(c_dir) = cache_dir {
                fs::create_dir_all(c_dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(c_dir, fs::Permissions::from_mode(0o700));
                }
                tempfile::NamedTempFile::new_in(c_dir)?
            } else {
                tempfile::NamedTempFile::new()?
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(df.path(), fs::Permissions::from_mode(0o600));
            }
            df.write_all(&mem_buf)?;
            df.write_all(&buf[..n])?;
            mem_buf.clear();
            mem_buf.shrink_to_fit();
            disk_file = Some(df);
        }
    }

    if let Some(ref mut df) = disk_file {
        df.flush()?;
    }

    let hash_hex_opt = mac_opt.map(|mac| format_cache_hash(&mac.finalize().into_bytes()));
    let spool = match disk_file {
        Some(df) => SpoolBuffer::Disk(df),
        None => SpoolBuffer::Memory(mem_buf),
    };

    Ok((spool, hash_hex_opt))
}

/// Encrypts a plaintext stream into output, querying and updating the cache if enabled.
/// Employs index-aware deduplication: if the cache misses (or was pruned by LRU / cleared),
/// checks if the existing staged blob in Git index decrypts to the exact same plaintext.
/// If so, outputs the existing staged ciphertext to permanently defeat phantom diffs!
fn encrypt_plaintext_stream<R: Read, W: Write>(
    stream: R,
    mut output: W,
    recipient: &dyn age::Recipient,
    cache_dir: Option<&Path>,
    cache_key: Option<&[u8]>,
    identity_opt: Option<&dyn age::Identity>,
    staged_ciphertext: Option<&[u8]>,
) -> Result<()> {
    let mac_opt = cache_key.map(|key| HmacSha256::new_from_slice(key).expect("HMAC key valid"));
    let (spool, hash_hex_opt) = spool_stream(stream, cache_dir, mac_opt)?;

    // 1. Fast path: Check on-disk HMAC cache
    if let (Some(c_dir), Some(hash_hex)) = (cache_dir, hash_hex_opt.as_ref()) {
        let cache_file = c_dir.join(format!("{hash_hex}.age"));
        if cache_file.exists() {
            let is_valid = if let Ok(mut f) = File::open(&cache_file) {
                let mut prefix = [0u8; AGE_HEADER_MAGIC.len()];
                f.read_exact(&mut prefix).is_ok() && is_age_ciphertext(&prefix)
            } else {
                false
            };

            if is_valid {
                // Touch mtime on cache hit to maintain true LRU (Least Recently Used) ordering
                let _ = filetime::set_file_mtime(&cache_file, filetime::FileTime::now());
                let mut cached_reader = File::open(&cache_file)?;
                io::copy(&mut cached_reader, &mut output)?;
                output.flush()?;
                return Ok(());
            } else {
                // Corrupted or truncated cache entry: treat as cache miss and purge bad entry
                eprintln!(
                    "git-agecrypt clean [WARNING]: Corrupted or truncated cache entry detected ({hash_hex}.age). Purging and re-encrypting."
                );
                let _ = fs::remove_file(&cache_file);
            }
        }
    }

    // 2. Index-aware deduplication: If cache missed (e.g. pruned by LRU, cleared, or fresh clone),
    // check if the existing staged Git blob decrypts to the exact same plaintext.
    // If so, reuse the existing ciphertext to permanently defeat phantom diffs!
    if let (Some(staged_bytes), Some(id), Some(hash_hex)) =
        (staged_ciphertext, identity_opt, hash_hex_opt.as_ref())
    {
        let prefix_len = std::cmp::min(staged_bytes.len(), AGE_HEADER_MAGIC.len());
        if is_age_ciphertext(&staged_bytes[..prefix_len])
            && let Ok(decryptor) = age::Decryptor::new(staged_bytes)
            && let Ok(mut reader) = decryptor.decrypt(std::iter::once(id))
        {
            let mut staged_mac =
                cache_key.map(|k| HmacSha256::new_from_slice(k).expect("valid key"));
            let mut drain_buf = [0u8; 64 * 1024];
            let mut read_failed = false;
            loop {
                match reader.read(&mut drain_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(ref mut mac) = staged_mac {
                            mac.update(&drain_buf[..n]);
                        }
                    }
                    Err(_) => {
                        read_failed = true;
                        break;
                    }
                }
            }

            if !read_failed {
                let staged_hash_opt =
                    staged_mac.map(|m| format_cache_hash(&m.finalize().into_bytes()));
                if staged_hash_opt.as_ref() == Some(hash_hex) {
                    output.write_all(staged_bytes)?;
                    output.flush()?;

                    // Repopulate local cache atomically so subsequent checks are immediate
                    if let Some(c_dir) = cache_dir {
                        let _ = fs::create_dir_all(c_dir);
                        let dest = c_dir.join(format!("{hash_hex}.age"));
                        if !dest.exists()
                            && let Ok(mut tmp) = tempfile::NamedTempFile::new_in(c_dir)
                            && tmp.write_all(staged_bytes).is_ok()
                            && tmp.as_file().sync_all().is_ok()
                        {
                            let _ = tmp.persist(&dest);
                        }
                    }
                    return Ok(());
                }
            }
        }
    }

    // Cache miss or no cache: encrypt plaintext
    let mut reader = spool.reader()?;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))
        .map_err(|e| anyhow!("Failed to initialize age encryptor for clean filter: {e}"))?;

    if let (Some(c_dir), Some(hash_hex)) = (cache_dir, hash_hex_opt.as_ref()) {
        fs::create_dir_all(c_dir)?;
        let mut cache_temp = tempfile::NamedTempFile::new_in(c_dir)?;
        let mut age_writer = encryptor
            .wrap_output(&mut cache_temp)
            .context("Failed to wrap cache output stream with age encryptor")?;
        io::copy(&mut reader, &mut age_writer)
            .context("Failed to encrypt stream during clean filter")?;
        age_writer.finish()?.flush()?;

        {
            let mut cache_read = File::open(cache_temp.path())?;
            io::copy(&mut cache_read, &mut output)?;
            output.flush()?;
        }

        // Guarantee physical media sync before atomic rename
        let _ = cache_temp.as_file().sync_all();

        let dest = c_dir.join(format!("{hash_hex}.age"));
        if !dest.exists() {
            let mut current_temp = cache_temp;
            let mut persist_res = current_temp.persist(&dest);
            let mut attempts = 0;
            while let Err(e) = persist_res {
                if dest.exists() && fs::metadata(&dest).map(|m| m.len() > 0).unwrap_or(false) {
                    break;
                }
                attempts += 1;
                if attempts >= 5 {
                    // Auxiliary cache persist failed after retries (e.g. concurrent lock or disk quota).
                    // Do not fail the clean filter since output ciphertext was already written to Git.
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(15 * attempts as u64));
                current_temp = e.file;
                persist_res = current_temp.persist(&dest);
            }
            // Opportunistically prune (approx 1 in 32 cache writes) using runtime timestamp entropy
            // Dividing by 100 accounts for Windows FILETIME 100-nanosecond timer quantization
            let should_prune = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.subsec_nanos() / 100) % 32 == 0)
                .unwrap_or(false);
            if should_prune {
                let _ = prune_cache_if_needed(c_dir, 500, 100 * 1024 * 1024);
            }
        }
    } else {
        let mut age_writer = encryptor
            .wrap_output(&mut output)
            .context("Failed to wrap output stream with age encryptor")?;
        io::copy(&mut reader, &mut age_writer)
            .context("Failed to encrypt stream during clean filter")?;
        age_writer.finish()?.flush()?;
    }

    Ok(())
}

/// Git `clean` filter:
/// Reads stream `input` and writes to `output`.
///
/// If `input` is ALREADY an age ciphertext:
/// - If `identity_opt` is None (repo is locked), passes through directly to avoid double-encryption.
/// - If `identity_opt` is Some (repo is unlocked), verifies decryptability. If valid, passes through;
///   if invalid (e.g. test fixture or documentation starting with magic header), treats as plaintext and encrypts.
///
/// If `input` is plaintext:
/// - Checks `cache_dir` for a matching HMAC-SHA256 ciphertext cache entry (keyed by the repository master key).
/// - If cached, outputs the exact cached ciphertext (eliminating phantom git diffs without leaking plaintext hashes).
/// - If not cached, encrypts with `recipient`, outputs to `output`, and caches it.
///
/// Stream-based: never buffers full file in heap memory.
pub fn clean_stream<R: Read, W: Write>(
    input: R,
    mut output: W,
    recipient: &dyn age::Recipient,
    cache_dir: Option<&Path>,
    identity_opt: Option<&dyn age::Identity>,
    cache_key: Option<&[u8]>,
    staged_ciphertext: Option<&[u8]>,
) -> Result<()> {
    let (prefix, mut stream) = peek_prefix(input, AGE_HEADER_MAGIC.len())?;

    if is_age_ciphertext(&prefix) {
        if let Some(id) = identity_opt {
            // Repo is unlocked: verify this is actually a valid Age ciphertext for our key
            let (spool, _) = spool_stream(stream, cache_dir, None)?;
            let probe_reader = spool.reader()?;
            match age::Decryptor::new(probe_reader) {
                Ok(decryptor) => {
                    // Structurally valid Age container. Verify payload authentication.
                    match decryptor.decrypt(std::iter::once(id)) {
                        Ok(mut reader) => {
                            let mut drain = [0u8; 64 * 1024];
                            let mut payload_corrupted = false;
                            loop {
                                match reader.read(&mut drain) {
                                    Ok(0) => break,
                                    Ok(_) => {}
                                    Err(_) => {
                                        payload_corrupted = true;
                                        break;
                                    }
                                }
                            }
                            if payload_corrupted {
                                return Err(anyhow!(
                                    "Corrupted age ciphertext detected: header parsed successfully but payload authentication failed! \
                                     Aborting clean filter to prevent committing corrupted secrets."
                                ));
                            }

                            // 100% genuine, intact ciphertext: pass through untouched
                            let mut valid_file = spool.reader()?;
                            io::copy(&mut valid_file, &mut output)?;
                            output.flush()?;
                            return Ok(());
                        }
                        Err(
                            age::DecryptError::NoMatchingKeys
                            | age::DecryptError::ExcessiveWork { .. },
                        ) => {
                            // Structurally valid Age container encrypted for a different or historical recipient
                            // (e.g. historical branch prior to rekey, or external recipient).
                            // Pass through untouched so checking out, switching, or stashing historical branches succeeds!
                            eprintln!(
                                "git-agecrypt clean [WARNING]: File is encrypted with a historical or foreign key (does not match active recipient)."
                            );
                            let mut valid_file = spool.reader()?;
                            io::copy(&mut valid_file, &mut output)?;
                            output.flush()?;
                            return Ok(());
                        }
                        Err(err) => {
                            return Err(anyhow!(
                                "Corrupted age ciphertext detected: header integrity verification failed ({err})! \
                                 Aborting clean filter to prevent double-encrypting corrupted secrets."
                            ));
                        }
                    }
                }
                Err(_) => {
                    // Not an Age container (e.g. documentation starting with 'age-encryption.org/v1\n').
                    // Counter-trap: Must encrypt so plaintext is never committed to Git!
                    let temp_read = spool.reader()?;
                    return encrypt_plaintext_stream(
                        temp_read,
                        output,
                        recipient,
                        cache_dir,
                        cache_key,
                        identity_opt,
                        staged_ciphertext,
                    );
                }
            }
        } else {
            // Repo is locked: pass through raw ciphertext directly
            io::copy(&mut stream, &mut output)?;
            output.flush()?;
            return Ok(());
        }
    }

    encrypt_plaintext_stream(
        stream,
        output,
        recipient,
        cache_dir,
        cache_key,
        identity_opt,
        staged_ciphertext,
    )
}

/// Git `smudge` filter:
/// Reads stream `input` and writes to `output`.
///
/// If `input` is NOT age ciphertext, passes through directly (e.g. newly created plaintext file).
///
/// If `input` IS age ciphertext:
/// - If `identity` is None (repo is locked), returns an error so Git aborts or handles it.
/// - If `identity` is Some, decrypts using the repository identity.
/// - If `cache_dir` and `cache_key` are Some, caches the incoming ciphertext keyed by HMAC-SHA256(master_key, plaintext).
///
/// Stream-based: processes data in streaming chunks.
pub fn smudge_stream<R: Read, W: Write>(
    input: R,
    mut output: W,
    identity: Option<&dyn age::Identity>,
    cache_dir: Option<&Path>,
    cache_key: Option<&[u8]>,
) -> Result<()> {
    let (prefix, mut stream) = peek_prefix(input, AGE_HEADER_MAGIC.len())?;

    if !is_age_ciphertext(&prefix) {
        // Plaintext file or non-age stream: pass through directly
        io::copy(&mut stream, &mut output)?;
        output.flush()?;
        return Ok(());
    }

    // Input is age ciphertext
    let Some(id) = identity else {
        // Repository is locked: pass through raw ciphertext directly so Git checkout/clone/switch succeeds!
        io::copy(&mut stream, &mut output)?;
        output.flush()?;
        return Ok(());
    };

    if let (Some(c_dir), Some(key)) = (cache_dir, cache_key) {
        fs::create_dir_all(c_dir)?;
        let mut cipher_temp = tempfile::NamedTempFile::new_in(c_dir)?;
        io::copy(&mut stream, &mut cipher_temp)?;
        cipher_temp.flush()?;

        let hash_hex: String = {
            let cipher_file = File::open(cipher_temp.path())?;
            let decryptor = age::Decryptor::new(cipher_file)
                .map_err(|e| anyhow!("Failed to parse age ciphertext in smudge filter: {e}"))?;

            if decryptor.is_scrypt() {
                return Err(anyhow!(
                    "Unexpected passphrase-encrypted file in git repository"
                ));
            }

            let decrypt_res = decryptor.decrypt(std::iter::once(id));
            let mut reader = match decrypt_res {
                Ok(r) => r,
                Err(
                    age::DecryptError::NoMatchingKeys | age::DecryptError::ExcessiveWork { .. },
                ) => {
                    eprintln!(
                        "git-agecrypt smudge [WARNING]: File is encrypted with a historical or foreign key (cannot decrypt with active master key). \
                         Leaving raw ciphertext on disk. Run 'git-agecrypt rewrap' to re-encrypt under active master key."
                    );
                    let mut raw_file = File::open(cipher_temp.path())?;
                    io::copy(&mut raw_file, &mut output)?;
                    output.flush()?;
                    return Ok(());
                }
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to decrypt age ciphertext during smudge filter: {e}"
                    ));
                }
            };

            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key valid");
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                mac.update(&buf[..n]);
                output.write_all(&buf[..n])?;
            }
            output.flush()?;
            format_cache_hash(&mac.finalize().into_bytes())
        };

        let dest = c_dir.join(format!("{hash_hex}.age"));
        if !dest.exists() {
            let mut current_temp = cipher_temp;
            let mut persist_res = current_temp.persist(&dest);
            let mut attempts = 0;
            while let Err(e) = persist_res {
                if dest.exists() && fs::metadata(&dest).map(|m| m.len() > 0).unwrap_or(false) {
                    break;
                }
                attempts += 1;
                if attempts >= 5 {
                    // Auxiliary cache persist failed after retries (e.g. concurrent lock or disk quota).
                    // Do not fail the smudge filter since output cleartext was already delivered to Git.
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(15 * attempts as u64));
                current_temp = e.file;
                persist_res = current_temp.persist(&dest);
            }
            // Opportunistically prune (approx 1 in 32 cache writes) using runtime timestamp entropy
            // Dividing by 100 accounts for Windows FILETIME 100-nanosecond timer quantization
            let should_prune = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.subsec_nanos() / 100) % 32 == 0)
                .unwrap_or(false);
            if should_prune {
                let _ = prune_cache_if_needed(c_dir, 500, 100 * 1024 * 1024);
            }
        } else {
            let _ = filetime::set_file_mtime(&dest, filetime::FileTime::now());
        }
    } else {
        let mut cipher_temp = tempfile::NamedTempFile::new()?;
        io::copy(&mut stream, &mut cipher_temp)?;
        cipher_temp.flush()?;

        let cipher_file = File::open(cipher_temp.path())?;
        let decryptor = age::Decryptor::new(cipher_file)
            .map_err(|e| anyhow!("Failed to parse age ciphertext in smudge filter: {e}"))?;

        if decryptor.is_scrypt() {
            return Err(anyhow!(
                "Unexpected passphrase-encrypted file in git repository"
            ));
        }

        let decrypt_res = decryptor.decrypt(std::iter::once(id));
        let mut reader = match decrypt_res {
            Ok(r) => r,
            Err(age::DecryptError::NoMatchingKeys | age::DecryptError::ExcessiveWork { .. }) => {
                eprintln!(
                    "git-agecrypt smudge [WARNING]: File is encrypted with a historical or foreign key (cannot decrypt with active master key). \
                     Leaving raw ciphertext on disk. Run 'git-agecrypt rewrap' to re-encrypt under active master key."
                );
                let mut raw_file = File::open(cipher_temp.path())?;
                io::copy(&mut raw_file, &mut output)?;
                output.flush()?;
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to decrypt age ciphertext during smudge filter: {e}"
                ));
            }
        };

        io::copy(&mut reader, &mut output)
            .context("Failed to write decrypted data to output during smudge filter")?;
        output.flush()?;
    }

    Ok(())
}

/// Plain stream decryption using a repository identity.
pub fn decrypt_stream<R: Read, W: Write>(
    input: R,
    mut output: W,
    identity: &dyn age::Identity,
) -> Result<()> {
    let decryptor =
        age::Decryptor::new(input).map_err(|e| anyhow!("Failed to parse age ciphertext: {e}"))?;

    if decryptor.is_scrypt() {
        return Err(anyhow!("Unexpected passphrase-encrypted file"));
    }

    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
        .context("Failed to decrypt age ciphertext")?;

    io::copy(&mut reader, &mut output)?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    #[test]
    fn test_generate_and_parse_master_identity() {
        let (identity, recipient) = generate_master_identity();
        let pub_str = recipient.to_string();
        assert!(pub_str.starts_with("age1"));

        let parsed = parse_recipient(&pub_str).expect("Failed to parse recipient");
        let secret_str = identity.to_string();

        let wrapped =
            wrap_master_key(secret_str.expose_secret(), parsed.as_ref()).expect("Wrap failed");
        assert!(wrapped.contains("BEGIN AGE ENCRYPTED FILE"));

        let identities: Vec<Box<dyn age::Identity>> = vec![Box::new(identity)];
        let unwrapped = unwrap_master_key(&wrapped, &identities).expect("Unwrap failed");
        assert_eq!(secret_str.expose_secret(), &unwrapped);

        // Test with preamble metadata
        let (id2, rec2) = generate_master_identity();
        let pub_str2 = rec2.to_string();
        let wrapped_meta = wrap_master_key_with_metadata(
            id2.to_string().expose_secret(),
            &rec2 as &dyn age::Recipient,
            &pub_str2,
        )
        .expect("Wrap with metadata failed");

        let extracted = extract_recipient_public_key(&wrapped_meta).expect("Extract failed");
        assert_eq!(extracted, pub_str2);

        let id2_boxed: Vec<Box<dyn age::Identity>> = vec![Box::new(id2.clone())];
        let unwrapped_meta =
            unwrap_master_key(&wrapped_meta, &id2_boxed).expect("Unwrap metadata failed");
        assert_eq!(id2.to_string().expose_secret(), unwrapped_meta);
    }

    #[test]
    fn test_clean_and_smudge_stream_roundtrip() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();
        let original_data =
            b"DATABASE_URL=postgres://user:pass@localhost:5432/mydb\nSECRET_KEY=supersecret123\n";

        // Clean (encrypt)
        let mut encrypted = Vec::new();
        clean_stream(
            Cursor::new(original_data.to_vec()),
            &mut encrypted,
            &recipient,
            None,
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .expect("Clean failed");

        assert!(is_age_ciphertext(&encrypted));

        // Clean idempotency: clean on already-encrypted data should pass through unmodified
        let mut clean_again = Vec::new();
        clean_stream(
            Cursor::new(encrypted.clone()),
            &mut clean_again,
            &recipient,
            None,
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .expect("Clean again failed");
        assert_eq!(encrypted, clean_again);

        // Smudge (decrypt) with identity
        let mut decrypted = Vec::new();
        smudge_stream(
            Cursor::new(encrypted.clone()),
            &mut decrypted,
            Some(&identity),
            None,
            Some(&key_bytes),
        )
        .expect("Smudge failed");
        assert_eq!(original_data.as_slice(), decrypted.as_slice());

        // Smudge with None identity (repository locked) should pass through raw ciphertext cleanly!
        let mut locked_out = Vec::new();
        smudge_stream(
            Cursor::new(encrypted.clone()),
            &mut locked_out,
            None,
            None,
            None,
        )
        .expect("Smudge with None identity should pass through ciphertext cleanly");
        assert_eq!(encrypted, locked_out);

        // Smudge on plaintext should pass through as-is
        let mut plain_out = Vec::new();
        smudge_stream(
            Cursor::new(original_data.to_vec()),
            &mut plain_out,
            None,
            None,
            None,
        )
        .expect("Smudge on plaintext failed");
        assert_eq!(original_data.as_slice(), plain_out.as_slice());
    }

    #[test]
    fn test_empty_file_roundtrip() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();
        let empty_data = b"";

        let mut encrypted = Vec::new();
        clean_stream(
            Cursor::new(empty_data.to_vec()),
            &mut encrypted,
            &recipient,
            None,
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .expect("Clean empty failed");
        assert!(is_age_ciphertext(&encrypted));

        let mut decrypted = Vec::new();
        smudge_stream(
            Cursor::new(encrypted),
            &mut decrypted,
            Some(&identity),
            None,
            Some(&key_bytes),
        )
        .expect("Smudge empty failed");
        assert_eq!(b"", decrypted.as_slice());
    }

    #[test]
    fn test_clean_and_smudge_caching_deterministic() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();
        let original_data = b"API_KEY=test_cache_secret_12345\n";
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let cache_dir = temp_dir.path().join("cache");

        // First clean: encrypts and caches
        let mut first_ciphertext = Vec::new();
        clean_stream(
            Cursor::new(original_data.to_vec()),
            &mut first_ciphertext,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .expect("First clean failed");
        assert!(is_age_ciphertext(&first_ciphertext));

        // Second clean on the exact same plaintext: should hit cache and be BIT-FOR-BIT IDENTICAL!
        let mut second_ciphertext = Vec::new();
        clean_stream(
            Cursor::new(original_data.to_vec()),
            &mut second_ciphertext,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .expect("Second clean failed");

        assert_eq!(
            first_ciphertext, second_ciphertext,
            "Ciphertexts must be bit-for-bit identical due to deterministic cache hit!"
        );

        // Smudge with cache_dir should decrypt and preserve cache
        let mut decrypted = Vec::new();
        smudge_stream(
            Cursor::new(first_ciphertext),
            &mut decrypted,
            Some(&identity),
            Some(&cache_dir),
            Some(&key_bytes),
        )
        .expect("Smudge failed");
        assert_eq!(original_data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_clean_sniffing_counter_trap_encrypts_fake_header() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();
        // A plaintext file that starts with age header (e.g. markdown docs or test fixture)
        let fake_age_plaintext =
            b"age-encryption.org/v1\n-> This is actually documentation or a test fixture!\n";

        // When repo is unlocked (identity is Some), clean_stream verifies whether it can decrypt it.
        // Decryption fails because it's NOT genuine ciphertext encrypted with this master key.
        // Therefore, clean_stream encrypts it to prevent plaintext leakage!
        let mut encrypted = Vec::new();
        clean_stream(
            Cursor::new(fake_age_plaintext.to_vec()),
            &mut encrypted,
            &recipient,
            None,
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .expect("Clean fake age header failed");

        // The result must be a genuine age ciphertext
        assert!(is_age_ciphertext(&encrypted));

        // When decrypted with identity, we get our original fake_age_plaintext back!
        let mut decrypted = Vec::new();
        smudge_stream(
            Cursor::new(encrypted),
            &mut decrypted,
            Some(&identity),
            None,
            Some(&key_bytes),
        )
        .expect("Smudge failed");
        assert_eq!(fake_age_plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hmac_keyed_cache_filename() {
        let key1 = b"master_key_1";
        let key2 = b"master_key_2";
        let plaintext = b"SECRET_PASSWORD=supersecret";

        let hash1 = compute_cache_filename(key1, plaintext);
        let hash2 = compute_cache_filename(key2, plaintext);
        let hash1_repeat = compute_cache_filename(key1, plaintext);

        assert_eq!(
            hash1, hash1_repeat,
            "HMAC must be deterministic for same key and data"
        );
        assert_ne!(
            hash1, hash2,
            "HMAC filenames must differ across different master keys"
        );
        assert_eq!(
            hash1.len(),
            32,
            "HMAC-SHA256 hex string must be 32 characters (128-bit hash) for MAX_PATH safety"
        );
    }

    #[test]
    fn test_cache_lru_pruning() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir_all(&cache_dir).unwrap();

        // Create 8 cache files with spaced mtimes
        let now = std::time::SystemTime::now();
        for i in 0..8 {
            let file_path = cache_dir.join(format!("entry_{i}.age"));
            fs::write(&file_path, format!("cache payload {i}")).unwrap();
            let file_time =
                filetime::FileTime::from_system_time(now + std::time::Duration::from_secs(i * 10));
            filetime::set_file_mtime(&file_path, file_time).unwrap();
        }

        assert_eq!(fs::read_dir(&cache_dir).unwrap().count(), 8);

        // Prune with limit = 4 entries
        prune_cache_if_needed(&cache_dir, 4, 1024 * 1024).expect("Prune failed");

        let remaining: Vec<String> = fs::read_dir(&cache_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();

        assert_eq!(remaining.len(), 4);
        // The 4 newest entries (4, 5, 6, 7) must remain
        assert!(remaining.contains(&"entry_4.age".to_string()));
        assert!(remaining.contains(&"entry_5.age".to_string()));
        assert!(remaining.contains(&"entry_6.age".to_string()));
        assert!(remaining.contains(&"entry_7.age".to_string()));
        // Oldest (0, 1, 2, 3) must be evicted
        assert!(!remaining.contains(&"entry_0.age".to_string()));
        assert!(!remaining.contains(&"entry_1.age".to_string()));
    }

    #[test]
    fn test_cache_lru_touches_mtime() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let cache_dir = temp_dir.path().join("cache");

        let secret_a = b"SECRET_A=first_created\n";
        let secret_b = b"SECRET_B=second_created\n";

        // Clean A and B to populate cache
        let mut enc_a = Vec::new();
        clean_stream(
            Cursor::new(secret_a.to_vec()),
            &mut enc_a,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .unwrap();

        let mut enc_b = Vec::new();
        clean_stream(
            Cursor::new(secret_b.to_vec()),
            &mut enc_b,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .unwrap();

        let hash_a = compute_cache_filename(&key_bytes, secret_a);
        let hash_b = compute_cache_filename(&key_bytes, secret_b);
        let path_a = cache_dir.join(format!("{hash_a}.age"));
        let path_b = cache_dir.join(format!("{hash_b}.age"));

        // Artificially set A to be much older than B
        let now = std::time::SystemTime::now();
        let old_time =
            filetime::FileTime::from_system_time(now - std::time::Duration::from_secs(300));
        let mid_time =
            filetime::FileTime::from_system_time(now - std::time::Duration::from_secs(100));
        filetime::set_file_mtime(&path_a, old_time).unwrap();
        filetime::set_file_mtime(&path_b, mid_time).unwrap();

        // Now trigger a cache HIT on A:
        let mut out_a = Vec::new();
        clean_stream(
            Cursor::new(secret_a.to_vec()),
            &mut out_a,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .unwrap();

        // Verify that A's mtime was touched and is now NEWER than B's mtime!
        let mtime_a = fs::metadata(&path_a).unwrap().modified().unwrap();
        let mtime_b = fs::metadata(&path_b).unwrap().modified().unwrap();
        assert!(
            mtime_a > mtime_b,
            "Cache hit must touch mtime so frequently accessed file is newer"
        );

        // Prune with max_entries = 1: B must be evicted, and A must be kept!
        prune_cache_if_needed(&cache_dir, 1, 1024 * 1024).unwrap();
        assert!(
            path_a.exists(),
            "Frequently used secret A must be kept by LRU!"
        );
        assert!(
            !path_b.exists(),
            "Older/inactive secret B must be evicted by LRU!"
        );
    }

    #[test]
    fn test_clean_aborts_on_corrupted_ciphertext() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = b"01234567890123456789012345678901";

        let plaintext = b"DB_PASS=AuthenticSecret123!\n";
        let mut clean_cipher = Vec::new();
        clean_stream(
            Cursor::new(plaintext),
            &mut clean_cipher,
            &recipient,
            None,
            Some(&identity),
            Some(key_bytes),
            None,
        )
        .unwrap();

        assert!(is_age_ciphertext(&clean_cipher));

        // Corrupt a byte in the payload area
        let mut corrupted_cipher = clean_cipher.clone();
        let len = corrupted_cipher.len();
        corrupted_cipher[len - 5] ^= 0xFF;

        // Clean filter on corrupted ciphertext must NOT double-encrypt; it must return an Err
        let mut out = Vec::new();
        let res = clean_stream(
            Cursor::new(corrupted_cipher),
            &mut out,
            &recipient,
            None,
            Some(&identity),
            Some(key_bytes),
            None,
        );

        assert!(
            res.is_err(),
            "Clean filter must fail on corrupted ciphertext"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Corrupted age ciphertext detected"),
            "Error message must clearly identify corrupted ciphertext: {err_msg}"
        );
    }

    #[test]
    fn test_clean_stream_index_aware_deduplication() {
        let (identity, recipient) = generate_master_identity();
        let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");

        let plaintext = b"PRODUCTION_TOKEN=abcdef123456\n";

        // Initial clean to generate a valid ciphertext (with no staged blob)
        let mut initial_cipher = Vec::new();
        clean_stream(
            Cursor::new(plaintext.to_vec()),
            &mut initial_cipher,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            None,
        )
        .unwrap();

        // Simulate cache wipe (e.g. fresh clone or LRU eviction)
        fs::remove_dir_all(&cache_dir).unwrap();
        assert!(!cache_dir.exists());

        // Now run clean_stream with cache empty, but providing the staged_ciphertext!
        let mut deduped_cipher = Vec::new();
        clean_stream(
            Cursor::new(plaintext.to_vec()),
            &mut deduped_cipher,
            &recipient,
            Some(&cache_dir),
            Some(&identity),
            Some(&key_bytes),
            Some(&initial_cipher),
        )
        .unwrap();

        // It must match bit-for-bit with the staged ciphertext!
        assert_eq!(
            initial_cipher, deduped_cipher,
            "Index-aware deduplication must preserve identical ciphertext across cache wipes"
        );

        // Also verify the cache entry was repopulated
        let hash = compute_cache_filename(&key_bytes, plaintext);
        let cached_file = cache_dir.join(format!("{hash}.age"));
        assert!(
            cached_file.exists(),
            "Cache entry must be repopulated from staged ciphertext"
        );
        let repopulated_content = fs::read(cached_file).unwrap();
        assert_eq!(repopulated_content, initial_cipher);
    }

    #[test]
    fn test_spool_buffer_memory_and_disk() {
        let temp_dir = tempfile::tempdir().unwrap();

        // 1. Small stream (< 1 MiB) -> stays in Memory
        let small_data = b"SECRET_API_KEY=1234567890abcdef\n";
        let (spool_small, mac_small) = spool_stream(
            Cursor::new(small_data.to_vec()),
            Some(temp_dir.path()),
            None,
        )
        .unwrap();
        assert!(spool_small.is_in_memory());
        assert!(mac_small.is_none());
        let mut read_back = Vec::new();
        spool_small
            .reader()
            .unwrap()
            .read_to_end(&mut read_back)
            .unwrap();
        assert_eq!(read_back, small_data);

        // 2. Large stream (> 1 MiB) -> spills to Disk
        let large_size = 1024 * 1024 + 100; // 1 MiB + 100 bytes
        let large_data = vec![0x42u8; large_size];
        let (spool_large, _) =
            spool_stream(Cursor::new(large_data.clone()), Some(temp_dir.path()), None).unwrap();
        assert!(!spool_large.is_in_memory());
        let mut large_read_back = Vec::new();
        spool_large
            .reader()
            .unwrap()
            .read_to_end(&mut large_read_back)
            .unwrap();
        assert_eq!(large_read_back, large_data);
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]

        #[test]
        fn proptest_clean_and_smudge_roundtrip(data in proptest::collection::vec(proptest::num::u8::ANY, 0..16384)) {
            let (identity, recipient) = generate_master_identity();
            let mut ciphertext = Vec::new();
            clean_stream(Cursor::new(&data), &mut ciphertext, &recipient, None, Some(&identity), None, None)
                .expect("clean_stream must not fail on arbitrary bytes");

            let mut decrypted = Vec::new();
            smudge_stream(Cursor::new(&ciphertext), &mut decrypted, Some(&identity), None, None)
                .expect("smudge_stream must decrypt authenticated ciphertext");

            proptest::prop_assert_eq!(data, decrypted);
        }

        #[test]
        fn proptest_smudge_arbitrary_bytes_never_panics(corrupt in proptest::collection::vec(proptest::num::u8::ANY, 0..4096)) {
            let (identity, _) = generate_master_identity();
            let mut decrypted = Vec::new();
            let _ = smudge_stream(Cursor::new(&corrupt), &mut decrypted, Some(&identity), None, None);
        }

        #[test]
        fn proptest_clean_arbitrary_bytes_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..4096)) {
            let (identity, recipient) = generate_master_identity();
            let mut ciphertext = Vec::new();
            let _ = clean_stream(Cursor::new(&data), &mut ciphertext, &recipient, None, Some(&identity), None, None);
        }
    }
}
