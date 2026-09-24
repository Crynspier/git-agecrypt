use anyhow::{Context, Result, anyhow};
use std::io::Read;

/// Validates GitHub username according to official GitHub specification.
pub fn is_valid_github_username(username: &str) -> bool {
    let clean = username.trim().trim_start_matches('@');
    if clean.is_empty() || clean.len() > 39 {
        return false;
    }
    if clean.starts_with('-') || clean.ends_with('-') {
        return false;
    }
    if clean.contains("--") {
        return false;
    }
    clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Fetches public SSH keys from GitHub for a given username.
/// Returns a list of valid recipient strings (preferring ssh-ed25519).
pub fn fetch_github_keys(username: &str) -> Result<Vec<String>> {
    let clean_user = username.trim().trim_start_matches('@');
    if !is_valid_github_username(clean_user) {
        return Err(anyhow!(
            "Invalid GitHub username '{username}': GitHub usernames may only contain alphanumeric characters and single hyphens (max 39 characters)."
        ));
    }

    let url = format!("https://github.com/{clean_user}.keys");
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        // H2: never follow redirects; a redirect could steer key retrieval to an
        // attacker-controlled or plaintext-HTTP endpoint.
        .redirects(0)
        .build();
    let response = agent
        .get(&url)
        .set("User-Agent", "git-agecrypt")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(404, _) => anyhow!("GitHub user '{clean_user}' was not found"),
            ureq::Error::Status(403, _) | ureq::Error::Status(429, _) => anyhow!(
                "GitHub API rate limit exceeded when fetching keys for '{clean_user}'. Please supply the public key file or string via --identity (-i) instead."
            ),
            other => anyhow!("Failed to fetch keys for GitHub user '{clean_user}': {other}"),
        })?;

    if (300..400).contains(&response.status()) {
        return Err(anyhow!(
            "Unexpected HTTP redirect ({}) when fetching keys for GitHub user '{clean_user}'; redirects are disabled for security.",
            response.status()
        ));
    }

    let mut buf = Vec::new();
    let reader = response.into_reader();
    reader
        .take(512 * 1024)
        .read_to_end(&mut buf)
        .context("Failed to read response body from GitHub")?;
    let body = String::from_utf8_lossy(&buf);

    let mut keys = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // age supports ssh-ed25519 and ssh-rsa
        if trimmed.starts_with("ssh-ed25519") || trimmed.starts_with("ssh-rsa") {
            keys.push(trimmed.to_string());
        }
    }

    if keys.is_empty() {
        return Err(anyhow!(
            "No compatible SSH keys (ssh-ed25519 or ssh-rsa) found for GitHub user '{clean_user}'"
        ));
    }

    // H3: the GitHub .keys endpoint is authenticated only by TLS to github.com, not to
    // the account owner. Surface the enrolled keys so users can verify them out-of-band
    // (e.g. against the keys shown in the account's GitHub SSH settings).
    eprintln!("git-agecrypt [NOTICE]: Enrolled SSH public key(s) for GitHub user '{clean_user}':");
    for key in &keys {
        eprintln!("  * {key}");
    }
    eprintln!("Verify these match the keys in the account's GitHub settings before trusting them.");

    Ok(keys)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_filter_ssh_keys() {
        let sample = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host\necdsa-sha2-nistp256 AAAAE... invalid\nssh-rsa AAAAB3NzaC1yc2E... rsa-user\n";
        let mut parsed = Vec::new();
        for line in sample.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ssh-ed25519") || trimmed.starts_with("ssh-rsa") {
                parsed.push(trimmed.to_string());
            }
        }
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].starts_with("ssh-ed25519"));
        assert!(parsed[1].starts_with("ssh-rsa"));
    }

    #[test]
    fn test_github_username_validation() {
        use super::is_valid_github_username;
        assert!(is_valid_github_username("octocat"));
        assert!(is_valid_github_username("@octocat"));
        assert!(is_valid_github_username("john-doe-123"));
        assert!(!is_valid_github_username(""));
        assert!(!is_valid_github_username("-invalid"));
        assert!(!is_valid_github_username("invalid-"));
        assert!(!is_valid_github_username("in--valid"));
        assert!(!is_valid_github_username("user/repo"));
        assert!(!is_valid_github_username("user name"));
        assert!(!is_valid_github_username("a".repeat(40).as_str()));
    }
}
