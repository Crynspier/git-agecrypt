# `git-agecrypt` Operations, Upgrade, and Disaster Recovery Guide

This guide covers day-to-day repository administration, team onboarding and offboarding, multi-ring isolation, upgrades and rollbacks, diagnostics (`inspect`), and clean-room disaster recovery (`export-age` and standalone `age` CLI recovery).

---

## 1. Team Onboarding and Offboarding

### 1.1 Onboarding a Collaborator or CI Runner
1. Ensure your local repository is unlocked (`git-agecrypt status`).
2. Enroll the collaborator's public key (`age1...`, `ssh-ed25519`, or `ssh-rsa`):
   ```bash
   # From a public key string or file
   git-agecrypt add-recipient -i "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" -n alice

   # Or fetch SSH keys from GitHub (verify fingerprints before committing!)
   git-agecrypt add-recipient --github alice -n alice
   ```
3. Commit and push the newly created `.git-agecrypt/keys/alice.age` envelope:
   ```bash
   git add .git-agecrypt/keys/
   git commit -m "chore(secrets): enroll alice as recipient"
   git push
   ```
4. The new collaborator pulls and runs `git-agecrypt unlock` (or `git-agecrypt unlock ~/.ssh/id_ed25519`).

### 1.2 Offboarding a Collaborator (Revocation + Master Key Rotation)
1. Remove the collaborator's recipient envelope and rotate the ring's master key:
   ```bash
   git-agecrypt remove-recipient alice
   git-agecrypt rekey
   ```
2. Commit and push the rotated metadata and re-encrypted secrets:
   ```bash
   git add .git-agecrypt
   git commit -m "security(secrets): revoke alice and rotate master key"
   git push
   ```
3. **Important Forward-Secrecy Note:** Rotating the master key ensures the revoked collaborator cannot decrypt any *future* secrets committed after the rotation. However, because Git history is immutable, any secrets present in historical commits prior to the rotation remain decryptable by anyone who saved a copy of the old history and old master key. Always rotate actual external credentials (API tokens, database passwords, TLS private keys) in your upstream providers when offboarding a collaborator.

---

## 2. Scoped Multi-Ring Isolation (`--ring`)

Use named rings to isolate environments (e.g., `dev`, `staging`, `prod`) so developers or CI jobs only unlock the secrets they need:

```bash
# 1. Initialize the 'prod' ring
git-agecrypt init --ring prod

# 2. Map production paths in .gitattributes
echo "secrets/prod/** filter=agecrypt-prod diff=agecrypt-prod merge=agecrypt-prod -text" >> .gitattributes

# 3. Enroll production recipients
git-agecrypt add-recipient --ring prod -i "age1..." -n prod-deployer

# 4. Unlock, lock, or rekey only the 'prod' ring
git-agecrypt unlock --ring prod ~/.config/age/prod-key.txt
git-agecrypt lock --ring prod
git-agecrypt rekey --ring prod
```

---

## 3. Historical Branch Merges and Cherry-Picks (`rewrap`)

When merging or cherry-picking a commit created *before* a `rekey` operation, historical blobs are encrypted under the previous master key. To prevent forward-secrecy regressions (`check` blocks committing blobs encrypted with a revoked key):

```bash
# Re-encrypt a specific file under the current active master key
git-agecrypt rewrap secrets/app.secret.env

# Or scan and re-encrypt all tracked secrets containing historical ciphertexts
git-agecrypt rewrap --all
```

> **Shallow Clone Note:** Discovering historical master keys across Git commits requires commit history (`fetch-depth: 0` or `git fetch --unshallow`), unless you pass the historical key directly via `git-agecrypt rewrap --identity <HISTORICAL_KEY>`.

---

## 4. Diagnostics and Health Inspection (`inspect`)

Run `git-agecrypt inspect` at any time to perform a read-only diagnostic check of the repository's format version, rings, recipient envelopes, local key state, transaction journal, and tracked files:

```bash
# Human-readable diagnostic report
git-agecrypt inspect

# Machine-readable JSON report for CI / monitoring
git-agecrypt inspect --format json

# Inspect a specific ring
git-agecrypt inspect --ring prod
```

---

## 5. Interoperability and Disaster Recovery

### 5.1 Exporting a Secret to a Standard `age` File (`export-age`)
To export a tracked secret to a standalone, standard `age`-encrypted file for an external recipient or backup vault without writing plaintext or raw keys to stdout:

```bash
git-agecrypt export-age secrets/prod.env \
  --recipient "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" \
  --output /tmp/prod.env.age
```

The resulting `/tmp/prod.env.age` file can be decrypted directly with the upstream `age` CLI:
```bash
age --decrypt --identity ~/.config/age/keys.txt /tmp/prod.env.age
```

### 5.2 Clean-Room Manual Recovery (Without `git-agecrypt` Installed)
Because `git-agecrypt` Format Version 1 uses 100% standard `age` v1 primitives, you can recover every secret in a repository using **only** `git` and the standard [`age` CLI](https://github.com/FiloSottile/age) even if `git-agecrypt` is completely unavailable:

1. **Unwrap the repository master key (`AGE-SECRET-KEY-1...`) from your recipient envelope** in `.git-agecrypt/keys/<your_name>.age` using your personal `age` or SSH private key:
   ```bash
   grep -v '^#' .git-agecrypt/keys/alice.age | age --decrypt --identity ~/.ssh/id_ed25519 > /tmp/recovered-repo.key
   chmod 600 /tmp/recovered-repo.key
   ```
2. **Extract the encrypted blob from Git and decrypt it with `age`:**
   ```bash
   git show HEAD:secrets/app.secret.env | age --decrypt --identity /tmp/recovered-repo.key > /tmp/app.secret.env
   ```
3. **Clean up temporary master key:**
   ```bash
   rm -f /tmp/recovered-repo.key
   ```

---

## 6. Upgrade and Rollback Procedures

### 6.1 Upgrading `git-agecrypt` Across Format Version 1 Releases
1. **Verify clean state before upgrading:**
   ```bash
   git status
   git-agecrypt status
   ```
2. **Install the new `git-agecrypt` binary** (via verified GitHub Release archive, `cargo install --locked agecrypt`, or package manager).
3. **Verify repository health and refresh hooks:**
   ```bash
   git-agecrypt --version
   git-agecrypt inspect
   git-agecrypt install-hooks
   ```
   All Format Version 1 repositories (including implicit v1 repositories) are 100% backward-compatible across Format Version 1 releases without re-encrypting files or rotating keys.

### 6.2 Rolling Back a Binary Upgrade
- Because Format Version 1 is preserved on disk, rolling back the `git-agecrypt` binary to a previous Format Version 1 release requires only replacing the binary on `PATH` and running `git-agecrypt status`.
- If `.git-agecrypt/format` contains `1`, any Format Version 1 binary can read `.git-agecrypt/repo.pub` and `.git-agecrypt/keys/*.age` without modification.
