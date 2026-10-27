# Server-Side and Hosted CI Secret Policy Enforcement

Client-side Git filters (`clean`/`smudge`) and local hooks (`pre-commit`, `pre-merge-commit`, `pre-push`) protect developers from accidental leaks, but a client can bypass local hooks with `git commit --no-verify` or `git push --no-verify`, or forget to run `git-agecrypt init`.

To protect remote repositories, `git-agecrypt` provides two distinct enforcement layers with fundamentally different security boundaries:

1. **Authoritative Server-Side `pre-receive` Hook (`git-agecrypt check --pre-receive` + `examples/hooks/pre-receive`)**:
   Runs synchronously on the Git server *before* incoming Git objects are committed to the repository's permanent object database. If a violation is detected, the entire push transaction is rejected and rolled back, ensuring plaintext secrets never enter remote storage.
2. **Hosted Git CI Enforcement (`git-agecrypt check --commit-range` + `examples/github-actions/agecrypt-verify.yml`)**:
   Runs asynchronously on hosted platforms (e.g. GitHub.com, GitLab.com) *after* refs have already been pushed. It prevents merging unencrypted commits into protected branches, but cannot prevent the initial network push from writing objects to the remote repository.

---

## 1. Threat Model & Guarantees

When run in authoritative pre-receive or CI check mode, `git-agecrypt` enforces:
- **Zero Plaintext Bypass**: Blocks commits where a secret matched by `.gitattributes` contains cleartext data instead of a valid Age ciphertext.
- **Corrupted Ciphertext Rejection**: Validates that all Age encrypted blobs have valid headers parseable by the `age` format specification.
- **Historical & Foreign Key Rejection**: Verifies that protected secrets are encrypted under the active ring master key, preventing replay of revoked or foreign key ciphertexts.
- **Unprotected Secret Renames**: Blocks commits that attempt to rename a protected secret file to an unprotected path without prior explicit re-wrapping.
- **Shell-Safe Filenames**: Rejects commits containing secret filenames with characters that could trigger command injection during Git driver shell expansion (e.g., quotes, control characters, backticks).
- **Format Integrity**: Verifies `.git-agecrypt/format` version compliance across pushed revisions.

---

## 2. Deploying the Native Server-Side `pre-receive` Hook

### 2.1 Installation on a Bare Git Repository / Self-Hosted Server
1. Install the `git-agecrypt` binary on the Git server so it is available on `PATH`.
2. Copy [`examples/hooks/pre-receive`](../examples/hooks/pre-receive) into your bare repository's `hooks/pre-receive` path:
   ```bash
   cp examples/hooks/pre-receive /srv/git/my-repo.git/hooks/pre-receive
   chmod +x /srv/git/my-repo.git/hooks/pre-receive
   ```

### 2.2 Supported Push Scenarios
`git-agecrypt check --pre-receive` handles the full Git `pre-receive` stdin protocol (`<old_oid> <new_oid> <refname>`):
- **New branch / initial push** (`old_oid = 0000...`): Inspects all commits reachable from `new_oid` not already reachable from existing refs, plus the tip tree of `new_oid`.
- **Standard fast-forward push**: Inspects `old_oid..new_oid` and the tip tree of `new_oid`.
- **Force-push (non-fast-forward rewrite)**: Inspects all rewritten commits in `old_oid..new_oid` and the new tip tree.
- **Merge commits**: Inspects all commits introduced by the merge parents and the merged tip tree.
- **Multi-ref push (`git push --all` / atomic multi-branch push)**: Evaluates every ref update line from stdin and rejects the push if any ref contains a violation.
- **Branch or tag deletion** (`new_oid = 0000...`): Allowed cleanly without false positives.

### 2.3 Gradual Rollout: Strict Mode vs. Report-Only Mode
When rolling out enforcement on an existing repository, you can start in **report-only mode** so violations are logged to the Git server output without blocking pushes:

- **CLI flag:** `git-agecrypt check --pre-receive --report-only`
- **Hook environment variable:** `export GIT_AGECRYPT_REPORT_ONLY=1`
- **Strict mode (default):** Exits with status `1` and rejects the push on any policy violation.

---

## 3. Deploying Hosted Git CI Enforcement (GitHub Actions)

On hosted platforms (such as GitHub.com) where custom bare-repository `pre-receive` hooks are unavailable on standard plans, copy [`examples/github-actions/agecrypt-verify.yml`](../examples/github-actions/agecrypt-verify.yml) to `.github/workflows/agecrypt-verify.yml` and mark the job as a **Required Status Check** in branch protection rules.

```yaml
- name: Verify repository metadata format and health
  run: git-agecrypt inspect --format json

- name: Verify commits in pull request
  run: git-agecrypt check --commit-range "${{ github.event.pull_request.base.sha }}..${{ github.sha }}"
```

> [!WARNING]
> **Crucial Security Boundary Distinction**:
> Unlike a server-side `pre-receive` hook—which rejects plaintext *before* objects enter the remote repository—a GitHub Actions workflow runs *after* a branch or pull request ref has already arrived on GitHub's servers.
> If a contributor pushes a plaintext secret to a feature branch or PR:
> 1. The CI check will fail and prevent merging into `main`.
> 2. However, the plaintext secret blob has **already been transmitted and stored** in the remote repository's Git object database.
> 3. Therefore, **the exposed credential must be considered compromised and rotated immediately**, followed by rewriting or deleting the remote branch.

---

## 4. Exit Codes

- `0`: Inspection passed. All secrets are properly encrypted and formatted.
- `1`: Policy violation detected (in strict mode). Plaintext secrets, corrupted ciphertext, or unsafe renames present.
