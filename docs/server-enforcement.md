# Server-Side and Hosted CI Secret Policy Enforcement

`git-agecrypt` provides robust server-side protection to ensure that no plaintext secrets, corrupted Age blobs, or unauthorized access changes are ever introduced into a Git repository.

---

## 1. Threat Model & Guarantees

Server-side enforcement acts as an authoritative security boundary:
- **Zero Plaintext Bypass**: Blocks commits where a secret matched by `.gitattributes` contains cleartext data instead of a valid Age ciphertext.
- **Corrupted Ciphertext Rejection**: Validates that all Age encrypted blobs have valid headers parseable by the `age` format specification.
- **Unprotected Secret Renames**: Blocks commits that attempt to rename a protected secret file to an unprotected path without prior explicit re-wrapping.
- **Shell-Safe Filenames**: Rejects commits containing secret filenames with characters that could trigger command injection during Git filter/diff/merge driver execution (e.g., quotes, control characters, backticks).
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

---

## 4. Exit Codes

- `0`: Inspection passed. All secrets are properly encrypted and formatted.
- `1`: Policy violation detected (in strict mode). Plaintext secrets, corrupted ciphertext, or unsafe renames present.
