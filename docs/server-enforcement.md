# Server-Side and CI Policy Enforcement Guide

Client-side Git filters (`clean`/`smudge`) and local hooks (`pre-commit`, `pre-merge-commit`, `pre-push`) protect developers from accidental secret leaks, but a client can bypass local hooks with `git commit --no-verify` or `git push --no-verify`, or forget to run `git-agecrypt init`.

To enforce zero-trust verification on every push and pull request, `git-agecrypt` provides two complementary server/CI enforcement layers:
1. **Native Server-Side `pre-receive` Hook (`git-agecrypt check --pre-receive` + `examples/hooks/pre-receive`)** for self-hosted Git servers, Gitea, Forgejo, GitLab self-managed, and bare Git repositories.
2. **Hosted Git CI Enforcement (`git-agecrypt check --commit-range` + `examples/github-actions/agecrypt-verify.yml`)** for GitHub.com, GitLab.com, and environments where custom `pre-receive` hooks are not supported.

---

## 1. What Server & CI Enforcement Verifies

When `git-agecrypt check --pre-receive` or `git-agecrypt check --commit-range <RANGE>` runs, it inspects the Git object database directly (supporting **bare repositories** without a working tree) and enforces:

1. **No Plaintext Secrets on Protected Paths:** Every blob added, modified, or present in the target tip tree whose path matches a `filter=agecrypt` or `filter=agecrypt-<ring>` pattern in that commit's root or nested `<subdir>/.gitattributes` files MUST begin with a valid `age-encryption.org/v1\n` header.
2. **Valid `age` Ciphertext Header, Recipient Stanzas, and Active Key Match (When Unlocked):** Every protected ciphertext blob is parsed through `age::Decryptor` to confirm structurally valid recipient stanzas and header MAC framing (rejecting truncated or corrupted ciphertexts). When run in an unlocked repository where the local master key matches the commit's `repo.pub`, `check` also verifies that tip blobs decrypt under the active master key (rejecting stale/historical or foreign key ciphertexts).
3. **No Unprotected Secret Renames:** Renaming or copying a file from a path governed by `filter=agecrypt*` to a path not covered by `filter=agecrypt*` is rejected in both local (`--pre-push`) and server/CI (`--pre-receive`, `--commit-range`) enforcement modes.
4. **Shell-Safe Tracked Paths:** Paths containing `"`, `` ` ``, `$`, `\`, or control characters (`0x00..=0x1F`, `0x7F`) are rejected to prevent Git filter command-line shell injection.
5. **Ring & Metadata Consistency:**
   - Validates `.git-agecrypt/format` (and per-ring `format` files) against `FORMAT_VERSION = 1`.
   - Validates `.git-agecrypt/repo.pub` (and `.git-agecrypt/rings/<ring>/repo.pub`) as a valid `age1...` X25519 public key.
   - Validates every `.git-agecrypt/keys/*.age` (and `.git-agecrypt/rings/<ring>/keys/*.age`) recipient envelope header (`# public-key:`) and ASCII armor structure.
   - Verifies that every ring referenced in `.gitattributes` that protects files in the tree has a valid `repo.pub` and at least one valid `.age` recipient envelope.
6. **Untracked Secret Heuristics (unless `--allow-untracked-secrets` is passed):** Flags candidate secret filenames (`.env`, `*.secret.*`, `*.pem`, `*.key`, `secrets/**`) or PEM/AKIA credential markers committed as plaintext outside `.gitattributes`.

---

## 2. Deploying the Native Server-Side `pre-receive` Hook

### 2.1 Installation on a Bare Git Repository / Self-Hosted Server
1. Install the `git-agecrypt` binary on the Git server so it is available on `PATH`.
2. Copy [`examples/hooks/pre-receive`](file:///C:/Users/leonz/Desktop/git-agecrypt/examples/hooks/pre-receive) into your bare repository's `hooks/pre-receive` path:
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

On hosted platforms (such as GitHub.com) where custom bare-repository `pre-receive` hooks are unavailable on standard plans, copy [`examples/github-actions/agecrypt-verify.yml`](file:///C:/Users/leonz/Desktop/git-agecrypt/examples/github-actions/agecrypt-verify.yml) to `.github/workflows/agecrypt-verify.yml` and mark the job as a **Required Status Check** in branch protection rules.

```yaml
- name: Verify repository metadata format and health
  run: git-agecrypt inspect --format json

- name: Verify commits in pull request
  run: git-agecrypt check --commit-range "${{ github.event.pull_request.base.sha }}..${{ github.sha }}"
```

> [!WARNING]
> Unlike a server-side `pre-receive` hook—which rejects plaintext before objects enter the remote repository—a GitHub Action runs *after* a branch or PR ref is pushed to the remote. If a contributor pushes a plaintext secret to a PR branch and the CI check fails, the secret was still exposed to the remote repository's object database and **must be rotated immediately**.
