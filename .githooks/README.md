# Secret scanning

This public repository scans committed secrets with Gitleaks v8.30.1 on pull requests, pushes to `main`, manual dispatches, and a weekly scheduled run. The CI action is pinned to a commit SHA and does not post potential secret values in PR comments, summary output, or downloadable reports.

## Local check (optional, but recommended)

1. Install [Gitleaks](https://github.com/gitleaks/gitleaks/releases) v8.30.1 or a compatible newer version on your machine.
2. Run `gitleaks git . --log-opts="--all" --redact=100` for committed history, and `gitleaks dir . --redact=100` to check uncommitted files. The latter scans the filesystem and may re-flag reviewed synthetic test values because history-specific fingerprints do not apply to a filesystem scan; inspect these carefully instead of suppressing whole test paths. Avoid placing unrelated private files under this repository.
3. To enable the versioned pre-push hook, first check `git config --local --get core.hooksPath`. If another hooks directory is configured, integrate the hook manually instead of overwriting it. Otherwise opt in with `git config --local core.hooksPath .githooks`. Git for Windows runs the shell hook via Git Bash. Without Gitleaks installed, the opted-in hook fails closed.

The hook checks Git history before publishing; it is not enabled merely by cloning the repository. GitHub Actions is a *post-push* safety net, so a leaked credential is public as soon as it reaches GitHub.

## If a finding appears

- Never paste the secret or its full scan log into a public issue, pull request, or chat.
- Check whether it is a real credential or synthetic test data. For real credentials, **revoke/rotate first**; deleting the file does not erase Git history.
- The `.gitleaksignore` file (when present) holds only full, reviewed historical test-fixture fingerprints. Do not add broad path/rule/regex exclusions or baseline newly exposed credentials merely to turn CI green.
- Do not assume passing Gitleaks proves there are no secrets: custom credentials, issue comments, CI logs, archives, and untracked files may need separate review.
