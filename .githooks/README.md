# Secret scanning

GitHub checks proposed commits in pull requests **targeting `main`**, pushes to `main`, manual dispatches and weekly runs. The PR workflow runs from the trusted base branch (`pull_request_target`) and treats proposed source as **data only**: it must never execute PR scripts or grant write permissions. Its Gitleaks v8.30.1 CLI archive is verified against an official pinned SHA-256. It reads allowlisted historical synthetic fixtures only from the **trusted base**, using explicit pinned default detection rules. Pull requests cannot bypass scanning by editing their own `.gitleaks.toml`, `.gitleaksignore`, or workflow.

## Optional local pre-push guard

1. Install [Gitleaks](https://github.com/gitleaks/gitleaks/releases), ideally v8.30.1.
2. Run `gitleaks git . --log-opts="--all" --redact=100` for committed history. Run `gitleaks dir . --redact=100` for worktree files (synthetic test fixtures can cause false positives in directory mode; assess rather than broadly suppress).
3. Check `git config --local --get core.hooksPath`. If it is unset, opt in with `git config --local core.hooksPath .githooks`. If already configured, integrate manually rather than overwriting existing hooks.

The hook also reads Git's pre-push standard input to scan **explicit pushed commits outside ordinary local refs**. Without Gitleaks installed the opt-in hook fails closed. It does not run automatically after cloning. Windows Git Bash supports the `sh` hook.

## If a finding appears

Never paste the detected value in a public issue/PR/log. Verify whether it is a real live credential or a synthetic fixture. Revoke and rotate actual exposed credentials immediately; removing a line does not remove it from history. Do not add broad rule/path exceptions merely to make CI green.

A green scan does not certify absence of secrets in custom formats, untracked files, issue comments, runner logs or archives. GitHub PR checks run after PR commits have been sent to GitHub; the local hook helps avoid public exposure before Push when deliberately enabled.
