#!/usr/bin/env python3
"""Fail-open GitHub Actions path classifier: skip heavy CI only for Markdown-only diffs.

The caller must checkout with fetch-depth: 0. If the event, commit range, or
Git graph cannot be proven, full validation remains mandatory.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=root, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=False,
    )


def needs_heavy_validation(
    event: str, base: str, head: str, before: str, root: Path,
) -> bool:
    """True unless a verifiable non-empty diff consists only of *.md files."""
    if event == "pull_request":
        start = base
    elif event == "push":
        start = before
    else:  # workflow_dispatch, schedule, unknown events: full coverage
        return True

    if not _SHA.fullmatch(start or "") or not _SHA.fullmatch(head or ""):
        return True
    if _git(root, "cat-file", "-e", f"{start}^{{commit}}").returncode:
        return True
    if _git(root, "cat-file", "-e", f"{head}^{{commit}}").returncode:
        return True
    if event == "push" and _git(
        root, "merge-base", "--is-ancestor", start, head
    ).returncode:
        return True

    result = _git(root, "diff", "--name-only", "-z", start, head)
    if result.returncode:
        return True
    paths = [p for p in result.stdout.split(b"\0") if p]
    if not paths:
        return True
    return any(not path.lower().endswith(b".md") for path in paths)


def main() -> None:
    heavy = needs_heavy_validation(
        os.environ.get("GITHUB_EVENT_NAME", ""),
        os.environ.get("PR_BASE_SHA", ""),
        os.environ.get("PR_HEAD_SHA", "") or os.environ.get("GITHUB_SHA", ""),
        os.environ.get("PUSH_BEFORE_SHA", ""),
        Path.cwd(),
    )
    choice = "true" if heavy else "false"
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write(f"heavy={choice}\n")
    print(f"Heavy code tests: {choice} (unknown ranges fail open)")


if __name__ == "__main__":
    main()
