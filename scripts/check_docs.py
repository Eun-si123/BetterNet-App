#!/usr/bin/env python3
"""Offline local Markdown link check for public BetterNet documentation.

No network, credentials, APKs, or dependencies. External URLs are intentionally
out of scope; this check validates that relative project files exist and cannot
escape the provided repository root. Run from any working directory.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

# Markdown links; ignore fenced source code. Angle-wrapped destinations and
# external web anchors are supported; dynamic/reference-style links are not.
LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\((<[^>\n]+>|[^\s)>]+)(?:\s+[\x27\x22][^\n]*[\x27\x22])?\)")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def documents(root: Path) -> list[Path]:
    selected = [root / "README.md", root / "AGENTS.md"]
    selected += list((root / "docs").rglob("*.md")) if (root / "docs").is_dir() else []
    selected += list((root / "gateway").rglob("*.md")) if (root / "gateway").is_dir() else []
    return sorted(set(path for path in selected if path.is_file()))


def check(root: Path) -> list[str]:
    root = root.resolve()
    failures: list[str] = []
    for doc in documents(root):
        active_fence: str | None = None
        for line_number, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            opening = FENCE.match(line)
            if opening:
                marker = opening.group(1)
                if active_fence is None:
                    active_fence = marker
                elif (marker[0] == active_fence[0] and len(marker) >= len(active_fence)
                      and not line[opening.end(1):].strip()):
                    # A language tag after the marker is not a closing fence.
                    active_fence = None
                continue
            if active_fence is not None:
                continue
            for match in LINK.finditer(line):
                raw = match.group(1).strip("<>")
                if raw.startswith("#"):
                    continue  # Local fragment without file path.
                url = urlsplit(raw)
                if url.scheme or url.netloc:
                    continue  # External HTTP(S), mailto, etc: no network I/O.
                local_name = unquote(url.path)
                if not local_name:
                    continue
                if local_name.startswith("/"):
                    failures.append(f"{doc.relative_to(root)}:{line_number}: absolute path: {raw}")
                    continue
                target = (doc.parent / local_name).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    failures.append(f"{doc.relative_to(root)}:{line_number}: escapes repository: {raw}")
                    continue
                if not target.is_file():
                    failures.append(f"{doc.relative_to(root)}:{line_number}: broken local link: {raw}")
    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    errors = check(root)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"FAIL: {len(errors)} documentation link(s) invalid", file=sys.stderr)
        return 1
    print(f"PASS: local links in {len(documents(root.resolve()))} Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
