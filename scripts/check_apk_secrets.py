#!/usr/bin/env python3
"""Conservative, bounded detector for high-confidence credentials inside built APKs.

Scans *decompressed APK entries*, not just the ZIP bytes. It does not claim to
detect every secret; findings report an entry name and signature only, never
the credential itself.
"""
from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

CHUNK = 1024 * 1024
OVERLAP = 256
MAX_ENTRY = 128 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_ENTRIES = 20000

SIGNATURES = (
    ("OpenAI private token", re.compile(rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b")),
    ("Stripe private token", re.compile(rb"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("GitHub private token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("Resend private token", re.compile(rb"\bre_[A-Za-z0-9]{30,}\b")),
    ("AWS access key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("PEM private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


class ScanError(Exception):
    """APK inspection could not be completed safely."""


def inspect_apk(path: Path) -> list[tuple[str, str]]:
    if not path.is_file():
        raise ScanError("APK is missing or is not a regular file")
    findings = []
    try:
        with zipfile.ZipFile(path) as apk:
            entries = apk.infolist()
            if len(entries) > MAX_ENTRIES or any(
                entry.file_size > MAX_ENTRY for entry in entries
            ) or sum(entry.file_size for entry in entries) > MAX_ARCHIVE:
                raise ScanError("APK exceeds bounded inspection limits")
            for entry in entries:
                if entry.is_dir():
                    continue
                matches = set()
                with apk.open(entry) as stream:
                    tail = b""
                    while True:
                        data = stream.read(CHUNK)
                        if not data:
                            break
                        segment = tail + data
                        for name, pattern in SIGNATURES:
                            if name not in matches and pattern.search(segment):
                                matches.add(name)
                        tail = segment[-OVERLAP:]
                findings.extend((entry.filename, name) for name in sorted(matches))
    except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ScanError("APK could not be fully inspected") from exc
    return findings


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: check_apk_secrets.py PATH_TO_APK", file=sys.stderr)
        return 2
    try:
        findings = inspect_apk(Path(argv[1]))
    except ScanError as exc:
        print("APK secret inspection failed: " + str(exc), file=sys.stderr)
        return 2
    for entry, signature in findings:
        print(f"Potential embedded credential ({signature}) in {entry!r}", file=sys.stderr)
    if findings:
        print(f"Blocked: {len(findings)} potential credential signature(s).", file=sys.stderr)
        return 1
    print("APK high-confidence credential signature scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
