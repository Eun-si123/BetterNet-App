#!/usr/bin/env python3
"""Check the *resolved* Netty versions used by the Gradle plugin build classpath.

Usage: ./gradlew buildEnvironment :app:buildEnvironment | python3 scripts/check_gradle_classpath.py
A requested old version shown as "4.1.110.Final -> 4.1.137.Final" is safe;
an actual *selected* old version is not. Missing evidence fails closed.
"""
from __future__ import annotations

import re
import sys

# Gradle indented dependency tree lines, including transitive and cached nodes.
NETTY = re.compile(
    r"io\.netty:(netty-[a-z0-9-]+):"
    r"(4\.1\.\d+\.Final)"
    r"(?:\s*->\s*(4\.1\.\d+\.Final))?"
)
PATCHED_VERSION = "4.1.137.Final"
CRITICAL_MODULES = frozenset({
    "netty-handler", "netty-codec-http", "netty-codec-http2",
    "netty-codec", "netty-common",
})


def check_versions(report: str) -> list[str]:
    found: dict[str, set[str]] = {}
    for line in report.splitlines():
        for match in NETTY.finditer(line):
            name, requested, selected = match.groups()
            found.setdefault(name, set()).add(selected or requested)

    problems = []
    missing = CRITICAL_MODULES - found.keys()
    if missing:
        problems.append("No classpath evidence for: " + ", ".join(sorted(missing)))
    for name, versions in sorted(found.items()):
        if versions != {PATCHED_VERSION}:
            problems.append(f"{name}: resolved {', '.join(sorted(versions))}; expected {PATCHED_VERSION}")
    if not found:
        problems.append("No Netty modules detected in Gradle buildEnvironment output")
    return problems


def main() -> int:
    text = sys.stdin.read()
    errors = check_versions(text)
    if errors:
        for problem in errors:
            print("::error::" + problem, file=sys.stderr)
        return 1
    print(f"Verified all resolved Gradle plugin Netty modules at {PATCHED_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
