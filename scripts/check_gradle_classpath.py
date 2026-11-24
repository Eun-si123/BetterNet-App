#!/usr/bin/env python3
"""Check the *resolved* Netty versions used by the Gradle plugin build classpath.

Usage: ./gradlew buildEnvironment :app:buildEnvironment | python3 scripts/check_gradle_classpath.py
A requested old version shown as "4.1.110.Final -> 4.1.137.Final" is safe;
an actual *selected* old version is not. Missing evidence fails closed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

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


def check_versions(report: str, *, allow_no_netty: bool = False) -> list[str]:
    found: dict[str, set[str]] = {}
    for line in report.splitlines():
        for match in NETTY.finditer(line):
            name, requested, selected = match.groups()
            found.setdefault(name, set()).add(selected or requested)

    if not found and allow_no_netty:
        return []

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
    # AGP 9+ no longer has the previous Netty-bearing gRPC plugin graph.
    # In this case, *absence* is the desired classpath result, not a failure.
    # Keep rejecting missing evidence for AGP 8.x and any older plugin.
    build = Path('build.gradle.kts').read_text(encoding='utf-8')
    agp = re.search(r'id\("com\.android\.application"\)\s+version\s+"(\d+)\.', build)
    if not agp:
        print('::error::Cannot identify Android Gradle Plugin major', file=sys.stderr)
        return 1
    agp_major = int(agp.group(1))
    errors = check_versions(text, allow_no_netty=agp_major >= 9)
    if errors:
        for problem in errors:
            print("::error::" + problem, file=sys.stderr)
        return 1
    print(f"Verified Gradle plugin Netty classpath policy for AGP {agp_major}: "
          f"either absent (AGP 9+) or all resolved modules at {PATCHED_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
