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



# Vulnerable transitive AGP and Android-testing dependencies, *not* app runtime.
# Versions are selected from current GitHub advisories and compatible stable releases.
OTHER_PATCHES = {
    "org.bouncycastle:bcprov-jdk18on": "1.86",
    "org.bouncycastle:bcpkix-jdk18on": "1.86",
    "org.bouncycastle:bcutil-jdk18on": "1.86",
    "org.bitbucket.b_c:jose4j": "0.9.6",
    "org.jdom:jdom2": "2.0.6.1",
    "org.apache.commons:commons-compress": "1.26.0",
    "com.google.guava:guava": "33.7.2-jre",
}
OTHER_PATTERN = re.compile(
    r"(?P<module>org\.bouncycastle:(?:bcprov|bcpkix|bcutil)-jdk18on"
    r"|org\.bitbucket\.b_c:jose4j|org\.jdom:jdom2"
    r"|org\.apache\.commons:commons-compress|com\.google\.guava:guava):"
    r"(?P<requested>[0-9][\w.+-]*)(?:\s*->\s*(?P<selected>[0-9][\w.+-]*))?"
)


def check_other_patches(report: str) -> list[str]:
    resolved: dict[str, set[str]] = {}
    for line in report.splitlines():
        for match in OTHER_PATTERN.finditer(line):
            module = match.group("module")
            version = match.group("selected") or match.group("requested")
            resolved.setdefault(module, set()).add(version)
    errors = []
    for module, expected in sorted(OTHER_PATCHES.items()):
        versions = resolved.get(module)
        if not versions:
            errors.append(f"No build classpath evidence for: {module}")
        elif versions != {expected}:
            errors.append(
                f"{module}: resolved {', '.join(sorted(versions))}; expected {expected}"
            )
    return errors


def main() -> int:
    text = sys.stdin.read()
    errors = check_versions(text) + check_other_patches(text)
    if errors:
        for problem in errors:
            print("::error::" + problem, file=sys.stderr)
        return 1
    print(f"Verified resolved Netty and other Gradle plugin dependency patches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
