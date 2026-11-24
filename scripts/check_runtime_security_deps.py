#!/usr/bin/env python3
"""Reject currently vulnerable Gradle *build tool* dependencies if packaged as app runtime.

Run separately against debugRuntimeClasspath and releaseRuntimeClasspath.
This does not dismiss Dependabot's build-time findings, nor claim an APK exploit.
"""
from __future__ import annotations

import re
import sys

# Exact versions currently flagged in the trusted-main Dependabot graph.
# Keep strict exact guards instead of banning all legitimate patched libraries.
VULNERABLE = {
    "org.bouncycastle:bcprov-jdk18on": {"1.80.2", "1.79"},
    "org.bouncycastle:bcpkix-jdk18on": {"1.80.2", "1.79"},
    "com.google.guava:guava": {"33.4.0-jre", "33.3.1-jre"},
    "org.bitbucket.b_c:jose4j": {"0.9.5"},
    "org.jdom:jdom2": {"2.0.6"},
    "org.apache.commons:commons-lang3": {"3.16.0"},
    "org.apache.httpcomponents:httpclient": {"4.5.6"},
    "org.jetbrains.kotlin:kotlin-gradle-plugin": {"2.2.10", "2.2.21"},
}
COORD = re.compile(
    r"(?<![\w.-])(?P<group>[A-Za-z][\w.-]*):"
    r"(?P<artifact>[\w.-]+):(?P<requested>[\w.+-]+)"
    r"(?:\s*->\s*(?P<selected>[\w.+-]+))?"
)
NETTY = re.compile(r"^4\.1\.(\d+)\.Final$")


def vulnerable_entries(report: str) -> list[str]:
    errors = set()
    for line in report.splitlines():
        for match in COORD.finditer(line):
            key = match.group("group") + ":" + match.group("artifact")
            version = match.group("selected") or match.group("requested")
            if version in VULNERABLE.get(key, set()):
                errors.add(f"{key}:{version}")
            if key.startswith("io.netty:"):
                v = NETTY.fullmatch(version)
                if v and int(v.group(1)) < 137:
                    errors.add(f"{key}:{version}")
    return sorted(errors)


def main() -> int:
    report = sys.stdin.read()
    if "runtimeClasspath" not in report:
        print("::error::Missing runtimeClasspath evidence; refusing empty audit", file=sys.stderr)
        return 1
    if "BUILD FAILED" in report or "FAILED" in report:
        print("::error::Gradle dependency report signals failure", file=sys.stderr)
        return 1
    errors = vulnerable_entries(report)
    if errors:
        for e in errors:
            print("::error::Vulnerable runtime dependency " + e, file=sys.stderr)
        return 1
    print("Verified no currently known vulnerable build-tool versions in app runtime classpath")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
