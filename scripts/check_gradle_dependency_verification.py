#!/usr/bin/env python3
"""Audit Gradle SHA-256 verification policy; not a vulnerability scanner."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

NS = "{https://schema.gradle.org/dependency-verification}"
HEX64 = re.compile(r"[0-9a-f]{64}$")


def validate(path: Path, minimum: int = 50) -> list[str]:
    if not path.is_file():
        return ["Missing verification-metadata.xml"]
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        return [f"Invalid XML: {e}"]
    if root.tag != NS + "verification-metadata":
        return ["Unexpected Gradle metadata namespace"]
    errors: list[str] = []
    if root.findtext(NS + "configuration/" + NS + "verify-metadata") != "true":
        errors.append("Metadata verification is disabled")
    if root.findall(".//" + NS + "trusted-artifacts"):
        errors.append("Broad trusted-artifacts bypass is forbidden")
    components = root.find(NS + "components")
    if components is None or len(components) < minimum:
        return errors + ["Dependency metadata is empty or incomplete"]
    seen: set[tuple[str, str, str]] = set()
    hashes = 0
    for c in components:
        coord = tuple(c.attrib.get(k, "") for k in ("group", "name", "version"))
        if not all(coord) or coord in seen:
            errors.append(f"Invalid or duplicated component: {coord}")
        seen.add(coord)
        for artifact in c.findall(NS + "artifact"):
            entries = artifact.findall(NS + "sha256")
            if len(entries) != 1 or not HEX64.fullmatch(entries[0].get("value", "") if entries else ""):
                errors.append(f"Invalid SHA-256 entry: {coord}")
            hashes += len(entries)
    if hashes < minimum:
        errors.append("Missing artifact SHA-256 entries")
    if not any(g == "com.android.tools.build" and n == "gradle" for g, n, _ in seen):
        errors.append("Android Gradle Plugin missing from verification list")
    return errors


def main() -> int:
    errors = validate(Path("gradle/verification-metadata.xml"))
    for error in errors:
        print("::error::" + error, file=sys.stderr)
    if errors:
        return 1
    print("Gradle dependency SHA-256 verification policy validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
