#!/usr/bin/env python3
"""Fail CI if the dormant VPN can be selected as an always-on VPN.

Check Android Gradle Plugin's merged manifest, not just the source manifest:
library manifests and build variants can change the final service metadata.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"
SERVICE = "io.betternet.next.SelectedAppVpnService"
ALWAYS_ON = "android.net.VpnService.SUPPORTS_ALWAYS_ON"


def is_opted_out(manifest: Path) -> bool:
    root = ET.parse(manifest).getroot()
    services = [
        service for service in root.findall(".//service")
        if service.get(ANDROID + "name") in (SERVICE, ".SelectedAppVpnService")
    ]
    if len(services) != 1:
        return False
    settings = [
        entry.get(ANDROID + "value")
        for entry in services[0].findall("meta-data")
        if entry.get(ANDROID + "name") == ALWAYS_ON
    ]
    return settings == ["false"]


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: verify-vpn-manifest.py <AGP intermediates directory>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    # AGP uses either merged_manifests or merged_manifest by version.
    manifests = [
        p for p in root.rglob("AndroidManifest.xml")
        if any(part in ("merged_manifests", "merged_manifest") for part in p.parts)
        and "debug" in p.parts
    ]
    if not manifests:
        print("FAIL: no debug merged manifest found", file=sys.stderr)
        return 1
    for manifest in manifests:
        if not is_opted_out(manifest):
            print(f"FAIL: dormant VPN always-on opt-out absent: {manifest}", file=sys.stderr)
            return 1
    print(f"PASS: always-on disabled in {len(manifests)} debug merged manifest(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
