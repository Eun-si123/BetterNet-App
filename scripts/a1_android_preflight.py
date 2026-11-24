#!/usr/bin/env python3
"""Read-only A1 Android debugging preflight. Never starts a VPN or sends tokens.

Usage:
  python scripts/a1_android_preflight.py
  python scripts/a1_android_preflight.py --adb /path/to/adb --serial DEVICE

A PASS here only makes a device eligible for *manual, owner-approved* A1 tests.
It never proves routed HTTPS, selected-app isolation or zero data charges.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from collections.abc import Callable

PACKAGE = "io.betternet.next"
MIN_ANDROID_API = 26


def find_adb(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit  # Fail visibly if not present; do not silently use another binary.
    command = shutil.which("adb")
    if command:
        return command
    name = "adb.exe" if os.name == "nt" else "adb"
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        folder = os.environ.get(variable)
        if folder:
            path = Path(folder) / "platform-tools" / name
            if path.is_file():
                return str(path)
    return None


def parse_devices(output: str) -> list[tuple[str, str]]:
    """No serial appears in user-facing output; only use it in adb -s arguments."""
    parsed: list[tuple[str, str]] = []
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) >= 2 and fields[1] in ("device", "offline", "unauthorized", "recovery", "sideload"):
            parsed.append((fields[0], fields[1]))
    return parsed


def evaluate(
    adb: str | None, serial: str | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[bool, list[str]]:
    messages: list[str] = []
    if not adb:
        return False, ["BLOCKED: adb executable not found (install Android platform-tools)."]

    def command(parts: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return run(
                [adb] + parts,
                capture_output=True, text=True, timeout=12, check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

    found = command(["devices"])
    if found is None or found.returncode != 0:
        return False, ["BLOCKED: adb devices failed or timed out."]
    devices = parse_devices(found.stdout)
    authorized = [device for device, state in devices if state == "device"]
    if serial is not None:
        if not any(device == serial for device in authorized):
            return False, ["BLOCKED: requested device is not authorized and online."]
        selected = serial
    elif len(authorized) != 1:
        return False, [
            "BLOCKED: expected exactly one authorized online device; "
            "offline/unauthorized devices do not qualify. Use --serial when needed."
        ]
    else:
        selected = authorized[0]
    messages.append("PASS: one explicitly selected, authorized ADB device (serial redacted).")

    def shell(*parts: str) -> subprocess.CompletedProcess[str] | None:
        return command(["-s", selected, "shell", *parts])

    sdk = shell("getprop", "ro.build.version.sdk")
    if sdk is None or sdk.returncode != 0 or not sdk.stdout.strip().isdigit():
        return False, messages + ["BLOCKED: Android SDK level could not be verified."]
    sdk_level = int(sdk.stdout.strip())
    if sdk_level < MIN_ANDROID_API:
        return False, messages + [f"BLOCKED: Android API {sdk_level} is below minSdk {MIN_ANDROID_API}."]
    messages.append(f"PASS: Android API {sdk_level} (meets minSdk {MIN_ANDROID_API}).")

    installed = shell("pm", "path", PACKAGE)
    if installed is None or installed.returncode != 0 or not any(
        line.startswith("package:") for line in installed.stdout.splitlines()
    ):
        return False, messages + ["BLOCKED: BetterNet debug APK not installed under expected package."]
    messages.append("PASS: BetterNet application package installed.")

    # run-as succeeds for a normal debuggable app and fails for release builds.
    # Do not inspect app data, private files, APK signatures or global logs.
    debuggable = shell("run-as", PACKAGE, "id")
    if debuggable is None or debuggable.returncode != 0 or "uid=" not in debuggable.stdout:
        return False, messages + [
            "BLOCKED: debuggable app identity not confirmed (release or OEM policy)."
        ]
    messages.append("PASS: Android run-as confirms a debuggable test package.")
    messages.append(
        "A1 DEVICE RESULT: NOT RUN. This preflight never requests VPN consent, "
        "opens a route, connects to a gateway, or transmits credentials."
    )
    return True, messages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=None, help="explicit adb binary (optional)")
    parser.add_argument("--serial", default=None, help="device selector, never printed")
    args = parser.parse_args(argv)
    ready, lines = evaluate(find_adb(args.adb), serial=args.serial)
    for line in lines:
        print(line)
    if not ready:
        print("A1 DEVICE RESULT: NOT RUN (BLOCKED). No VPN or network test was executed.")
    return 0 if ready else 2


if __name__ == "__main__":
    sys.exit(main())
