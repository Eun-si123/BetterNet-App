import subprocess
import unittest

from a1_android_preflight import evaluate, parse_devices


class FakeAdb:
    def __init__(self, devices, sdk="35", package=True, debuggable=True):
        self.devices = devices
        self.sdk = sdk
        self.package = package
        self.debuggable = debuggable
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[1:] == ["devices"]:
            return subprocess.CompletedProcess(command, 0, self.devices, "")
        args = command[1:]
        if args[0:3] != ["-s", args[1], "shell"]:
            raise AssertionError("Only exactly scoped read-only device shell operations permitted")
        operation = args[3:]
        if operation == ["getprop", "ro.build.version.sdk"]:
            return subprocess.CompletedProcess(command, 0, self.sdk, "")
        if operation == ["pm", "path", "io.betternet.next"]:
            return subprocess.CompletedProcess(
                command, 0 if self.package else 1,
                "package:/data/app/safe/base.apk\n" if self.package else "", ""
            )
        if operation == ["run-as", "io.betternet.next", "id"]:
            return subprocess.CompletedProcess(
                command, 0 if self.debuggable else 1,
                "uid=10055(app)" if self.debuggable else "", ""
            )
        raise AssertionError(f"Unexpected ADB operation: {operation}")


class TestAndroidA1Preflight(unittest.TestCase):
    def test_parse_device_records_without_forwarding_untrusted_lines(self):
        devices = parse_devices(
            "List of devices attached\n\nabc\tdevice product:x\n"
            "def\tunauthorized\nxyz\toffline\n* daemon started\n"
        )
        self.assertEqual([("abc", "device"), ("def", "unauthorized"), ("xyz", "offline")],
                         devices)

    def test_suitable_debug_phone_does_not_start_vpn_or_read_tokens(self):
        fake = FakeAdb("List of devices attached\nSERIAL-SECRET\tdevice\n")
        ready, messages = evaluate("adb", run=fake)
        self.assertTrue(ready, messages)
        self.assertTrue(any("NOT RUN" in line for line in messages))
        self.assertFalse(any("SERIAL-SECRET" in line for line in messages))
        allowed = (
            ["getprop", "ro.build.version.sdk"],
            ["pm", "path", "io.betternet.next"],
            ["run-as", "io.betternet.next", "id"],
        )
        self.assertEqual(4, len(fake.calls))
        self.assertEqual(["adb", "devices"], fake.calls[0])
        self.assertTrue(all(command[0:4] == ["adb", "-s", "SERIAL-SECRET", "shell"]
                            and command[4:] in allowed for command in fake.calls[1:]))

    def test_multiple_devices_requires_explicit_selector(self):
        fake = FakeAdb("List of devices attached\nA\tdevice\nB\tdevice\n")
        ready, lines = evaluate("adb", run=fake)
        self.assertFalse(ready)
        self.assertEqual(1, len(fake.calls))
        ready, lines = evaluate("adb", serial="B", run=fake)
        self.assertTrue(ready, lines)
        self.assertFalse(any("serial B" in line for line in lines))

    def test_offline_unauthorized_or_missing_devices_block_before_shell(self):
        for devices in (
            "List of devices attached\n",
            "List of devices attached\nB\toffline\n",
            "List of devices attached\nC\tunauthorized\n",
        ):
            with self.subTest(devices=devices):
                fake = FakeAdb(devices)
                ready, _ = evaluate("adb", run=fake)
                self.assertFalse(ready)
                self.assertEqual(1, len(fake.calls))

    def test_wrong_selector_cannot_use_other_connected_phone(self):
        fake = FakeAdb("List of devices attached\nA\tdevice\nB\toffline\n")
        ready, _ = evaluate("adb", serial="B", run=fake)
        self.assertFalse(ready)
        self.assertEqual(1, len(fake.calls))

    def test_missing_apk_release_build_and_old_android_block(self):
        cases = [
            dict(sdk="25", package=True, debuggable=True),
            dict(sdk="35", package=False, debuggable=True),
            dict(sdk="35", package=True, debuggable=False),
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                fake = FakeAdb("List of devices attached\nA\tdevice\n", **overrides)
                ready, lines = evaluate("adb", run=fake)
                self.assertFalse(ready)
                self.assertTrue(lines[-1].startswith("BLOCKED:"))

    def test_missing_adb_blocks_without_executing_anything(self):
        ready, lines = evaluate(None)
        self.assertFalse(ready)
        self.assertIn("adb executable", lines[0])


if __name__ == "__main__":
    unittest.main()
