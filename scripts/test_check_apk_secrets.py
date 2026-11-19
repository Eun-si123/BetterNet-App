"""Regression fixtures for scanning packaged, decompressed APK content."""
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_apk_secrets import ScanError, inspect_apk, main


class ApkSecretScanTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.workdir.cleanup)
        self.apk = Path(self.workdir.name) / "sample.apk"

    def make_apk(self, content):
        with zipfile.ZipFile(self.apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("assets/config.json", content)

    def test_clean_apk(self):
        self.make_apk(b'{"debug": false, "endpoint": "https://example.invalid"}')
        self.assertEqual(inspect_apk(self.apk), [])
        self.assertEqual(main(["check_apk_secrets.py", str(self.apk)]), 0)

    def test_secret_inside_compressed_entry(self):
        self.make_apk(b'{"key":"' + b"sk_live_" + b"A" * 32 + b'"}')
        self.assertEqual(
            inspect_apk(self.apk), [("assets/config.json", "Stripe private token")]
        )
        self.assertEqual(main(["check_apk_secrets.py", str(self.apk)]), 1)

    def test_secret_split_across_read_boundary(self):
        prefix = b"." * (1024 * 1024 - 5)
        self.make_apk(prefix + b"sk-proj-" + b"Q" * 40 + b" ")
        self.assertIn(
            ("assets/config.json", "OpenAI private token"), inspect_apk(self.apk)
        )

    def test_missing_or_corrupt_apk_fails_closed(self):
        with self.assertRaises(ScanError):
            inspect_apk(self.apk)
        self.apk.write_bytes(b"not a zip")
        with self.assertRaises(ScanError):
            inspect_apk(self.apk)
        self.assertEqual(main(["check_apk_secrets.py", str(self.apk)]), 2)


if __name__ == "__main__":
    unittest.main()
