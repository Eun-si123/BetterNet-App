"""Regression tests for Gradle verification SHA-256 policy."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts.check_gradle_dependency_verification import validate

NS = "https://schema.gradle.org/dependency-verification"


def sample(hash_value="a" * 64, verified="true", extra="", group="com.android.tools.build"):
    return f"""<verification-metadata xmlns="{NS}">
<configuration><verify-metadata>{verified}</verify-metadata></configuration>
{extra}
<components><component group="{group}" name="gradle" version="9.4.0">
<artifact name="gradle.pom"><sha256 value="{hash_value}"/></artifact>
</component></components></verification-metadata>"""


class VerificationTests(TestCase):
    def inspect(self, xml):
        with TemporaryDirectory() as tmp:
            file = Path(tmp) / "v.xml"
            file.write_text(xml, encoding="utf-8")
            return validate(file, minimum=1)

    def test_valid_sample(self):
        self.assertEqual(self.inspect(sample()), [])

    def test_modified_hash_rejected(self):
        self.assertTrue(self.inspect(sample(hash_value="invalid")))

    def test_disabled_verification_rejected(self):
        self.assertTrue(self.inspect(sample(verified="false")))

    def test_trusted_artifact_bypass_rejected(self):
        self.assertTrue(self.inspect(sample(extra="<trusted-artifacts/>")))

    def test_missing_android_plugin_rejected(self):
        self.assertTrue(self.inspect(sample(group="example")))

    def test_missing_file_rejected(self):
        with TemporaryDirectory() as tmp:
            self.assertTrue(validate(Path(tmp) / "none.xml", minimum=1))
