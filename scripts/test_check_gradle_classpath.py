"""Safety regressions for Gradle resolved dependency output parsing."""
import unittest
from scripts.check_gradle_classpath import (check_versions, check_other_patches, OTHER_PATCHES, CRITICAL_MODULES, PATCHED_VERSION)


def example(version: str, replacement: str | None = None) -> str:
    return "\n".join(
        f"+--- io.netty:{module}:{version}"
        + (f" -> {replacement} (*)" if replacement else " (*)")
        for module in sorted(CRITICAL_MODULES)
    )


class TestNettyBuildscriptClasspath(unittest.TestCase):
    def test_all_fixed(self):
        self.assertEqual(check_versions(example(PATCHED_VERSION)), [])

    def test_original_transitive_version_is_allowed_when_resolved_fixed(self):
        self.assertEqual(check_versions(example("4.1.110.Final", PATCHED_VERSION)), [])

    def test_unfixed_resolved_version_is_rejected(self):
        self.assertTrue(check_versions(example("4.1.110.Final")))

    def test_missing_modules_are_rejected(self):
        self.assertTrue(check_versions("No dependencies"))

    def test_mixed_resolved_versions_are_rejected(self):
        self.assertTrue(check_versions(example(PATCHED_VERSION) + "\n+--- io.netty:netty-handler:4.1.110.Final"))


class TestOtherBuildscriptPatches(unittest.TestCase):
    def report(self, use_old=False):
        lines = []
        for module, patched in OTHER_PATCHES.items():
            original = "1.79" if module.startswith("org.bouncycastle:") else (
                "0.9.5" if module.endswith("jose4j") else (
                    "2.0.6" if module.endswith("jdom2") else (
                        "1.21" if module.endswith("commons-compress") else "33.3.1-jre"
                    )
                )
            )
            lines.append(f"+--- {module}:{original} -> {patched} (*)")
        return "\n".join(lines)

    def test_patched_all_seven(self):
        self.assertEqual(check_other_patches(self.report()), [])

    def test_missing_evidence_rejected(self):
        self.assertTrue(check_other_patches("No dependencies"))

    def test_unpatched_selected_version_rejected(self):
        report = self.report().replace("1.79 -> 1.86", "1.79", 1)
        self.assertTrue(check_other_patches(report))



if __name__ == "__main__":
    unittest.main()
