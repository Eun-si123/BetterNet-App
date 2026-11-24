"""Safety regressions for Gradle resolved dependency output parsing."""
import unittest
from scripts.check_gradle_classpath import check_versions, CRITICAL_MODULES, PATCHED_VERSION


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


if __name__ == "__main__":
    unittest.main()
