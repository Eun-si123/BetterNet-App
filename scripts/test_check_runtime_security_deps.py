"""Regression tests for runtime-only security dependency evidence."""
import io
import unittest
from unittest.mock import patch
from scripts.check_runtime_security_deps import vulnerable_entries, main


class RuntimeDependencyAuditTests(unittest.TestCase):
    def test_old_build_dependencies_are_rejected(self):
        text = ("debugRuntimeClasspath\n"
                "+--- org.bouncycastle:bcprov-jdk18on:1.80.2\n"
                "+--- io.netty:netty-handler:4.1.110.Final\n")
        found = vulnerable_entries(text)
        self.assertEqual(len(found), 2)

    def test_patched_selected_version_is_not_rejected(self):
        text = ("releaseRuntimeClasspath\n"
                "+--- org.bouncycastle:bcprov-jdk18on:1.80.2 -> 1.86 (*)\n"
                "+--- io.netty:netty-handler:4.1.110.Final -> 4.1.137.Final (*)")
        self.assertEqual(vulnerable_entries(text), [])

    def test_readme_or_random_text_does_not_appear_as_dependency(self):
        self.assertEqual(vulnerable_entries("README: vulnerability in a buildscript"), [])

    def test_exact_debug_runtime_configuration_header_passes(self):
        with patch("sys.argv", ["audit.py", "debugRuntimeClasspath"]), \
             patch("sys.stdin", io.StringIO("debugRuntimeClasspath - Runtime classpath of variant debug.\\nNo dependencies")):
            self.assertEqual(main(), 0)

    def test_mismatched_configuration_header_fails_closed(self):
        with patch("sys.argv", ["audit.py", "releaseRuntimeClasspath"]), \
             patch("sys.stdin", io.StringIO("debugRuntimeClasspath - Runtime classpath of variant debug.\\nNo dependencies")):
            self.assertEqual(main(), 1)

    def test_kotlin_stdlib_is_not_the_gradle_plugin(self):
        self.assertEqual(vulnerable_entries("+--- org.jetbrains.kotlin:kotlin-stdlib:2.2.10"), [])


if __name__ == "__main__":
    unittest.main()
