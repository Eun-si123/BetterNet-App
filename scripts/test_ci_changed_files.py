"""Regression tests for fail-open docs-only CI change classification."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.ci_changed_files import needs_heavy_validation


class ChangeScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "CI Test")
        (self.repo / "README.md").write_text("one\n", encoding="utf-8")
        (self.repo / "sample.py").write_text("print(1)\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "initial")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()

    def commit(self, filename, content):
        p = self.repo / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "update")
        return self.git("rev-parse", "HEAD")

    def test_markdown_only_pr_and_push_skip_heavy(self):
        head = self.commit("docs/roadmap.md", "new document\n")
        self.assertFalse(needs_heavy_validation(
            "pull_request", self.base, head, "", self.repo))
        self.assertFalse(needs_heavy_validation(
            "push", "", head, self.base, self.repo))

    def test_mixed_markdown_and_code_still_runs(self):
        self.commit("README.md", "two\n")
        head = self.commit("sample.py", "print(2)\n")
        self.assertTrue(needs_heavy_validation(
            "pull_request", self.base, head, "", self.repo))

    def test_workflow_or_manual_or_unsupported_event_runs(self):
        head = self.commit(".github/workflows/ci.yml", "name: check\n")
        self.assertTrue(needs_heavy_validation(
            "pull_request", self.base, head, "", self.repo))
        self.assertTrue(needs_heavy_validation(
            "workflow_dispatch", self.base, head, "", self.repo))
        self.assertTrue(needs_heavy_validation(
            "schedule", self.base, head, "", self.repo))

    def test_missing_history_empty_and_untrusted_range_run(self):
        self.assertTrue(needs_heavy_validation(
            "pull_request", self.base, self.base, "", self.repo))
        self.assertTrue(needs_heavy_validation(
            "push", "", self.base, "0" * 40, self.repo))
        self.assertTrue(needs_heavy_validation(
            "pull_request", "not-a-commit", self.base, "", self.repo))

    def test_non_ancestor_push_fails_open(self):
        head = self.commit("README.md", "two\n")
        self.assertTrue(needs_heavy_validation(
            "push", "", self.base, head, self.repo))


if __name__ == "__main__":
    unittest.main()
