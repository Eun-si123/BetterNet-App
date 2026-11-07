"""Independent negative/positive cases for the offline docs-link checker."""

import tempfile
import unittest
from pathlib import Path

from check_docs import check


class MarkdownLinkChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_text("# Test\n")

    def test_valid_relative_and_remote_links(self):
        (self.root / "docs" / "plan.md").write_text(
            "[root](../README.md) [external](https://example.org/any) [anchor](#start)\n"
        )
        self.assertEqual([], check(self.root))

    def test_broken_relative_link_is_rejected(self):
        (self.root / "docs" / "plan.md").write_text("[missing](nonexistent.md)\n")
        self.assertTrue(any("broken local link" in x for x in check(self.root)))

    def test_repository_escape_is_rejected(self):
        (self.root / "docs" / "plan.md").write_text("[escape](../../secret.md)\n")
        self.assertTrue(any("escapes repository" in x for x in check(self.root)))

    def test_fenced_fake_link_is_ignored(self):
        (self.root / "docs" / "plan.md").write_text(
            "```markdown\n[illustration](not-a-file.md)\n```\n"
        )
        self.assertEqual([], check(self.root))

    def test_percent_encoded_nonexistent_target_is_rejected(self):
        (self.root / "docs" / "plan.md").write_text("[bad](missing%20file.md)\n")
        self.assertTrue(any("broken local link" in x for x in check(self.root)))


if __name__ == "__main__":
    unittest.main()
