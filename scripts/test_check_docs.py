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

    def test_broken_angle_wrapped_link_with_spaces_is_rejected(self):
        (self.root / "docs" / "plan.md").write_text(
            "[missing](<missing local file.md>)\n"
        )
        self.assertTrue(any("broken local link" in x for x in check(self.root)))

    def test_existing_angle_wrapped_link_with_spaces_is_valid(self):
        (self.root / "docs" / "existing local file.md").write_text("OK\n")
        (self.root / "docs" / "plan.md").write_text(
            "[present](<existing local file.md>)\n"
        )
        self.assertEqual([], check(self.root))

    def test_backtick_language_tag_cannot_close_code_fence(self):
        fence = chr(96) * 3
        (self.root / "docs" / "plan.md").write_text(
            f"{fence}text\n[illustration](fake1.md)\n"
            f"{fence}python\n[illustration](fake2.md)\n"
            f"{fence}\n[missing](real-missing.md)\n"
        )
        problems = check(self.root)
        self.assertEqual(1, len(problems))
        self.assertIn("real-missing.md", problems[0])

    def test_percent_encoded_nonexistent_target_is_rejected(self):
        (self.root / "docs" / "plan.md").write_text("[bad](missing%20file.md)\n")
        self.assertTrue(any("broken local link" in x for x in check(self.root)))


if __name__ == "__main__":
    unittest.main()
