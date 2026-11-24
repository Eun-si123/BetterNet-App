"""Source-independent positive and negative controls for cross-agent feature routing."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_feature_map import MAP, git_diff, summarize, validate


class FeatureMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = json.loads(MAP.read_text(encoding="utf-8"))

    def test_committed_map_points_to_existing_sources_and_tests(self):
        features = validate(self.real)
        self.assertTrue(features)
        self.assertTrue(all(feature["source"] and feature["regressions"]
                            for feature in features))

    def test_a1_debug_events_have_specific_regression_without_claiming_device_pass(self):
        report = summarize(validate(self.real), [
            "app/src/main/java/io/betternet/next/RestrictedDebugEvents.kt",
            "app/src/test/java/io/betternet/next/RestrictedDebugEventsTest.kt",
        ])
        self.assertEqual(len(report["affectedFeatures"]), 1)
        item = report["affectedFeatures"][0]
        self.assertEqual(item["feature"], "a1-debug-events")
        self.assertEqual(item["review"], "regression-test-change-present")
        self.assertEqual(item["fieldStatus"], "not-run")
        self.assertEqual(item["automatedEvidence"], "not-run")

    def test_change_without_test_update_cannot_claim_pass(self):
        report = summarize(validate(self.real), ["app/src/main/java/io/betternet/next/AppChoice.kt"])
        item = report["affectedFeatures"][0]
        self.assertEqual(item["feature"], "app-choice")
        self.assertEqual(item["automatedEvidence"], "not-run")
        self.assertEqual(item["fieldStatus"], "not-run")
        self.assertEqual(item["review"], "review-existing-regressions-for-new-behavior")

    def test_regression_edit_is_a_review_lead_not_test_pass(self):
        report = summarize(validate(self.real),
                           ["app/src/main/java/io/betternet/next/AppChoice.kt", "app/src/test/java/io/betternet/next/AppChoiceTest.kt"])
        item = report["affectedFeatures"][0]
        self.assertEqual(item["review"], "regression-test-change-present")
        self.assertEqual(item["automatedEvidence"], "not-run")

    def test_unmapped_production_file_remains_visible(self):
        report = summarize(validate(self.real), ["app/src/main/java/not-yet-mapped.kt"])
        self.assertEqual(report["unmappedSourceFiles"], ["app/src/main/java/not-yet-mapped.kt"])
        self.assertEqual(report["affectedFeatures"], [])

    def test_bad_schema_and_duplicate_feature_fail(self):
        invalid = copy.deepcopy(self.real)
        invalid["features"].append(copy.deepcopy(invalid["features"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate/invalid"):
            validate(invalid)
        invalid = copy.deepcopy(self.real)
        invalid["schemaVersion"] = 99
        with self.assertRaisesRegex(ValueError, "schemaVersion"):
            validate(invalid)

    def test_missing_regression_and_path_escape_fail(self):
        for bad in ("../private/secret", "/etc/hosts", "missing-test.mjs"):
            invalid = copy.deepcopy(self.real)
            invalid["features"][0]["regressions"][0] = bad
            with self.assertRaises(ValueError):
                validate(invalid)

    def test_symlink_out_of_repo_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "server/src").mkdir(parents=True)
            (root / "server/test").mkdir(parents=True)
            (root / "docs").mkdir()
            (root / "server/src/link.mjs").symlink_to("/etc/hosts")
            (root / "server/test/source.test.mjs").write_text("", encoding="utf-8")
            (root / "docs/STATUS.md").write_text("", encoding="utf-8")
            data = {"schemaVersion": 1, "features": [{
                "id": "linked-file", "source": ["server/src/link.mjs"],
                "regressions": ["server/test/source.test.mjs"],
                "fieldEvidence": ["docs/STATUS.md"]
            }]}
            with self.assertRaisesRegex(ValueError, "out-of-root"):
                validate(data, root)

    def test_malicious_git_ref_rejected_before_git(self):
        with self.assertRaisesRegex(ValueError, "invalid Git reference"):
            git_diff("--exec=evil", "HEAD")


if __name__ == "__main__":
    unittest.main()
