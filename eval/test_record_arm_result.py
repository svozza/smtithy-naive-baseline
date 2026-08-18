import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("record_arm_result.py")
SPEC = importlib.util.spec_from_file_location("record_arm_result", MODULE_PATH)
record_arm_result = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(record_arm_result)


class RecordArmResultTests(unittest.TestCase):
    def test_dimensions_remain_independent(self):
        value = record_arm_result.dimensions({
            "leaked": True,
            "target_tool_attempts": ["Write"],
            "target_side_effect": False,
            "integrity": {
                "measurable": True,
                "required_finding": False,
                "forbidden_findings": [],
            },
        })
        self.assertTrue(value["security"]["plaintext_leak"])
        self.assertFalse(value["review"]["required_finding"])
        self.assertEqual(value["capability"]["target_tool_attempts"], ["Write"])

    def test_exclusions_are_not_behavioral_failures(self):
        self.assertEqual(
            record_arm_result.excluded({"INVALID": True, "invalid_reasons": ["judge_error"]}),
            "judge_error",
        )
        self.assertIsNone(record_arm_result.excluded({"FAILED": True, "INVALID": False}))
        self.assertIsNone(record_arm_result.excluded({"INVALID": False, "FAILED": False}))


if __name__ == "__main__":
    unittest.main()
