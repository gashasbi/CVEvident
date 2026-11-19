from __future__ import annotations

import unittest

from cvevident.applicability import evaluate_nvd_configurations


TARGET = "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*"
MATCHING_NODE = {
    "operator": "OR",
    "cpeMatch": [{
        "criteria": TARGET,
        "vulnerable": True,
    }],
}


class NVDConfigurationValidationTests(unittest.TestCase):
    def test_non_boolean_negate_makes_node_indeterminate(self):
        for value in ("true", 1, None):
            with self.subTest(value=value):
                cve = {
                    "configurations": [{
                        "operator": "OR",
                        "nodes": [{
                            **MATCHING_NODE,
                            "negate": value,
                        }],
                    }]
                }
                result = evaluate_nvd_configurations(cve, [TARGET])
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["result"], "configuration_indeterminate")

    def test_malformed_cpe_match_collection_is_not_ignored(self):
        cve = {
            "configurations": [{
                "operator": "OR",
                "cpeMatch": "not-an-array",
                "nodes": [MATCHING_NODE],
            }]
        }
        result = evaluate_nvd_configurations(cve, [TARGET])
        self.assertEqual(result["status"], "unknown")

    def test_malformed_child_collection_is_not_ignored(self):
        for field in ("nodes", "children"):
            with self.subTest(field=field):
                cve = {
                    "configurations": [{
                        "operator": "OR",
                        field: "not-an-array",
                        "cpeMatch": [{
                            "criteria": TARGET,
                            "vulnerable": True,
                        }],
                    }]
                }
                result = evaluate_nvd_configurations(cve, [TARGET])
                self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
