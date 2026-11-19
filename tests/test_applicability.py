from __future__ import annotations

import unittest

from cvevident.applicability import evaluate_nvd_configurations, parse_cpe23


class ApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.target = "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*"

    def test_parser_accepts_escaped_reserved_characters(self):
        value = r"cpe:2.3:a:acme:reader\:plus\+edition:2.4:*:*:en-US:*:*:*:*"

        parsed = parse_cpe23(value)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["product"], r"reader\:plus\+edition")

    def test_parser_rejects_malformed_components_and_escapes(self):
        invalid_values = [
            "cpe:2.3:x:acme:reader:2.4:*:*:*:*:*:*:*",
            "cpe:2.3:a:acme::2.4:*:*:*:*:*:*:*",
            "cpe:2.3:a:acme:reader+edition:2.4:*:*:*:*:*:*:*",
            r"cpe:2.3:a:acme:reader\q:2.4:*:*:*:*:*:*:*",
            "cpe:2.3:a:acme:reader:2.4:*:*:english:*:*:*:*",
            "cpe:2.3:a:acme:réader:2.4:*:*:*:*:*:*:*",
            "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:tail\\",
        ]

        for value in invalid_values:
            with self.subTest(value=value):
                self.assertIsNone(parse_cpe23(value))

    def test_unescaped_wildcard_patterns_are_unknown(self):
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        patterned_target = "cpe:2.3:a:acme:reader*:2.4:*:*:*:*:*:*:*"

        result = evaluate_nvd_configurations(cve, [patterned_target])

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(
            result["matched_conditions"][0]["reason"],
            "unsupported_cpe_wildcard",
        )

    def test_escaped_wildcard_is_compared_as_a_literal(self):
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": r"cpe:2.3:a:acme:reader\*:2.4:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        target = r"cpe:2.3:a:acme:reader\*:2.4:*:*:*:*:*:*:*"

        self.assertEqual(evaluate_nvd_configurations(cve, [target])["status"], "applicable")

    def test_exact_environment_cpe_matches(self):
        cve = {
            "configurations": [{
                "operator": "OR",
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        result = evaluate_nvd_configurations(cve, [self.target])
        self.assertEqual(result["status"], "applicable")
        self.assertEqual(len(result["matched_conditions"]), 1)

    def test_and_node_requires_every_condition(self):
        cve = {
            "configurations": [{
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }],
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:o:microsoft:windows_10:10:*:*:*:*:*:*:*",
                            "vulnerable": False,
                        }],
                    },
                ],
            }]
        }
        self.assertEqual(evaluate_nvd_configurations(cve, [self.target])["status"], "not_applicable")
        windows = "cpe:2.3:o:microsoft:windows_10:10:*:*:*:*:*:*:*"
        self.assertEqual(evaluate_nvd_configurations(cve, [self.target, windows])["status"], "applicable")

    def test_negated_configuration_node_is_evaluated(self):
        cve = {
            "configurations": [{
                "operator": "OR",
                "nodes": [{
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        self.assertEqual(evaluate_nvd_configurations(cve, [self.target])["status"], "not_applicable")
        other = "cpe:2.3:a:acme:reader:2.5:*:*:*:*:*:*:*"
        self.assertEqual(evaluate_nvd_configurations(cve, [other])["status"], "applicable")

    def test_numeric_version_bounds_are_evaluated(self):
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:acme:reader:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "2.0",
                        "versionEndExcluding": "3.0",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        self.assertEqual(evaluate_nvd_configurations(cve, [self.target])["status"], "applicable")
        other = "cpe:2.3:a:acme:reader:3.0:*:*:*:*:*:*:*"
        self.assertEqual(evaluate_nvd_configurations(cve, [other])["status"], "not_applicable")

    def test_unsupported_version_range_is_unknown(self):
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:acme:reader:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "2.x",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        self.assertEqual(evaluate_nvd_configurations(cve, [self.target])["status"], "unknown")

    def test_invalid_or_missing_configuration_is_unknown(self):
        self.assertEqual(evaluate_nvd_configurations({}, [self.target])["status"], "unknown")
        self.assertEqual(evaluate_nvd_configurations({}, [])["status"], "unknown")
        self.assertIsNone(parse_cpe23("not-a-cpe"))
        self.assertEqual(
            evaluate_nvd_configurations({}, ["not-a-cpe"])["result"],
            "invalid_environment_cpe",
        )

    def test_wildcard_environment_component_is_indeterminate(self):
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }],
                }],
            }]
        }
        wildcard_target = "cpe:2.3:a:acme:reader:*:*:*:*:*:*:*:*"
        self.assertEqual(evaluate_nvd_configurations(cve, [wildcard_target])["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
