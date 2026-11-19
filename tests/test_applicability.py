from __future__ import annotations

import unittest

from cvevident.applicability import compare_cpe23, evaluate_nvd_configurations, parse_cpe23


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
        self.assertEqual(result["matched_conditions"][0]["name_relation"], "equal")

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


    def test_source_wildcards_match_specific_target_components(self):
        cases = [
            ("acme*", "acme"),
            ("acme*", "acme-tools"),
            ("ACME*", "acme-tools"),
            ("*reader", "document-reader"),
            ("?cme", "acme"),
            ("acme?", "acme"),
            ("acme?", "acmex"),
        ]
        for pattern, target_vendor in cases:
            with self.subTest(pattern=pattern, target=target_vendor):
                criteria = f"cpe:2.3:a:{pattern}:reader:2.4:*:*:*:*:*:*:*"
                target = f"cpe:2.3:a:{target_vendor}:reader:2.4:*:*:*:*:*:*:*"
                cve = {"configurations": [{"nodes": [{"cpeMatch": [{
                    "criteria": criteria, "vulnerable": True,
                }]}]}]}
                self.assertEqual(
                    evaluate_nvd_configurations(cve, [target])["status"],
                    "applicable",
                )

    def test_nonmatching_source_wildcard_is_not_applicable(self):
        criteria = "cpe:2.3:a:acme*:reader:2.4:*:*:*:*:*:*:*"
        target = "cpe:2.3:a:other:reader:2.4:*:*:*:*:*:*:*"
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": criteria, "vulnerable": True,
        }]}]}]}

        self.assertEqual(
            evaluate_nvd_configurations(cve, [target])["status"],
            "not_applicable",
        )

    def test_cpe_any_and_na_attribute_relations_follow_nist_rules(self):
        cases = [
            ("*", "-", "applicable"),
            ("*", "acme", "applicable"),
            ("-", "-", "applicable"),
            ("-", "acme", "not_applicable"),
            ("acme", "-", "not_applicable"),
        ]
        for source_vendor, target_vendor, expected in cases:
            with self.subTest(source=source_vendor, target=target_vendor):
                criteria = f"cpe:2.3:a:{source_vendor}:reader:2.4:*:*:*:*:*:*:*"
                target = f"cpe:2.3:a:{target_vendor}:reader:2.4:*:*:*:*:*:*:*"
                cve = {"configurations": [{"nodes": [{"cpeMatch": [{
                    "criteria": criteria, "vulnerable": True,
                }]}]}]}
                self.assertEqual(
                    evaluate_nvd_configurations(cve, [target])["status"],
                    expected,
                )

    def test_escaped_wildcard_is_not_treated_as_a_pattern(self):
        criteria = r"cpe:2.3:a:acme:reader\*:2.4:*:*:*:*:*:*:*"
        literal_target = r"cpe:2.3:a:acme:reader\*:2.4:*:*:*:*:*:*:*"
        other_target = "cpe:2.3:a:acme:readerx:2.4:*:*:*:*:*:*:*"
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": criteria, "vulnerable": True,
        }]}]}]}

        self.assertEqual(
            evaluate_nvd_configurations(cve, [literal_target])["status"],
            "applicable",
        )
        self.assertEqual(
            evaluate_nvd_configurations(cve, [other_target])["status"],
            "not_applicable",
        )


    def test_wildcard_target_attributes_are_undefined(self):
        cases = [
            ("acme*", "acme*"),
            ("*", "acme*"),
        ]
        for source_vendor, target_vendor in cases:
            with self.subTest(source=source_vendor, target=target_vendor):
                criteria = f"cpe:2.3:a:{source_vendor}:reader:2.4:*:*:*:*:*:*:*"
                target = f"cpe:2.3:a:{target_vendor}:reader:2.4:*:*:*:*:*:*:*"
                cve = {"configurations": [{"nodes": [{"cpeMatch": [{
                    "criteria": criteria, "vulnerable": True,
                }]}]}]}
                self.assertEqual(
                    evaluate_nvd_configurations(cve, [target])["status"],
                    "unknown",
                )


    def test_version_wildcard_matches_a_concrete_target_version(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:acme:reader:9.*:*:*:*:*:*:*:*",
            "vulnerable": True,
        }]}]}]}
        matching = "cpe:2.3:a:acme:reader:9.3.2:*:*:*:*:*:*:*"
        different = "cpe:2.3:a:acme:reader:8.3.2:*:*:*:*:*:*:*"

        result = evaluate_nvd_configurations(cve, [matching])
        self.assertEqual(result["status"], "applicable")
        self.assertEqual(result["matched_conditions"][0]["name_relation"], "superset")
        self.assertEqual(
            evaluate_nvd_configurations(cve, [different])["status"],
            "not_applicable",
        )

    def test_cpe_literal_comparison_is_case_insensitive(self):
        criteria = "cpe:2.3:a:Acme:Reader:2.4:*:*:*:*:*:*:*"
        target = "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*"
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": criteria, "vulnerable": True,
        }]}]}]}

        self.assertEqual(
            evaluate_nvd_configurations(cve, [target])["status"],
            "applicable",
        )


    def test_cpe_name_comparison_returns_nist_set_relations(self):
        cases = [
            (
                "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                "equal",
            ),
            (
                "cpe:2.3:a:acme*:reader:2.4:*:*:*:*:*:*:*",
                "cpe:2.3:a:acme-tools:reader:2.4:*:*:*:*:*:*:*",
                "superset",
            ),
            (
                "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                "cpe:2.3:a:*:reader:2.4:*:*:*:*:*:*:*",
                "subset",
            ),
            (
                "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                "cpe:2.3:a:other:reader:2.4:*:*:*:*:*:*:*",
                "disjoint",
            ),
            (
                "cpe:2.3:a:*:reader:2.4:*:*:*:*:*:*:*",
                "cpe:2.3:a:acme*:reader:2.4:*:*:*:*:*:*:*",
                "undefined",
            ),
            (
                "cpe:2.3:a:acme*:reader:2.4:*:*:*:*:*:*:*",
                "cpe:2.3:a:acme*:reader:2.4:*:*:*:*:*:*:*",
                "undefined",
            ),
        ]
        for source, target, expected in cases:
            with self.subTest(source=source, target=target):
                self.assertEqual(compare_cpe23(source, target)["relation"], expected)


    def test_cpe_attribute_relation_matrix_matches_nist_table_6_2(self):
        cases = [
            ("*", "*", "equal"),
            ("*", "-", "superset"),
            ("*", "acme", "superset"),
            ("*", "acme*", "undefined"),
            ("-", "*", "subset"),
            ("-", "-", "equal"),
            ("-", "acme", "disjoint"),
            ("-", "acme*", "undefined"),
            ("acme", "acme", "equal"),
            ("acme", "other", "disjoint"),
            ("acme", "acme*", "undefined"),
            ("acme", "-", "disjoint"),
            ("acme", "*", "subset"),
            ("acme*", "acme", "superset"),
            ("acme*", "other", "disjoint"),
            ("acme*", "*", "subset"),
            ("acme*", "-", "disjoint"),
            ("acme*", "other*", "undefined"),
        ]
        for source_vendor, target_vendor, expected in cases:
            with self.subTest(source=source_vendor, target=target_vendor):
                source = f"cpe:2.3:a:{source_vendor}:reader:2.4:*:*:*:*:*:*:*"
                target = f"cpe:2.3:a:{target_vendor}:reader:2.4:*:*:*:*:*:*:*"
                self.assertEqual(
                    compare_cpe23(source, target)["attribute_relations"]["vendor"],
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
