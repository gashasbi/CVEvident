from __future__ import annotations

import unittest

from cvevident.applicability import parse_cpe23


class CPE23WildcardSyntaxTests(unittest.TestCase):
    def test_question_mark_only_components_are_valid(self):
        for component in ("?", "??", "???"):
            with self.subTest(component=component):
                value = f"cpe:2.3:a:acme:reader:2.4:{component}:*:*:*:*:*:*"
                self.assertIsNotNone(parse_cpe23(value))

    def test_documented_leading_and_trailing_wildcard_sequences_are_valid(self):
        valid_components = ("??foo", "bar???", "??baz???", "?foo*", "*bar??")
        for component in valid_components:
            with self.subTest(component=component):
                value = f"cpe:2.3:a:acme:reader:2.4:{component}:*:*:*:*:*:*"
                self.assertIsNotNone(parse_cpe23(value))

    def test_embedded_or_misordered_wildcards_are_rejected(self):
        invalid_components = (
            "foo?bar",
            "bar??baz",
            "q??x",
            "**foo",
            "bar***",
            "*?foobar",
            "foobar*?",
        )
        for component in invalid_components:
            with self.subTest(component=component):
                value = f"cpe:2.3:a:acme:reader:2.4:{component}:*:*:*:*:*:*"
                self.assertIsNone(parse_cpe23(value))


if __name__ == "__main__":
    unittest.main()
