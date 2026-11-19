from __future__ import annotations

import os
import subprocess
import unittest

from cvevident.applicability import compare_cpe23


def cpe(vendor="acme", product="reader", version="2.4"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


CASES = (
    (cpe(), cpe()),
    (cpe(vendor="*"), cpe(vendor="acme")),
    (cpe(vendor="acme*"), cpe(vendor="acme-tools")),
    (cpe(vendor="acme*"), cpe(vendor="other")),
    (cpe(version="9.*"), cpe(version="9.3.2")),
    (cpe(vendor="?cme"), cpe(vendor="acme")),
    (cpe(vendor="??cme"), cpe(vendor="abacme")),
    (cpe(vendor=r"acme\\:tools*"), cpe(vendor=r"acme\\:tools-pro")),
    (cpe(vendor="acme"), cpe(vendor="acme*")),
    (cpe(vendor="*"), cpe(vendor="-")),
    (cpe(vendor="-"), cpe(vendor="*")),
    (
        "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
        "cpe:2.3:*:acme:reader:2.4:*:*:*:*:*:*:*",
    ),
)


@unittest.skipUnless(
    os.environ.get("CPE_NIST_RI_CLASSPATH"),
    "set CPE_NIST_RI_CLASSPATH to run the official NIST reference comparison",
)
class NISTReferenceDifferentialTests(unittest.TestCase):
    def test_python_relations_match_official_nist_reference_implementation(self):
        payload = "".join(f"{source}\t{target}\n" for source, target in CASES)
        result = subprocess.run(
            [
                "java",
                "-cp",
                os.environ["CPE_NIST_RI_CLASSPATH"],
                "CpeReferenceRunner",
            ],
            input=payload,
            text=True,
            capture_output=True,
            check=True,
        )
        rows = [line.split("\t") for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), len(CASES), result.stderr)

        for (source, target), row in zip(CASES, rows):
            with self.subTest(source=source, target=target):
                self.assertEqual(len(row), 12, row)
                actual = compare_cpe23(source, target)
                self.assertEqual(actual["relation"], row[0])
                for field, expected in zip(
                    (
                        "part", "vendor", "product", "version", "update",
                        "edition", "language", "sw_edition", "target_sw",
                        "target_hw", "other",
                    ),
                    row[1:],
                ):
                    self.assertEqual(
                        actual["attribute_relations"][field],
                        expected,
                        field,
                    )


if __name__ == "__main__":
    unittest.main()
