from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cvevident.analyzer import analyze_file
from cvevident.db import init_db
from cvevident.store import import_evidence_rules_json, import_nvd_json
from cvevident.reporting import to_html, to_markdown


class CorrelationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "cvevident.sqlite3"
        init_db(self.db)
        nvd = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-12345",
                    "published": "2099-01-01T00:00:00.000Z",
                    "lastModified": "2099-01-02T00:00:00.000Z",
                    "descriptions": [{"lang": "en", "value": "Synthetic integration test"}],
                    "configurations": [{
                        "operator": "OR",
                        "nodes": [{
                            "operator": "OR",
                            "cpeMatch": [{
                                "criteria": "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
                                "vulnerable": True,
                            }],
                        }],
                    }],
                }
            }]
        }
        self.write_json("nvd.json", nvd)
        import_nvd_json(self.root / "nvd.json", self.db)
        rules = {
            "rules": [{
                "rule_id": "rtf-header-source-link",
                "cve_id": "CVE-2099-12345",
                "parser_family": "rtf",
                "evidence_type": "rtf_structure",
                "evidence_key": "rtf.header",
                "value_equals": "found",
                "coverage_domain": "container_structure",
                "source_name": "Synthetic advisory",
                "source_url": "https://example.test/advisory",
                "evidence_basis": "Synthetic test rule for integration coverage.",
                "confidence": "high",
                "verified": True,
            }]
        }
        self.write_json("rules.json", rules)
        import_evidence_rules_json(self.root / "rules.json", self.db)

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_analyze_combines_rule_and_environment_context(self):
        document = self.root / "sample.rtf"
        document.write_text(r"{\rtf1 CVEvident sample}", encoding="ascii")
        report = analyze_file(
            document,
            self.db,
            environment_cpes=["cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*"],
        )
        self.assertEqual(report["evidence_correlation"]["cve_results"][0]["status"], "MATCH")
        association = next(
            item for item in report["cve_associations"]
            if item["cve_id"] == "CVE-2099-12345"
        )
        self.assertEqual(association["correlation_status"], "MATCH")
        self.assertIn("parser_evidence_rule", association["association_basis_types"])
        self.assertIn("environment_cpe", association["association_basis_types"])
        self.assertEqual(
            report["environment_context"]["candidate_cves"][0]["applicability"]["status"],
            "applicable",
        )
        markdown = to_markdown(report)
        html = to_html(report)
        self.assertIn("Source-backed parser evidence correlation", markdown)
        self.assertIn("`MATCH`", markdown)
        self.assertIn("Synthetic advisory", markdown)
        self.assertIn("Synthetic test rule for integration coverage.", markdown)
        self.assertIn("Source-backed parser evidence correlation", html)


if __name__ == "__main__":
    unittest.main()
