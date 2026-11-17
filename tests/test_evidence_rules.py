from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cvevident.correlation import correlate_evidence_rules
from cvevident.db import connect, init_db
from cvevident.store import import_evidence_rules_json, import_nvd_json
from cvevident.cli import build_parser, main


class EvidenceRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "rules.sqlite3"
        init_db(self.db)
        self.nvd_file = self.write_json("nvd.json", {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-12345",
                    "published": "2099-01-01T00:00:00.000Z",
                    "lastModified": "2099-01-02T00:00:00.000Z",
                    "descriptions": [{"lang": "en", "value": "Synthetic evidence rule test"}],
                    "configurations": [],
                }
            }]
        })
        import_nvd_json(self.nvd_file, self.db)

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_import_and_match_exact_parser_observation(self):
        rules = {
            "rules": [{
                "rule_id": "acme-reader-vba",
                "cve_id": "CVE-2099-12345",
                "parser_family": "ooxml",
                "evidence_type": "office_structural_feature",
                "evidence_key": "office.structure.vba_project_present",
                "value_equals": True,
                "coverage_domain": "active_content_indicators",
                "source_name": "Vendor security advisory",
                "source_url": "https://example.test/advisory",
                "evidence_basis": "The advisory identifies this macro-enabled document condition.",
                "confidence": "high",
                "verified": True,
            }]
        }
        self.assertEqual(import_evidence_rules_json(self.write_json("rules.json", rules), self.db), 1)
        report = {
            "office_analysis": {"status": "parsed"},
            "analysis_coverage": {
                "parser_coverage": {
                    "domains": {
                        "active_content_indicators": {"status": "complete"}
                    }
                }
            },
            "evidence": [{
                "evidence_id": "EV-000001",
                "evidence_type": "office_structural_feature",
                "key": "office.structure.vba_project_present",
                "value": True,
            }],
        }
        result = correlate_evidence_rules(report, str(self.db))
        match = result["cve_results"][0]
        self.assertEqual(match["status"], "MATCH")
        self.assertEqual(match["matched_rules"][0]["evidence_id"], "EV-000001")
        self.assertTrue(match["matched_rules"][0]["verified"])

    def test_complete_coverage_allows_rule_no_match(self):
        self.import_rule()
        report = {
            "office_analysis": {"status": "parsed"},
            "analysis_coverage": {
                "parser_coverage": {
                    "domains": {
                        "active_content_indicators": {"status": "complete"}
                    }
                }
            },
            "evidence": [],
        }
        result = correlate_evidence_rules(report, str(self.db))
        self.assertEqual(result["cve_results"][0]["status"], "NO_MATCH")

    def test_incomplete_coverage_keeps_absence_unknown(self):
        self.import_rule()
        report = {
            "office_analysis": {"status": "partial"},
            "analysis_coverage": {
                "parser_coverage": {
                    "domains": {
                        "active_content_indicators": {"status": "partial"}
                    }
                }
            },
            "evidence": [],
        }
        result = correlate_evidence_rules(report, str(self.db))
        self.assertEqual(result["cve_results"][0]["status"], "UNKNOWN")

    def test_cli_accepts_evidence_rule_import_command(self):
        args = build_parser().parse_args(["import-evidence-rules", "rules.json"])
        self.assertEqual(args.command, "import-evidence-rules")
        self.assertEqual(args.json_file, "rules.json")
        analyze_args = build_parser().parse_args([
            "analyze", "sample.rtf", "--environment-cpe",
            "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*",
        ])
        self.assertEqual(analyze_args.environment_cpe, [
            "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*"
        ])

    def test_cli_imports_evidence_rules(self):
        rules = {
            "rules": [{
                "rule_id": "cli-import-rule",
                "cve_id": "CVE-2099-12345",
                "parser_family": "ooxml",
                "evidence_type": "office_structural_feature",
                "evidence_key": "office.structure.vba_project_present",
                "source_name": "Vendor security advisory",
                "source_url": "https://example.test/advisory",
                "evidence_basis": "Synthetic CLI import test.",
            }]
        }
        path = self.write_json("cli-rules.json", rules)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--db", str(self.db), "import-evidence-rules", str(path)])
        self.assertEqual(code, 0)
        self.assertIn('"rules_imported": 1', output.getvalue())

    def test_old_database_without_rule_table_returns_unavailable_status(self):
        old_db = self.root / "old.sqlite3"
        import sqlite3
        sqlite3.connect(old_db).close()
        result = correlate_evidence_rules({"office_analysis": {"status": "parsed"}}, str(old_db))
        self.assertEqual(result["status"], "rule_store_unavailable")
        self.assertEqual(result["cve_results"], [])

    def test_import_rejects_unknown_cve(self):
        rules = {
            "rules": [{
                "rule_id": "missing-cve",
                "cve_id": "CVE-2099-99999",
                "parser_family": "ooxml",
                "evidence_type": "office_structural_feature",
                "evidence_key": "office.structure.vba_project_present",
                "source_name": "Source",
                "source_url": "https://example.test/advisory",
                "evidence_basis": "Basis",
            }]
        }
        with self.assertRaisesRegex(ValueError, "must be imported"):
            import_evidence_rules_json(self.write_json("missing.json", rules), self.db)

    def import_rule(self):
        rules = {
            "rules": [{
                "rule_id": "acme-reader-vba",
                "cve_id": "CVE-2099-12345",
                "parser_family": "ooxml",
                "evidence_type": "office_structural_feature",
                "evidence_key": "office.structure.vba_project_present",
                "value_equals": True,
                "coverage_domain": "active_content_indicators",
                "source_name": "Vendor security advisory",
                "source_url": "https://example.test/advisory",
                "evidence_basis": "The advisory identifies this macro-enabled document condition.",
            }]
        }
        import_evidence_rules_json(self.write_json("rules.json", rules), self.db)


if __name__ == "__main__":
    unittest.main()
