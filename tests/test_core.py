from __future__ import annotations

import contextlib
import gzip
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter

from cvevident.analyzer import analyze_file
from cvevident.cli import main
from cvevident.db import SCHEMA_VERSION, connect, init_db
from cvevident.pdf_triage import analyze_pdf, shannon_entropy
from cvevident.reporting import to_html, to_markdown
from cvevident.sources import download, sync_nvd_year
from cvevident.store import (
    get_analysis, get_cve, get_stats, import_epss_csv, import_kev_json,
    import_nvd_json, import_reference_samples_json, lookup_reference_samples, search_cves, search_product_cves,
)


class TempProject(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "test.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def write_json(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @contextlib.contextmanager
    def capture_expected_pdf_parser_warning(self):
        """Capture pypdf's expected warning for intentionally truncated test PDFs."""
        with self.assertLogs("pypdf._reader", level="WARNING") as captured:
            yield
        self.assertTrue(
            any("EOF marker not found" in record.getMessage() for record in captured.records),
            "Expected pypdf to report the deliberately missing PDF EOF marker.",
        )

    def nvd_payload(self, cve_id="CVE-2099-12345", product="pdf_reader", vendor="example", vulnerable=True):
        return {"vulnerabilities": [{"cve": {
            "id": cve_id,
            "published": "2099-01-01T00:00:00.000Z",
            "lastModified": "2099-01-02T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Example PDF reader parser vulnerability"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
            "references": [{"url": "https://example.test/advisory", "source": "example", "tags": ["Vendor Advisory"]}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                "criteria": f"cpe:2.3:a:{vendor}:{product}:1.0:*:*:*:*:*:*:*",
                "matchCriteriaId": "12345678-1234-1234-1234-123456789abc",
                "vulnerable": vulnerable,
                "versionEndExcluding": "2.0"
            }]}]}]
        }}]}


class EntropyAndPDFTests(TempProject):
    def test_entropy_empty_and_constant(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"A" * 100), 0.0)

    def test_entropy_two_symbols(self):
        self.assertAlmostEqual(shannon_entropy(b"AB"), 1.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0)

    def test_analyze_pdf_hash_markers_and_cautious_verdict(self):
        file_path = self.root / "sample.pdf"
        file_path.write_bytes(b"%PDF-1.7\n<< /OpenAction /JavaScript /JS 1 /EmbeddedFile >>\n%%EOF")
        report = analyze_pdf(file_path)
        self.assertEqual(report["file"]["file_type"], "pdf")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        self.assertEqual(report["metrics"]["marker_counts"]["pdf.js_name"], 1)
        self.assertEqual(report["metrics"]["marker_counts"]["pdf.javascript_name"], 1)
        self.assertEqual(len(report["file"]["sha256"]), 64)

    def test_js_token_not_double_counted_inside_javascript(self):
        file_path = self.root / "sample.pdf"
        file_path.write_bytes(b"%PDF-1.7 /JavaScript")
        with self.capture_expected_pdf_parser_warning():
            report = analyze_pdf(file_path)
        self.assertEqual(report["metrics"]["marker_counts"]["pdf.js_name"], 0)
        self.assertEqual(report["metrics"]["marker_counts"]["pdf.javascript_name"], 1)

    def test_non_pdf_is_not_misclassified_as_pdf(self):
        file_path = self.root / "notes.txt"
        file_path.write_text("/OpenAction", encoding="utf-8")
        report = analyze_pdf(file_path)
        self.assertEqual(report["file"]["file_type"], "unknown_or_non_pdf")
        self.assertTrue(any("No %PDF- header" in warning for warning in report["warnings"]))

    def test_over_limit_rejected(self):
        file_path = self.root / "big.pdf"
        file_path.write_bytes(b"%PDF-1.7" + b"x" * 128)
        with self.assertRaises(ValueError):
            analyze_pdf(file_path, max_bytes=32)

    def test_nonpositive_limit_rejected(self):
        file_path = self.root / "a.pdf"
        file_path.write_bytes(b"%PDF-1.7")
        with self.assertRaises(ValueError):
            analyze_pdf(file_path, max_bytes=0)

    def test_missing_file_rejected(self):
        with self.assertRaises(FileNotFoundError):
            analyze_pdf(self.root / "missing.pdf")

    def test_structural_parser_reads_valid_pdf_page_tree(self):
        file_path = self.root / "valid.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        with file_path.open("wb") as handle:
            writer.write(handle)
        report = analyze_pdf(file_path)
        structural = report["structural_analysis"]
        self.assertEqual(structural["status"], "parsed")
        self.assertEqual(structural["page_count_declared"], 1)
        self.assertFalse(structural["encrypted"])
        self.assertEqual(structural["features"]["javascript_action_count"], 0)

    def test_structural_parser_detects_javascript_action_without_executing_it(self):
        file_path = self.root / "synthetic-action.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        # Test-only inert script. CVEvident parses but never executes this PDF action.
        # pypdf 6.21+ deprecates add_js(); retain compatibility with older local test environments.
        if hasattr(writer, "add_open_action"):
            from pypdf.actions import JavaScript
            writer.add_open_action(JavaScript("void(0);"))
        else:
            writer.add_js("void(0);")
        with file_path.open("wb") as handle:
            writer.write(handle)
        report = analyze_pdf(file_path)
        self.assertEqual(report["structural_analysis"]["status"], "parsed")
        self.assertEqual(report["structural_analysis"]["features"]["javascript_action_count"], 1)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        self.assertTrue(any(e["key"] == "pdf.structure.javascript_action_count" for e in report["evidence"]))

        # Structural findings should retain a logical object path, so later analysis
        # can explain where an observation originated rather than report only totals.
        findings = [
            item for item in report["structural_analysis"]["findings"]
            if item["feature"] == "action_type" and item["value"] == "/JavaScript"
        ]
        self.assertTrue(findings)
        self.assertTrue(findings[0]["object_path"].startswith("/Root"))
        self.assertIn("/S", findings[0]["object_path"])
        self.assertIn("location_semantics", report["structural_analysis"])
        finding_evidence = [
            item for item in report["evidence"]
            if item["evidence_type"] == "pdf_structural_finding"
            and item["value"] == "/JavaScript"
        ]
        self.assertTrue(finding_evidence)
        self.assertTrue(finding_evidence[0]["details"]["object_path"].startswith("/Root"))

    def test_lexical_javascript_string_is_not_structural_action(self):
        file_path = self.root / "metadata.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.add_metadata({"/Title": "A harmless document mentioning /JavaScript text"})
        with file_path.open("wb") as handle:
            writer.write(handle)
        # A PDF comment containing the marker should trigger lexical matching but not
        # be mistaken for a parsed /S /JavaScript action.
        with file_path.open("ab") as handle:
            handle.write(b"\n% Harmless comment mentions /JavaScript\n")
        report = analyze_pdf(file_path)
        self.assertEqual(report["structural_analysis"]["status"], "parsed")
        self.assertEqual(report["metrics"]["marker_counts"]["pdf.javascript_name"], 1)
        self.assertEqual(report["structural_analysis"]["features"]["javascript_action_count"], 0)
        self.assertFalse(any(
            item["feature"] == "action_type" and item["value"] == "/JavaScript"
            for item in report["structural_analysis"].get("findings", [])
        ))

    def test_incomplete_marker_fixture_keeps_lexical_results_on_parser_failure(self):
        file_path = self.root / "incomplete.pdf"
        file_path.write_bytes(b"%PDF-1.7\n<< /OpenAction /JavaScript >>")
        with self.capture_expected_pdf_parser_warning():
            report = analyze_pdf(file_path)
        self.assertEqual(report["metrics"]["marker_counts"]["pdf.open_action_name"], 1)
        self.assertEqual(report["structural_analysis"]["status"], "failed")
        self.assertEqual(report["structural_analysis"]["findings"], [])
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")


class DatabaseAndImportTests(TempProject):
    def test_nvd_import_extracts_fields_products_references_and_cwe(self):
        path = self.write_json("nvd.json", self.nvd_payload())
        self.assertEqual(import_nvd_json(path, self.db), 1)
        result = get_cve("CVE-2099-12345", self.db)
        self.assertEqual(result["cvss_score"], 8.1)
        self.assertEqual(result["cvss_severity"], "HIGH")
        self.assertEqual(result["affected_products"][0]["product"], "pdf_reader")
        self.assertEqual(result["references"][0]["url"], "https://example.test/advisory")
        self.assertEqual(result["weaknesses"][0]["cwe_id"], "CWE-787")

    def test_gzipped_nvd_import(self):
        path = self.root / "nvd.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(self.nvd_payload(), handle)
        self.assertEqual(import_nvd_json(path, self.db), 1)
        self.assertIsNotNone(get_cve("CVE-2099-12345", self.db))

    def test_optional_ijson_streaming_import_path(self):
        import types
        path = self.write_json("stream.json", self.nvd_payload())
        fake = types.ModuleType("ijson")
        def fake_parse(handle):
            json.load(handle)
            yield ("", "start_map", None)
            yield ("", "map_key", "vulnerabilities")
            yield ("vulnerabilities", "start_array", None)
        def fake_items(handle, prefix):
            self.assertEqual(prefix, "vulnerabilities.item")
            return iter(json.load(handle)["vulnerabilities"])
        fake.parse = fake_parse
        fake.items = fake_items
        with patch.dict("sys.modules", {"ijson": fake}):
            self.assertEqual(import_nvd_json(path, self.db), 1)
        self.assertIsNotNone(get_cve("CVE-2099-12345", self.db))

    def test_invalid_nvd_shape_rejected(self):
        path = self.write_json("bad.json", {"results": []})
        with self.assertRaises(ValueError):
            import_nvd_json(path, self.db)

    def test_recursive_cpe_children(self):
        payload = self.nvd_payload()
        node = payload["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]
        node["cpeMatch"] = []
        node["children"] = [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:acme:viewer:3.1:*:*:*:*:*:*:*", "vulnerable": True
        }]}]
        path = self.write_json("nested.json", payload)
        import_nvd_json(path, self.db)
        self.assertEqual(search_product_cves("acme viewer", self.db)[0]["matched_product"], "viewer")

    def test_cpe_marked_nonvulnerable_not_returned_as_product_candidate(self):
        path = self.write_json("nonvuln.json", self.nvd_payload(vulnerable=False))
        import_nvd_json(path, self.db)
        self.assertEqual(search_product_cves("example pdf_reader", self.db), [])

    def test_product_search_handles_literal_underscores_after_sql_prefilter(self):
        payload = {"vulnerabilities": [
            self.nvd_payload(cve_id="CVE-2099-12345", product="reader_v2")["vulnerabilities"][0],
            self.nvd_payload(cve_id="CVE-2099-12346", product="readerxv2")["vulnerabilities"][0],
        ]}
        path = self.write_json("underscore-products.json", payload)
        import_nvd_json(path, self.db)
        results = search_product_cves("reader_v2", self.db)
        self.assertEqual([row["cve_id"] for row in results], ["CVE-2099-12345"])

    def test_product_search_requires_token_boundaries(self):
        payload = {"vulnerabilities": [
            self.nvd_payload(cve_id="CVE-2099-12345", product="application")["vulnerabilities"][0],
            self.nvd_payload(cve_id="CVE-2099-12346", product="app")["vulnerabilities"][0],
        ]}
        path = self.write_json("token-boundary-products.json", payload)
        import_nvd_json(path, self.db)
        results = search_product_cves("app", self.db)
        self.assertEqual([row["cve_id"] for row in results], ["CVE-2099-12346"])

    def test_kev_import_and_does_not_overwrite_nvd_description(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        kev = self.write_json("kev.json", {"vulnerabilities": [{
            "cveID": "CVE-2099-12345", "dateAdded": "2099-01-03",
            "shortDescription": "Short KEV description", "requiredAction": "Patch now"
        }]})
        self.assertEqual(import_kev_json(kev, self.db), 1)
        row = get_cve("CVE-2099-12345", self.db)
        self.assertTrue(row["cisa_kev"])
        self.assertEqual(row["description"], "Example PDF reader parser vulnerability")
        self.assertEqual(row["kev_date_added"], "2099-01-03")

    def test_epss_csv_and_gzip(self):
        path = self.root / "epss.csv"
        path.write_text("#model_version:test\ncve,epss,percentile\nCVE-2099-34567,0.42,0.91\nCVE-2099-34568,2.0,0.5\n", encoding="utf-8")
        self.assertEqual(import_epss_csv(path, self.db), 1)
        row = get_cve("CVE-2099-34567", self.db)
        self.assertAlmostEqual(row["epss_score"], 0.42)
        gz_path = self.root / "epss.csv.gz"
        with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
            handle.write("cve,epss,percentile\nCVE-2099-45678,0.2,0.8\n")
        self.assertEqual(import_epss_csv(gz_path, self.db), 1)

    def test_repeated_epss_import_does_not_duplicate_null_timestamp_observations(self):
        path = self.root / "epss.csv"
        path.write_text("cve,epss,percentile\nCVE-2099-34567,0.42,0.91\n", encoding="utf-8")
        import_epss_csv(path, self.db)
        import_epss_csv(path, self.db)
        with connect(self.db) as conn:
            observations = conn.execute(
                "SELECT COUNT(*) FROM source_observations WHERE cve_id=? AND source_name='FIRST EPSS' AND source_updated_at IS NULL",
                ("CVE-2099-34567",),
            ).fetchone()[0]
        self.assertEqual(observations, 1)

    def test_bad_epss_header_rejected(self):
        path = self.root / "epss.csv"
        path.write_text("id,score\nabc,1\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            import_epss_csv(path, self.db)

    def test_exact_cve_search(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        self.assertEqual(search_cves("cve-2099-12345", self.db)[0]["cve_id"], "CVE-2099-12345")

    def test_product_candidate_scores_are_context_not_attribution(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        candidates = search_product_cves("example pdf_reader", self.db)
        self.assertEqual(candidates[0]["cve_id"], "CVE-2099-12345")
        self.assertEqual(candidates[0]["assessment"], "product_context_candidate_not_file_attribution")
        self.assertLessEqual(candidates[0]["product_relevance_score"], 100)

    def test_product_context_association_is_not_file_attribution(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        pdf = self.root / "context-only.pdf"
        pdf.write_bytes(b"%PDF-1.7\n%%EOF")
        report = analyze_file(pdf, self.db, target_product="example pdf_reader")
        self.assertEqual(len(report["cve_associations"]), 1)
        association = report["cve_associations"][0]
        self.assertEqual(association["cve_id"], "CVE-2099-12345")
        self.assertEqual(association["association_basis_types"], ["product_context"])
        self.assertEqual(association["assessment"], "product_context_candidate_not_file_attribution")
        self.assertEqual(association["association_bases"][0]["type"], "product_context")
        self.assertIn("does not attribute the file", association["association_bases"][0]["interpretation"])

    def test_exact_sample_cve_association_is_saved_without_product_context(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        pdf = self.root / "exact-sample-only.pdf"
        pdf.write_bytes(b"%PDF-1.7\n%%EOF")
        digest = __import__("hashlib").sha256(pdf.read_bytes()).hexdigest()
        sample_path = self.write_json("samples.json", {"samples": [{
            "sample_id": "SAMPLE-ONLY", "sha256": digest, "file_type": "pdf",
            "label": "suspicious", "source_name": "unit test", "label_basis": "synthetic test relation",
            "confidence": "medium", "cve_links": [{
                "cve_id": "CVE-2099-12345", "evidence_basis": "unit test only",
                "confidence": "medium", "verified": False,
            }]
        }]})
        import_reference_samples_json(sample_path, self.db)
        report = analyze_file(pdf, self.db)
        self.assertEqual(len(report["cve_associations"]), 1)
        association = report["cve_associations"][0]
        self.assertEqual(association["association_basis_types"], ["exact_sha256_sample_match"])
        self.assertEqual(association["assessment"], "exact_sample_link_not_proof_of_exploitability")
        self.assertEqual(association["cvss_score"], 8.1)
        loaded = get_analysis(report["analysis_id"], self.db)
        self.assertEqual(loaded["cve_associations"], report["cve_associations"])
        self.assertEqual(len(loaded["stored_candidates"]), 1)
        self.assertEqual(loaded["stored_candidates"][0]["score"], 100.0)
        rationale = json.loads(loaded["stored_candidates"][0]["rationale_json"])
        self.assertEqual(rationale["score_semantics"], "exact_sha256_sample_retrieval_score_not_cve_link_confidence")
        self.assertFalse(rationale["score_is_probability"])

    def test_reference_sample_import_with_cve_link(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        sample = self.write_json("samples.json", {"samples": [{
            "sample_id": "SYNTHETIC-001", "sha256": "a" * 64, "file_type": "pdf",
            "label": "suspicious", "source_name": "local test fixture", "label_basis": "synthetic test only",
            "confidence": "low", "cve_links": [{
                "cve_id": "CVE-2099-12345", "evidence_basis": "synthetic relation for unit test", "confidence": "low"
            }]
        }]})
        self.assertEqual(import_reference_samples_json(sample, self.db), 1)
        self.assertEqual(get_stats(self.db)["reference_samples"], 1)
        with connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM sample_vulnerability_links").fetchone()[0], 1)

    def test_exact_reference_sample_hash_lookup(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        sample = self.write_json("samples.json", {"samples": [{
            "sample_id": "EXACT-001", "sha256": "b" * 64, "file_type": "pdf",
            "label": "suspicious", "source_name": "unit test", "label_basis": "synthetic",
            "confidence": "low", "cve_links": [{"cve_id": "CVE-2099-12345", "evidence_basis": "test mapping", "confidence": "low"}]
        }]})
        import_reference_samples_json(sample, self.db)
        matches = lookup_reference_samples("b" * 64, self.db)
        self.assertEqual(matches[0]["sample_id"], "EXACT-001")
        self.assertEqual(matches[0]["match_type"], "exact_sha256")
        self.assertEqual(matches[0]["cve_links"][0]["cve_id"], "CVE-2099-12345")

    def test_reference_sample_invalid_hash_rejected(self):
        path = self.write_json("samples.json", {"samples": [{
            "sample_id": "bad", "sha256": "not-a-hash", "file_type": "pdf", "label": "unknown",
            "source_name": "test", "label_basis": "test"
        }]})
        with self.assertRaises(ValueError):
            import_reference_samples_json(path, self.db)

    def test_analysis_persists_and_reloads(self):
        import_nvd_json(self.write_json("nvd.json", self.nvd_payload()), self.db)
        pdf = self.root / "sample.pdf"
        pdf.write_bytes(b"%PDF-1.7\n<< /OpenAction /JavaScript >>\n%%EOF")
        digest = __import__("hashlib").sha256(pdf.read_bytes()).hexdigest()
        sample_path = self.write_json("samples.json", {"samples": [{
            "sample_id": "ANALYSIS-EXACT", "sha256": digest, "file_type": "pdf",
            "label": "suspicious", "source_name": "synthetic unit test", "label_basis": "test-only exact hash",
            "confidence": "low", "cve_links": [{"cve_id": "CVE-2099-12345", "evidence_basis": "synthetic test relation", "confidence": "low"}]
        }]})
        import_reference_samples_json(sample_path, self.db)
        report = analyze_file(pdf, self.db, target_product="example pdf_reader")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        self.assertEqual(report["target_context"]["candidate_cves"][0]["cve_id"], "CVE-2099-12345")
        self.assertEqual(report["reference_sample_matches"][0]["sample_id"], "ANALYSIS-EXACT")
        association = report["cve_associations"][0]
        self.assertEqual(association["cve_id"], "CVE-2099-12345")
        self.assertEqual(
            association["association_basis_types"],
            ["exact_sha256_sample_match", "product_context"],
        )
        sample_basis = next(
            item for item in association["association_bases"]
            if item["type"] == "exact_sha256_sample_match"
        )
        self.assertFalse(sample_basis["link_verified"])
        self.assertEqual(sample_basis["link_confidence"], "low")
        self.assertIn("not_proof_of_exploitability", association["assessment"])
        loaded = get_analysis(report["analysis_id"], self.db)
        self.assertEqual(loaded["file"]["sha256"], report["file"]["sha256"])
        self.assertEqual(loaded["cve_associations"], report["cve_associations"])
        self.assertIsInstance(loaded["evidence"][0]["value"], (str, int))
        self.assertEqual(len(loaded["evidence"]), len(report["evidence"]))
        self.assertEqual(loaded["stored_candidates"][0]["assessment"], association["assessment"])

    def test_stats_has_schema_sources_and_count(self):
        self.assertEqual(get_stats(self.db)["schema_version"], str(SCHEMA_VERSION))
        self.assertEqual(get_stats(self.db)["vulnerabilities"], 0)


class MigrationTests(unittest.TestCase):
    def test_migrates_legacy_v1_source_sync_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.sqlite3"
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                INSERT INTO schema_meta VALUES('schema_version','1');
                CREATE TABLE source_sync(source TEXT PRIMARY KEY,last_success_at TEXT,records_seen INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'never_run',details TEXT);
            """)
            conn.commit(); conn.close()
            init_db(path)
            with connect(path) as migrated:
                columns = {row[1] for row in migrated.execute("PRAGMA table_info(source_sync)")}
                self.assertIn("last_attempt_at", columns)
                self.assertEqual(migrated.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "2")


class ReportAndCLITests(TempProject):
    def test_report_html_escapes_untrusted_filename(self):
        # Windows forbids angle brackets in actual filenames. Test this HTML
        # trust boundary by injecting an untrusted filename into the report
        # object rather than creating an OS-level filename that is not portable.
        pdf = self.root / "sample.pdf"
        pdf.write_bytes(b"%PDF-1.7")
        with self.capture_expected_pdf_parser_warning():
            report = analyze_pdf(pdf)
        report["file"]["filename"] = "<script>alert(1)</script>.pdf"
        rendered = to_html(report)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;.pdf", rendered)

    def test_markdown_report_includes_structural_finding_location(self):
        report = {
            "file": {"filename": "sample.pdf", "file_type": "pdf", "size_bytes": 100, "sha256": "a" * 64},
            "assessment": {"verdict": "not_assessed"},
            "metrics": {"pdf_header_found": True, "global_byte_entropy_bits_per_byte": 2.0},
            "structural_analysis": {"status": "parsed", "parser": "pypdf", "parser_version": "6.21.1",
                                    "page_count_declared": 1, "encrypted": False, "containers_inspected": 5,
                                    "truncated": False, "features": {}},
            "evidence": [{
                "evidence_type": "pdf_structural_finding",
                "key": "pdf.structure.finding.action_type",
                "value": "/JavaScript",
                "severity": "info",
                "details": {"object_path": "/Root/Names/JavaScript/[0]/A/S",
                            "object_reference": "12 0 R", "path_truncated": False,
                            "interpretation": "Static structural observation only."},
            }],
            "warnings": [],
        }
        rendered = to_markdown(report)
        self.assertIn("Object path: `/Root/Names/JavaScript/[0]/A/S`", rendered)
        self.assertIn("Object reference: `12 0 R`", rendered)

    def test_html_report_escapes_structural_finding_location(self):
        report = {
            "file": {"filename": "sample.pdf", "file_type": "pdf", "size_bytes": 100, "sha256": "b" * 64},
            "assessment": {"verdict": "not_assessed"},
            "metrics": {"pdf_header_found": True, "global_byte_entropy_bits_per_byte": 2.0},
            "structural_analysis": {},
            "evidence": [{
                "evidence_type": "pdf_structural_finding",
                "key": "pdf.structure.finding.action_type",
                "value": "/JavaScript",
                "severity": "info",
                "details": {"object_path": "/Root/<script>alert(1)</script>",
                            "object_reference": "12 0 R", "path_truncated": False},
            }],
            "warnings": [],
        }
        rendered = to_html(report)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertIn("Object reference", rendered)

    def test_markdown_and_html_report_show_cve_association_bases_safely(self):
        report = {
            "file": {"filename": "sample.pdf", "file_type": "pdf", "size_bytes": 100, "sha256": "c" * 64},
            "assessment": {"verdict": "not_assessed"},
            "metrics": {"pdf_header_found": True, "global_byte_entropy_bits_per_byte": 2.0},
            "structural_analysis": {},
            "evidence": [],
            "target_context": {"target_product": "log4j", "candidate_cves": []},
            "cve_association_policy": "Associations are candidates only.",
            "cve_associations": [{
                "cve_id": "CVE-2099-12345", "description": "Synthetic test record",
                "cvss_score": 8.1, "cvss_severity": "HIGH", "cisa_kev": False, "epss_score": None,
                "assessment": "exact_sample_link_not_proof_of_exploitability",
                "association_bases": [{
                    "type": "exact_sha256_sample_match", "sample_id": "SAMPLE-001",
                    "sample_label": "suspicious", "sample_confidence": "low",
                    "link_confidence": "low", "link_verified": False,
                    "link_evidence_basis": "test-only metadata", "interpretation": "Not proof of exploitability.",
                    "sample_source_name": "unit test",
                }],
                "association_basis_types": ["exact_sha256_sample_match"],
            }],
            "warnings": [],
        }
        markdown = to_markdown(report)
        html_report = to_html(report)
        self.assertIn("## CVE association candidates", markdown)
        self.assertIn("exact SHA-256 match to registered sample", markdown)
        self.assertIn("link verified: no", markdown)
        self.assertIn("CVE-2099-12345", html_report)
        self.assertIn("test-only metadata", html_report)
        self.assertIn("Not proof of exploitability.", html_report)
        self.assertNotIn("<script>", html_report)

    def test_markdown_report_mentions_not_assessed(self):
        pdf = self.root / "sample.pdf"
        pdf.write_bytes(b"%PDF-1.7")
        with self.capture_expected_pdf_parser_warning():
            rendered = to_markdown(analyze_pdf(pdf))
        self.assertIn("not_assessed", rendered)
        self.assertIn("not a malware verdict", rendered)

    def test_cli_init_stats_doctor(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--db", str(self.db), "init-db"]), 0)
            self.assertEqual(main(["--db", str(self.db), "stats"]), 0)
            self.assertEqual(main(["--db", str(self.db), "doctor"]), 0)
        self.assertIn('"healthy": true', output.getvalue())

    def test_cli_import_and_search(self):
        nvd_path = self.write_json("nvd.json", self.nvd_payload())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--db", str(self.db), "import-nvd", str(nvd_path)]), 0)
            self.assertEqual(main(["--db", str(self.db), "show-cve", "CVE-2099-12345"]), 0)
        self.assertIn("CVE-2099-12345", output.getvalue())

    def test_cli_analyze_writes_report_file(self):
        pdf = self.root / "sample.pdf"
        pdf.write_bytes(b"%PDF-1.7 /OpenAction")
        output = self.root / "reports" / "report.md"
        with self.capture_expected_pdf_parser_warning():
            result = main(["--db", str(self.db), "analyze", str(pdf), "--format", "markdown", "--output", str(output)])
        self.assertEqual(result, 0)
        self.assertTrue(output.exists())
        self.assertIn("CVEvident Analysis Report", output.read_text(encoding="utf-8"))


class DownloadTests(unittest.TestCase):
    class FakeResponse:
        def __init__(self, payload: bytes):
            self.payload = payload
            self.offset = 0
            self.headers = {"Content-Length": str(len(payload))}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1):
            if size < 0: size = len(self.payload) - self.offset
            chunk = self.payload[self.offset:self.offset + size]
            self.offset += len(chunk)
            return chunk

    def test_download_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "download.bin"
            with patch("urllib.request.urlopen", return_value=self.FakeResponse(b"payload")):
                self.assertEqual(download("https://example.test/file", output), output)
            self.assertEqual(output.read_bytes(), b"payload")
            self.assertFalse(list(Path(tmp).glob("*.part")))

    def test_nvd_year_feed_metadata_hash_and_skip(self):
        import hashlib
        import datetime
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "vulns.sqlite3"
            init_db(db)
            year = datetime.datetime.now(datetime.timezone.utc).year
            data = json.dumps({"vulnerabilities": [{"cve": {
                "id": "CVE-2099-12345", "descriptions": [{"lang": "en", "value": "Synthetic annual-feed record"}],
                "references": []
            }}]}).encode()
            expected = hashlib.sha256(data).hexdigest()
            meta = f"lastModifiedDate:2099-01-01T00:00:00.000Z\nsize:{len(data)}\ngzSize:100\nsha256:{expected}\n".encode()
            feed = gzip.compress(data)
            calls = []
            def fake_download(url, destination, timeout=60, max_bytes=500 * 1024 * 1024):
                calls.append(url)
                destination = Path(destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if url.endswith(".meta"):
                    destination.write_bytes(meta)
                else:
                    destination.write_bytes(feed)
                return destination
            with patch("cvevident.sources.download", side_effect=fake_download):
                result = sync_nvd_year(year, db, root / "cache")
                self.assertEqual(result["status"], "imported")
                self.assertEqual(result["records_imported"], 1)
                before_second = len(calls)
                result2 = sync_nvd_year(year, db, root / "cache")
                self.assertEqual(result2["status"], "up_to_date")
                self.assertEqual(len(calls), before_second + 1)  # only META is fetched on an unchanged feed
            self.assertIsNotNone(__import__("cvevident.store", fromlist=["get_cve"]).get_cve("CVE-2099-12345", db))

    def test_nvd_year_rejects_feed_with_wrong_sha256(self):
        import datetime
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); db = root / "db.sqlite3"; init_db(db)
            year = datetime.datetime.now(datetime.timezone.utc).year
            meta = ("lastModifiedDate:2099-01-01T00:00:00.000Z\nsize:10\ngzSize:20\nsha256:" + "0" * 64 + "\n").encode()
            def fake_download(url, destination, timeout=60, max_bytes=500 * 1024 * 1024):
                destination = Path(destination); destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(meta if url.endswith(".meta") else gzip.compress(b'{"vulnerabilities":[]}'))
                return destination
            with patch("cvevident.sources.download", side_effect=fake_download):
                with self.assertRaises(RuntimeError):
                    sync_nvd_year(year, db, root / "cache")
            with connect(db) as conn:
                state = conn.execute("SELECT status FROM source_sync WHERE source=?", (f"NVD yearly {year}",)).fetchone()
                self.assertEqual(state["status"], "error")

    def test_nvd_year_rejects_out_of_range(self):
        import datetime
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "db.sqlite3"
            init_db(db)
            with self.assertRaises(ValueError):
                sync_nvd_year(1999, db, Path(tmp) / "cache")

    def test_download_size_limit_prevents_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "download.bin"
            output.write_bytes(b"old")
            with patch("urllib.request.urlopen", return_value=self.FakeResponse(b"larger payload")):
                with self.assertRaises(RuntimeError):
                    download("https://example.test/file", output, max_bytes=3)
            self.assertEqual(output.read_bytes(), b"old")


if __name__ == "__main__":
    unittest.main(verbosity=2)
