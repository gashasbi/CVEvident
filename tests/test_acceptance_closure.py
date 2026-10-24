"""Cross-axis acceptance contracts for the existing CVEvident scope.

These tests intentionally exercise public integration points. They do not claim
full NVD applicability evaluation, dynamic analysis, or a malware verdict.
"""
from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

from pypdf import PdfWriter

from cvevident import __version__
from cvevident.analyzer import analyze_file
from cvevident.cli import main
from cvevident.db import SCHEMA_VERSION, connect, init_db
from cvevident.reporting import serialize_json, to_html, to_markdown
from cvevident.store import get_analysis, get_source_freshness, import_nvd_json

OLE_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")
FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def _minimal_cfb_word() -> bytes:
    """Build the smallest CFB directory fixture used by the existing format tests."""
    sector_size = 512
    header = bytearray(sector_size)
    header[:8] = OLE_SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, 3)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, 0)
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<I", header, 60, EOC)
    struct.pack_into("<I", header, 68, EOC)
    struct.pack_into("<109I", header, 76, 1, *([FREE] * 108))

    directory = bytearray(512)
    for index, (name, kind) in enumerate((("Root Entry", 5), ("WordDocument", 2))):
        entry = memoryview(directory)[index * 128:(index + 1) * 128]
        encoded = name.encode("utf-16le") + b"\x00\x00"
        entry[:len(encoded)] = encoded
        struct.pack_into("<H", entry, 64, len(encoded))
        entry[66] = kind
        entry[67] = 1
        struct.pack_into("<III", entry, 68, FREE, FREE, FREE)
        struct.pack_into("<I", entry, 116, EOC)
        struct.pack_into("<Q", entry, 120, 0)

    fat_values = [FREE] * 128
    fat_values[0] = EOC
    fat_values[1] = FATSECT
    return bytes(header) + bytes(directory) + struct.pack("<128I", *fat_values)


def _minimal_docx(path: Path) -> Path:
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            '</Relationships>'
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p/></w:body></w:document>'
        ),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in parts.items():
            archive.writestr(name, value)
    return path


def _minimal_odt_bytes() -> bytes:
    stream = BytesIO()
    mime = "application/vnd.oasis.opendocument.text"
    manifest = (
        '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
        'manifest:version="1.2"><manifest:file-entry manifest:full-path="/" '
        'manifest:media-type="application/vnd.oasis.opendocument.text"/></manifest:manifest>'
    )
    content = (
        '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2">'
        '<office:body><office:text><text:p>acceptance fixture</text:p></office:text></office:body>'
        '</office:document-content>'
    )
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("mimetype", mime, compress_type=zipfile.ZIP_STORED)
        archive.writestr("META-INF/manifest.xml", manifest)
        archive.writestr("content.xml", content)
    return stream.getvalue()


def _minimal_pdf(path: Path, *, marker: bool = False) -> Path:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as handle:
        writer.write(handle)
    if marker:
        with path.open("ab") as handle:
            handle.write(b"\n% static acceptance comment /JavaScript /OpenAction\n")
    return path


def _synthetic_nvd_payload() -> dict[str, object]:
    return {
        "vulnerabilities": [{"cve": {
            "id": "CVE-2099-12345",
            "published": "2099-01-01T00:00:00.000Z",
            "lastModified": "2099-01-02T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Synthetic acceptance-only record"}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                "vulnerable": True,
                "versionStartIncluding": "1.0",
                "versionEndExcluding": "3.0",
            }]}]}],
        }}]
    }


class ProjectAcceptanceClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "acceptance.sqlite3"
        init_db(self.db)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_supported_format_families_share_truthful_report_and_traceability_contract(self) -> None:
        pdf = _minimal_pdf(self.root / "sample.pdf", marker=True)
        docx = _minimal_docx(self.root / "sample.docx")
        odt = self._write("sample.odt", _minimal_odt_bytes())
        cfb = self._write("legacy.doc", _minimal_cfb_word())
        rtf = self._write("sample.rtf", b'{\\rtf1\\ansi{\\field{\\*\\fldinst HYPERLINK "https://example.invalid"}{\\fldrslt link}}}')
        cases = ((pdf, "pdf"), (docx, "docx"), (odt, "odt"), (cfb, "doc"), (rtf, "rtf"))

        for path, expected_type in cases:
            with self.subTest(file_type=expected_type):
                report = analyze_file(path, self.db)
                self.assertEqual(report["file"]["file_type"], expected_type)
                self.assertEqual(report["assessment"]["verdict"], "not_assessed")
                self.assertIn("analysis_coverage", report)
                self.assertIn("evidence_traceability", report)
                self.assertIn(
                    "does not establish that the file is safe",
                    report["analysis_coverage"]["absence_of_findings_means"],
                )
                evidence = report["evidence"]
                evidence_ids = [item.get("evidence_id") for item in evidence]
                self.assertTrue(evidence_ids)
                self.assertEqual(len(evidence_ids), len(set(evidence_ids)))
                for item in evidence:
                    self.assertTrue(item.get("evidence_id"))
                    self.assertEqual(item["source_locator"].get("input_sha256"), report["file"]["sha256"])
                    self.assertEqual(
                        item["details"]["traceability"]["evidence_id"],
                        item["evidence_id"],
                    )

                loaded = get_analysis(report["analysis_id"], self.db)
                self.assertIsNotNone(loaded)
                loaded_ids = [item.get("evidence_id") for item in loaded["evidence"]]
                self.assertEqual(loaded_ids, evidence_ids)
                self.assertTrue(all(item.get("source_locator") for item in loaded["evidence"]))
                markdown = to_markdown(loaded)
                html = to_html(loaded)
                self.assertIn("Evidence ID", markdown)
                self.assertIn("Evidence ID", html)
                self.assertIn("does not establish that the file is safe", markdown.lower())
                self.assertIn("CVEvident Analysis Report", html)
                encoded = json.loads(serialize_json(loaded))
                self.assertEqual(
                    [item["evidence_id"] for item in encoded["evidence"]], evidence_ids
                )

    def test_signature_based_dispatch_keeps_misnamed_odf_explicitly_partial(self) -> None:
        misnamed = self._write("package.docx", _minimal_odt_bytes())
        report = analyze_file(misnamed, self.db)
        self.assertEqual(report["file"]["file_type"], "odt")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("extension" in warning.lower() for warning in report["warnings"]))

    def test_unknown_and_corrupt_inputs_are_never_promoted_to_safe(self) -> None:
        unknown = self._write("unknown.bin", b"not a supported document\x00\x01")
        report = analyze_file(unknown, self.db)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        self.assertFalse(report["analysis_coverage"]["complete_for_declared_static_scope"])
        self.assertTrue(any("not recognized as a supported format" in reason for reason in report["analysis_coverage"]["limitation_reasons"]))
        self.assertIn("does not establish that the file is safe", report["analysis_coverage"]["absence_of_findings_means"])

        corrupt = self._write("corrupt.odt", b"PK\x03\x04 definitely not a usable zip")
        failed = analyze_file(corrupt, self.db)
        self.assertEqual(failed["assessment"]["verdict"], "not_assessed")
        self.assertEqual(failed["odf_analysis"]["status"], "failed")
        self.assertFalse(failed["analysis_coverage"]["complete_for_declared_static_scope"])

    def test_analysis_database_write_failure_rolls_back_run_and_evidence_rows(self) -> None:
        pdf = _minimal_pdf(self.root / "write-failure.pdf")
        with connect(self.db) as conn:
            conn.execute(
                """CREATE TRIGGER fail_evidence_insert BEFORE INSERT ON evidence
                   BEGIN SELECT RAISE(ABORT, 'synthetic evidence write failure'); END"""
            )

        with self.assertRaises(sqlite3.IntegrityError):
            analyze_file(pdf, self.db)

        with connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)

    def test_repeated_analysis_has_distinct_ids_and_stable_file_identity(self) -> None:
        rtf = self._write("repeat.rtf", b"{\\rtf1\\ansi stable fixture}")
        first = analyze_file(rtf, self.db)
        second = analyze_file(rtf, self.db)
        self.assertNotEqual(first["analysis_id"], second["analysis_id"])
        self.assertLess(first["analysis_id"], second["analysis_id"])
        self.assertEqual(first["file"]["sha256"], second["file"]["sha256"])
        for analysis_id in (first["analysis_id"], second["analysis_id"]):
            stored = get_analysis(analysis_id, self.db)
            self.assertIsNotNone(stored)
            self.assertEqual(stored["file"]["sha256"], first["file"]["sha256"])
            self.assertTrue(all(e.get("evidence_id") for e in stored["evidence"]))

    def test_concurrent_analysis_writes_keep_unique_ids_and_database_integrity(self) -> None:
        paths = [
            self._write(f"parallel-{index}.rtf", f"{{\\rtf1\\ansi parallel fixture {index}}}".encode())
            for index in range(4)
        ]
        with ThreadPoolExecutor(max_workers=4) as pool:
            reports = list(pool.map(lambda path: analyze_file(path, self.db), paths))

        ids = [report["analysis_id"] for report in reports]
        self.assertEqual(len(ids), len(set(ids)))
        with connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 4)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], sum(len(r["evidence"]) for r in reports))
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_failed_analysis_cli_returns_nonzero_and_does_not_persist_analysis(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--db", str(self.db), "analyze", str(self.root / "missing.pdf")])
        self.assertNotEqual(code, 0)
        with connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 0)
        self.assertTrue(stderr.getvalue().strip() or stdout.getvalue().strip())

    def test_package_version_and_database_schema_remain_at_the_declared_baseline(self) -> None:
        self.assertEqual(__version__, "0.1.0")
        self.assertEqual(SCHEMA_VERSION, 2)

    def test_configured_file_size_limit_is_enforced_before_persistent_analysis(self) -> None:
        path = self._write("oversized.rtf", b"{\\rtf1\\ansi " + b"A" * 4096 + b"}")
        with self.assertRaises(ValueError):
            analyze_file(path, self.db, max_bytes=128)
        with connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 0)

    def test_local_source_freshness_is_unknown_before_successful_import(self) -> None:
        freshness = get_source_freshness(self.db)
        for source_name in ("NVD", "CISA KEV", "FIRST EPSS"):
            self.assertIn(source_name, freshness["sources"])
            record = freshness["sources"][source_name]
            self.assertEqual(record["state"], "never_run")
            self.assertIsNone(record["last_success_at"])

    def test_product_cve_evidence_reference_resolves_through_report_and_database(self) -> None:
        nvd_file = self.root / "nvd.json"
        nvd_file.write_text(json.dumps(_synthetic_nvd_payload()), encoding="utf-8")
        self.assertEqual(import_nvd_json(nvd_file, self.db), 1)
        rtf = self._write("context.rtf", b"{\\rtf1\\ansi product context only}")

        report = analyze_file(
            rtf, self.db, target_product="log4j", target_vendor="apache", target_version="2.14.1"
        )
        candidate = report["target_context"]["candidate_cves"][0]
        self.assertEqual(candidate["cve_id"], "CVE-2099-12345")
        self.assertEqual(candidate["version_match_status"], "within_declared_numeric_version_bounds")
        evidence_by_id = {item["evidence_id"]: item for item in report["evidence"]}
        self.assertIn(candidate["evidence_id"], evidence_by_id)
        association = next(item for item in report["cve_associations"] if item["cve_id"] == candidate["cve_id"])
        product_basis = next(basis for basis in association["association_bases"] if basis["type"] == "product_context")
        reference = product_basis["evidence_reference"]
        self.assertEqual(reference["resolution"], "resolved")
        self.assertEqual(reference["evidence_id"], candidate["evidence_id"])
        self.assertEqual(association["assessment"], "product_context_candidate_not_file_attribution")
        self.assertFalse(report["analysis_coverage"]["cve_file_attribution_performed"])

    def test_malformed_nvd_import_leaves_no_partial_rows(self) -> None:
        malformed = self.root / "broken-nvd.json"
        valid_prefix = json.dumps(_synthetic_nvd_payload())
        malformed.write_text(valid_prefix + " trailing-garbage", encoding="utf-8")
        with self.assertRaises(ValueError):
            import_nvd_json(malformed, self.db)
        with connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM affected_products").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
