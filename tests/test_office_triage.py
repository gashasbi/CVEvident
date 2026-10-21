from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from cvevident.analyzer import analyze_file
from cvevident.cli import main
from cvevident.office_triage import MAIN_CONTENT_TYPES, OFFICE_EXTENSIONS, analyze_office
from cvevident.db import init_db
from cvevident.reporting import to_html, to_markdown
from cvevident.store import get_analysis


MAIN_PARTS = {
    "docx": "word/document.xml", "docm": "word/document.xml",
    "dotx": "word/document.xml", "dotm": "word/document.xml",
    "xlsx": "xl/workbook.xml", "xlsm": "xl/workbook.xml",
    "xltx": "xl/workbook.xml", "xltm": "xl/workbook.xml",
    "xlsb": "xl/workbook.bin", "xlam": "xl/workbook.xml",
    "pptx": "ppt/presentation.xml", "pptm": "ppt/presentation.xml",
    "ppsx": "ppt/presentation.xml", "ppsm": "ppt/presentation.xml",
    "potx": "ppt/presentation.xml", "potm": "ppt/presentation.xml",
    "ppam": "ppt/presentation.xml", "sldx": "ppt/slides/slide1.xml", "sldm": "ppt/slides/slide1.xml",
}


def create_office_package(path: Path, fmt: str = "docx", extra_parts: dict[str, bytes] | None = None) -> Path:
    content_type = next(key for key, value in MAIN_CONTENT_TYPES.items() if value[0] == fmt)
    main_part = MAIN_PARTS[fmt]
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            f'<Override PartName="/{main_part}" ContentType="{content_type}"/>'
            '</Types>'
        ).encode(),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            f'Target="{main_part}"/>'
            '</Relationships>'
        ).encode(),
    }
    if main_part.endswith(".xml"):
        family = next(value[1] for value in MAIN_CONTENT_TYPES.values() if value[0] == fmt)
        if family == "word":
            body = '<w:document xmlns:w="urn:test:word"><w:body><w:p><w:hyperlink/><w:altChunk/><w:instrText>DDEAUTO file</w:instrText></w:p></w:body></w:document>'
        elif family == "powerpoint":
            body = '<p:presentation xmlns:p="urn:test:ppt"><p:sldIdLst><p:sldId/></p:sldIdLst></p:presentation>'
        else:
            body = '<workbook xmlns="urn:test:excel"><sheets/></workbook>'
        parts[main_part] = body.encode()
    else:
        parts[main_part] = b"\x00\x01\x02binary-workbook-fixture"
    for name, value in (extra_parts or {}).items():
        parts[name] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in parts.items():
            archive.writestr(name, value)
    return path


class OfficeTriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_recognizes_all_supported_office_open_xml_variants(self):
        # All supported document/template/workbook/slideshow/slide content types should
        # be recognized from the package manifest, not just from the filename suffix.
        self.assertEqual(set(MAIN_PARTS), {ext.lstrip(".") for ext in OFFICE_EXTENSIONS})
        for fmt in sorted(MAIN_PARTS):
            with self.subTest(fmt=fmt):
                path = create_office_package(self.root / f"fixture.{fmt}", fmt)
                report = analyze_office(str(path))
                self.assertEqual(report["file"]["file_type"], fmt)
                self.assertEqual(report["office_analysis"]["format_id"], fmt)
                expected_macro_capability = next(value[2] for value in MAIN_CONTENT_TYPES.values() if value[0] == fmt)
                self.assertEqual(report["office_analysis"]["macro_enabled_format"], expected_macro_capability)
                self.assertIn(report["office_analysis"]["status"], {"parsed", "partial"})
                self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_detects_macro_project_and_external_relationships_without_opening_target(self):
        extras = {
            "word/vbaProject.bin": b"not-executable-test-fixture",
            "word/embeddings/oleObject1.bin": b"embedded-fixture",
            "word/activeX/activeX1.bin": b"activex-fixture",
            "word/_rels/document.xml.rels": (
                '<?xml version="1.0"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                'Target="https://example.test/not-opened" TargetMode="External"/>'
                '</Relationships>'
            ).encode(),
        }
        path = create_office_package(self.root / "sample.docm", "docm", extras)
        report = analyze_office(str(path))
        office = report["office_analysis"]
        self.assertTrue(office["macro_enabled_format"])
        self.assertTrue(office["vba_project_present"])
        self.assertEqual(office["features"]["embedded_object_part_count"], 1)
        self.assertEqual(office["features"]["activex_part_count"], 1)
        self.assertEqual(office["features"]["external_relationship_count"], 1)
        self.assertEqual(office["external_relationships"][0]["target"], "https://example.test/not-opened")
        self.assertTrue(any("not opened" in warning for warning in report["warnings"]))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")


    def test_detects_drawingml_ole_and_hyperlink_elements(self):
        # PowerPoint/DrawingML uses the local names oleObj, hlinkClick, and
        # hlinkMouseOver (not the Word-specific names oleObject/hyperlink).
        extras = {
            "ppt/slides/slide1.xml": (
                '<p:sld xmlns:p="urn:test:ppt" xmlns:a="urn:test:drawingml">'
                '<p:oleObj/><a:hlinkClick/><a:hlinkMouseOver/></p:sld>'
            ).encode(),
        }
        path = create_office_package(self.root / "drawingml.pptm", "pptm", extras)
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["ole_object_element_count"], 1)
        self.assertEqual(features["hyperlink_element_count"], 2)

    def test_detects_excel_external_formula_indicators(self):
        extras = {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="urn:test:excel"><sheetData><row><c r="A1">'
                '<f>[Other.xlsx]Sheet1!A1+WEBSERVICE("https://example.test")</f>'
                '</c></row></sheetData></worksheet>'
            ).encode(),
            "xl/externalLinks/externalLink1.xml": b'<externalLink/>',
        }
        path = create_office_package(self.root / "book.xlsm", "xlsm", extras)
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["external_formula_reference_count"], 1)
        self.assertEqual(features["formula_network_function_count"], 1)
        self.assertEqual(features["external_link_part_count"], 1)

    def test_realistic_presentation_with_slide_content_type_is_parsed(self):
        # A normal PPTX manifest declares both presentation.xml and every slide part.
        # Slide content types are not competing package main parts; the root
        # officeDocument relationship selects ppt/presentation.xml.
        manifest = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/ppt/presentation.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            '<Override PartName="/ppt/slides/slide1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
            '</Types>'
        ).encode()
        extras = {
            "[Content_Types].xml": manifest,
            "ppt/slides/slide1.xml": b'<p:sld xmlns:p="urn:test:ppt"><p:cSld/></p:sld>',
            "ppt/slides/_rels/slide1.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
            ).encode(),
        }
        path = create_office_package(self.root / "realistic.pptx", "pptx", extras)
        report = analyze_office(str(path))
        office = report["office_analysis"]
        self.assertEqual(report["file"]["file_type"], "pptx")
        self.assertEqual(office["main_part"], "ppt/presentation.xml")
        self.assertEqual(office["status"], "parsed")
        self.assertFalse(any("multiple conflicting Office main parts" in w for w in report["warnings"]))

    def test_format_is_detected_from_content_type_when_extension_mismatches(self):
        path = create_office_package(self.root / "renamed.docx", "xlsx")
        report = analyze_office(str(path))
        self.assertEqual(report["file"]["file_type"], "xlsx")
        self.assertFalse(report["office_analysis"]["extension_matches_detected_format"])
        self.assertIn("office.extension_mismatch", [item["key"] for item in report["evidence"]])

    def test_zip_container_without_office_manifest_is_not_misclassified(self):
        path = self.root / "not-office.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "ordinary ZIP")
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["status"], "unsupported")
        self.assertEqual(report["file"]["file_type"], "unknown_or_non_office")

    def test_non_zip_with_office_extension_reports_failed_package(self):
        path = self.root / "broken.docx"
        path.write_bytes(b"not a zip package")
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["status"], "failed")
        self.assertEqual(report["file"]["file_type"], "unknown_or_non_office")

    def test_password_protected_ooxml_container_is_not_decrypted(self):
        path = self.root / "protected.docx"
        path.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"opaque protected fixture")
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["status"], "unsupported")
        self.assertTrue(any("not decrypted" in warning for warning in report["warnings"]))


    def test_entry_budget_produces_partial_status_without_extraction(self):
        extras = {f"customXml/item{i}.xml": b"<item/>" for i in range(6)}
        path = create_office_package(self.root / "large-parts.docx", "docx", extras)
        report = analyze_office(str(path), max_archive_entries=3)
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(report["office_analysis"]["truncated"])
        self.assertTrue(any("entries" in warning for warning in report["warnings"]))

    def test_entity_declarations_are_not_processed(self):
        extras = {"word/document.xml": b'<!DOCTYPE x [<!ENTITY boom "boom">]><x>&boom;</x>'}
        path = create_office_package(self.root / "entity.docx", "docx", extras)
        report = analyze_office(str(path))
        self.assertIn(report["office_analysis"]["status"], {"partial", "parsed"})
        self.assertTrue(any("DTD/entity" in warning for warning in report["warnings"]))

    def test_traversal_like_member_is_reported_without_extracting_it(self):
        marker = self.root.parent / "cvevident-no-extract-check.bin"
        self.assertFalse(marker.exists())
        path = create_office_package(
            self.root / "traversal.docx", "docx", {"../cvevident-no-extract-check.bin": b"not extracted"}
        )
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertEqual(report["office_analysis"]["features"]["unsafe_member_name_count"], 1)
        self.assertFalse(marker.exists())

    def test_oversized_xml_part_is_skipped_and_status_is_partial(self):
        large_xml = b"<document>" + (b"<p>bounded</p>" * 100) + b"</document>"
        path = create_office_package(self.root / "oversized-part.docx", "docx", {"word/document.xml": large_xml})
        report = analyze_office(str(path), max_xml_part_bytes=512)
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(any("per-part limit" in warning for warning in report["warnings"]))

    def test_truncated_legacy_binary_office_is_explicitly_failed_by_cfb_analyzer(self):
        path = self.root / "legacy.doc"
        path.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"legacy fixture")
        db_path = self.root / "legacy.sqlite3"
        init_db(db_path)
        report = analyze_file(path, db_path=db_path)
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertIn("header", report["legacy_office_analysis"]["warnings"][0].lower())



class OfficeAnalyzerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "office.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_analyze_file_routes_office_persists_and_replays_report(self):
        path = create_office_package(
            self.root / "sample.pptm",
            "pptm",
            {"ppt/vbaProject.bin": b"synthetic macro fixture"},
        )
        report = analyze_file(path, self.db)
        self.assertEqual(report["file"]["file_type"], "pptm")
        self.assertIn("office_analysis", report)
        self.assertIn("OOXML content-type-based format identification", report["scope"]["implemented"])
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        replayed = get_analysis(report["analysis_id"], self.db)
        self.assertEqual(replayed["file"]["sha256"], report["file"]["sha256"])
        self.assertEqual(replayed["office_analysis"]["format_id"], "pptm")
        self.assertTrue(replayed["office_analysis"]["vba_project_present"])

    def test_cli_analyze_writes_office_report_in_markdown_and_html(self):
        path = create_office_package(self.root / "book.xlsx", "xlsx")
        markdown_path = self.root / "reports" / "office.md"
        html_path = self.root / "reports" / "office.html"
        self.assertEqual(main(["--db", str(self.db), "analyze", str(path), "--format", "markdown", "--output", str(markdown_path)]), 0)
        self.assertEqual(main(["--db", str(self.db), "analyze", str(path), "--format", "html", "--output", str(html_path)]), 0)
        markdown = markdown_path.read_text(encoding="utf-8")
        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("Office package analysis", markdown)
        self.assertIn("xlsx", markdown)
        self.assertIn("Office package analysis", html_text)
        self.assertIn("not a malware verdict", html_text)


if __name__ == "__main__":
    unittest.main()
