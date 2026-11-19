from __future__ import annotations

import struct
import tempfile
import warnings
import unittest
import zipfile
from pathlib import Path

from cvevident.analyzer import analyze_file
from cvevident.cli import main
from cvevident.office_triage import MAX_COMPRESSION_RATIO, MAIN_CONTENT_TYPES, OFFICE_EXTENSIONS, analyze_office
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



    def test_external_relationships_are_classified_without_fetching_targets(self):
        extras = {
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                'Target="https://example.test/document|note" TargetMode="External"/>'
                '<Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="mhtml:https://example.test/payload!x-usc:https://example.test/remote.html" TargetMode="External"/>'
                '<Relationship Id="r3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                'Target="\\\\fileserver\\templates\\template.dotm" TargetMode="External"/>'
                '<Relationship Id="r4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath" '
                'Target="file:///C:/data/book.xlsx" TargetMode="External"/>'
                '<Relationship Id="r5" Type="https://example.test/relationships/custom" '
                'Target="urn:example:external" TargetMode="External"/>'
                '</Relationships>'
            ).encode(),
        }
        path = create_office_package(
            self.root / "relationship-classification.docm", "docm", extras
        )
        report = analyze_office(str(path))
        office = report["office_analysis"]
        relationships = office["external_relationships"]

        self.assertEqual(office["features"]["external_relationship_count"], 5)
        by_kind = {item.get("relationship_kind"): item for item in relationships}

        self.assertEqual(by_kind["hyperlink"]["target_kind"], "https_url")
        self.assertEqual(by_kind["hyperlink"]["target_scheme"], "https")
        self.assertEqual(by_kind["ole_object"]["target_kind"], "mhtml_uri")
        self.assertEqual(by_kind["ole_object"]["target_scheme"], "mhtml")
        self.assertEqual(by_kind["attached_template"]["target_kind"], "unc_path")
        self.assertIsNone(by_kind["attached_template"]["target_scheme"])
        self.assertEqual(by_kind["external_link_path"]["target_kind"], "file_uri")
        self.assertEqual(by_kind["external_link_path"]["target_scheme"], "file")
        self.assertEqual(by_kind["other"]["target_kind"], "other_uri")
        self.assertEqual(by_kind["other"]["target_scheme"], "urn")

        markdown = to_markdown(report)
        html = to_html(report)
        self.assertEqual(by_kind["hyperlink"]["target"], "https://example.test/document|note")
        self.assertIn("Relationship kind", markdown)
        self.assertIn("https_url", markdown)
        self.assertIn("mhtml_uri", markdown)
        self.assertIn(r"https://example.test/document\|note", markdown)
        self.assertIn("Relationship kind", html)
        self.assertIn("<h3>External relationships (targets not opened)</h3>", html)
        self.assertIn("mhtml_uri", html)
        self.assertIn("<td>https://example.test/document|note</td>", html)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        self.assertTrue(any("not opened" in warning.lower() for warning in office["warnings"]))


    def test_external_attached_template_relationship_is_reported_separately(self):
        extras = {
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rTemplate" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                'Target="https://example.test/template.dotm" TargetMode="External"/>'
                '</Relationships>'
            ).encode(),
            "xl/connections.xml": b"<connections/>",
            "xl/queryTables/queryTable1.xml": b"<queryTable/>",
        }
        path = create_office_package(self.root / "template.docm", "docm", extras)
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]

        self.assertEqual(features["external_attached_template_relationship_count"], 1)
        self.assertEqual(features["external_connection_part_count"], 1)
        self.assertEqual(features["query_table_part_count"], 1)
        self.assertEqual(report["office_analysis"]["external_relationships"][0]["relationship_kind"], "attached_template")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_object_metadata_is_linked_to_internal_embedded_part(self):
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" ProgID="Package" '
                'ShapeID="_x0000_i1025" DrawAspect="Content" ObjectID="_123456" '
                'r:id="rIdEmb1"/></w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdEmb1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/oleObject1.bin"/>'
                '</Relationships>'
            ).encode(),
            "word/embeddings/oleObject1.bin": b"static-ole-fixture",
        }
        path = create_office_package(
            self.root / "ole-object-metadata.docm", "docm", extras
        )
        report = analyze_file(path)
        office = report["office_analysis"]

        references = office["ole_object_references"]
        self.assertEqual(len(references), 1)
        ole = references[0]
        self.assertEqual(ole["source_part"], "word/document.xml")
        self.assertEqual(ole["relationship_id"], "rIdEmb1")
        self.assertEqual(ole["prog_id"], "Package")
        self.assertEqual(ole["shape_id"], "_x0000_i1025")
        self.assertEqual(ole["object_id"], "_123456")
        self.assertEqual(ole["draw_aspect"], "Content")
        self.assertEqual(ole["embedded_part"], "word/embeddings/oleObject1.bin")
        self.assertTrue(ole["embedded_part_present"])
        self.assertEqual(office["features"]["ole_object_element_count"], 1)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")
        ole_evidence = [
            item for item in report["evidence"]
            if item.get("evidence_type") == "office_ole_object_reference"
        ]
        self.assertEqual(len(ole_evidence), 1)
        trace = ole_evidence[0]["details"]["traceability"]
        self.assertEqual(ole_evidence[0]["details"]["object_type"], "Embed")
        self.assertEqual(
            trace["extraction_method"], "bounded_ooxml_zip_and_xml_inspection"
        )
        self.assertEqual(trace["observed_value"], "word/embeddings/oleObject1.bin")
        self.assertEqual(trace["source_locator"]["kind"], "package_member_location")
        self.assertEqual(
            trace["source_locator"]["package_member"], "word/document.xml"
        )
        self.assertEqual(
            trace["source_locator"]["relationship_type"],
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
        )
        self.assertEqual(trace["source_locator"]["relationship_id"], "rIdEmb1")
        self.assertEqual(
            trace["source_locator"]["target"],
            "word/embeddings/oleObject1.bin",
        )
        self.assertEqual(trace["source_locator"]["element"], "OLEObject")

    def test_ole_embedded_payload_signatures_are_identified_with_bounded_reads(self):
        signatures = [
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_cfb", "cfb_header"),
            (b"%PDF-1.7\n", "pdf", "pdf_header"),
            (b"PK\x03\x04", "zip", "zip_local_file_header"),
            (b"PK\x05\x06", "zip", "zip_empty_archive"),
            (b"PK\x07\x08", "zip", "zip_spanned_archive"),
            (b"{\\rtf1", "rtf", "rtf_header"),
            (b"MZ", "mz_executable", "mz_header"),
            (b"\x7fELF", "elf_binary", "elf_header"),
            (b"MSCF", "cab_archive", "cab_header"),
            (b"\x1f\x8b", "gzip", "gzip_header"),
            (b"7z\xbc\xaf\x27\x1c", "7z", "7z_header"),
            (b"Rar!\x1a\x07\x00", "rar", "rar4_header"),
            (b"Rar!\x1a\x07\x01\x00", "rar", "rar5_header"),
        ]

        for index, (header, expected_kind, expected_signature) in enumerate(signatures):
            with self.subTest(kind=expected_kind, signature=expected_signature):
                payload = header + (b"X" * 128)
                relationship_id = f"rIdSignature{index}"
                extras = {
                    "word/document.xml": (
                        '<w:document xmlns:w="urn:test:word" '
                        'xmlns:o="urn:test:office" '
                        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                        f'<w:body><w:object><o:OLEObject Type="Embed" r:id="{relationship_id}"/>'
                        '</w:object></w:body></w:document>'
                    ).encode(),
                    "word/_rels/document.xml.rels": (
                        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                        f'<Relationship Id="{relationship_id}" '
                        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                        f'Target="embeddings/payload{index}.bin"/>'
                        '</Relationships>'
                    ).encode(),
                    f"word/embeddings/payload{index}.bin": payload,
                }
                path = create_office_package(
                    self.root / f"ole-signature-{index}.docx", "docx", extras
                )
                report = analyze_file(path)
                ole = report["office_analysis"]["ole_object_references"][0]

                self.assertEqual(ole["embedded_content_status"], "identified")
                self.assertEqual(ole["embedded_content_kind"], expected_kind)
                self.assertEqual(
                    ole["embedded_content_signature"], expected_signature
                )
                self.assertEqual(
                    ole["embedded_content_bytes_inspected"], 64
                )

    def test_ole_embedded_payload_with_unknown_signature_is_not_misclassified(self):
        payload = b"UNKNOWN-CONTENT-" + (b"X" * 128)
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" r:id="rIdUnknown"/>'
                '</w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdUnknown" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/unknown.bin"/>'
                '</Relationships>'
            ).encode(),
            "word/embeddings/unknown.bin": payload,
        }
        path = create_office_package(
            self.root / "ole-unknown-payload.docx", "docx", extras
        )
        report = analyze_file(path)
        ole = report["office_analysis"]["ole_object_references"][0]

        self.assertEqual(ole["embedded_content_status"], "unrecognized")
        self.assertIsNone(ole["embedded_content_kind"])
        self.assertIsNone(ole["embedded_content_signature"])
        self.assertEqual(ole["embedded_content_bytes_inspected"], 64)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_duplicate_embedded_member_is_reported_as_ambiguous(self):
        member_name = "word/embeddings/duplicate.bin"
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" r:id="rIdDuplicate"/>'
                '</w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdDuplicate" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/duplicate.bin"/>'
                '</Relationships>'
            ).encode(),
            member_name: b"%PDF-1.7\\nfirst-payload",
        }
        path = create_office_package(
            self.root / "ole-duplicate-member.docx", "docx", extras
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr(member_name, b"%PDF-1.7\\nsecond-payload")

        report = analyze_file(path)
        ole = report["office_analysis"]["ole_object_references"][0]

        self.assertEqual(ole["relationship_status"], "ambiguous_embedded_part")
        self.assertTrue(ole["embedded_part_present"])
        self.assertTrue(ole["embedded_part_ambiguous"])
        self.assertEqual(ole["embedded_content_status"], "not_inspected")
        self.assertEqual(ole["embedded_content_bytes_inspected"], 0)
        self.assertIsNone(ole["embedded_content_kind"])

        ole_evidence = [
            item for item in report["evidence"]
            if item.get("evidence_type") == "office_ole_object_reference"
        ]
        self.assertEqual(len(ole_evidence), 1)
        details = ole_evidence[0]["details"]
        self.assertTrue(details["embedded_part_present"])
        self.assertTrue(details["embedded_part_ambiguous"])
        self.assertEqual(
            details["relationship_status"], "ambiguous_embedded_part"
        )

        markdown = to_markdown(report)
        self.assertIn("ambiguous_embedded_part", markdown)
        html = to_html(report)
        self.assertIn("ambiguous_embedded_part", html)

        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_encrypted_embedded_member_is_not_reported_missing(self):
        member_name = "word/embeddings/encrypted.bin"
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" r:id="rIdEncrypted"/>'
                '</w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdEncrypted" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/encrypted.bin"/>'
                '</Relationships>'
            ).encode(),
            member_name: b"%PDF-1.7\\nstatic-encrypted-fixture",
        }
        path = create_office_package(
            self.root / "ole-encrypted-member.docx", "docx", extras
        )

        raw = bytearray(path.read_bytes())
        with zipfile.ZipFile(path, "r") as archive:
            info = archive.getinfo(member_name)
            local_offset = info.header_offset
            local_flags = struct.unpack_from("<H", raw, local_offset + 6)[0]
            struct.pack_into("<H", raw, local_offset + 6, local_flags | 0x1)

            position = archive.start_dir
            target_name = member_name.encode()
            central_found = False
            while position < len(raw):
                if raw[position:position + 4] != b"PK\x01\x02":
                    break
                filename_length, extra_length, comment_length = struct.unpack_from(
                    "<HHH", raw, position + 28
                )
                filename_start = position + 46
                filename = bytes(raw[filename_start:filename_start + filename_length])
                if filename == target_name:
                    central_flags = struct.unpack_from("<H", raw, position + 8)[0]
                    struct.pack_into("<H", raw, position + 8, central_flags | 0x1)
                    central_found = True
                    break
                position += 46 + filename_length + extra_length + comment_length

        self.assertTrue(central_found)
        path.write_bytes(raw)

        report = analyze_file(path)
        ole = report["office_analysis"]["ole_object_references"][0]

        self.assertEqual(ole["relationship_status"], "linked")
        self.assertTrue(ole["embedded_part_present"])
        self.assertEqual(
            ole["embedded_content_status"], "skipped_encrypted"
        )
        self.assertEqual(
            ole["embedded_content_skip_reason"], "encrypted_member"
        )
        self.assertEqual(ole["embedded_content_bytes_inspected"], 0)
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_embedded_member_with_unsupported_compression_is_skipped(self):
        member_name = "word/embeddings/unsupported.bin"
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" r:id="rIdUnsupported"/>'
                '</w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdUnsupported" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/unsupported.bin"/>'
                '</Relationships>'
            ).encode(),
            member_name: b"%PDF-1.7\\nstatic-unsupported-compression-fixture",
        }
        path = create_office_package(
            self.root / "ole-unsupported-compression.docx", "docx", extras
        )

        raw = bytearray(path.read_bytes())
        with zipfile.ZipFile(path, "r") as archive:
            info = archive.getinfo(member_name)
            struct.pack_into("<H", raw, info.header_offset + 8, 99)

            position = archive.start_dir
            target_name = member_name.encode()
            central_found = False
            while position < len(raw):
                if raw[position:position + 4] != b"PK\x01\x02":
                    break
                filename_length, extra_length, comment_length = struct.unpack_from(
                    "<HHH", raw, position + 28
                )
                filename_start = position + 46
                filename = bytes(raw[filename_start:filename_start + filename_length])
                if filename == target_name:
                    struct.pack_into("<H", raw, position + 10, 99)
                    central_found = True
                    break
                position += 46 + filename_length + extra_length + comment_length

        self.assertTrue(central_found)
        path.write_bytes(raw)

        report = analyze_file(path)
        ole = report["office_analysis"]["ole_object_references"][0]

        self.assertEqual(ole["relationship_status"], "linked")
        self.assertEqual(
            ole["embedded_content_status"], "skipped_unsupported_compression"
        )
        self.assertEqual(
            ole["embedded_content_skip_reason"], "unsupported_compression_method"
        )
        self.assertEqual(ole["embedded_content_bytes_inspected"], 0)
        self.assertIsNone(ole["embedded_content_kind"])
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_embedded_payload_with_excessive_compression_is_not_read(self):
        payload = b"A" * (8 * 1024 * 1024)
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" r:id="rIdCompressed"/>'
                '</w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdCompressed" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/compressed.bin"/>'
                '</Relationships>'
            ).encode(),
            "word/embeddings/compressed.bin": payload,
        }
        path = create_office_package(
            self.root / "ole-compression-limit.docx", "docx", extras
        )

        with zipfile.ZipFile(path, "r") as archive:
            info = archive.getinfo("word/embeddings/compressed.bin")
            self.assertGreater(
                info.file_size / info.compress_size, MAX_COMPRESSION_RATIO
            )

        report = analyze_file(path)
        ole = report["office_analysis"]["ole_object_references"][0]

        self.assertEqual(ole["relationship_status"], "linked")
        self.assertEqual(
            ole["embedded_content_status"], "skipped_compression_ratio"
        )
        self.assertEqual(
            ole["embedded_content_skip_reason"], "compression_ratio_limit"
        )
        self.assertEqual(ole["embedded_content_bytes_inspected"], 0)
        self.assertIsNone(ole["embedded_content_kind"])
        self.assertIsNone(ole["embedded_content_signature"])
        self.assertEqual(report["office_analysis"]["status"], "partial")

        ole_evidence = [
            item for item in report["evidence"]
            if item.get("evidence_type") == "office_ole_object_reference"
        ]
        self.assertEqual(len(ole_evidence), 1)
        self.assertEqual(
            ole_evidence[0]["details"]["embedded_content_status"],
            "skipped_compression_ratio",
        )
        self.assertEqual(
            ole_evidence[0]["details"]["embedded_content_skip_reason"],
            "compression_ratio_limit",
        )

        markdown = to_markdown(report)
        self.assertIn("skipped_compression_ratio", markdown)
        self.assertIn("compression_ratio_limit", markdown)

        html = to_html(report)
        self.assertIn("skipped_compression_ratio", html)
        self.assertIn("compression_ratio_limit", html)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_object_embedded_payload_signature_identifies_pdf(self):
        payload = b"%PDF-1.7\\nstatic-pdf-fixture"
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" '
                'ProgID="Package" r:id="rIdPdf"/></w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdPdf" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/document.bin"/>'
                '</Relationships>'
            ).encode(),
            "word/embeddings/document.bin": payload,
        }
        path = create_office_package(
            self.root / "ole-embedded-pdf.docx", "docx", extras
        )
        report = analyze_file(path)
        references = report["office_analysis"]["ole_object_references"]

        self.assertEqual(len(references), 1)
        ole = references[0]
        self.assertEqual(ole["relationship_status"], "linked")
        self.assertEqual(ole["embedded_content_status"], "identified")
        self.assertEqual(ole["embedded_content_kind"], "pdf")
        self.assertEqual(ole["embedded_content_signature"], "pdf_header")
        self.assertEqual(
            ole["embedded_content_bytes_inspected"], len(payload)
        )
        ole_evidence = [
            item for item in report["evidence"]
            if item.get("evidence_type") == "office_ole_object_reference"
        ]
        self.assertEqual(len(ole_evidence), 1)
        details = ole_evidence[0]["details"]
        self.assertEqual(details["embedded_content_status"], "identified")
        self.assertEqual(details["embedded_content_kind"], "pdf")
        self.assertEqual(details["embedded_content_signature"], "pdf_header")
        self.assertEqual(details["embedded_content_bytes_inspected"], len(payload))
        self.assertIn("bounded prefix", details["interpretation"].casefold())
        self.assertIn("not executed", details["interpretation"].casefold())

        markdown = to_markdown(report)
        self.assertIn("Embedded content kind", markdown)
        self.assertIn("pdf_header", markdown)
        self.assertIn("bounded payload signature", markdown.casefold())
        self.assertNotIn("payload bytes not read", markdown.casefold())

        html = to_html(report)
        self.assertIn("pdf_header", html)
        self.assertIn("bounded payload signature", html.casefold())
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_ole_object_rejects_unrecognized_relationship_type_uri(self):
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body><w:object><o:OLEObject Type="Embed" '
                'ProgID="Package" r:id="rIdForged"/></w:object></w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdForged" '
                'Type="https://attacker.example/types/oleObject" '
                'Target="embeddings/payload.bin"/>'
                '</Relationships>'
            ).encode(),
            "word/embeddings/payload.bin": b"static-ole-fixture",
        }
        path = create_office_package(
            self.root / "ole-forged-relationship.docm", "docm", extras
        )
        report = analyze_file(path)
        references = report["office_analysis"]["ole_object_references"]

        self.assertEqual(len(references), 1)
        self.assertEqual(
            references[0]["relationship_status"], "relationship_not_found"
        )
        self.assertIsNone(references[0]["embedded_part"])

    def test_ole_object_links_fail_closed_for_ambiguous_missing_and_unsafe_targets(self):
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word" '
                'xmlns:o="urn:test:office" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<w:body>'
                '<o:OLEObject ProgID="Unsafe" r:id="rUnsafe"/>'
                '<o:OLEObject ProgID="Missing" r:id="rMissing"/>'
                '<o:OLEObject ProgID="Ambiguous" r:id="rAmbiguous"/>'
                '<o:OLEObject ProgID="NoRelationshipId"/>'
                '</w:body></w:document>'
            ).encode(),
            "word/_rels/document.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rUnsafe" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="%2e%2e/%2e%2e/outside.bin"/>'
                '<Relationship Id="rMissing" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/missing.bin"/>'
                '<Relationship Id="rAmbiguous" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/first.bin"/>'
                '<Relationship Id="rAmbiguous" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
                'Target="embeddings/second.bin"/>'
                '</Relationships>'
            ).encode(),
        }
        path = create_office_package(
            self.root / "ole-object-invalid-links.docm", "docm", extras
        )

        report = analyze_file(path)
        references = report["office_analysis"]["ole_object_references"]
        by_id = {
            item["relationship_id"]: item
            for item in references
            if item["relationship_id"]
        }
        missing_id = next(
            item for item in references if not item["relationship_id"]
        )

        self.assertEqual(by_id["rUnsafe"]["relationship_status"], "unsafe_target")
        self.assertIsNone(by_id["rUnsafe"]["embedded_part"])
        self.assertEqual(
            by_id["rMissing"]["relationship_status"], "embedded_part_missing"
        )
        self.assertFalse(by_id["rMissing"]["embedded_part_present"])
        self.assertEqual(
            by_id["rAmbiguous"]["relationship_status"], "ambiguous_relationship"
        )
        self.assertIsNone(by_id["rAmbiguous"]["embedded_part"])
        self.assertEqual(
            missing_id["relationship_status"], "missing_relationship_id"
        )
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

    def test_detects_field_instruction_in_simple_word_field(self):
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word"><w:body><w:p>'
                '<w:fldSimple w:instr=" HYPERLINK &quot;https://example.test/&quot; ">'
                '<w:r><w:t>link</w:t></w:r></w:fldSimple>'
                '</w:p></w:body></w:document>'
            ).encode(),
        }
        path = create_office_package(self.root / "simple-field.docx", "docx", extras)
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["features"]["field_instruction_count"], 1)

        extras["word/document.xml"] = (
            '<w:document xmlns:w="urn:test:word"><w:body><w:p>'
            '<w:fldSimple w:instr=" PAGE "><w:r><w:t>1</w:t></w:r></w:fldSimple>'
            '</w:p></w:body></w:document>'
        ).encode()
        path = create_office_package(self.root / "ordinary-field.docx", "docx", extras)
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["features"]["field_instruction_count"], 0)

    def test_detects_field_instruction_split_across_word_runs(self):
        extras = {
            "word/document.xml": (
                '<w:document xmlns:w="urn:test:word"><w:body><w:p>'
                '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
                '<w:r><w:instrText>HYPER</w:instrText></w:r>'
                '<w:r><w:instrText>LINK &quot;https://example.test/&quot;</w:instrText></w:r>'
                '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
                '<w:r><w:t>link</w:t></w:r>'
                '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
                '</w:p></w:body></w:document>'
            ).encode(),
        }
        path = create_office_package(self.root / "split-field.docx", "docx", extras)
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["features"]["field_instruction_count"], 1)

        extras["word/document.xml"] = (
            '<w:document xmlns:w="urn:test:word"><w:body><w:p>'
            '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText>NUM</w:instrText></w:r>'
            '<w:r><w:instrText>PAGES</w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
            '</w:p></w:body></w:document>'
        ).encode()
        path = create_office_package(self.root / "ordinary-split-field.docx", "docx", extras)
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["features"]["field_instruction_count"], 0)

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

    def test_detects_network_functions_in_excel_defined_names(self):
        extras = {
            "xl/workbook.xml": (
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheets/>'
                '<definedNames>'
                '<definedName name="ExternalLink">HYPERLINK("https://example.invalid/","open")</definedName>'
                '<definedName name="Ordinary">SUM(Sheet1!A1:A2)</definedName>'
                '</definedNames>'
                '</workbook>'
            ).encode(),
        }
        path = create_office_package(self.root / "defined-name.xlsx", "xlsx", extras)
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["formula_network_function_count"], 1)

    def test_detects_quoted_external_workbook_reference_with_spaces(self):
        extras = {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="urn:test:excel"><sheetData><row><c r="A1">'
                "<f>'[Budget.xlsx]Annual Summary'!A1</f>"
                '</c></row></sheetData></worksheet>'
            ).encode(),
        }
        path = create_office_package(
            self.root / "quoted-external-reference.xlsx", "xlsx", extras
        )
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["external_formula_reference_count"], 1)

    def test_excel_structured_table_reference_is_not_external_workbook(self):
        extras = {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="urn:test:excel"><sheetData>'
                '<row><c r="A1"><f>SUM(Table1[Amount])</f></c></row>'
                '</sheetData></worksheet>'
            ).encode(),
        }
        path = create_office_package(
            self.root / "structured-reference.xlsx", "xlsx", extras
        )
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["external_formula_reference_count"], 0)

    def test_ignores_external_workbook_references_inside_excel_string_literals(self):
        extras = {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="urn:test:excel"><sheetData><row>'
                '<c r="A1"><f>"[Budget.xlsx]Annual!A1"</f></c>'
                '<c r="A2"><f>IF(A1="[Fake.xlsx]Sheet1!A1",'
                "'[Real.xlsx]Annual Summary'!B2,0)</f></c>"
                '<c r="A3"><f>="text ""[Quoted.xlsx]Sheet1!A1"""</f></c>'
                '</row></sheetData></worksheet>'
            ).encode(),
        }
        path = create_office_package(
            self.root / "external-reference-string-literals.xlsx",
            "xlsx",
            extras,
        )
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["external_formula_reference_count"], 1)

    def test_ignores_network_function_names_inside_excel_string_literals(self):
        extras = {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="urn:test:excel"><sheetData><row>'
                '<c r="A1"><f>"WEBSERVICE("</f></c>'
                '<c r="A2"><f>IFERROR(wEbSeRvIcE("https://example.invalid/"),0)</f></c>'
                '<c r="A3"><f>WEBSERVICEX("https://example.invalid/")</f></c>'
                '<c r="A4"><f>="text ""WEBSERVICE("" text"</f></c>'
                '</row></sheetData></worksheet>'
            ).encode(),
        }
        path = create_office_package(
            self.root / "formula-string-literals.xlsx", "xlsx", extras
        )
        report = analyze_office(str(path))
        features = report["office_analysis"]["features"]
        self.assertEqual(features["formula_network_function_count"], 1)

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
