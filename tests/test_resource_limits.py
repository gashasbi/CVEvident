"""Boundary and resource-budget acceptance tests for CVEvident parsers.

These tests deliberately lower internal limits with unittest.mock.patch so that
resource-limit behavior can be exercised quickly without allocating large files.
"""
from __future__ import annotations

import hashlib
import io
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter

from cvevident.file_input import read_file
from cvevident import legacy_office_triage, odf_triage, office_triage, pdf_structure, rtf_triage
from cvevident.legacy_office_triage import OLE_SIGNATURE, analyze_legacy_office
from cvevident.odf_triage import analyze_opendocument
from cvevident.office_triage import analyze_office
from cvevident.pdf_structure import analyze_pdf_structure
from cvevident.pdf_triage import analyze_pdf
from cvevident.rtf_triage import analyze_rtf


_ODF_MIME = "application/vnd.oasis.opendocument.text"
_ODF_MANIFEST = (
    b'<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>'
)
_ODF_CONTENT = (
    b'<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    b'xmlns:xlink="http://www.w3.org/1999/xlink"><office:body><office:text/></office:body></office:document-content>'
)


def _write_pdf(path: Path, *, with_action: bool = False) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if with_action:
        if hasattr(writer, "add_open_action"):
            from pypdf.actions import JavaScript
            writer.add_open_action(JavaScript("void(0);"))
        else:  # Compatibility with older pypdf environments.
            writer.add_js("void(0);")
    stream = io.BytesIO()
    writer.write(stream)
    data = stream.getvalue()
    path.write_bytes(data)
    return data


def _office_package(
    path: Path,
    *,
    extra_members: tuple[tuple[str, bytes], ...] = (),
    main_xml: bytes | None = None,
    compress_members: frozenset[str] = frozenset(),
) -> Path:
    content_types = (
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b'<Override PartName="/word/document.xml" '
        b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        b'</Types>'
    )
    root_rels = (
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        b'Target="word/document.xml"/>'
        b'</Relationships>'
    )
    main = main_xml or b'<w:document xmlns:w="urn:test:word"><w:body/></w:document>'
    members = [
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", root_rels),
        ("word/document.xml", main),
        *extra_members,
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members:
            method = zipfile.ZIP_DEFLATED if name in compress_members else zipfile.ZIP_STORED
            archive.writestr(name, data, compress_type=method)
    return path


def _odf_package(
    path: Path,
    *,
    content: bytes = _ODF_CONTENT,
    extra_members: tuple[tuple[str, bytes], ...] = (),
    compress_members: frozenset[str] = frozenset({"content.xml"}),
    compress_mimetype: bool = False,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "mimetype", _ODF_MIME,
            compress_type=zipfile.ZIP_DEFLATED if compress_mimetype else zipfile.ZIP_STORED,
        )
        archive.writestr("META-INF/manifest.xml", _ODF_MANIFEST, compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "content.xml", content,
            compress_type=zipfile.ZIP_DEFLATED if "content.xml" in compress_members else zipfile.ZIP_STORED,
        )
        for name, data in extra_members:
            method = zipfile.ZIP_DEFLATED if name in compress_members else zipfile.ZIP_STORED
            archive.writestr(name, data, compress_type=method)
    return path


def _cfb_entry(name: str, entry_type: int) -> bytes:
    free = 0xFFFFFFFF
    eoc = 0xFFFFFFFE
    raw = bytearray(128)
    encoded = name.encode("utf-16le") + b"\x00\x00"
    if len(encoded) > 64:
        raise ValueError("test CFB entry name too long")
    raw[:len(encoded)] = encoded
    struct.pack_into("<H", raw, 64, len(encoded))
    raw[66] = entry_type
    raw[67] = 1
    struct.pack_into("<III", raw, 68, free, free, free)
    struct.pack_into("<I", raw, 116, eoc)
    struct.pack_into("<Q", raw, 120, 0)
    return bytes(raw)


def _cfb_package(names: tuple[tuple[str, int], ...] = (("Root Entry", 5), ("WordDocument", 2))) -> bytes:
    free = 0xFFFFFFFF
    eoc = 0xFFFFFFFE
    fatsect = 0xFFFFFFFD
    sector_size = 512
    entries = [_cfb_entry(name, kind) for name, kind in names]
    directory_sector_count = max(1, (len(entries) + 3) // 4)
    directory_ids = list(range(directory_sector_count))
    fat_sector_id = directory_sector_count

    header = bytearray(sector_size)
    header[:8] = OLE_SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, 3)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, directory_ids[0])
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<I", header, 60, eoc)
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, eoc)
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<109I", header, 76, *([fat_sector_id] + [free] * 108))

    directory = b"".join(entries).ljust(directory_sector_count * sector_size, b"\x00")
    fat_words = [free] * (sector_size // 4)
    for index, sector_id in enumerate(directory_ids):
        fat_words[sector_id] = directory_ids[index + 1] if index + 1 < len(directory_ids) else eoc
    fat_words[fat_sector_id] = fatsect
    fat_sector = struct.pack("<128I", *fat_words)
    return bytes(header) + directory + fat_sector


class SharedInputAndPdfResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_file_input_accepts_exact_limit_and_hashes_exact_bytes(self):
        payload = b"exact boundary"
        path = self.root / "exact.bin"
        path.write_bytes(payload)
        result = read_file(path, max_bytes=len(payload))
        self.assertEqual(result.data, payload)
        self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())

    def test_file_input_rejects_one_byte_over_limit(self):
        path = self.root / "over.bin"
        path.write_bytes(b"123456")
        with self.assertRaisesRegex(ValueError, "configured limit"):
            read_file(path, max_bytes=5)

    def test_pdf_container_budget_marks_partial(self):
        data = _write_pdf(self.root / "containers.pdf")
        with patch.object(pdf_structure, "_MAX_CONTAINERS", 1):
            result = analyze_pdf_structure(data, True)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertIn("safety budget", " ".join(result["warnings"]))

    def test_pdf_depth_budget_marks_partial(self):
        data = _write_pdf(self.root / "depth.pdf")
        with patch.object(pdf_structure, "_MAX_DEPTH", 0):
            result = analyze_pdf_structure(data, True)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertIn("depth", " ".join(result["warnings"]))

    def test_pdf_findings_budget_marks_omitted_findings(self):
        data = _write_pdf(self.root / "findings.pdf", with_action=True)
        with patch.object(pdf_structure, "_MAX_FINDINGS", 0):
            result = analyze_pdf_structure(data, True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["findings_truncated"])
        self.assertIn("reporting limit", " ".join(result["warnings"]))

    def test_pdf_object_path_limit_has_exact_and_over_limit_cases(self):
        with patch.object(pdf_structure, "_MAX_PATH_LENGTH", 10):
            exact, exact_truncated = pdf_structure._join_object_path("12345", "67890", False)
            longer, longer_truncated = pdf_structure._join_object_path("12345", "678901", False)
        self.assertEqual(exact, "1234567890")
        self.assertFalse(exact_truncated)
        self.assertEqual(len(longer), 10)
        self.assertTrue(longer.endswith("..."))
        self.assertTrue(longer_truncated)

    def test_pdf_analysis_surfaces_path_truncation_in_a_finding(self):
        data = _write_pdf(self.root / "path.pdf", with_action=True)
        with patch.object(pdf_structure, "_MAX_PATH_LENGTH", 8):
            report = analyze_pdf(self._write_bytes("path-copy.pdf", data))
        findings = report["structural_analysis"]["findings"]
        self.assertTrue(any(item["path_truncated"] for item in findings))

    def _write_bytes(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path


class OfficeXmlResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _analyze(self, name: str, **kwargs):
        path = _office_package(self.root / name, **kwargs.pop("package_options", {}))
        return analyze_office(str(path), **kwargs)

    def test_archive_entry_budget_marks_partial(self):
        report = self._analyze(
            "entries.docx", max_archive_entries=3,
            package_options={"extra_members": (("custom/data.bin", b"x"),)},
        )
        office = report["office_analysis"]
        self.assertEqual(office["status"], "partial")
        self.assertTrue(office["truncated"])
        self.assertTrue(any("only the first 3 entries" in w for w in report["warnings"]))

    def test_declared_uncompressed_package_budget_marks_partial(self):
        report = self._analyze("package-budget.docx", max_total_uncompressed_bytes=1)
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(any("Declared uncompressed package size" in w for w in report["warnings"]))

    def test_per_xml_part_budget_skips_oversized_main_part(self):
        large = b'<w:document xmlns:w="urn:test">' + b"x" * 1200 + b"</w:document>"
        report = self._analyze(
            "part-budget.docx", max_xml_part_bytes=512,
            package_options={"main_xml": large},
        )
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(any("per-part limit" in w for w in report["warnings"]))

    def test_xml_part_count_budget_marks_partial(self):
        extras = tuple((f"custom/part{i}.xml", b"<item/>") for i in range(4))
        report = self._analyze(
            "part-count.docx", max_xml_parts=2,
            package_options={"extra_members": extras},
        )
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(any("XML part count exceeds the limit (2)" in w for w in report["warnings"]))

    def test_total_xml_budget_caps_all_xml_parser_input_bytes(self):
        path = _office_package(self.root / "total-xml.docx")
        parser = office_triage._parse_xml
        parsed_sizes: list[int] = []

        def track_parse(data: bytes):
            parsed_sizes.append(len(data))
            return parser(data)

        budget = 64
        with patch.object(office_triage, "_parse_xml", side_effect=track_parse):
            report = analyze_office(str(path), max_total_xml_bytes=budget)

        # The budget is meant to cap total XML inspection, including the manifest
        # and relationships needed for classification, not only the later scan loop.
        self.assertLessEqual(sum(parsed_sizes), budget)
        self.assertEqual(report["office_analysis"]["status"], "partial")

    def test_compression_ratio_limit_skips_high_ratio_xml_member(self):
        bomb_like = b"<data>" + b"A" * 5000 + b"</data>"
        path = _office_package(
            self.root / "ratio.docx",
            extra_members=(("custom/repeated.xml", bomb_like),),
            compress_members=frozenset({"custom/repeated.xml"}),
        )
        with patch.object(office_triage, "MAX_COMPRESSION_RATIO", 2):
            report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(any("compression-ratio limit" in w for w in report["warnings"]))

    def test_relationship_example_limit_does_not_limit_total_count(self):
        rel_namespace = "http://schemas.openxmlformats.org/package/2006/relationships"
        relations = [
            f'<Relationship Id="r{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.test/{i}" TargetMode="External"/>'
            for i in range(5)
        ]
        rel_xml = f'<Relationships xmlns="{rel_namespace}">' + "".join(relations) + "</Relationships>"
        path = _office_package(
            self.root / "relationships.docx",
            extra_members=(("word/_rels/document.xml.rels", rel_xml.encode()),),
        )
        with patch.object(office_triage, "MAX_RELATIONSHIP_EXAMPLES", 2):
            report = analyze_office(str(path))
        analysis = report["office_analysis"]
        self.assertEqual(analysis["features"]["external_relationship_count"], 5)
        self.assertEqual(len(analysis["external_relationships"]), 2)

    def test_parts_inventory_limit_only_limits_examples(self):
        extras = tuple((f"custom/part{i}.xml", b"<item/>") for i in range(5))
        path = _office_package(self.root / "inventory.docx", extra_members=extras)
        with patch.object(office_triage, "MAX_PART_EXAMPLES", 2):
            report = analyze_office(str(path))
        analysis = report["office_analysis"]
        self.assertGreater(analysis["xml_parts_inspected"], 2)
        self.assertEqual(len(analysis["parts_inventory"]), 2)

    def test_duplicate_zip_member_names_are_skipped_and_reported(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            path = _office_package(
                self.root / "duplicate.docx",
                extra_members=(("word/document.xml", b"<alternate/>"),),
            )
        report = analyze_office(str(path))
        self.assertEqual(report["office_analysis"]["status"], "partial")
        self.assertTrue(any("duplicate member name" in w for w in report["warnings"]))


    def test_case_insensitive_duplicate_zip_member_names_are_skipped_and_reported(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            path = _office_package(
                self.root / "case-collision.docx",
                extra_members=(("WORD/DOCUMENT.XML", b"<alternate/>"),),
            )
        report = analyze_office(str(path))
        analysis = report["office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertTrue(any("case-insensitive member-name collision" in w for w in report["warnings"]))
        self.assertNotIn("word/document.xml", analysis["parts_inventory"])
        self.assertNotIn("WORD/DOCUMENT.XML", analysis["parts_inventory"])


class OdfResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _analyze(self, name: str, **kwargs):
        path = _odf_package(self.root / name, **kwargs.pop("package_options", {}))
        return analyze_opendocument(str(path), **kwargs)

    def test_archive_entry_budget_marks_partial(self):
        report = self._analyze(
            "entries.odt", max_archive_entries=2,
            package_options={"extra_members": (("Pictures/picture.bin", b"x"),)},
        )
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("only the first 2" in w for w in report["warnings"]))

    def test_declared_uncompressed_package_budget_marks_partial(self):
        report = self._analyze("package-budget.odt", max_total_uncompressed_bytes=1)
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("Declared uncompressed package size" in w for w in report["warnings"]))

    def test_per_xml_part_budget_skips_large_content(self):
        large = b"<doc>" + b"x" * 300 + b"</doc>"
        report = self._analyze(
            "part-budget.odt", max_xml_part_bytes=128,
            package_options={"content": large},
        )
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("per-part size limit" in w for w in report["warnings"]))

    def test_total_xml_budget_skips_selected_xml(self):
        report = self._analyze("total-xml.odt", max_total_xml_bytes=32)
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertLessEqual(report["odf_analysis"]["xml_bytes_inspected"], 32)
        self.assertTrue(any("Total XML inspection byte limit" in w for w in report["warnings"]))

    def test_xml_part_count_budget_marks_partial(self):
        report = self._analyze("part-count.odt", max_xml_parts=1)
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertLessEqual(report["odf_analysis"]["xml_parts_inspected"], 1)
        self.assertTrue(any("inspection count cap" in w for w in report["warnings"]))

    def test_compression_ratio_limit_skips_high_ratio_xml(self):
        repetitive = b"<doc>" + b"same value " * 300 + b"</doc>"
        path = _odf_package(
            self.root / "ratio.odt", content=repetitive,
            compress_members=frozenset({"content.xml"}),
        )
        with patch.object(odf_triage, "MAX_COMPRESSION_RATIO", 2):
            report = analyze_opendocument(str(path))
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("compression-ratio limit" in w for w in report["warnings"]))

    def test_external_reference_example_limit_does_not_limit_total_count(self):
        links = "".join(f'<a xlink:href="https://example.test/{i}"/>' for i in range(5))
        content = (
            '<doc xmlns:xlink="http://www.w3.org/1999/xlink">' + links + "</doc>"
        ).encode()
        path = _odf_package(self.root / "external-links.odt", content=content)
        with patch.object(odf_triage, "MAX_EXTERNAL_EXAMPLES", 2):
            report = analyze_opendocument(str(path))
        analysis = report["odf_analysis"]
        self.assertEqual(analysis["features"]["external_reference_count"], 5)
        self.assertEqual(len(analysis["external_references"]), 2)

    def test_macro_and_embedded_member_examples_are_bounded(self):
        extras = (
            ("Basic/One/a.xml", b"<a/>"),
            ("Scripts/Two/b.xml", b"<b/>"),
            ("Basic/Three/c.xml", b"<c/>"),
            ("Objects/One/content.xml", b"<object/>"),
            ("Objects/Two/content.xml", b"<object/>"),
        )
        path = _odf_package(self.root / "member-examples.odt", extra_members=extras)
        with patch.object(odf_triage, "MAX_PART_EXAMPLES", 1):
            report = analyze_opendocument(str(path))
        analysis = report["odf_analysis"]
        self.assertGreater(analysis["features"]["script_or_basic_member_count"], 1)
        self.assertLessEqual(len(analysis["macro_or_script_members"]), 1)
        self.assertLessEqual(len(analysis["embedded_object_members"]), 1)


class RtfResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _analyze(self, name: str, payload: bytes, **kwargs):
        path = self.root / name
        path.write_bytes(payload)
        return analyze_rtf(str(path), **kwargs)

    def test_scan_limit_exact_boundary_and_one_byte_over(self):
        data = b"{\\rtf1\\ansi ok}"
        exact = self._analyze("exact.rtf", data, max_scan_bytes=len(data))
        over = self._analyze("over.rtf", data, max_scan_bytes=len(data) - 1)
        self.assertEqual(exact["rtf_analysis"]["status"], "parsed")
        self.assertFalse(exact["rtf_analysis"]["truncated"])
        self.assertEqual(over["rtf_analysis"]["status"], "partial")
        self.assertTrue(over["rtf_analysis"]["truncated"])

    def test_group_depth_exact_limit_and_one_over(self):
        exact_data = b"{\\rtf1{\\foo text}}"
        over_data = b"{\\rtf1{{\\foo text}}}"
        with patch.object(rtf_triage, "MAX_RTF_GROUP_DEPTH", 2):
            exact = self._analyze("depth-exact.rtf", exact_data)
            over = self._analyze("depth-over.rtf", over_data)
        self.assertEqual(exact["rtf_analysis"]["maximum_group_depth"], 2)
        self.assertEqual(exact["rtf_analysis"]["status"], "parsed")
        self.assertEqual(over["rtf_analysis"]["maximum_group_depth"], 3)
        self.assertTrue(over["rtf_analysis"]["truncated"])
        self.assertTrue(any("nesting limit" in w for w in over["warnings"]))

    def test_control_word_limit_exact_and_one_over(self):
        exact_data = b"{\\rtf1\\ansi\\foo text}"
        over_data = b"{\\rtf1\\ansi\\foo\\bar text}"
        with patch.object(rtf_triage, "MAX_RTF_CONTROL_WORDS", 3):
            exact = self._analyze("controls-exact.rtf", exact_data)
            over = self._analyze("controls-over.rtf", over_data)
        self.assertEqual(exact["rtf_analysis"]["status"], "parsed")
        self.assertFalse(exact["rtf_analysis"]["truncated"])
        self.assertTrue(over["rtf_analysis"]["truncated"])
        self.assertTrue(any("control-word limit" in w for w in over["warnings"]))

    def test_binary_payload_declared_past_eof_marks_partial(self):
        report = self._analyze("bin-truncated.rtf", b"{\\rtf1\\bin20 abc}")
        self.assertEqual(report["rtf_analysis"]["status"], "partial")
        self.assertTrue(report["rtf_analysis"]["truncated"])
        self.assertTrue(any("payload declared more bytes" in w for w in report["warnings"]))

    def test_unbalanced_braces_marks_partial(self):
        report = self._analyze("brace.rtf", b"{\\rtf1}}")
        self.assertEqual(report["rtf_analysis"]["status"], "partial")
        self.assertTrue(any("brace/group balance" in w for w in report["warnings"]))


class LegacyCfbResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _analyze(self, name: str, data: bytes):
        path = self.root / name
        path.write_bytes(data)
        return analyze_legacy_office(str(path))

    def test_fat_and_difat_counts_over_configured_caps_fail_early(self):
        valid = _cfb_package()
        with patch.object(legacy_office_triage, "_MAX_FAT_SECTORS", 0):
            fat_report = self._analyze("fat-cap.doc", valid)
        difat_data = bytearray(valid)
        struct.pack_into("<I", difat_data, 72, 1)
        with patch.object(legacy_office_triage, "_MAX_DIFAT_SECTORS", 0):
            difat_report = self._analyze("difat-cap.doc", bytes(difat_data))
        for report in (fat_report, difat_report):
            self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
            self.assertTrue(any("FAT or DIFAT count exceeds" in w for w in report["warnings"]))

    def test_total_sector_limit_fails_before_chain_walk(self):
        with patch.object(legacy_office_triage, "_MAX_CHAIN_SECTORS", 1):
            report = self._analyze("sector-cap.doc", _cfb_package())
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("sector count exceeds" in w for w in report["warnings"]))

    def test_directory_byte_cap_marks_chain_truncated(self):
        with patch.object(legacy_office_triage, "_MAX_DIRECTORY_BYTES", 128):
            report = self._analyze("directory-byte-cap.doc", _cfb_package())
        analysis = report["legacy_office_analysis"]
        self.assertTrue(analysis["truncated"])
        self.assertTrue(analysis["features"]["directory_chain_truncated"])
        self.assertTrue(any("byte limit reached" in w for w in report["warnings"]))

    def test_directory_entry_count_cap_is_explicit(self):
        data = b"".join(_cfb_entry(name, kind) for name, kind in (
            ("Root Entry", 5), ("WordDocument", 2), ("ExtraOne", 2),
        ))
        with patch.object(legacy_office_triage, "_MAX_DIRECTORY_ENTRIES", 2):
            entries, truncated, _warnings = legacy_office_triage._parse_directory(data)
        self.assertEqual(len(entries), 2)
        self.assertTrue(truncated)

    def test_follow_chain_handles_cycle_invalid_reference_and_byte_cap(self):
        sector_size = 512
        data = bytes(sector_size) + b"A" * sector_size + b"B" * sector_size
        eoc = legacy_office_triage._ENDOFCHAIN

        _bytes, partial, error = legacy_office_triage._follow_chain(
            0, [1, 0], data, sector_size, 2, max_sectors=10, max_bytes=4096,
        )
        self.assertTrue(partial)
        self.assertIn("cycle", error or "")

        _bytes, partial, error = legacy_office_triage._follow_chain(
            2, [eoc], data, sector_size, 2, max_sectors=10, max_bytes=4096,
        )
        self.assertTrue(partial)
        self.assertIn("invalid or unavailable FAT entry", error or "")

        payload, partial, error = legacy_office_triage._follow_chain(
            0, [eoc], data, sector_size, 2, max_sectors=10, max_bytes=17,
        )
        self.assertEqual(len(payload), 17)
        self.assertTrue(partial)
        self.assertIn("byte limit reached", error or "")

    def test_invalid_header_fields_fail_cleanly(self):
        valid = bytearray(_cfb_package())
        struct.pack_into("<H", valid, 28, 0x1234)
        report = self._analyze("bad-byte-order.doc", bytes(valid))
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("byte-order marker is invalid" in w for w in report["warnings"]))


    def test_directory_entry_rejects_missing_utf16_terminator(self):
        raw = bytearray(_cfb_entry("WordDocument", 2))
        name_length = struct.unpack_from("<H", raw, 64)[0]
        raw[name_length - 2:name_length] = b"AB"

        entries, truncated, warnings = legacy_office_triage._parse_directory(
            bytes(raw)
        )

        self.assertFalse(truncated)
        self.assertEqual(entries[0]["name"], "<invalid-name-entry-0>")
        self.assertTrue(
            any("terminator" in warning.lower() for warning in warnings)
        )


if __name__ == "__main__":
    unittest.main()
