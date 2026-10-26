from __future__ import annotations

import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from pypdf import PdfWriter

from cvevident.analyzer import analyze_file
from cvevident.db import init_db
from cvevident.odf_triage import analyze_opendocument

OLE_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")
FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
ODF_MIME = "application/vnd.oasis.opendocument.text"


def _pdf_bytes() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _ooxml_bytes(main_xml: bytes = b'<w:document xmlns:w="urn:test:word"><w:body/></w:document>') -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            b'<Override PartName="/word/document.xml" '
            b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            b'</Types>',
        )
        archive.writestr(
            "_rels/.rels",
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            b'Target="word/document.xml"/>'
            b'</Relationships>',
        )
        archive.writestr("word/document.xml", main_xml)
    return output.getvalue()


def _odf_bytes(content_xml: bytes = b'<office:document-content xmlns:office="urn:test:office"/>') -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("mimetype", ODF_MIME, compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "META-INF/manifest.xml",
            b'<manifest:manifest xmlns:manifest="urn:test:manifest"/>',
            compress_type=zipfile.ZIP_DEFLATED,
        )
        archive.writestr("content.xml", content_xml, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


def _rtf_bytes() -> bytes:
    return b"{\\rtf1\\ansi sample}"


def _cfb_word_bytes() -> bytes:
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

    directory = bytearray(sector_size)
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

    fat_entries = [FREE] * 128
    fat_entries[0] = EOC
    fat_entries[1] = FATSECT
    fat = struct.pack("<128I", *fat_entries)
    return bytes(header) + bytes(directory) + fat


def _corrupt_first_compressed_byte(package: bytes, member_name: str) -> bytes:
    damaged = bytearray(package)
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        info = archive.getinfo(member_name)
        if info.compress_type != zipfile.ZIP_DEFLATED:
            raise AssertionError(f"{member_name} is not deflated in the fixture")
        offset = info.header_offset
        name_length, extra_length = struct.unpack_from("<HH", damaged, offset + 26)
        payload_offset = offset + 30 + name_length + extra_length
        if info.compress_size < 1:
            raise AssertionError(f"{member_name} has no compressed payload")
        # 0xff encodes a reserved DEFLATE block type when encountered at stream start.
        damaged[payload_offset] = 0xFF
    return bytes(damaged)


class DispatchFailureMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "dispatch.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def _analyze(self, filename: str, data: bytes, **kwargs):
        path = self.root / filename
        path.write_bytes(data)
        return analyze_file(path, db_path=self.db, **kwargs)

    def test_content_signatures_override_mismatched_suffixes_for_each_family(self):
        cases = [
            ("pdf-with-docx-suffix.docx", _pdf_bytes(), "structural_analysis"),
            ("ooxml-with-odt-suffix.odt", _ooxml_bytes(), "office_analysis"),
            ("odf-with-docx-suffix.docx", _odf_bytes(), "odf_analysis"),
            ("rtf-with-doc-suffix.doc", _rtf_bytes(), "rtf_analysis"),
            ("cfb-with-bin-suffix.bin", _cfb_word_bytes(), "legacy_office_analysis"),
        ]
        for filename, payload, expected_section in cases:
            with self.subTest(filename=filename):
                report = self._analyze(filename, payload)
                self.assertIn(expected_section, report)
                self.assertEqual(report["assessment"]["verdict"], "not_assessed")
                self.assertTrue(report.get("analysis_id"))

        pdf_report = self._analyze("second-pdf.docx", _pdf_bytes())
        self.assertEqual(pdf_report["file"]["file_type"], "pdf")
        ooxml_report = self._analyze("second-ooxml.odt", _ooxml_bytes())
        self.assertEqual(ooxml_report["office_analysis"]["format_id"], "docx")
        odf_report = self._analyze("second-odf.docx", _odf_bytes())
        self.assertEqual(odf_report["odf_analysis"]["format_id"], "odt")
        rtf_report = self._analyze("second-rtf.doc", _rtf_bytes())
        self.assertEqual(rtf_report["file"]["file_type"], "rtf")
        cfb_report = self._analyze("second-cfb.bin", _cfb_word_bytes())
        self.assertEqual(cfb_report["legacy_office_analysis"]["family"], "word")

    def test_max_bytes_is_enforced_through_dispatch_for_every_supported_family(self):
        cases = [
            ("limited.pdf", _pdf_bytes()),
            ("limited.docx", _ooxml_bytes()),
            ("limited.odt", _odf_bytes()),
            ("limited.rtf", _rtf_bytes()),
            ("limited.doc", _cfb_word_bytes()),
        ]
        for filename, payload in cases:
            with self.subTest(filename=filename):
                path = self.root / filename
                path.write_bytes(payload)
                with self.assertRaisesRegex(ValueError, "configured limit"):
                    analyze_file(path, db_path=self.db, max_bytes=len(payload) - 1)

    def test_malformed_format_inputs_return_cautious_reports(self):
        cases = [
            ("broken.docx", b"PK\x03\x04" + b"\x00" * 40, "office_analysis", "failed"),
            ("broken.odt", b"PK\x03\x04" + b"\x00" * 40, "odf_analysis", "failed"),
            ("broken.rtf", b"plain text, not RTF", "rtf_analysis", "failed"),
            ("broken.doc", OLE_SIGNATURE + b"\x00" * 20, "legacy_office_analysis", "failed"),
        ]
        for filename, payload, section, expected_status in cases:
            with self.subTest(filename=filename):
                report = self._analyze(filename, payload)
                self.assertIn(section, report)
                self.assertEqual(report[section]["status"], expected_status)
                self.assertEqual(report["assessment"]["verdict"], "not_assessed")

        pdf_report = self._analyze("broken.pdf", b"%PDF-1.7\n<< /OpenAction")
        self.assertEqual(pdf_report["structural_analysis"]["status"], "failed")
        self.assertEqual(pdf_report["assessment"]["verdict"], "not_assessed")

    def test_failed_ooxml_zip_is_not_silently_reinterpreted_as_odf(self):
        report = self._analyze("corrupt.docx", b"PK\x03\x04" + b"not-a-complete-zip")
        self.assertIn("office_analysis", report)
        self.assertNotIn("odf_analysis", report)
        self.assertEqual(report["office_analysis"]["status"], "failed")

    def test_ordinary_zip_without_office_or_odf_markers_stays_unsupported(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("readme.txt", b"ordinary ZIP, not a document")
        report = self._analyze("ordinary.zip", stream.getvalue())
        self.assertIn("office_analysis", report)
        self.assertNotIn("odf_analysis", report)
        self.assertEqual(report["office_analysis"]["status"], "unsupported")
        self.assertEqual(report["file"]["file_type"], "unknown_or_non_office")

    def test_malformed_xml_parts_are_reported_without_uncaught_parse_errors(self):
        office_report = self._analyze("bad-main-xml.docx", _ooxml_bytes(b"<document><unclosed></document>"))
        self.assertEqual(office_report["office_analysis"]["status"], "partial")
        self.assertTrue(any("could not be safely parsed" in item for item in office_report["warnings"]))

        odf_report = self._analyze("bad-content-xml.odt", _odf_bytes(b"<document><unclosed></document>"))
        self.assertEqual(odf_report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("could not be safely parsed" in item for item in odf_report["warnings"]))

    def test_corrupt_odf_deflate_stream_is_reported_instead_of_escaping_parser(self):
        damaged = _corrupt_first_compressed_byte(_odf_bytes(), "content.xml")
        path = self.root / "damaged-deflate.odt"
        path.write_bytes(damaged)
        report = analyze_opendocument(str(path))
        self.assertIn(report["odf_analysis"]["status"], {"partial", "failed"})
        self.assertTrue(report["odf_analysis"]["warnings"])

    def test_missing_files_are_reported_by_the_selected_analyzer(self):
        for filename in ("missing.pdf", "missing.docx", "missing.odt", "missing.rtf", "missing.doc"):
            with self.subTest(filename=filename):
                with self.assertRaises(FileNotFoundError):
                    analyze_file(self.root / filename, db_path=self.db)


    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_analyze_file_rejects_fifo_without_blocking(self):
        fifo_path = self.root / "input.pdf"
        os.mkfifo(fifo_path)

        probe = "\n".join((
            "import sys",
            "from cvevident.analyzer import analyze_file",
            "try:",
            "    analyze_file(sys.argv[1], db_path=sys.argv[2])",
            "except FileNotFoundError:",
            "    raise SystemExit(0)",
            "raise SystemExit(3)",
        ))
        try:
            result = subprocess.run(
                [sys.executable, "-c", probe, str(fifo_path), str(self.db)],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail(
                "analyze_file blocked while probing a FIFO before bounded input validation"
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout={result.stdout!r}; stderr={result.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
