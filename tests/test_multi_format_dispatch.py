import struct
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from cvevident.analyzer import analyze_file
from cvevident.db import init_db
from cvevident.reporting import to_html, to_markdown
from cvevident.store import get_analysis

OLE_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")
FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def minimal_cfb_word() -> bytes:
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
    fat = struct.pack("<128I", *fat_values)
    return bytes(header) + bytes(directory) + fat


def minimal_odf_text() -> bytes:
    buffer = BytesIO()
    mime = "application/vnd.oasis.opendocument.text"
    content = '''<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'''
    manifest = '''<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>'''
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("mimetype", mime, compress_type=zipfile.ZIP_STORED)
        archive.writestr("content.xml", content)
        archive.writestr("META-INF/manifest.xml", manifest)
    return buffer.getvalue()


class MultiFormatDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "analysis.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_legacy_doc_rtf_and_odt_dispatch_persist_and_render(self):
        cases = [
            ("legacy.doc", minimal_cfb_word(), "doc", "Legacy Office (OLE/CFB) analysis"),
            ("field.rtf", b'{\\rtf1\\ansi{\\field{\\*\\fldinst HYPERLINK "https://example.test"}{\\fldrslt link}}}', "rtf", "RTF analysis"),
            ("package.odt", minimal_odf_text(), "odt", "OpenDocument package analysis"),
        ]
        for name, data, expected_type, heading in cases:
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(data)
                report = analyze_file(path, self.db)
                self.assertEqual(report["file"]["file_type"], expected_type)
                self.assertEqual(report["assessment"]["verdict"], "not_assessed")
                loaded = get_analysis(report["analysis_id"], self.db)
                self.assertIsNotNone(loaded)
                self.assertEqual(loaded["file"]["sha256"], report["file"]["sha256"])
                self.assertIn(heading, to_markdown(loaded))
                self.assertIn("CVEvident Analysis Report", to_html(loaded))

    def test_zip_signature_can_override_wrong_odf_or_office_suffix(self):
        path = self.root / "misnamed.docx"
        path.write_bytes(minimal_odf_text())
        report = analyze_file(path, self.db)
        self.assertEqual(report["file"]["file_type"], "odt")
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertFalse(report["odf_analysis"]["extension_matches_detected_format"])
        self.assertIn("does not match", " ".join(report["warnings"]))

    def test_rtf_signature_overrides_legacy_office_suffix(self):
        path = self.root / "misnamed.doc"
        path.write_bytes(b'{\\rtf1\\ansi harmless text}')
        report = analyze_file(path, self.db)
        self.assertEqual(report["file"]["file_type"], "rtf")
        self.assertEqual(report["rtf_analysis"]["status"], "partial")
        self.assertIn("differs from the detected RTF", " ".join(report["warnings"]))


if __name__ == "__main__":
    unittest.main()
