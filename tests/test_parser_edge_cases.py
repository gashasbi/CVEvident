"""Final edge-case acceptance tests for parser cycles and malformed containers."""
from __future__ import annotations

import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject

from cvevident.legacy_office_triage import OLE_SIGNATURE, analyze_legacy_office
from cvevident.odf_triage import analyze_opendocument, is_opendocument_package
from cvevident.pdf_structure import analyze_pdf_structure


_FREE = 0xFFFFFFFF
_EOC = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_ODF_MIME = "application/vnd.oasis.opendocument.text"


def _cfb_entry(name: str, entry_type: int) -> bytes:
    raw = bytearray(128)
    encoded = name.encode("utf-16le") + b"\x00\x00"
    raw[:len(encoded)] = encoded
    struct.pack_into("<H", raw, 64, len(encoded))
    raw[66] = entry_type
    raw[67] = 1
    struct.pack_into("<III", raw, 68, _FREE, _FREE, _FREE)
    struct.pack_into("<I", raw, 116, _EOC)
    struct.pack_into("<Q", raw, 120, 0)
    return bytes(raw)


def _cfb_package(names=(('Root Entry', 5), ('WordDocument', 2))) -> bytes:
    sector_size = 512
    entries = [_cfb_entry(name, kind) for name, kind in names]
    dir_count = max(1, (len(entries) + 3) // 4)
    directory_ids = list(range(dir_count))
    fat_sid = dir_count

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
    struct.pack_into("<I", header, 60, _EOC)
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, _EOC)
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<109I", header, 76, *([fat_sid] + [_FREE] * 108))

    directory = b"".join(entries).ljust(dir_count * sector_size, b"\x00")
    fat = [_FREE] * (sector_size // 4)
    for idx, sid in enumerate(directory_ids):
        fat[sid] = directory_ids[idx + 1] if idx + 1 < len(directory_ids) else _EOC
    fat[fat_sid] = _FATSECT
    fat_bytes = struct.pack("<128I", *fat)
    return bytes(header) + directory + fat_bytes


def _odf_bytes() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("mimetype", _ODF_MIME, compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "META-INF/manifest.xml",
            b'<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>',
        )
        archive.writestr(
            "content.xml",
            b'<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>',
        )
    return stream.getvalue()


def _damage_stored_mimetype_crc(data: bytes) -> bytes:
    damaged = bytearray(data)
    name_length = struct.unpack_from("<H", damaged, 26)[0]
    extra_length = struct.unpack_from("<H", damaged, 28)[0]
    payload_offset = 30 + name_length + extra_length
    damaged[payload_offset] ^= 1
    return bytes(damaged)


class PdfGraphEdgeCaseTests(unittest.TestCase):
    def test_indirect_self_reference_is_detected_without_unbounded_traversal(self):
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        cyclic = DictionaryObject()
        ref = writer._add_object(cyclic)
        cyclic[NameObject("/Self")] = ref
        writer._root_object[NameObject("/AuditCycle")] = ref

        output = io.BytesIO()
        writer.write(output)
        result = analyze_pdf_structure(output.getvalue(), is_pdf=True)

        self.assertIn(result["status"], {"parsed", "partial"})
        self.assertLess(result["containers_inspected"], 100)
        self.assertEqual(result["status"], "parsed")
        self.assertFalse(result["truncated"])


class LegacyCfbEdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _analyze(self, name: str, data: bytes):
        path = self.root / name
        path.write_bytes(data)
        return analyze_legacy_office(str(path))

    def test_difat_cycle_is_reported_as_partial(self):
        data = bytearray(_cfb_package())
        # Append sector 2 as a DIFAT sector whose next pointer loops to itself.
        difat_sector = struct.pack("<128I", *([_FREE] * 127 + [2]))
        data.extend(difat_sector)
        struct.pack_into("<I", data, 68, 2)  # First DIFAT sector
        struct.pack_into("<I", data, 72, 2)  # Visit the chain twice to detect cycle

        report = self._analyze("difat-cycle.doc", bytes(data))
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertTrue(analysis["truncated"])
        self.assertTrue(any("DIFAT chain contains a cycle" in w for w in report["warnings"]))

    def test_invalid_version_sector_shift_and_mini_sector_shift_fail_cleanly(self):
        mutations = (
            (26, 5, "version or sector-size"),
            (30, 10, "version or sector-size"),
            (32, 7, "mini-sector shift"),
        )
        for offset, value, warning_text in mutations:
            with self.subTest(offset=offset, value=value):
                data = bytearray(_cfb_package())
                struct.pack_into("<H", data, offset, value)
                report = self._analyze(f"bad-header-{offset}.doc", bytes(data))
                self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
                self.assertTrue(any(warning_text in w for w in report["warnings"]))

    def test_directory_entry_cap_propagates_to_final_report(self):
        data = _cfb_package((
            ("Root Entry", 5),
            ("WordDocument", 2),
            ("ExtraEntry", 2),
        ))
        with patch("cvevident.legacy_office_triage._MAX_DIRECTORY_ENTRIES", 2):
            report = self._analyze("directory-entry-cap.doc", data)

        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertTrue(analysis["truncated"])
        self.assertTrue(analysis["features"]["directory_inventory_truncated"])
        self.assertTrue(any("Directory entry inventory was capped" in w for w in report["warnings"]))


class OdfMimetypeEdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_corrupt_stored_mimetype_crc_returns_failure_report_without_exception(self):
        damaged = _damage_stored_mimetype_crc(_odf_bytes())
        path = self.root / "bad-mimetype.odt"
        path.write_bytes(damaged)

        self.assertFalse(is_opendocument_package(damaged))
        report = analyze_opendocument(str(path))
        analysis = report["odf_analysis"]

        self.assertEqual(analysis["status"], "failed")
        self.assertTrue(any("mimetype member is invalid or unreadable" in w for w in report["warnings"]))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")


if __name__ == "__main__":
    unittest.main()
