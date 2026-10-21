import struct
import tempfile
import unittest
from pathlib import Path

from cvevident.legacy_office_triage import OLE_SIGNATURE, analyze_legacy_office

FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def build_cfb(names, *, major=3):
    """Build a minimal synthetic CFB directory with named streams; no stream data."""
    sector_size = 512 if major == 3 else 4096
    entries = []
    for index, (name, entry_type) in enumerate(names):
        raw = bytearray(128)
        encoded = name.encode("utf-16le") + b"\x00\x00"
        if len(encoded) > 64:
            raise ValueError("test name too long")
        raw[:len(encoded)] = encoded
        struct.pack_into("<H", raw, 64, len(encoded))
        raw[66] = entry_type
        raw[67] = 1
        struct.pack_into("<III", raw, 68, FREE, FREE, FREE)
        struct.pack_into("<I", raw, 116, EOC)
        struct.pack_into("<Q", raw, 120, 0)
        entries.append(bytes(raw))
    per_sector = sector_size // 128
    directory_sector_count = max(1, (len(entries) + per_sector - 1) // per_sector)
    directory_sector_ids = list(range(directory_sector_count))
    fat_sector_id = directory_sector_count

    header = bytearray(sector_size)
    header[:8] = OLE_SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, major)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9 if major == 3 else 12)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 40, 0 if major == 3 else directory_sector_count)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, directory_sector_ids[0])
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<I", header, 60, EOC)
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, EOC)
    struct.pack_into("<I", header, 72, 0)
    difat = [fat_sector_id] + [FREE] * 108
    struct.pack_into("<109I", header, 76, *difat)

    dir_stream = b"".join(entries)
    dir_stream = dir_stream.ljust(directory_sector_count * sector_size, b"\x00")
    fat_words = [FREE] * (sector_size // 4)
    for idx, sector_id in enumerate(directory_sector_ids):
        fat_words[sector_id] = directory_sector_ids[idx + 1] if idx + 1 < len(directory_sector_ids) else EOC
    fat_words[fat_sector_id] = FATSECT
    fat_sector = struct.pack(f"<{sector_size // 4}I", *fat_words)
    return bytes(header) + dir_stream + fat_sector


class LegacyOfficeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return analyze_legacy_office(str(path))

    def test_detects_legacy_word_and_vba_directory_indicators(self):
        data = build_cfb([
            ("Root Entry", 5), ("WordDocument", 2), ("0Table", 2),
            ("VBA", 1), ("dir", 2), ("_VBA_PROJECT", 2), ("PROJECT", 2),
        ])
        report = self.analyze("sample.doc", data)
        self.assertEqual(report["file"]["file_type"], "doc")
        self.assertEqual(report["legacy_office_analysis"]["family"], "word")
        self.assertEqual(report["legacy_office_analysis"]["status"], "parsed")
        self.assertTrue(report["legacy_office_analysis"]["vba_project_present"])
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_detects_excel_and_powerpoint_stream_families(self):
        excel = self.analyze("sample.xls", build_cfb([("Root Entry", 5), ("Workbook", 2)]))
        power = self.analyze("sample.ppt", build_cfb([("Root Entry", 5), ("PowerPoint Document", 2)]))
        self.assertEqual(excel["legacy_office_analysis"]["family"], "excel")
        self.assertEqual(power["legacy_office_analysis"]["family"], "powerpoint")
        self.assertEqual(excel["file"]["file_type"], "xls")
        self.assertEqual(power["file"]["file_type"], "ppt")

    def test_wrong_extension_reports_family_mismatch(self):
        report = self.analyze("mistyped.xls", build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        self.assertEqual(report["legacy_office_analysis"]["family"], "word")
        self.assertFalse(report["legacy_office_analysis"]["extension_matches_detected_family"])
        self.assertIn("does not match", " ".join(report["warnings"]))

    def test_non_cfb_with_doc_suffix_fails_explicitly(self):
        report = self.analyze("not-really.doc", b"not a compound file")
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")

    def test_truncated_cfb_does_not_claim_parsed(self):
        report = self.analyze("truncated.doc", OLE_SIGNATURE + b"\x00" * 64)
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")

    def test_supports_version_four_cfb_sector_size(self):
        report = self.analyze("version4.doc", build_cfb([("Root Entry", 5), ("WordDocument", 2)], major=4))
        self.assertEqual(report["legacy_office_analysis"]["status"], "parsed")
        self.assertEqual(report["legacy_office_analysis"]["sector_size"], 4096)

    def test_directory_chain_cycle_is_partial_not_trusted(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        # In the generated CFB, the FAT sector follows the single directory sector.
        struct.pack_into("<I", data, 1024, 0)
        report = self.analyze("cycle.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "partial")
        self.assertTrue(any("cycle" in warning for warning in report["warnings"]))

    def test_directory_inventory_is_bounded(self):
        report = self.analyze("many.doc", build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        self.assertLessEqual(len(report["legacy_office_analysis"]["directory_inventory"]), 300)


    def test_empty_directory_chain_preserves_error_and_truncation(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        struct.pack_into("<I", data, 48, 2)

        report = self.analyze("bad-start.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "failed")
        self.assertTrue(analysis["truncated"])
        self.assertTrue(analysis["features"]["directory_chain_truncated"])
        self.assertTrue(any("Directory chain:" in warning for warning in analysis["warnings"]))
        self.assertTrue(any("invalid or unavailable FAT entry" in warning for warning in analysis["warnings"]))
        self.assertTrue(any("Directory chain:" in warning for warning in report["warnings"]))

if __name__ == "__main__":
    unittest.main()
