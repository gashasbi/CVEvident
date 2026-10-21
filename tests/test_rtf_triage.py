import tempfile
import unittest
from pathlib import Path

from cvevident.rtf_triage import analyze_rtf, has_rtf_signature


class RtfTriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, name, data, **kwargs):
        path = self.root / name
        path.write_bytes(data)
        return analyze_rtf(str(path), **kwargs)

    def test_rtf_field_object_and_external_target_indicators(self):
        data = (b'{\\rtf1\\ansi{\\field{\\*\\fldinst HYPERLINK "https://example.test/path"}'
                b'{\\fldrslt click}}{\\object\\objemb{\\*\\objdata 001122}}}')
        self.assertTrue(has_rtf_signature(data))
        report = self.analyze("sample.rtf", data)
        analysis = report["rtf_analysis"]
        self.assertEqual(report["file"]["file_type"], "rtf")
        self.assertEqual(analysis["status"], "parsed")
        self.assertGreater(analysis["features"]["object_group_indicator_count"], 0)
        self.assertGreater(analysis["features"]["external_target_count"], 0)
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_binary_payload_is_skipped_not_tokenized(self):
        data = b'{\\rtf1\\ansi\\bin8 ' + b'http://x!' + b' text}'
        report = self.analyze("binary.rtf", data)
        self.assertEqual(report["rtf_analysis"]["status"], "parsed")
        self.assertEqual(report["rtf_analysis"]["features"]["external_target_count"], 0)

    def test_bad_header_with_rtf_extension_is_failed(self):
        report = self.analyze("bad.rtf", b"plain text /object")
        self.assertEqual(report["rtf_analysis"]["status"], "failed")
        self.assertEqual(report["file"]["file_type"], "unknown_or_non_rtf")

    def test_scan_cap_marks_partial(self):
        data = b'{\\rtf1 ' + b'A' * 128 + b'}'
        report = self.analyze("capped.rtf", data, max_scan_bytes=32)
        self.assertEqual(report["rtf_analysis"]["status"], "partial")
        self.assertTrue(report["rtf_analysis"]["truncated"])

    def test_reports_rtf_version(self):
        report = self.analyze("version.rtf", b'{\\rtf1\\ansi hello}')
        self.assertEqual(report["rtf_analysis"]["rtf_version"], 1)


if __name__ == "__main__":
    unittest.main()
