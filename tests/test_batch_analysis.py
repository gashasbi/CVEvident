from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvevident.cli import main
from cvevident.db import init_db


class BatchAnalysisCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "batch.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative: str, data: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_batch(self, *args: str):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--db", str(self.db), "analyze-batch", *map(str, args)])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_batch_continues_after_missing_input_and_writes_per_file_reports(self):
        text = self.write("first.txt", b"ordinary text file")
        rtf = self.write("second.rtf", b"{\\rtf1\\ansi batch fixture}")
        missing = self.root / "missing.pdf"
        reports_dir = self.root / "reports"

        code, output, _stderr = self.run_batch(
            str(text), str(missing), str(rtf), "--reports-dir", str(reports_dir),
        )

        summary = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["counts"]["files_discovered"], 2)
        self.assertEqual(summary["counts"]["files_analyzed"], 2)
        self.assertEqual(summary["counts"]["files_failed"], 1)
        self.assertEqual(summary["counts"]["reports_written"], 2)
        failed = [row for row in summary["results"] if row["status"] == "error"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["stage"], "discovery")
        saved = [row for row in summary["results"] if row.get("report_path")]
        self.assertEqual(len(saved), 2)
        for row in saved:
            per_file = json.loads(Path(row["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(per_file["file"]["sha256"], row["sha256"])

    def test_directory_scan_is_nonrecursive_by_default_and_recursive_on_request(self):
        root = self.root / "input-dir"
        self.write("input-dir/top.rtf", b"{\\rtf1\\ansi top}")
        self.write("input-dir/nested/child.rtf", b"{\\rtf1\\ansi child}")

        code, output, _stderr = self.run_batch(str(root))
        shallow = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(shallow["counts"]["files_discovered"], 1)

        code, output, _stderr = self.run_batch(str(root), "--recursive")
        recursive = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(recursive["counts"]["files_discovered"], 2)
        self.assertEqual(recursive["counts"]["files_analyzed"], 2)

    def test_max_files_stops_enumeration_and_marks_summary_partial(self):
        root = self.root / "many"
        for name in ("a.rtf", "b.rtf", "c.rtf"):
            self.write(f"many/{name}", b"{\\rtf1\\ansi fixture}")

        code, output, _stderr = self.run_batch(str(root), "--max-files", "2")
        summary = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["counts"]["files_discovered"], 2)
        self.assertEqual(summary["counts"]["files_analyzed"], 2)
        self.assertTrue(summary["file_limit_reached"])
        self.assertTrue(any("Maximum batch file count" in warning for warning in summary["warnings"]))

    def test_summary_json_can_be_saved_to_a_file(self):
        path = self.write("sample.rtf", b"{\\rtf1\\ansi summary output}")
        summary_path = self.root / "out" / "batch-summary.json"

        code, stdout, _stderr = self.run_batch(str(path), "--output", str(summary_path))

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(summary_path.read_text(encoding="utf-8"))["status"], "ok")
        self.assertEqual(json.loads(stdout)["status"], "ok")

    def test_empty_directory_and_missing_path_are_reported_without_crashing(self):
        empty = self.root / "empty"
        empty.mkdir()
        missing = self.root / "not-here.rtf"

        code, output, _stderr = self.run_batch(str(empty), str(missing))
        summary = json.loads(output)

        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["counts"]["files_analyzed"], 0)
        self.assertEqual(summary["counts"]["files_failed"], 2)
        self.assertTrue(all(row["status"] == "error" for row in summary["results"]))

    def test_analyzer_exception_for_one_file_does_not_stop_the_next_file(self):
        first = self.write("bad.rtf", b"{\\rtf1\\ansi one}")
        second = self.write("good.rtf", b"{\\rtf1\\ansi two}")
        successful_report = {
            "file": {"file_type": "rtf", "sha256": "abc123"},
            "analysis_id": 42,
        }

        with patch("cvevident.cli.analyze_file", side_effect=[ValueError("fixture error"), successful_report]):
            code, output, _stderr = self.run_batch(str(first), str(second))

        summary = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(summary["counts"]["files_analyzed"], 1)
        self.assertEqual(summary["counts"]["files_failed"], 1)
        self.assertEqual(summary["results"][0]["stage"], "analysis")
        self.assertEqual(summary["results"][1]["analysis_id"], 42)

    def test_batch_marks_parser_failure_and_continues_with_other_inputs(self):
        good = self.write("good.rtf", b"{\\rtf1\\ansi valid fixture}")
        broken = self.write("broken.docx", b"PK\x03\x04broken")
        unknown = self.write("unknown.bin", b"unknown file content")
        reports_dir = self.root / "mixed-reports"

        code, output, _stderr = self.run_batch(
            str(good), str(broken), str(unknown), str(good),
            "--reports-dir", str(reports_dir),
        )
        summary = json.loads(output)
        results = {
            Path(item["path"]).name: item
            for item in summary["results"]
            if item.get("path")
        }

        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["counts"]["files_discovered"], 3)
        self.assertEqual(summary["counts"]["files_analyzed"], 2)
        self.assertEqual(summary["counts"]["files_failed"], 1)
        self.assertEqual(summary["counts"]["reports_written"], 3)
        self.assertEqual(summary["counts"]["duplicates_skipped"], 1)
        self.assertEqual(results["good.rtf"]["status"], "ok")
        self.assertEqual(results["unknown.bin"]["status"], "ok")
        self.assertEqual(results["broken.docx"]["status"], "error")
        self.assertEqual(results["broken.docx"]["stage"], "analysis")
        self.assertEqual(results["broken.docx"]["analysis_status"], "failed")

        report_path = Path(results["broken.docx"]["report_path"])
        self.assertTrue(report_path.is_file())
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["office_analysis"]["status"], "failed")

    def test_duplicate_file_paths_are_analyzed_once(self):
        path = self.write("once.rtf", b"{\\rtf1\\ansi once}")

        code, output, _stderr = self.run_batch(str(path), str(path))
        summary = json.loads(output)

        self.assertEqual(code, 0)
        self.assertEqual(summary["counts"]["files_discovered"], 1)
        self.assertEqual(summary["counts"]["files_analyzed"], 1)
        self.assertEqual(summary["counts"]["duplicates_skipped"], 1)
        self.assertTrue(any("Duplicate file paths" in warning for warning in summary["warnings"]))

    def test_nonpositive_max_files_is_a_cli_usage_error(self):
        path = self.write("sample.rtf", b"{\\rtf1\\ansi fixture}")
        code, _stdout, stderr = self.run_batch(str(path), "--max-files", "0")
        self.assertEqual(code, 2)
        self.assertIn("--max-files must be positive", stderr)


if __name__ == "__main__":
    unittest.main()
