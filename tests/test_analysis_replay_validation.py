from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cvevident.db import connect, init_db
from cvevident.store import get_analysis


class AnalysisReplayValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = Path(self.temp_dir.name) / "test.sqlite3"
        init_db(self.db_path)

    def add_analysis(self, summary_json):
        with connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO analysis_runs
                   (filename, sha256, file_type, size_bytes, verdict, created_at, summary_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    "sample.pdf",
                    "a" * 64,
                    "pdf",
                    1,
                    "not_assessed",
                    "2026-11-19T00:00:00+00:00",
                    summary_json,
                ),
            )
            return cursor.lastrowid

    def test_non_object_summary_json_is_rejected(self):
        analysis_id = self.add_analysis("[]")
        with self.assertRaisesRegex(ValueError, "summary.*JSON object"):
            get_analysis(analysis_id, self.db_path)

    def test_invalid_evidence_details_json_is_rejected(self):
        analysis_id = self.add_analysis("{}")
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO evidence
                   (analysis_id, evidence_type, evidence_key, value_text, details_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (analysis_id, "marker", "test", "null", "{"),
            )
        with self.assertRaisesRegex(ValueError, "evidence details.*valid JSON"):
            get_analysis(analysis_id, self.db_path)

    def test_non_object_evidence_details_json_is_rejected(self):
        analysis_id = self.add_analysis("{}")
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO evidence
                   (analysis_id, evidence_type, evidence_key, value_text, details_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (analysis_id, "marker", "test", "null", "[]"),
            )
        with self.assertRaisesRegex(ValueError, "evidence details.*JSON object"):
            get_analysis(analysis_id, self.db_path)


if __name__ == "__main__":
    unittest.main()
