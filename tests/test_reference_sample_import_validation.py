from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cvevident.db import init_db
from cvevident.store import import_reference_samples_json, lookup_reference_samples


SAMPLE = {
    "sample_id": "sample-one",
    "sha256": "a" * 64,
    "file_type": "pdf",
    "label": "unknown",
    "source_name": "test fixture",
    "label_basis": "synthetic test data",
}


class ReferenceSampleImportValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "test.sqlite3"
        init_db(self.db_path)

    def import_payload(self, samples):
        path = self.root / "samples.json"
        path.write_text(json.dumps({"samples": samples}), encoding="utf-8")
        return import_reference_samples_json(path, self.db_path)

    def test_non_object_sample_is_rejected_and_prior_rows_roll_back(self):
        with self.assertRaisesRegex(ValueError, "Sample 2 must be a JSON object"):
            self.import_payload([SAMPLE, None])

        self.assertEqual(lookup_reference_samples("a" * 64, self.db_path), [])

    def test_non_object_cve_link_is_rejected_and_sample_rolls_back(self):
        sample = {**SAMPLE, "cve_links": [None]}
        with self.assertRaisesRegex(ValueError, "CVE link 1 for sample sample-one must be a JSON object"):
            self.import_payload([sample])

        self.assertEqual(lookup_reference_samples("a" * 64, self.db_path), [])


if __name__ == "__main__":
    unittest.main()
