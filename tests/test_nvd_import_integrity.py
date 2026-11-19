from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cvevident.db import connect, init_db
from cvevident.store import import_nvd_json


CPE = "cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*"


def nvd_record(configurations):
    return {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-12345",
                "descriptions": [{"lang": "en", "value": "Synthetic test record"}],
                "configurations": configurations,
            }
        }]
    }


class NVDImportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "test.sqlite3"
        init_db(self.db_path)
        self.feed_path = self.root / "nvd.json"

    def write_feed(self, configurations):
        self.feed_path.write_text(
            json.dumps(nvd_record(configurations)),
            encoding="utf-8",
        )

    def product_count(self):
        with connect(self.db_path) as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM affected_products WHERE cve_id=?",
                ("CVE-2024-12345",),
            ).fetchone()[0]

    def test_malformed_configuration_does_not_delete_previous_product_rows(self):
        valid = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{"criteria": CPE, "vulnerable": True}],
            }]
        }]
        self.write_feed(valid)
        self.assertEqual(import_nvd_json(self.feed_path, self.db_path), 1)
        self.assertEqual(self.product_count(), 1)

        self.write_feed("not-an-array")
        self.assertEqual(import_nvd_json(self.feed_path, self.db_path), 1)

        self.assertEqual(self.product_count(), 1)
        with connect(self.db_path) as conn:
            status = conn.execute(
                "SELECT status FROM source_sync WHERE source='NVD'"
            ).fetchone()[0]
        self.assertEqual(status, "partial")


    def test_null_operator_or_negate_preserves_previous_product_rows(self):
        valid = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{"criteria": CPE, "vulnerable": True}],
            }]
        }]
        self.write_feed(valid)
        import_nvd_json(self.feed_path, self.db_path)
        self.assertEqual(self.product_count(), 1)

        malformed = [{
            "nodes": [{
                "operator": None,
                "negate": False,
                "cpeMatch": [{"criteria": CPE, "vulnerable": True}],
            }]
        }]
        self.write_feed(malformed)
        import_nvd_json(self.feed_path, self.db_path)
        self.assertEqual(self.product_count(), 1)

        malformed = [{
            "nodes": [{
                "operator": "OR",
                "negate": None,
                "cpeMatch": [{"criteria": CPE, "vulnerable": True}],
            }]
        }]
        self.write_feed(malformed)
        import_nvd_json(self.feed_path, self.db_path)
        self.assertEqual(self.product_count(), 1)
        with connect(self.db_path) as conn:
            status = conn.execute(
                "SELECT status FROM source_sync WHERE source='NVD'"
            ).fetchone()[0]
        self.assertEqual(status, "partial")



if __name__ == "__main__":
    unittest.main()
