"""Acceptance for source freshness states, including malformed timestamps and failed refreshes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cvevident.db import connect, init_db
from cvevident.store import get_source_freshness


def test_source_freshness_distinguishes_invalid_old_and_failed_latest_attempts(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "freshness.sqlite3")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    old_success = (now - timedelta(days=70)).isoformat()
    failed_attempt = (now - timedelta(days=1)).isoformat()
    fresh_success = (now - timedelta(hours=2)).isoformat()

    with connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details) VALUES(?,?,?,?,?,?)",
            [
                ("NVD yearly 2020", old_success, old_success, 12, "success", "old yearly cache"),
                ("NVD", old_success, failed_attempt, 0, "error", "refresh failed"),
                ("CISA KEV", "not-a-timestamp", "also-invalid", 0, "error", "invalid fixture timestamp"),
                ("FIRST EPSS", fresh_success, fresh_success, 100, "success", "fresh local import"),
            ],
        )

    result = get_source_freshness(db_path)["sources"]
    assert result["NVD"]["state"] == "last_attempt_not_successful"
    assert result["NVD"]["freshness_class"] == "stale_by_local_import_age"
    assert result["NVD"]["sync_record_count"] == 2
    assert result["NVD"]["last_success_age_seconds"] is not None
    assert result["CISA KEV"]["state"] == "no_successful_local_import"
    assert result["CISA KEV"]["freshness_class"] == "unknown"
    assert result["FIRST EPSS"]["state"] == "available_from_local_import"
    assert result["FIRST EPSS"]["freshness_class"] == "fresh_by_local_import_age"
