"""Integrated reliability checks for data synchronization, import transactions, and product context."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cvevident.db import connect, init_db
from cvevident.evidence_engine import build_product_context
from cvevident.product_matching import classify_name_match, split_product_version
from cvevident.sources import download, sync_nvd_modified, sync_nvd_year, sync_nvd_years
from cvevident.store import (
    get_cve,
    get_source_freshness,
    import_epss_csv,
    import_kev_json,
    import_nvd_json,
    import_reference_samples_json,
    search_product_cves,
)


class FakeResponse:
    def __init__(self, body: bytes, *, content_length: str | None = None):
        self.body = body
        self.offset = 0
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body) - self.offset
        result = self.body[self.offset:self.offset + size]
        self.offset += len(result)
        return result


def _nvd_record(cve_id: str = "CVE-2099-12345", *, cpe_matches=None) -> dict:
    cve = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "Synthetic test record"}],
        "references": [],
    }
    if cpe_matches is not None:
        cve["configurations"] = [{"nodes": [{"cpeMatch": cpe_matches}]}]
    return {"cve": cve}


def _page(start: int, total: int, records: list[dict]) -> dict:
    return {
        "startIndex": start,
        "totalResults": total,
        "resultsPerPage": len(records),
        "vulnerabilities": records,
    }


def test_download_truncated_content_length_preserves_previous_file(tmp_path: Path) -> None:
    destination = tmp_path / "feed.json"
    destination.write_bytes(b"previous-good-feed")
    response = FakeResponse(b"short", content_length="99")

    with patch("cvevident.sources.urllib.request.urlopen", return_value=response):
        with pytest.raises(RuntimeError, match="Incomplete download"):
            download("https://example.invalid/feed", destination)

    assert destination.read_bytes() == b"previous-good-feed"
    assert not list(tmp_path.glob("*.part"))


def test_nvd_modified_sync_does_not_commit_first_page_if_second_page_fails(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    prior_success = "2025-01-02T03:04:05+00:00"
    with connect(db) as conn:
        conn.execute(
            "INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details) "
            "VALUES('NVD',?,?,?,?,?)",
            (prior_success, prior_success, 42, "success", "prior-good-import"),
        )

    first_page = _page(0, 2, [_nvd_record()])
    with patch("cvevident.sources._request_json", side_effect=[first_page, RuntimeError("second page failed")]), \
         patch("cvevident.sources.time.sleep"):
        with pytest.raises(RuntimeError, match="second page failed"):
            sync_nvd_modified(db, days=1, cache_dir=tmp_path / "cache", sleep_seconds=0)

    assert get_cve("CVE-2099-12345", db) is None
    with connect(db) as conn:
        state = conn.execute(
            "SELECT last_success_at,last_attempt_at,records_seen,status FROM source_sync WHERE source='NVD'"
        ).fetchone()
    assert state["last_success_at"] == prior_success
    assert state["records_seen"] == 42
    assert state["status"] == "error"
    assert state["last_attempt_at"] != prior_success
    assert not list((tmp_path / "cache").glob("nvd-modified-aggregate-*.json"))


def test_nvd_modified_sync_imports_only_after_all_pages_validate(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    pages = [
        _page(0, 2, [_nvd_record("CVE-2099-12345")]),
        _page(1, 2, [_nvd_record("CVE-2099-12346")]),
    ]
    with patch("cvevident.sources._request_json", side_effect=pages), patch("cvevident.sources.time.sleep"):
        imported = sync_nvd_modified(db, days=1, cache_dir=tmp_path / "cache", sleep_seconds=0)

    assert imported == 2
    assert get_cve("CVE-2099-12345", db) is not None
    assert get_cve("CVE-2099-12346", db) is not None
    freshness = get_source_freshness(db)["sources"]["NVD"]
    assert freshness["state"] == "available_from_local_import"
    assert freshness["records_seen_on_latest_success"] == 2


def test_nvd_modified_sync_accepts_short_final_page_using_actual_record_count(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    pages = [
        _page(0, 3, [_nvd_record("CVE-2099-12345"), _nvd_record("CVE-2099-12346")]),
        {
            "startIndex": 2,
            "resultsPerPage": 2000,
            "totalResults": 3,
            "vulnerabilities": [_nvd_record("CVE-2099-12347")],
        },
    ]
    with patch("cvevident.sources._request_json", side_effect=pages), patch("cvevident.sources.time.sleep"):
        imported = sync_nvd_modified(db, days=1, cache_dir=tmp_path / "cache", sleep_seconds=0)

    assert imported == 3
    assert all(get_cve(cve_id, db) is not None for cve_id in (
        "CVE-2099-12345", "CVE-2099-12346", "CVE-2099-12347"
    ))


def test_nvd_modified_sync_rejects_pagination_total_change_without_import(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    pages = [
        _page(0, 2, [_nvd_record("CVE-2099-12345")]),
        _page(1, 3, [_nvd_record("CVE-2099-12346")]),
    ]
    with patch("cvevident.sources._request_json", side_effect=pages), patch("cvevident.sources.time.sleep"):
        with pytest.raises(RuntimeError, match="totalResults changed"):
            sync_nvd_modified(db, days=1, cache_dir=tmp_path / "cache", sleep_seconds=0)

    assert get_cve("CVE-2099-12345", db) is None
    assert get_cve("CVE-2099-12346", db) is None
    with connect(db) as conn:
        state = conn.execute("SELECT status FROM source_sync WHERE source='NVD'").fetchone()
    assert state["status"] == "error"


def test_nvd_import_skips_non_object_record_and_imports_valid_record(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [_nvd_record(), None]}), encoding="utf-8")

    assert import_nvd_json(source, db) == 1

    assert get_cve("CVE-2099-12345", db) is not None
    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM source_sync WHERE source='NVD'").fetchone()[0] == 1



def test_nvd_import_rolls_back_when_second_record_processing_fails(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [
        _nvd_record("CVE-2099-12345"),
        _nvd_record("CVE-2099-12346"),
    ]}), encoding="utf-8")

    import cvevident.store as store

    original = store._upsert_vulnerability
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("intentional second-record failure")
        return original(*args, **kwargs)

    with patch("cvevident.store._upsert_vulnerability", side_effect=fail_second):
        with pytest.raises(RuntimeError, match="second-record failure"):
            import_nvd_json(source, db)

    assert get_cve("CVE-2099-12345", db) is None
    assert get_cve("CVE-2099-12346", db) is None
    with connect(db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM source_sync WHERE source='NVD'"
        ).fetchone()[0] == 0


def test_kev_import_prevalidates_all_rows_before_mutating_database(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "kev.json"
    source.write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2099-12345", "shortDescription": "Valid prefix"},
        {"cveID": "not-a-cve"},
    ]}), encoding="utf-8")

    assert import_kev_json(source, db) == 1

    assert get_cve("CVE-2099-12345", db) is not None
    with connect(db) as conn:
        state = conn.execute(
            "SELECT last_success_at, records_seen, status, details "
            "FROM source_sync WHERE source='CISA KEV'"
        ).fetchone()
    assert state is not None
    assert state["status"] == "partial"
    assert state["last_success_at"] is None
    assert state["records_seen"] == 0
    assert "valid_rows=1" in state["details"]
    assert "skipped_invalid_rows=1" in state["details"]


def test_reference_sample_import_skips_non_object_row(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "samples.json"
    sample = {
        "sample_id": "LOCAL-1",
        "sha256": "a" * 64,
        "file_type": "pdf",
        "label": "unknown",
        "source_name": "synthetic test",
        "label_basis": "test fixture only",
    }
    source.write_text(json.dumps({"samples": [sample, None]}), encoding="utf-8")

    assert import_reference_samples_json(source, db) == 1

    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM reference_samples").fetchone()[0] == 1


def test_reference_sample_import_rolls_back_when_cve_link_is_invalid(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "samples-invalid-link.json"
    sample = {
        "sample_id": "LOCAL-ROLLBACK-1",
        "sha256": "b" * 64,
        "file_type": "pdf",
        "label": "unknown",
        "source_name": "synthetic test",
        "label_basis": "rollback test fixture",
        "cve_links": [
            {
                "cve_id": "CVE-2099-12345",
                "evidence_basis": "synthetic test only",
            }
        ],
    }
    source.write_text(json.dumps({"samples": [sample]}), encoding="utf-8")

    with pytest.raises(ValueError):
        import_reference_samples_json(source, db)

    with connect(db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM reference_samples WHERE sample_id='LOCAL-ROLLBACK-1'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM sample_vulnerability_links"
        ).fetchone()[0] == 0


def test_epss_import_provenance_reports_skipped_invalid_rows(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "epss.csv"
    source.write_text(
        "cve,epss,percentile\nCVE-2099-12345,0.42,0.91\nCVE-2099-12346,2.0,0.5\n",
        encoding="utf-8",
    )

    assert import_epss_csv(source, db) == 1
    with connect(db) as conn:
        state = conn.execute(
            "SELECT last_success_at,last_attempt_at,records_seen,status,details "
            "FROM source_sync WHERE source='FIRST EPSS'"
        ).fetchone()
    assert state["status"] == "partial"
    assert state["last_success_at"] is None
    assert state["records_seen"] == 0
    assert "valid_rows=1" in state["details"]
    assert "skipped_invalid_rows=1" in state["details"]


def test_annual_feed_checksum_failure_keeps_previous_cache_and_last_success(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    year = 2025
    cache = tmp_path / "cache"
    cache.mkdir()
    feed_path = cache / f"nvdcve-2.0-{year}.json.gz"
    previous_uncompressed = json.dumps({"vulnerabilities": []}).encode()
    feed_path.write_bytes(gzip.compress(previous_uncompressed))
    previous_feed = feed_path.read_bytes()
    previous_success = "2025-03-04T05:06:07+00:00"
    with connect(db) as conn:
        conn.execute(
            "INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details) "
            "VALUES(?,?,?,?,?,?)",
            (f"NVD yearly {year}", previous_success, previous_success, 7, "success", "year=2025; sha256=old"),
        )

    bad_plain = b'{"vulnerabilities":[]}'
    bad_meta = f"sha256:{hashlib.sha256(b'different-feed').hexdigest()}\n".encode()

    def fake_download(url, destination, timeout=60, max_bytes=500 * 1024 * 1024):
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bad_meta if url.endswith(".meta") else gzip.compress(bad_plain))
        return target

    with patch("cvevident.sources.download", side_effect=fake_download):
        with pytest.raises(RuntimeError, match="SHA-256 verification failed"):
            sync_nvd_year(year, db, cache)

    assert feed_path.read_bytes() == previous_feed
    assert not list(cache.glob("*.download.gz"))
    with connect(db) as conn:
        state = conn.execute(
            "SELECT last_success_at,records_seen,status FROM source_sync WHERE source=?",
            (f"NVD yearly {year}",),
        ).fetchone()
    assert state["last_success_at"] == previous_success
    assert state["records_seen"] == 7
    assert state["status"] == "error"


def test_product_ambiguity_counts_all_matching_identities_not_only_display_rows(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    cpe_matches = [
        {"criteria": f"cpe:2.3:a:vendor{index:02d}:widget:*:*:*:*:*:*:*:*", "vulnerable": True}
        for index in range(12)
    ]
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [_nvd_record(cpe_matches=cpe_matches)]}), encoding="utf-8")
    import_nvd_json(source, db)

    result = search_product_cves("widget", db)[0]
    assert result["matched_cpe_row_count"] == 12
    assert len(result["matching_product_rows"]) == 10
    assert result["query_ambiguity"]["distinct_matched_product_identity_count"] == 12
    assert result["query_ambiguity"]["status"] == "ambiguous_multiple_product_identities"


def test_explicit_version_conflict_is_reported_and_suffix_does_not_pollute_product_name() -> None:
    assert split_product_version("Acme Viewer 1.0", "2.0") == (
        "Acme Viewer", "2.0", "explicit_option_conflicts_with_query_suffix"
    )
    assert split_product_version("Acme Viewer 2.0", "2.0.0") == (
        "Acme Viewer", "2.0.0", "explicit_option"
    )


def test_product_context_exposes_explicit_version_conflict(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    cpe = "cpe:2.3:a:acme:viewer:2.0:*:*:*:*:*:*:*"
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [
        _nvd_record(cpe_matches=[{"criteria": cpe, "vulnerable": True}])
    ]}), encoding="utf-8")
    import_nvd_json(source, db)

    context = build_product_context("Acme Viewer 1.0", str(db), target_version="2.0")
    assert context["target_product"] == "Acme Viewer"
    assert context["target_version"] == "2.0"
    assert context["version_input_conflict"] is True
    assert "conflicts with the explicit target version" in context["version_input_warning"]
    assert context["candidate_cves"][0]["query_normalization"]["version_input_conflict"] is True


def test_request_json_retries_truncated_json_and_accepts_next_valid_response(monkeypatch) -> None:
    from cvevident.sources import _request_json

    malformed = FakeResponse(b'{"vulnerabilities":', content_length=str(len(b'{"vulnerabilities":')))
    valid_body = b'{"startIndex":0,"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}'
    valid = FakeResponse(valid_body, content_length=str(len(valid_body)))
    with patch("cvevident.sources.urllib.request.urlopen", side_effect=[malformed, valid]), \
         patch("cvevident.sources.time.sleep"):
        payload = _request_json("https://example.invalid/nvd")

    assert payload["vulnerabilities"] == []
    assert payload["totalResults"] == 0


def test_request_json_enforces_response_byte_cap(monkeypatch) -> None:
    from cvevident.sources import _request_json

    monkeypatch.setattr("cvevident.sources.MAX_NVD_API_RESPONSE_BYTES", 4)
    response = FakeResponse(b"12345", content_length="5")
    with patch("cvevident.sources.urllib.request.urlopen", return_value=response):
        with pytest.raises(RuntimeError, match="limit"):
            _request_json("https://example.invalid/nvd")



def test_nvd_year_range_reports_partial_result_when_one_year_fails(tmp_path: Path) -> None:
    calls = []

    def sync_year(year, db_path, cache_dir, force_download):
        calls.append(year)
        if year == 2025:
            return {"year": year, "status": "imported", "records_imported": 3}
        if year == 2026:
            raise RuntimeError("synthetic feed failure")
        return {"year": year, "status": "up_to_date", "records_imported": 0}

    with patch("cvevident.sources.sync_nvd_year", side_effect=sync_year):
        result = sync_nvd_years(2025, 2026, tmp_path / "unused.sqlite3", tmp_path / "cache")

    assert calls == [2025, 2026]
    assert result["status"] == "partial_or_failed"
    assert result["records_imported"] == 3
    assert [row["status"] for row in result["years"]] == ["imported", "error"]


def test_streaming_and_standard_nvd_imports_produce_equivalent_records(tmp_path: Path) -> None:
    import sys
    import types

    payload = {"vulnerabilities": [_nvd_record(cpe_matches=[
        {"criteria": "cpe:2.3:a:acme:viewer:2.0:*:*:*:*:*:*:*", "vulnerable": True}
    ])]}
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    streaming_db = tmp_path / "streaming.sqlite3"
    standard_db = tmp_path / "standard.sqlite3"
    init_db(streaming_db)
    init_db(standard_db)

    fake = types.ModuleType("ijson")
    def fake_parse(handle):
        json.load(handle)
        yield ("", "start_map", None)
        yield ("", "map_key", "vulnerabilities")
        yield ("vulnerabilities", "start_array", None)
    def fake_items(handle, prefix):
        assert prefix == "vulnerabilities.item"
        return iter(json.load(handle)["vulnerabilities"])
    fake.parse = fake_parse
    fake.items = fake_items

    with patch.dict(sys.modules, {"ijson": fake}):
        streamed_count = import_nvd_json(source, streaming_db)
    with patch.dict(sys.modules, {"ijson": None}):
        standard_count = import_nvd_json(source, standard_db)

    assert streamed_count == standard_count == 1
    streamed = get_cve("CVE-2099-12345", streaming_db)
    standard = get_cve("CVE-2099-12345", standard_db)
    assert streamed["description"] == standard["description"]
    assert streamed["affected_products"] == standard["affected_products"]
    assert streamed["references"] == standard["references"]


def test_streaming_nvd_import_rejects_non_array_vulnerabilities_root(tmp_path: Path) -> None:
    import sys
    import types

    db = tmp_path / "streaming-invalid-root.sqlite3"
    init_db(db)
    source = tmp_path / "nvd-invalid-root.json"
    source.write_text('{"vulnerabilities": null}', encoding="utf-8")

    fake = types.ModuleType("ijson")
    def fake_parse(handle):
        json.load(handle)
        yield ("", "start_map", None)
        yield ("", "map_key", "vulnerabilities")
        yield ("vulnerabilities", "null", None)
    def fake_items(handle, prefix):
        return iter(())
    fake.parse = fake_parse
    fake.items = fake_items

    with patch.dict(sys.modules, {"ijson": fake}):
        with pytest.raises(ValueError, match="vulnerabilities.*array"):
            import_nvd_json(source, db)

    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM source_sync WHERE source='NVD'").fetchone()[0] == 0


def test_reimporting_same_nvd_record_is_idempotent_for_related_rows(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    record = _nvd_record(cpe_matches=[{
        "criteria": "cpe:2.3:a:acme:viewer:2.0:*:*:*:*:*:*:*", "vulnerable": True
    }])
    record["cve"]["references"] = [{"url": "https://example.invalid/ref", "source": "test", "tags": []}]
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [record]}), encoding="utf-8")

    assert import_nvd_json(source, db) == 1
    assert import_nvd_json(source, db) == 1
    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM affected_products").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM vulnerability_references").fetchone()[0] == 1


def test_vendor_only_results_rank_below_product_name_matches(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    records = [
        _nvd_record("CVE-2099-12345", cpe_matches=[{
            "criteria": "cpe:2.3:a:acme:viewer:*:*:*:*:*:*:*:*", "vulnerable": True
        }]),
        _nvd_record("CVE-2099-12346", cpe_matches=[{
            "criteria": "cpe:2.3:a:other:acme_tool:*:*:*:*:*:*:*:*", "vulnerable": True
        }]),
    ]
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": records}), encoding="utf-8")
    import_nvd_json(source, db)

    results = search_product_cves("acme", db)
    assert results[0]["cve_id"] == "CVE-2099-12346"
    assert results[0]["name_match_class"] == "all_query_terms_match"
    vendor_only = next(item for item in results if item["cve_id"] == "CVE-2099-12345")
    assert vendor_only["name_match_class"] == "vendor_only_match"
    assert vendor_only["product_relevance_score"] == 50.0

def test_vendor_only_product_query_is_labeled_lower_confidence_context() -> None:
    context = classify_name_match("acme", "acme", "viewer")
    assert context["name_match_class"] == "vendor_only_match"
    assert context["matching_vendor_terms"] == ["acme"]
    assert context["matching_product_terms"] == []
    assert context["name_match_score"] == 50.0


def test_epss_partial_import_preserves_previous_success_snapshot(tmp_path: Path) -> None:
    db = tmp_path / "local.sqlite3"
    init_db(db)
    previous_success = "2025-01-02T03:04:05+00:00"
    with connect(db) as conn:
        conn.execute(
            "INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details) "
            "VALUES('FIRST EPSS',?,?,?,?,?)",
            (previous_success, previous_success, 123, "success", "prior-complete-feed"),
        )
    source = tmp_path / "epss.csv"
    source.write_text(
        "cve,epss,percentile\nCVE-2099-12345,0.25,0.5\nCVE-2099-12346,invalid,0.2\n",
        encoding="utf-8",
    )

    assert import_epss_csv(source, db) == 1
    with connect(db) as conn:
        state = conn.execute(
            "SELECT last_success_at,last_attempt_at,records_seen,status,details "
            "FROM source_sync WHERE source='FIRST EPSS'"
        ).fetchone()
    assert state["last_success_at"] == previous_success
    assert state["last_attempt_at"] != previous_success
    assert state["records_seen"] == 123
    assert state["status"] == "partial"
    assert "skipped_invalid_rows=1" in state["details"]


def test_request_json_retries_transient_http_503(monkeypatch) -> None:
    from email.message import Message
    from urllib.error import HTTPError

    from cvevident.sources import _request_json

    headers = Message()
    headers["Retry-After"] = "0"
    transient = HTTPError(
        "https://example.invalid/nvd", 503, "temporarily unavailable", headers, None
    )
    body = b'{"startIndex":0,"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}'
    response = FakeResponse(body, content_length=str(len(body)))
    with patch("cvevident.sources.urllib.request.urlopen", side_effect=[transient, response]) as opener, \
         patch("cvevident.sources.time.sleep"):
        payload = _request_json("https://example.invalid/nvd")

    assert opener.call_count == 2
    assert payload["vulnerabilities"] == []


def test_search_product_cli_reports_conflicting_explicit_version(tmp_path: Path, capsys) -> None:
    from cvevident.cli import main

    db = tmp_path / "local.sqlite3"
    init_db(db)
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [_nvd_record()]}), encoding="utf-8")
    import_nvd_json(source, db)

    assert main([
        "--db", str(db), "search-product", "Acme Viewer 1.0", "--version", "2.0"
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["version_input_conflict"] is True
    assert output["version_input_method"] == "explicit_option_conflicts_with_query_suffix"
    assert "conflicts" in output["version_input_warning"]

@pytest.mark.parametrize(
    "body",
    [
        b'{"message":"valid JSON but missing vulnerabilities"}',
        b'{"vulnerabilities":"not-an-array"}',
        b'{"vulnerabilities":[null]}',
        b'{"vulnerabilities":[{"id":"CVE-2099-12345"}]}',
    ],
)
def test_request_json_rejects_valid_json_with_invalid_nvd_structure(
    body: bytes,
) -> None:
    from cvevident.sources import _request_json

    response = FakeResponse(body, content_length=str(len(body)))
    with patch("cvevident.sources.urllib.request.urlopen", return_value=response):
        with pytest.raises(RuntimeError):
            _request_json("https://example.invalid/nvd")

def test_explicit_version_suffix_edge_cases_are_conservative() -> None:
    assert split_product_version("Acme Viewer 2.0-beta", "2.0") == (
        "Acme Viewer", "2.0", "explicit_option_conflicts_with_query_suffix"
    )
    assert split_product_version("Acme Viewer 2.0", "2.0-beta") == (
        "Acme Viewer", "2.0-beta", "explicit_option_conflicts_with_query_suffix"
    )
    assert split_product_version("Acme Viewer 2.0-beta", "2.0-beta") == (
        "Acme Viewer", "2.0-beta", "explicit_option"
    )
    assert split_product_version("Acme Viewer 2.0", "2.0.0") == (
        "Acme Viewer", "2.0.0", "explicit_option"
    )
