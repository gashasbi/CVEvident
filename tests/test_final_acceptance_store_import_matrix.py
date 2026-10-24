"""Final acceptance matrix for malformed and mixed-quality local source imports."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from cvevident.db import connect, init_db
from cvevident.store import (
    get_analysis,
    import_epss_csv,
    import_kev_json,
    import_nvd_json,
    import_reference_samples_json,
    search_cves,
)


def _write_json(path: Path, payload) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _sample(**overrides):
    row = {
        "sample_id": "sample-boundary-001",
        "sha256": "A" * 64,
        "file_type": "pdf",
        "label": "unknown",
        "source_name": "synthetic acceptance fixture",
        "label_basis": "test metadata only",
        "cve_links": [None],
    }
    row.update(overrides)
    return row


def test_nvd_import_skips_invalid_records_and_filters_references_and_weaknesses(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "store.sqlite3")
    payload = {
        "vulnerabilities": [
            None,
            {"cve": None},
            {"cve": {"id": "not-a-cve"}},
            {
                "cve": {
                    "id": "CVE-2099-12345",
                    "published": "2099-01-01T00:00:00Z",
                    "descriptions": [None, {"lang": "fr", "value": "ignored language"}, {"lang": "en", "value": "Valid record"}],
                    "references": [None, {"url": 8}, {"url": "https://example.test/advisory", "source": "fixture", "tags": ["Vendor Advisory"]}],
                    "weaknesses": [None, {"description": [None, {"value": "CWE-787"}, {"value": "not-a-cwe"}]}],
                    "configurations": [],
                }
            },
        ]
    }
    path = _write_json(tmp_path / "nvd.json", payload)

    assert import_nvd_json(path, db_path) == 1
    with connect(db_path) as conn:
        vulnerability = conn.execute("SELECT description FROM vulnerabilities WHERE cve_id='CVE-2099-12345'").fetchone()
        references = conn.execute("SELECT url,name FROM vulnerability_references").fetchall()
        weaknesses = conn.execute("SELECT cwe_id FROM vulnerability_weaknesses").fetchall()
        source = conn.execute("SELECT records_seen,status FROM source_sync WHERE source='NVD'").fetchone()

    assert vulnerability["description"] == "Valid record"
    assert [tuple(row) for row in references] == [("https://example.test/advisory", "fixture")]
    assert [row["cwe_id"] for row in weaknesses] == ["CWE-787"]
    assert (source["records_seen"], source["status"]) == (1, "success")


@pytest.mark.parametrize(
    ("importer", "filename", "message"),
    [
        (import_nvd_json, "missing-nvd.json", "NVD import file not found"),
        (import_kev_json, "missing-kev.json", "CISA KEV file not found"),
        (import_epss_csv, "missing-epss.csv", "EPSS CSV file not found"),
    ],
)
def test_source_importers_fail_explicitly_for_missing_files(
    tmp_path: Path, importer, filename: str, message: str
) -> None:
    with pytest.raises(FileNotFoundError, match=message):
        importer(tmp_path / filename, tmp_path / "db.sqlite3")


def test_kev_import_skips_invalid_rows_and_only_records_http_notes(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "kev.sqlite3")
    payload = {
        "vulnerabilities": [
            None,
            {"cveID": 4},
            {"cveID": "invalid"},
            {"cveID": "CVE-2024-1234", "shortDescription": "valid", "notes": "javascript:alert(1)"},
            {"cveID": "CVE-2024-5678", "vulnerabilityName": "second", "notes": "https://example.test/kev"},
        ]
    }
    path = _write_json(tmp_path / "kev.json", payload)

    assert import_kev_json(path, db_path) == 2
    with connect(db_path) as conn:
        rows = conn.execute("SELECT cve_id,cisa_kev,description FROM vulnerabilities ORDER BY cve_id").fetchall()
        refs = conn.execute("SELECT cve_id,url FROM vulnerability_references").fetchall()

    assert [(row["cve_id"], row["cisa_kev"]) for row in rows] == [
        ("CVE-2024-1234", 1), ("CVE-2024-5678", 1)
    ]
    assert [row["url"] for row in refs] == ["https://example.test/kev"]


def test_epss_import_skips_bad_ids_numbers_and_out_of_range_values(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "epss.sqlite3")
    path = tmp_path / "scores.csv"
    path.write_text(
        "# generated fixture metadata\nCVE, EPSS, Percentile\n"
        "bad-id,0.1,0.2\n"
        "CVE-2024-1001,not-a-number,0.2\n"
        "CVE-2024-1002,0.2,2.0\n"
        "CVE-2024-1003,0.2,0.8\n",
        encoding="utf-8",
    )

    assert import_epss_csv(path, db_path) == 1
    with connect(db_path) as conn:
        rows = conn.execute("SELECT cve_id,epss_score,epss_percentile FROM vulnerabilities").fetchall()
    assert [tuple(row) for row in rows] == [("CVE-2024-1003", 0.2, 0.8)]


def test_reference_sample_import_skips_non_object_samples_and_non_object_links(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "samples.sqlite3")
    path = _write_json(tmp_path / "samples.json", {"samples": [None, "not-a-row", _sample()]})

    assert import_reference_samples_json(path, db_path) == 1
    with connect(db_path) as conn:
        row = conn.execute("SELECT sample_id,sha256,label FROM reference_samples").fetchone()
        link_count = conn.execute("SELECT COUNT(*) FROM sample_vulnerability_links").fetchone()[0]
    assert row["sample_id"] == "sample-boundary-001"
    assert row["sha256"] == "a" * 64
    assert row["label"] == "unknown"
    assert link_count == 0


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"label": "unclassified"}, "Unsupported label"),
        ({"confidence": "absolute"}, "Unsupported confidence value"),
        ({"cve_links": [{"cve_id": "bad-cve"}]}, "Invalid CVE ID"),
        ({"cve_links": [{"cve_id": "CVE-2024-1234", "confidence": "absolute"}]}, "Unsupported confidence value in sample CVE link"),
        ({"cve_links": [{"cve_id": "CVE-2024-1234"}]}, "must be imported before linking sample"),
    ],
)
def test_reference_sample_import_rejects_invalid_labels_and_links_atomically(
    tmp_path: Path, overrides: dict, message: str
) -> None:
    db_path = init_db(tmp_path / "samples.sqlite3")
    path = _write_json(tmp_path / "samples.json", {"samples": [_sample(**overrides)]})

    with pytest.raises(ValueError, match=message):
        import_reference_samples_json(path, db_path)

    with connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM reference_samples").fetchone()[0] == 0


def test_search_cves_empty_or_unusable_queries_return_no_results(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "search.sqlite3")
    assert search_cves("", db_path) == []
    assert search_cves("   ", db_path) == []
    assert search_cves("!!!", db_path) == []
    assert search_cves("CVE-2099-99999", db_path) == []


def test_get_analysis_returns_none_for_missing_and_raw_value_for_non_json_text(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "analysis.sqlite3")
    assert get_analysis(999, db_path) is None
    with connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO analysis_runs(filename,sha256,file_type,size_bytes,verdict,target_product,created_at,summary_json) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("sample.bin", "a" * 64, "unknown_or_non_pdf", 1, "not_assessed", None, "2026-01-01T00:00:00+00:00", "{}"),
        )
        analysis_id = cursor.lastrowid
        conn.execute(
            "INSERT INTO evidence(analysis_id,evidence_type,evidence_key,value_text,severity,details_json) VALUES(?,?,?,?,?,?)",
            (analysis_id, "test", "raw-value", "legacy non-json text", "info", "{}"),
        )

    report = get_analysis(analysis_id, db_path)
    assert report is not None
    assert report["evidence"][0]["value"] == "legacy non-json text"
    assert report["evidence"][0]["details"] == {}
