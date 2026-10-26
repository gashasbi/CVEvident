"""CLI dispatcher acceptance for import, sync, and lookup success/failure branches."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from cvevident import cli
from cvevident.db import init_db


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return init_db(tmp_path / "cli.sqlite3")


@pytest.mark.parametrize(
    ("command", "function_name", "result_key", "source_name"),
    [
        ("import-kev", "import_kev_json", "records_imported", "CISA KEV"),
        ("import-epss", "import_epss_csv", "records_imported", "FIRST EPSS"),
        ("import-samples", "import_reference_samples_json", "samples_imported", "curated reference samples"),
    ],
)
def test_cli_import_commands_emit_source_specific_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_path: Path,
    command: str,
    function_name: str,
    result_key: str,
    source_name: str,
) -> None:
    monkeypatch.setattr(cli, function_name, lambda *_args, **_kwargs: 7)
    file_arg = "fixture.csv" if command == "import-epss" else "fixture.json"

    assert cli.main(["--db", str(db_path), command, file_arg]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"source": source_name, result_key: 7}


def test_cli_sync_all_keeps_each_source_outcome_when_one_source_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(cli, "sync_nvd_modified", lambda *_args, **_kwargs: 12)
    monkeypatch.setattr(cli, "sync_kev", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("KEV unavailable")))
    monkeypatch.setattr(cli, "sync_epss", lambda *_args, **_kwargs: 5)

    assert cli.main(["--db", str(db_path), "sync-all"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "partial_or_failed"
    assert result["sources"]["NVD"] == {"status": "ok", "records_imported": 12}
    assert result["sources"]["CISA KEV"] == {"status": "error", "error": "KEV unavailable"}
    assert result["sources"]["FIRST EPSS"] == {"status": "ok", "records_imported": 5}


def test_cli_sync_nvd_years_returns_nonzero_for_partial_aggregate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(
        cli,
        "sync_nvd_years",
        lambda *_args, **_kwargs: {"status": "partial_or_failed", "from_year": 2020,
                                    "to_year": 2021, "years": [{"year": 2021, "status": "error"}],
                                    "records_imported": 0},
    )

    assert cli.main(["--db", str(db_path), "sync-nvd-years", "--from-year", "2020", "--to-year", "2021"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["source"] == "NVD"
    assert result["status"] == "partial_or_failed"


def test_cli_sync_nvd_year_serializes_success_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(
        cli,
        "sync_nvd_year",
        lambda year, *_args, **_kwargs: {"year": year, "status": "up_to_date", "records_imported": 0},
    )
    assert cli.main(["--db", str(db_path), "sync-nvd-year", "2024"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source"] == "NVD"
    assert result["year"] == 2024
    assert result["status"] == "up_to_date"


def test_cli_not_found_lookup_paths_emit_json_and_nonzero_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(cli, "get_cve", lambda *_args, **_kwargs: None)
    assert cli.main(["--db", str(db_path), "show-cve", "cve-2024-1234"]) == 1
    cve_result = json.loads(capsys.readouterr().out)
    assert cve_result["status"] == "not_found"
    assert cve_result["cve_id"] == "CVE-2024-1234"

    monkeypatch.setattr(cli, "get_analysis", lambda *_args, **_kwargs: None)
    assert cli.main(["--db", str(db_path), "show-analysis", "99"]) == 1
    analysis_result = json.loads(capsys.readouterr().out)
    assert analysis_result == {"status": "not_found", "analysis_id": 99}


def test_cli_product_search_empty_result_is_explicitly_not_a_file_attribution(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(cli, "search_product_cves", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(cli, "get_source_freshness", lambda *_args, **_kwargs: {"sources": {}})

    assert cli.main(["--db", str(db_path), "search-product", "Unknown Widget"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["results"] == []
    assert result["query_ambiguity"]["status"] == "no_product_identity_returned"
    assert "not file evidence" in result["note"]


@pytest.mark.parametrize(
    ("command", "function_name", "extra_args", "expected_source"),
    [
        ("sync-kev", "sync_kev", ["--cache-file", "kev.json"], "CISA KEV"),
        ("sync-epss", "sync_epss", ["--cache-file", "epss.csv.gz"], "FIRST EPSS"),
        ("sync-nvd", "sync_nvd_modified", ["--days", "2", "--cache-dir", "cache"], "NVD"),
    ],
)
def test_cli_individual_sync_commands_emit_success_counts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_path: Path,
    command: str,
    function_name: str,
    extra_args: list[str],
    expected_source: str,
) -> None:
    monkeypatch.setattr(cli, function_name, lambda *_args, **_kwargs: 6)
    assert cli.main(["--db", str(db_path), command, *extra_args]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"source": expected_source, "records_imported": 6}


def test_cli_doctor_returns_nonzero_when_database_health_check_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(cli, "_doctor", lambda _path: {"healthy": False, "integrity_check": "corrupt"})
    assert cli.main(["--db", str(db_path), "doctor"]) == 1
    assert json.loads(capsys.readouterr().out)["healthy"] is False


def test_cli_converts_database_initialization_errors_to_exit_code_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(cli, "init_db", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("schema unavailable")))
    assert cli.main(["--db", str(db_path), "stats"]) == 2
    captured = capsys.readouterr()
    assert "error: schema unavailable" in captured.err


def test_cli_analyze_returns_nonzero_when_parser_reports_failure(
    capsys: pytest.CaptureFixture[str], db_path: Path, tmp_path: Path
) -> None:
    source = tmp_path / "broken.docx"
    source.write_bytes(b"PK\\x03\\x04broken")

    code = cli.main([
        "--db", str(db_path), "analyze", str(source), "--format", "json"
    ])
    report = json.loads(capsys.readouterr().out)

    assert code == 1
    assert report["office_analysis"]["status"] == "failed"
    assert report["analysis_id"] is not None


def test_cli_show_analysis_returns_error_for_corrupt_stored_summary(
    capsys: pytest.CaptureFixture[str], db_path: Path, tmp_path: Path
) -> None:
    source = tmp_path / "corrupt-summary.rtf"
    source.write_bytes(b"{\\rtf1\\ansi corrupt summary fixture}")

    assert cli.main([
        "--db", str(db_path), "analyze", str(source), "--format", "json"
    ]) == 0
    original = json.loads(capsys.readouterr().out)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE analysis_runs SET summary_json = ? WHERE id = ?",
            ("{invalid json", original["analysis_id"]),
        )

    code = cli.main([
        "--db", str(db_path), "show-analysis",
        str(original["analysis_id"]), "--format", "json",
    ])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "error:" in captured.err


def test_cli_show_analysis_returns_error_for_corrupt_evidence_details(
    capsys: pytest.CaptureFixture[str], db_path: Path, tmp_path: Path
) -> None:
    source = tmp_path / "corrupt-evidence.rtf"
    source.write_bytes(b"{\\rtf1\\ansi corrupt evidence fixture}")

    assert cli.main([
        "--db", str(db_path), "analyze", str(source), "--format", "json"
    ]) == 0
    original = json.loads(capsys.readouterr().out)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO evidence (analysis_id, evidence_type, evidence_key, value_text, severity, details_json) VALUES (?, ?, ?, ?, ?, ?)",
            (original["analysis_id"], "fixture", "fixture", "{}", "info", "{invalid json"),
        )

    code = cli.main([
        "--db", str(db_path), "show-analysis",
        str(original["analysis_id"]), "--format", "json",
    ])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "error:" in captured.err


def test_cli_show_analysis_rebuilds_saved_report_from_database(
    capsys: pytest.CaptureFixture[str], db_path: Path, tmp_path: Path
) -> None:
    source = tmp_path / "roundtrip.rtf"
    source.write_bytes(b"{\\rtf1\\ansi report roundtrip fixture}")

    assert cli.main([
        "--db", str(db_path), "analyze", str(source), "--format", "json"
    ]) == 0
    original = json.loads(capsys.readouterr().out)
    analysis_id = original["analysis_id"]

    assert cli.main([
        "--db", str(db_path), "show-analysis", str(analysis_id), "--format", "json"
    ]) == 0
    rebuilt = json.loads(capsys.readouterr().out)

    assert rebuilt["analysis_id"] == analysis_id
    assert rebuilt["file"]["sha256"] == original["file"]["sha256"]
    assert rebuilt["file"]["filename"] == original["file"]["filename"]
    assert rebuilt["warnings"] == original["warnings"]
    assert rebuilt["evidence"] == original["evidence"]


def test_cli_analyze_output_write_failure_returns_error(
    capsys: pytest.CaptureFixture[str], db_path: Path, tmp_path: Path
) -> None:
    source = tmp_path / "output-failure.rtf"
    source.write_bytes(b"{\\rtf1\\ansi output failure fixture}")
    output_dir = tmp_path / "existing-output-directory"
    output_dir.mkdir()

    assert cli.main([
        "--db", str(db_path), "analyze", str(source),
        "--format", "json", "--output", str(output_dir),
    ]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


def test_cli_show_analysis_output_write_failure_returns_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_path: Path,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "get_analysis", lambda *_args, **_kwargs: {
        "analysis_id": 7, "file": {"filename": "sample.rtf"}, "evidence": [], "warnings": []
    })
    output_dir = tmp_path / "existing-output-directory"
    output_dir.mkdir()

    assert cli.main([
        "--db", str(db_path), "show-analysis", "7",
        "--format", "json", "--output", str(output_dir),
    ]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


def test_cli_show_analysis_renders_found_report_to_requested_format(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], db_path: Path
) -> None:
    monkeypatch.setattr(cli, "get_analysis", lambda *_args, **_kwargs: {
        "analysis_id": 7, "file": {"filename": "sample.docx"}, "evidence": [], "warnings": []
    })
    assert cli.main(["--db", str(db_path), "show-analysis", "7", "--format", "markdown"]) == 0
    assert "CVEvident Analysis Report" in capsys.readouterr().out
