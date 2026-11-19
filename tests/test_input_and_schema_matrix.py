"""Final edge acceptance for shared file reads, PDF lexical helpers, and schema guards."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from cvevident import cli, file_input, pdf_structure
from cvevident.db import connect, init_db
from cvevident.pdf_triage import _find_pdf_name_offsets, _window_entropy


def test_read_file_rejects_a_directory_as_non_regular_input(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="not a regular file"):
        file_input.read_file(tmp_path)


def test_read_file_wraps_stat_permission_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"data")
    original_stat = Path.stat

    def denied_stat(self, *args, **kwargs):
        if self == target:
            raise PermissionError("synthetic stat denial")
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied_stat)
    with pytest.raises(OSError, match="Could not read input file: synthetic stat denial"):
        file_input.read_file(target)


def test_read_file_wraps_open_permission_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"data")
    monkeypatch.setattr(file_input.os, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("synthetic open denial")))
    with pytest.raises(OSError, match="Could not read input file: synthetic open denial"):
        file_input.read_file(target)


def test_read_file_rejects_descriptor_that_changed_to_non_regular_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"data")
    with monkeypatch.context() as patcher:
        patcher.setattr(file_input.os, "open", lambda *_args, **_kwargs: 12345)
        patcher.setattr(file_input.os, "fstat", lambda _fd: SimpleNamespace(st_mode=stat.S_IFIFO))
        patcher.setattr(file_input.os, "close", lambda _fd: None)
        with pytest.raises(FileNotFoundError, match="changed to a non-regular file"):
            file_input.read_file(target)


def test_read_file_wraps_read_errors_after_open(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"data")

    class FailingHandle:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            raise PermissionError("synthetic read denial")

    with monkeypatch.context() as patcher:
        patcher.setattr(file_input.os, "open", lambda *_args, **_kwargs: 12345)
        patcher.setattr(file_input.os, "fstat", lambda _fd: SimpleNamespace(st_mode=stat.S_IFREG))
        patcher.setattr(file_input.os, "fdopen", lambda *_args, **_kwargs: FailingHandle())
        with pytest.raises(OSError, match="Could not read input file: synthetic read denial"):
            file_input.read_file(target)


def test_empty_entropy_window_and_bounded_lexical_offsets_are_explicit() -> None:
    assert _window_entropy(b"") == {"window_size": 4096, "window_count": 0, "mean": 0.0, "max": 0.0, "min": 0.0}
    offsets, truncated = _find_pdf_name_offsets(b"/JS /JavaScript /JS /JS", b"/JS", limit=1)
    assert offsets == [0]
    assert truncated is True


def test_pdf_reference_label_rejects_missing_and_unconvertible_identifiers() -> None:
    assert pdf_structure._reference_label(object()) is None
    assert pdf_structure._reference_label(SimpleNamespace(idnum="not-an-integer", generation=0)) is None
    assert pdf_structure._reference_label(SimpleNamespace(idnum=12, generation=3)) == "12 3 R"


def test_database_newer_schema_is_rejected_without_downgrade(tmp_path: Path) -> None:
    db_path = init_db(tmp_path / "future.sqlite3")
    with connect(db_path) as conn:
        conn.execute("UPDATE schema_meta SET value='999' WHERE key='schema_version'")
    with pytest.raises(RuntimeError, match="newer than this program supports"):
        init_db(db_path)
    with connect(db_path) as conn:
        assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == "999"



def test_doctor_reports_missing_schema_objects_without_repairing_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = init_db(tmp_path / "incomplete.sqlite3")
    with connect(db_path) as conn:
        conn.execute("DROP TABLE source_sync")
        conn.execute("ALTER TABLE analysis_runs DROP COLUMN target_product")
        conn.execute("DROP INDEX idx_analysis_sha256")

    exit_code = cli.main(["--db", str(db_path), "doctor"])

    assert exit_code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["healthy"] is False
    assert "source_sync" in result["missing_tables"]
    assert "target_product" in result["missing_columns"]["analysis_runs"]
    assert "idx_analysis_sha256" in result["missing_indexes"]

    with connect(db_path) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_sync'"
        ).fetchone()
    assert table is None


def test_doctor_does_not_create_a_missing_database(tmp_path: Path) -> None:
    missing_db = tmp_path / "missing.sqlite3"

    result = cli._doctor(str(missing_db))

    assert result["healthy"] is False
    assert result["database_exists"] is False
    assert result["integrity_check"] == "not_run"
    assert missing_db.exists() is False
