from __future__ import annotations

import io
import json
import sys
import time

import pytest

from cvevident import cli
from cvevident.progress import progress


class TerminalStream(io.StringIO):
    def isatty(self) -> bool:
        return True


class PipeStream(io.StringIO):
    def isatty(self) -> bool:
        return False


def test_progress_renders_and_finishes_on_terminal() -> None:
    stream = TerminalStream()

    with progress("Synchronizing test source", stream):
        pass

    output = stream.getvalue()
    assert "Synchronizing test source [" in output
    assert "[done]" in output


def test_progress_reports_failure_and_reraises() -> None:
    stream = TerminalStream()

    with pytest.raises(RuntimeError, match="test failure"):
        with progress("Synchronizing test source", stream):
            raise RuntimeError("test failure")

    assert "[failed]" in stream.getvalue()


def test_progress_is_silent_for_non_terminal_output() -> None:
    stream = PipeStream()

    with progress("Synchronizing test source", stream):
        pass

    assert stream.getvalue() == ""


def test_cli_import_shows_progress_on_stderr_and_keeps_json_on_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = TerminalStream()
    standard_output = io.StringIO()
    monkeypatch.setattr(sys, "stderr", terminal)
    monkeypatch.setattr(sys, "stdout", standard_output)
    monkeypatch.setattr(cli, "init_db", lambda _path: ":memory:")

    def import_records(_path: str, _db_path: str) -> int:
        time.sleep(0.16)
        return 5

    monkeypatch.setattr(cli, "import_nvd_json", import_records)

    assert cli.main(["import-nvd", "records.json"]) == 0

    assert json.loads(standard_output.getvalue()) == {
        "source": "NVD",
        "records_imported": 5,
    }
    assert "Importing NVD records [" in terminal.getvalue()
    assert "[done]" in terminal.getvalue()


def test_progress_updates_percentage_without_creating_new_lines() -> None:
    stream = TerminalStream()

    with progress("Synchronizing test source", stream) as bar:
        bar.update(25, 100, "records downloaded")
        bar.update(50, 100, "records downloaded")
        bar.update(100, 100, "records imported")

    output = stream.getvalue()
    assert "25% 25/100" in output
    assert "50% 50/100" in output
    assert "100% 100/100" in output
    assert "\x1b[2K" in output
    assert output.count("\n") == 1


def test_cli_handles_keyboard_interrupt_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = TerminalStream()
    standard_output = io.StringIO()
    monkeypatch.setattr(sys, "stderr", terminal)
    monkeypatch.setattr(sys, "stdout", standard_output)
    monkeypatch.setattr(cli, "init_db", lambda _path: ":memory:")

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "sync_nvd_modified", interrupt)

    assert cli.main(["sync-nvd"]) == 130
    assert "operation cancelled" in terminal.getvalue()
    assert "[cancelled]" in terminal.getvalue()
    assert "Traceback" not in terminal.getvalue()
    assert standard_output.getvalue() == ""


def test_progress_line_stays_within_terminal_width(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    import cvevident.progress as progress_module

    monkeypatch.setattr(progress_module.shutil, "get_terminal_size", lambda _fallback: os.terminal_size((80, 24)))
    stream = TerminalStream()

    with progress("Synchronizing recently modified NVD records", stream) as bar:
        bar.update(2500, 10000, "downloaded")
        bar.update(7500, 10000, "saving")

    lines = [line.removeprefix("\x1b[2K") for line in stream.getvalue().split("\r") if line]
    assert all(len(line) <= 80 for line in lines)
