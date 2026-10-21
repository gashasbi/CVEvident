"""Acceptance tests for batch-analysis failure isolation and traversal safety."""

import json
import os
from pathlib import Path

import pytest
from pypdf import PdfWriter

from cvevident.cli import main


def _make_pdf(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as stream:
        writer.write(stream)
    return path


def _run_batch(
    tmp_path: Path,
    inputs: list[Path],
    *,
    recursive: bool = False,
    max_files: int | None = None,
    reports_dir: Path | None = None,
    output: Path | None = None,
) -> tuple[int, dict]:
    db_path = tmp_path / "batch.sqlite3"
    reports_dir = reports_dir or tmp_path / "reports"
    output = output or tmp_path / "summary.json"

    argv = ["--db", str(db_path), "analyze-batch"]
    argv.extend(str(path) for path in inputs)
    if recursive:
        argv.append("--recursive")
    if max_files is not None:
        argv.extend(["--max-files", str(max_files)])
    argv.extend(["--reports-dir", str(reports_dir), "--output", str(output)])

    exit_code = main(argv)
    return exit_code, json.loads(output.read_text(encoding="utf-8"))


def test_nonrecursive_directory_scan_does_not_include_nested_files(tmp_path: Path) -> None:
    root = tmp_path / "input"
    top_level = _make_pdf(root / "top.pdf")
    _make_pdf(root / "nested" / "child.pdf")

    exit_code, summary = _run_batch(tmp_path, [root])

    assert exit_code == 0
    assert summary["status"] == "ok"
    assert [Path(item["path"]).resolve() for item in summary["results"]] == [
        top_level.resolve()
    ]
    assert summary["counts"]["files_analyzed"] == 1


def test_recursive_scan_is_deterministic_and_does_not_follow_symlink_cycle(
    tmp_path: Path,
) -> None:
    root = tmp_path / "input"
    top_level = _make_pdf(root / "top.pdf")
    nested = _make_pdf(root / "nested" / "child.pdf")

    cycle = root / "nested" / "back-to-root"
    try:
        cycle.symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    first_exit, first_summary = _run_batch(
        tmp_path,
        [root],
        recursive=True,
        reports_dir=tmp_path / "reports-first",
        output=tmp_path / "summary-first.json",
    )
    second_exit, second_summary = _run_batch(
        tmp_path,
        [root],
        recursive=True,
        reports_dir=tmp_path / "reports-second",
        output=tmp_path / "summary-second.json",
    )

    assert first_exit == second_exit == 0
    assert first_summary["status"] == second_summary["status"] == "ok"
    paths = [Path(item["path"]).resolve() for item in first_summary["results"]]
    repeated_paths = [
        Path(item["path"]).resolve() for item in second_summary["results"]
    ]
    assert paths == repeated_paths, "recursive traversal must be deterministic"
    assert set(paths) == {top_level.resolve(), nested.resolve()}
    assert len(paths) == 2, "the symlink cycle must not duplicate discovered files"
    assert first_summary["counts"]["files_analyzed"] == 2
    assert second_summary["counts"]["files_analyzed"] == 2


def test_same_basename_inputs_write_distinct_per_file_reports(tmp_path: Path) -> None:
    first = _make_pdf(tmp_path / "left" / "same.pdf")
    second = _make_pdf(tmp_path / "right" / "same.pdf")
    reports_dir = tmp_path / "reports"

    exit_code, summary = _run_batch(
        tmp_path,
        [first, second],
        reports_dir=reports_dir,
    )

    assert exit_code == 0
    assert summary["status"] == "ok"
    report_paths = [Path(item["report_path"]) for item in summary["results"]]
    assert len(report_paths) == 2
    assert len(set(report_paths)) == 2
    assert all(path.is_file() for path in report_paths)
    assert summary["counts"]["reports_written"] == 2


def test_report_write_failure_is_recorded_and_later_file_is_still_processed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _make_pdf(tmp_path / "input" / "first.pdf")
    second = _make_pdf(tmp_path / "input" / "second.pdf")
    reports_dir = tmp_path / "reports"
    output = tmp_path / "summary.json"
    original_write_text = Path.write_text

    def fail_first_report(self: Path, data: str, *args, **kwargs):
        if self.parent == reports_dir and self.name.startswith("0001-"):
            raise OSError("simulated report-write failure")
        return original_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_first_report)
    exit_code, summary = _run_batch(
        tmp_path,
        [first, second],
        reports_dir=reports_dir,
        output=output,
    )

    assert exit_code == 1
    assert summary["status"] == "partial"
    assert summary["counts"]["files_failed"] == 1
    assert summary["counts"]["reports_written"] == 1
    assert len(summary["results"]) == 2
    assert summary["results"][1]["status"] == "ok"
    assert (reports_dir / "0002-second.json").is_file()
    assert any(
        "report" in str(item).lower() or "write" in str(item).lower()
        for item in summary["results"]
        if item.get("status") == "error"
    )


def test_summary_output_write_failure_returns_cli_error(tmp_path: Path) -> None:
    pdf = _make_pdf(tmp_path / "input.pdf")
    output_directory = tmp_path / "summary-is-a-directory"
    output_directory.mkdir()

    exit_code = main(
        [
            "--db",
            str(tmp_path / "batch.sqlite3"),
            "analyze-batch",
            str(pdf),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--output",
            str(output_directory),
        ]
    )

    assert exit_code == 2


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is not supported here")
def test_special_file_input_is_rejected_without_blocking_later_files(
    tmp_path: Path,
) -> None:
    fifo = tmp_path / "input" / "not-a-regular-file.pdf"
    fifo.parent.mkdir(parents=True)
    os.mkfifo(fifo)
    valid_pdf = _make_pdf(tmp_path / "input" / "valid.pdf")

    exit_code, summary = _run_batch(tmp_path, [fifo, valid_pdf])

    assert exit_code == 1
    assert summary["status"] == "partial"
    assert summary["results"][0]["status"] == "error"
    assert summary["results"][1]["status"] == "ok"
    assert Path(summary["results"][1]["path"]).resolve() == valid_pdf.resolve()


def test_max_files_cap_selects_stable_prefix_of_sorted_directory_entries(
    tmp_path: Path,
) -> None:
    root = tmp_path / "input"
    alpha = _make_pdf(root / "alpha.pdf")
    _make_pdf(root / "beta.pdf")
    _make_pdf(root / "gamma.pdf")

    exit_code, summary = _run_batch(tmp_path, [root], recursive=True, max_files=2)

    assert exit_code == 1
    assert summary["status"] in {"partial", "failed"}
    paths = [Path(item["path"]).resolve() for item in summary["results"]]
    assert paths == [alpha.resolve(), (root / "beta.pdf").resolve()]
    assert summary["counts"]["files_analyzed"] == 2
    assert summary["counts"]["files_failed"] == 0
    assert summary["warnings"], "a capped batch must explain that inputs were omitted"
