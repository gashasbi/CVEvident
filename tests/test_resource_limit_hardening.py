"""Regression tests for end-to-end parser resource guardrails."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path

import pytest
import pypdf
from pypdf import PdfWriter

from cvevident import file_input, pdf_structure
from cvevident.file_input import read_file


def _pdf_bytes() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


def test_file_reader_rejects_descriptor_replaced_by_fifo_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-check the opened descriptor rather than trusting a prior stat()."""
    if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
        pytest.skip("FIFO race simulation requires POSIX non-blocking open support")

    target = tmp_path / "input.bin"
    target.write_bytes(b"initial regular file")
    fifo = tmp_path / "replacement.fifo"
    os.mkfifo(fifo)

    real_open = os.open
    opened_replacement = False

    def replace_at_open(path, flags, *args, **kwargs):
        nonlocal opened_replacement
        if Path(path) == target:
            opened_replacement = True
            return real_open(fifo, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_input.os, "open", replace_at_open)

    with pytest.raises(FileNotFoundError, match="non-regular file"):
        read_file(target, max_bytes=1024)
    assert opened_replacement


def test_pdf_parse_uses_bounded_configuration_and_restores_prior_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert callable(getattr(pypdf, "apply_configuration", None)), (
        "install the pypdf version required by pyproject.toml; resource configuration API is missing"
    )
    assert getattr(pypdf, "Configuration", None) is not None, (
        "install the pypdf version required by pyproject.toml; Configuration is missing"
    )
    original_apply = pypdf.apply_configuration
    initial_configuration = pypdf.get_configuration()
    applied: dict[str, object] = {}

    @contextlib.contextmanager
    def observe_configuration(**overrides):
        applied.update(overrides)
        with original_apply(**overrides) as configured:
            yield configured

    monkeypatch.setattr(pypdf, "apply_configuration", observe_configuration)
    result = pdf_structure.analyze_pdf_structure(_pdf_bytes(), is_pdf=True)

    assert result["status"] in {"parsed", "partial"}
    assert applied["maximum_declared_stream_length"] <= 16 * 1024 * 1024
    assert applied["zlib_maximum_output_length"] <= 16 * 1024 * 1024
    assert applied["lzw_maximum_output_length"] <= 16 * 1024 * 1024
    assert applied["jbig2_maximum_output_length"] <= 16 * 1024 * 1024
    assert applied["array_maximum_element_count"] <= 50_000
    assert applied["dictionary_maximum_element_count"] <= 50_000
    assert applied["stream_decoding_work_maximum_length"] <= 64 * 1024 * 1024
    assert applied["stream_parsing_work_maximum_count"] <= 500_000
    assert applied["jbig2dec_binary"] is None
    assert applied["disable_legacy_handling"] is True
    assert pypdf.get_configuration() == initial_configuration


def test_pdf_parser_fails_closed_if_configuration_api_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pypdf, "apply_configuration", None, raising=False)

    result = pdf_structure.analyze_pdf_structure(_pdf_bytes(), is_pdf=True)

    assert result["status"] == "failed"
    assert "required resource-limit configuration API" in " ".join(result["warnings"])


@pytest.mark.skipif(
    not callable(getattr(pypdf, "apply_configuration", None))
    or getattr(pypdf, "Configuration", None) is None,
    reason="test requires the resource-limit Configuration API",
)
def test_pdf_parser_fails_closed_if_limit_setup_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_configuration(**_overrides):
        raise RuntimeError("configuration setup failed")

    monkeypatch.setattr(pypdf, "apply_configuration", broken_configuration, raising=False)
    result = pdf_structure.analyze_pdf_structure(_pdf_bytes(), is_pdf=True)

    assert result["status"] == "failed"
    assert "could not be applied (RuntimeError)" in " ".join(result["warnings"])

@pytest.mark.skipif(
    not callable(getattr(pypdf, "apply_configuration", None))
    or getattr(pypdf, "Configuration", None) is None,
    reason="test requires the resource-limit Configuration API",
)
def test_pdf_parser_fails_closed_if_configuration_cleanup_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenCleanup:
        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, traceback):
            raise RuntimeError("configuration cleanup failed")

    monkeypatch.setattr(
        pypdf,
        "apply_configuration",
        lambda **_overrides: BrokenCleanup(),
    )

    result = pdf_structure.analyze_pdf_structure(_pdf_bytes(), is_pdf=True)

    assert result["status"] == "failed"
    assert "could not be restored (RuntimeError)" in " ".join(result["warnings"])
