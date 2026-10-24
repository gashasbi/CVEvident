from __future__ import annotations

import io
import re

from pypdf import PdfWriter

from cvevident.pdf_structure import analyze_pdf_structure


def _make_pdf(page_count: int) -> bytes:
    writer = PdfWriter()
    for _ in range(page_count):
        writer.add_blank_page(width=72, height=72)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _corrupt_last_startxref(data: bytes) -> bytes:
    matches = list(re.finditer(rb"startxref\s+(\d+)", data))
    assert matches, "fixture must include a startxref pointer"
    match = matches[-1]
    invalid_offset = str(len(data) + 2048).encode("ascii")
    return data[:match.start(1)] + invalid_offset + data[match.end(1):]


def test_recovered_bad_startxref_is_recorded_and_parse_is_partial() -> None:
    result = analyze_pdf_structure(
        _corrupt_last_startxref(_make_pdf(page_count=1)), is_pdf=True
    )

    assert result["status"] == "partial"
    assert result["parser_diagnostics_count"] >= 1
    assert result["parser_diagnostics"]
    assert any(
        "xref" in message.lower()
        for message in result["parser_diagnostics"]
    )
    assert any(
        "diagnostic(s)" in warning.lower()
        for warning in result["warnings"]
    )


def test_valid_zero_page_pdf_is_explained_without_being_failed() -> None:
    result = analyze_pdf_structure(_make_pdf(page_count=0), is_pdf=True)

    assert result["status"] == "parsed"
    assert result["page_count_declared"] == 0
    assert any(
        "declares zero pages" in warning.lower()
        for warning in result["warnings"]
    )
    assert result["parser_diagnostics_count"] == 0


def test_clean_pdf_has_no_recovery_diagnostics() -> None:
    result = analyze_pdf_structure(_make_pdf(page_count=1), is_pdf=True)

    assert result["status"] == "parsed"
    assert result["page_count_declared"] == 1
    assert result["parser_diagnostics_count"] == 0
    assert result["parser_diagnostics"] == []
