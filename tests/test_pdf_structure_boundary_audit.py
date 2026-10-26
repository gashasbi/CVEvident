from __future__ import annotations

import io

import pypdf
import pytest
from pypdf import PdfWriter
from pypdf.generic import (
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

from cvevident import pdf_structure
from cvevident.pdf_structure import analyze_pdf_structure
from cvevident.pdf_triage import analyze_pdf


def install_fake_reader(monkeypatch, trailer, *, encrypted=False):
    class FakePdfReader:
        def __init__(
            self,
            stream,
            strict=False,
            root_object_recovery_limit=10_000,
        ):
            self.trailer = trailer
            self.is_encrypted = encrypted

    monkeypatch.setattr(pypdf, "PdfReader", FakePdfReader)


def analyze_fake_pdf(monkeypatch, trailer, *, encrypted=False):
    install_fake_reader(monkeypatch, trailer, encrypted=encrypted)
    return analyze_pdf_structure(b"%PDF-1.7\n", True)


def write_pdf(writer):
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def test_encrypted_pdf_is_reported_without_object_graph_inspection():
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt("test-user-password")

    result = analyze_pdf_structure(write_pdf(writer), True)

    assert result["status"] == "encrypted"
    assert result["encrypted"] is True
    assert result["findings"] == []
    assert any("without a password" in warning for warning in result["warnings"])


@pytest.mark.parametrize(
    "trailer",
    [
        DictionaryObject(),
        DictionaryObject({
            NameObject("/Root"): TextStringObject("not a catalog")
        }),
    ],
    ids=["missing-root", "non-dictionary-root"],
)
def test_missing_or_non_dictionary_catalog_fails_cautiously(
    monkeypatch, trailer
):
    result = analyze_fake_pdf(monkeypatch, trailer)

    assert result["status"] == "failed"
    assert result["findings"] == []
    assert any(
        "readable catalog dictionary" in warning
        for warning in result["warnings"]
    )


def test_unresolvable_root_reference_returns_failed_report(monkeypatch):
    trailer = DictionaryObject()
    trailer[NameObject("/Root")] = IndirectObject(77, 0, None)

    original_get_object = IndirectObject.get_object

    def fail_selected_reference(reference):
        if reference.idnum == 77:
            raise RuntimeError("synthetic unresolved catalog")
        return original_get_object(reference)

    monkeypatch.setattr(
        IndirectObject, "get_object", fail_selected_reference
    )

    result = analyze_fake_pdf(monkeypatch, trailer)

    assert result["status"] == "failed"
    assert result["findings"] == []
    assert any(
        "catalog could not be resolved (RuntimeError)" in warning
        for warning in result["warnings"]
    )


def test_out_of_range_declared_page_count_is_not_trusted(monkeypatch):
    pages = DictionaryObject()
    pages[NameObject("/Count")] = NumberObject(-1)

    root = DictionaryObject()
    root[NameObject("/Pages")] = pages

    trailer = DictionaryObject()
    trailer[NameObject("/Root")] = root

    result = analyze_fake_pdf(monkeypatch, trailer)

    assert result["page_count_declared"] is None
    assert any(
        "declared page count was outside the reporting range"
        in warning
        for warning in result["warnings"]
    )


def test_unreadable_declared_page_count_is_recorded_as_resolution_error(
    monkeypatch,
):
    pages = DictionaryObject()
    pages[NameObject("/Count")] = NameObject("/not-an-integer")

    root = DictionaryObject()
    root[NameObject("/Pages")] = pages

    trailer = DictionaryObject()
    trailer[NameObject("/Root")] = root

    result = analyze_fake_pdf(monkeypatch, trailer)

    assert result["status"] == "partial"
    assert result["resolution_errors"] >= 1
    assert "ValueError" in result["resolution_error_types"]
    assert any(
        "Some indirect objects could not be resolved" in warning
        for warning in result["warnings"]
    )


def test_unreadable_javascript_name_tree_is_reported_as_incomplete(
    monkeypatch,
):
    root = DictionaryObject()
    root[NameObject("/Names")] = IndirectObject(78, 0, None)

    trailer = DictionaryObject()
    trailer[NameObject("/Root")] = root

    original_get_object = IndirectObject.get_object

    def fail_selected_reference(reference):
        if reference.idnum == 78:
            raise RuntimeError("synthetic name-tree failure")
        return original_get_object(reference)

    monkeypatch.setattr(
        IndirectObject, "get_object", fail_selected_reference
    )

    result = analyze_fake_pdf(monkeypatch, trailer)

    assert result["status"] == "partial"
    assert result["resolution_errors"] >= 1
    assert "RuntimeError" in result["resolution_error_types"]
    assert any(
        "incomplete" in warning.lower()
        for warning in result["warnings"]
    )


def test_failed_pdf_traversal_discards_partial_structural_feature_evidence(
    monkeypatch, tmp_path
):
    from cvevident.pdf_triage import analyze_pdf

    class FailingDictionary(DictionaryObject):
        def items(self):
            raise RuntimeError("synthetic traversal failure")

    root = FailingDictionary()
    root[NameObject("/OpenAction")] = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript")
    })
    trailer = DictionaryObject()
    trailer[NameObject("/Root")] = root
    install_fake_reader(monkeypatch, trailer)

    path = tmp_path / "partial-failure.pdf"
    path.write_bytes(b"%PDF-1.7\\n")
    report = analyze_pdf(path)
    analysis = report["structural_analysis"]

    assert analysis["status"] == "failed"
    assert analysis["findings"] == []
    assert analysis["features"]["catalog_open_action_present"] is False
    assert analysis["features"]["open_action_entries"] == 0
    assert not any(
        item.get("key") == "pdf.structure.catalog_open_action_present"
        for item in report["evidence"]
    )


def test_structural_indicators_are_reported_without_executing_actions():
    writer = PdfWriter()
    page = writer.add_blank_page(width=72, height=72)
    root = writer._root_object

    root[NameObject("/AcroForm")] = writer._add_object(
        DictionaryObject()
    )
    root[NameObject("/OpenAction")] = writer._add_object(
        DictionaryObject({
            NameObject("/S"): NameObject("/JavaScript"),
            NameObject("/JS"): TextStringObject("synthetic-test-code"),
        })
    )
    root[NameObject("/AA")] = writer._add_object(DictionaryObject())

    names = DictionaryObject()
    names[NameObject("/JavaScript")] = writer._add_object(
        DictionaryObject()
    )
    root[NameObject("/Names")] = writer._add_object(names)

    additional_indicators = DictionaryObject()
    additional_indicators[NameObject("/EmbeddedFiles")] = writer._add_object(
        DictionaryObject()
    )
    additional_indicators[NameObject("/EF")] = writer._add_object(
        DictionaryObject()
    )
    additional_indicators[NameObject("/RichMediaContent")] = (
        writer._add_object(DictionaryObject())
    )
    root[NameObject("/SyntheticIndicators")] = writer._add_object(
        additional_indicators
    )

    annotation = DictionaryObject()
    annotation[NameObject("/Subtype")] = NameObject("/Link")
    annotation[NameObject("/S")] = NameObject("/FutureUnknownAction")
    page[NameObject("/Annots")] = writer._add_object(
        pypdf.generic.ArrayObject([writer._add_object(annotation)])
    )

    result = analyze_pdf_structure(write_pdf(writer), True)

    assert result["status"] == "parsed"
    features = result["features"]

    assert features["catalog_open_action_present"] is True
    assert features["catalog_additional_actions_present"] is True
    assert features["acroform_present"] is True
    assert features["javascript_name_tree_present"] is True
    assert features["open_action_entries"] >= 1
    assert features["additional_action_entries"] >= 1
    assert features["embedded_files_name_tree_count"] >= 1
    assert features["file_specifications_with_embedded_data"] >= 1
    assert features["rich_media_indicators"] >= 1
    assert features["annotations_total"] >= 1
    assert features["link_annotations"] >= 1
    assert features["unknown_action_count"] >= 1
    assert result["findings"]
    assert any(
        "no PDF JavaScript" in warning
        for warning in result["warnings"]
    )
    assert "synthetic-test-code" not in str(result["findings"])


def test_pdf_marker_count_does_not_materialize_all_matches(monkeypatch):
    from cvevident import pdf_triage

    data = b"/JavaScript " * 10000

    def reject_findall(*args, **kwargs):
        raise AssertionError("marker counting must not materialize every match")

    monkeypatch.setattr(pdf_triage.re, "findall", reject_findall)

    assert pdf_triage._count_pdf_name(data, b"/JavaScript") == 10000


def test_pdf_marker_offsets_limit_exact_and_over_limit():
    from cvevident.pdf_triage import _find_pdf_name_offsets

    marker = b"/JavaScript"
    data = b"/JavaScript /JavaScript"

    offsets, truncated = _find_pdf_name_offsets(data, marker, limit=2)
    assert offsets == [0, len(marker) + 1]
    assert truncated is False

    data += b" /JavaScript"
    offsets, truncated = _find_pdf_name_offsets(data, marker, limit=2)
    assert offsets == [0, len(marker) + 1]
    assert truncated is True


def test_pdf_header_offset_boundary_includes_last_allowed_start(tmp_path):
    last_allowed = tmp_path / "header-at-1023.pdf"
    last_allowed.write_bytes(b"x" * 1023 + b"%PDF-1.7\\n")

    report = analyze_pdf(last_allowed)

    assert report["metrics"]["pdf_header_found"] is True
    assert report["metrics"]["pdf_header_offset"] == 1023
    assert report["file"]["file_type"] == "pdf"

    beyond_limit = tmp_path / "header-at-1024.pdf"
    beyond_limit.write_bytes(b"x" * 1024 + b"%PDF-1.7\\n")

    report = analyze_pdf(beyond_limit)

    assert report["metrics"]["pdf_header_found"] is False
    assert report["metrics"]["pdf_header_offset"] is None
    assert report["structural_analysis"]["status"] == "skipped_not_pdf"


def test_non_integer_declared_pdf_page_count_is_not_trusted(monkeypatch):
    from pypdf.generic import FloatObject

    pages = DictionaryObject({
        NameObject("/Count"): FloatObject(2.5)
    })
    root = DictionaryObject({
        NameObject("/Pages"): pages
    })
    trailer = DictionaryObject({
        NameObject("/Root"): root
    })

    result = analyze_fake_pdf(monkeypatch, trailer)

    assert result["page_count_declared"] is None
    assert any(
        "declared page count" in warning.lower()
        and "not trusted" in warning.lower()
        for warning in result["warnings"]
    )
