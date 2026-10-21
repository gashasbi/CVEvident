from __future__ import annotations

import io
import struct
import zipfile
from unittest import mock

import pytest

from cvevident.archive_limits import (
    MAX_XML_DEPTH,
    bounded_zip_data,
    ensure_zip_entry_limit,
    parse_xml_bounded,
)
from cvevident.office_triage import _parse_xml, analyze_office
from cvevident import odf_triage


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return target.getvalue()


def test_zip_entry_count_within_limit_is_accepted() -> None:
    data = _zip_bytes([("one.txt", b"1"), ("two.txt", b"2")])
    assert ensure_zip_entry_limit(data, max_entries=2) == 2


def test_bounded_zip_data_keeps_only_the_allowed_central_records() -> None:
    data = _zip_bytes([("one.txt", b"1"), ("two.txt", b"22"), ("three.txt", b"333")])
    bounded, original_count, declared_bytes, truncated = bounded_zip_data(data, max_entries=2)
    assert original_count == 3
    assert declared_bytes == 6
    assert truncated is True
    with zipfile.ZipFile(io.BytesIO(bounded), "r") as archive:
        assert archive.namelist() == ["one.txt", "two.txt"]


def test_zip_entry_limit_rejects_archive_before_zipfile_construction() -> None:
    data = _zip_bytes([("one.txt", b"1"), ("two.txt", b"2")])
    with mock.patch.object(zipfile, "ZipFile", side_effect=AssertionError("ZipFile must not be constructed")) as factory:
        with pytest.raises(ValueError, match="exceeds configured limit"):
            ensure_zip_entry_limit(data, max_entries=1)
        factory.assert_not_called()


def test_zip_preflight_detects_underreported_eocd_entry_count() -> None:
    data = bytearray(_zip_bytes([("one.txt", b"1"), ("two.txt", b"2")]))
    eocd_pos = data.rfind(b"PK\x05\x06")
    assert eocd_pos >= 0
    struct.pack_into("<H", data, eocd_pos + 8, 1)
    struct.pack_into("<H", data, eocd_pos + 10, 1)
    with pytest.raises(ValueError, match="member count exceeds configured limit"):
        ensure_zip_entry_limit(bytes(data), max_entries=1)


def test_zip_preflight_rejects_corrupt_central_directory() -> None:
    data = bytearray(_zip_bytes([("one.txt", b"1")]))
    eocd_pos = data.rfind(b"PK\x05\x06")
    directory_size = struct.unpack_from("<I", data, eocd_pos + 12)[0]
    directory_start = eocd_pos - directory_size
    data[directory_start:directory_start + 4] = b"BAD!"
    with pytest.raises(ValueError, match="central directory"):
        ensure_zip_entry_limit(bytes(data), max_entries=10)


def test_odf_probe_preflights_entry_budget_before_opening_archive(monkeypatch) -> None:
    data = _zip_bytes([
        ("mimetype", b"application/vnd.oasis.opendocument.text"),
        ("content.xml", b"<document-content />"),
    ])
    monkeypatch.setattr(odf_triage, "MAX_ARCHIVE_ENTRIES", 1)
    with mock.patch.object(zipfile, "ZipFile", side_effect=AssertionError("ZipFile must not be constructed")) as factory:
        assert odf_triage.is_opendocument_package(data) is False
        factory.assert_not_called()


def test_xml_parser_rejects_depth_above_default_limit() -> None:
    depth = MAX_XML_DEPTH + 1
    data = (b"<x>" * depth) + (b"</x>" * depth)
    with pytest.raises(ValueError, match="nesting depth exceeds"):
        _parse_xml(data)


def test_xml_parser_rejects_element_count_over_explicit_budget() -> None:
    data = b"<root>" + (b"<item/>" * 8) + b"</root>"
    with pytest.raises(ValueError, match="element count exceeds"):
        parse_xml_bounded(data, max_elements=5, max_depth=8)


def test_xml_parser_accepts_document_at_configured_boundaries() -> None:
    root = parse_xml_bounded(
        b"<root><item/><item/></root>", max_elements=3, max_depth=2
    )
    assert root.tag == "root"
    assert len(root) == 2


def test_existing_dtd_entity_guard_remains_active() -> None:
    with pytest.raises(ValueError, match="DTD/entity"):
        _parse_xml(b"<!DOCTYPE root [<!ENTITY x 'y'>]><root>&x;</root>")

def test_dtd_entity_guard_detects_utf16_markup_before_parsing() -> None:
    payload = '<!DOCTYPE root [<!ENTITY x "value">]><root>&x;</root>'.encode("utf-16")
    with pytest.raises(ValueError, match="DTD/entity"):
        _parse_xml(payload)


def test_ooxml_analysis_opens_only_bounded_central_directory(tmp_path) -> None:
    path = tmp_path / "too-many.docx"
    path.write_bytes(_zip_bytes([("one.txt", b"1"), ("two.txt", b"2")]))
    real_zipfile = zipfile.ZipFile
    opened_entry_counts: list[int] = []

    def tracked_zipfile(*args, **kwargs):
        archive = real_zipfile(*args, **kwargs)
        opened_entry_counts.append(len(archive.infolist()))
        return archive

    with mock.patch.object(zipfile, "ZipFile", side_effect=tracked_zipfile):
        analyze_office(str(path), max_archive_entries=1)
    assert opened_entry_counts == [1]


def test_odf_analysis_opens_only_bounded_central_directory(tmp_path) -> None:
    path = tmp_path / "too-many.odt"
    path.write_bytes(_zip_bytes([
        ("mimetype", b"application/vnd.oasis.opendocument.text"),
        ("content.xml", b"<document-content />"),
    ]))
    real_zipfile = zipfile.ZipFile
    opened_entry_counts: list[int] = []

    def tracked_zipfile(*args, **kwargs):
        archive = real_zipfile(*args, **kwargs)
        opened_entry_counts.append(len(archive.infolist()))
        return archive

    with mock.patch.object(zipfile, "ZipFile", side_effect=tracked_zipfile):
        odf_triage.analyze_opendocument(str(path), max_archive_entries=1)
    assert opened_entry_counts == [1]
