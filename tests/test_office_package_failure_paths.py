from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

import pytest

from cvevident.office_triage import MAIN_CONTENT_TYPES, analyze_office


CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
RELATIONSHIPS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_DOCUMENT_REL_TYPE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/"
    "relationships/officeDocument"
)


def _main_content_type(fmt: str) -> str:
    return next(
        content_type
        for content_type, metadata in MAIN_CONTENT_TYPES.items()
        if metadata[0] == fmt
    )


def _types_xml(overrides):
    entries = [
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    ]
    for part, content_type in overrides:
        entries.append(
            f"<Override PartName={quoteattr('/' + part)} "
            f"ContentType={quoteattr(content_type)}/>"
        )
    return (
        f'<Types xmlns="{CONTENT_TYPES_NS}">'
        + "".join(entries)
        + "</Types>"
    ).encode()


def _relationships_xml(relationships):
    entries = []
    for index, (target, mode) in enumerate(relationships, start=1):
        mode_attr = (
            f" TargetMode={quoteattr(mode)}" if mode is not None else ""
        )
        entries.append(
            f"<Relationship Id={quoteattr('rId' + str(index))} "
            f"Type={quoteattr(OFFICE_DOCUMENT_REL_TYPE)} "
            f"Target={quoteattr(target)}{mode_attr}/>"
        )
    return (
        f'<Relationships xmlns="{RELATIONSHIPS_NS}">'
        + "".join(entries)
        + "</Relationships>"
    ).encode()


def _minimal_part(part):
    if part.startswith("word/"):
        return b'<w:document xmlns:w="urn:test"><w:body/></w:document>'
    if part.startswith("xl/"):
        return b'<workbook xmlns="urn:test"/>'
    if part.startswith("ppt/"):
        return b'<p:presentation xmlns:p="urn:test"/>'
    return b"<root/>"


def _write_package(
    path: Path,
    *,
    overrides=None,
    relationships=None,
    content_types_raw=None,
    root_relationships_raw=None,
    include_root_relationships=True,
    omit_parts=(),
    directories=(),
    extra_parts=None,
):
    if overrides is None:
        overrides = [
            ("word/document.xml", _main_content_type("docx")),
        ]

    if relationships is None:
        relationships = [("word/document.xml", None)]

    parts = {
        "[Content_Types].xml": (
            content_types_raw
            if content_types_raw is not None
            else _types_xml(overrides)
        ),
    }

    if include_root_relationships:
        parts["_rels/.rels"] = (
            root_relationships_raw
            if root_relationships_raw is not None
            else _relationships_xml(relationships)
        )

    for part, _content_type in overrides:
        if part not in set(omit_parts):
            parts[part] = _minimal_part(part)

    parts.update(extra_parts or {})
    path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(
        path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for directory in directories:
            directory_name = directory.rstrip("/") + "/"
            archive.writestr(directory_name, b"")
        for name, content in parts.items():
            archive.writestr(name, content)

    return path


def _warnings(report):
    values = list(report.get("warnings", []))
    values.extend(report.get("office_analysis", {}).get("warnings", []))
    return "\n".join(str(value) for value in values)


def _set_member_encrypted_flag(path: Path, member_name: str):
    """Mark a ZIP member encrypted in both local and central headers."""
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0, "Fixture ZIP must have an EOCD record"

    cursor = struct.unpack_from("<I", data, eocd + 16)[0]
    found = False

    while cursor + 46 <= eocd:
        if data[cursor:cursor + 4] != b"PK\x01\x02":
            break

        name_len, extra_len, comment_len = struct.unpack_from(
            "<HHH", data, cursor + 28
        )
        name_start = cursor + 46
        name = bytes(data[name_start:name_start + name_len]).decode("utf-8")

        if name == member_name:
            flags = struct.unpack_from("<H", data, cursor + 8)[0]
            struct.pack_into("<H", data, cursor + 8, flags | 1)

            local_offset = struct.unpack_from("<I", data, cursor + 42)[0]
            assert data[local_offset:local_offset + 4] == b"PK\x03\x04"
            local_flags = struct.unpack_from("<H", data, local_offset + 6)[0]
            struct.pack_into("<H", data, local_offset + 6, local_flags | 1)
            found = True
            break

        cursor += 46 + name_len + extra_len + comment_len

    assert found, f"ZIP member not found: {member_name}"
    path.write_bytes(data)


class TestOfficePackageFailurePaths:
    def test_malformed_content_types_manifest_fails_closed(self, tmp_path):
        path = _write_package(
            tmp_path / "broken-manifest.docx",
            content_types_raw=b"<Types",
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "failed"
        assert report["office_analysis"]["truncated"] is True
        assert "content-type manifest could not be parsed safely" in _warnings(report)

    def test_missing_root_relationships_does_not_identify_a_document(self, tmp_path):
        path = _write_package(
            tmp_path / "missing-root-rels.docx",
            include_root_relationships=False,
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "unsupported"
        assert "lacks the root relationships part" in _warnings(report)

    def test_malformed_root_relationships_fail_closed(self, tmp_path):
        path = _write_package(
            tmp_path / "broken-root-rels.docx",
            root_relationships_raw=b"<Relationships",
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "failed"
        assert report["office_analysis"]["truncated"] is True
        assert "root relationships could not be parsed safely" in _warnings(report)

    def test_external_root_relationship_is_never_fetched(self, tmp_path):
        path = _write_package(
            tmp_path / "external-root-target.docx",
            relationships=[("https://example.invalid/document.xml", "External")],
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "unsupported"
        assert report["office_analysis"]["truncated"] is True
        assert "external targets are never fetched" in _warnings(report)

    def test_traversal_root_relationship_is_not_followed(self, tmp_path):
        path = _write_package(
            tmp_path / "unsafe-root-target.docx",
            relationships=[("../word/document.xml", None)],
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "unsupported"
        assert report["office_analysis"]["truncated"] is True
        assert "unsafe or unsupported target path" in _warnings(report)

    def test_unknown_main_part_content_type_is_not_assumed_to_be_office(self, tmp_path):
        path = _write_package(
            tmp_path / "unknown-main-type.docx",
            overrides=[("custom/main.xml", "application/example")],
            relationships=[("custom/main.xml", None)],
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "unsupported"
        assert "no supported Office main-part content type" in _warnings(report)
        assert "did not identify a supported Word, Excel, or PowerPoint" in _warnings(report)

    def test_conflicting_main_relationships_are_reported_as_partial(self, tmp_path):
        path = _write_package(
            tmp_path / "conflicting-main-parts.docx",
            overrides=[
                ("word/document.xml", _main_content_type("docx")),
                ("xl/workbook.xml", _main_content_type("xlsx")),
            ],
            relationships=[
                ("word/document.xml", None),
                ("xl/workbook.xml", None),
            ],
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "partial"
        assert report["office_analysis"]["format_id"] == "docx"
        assert "multiple conflicting Office main parts" in _warnings(report)

    def test_explicit_directory_member_is_ignored_for_opc_name_collisions(self, tmp_path):
        path = _write_package(
            tmp_path / "directory-entry.docx",
            directories=["word"],
        )

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] in {"parsed", "partial"}
        assert "duplicate member name" not in _warnings(report)
        assert "case-insensitive member-name collision" not in _warnings(report)

    def test_encrypted_main_member_is_not_read_as_plain_xml(self, tmp_path):
        path = _write_package(tmp_path / "encrypted-member.docx")
        _set_member_encrypted_flag(path, "word/document.xml")

        report = analyze_office(str(path))

        assert report["office_analysis"]["status"] == "partial"
        assert "encrypted member(s); encrypted content was not read" in _warnings(report)

    def test_xml_part_count_limit_is_enforced_before_reading_main_part(self, tmp_path):
        path = _write_package(tmp_path / "xml-part-budget.docx")

        report = analyze_office(str(path), max_xml_parts=2)

        assert report["office_analysis"]["status"] == "partial"
        assert "XML part count exceeds the limit (2)" in _warnings(report)
