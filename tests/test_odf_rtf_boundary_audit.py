from __future__ import annotations

import io
import struct
import zipfile
import warnings
from pathlib import Path

import pytest

from cvevident.odf_triage import (
    ODF_MIME_TYPES,
    _is_external_target,
    analyze_opendocument,
    is_opendocument_package,
)
from cvevident.rtf_triage import _scan_rtf, analyze_rtf


ODF_MIME = "application/vnd.oasis.opendocument.text"
MANIFEST = (
    '<manifest:manifest '
    'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>'
)
CONTENT = (
    '<office:document-content '
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'
)


def _as_bytes(value):
    return value.encode("utf-8") if isinstance(value, str) else value


def build_odf(
    *,
    mimetype=ODF_MIME,
    content=CONTENT,
    manifest=MANIFEST,
    extra_members=(),
    duplicate_members=(),
    compress_mimetype=False,
    mimetype_first=True,
):
    """Construct a small ODF-like package for defensive parser tests."""
    mime_bytes = _as_bytes(mimetype)
    content_bytes = None if content is None else _as_bytes(content)
    manifest_bytes = None if manifest is None else _as_bytes(manifest)

    entries = []
    if mimetype_first:
        entries.append((
            "mimetype",
            mime_bytes,
            zipfile.ZIP_DEFLATED if compress_mimetype else zipfile.ZIP_STORED,
        ))
    if content_bytes is not None:
        entries.append(("content.xml", content_bytes, zipfile.ZIP_DEFLATED))
    if manifest_bytes is not None:
        entries.append(("META-INF/manifest.xml", manifest_bytes, zipfile.ZIP_DEFLATED))
    if not mimetype_first:
        entries.append(("mimetype", mime_bytes, zipfile.ZIP_STORED))

    entries.extend(
        (name, _as_bytes(value), zipfile.ZIP_DEFLATED)
        for name, value in extra_members
    )
    entries.extend(
        (name, _as_bytes(value), zipfile.ZIP_DEFLATED)
        for name, value in duplicate_members
    )

    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"Duplicate name: 'content[.]xml'",
            category=UserWarning,
        )
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, value, compression in entries:
                archive.writestr(name, value, compress_type=compression)
    return buffer.getvalue()


def analyze_odf(tmp_path, data, *, name="sample.odt", **kwargs):
    path = tmp_path / name
    path.write_bytes(data)
    return analyze_opendocument(str(path), **kwargs)


def _mark_zip_member_encrypted(data, member_name):
    """Set the encrypted flag in a test ZIP's local and central headers."""
    data = bytearray(data)
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0

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
    return bytes(data)


def _warnings(report):
    return "\n".join(
        [str(item) for item in report.get("warnings", [])]
        + [
            str(item)
            for item in report.get("odf_analysis", {}).get("warnings", [])
        ]
    )


class TestOdfTargetClassification:
    @pytest.mark.parametrize(
        "target",
        ["", "#fragment", "./relative.xml", "../relative.xml", "../"],
    )
    def test_relative_or_empty_targets_are_not_external(self, target):
        assert _is_external_target(target) is False

    @pytest.mark.parametrize(
        "target",
        [
            "https://example.invalid/document.xml",
            "mailto:test@example.invalid",
            "//example.invalid/document.xml",
            "file:///tmp/document.xml",
            "smb://server/share/document.xml",
        ],
    )
    def test_absolute_external_targets_are_detected(self, target):
        assert _is_external_target(target) is True

    def test_ordinary_package_relative_path_is_not_external(self):
        assert _is_external_target("Pictures/image.png") is False


class TestOdfMimetypeBoundaries:
    def test_signature_probe_rejects_mimetype_that_is_not_first(self):
        data = build_odf(mimetype_first=False)
        assert is_opendocument_package(data) is False

    def test_signature_probe_rejects_compressed_mimetype(self):
        data = build_odf(compress_mimetype=True)
        assert is_opendocument_package(data) is False

    def test_signature_probe_rejects_oversized_mimetype(self):
        data = build_odf(mimetype=b"A" * 257)
        assert is_opendocument_package(data) is False

    def test_signature_probe_rejects_non_ascii_mimetype(self):
        data = build_odf(mimetype=b"\xff\xfe")
        assert is_opendocument_package(data) is False

    def test_analysis_fails_for_mimetype_over_read_limit(self, tmp_path):
        report = analyze_odf(tmp_path, build_odf(mimetype=b"A" * 257))
        assert report["odf_analysis"]["status"] == "failed"
        assert "mimetype member exceeds" in _warnings(report)

    def test_analysis_fails_for_non_ascii_mimetype(self, tmp_path):
        report = analyze_odf(tmp_path, build_odf(mimetype=b"\xff"))
        assert report["odf_analysis"]["status"] == "failed"
        assert "mimetype member is invalid or unreadable" in _warnings(report)

    def test_unknown_mimetype_is_unsupported_not_misclassified(self, tmp_path):
        report = analyze_odf(
            tmp_path,
            build_odf(mimetype="application/example.unknown"),
        )
        assert report["odf_analysis"]["status"] == "unsupported"
        assert report["odf_analysis"]["mimetype"] == "application/example.unknown"
        assert "does not identify a supported OpenDocument" in _warnings(report)

    def test_each_public_mimetype_has_a_recognized_extension(self):
        supported_formats = {"odt", "ott", "ods", "ots", "odp", "otp"}
        assert ODF_MIME_TYPES
        for mime, (format_id, _family) in ODF_MIME_TYPES.items():
            assert mime.startswith("application/vnd.oasis.opendocument.")
            assert format_id in supported_formats


class TestOdfPackageBoundaryCases:
    @pytest.mark.parametrize(
        "option",
        [
            "max_archive_entries",
            "max_total_uncompressed_bytes",
            "max_xml_part_bytes",
            "max_total_xml_bytes",
            "max_xml_parts",
        ],
    )
    def test_rejects_nonpositive_resource_limits_before_file_read(self, tmp_path, option):
        with pytest.raises(ValueError, match="positive"):
            analyze_opendocument(
                str(tmp_path / "file-does-not-exist.odt"),
                **{option: 0},
            )

    def test_duplicate_content_member_is_skipped_and_reported(self, tmp_path):
        data = build_odf(
            duplicate_members=[("content.xml", CONTENT)],
        )
        report = analyze_odf(tmp_path, data)

        assert report["odf_analysis"]["status"] == "partial"
        assert "duplicate member name" in _warnings(report)
        assert "Required OpenDocument content.xml member is missing" in _warnings(report)

    def test_encrypted_content_member_is_not_parsed(self, tmp_path):
        data = _mark_zip_member_encrypted(
            build_odf(),
            "content.xml",
        )
        report = analyze_odf(tmp_path, data)

        assert report["odf_analysis"]["status"] == "partial"
        assert "encrypted member(s); encrypted content was not read" in _warnings(report)
        assert "Required OpenDocument content.xml member is missing" in _warnings(report)

    def test_missing_content_member_is_explicitly_partial(self, tmp_path):
        report = analyze_odf(tmp_path, build_odf(content=None))

        assert report["odf_analysis"]["status"] == "partial"
        assert "Required OpenDocument content.xml member is missing" in _warnings(report)

    def test_missing_manifest_is_explicitly_partial(self, tmp_path):
        report = analyze_odf(tmp_path, build_odf(manifest=None))

        assert report["odf_analysis"]["status"] == "partial"
        assert "META-INF/manifest.xml is missing" in _warnings(report)

    def test_signature_macro_and_database_members_are_counted(self, tmp_path):
        content = (
            '<office:document-content '
            'xmlns:office="urn:test:office" '
            'xmlns:draw="urn:test:draw" '
            'xmlns:table="urn:test:table">'
            "<draw:object/><table:dde-link/><table:database-range/>"
            "</office:document-content>"
        )
        data = build_odf(
            content=content,
            extra_members=[
                ("META-INF/documentsignatures.xml", "<signatures/>"),
                ("Basic/Standard/MacroModule.xml", b"static fixture"),
                ("database/database.xml", b"static fixture"),
            ],
        )
        report = analyze_odf(tmp_path, data)
        features = report["odf_analysis"]["features"]

        assert features["digital_signature_part_present"] == 1
        assert features["embedded_object_element_count"] >= 1
        assert features["dde_element_count"] >= 1
        assert features["database_related_element_count"] >= 1
        assert features["macro_named_member_count"] >= 1
        assert features["database_named_member_count"] >= 1


class TestRtfScannerBoundaryCases:
    def test_rejects_nonpositive_scan_limit_before_file_read(self, tmp_path):
        with pytest.raises(ValueError, match="positive"):
            analyze_rtf(
                str(tmp_path / "file-does-not-exist.rtf"),
                max_scan_bytes=0,
            )

    def test_terminal_backslash_does_not_raise(self):
        result = _scan_rtf(b"{\\rtf1\\")
        assert result["group_balance"] == 1
        assert result["negative_group_balance"] is False

    def test_escaped_braces_backslash_hex_and_control_symbols_in_field(self):
        data = (
            b'{\\rtf1{\\field{\\*\\fldinst HYPERLINK "'
            b"\\'68ttps://example.invalid/path"
            b"\\~with\\_escaped\\-symbols"
            b"\\{literal\\}\\\\tail"
            b'"}}}'
        )
        result = _scan_rtf(data)

        assert result["field_instructions_scanned_bytes"] > 0
        assert result["external_target_count"] >= 1
        assert result["field_instruction_examples"]

    def test_negative_control_word_parameter_does_not_corrupt_scan(self):
        result = _scan_rtf(b"{\\rtf1\\synthetic-23 text}")

        assert result["group_balance"] == 0
        assert result["negative_group_balance"] is False
        assert result["binary_payload_truncated"] is False

    def test_trailing_unclosed_group_is_reported_in_scan_result(self):
        result = _scan_rtf(b"{\\rtf1{\\ansi text}")

        assert result["group_balance"] == 1
        assert result["negative_group_balance"] is False

    def test_unmatched_closing_brace_is_reported(self):
        result = _scan_rtf(b"{\\rtf1 text}}")

        assert result["negative_group_balance"] is True
        assert result["group_balance"] is None
