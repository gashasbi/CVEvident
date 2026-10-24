import io
import struct
import zipfile

import pytest

from cvevident.archive_limits import (
    _scan_central_directory,
    _zip64_uncompressed_size,
    parse_xml_bounded,
)
from cvevident.office_triage import (
    _is_unsafe_member_name,
    _relationship_source,
    _resolve_package_relationship_target,
)


_ZIP64_EOCD = 0x06064B50
_ZIP64_LOCATOR = 0x07064B50
_EOCD = 0x06054B50


def make_empty_zip64(
    *,
    locator_disk=0,
    total_disks=1,
    record_signature=_ZIP64_EOCD,
    record_size=44,
    entries_on_disk=0,
    entries_total=0,
    disk_number=0,
    directory_disk=0,
):
    """Construct a minimal ZIP64 archive with no central-directory entries."""
    record = struct.pack(
        "<IQHHIIQQQQ",
        record_signature,
        record_size,
        45,
        45,
        disk_number,
        directory_disk,
        entries_on_disk,
        entries_total,
        0,  # Central-directory size.
        0,  # Central-directory offset.
    )
    locator = struct.pack(
        "<IIQI",
        _ZIP64_LOCATOR,
        locator_disk,
        0,  # ZIP64 EOCD offset.
        total_disks,
    )
    ordinary_eocd = struct.pack(
        "<IHHHHIIH",
        _EOCD,
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return bytearray(record + locator + ordinary_eocd)


def make_zip(*entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


class TestZip64ExtraField:
    def test_reads_zip64_size_after_unknown_extra_field(self):
        extra = (
            struct.pack("<HHI", 0xCAFE, 4, 1234)
            + struct.pack("<HHQ", 0x0001, 8, 987654)
        )
        assert _zip64_uncompressed_size(extra) == 987654

    def test_rejects_missing_zip64_size(self):
        extra = struct.pack("<HHI", 0xCAFE, 4, 1234)
        with pytest.raises(ValueError, match="missing"):
            _zip64_uncompressed_size(extra)

    def test_rejects_truncated_extra_field_header_without_crashing(self):
        with pytest.raises(ValueError, match="missing"):
            _zip64_uncompressed_size(b"\x01\x00\x08")

    def test_rejects_extra_field_length_past_buffer_end(self):
        extra = struct.pack("<HH", 0xCAFE, 16) + b"\x00\x01"
        with pytest.raises(ValueError, match="malformed"):
            _zip64_uncompressed_size(extra)

    def test_rejects_zip64_field_without_complete_uncompressed_size(self):
        extra = struct.pack("<HHI", 0x0001, 4, 1234)
        with pytest.raises(ValueError, match="omits"):
            _zip64_uncompressed_size(extra)


class TestZipCentralDirectoryBoundary:
    def test_rejects_nonpositive_member_limit_before_scanning(self):
        with pytest.raises(ValueError, match="positive"):
            _scan_central_directory(b"", max_entries=0)

    def test_rejects_input_without_end_of_central_directory(self):
        with pytest.raises(ValueError):
            _scan_central_directory(b"not a ZIP archive", max_entries=10)

    def test_accepts_a_well_formed_empty_zip64_archive(self):
        result = _scan_central_directory(
            bytes(make_empty_zip64()),
            max_entries=10,
        )
        assert result["actual_entries"] == 0
        assert result["declared_entries"] == 0
        assert result["total_uncompressed_bytes"] == 0

    @pytest.mark.parametrize(
        "mutation",
        [
            "bad_locator_signature",
            "multidisk_locator",
            "bad_zip64_signature",
            "undersized_zip64_record",
            "inconsistent_entry_counts",
            "multidisk_record",
        ],
    )
    def test_rejects_malformed_or_multidisk_zip64(self, mutation):
        kwargs = {}
        if mutation == "multidisk_locator":
            kwargs["locator_disk"] = 1
        elif mutation == "undersized_zip64_record":
            kwargs["record_size"] = 43
        elif mutation == "inconsistent_entry_counts":
            kwargs["entries_on_disk"] = 1
            kwargs["entries_total"] = 0
        elif mutation == "multidisk_record":
            kwargs["disk_number"] = 1

        data = make_empty_zip64(**kwargs)

        if mutation == "bad_locator_signature":
            data[56:60] = b"NOPE"
        elif mutation == "bad_zip64_signature":
            data[0:4] = b"NOPE"

        with pytest.raises(ValueError):
            _scan_central_directory(bytes(data), max_entries=10)

    def test_rejects_central_directory_offset_outside_archive(self):
        data = bytearray(make_zip(("sample.txt", "content")))
        eocd_pos = data.rfind(struct.pack("<I", _EOCD))
        assert eocd_pos >= 0

        # EOCD central-directory offset field.
        struct.pack_into("<I", data, eocd_pos + 16, 0xFFFFFFFF)

        with pytest.raises(ValueError):
            _scan_central_directory(bytes(data), max_entries=10)


class TestBoundedXmlParserBoundary:
    def test_rejects_nonpositive_element_limit(self):
        with pytest.raises(ValueError, match="positive"):
            parse_xml_bounded(b"<root/>", max_elements=0, max_depth=5)

    def test_rejects_nonpositive_depth_limit(self):
        with pytest.raises(ValueError, match="positive"):
            parse_xml_bounded(b"<root/>", max_elements=5, max_depth=0)

    def test_accepts_document_exactly_at_element_and_depth_limits(self):
        root = parse_xml_bounded(
            b"<root><child/></root>",
            max_elements=2,
            max_depth=2,
        )
        assert root.tag == "root"
        assert root[0].tag == "child"

    def test_rejects_document_over_element_limit(self):
        with pytest.raises(ValueError):
            parse_xml_bounded(
                b"<root><a/><b/></root>",
                max_elements=2,
                max_depth=10,
            )

    def test_rejects_document_over_nesting_limit(self):
        with pytest.raises(ValueError):
            parse_xml_bounded(
                b"<root><a><b/></a></root>",
                max_elements=10,
                max_depth=2,
            )


class TestOfficePackagePathBoundary:
    @pytest.mark.parametrize(
        "name",
        [
            "../outside.xml",
            "word/../outside.xml",
            "/absolute/document.xml",
            "C:\\outside\\document.xml",
            "C:/outside/document.xml",
        ],
    )
    def test_rejects_unsafe_package_member_names(self, name):
        assert _is_unsafe_member_name(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "word/document.xml",
            "xl/workbook.xml",
            "ppt/slides/slide1.xml",
        ],
    )
    def test_accepts_normal_relative_package_member_names(self, name):
        assert _is_unsafe_member_name(name) is False

    def test_maps_relationship_part_to_its_source_part(self):
        assert (
            _relationship_source("word/_rels/document.xml.rels")
            == "word/document.xml"
        )

    def test_relationship_source_without_rels_directory_is_bounded_fallback(self):
        value = _relationship_source("word/document.xml.rels")
        assert isinstance(value, str)
        assert value == "word/document.xml.rels"

    @pytest.mark.parametrize(
        "target",
        [
            "https://example.invalid/document.xml",
            "//example.invalid/document.xml",
            "word/document.xml?query=1",
            "word/document.xml#fragment",
            "",
            "word\\document.xml",
            "word//document.xml",
            "word/./document.xml",
            "word/../document.xml",
            "word/%00document.xml",
        ],
    )
    def test_rejects_unsafe_relationship_targets(self, target):
        assert _resolve_package_relationship_target(target) is None

    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("word/document.xml", "word/document.xml"),
            ("/word/document.xml", "word/document.xml"),
            ("xl/worksheets/sheet1.xml", "xl/worksheets/sheet1.xml"),
        ],
    )
    def test_resolves_normal_relative_relationship_targets(self, target, expected):
        assert _resolve_package_relationship_target(target) == expected
