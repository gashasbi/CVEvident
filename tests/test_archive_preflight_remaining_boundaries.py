from __future__ import annotations

import io
import struct
import zipfile
from unittest.mock import patch

import pytest

from cvevident import archive_limits
from cvevident.archive_limits import (
    _find_eocd,
    _scan_central_directory,
    bounded_zip_data,
    ensure_zip_entry_limit,
)


EOCD = b"PK\x05\x06"
CENTRAL = b"PK\x01\x02"


def make_zip(*members, comment=b""):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)
        archive.comment = comment
    return buffer.getvalue()


def locate_eocd(data):
    pos = data.rfind(EOCD)
    assert pos >= 0
    return pos


def central_directory_start(data):
    pos = locate_eocd(data)
    size = struct.unpack_from("<I", data, pos + 12)[0]
    start = pos - size
    assert data[start:start + 4] == CENTRAL
    return start


class TestEocdSearchBoundaries:
    def test_skips_false_eocd_signature_inside_archive_comment(self):
        # The fake signature advertises a comment longer than the remaining
        # bytes, so the scanner must continue searching backwards.
        fake_signature = EOCD + b"\x00" * 16 + b"\xff\xff" + b"tail"
        data = make_zip(
            ("sample.txt", b"sample"),
            comment=fake_signature,
        )

        actual_eocd = len(data) - len(fake_signature) - 22
        assert _find_eocd(data) == actual_eocd

    def test_rejects_data_without_any_eocd_signature(self):
        assert _find_eocd(b"not a ZIP archive") == -1


class TestCentralDirectoryCorruptionBoundaries:
    def test_rejects_multidisk_eocd(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        pos = locate_eocd(data)
        struct.pack_into("<H", data, pos + 4, 1)

        with pytest.raises(ValueError, match="multi-disk or inconsistent ZIP"):
            _scan_central_directory(bytes(data), max_entries=10)

    def test_rejects_directory_size_outside_archive_bounds(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        pos = locate_eocd(data)
        # Avoid the ZIP64 sentinel so the ordinary bounds check is reached.
        struct.pack_into("<I", data, pos + 12, 0xFFFFFFFE)

        with pytest.raises(ValueError, match="central-directory bounds"):
            _scan_central_directory(bytes(data), max_entries=10)

    def test_rejects_directory_offset_after_physical_start(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        pos = locate_eocd(data)
        # Keep this distinct from the ZIP64 sentinel.
        struct.pack_into("<I", data, pos + 16, 0xFFFFFFFE)

        with pytest.raises(ValueError, match="central-directory offset"):
            _scan_central_directory(bytes(data), max_entries=10)

    def test_rejects_member_record_that_exceeds_directory_end(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        start = central_directory_start(data)

        # Central-directory filename length is at offset 28 in its record.
        struct.pack_into("<H", data, start + 28, 0xFFFF)

        with pytest.raises(ValueError, match="member extends beyond"):
            _scan_central_directory(bytes(data), max_entries=10)

    def test_rejects_trailing_bytes_inside_declared_directory(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        pos = locate_eocd(data)
        original_size = struct.unpack_from("<I", data, pos + 12)[0]

        # Insert one unexpected byte between the central directory and EOCD,
        # then update the declared size so the directory bounds include it.
        data[pos:pos] = bytes([0])
        pos = locate_eocd(data)
        struct.pack_into("<I", data, pos + 12, original_size + 1)

        with pytest.raises(ValueError, match="malformed member record"):
            _scan_central_directory(bytes(data), max_entries=10)

class TestZip64CentralDirectoryBoundaries:
    def test_reads_uncompressed_size_from_zip64_extra_field(self):
        data = bytearray(make_zip(("a.txt", b"abc")))
        start = central_directory_start(data)
        pos = locate_eocd(data)
        original_directory_size = struct.unpack_from("<I", data, pos + 12)[0]

        name_length = struct.unpack_from("<H", data, start + 28)[0]
        extra_length = struct.unpack_from("<H", data, start + 30)[0]
        extra_position = start + 46 + name_length + extra_length

        expected_size = 987654
        zip64_extra = struct.pack("<HHQ", 0x0001, 8, expected_size)

        # Add one ZIP64 field to the central record and update its metadata.
        data[extra_position:extra_position] = zip64_extra
        struct.pack_into("<I", data, start + 24, 0xFFFFFFFF)
        struct.pack_into("<H", data, start + 30, extra_length + len(zip64_extra))

        pos = locate_eocd(data)
        struct.pack_into(
            "<I", data, pos + 12, original_directory_size + len(zip64_extra)
        )

        result = _scan_central_directory(bytes(data), max_entries=10)
        assert result["actual_entries"] == 1
        assert result["total_uncompressed_bytes"] == expected_size

    def test_ensure_entry_limit_rejects_eocd_count_mismatch(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        pos = locate_eocd(data)
        struct.pack_into("<H", data, pos + 8, 0)
        struct.pack_into("<H", data, pos + 10, 0)

        with pytest.raises(ValueError, match="declared member count"):
            ensure_zip_entry_limit(bytes(data), max_entries=10)

    def test_bounded_archive_rejects_eocd_count_mismatch(self):
        data = bytearray(make_zip(("a.txt", b"a")))
        pos = locate_eocd(data)
        struct.pack_into("<H", data, pos + 8, 0)
        struct.pack_into("<H", data, pos + 10, 0)

        with pytest.raises(ValueError, match="declared member count"):
            bounded_zip_data(bytes(data), max_entries=10)

    def test_rejects_unsupported_zip64_output_entry_limit(self):
        fake_scan = {
            "actual_entries": 65536,
            "declared_entries": 65536,
            "total_uncompressed_bytes": 0,
            "directory_start": 0,
            "first_limit_end": 0,
            "directory_offset": 0,
        }

        with patch.object(
            archive_limits, "_scan_central_directory", return_value=fake_scan
        ):
            with pytest.raises(ValueError, match="above 65534"):
                bounded_zip_data(b"", max_entries=65535)

    def test_rejects_truncation_that_would_require_zip64_output(self):
        directory_start = 1 << 32
        fake_scan = {
            "actual_entries": 2,
            "declared_entries": 2,
            "total_uncompressed_bytes": 0,
            "directory_start": directory_start,
            "first_limit_end": directory_start + 100,
            "directory_offset": directory_start,
        }

        with patch.object(
            archive_limits, "_scan_central_directory", return_value=fake_scan
        ):
            with pytest.raises(ValueError, match="requires unsupported ZIP64 output"):
                bounded_zip_data(b"", max_entries=1)
