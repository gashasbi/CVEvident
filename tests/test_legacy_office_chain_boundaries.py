from __future__ import annotations

import struct

import pytest

from cvevident import legacy_office_triage as legacy


SECTOR_SIZE = 512


class TestReadSectorBoundaries:
    def test_reads_a_sector_after_the_compound_file_header(self):
        data = b"\x00" * SECTOR_SIZE + b"A" * SECTOR_SIZE

        assert legacy._read_sector(data, SECTOR_SIZE, 0, 1) == b"A" * SECTOR_SIZE

    @pytest.mark.parametrize("sector_id", [-1, 1, 100])
    def test_rejects_sector_ids_outside_declared_file(self, sector_id):
        data = b"\x00" * (2 * SECTOR_SIZE)

        with pytest.raises(ValueError, match="outside the file"):
            legacy._read_sector(data, SECTOR_SIZE, sector_id, 1)

    def test_rejects_sector_that_extends_past_end_of_input(self):
        # The declared sector count says sector zero exists, but only the
        # compound-file header is present in the byte buffer.
        with pytest.raises(ValueError, match="beyond end of file"):
            legacy._read_sector(b"\x00" * SECTOR_SIZE, SECTOR_SIZE, 0, 1)


class TestFollowChainBoundaries:
    @pytest.mark.parametrize(
        "first_sector",
        [legacy._ENDOFCHAIN, legacy._FREESECT],
    )
    def test_terminal_first_sector_returns_empty_chain(self, first_sector):
        result = legacy._follow_chain(
            first_sector,
            [],
            b"",
            SECTOR_SIZE,
            0,
            max_sectors=10,
            max_bytes=SECTOR_SIZE,
        )

        assert result == (b"", False, None)

    def test_rejects_first_sector_missing_from_fat_table(self):
        result = legacy._follow_chain(
            0,
            [],
            b"\x00" * (2 * SECTOR_SIZE),
            SECTOR_SIZE,
            1,
            max_sectors=10,
            max_bytes=SECTOR_SIZE,
        )

        content, partial, error = result
        assert content == b""
        assert partial is True
        assert "invalid or unavailable FAT entry" in error

    def test_rejects_first_sector_outside_declared_sector_count(self):
        result = legacy._follow_chain(
            1,
            [legacy._ENDOFCHAIN],
            b"\x00" * (2 * SECTOR_SIZE),
            SECTOR_SIZE,
            1,
            max_sectors=10,
            max_bytes=SECTOR_SIZE,
        )

        content, partial, error = result
        assert content == b""
        assert partial is True
        assert "invalid or unavailable FAT entry" in error

    def test_reports_truncated_sector_data_without_raising(self):
        result = legacy._follow_chain(
            0,
            [legacy._ENDOFCHAIN],
            b"\x00" * SECTOR_SIZE,
            SECTOR_SIZE,
            1,
            max_sectors=10,
            max_bytes=SECTOR_SIZE,
        )

        content, partial, error = result
        assert content == b""
        assert partial is True
        assert "beyond end of file" in error

    def test_zero_byte_budget_stops_before_retaining_sector_content(self):
        data = b"\x00" * SECTOR_SIZE + b"A" * SECTOR_SIZE

        content, partial, error = legacy._follow_chain(
            0,
            [legacy._ENDOFCHAIN],
            data,
            SECTOR_SIZE,
            1,
            max_sectors=10,
            max_bytes=0,
        )

        assert content == b""
        assert partial is True
        assert error == "sector-chain byte limit reached"

    def test_partial_sector_is_capped_to_remaining_byte_budget(self):
        data = b"\x00" * SECTOR_SIZE + b"A" * SECTOR_SIZE

        content, partial, error = legacy._follow_chain(
            0,
            [legacy._ENDOFCHAIN],
            data,
            SECTOR_SIZE,
            1,
            max_sectors=10,
            max_bytes=7,
        )

        assert content == b"A" * 7
        assert partial is True
        assert error == "sector-chain byte limit reached"

    def test_traversal_budget_stops_a_nonterminating_chain(self):
        data = b"\x00" * SECTOR_SIZE + b"B" * SECTOR_SIZE

        content, partial, error = legacy._follow_chain(
            0,
            [0],
            data,
            SECTOR_SIZE,
            1,
            max_sectors=1,
            max_bytes=SECTOR_SIZE,
        )

        assert content == b"B" * SECTOR_SIZE
        assert partial is True
        assert error == "sector-chain traversal limit reached"

    def test_successfully_follows_sector_then_end_of_chain(self):
        data = (
            b"\x00" * SECTOR_SIZE
            + b"A" * SECTOR_SIZE
            + b"B" * SECTOR_SIZE
        )

        content, partial, error = legacy._follow_chain(
            0,
            [1, legacy._ENDOFCHAIN],
            data,
            SECTOR_SIZE,
            2,
            max_sectors=10,
            max_bytes=2 * SECTOR_SIZE,
        )

        assert content == b"A" * SECTOR_SIZE + b"B" * SECTOR_SIZE
        assert partial is False
        assert error is None


def _directory_entry(*, name_length, entry_type=2, name_prefix=b""):
    raw = bytearray(128)
    raw[:min(len(name_prefix), 64)] = name_prefix[:64]
    struct.pack_into("<H", raw, 64, name_length)
    raw[66] = entry_type
    struct.pack_into("<I", raw, 116, legacy._ENDOFCHAIN)
    struct.pack_into("<Q", raw, 120, 0)
    return bytes(raw)


class TestDirectoryParsingBoundaries:
    def test_reports_directory_stream_with_partial_entry_bytes(self):
        entries, truncated, warnings = legacy._parse_directory(b"\x01")

        assert entries == []
        assert truncated is False
        assert any("not a multiple" in warning for warning in warnings)

    @pytest.mark.parametrize("name_length", [0, 1, 3, 66, 100])
    def test_replaces_invalid_utf16_name_lengths(self, name_length):
        raw = _directory_entry(name_length=name_length)

        entries, truncated, warnings = legacy._parse_directory(raw)

        assert len(entries) == 1
        assert truncated is False
        assert entries[0]["name"] == "<invalid-name-entry-0>"
        assert any("invalid UTF-16 name length" in warning for warning in warnings)

    def test_replaces_malformed_utf16_name_without_crashing(self):
        # An unpaired UTF-16 high surrogate is invalid under strict decoding.
        raw = _directory_entry(name_length=4, name_prefix=b"\x00\xd8\x00\x00")

        entries, truncated, warnings = legacy._parse_directory(raw)

        assert len(entries) == 1
        assert entries[0]["name"] == "<invalid-name-entry-0>"
        assert any("invalid UTF-16 name" in warning for warning in warnings)

    def test_ignores_unknown_directory_entry_types(self):
        raw = _directory_entry(name_length=4, entry_type=0, name_prefix=b"X\x00\x00\x00")

        entries, truncated, warnings = legacy._parse_directory(raw)

        assert entries == []
        assert truncated is False
        assert warnings == []

    def test_parses_valid_stream_entry_metadata(self):
        raw = bytearray(
            _directory_entry(name_length=4, name_prefix=b"X\x00\x00\x00")
        )
        struct.pack_into("<I", raw, 68, 2)
        struct.pack_into("<I", raw, 72, 3)
        struct.pack_into("<I", raw, 76, 4)
        struct.pack_into("<I", raw, 116, 7)
        struct.pack_into("<Q", raw, 120, 1234)

        entries, truncated, warnings = legacy._parse_directory(bytes(raw))

        assert truncated is False
        assert warnings == []
        assert entries == [{
            "index": 0,
            "name": "X",
            "type": "stream",
            "starting_sector": 7,
            "declared_size_bytes": 1234,
            "left_sibling_id": 2,
            "right_sibling_id": 3,
            "child_id": 4,
        }]
