import pytest

from cvevident import legacy_office_triage as legacy


SECTOR_SIZE = 512
EOC = legacy._ENDOFCHAIN
FREE = legacy._FREESECT


def test_declared_stream_size_trims_sector_padding():
    data = b"\x00" * SECTOR_SIZE + b"HELLO" + b"\x00" * (SECTOR_SIZE - 5)

    content, partial, error = legacy._read_declared_stream(
        0, 5, [EOC], data, SECTOR_SIZE, 1,
        max_sectors=10, max_bytes=1024,
    )

    assert content == b"HELLO"
    assert partial is False
    assert error is None


def test_declared_stream_rejects_size_above_byte_budget():
    content, partial, error = legacy._read_declared_stream(
        0, 513, [EOC], b"\x00" * 1024, SECTOR_SIZE, 1,
        max_sectors=10, max_bytes=512,
    )

    assert content == b""
    assert partial is True
    assert "byte limit" in error


def test_declared_stream_reports_chain_shorter_than_declared_size():
    data = b"\x00" * SECTOR_SIZE + b"A" * SECTOR_SIZE

    content, partial, error = legacy._read_declared_stream(
        0, 700, [EOC], data, SECTOR_SIZE, 1,
        max_sectors=10, max_bytes=1024,
    )

    assert content == b"A" * SECTOR_SIZE
    assert partial is True
    assert "shorter" in error


def test_declared_stream_reports_cyclic_chain():
    data = b"\x00" * SECTOR_SIZE + b"A" * SECTOR_SIZE

    content, partial, error = legacy._read_declared_stream(
        0, 600, [0], data, SECTOR_SIZE, 1,
        max_sectors=10, max_bytes=1024,
    )

    assert content == b"A" * SECTOR_SIZE
    assert partial is True
    assert "cycle" in error


def test_zero_length_stream_does_not_read_sector():
    content, partial, error = legacy._read_declared_stream(
        EOC, 0, [], b"", SECTOR_SIZE, 0,
        max_sectors=10, max_bytes=0,
    )

    assert content == b""
    assert partial is False
    assert error is None


def test_zero_length_stream_with_allocated_chain_is_reported():
    content, partial, error = legacy._read_declared_stream(
        0, 0, [EOC], b"\x00" * 1024, SECTOR_SIZE, 1,
        max_sectors=10, max_bytes=1024,
    )

    assert content == b""
    assert partial is True
    assert "zero" in error.casefold()
