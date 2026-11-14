import pytest

from cvevident import legacy_office_triage as legacy


MINI_SIZE = 64
EOC = legacy._ENDOFCHAIN


def test_mini_stream_reads_declared_size_without_padding():
    data = b"HELLO" + b"\x00" * (MINI_SIZE - 5)

    content, partial, error = legacy._read_declared_mini_stream(
        0, 5, [EOC], data,
        max_sectors=10, max_bytes=1024,
    )

    assert content == b"HELLO"
    assert partial is False
    assert error is None


def test_mini_stream_rejects_declared_size_over_byte_budget():
    content, partial, error = legacy._read_declared_mini_stream(
        0, 65, [EOC], b"A" * 128,
        max_sectors=10, max_bytes=64,
    )

    assert content == b""
    assert partial is True
    assert "byte limit" in error


def test_mini_stream_reports_short_chain():
    content, partial, error = legacy._read_declared_mini_stream(
        0, 100, [EOC], b"A" * MINI_SIZE,
        max_sectors=10, max_bytes=128,
    )

    assert content == b"A" * MINI_SIZE
    assert partial is True
    assert "shorter" in error


def test_mini_stream_reports_cycle():
    data = b"A" * MINI_SIZE + b"B" * MINI_SIZE

    content, partial, error = legacy._read_declared_mini_stream(
        0, 129, [1, 0], data,
        max_sectors=10, max_bytes=192,
    )

    assert content == data
    assert partial is True
    assert "cycle" in error


def test_mini_stream_rejects_index_outside_root_mini_stream():
    content, partial, error = legacy._read_declared_mini_stream(
        2, 5, [EOC, EOC, EOC], b"A" * MINI_SIZE,
        max_sectors=10, max_bytes=64,
    )

    assert content == b""
    assert partial is True
    assert "outside" in error


def test_zero_length_mini_stream_does_not_read_chain():
    content, partial, error = legacy._read_declared_mini_stream(
        EOC, 0, [], b"",
        max_sectors=10, max_bytes=0,
    )

    assert content == b""
    assert partial is False
    assert error is None


def test_zero_length_mini_stream_with_allocated_chain_is_reported():
    content, partial, error = legacy._read_declared_mini_stream(
        0, 0, [EOC], b"A" * MINI_SIZE,
        max_sectors=10, max_bytes=64,
    )

    assert content == b""
    assert partial is True
    assert "zero" in error.casefold()


def test_mini_stream_rejects_chain_exceeding_sector_traversal_budget():
    data = b"A" * MINI_SIZE + b"B" * MINI_SIZE

    content, partial, error = legacy._read_declared_mini_stream(
        0, 65, [1, EOC], data,
        max_sectors=1, max_bytes=128,
    )

    assert content == b""
    assert partial is True
    assert "traversal limit" in error.casefold()


def test_mini_stream_rejects_boolean_mini_sector_size():
    content, partial, error = legacy._read_declared_mini_stream(
        0, 5, [EOC], b"A" * MINI_SIZE,
        max_sectors=10, max_bytes=64,
        mini_sector_size=True,
    )

    assert content == b""
    assert partial is True
    assert "mini-sector size is invalid" in error


@pytest.mark.parametrize("first_mini_sector", [True, False, "0", None, 1.5])
def test_mini_stream_rejects_invalid_first_sector_type(first_mini_sector):
    content, partial, error = legacy._read_declared_mini_stream(
        first_mini_sector, 5, [EOC], b"A" * MINI_SIZE,
        max_sectors=10, max_bytes=64,
    )

    assert content == b""
    assert partial is True
    assert "first mini-sector" in error.casefold()
