import struct

from cvevident.legacy_office_triage import OLE_SIGNATURE, analyze_legacy_office


FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
SECTOR_SIZE = 512


def _directory_entry(
    name,
    entry_type,
    *,
    child=FREE,
    start_sector=EOC,
    size=0,
):
    entry = bytearray(128)
    encoded = name.encode("utf-16le") + b"\x00\x00"

    if len(encoded) > 64:
        raise ValueError("Directory entry name is too long")

    entry[:len(encoded)] = encoded
    struct.pack_into("<H", entry, 64, len(encoded))
    entry[66] = entry_type
    entry[67] = 1
    struct.pack_into("<III", entry, 68, FREE, FREE, child)
    struct.pack_into("<I", entry, 116, start_sector)
    struct.pack_into("<Q", entry, 120, size)
    return bytes(entry)


def _build_cfb_with_mini_stream():
    # Physical sectors: directory=0, FAT=1, MiniFAT=2,
    # Root Mini Stream backing data=3.
    header = bytearray(SECTOR_SIZE)
    header[:8] = OLE_SIGNATURE

    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, 3)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9)
    struct.pack_into("<H", header, 32, 6)

    struct.pack_into("<I", header, 40, 0)       # Directory sectors, v3
    struct.pack_into("<I", header, 44, 1)       # FAT sector count
    struct.pack_into("<I", header, 48, 0)       # First directory sector
    struct.pack_into("<I", header, 56, 4096)    # Mini stream cutoff
    struct.pack_into("<I", header, 60, 2)       # First MiniFAT sector
    struct.pack_into("<I", header, 64, 1)       # MiniFAT sector count
    struct.pack_into("<I", header, 68, EOC)     # First DIFAT sector
    struct.pack_into("<I", header, 72, 0)       # DIFAT sector count

    difat = [1] + [FREE] * 108
    struct.pack_into("<109I", header, 76, *difat)

    directory = bytearray(SECTOR_SIZE)
    directory[0:128] = _directory_entry(
        "Root Entry",
        5,
        child=1,
        start_sector=3,
        size=SECTOR_SIZE,
    )
    directory[128:256] = _directory_entry(
        "TinyStream",
        2,
        start_sector=0,  # Mini-sector index, not a physical sector
        size=5,
    )

    fat_words = [FREE] * (SECTOR_SIZE // 4)
    fat_words[0] = EOC
    fat_words[1] = FATSECT
    fat_words[2] = EOC
    fat_words[3] = EOC
    fat_sector = struct.pack("<128I", *fat_words)

    mini_fat_words = [FREE] * (SECTOR_SIZE // 4)
    mini_fat_words[0] = EOC
    mini_fat_sector = struct.pack("<128I", *mini_fat_words)

    # The first mini-sector contains five known bytes.
    root_mini_stream = b"HELLO" + bytes(SECTOR_SIZE - 5)

    return (
        bytes(header)
        + bytes(directory)
        + fat_sector
        + mini_fat_sector
        + root_mini_stream
    )


def test_analyzer_loads_minifat_and_root_mini_stream(tmp_path):
    sample = tmp_path / "mini-stream.doc"
    sample.write_bytes(_build_cfb_with_mini_stream())

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    assert analysis["mini_fat_status"] == "parsed"
    assert analysis["mini_fat_entry_count"] == 128
    assert analysis["mini_fat_sector_count_declared"] == 1

    assert analysis["root_mini_stream_status"] == "read"
    assert analysis["root_mini_stream_size_declared"] == SECTOR_SIZE
    assert analysis["root_mini_stream_bytes_read"] == SECTOR_SIZE
    assert analysis["root_mini_stream_error"] is None

    # The individual mini stream must be read, but its bytes must not
    # be exposed in the report.
    tiny = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )
    assert tiny["allocation"] == "mini"
    assert tiny["declared_size_bytes"] == 5
    assert tiny["bytes_read"] == 5
    assert tiny["status"] == "read"
    assert "content" not in tiny
    assert "data" not in tiny


def test_stream_reader_enforces_per_stream_byte_limit(tmp_path, monkeypatch):
    import cvevident.legacy_office_triage as triage

    monkeypatch.setattr(triage, "_MAX_STREAM_BYTES", 4)

    sample = tmp_path / "per-stream-limit.doc"
    sample.write_bytes(_build_cfb_with_mini_stream())

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    tiny = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )
    assert tiny["status"] == "skipped"
    assert tiny["bytes_read"] == 0
    assert "per-stream byte limit" in tiny["error"]
    assert analysis["stream_skipped_count"] == 1


def test_stream_reader_enforces_aggregate_byte_budget(tmp_path, monkeypatch):
    import cvevident.legacy_office_triage as triage

    monkeypatch.setattr(triage, "_MAX_TOTAL_STREAM_BYTES", 4)

    sample = tmp_path / "aggregate-stream-limit.doc"
    sample.write_bytes(_build_cfb_with_mini_stream())

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    tiny = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )
    assert tiny["status"] == "skipped"
    assert tiny["bytes_read"] == 0
    assert "aggregate stream byte budget" in tiny["error"]
    assert analysis["stream_bytes_reserved"] == 0
    assert analysis["stream_skipped_count"] == 1


def test_stream_reader_enforces_stream_count_limit(tmp_path, monkeypatch):
    import cvevident.legacy_office_triage as triage

    monkeypatch.setattr(triage, "_MAX_STREAMS_TO_READ", 0)

    sample = tmp_path / "stream-count-limit.doc"
    sample.write_bytes(_build_cfb_with_mini_stream())

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    assert analysis["stream_inventory"] == []
    assert analysis["stream_inventory_truncated"] is True
    assert analysis["stream_read_count"] == 0


def _build_cfb_with_empty_mini_stream(start_sector):
    data = bytearray(_build_cfb_with_mini_stream())

    # TinyStream directory entry: directory sector 0, entry index 1.
    entry_offset = SECTOR_SIZE + 128
    struct.pack_into("<I", data, entry_offset + 116, start_sector)
    struct.pack_into("<Q", data, entry_offset + 120, 0)

    return bytes(data)


def test_empty_stream_is_counted_exactly_once(tmp_path):
    sample = tmp_path / "empty-stream.doc"
    sample.write_bytes(_build_cfb_with_empty_mini_stream(EOC))

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    empty = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert empty["declared_size_bytes"] == 0
    assert empty["bytes_read"] == 0
    assert empty["status"] == "read"
    assert empty["error"] is None
    assert analysis["stream_read_count"] == 1
    assert analysis["stream_partial_count"] == 0


def test_empty_stream_with_allocated_chain_is_counted_partial_once(tmp_path):
    sample = tmp_path / "empty-stream-allocated.doc"
    sample.write_bytes(_build_cfb_with_empty_mini_stream(0))

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    empty = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert empty["declared_size_bytes"] == 0
    assert empty["bytes_read"] == 0
    assert empty["status"] == "partial"
    assert "zero-length stream" in empty["error"]
    assert analysis["stream_partial_count"] == 1
    assert analysis["stream_read_count"] == 0


def _build_cfb_with_regular_stream():
    data = bytearray(_build_cfb_with_mini_stream())

    # Convert TinyStream to a regular 4096-byte stream.
    entry_offset = SECTOR_SIZE + 128
    struct.pack_into("<I", data, entry_offset + 116, 4)
    struct.pack_into("<Q", data, entry_offset + 120, 4096)

    # Physical sectors 4..11 form an eight-sector FAT chain.
    fat_offset = SECTOR_SIZE * 2
    for sector_id in range(4, 11):
        struct.pack_into("<I", data, fat_offset + sector_id * 4, sector_id + 1)
    struct.pack_into("<I", data, fat_offset + 11 * 4, EOC)

    # Append eight sectors with deterministic test data.
    stream_data = bytes((index % 251 for index in range(4096)))
    data.extend(stream_data)

    return bytes(data)


def test_analyzer_reads_multisector_regular_stream(tmp_path):
    sample = tmp_path / "regular-stream.doc"
    sample.write_bytes(_build_cfb_with_regular_stream())

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    stream = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["allocation"] == "regular"
    assert stream["declared_size_bytes"] == 4096
    assert stream["bytes_read"] == 4096
    assert stream["status"] == "read"
    assert stream["error"] is None
    assert analysis["stream_read_count"] == 1
    assert analysis["stream_partial_count"] == 0
    assert "content" not in stream
    assert "data" not in stream


def test_analyzer_reports_short_regular_stream_chain(tmp_path):
    data = bytearray(_build_cfb_with_regular_stream())

    # Break the FAT chain after the first sector.
    fat_offset = SECTOR_SIZE * 2
    struct.pack_into("<I", data, fat_offset + 4 * 4, EOC)

    sample = tmp_path / "short-regular-stream.doc"
    sample.write_bytes(data)

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    stream = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["allocation"] == "regular"
    assert stream["declared_size_bytes"] == 4096
    assert stream["bytes_read"] == SECTOR_SIZE
    assert stream["status"] == "partial"
    assert "shorter" in stream["error"].casefold()
    assert analysis["stream_partial_count"] == 1
    assert analysis["stream_read_count"] == 0


def test_analyzer_reports_short_regular_stream_chain(tmp_path):
    data = bytearray(_build_cfb_with_regular_stream())

    # Break the FAT chain after the first sector.
    fat_offset = SECTOR_SIZE * 2
    struct.pack_into("<I", data, fat_offset + 4 * 4, EOC)

    sample = tmp_path / "short-regular-stream.doc"
    sample.write_bytes(data)

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    stream = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["allocation"] == "regular"
    assert stream["declared_size_bytes"] == 4096
    assert stream["bytes_read"] == SECTOR_SIZE
    assert stream["status"] == "partial"
    assert "shorter" in stream["error"].casefold()
    assert analysis["stream_partial_count"] == 1
    assert analysis["stream_read_count"] == 0


def test_analyzer_reports_cyclic_regular_stream_chain(tmp_path):
    data = bytearray(_build_cfb_with_regular_stream())

    # Create a cycle: sector 4 -> sector 5 -> sector 4.
    fat_offset = SECTOR_SIZE * 2
    struct.pack_into("<I", data, fat_offset + 4 * 4, 5)
    struct.pack_into("<I", data, fat_offset + 5 * 4, 4)

    sample = tmp_path / "cyclic-regular-stream.doc"
    sample.write_bytes(data)

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]

    stream = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["allocation"] == "regular"
    assert stream["status"] == "partial"
    assert stream["bytes_read"] == 2 * SECTOR_SIZE
    assert "cycle" in stream["error"].casefold()
    assert analysis["stream_partial_count"] == 1
    assert analysis["stream_read_count"] == 0


def test_mini_stream_identifies_pdf_signature_without_exposing_content(tmp_path):
    data = bytearray(_build_cfb_with_mini_stream())

    # Root Mini Stream starts after the header and three physical sectors.
    data[SECTOR_SIZE * 4:SECTOR_SIZE * 4 + 5] = b"%PDF-"

    sample = tmp_path / "mini-pdf.doc"
    sample.write_bytes(data)

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]
    stream = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["status"] == "read"
    assert stream["content_status"] == "identified"
    assert stream["content_kind"] == "pdf"
    assert stream["content_signature"] == "pdf_header"
    assert stream["content_bytes_inspected"] == 5
    assert "content" not in stream
    assert "data" not in stream
    assert report["assessment"]["verdict"] == "not_assessed"


def test_regular_stream_identifies_zip_signature_without_exposing_content(tmp_path):
    data = bytearray(_build_cfb_with_regular_stream())

    # Regular stream data starts immediately after the original CFB sectors.
    stream_offset = len(_build_cfb_with_mini_stream())
    data[stream_offset:stream_offset + 4] = b"PK\x03\x04"

    sample = tmp_path / "regular-zip.doc"
    sample.write_bytes(data)

    report = analyze_legacy_office(str(sample))
    analysis = report["legacy_office_analysis"]
    stream = next(
        item for item in analysis["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["status"] == "read"
    assert stream["content_status"] == "identified"
    assert stream["content_kind"] == "zip"
    assert stream["content_signature"] == "zip_local_file_header"
    assert stream["content_bytes_inspected"] == 8
    assert "content" not in stream
    assert "data" not in stream
    assert report["assessment"]["verdict"] == "not_assessed"


def test_unknown_stream_content_remains_unrecognized(tmp_path):
    sample = tmp_path / "unknown-content.doc"
    sample.write_bytes(_build_cfb_with_mini_stream())

    report = analyze_legacy_office(str(sample))
    stream = next(
        item for item in report["legacy_office_analysis"]["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["content_status"] == "unrecognized"
    assert stream["content_kind"] is None
    assert stream["content_signature"] is None
    assert stream["content_bytes_inspected"] == 5
    assert report["assessment"]["verdict"] == "not_assessed"


def test_skipped_stream_is_not_signature_inspected(tmp_path, monkeypatch):
    import cvevident.legacy_office_triage as triage

    monkeypatch.setattr(triage, "_MAX_STREAM_BYTES", 4)

    sample = tmp_path / "skipped-signature.doc"
    sample.write_bytes(_build_cfb_with_mini_stream())

    report = analyze_legacy_office(str(sample))
    stream = next(
        item for item in report["legacy_office_analysis"]["stream_inventory"]
        if item["name"] == "TinyStream"
    )

    assert stream["status"] == "skipped"
    assert stream["content_status"] == "not_inspected"
    assert stream["content_kind"] is None
    assert stream["content_signature"] is None
    assert stream["content_bytes_inspected"] == 0
