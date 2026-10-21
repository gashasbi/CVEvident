"""Preflight and bound parsing of untrusted ZIP and XML containers."""
from __future__ import annotations

import struct
from xml.etree import ElementTree

MAX_XML_ELEMENTS = 100_000
MAX_XML_DEPTH = 256

_EOCD = b"PK\x05\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_EOCD = b"PK\x06\x06"
_CENTRAL_HEADER = b"PK\x01\x02"
_EOCD_MIN_SIZE = 22
_MAX_ZIP_COMMENT = 0xFFFF
_ZIP64_SENTINEL_16 = 0xFFFF
_ZIP64_SENTINEL_32 = 0xFFFFFFFF


def _find_eocd(data: bytes) -> int:
    """Return the last plausible EOCD offset, or -1 if absent."""
    lower = max(0, len(data) - (_EOCD_MIN_SIZE + _MAX_ZIP_COMMENT))
    pos = data.rfind(_EOCD, lower)
    while pos >= lower:
        if pos + _EOCD_MIN_SIZE <= len(data):
            comment_length = struct.unpack_from("<H", data, pos + 20)[0]
            if pos + _EOCD_MIN_SIZE + comment_length <= len(data):
                return pos
        pos = data.rfind(_EOCD, lower, pos)
    return -1


def _zip64_uncompressed_size(extra: bytes) -> int:
    """Read the uncompressed-size value required by a ZIP64 central record."""
    offset = 0
    while offset + 4 <= len(extra):
        field_id, field_size = struct.unpack_from("<HH", extra, offset)
        start = offset + 4
        end = start + field_size
        if end > len(extra):
            raise ValueError("ZIP central-directory extra field is malformed")
        if field_id == 0x0001:
            if field_size < 8:
                raise ValueError("ZIP64 extra field omits the uncompressed size")
            return struct.unpack_from("<Q", extra, start)[0]
        offset = end
    raise ValueError("ZIP64 uncompressed size is missing from the central-directory extra fields")


def _scan_central_directory(data: bytes, max_entries: int) -> dict[str, int]:
    """Validate and scan central-directory records without building ZipInfo objects."""
    if max_entries < 1:
        raise ValueError("ZIP member limit must be positive")
    eocd_pos = _find_eocd(data)
    if eocd_pos < 0:
        raise ValueError("ZIP end-of-central-directory record is missing or malformed")

    disk_number, directory_disk, entries_on_disk, declared_entries = struct.unpack_from(
        "<4H", data, eocd_pos + 4
    )
    directory_size, directory_offset = struct.unpack_from("<2I", data, eocd_pos + 12)
    uses_zip64 = (
        entries_on_disk == _ZIP64_SENTINEL_16
        or declared_entries == _ZIP64_SENTINEL_16
        or directory_size == _ZIP64_SENTINEL_32
        or directory_offset == _ZIP64_SENTINEL_32
    )

    if uses_zip64:
        locator_pos = eocd_pos - 20
        if locator_pos < 0 or data[locator_pos:locator_pos + 4] != _ZIP64_LOCATOR:
            raise ValueError("ZIP64 locator is missing or malformed")
        locator_disk = struct.unpack_from("<I", data, locator_pos + 4)[0]
        zip64_offset = struct.unpack_from("<Q", data, locator_pos + 8)[0]
        total_disks = struct.unpack_from("<I", data, locator_pos + 16)[0]
        if locator_disk != 0 or total_disks != 1:
            raise ValueError("multi-disk ZIP64 archives are not supported")
        if zip64_offset + 56 > locator_pos or data[zip64_offset:zip64_offset + 4] != _ZIP64_EOCD:
            raise ValueError("ZIP64 end-of-central-directory record is unsupported or malformed")
        record_size = struct.unpack_from("<Q", data, zip64_offset + 4)[0]
        if record_size < 44 or zip64_offset + 12 + record_size != locator_pos:
            raise ValueError("ZIP64 end-of-central-directory record has an invalid size")
        z_disk, z_directory_disk = struct.unpack_from("<2I", data, zip64_offset + 16)
        entries_on_disk, declared_entries = struct.unpack_from("<2Q", data, zip64_offset + 24)
        directory_size, directory_offset = struct.unpack_from("<2Q", data, zip64_offset + 40)
        directory_end = zip64_offset
        if z_disk != 0 or z_directory_disk != 0 or entries_on_disk != declared_entries:
            raise ValueError("multi-disk or inconsistent ZIP64 archives are not supported")
    else:
        directory_end = eocd_pos
        if disk_number != 0 or directory_disk != 0 or entries_on_disk != declared_entries:
            raise ValueError("multi-disk or inconsistent ZIP archives are not supported")

    directory_start = directory_end - directory_size
    if directory_size < 0 or directory_start < 0 or directory_end > len(data):
        raise ValueError("ZIP central-directory bounds are invalid")
    # A prepended self-extracting stub is allowed; the physical directory must
    # start at (or after) the offset relative to the start of the ZIP payload.
    if directory_offset > directory_start:
        raise ValueError("ZIP central-directory offset is invalid")

    cursor = directory_start
    actual_entries = 0
    first_limit_end = directory_start
    total_uncompressed_bytes = 0
    while cursor < directory_end:
        if directory_end - cursor < 46 or data[cursor:cursor + 4] != _CENTRAL_HEADER:
            raise ValueError("ZIP central directory contains a malformed member record")
        compressed_size = struct.unpack_from("<I", data, cursor + 20)[0]
        uncompressed_size = struct.unpack_from("<I", data, cursor + 24)[0]
        name_len, extra_len, comment_len = struct.unpack_from("<3H", data, cursor + 28)
        record_end = cursor + 46 + name_len + extra_len + comment_len
        if record_end > directory_end:
            raise ValueError("ZIP central-directory member extends beyond its declared bounds")
        if uncompressed_size == _ZIP64_SENTINEL_32:
            extra_start = cursor + 46 + name_len
            extra = data[extra_start:extra_start + extra_len]
            uncompressed_size = _zip64_uncompressed_size(extra)
        total_uncompressed_bytes += uncompressed_size
        actual_entries += 1
        if actual_entries == max_entries:
            first_limit_end = record_end
        cursor = record_end

    if cursor != directory_end:
        raise ValueError("ZIP central-directory size does not match its member records")
    return {
        "directory_start": directory_start,
        "directory_end": directory_end,
        "directory_offset": directory_offset,
        "declared_entries": declared_entries,
        "actual_entries": actual_entries,
        "first_limit_end": first_limit_end,
        "total_uncompressed_bytes": total_uncompressed_bytes,
    }


def ensure_zip_entry_limit(data: bytes, max_entries: int = 10_000) -> int:
    """Validate the directory and reject archives exceeding ``max_entries``.

    This preflight scans raw central-directory records, avoiding ZipInfo allocation.
    """
    info = _scan_central_directory(data, max_entries)
    actual_entries = info["actual_entries"]
    if actual_entries > max_entries:
        raise ValueError(f"ZIP member count exceeds configured limit ({max_entries})")
    if actual_entries != info["declared_entries"]:
        raise ValueError("ZIP declared member count does not match the central directory")
    return actual_entries


def bounded_zip_data(
    data: bytes, max_entries: int = 10_000
) -> tuple[bytes, int, int, bool]:
    """Return ZIP bytes whose directory contains at most ``max_entries`` records.

    If the source contains more records, the local-file data is kept intact and a
    replacement EOCD points to only the first ``max_entries`` central records. This
    lets zipfile build only the bounded ZipInfo list while preserving useful partial
    analysis. The return tuple is (zip_bytes, original_entry_count,
    total_declared_uncompressed_bytes, was_truncated).
    """
    info = _scan_central_directory(data, max_entries)
    actual_entries = info["actual_entries"]
    if actual_entries != info["declared_entries"]:
        raise ValueError("ZIP declared member count does not match the central directory")
    total_uncompressed = info["total_uncompressed_bytes"]
    if actual_entries <= max_entries:
        return data, actual_entries, total_uncompressed, False

    # The project input-size budget keeps these offsets far below ZIP's 4 GiB
    # limit. Fail closed if this helper is called with a larger unsupported input.
    if max_entries >= _ZIP64_SENTINEL_16:
        raise ValueError("ZIP entry limits above 65534 cannot be materialized as a bounded archive")
    directory_start = info["directory_start"]
    cutoff = info["first_limit_end"]
    directory_offset = info["directory_offset"]
    bounded_directory_size = cutoff - directory_start
    if max(directory_start, directory_offset, bounded_directory_size) >= _ZIP64_SENTINEL_32:
        raise ValueError("Truncated ZIP directory requires unsupported ZIP64 output")
    bounded_directory = data[directory_start:cutoff]
    eocd = struct.pack(
        "<4s4H2IH",
        _EOCD,
        0, 0,
        max_entries, max_entries,
        bounded_directory_size,
        directory_offset,
        0,
    )
    bounded_data = data[:directory_start] + bounded_directory + eocd
    return bounded_data, actual_entries, total_uncompressed, True


class _BoundedTreeBuilder(ElementTree.TreeBuilder):
    def __init__(self, max_elements: int, max_depth: int) -> None:
        super().__init__()
        self.max_elements = max_elements
        self.max_depth = max_depth
        self.elements = 0
        self.depth = 0

    def start(self, tag: str, attrs: dict[str, str]):
        next_depth = self.depth + 1
        if next_depth > self.max_depth:
            raise ValueError(f"XML nesting depth exceeds configured limit ({self.max_depth})")
        next_elements = self.elements + 1
        if next_elements > self.max_elements:
            raise ValueError(f"XML element count exceeds configured limit ({self.max_elements})")
        element = super().start(tag, attrs)
        self.depth = next_depth
        self.elements = next_elements
        return element

    def end(self, tag: str):
        element = super().end(tag)
        self.depth -= 1
        return element


def parse_xml_bounded(
    data: bytes,
    *,
    max_elements: int = MAX_XML_ELEMENTS,
    max_depth: int = MAX_XML_DEPTH,
) -> ElementTree.Element:
    """Build an XML tree while enforcing element-count and nesting limits."""
    if max_elements < 1 or max_depth < 1:
        raise ValueError("XML parsing limits must be positive")
    builder = _BoundedTreeBuilder(max_elements=max_elements, max_depth=max_depth)
    parser = ElementTree.XMLParser(target=builder)
    parser.feed(data)
    return parser.close()
