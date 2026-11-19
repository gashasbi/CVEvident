"""Bounded, static triage for legacy OLE/CFB Office files.

This module validates a bounded subset of the Compound File Binary container,
inventories directory entries, and parses limited VBA project metadata. It does
not interpret document content or VBA source code and is not a full OLE parser
or a malware verdict.
"""
from __future__ import annotations

import struct
from collections import Counter
from typing import Any

from .file_input import read_file
from .content_signatures import (
    MAX_CONTENT_SIGNATURE_BYTES,
    identify_content_signature,
)

OLE_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")
LEGACY_FORMAT_EXTENSIONS = {
    ".doc": "doc", ".xls": "xls", ".ppt": "ppt",
    ".dot": "doc", ".xlt": "xls", ".xla": "xls",
    ".pps": "ppt", ".pot": "ppt",
}

_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_DIFSECT = 0xFFFFFFFC
_MAX_FAT_SECTORS = 4096
_MAX_DIFAT_SECTORS = 4096
_MAX_MINIFAT_SECTORS = 4096
_MAX_MINIFAT_BYTES = 16 * 1024 * 1024
_MAX_ROOT_MINI_STREAM_BYTES = 32 * 1024 * 1024
_MAX_STREAMS_TO_READ = 300
_MAX_STREAM_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_STREAM_BYTES = 32 * 1024 * 1024
_MAX_DIRECTORY_BYTES = 8 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 65536
_MAX_CHAIN_SECTORS = 200000
_MAX_INVENTORY = 300


def _decompress_vba_container(data: bytes, *, max_output: int = 1024 * 1024) -> bytes:
    if not data or data[0] != 0x01:
        raise ValueError("VBA compressed container signature is invalid")
    if len(data) > _MAX_STREAM_BYTES:
        raise ValueError("VBA compressed container exceeds the configured input limit")
    output = bytearray()
    position = 1
    while position < len(data):
        if len(data) - position < 2:
            raise ValueError("VBA compressed chunk header is truncated")
        header = struct.unpack_from("<H", data, position)[0]
        chunk_size = (header & 0x0FFF) + 3
        chunk_signature = (header >> 12) & 0x07
        compressed = bool(header & 0x8000)
        if chunk_signature != 0x03 or chunk_size < 3 or chunk_size > 4098:
            raise ValueError("VBA compressed chunk header is invalid")
        chunk_end = position + chunk_size
        if chunk_end > len(data):
            raise ValueError("VBA compressed chunk exceeds the available stream bytes")
        chunk_position = position + 2
        chunk_output = bytearray()
        if not compressed:
            if chunk_size != 4098:
                raise ValueError("VBA raw chunk has an invalid declared size")
            chunk_output.extend(data[chunk_position:chunk_end])
            if len(chunk_output) != 4096:
                raise ValueError("VBA raw chunk does not contain 4096 bytes")
        else:
            while chunk_position < chunk_end:
                flags = data[chunk_position]
                chunk_position += 1
                for bit in range(8):
                    if chunk_position >= chunk_end or len(chunk_output) >= 4096:
                        break
                    if flags & (1 << bit):
                        if chunk_end - chunk_position < 2:
                            raise ValueError("VBA copy token is truncated")
                        token = struct.unpack_from("<H", data, chunk_position)[0]
                        chunk_position += 2
                        current = len(chunk_output)
                        bit_count = max(4, (current - 1).bit_length())
                        length_mask = 0xFFFF >> bit_count
                        copy_offset = (token >> (16 - bit_count)) + 1
                        copy_length = (token & length_mask) + 3
                        if copy_offset > current or current + copy_length > 4096:
                            raise ValueError("VBA copy token references bytes outside the current chunk")
                        for _ in range(copy_length):
                            chunk_output.append(chunk_output[-copy_offset])
                    else:
                        chunk_output.append(data[chunk_position])
                        chunk_position += 1
            if chunk_position != chunk_end:
                raise ValueError("VBA compressed chunk contains unconsumed bytes")
        if len(output) + len(chunk_output) > max_output:
            raise ValueError("VBA decompressed data exceeds the configured output limit")
        output.extend(chunk_output)
        position = chunk_end
    return bytes(output)


def _parse_vba_module_block(data: bytes) -> list[dict[str, Any]]:
    if len(data) > 1024 * 1024:
        raise ValueError("VBA dir data exceeds the configured parsing limit")

    def read_record(offset: int, expected_id: int | None = None) -> tuple[int, bytes, int]:
        if offset < 0 or len(data) - offset < 6:
            raise ValueError("VBA dir record header is truncated")
        record_id, size = struct.unpack_from("<HI", data, offset)
        end = offset + 6 + size
        if end > len(data):
            raise ValueError("VBA dir record exceeds the available data")
        if expected_id is not None and record_id != expected_id:
            raise ValueError(f"VBA dir record 0x{record_id:04X} does not match expected 0x{expected_id:04X}")
        return record_id, data[offset + 6:end], end

    candidates = []
    candidate_attempts = 0
    for offset in range(max(0, len(data) - 12)):
        if data[offset:offset + 6] != b"\x0f\x00\x02\x00\x00\x00":
            continue
        candidate_attempts += 1
        if candidate_attempts > 32:
            break
        try:
            _, count_data, cursor = read_record(offset, 0x000F)
            if len(count_data) != 2:
                continue
            module_count = struct.unpack("<H", count_data)[0]
            if module_count > 4096:
                continue
            _, cookie_data, cursor = read_record(cursor, 0x0013)
            if len(cookie_data) != 2:
                continue
            modules = []
            seen_names = set()
            for _ in range(module_count):
                _, name_data, cursor = read_record(cursor, 0x0019)
                if not name_data or len(name_data) > 4096:
                    raise ValueError("VBA module name is empty or too long")
                module_name = name_data.decode("cp1252", errors="replace")
                if cursor + 6 <= len(data) and struct.unpack_from("<H", data, cursor)[0] == 0x0047:
                    _, _, cursor = read_record(cursor, 0x0047)
                _, stream_data, cursor = read_record(cursor, 0x001A)
                if not stream_data or len(stream_data) > 4096:
                    raise ValueError("VBA module stream name is empty or too long")
                stream_name = stream_data.decode("cp1252", errors="replace")
                if cursor + 6 > len(data) or struct.unpack_from("<H", data, cursor)[0] != 0x0032:
                    raise ValueError("VBA module stream Unicode marker is missing")
                _, stream_unicode, cursor = read_record(cursor, 0x0032)
                if len(stream_unicode) % 2 or len(stream_unicode) > 8192:
                    raise ValueError("VBA module stream Unicode name is invalid")
                if stream_unicode:
                    stream_name = stream_unicode.decode("utf-16le", errors="replace")
                if cursor + 6 <= len(data) and struct.unpack_from("<H", data, cursor)[0] == 0x001C:
                    _, _, cursor = read_record(cursor, 0x001C)
                    if cursor + 6 > len(data) or struct.unpack_from("<H", data, cursor)[0] != 0x0048:
                        raise ValueError("VBA module docstring Unicode marker is missing")
                    _, _, cursor = read_record(cursor, 0x0048)
                _, offset_data, cursor = read_record(cursor, 0x0031)
                if len(offset_data) != 4:
                    raise ValueError("VBA module source offset has an invalid size")
                source_offset = struct.unpack("<I", offset_data)[0]
                _, help_data, cursor = read_record(cursor, 0x001E)
                if len(help_data) != 4:
                    raise ValueError("VBA module help context has an invalid size")
                _, cookie_data, cursor = read_record(cursor, 0x002C)
                if len(cookie_data) != 2:
                    raise ValueError("VBA module cookie has an invalid size")
                module_type, type_data, cursor = read_record(cursor)
                if module_type not in (0x0021, 0x0022) or type_data:
                    raise ValueError("VBA module type record is invalid")
                while cursor + 6 <= len(data):
                    optional_id = struct.unpack_from("<H", data, cursor)[0]
                    if optional_id not in (0x0025, 0x0028):
                        break
                    _, optional_data, cursor = read_record(cursor)
                    if optional_data:
                        raise ValueError("VBA optional module record has an invalid size")
                if cursor + 6 > len(data) or struct.unpack_from("<H", data, cursor)[0] != 0x002B:
                    raise ValueError("VBA module terminator is missing")
                _, terminator_data, cursor = read_record(cursor, 0x002B)
                if terminator_data:
                    raise ValueError("VBA module terminator has an invalid size")
                if len(data) - cursor < 4 or data[cursor:cursor + 4] != b"\x00\x00\x00\x00":
                    raise ValueError("VBA module reserved field is invalid")
                cursor += 4
                normalized_stream = stream_name.casefold()
                if normalized_stream in seen_names:
                    raise ValueError("VBA module stream names are duplicated")
                seen_names.add(normalized_stream)
                modules.append({
                    "name": module_name[:128],
                    "stream_name": stream_name[:128],
                    "source_offset": source_offset,
                    "module_type": "procedural" if module_type == 0x0021 else "document_or_class",
                })
            if len(data) - cursor < 6 or struct.unpack_from("<H", data, cursor)[0] != 0x0010:
                raise ValueError("VBA dir project terminator is missing")
            _, terminator_data, cursor = read_record(cursor, 0x0010)
            if terminator_data or len(data) - cursor < 4 or data[cursor:cursor + 4] != b"\x00\x00\x00\x00":
                raise ValueError("VBA dir reserved terminator field is invalid")
            candidates.append(modules)
        except (ValueError, UnicodeError, struct.error):
            continue
    if not candidates:
        raise ValueError("VBA dir module records could not be parsed")
    if any(candidate != candidates[0] for candidate in candidates[1:]):
        raise ValueError("VBA dir contains ambiguous module record sequences")
    return candidates[0]


def _safe_text(value: Any, limit: int = 240) -> str:
    text = "" if value is None else str(value)
    text = "".join(ch if ch >= " " and ch not in "\x7f" else " " for ch in text)
    return " ".join(text.split())[:limit]


def _base_report(file_input: Any, status: str, message: str, file_type: str = "unknown_ole_cfb") -> dict[str, Any]:
    return {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                 "sha256": file_input.sha256, "file_type": file_type},
        "assessment": {"verdict": "not_assessed",
                       "reason": "Legacy Office observations are static structure only; no malware verdict or CVE attribution is made."},
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256},
        "legacy_office_analysis": {
            "status": status, "family": None, "format_id": None,
            "container_format": "OLE Compound File Binary (CFB)",
            "sector_size": None, "directory_entry_count": 0,
            "stream_count": 0, "storage_count": 0,
            "root_directory_entry_valid": None, "truncated": False,
            "features": {}, "directory_inventory": [], "directory_tree_valid": None, "warnings": [message],
        },
        "evidence": [
            {"evidence_type": "file_identity", "key": "sha256", "value": file_input.sha256,
             "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"}},
            {"evidence_type": "file_identity", "key": "file_size_bytes", "value": file_input.size_bytes,
             "severity": "info", "details": {"meaning": "input bytes read within the configured limit"}},
            {"evidence_type": "legacy_office_status", "key": "legacy_office.container_status", "value": status,
             "severity": "warning", "details": {"interpretation": message}},
        ],
        "warnings": [message,
                     "Legacy Office analysis inspects bounded OLE/CFB header and directory metadata only; stream bodies and macros are not executed or extracted."],
    }


def _read_sector(data: bytes, sector_size: int, sector_id: int, total_sectors: int) -> bytes:
    if sector_id < 0 or sector_id >= total_sectors:
        raise ValueError(f"sector identifier {sector_id} is outside the file")
    start = (sector_id + 1) * sector_size
    end = start + sector_size
    if end > len(data):
        raise ValueError("sector extends beyond end of file")
    return data[start:end]


def _follow_chain(first_sector: int, table: list[int], data: bytes, sector_size: int,
                  total_sectors: int, *, max_sectors: int, max_bytes: int) -> tuple[bytes, bool, str | None]:
    if first_sector in (_ENDOFCHAIN, _FREESECT):
        return b"", False, None
    current = first_sector
    visited: set[int] = set()
    chunks: list[bytes] = []
    total = 0
    partial = False
    error: str | None = None
    for _ in range(max_sectors):
        if current in (_ENDOFCHAIN, _FREESECT):
            break
        if current in visited:
            partial = True
            error = "sector chain contains a cycle"
            break
        if current >= total_sectors or current >= len(table):
            partial = True
            error = "sector chain references an invalid or unavailable FAT entry"
            break
        visited.add(current)
        try:
            chunk = _read_sector(data, sector_size, current, total_sectors)
        except ValueError as exc:
            partial = True
            error = str(exc)
            break
        room = max_bytes - total
        if room <= 0:
            partial = True
            error = "sector-chain byte limit reached"
            break
        if len(chunk) > room:
            chunks.append(chunk[:room])
            total += room
            partial = True
            error = "sector-chain byte limit reached"
            break
        chunks.append(chunk)
        total += len(chunk)
        current = table[current]
    else:
        partial = True
        error = "sector-chain traversal limit reached"
    if current not in (_ENDOFCHAIN, _FREESECT) and error is None:
        partial = True
        error = "sector-chain traversal ended before end-of-chain"
    return b"".join(chunks), partial, error



def _read_declared_stream(
    first_sector: int,
    declared_size: int,
    table: list[int],
    data: bytes,
    sector_size: int,
    total_sectors: int,
    *,
    max_sectors: int,
    max_bytes: int,
) -> tuple[bytes, bool, str | None]:
    """Read exactly one declared-size FAT stream within strict resource limits."""
    if not isinstance(declared_size, int) or declared_size < 0:
        return b"", True, "declared stream size is invalid"

    if max_bytes < 0 or max_sectors < 0:
        return b"", True, "stream resource budget is invalid"

    if declared_size == 0:
        if first_sector not in (_ENDOFCHAIN, _FREESECT):
            return b"", True, "zero-length stream has an allocated sector chain"
        return b"", False, None

    if declared_size > max_bytes:
        return b"", True, "declared stream exceeds configured byte limit"

    if sector_size <= 0:
        return b"", True, "stream sector size is invalid"

    required_sectors = (declared_size + sector_size - 1) // sector_size
    if required_sectors > max_sectors:
        return b"", True, "declared stream exceeds configured sector traversal limit"

    if first_sector in (_ENDOFCHAIN, _FREESECT):
        return b"", True, "stream chain is shorter than its declared size"

    current = first_sector
    visited: set[int] = set()
    chunks: list[bytes] = []
    total = 0

    while total < declared_size:
        if len(visited) >= max_sectors:
            return b"".join(chunks), True, "stream chain traversal limit reached"

        if current in (_ENDOFCHAIN, _FREESECT):
            return b"".join(chunks), True, "stream chain is shorter than its declared size"

        if current in visited:
            return b"".join(chunks), True, "stream chain contains a cycle"

        if current >= total_sectors or current >= len(table):
            return (
                b"".join(chunks),
                True,
                "stream chain references an invalid or unavailable FAT entry",
            )

        visited.add(current)

        try:
            sector = _read_sector(data, sector_size, current, total_sectors)
        except ValueError as exc:
            return b"".join(chunks), True, _safe_text(exc)

        remaining = declared_size - total
        take = min(len(sector), remaining)
        if take <= 0:
            return b"".join(chunks), True, "stream sector contains no readable bytes"

        chunks.append(sector[:take])
        total += take

        if total < declared_size:
            current = table[current]

    return b"".join(chunks), False, None



def _read_declared_mini_stream(
    first_mini_sector: int,
    declared_size: int,
    mini_fat: list[int],
    root_mini_stream: bytes,
    *,
    max_sectors: int,
    max_bytes: int,
    mini_sector_size: int = 64,
) -> tuple[bytes, bool, str | None]:
    """Read exactly one declared-size Mini Stream within strict resource limits."""
    if not isinstance(declared_size, int) or isinstance(declared_size, bool) or declared_size < 0:
        return b"", True, "declared mini stream size is invalid"

    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not isinstance(max_sectors, int)
        or isinstance(max_sectors, bool)
        or max_bytes < 0
        or max_sectors < 0
    ):
        return b"", True, "mini stream resource budget is invalid"

    if (
        not isinstance(mini_sector_size, int)
        or isinstance(mini_sector_size, bool)
        or mini_sector_size <= 0
    ):
        return b"", True, "mini-sector size is invalid"
    if (
        not isinstance(first_mini_sector, int)
        or isinstance(first_mini_sector, bool)
        or (
            first_mini_sector not in (_ENDOFCHAIN, _FREESECT)
            and first_mini_sector < 0
        )
    ):
        return b"", True, "first mini-sector index is invalid"

    if declared_size == 0:
        if first_mini_sector not in (_ENDOFCHAIN, _FREESECT):
            return b"", True, "zero-length mini stream has an allocated sector chain"
        return b"", False, None

    if declared_size > max_bytes:
        return b"", True, "declared mini stream exceeds configured byte limit"

    required_sectors = (declared_size + mini_sector_size - 1) // mini_sector_size
    if required_sectors > max_sectors:
        return b"", True, "declared mini stream exceeds configured traversal limit"

    if first_mini_sector in (_ENDOFCHAIN, _FREESECT):
        return b"", True, "mini stream chain is shorter than its declared size"

    current = first_mini_sector
    visited: set[int] = set()
    chunks: list[bytes] = []
    total = 0

    while total < declared_size:
        if len(visited) >= max_sectors:
            return b"".join(chunks), True, "mini stream chain traversal limit reached"

        if current in (_ENDOFCHAIN, _FREESECT):
            return b"".join(chunks), True, "mini stream chain is shorter than its declared size"

        if not isinstance(current, int) or current < 0 or current >= len(mini_fat):
            return b"".join(chunks), True, "mini stream chain references an invalid MiniFAT entry"

        if current in visited:
            return b"".join(chunks), True, "mini stream chain contains a cycle"

        offset = current * mini_sector_size
        end = offset + mini_sector_size
        if end > len(root_mini_stream):
            return b"".join(chunks), True, "mini-sector references data outside the root Mini Stream"

        visited.add(current)
        sector = root_mini_stream[offset:end]
        remaining = declared_size - total
        take = min(len(sector), remaining)

        if take <= 0:
            return b"".join(chunks), True, "mini-sector contains no readable bytes"

        chunks.append(sector[:take])
        total += take

        if total < declared_size:
            current = mini_fat[current]

    return b"".join(chunks), False, None


def _parse_directory(
    directory_bytes: bytes,
    *,
    major_version: int = 3,
) -> tuple[list[dict[str, Any]], bool, list[str]]:
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    if len(directory_bytes) % 128:
        warnings.append("Directory stream length is not a multiple of the 128-byte directory-entry size.")
    n = min(len(directory_bytes) // 128, _MAX_DIRECTORY_ENTRIES)
    truncated = len(directory_bytes) // 128 > _MAX_DIRECTORY_ENTRIES
    for index in range(n):
        raw = directory_bytes[index * 128:(index + 1) * 128]
        entry_type = raw[66]
        if entry_type not in (1, 2, 5):
            continue
        name_length = struct.unpack_from("<H", raw, 64)[0]
        if name_length < 2 or name_length > 64 or name_length % 2:
            name = f"<invalid-name-entry-{index}>"
            warnings.append(f"Directory entry {index} has an invalid UTF-16 name length.")
        elif raw[name_length - 2:name_length] != b"\x00\x00":
            name = f"<invalid-name-entry-{index}>"
            warnings.append(f"Directory entry {index} has a missing UTF-16 name terminator.")
        else:
            try:
                name = raw[:name_length - 2].decode("utf-16le", errors="strict")
            except UnicodeDecodeError:
                name = f"<invalid-name-entry-{index}>"
                warnings.append(f"Directory entry {index} has an invalid UTF-16 name.")
        start_sector = struct.unpack_from("<I", raw, 116)[0]
        size = struct.unpack_from("<Q", raw, 120)[0]

        if entry_type == 2 and major_version == 3 and size > 0xFFFFFFFF:
            warnings.append(
                f"Directory stream entry {index} declares a size exceeding "
                "the 32-bit limit required by CFB version 3."
            )

        entries.append({
            "index": index,
            "name": _safe_text(name, 128),
            "type": {1: "storage", 2: "stream", 5: "root_storage"}[entry_type],
            "starting_sector": start_sector,
            "declared_size_bytes": int(size),
            "left_sibling_id": struct.unpack_from("<I", raw, 68)[0],
            "right_sibling_id": struct.unpack_from("<I", raw, 72)[0],
            "child_id": struct.unpack_from("<I", raw, 76)[0],
        })
    return entries, truncated, warnings


def _build_directory_parent_map(
    entries: list[dict[str, Any]],
    *,
    directory_tree_valid: bool | None,
) -> dict[int, int] | None:
    if directory_tree_valid is not True:
        return None

    entries_by_id = {entry["index"]: entry for entry in entries}
    root = entries_by_id.get(0)
    if root is None or root["type"] != "root_storage":
        return None

    parent_by_id: dict[int, int] = {}
    pending_storages = [0]
    visited_storages: set[int] = set()
    visited_entries: set[int] = set()

    while pending_storages:
        storage_id = pending_storages.pop()
        if storage_id in visited_storages:
            return None
        visited_storages.add(storage_id)
        storage = entries_by_id.get(storage_id)
        if storage is None or storage["type"] not in ("storage", "root_storage"):
            return None

        tree_root = storage["child_id"]
        if tree_root == _FREESECT:
            continue
        stack = [tree_root]
        while stack:
            entry_id = stack.pop()
            if entry_id == _FREESECT:
                continue
            entry = entries_by_id.get(entry_id)
            if entry is None or entry["type"] not in ("storage", "stream"):
                return None
            if entry_id in visited_entries or entry_id in parent_by_id:
                return None
            visited_entries.add(entry_id)
            parent_by_id[entry_id] = storage_id
            if entry["left_sibling_id"] != _FREESECT:
                stack.append(entry["left_sibling_id"])
            if entry["right_sibling_id"] != _FREESECT:
                stack.append(entry["right_sibling_id"])
            if entry["type"] == "storage":
                pending_storages.append(entry_id)

    return parent_by_id


def _cfb_simple_upper_code_unit(code_unit: int) -> int:
    if 0xD800 <= code_unit <= 0xDFFF:
        return code_unit

    character = chr(code_unit)
    uppercase = character.upper()
    if len(uppercase) == 1:
        return ord(uppercase)

    titlecase = character.title()
    if len(titlecase) == 1:
        return ord(titlecase)

    return code_unit


def _cfb_directory_name_sort_key(raw: bytes) -> tuple[int, tuple[int, ...]] | None:
    name_length = struct.unpack_from("<H", raw, 64)[0]
    if (
        name_length < 2
        or name_length > 64
        or name_length % 2
        or raw[name_length - 2:name_length] != b"\x00\x00"
    ):
        return None

    code_units = struct.unpack(
        f"<{(name_length - 2) // 2}H",
        raw[:name_length - 2],
    )
    uppercase_units = [
        _cfb_simple_upper_code_unit(code_unit)
        for code_unit in code_units
    ]

    return name_length, tuple(uppercase_units)


def _validate_directory_references(
    directory_bytes: bytes,
    *,
    complete: bool = True,
) -> tuple[bool | None, list[str]]:
    warnings: list[str] = []
    if not complete or len(directory_bytes) % 128:
        return None, [
            "Directory tree references could not be fully validated because the directory stream is incomplete."
        ]

    entry_count = len(directory_bytes) // 128
    valid = True
    directory_references_safe = True
    reported = 0
    warning_limit = 25

    def add_warning(message: str) -> None:
        nonlocal reported
        if reported < warning_limit:
            warnings.append(message)
        elif reported == warning_limit:
            warnings.append("Additional directory tree validation warnings were omitted.")
        reported += 1

    for index in range(entry_count):
        raw = directory_bytes[index * 128:(index + 1) * 128]
        entry_type = raw[66]
        if entry_type == 0:
            continue
        if entry_type not in (1, 2, 5):
            valid = False
            add_warning(
                f"Directory tree entry {index} has unsupported entry type {entry_type}."
            )
            continue

        color_flag = raw[67]
        if color_flag not in (0, 1):
            valid = False
            add_warning(
                f"Directory tree entry {index} has invalid color flag {color_flag}; expected red (0) or black (1)."
            )

        name_length = struct.unpack_from("<H", raw, 64)[0]
        if (
            2 <= name_length <= 64
            and name_length % 2 == 0
            and raw[name_length - 2] == 0
            and raw[name_length - 1] == 0
        ):
            name_units = struct.unpack(
                f"<{(name_length - 2) // 2}H",
                raw[:name_length - 2],
            )
            forbidden_units = {0x0000, 0x002F, 0x005C, 0x003A, 0x0021}
            if any(unit in forbidden_units for unit in name_units):
                valid = False
                add_warning(
                    f"Directory tree entry {index} name contains forbidden CFB character(s)."
                )

        left_id, right_id, child_id = struct.unpack_from("<III", raw, 68)

        for field_name, target_id in (
            ("left_sibling_id", left_id),
            ("right_sibling_id", right_id),
        ):
            if target_id == _FREESECT:
                continue
            if target_id >= entry_count:
                valid = False
                directory_references_safe = False
                add_warning(
                    f"Directory tree entry {index} {field_name} reference "
                    f"{target_id} is outside the directory stream ({entry_count} entries)."
                )
            elif directory_bytes[target_id * 128 + 66] not in (1, 2):
                valid = False
                directory_references_safe = False
                add_warning(
                    f"Directory tree entry {index} {field_name} reference "
                    f"{target_id} does not identify a storage or stream entry."
                )

        if child_id != _FREESECT:
            if entry_type not in (1, 5):
                valid = False
                add_warning(
                    f"Directory tree stream entry {index} has a child reference."
                )
            if child_id >= entry_count:
                valid = False
                directory_references_safe = False
                add_warning(
                    f"Directory tree entry {index} child_id reference "
                    f"{child_id} is outside the directory stream ({entry_count} entries)."
                )
            elif directory_bytes[child_id * 128 + 66] not in (1, 2):
                valid = False
                directory_references_safe = False
                add_warning(
                    f"Directory tree entry {index} child_id reference "
                    f"{child_id} does not identify a storage or stream entry."
                )
            elif directory_bytes[child_id * 128 + 67] != 1:
                valid = False
                add_warning(
                    f"Directory tree root entry {child_id} referenced by "
                    f"storage entry {index} is red; sibling-tree roots must be black."
                )

    if directory_references_safe:
        state = bytearray(entry_count)
        for start in range(entry_count):
            start_type = directory_bytes[start * 128 + 66]
            if start_type not in (1, 2, 5) or state[start] != 0:
                continue

            stack = [(start, False)]
            while stack:
                node_id, exiting = stack.pop()

                if exiting:
                    state[node_id] = 2
                    continue

                if state[node_id] == 1:
                    valid = False
                    add_warning(
                        f"Directory tree contains a cycle involving entry {node_id}."
                    )
                    continue

                if state[node_id] == 2:
                    valid = False
                    add_warning(
                        f"Directory tree entry {node_id} is referenced more than once."
                    )
                    continue

                state[node_id] = 1
                stack.append((node_id, True))

                raw = directory_bytes[node_id * 128:(node_id + 1) * 128]
                entry_type = raw[66]
                left_id, right_id, child_id = struct.unpack_from("<III", raw, 68)

                targets = []
                if entry_type in (1, 2):
                    for field_name, target_id in (
                        ("left_sibling_id", left_id),
                        ("right_sibling_id", right_id),
                    ):
                        if target_id == _FREESECT:
                            continue
                        target_color = directory_bytes[target_id * 128 + 67]
                        if raw[67] == 0 and target_color == 0:
                            valid = False
                            add_warning(
                                "Directory tree contains consecutive red sibling "
                                f"nodes {node_id} and {target_id} via {field_name}."
                            )
                        targets.append(target_id)

                if entry_type in (1, 5) and child_id != _FREESECT:
                    targets.append(child_id)

                for target_id in targets:
                    stack.append((target_id, False))

    if directory_references_safe:
        bst_visited_nodes = set()
        for storage_id in range(entry_count):
            storage_raw = directory_bytes[
                storage_id * 128:(storage_id + 1) * 128
            ]
            if storage_raw[66] not in (1, 5):
                continue

            tree_root = struct.unpack_from("<I", storage_raw, 76)[0]
            if tree_root == _FREESECT:
                continue

            stack = [(tree_root, None, None)]
            while stack:
                node_id, lower_bound, upper_bound = stack.pop()
                if node_id in bst_visited_nodes:
                    continue
                bst_visited_nodes.add(node_id)
                raw = directory_bytes[node_id * 128:(node_id + 1) * 128]
                left_id, right_id = struct.unpack_from("<II", raw, 68)
                key = _cfb_directory_name_sort_key(raw)

                if key is None:
                    valid = False
                    add_warning(
                        f"Directory tree entry {node_id} has an invalid name and cannot be ordered."
                    )
                    if right_id != _FREESECT:
                        stack.append((right_id, lower_bound, upper_bound))
                    if left_id != _FREESECT:
                        stack.append((left_id, lower_bound, upper_bound))
                    continue

                if lower_bound is not None and key <= lower_bound:
                    valid = False
                    add_warning(
                        f"Directory tree entry {node_id} violates CFB name ordering or sibling-name uniqueness."
                    )
                if upper_bound is not None and key >= upper_bound:
                    valid = False
                    add_warning(
                        f"Directory tree entry {node_id} violates CFB name ordering or sibling-name uniqueness."
                    )

                if right_id != _FREESECT:
                    stack.append((right_id, key, upper_bound))
                if left_id != _FREESECT:
                    stack.append((left_id, lower_bound, key))

    if directory_references_safe:
        reachable = bytearray(entry_count)
        stack = [0] if entry_count else []

        while stack:
            node_id = stack.pop()
            if reachable[node_id]:
                continue
            reachable[node_id] = 1

            raw = directory_bytes[node_id * 128:(node_id + 1) * 128]
            entry_type = raw[66]
            left_id, right_id, child_id = struct.unpack_from("<III", raw, 68)

            if entry_type in (1, 2):
                if left_id != _FREESECT:
                    stack.append(left_id)
                if right_id != _FREESECT:
                    stack.append(right_id)

            if entry_type in (1, 5) and child_id != _FREESECT:
                stack.append(child_id)

        for node_id in range(entry_count):
            entry_type = directory_bytes[node_id * 128 + 66]
            if entry_type not in (1, 2, 5) or reachable[node_id]:
                continue
            valid = False
            add_warning(
                f"Directory tree entry {node_id} is unreachable from root entry 0."
            )

    return valid, warnings


def analyze_legacy_office(path: str, max_bytes: int = 100 * 1024 * 1024) -> dict[str, Any]:
    """Inspect an OLE/CFB container without extracting or parsing stream contents."""
    file_input = read_file(path, max_bytes=max_bytes)
    data = file_input.data
    suffix = file_input.path.suffix.lower()
    if not data.startswith(OLE_SIGNATURE):
        message = "Input does not have the OLE/CFB signature; legacy Office structure was not parsed."
        report = _base_report(file_input, "failed" if suffix in LEGACY_FORMAT_EXTENSIONS else "unsupported", message)
        return report

    if len(data) < 512:
        return _base_report(file_input, "failed", "OLE/CFB file is shorter than the minimum 512-byte header.")

    warnings: list[str] = []
    partial = False
    major_version = struct.unpack_from("<H", data, 26)[0]
    byte_order = struct.unpack_from("<H", data, 28)[0]
    sector_shift = struct.unpack_from("<H", data, 30)[0]
    mini_sector_shift = struct.unpack_from("<H", data, 32)[0]
    if byte_order != 0xFFFE:
        return _base_report(file_input, "failed", "OLE/CFB byte-order marker is invalid.")
    if (major_version, sector_shift) not in ((3, 9), (4, 12)):
        return _base_report(file_input, "failed", "OLE/CFB version or sector-size fields are unsupported or invalid.")
    if mini_sector_shift != 6:
        return _base_report(file_input, "failed", "OLE/CFB mini-sector shift is invalid; expected 64-byte mini sectors.")

    mini_stream_cutoff = struct.unpack_from("<I", data, 56)[0]
    if mini_stream_cutoff != 4096:
        return _base_report(
            file_input,
            "failed",
            "OLE/CFB mini-stream cutoff is invalid; expected 4096 bytes.",
        )

    sector_size = 1 << sector_shift
    if len(data) < sector_size or (len(data) % sector_size):
        warnings.append("OLE/CFB byte length is not aligned to its declared sector size.")
        partial = True
    total_sectors = max(0, len(data) // sector_size - 1)
    if total_sectors > _MAX_CHAIN_SECTORS:
        return _base_report(file_input, "failed", "OLE/CFB sector count exceeds the configured traversal limit.")

    num_fat_sectors = struct.unpack_from("<I", data, 44)[0]
    first_directory_sector = struct.unpack_from("<I", data, 48)[0]
    first_mini_fat_sector = struct.unpack_from("<I", data, 60)[0]
    num_mini_fat_sectors = struct.unpack_from("<I", data, 64)[0]
    first_difat_sector = struct.unpack_from("<I", data, 68)[0]
    num_difat_sectors = struct.unpack_from("<I", data, 72)[0]
    if (
        num_fat_sectors > _MAX_FAT_SECTORS
        or num_difat_sectors > _MAX_DIFAT_SECTORS
        or num_mini_fat_sectors > _MAX_MINIFAT_SECTORS
    ):
        return _base_report(
            file_input,
            "failed",
            "OLE/CFB FAT or DIFAT count exceeds the configured structural limit, or MiniFAT count exceeds its configured limit.",
        )

    difat: list[int] = list(struct.unpack_from("<109I", data, 76))
    difat = [sid for sid in difat if sid not in (_FREESECT, _ENDOFCHAIN, _FATSECT, _DIFSECT)]
    current = first_difat_sector
    visited_difat: set[int] = set()
    per_difat = sector_size // 4
    for _ in range(min(num_difat_sectors, _MAX_DIFAT_SECTORS)):
        if current in (_ENDOFCHAIN, _FREESECT):
            break
        if current in visited_difat or current >= total_sectors:
            warnings.append("DIFAT chain contains a cycle or invalid sector reference.")
            partial = True
            break
        visited_difat.add(current)
        try:
            raw_sector = _read_sector(data, sector_size, current, total_sectors)
        except ValueError as exc:
            warnings.append(_safe_text(exc))
            partial = True
            break
        values = struct.unpack(f"<{per_difat}I", raw_sector)
        difat.extend(sid for sid in values[:-1] if sid not in (_FREESECT, _ENDOFCHAIN, _FATSECT, _DIFSECT))
        current = values[-1]
    if num_difat_sectors and current not in (_ENDOFCHAIN, _FREESECT) and len(visited_difat) >= num_difat_sectors:
        warnings.append("DIFAT chain did not terminate at the declared end.")
        partial = True

    fat_sector_ids = difat[:num_fat_sectors]
    if len(set(fat_sector_ids)) != len(fat_sector_ids):
        warnings.append("DIFAT contains duplicate FAT-sector identifiers; duplicate entries were ignored.")
        partial = True
        fat_sector_ids = list(dict.fromkeys(fat_sector_ids))
    if len(fat_sector_ids) < num_fat_sectors:
        warnings.append("Fewer FAT sectors were discoverable than the header declares.")
        partial = True
    fat_words: list[int] = []
    for sid in fat_sector_ids:
        if sid >= total_sectors:
            warnings.append("FAT references a sector outside the file.")
            partial = True
            continue
        try:
            fat_words.extend(struct.unpack(f"<{per_difat}I", _read_sector(data, sector_size, sid, total_sectors)))
        except (ValueError, struct.error) as exc:
            warnings.append(_safe_text(exc))
            partial = True

    for fat_sid in fat_sector_ids:
        if fat_sid < len(fat_words) and fat_words[fat_sid] != _FATSECT:
            warnings.append(f"FAT sector {fat_sid} is not marked as a FAT sector in the FAT table.")
            partial = True

    directory_bytes, chain_partial, chain_error = _follow_chain(
        first_directory_sector, fat_words, data, sector_size, total_sectors,
        max_sectors=min(_MAX_CHAIN_SECTORS, total_sectors), max_bytes=_MAX_DIRECTORY_BYTES,
    )
    if chain_partial:
        partial = True
        if chain_error:
            warnings.append(f"Directory chain: {chain_error}.")
    if not directory_bytes:
        message = "OLE/CFB directory stream is unavailable or empty."
        report = _base_report(file_input, "failed", message)
        analysis = report["legacy_office_analysis"]
        analysis["truncated"] = bool(chain_partial)
        analysis["features"]["directory_chain_truncated"] = bool(chain_partial)

        # Preserve structural errors discovered before the directory read failed.
        failure_warnings = [*warnings, message]
        analysis["warnings"] = list(dict.fromkeys(failure_warnings))
        report["warnings"] = list(dict.fromkeys([
            *failure_warnings,
            "Legacy Office analysis inspects bounded OLE/CFB header and directory metadata only; stream bodies and macros are not executed or extracted.",
        ]))
        return report

    entries, entries_truncated, parse_warnings = _parse_directory(
        directory_bytes,
        major_version=major_version,
    )
    warnings.extend(parse_warnings)

    directory_tree_valid, directory_tree_warnings = _validate_directory_references(
        directory_bytes,
        complete=(
            not chain_partial
            and not entries_truncated
            and len(directory_bytes) % 128 == 0
        ),
    )
    if len(directory_bytes) >= 128:
        root_left_sibling_id = struct.unpack_from(
            "<I", directory_bytes, 68
        )[0]
        root_right_sibling_id = struct.unpack_from(
            "<I", directory_bytes, 72
        )[0]
        if (
            root_left_sibling_id != _FREESECT
            or root_right_sibling_id != _FREESECT
        ):
            directory_tree_valid = False
            directory_tree_warnings.append(
                "Root directory entry has sibling references; "
                "left and right sibling IDs must both be NOSTREAM."
            )
    warnings.extend(directory_tree_warnings)
    if directory_tree_valid is False:
        partial = True

    inventory_truncated = entries_truncated or len(entries) > _MAX_INVENTORY

    if entries_truncated:
        warnings.append("Directory entry inventory was capped at the configured maximum.")
        partial = True
    if len(entries) > _MAX_INVENTORY:
        warnings.append(f"Directory inventory was capped at {_MAX_INVENTORY} entries.")
    if inventory_truncated:
        partial = True
    if parse_warnings:
        partial = True

    root_entries = [entry for entry in entries if entry["type"] == "root_storage"]
    root_entry_zero = next(
        (entry for entry in entries if entry["index"] == 0),
        None,
    )
    root_record_complete = len(directory_bytes) >= 128
    root_is_first = (
        root_record_complete
        and root_entry_zero is not None
        and root_entry_zero["type"] == "root_storage"
        and root_entry_zero["name"] == "Root Entry"
    )

    if root_record_complete and (not root_is_first or len(root_entries) > 1):
        message = (
            "OLE/CFB directory does not contain exactly one required Root Entry "
            "at directory entry zero."
        )
        report = _base_report(file_input, "failed", message)
        analysis = report["legacy_office_analysis"]
        analysis.update({
            "directory_entry_count": len(entries),
            "stream_count": sum(entry["type"] == "stream" for entry in entries),
            "storage_count": sum(
                entry["type"] in ("storage", "root_storage")
                for entry in entries
            ),
            "root_directory_entry_valid": False,
            "directory_chain_truncated": bool(chain_partial),
            "truncated": bool(partial or entries_truncated or inventory_truncated),
            "directory_inventory": entries[:_MAX_INVENTORY],
            "warnings": list(dict.fromkeys([*warnings, message])),
        })
        report["warnings"] = list(dict.fromkeys([
            *warnings,
            message,
            "Legacy Office analysis inspects bounded OLE/CFB header and directory metadata only; stream bodies and macros are not executed or extracted.",
        ]))
        return report

    if not root_record_complete:
        message = (
            "OLE/CFB root directory entry could not be validated because "
            "the directory stream ended before a complete first entry was available."
        )
        report = _base_report(file_input, "partial", message)
        analysis = report["legacy_office_analysis"]
        analysis.update({
            "directory_entry_count": len(entries),
            "stream_count": sum(entry["type"] == "stream" for entry in entries),
            "storage_count": sum(
                entry["type"] in ("storage", "root_storage")
                for entry in entries
            ),
            "root_directory_entry_valid": None,
            "directory_chain_truncated": bool(chain_partial),
            "truncated": True,
            "features": {
                "directory_chain_truncated": bool(chain_partial),
            },
            "directory_inventory": entries[:_MAX_INVENTORY],
            "warnings": list(dict.fromkeys([*warnings, message])),
        })
        report["warnings"] = list(dict.fromkeys([
            *warnings,
            message,
            "Legacy Office analysis inspects bounded OLE/CFB header and directory metadata only; stream bodies and macros are not executed or extracted.",
        ]))
        return report

    root_directory_entry_valid = None if chain_partial or entries_truncated else True

    # MiniFAT is stored in regular FAT sectors. Parse it only after the
    # directory Root Entry has been validated.
    mini_fat: list[int] = []
    mini_fat_status = "absent"
    mini_fat_error: str | None = None
    mini_fat_partial = False

    if num_mini_fat_sectors == 0:
        if first_mini_fat_sector not in (_ENDOFCHAIN, _FREESECT):
            mini_fat_status = "partial"
            mini_fat_partial = True
            mini_fat_error = (
                "MiniFAT start sector is allocated but the declared MiniFAT sector count is zero"
            )
    else:
        mini_fat_declared_bytes = num_mini_fat_sectors * sector_size
        if mini_fat_declared_bytes > _MAX_MINIFAT_BYTES:
            mini_fat_status = "partial"
            mini_fat_partial = True
            mini_fat_error = "declared MiniFAT exceeds the configured byte limit"
        else:
            mini_fat_bytes, mini_fat_partial, mini_fat_error = _read_declared_stream(
                first_mini_fat_sector,
                mini_fat_declared_bytes,
                fat_words,
                data,
                sector_size,
                total_sectors,
                max_sectors=min(num_mini_fat_sectors, total_sectors),
                max_bytes=_MAX_MINIFAT_BYTES,
            )
            if not mini_fat_partial and len(mini_fat_bytes) % 4 == 0:
                mini_fat = [
                    value[0]
                    for value in struct.iter_unpack("<I", mini_fat_bytes)
                ]
                mini_fat_status = "parsed"
            else:
                mini_fat_status = "partial"
                if mini_fat_error is None:
                    mini_fat_error = "MiniFAT byte length is not divisible by four"

    if mini_fat_partial:
        partial = True
        warnings.append(
            f"MiniFAT: {mini_fat_error or 'MiniFAT could not be parsed completely'}."
        )

    # The Root Entry stream backs mini-sector allocations. Reading it does
    # not interpret individual document streams.
    root_mini_stream = b""
    root_mini_stream_partial = False
    root_mini_stream_error: str | None = None
    root_mini_stream_status = "empty"
    root_mini_stream_declared_size = root_entry_zero["declared_size_bytes"]

    if root_mini_stream_declared_size:
        (
            root_mini_stream,
            root_mini_stream_partial,
            root_mini_stream_error,
        ) = _read_declared_stream(
            root_entry_zero["starting_sector"],
            root_mini_stream_declared_size,
            fat_words,
            data,
            sector_size,
            total_sectors,
            max_sectors=min(_MAX_CHAIN_SECTORS, total_sectors),
            max_bytes=_MAX_ROOT_MINI_STREAM_BYTES,
        )
        root_mini_stream_status = (
            "partial" if root_mini_stream_partial else "read"
        )
        if root_mini_stream_partial:
            partial = True
            warnings.append(
                "Root Mini Stream: "
                f"{root_mini_stream_error or 'root Mini Stream could not be read completely'}."
            )
        elif not mini_fat:
            partial = True
            root_mini_stream_status = "read_without_minifat"
            warnings.append(
                "Root Mini Stream is present, but no usable MiniFAT entries are available."
            )
    elif root_entry_zero["starting_sector"] not in (_ENDOFCHAIN, _FREESECT):
        partial = True
        root_mini_stream_partial = True
        root_mini_stream_status = "partial"
        root_mini_stream_error = (
            "zero-length Root Mini Stream has an allocated sector chain"
        )
        warnings.append(f"Root Mini Stream: {root_mini_stream_error}.")

    if mini_fat and not root_mini_stream:
        partial = True
        warnings.append(
            "MiniFAT entries are present, but the Root Mini Stream is empty or unavailable."
        )

    names_lower = [entry["name"].casefold() for entry in entries]
    names = set(names_lower)
    if "worddocument" in names:
        family, canonical = "word", "doc"
    elif "workbook" in names or "book" in names:
        family, canonical = "excel", "xls"
    elif "powerpoint document" in names:
        family, canonical = "powerpoint", "ppt"
    else:
        family, canonical = None, "unknown_ole_cfb"

    extension_family = {"doc": "word", "dot": "word", "xls": "excel", "xlt": "excel", "xla": "excel",
                        "ppt": "powerpoint", "pps": "powerpoint", "pot": "powerpoint"}.get(suffix.lstrip("."))
    detected_type = suffix.lstrip(".") if extension_family and extension_family == family else canonical
    if family is None:
        if "encryptedpackage" in names and "encryptioninfo" in names:
            message = "OLE/CFB container appears to wrap encrypted OOXML data; contents were not decrypted or parsed."
            status = "unsupported"
            detected_type = "encrypted_office_container"
        else:
            message = "OLE/CFB directory was inspected, but expected legacy Word, Excel, or PowerPoint stream names were not identified."
            status = "unsupported"
    else:
        message = "OLE/CFB header and directory metadata parsed; document stream bodies and macro code were not read."
        status = "partial" if partial else "parsed"
    if extension_family and family and extension_family != family:
        warnings.append(f"Filename extension {suffix} does not match the detected {family} stream family.")
        partial = True
        status = "partial"
    stream_entries = [entry for entry in entries if entry["type"] == "stream"]
    storage_entries = [entry for entry in entries if entry["type"] in ("storage", "root_storage")]
    parent_by_id = _build_directory_parent_map(
        entries,
        directory_tree_valid=(
            directory_tree_valid
            if not chain_partial and not entries_truncated and len(directory_bytes) % 128 == 0
            else None
        ),
    )
    entries_by_id = {entry["index"]: entry for entry in entries}
    root_children = {
        entry_id for entry_id, parent_id in (parent_by_id or {}).items()
        if parent_id == 0
    }
    vba_storage_entries = [
        entry for entry in entries
        if entry["index"] in root_children
        and entry["type"] == "storage"
        and entry["name"].casefold() == "vba"
    ]
    vba_storage_for_read = vba_storage_entries[0] if len(vba_storage_entries) == 1 else None
    vba_child_ids_for_read = {
        entry_id for entry_id, parent_id in (parent_by_id or {}).items()
        if vba_storage_for_read is not None and parent_id == vba_storage_for_read["index"]
    }
    vba_stream_data: dict[str, bytes] = {}

    # Read bounded stream contents only for structural validation. Raw bytes
    # are discarded immediately and are never included in the report.
    stream_inventory: list[dict[str, Any]] = []
    stream_bytes_reserved = 0
    stream_read_count = 0
    stream_skipped_count = 0
    stream_partial_count = 0
    stream_inventory_truncated = len(stream_entries) > _MAX_STREAMS_TO_READ

    for entry in stream_entries[:_MAX_STREAMS_TO_READ]:
        declared_size = entry["declared_size_bytes"]
        first_sector = entry["starting_sector"]
        allocation = "mini" if declared_size < mini_stream_cutoff else "regular"

        item: dict[str, Any] = {
            "index": entry["index"],
            "name": entry["name"],
            "allocation": allocation,
            "declared_size_bytes": declared_size,
            "bytes_read": 0,
            "status": "skipped",
            "error": None,
            "content_status": "not_inspected",
            "content_kind": None,
            "content_signature": None,
            "content_bytes_inspected": 0,
        }

        if declared_size > _MAX_STREAM_BYTES:
            item["error"] = "declared stream exceeds per-stream byte limit"
            stream_skipped_count += 1
            stream_inventory.append(item)
            continue

        if declared_size > _MAX_TOTAL_STREAM_BYTES - stream_bytes_reserved:
            item["error"] = "aggregate stream byte budget exhausted"
            stream_skipped_count += 1
            stream_inventory.append(item)
            continue

        # Reserve the full declared size before attempting a read. Failed
        # chains therefore cannot be used to bypass the aggregate budget.
        stream_bytes_reserved += declared_size

        # Empty streams have no allocation chain to follow. Their starting
        # sector must nevertheless use a valid empty-chain marker.
        if declared_size == 0:
            stream_data = b""
            stream_partial = False
            stream_error = None
            if first_sector not in (_ENDOFCHAIN, _FREESECT):
                stream_partial = True
                stream_error = "zero-length stream has an allocated sector chain"
        elif allocation == "mini":
            if mini_fat_status != "parsed" or root_mini_stream_status != "read":
                stream_data = b""
                stream_error = "MiniFAT or Root Mini Stream is unavailable"
                stream_partial = True
            else:
                stream_data, stream_partial, stream_error = _read_declared_mini_stream(
                    first_sector,
                    declared_size,
                    mini_fat,
                    root_mini_stream,
                    max_sectors=min(_MAX_CHAIN_SECTORS, len(mini_fat)),
                    max_bytes=_MAX_STREAM_BYTES,
                    mini_sector_size=1 << mini_sector_shift,
                )
        else:
            stream_data, stream_partial, stream_error = _read_declared_stream(
                first_sector,
                declared_size,
                fat_words,
                data,
                sector_size,
                total_sectors,
                max_sectors=min(_MAX_CHAIN_SECTORS, total_sectors),
                max_bytes=_MAX_STREAM_BYTES,
            )

        item["bytes_read"] = len(stream_data)

        signature_prefix = stream_data[:MAX_CONTENT_SIGNATURE_BYTES]
        item["content_bytes_inspected"] = len(signature_prefix)

        if not signature_prefix:
            item["content_status"] = "empty"
        else:
            identified = identify_content_signature(signature_prefix)
            if identified is None:
                item["content_status"] = "unrecognized"
            else:
                item["content_status"] = "identified"
                item["content_kind"], item["content_signature"] = identified

        item["status"] = "partial" if stream_partial else "read"
        item["error"] = stream_error

        if stream_partial:
            stream_partial_count += 1
            warnings.append(
                f"Stream {entry['name']!r}: "
                f"{stream_error or 'stream could not be read completely'}."
            )
        else:
            stream_read_count += 1

        stream_inventory.append(item)
        if (
            not stream_partial
            and entry["index"] in vba_child_ids_for_read
            and len(vba_stream_data) < 256
        ):
            vba_stream_data[entry["name"].casefold()] = stream_data
        del stream_data

    if stream_inventory_truncated:
        warnings.append(
            f"Stream inventory was limited to {_MAX_STREAMS_TO_READ} entries."
        )

    if stream_skipped_count:
        warnings.append(
            f"{stream_skipped_count} stream(s) were skipped due to configured resource limits."
        )

    vba_related_names = {"vba", "dir", "_vba_project", "project", "projectwm", "projectlk"}
    stream_names = {entry["name"].casefold() for entry in stream_entries}
    storage_names = {entry["name"].casefold() for entry in storage_entries}
    vba_storage = vba_storage_for_read
    root_project_stream_present = any(
        entry_id in entries_by_id
        and entries_by_id[entry_id]["type"] == "stream"
        and entries_by_id[entry_id]["name"].casefold() == "project"
        for entry_id in root_children
    )
    vba_children = {
        entry_id for entry_id, parent_id in (parent_by_id or {}).items()
        if vba_storage is not None and parent_id == vba_storage["index"]
    }
    vba_child_names = {
        entries_by_id[entry_id]["name"].casefold()
        for entry_id in vba_children
        if entry_id in entries_by_id and entries_by_id[entry_id]["type"] == "stream"
    }
    vba_required_streams_present = {"_vba_project", "dir"}.issubset(vba_child_names)
    vba_present = bool(
        vba_storage and root_project_stream_present and vba_required_streams_present
    )
    if parent_by_id is None:
        vba_structure_status = "indeterminate"
    elif vba_present:
        vba_structure_status = "required_entries_present"
    elif vba_storage or "vba" in storage_names:
        vba_structure_status = "incomplete"
    else:
        vba_structure_status = "not_found"

    vba_dir_status = "not_available"
    vba_modules: list[dict[str, Any]] = []
    vba_module_streams_present = False
    vba_module_streams_complete = False
    if vba_present:
        dir_data = vba_stream_data.get("dir")
        if dir_data:
            try:
                decompressed_dir = _decompress_vba_container(dir_data)
                vba_modules = _parse_vba_module_block(decompressed_dir)
                vba_dir_status = "parsed"
                module_entries_present = []
                module_checks = []
                for module in vba_modules:
                    module_stream = vba_stream_data.get(module["stream_name"].casefold())
                    module_entry = next((
                        entry for entry in entries
                        if entry["index"] in vba_child_ids_for_read
                        and entry["type"] == "stream"
                        and entry["name"].casefold() == module["stream_name"].casefold()
                    ), None)
                    if module_entry is None:
                        module_entries_present.append(False)
                        module_checks.append(False)
                        continue
                    module_entries_present.append(True)
                    stream_size = module_entry["declared_size_bytes"]
                    source_offset = module["source_offset"]
                    module_checks.append(
                        module_stream is not None
                        and source_offset < stream_size
                        and len(module_stream) == stream_size
                        and module_stream[source_offset:source_offset + 1] == b"\x01"
                    )
                vba_module_streams_present = (
                    bool(vba_modules)
                    and len(module_entries_present) == len(vba_modules)
                    and all(module_entries_present)
                )
                vba_module_streams_complete = (
                    bool(vba_modules)
                    and len(module_checks) == len(vba_modules)
                    and all(module_checks)
                )
            except ValueError as exc:
                vba_dir_status = "invalid"
                warnings.append(f"VBA dir stream could not be validated: {_safe_text(exc)}.")
        else:
            vba_dir_status = "unavailable"

    if parent_by_id is None:
        vba_validation_status = "indeterminate"
    elif not vba_storage:
        vba_validation_status = "not_found"
    elif not vba_present:
        vba_validation_status = "incomplete"
    elif vba_dir_status == "invalid":
        vba_validation_status = "invalid_dir_stream"
    elif vba_dir_status != "parsed":
        vba_validation_status = "dir_stream_unavailable"
    elif not vba_module_streams_present:
        vba_validation_status = "module_streams_missing"
    elif not vba_module_streams_complete:
        vba_validation_status = "module_streams_unverified"
    else:
        vba_validation_status = "module_streams_confirmed"

    encrypted_container = {"encryptedpackage", "encryptioninfo"}.issubset(names)
    embedded_entries = [entry for entry in entries if (
        entry["name"].casefold().startswith("mbd") or entry["name"].casefold() in {"objectpool", "ole10native"}
        or "object" in entry["name"].casefold() and entry["type"] == "storage"
    )]
    external_link_names = {"externsheet", "supbook", "linkinfo", "linktable"} & names
    features = {
        "vba_project_present": bool(vba_present),
        "vba_related_directory_entry_count": sum(1 for n in names_lower if n in vba_related_names),
        "vba_project_stream_name_present": "_vba_project" in stream_names,
        "vba_directory_stream_name_present": "dir" in stream_names,
        "vba_project_metadata_stream_name_present": "project" in stream_names,
        "vba_storage_name_present": "vba" in storage_names,
        "vba_storage_at_root_present": vba_storage is not None,
        "vba_required_streams_present": bool(vba_required_streams_present),
        "vba_root_project_stream_present": bool(root_project_stream_present),
        "vba_dir_stream_parsed": vba_dir_status == "parsed",
        "vba_module_count": len(vba_modules),
        "vba_module_streams_present": bool(vba_module_streams_present),
        "vba_module_streams_complete": bool(vba_module_streams_complete),
        "vba_project_metadata_validated": vba_validation_status == "module_streams_confirmed",
        "vba_project_workspace_stream_name_present": "projectwm" in stream_names,
        "vba_project_link_stream_name_present": "projectlk" in stream_names,
        "embedded_object_indicator_count": len(embedded_entries),
        "external_link_stream_name_count": len(external_link_names),
        "encrypted_office_container_present": bool(encrypted_container),
        "directory_chain_truncated": bool(chain_partial),
        "directory_inventory_truncated": bool(inventory_truncated),
        "mini_fat_truncated": bool(mini_fat_partial),
        "root_mini_stream_truncated": bool(root_mini_stream_partial),
        "stream_inventory_truncated": bool(stream_inventory_truncated),
        "stream_read_partial": bool(stream_partial_count),
    }
    if family is None:
        # The directory metadata is still useful even when stream-family identity is unknown.
        file_type = detected_type
    else:
        file_type = detected_type

    if suffix in LEGACY_FORMAT_EXTENSIONS:
        expected_ext_family = {
            ".doc": "word", ".dot": "word",
            ".xls": "excel", ".xlt": "excel", ".xla": "excel",
            ".ppt": "powerpoint", ".pps": "powerpoint", ".pot": "powerpoint",
        }.get(suffix)
        extension_matches = expected_ext_family == family
    else:
        extension_matches = bool(extension_family and extension_family == family)
    if not extension_matches and suffix:
        warnings.append(f"Filename extension {suffix} does not reliably match the detected CFB document family.")
        if family is not None:
            partial = True
            status = "partial"

    if vba_present:
        if vba_dir_status == "parsed" and vba_module_streams_complete:
            warnings.append(
                "VBA dir records were parsed and every declared module stream was found with a bounded "
                "source-container signature check; module source code was not decompressed or interpreted."
            )
        elif vba_dir_status == "parsed":
            warnings.append(
                "VBA dir records were parsed, but one or more declared module streams could not be confirmed; "
                "full VBA project validity is unverified."
            )
        else:
            warnings.append(
                "VBA root and storage hierarchy entries are present, but the dir stream could not be fully parsed; "
                "full VBA project validity is unverified."
            )
    warnings.append(
        "CFB stream bodies were read only within strict resource limits for structural validation; "
        "VBA source and embedded content were not interpreted or executed."
    )
    if family is None and status == "unsupported":
        warnings.insert(0, message)

    report = {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                 "sha256": file_input.sha256, "file_type": file_type},
        "assessment": {"verdict": "not_assessed",
                       "reason": "Legacy Office CFB observations are contextual metadata; bounded stream reads are used only for structural validation, and no macro or document content is interpreted or executed."},
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256},
        "legacy_office_analysis": {
            "status": status, "family": family, "format_id": detected_type,
            "container_format": "OLE Compound File Binary (CFB)",
            "major_version": major_version, "byte_order_valid": byte_order == 0xFFFE,
            "sector_size": sector_size, "mini_sector_size": 1 << mini_sector_shift if mini_sector_shift < 16 else None,
            "physical_sector_count": total_sectors, "fat_sector_count_declared": num_fat_sectors,
            "difat_sector_count_declared": num_difat_sectors,
            "mini_fat_sector_count_declared": num_mini_fat_sectors,
            "mini_fat_entry_count": len(mini_fat),
            "mini_fat_status": mini_fat_status,
            "mini_fat_error": mini_fat_error,
            "root_mini_stream_size_declared": root_mini_stream_declared_size,
            "root_mini_stream_bytes_read": len(root_mini_stream),
            "root_mini_stream_status": root_mini_stream_status,
            "root_mini_stream_error": root_mini_stream_error,
            "stream_inventory": stream_inventory,
            "stream_read_count": stream_read_count,
            "stream_skipped_count": stream_skipped_count,
            "stream_partial_count": stream_partial_count,
            "stream_bytes_reserved": stream_bytes_reserved,
            "stream_inventory_truncated": stream_inventory_truncated,
            "directory_entry_count": len(entries), "stream_count": len(stream_entries),
            "storage_count": len(storage_entries), "directory_chain_truncated": chain_partial,
            "directory_tree_valid": directory_tree_valid,
            "root_directory_entry_valid": root_directory_entry_valid,
            "truncated": bool(partial or entries_truncated or inventory_truncated),
            "macro_enabled_format": bool(vba_present), "vba_project_present": bool(vba_present),
            "vba_project_structure_status": vba_structure_status,
            "vba_project_validation_status": vba_validation_status,
            "vba_dir_stream_status": vba_dir_status,
            "vba_module_count": len(vba_modules),
            "vba_modules": [
                {"name": module["name"], "stream_name": module["stream_name"],
                 "source_offset": module["source_offset"], "module_type": module["module_type"]}
                for module in vba_modules[:256]
            ],
            "encrypted_content_present": bool(encrypted_container),
            "extension_matches_detected_family": extension_matches,
            "features": features,
            "directory_inventory": entries[:_MAX_INVENTORY],
            "warnings": list(dict.fromkeys(warnings)),
        },
        "evidence": [
            {"evidence_type": "legacy_office_container", "key": "legacy_office.container_status", "value": status,
             "severity": "warning" if status != "parsed" else "info",
             "details": {"interpretation": message, "container_format": "OLE CFB"}},
            {"evidence_type": "legacy_office_container", "key": "legacy_office.detected_family", "value": family or "unknown",
             "severity": "info", "details": {"format_id": detected_type, "extension_matches_detected_family": extension_matches}},
        ],
        "warnings": list(dict.fromkeys([message, *warnings,
            "Legacy Office stream bodies and macros are never executed, opened, or extracted by this analyzer."])),
    }
    for key, value in features.items():
        if value:
            if key in {
                "vba_dir_stream_parsed", "vba_module_count",
                "vba_module_streams_present", "vba_module_streams_complete",
                "vba_project_metadata_validated",
            }:
                interpretation = (
                    "Bounded VBA metadata or module-stream structure observation; "
                    "VBA source code was not interpreted or executed."
                )
            else:
                interpretation = (
                    "Directory-name or container-structure indicator only; "
                    "it is not proof of maliciousness."
                )
            report["evidence"].append({
                "evidence_type": "legacy_office_indicator", "key": f"legacy_office.{key}", "value": value,
                "severity": "info", "details": {"context_only": True, "interpretation": interpretation},
            })
    return report
