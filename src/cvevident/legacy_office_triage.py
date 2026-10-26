"""Bounded, static directory-level triage for legacy OLE/CFB Office files.

This module does not extract or interpret document stream bodies. It validates a
bounded subset of the Compound File Binary container and inventories directory
entry names/sizes to identify Word/Excel/PowerPoint families and macro/embedding
indicators. It is not a full OLE parser or a malware verdict.
"""
from __future__ import annotations

import struct
from collections import Counter
from typing import Any

from .file_input import read_file

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
_MAX_DIRECTORY_BYTES = 8 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 65536
_MAX_CHAIN_SECTORS = 200000
_MAX_INVENTORY = 300


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
            "stream_count": 0, "storage_count": 0, "truncated": False,
            "features": {}, "directory_inventory": [], "warnings": [message],
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


def _parse_directory(directory_bytes: bytes) -> tuple[list[dict[str, Any]], bool, list[str]]:
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
    if struct.unpack_from("<H", data, 32)[0] != 6:
        return _base_report(file_input, "failed", "OLE/CFB mini-sector shift is invalid; expected 64-byte mini sectors.")
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
    if num_fat_sectors > _MAX_FAT_SECTORS or num_difat_sectors > _MAX_DIFAT_SECTORS:
        return _base_report(file_input, "failed", "OLE/CFB FAT or DIFAT count exceeds the configured structural limit.")

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

    entries, entries_truncated, parse_warnings = _parse_directory(directory_bytes)
    warnings.extend(parse_warnings)

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
    vba_related_names = {"vba", "dir", "_vba_project", "project", "projectwm"}
    vba_present = "vba" in names or {"_vba_project", "project"}.issubset(names) or "projectwm" in names
    encrypted_container = {"encryptedpackage", "encryptioninfo"}.issubset(names)
    embedded_entries = [entry for entry in entries if (
        entry["name"].casefold().startswith("mbd") or entry["name"].casefold() in {"objectpool", "ole10native"}
        or "object" in entry["name"].casefold() and entry["type"] == "storage"
    )]
    external_link_names = {"externsheet", "supbook", "linkinfo", "linktable"} & names
    features = {
        "vba_project_present": bool(vba_present),
        "vba_related_directory_entry_count": sum(1 for n in names_lower if n in vba_related_names),
        "embedded_object_indicator_count": len(embedded_entries),
        "external_link_stream_name_count": len(external_link_names),
        "encrypted_office_container_present": bool(encrypted_container),
        "directory_chain_truncated": bool(chain_partial),
        "directory_inventory_truncated": bool(inventory_truncated),
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

    warnings.append("CFB directory stream names are indicators only; stream bodies, VBA source, and OLE embedded content were not read or executed.")
    if family is None and status == "unsupported":
        warnings.insert(0, message)

    report = {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                 "sha256": file_input.sha256, "file_type": file_type},
        "assessment": {"verdict": "not_assessed",
                       "reason": "Legacy Office CFB observations are contextual metadata only; no macro or document stream was interpreted."},
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256},
        "legacy_office_analysis": {
            "status": status, "family": family, "format_id": detected_type,
            "container_format": "OLE Compound File Binary (CFB)",
            "major_version": major_version, "byte_order_valid": byte_order == 0xFFFE,
            "sector_size": sector_size, "mini_sector_size": 1 << mini_sector_shift if mini_sector_shift < 16 else None,
            "physical_sector_count": total_sectors, "fat_sector_count_declared": num_fat_sectors,
            "difat_sector_count_declared": num_difat_sectors,
            "mini_fat_sector_count_declared": num_mini_fat_sectors,
            "directory_entry_count": len(entries), "stream_count": len(stream_entries),
            "storage_count": len(storage_entries), "directory_chain_truncated": chain_partial,
            "truncated": bool(partial or entries_truncated or inventory_truncated),
            "macro_enabled_format": bool(vba_present), "vba_project_present": bool(vba_present),
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
            report["evidence"].append({
                "evidence_type": "legacy_office_indicator", "key": f"legacy_office.{key}", "value": value,
                "severity": "info", "details": {"context_only": True, "interpretation": "Directory-name indicator only; stream content was not inspected."},
            })
    return report
