"""Bounded, static lexical/structural triage for Rich Text Format (RTF)."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .file_input import read_file

RTF_EXTENSIONS = {".rtf"}
RTF_HEADER = re.compile(rb"^\s*\{\\rtf([0-9]+)(?=[\\\s{}])", re.I)
MAX_RTF_SCAN_BYTES = 16 * 1024 * 1024
MAX_RTF_GROUP_DEPTH = 4096
MAX_RTF_CONTROL_WORDS = 1_000_000

_CONTROL_INDICATORS = {
    "object", "objdata", "objclass", "objname", "objtime", "objupdate", "objautlink", "objemb", "objlink",
    "pict", "shppict", "nonshppict", "field", "fldinst", "fldrslt", "fldpriv", "datafield",
    "formfield", "filetbl", "xmlopen", "htmltag", "htmlrtf", "htmlbase", "datastore", "bin",
}
_FIELD_RISK_WORDS = re.compile(rb"(?i)\b(?:DDEAUTO|DDE|INCLUDETEXT|INCLUDEPICTURE|HYPERLINK|DATABASE|IMPORT|LINK)\b")
_URL_LITERAL = re.compile(rb"(?i)(?:https?|ftp|file|mailto|smb):[^\s\"'<>}{]{1,2048}|\\\\[^\s\"'<>}{]{1,2048}")
_CONTROL_WORD_START = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_HEX = frozenset(b"0123456789abcdefABCDEF")


def has_rtf_signature(data: bytes) -> bool:
    """Return whether the bounded prefix has a recognizable RTF header."""
    return bool(RTF_HEADER.match(data[:128]))


def _safe_text(value: Any, limit: int = 300) -> str:
    text = "" if value is None else str(value)
    text = "".join(ch if ch >= " " and ch not in "\x7f" else " " for ch in text)
    return " ".join(text.split())[:limit]


def _base_report(file_input: Any, status: str, message: str, file_type: str = "unknown_or_non_rtf") -> dict[str, Any]:
    return {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                 "sha256": file_input.sha256, "file_type": file_type},
        "assessment": {"verdict": "not_assessed",
                       "reason": "RTF observations are lexical and structural context only; no content is executed or treated as a malware verdict."},
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256},
        "rtf_analysis": {"status": status, "header_found": False, "rtf_version": None,
                         "bytes_scanned": 0, "group_balance": None, "maximum_group_depth": 0,
                         "features": {}, "field_instruction_examples": [], "truncated": False,
                         "warnings": [message]},
        "evidence": [
            {"evidence_type": "file_identity", "key": "sha256", "value": file_input.sha256,
             "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"}},
            {"evidence_type": "file_identity", "key": "file_size_bytes", "value": file_input.size_bytes,
             "severity": "info", "details": {"meaning": "input bytes read within configured limit"}},
            {"evidence_type": "rtf_status", "key": "rtf.status", "value": status,
             "severity": "warning", "details": {"interpretation": message}},
        ],
        "warnings": [message, "RTF indicators are static observations; OLE objects, embedded content and field targets are not opened or executed."],
    }


def _scan_rtf(data: bytes) -> dict[str, Any]:
    controls: Counter[str] = Counter()
    field_text = bytearray()
    depth = 0
    max_depth = 0
    negative_balance = False
    binary_truncated = False
    depth_limited = False
    i = 0
    scanned_control_count = 0
    # Stack marks whether the current group is a \fldinst destination. A nested group
    # inherits that state; \fldinst changes the top group only.
    fldinst_stack: list[bool] = []
    while i < len(data):
        byte = data[i]
        if byte == 0x7B:  # {
            depth += 1
            max_depth = max(max_depth, depth)
            if depth > MAX_RTF_GROUP_DEPTH:
                depth_limited = True
                break
            fldinst_stack.append(fldinst_stack[-1] if fldinst_stack else False)
            i += 1
            continue
        if byte == 0x7D:  # }
            if depth == 0:
                negative_balance = True
            else:
                depth -= 1
            if fldinst_stack:
                fldinst_stack.pop()
            i += 1
            continue
        if byte != 0x5C:  # backslash
            if fldinst_stack and fldinst_stack[-1]:
                field_text.append(byte)
            i += 1
            continue

        if i + 1 >= len(data):
            i += 1
            continue
        nxt = data[i + 1]
        # Escaped braces/backslash are literal text. Hex escapes are decoded only into
        # field text for safe target inspection; bytes in \binN payloads are skipped.
        if nxt in (0x5C, 0x7B, 0x7D):
            if fldinst_stack and fldinst_stack[-1]:
                field_text.append(nxt)
            i += 2
            continue
        if nxt == 0x27 and i + 3 < len(data) and data[i + 2] in _HEX and data[i + 3] in _HEX:
            if fldinst_stack and fldinst_stack[-1]:
                try:
                    field_text.append(int(data[i + 2:i + 4].decode("ascii"), 16))
                except ValueError:
                    pass
            i += 4
            continue
        if nxt not in _CONTROL_WORD_START:
            # Control symbol such as \*, \~, \-, or escaped punctuation.
            if nxt == 0x2A and fldinst_stack:
                # Destination marker; it does not itself change field context.
                pass
            elif fldinst_stack and fldinst_stack[-1] and nxt in (0x7E, 0x5F, 0x2D):
                field_text.append(0x20)
            i += 2
            continue

        start = i + 1
        j = start
        while j < len(data) and data[j] in _CONTROL_WORD_START:
            j += 1
        word = data[start:j].decode("ascii", errors="ignore").lower()
        sign = 1
        if j < len(data) and data[j] == 0x2D:
            sign = -1
            j += 1
        digits_start = j
        while j < len(data) and 0x30 <= data[j] <= 0x39 and j - digits_start < 12:
            j += 1
        parameter = sign * int(data[digits_start:j]) if j > digits_start else None
        if j < len(data) and data[j] == 0x20:
            j += 1
        scanned_control_count += 1
        if word in _CONTROL_INDICATORS:
            controls[word] += 1
        if word == "fldinst" and fldinst_stack:
            fldinst_stack[-1] = True
        if word == "bin" and parameter is not None and parameter >= 0:
            # The delimiter space (if present) was consumed above. Binary payload
            # bytes are not tokenized, avoiding false indicators inside embedded data.
            if parameter > len(data) - j:
                binary_truncated = True
                break
            i = j + parameter
        else:
            if fldinst_stack and fldinst_stack[-1] and word not in {"fldinst"}:
                field_text.extend(b" ")
            i = j
        if scanned_control_count > MAX_RTF_CONTROL_WORDS:
            break

    field_instructions = bytes(field_text)
    risk_word_count = sum(1 for _ in _FIELD_RISK_WORDS.finditer(field_instructions))
    url_count = sum(1 for _ in _URL_LITERAL.finditer(field_instructions))
    field_examples: list[str] = []
    segment_start = 0
    for separator in re.finditer(rb"[\r\n\x00]+", field_instructions):
        segment = field_instructions[segment_start:separator.start()]
        segment_start = separator.end()
        if segment.strip():
            field_examples.append(
                _safe_text(segment.decode("latin-1", errors="replace"), 240)
            )
            if len(field_examples) >= 10:
                break
    else:
        segment = field_instructions[segment_start:]
        if segment.strip() and len(field_examples) < 10:
            field_examples.append(
                _safe_text(segment.decode("latin-1", errors="replace"), 240)
            )
    return {
        "control_counts": dict(controls),
        "field_instruction_examples": field_examples,
        "field_instruction_indicator_count": risk_word_count,
        "external_target_count": url_count,
        "group_balance": None if negative_balance else depth,
        "maximum_group_depth": max_depth,
        "negative_group_balance": negative_balance,
        "binary_payload_truncated": binary_truncated,
        "depth_limit_reached": depth_limited,
        "control_word_limit_reached": scanned_control_count > MAX_RTF_CONTROL_WORDS,
        "field_instructions_scanned_bytes": len(field_instructions),
    }


def analyze_rtf(path: str, max_bytes: int = 100 * 1024 * 1024,
                *, max_scan_bytes: int = MAX_RTF_SCAN_BYTES) -> dict[str, Any]:
    if max_scan_bytes < 1:
        raise ValueError("max_scan_bytes must be positive")
    file_input = read_file(path, max_bytes=max_bytes)
    data = file_input.data
    suffix = file_input.path.suffix.lower()
    header_match = RTF_HEADER.match(data[:128])
    has_signature = bool(header_match)
    if not has_signature:
        message = "Input does not begin with a recognizable RTF header; RTF structure was not analyzed."
        report = _base_report(file_input, "failed" if suffix == ".rtf" else "unsupported", message)
        report["rtf_analysis"]["bytes_scanned"] = min(len(data), max_scan_bytes)
        report["warnings"].append("An RTF extension alone is not proof that the content is RTF.")
        return report

    scan_data = data[:max_scan_bytes]
    scan = _scan_rtf(scan_data)
    rtf_version = int(header_match.group(1)) if header_match else None
    truncated = len(data) > len(scan_data) or scan["binary_payload_truncated"] or scan["depth_limit_reached"] or scan["control_word_limit_reached"]
    warnings: list[str] = []
    if len(data) > len(scan_data):
        warnings.append(f"RTF scan was capped at {len(scan_data)} bytes; later content was not inspected.")
    if scan["binary_payload_truncated"]:
        warnings.append("An RTF \\binN payload declared more bytes than remained in the scanned range.")
    if scan["depth_limit_reached"]:
        warnings.append("RTF group nesting limit reached; remaining content was not inspected.")
    if scan["control_word_limit_reached"]:
        warnings.append("RTF control-word limit reached; remaining content was not inspected.")
    if scan["negative_group_balance"] or (scan["group_balance"] and not truncated):
        warnings.append("RTF brace/group balance is invalid or incomplete.")
    if suffix and suffix != ".rtf":
        warnings.append(f"File extension {suffix} differs from the detected RTF content.")
    status = "partial" if truncated or warnings else "parsed"
    features: dict[str, Any] = {f"{name}_control_count": count for name, count in scan["control_counts"].items()}
    features.update({
        "object_group_indicator_count": sum(scan["control_counts"].get(k, 0) for k in ("object", "objdata", "objemb", "objlink", "objautlink")),
        "picture_group_indicator_count": sum(scan["control_counts"].get(k, 0) for k in ("pict", "shppict", "nonshppict")),
        "field_instruction_group_count": scan["control_counts"].get("fldinst", 0),
        "field_instruction_indicator_count": scan["field_instruction_indicator_count"],
        "external_target_count": scan["external_target_count"],
    })
    report = {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                 "sha256": file_input.sha256, "file_type": "rtf"},
        "assessment": {"verdict": "not_assessed",
                       "reason": "RTF control words and field strings are contextual observations, not a malware verdict."},
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256,
                    "rtf_bytes_scanned": len(scan_data)},
        "rtf_analysis": {
            "status": status, "header_found": True,
            "rtf_version": rtf_version,
            "bytes_scanned": len(scan_data), "group_balance": scan["group_balance"],
            "maximum_group_depth": scan["maximum_group_depth"], "features": features,
            "field_instruction_examples": scan["field_instruction_examples"], "truncated": truncated,
            "warnings": list(dict.fromkeys(warnings)),
        },
        "evidence": [
            {"evidence_type": "file_identity", "key": "sha256", "value": file_input.sha256,
             "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"}},
            {"evidence_type": "file_identity", "key": "file_size_bytes", "value": file_input.size_bytes,
             "severity": "info", "details": {"meaning": "file size in bytes"}},
            {"evidence_type": "rtf_structure", "key": "rtf.header", "value": "found", "severity": "info",
             "details": {"rtf_version": rtf_version}},
            {"evidence_type": "rtf_structure", "key": "rtf.status", "value": status,
             "severity": "warning" if status != "parsed" else "info",
             "details": {"bytes_scanned": len(scan_data), "truncated": truncated, "context_only": True}},
        ],
        "warnings": list(dict.fromkeys([
            "RTF field instructions, object/picture groups and external-target strings are static indicators, not proof of maliciousness.",
            "OLE/object data, field targets and external resources were not executed, opened, extracted, or fetched.", *warnings,
        ])),
    }
    for key, value in features.items():
        if value:
            report["evidence"].append({"evidence_type": "rtf_indicator", "key": f"rtf.{key}", "value": value,
                "severity": "info", "details": {"context_only": True,
                "interpretation": "RTF lexical/group indicator only; it does not establish maliciousness."}})
    return report
