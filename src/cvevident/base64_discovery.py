from __future__ import annotations

import base64
import binascii
import hashlib
import mmap
import re
import tempfile
from typing import Any

_MAX_CANDIDATES = 128
_MAX_ENCODED_BYTES = 1024 * 1024
_MAX_DECODED_BYTES = 1024 * 1024
_MAX_TOTAL_DECODED_BYTES = 4 * 1024 * 1024
_MIN_ENCODED_LENGTH = 32
_MAX_WHITESPACE_GAP = 4

_BASE64_WHITESPACE = frozenset((0x09, 0x0A, 0x0D))


_SCAN_CHUNK_BYTES = 4096
_BASE64_CHUNK_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9+/=_-])"
    rb"[A-Za-z0-9+/_-]"
    rb"(?:[A-Za-z0-9+/_-]|[\t\r\n]{1,4}(?=[A-Za-z0-9+/_-]))*"
    rb"(?:=+)?"
    rb"(?![A-Za-z0-9+/=_-])"
)
_SCAN_BOUNDARY_OVERLAP_BYTES = _MAX_WHITESPACE_GAP + 4



def _is_base64_alphabet(value: int) -> bool:
    return (
        0x41 <= value <= 0x5A
        or 0x61 <= value <= 0x7A
        or 0x30 <= value <= 0x39
        or value in (0x2B, 0x2F, 0x2D, 0x5F)
    )


def _is_candidate_byte(value: int) -> bool:
    return _is_base64_alphabet(value) or value == 0x3D


def _count_encoded_bytes(data, start: int, end: int) -> int:
    count = 0
    tab = bytes((0x09,))
    carriage_return = bytes((0x0D,))
    line_feed = bytes((0x0A,))

    for offset in range(start, end, _SCAN_CHUNK_BYTES):
        chunk_end = min(offset + _SCAN_CHUNK_BYTES, end)
        segment = bytes(data[offset:chunk_end])
        count += (
            len(segment)
            - segment.count(tab)
            - segment.count(carriage_return)
            - segment.count(line_feed)
        )

    return count


def _candidate_spans(
    data: bytes | bytearray | memoryview,
    min_encoded_length: int,
):
    pending_start = None
    pending_end = None
    pending_encoded_length = 0
    pending_padded = False

    for chunk_start in range(0, len(data), _SCAN_CHUNK_BYTES):
        primary_end = min(
            chunk_start + _SCAN_CHUNK_BYTES,
            len(data),
        )
        scan_end = min(
            primary_end + _SCAN_BOUNDARY_OVERLAP_BYTES,
            len(data),
        )
        chunk = data[chunk_start:scan_end]

        for match in _BASE64_CHUNK_PATTERN.finditer(chunk):
            local_start, local_end = match.span()
            start = chunk_start + local_start
            end = chunk_start + local_end

            if start >= primary_end:
                continue

            if pending_start is None:
                encoded_length = _count_encoded_bytes(data, start, end)
                pending_start = start
                pending_end = end
                pending_encoded_length = encoded_length
                pending_padded = data[end - 1] == 0x3D
                continue

            if start < pending_end:
                if end > pending_end:
                    pending_encoded_length += _count_encoded_bytes(
                        data, pending_end, end
                    )
                    pending_end = end

                pending_padded = data[pending_end - 1] == 0x3D
                continue

            encoded_length = _count_encoded_bytes(data, start, end)
            gap_length = start - pending_end
            joinable = (
                not pending_padded
                and 0 <= gap_length <= _MAX_WHITESPACE_GAP
                and all(
                    data[index] in _BASE64_WHITESPACE
                    for index in range(pending_end, start)
                )
            )

            if joinable:
                pending_end = end
                pending_encoded_length += encoded_length
                pending_padded = data[end - 1] == 0x3D
                continue

            if pending_encoded_length >= min_encoded_length:
                yield pending_start, pending_end, pending_encoded_length

            pending_start = start
            pending_end = end
            pending_encoded_length = encoded_length
            pending_padded = data[end - 1] == 0x3D

    if (
        pending_start is not None
        and pending_encoded_length >= min_encoded_length
    ):
        yield pending_start, pending_end, pending_encoded_length


def _decode_candidate(encoded: bytes) -> tuple[bytes, str] | None:
    compact = encoded.translate(None, b"\t\r\n")
    if not compact:
        return None

    has_standard_alphabet = b"+" in compact or b"/" in compact
    has_urlsafe_alphabet = b"-" in compact or b"_" in compact
    if has_standard_alphabet and has_urlsafe_alphabet:
        return None

    unpadded = compact.rstrip(b"=")
    provided_padding = len(compact) - len(unpadded)

    if (
        provided_padding > 2
        or b"=" in unpadded
        or len(unpadded) % 4 == 1
    ):
        return None

    required_padding = (-len(unpadded)) % 4
    if provided_padding not in (0, required_padding):
        return None

    if required_padding > 2:
        return None

    padded = unpadded + b"=" * required_padding
    standard_form = unpadded.translate(
        bytes.maketrans(b"-_", b"+/")
    ) + b"=" * required_padding

    try:
        decoded = base64.b64decode(
            padded,
            altchars=b"-_" if has_urlsafe_alphabet else None,
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None

    if base64.b64encode(decoded) != standard_form:
        return None

    return decoded, "base64url" if has_urlsafe_alphabet else "base64"


def _identify_payload(prefix: bytes) -> tuple[str, str] | None:
    signatures = (
        (b"%PDF-", "pdf", "%PDF-"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ole_cfb", "D0CF11E0A1B11AE1"),
        (b"PK\x03\x04", "zip", "PK\\x03\\x04"),
        (b"PK\x05\x06", "zip", "PK\\x05\\x06"),
        (b"PK\x07\x08", "zip", "PK\\x07\\x08"),
        (b"{\\rtf", "rtf", "{\\rtf"),
        (b"\x7FELF", "elf", "7F454C46"),
        (b"MSCF", "cab", "MSCF"),
        (b"\x1F\x8B", "gzip", "1F8B"),
        (b"7z\xBC\xAF\x27\x1C", "7z", "377ABCAF271C"),
        (b"Rar!\x1A\x07\x00", "rar4", "526172211A0700"),
        (b"Rar!\x1A\x07\x01\x00", "rar5", "526172211A070100"),
        (b"MZ", "mz_executable", "MZ"),
        (b"\x89PNG\r\n\x1A\n", "png", "89504E470D0A1A0A"),
        (b"\xFF\xD8\xFF", "jpeg", "FFD8FF"),
        (b"GIF87a", "gif", "GIF87a"),
        (b"GIF89a", "gif", "GIF89a"),
    )

    for signature, kind, label in signatures:
        if prefix.startswith(signature):
            return kind, label

    return None


def discover_base64_candidates(
    data: bytes | bytearray | memoryview,
    *,
    max_candidates: int = _MAX_CANDIDATES,
    max_encoded_bytes: int = _MAX_ENCODED_BYTES,
    max_decoded_bytes: int = _MAX_DECODED_BYTES,
    max_total_decoded_bytes: int = _MAX_TOTAL_DECODED_BYTES,
    min_encoded_length: int = _MIN_ENCODED_LENGTH,
) -> list[dict[str, Any]]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")

    limits = (
        max_candidates,
        max_encoded_bytes,
        max_decoded_bytes,
        max_total_decoded_bytes,
        min_encoded_length,
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in limits
    ):
        raise ValueError("All discovery limits must be positive integers")

    if max_encoded_bytes < min_encoded_length:
        raise ValueError("max_encoded_bytes must be at least min_encoded_length")

    results: list[dict[str, Any]] = []
    total_decoded_bytes = 0

    for candidate_index, (start, end, encoded_length) in enumerate(
        _candidate_spans(data, min_encoded_length),
        start=1,
    ):
        if candidate_index > max_candidates:
            break

        record: dict[str, Any] = {
            "candidate_index": candidate_index,
            "source_offset_start": start,
            "source_offset_end": end,
            "encoded_length": encoded_length,
            "decode_status": "not_decoded",
            "encoding": "unknown",
            "decoded_length": None,
            "payload_kind": "unknown",
            "payload_signature": None,
            "payload_identification_status": "not_identified",
            "decoded_sha256": None,
        }

        if end - start > max_encoded_bytes:
            record["decode_status"] = "skipped_encoded_size_limit"
            results.append(record)
            continue

        raw_candidate = bytes(data[start:end])

        compact = raw_candidate.translate(None, b"\t\r\n")
        decoded_info = _decode_candidate(compact)

        if decoded_info is None:
            record["decode_status"] = "invalid_base64"
            results.append(record)
            continue

        unpadded_length = len(compact.rstrip(b"="))
        decoded_size = (unpadded_length * 3) // 4

        encoding = decoded_info[1]
        record["encoding"] = encoding

        if decoded_size > max_decoded_bytes:
            record["decode_status"] = "skipped_decoded_size_limit"
            results.append(record)
            continue

        if total_decoded_bytes + decoded_size > max_total_decoded_bytes:
            record["decode_status"] = "skipped_total_decode_limit"
            results.append(record)
            continue

        decoded = decoded_info[0]
        total_decoded_bytes += len(decoded)

        record["decode_status"] = "decoded"
        record["decoded_length"] = len(decoded)
        record["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()

        identified = _identify_payload(decoded[:64])
        if identified is not None:
            record["payload_kind"] = identified[0]
            record["payload_signature"] = identified[1]
            record["payload_identification_status"] = "recognized"
        else:
            record["payload_identification_status"] = "unrecognized"

        results.append(record)

    return results


_XML_BASE64_SCAN_BYTES = 16 * 1024 * 1024
_XML_BASE64_CANDIDATES = 128


def _xml_local_name(value: Any) -> str:
    name = str(value)
    if "}" in name:
        return name.rsplit("}", 1)[1]
    if ":" in name:
        return name.rsplit(":", 1)[1]
    return name


def _write_utf8_bounded(
    value: str,
    stream: Any,
    max_bytes: int,
    *,
    chunk_chars: int = 4096,
) -> tuple[int, bool]:
    """Write a UTF-8 prefix without exceeding a strict byte budget."""
    if max_bytes <= 0:
        return 0, bool(value)

    if chunk_chars <= 0:
        raise ValueError("chunk_chars must be positive")

    position = 0
    written = 0

    while position < len(value) and written < max_bytes:
        end = min(position + chunk_chars, len(value))
        chunk = value[position:end]
        encoded = chunk.encode("utf-8", errors="replace")
        available = max_bytes - written

        if len(encoded) <= available:
            stream.write(encoded)
            written += len(encoded)
            position = end
            continue

        # Find the largest character-aligned prefix within the remaining
        # byte budget. The search is bounded by chunk_chars.
        low = 0
        high = len(chunk)

        while low < high:
            middle = (low + high + 1) // 2
            candidate_size = len(
                chunk[:middle].encode("utf-8", errors="replace")
            )

            if candidate_size <= available:
                low = middle
            else:
                high = middle - 1

        if low:
            prefix = chunk[:low].encode("utf-8", errors="replace")
            stream.write(prefix)
            written += len(prefix)

        return written, True

    return written, position < len(value)


class Base64XmlEvidenceScanner:
    def __init__(self) -> None:
        self.evidence: list[dict[str, Any]] = []
        self.truncated = False
        self._scanned_bytes = 0
        self._candidate_count = 0
        self._decoded_bytes = 0

    def scan_node(self, package_member: str, node: Any) -> None:
        element_name = _xml_local_name(node.tag)

        self._scan_value(
            package_member,
            element_name,
            "text",
            getattr(node, "text", None),
        )

        for attr_name, attr_value in getattr(node, "attrib", {}).items():
            self._scan_value(
                package_member,
                element_name,
                "attribute",
                attr_value,
                attribute=_xml_local_name(attr_name),
            )

        self._scan_value(
            package_member,
            element_name,
            "tail",
            getattr(node, "tail", None),
        )

    def _scan_value(
        self,
        package_member: str,
        element_name: str,
        content_location: str,
        value: Any,
        *,
        attribute: str | None = None,
    ) -> None:
        if not isinstance(value, str) or len(value) < _MIN_ENCODED_LENGTH:
            return

        if self._candidate_count >= _XML_BASE64_CANDIDATES:
            self.truncated = True
            return

        remaining_scan = _XML_BASE64_SCAN_BYTES - self._scanned_bytes
        remaining_decode = (
            _MAX_TOTAL_DECODED_BYTES - self._decoded_bytes
        )

        if remaining_scan <= 0 or remaining_decode <= 0:
            self.truncated = True
            return

        remaining_candidates = (
            _XML_BASE64_CANDIDATES - self._candidate_count
        )

        with tempfile.TemporaryFile() as encoded_file:
            scanned_bytes, value_truncated = _write_utf8_bounded(
                value,
                encoded_file,
                remaining_scan,
            )

            if value_truncated:
                self.truncated = True

            self._scanned_bytes += scanned_bytes

            if scanned_bytes < _MIN_ENCODED_LENGTH:
                return

            encoded_file.flush()

            with mmap.mmap(
                encoded_file.fileno(),
                scanned_bytes,
                access=mmap.ACCESS_READ,
            ) as mapped:
                mapped_view = memoryview(mapped)
                try:
                    records = discover_base64_candidates(
                        mapped_view,
                        max_candidates=remaining_candidates,
                        max_encoded_bytes=_MAX_ENCODED_BYTES,
                        max_decoded_bytes=_MAX_DECODED_BYTES,
                        max_total_decoded_bytes=remaining_decode,
                        min_encoded_length=_MIN_ENCODED_LENGTH,
                    )
                finally:
                    mapped_view.release()

        self._candidate_count += len(records)

        if len(records) >= remaining_candidates:
            self.truncated = True

        for record in records:
            status = record["decode_status"]

            if status == "decoded":
                self._decoded_bytes += int(record["decoded_length"] or 0)
            elif not status.startswith("skipped_"):
                continue

            identified = (
                status == "decoded"
                and record["payload_identification_status"] == "recognized"
            )

            if not identified and status == "decoded":
                evidence_type = "embedded_base64_candidate"
                reported_value = "base64_candidate"
                interpretation = (
                    "A canonical Base64 value was decoded, but its content "
                    "did not match a recognized file signature."
                )
            elif identified:
                evidence_type = "embedded_base64_payload"
                reported_value = record["payload_kind"]
                interpretation = (
                    "Decoded Base64 content matched a recognized file "
                    "signature. The payload was not executed or extracted."
                )
            else:
                evidence_type = "embedded_base64_candidate"
                reported_value = "base64_candidate"
                interpretation = (
                    "A Base64-like candidate was bounded by analysis limits; "
                    "its decoded content and file signature were not verified."
                )

            locator = {
                "package_member": package_member[:300],
                "element": element_name[:100],
                "content_location": content_location,
                "attribute": attribute,
                "value_offset_start": record["source_offset_start"],
                "value_offset_end": record["source_offset_end"],
                "offset_basis": (
                    "UTF-8 byte offsets within this XML text or attribute "
                    "value, not offsets in the original package file."
                ),
            }

            self.evidence.append({
                "evidence_type": evidence_type,
                "key": "base64.embedded_payload",
                "value": reported_value,
                "severity": "info",
                "details": {
                    "context_only": True,
                    "interpretation": interpretation,
                    "decode_status": status,
                    "encoding": record["encoding"],
                    "encoded_length": record["encoded_length"],
                    "decoded_length": record["decoded_length"],
                    "payload_kind": record["payload_kind"],
                    "payload_signature": record["payload_signature"],
                    "payload_identification_status": (
                        record["payload_identification_status"]
                    ),
                    "decoded_sha256": record["decoded_sha256"],
                    "source_locator": locator,
                },
            })
