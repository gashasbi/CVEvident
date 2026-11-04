"""Bounded, static identification of embedded file content signatures.

This module only identifies known file headers. It does not parse, extract,
execute, or assess the safety of the identified content.
"""

from __future__ import annotations

from typing import Any


_CONTENT_SIGNATURES = (
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_cfb", "cfb_header"),
    (b"%PDF-", "pdf", "pdf_header"),
    (b"PK\x03\x04", "zip", "zip_local_file_header"),
    (b"PK\x05\x06", "zip", "zip_empty_archive"),
    (b"PK\x07\x08", "zip", "zip_spanned_archive"),
    (b"{\\rtf", "rtf", "rtf_header"),
    (b"\x7fELF", "elf_binary", "elf_header"),
    (b"MSCF", "cab_archive", "cab_header"),
    (b"\x1f\x8b", "gzip", "gzip_header"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7z_header"),
    (b"Rar!\x1a\x07\x00", "rar", "rar4_header"),
    (b"Rar!\x1a\x07\x01\x00", "rar", "rar5_header"),
)
MAX_CONTENT_SIGNATURE_BYTES = max(
    len(signature) for signature, _, _ in _CONTENT_SIGNATURES
)


def identify_content_signature(prefix: Any) -> tuple[str, str] | None:
    """Identify a known file signature at the beginning of a bounded prefix."""
    if not isinstance(prefix, (bytes, bytearray, memoryview)):
        return None

    max_signature_length = MAX_CONTENT_SIGNATURE_BYTES
    prefix = bytes(prefix[:max_signature_length])

    for signature, kind, label in _CONTENT_SIGNATURES:
        if prefix.startswith(signature):
            return kind, label

    if prefix.startswith(b"MZ"):
        return "mz_executable", "mz_header"

    return None
