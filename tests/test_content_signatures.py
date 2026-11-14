import pytest

from cvevident.content_signatures import identify_content_signature


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1payload", ("ole_cfb", "cfb_header")),
        (b"%PDF-1.7", ("pdf", "pdf_header")),
        (b"PK\x03\x04payload", ("zip", "zip_local_file_header")),
        (b"PK\x05\x06", ("zip", "zip_empty_archive")),
        (b"PK\x07\x08", ("zip", "zip_spanned_archive")),
        (b"{\\rtf1", ("rtf", "rtf_header")),
        (b"\x7fELF", ("elf_binary", "elf_header")),
        (b"MSCF", ("cab_archive", "cab_header")),
        (b"\x1f\x8b", ("gzip", "gzip_header")),
        (b"7z\xbc\xaf\x27\x1c", ("7z", "7z_header")),
        (b"Rar!\x1a\x07\x00", ("rar", "rar4_header")),
        (b"Rar!\x1a\x07\x01\x00", ("rar", "rar5_header")),
        (b"MZpayload", ("mz_executable", "mz_header")),
    ],
)
def test_known_content_signatures(prefix, expected):
    assert identify_content_signature(prefix) == expected


@pytest.mark.parametrize("prefix", [b"", b"UNKNOWN", b"not a file signature"])
def test_unknown_content_signature_is_not_classified(prefix):
    assert identify_content_signature(prefix) is None


@pytest.mark.parametrize("prefix", [None, 1, True, "MZ", object()])
def test_invalid_prefix_type_is_not_classified(prefix):
    assert identify_content_signature(prefix) is None


def test_signature_identification_accepts_bounded_bytes_like_inputs():
    assert identify_content_signature(bytearray(b"%PDF-")) == (
        "pdf",
        "pdf_header",
    )
    assert identify_content_signature(memoryview(b"MSCF")) == (
        "cab_archive",
        "cab_header",
    )
