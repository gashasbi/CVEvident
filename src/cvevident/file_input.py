"""Shared bounded file input and identity helpers for static analyzers."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileInput:
    """Bytes and stable identity for one input read within a configured limit."""

    path: Path
    data: bytes
    sha256: str

    @property
    def size_bytes(self) -> int:
        return len(self.data)


def read_file(path: str | Path, max_bytes: int = 100 * 1024 * 1024) -> FileInput:
    """Read one regular file with a hard byte cap and compute SHA-256.

    The helper does not infer a format or interpret file contents. Format-specific
    analyzers remain responsible for bounded parsing of the returned bytes.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")

    file_path = Path(path).expanduser()
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"Input file not found or not a regular file: {file_path}")

    try:
        with file_path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise OSError(f"Could not read input file: {exc}") from exc

    if len(data) > max_bytes:
        raise ValueError(
            f"Input exceeds the configured limit ({max_bytes} bytes). Use --max-bytes to raise the limit deliberately."
        )

    return FileInput(path=file_path, data=data, sha256=hashlib.sha256(data).hexdigest())
