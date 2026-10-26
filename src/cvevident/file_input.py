"""Shared bounded file input and identity helpers for static analyzers."""
from __future__ import annotations

import hashlib
import os
import stat
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
    try:
        before_open = file_path.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Input file not found or not a regular file: {file_path}"
        ) from exc
    except OSError as exc:
        raise OSError(f"Could not read input file: {exc}") from exc

    if not stat.S_ISREG(before_open.st_mode):
        raise FileNotFoundError(f"Input file not found or not a regular file: {file_path}")

    # The first type check can race with path replacement. Use a non-blocking
    # open where supported, then validate the actual descriptor before reading.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(file_path, flags)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise FileNotFoundError(
                f"Input file changed to a non-regular file before it could be read: {file_path}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None  # fdopen owns the descriptor now.
            data = handle.read(max_bytes + 1)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OSError(f"Could not read input file: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if len(data) > max_bytes:
        raise ValueError(
            f"Input exceeds the configured limit ({max_bytes} bytes). Use --max-bytes to raise the limit deliberately."
        )

    return FileInput(path=file_path, data=data, sha256=hashlib.sha256(data).hexdigest())

def read_prefix(path: str | Path, size: int = 1024) -> bytes:
    if size < 0:
        raise ValueError("size must be non-negative")

    file_path = Path(path).expanduser()
    try:
        before_open = file_path.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Input file not found or not a regular file: {file_path}"
        ) from exc
    except OSError as exc:
        raise OSError(f"Could not read input file: {exc}") from exc

    if not stat.S_ISREG(before_open.st_mode):
        raise FileNotFoundError(
            f"Input file not found or not a regular file: {file_path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(file_path, flags)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise FileNotFoundError(
                f"Input file changed to a non-regular file before it could be read: {file_path}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            return handle.read(size)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OSError(f"Could not read input file: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
