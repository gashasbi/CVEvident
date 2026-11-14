"""Terminal progress display for long-running CLI operations."""
from __future__ import annotations

import shutil
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from collections.abc import Iterator
from typing import TextIO


@dataclass
class Progress:
    message: str
    stream: TextIO
    enabled: bool
    width: int = 28
    last_stage: str | None = None
    last_percent: int = -1

    def update(self, current: int, total: int | None = None, detail: str | None = None) -> None:
        if not self.enabled:
            return
        current = max(0, int(current))
        if total is not None:
            total = max(0, int(total))
        columns = max(40, shutil.get_terminal_size((80, 24)).columns)
        message_limit = min(28, max(16, columns // 3))
        message = self.message
        if len(message) > message_limit:
            message = message[:message_limit - 3] + "..."
        if total:
            fraction = min(1.0, current / total)
            percent = int(fraction * 100)
            stage = detail or ""
            if stage == self.last_stage and percent == self.last_percent:
                return
            self.last_stage = stage
            self.last_percent = percent
            status = f"{fraction * 100:4.0f}% {current:,}/{total:,}"
        else:
            status = f"{current:,}"
        detail_text = (detail or "")[:12]
        bar_width = max(8, min(self.width, columns - len(message) - len(status) - len(detail_text) - 6))
        if total:
            filled = min(bar_width, int(fraction * bar_width))
        else:
            filled = min(bar_width, current % (bar_width + 1))
        bar = "#" * filled + "-" * (bar_width - filled)
        suffix = f" {detail_text}" if detail_text else ""
        line = f"{message} [{bar}] {status}{suffix}"
        self.stream.write("\r\x1b[2K" + line)
        self.stream.flush()


@contextmanager
def progress(message: str, stream: TextIO | None = None) -> Iterator[Progress]:
    output = stream if stream is not None else sys.stderr
    enabled = bool(getattr(output, "isatty", lambda: False)())
    display = Progress(message, output, enabled)
    if enabled:
        display.update(0, 1, "starting")
    failed = False
    cancelled = False
    try:
        yield display
    except KeyboardInterrupt:
        cancelled = True
        raise
    except BaseException:
        failed = True
        raise
    finally:
        if enabled:
            result = "cancelled" if cancelled else "failed" if failed else "done"
            output.write(f"\r\x1b[2K{message} [{result}]\n")
            output.flush()
