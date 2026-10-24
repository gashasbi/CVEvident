"""Opt-in, reproducible CVEvident workload benchmark (no CI timing thresholds).

Run from an activated project environment, for example:
  python scripts/benchmark_acceptance.py --records 2000 --files 20

This script generates synthetic NVD rows and benign PDFs in a temporary directory.
It does not access the network and does not write generated data into the repository.
The measurements are comparative baselines, not security or performance guarantees.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
src = REPO_ROOT / "src"
if src.is_dir() and str(src) not in sys.path:
    sys.path.insert(0, str(src))

import pypdf
from pypdf import PdfWriter

from cvevident import __version__
from cvevident.analyzer import analyze_file
from cvevident.db import init_db
from cvevident.store import get_stats, import_nvd_json, search_product_cves

try:
    import resource  # Unix only; tracemalloc remains available on Windows.
except ImportError:  # pragma: no cover - platform-specific fallback
    resource = None  # type: ignore[assignment]


MAX_RECORDS = 100_000
MAX_FILES = 500
MAX_PADDING_BYTES = 50 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 512 * 1024 * 1024


def _synthetic_record(index: int) -> dict[str, Any]:
    cve_id = f"CVE-2099-{index + 10000:05d}"
    product = f"benchmarkproduct-{index % 97:03d}"
    return {
        "cve": {
            "id": cve_id,
            "published": "2099-01-01T00:00:00.000Z",
            "lastModified": "2099-01-02T00:00:00.000Z",
            "descriptions": [{
                "lang": "en",
                "value": f"Synthetic benchmark record {index}; not a real vulnerability.",
            }],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                "criteria": f"cpe:2.3:a:benchmarkvendor:{product}:*:*:*:*:*:*:*:*",
                "vulnerable": True,
                "versionStartIncluding": "1.0",
                "versionEndExcluding": "4.0",
            }]}]}],
        }
    }


def _write_feed(path: Path, records: int) -> None:
    """Write the synthetic feed incrementally to avoid building a second large list."""
    with path.open("w", encoding="utf-8") as handle:
        handle.write('{"vulnerabilities":[')
        for index in range(records):
            if index:
                handle.write(",")
            json.dump(_synthetic_record(index), handle, separators=(",", ":"))
        handle.write("]}")


def _write_padded_pdf(path: Path, padding_bytes: int) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as handle:
        writer.write(handle)
    if padding_bytes:
        with path.open("ab") as handle:
            handle.write(b"\n% benchmark padding follows; no action is executed\n")
            handle.write(b"A" * padding_bytes)
            handle.write(b"\n")


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return round(ordered[index], 6)


def _rss_mib() -> float | None:
    if resource is None:
        return None
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux and the other supported Unix platforms generally use KiB.
    if sys.platform == "darwin":
        value /= 1024 * 1024
    else:
        value /= 1024
    return round(value, 3)


def run_benchmark(*, records: int, files: int, search_iterations: int, padding_bytes: int) -> dict[str, Any]:
    total_input = files * max(1, padding_bytes)
    if not 1 <= records <= MAX_RECORDS:
        raise ValueError(f"records must be between 1 and {MAX_RECORDS}")
    if not 1 <= files <= MAX_FILES:
        raise ValueError(f"files must be between 1 and {MAX_FILES}")
    if not 1 <= search_iterations <= 10_000:
        raise ValueError("search_iterations must be between 1 and 10000")
    if not 0 <= padding_bytes <= MAX_PADDING_BYTES:
        raise ValueError(f"padding_bytes must be between 0 and {MAX_PADDING_BYTES}")
    if total_input > MAX_TOTAL_INPUT_BYTES:
        raise ValueError(
            f"files * padding_bytes exceeds the {MAX_TOTAL_INPUT_BYTES}-byte temporary-input budget"
        )

    with tempfile.TemporaryDirectory(prefix="cvevident-benchmark-") as tmp:
        root = Path(tmp)
        feed = root / "synthetic-nvd.json"
        database = root / "benchmark.sqlite3"
        base_pdf = root / "base.pdf"

        feed_write_started = time.perf_counter()
        _write_feed(feed, records)
        feed_write_seconds = time.perf_counter() - feed_write_started
        feed_size_bytes = feed.stat().st_size

        db_setup_started = time.perf_counter()
        init_db(database)
        db_setup_seconds = time.perf_counter() - db_setup_started

        tracemalloc.start()
        tracemalloc.reset_peak()
        import_baseline, _ = tracemalloc.get_traced_memory()
        import_started = time.perf_counter()
        imported = import_nvd_json(feed, database)
        import_seconds = time.perf_counter() - import_started
        _, import_peak = tracemalloc.get_traced_memory()
        import_peak_delta = max(0, import_peak - import_baseline)

        search_times: list[float] = []
        tracemalloc.reset_peak()
        search_baseline, _ = tracemalloc.get_traced_memory()
        for _ in range(search_iterations):
            started = time.perf_counter()
            search_product_cves(
                "benchmarkproduct-007",
                db_path=database,
                limit=20,
                vendor="benchmarkvendor",
                version="2.1",
            )
            search_times.append(time.perf_counter() - started)
        _, search_peak = tracemalloc.get_traced_memory()
        search_peak_delta = max(0, search_peak - search_baseline)

        _write_padded_pdf(base_pdf, padding_bytes)
        payload = base_pdf.read_bytes()
        input_paths: list[Path] = []
        for index in range(files):
            target = root / f"sample-{index:04d}.pdf"
            target.write_bytes(payload)
            input_paths.append(target)

        analysis_times: list[float] = []
        analysis_started = time.perf_counter()
        tracemalloc.reset_peak()
        analysis_baseline, _ = tracemalloc.get_traced_memory()
        for path in input_paths:
            started = time.perf_counter()
            analyze_file(path, database)
            analysis_times.append(time.perf_counter() - started)
        analysis_seconds = time.perf_counter() - analysis_started
        _, analysis_peak = tracemalloc.get_traced_memory()
        analysis_peak_delta = max(0, analysis_peak - analysis_baseline)
        _, process_peak_python = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        stats = get_stats(database)
        return {
            "benchmark_schema_version": 1,
            "interpretation": (
                "Comparative local baseline only. No machine-independent timing threshold is enforced; "
                "synthetic CVE records are not real vulnerability data. Python allocation peaks do not include every native allocation."
            ),
            "environment": {
                "cvevident_version": __version__,
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "pypdf_version": getattr(pypdf, "__version__", "unknown"),
            },
            "workload": {
                "synthetic_nvd_records_requested": records,
                "synthetic_nvd_records_imported": imported,
                "synthetic_feed_size_bytes": feed_size_bytes,
                "analysis_files": files,
                "pdf_padding_bytes_per_file": padding_bytes,
                "total_pdf_input_bytes": sum(path.stat().st_size for path in input_paths),
                "product_search_iterations": search_iterations,
                "db_analysis_rows_after_benchmark": stats["analyses"],
                "db_vulnerability_rows_after_import": stats["vulnerabilities"],
            },
            "timings_seconds": {
                "synthetic_feed_write": round(feed_write_seconds, 6),
                "database_initialization": round(db_setup_seconds, 6),
                "nvd_import": round(import_seconds, 6),
                "product_search_median": _percentile(search_times, 0.50),
                "product_search_p95": _percentile(search_times, 0.95),
                "product_search_min": round(min(search_times), 6) if search_times else None,
                "analysis_total": round(analysis_seconds, 6),
                "analysis_files_per_second": round(files / analysis_seconds, 4) if analysis_seconds else None,
                "analysis_median_per_file": _percentile(analysis_times, 0.50),
                "analysis_p95_per_file": _percentile(analysis_times, 0.95),
            },
            "memory": {
                "python_peak_delta_during_import_mib": round(import_peak_delta / (1024 * 1024), 3),
                "python_peak_delta_during_search_mib": round(search_peak_delta / (1024 * 1024), 3),
                "python_peak_delta_during_analysis_mib": round(analysis_peak_delta / (1024 * 1024), 3),
                "python_traced_peak_mib": round(process_peak_python / (1024 * 1024), 3),
                "process_max_rss_mib_best_effort": _rss_mib(),
            },
            "database_size_bytes": database.stat().st_size,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=2_000, help="Synthetic NVD records (max 100000)")
    parser.add_argument("--files", type=int, default=20, help="PDF analyses (max 500)")
    parser.add_argument("--search-iterations", type=int, default=25, help="Repeated local product queries")
    parser.add_argument("--padding-bytes", type=int, default=1 * 1024 * 1024,
                        help="Trailing comment bytes per PDF (max 50 MiB)")
    parser.add_argument("--output", help="Write benchmark JSON to this path instead of stdout")
    args = parser.parse_args(argv)
    try:
        result = run_benchmark(
            records=args.records,
            files=args.files,
            search_iterations=args.search_iterations,
            padding_bytes=args.padding_bytes,
        )
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            output_path = Path(args.output).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"status": "ok", "output": str(output_path.resolve())}, ensure_ascii=False))
        else:
            print(rendered, end="")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
