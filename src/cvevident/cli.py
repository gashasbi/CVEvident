"""CVEvident command-line interface."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import analyze_file
from .db import SCHEMA_VERSION, connect, default_db_path, init_db
from .reporting import serialize_json, to_html, to_markdown
from .sources import sync_epss, sync_kev, sync_nvd_modified, sync_nvd_year, sync_nvd_years
from .store import (
    get_analysis, get_cve, get_stats, import_epss_csv, import_kev_json,
    import_nvd_json, import_reference_samples_json, search_cves, search_product_cves,
)


def _dump(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _write_output(content: str, output: str | None) -> None:
    if not output or output == "-":
        print(content, end="" if content.endswith("\n") else "\n")
        return
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _dump({"status": "ok", "output": str(path.resolve())})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cvevident",
        description="Local-first, evidence-led static triage for PDF, Office and OpenDocument files with local CVE context.",
    )
    parser.add_argument("--version", action="version", version=f"CVEvident {__version__}")
    parser.add_argument("--db", default=str(default_db_path()), help="SQLite path (must appear before the subcommand)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create or upgrade the local SQLite database")
    sub.add_parser("stats", help="Show database counts and synchronization status")
    sub.add_parser("doctor", help="Check local database integrity and schema version")

    p = sub.add_parser("import-nvd", help="Import an NVD 2.0 JSON or JSON.GZ data feed/API response")
    p.add_argument("json_file")
    p = sub.add_parser("import-kev", help="Import a downloaded CISA KEV JSON file")
    p.add_argument("json_file")
    p = sub.add_parser("import-epss", help="Import a downloaded FIRST EPSS CSV or CSV.GZ file")
    p.add_argument("csv_file")
    p = sub.add_parser("import-samples", help="Import curated reference-sample metadata from JSON (not file bytes)")
    p.add_argument("json_file")

    p = sub.add_parser("sync-kev", help="Download and import the free CISA KEV catalog")
    p.add_argument("--cache-file")
    p = sub.add_parser("sync-epss", help="Download and import the free FIRST EPSS scores")
    p.add_argument("--cache-file")
    p = sub.add_parser("sync-nvd", help="Sync recently modified NVD records (incremental only)")
    p.add_argument("--days", type=int, default=7, help="Modified lookback window, 1-120 days (default 7)")
    p.add_argument("--cache-dir")
    p = sub.add_parser("sync-nvd-year", help="Download, verify and import one official NVD annual feed")
    p.add_argument("year", type=int, help="CVE year; 2002 feed includes older records")
    p.add_argument("--cache-dir")
    p.add_argument("--force-download", action="store_true", help="Re-download feed even when this database is up-to-date")
    p = sub.add_parser("sync-nvd-years", help="Bootstrap/update several NVD annual feeds; can use substantial bandwidth and disk")
    p.add_argument("--from-year", type=int, default=2002, help="First feed year (2002 includes older CVEs)")
    p.add_argument("--to-year", type=int, help="Last feed year; default is current year")
    p.add_argument("--cache-dir")
    p.add_argument("--force-download", action="store_true")
    p = sub.add_parser("sync-all", help="Attempt NVD recent sync, CISA KEV, and EPSS; report each outcome")
    p.add_argument("--nvd-days", type=int, default=7)

    p = sub.add_parser("search", help="Lexically search locally imported CVE records")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("show-cve", help="Display a CVE and its locally imported products/references")
    p.add_argument("cve_id")

    p = sub.add_parser(
        "analyze",
        help="Run bounded static triage on supported PDF, Office, RTF or OpenDocument files",
        epilog=(
            "Office Open XML: Word .docx/.docm/.dotx/.dotm; "
            "Excel .xlsx/.xlsm/.xltx/.xltm/.xlsb/.xlam; "
            "PowerPoint .pptx/.pptm/.ppsx/.ppsm/.potx/.potm/.ppam/.sldx/.sldm. "
            "Legacy OLE/CFB Office: .doc/.xls/.ppt and related variants (bounded directory metadata only). "
            "Also supports static RTF (.rtf) and OpenDocument .odt/.ott/.ods/.ots/.odp/.otp. "
            "See docs/office-triage.md and docs/legacy-and-open-document-triage.md for limits."
        ),
    )
    p.add_argument("file")
    p.add_argument("--target-product", help="Product context for local affected-product CPE retrieval")
    p.add_argument("--output", help="Report path; use '-' or omit to print")
    p.add_argument("--format", choices=("json", "markdown", "html"), default="json")
    p.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024)
    p.add_argument("--candidate-limit", type=int, default=10)

    p = sub.add_parser("show-analysis", help="Rebuild a saved analysis report from the local database")
    p.add_argument("analysis_id", type=int)
    p.add_argument("--output")
    p.add_argument("--format", choices=("json", "markdown", "html"), default="json")

    p = sub.add_parser("search-product", help="Search CVEs using affected-product CPE fields only")
    p.add_argument("product")
    p.add_argument("--limit", type=int, default=20)
    return parser


def _render(report: dict[str, Any], fmt: str) -> str:
    if fmt == "markdown":
        return to_markdown(report) + "\n"
    if fmt == "html":
        return to_html(report) + "\n"
    return serialize_json(report)


def _doctor(db_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "program_version": __version__,
        "schema_expected": SCHEMA_VERSION,
        "database": str(Path(db_path).expanduser().resolve()),
    }
    with connect(db_path) as conn:
        result["sqlite_version"] = sqlite3.sqlite_version
        result["integrity_check"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
        row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        result["schema_actual"] = int(row[0]) if row else None
        result["healthy"] = result["integrity_check"] == "ok" and result["schema_actual"] == SCHEMA_VERSION
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        db_path = init_db(args.db)
        if args.command == "init-db":
            _dump({"status": "ok", "database": str(db_path), "schema_version": SCHEMA_VERSION, "version": __version__})
        elif args.command == "stats":
            _dump(get_stats(db_path))
        elif args.command == "doctor":
            result = _doctor(str(db_path))
            _dump(result)
            return 0 if result["healthy"] else 1
        elif args.command == "import-nvd":
            _dump({"source": "NVD", "records_imported": import_nvd_json(args.json_file, db_path)})
        elif args.command == "import-kev":
            _dump({"source": "CISA KEV", "records_imported": import_kev_json(args.json_file, db_path)})
        elif args.command == "import-epss":
            _dump({"source": "FIRST EPSS", "records_imported": import_epss_csv(args.csv_file, db_path)})
        elif args.command == "import-samples":
            _dump({"source": "curated reference samples", "samples_imported": import_reference_samples_json(args.json_file, db_path)})
        elif args.command == "sync-kev":
            _dump({"source": "CISA KEV", "records_imported": sync_kev(db_path, args.cache_file)})
        elif args.command == "sync-epss":
            _dump({"source": "FIRST EPSS", "records_imported": sync_epss(db_path, args.cache_file)})
        elif args.command == "sync-nvd":
            _dump({"source": "NVD", "records_imported": sync_nvd_modified(db_path, args.days, args.cache_dir)})
        elif args.command == "sync-nvd-year":
            _dump({"source": "NVD", **sync_nvd_year(args.year, db_path, args.cache_dir, args.force_download)})
        elif args.command == "sync-nvd-years":
            result = sync_nvd_years(args.from_year, args.to_year, db_path, args.cache_dir, args.force_download)
            _dump({"source": "NVD", **result})
            return 0 if result["status"] == "ok" else 1
        elif args.command == "sync-all":
            outcomes: dict[str, Any] = {}
            tasks = (
                ("NVD", lambda: sync_nvd_modified(db_path, args.nvd_days)),
                ("CISA KEV", lambda: sync_kev(db_path)),
                ("FIRST EPSS", lambda: sync_epss(db_path)),
            )
            for name, action in tasks:
                try:
                    outcomes[name] = {"status": "ok", "records_imported": action()}
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                    outcomes[name] = {"status": "error", "error": str(exc)}
            overall = "ok" if all(row["status"] == "ok" for row in outcomes.values()) else "partial_or_failed"
            _dump({"status": overall, "sources": outcomes, "note": "NVD sync is incremental; it is not a full initial CVE import."})
            return 0 if overall == "ok" else 1
        elif args.command == "search":
            _dump({"query": args.query, "results": search_cves(args.query, db_path, args.limit),
                   "note": "Lexical search results are not file/CVE attribution."})
        elif args.command == "search-product":
            _dump({"product": args.product, "results": search_product_cves(args.product, db_path, args.limit),
                   "note": "Product CPE retrieval is lexical; it does not evaluate full NVD configuration logic or prove an installed version is affected."})
        elif args.command == "show-cve":
            result = get_cve(args.cve_id, db_path)
            if result is None:
                _dump({"status": "not_found", "cve_id": args.cve_id.upper(), "database": str(db_path)})
                return 1
            result.pop("raw_json", None)
            _dump(result)
        elif args.command == "analyze":
            report = analyze_file(args.file, db_path, args.target_product, args.max_bytes, args.candidate_limit)
            _write_output(_render(report, args.format), args.output)
        elif args.command == "show-analysis":
            report = get_analysis(args.analysis_id, db_path)
            if report is None:
                _dump({"status": "not_found", "analysis_id": args.analysis_id})
                return 1
            _write_output(_render(report, args.format), args.output)
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
