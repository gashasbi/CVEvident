"""Data import, provenance, lexical search, and local database queries."""
from __future__ import annotations

import csv
import gzip
import zlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .db import connect
from .product_matching import (
    assess_version_context, cpe23_components, classify_name_match,
    normalize_product_text, product_tokens, split_product_version,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _first_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang", "").lower() == "en" and item.get("value"):
            return str(item["value"]).strip()
    for item in descriptions:
        if isinstance(item, dict) and item.get("value"):
            return str(item["value"]).strip()
    return ""


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        entry = entries[0] if isinstance(entries[0], dict) else {}
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        vector = data.get("vectorString")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        return score, str(severity).upper() if severity else None, str(vector) if vector else None
    return None, None, None


def _walk_cpe_matches(node: Any) -> Iterable[dict[str, Any]]:
    """Recursively collect NVD CPE criteria while preserving raw configuration JSON separately.

    This flattens CPE matches for lookup. It intentionally does not interpret AND/OR
    applicability logic; candidate matches therefore must not be treated as a proof
    that a specific version is affected.
    """
    if isinstance(node, list):
        for child in node:
            yield from _walk_cpe_matches(child)
        return
    if not isinstance(node, dict):
        return
    cpe_matches = node.get("cpeMatch")
    if isinstance(cpe_matches, list):
        for match in cpe_matches:
            if isinstance(match, dict):
                yield match
    for key in ("nodes", "children"):
        child_nodes = node.get(key)
        if isinstance(child_nodes, list):
            yield from _walk_cpe_matches(child_nodes)


def _parse_cpe(criteria: str) -> tuple[str | None, str | None]:
    """Extract decoded vendor/product fields while preserving original criteria separately."""
    components = cpe23_components(criteria)
    return components.get("vendor"), components.get("product")


def _extract_products(item: dict[str, Any]) -> list[dict[str, Any]]:
    cve = item.get("cve", item)
    products: list[dict[str, Any]] = []
    configurations = cve.get("configurations") or item.get("configurations") or []
    seen: set[tuple[Any, ...]] = set()
    for match in _walk_cpe_matches(configurations):
        criteria = match.get("criteria") or match.get("cpe23Uri")
        if not isinstance(criteria, str) or not criteria:
            continue
        vendor, product = _parse_cpe(criteria)
        values = {
            "criteria": criteria,
            "vendor": vendor,
            "product": product,
            "version_start_including": match.get("versionStartIncluding"),
            "version_start_excluding": match.get("versionStartExcluding"),
            "version_end_including": match.get("versionEndIncluding"),
            "version_end_excluding": match.get("versionEndExcluding"),
            "vulnerable": bool(match.get("vulnerable", False)),
        }
        key = tuple(values.values())
        if key not in seen:
            seen.add(key)
            products.append(values)
    return products


def _record_source_observation(conn: sqlite3.Connection, cve_id: str, source: str,
                               updated_at: str | None, raw: dict[str, Any] | None) -> None:
    observed = utc_now()
    raw_text = json.dumps(raw or {}, ensure_ascii=False, separators=(",", ":"))
    # SQLite UNIQUE permits multiple NULL values. EPSS rows do not carry a per-CVE
    # modified timestamp, so update the latest observation instead of growing one row
    # per CVE for every daily synchronization. NVD snapshots with timestamps are retained.
    if updated_at is None:
        existing = conn.execute(
            "SELECT id FROM source_observations WHERE cve_id=? AND source_name=? AND source_updated_at IS NULL ORDER BY id DESC LIMIT 1",
            (cve_id, source),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE source_observations SET observed_at=?,source_record_json=? WHERE id=?",
                (observed, raw_text, existing["id"]),
            )
            return
    conn.execute(
        "INSERT OR IGNORE INTO source_observations(cve_id,source_name,observed_at,source_updated_at,source_record_json) "
        "VALUES(?,?,?,?,?)",
        (cve_id, source, observed, updated_at, raw_text),
    )


def _upsert_vulnerability(conn: sqlite3.Connection, *, cve_id: str,
                          source: str, published: str | None,
                          modified: str | None, description: str,
                          cvss_score: float | None = None,
                          cvss_severity: str | None = None,
                          raw_json: dict[str, Any] | None = None) -> None:
    now = utc_now()
    existing = conn.execute("SELECT source, description FROM vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone()
    # Do not overwrite an NVD description with the usually shorter KEV summary.
    preserve_existing_description = existing and existing["source"] == "NVD" and source != "NVD"
    conn.execute(
        """INSERT INTO vulnerabilities
           (cve_id,source,published,modified,description,cvss_score,cvss_severity,raw_json,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(cve_id) DO UPDATE SET
             source=CASE WHEN excluded.source='NVD' THEN 'NVD' ELSE vulnerabilities.source END,
             published=COALESCE(excluded.published,vulnerabilities.published),
             modified=COALESCE(excluded.modified,vulnerabilities.modified),
             description=CASE
               WHEN excluded.source='NVD' AND excluded.description!='' THEN excluded.description
               WHEN vulnerabilities.description='' AND excluded.description!='' THEN excluded.description
               ELSE vulnerabilities.description END,
             cvss_score=COALESCE(excluded.cvss_score,vulnerabilities.cvss_score),
             cvss_severity=COALESCE(excluded.cvss_severity,vulnerabilities.cvss_severity),
             raw_json=CASE WHEN excluded.source='NVD' AND excluded.raw_json IS NOT NULL THEN excluded.raw_json
                           ELSE COALESCE(vulnerabilities.raw_json,excluded.raw_json) END,
             updated_at=excluded.updated_at""",
        (cve_id, source, published, modified,
         existing["description"] if preserve_existing_description else description,
         cvss_score, cvss_severity,
         json.dumps(raw_json, ensure_ascii=False, separators=(",", ":")) if raw_json is not None else None,
         now),
    )
    observation_payload = {"detail": "full record retained in vulnerabilities.raw_json"} if source == "NVD" else raw_json
    _record_source_observation(conn, cve_id, source, modified, observation_payload)


def _update_source_sync(
    conn: sqlite3.Connection,
    source: str,
    count: int,
    details: str,
    *,
    status: str = "success",
) -> None:
    """Record source import status without promoting a partial import to success."""
    now = utc_now()
    if status == "success":
        conn.execute(
            """INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET last_success_at=excluded.last_success_at,
               last_attempt_at=excluded.last_attempt_at,records_seen=excluded.records_seen,
               status='success',details=excluded.details""",
            (source, now, now, count, "success", details),
        )
    else:
        # Preserve the last-success timestamp and its record count. The current
        # attempt may have imported useful rows, but it is not a complete snapshot.
        conn.execute(
            """INSERT INTO source_sync(source,last_attempt_at,status,details)
               VALUES(?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,
               status=excluded.status,details=excluded.details""",
            (source, now, status, details),
        )


def _record_source_import_failure(
    db_path: str | Path | None, source: str, message: str
) -> None:
    """Record a failed import without replacing the last successful snapshot."""
    try:
        with connect(db_path) as conn:
            _update_source_sync(
                conn, source, 0, str(message)[:1000], status="error"
            )
    except sqlite3.Error:
        # Preserve the original import exception if the database is unavailable.
        pass


def _iter_nvd_items(source_path: Path) -> Iterable[dict[str, Any]]:
    """Yield NVD records, using optional ijson for memory-efficient bulk imports."""
    opener = gzip.open if source_path.suffix.lower() == ".gz" else open
    try:
        import ijson  # type: ignore[import-not-found]
    except ImportError:
        try:
            with opener(source_path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read valid NVD JSON from {source_path}: {exc}") from exc
        items = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise ValueError("Expected NVD 2.0 JSON with a 'vulnerabilities' array")
        yield from items
        return

    # Validate that the root-level key exists and is actually an array before
    # streaming. Otherwise ijson.items() can silently yield zero rows for e.g.
    # {"vulnerabilities": null}, unlike the standard JSON importer.
    try:
        found_array = False
        with opener(source_path, "rb") as handle:
            events = iter(ijson.parse(handle))
            for prefix, event, value in events:
                if prefix == "" and event == "map_key" and value == "vulnerabilities":
                    try:
                        value_prefix, value_event, _ = next(events)
                    except StopIteration as exc:
                        raise ValueError("Expected NVD 2.0 JSON with a 'vulnerabilities' array") from exc
                    if value_prefix != "vulnerabilities" or value_event != "start_array":
                        raise ValueError("Expected NVD 2.0 JSON with a 'vulnerabilities' array")
                    found_array = True
                    break
                if prefix == "" and event == "end_map":
                    break
        if not found_array:
            raise ValueError("Expected NVD 2.0 JSON with a 'vulnerabilities' array")
        with opener(source_path, "rb") as handle:
            yield from ijson.items(handle, "vulnerabilities.item")
    except ValueError:
        raise
    except Exception as exc:
        # Don't obscure intentional keyboard interrupts/system exits.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ValueError(f"Could not stream NVD JSON from {source_path}: {exc}") from exc


def import_nvd_json(path: str | Path, db_path: str | Path | None = None) -> int:
    """Import NVD 2.0 JSON (plain or gzip) and return the number of CVE records visited.

    Install the optional `bulk` extra (`pip install -e ".[bulk]"`) to stream annual
    feeds through ijson instead of materializing the entire JSON tree in memory.
    """
    source_path = Path(path).expanduser()
    if not source_path.is_file():
        message = f"NVD import file not found: {source_path}"
        _record_source_import_failure(db_path, "NVD", message)
        raise FileNotFoundError(message)
    count = 0
    skipped_invalid_records = 0
    try:
        with connect(db_path) as conn:
            for record_index, item in enumerate(_iter_nvd_items(source_path), start=1):
                if not isinstance(item, dict):
                    skipped_invalid_records += 1
                    continue
                cve = item.get("cve", item)
                if not isinstance(cve, dict):
                    skipped_invalid_records += 1
                    continue
                cve_id = cve.get("id")
                if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
                    skipped_invalid_records += 1
                    continue
                cve_id = cve_id.upper()
                score, severity, _vector = _cvss(cve)
                _upsert_vulnerability(
                    conn, cve_id=cve_id, source="NVD",
                    published=cve.get("published"), modified=cve.get("lastModified") or cve.get("modified"),
                    description=_first_description(cve), cvss_score=score,
                    cvss_severity=severity, raw_json=cve,
                )
                for ref in cve.get("references", []) or []:
                    if not isinstance(ref, dict) or not isinstance(ref.get("url"), str):
                        continue
                    conn.execute(
                        "INSERT OR IGNORE INTO vulnerability_references(cve_id,url,name,tags_json) VALUES(?,?,?,?)",
                        (cve_id, ref["url"], ref.get("source"), json.dumps(ref.get("tags", []), ensure_ascii=False)),
                    )
                for weakness in cve.get("weaknesses") or []:
                    if not isinstance(weakness, dict):
                        continue
                    for desc in weakness.get("description") or []:
                        if not isinstance(desc, dict):
                            continue
                        weakness_id = str(desc.get("value", ""))
                        if weakness_id.startswith("CWE-"):
                            conn.execute(
                                "INSERT OR IGNORE INTO vulnerability_weaknesses(cve_id,cwe_id,description) VALUES(?,?,?)",
                                (cve_id, weakness_id, ""),
                            )
                # An explicit configurations property means this record's product list is authoritative.
                if "configurations" in cve:
                    conn.execute("DELETE FROM affected_products WHERE cve_id=?", (cve_id,))
                    for product_row in _extract_products(item):
                        conn.execute(
                            """INSERT OR IGNORE INTO affected_products
                               (cve_id,criteria,vendor,product,version_start_including,version_start_excluding,
                                version_end_including,version_end_excluding,vulnerable)
                               VALUES(?,?,?,?,?,?,?,?,?)""",
                            (cve_id, product_row["criteria"], product_row["vendor"], product_row["product"],
                             product_row["version_start_including"], product_row["version_start_excluding"],
                             product_row["version_end_including"], product_row["version_end_excluding"],
                             int(product_row["vulnerable"])),
                        )
                count += 1
            details = (
                f"Imported {source_path.name}; valid_records={count}; "
                f"skipped_invalid_records={skipped_invalid_records}"
            )
            _update_source_sync(
                conn, "NVD", count, details,
                status="partial" if skipped_invalid_records else "success",
            )
    except (OSError, json.JSONDecodeError, EOFError, gzip.BadGzipFile, zlib.error) as exc:
        message = f"Could not read NVD JSON from {source_path}: {exc}"
        _record_source_import_failure(db_path, "NVD", message)
        raise ValueError(message) from exc
    except Exception as exc:
        # The transaction context has rolled back before this separate status write.
        _record_source_import_failure(db_path, "NVD", str(exc))
        raise
    return count


def import_kev_json(path: str | Path, db_path: str | Path | None = None) -> int:
    source_path = Path(path).expanduser()
    if not source_path.is_file():
        message = f"CISA KEV file not found: {source_path}"
        _record_source_import_failure(db_path, "CISA KEV", message)
        raise FileNotFoundError(message)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        message = f"Could not read valid CISA KEV JSON from {source_path}: {exc}"
        _record_source_import_failure(db_path, "CISA KEV", message)
        raise ValueError(message) from exc
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        message = "Expected CISA KEV JSON with a 'vulnerabilities' array"
        _record_source_import_failure(db_path, "CISA KEV", message)
        raise ValueError(message)
    validated_rows: list[tuple[dict[str, Any], str]] = []
    skipped_invalid_rows = 0
    for record_index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            skipped_invalid_rows += 1
            continue
        cve_id = row.get("cveID")
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id.strip()):
            skipped_invalid_rows += 1
            continue
        validated_rows.append((row, cve_id.strip().upper()))
    count = 0
    try:
        with connect(db_path) as conn:
            for row, cve_id in validated_rows:
                desc = str(row.get("shortDescription") or row.get("vulnerabilityName") or "")
                _upsert_vulnerability(conn, cve_id=cve_id, source="CISA KEV", published=None,
                                      modified=None, description=desc, raw_json=row)
                conn.execute(
                    "UPDATE vulnerabilities SET cisa_kev=1,kev_date_added=?,kev_notes=?,updated_at=? WHERE cve_id=?",
                    (row.get("dateAdded"), row.get("requiredAction"), utc_now(), cve_id),
                )
                notes_url = row.get("notes")
                if isinstance(notes_url, str) and notes_url.startswith(("https://", "http://")):
                    conn.execute(
                        "INSERT OR IGNORE INTO vulnerability_references(cve_id,url,name,tags_json) VALUES(?,?,?,?)",
                        (cve_id, notes_url, "CISA KEV notes", "[]"),
                    )
                count += 1
            details = (
                f"Imported {source_path.name}; valid_rows={count}; "
                f"skipped_invalid_rows={skipped_invalid_rows}"
            )
            _update_source_sync(
                conn, "CISA KEV", count, details,
                status="partial" if skipped_invalid_rows else "success",
            )
    except Exception as exc:
        _record_source_import_failure(db_path, "CISA KEV", str(exc))
        raise
    return count


def _open_maybe_gzip(path: str | Path):
    source_path = Path(path).expanduser()
    if source_path.suffix.lower() == ".gz":
        return gzip.open(source_path, "rt", encoding="utf-8", newline="")
    return source_path.open("r", encoding="utf-8-sig", newline="")


def import_epss_csv(path: str | Path, db_path: str | Path | None = None) -> int:
    source_path = Path(path).expanduser()
    if not source_path.is_file():
        message = f"EPSS CSV file not found: {source_path}"
        try:
            with connect(db_path) as failure_conn:
                _update_source_sync(
                    failure_conn, "FIRST EPSS", 0, message, status="error"
                )
        except sqlite3.Error:
            pass
        raise FileNotFoundError(message)
    count = 0
    skipped_invalid_rows = 0
    try:
        with _open_maybe_gzip(source_path) as handle, connect(db_path) as conn:
            data_lines = (line for line in handle if line.strip() and not line.lstrip().startswith("#"))
            reader = csv.DictReader(data_lines)
            required = {"cve", "epss", "percentile"}
            if not reader.fieldnames or not required.issubset({x.strip().lower() for x in reader.fieldnames}):
                raise ValueError("Expected FIRST EPSS CSV columns: cve, epss, percentile")
            # Preserve robust behavior if upstream capitalizes headers unexpectedly, but
            # make ignored data rows visible in source_sync details for auditability.
            for raw_row in reader:
                row = {str(key).strip().lower(): value for key, value in raw_row.items() if key}
                cve_id = (row.get("cve") or "").strip().upper()
                if not CVE_RE.fullmatch(cve_id):
                    skipped_invalid_rows += 1
                    continue
                try:
                    epss = float(row["epss"])
                    percentile = float(row["percentile"])
                except (TypeError, ValueError, KeyError):
                    skipped_invalid_rows += 1
                    continue
                if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
                    skipped_invalid_rows += 1
                    continue
                _upsert_vulnerability(conn, cve_id=cve_id, source="FIRST EPSS", published=None,
                                      modified=None, description="")
                conn.execute(
                    "UPDATE vulnerabilities SET epss_score=?,epss_percentile=?,updated_at=? WHERE cve_id=?",
                    (epss, percentile, utc_now(), cve_id),
                )
                count += 1
            details = f"Imported {source_path.name}; valid_rows={count}; skipped_invalid_rows={skipped_invalid_rows}"
            _update_source_sync(
                conn, "FIRST EPSS", count, details,
                status="partial" if skipped_invalid_rows else "success",
            )
    except (
        OSError,
        EOFError,
        gzip.BadGzipFile,
        zlib.error,
        csv.Error,
        UnicodeError,
    ) as exc:
        message = f"Could not read EPSS CSV {source_path}: {exc}"
        try:
            with connect(db_path) as failure_conn:
                _update_source_sync(
                    failure_conn, "FIRST EPSS", 0, message, status="error"
                )
        except sqlite3.Error:
            pass
        raise ValueError(message) from exc
    except (ValueError, sqlite3.Error) as exc:
        # The import transaction has rolled back before this handler runs.
        # Record failure separately while preserving the last successful snapshot.
        try:
            with connect(db_path) as failure_conn:
                _update_source_sync(
                    failure_conn, "FIRST EPSS", 0, str(exc)[:1000], status="error"
                )
        except sqlite3.Error:
            pass
        raise
    return count


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in re.findall(r"[A-Za-z0-9_.+-]+", text) if len(token) >= 2]


def search_cves(query: str, db_path: str | Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Lexical search across CVE IDs, descriptions, vendors/products, and CPE criteria."""
    if not query or not query.strip():
        return []
    safe_limit = max(1, min(int(limit), 200))
    exact = query.strip().upper()
    with connect(db_path) as conn:
        if CVE_RE.fullmatch(exact):
            row = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id=?", (exact,)).fetchone()
            return [dict(row)] if row else []
        terms = list(dict.fromkeys(tokenize(query)))
        if not terms:
            return []
        match_clauses: list[str] = []
        args: list[Any] = []
        for term in terms:
            like = f"%{term}%"
            match_clauses.append(
                "(lower(v.cve_id) LIKE ? OR lower(v.description) LIKE ? OR EXISTS ("
                "SELECT 1 FROM affected_products p WHERE p.cve_id=v.cve_id AND "
                "(lower(coalesce(p.vendor,'')) LIKE ? OR lower(coalesce(p.product,'')) LIKE ? OR lower(p.criteria) LIKE ?)))"
            )
            args.extend([like, like, like, like, like])
        sql = "SELECT DISTINCT v.* FROM vulnerabilities v WHERE " + " AND ".join(match_clauses)
        sql += " ORDER BY v.cisa_kev DESC, COALESCE(v.epss_score,0) DESC, v.modified DESC LIMIT ?"
        args.append(safe_limit)
        return [dict(row) for row in conn.execute(sql, args).fetchall()]


def get_source_freshness(db_path: str | Path | None = None) -> dict[str, Any]:
    """Summarize successful local imports without claiming upstream completeness.

    NVD yearly feed imports are grouped as NVD; the per-source rows remain available
    in the result so a caller can inspect the actual local coverage.
    """
    with connect(db_path) as conn:
        rows = [dict(row) for row in conn.execute(
            "SELECT source,last_success_at,last_attempt_at,records_seen,status,details "
            "FROM source_sync ORDER BY source"
        ).fetchall()]

    now = datetime.now(timezone.utc)

    def parse_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except ValueError:
            return None

    source_groups = {
        "NVD": lambda name: name == "NVD" or name.startswith("NVD yearly "),
        "CISA KEV": lambda name: name == "CISA KEV",
        "FIRST EPSS": lambda name: name == "FIRST EPSS",
    }
    freshness: dict[str, Any] = {"as_of": now.replace(microsecond=0).isoformat(), "sources": {}}
    thresholds = {"NVD": 30, "CISA KEV": 3, "FIRST EPSS": 3}

    for canonical, predicate in source_groups.items():
        group = [row for row in rows if predicate(str(row.get("source") or ""))]
        successful = [row for row in group if parse_timestamp(row.get("last_success_at")) is not None]
        latest_success = max(successful, key=lambda row: parse_timestamp(row.get("last_success_at")) or datetime.min.replace(tzinfo=timezone.utc), default=None)
        latest_attempt = max(group, key=lambda row: parse_timestamp(row.get("last_attempt_at")) or datetime.min.replace(tzinfo=timezone.utc), default=None)
        success_time = parse_timestamp(latest_success.get("last_success_at")) if latest_success else None
        attempt_time = parse_timestamp(latest_attempt.get("last_attempt_at")) if latest_attempt else None
        age_seconds = max(0, int((now - success_time).total_seconds())) if success_time else None
        threshold = thresholds[canonical]
        if age_seconds is None:
            freshness_class = "unknown"
        elif age_seconds <= threshold * 86400:
            freshness_class = "fresh_by_local_import_age"
        elif age_seconds <= threshold * 2 * 86400:
            freshness_class = "aging_by_local_import_age"
        else:
            freshness_class = "stale_by_local_import_age"
        latest_attempt_status = str(latest_attempt.get("status") or "unknown") if latest_attempt else "never_run"
        if not group:
            state = "never_run"
        elif success_time is None:
            state = "no_successful_local_import"
        elif latest_attempt_status != "success" and attempt_time and attempt_time > success_time:
            state = "last_attempt_not_successful"
        else:
            state = "available_from_local_import"
        freshness["sources"][canonical] = {
            "state": state,
            "freshness_class": freshness_class,
            "latest_attempt_status": latest_attempt_status,
            "last_success_at": latest_success.get("last_success_at") if latest_success else None,
            "last_attempt_at": latest_attempt.get("last_attempt_at") if latest_attempt else None,
            "last_success_age_seconds": age_seconds,
            "freshness_threshold_days": threshold,
            "records_seen_on_latest_success": latest_success.get("records_seen") if latest_success else None,
            "latest_success_details": latest_success.get("details") if latest_success else None,
            "sync_record_count": len(group),
            "local_sync_rows": [
                {"source": row.get("source"), "status": row.get("status"),
                 "last_success_at": row.get("last_success_at"), "last_attempt_at": row.get("last_attempt_at"),
                 "records_seen": row.get("records_seen"), "details": row.get("details")}
                for row in sorted(group, key=lambda item: str(item.get("source") or ""))
            ],
            "limitation": "Freshness is measured from local successful import timestamps; it does not prove complete or current upstream coverage.",
        }
    return freshness


def _source_signal_snapshot(row: dict[str, Any], freshness: dict[str, Any]) -> dict[str, Any]:
    sources = freshness.get("sources", {})
    kev_freshness = sources.get("CISA KEV", {})
    epss_freshness = sources.get("FIRST EPSS", {})
    kev_listed = bool(row.get("cisa_kev"))
    epss_available = row.get("epss_score") is not None
    kev_state = (
        "listed_in_local_kev_snapshot" if kev_listed
        else "not_listed_in_successfully_imported_local_kev_snapshot"
        if kev_freshness.get("state") in {"available_from_local_import", "last_attempt_not_successful"}
        else "unknown_no_successful_local_kev_import"
    )
    epss_state = (
        "score_available_in_local_record" if epss_available
        else "no_score_in_local_record_after_successful_local_epss_import"
        if epss_freshness.get("state") in {"available_from_local_import", "last_attempt_not_successful"}
        else "unknown_no_successful_local_epss_import"
    )
    return {
        "NVD": {
            "cve_record_present": True,
            "published": row.get("published"),
            "modified": row.get("modified"),
            "last_successful_local_import": sources.get("NVD", {}).get("last_success_at"),
            "freshness_class": sources.get("NVD", {}).get("freshness_class", "unknown"),
        },
        "CISA KEV": {
            "listed": kev_listed,
            "date_added": row.get("kev_date_added"),
            "state": kev_state,
            "freshness_class": kev_freshness.get("freshness_class", "unknown"),
        },
        "FIRST EPSS": {
            "score": row.get("epss_score"),
            "percentile": row.get("epss_percentile"),
            "state": epss_state,
            "freshness_class": epss_freshness.get("freshness_class", "unknown"),
        },
    }


def search_product_cves(
    query: str,
    db_path: str | Path | None = None,
    limit: int = 20,
    *,
    vendor: str | None = None,
    version: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve CPE product candidates with explicit name/version-context semantics.

    Product matching remains lexical. Version assessment is limited to exact CPE
    version strings and simple dotted-numeric range bounds. NVD's nested configuration
    logic is not evaluated, so no row is promoted to a vulnerability verdict.
    """
    query_name, target_version, version_input_method = split_product_version(query, version)
    terms = list(dict.fromkeys(product_tokens(query_name)))
    if not terms:
        return []
    requested_vendor = normalize_product_text(vendor)
    safe_limit = max(1, min(int(limit), 200))
    freshness = get_source_freshness(db_path)
    candidates: dict[str, dict[str, Any]] = {}
    # Keep the full identity set independent of the per-CVE row display cap below.
    # Otherwise a CVE with many CPE rows can hide additional product identities and
    # make the ambiguity summary falsely appear narrower than the actual retrieval.
    matched_identity_pairs: set[tuple[str, str]] = set()

    def like_pattern(term: str) -> str:
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"%{escaped}%"

    term_clauses: list[str] = []
    sql_args: list[Any] = []
    for term in terms:
        pattern = like_pattern(term)
        term_clauses.append(
            "(coalesce(p.vendor,'') LIKE ? ESCAPE '\\' "
            "OR coalesce(p.product,'') LIKE ? ESCAPE '\\' "
            "OR p.criteria LIKE ? ESCAPE '\\')"
        )
        sql_args.extend((pattern, pattern, pattern))

    sql = """SELECT v.cve_id, v.description, v.published, v.modified,
                    v.cvss_score, v.cvss_severity, v.cisa_kev, v.kev_date_added,
                    v.epss_score, v.epss_percentile,
                    p.vendor AS matched_vendor, p.product AS matched_product,
                    p.criteria AS matched_criteria, p.vulnerable AS cpe_vulnerable,
                    p.version_start_including, p.version_start_excluding,
                    p.version_end_including, p.version_end_excluding
             FROM affected_products p
             JOIN vulnerabilities v ON v.cve_id=p.cve_id
             WHERE p.vulnerable=1 AND (""" + " OR ".join(term_clauses) + ")"

    row_identity_key = ("matched_vendor", "matched_product", "matched_criteria", "version_start_including",
                        "version_start_excluding", "version_end_including", "version_end_excluding")
    match_class_rank = {
        "exact_normalized_vendor_product": 4,
        "all_query_terms_match": 3,
        "partial_query_term_match": 2,
        "vendor_only_match": 1,
    }
    version_rank = {
        "exact_cpe_version_match": 5,
        "within_declared_numeric_version_bounds": 4,
        "wildcard_cpe_version": 3,
        "not_evaluated_no_target_version": 2,
        "range_metadata_available_target_version_missing": 2,
        "exact_cpe_version_present_target_version_missing": 2,
        "range_comparison_indeterminate": 1,
        "cpe_version_component_unavailable": 1,
        "not_applicable_cpe_version_component": 1,
        "exact_cpe_version_mismatch": 0,
        "outside_declared_numeric_version_bounds": 0,
    }

    with connect(db_path) as conn:
        for raw_row in conn.execute(sql, sql_args):
            row = dict(raw_row)
            components = cpe23_components(row.get("matched_criteria"))
            # Re-parse the original CPE criteria for matching so older rows imported by
            # a less careful parser can still get correctly split escaped components.
            matched_vendor = components.get("vendor") or row.get("matched_vendor")
            matched_product = components.get("product") or row.get("matched_product")
            if requested_vendor and normalize_product_text(matched_vendor) != requested_vendor:
                continue
            name_context = classify_name_match(query_name, matched_vendor, matched_product)
            matching = name_context["matching_query_terms"]
            if not matching:
                continue
            normalized_vendor = normalize_product_text(matched_vendor)
            normalized_product = normalize_product_text(matched_product)
            if normalized_vendor or normalized_product:
                matched_identity_pairs.add((normalized_vendor, normalized_product))
            version_context = assess_version_context(target_version, row)
            score = name_context["name_match_score"]
            if name_context["name_match_class"] == "exact_normalized_vendor_product":
                score = min(100.0, score + 10.0)
            candidate = {
                "cve_id": row["cve_id"],
                "description": row["description"],
                "published": row["published"],
                "modified": row["modified"],
                "cvss_score": row["cvss_score"],
                "cvss_severity": row["cvss_severity"],
                "cisa_kev": bool(row["cisa_kev"]),
                "kev_date_added": row["kev_date_added"],
                "epss_score": row["epss_score"],
                "epss_percentile": row["epss_percentile"],
                "matched_vendor": matched_vendor,
                "matched_product": matched_product,
                "matched_criteria": row["matched_criteria"],
                "cpe_vulnerable": bool(row["cpe_vulnerable"]),
                "version_start_including": row["version_start_including"],
                "version_start_excluding": row["version_start_excluding"],
                "version_end_including": row["version_end_including"],
                "version_end_excluding": row["version_end_excluding"],
                "product_relevance_score": score,
                "matching_query_terms": matching,
                "matching_vendor_terms": name_context["matching_vendor_terms"],
                "matching_product_terms": name_context["matching_product_terms"],
                "query_normalization": {
                    "original_query": query,
                    "normalized_product_query": name_context["normalized_query"],
                    "query_terms": terms,
                    "version_input_method": version_input_method,
                    "version_input_conflict": version_input_method == "explicit_option_conflicts_with_query_suffix",
                    "target_vendor": vendor,
                    "normalized_target_vendor": requested_vendor or None,
                    "target_version": target_version,
                },
                "name_match_class": name_context["name_match_class"],
                "version_context": version_context,
                "version_match_status": version_context["status"],
                "match_method": "normalized_vendor_product_token_overlap_against_local_NVD_CPE_rows",
                "retrieval_source": "local_NVD_affected_products_table",
                "configuration_evaluation": "not_performed_nested_NVD_AND_OR_logic_not_evaluated",
                "local_source_signals": _source_signal_snapshot(row, freshness),
                "candidate_relevance": (
                    "name_match_but_target_version_does_not_match_this_CPE_row"
                    if target_version and version_context["status"] in {
                        "exact_cpe_version_mismatch", "outside_declared_numeric_version_bounds"
                    } else
                    "name_and_version_context_match_full_applicability_unevaluated"
                    if target_version and version_context["status"] in {
                        "exact_cpe_version_match", "within_declared_numeric_version_bounds"
                    } else
                    "name_match_version_comparison_indeterminate"
                    if target_version and version_context["status"] == "range_comparison_indeterminate"
                    else
                    "name_match_version_not_supplied" if not target_version
                    else "name_match_version_context_not_conclusive"
                ),
                "assessment": "product_context_candidate_not_file_attribution",
            }
            product_row = {key: row.get(key) for key in row_identity_key}
            product_row.update({
                "vendor": matched_vendor,
                "product": matched_product,
                "name_match_class": name_context["name_match_class"],
                "version_match_status": version_context["status"],
                "version_context": version_context,
            })
            candidate["matching_product_rows"] = [product_row]
            candidate["matched_cpe_row_count"] = 1
            candidate["_rank"] = (
                match_class_rank.get(name_context["name_match_class"], 0),
                version_rank.get(version_context["status"], 1) if target_version else 0,
                score,
            )
            cve_id = row["cve_id"]
            existing = candidates.get(cve_id)
            if existing is None:
                candidates[cve_id] = candidate
                continue
            row_signature = tuple(product_row.get(key) for key in row_identity_key)
            existing_signatures = {
                tuple(item.get(key) for key in row_identity_key)
                for item in existing.get("matching_product_rows", [])
            }
            if row_signature not in existing_signatures:
                existing["matched_cpe_row_count"] += 1
                if len(existing["matching_product_rows"]) < 10:
                    existing["matching_product_rows"].append(product_row)
            if candidate["_rank"] > existing["_rank"]:
                rows = existing["matching_product_rows"]
                count = existing["matched_cpe_row_count"]
                candidate["matching_product_rows"] = rows
                candidate["matched_cpe_row_count"] = count
                candidates[cve_id] = candidate

    results = list(candidates.values())
    identities = sorted(matched_identity_pairs)
    ambiguity = {
        "status": "ambiguous_multiple_product_identities" if len(identities) > 1 else "single_or_unconfirmed_product_identity",
        "distinct_matched_product_identity_count": len(identities),
        "result_limit": safe_limit,
        "assessment_scope": "identity ambiguity is computed across all matching CPE rows before the per-CVE result limit is applied",
        "matched_product_identities": [
            {"vendor": vendor or None, "product": product or None}
            for vendor, product in identities[:20]
        ],
        "identities_truncated": len(identities) > 20,
        "interpretation": (
            "Multiple distinct vendor/product identities matched the lexical query; review vendor, product and version fields."
            if len(identities) > 1 else
            "A single or unconfirmed vendor/product identity was retrieved; lexical matching still does not prove product presence."
        ),
    }
    for candidate in results:
        candidate["query_ambiguity"] = ambiguity
        candidate.pop("_rank", None)
    return sorted(results, key=lambda item: (
        -match_class_rank.get(item.get("name_match_class", ""), 0),
        -version_rank.get(item.get("version_match_status", ""), 1) if target_version else 0,
        -item["product_relevance_score"],
        -int(item["cisa_kev"]),
        -(item["epss_score"] or 0.0),
        item["cve_id"],
    ))[:safe_limit]


def get_cve(cve_id: str, db_path: str | Path | None = None) -> dict[str, Any] | None:
    cve_id = cve_id.strip().upper()
    if not CVE_RE.fullmatch(cve_id):
        raise ValueError("CVE ID must look like CVE-2024-12345")
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["references"] = [dict(r) for r in conn.execute(
            "SELECT url,name,tags_json FROM vulnerability_references WHERE cve_id=? ORDER BY url", (cve_id,)
        ).fetchall()]
        result["weaknesses"] = [dict(r) for r in conn.execute(
            "SELECT cwe_id,description FROM vulnerability_weaknesses WHERE cve_id=? ORDER BY cwe_id", (cve_id,)
        ).fetchall()]
        result["affected_products"] = [dict(r) for r in conn.execute(
            "SELECT criteria,vendor,product,version_start_including,version_start_excluding,"
            "version_end_including,version_end_excluding,vulnerable FROM affected_products WHERE cve_id=? ORDER BY vendor,product",
            (cve_id,),
        ).fetchall()]
        return result


def import_reference_samples_json(path: str | Path, db_path: str | Path | None = None) -> int:
    """Import curated sample metadata; input JSON never contains or executes sample bytes.

    Expected format: {"samples": [{"sample_id", "sha256", "file_type", "label",
    "source_name", "label_basis", optional metadata, "cve_links": [...]}]}.
    Labels and links are user-provided claims; provenance/confidence are retained verbatim.
    """
    path = Path(path).expanduser()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read reference-sample JSON: {exc}") from exc
    samples = payload.get("samples") if isinstance(payload, dict) else None
    if not isinstance(samples, list):
        raise ValueError("Expected JSON object with a 'samples' array")
    count = 0
    with connect(db_path) as conn:
        for sample_index, sample in enumerate(samples, start=1):
            if not isinstance(sample, dict):
                continue
            required = ("sample_id", "sha256", "file_type", "label", "source_name", "label_basis")
            if any(not isinstance(sample.get(key), str) or not sample[key].strip() for key in required):
                raise ValueError(f"Each sample requires non-empty string fields: {', '.join(required)}")
            sha256 = sample["sha256"].lower()
            if not re.fullmatch(r"[0-9a-f]{64}", sha256):
                raise ValueError(f"Invalid SHA-256 for sample {sample['sample_id']}")
            label = sample["label"].lower()
            confidence = str(sample.get("confidence", "unknown")).lower()
            if label not in {"benign", "malicious", "suspicious", "unknown"}:
                raise ValueError(f"Unsupported label for sample {sample['sample_id']}: {label}")
            if confidence not in {"verified", "high", "medium", "low", "unknown"}:
                raise ValueError(f"Unsupported confidence value: {confidence}")
            conn.execute(
                """INSERT INTO reference_samples
                   (sample_id,sha256,file_name,file_type,label,source_name,source_url,product_name,product_version,
                    label_basis,confidence,notes,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(sample_id) DO UPDATE SET sha256=excluded.sha256,file_name=excluded.file_name,
                    file_type=excluded.file_type,label=excluded.label,source_name=excluded.source_name,
                    source_url=excluded.source_url,product_name=excluded.product_name,product_version=excluded.product_version,
                    label_basis=excluded.label_basis,confidence=excluded.confidence,notes=excluded.notes""",
                (sample["sample_id"], sha256, sample.get("file_name", ""), sample["file_type"], label,
                 sample["source_name"], sample.get("source_url"), sample.get("product_name"), sample.get("product_version"),
                 sample["label_basis"], confidence, sample.get("notes", ""), utc_now()),
            )
            raw_links = sample.get("cve_links", []) or []
            if not isinstance(raw_links, list):
                raise ValueError(f"cve_links for sample {sample['sample_id']} must be an array")
            for link_index, link in enumerate(raw_links, start=1):
                if not isinstance(link, dict):
                    continue
                cve_id = str(link.get("cve_id", "")).upper()
                if not CVE_RE.fullmatch(cve_id):
                    raise ValueError(f"Invalid CVE ID in sample {sample['sample_id']}: {cve_id}")
                link_confidence = str(link.get("confidence", "unknown")).lower()
                if link_confidence not in {"verified", "high", "medium", "low", "unknown"}:
                    raise ValueError(f"Unsupported confidence value in sample CVE link: {link_confidence}")
                if not conn.execute("SELECT 1 FROM vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone():
                    raise ValueError(f"CVE {cve_id} must be imported before linking sample {sample['sample_id']}")
                conn.execute(
                    """INSERT INTO sample_vulnerability_links(sample_id,cve_id,association_type,evidence_basis,confidence,
                       verified,source_url) VALUES(?,?,?,?,?,?,?) ON CONFLICT(sample_id,cve_id,association_type) DO UPDATE SET
                       evidence_basis=excluded.evidence_basis,confidence=excluded.confidence,verified=excluded.verified,
                       source_url=excluded.source_url""",
                    (sample["sample_id"], cve_id, str(link.get("association_type", "reported")),
                     str(link.get("evidence_basis", "")), link_confidence,
                     int(bool(link.get("verified", False))), link.get("source_url")),
                )
            count += 1
    return count


def lookup_reference_samples(sha256: str, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return exact-SHA sample matches with the provenance and linked CVEs preserved."""
    normalized = sha256.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM reference_samples WHERE sha256=?", (normalized,)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["cve_links"] = [dict(link) for link in conn.execute(
                "SELECT l.cve_id,l.association_type,l.evidence_basis,l.confidence,l.verified,l.source_url, "
                "v.description,v.published,v.modified,v.cvss_score,v.cvss_severity,v.cisa_kev,v.kev_date_added, "
                "v.epss_score,v.epss_percentile "
                "FROM sample_vulnerability_links l JOIN vulnerabilities v USING(cve_id) "
                "WHERE l.sample_id=? ORDER BY l.cve_id", (item["sample_id"],)
            ).fetchall()]
            item["match_type"] = "exact_sha256"
            item["interpretation"] = (
                "Exact byte-for-byte SHA-256 match to registered sample metadata. The sample's label and CVE links "
                "retain the submitted provenance; a link is not automatically proof of exploitability."
            )
            result.append(item)
        return result


def get_stats(db_path: str | Path | None = None) -> dict[str, Any]:
    with connect(db_path) as conn:
        counts = {
            "vulnerabilities": conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
            "cisa_kev": conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cisa_kev=1").fetchone()[0],
            "affected_products": conn.execute("SELECT COUNT(*) FROM affected_products").fetchone()[0],
            "references": conn.execute("SELECT COUNT(*) FROM vulnerability_references").fetchone()[0],
            "analyses": conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0],
            "evidence_items": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            "reference_samples": conn.execute("SELECT COUNT(*) FROM reference_samples").fetchone()[0],
            "sample_cve_links": conn.execute("SELECT COUNT(*) FROM sample_vulnerability_links").fetchone()[0],
            "schema_version": conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0],
        }
        counts["sources"] = [dict(row) for row in conn.execute("SELECT * FROM source_sync ORDER BY source").fetchall()]
        return counts


def get_analysis(analysis_id: int, db_path: str | Path | None = None) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM analysis_runs WHERE id=?", (analysis_id,)).fetchone()
        if not row:
            return None
        report = json.loads(row["summary_json"])
        report["analysis_id"] = row["id"]
        report["created_at"] = row["created_at"]
        report["evidence"] = []
        for evidence_row in conn.execute(
            "SELECT evidence_type,evidence_key,value_text,severity,details_json FROM evidence WHERE analysis_id=? ORDER BY id",
            (analysis_id,),
        ):
            item = dict(evidence_row)
            item["key"] = item.pop("evidence_key")
            raw_value = item.pop("value_text")
            try:
                item["value"] = json.loads(raw_value)
            except (TypeError, json.JSONDecodeError):
                item["value"] = raw_value
            item["details"] = json.loads(item.pop("details_json"))
            # Rehydrate report-level provenance after loading normalized evidence rows.
            # Traceability is already present in details_json, so the schema stays unchanged.
            traceability = item["details"].get("traceability")
            if isinstance(traceability, dict):
                item["evidence_id"] = traceability.get("evidence_id")
                item["evidence_class"] = traceability.get("evidence_class")
                item["evidence_origin"] = traceability.get("evidence_origin")
                source_locator = traceability.get("source_locator")
                if isinstance(source_locator, dict):
                    item["source_locator"] = source_locator
            report["evidence"].append(item)
        report["stored_candidates"] = [dict(item) for item in conn.execute(
            "SELECT c.cve_id,c.rank,c.score,c.assessment,c.rationale_json,v.description,v.cvss_score,v.cvss_severity,v.cisa_kev,v.epss_score "
            "FROM candidate_associations c JOIN vulnerabilities v USING(cve_id) WHERE c.analysis_id=? ORDER BY c.rank",
            (analysis_id,),
        )]
        return report
