"""Data import, provenance, lexical search, and local database queries."""
from __future__ import annotations

import csv
import gzip
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .db import connect

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
    # CPE 2.3 fields: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    # Escaped delimiters are not fully decoded here; original criteria is preserved.
    parts = criteria.split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor, product = parts[3], parts[4]
        return (vendor if vendor not in {"", "*", "-"} else None,
                product if product not in {"", "*", "-"} else None)
    return None, None


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


def _update_source_sync(conn: sqlite3.Connection, source: str, count: int, details: str) -> None:
    now = utc_now()
    conn.execute(
        """INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(source) DO UPDATE SET last_success_at=excluded.last_success_at,
           last_attempt_at=excluded.last_attempt_at,records_seen=excluded.records_seen,
           status='success',details=excluded.details""",
        (source, now, now, count, "success", details),
    )


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

    # Validate the root key first, then reopen and stream one vulnerability at a time.
    try:
        found_key = False
        with opener(source_path, "rb") as handle:
            for prefix, event, value in ijson.parse(handle):
                if prefix == "" and event == "map_key" and value == "vulnerabilities":
                    found_key = True
                    break
                if prefix == "" and event == "end_map":
                    break
        if not found_key:
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
        raise FileNotFoundError(f"NVD import file not found: {source_path}")
    count = 0
    try:
        with connect(db_path) as conn:
            for item in _iter_nvd_items(source_path):
                if not isinstance(item, dict):
                    continue
                cve = item.get("cve", item)
                if not isinstance(cve, dict):
                    continue
                cve_id = cve.get("id")
                if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
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
            _update_source_sync(conn, "NVD", count, f"Imported {source_path.name}")
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read NVD JSON from {source_path}: {exc}") from exc
    return count


def import_kev_json(path: str | Path, db_path: str | Path | None = None) -> int:
    source_path = Path(path).expanduser()
    if not source_path.is_file():
        raise FileNotFoundError(f"CISA KEV file not found: {source_path}")
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read valid CISA KEV JSON from {source_path}: {exc}") from exc
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("Expected CISA KEV JSON with a 'vulnerabilities' array")
    count = 0
    with connect(db_path) as conn:
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve_id = row.get("cveID")
            if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
                continue
            cve_id = cve_id.upper()
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
        _update_source_sync(conn, "CISA KEV", count, f"Imported {source_path.name}")
    return count


def _open_maybe_gzip(path: str | Path):
    source_path = Path(path).expanduser()
    if source_path.suffix.lower() == ".gz":
        return gzip.open(source_path, "rt", encoding="utf-8", newline="")
    return source_path.open("r", encoding="utf-8-sig", newline="")


def import_epss_csv(path: str | Path, db_path: str | Path | None = None) -> int:
    source_path = Path(path).expanduser()
    if not source_path.is_file():
        raise FileNotFoundError(f"EPSS CSV file not found: {source_path}")
    count = 0
    try:
        with _open_maybe_gzip(source_path) as handle, connect(db_path) as conn:
            data_lines = (line for line in handle if line.strip() and not line.lstrip().startswith("#"))
            reader = csv.DictReader(data_lines)
            required = {"cve", "epss", "percentile"}
            if not reader.fieldnames or not required.issubset({x.strip().lower() for x in reader.fieldnames}):
                raise ValueError("Expected FIRST EPSS CSV columns: cve, epss, percentile")
            # Preserve robust behavior if upstream capitalizes headers unexpectedly.
            for raw_row in reader:
                row = {str(key).strip().lower(): value for key, value in raw_row.items() if key}
                cve_id = (row.get("cve") or "").strip().upper()
                if not CVE_RE.fullmatch(cve_id):
                    continue
                try:
                    epss = float(row["epss"])
                    percentile = float(row["percentile"])
                except (TypeError, ValueError, KeyError):
                    continue
                if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
                    continue
                _upsert_vulnerability(conn, cve_id=cve_id, source="FIRST EPSS", published=None,
                                      modified=None, description="")
                conn.execute(
                    "UPDATE vulnerabilities SET epss_score=?,epss_percentile=?,updated_at=? WHERE cve_id=?",
                    (epss, percentile, utc_now(), cve_id),
                )
                count += 1
            _update_source_sync(conn, "FIRST EPSS", count, f"Imported {source_path.name}")
    except (OSError, gzip.BadGzipFile) as exc:
        raise ValueError(f"Could not read EPSS CSV {source_path}: {exc}") from exc
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


def search_product_cves(query: str, db_path: str | Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Find CVEs whose NVD affected-product criteria lexically resemble the target product.

    This is a candidate retrieval aid, not CPE range evaluation or proof a particular
    installed version is vulnerable. Product CPE criteria may have logical AND/OR context.

    Important performance note: filter matching CPE rows in SQLite before materializing
    Python objects. NVD databases can contain millions of affected-product rows; selecting
    every row (including the large raw_json field) and filtering it in Python can exhaust
    memory or make interactive terminals appear unresponsive.
    """
    terms = list(dict.fromkeys(tokenize(query)))
    if not terms:
        return []
    safe_limit = max(1, min(int(limit), 200))
    candidates: dict[str, dict[str, Any]] = {}

    def like_pattern(term: str) -> str:
        # Treat user input literally; LIKE wildcards in a query must not broaden matches.
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

    # Select only fields used by ranking; raw_json is intentionally excluded. Filtering
    # inside SQLite avoids copying millions of irrelevant joined rows into Python memory.
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

    with connect(db_path) as conn:
        # Iterate the filtered cursor instead of fetchall(), limiting peak memory to
        # relevant rows only. This still performs a lexical scan in SQLite, not full CPE
        # configuration evaluation.
        for row in conn.execute(sql, sql_args):
            rowd = dict(row)
            product_text = " ".join(
                str(rowd.get(key) or "")
                for key in ("matched_vendor", "matched_product", "matched_criteria")
            ).lower()
            matching = [
                term for term in terms
                if term in product_text or term.replace("_", " ") in product_text
            ]
            if not matching:
                continue
            score = round(100.0 * len(set(matching)) / len(set(terms)), 2)
            if query.strip().lower() in product_text:
                score = min(100.0, score + 10.0)
            cve_id = rowd["cve_id"]
            candidate = {
                "cve_id": cve_id,
                "description": rowd["description"],
                "published": rowd["published"],
                "modified": rowd["modified"],
                "cvss_score": rowd["cvss_score"],
                "cvss_severity": rowd["cvss_severity"],
                "cisa_kev": bool(rowd["cisa_kev"]),
                "kev_date_added": rowd["kev_date_added"],
                "epss_score": rowd["epss_score"],
                "epss_percentile": rowd["epss_percentile"],
                "matched_vendor": rowd["matched_vendor"],
                "matched_product": rowd["matched_product"],
                "matched_criteria": rowd["matched_criteria"],
                "cpe_vulnerable": bool(rowd["cpe_vulnerable"]),
                "version_start_including": rowd["version_start_including"],
                "version_start_excluding": rowd["version_start_excluding"],
                "version_end_including": rowd["version_end_including"],
                "version_end_excluding": rowd["version_end_excluding"],
                "product_relevance_score": score,
                "matching_query_terms": matching,
                "assessment": "product_context_candidate_not_file_attribution",
            }
            existing = candidates.get(cve_id)
            if existing is None or candidate["product_relevance_score"] > existing["product_relevance_score"]:
                candidates[cve_id] = candidate

    return sorted(candidates.values(), key=lambda item: (
        -item["product_relevance_score"], -int(item["cisa_kev"]),
        -(item["epss_score"] or 0.0), item["cve_id"]
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
        for sample in samples:
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
            for link in sample.get("cve_links", []) or []:
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
            report["evidence"].append(item)
        report["stored_candidates"] = [dict(item) for item in conn.execute(
            "SELECT c.cve_id,c.rank,c.score,c.assessment,c.rationale_json,v.description,v.cvss_score,v.cvss_severity,v.cisa_kev,v.epss_score "
            "FROM candidate_associations c JOIN vulnerabilities v USING(cve_id) WHERE c.analysis_id=? ORDER BY c.rank",
            (analysis_id,),
        )]
        return report
