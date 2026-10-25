"""Free public-source download/synchronization. Network calls are opt-in via CLI."""
from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
import sqlite3
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .db import connect
from .store import import_epss_csv, import_kev_json, import_nvd_json, utc_now

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "CVEvident/0.1.0 (local research tool; no telemetry)"
MAX_NVD_API_RESPONSE_BYTES = 64 * 1024 * 1024


def download(url: str, destination: str | Path, timeout: int = 60,
             max_bytes: int = 500 * 1024 * 1024) -> Path:
    """Download atomically to a cache file with a size limit; don't leave partial files."""
    target = Path(destination).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    temporary: Path | None = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_length = response.headers.get("Content-Length")
            expected_length: int | None = None
            if content_length not in (None, ""):
                try:
                    expected_length = int(content_length)
                except (TypeError, ValueError) as exc:
                    raise RuntimeError(f"Invalid Content-Length while downloading {url}") from exc
                if expected_length < 0:
                    raise RuntimeError(f"Invalid negative Content-Length while downloading {url}")
                if expected_length > max_bytes:
                    raise RuntimeError(f"Download exceeds size limit ({max_bytes} bytes): {url}")
            fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".part", dir=target.parent)
            temporary = Path(tmp_name)
            total = 0
            with os.fdopen(fd, "wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"Download exceeds size limit ({max_bytes} bytes): {url}")
                    output.write(chunk)
        if expected_length is not None and total != expected_length:
            raise RuntimeError(
                f"Incomplete download from {url}: expected {expected_length} bytes, received {total}"
            )
        if total == 0:
            raise RuntimeError(f"Downloaded an empty response from {url}")
        temporary.replace(target)
        temporary = None
        return target
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} while downloading {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not download {url}: {exc.reason}") from exc
    except http.client.HTTPException as exc:
        raise RuntimeError(f"Incomplete or invalid HTTP response while downloading {url}: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _mark_failure(db_path: str | Path | None, source: str, message: str) -> None:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO source_sync(source,last_attempt_at,status,details) VALUES(?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,
               status='error',details=excluded.details""",
            (source, now, "error", message[:1000]),
        )


def sync_kev(db_path: str | Path | None = None, destination: str | Path | None = None) -> int:
    path = Path(destination).expanduser() if destination else Path.home() / ".cvevident" / "cache" / "known_exploited_vulnerabilities.json"
    try:
        download(KEV_URL, path)
        return import_kev_json(path, db_path=db_path)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        _mark_failure(db_path, "CISA KEV", str(exc))
        raise


def sync_epss(db_path: str | Path | None = None, destination: str | Path | None = None) -> int:
    path = Path(destination).expanduser() if destination else Path.home() / ".cvevident" / "cache" / "epss_scores-current.csv.gz"
    try:
        download(EPSS_URL, path)
        return import_epss_csv(path, db_path=db_path)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        _mark_failure(db_path, "FIRST EPSS", str(exc))
        raise


def _parse_meta(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def _sha256_uncompressed_gzip(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with gzip.open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, EOFError, zlib.error) as exc:
        raise RuntimeError(f"Downloaded NVD feed is not a valid gzip stream: {exc}") from exc
    return digest.hexdigest()


def sync_nvd_year(year: int, db_path: str | Path | None = None,
                  cache_dir: str | Path | None = None, force_download: bool = False) -> dict[str, Any]:
    """Download and import one official annual NVD 2.0 feed with metadata/SHA validation.

    NVD's 2002 annual feed also contains records preceding and including CVE-2002;
    later annual feeds are keyed by their CVE year. This function is intentionally
    one year at a time so users can control bandwidth and local database size.
    """
    from datetime import datetime as _datetime
    current_year = _datetime.now(timezone.utc).year
    if not 2002 <= int(year) <= current_year:
        raise ValueError(f"year must be between 2002 and {current_year}; the 2002 feed includes older CVEs")
    year = int(year)
    dest_dir = Path(cache_dir).expanduser() if cache_dir else Path.home() / ".cvevident" / "cache" / "nvd-yearly"
    name = f"nvdcve-2.0-{year}.json.gz"
    feed_path = dest_dir / name
    meta_path = dest_dir / f"nvdcve-2.0-{year}.meta"
    feed_url = f"{NVD_FEED_BASE}/{name}"
    meta_url = f"{NVD_FEED_BASE}/nvdcve-2.0-{year}.meta"
    source_key = f"NVD yearly {year}"
    candidate_path: Path | None = None
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        download(meta_url, meta_path, max_bytes=2 * 1024 * 1024)
        meta_text = meta_path.read_text(encoding="utf-8")
        meta = _parse_meta(meta_text)
        expected_sha = meta.get("sha256")
        if not expected_sha or not re_full_sha256(expected_sha):
            raise RuntimeError(f"NVD metadata file for {year} does not contain a valid SHA-256")
        with connect(db_path) as conn:
            state = conn.execute("SELECT records_seen,details FROM source_sync WHERE source=?", (source_key,)).fetchone()
        if state and f"sha256={expected_sha}" in (state["details"] or "") and not force_download:
            # Metadata has been fetched freshly above; no need to re-download/re-import if this DB
            # has already completed this exact feed version.
            with connect(db_path) as conn:
                now = utc_now()
                conn.execute("UPDATE source_sync SET last_attempt_at=?,status='success',details=? WHERE source=?",
                             (now, f"year={year}; sha256={expected_sha}; unchanged", source_key))
            return {"year": year, "status": "up_to_date", "records_imported": 0, "feed_sha256": expected_sha}
        cached_valid = False
        if feed_path.is_file() and not force_download:
            try:
                cached_valid = _sha256_uncompressed_gzip(feed_path).lower() == expected_sha.lower()
            except RuntimeError:
                cached_valid = False
        if cached_valid:
            actual_sha = _sha256_uncompressed_gzip(feed_path)
            import_path = feed_path
        else:
            # Keep any previous cache intact until the newly downloaded feed has
            # passed the digest check. The temporary name still ends in .gz so the
            # regular importer selects gzip mode correctly.
            candidate_path = dest_dir / f".{name}.{os.getpid()}.{time.time_ns()}.download.gz"
            download(feed_url, candidate_path, max_bytes=500 * 1024 * 1024)
            actual_sha = _sha256_uncompressed_gzip(candidate_path)
            if actual_sha.lower() != expected_sha.lower():
                raise RuntimeError(
                    f"SHA-256 verification failed for NVD {year} feed: metadata={expected_sha}, actual={actual_sha}"
                )
            import_path = candidate_path
        if actual_sha.lower() != expected_sha.lower():
            raise RuntimeError(f"SHA-256 verification failed for NVD {year} feed: metadata={expected_sha}, actual={actual_sha}")
        count = import_nvd_json(import_path, db_path=db_path)
        if candidate_path is not None:
            candidate_path.replace(feed_path)
            candidate_path = None
        now = utc_now()
        with connect(db_path) as conn:
            conn.execute(
                """INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details)
                   VALUES(?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET last_success_at=excluded.last_success_at,
                   last_attempt_at=excluded.last_attempt_at,records_seen=excluded.records_seen,status='success',details=excluded.details""",
                (source_key, now, now, count, "success", f"year={year}; sha256={expected_sha}"),
            )
        return {"year": year, "status": "imported", "records_imported": count, "feed_sha256": expected_sha}
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        _mark_failure(db_path, source_key, str(exc))
        raise
    finally:
        if candidate_path is not None:
            try:
                candidate_path.unlink(missing_ok=True)
            except OSError:
                pass


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def sync_nvd_years(from_year: int = 2002, to_year: int | None = None,
                   db_path: str | Path | None = None, cache_dir: str | Path | None = None,
                   force_download: bool = False) -> dict[str, Any]:
    """Import a range of annual feeds, continuing after per-year failures."""
    from datetime import datetime as _datetime
    end_year = int(to_year) if to_year is not None else _datetime.now(timezone.utc).year
    if not 2002 <= int(from_year) <= end_year <= _datetime.now(timezone.utc).year:
        raise ValueError("year range must satisfy 2002 <= from_year <= to_year <= current year")
    results: list[dict[str, Any]] = []
    for year in range(int(from_year), end_year + 1):
        try:
            results.append(sync_nvd_year(year, db_path, cache_dir, force_download))
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            results.append({"year": year, "status": "error", "error": str(exc)})
    return {
        "status": "ok" if all(row["status"] in {"imported", "up_to_date"} for row in results) else "partial_or_failed",
        "from_year": int(from_year), "to_year": end_year, "years": results,
        "records_imported": sum(int(row.get("records_imported", 0)) for row in results),
    }


def _request_json(url: str, headers: dict[str, str] | None = None, timeout: int = 90) -> dict[str, Any]:
    """Fetch one bounded NVD API page and validate its basic JSON structure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content_length = response.headers.get("Content-Length")
                expected_length: int | None = None
                if content_length not in (None, ""):
                    try:
                        expected_length = int(content_length)
                    except (TypeError, ValueError) as exc:
                        raise RuntimeError("NVD API returned an invalid Content-Length") from exc
                    if expected_length < 0 or expected_length > MAX_NVD_API_RESPONSE_BYTES:
                        raise RuntimeError(
                            f"NVD API response exceeds the {MAX_NVD_API_RESPONSE_BYTES}-byte limit or has invalid length"
                        )
                body = response.read(MAX_NVD_API_RESPONSE_BYTES + 1)
                if len(body) > MAX_NVD_API_RESPONSE_BYTES:
                    raise RuntimeError(
                        f"NVD API response exceeds the {MAX_NVD_API_RESPONSE_BYTES}-byte limit"
                    )
                if expected_length is not None and len(body) != expected_length:
                    last_error = RuntimeError(
                        f"NVD API response was incomplete: expected {expected_length} bytes, received {len(body)}"
                    )
                    if attempt < 3:
                        time.sleep(min(8.0, 2.0 ** attempt))
                        continue
                    raise RuntimeError(str(last_error)) from last_error
            try:
                payload = json.loads(body.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise RuntimeError(
                    f"NVD API returned invalid JSON (possibly truncated): {exc}"
                ) from exc
            except json.JSONDecodeError as exc:
                # Retry only if the parser reached the end of the body.
                # Clearly invalid JSON near the beginning fails immediately.
                if exc.pos >= max(0, len(body) - 1) and attempt < 3:
                    last_error = exc
                    time.sleep(min(8.0, 2.0 ** attempt))
                    continue
                raise RuntimeError(
                    f"NVD API returned invalid JSON (possibly truncated): {exc}"
                ) from exc
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise RuntimeError("NVD API response did not contain a vulnerabilities array")
            for index, item in enumerate(payload["vulnerabilities"], start=1):
                if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                    raise RuntimeError(f"NVD API vulnerabilities item {index} was not a CVE record object")
            return payload
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", errors="replace")
            if exc.code in {429, 500, 502, 503, 504} and attempt < 3:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    delay = min(30.0, max(1.0, float(retry_after))) if retry_after else min(30.0, 2.0 ** attempt)
                except ValueError:
                    delay = min(30.0, 2.0 ** attempt)
                time.sleep(delay)
                last_error = exc
                continue
            raise RuntimeError(f"NVD API returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(min(8.0, 2.0 ** attempt))
                continue
            raise RuntimeError(f"NVD API request failed: {exc.reason}") from exc
        except http.client.HTTPException as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(min(8.0, 2.0 ** attempt))
                continue
            raise RuntimeError(f"NVD API response was incomplete or invalid: {exc}") from exc
    raise RuntimeError(f"NVD API request failed after retries: {last_error}")


def sync_nvd_modified(db_path: str | Path | None = None, days: int = 7,
                      cache_dir: str | Path | None = None, sleep_seconds: float | None = None) -> int:
    """Import recent NVD modifications atomically after every page has been validated.

    Page responses are cached individually, but database changes are deferred until
    all advertised pages have been fetched. A failed later page therefore cannot
    leave an apparently successful partial import in the local database.
    """
    if not 1 <= days <= 120:
        raise ValueError("days must be between 1 and 120 for the NVD modified-date API")
    if sleep_seconds is not None and sleep_seconds < 0:
        raise ValueError("sleep_seconds cannot be negative")
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": "2000",
    }
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    total_imported = 0
    start_index = 0
    expected_total: int | None = None
    aggregate_path: Path | None = None
    try:
        dest_dir = Path(cache_dir).expanduser() if cache_dir else Path.home() / ".cvevident" / "cache" / "nvd-modified"
        dest_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="nvd-modified-aggregate-", suffix=".json", dir=dest_dir)
        aggregate_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as aggregate:
            aggregate.write('{"vulnerabilities":[')
            first_record = True
            while True:
                query = urllib.parse.urlencode({**params, "startIndex": str(start_index)})
                payload = _request_json(f"{NVD_URL}?{query}", headers=headers)
                items = payload["vulnerabilities"]

                page_total = payload.get("totalResults")
                page_start = payload.get("startIndex")
                page_size = payload.get("resultsPerPage")
                for key, value in (("totalResults", page_total), ("startIndex", page_start),
                                   ("resultsPerPage", page_size)):
                    if type(value) is not int or value < 0:
                        raise RuntimeError(f"NVD API pagination field {key} must be a non-negative integer")
                if page_start != start_index:
                    raise RuntimeError(
                        f"NVD API pagination mismatch: requested startIndex={start_index}, received {page_start}"
                    )
                actual_count = len(items)
                requested_page_limit = int(params["resultsPerPage"])
                if page_size > requested_page_limit or actual_count > requested_page_limit:
                    raise RuntimeError("NVD API returned more records than the requested page size")
                if actual_count > page_size:
                    raise RuntimeError(
                        f"NVD API pagination mismatch: resultsPerPage={page_size}, but received {actual_count} records"
                    )
                if expected_total is None:
                    expected_total = page_total
                elif page_total != expected_total:
                    raise RuntimeError(
                        f"NVD API totalResults changed during pagination ({expected_total} to {page_total}); sync aborted"
                    )
                if start_index + actual_count > page_total:
                    raise RuntimeError("NVD API page extends beyond totalResults")
                if actual_count == 0 and start_index < page_total:
                    raise RuntimeError(
                        f"NVD API returned an empty page at startIndex={start_index} before totalResults={page_total}"
                    )
                if actual_count < page_size and start_index + actual_count < page_total:
                    raise RuntimeError(
                        "NVD API returned a short page before totalResults was reached; sync aborted"
                    )

                for index, item in enumerate(items, start=1):
                    cve = item.get("cve")
                    cve_id = cve.get("id") if isinstance(cve, dict) else None
                    if not isinstance(cve_id, str) or not cve_id.strip():
                        raise RuntimeError(f"NVD API page contains a record without a CVE ID (item {index})")
                    if not first_record:
                        aggregate.write(",")
                    json.dump(item, aggregate, ensure_ascii=False, separators=(",", ":"))
                    first_record = False

                batch_path = dest_dir / f"nvd-{start.strftime('%Y%m%d')}-{end.strftime('%Y%m%d')}-{start_index}.json"
                page_part = batch_path.with_suffix(batch_path.suffix + ".part")
                try:
                    page_part.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                    page_part.replace(batch_path)
                finally:
                    page_part.unlink(missing_ok=True)

                if start_index + actual_count >= page_total:
                    break
                if actual_count <= 0:
                    raise RuntimeError("NVD API pagination made no progress")
                start_index += actual_count
                if sleep_seconds is not None:
                    time.sleep(sleep_seconds)
                else:
                    time.sleep(0.7 if api_key else 6.0)
            aggregate.write("]}")
            aggregate.flush()
            os.fsync(aggregate.fileno())

        # import_nvd_json wraps its writes in one SQLite transaction. No page is
        # imported until pagination and every response have passed validation.
        total_imported = import_nvd_json(aggregate_path, db_path=db_path)
        return total_imported
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        _mark_failure(db_path, "NVD", str(exc))
        raise
    finally:
        if aggregate_path is not None:
            try:
                aggregate_path.unlink(missing_ok=True)
            except OSError:
                pass
