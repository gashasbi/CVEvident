"""Free public-source download/synchronization. Network calls are opt-in via CLI."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
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
            if content_length and int(content_length) > max_bytes:
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
        if total == 0:
            raise RuntimeError(f"Downloaded an empty response from {url}")
        temporary.replace(target)
        temporary = None
        return target
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} while downloading {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not download {url}: {exc.reason}") from exc
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
    except (OSError, ValueError, RuntimeError) as exc:
        _mark_failure(db_path, "CISA KEV", str(exc))
        raise


def sync_epss(db_path: str | Path | None = None, destination: str | Path | None = None) -> int:
    path = Path(destination).expanduser() if destination else Path.home() / ".cvevident" / "cache" / "epss_scores-current.csv.gz"
    try:
        download(EPSS_URL, path)
        return import_epss_csv(path, db_path=db_path)
    except (OSError, ValueError, RuntimeError) as exc:
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
    except (OSError, EOFError) as exc:
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
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = f"nvdcve-2.0-{year}.json.gz"
    feed_path = dest_dir / name
    meta_path = dest_dir / f"nvdcve-2.0-{year}.meta"
    feed_url = f"{NVD_FEED_BASE}/{name}"
    meta_url = f"{NVD_FEED_BASE}/nvdcve-2.0-{year}.meta"
    source_key = f"NVD yearly {year}"
    try:
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
        if not cached_valid:
            download(feed_url, feed_path, max_bytes=500 * 1024 * 1024)
        actual_sha = _sha256_uncompressed_gzip(feed_path)
        if actual_sha.lower() != expected_sha.lower():
            raise RuntimeError(f"SHA-256 verification failed for NVD {year} feed: metadata={expected_sha}, actual={actual_sha}")
        count = import_nvd_json(feed_path, db_path=db_path)
        now = utc_now()
        with connect(db_path) as conn:
            conn.execute(
                """INSERT INTO source_sync(source,last_success_at,last_attempt_at,records_seen,status,details)
                   VALUES(?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET last_success_at=excluded.last_success_at,
                   last_attempt_at=excluded.last_attempt_at,records_seen=excluded.records_seen,status='success',details=excluded.details""",
                (source_key, now, now, count, "success", f"year={year}; sha256={expected_sha}"),
            )
        return {"year": year, "status": "imported", "records_imported": count, "feed_sha256": expected_sha}
    except (OSError, ValueError, RuntimeError) as exc:
        _mark_failure(db_path, source_key, str(exc))
        raise


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
        except (OSError, ValueError, RuntimeError) as exc:
            results.append({"year": year, "status": "error", "error": str(exc)})
    return {
        "status": "ok" if all(row["status"] in {"imported", "up_to_date"} for row in results) else "partial_or_failed",
        "from_year": int(from_year), "to_year": end_year, "years": results,
        "records_imported": sum(int(row.get("records_imported", 0)) for row in results),
    }


def _request_json(url: str, headers: dict[str, str] | None = None, timeout: int = 90) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise RuntimeError("NVD API response did not contain a vulnerabilities array")
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
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"NVD API returned invalid JSON: {exc}") from exc
    raise RuntimeError(f"NVD API request failed after retries: {last_error}")


def sync_nvd_modified(db_path: str | Path | None = None, days: int = 7,
                      cache_dir: str | Path | None = None, sleep_seconds: float | None = None) -> int:
    """Import recent NVD modifications. This is incremental sync, not an initial full database load."""
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
    dest_dir = Path(cache_dir).expanduser() if cache_dir else Path.home() / ".cvevident" / "cache" / "nvd-modified"
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        while True:
            query = urllib.parse.urlencode({**params, "startIndex": str(start_index)})
            payload = _request_json(f"{NVD_URL}?{query}", headers=headers)
            batch_path = dest_dir / f"nvd-{start.strftime('%Y%m%d')}-{end.strftime('%Y%m%d')}-{start_index}.json"
            temporary = batch_path.with_suffix(batch_path.suffix + ".part")
            temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            temporary.replace(batch_path)
            total_imported += import_nvd_json(batch_path, db_path=db_path)
            total_results = int(payload.get("totalResults", 0) or 0)
            page_size = int(payload.get("resultsPerPage", 0) or len(payload.get("vulnerabilities", [])))
            if not payload.get("vulnerabilities") or page_size <= 0:
                break
            start_index += page_size
            if start_index >= total_results:
                break
            if sleep_seconds is not None:
                time.sleep(sleep_seconds)
            else:
                time.sleep(0.7 if api_key else 6.0)
        return total_imported
    except (OSError, ValueError, RuntimeError) as exc:
        _mark_failure(db_path, "NVD", str(exc))
        raise
