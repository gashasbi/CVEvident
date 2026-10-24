"""Final acceptance matrix for bounded, retry-safe public source synchronization."""
from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

from cvevident import sources
from cvevident.db import connect, init_db


class _Response:
    def __init__(self, payload: bytes, headers: dict[str, str] | None = None):
        self.payload = payload
        self.headers = headers or {}

    def read(self, size: int = -1) -> bytes:
        return self.payload if size < 0 else self.payload[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _http_error(code: int, *, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError(
        "https://nvd.example.test/api", code, "synthetic error", headers, io.BytesIO(b"upstream message")
    )


def test_request_json_retries_transient_http_error_and_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = []
    sleeps = []

    def fake_urlopen(request, timeout):
        attempts.append((request, timeout))
        if len(attempts) == 1:
            raise _http_error(503, retry_after="not-a-number")
        return _Response(b'{"vulnerabilities": [], "totalResults": 0}')

    monkeypatch.setattr(sources.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(sources.time, "sleep", sleeps.append)

    result = sources._request_json("https://nvd.example.test/api", headers={"apiKey": "test-key"}, timeout=7)

    assert result == {"vulnerabilities": [], "totalResults": 0}
    assert len(attempts) == 2
    assert attempts[0][1] == 7
    assert any(key.lower() == "apikey" and value == "test-key" for key, value in attempts[0][0].header_items())
    assert sleeps == [1.0]


def test_request_json_does_not_retry_permanent_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    sleeps = []

    def fake_urlopen(_request, timeout):
        calls.append(timeout)
        raise _http_error(404)

    monkeypatch.setattr(sources.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(sources.time, "sleep", sleeps.append)

    with pytest.raises(RuntimeError, match="HTTP 404"):
        sources._request_json("https://nvd.example.test/api")

    assert len(calls) == 1
    assert sleeps == []


def test_request_json_retries_url_errors_then_reports_final_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    sleeps = []

    def fake_urlopen(_request, timeout):
        calls.append(timeout)
        raise urllib.error.URLError("synthetic offline")

    monkeypatch.setattr(sources.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(sources.time, "sleep", sleeps.append)

    with pytest.raises(RuntimeError, match="synthetic offline"):
        sources._request_json("https://nvd.example.test/api")

    assert len(calls) == 4
    assert sleeps == [1, 2, 4]


def test_request_json_rejects_invalid_json_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        sources.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (calls.append(True) or _Response(b"not-json")),
    )

    with pytest.raises(RuntimeError, match="invalid JSON"):
        sources._request_json("https://nvd.example.test/api")

    assert calls == [True]


@pytest.mark.parametrize("days", [0, -1, 121, 999])
def test_sync_nvd_modified_rejects_out_of_range_windows_before_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, days: int
) -> None:
    monkeypatch.setattr(sources, "_request_json", lambda *_args, **_kwargs: pytest.fail("network must not be called"))
    with pytest.raises(ValueError, match="days must be between 1 and 120"):
        sources.sync_nvd_modified(db_path=tmp_path / "unused.sqlite3", days=days, cache_dir=tmp_path)


def test_sync_nvd_modified_paginates_and_passes_api_key_without_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = init_db(tmp_path / "sources.sqlite3")
    cache_dir = tmp_path / "cache"
    calls: list[tuple[int, dict[str, str]]] = []
    slept: list[float] = []
    payloads = {
        0: {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": [{"id": 1}, {"id": 2}]},
        2: {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": [{"id": 3}]},
    }

    def fake_request(url: str, headers=None):
        parsed = urllib.parse.urlsplit(url)
        start_index = int(urllib.parse.parse_qs(parsed.query)["startIndex"][0])
        calls.append((start_index, headers or {}))
        return payloads[start_index]

    def fake_import(path, db_path=None):
        return len(json.loads(Path(path).read_text(encoding="utf-8"))["vulnerabilities"])

    monkeypatch.setenv("NVD_API_KEY", "acceptance-test-key")
    monkeypatch.setattr(sources, "_request_json", fake_request)
    monkeypatch.setattr(sources, "import_nvd_json", fake_import)
    monkeypatch.setattr(sources.time, "sleep", slept.append)

    imported = sources.sync_nvd_modified(db_path, days=3, cache_dir=cache_dir, sleep_seconds=0)

    assert imported == 3
    assert [index for index, _ in calls] == [0, 2]
    assert all(headers == {"apiKey": "acceptance-test-key"} for _, headers in calls)
    assert slept == [0]
    assert len(list(cache_dir.glob("nvd-*.json"))) == 2
    assert not list(cache_dir.glob("*.part"))


def test_sync_nvd_modified_records_failure_in_local_source_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = init_db(tmp_path / "sources.sqlite3")
    monkeypatch.setattr(sources, "_request_json", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline marker")))

    with pytest.raises(RuntimeError, match="offline marker"):
        sources.sync_nvd_modified(db_path, cache_dir=tmp_path / "cache")

    with connect(db_path) as conn:
        row = conn.execute("SELECT status,details FROM source_sync WHERE source='NVD'").fetchone()
    assert row["status"] == "error"
    assert "offline marker" in row["details"]


def test_sync_nvd_years_continues_after_one_year_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_sync(year, *_args, **_kwargs):
        if year == 2021:
            raise RuntimeError("synthetic 2021 failure")
        return {"year": year, "status": "imported", "records_imported": 4}

    monkeypatch.setattr(sources, "sync_nvd_year", fake_sync)
    result = sources.sync_nvd_years(2020, 2022, db_path=":memory:")

    assert result["status"] == "partial_or_failed"
    assert [row["year"] for row in result["years"]] == [2020, 2021, 2022]
    assert result["years"][1] == {"year": 2021, "status": "error", "error": "synthetic 2021 failure"}
    assert result["records_imported"] == 8


def test_sync_nvd_years_rejects_invalid_range_before_any_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "sync_nvd_year", lambda *_args, **_kwargs: pytest.fail("sync must not run"))
    with pytest.raises(ValueError, match="year range must satisfy"):
        sources.sync_nvd_years(2025, 2024)
