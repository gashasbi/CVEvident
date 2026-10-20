"""SQLite storage and additive schema migration for CVEvident."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 2

SCHEMA = r"""
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'unknown',
    published TEXT,
    modified TEXT,
    description TEXT NOT NULL DEFAULT '',
    cvss_score REAL,
    cvss_severity TEXT,
    cisa_kev INTEGER NOT NULL DEFAULT 0 CHECK(cisa_kev IN (0,1)),
    kev_date_added TEXT,
    kev_notes TEXT,
    epss_score REAL CHECK(epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)),
    epss_percentile REAL CHECK(epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)),
    raw_json TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vulnerabilities(modified);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(cisa_kev);
CREATE INDEX IF NOT EXISTS idx_vuln_epss ON vulnerabilities(epss_score);
CREATE TABLE IF NOT EXISTS vulnerability_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    name TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(cve_id, url)
);
CREATE TABLE IF NOT EXISTS vulnerability_weaknesses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    cwe_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    UNIQUE(cve_id, cwe_id, description)
);
CREATE TABLE IF NOT EXISTS affected_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    criteria TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    vulnerable INTEGER NOT NULL DEFAULT 1 CHECK(vulnerable IN (0,1)),
    UNIQUE(cve_id, criteria, version_start_including, version_start_excluding,
           version_end_including, version_end_excluding)
);
CREATE INDEX IF NOT EXISTS idx_products_vendor_product ON affected_products(vendor, product);
CREATE INDEX IF NOT EXISTS idx_products_cve ON affected_products(cve_id);
CREATE TABLE IF NOT EXISTS source_sync (
    source TEXT PRIMARY KEY,
    last_success_at TEXT,
    last_attempt_at TEXT,
    records_seen INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'never_run',
    details TEXT
);
CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    verdict TEXT NOT NULL DEFAULT 'not_assessed',
    target_product TEXT,
    created_at TEXT NOT NULL,
    summary_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_sha256 ON analysis_runs(sha256);
CREATE INDEX IF NOT EXISTS idx_analysis_created ON analysis_runs(created_at);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    evidence_key TEXT NOT NULL,
    value_text TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_evidence_analysis ON evidence(analysis_id);
CREATE INDEX IF NOT EXISTS idx_evidence_key ON evidence(evidence_key);
CREATE TABLE IF NOT EXISTS candidate_associations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    rank INTEGER NOT NULL,
    score REAL NOT NULL DEFAULT 0,
    assessment TEXT NOT NULL DEFAULT 'context_candidate_not_file_attribution',
    rationale_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(analysis_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_candidate_analysis ON candidate_associations(analysis_id, rank);
CREATE TABLE IF NOT EXISTS reference_samples (
    sample_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    file_name TEXT NOT NULL DEFAULT '',
    file_type TEXT NOT NULL,
    label TEXT NOT NULL CHECK(label IN ('benign','malicious','suspicious','unknown')),
    source_name TEXT NOT NULL,
    source_url TEXT,
    product_name TEXT,
    product_version TEXT,
    label_basis TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'unknown' CHECK(confidence IN ('verified','high','medium','low','unknown')),
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sample_vulnerability_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL REFERENCES reference_samples(sample_id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    association_type TEXT NOT NULL DEFAULT 'reported',
    evidence_basis TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'unknown' CHECK(confidence IN ('verified','high','medium','low','unknown')),
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)),
    source_url TEXT,
    UNIQUE(sample_id, cve_id, association_type)
);
CREATE TABLE IF NOT EXISTS source_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    source_name TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source_updated_at TEXT,
    source_record_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(cve_id, source_name, source_updated_at)
);
"""


def default_db_path() -> Path:
    """Return the local per-user database path; CVEVIDENT_HOME can override its directory."""
    base = os.environ.get("CVEVIDENT_HOME")
    home = Path(base).expanduser() if base else Path.home() / ".cvevident"
    return home / "cvevident.sqlite3"


class ClosingConnection(sqlite3.Connection):
    """Connection context manager that commits/rolls back and then closes the handle."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path).expanduser() if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30.0, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(db_path: str | Path | None = None) -> Path:
    """Create schema and perform safe additive upgrades from prior CVEvident releases."""
    path = Path(db_path).expanduser() if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        current = conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone() if _table_exists(conn, "schema_meta") else None
        current_version = int(current[0]) if current else 0
        if current_version > SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {current_version} is newer than this program supports ({SCHEMA_VERSION})."
            )
        conn.executescript(SCHEMA)
        # Additive migrations for databases created by CVEvident 0.1.x.
        _ensure_column(conn, "source_sync", "last_attempt_at", "TEXT")
        conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
    return path


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
