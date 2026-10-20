"""Coordinates static file triage, contextual CVE retrieval, and persistence."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .db import connect
from .evidence_engine import build_product_context, evidence_summary
from .pdf_triage import analyze_pdf
from .store import lookup_reference_samples


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def analyze_file(path: str | Path, db_path: str | Path | None = None,
                 target_product: str | None = None, max_bytes: int = 100 * 1024 * 1024,
                 candidate_limit: int = 10) -> dict[str, Any]:
    report = analyze_pdf(path, max_bytes=max_bytes)
    report["tool_version"] = __version__
    report["created_at"] = _now()
    report["scope"] = {
        "implemented": ["sha256", "PDF header check", "byte entropy", "local entropy", "PDF-name lexical counts", "bounded pypdf object-graph inspection", "PDF action/annotation/form/embedded-file structural indicators"],
        "not_implemented": ["complete semantic PDF validation", "arbitrary stream-content extraction", "dynamic analysis", "exploit detection", "definitive CVE attribution"],
    }
    report["reference_sample_matches"] = lookup_reference_samples(report["file"]["sha256"], db_path)
    for sample in report["reference_sample_matches"]:
        report["evidence"].append({
            "evidence_type": "reference_sample_match",
            "key": sample["sample_id"],
            "value": "exact_sha256_match",
            "severity": "info",
            "details": {
                "label": sample["label"],
                "confidence": sample["confidence"],
                "source_name": sample["source_name"],
                "source_url": sample["source_url"],
                "label_basis": sample["label_basis"],
                "linked_cves": sample["cve_links"],
                "interpretation": sample["interpretation"],
            },
        })
    report["target_context"] = build_product_context(target_product, str(db_path) if db_path else None, candidate_limit)
    report["evidence_summary"] = evidence_summary(report["evidence"])
    # Store full report context as well as normalized evidence rows. This supports later report replay.
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO analysis_runs(filename,sha256,file_type,size_bytes,verdict,target_product,created_at,summary_json)
               VALUES(?,?,?,?,?,?,?,?)""",
            (report["file"]["filename"], report["file"]["sha256"], report["file"]["file_type"],
             report["file"]["size_bytes"], report["assessment"]["verdict"], target_product,
             report["created_at"], json.dumps(report, ensure_ascii=False, separators=(",", ":"))),
        )
        analysis_id = int(cur.lastrowid)
        for item in report["evidence"]:
            conn.execute(
                """INSERT INTO evidence(analysis_id,evidence_type,evidence_key,value_text,severity,details_json)
                   VALUES(?,?,?,?,?,?)""",
                (analysis_id, item["evidence_type"], item["key"], json.dumps(item["value"], ensure_ascii=False),
                 item.get("severity", "info"), json.dumps(item.get("details", {}), ensure_ascii=False)),
            )
        for rank, candidate in enumerate(report["target_context"]["candidate_cves"], start=1):
            conn.execute(
                """INSERT OR IGNORE INTO candidate_associations(analysis_id,cve_id,rank,score,assessment,rationale_json)
                   VALUES(?,?,?,?,?,?)""",
                (analysis_id, candidate["cve_id"], rank, float(candidate["product_relevance_score"]),
                 "product_context_candidate_not_file_attribution",
                 json.dumps({
                     "matched_vendor": candidate["matched_vendor"],
                     "matched_product": candidate["matched_product"],
                     "matching_query_terms": candidate["matching_query_terms"],
                     "score_semantics": "lexical_product_retrieval_score_not_probability",
                 }, ensure_ascii=False)),
            )
    report["analysis_id"] = analysis_id
    return report
