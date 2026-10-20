"""Coordinates static file triage, contextual CVE retrieval, and persistence."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .db import connect
from .evidence_engine import build_cve_associations, build_product_context, evidence_summary
from .pdf_triage import analyze_pdf
from .office_triage import LEGACY_OFFICE_EXTENSIONS, OFFICE_EXTENSIONS, analyze_office
from .store import lookup_reference_samples


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def analyze_file(path: str | Path, db_path: str | Path | None = None,
                 target_product: str | None = None, max_bytes: int = 100 * 1024 * 1024,
                 candidate_limit: int = 10) -> dict[str, Any]:
    input_path = Path(path).expanduser()
    suffix = input_path.suffix.lower()
    try:
        with input_path.open("rb") as handle:
            prefix = handle.read(1024)
    except OSError:
        # Let the selected analyzer provide the established missing/unreadable-file error.
        prefix = b""

    # Prefer content signatures over suffixes when a file is clearly a PDF or ZIP
    # package. The OOXML analyzer validates its own content-type manifest before
    # treating a ZIP as an Office document.
    if b"%PDF-" in prefix[:1024]:
        report = analyze_pdf(input_path, max_bytes=max_bytes)
    elif suffix in OFFICE_EXTENSIONS or suffix in LEGACY_OFFICE_EXTENSIONS or prefix.startswith(
        (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    ):
        report = analyze_office(str(input_path), max_bytes=max_bytes)
    else:
        # Preserve PDF triage's prior behavior for unknown/non-PDF inputs while the
        # caller is migrating; future format analyzers can join this dispatch layer.
        report = analyze_pdf(input_path, max_bytes=max_bytes)

    report["tool_version"] = __version__
    report["created_at"] = _now()
    if report.get("office_analysis") is not None:
        report["scope"] = {
            "implemented": [
                "SHA-256 and bounded input read", "OOXML content-type-based format identification",
                "bounded ZIP member inventory", "bounded XML and package relationship inspection",
                "VBA/ActiveX/embedded-object/external-link structural indicators",
                "Office formula/field/link indicators when present in inspected XML parts",
            ],
            "not_implemented": [
                "legacy binary OLE/CFB Office parsing", "VBA decompilation or execution",
                "full semantic Word/Excel/PowerPoint parsing", "opening/fetching external targets",
                "embedded-object extraction or execution", "dynamic analysis", "exploit detection",
                "definitive CVE attribution",
            ],
        }
    else:
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
    report["cve_associations"] = build_cve_associations(
        report["reference_sample_matches"], report["target_context"]
    )
    report["cve_association_policy"] = (
        "Candidate relations are separated by basis. Exact SHA-256 matches identify registered sample bytes; "
        "linked CVEs retain the sample metadata's provenance and verification status. Product-context matches "
        "are lexical retrieval results only. None of these relations alone proves exploitability."
    )
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
        for rank, candidate in enumerate(report["cve_associations"], start=1):
            bases = candidate["association_bases"]
            has_exact_sample_match = any(
                basis["type"] == "exact_sha256_sample_match" for basis in bases
            )
            product_scores = [
                float(basis.get("product_relevance_score") or 0.0)
                for basis in bases if basis["type"] == "product_context"
            ]
            score = 100.0 if has_exact_sample_match else max(product_scores, default=0.0)
            score_semantics = (
                "exact_sha256_sample_retrieval_score_not_cve_link_confidence"
                if has_exact_sample_match
                else "lexical_product_retrieval_score_not_probability"
            )
            conn.execute(
                """INSERT OR IGNORE INTO candidate_associations(analysis_id,cve_id,rank,score,assessment,rationale_json)
                   VALUES(?,?,?,?,?,?)""",
                (analysis_id, candidate["cve_id"], rank, score, candidate["assessment"],
                 json.dumps({
                     "association_basis_types": candidate["association_basis_types"],
                     "association_bases": bases,
                     "score_semantics": score_semantics,
                     "score_is_probability": False,
                 }, ensure_ascii=False)),
            )
    report["analysis_id"] = analysis_id
    return report
