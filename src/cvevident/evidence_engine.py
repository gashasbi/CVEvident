"""Deterministic evidence packaging and candidate ranking.

Scores in this module are retrieval/context scores only. They are not probabilities
that a file exploits a CVE.
"""
from __future__ import annotations

from typing import Any

from .store import search_product_cves


def build_product_context(target_product: str | None, db_path: str | None,
                          limit: int = 10) -> dict[str, Any]:
    if not target_product or not target_product.strip():
        return {
            "target_product": None,
            "candidate_cves": [],
            "retrieval_method": "not_requested",
            "interpretation": "No target product was supplied; no product-context CVE search was performed.",
        }
    candidates = search_product_cves(target_product, db_path=db_path, limit=limit)
    return {
        "target_product": target_product.strip(),
        "candidate_cves": candidates,
        "retrieval_method": "lexical_match_against_NVD_affected_product_criteria",
        "interpretation": (
            "These are product-context candidates only. The lexical score is not a probability, "
            "does not evaluate all NVD configuration logic or version ranges, and does not attribute the file to a CVE."
        ),
    }


def evidence_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in evidence:
        kind = str(item.get("evidence_type", "unknown"))
        counts[kind] = counts.get(kind, 0) + 1
    marker_hits = [
        {"key": item["key"], "count": item.get("value")}
        for item in evidence if item.get("evidence_type") == "pdf_lexical_marker"
    ]
    return {
        "evidence_count": len(evidence),
        "evidence_counts_by_type": counts,
        "pdf_lexical_markers_observed": marker_hits,
        "malware_verdict": "not_assessed",
        "cve_attribution": "not_assessed",
    }
