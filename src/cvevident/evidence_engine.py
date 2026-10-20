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


def build_cve_associations(reference_sample_matches: list[dict[str, Any]],
                           target_context: dict[str, Any]) -> list[dict[str, Any]]:
    """Combine explicit sample-to-CVE links and product-context retrieval without conflating them.

    An exact hash match establishes byte identity with curated sample metadata only. The sample's
    CVE link retains its own provenance/confidence/verification state; it is not proof that the
    file exploits the CVE. Product-context matches are independent context and never file attribution.
    """
    associations: dict[str, dict[str, Any]] = {}
    metadata_fields = (
        "description", "published", "modified", "cvss_score", "cvss_severity",
        "cisa_kev", "kev_date_added", "epss_score", "epss_percentile",
    )

    def ensure(cve_id: str) -> dict[str, Any]:
        item = associations.get(cve_id)
        if item is None:
            item = {
                "cve_id": cve_id,
                **{field: None for field in metadata_fields},
                "association_bases": [],
                "assessment": "candidate_not_file_attribution",
            }
            associations[cve_id] = item
        return item

    def merge_metadata(item: dict[str, Any], source: dict[str, Any]) -> None:
        for field in metadata_fields:
            value = source.get(field)
            if value is not None and value != "":
                item[field] = value
        if item.get("cisa_kev") is not None:
            item["cisa_kev"] = bool(item["cisa_kev"])

    for sample in reference_sample_matches:
        for link in sample.get("cve_links", []) or []:
            cve_id = str(link.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            item = ensure(cve_id)
            merge_metadata(item, link)
            item["association_bases"].append({
                "type": "exact_sha256_sample_match",
                "sample_id": sample.get("sample_id"),
                "sample_label": sample.get("label", "unknown"),
                "sample_confidence": sample.get("confidence", "unknown"),
                "sample_label_basis": sample.get("label_basis", ""),
                "sample_source_name": sample.get("source_name", ""),
                "sample_source_url": sample.get("source_url"),
                "link_association_type": link.get("association_type", "reported"),
                "link_confidence": link.get("confidence", "unknown"),
                "link_verified": bool(link.get("verified", False)),
                "link_evidence_basis": link.get("evidence_basis", ""),
                "link_source_url": link.get("source_url"),
                "evidence_reference": {
                    "evidence_type": "reference_sample_match",
                    "key": sample.get("sample_id"),
                },
                "interpretation": (
                    "The file SHA-256 exactly matches this registered sample. The CVE link inherits "
                    "the sample metadata's provenance and verification state; this is not proof of exploitability."
                ),
            })

    for candidate in target_context.get("candidate_cves", []) or []:
        cve_id = str(candidate.get("cve_id") or "").strip().upper()
        if not cve_id:
            continue
        item = ensure(cve_id)
        merge_metadata(item, candidate)
        item["association_bases"].append({
            "type": "product_context",
            "target_product": target_context.get("target_product"),
            "matched_vendor": candidate.get("matched_vendor"),
            "matched_product": candidate.get("matched_product"),
            "matched_criteria": candidate.get("matched_criteria"),
            "matching_query_terms": candidate.get("matching_query_terms", []),
            "product_relevance_score": candidate.get("product_relevance_score"),
            "cpe_vulnerable": candidate.get("cpe_vulnerable"),
            "version_start_including": candidate.get("version_start_including"),
            "version_start_excluding": candidate.get("version_start_excluding"),
            "version_end_including": candidate.get("version_end_including"),
            "version_end_excluding": candidate.get("version_end_excluding"),
            "score_semantics": "lexical_product_retrieval_score_not_probability",
            "interpretation": (
                "Product-context retrieval only. The file does not establish that this product or version "
                "is present, and this match does not attribute the file to the CVE."
            ),
        })

    for item in associations.values():
        basis_types = {basis["type"] for basis in item["association_bases"]}
        if basis_types == {"exact_sha256_sample_match", "product_context"}:
            item["assessment"] = "exact_sample_link_and_product_context_not_proof_of_exploitability"
        elif "exact_sha256_sample_match" in basis_types:
            item["assessment"] = "exact_sample_link_not_proof_of_exploitability"
        else:
            item["assessment"] = "product_context_candidate_not_file_attribution"
        item["association_basis_types"] = sorted(basis_types)

    # Review order only: explicit exact-hash sample relations first, verified CVE links next,
    # followed by product-context retrieval score. This ordering is not a probability estimate.
    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        exact_bases = [b for b in item["association_bases"] if b["type"] == "exact_sha256_sample_match"]
        verified = any(bool(b.get("link_verified")) for b in exact_bases)
        product_scores = [
            float(b.get("product_relevance_score") or 0.0)
            for b in item["association_bases"] if b["type"] == "product_context"
        ]
        return (
            -int(bool(exact_bases)), -int(verified), -max(product_scores, default=0.0), item["cve_id"]
        )

    return sorted(associations.values(), key=sort_key)


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
