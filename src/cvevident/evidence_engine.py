"""Deterministic evidence packaging and candidate ranking.

Scores in this module are retrieval/context scores only. They are not probabilities
that a file exploits a CVE.
"""
from __future__ import annotations

from typing import Any

from .store import get_source_freshness, search_product_cves
from .product_matching import normalize_product_text, split_product_version


def build_product_context(
    target_product: str | None,
    db_path: str | None,
    limit: int = 10,
    target_vendor: str | None = None,
    target_version: str | None = None,
) -> dict[str, Any]:
    """Retrieve transparent product candidates and the local source freshness snapshot."""
    freshness = get_source_freshness(db_path)
    if not target_product or not target_product.strip():
        return {
            "target_product": None,
            "target_vendor": target_vendor.strip() if target_vendor else None,
            "target_version": target_version.strip() if target_version else None,
            "candidate_cves": [],
            "retrieval_method": "not_requested",
            "source_freshness": freshness,
            "product_identity_ambiguity": {
                "status": "not_assessed_no_product_query",
                "distinct_matched_product_identity_count": 0,
                "matched_product_identities": [],
            },
            "configuration_evaluation": "not_performed",
            "interpretation": "No target product was supplied; no product-context CVE search was performed.",
        }

    query_name, resolved_version, version_input_method = split_product_version(target_product, target_version)
    candidates = search_product_cves(
        target_product, db_path=db_path, limit=limit, vendor=target_vendor, version=target_version,
    )
    if candidates and isinstance(candidates[0].get("query_ambiguity"), dict):
        identity_summary = dict(candidates[0]["query_ambiguity"])
    else:
        identity_summary = {
            "status": "no_product_identity_returned",
            "distinct_matched_product_identity_count": 0,
            "result_limit": max(1, min(int(limit), 200)),
            "assessment_scope": "no candidate identity was returned",
            "matched_product_identities": [],
        }
    identity_summary.setdefault("interpretation", (
        "This is a lexical identity estimate, not proof the product is present in the file."
    ))
    return {
        "target_product": query_name,
        "target_product_input": target_product,
        "target_vendor": target_vendor.strip() if target_vendor else None,
        "normalized_target_product": normalize_product_text(query_name),
        "normalized_target_vendor": normalize_product_text(target_vendor) or None,
        "target_version": resolved_version,
        "version_input_method": version_input_method,
        "version_input_conflict": version_input_method == "explicit_option_conflicts_with_query_suffix",
        "version_input_warning": (
            "The product query ended with a version that conflicts with the explicit target version; "
            "the explicit target-version option was used for version context."
            if version_input_method == "explicit_option_conflicts_with_query_suffix" else None
        ),
        "candidate_cves": candidates,
        "retrieval_method": "normalized_vendor_product_token_overlap_against_local_NVD_CPE_rows",
        "matching_policy": {
            "name_normalization": "Unicode NFKC, casefold, punctuation/underscore/hyphen token normalization",
            "name_match_classes": [
                "exact_normalized_vendor_product", "all_query_terms_match",
                "partial_query_term_match", "vendor_only_match",
            ],
            "name_match_score": "product-name query terms carry full weight; vendor-only terms carry half weight",
            "version_assessment": "exact CPE version or simple dotted-numeric bounds only; unsupported syntax is indeterminate",
            "full_nvd_configuration_evaluation": False,
        },
        "product_identity_ambiguity": identity_summary,
        "source_freshness": freshness,
        "configuration_evaluation": "not_performed_nested_NVD_AND_OR_logic_and_platform_conditions_not_evaluated",
        "interpretation": (
            (
                "The supplied product query ended in a version that conflicts with the explicit target version; "
                "the explicit target-version option was used. "
            ) if version_input_method == "explicit_option_conflicts_with_query_suffix" else ""
        ) + (
            "These candidates were retrieved by normalized lexical overlap against locally imported NVD affected-product rows. "
            "Optional version context is evaluated only for exact CPE versions and simple dotted-numeric bounds. The full NVD "
            "configuration tree, including nested AND/OR conditions and platform context, is not evaluated. Product presence in "
            "the analyzed file is not established; KEV and EPSS are separate vulnerability-level signals, not file evidence."
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
                    "evidence_id": sample.get("evidence_id"),
                    "resolution": "resolved" if sample.get("evidence_id") else "unresolved",
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
            "target_product_input": target_context.get("target_product_input"),
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
            "target_vendor": target_context.get("target_vendor"),
            "target_version": target_context.get("target_version"),
            "name_match_class": candidate.get("name_match_class"),
            "version_match_status": candidate.get("version_match_status"),
            "version_context": candidate.get("version_context"),
            "candidate_relevance": candidate.get("candidate_relevance"),
            "query_normalization": candidate.get("query_normalization"),
            "query_ambiguity": candidate.get("query_ambiguity"),
            "matching_product_rows": candidate.get("matching_product_rows", []),
            "matched_cpe_row_count": candidate.get("matched_cpe_row_count", 1),
            "match_method": candidate.get("match_method"),
            "retrieval_source": candidate.get("retrieval_source"),
            "local_source_signals": candidate.get("local_source_signals"),
            "configuration_evaluation": candidate.get("configuration_evaluation"),
            "score_semantics": "lexical_product_retrieval_score_not_probability",
            "retrieval_method": target_context.get("retrieval_method"),
            "evidence_reference": {
                "evidence_type": "product_context_candidate",
                "key": cve_id,
                "evidence_id": candidate.get("evidence_id"),
                "resolution": "resolved" if candidate.get("evidence_id") else "unresolved",
            },
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
    class_counts: dict[str, int] = {}
    locator_counts: dict[str, int] = {}
    for item in evidence:
        kind = str(item.get("evidence_type", "unknown"))
        counts[kind] = counts.get(kind, 0) + 1
        evidence_class = str(item.get("evidence_class", "unclassified"))
        class_counts[evidence_class] = class_counts.get(evidence_class, 0) + 1
        locator = item.get("source_locator") or {}
        locator_kind = str(locator.get("kind", "unlocated")) if isinstance(locator, dict) else "unlocated"
        locator_counts[locator_kind] = locator_counts.get(locator_kind, 0) + 1
    marker_hits = [
        {"key": item["key"], "count": item.get("value")}
        for item in evidence if item.get("evidence_type") == "pdf_lexical_marker"
    ]
    return {
        "evidence_count": len(evidence),
        "evidence_counts_by_type": counts,
        "evidence_counts_by_class": class_counts,
        "evidence_counts_by_source_locator": locator_counts,
        "pdf_lexical_markers_observed": marker_hits,
        "malware_verdict": "not_assessed",
        "cve_attribution": "not_assessed",
    }
