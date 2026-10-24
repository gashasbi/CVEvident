from __future__ import annotations

from pathlib import Path

from cvevident.evidence_engine import build_cve_associations, evidence_summary
from cvevident.evidence_trace import (
    append_product_context_evidence,
    append_reported_source_evidence,
    finalize_evidence_traceability,
)
from cvevident.pdf_triage import analyze_pdf
from cvevident.reporting import to_markdown

def _traceable_report() -> dict:
    return {
        "file": {
            "filename": "sample.pdf",
            "file_type": "pdf",
            "sha256": "a" * 64,
            "size_bytes": 100,
        },
        "assessment": {"verdict": "not_assessed", "reason": "Static observations only."},
        "metrics": {},
        "warnings": [],
        "scope": {
            "implemented": ["bounded static PDF parsing"],
            "not_implemented": ["dynamic analysis", "definitive CVE attribution"],
        },
        "structural_analysis": {
            "status": "partial",
            "truncated": True,
            "findings_truncated": True,
            "warnings": ["Object traversal budget reached."],
            "findings": [{"finding_type": "open_action_entry"}],
        },
        "evidence": [
            {
                "evidence_type": "pdf_structural_finding",
                "key": "open_action_entry",
                "value": True,
                "severity": "info",
                "details": {
                    "object_path": "/Root/OpenAction",
                    "object_reference": "1 0 R",
                    "object_path_truncated": False,
                    "interpretation": "An entry was parsed; this is contextual only.",
                },
            },
            {
                "evidence_type": "reference_sample_match",
                "key": "sample-001",
                "value": "exact_sha256_match",
                "severity": "info",
                "details": {
                    "source_name": "curated test set",
                    "source_url": "https://example.invalid/source",
                    "label_basis": "documented sample metadata",
                },
            },
        ],
        "reference_sample_matches": [
            {
                "sample_id": "sample-001",
                "label": "test-sample",
                "confidence": "medium",
                "label_basis": "documented sample metadata",
                "source_name": "curated test set",
                "source_url": "https://example.invalid/source",
                "cve_links": [{
                    "cve_id": "CVE-2024-1234",
                    "association_type": "reported",
                    "confidence": "medium",
                    "verified": False,
                    "evidence_basis": "source record",
                }],
            }
        ],
        "target_context": {
            "target_product": "Acme Widget",
            "retrieval_method": "lexical_match_against_NVD_affected_product_criteria",
            "interpretation": "Product context only.",
            "candidate_cves": [{
                "cve_id": "CVE-2024-5678",
                "matched_vendor": "acme",
                "matched_product": "widget",
                "matched_criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                "matching_query_terms": ["widget"],
                "product_relevance_score": 72.0,
                "cpe_vulnerable": True,
                "version_start_including": None,
                "version_start_excluding": None,
                "version_end_including": None,
                "version_end_excluding": None,
            }],
        },
    }

def test_traceability_assigns_unique_ids_and_exact_pdf_object_locator() -> None:
    report = _traceable_report()
    append_product_context_evidence(report)
    finalize_evidence_traceability(report)

    evidence = report["evidence"]
    ids = [item["evidence_id"] for item in evidence]
    assert ids == [f"EV-{index:06d}" for index in range(1, len(evidence) + 1)]
    assert len(ids) == len(set(ids))

    finding = evidence[0]
    assert finding["evidence_class"] == "static_parser_observation"
    assert finding["source_locator"]["kind"] == "pdf_object_graph"
    assert finding["source_locator"]["object_path"] == "/Root/OpenAction"
    assert finding["source_locator"]["object_reference"] == "1 0 R"
    assert finding["details"]["traceability"]["evidence_id"] == finding["evidence_id"]

def test_cve_associations_resolve_to_distinct_evidence_bases() -> None:
    report = _traceable_report()
    append_product_context_evidence(report)
    finalize_evidence_traceability(report)
    associations = build_cve_associations(
        report["reference_sample_matches"], report["target_context"]
    )

    by_cve = {item["cve_id"]: item for item in associations}
    sample_basis = by_cve["CVE-2024-1234"]["association_bases"][0]
    context_basis = by_cve["CVE-2024-5678"]["association_bases"][0]
    assert sample_basis["type"] == "exact_sha256_sample_match"
    assert sample_basis["evidence_reference"]["evidence_id"] == report["reference_sample_matches"][0]["evidence_id"]
    assert context_basis["type"] == "product_context"
    assert context_basis["evidence_reference"]["evidence_id"] == report["target_context"]["candidate_cves"][0]["evidence_id"]
    assert context_basis["retrieval_method"] == "lexical_match_against_NVD_affected_product_criteria"
    assert "not_probability" in context_basis["score_semantics"]

def test_coverage_marks_incomplete_parser_scope_and_explains_absence() -> None:
    report = _traceable_report()
    finalize_evidence_traceability(report)
    coverage = report["analysis_coverage"]

    assert coverage["parser_status"] == "partial"
    assert coverage["truncated"] is True
    assert coverage["complete_for_declared_static_scope"] is False
    assert coverage["semantic_validation_performed"] is False
    assert "dynamic analysis" in coverage["not_implemented_scope"]
    assert "does not establish that the file is safe" in coverage["absence_of_findings_means"]
    assert any("Not inspected by the declared scope" in item for item in report["warnings"])

def test_encrypted_pdf_does_not_claim_complete_static_coverage() -> None:
    report = _traceable_report()
    report["structural_analysis"] = {
        "status": "encrypted",
        "truncated": False,
        "warnings": ["The PDF is encrypted. Object-graph inspection was skipped without a password."],
        "findings": [],
    }

    finalize_evidence_traceability(report)

    coverage = report["analysis_coverage"]
    assert coverage["parser_status"] == "encrypted"
    assert coverage["complete_for_declared_static_scope"] is False
    assert any("encrypted" in reason.lower() for reason in coverage["limitation_reasons"])


def test_evidence_summary_reports_classes_and_locator_kinds() -> None:
    report = _traceable_report()
    append_product_context_evidence(report)
    finalize_evidence_traceability(report)

    summary = evidence_summary(report["evidence"])
    assert summary["evidence_counts_by_class"]["contextual_retrieval"] == 1
    assert summary["evidence_counts_by_source_locator"]["pdf_object_graph"] == 1
    assert summary["evidence_count"] == len(report["evidence"])

def test_markdown_report_displays_evidence_ids_and_source_locations() -> None:
    report = _traceable_report()
    append_product_context_evidence(report)
    finalize_evidence_traceability(report)
    report["tool_version"] = "0.1.0"
    report["created_at"] = "2026-10-21T00:00:00+00:00"
    markdown = to_markdown(report)

    assert "Evidence ID: `EV-000001`" in markdown
    assert "Source locator: `pdf_object_graph`" in markdown
    assert "Locator limitation:" in markdown
    assert "matched criteria: cpe:2.3:a:acme:widget" in markdown
    assert "Not inspected by the declared scope" in markdown
    assert "does not establish that the file is safe" in markdown

def test_pdf_lexical_marker_evidence_contains_zero_based_byte_offsets(tmp_path: Path) -> None:
    path = tmp_path / "marker.pdf"
    data = b"%PDF-1.7\n/JavaScript /OpenAction\n"
    path.write_bytes(data)

    report = analyze_pdf(path)
    marker = next(
        item for item in report["evidence"]
        if item.get("evidence_type") == "pdf_lexical_marker"
        and item.get("key") == "pdf.javascript_name"
    )
    assert marker["details"]["byte_offsets"] == [data.index(b"/JavaScript")]
    assert marker["details"]["byte_offsets_truncated"] is False
    assert marker["details"]["offset_basis"].startswith("zero-based byte offsets")

def test_package_relation_and_directory_records_keep_source_locations() -> None:
    report = _traceable_report()
    report["office_analysis"] = {
        "status": "parsed",
        "parts_inventory": ["word/document.xml"],
        "external_relationships": [{
            "source_part": "word/_rels/document.xml.rels",
            "relationship_type": "hyperlink",
            "target": "https://example.invalid/resource",
        }],
        "truncated": False,
    }
    report["odf_analysis"] = {
        "status": "parsed",
        "parts_inventory": ["content.xml"],
        "external_references": [{
            "part": "content.xml",
            "element": "text:a",
            "target": "https://example.invalid/odf",
        }],
    }
    report["legacy_office_analysis"] = {
        "status": "parsed",
        "directory_inventory": [{
            "name": "VBA/dir",
            "type": "stream",
            "declared_size_bytes": 128,
        }],
        "directory_inventory_truncated": False,
    }
    append_product_context_evidence(report)
    append_reported_source_evidence(report)
    finalize_evidence_traceability(report)

    office_record = next(item for item in report["evidence"] if item["evidence_type"] == "office_external_relationship")
    assert office_record["source_locator"]["kind"] == "package_member_location"
    assert office_record["source_locator"]["package_member"] == "word/_rels/document.xml.rels"

    odf_record = next(item for item in report["evidence"] if item["evidence_type"] == "odf_external_reference")
    assert odf_record["source_locator"]["package_member"] == "content.xml"
    assert odf_record["source_locator"]["element"] == "text:a"

    legacy_record = next(item for item in report["evidence"] if item["evidence_type"] == "legacy_office_directory_entry")
    assert legacy_record["source_locator"]["kind"] == "ole_cfb_directory_inventory_entry"
    assert legacy_record["source_locator"]["name"] == "VBA/dir"
