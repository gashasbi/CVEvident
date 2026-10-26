from __future__ import annotations

import json
from pathlib import Path

from cvevident.evidence_engine import build_cve_associations, evidence_summary
from cvevident.evidence_trace import (
    append_product_context_evidence,
    append_reported_source_evidence,
    finalize_evidence_traceability,
)
from cvevident.pdf_triage import analyze_pdf
from cvevident.reporting import serialize_json, to_html, to_markdown

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



def test_traceability_exposes_method_value_and_consistent_feature_assessments() -> None:
    report = _traceable_report()
    report["warnings"] = []
    report["structural_analysis"].update({
        "status": "partial",
        "truncated": True,
        "findings_truncated": True,
        "containers_inspected": 2,
        "features": {
            "javascript_action_count": 0,
            "launch_action_count": 1,
        },
        "warnings": [],
    })

    finalize_evidence_traceability(report)

    finding = report["evidence"][0]
    trace = finding["details"]["traceability"]

    assert trace["evidence_type"] == "pdf_structural_finding"
    assert trace["extraction_method"] == "pypdf_object_graph_traversal"
    assert trace["observed_value"] is True
    assert trace["source_locator"] == finding["source_locator"]
    assert trace["analysis_limitations"]

    assessments = {
        item["feature"]: item
        for item in report["analysis_coverage"]["feature_assessments"]
    }
    assert assessments["launch_action_count"]["status"] == "observed"
    assert assessments["javascript_action_count"]["status"] == "not_found_in_inspected_scope"

    encoded = json.loads(serialize_json(report))
    assert encoded["analysis_coverage"]["feature_assessments"] == report["analysis_coverage"]["feature_assessments"]

    markdown = to_markdown(report)
    html = to_html(report)

    assert "Extraction method: `pypdf_object_graph_traversal`" in markdown
    assert "not_found_in_inspected_scope" in markdown
    assert "pypdf_object_graph_traversal" in html
    assert "not_found_in_inspected_scope" in html


def test_traceability_extraction_methods_match_the_actual_evidence_kind() -> None:
    report = _traceable_report()
    report["office_analysis"] = {
        "status": "failed",
        "truncated": False,
        "features": {},
        "warnings": [],
    }
    report["evidence"] = [
        {
            "evidence_type": "format_check",
            "key": "office.extension_mismatch",
            "value": True,
            "severity": "info",
            "details": {},
        },
        {
            "evidence_type": "office_package_status",
            "key": "office.package_status",
            "value": "failed",
            "severity": "warning",
            "details": {},
        },
        {
            "evidence_type": "file_identity",
            "key": "sha256",
            "value": "a" * 64,
            "severity": "info",
            "details": {"algorithm": "SHA-256"},
        },
    ]

    finalize_evidence_traceability(report)
    by_key = {item["key"]: item for item in report["evidence"]}

    extension_trace = by_key["office.extension_mismatch"]["details"]["traceability"]
    status_trace = by_key["office.package_status"]["details"]["traceability"]
    identity_trace = by_key["sha256"]["details"]["traceability"]

    assert extension_trace["extraction_method"] == "filename_extension_vs_detected_format_comparison"
    assert status_trace["extraction_method"] == "parser_status_and_coverage_reporting"
    assert any(
        "file identity metadata" in limitation.lower()
        for limitation in identity_trace["analysis_limitations"]
    )


def test_traceability_extraction_methods_match_the_actual_evidence_kind() -> None:
    report = _traceable_report()
    report["office_analysis"] = {
        "status": "failed",
        "truncated": False,
        "features": {},
        "warnings": [],
    }
    report["evidence"] = [
        {
            "evidence_type": "format_check",
            "key": "office.extension_mismatch",
            "value": True,
            "severity": "info",
            "details": {},
        },
        {
            "evidence_type": "office_package_status",
            "key": "office.package_status",
            "value": "failed",
            "severity": "warning",
            "details": {},
        },
        {
            "evidence_type": "file_identity",
            "key": "sha256",
            "value": "a" * 64,
            "severity": "info",
            "details": {"algorithm": "SHA-256"},
        },
    ]

    finalize_evidence_traceability(report)
    by_key = {item["key"]: item for item in report["evidence"]}

    extension_trace = by_key["office.extension_mismatch"]["details"]["traceability"]
    status_trace = by_key["office.package_status"]["details"]["traceability"]
    identity_trace = by_key["sha256"]["details"]["traceability"]

    assert extension_trace["extraction_method"] == "filename_extension_vs_detected_format_comparison"
    assert status_trace["extraction_method"] == "parser_status_and_coverage_reporting"
    assert any(
        "file identity metadata" in limitation.lower()
        for limitation in identity_trace["analysis_limitations"]
    )


def test_feature_assessments_distinguish_absent_from_unassessed() -> None:
    cases = (
        ("parsed", False, 2, "not_found"),
        ("parsed", True, 2, "not_found_in_inspected_scope"),
        ("partial", True, 2, "not_found_in_inspected_scope"),
        ("failed", False, 2, "not_assessed"),
        ("failed", False, 0, "not_assessed"),
    )

    for status, truncated, inspected, expected in cases:
        report = _traceable_report()
        report["warnings"] = []
        report["structural_analysis"].update({
            "status": status,
            "truncated": truncated,
            "findings_truncated": truncated,
            "containers_inspected": inspected,
            "features": {"javascript_action_count": 0},
            "warnings": [],
        })

        finalize_evidence_traceability(report)

        assessments = {
            item["feature"]: item
            for item in report["analysis_coverage"]["feature_assessments"]
        }
        assessment = assessments["javascript_action_count"]
        assert assessment["status"] == expected

        limitations = " ".join(assessment["analysis_limitations"])
        if expected == "not_found":
            assert "completed declared static scope" in limitations
        elif expected == "not_found_in_inspected_scope":
            assert "uninspected content" in limitations
        else:
            assert "absence must not be inferred" in limitations

        encoded = json.loads(serialize_json(report))
        serialized_assessment = next(
            item for item in encoded["analysis_coverage"]["feature_assessments"]
            if item["feature"] == "javascript_action_count"
        )
        assert serialized_assessment["status"] == expected

        markdown = to_markdown(report)
        html = to_html(report)
        assert expected in markdown
        assert expected in html
