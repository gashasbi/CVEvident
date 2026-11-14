from __future__ import annotations

import json

import pytest

from cvevident.coverage import build_parser_coverage
from cvevident.evidence_trace import finalize_evidence_traceability
from cvevident.reporting import serialize_json, to_html, to_markdown


PARSER_CASES = (
    (
        "structural_analysis",
        "pdf",
        {"status": "parsed", "containers_inspected": 12, "features": {"javascript_action_count": 1}},
    ),
    (
        "office_analysis",
        "docx",
        {"status": "parsed", "container_entry_count": 14, "xml_parts_inspected": 5,
         "features": {"vba_project_present": False, "embedded_object_part_count": 1}},
    ),
    (
        "odf_analysis",
        "odt",
        {"status": "parsed", "container_entry_count": 8, "xml_parts_inspected": 4,
         "features": {"script_or_basic_member_count": 0, "embedded_object_member_count": 1}},
    ),
    (
        "legacy_office_analysis",
        "doc",
        {"status": "parsed", "directory_entry_count": 9, "stream_read_count": 3,
         "features": {"vba_project_present": True, "embedded_object_indicator_count": 1}},
    ),
    (
        "rtf_analysis",
        "rtf",
        {"status": "parsed", "bytes_scanned": 2048,
         "features": {"field_instruction_group_count": 1, "external_target_count": 1}},
    ),
)


@pytest.mark.parametrize("section,file_type,parser", PARSER_CASES)
def test_supported_parsers_share_the_same_coverage_domains(section, file_type, parser):
    report = {
        "file": {"file_type": file_type},
        section: parser,
    }

    coverage = build_parser_coverage(report)

    assert coverage["schema_version"] == 1
    assert coverage["parser_section"] == section
    assert coverage["parser_family"] in {"pdf", "ooxml", "odf", "legacy_office", "rtf"}
    assert coverage["overall_status"] == "complete"
    assert set(coverage["domains"]) == {
        "format_identification",
        "container_structure",
        "content_inspection",
        "embedded_object_inventory",
        "external_reference_inventory",
        "active_content_indicators",
        "semantic_interpretation",
    }
    for name, domain in coverage["domains"].items():
        assert domain["status"] in {
            "complete", "partial", "not_inspected", "not_applicable",
            "failed", "unavailable", "unsupported", "unknown",
        }
        assert "in_declared_scope" in domain
        assert "inspected_count" in domain
        assert "observed_count" in domain
        assert "limit_reached" in domain
        assert "scope" in domain
        assert "limitations" in domain
    assert coverage["domains"]["semantic_interpretation"]["status"] == "not_inspected"
    assert coverage["domains"]["semantic_interpretation"]["in_declared_scope"] is False


def test_parser_coverage_marks_only_limited_domains_partial():
    report = {
        "file": {"file_type": "pdf"},
        "structural_analysis": {
            "status": "parsed",
            "containers_inspected": 20,
            "findings_truncated": True,
            "features": {"embedded_files_name_tree_count": 2},
            "warnings": [],
        },
    }

    coverage = build_parser_coverage(report)

    assert coverage["domains"]["container_structure"]["status"] == "complete"
    assert coverage["domains"]["embedded_object_inventory"]["status"] == "partial"
    assert coverage["domains"]["external_reference_inventory"]["status"] == "partial"
    assert coverage["overall_status"] == "partial"
    assert coverage["domains"]["embedded_object_inventory"]["limit_reached"] is True


def test_object_reference_cap_only_limits_the_embedded_inventory_domain():
    report = {
        "file": {"file_type": "docx"},
        "office_analysis": {
            "status": "parsed",
            "container_entry_count": 12,
            "xml_parts_inspected": 4,
            "ole_object_references_truncated": True,
            "features": {"embedded_object_part_count": 2},
            "warnings": [],
        },
    }

    coverage = build_parser_coverage(report)

    assert coverage["domains"]["container_structure"]["status"] == "complete"
    assert coverage["domains"]["content_inspection"]["status"] == "complete"
    assert coverage["domains"]["embedded_object_inventory"]["status"] == "partial"
    assert coverage["domains"]["external_reference_inventory"]["status"] == "complete"
    assert coverage["domains"]["active_content_indicators"]["status"] == "complete"


def test_parser_coverage_preserves_encrypted_content_as_not_inspected():
    report = {
        "file": {"file_type": "pdf"},
        "structural_analysis": {
            "status": "encrypted",
            "containers_inspected": 0,
            "features": {},
            "warnings": ["The PDF is encrypted."],
        },
    }

    coverage = build_parser_coverage(report)

    assert coverage["domains"]["format_identification"]["status"] == "complete"
    assert coverage["domains"]["container_structure"]["status"] == "not_inspected"
    assert coverage["domains"]["content_inspection"]["status"] == "not_inspected"
    assert coverage["overall_status"] == "partial"


def test_parser_coverage_does_not_claim_supported_format_when_unknown():
    report = {
        "file": {"file_type": "unknown_or_non_pdf"},
        "structural_analysis": {
            "status": "skipped_not_pdf",
            "containers_inspected": 0,
            "features": {},
            "warnings": ["No PDF header was found."],
        },
    }

    coverage = build_parser_coverage(report)

    assert coverage["domains"]["format_identification"]["status"] == "unknown"
    assert coverage["domains"]["container_structure"]["status"] == "unsupported"
    assert coverage["overall_status"] == "unsupported"


def test_finalized_report_and_markdown_include_normalized_parser_coverage():
    report = {
        "file": {"filename": "sample.docx", "file_type": "docx", "size_bytes": 100, "sha256": "a" * 64},
        "assessment": {"verdict": "not_assessed"},
        "metrics": {},
        "warnings": [],
        "scope": {"implemented": ["bounded XML inspection"], "not_implemented": ["document rendering"]},
        "office_analysis": {
            "status": "parsed",
            "container_entry_count": 6,
            "xml_parts_inspected": 3,
            "features": {"external_relationship_count": 2},
            "warnings": [],
        },
        "evidence": [],
        "target_context": {},
    }

    finalize_evidence_traceability(report)
    rendered = to_markdown(report)
    html_rendered = to_html(report)
    encoded = json.loads(serialize_json(report))

    coverage = report["analysis_coverage"]["parser_coverage"]
    assert coverage["parser_family"] == "ooxml"
    assert coverage["domains"]["external_reference_inventory"]["observed_count"] == 2
    assert "## Parser coverage" in rendered
    assert "external_reference_inventory" in rendered
    assert "complete" in rendered
    assert "Parser coverage" in html_rendered
    assert "external_reference_inventory" in html_rendered
    assert encoded["analysis_coverage"]["parser_coverage"] == coverage
