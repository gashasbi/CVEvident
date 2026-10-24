"""Boundary coverage for optional Markdown report locator/context fields."""

from __future__ import annotations

from cvevident.reporting import to_markdown


def _evidence(index: int, locator: dict, *, details: dict | None = None) -> dict:
    return {
        "evidence_id": f"EV-{index:06d}",
        "evidence_type": "test_locator",
        "key": f"test.locator.{index}",
        "value": "observed",
        "severity": "info",
        "details": details or {},
        "source_locator": locator,
    }


def _report(*, evidence: list[dict] | None = None, target_context: dict | None = None) -> dict:
    return {
        "file": {
            "filename": "sample.docx",
            "file_type": "docx",
            "size_bytes": 128,
            "sha256": "a" * 64,
        },
        "assessment": {"verdict": "not_assessed", "reason": "Static observations only."},
        "metrics": {},
        "warnings": [],
        "evidence": evidence or [],
        "target_context": target_context or {},
    }


def test_markdown_renders_bounded_and_alternative_source_locator_shapes() -> None:
    evidence = [
        _evidence(
            1,
            {
                "kind": "pdf_lexical_marker",
                "precision": "bounded",
                "byte_offsets": [12, 31],
                "offsets_truncated": True,
            },
            details={"path_truncated": True},
        ),
        _evidence(
            2,
            {
                "kind": "package_inventory",
                "precision": "bounded",
                "member_names": ["word/document.xml", "word/styles.xml"],
                "member_list_is_bounded": True,
            },
        ),
        _evidence(
            3,
            {
                "kind": "package_member",
                "precision": "exact",
                "package_member": "word/document.xml",
                "element": "w:fldSimple",
                "target": "https://example.invalid/resource\nwith newline",
            },
        ),
        _evidence(
            4,
            {
                "kind": "cve_candidate",
                "precision": "contextual",
                "cve_id": "CVE-2026-12345",
                "retrieval_method": "lexical_match",
                "target_product": "Widget",
                "matched_criteria": "cpe:2.3:" + ("a" * 350),
                "matching_query_terms": ["widget", "vendor"],
            },
        ),
        _evidence(
            5,
            {
                "kind": "reference_sample",
                "precision": "exact",
                "sample_id": "SAMPLE-001",
                "source_name": "sample registry",
                "label_basis": "curated metadata",
                "source_url": "https://example.invalid/" + ("x" * 300),
            },
        ),
        _evidence(
            6,
            {
                "kind": "package_inventory_entry",
                "precision": "exact",
                "inventory_ordinal": 4,
                "name": "word/document.xml",
                "entry_type": "XML",
                "declared_size_bytes": 128,
            },
        ),
        _evidence(
            7,
            {
                "kind": "byte_range",
                "precision": "bounded",
                "byte_range_end_exclusive": 256,
            },
        ),
        _evidence(
            8,
            {
                "kind": "coarse_location",
                "precision": "coarse",
                "limitation": "Exact source unavailable\nbut coarse location retained.",
            },
        ),
    ]

    rendered = to_markdown(_report(evidence=evidence))

    assert "additional occurrences omitted" in rendered
    assert "member list bounded" in rendered
    assert "word/document.xml; element w:fldSimple; target https://example.invalid/resource with newline" in rendered
