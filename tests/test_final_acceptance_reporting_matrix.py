"""Cross-section Markdown report acceptance for optional static-analysis evidence."""
from __future__ import annotations

from cvevident.reporting import to_markdown


def _base_report() -> dict:
    return {
        "file": {"filename": "report.docx", "file_type": "docx", "size_bytes": 4096, "sha256": "a" * 64},
        "assessment": {"verdict": "not_assessed", "reason": "Static triage only."},
        "metrics": {},
        "warnings": ["outer warning"],
        "evidence": [],
        "target_context": {},
    }


def test_markdown_renders_office_inventory_limits_and_product_context_branches() -> None:
    report = _base_report()
    report["office_analysis"] = {
        "status": "partial",
        "format_id": "docx",
        "family": "word",
        "main_part": "word/document.xml\nwith newline",
        "container_entry_count": 12,
        "declared_uncompressed_bytes": 5000,
        "xml_parts_inspected": 2,
        "xml_bytes_inspected": 100,
        "macro_enabled_format": False,
        "vba_project_present": False,
        "truncated": True,
        "features": {"positive": 2, "boolean_true": True, "boolean_false": False, "zero": 0, "negative": -1},
        "external_relationships": [
            {"source_part": "word/document.xml", "relationship_type": "hyperlink", "target": f"https://example.test/{i}|target"}
            for i in range(26)
        ],
        "parts_inventory": [f"word/part-{i:03d}.xml" for i in range(81)],
        "warnings": ["manifest\nwas partial"],
    }
    report["target_context"] = {
        "target_product": "Widget",
        "target_vendor": "Example Vendor\nNormalized",
        "target_version": "1.2.3",
        "normalized_target_product": "widget",
        "interpretation": "Context only; not file attribution.",
        "product_identity_ambiguity": {
            "status": "ambiguous\nidentity",
            "distinct_matched_product_identity_count": 2,
            "matched_product_identities": [
                {"vendor": "example", "product": "widget"},
                {"vendor": None, "product": None},
            ],
        },
        "source_freshness": {
            "sources": {
                "NVD": {"state": "available", "freshness_class": "fresh", "last_success_at": "2026-10-20"},
                "CISA KEV": {"state": "unknown", "freshness_class": "unknown", "last_success_at": None},
            }
        },
        "candidate_cves": [{"cve_id": "CVE-2026-1234", "product_relevance_score": 4, "cvss_score": 8.1,
                            "cvss_severity": "HIGH", "cisa_kev": True, "epss_score": 0.7}],
    }

    rendered = to_markdown(report)

    assert "## Office package analysis" in rendered
    assert "Main part: `word/document.xml with newline`" in rendered
    assert "| `positive` | `2` |" in rendered
    assert "| `boolean_true` | `True` |" in rendered
    assert "| `boolean_false` |" not in rendered
    assert "| `zero` |" not in rendered
    assert "| `negative` |" not in rendered
    assert rendered.count("https://example.test/") == 25
    assert "word/part-079.xml" in rendered
    assert "word/part-080.xml" not in rendered
    assert "Target vendor filter: `Example Vendor Normalized`" in rendered
    assert "distinct matched identities: `2`" in rendered
    assert "unknown-vendor:unknown-product" in rendered
    assert "Local vulnerability-data freshness" in rendered
    assert "CVE-2026-1234" in rendered
    assert "outer warning" in rendered
    assert "manifest was partial" in rendered


def test_markdown_renders_sample_association_metadata_and_product_context_basis() -> None:
    report = _base_report()
    report["target_context"] = {
        "target_product": "widget",
        "interpretation": "Lexical product context only.",
        "candidate_cves": [],
    }
    report["cve_association_policy"] = "candidate associations are not proof\nfor line formatting"
    report["cve_associations"] = [
        {
            "cve_id": "CVE-2024-1234",
            "assessment": "candidate_not_file_attribution",
            "description": "An example vulnerability.",
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "cisa_kev": None,
            "published": "2024-01-01",
            "modified": None,
            "epss_score": None,
            "association_bases": [
                {
                    "type": "exact_sha256_sample_match",
                    "sample_id": "sample-1",
                    "sample_label": "unknown",
                    "sample_confidence": "low",
                    "link_confidence": "medium",
                    "link_verified": False,
                    "link_association_type": "reported",
                    "link_evidence_basis": "source record",
                    "sample_source_name": "curated registry",
                    "sample_source_url": "https://example.test/sample-source",
                    "interpretation": "An exact hash match is sample metadata, not a malware verdict.",
                },
                {
                    "type": "product_context",
                    "target_product": "widget",
                    "matched_vendor": "example",
                    "matched_product": "widget",
                    "product_relevance_score": 3,
                    "matched_criteria": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
                    "name_match_class": "exact_token_match",
                    "candidate_relevance": "contextual",
                    "version_context": {"status": "indeterminate", "comparison_method": "simple_range",
                                        "interpretation": "No complete applicability evaluation."},
                    "query_normalization": {"normalized_product_query": "widget"},
                    "matching_query_terms": ["widget", "example"],
                    "local_source_signals": {
                        "NVD": {"state": "available"},
                        "CISA KEV": {"state": "unknown"},
                        "FIRST EPSS": {"freshness_class": "stale"},
                    },
                    "interpretation": "Lexical context only; no file attribution.",
                },
            ],
        }
    ]

    rendered = to_markdown(report)

    assert "## CVE association candidates" in rendered
    assert "CVE-2024-1234" in rendered
    assert "candidate associations are not proof for line formatting" in rendered
    assert "Basis: exact SHA-256 match to registered sample `sample-1`" in rendered
    assert "link verified: no" in rendered
    assert "Link type: reported" in rendered
    assert "Link evidence basis: source record" in rendered
    assert "Sample source: curated registry" in rendered
    assert "Basis: product context; target product `widget`" in rendered
    assert "Matched CPE: `cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*`" in rendered
    assert "Version context: `indeterminate` via `simple_range`" in rendered
    assert "Normalized query: `widget`; matched terms: `widget, example`" in rendered
    assert "NVD local signal: `available`" in rendered
    assert "CISA KEV local signal: `unknown`" in rendered
    assert "FIRST EPSS local signal: `stale`" in rendered


def test_markdown_renders_odf_rtf_and_legacy_office_sections_with_bounded_examples() -> None:
    odf_report = _base_report()
    odf_report["odf_analysis"] = {
        "status": "partial", "format_id": "ods", "family": "spreadsheet",
        "mimetype": "application/vnd.oasis.opendocument.spreadsheet",
        "main_part": "content.xml\nline", "container_entry_count": 10,
        "declared_uncompressed_bytes": 1000, "xml_parts_inspected": 2, "xml_bytes_inspected": 500,
        "mimetype_first_and_uncompressed": True, "truncated": True,
        "features": {"external_references": 2, "false_feature": False},
        "external_references": [{"part": "content.xml", "element": "table:cell", "target": f"https://example.test/{i}|x"} for i in range(26)],
        "warnings": ["ODF\nwarning"],
    }
    odf = to_markdown(odf_report)
    assert "## OpenDocument package analysis" in odf
    assert "Mimetype: `application/vnd.oasis.opendocument.spreadsheet`" in odf
    assert odf.count("https://example.test/") == 25
    assert "| `external_references` | `2` |" in odf
    assert "ODF warning" in odf

    rtf_report = _base_report()
    rtf_report["rtf_analysis"] = {
        "status": "partial", "bytes_scanned": 50, "maximum_group_depth": 4,
        "header_found": True, "rtf_version": 1, "group_balance": -1, "truncated": True,
        "features": {"field_instructions": 1, "false_feature": False},
        "field_instruction_examples": [f"field-{index}" for index in range(11)],
        "warnings": ["unclosed group\nfound"],
    }
    rtf = to_markdown(rtf_report)
    assert "## RTF analysis" in rtf
    assert "RTF bytes scanned: `50`" in rtf
    assert "field-9" in rtf and "field-10" not in rtf
    assert "unclosed group found" in rtf
    assert "| `field_instructions` | `1` |" in rtf

    legacy_report = _base_report()
    legacy_report["legacy_office_analysis"] = {
        "status": "partial", "family": "word", "format_id": "doc", "sector_size": 512,
        "directory_entry_count": 2, "stream_count": 1, "storage_count": 1,
        "vba_project_present": True, "encrypted_content_present": False, "truncated": True,
        "features": {"vba_project_present": True, "empty_feature": False},
        "directory_inventory": [
            {"name": f"entry-{index}|unsafe", "type": "stream", "declared_size_bytes": index}
            for index in range(101)
        ],
        "warnings": ["directory\nwas partial"],
    }
    legacy = to_markdown(legacy_report)
    assert "## Legacy Office (OLE/CFB) analysis" in legacy
    assert "| `vba_project_present` | `True` |" in legacy
    assert "entry-99\\|unsafe" in legacy
    assert "entry-100\\|unsafe" not in legacy
    assert "directory was partial" in legacy
