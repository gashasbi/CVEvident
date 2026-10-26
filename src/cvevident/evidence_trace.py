"""Stable, conservative source references for evidence and analysis coverage.

Evidence IDs are scoped to one report. Locators describe what the parser actually
recorded; they never upgrade an aggregate count into a claimed exact source location.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

_ABSENCE_CAVEAT = (
    "No recorded indicator means only that no supported indicator was observed within "
    "the inspected scope; it does not establish that the file is safe."
)

def append_product_context_evidence(report: dict[str, Any]) -> None:
    """Represent each local product-context candidate as retrieval evidence.

    These records describe a local database query result, not a fact discovered in
    the input file. They are kept separate from parser observations.
    """
    context = report.get("target_context") or {}
    target_product = context.get("target_product")
    retrieval_method = context.get("retrieval_method", "unknown")
    evidence = report.setdefault("evidence", [])
    existing = {
        str(item.get("key"))
        for item in evidence
        if item.get("evidence_type") == "product_context_candidate"
    }

    for candidate in context.get("candidate_cves", []) or []:
        cve_id = str(candidate.get("cve_id") or "").strip().upper()
        if not cve_id or cve_id in existing:
            continue
        existing.add(cve_id)
        evidence.append({
            "evidence_type": "product_context_candidate",
            "key": cve_id,
            "value": "candidate_retrieved",
            "severity": "info",
            "details": {
                "origin": "local_vulnerability_database_query",
                "target_product": target_product,
                "retrieval_method": retrieval_method,
                "matched_vendor": candidate.get("matched_vendor"),
                "matched_product": candidate.get("matched_product"),
                "matched_criteria": candidate.get("matched_criteria"),
                "matching_query_terms": candidate.get("matching_query_terms", []),
                "product_relevance_score": candidate.get("product_relevance_score"),
                "score_semantics": "lexical_product_retrieval_score_not_probability",
                "interpretation": (
                    "Retrieved from the local affected-product database using the recorded "
                    "query/matching fields. This does not show that the product or version "
                    "is present in the input file and does not attribute the file to the CVE."
                ),
            },
        })

def append_reported_source_evidence(report: dict[str, Any]) -> None:
    """Promote bounded per-part/per-entry parser examples to individually linked records."""
    evidence = report.setdefault("evidence", [])
    existing = {
        (str(item.get("evidence_type")), str(item.get("key")))
        for item in evidence
    }

    office = report.get("office_analysis") or {}
    relationships = office.get("external_relationships", []) or []
    for index, relation in enumerate(relationships, start=1):
        if not isinstance(relation, dict):
            continue
        key = f"office.external_relationship.{index:04d}"
        if ("office_external_relationship", key) in existing:
            continue
        evidence.append({
            "evidence_type": "office_external_relationship",
            "key": key,
            "value": relation.get("target"),
            "severity": "info",
            "details": {
                "source_part": relation.get("source_part"),
                "relationship_type": relation.get("relationship_type"),
                "target": relation.get("target"),
                "source_example_ordinal": index,
                "source_examples_may_be_bounded": len(relationships) >= 25,
                "interpretation": "A package relationship target was recorded from this source part; the target was not opened or fetched and is not a maliciousness verdict.",
            },
        })

    odf = report.get("odf_analysis") or {}
    references = odf.get("external_references", []) or []
    for index, reference in enumerate(references, start=1):
        if not isinstance(reference, dict):
            continue
        key = f"odf.external_reference.{index:04d}"
        if ("odf_external_reference", key) in existing:
            continue
        evidence.append({
            "evidence_type": "odf_external_reference",
            "key": key,
            "value": reference.get("target"),
            "severity": "info",
            "details": {
                "part": reference.get("part"),
                "element": reference.get("element"),
                "target": reference.get("target"),
                "source_example_ordinal": index,
                "source_examples_may_be_bounded": len(references) >= 25,
                "interpretation": "An external reference string was parsed from this package member and element; the target was not opened or fetched.",
            },
        })

    legacy = report.get("legacy_office_analysis") or {}
    entries = legacy.get("directory_inventory", []) or []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        key = f"legacy_office.directory_entry.{index:04d}"
        if ("legacy_office_directory_entry", key) in existing:
            continue
        evidence.append({
            "evidence_type": "legacy_office_directory_entry",
            "key": key,
            "value": entry.get("name"),
            "severity": "info",
            "details": {
                "directory_inventory_ordinal": index,
                "name": entry.get("name"),
                "entry_type": entry.get("type"),
                "declared_size_bytes": entry.get("declared_size_bytes"),
                "inventory_truncated": bool(legacy.get("directory_inventory_truncated")),
                "interpretation": "This is a metadata-only OLE/CFB directory inventory entry; it does not describe stream-body contents.",
            },
        })

def _evidence_class(item: dict[str, Any]) -> str:
    kind = str(item.get("evidence_type", "unknown"))
    if kind == "file_identity":
        return "file_identity"
    if kind == "reference_sample_match":
        return "reference_metadata_match"
    if kind == "product_context_candidate":
        return "contextual_retrieval"
    if kind in {"pdf_parser", "office_package_status", "legacy_office_status", "rtf_status", "odf_package_status"}:
        return "parser_coverage"
    if kind == "format_check" or kind == "office_format":
        return "format_observation"
    if "lexical" in kind:
        return "lexical_observation"
    return "static_parser_observation"

def _base_file_locator(report: dict[str, Any]) -> dict[str, Any]:
    file_info = report.get("file") or {}
    return {
        "filename": file_info.get("filename"),
        "input_sha256": file_info.get("sha256"),
    }

def _source_locator(item: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Build a locator with an explicit precision/limitation statement."""
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    kind = str(item.get("evidence_type", "unknown"))
    file_locator = _base_file_locator(report)

    supplied = details.get("source_locator")
    if isinstance(supplied, dict):
        return {**supplied, **file_locator}

    offsets = details.get("byte_offsets")
    if isinstance(offsets, list):
        return {
            "kind": "input_file_byte_offsets",
            **file_locator,
            "byte_offsets": offsets,
            "offset_base": 0,
            "offset_unit": "bytes",
            "offsets_truncated": bool(details.get("byte_offsets_truncated", False)),
            "precision": "exact_lexical_match_offsets",
            "limitation": "A lexical byte match is not proof of a parsed semantic object or malicious behavior.",
        }

    source_offset = details.get("offset")
    if isinstance(source_offset, int) and not isinstance(source_offset, bool):
        return {
            "kind": "input_file_byte_offset",
            **file_locator,
            "byte_offset": source_offset,
            "offset_base": 0,
            "offset_unit": "bytes",
            "precision": "exact_reported_byte_offset",
            "limitation": "This is the offset reported by the format/header check, not a semantic object location.",
        }

    object_path = details.get("object_path")
    object_reference = details.get("object_reference")
    if object_path or object_reference:
        return {
            "kind": "pdf_object_graph",
            **file_locator,
            "object_path": object_path,
            "object_reference": object_reference,
            "path_truncated": details.get("object_path_truncated", details.get("path_truncated")),
            "precision": "parsed_object_graph_path_not_byte_offset",
            "limitation": (
                "The path is the parser's best-effort path through the parsed PDF object graph; "
                "it is not a byte offset or a rendered page coordinate."
            ),
        }

    if kind == "reference_sample_match":
        return {
            "kind": "local_reference_sample_record",
            **file_locator,
            "sample_id": item.get("key"),
            "source_name": details.get("source_name"),
            "source_url": details.get("source_url"),
            "label_basis": details.get("label_basis"),
            "precision": "exact_sha256_match_to_registered_metadata",
            "limitation": "The match proves byte identity with the registered sample metadata only; inherited labels retain their own provenance.",
        }

    if kind == "product_context_candidate":
        return {
            "kind": "local_vulnerability_database_candidate",
            **file_locator,
            "cve_id": item.get("key"),
            "target_product": details.get("target_product"),
            "retrieval_method": details.get("retrieval_method"),
            "matched_criteria": details.get("matched_criteria"),
            "matching_query_terms": details.get("matching_query_terms", []),
            "precision": "database_record_and_lexical_match_fields",
            "limitation": "This locator points to a local retrieval result, not to a location in the input file.",
        }

    # These records were promoted from parser examples and have per-record source fields.
    # Resolve them before the package-wide aggregate fallbacks below.
    package_member = details.get("source_part") or details.get("part") or details.get("member_name")
    if isinstance(package_member, str) and package_member:
        return {
            "kind": "package_member_location",
            **file_locator,
            "package_member": package_member,
            "element": details.get("element"),
            "relationship_type": details.get("relationship_type"),
            "target": details.get("target"),
            "source_example_ordinal": details.get("source_example_ordinal"),
            "precision": "exact_reported_package_member_and_element_or_relationship_metadata",
            "limitation": "The package member and parsed element/relationship are identified; this is not an offset into the compressed ZIP or XML bytes.",
        }

    directory_ordinal = details.get("directory_inventory_ordinal")
    if isinstance(directory_ordinal, int) and not isinstance(directory_ordinal, bool):
        return {
            "kind": "ole_cfb_directory_inventory_entry",
            **file_locator,
            "inventory_ordinal": directory_ordinal,
            "name": details.get("name"),
            "entry_type": details.get("entry_type"),
            "declared_size_bytes": details.get("declared_size_bytes"),
            "precision": "directory_inventory_entry_not_file_byte_offset",
            "limitation": "This identifies an entry in the parser's bounded CFB directory inventory; stream body bytes are not parsed.",
        }

    # Package-level features are often aggregated while parsing multiple parts. Keep
    # the examined member set visible, but state when the parser did not retain the
    # specific member/element that contributed to an aggregate count.
    office = report.get("office_analysis") or {}
    if kind.startswith("office_") or str(item.get("key", "")).startswith("office."):
        relationships = office.get("external_relationships", []) or []
        related_members = sorted({
            str(row.get("source_part")) for row in relationships
            if isinstance(row, dict) and row.get("source_part")
        })
        members = (related_members or office.get("parts_inventory", [])) if "relationship" in str(item.get("key", "")).lower() else office.get("parts_inventory", [])
        return {
            "kind": "ooxml_package_members",
            **file_locator,
            "member_names": list(members or []),
            "member_list_is_bounded": bool(office.get("truncated")) or len(members or []) >= 80,
            "precision": "package_member_set_or_relation_sources_not_exact_xml_element",
            "limitation": "Aggregate Office feature counters do not retain a per-element source location in this parser version.",
        }

    odf = report.get("odf_analysis") or {}
    if kind.startswith("odf_") or str(item.get("key", "")).startswith("odf."):
        refs = odf.get("external_references", []) or []
        source_members = sorted({
            str(row.get("part")) for row in refs
            if isinstance(row, dict) and row.get("part")
        })
        members = source_members if "external_reference" in kind else odf.get("parts_inventory", [])
        return {
            "kind": "odf_package_members",
            **file_locator,
            "member_names": list(members or []),
            "member_list_is_bounded": bool(odf.get("truncated")) or len(members or []) >= 80 or len(refs) >= 25,
            "precision": "package_member_set_or_reported_reference_examples",
            "limitation": "Aggregate OpenDocument feature counts do not retain a per-element source location; external-reference examples may be capped.",
        }

    legacy = report.get("legacy_office_analysis") or {}
    if kind.startswith("legacy_office_") or str(item.get("key", "")).startswith("legacy_office."):
        entries = legacy.get("directory_inventory", []) or []
        return {
            "kind": "ole_cfb_directory_inventory",
            **file_locator,
            "directory_entries": [
                {"name": entry.get("name"), "type": entry.get("type"), "index": entry.get("index")}
                for entry in entries if isinstance(entry, dict)
            ],
            "inventory_truncated": bool(legacy.get("directory_inventory_truncated")),
            "precision": "bounded_directory_inventory_not_stream_body_offset",
            "limitation": "Legacy Office stream bodies are not parsed; aggregate indicators may not identify one exact directory entry.",
        }

    rtf = report.get("rtf_analysis") or {}
    if kind.startswith("rtf_") or str(item.get("key", "")).startswith("rtf."):
        scanned = int(rtf.get("bytes_scanned") or 0)
        return {
            "kind": "rtf_scanned_byte_range",
            **file_locator,
            "byte_range_start": 0,
            "byte_range_end_exclusive": scanned,
            "bytes_scanned": scanned,
            "precision": "bounded_scan_range_not_exact_token_offset",
            "limitation": "The current RTF indicator record does not retain the offset of each individual control word/field token.",
        }

    structural = report.get("structural_analysis") or {}
    if kind.startswith("pdf_structural_") or str(item.get("key", "")).startswith("pdf.structure."):
        return {
            "kind": "pdf_object_graph_aggregate",
            **file_locator,
            "parser_status": structural.get("status"),
            "finding_locations_available": bool(structural.get("findings")),
            "precision": "aggregate_feature_not_individually_attributed_to_object",
            "limitation": "This feature is an aggregate parser result; this evidence item does not identify each contributing object.",
        }

    return {
        "kind": "input_file_scope",
        **file_locator,
        "precision": "file_level_only",
        "limitation": "The producing parser did not emit a narrower source coordinate for this evidence item.",
    }

def _extraction_method(item: dict[str, Any]) -> str:
    kind = str(item.get("evidence_type", "unknown"))
    key = str(item.get("key", ""))

    if kind == "pdf_lexical_marker":
        return "bounded_pdf_input_byte_scan"
    if kind.startswith("pdf_structural"):
        return "pypdf_object_graph_traversal"
    if (
        kind == "pdf_parser"
        or kind.endswith("_status")
        or key.endswith("_status")
        or key.endswith(".status")
    ):
        return "parser_status_and_coverage_reporting"
    if kind == "file_identity":
        if key == "sha256":
            return "sha256_digest_of_input_bytes"
        if key == "file_size_bytes":
            return "input_byte_length"
        return "input_file_metadata_read"
    if kind == "format_check":
        if "extension_mismatch" in key:
            return "filename_extension_vs_detected_format_comparison"
        return "input_signature_or_format_header_check"
    if kind == "reference_sample_match":
        return "local_reference_sample_sha256_lookup"
    if kind == "product_context_candidate":
        return "local_vulnerability_database_product_context_lookup"
    if kind.startswith("office_") or key.startswith("office."):
        return "bounded_ooxml_zip_and_xml_inspection"
    if kind.startswith("odf_") or key.startswith("odf."):
        return "bounded_opendocument_zip_and_xml_inspection"
    if kind.startswith("legacy_office_") or key.startswith("legacy_office."):
        return "bounded_ole_cfb_directory_inspection"
    if kind.startswith("rtf_") or key.startswith("rtf."):
        return "bounded_rtf_scan"
    return "parser_reported_observation"


def _safe_observed_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        normalized = " ".join(value.split())
        if len(normalized) <= 500:
            return normalized
        return {"preview": normalized[:500], "truncated": True}
    if isinstance(value, dict):
        return {
            "type": "object",
            "key_count": len(value),
            "keys_preview": [str(key)[:100] for key in list(value)[:20]],
        }
    if isinstance(value, (list, tuple, set)):
        return {"type": "collection", "item_count": len(value)}
    return {"type": type(value).__name__}


def _evidence_parser_section(item: dict[str, Any]) -> str | None:
    kind = str(item.get("evidence_type", ""))
    key = str(item.get("key", ""))

    if kind.startswith("pdf_structural") or kind == "pdf_parser" or key.startswith("pdf.structure."):
        return "structural_analysis"
    if kind.startswith("office_") or key.startswith("office."):
        return "office_analysis"
    if kind.startswith("odf_") or key.startswith("odf."):
        return "odf_analysis"
    if kind.startswith("legacy_office_") or key.startswith("legacy_office."):
        return "legacy_office_analysis"
    if kind.startswith("rtf_") or key.startswith("rtf."):
        return "rtf_analysis"
    return None


def _evidence_limitations(
    item: dict[str, Any], locator: dict[str, Any], report: dict[str, Any]
) -> list[str]:
    limitations: list[str] = []
    kind = str(item.get("evidence_type", ""))

    if kind == "file_identity":
        limitations.append(
            "File identity metadata describes the input bytes; it is not a content finding "
            "and does not establish file safety."
        )
    elif kind == "format_check":
        limitations.append(
            "Format identification is a static check; it does not establish that the file "
            "is well-formed or safe."
        )
    elif kind == "reference_sample_match":
        limitations.append(
            "A local reference-sample hash match is a byte-identity association, not proof "
            "of exploitability or malicious behavior."
        )
    elif kind == "product_context_candidate":
        limitations.append(
            "Product context is a local database association, not attribution of this file "
            "to a vulnerable product or proof of exploitability."
        )

    locator_limitation = locator.get("limitation")
    if isinstance(locator_limitation, str) and locator_limitation:
        limitations.append(locator_limitation)

    section = _evidence_parser_section(item)
    parser = report.get(section) if section else None
    if isinstance(parser, dict):
        status = str(parser.get("status", "unknown")).lower()
        if status in {"partial", "failed", "unavailable", "unsupported", "unknown", "encrypted"}:
            limitations.append(f"{section} reports parser status '{status}'.")
        if (
            parser.get("truncated")
            or parser.get("findings_truncated")
            or parser.get("inventory_truncated")
        ):
            limitations.append(
                "Parser output was truncated or capped; uninspected content is not represented by this observation."
            )

    if not limitations:
        limitations.append(
            "This is a static parser observation; it does not establish file safety or exploitability."
        )
    return list(dict.fromkeys(limitations))


def _feature_assessments(report: dict[str, Any]) -> list[dict[str, Any]]:
    specifications = (
        ("structural_analysis", "pypdf_object_graph_traversal", "containers_inspected", "PDF object containers"),
        ("office_analysis", "bounded_ooxml_zip_and_xml_inspection", "xml_parts_inspected", "XML parts"),
        ("odf_analysis", "bounded_opendocument_zip_and_xml_inspection", "xml_parts_inspected", "XML parts"),
        ("legacy_office_analysis", "bounded_ole_cfb_directory_inspection", "directory_entry_count", "CFB directory entries"),
        ("rtf_analysis", "bounded_rtf_scan", "bytes_scanned", "bytes"),
    )
    hard_incomplete_statuses = {
        "failed", "unavailable", "unsupported", "unknown", "encrypted",
    }
    results: list[dict[str, Any]] = []

    for section, method, count_key, unit in specifications:
        parser = report.get(section)
        if not isinstance(parser, dict):
            continue
        features = parser.get("features")
        if not isinstance(features, dict):
            continue

        parser_status = str(parser.get("status", "unknown")).lower()
        truncated = bool(
            parser.get("truncated")
            or parser.get("findings_truncated")
            or parser.get("inventory_truncated")
        )
        inspected_count = parser.get(count_key, 0)
        if not isinstance(inspected_count, int) or isinstance(inspected_count, bool):
            inspected_count = 0
        inspected_count = max(0, inspected_count)

        for feature, value in sorted(features.items(), key=lambda pair: str(pair[0])):
            if value is True:
                status = "observed"
            elif isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                status = "observed"
            elif isinstance(value, (str, list, tuple, dict, set)) and bool(value):
                status = "observed"
            elif value is None:
                status = "not_assessed"
            elif parser_status in hard_incomplete_statuses or inspected_count == 0:
                status = "not_assessed"
            elif parser_status == "partial" or truncated:
                status = "not_found_in_inspected_scope"
            else:
                status = "not_found"

            if status == "observed":
                limitations = [
                    "Static observation only; this does not establish maliciousness or exploitability."
                ]
            elif status == "not_found":
                limitations = [
                    "No instance was recorded in the completed declared static scope; absence does not establish safety."
                ]
            elif status == "not_found_in_inspected_scope":
                limitations = [
                    "No instance was recorded in the inspected scope; uninspected content may contain additional instances."
                ]
            else:
                limitations = [
                    "The relevant feature could not be assessed reliably; absence must not be inferred."
                ]

            if parser_status in hard_incomplete_statuses or parser_status == "partial" or truncated:
                limitations.append(
                    f"{section} status is '{parser_status}'"
                    + (" and its output was truncated or capped." if truncated else ".")
                )
                parser_warnings = parser.get("warnings", [])
                if isinstance(parser_warnings, list):
                    limitations.extend(
                        str(warning) for warning in parser_warnings[:3] if warning
                    )

            results.append({
                "parser_section": section,
                "feature": str(feature),
                "status": status,
                "observed_value": _safe_observed_value(value),
                "extraction_method": method,
                "inspected_scope": {"count": inspected_count, "unit": unit},
                "analysis_limitations": list(dict.fromkeys(limitations)),
            })

    return results


def finalize_evidence_traceability(report: dict[str, Any]) -> None:
    """Assign report-local IDs, attach locators and summarize analysis coverage."""
    evidence = report.setdefault("evidence", [])
    sample_ids: dict[str, str] = {}
    candidate_ids: dict[str, str] = {}
    class_counts: Counter[str] = Counter()
    locator_counts: Counter[str] = Counter()
    precision_counts: Counter[str] = Counter()

    for index, item in enumerate(evidence, start=1):
        evidence_id = f"EV-{index:06d}"
        evidence_class = _evidence_class(item)
        locator = _source_locator(item, report)
        item["evidence_id"] = evidence_id
        item["evidence_class"] = evidence_class
        item["evidence_origin"] = (
            "local_reference_sample_database" if item.get("evidence_type") == "reference_sample_match"
            else "local_vulnerability_database" if item.get("evidence_type") == "product_context_candidate"
            else "input_file_parser_or_file_identity"
        )
        item["source_locator"] = locator

        # Persist the same traceability fields in the normalized evidence row's
        # details_json as well as in the report's top-level evidence object.
        details = item.get("details")
        if not isinstance(details, dict):
            details = {}
            item["details"] = details
        details["traceability"] = {
            "evidence_id": evidence_id,
            "evidence_type": str(item.get("evidence_type", "unknown")),
            "evidence_class": evidence_class,
            "evidence_origin": item["evidence_origin"],
            "extraction_method": _extraction_method(item),
            "observed_value": _safe_observed_value(item.get("value")),
            "source_locator": locator,
            "analysis_limitations": _evidence_limitations(item, locator, report),
        }
        class_counts[evidence_class] += 1
        locator_counts[str(locator.get("kind", "unknown"))] += 1
        precision_counts[str(locator.get("precision", "unknown"))] += 1

        evidence_type = item.get("evidence_type")
        if evidence_type == "reference_sample_match":
            sample_ids.setdefault(str(item.get("key", "")), evidence_id)
        elif evidence_type == "product_context_candidate":
            candidate_ids.setdefault(str(item.get("key", "")).upper(), evidence_id)

    for sample in report.get("reference_sample_matches", []) or []:
        if isinstance(sample, dict):
            sample["evidence_id"] = sample_ids.get(str(sample.get("sample_id", "")))
    context = report.get("target_context") or {}
    for candidate in context.get("candidate_cves", []) or []:
        if isinstance(candidate, dict):
            candidate["evidence_id"] = candidate_ids.get(str(candidate.get("cve_id", "")).upper())

    report["evidence_traceability"] = {
        "schema_version": 1,
        "id_scope": "IDs are deterministic within this report's evidence ordering; they are not database primary keys or stable across report revisions.",
        "evidence_count": len(evidence),
        "evidence_classes": dict(sorted(class_counts.items())),
        "source_locator_kinds": dict(sorted(locator_counts.items())),
        "source_locator_precisions": dict(sorted(precision_counts.items())),
        "locator_limitation": "A locator is only as precise as the producing parser. Aggregate locations are explicitly marked and are not promoted to exact offsets.",
    }

    parser_sections = (
        "office_analysis", "odf_analysis", "legacy_office_analysis",
        "rtf_analysis", "structural_analysis",
    )
    section_name = next((name for name in parser_sections if isinstance(report.get(name), dict)), None)
    parser_report = report.get(section_name, {}) if section_name else {}
    parser_status = parser_report.get("status", "unknown")
    truncated = bool(
        parser_report.get("truncated")
        or parser_report.get("findings_truncated")
        or parser_report.get("inventory_truncated")
    )
    incomplete_statuses = {"partial", "failed", "unavailable", "unsupported", "unknown", "encrypted"}
    scope = report.get("scope") or {}
    limitation_reasons: list[str] = []
    for value in list(scope.get("not_implemented", []) or []):
        if value and value not in limitation_reasons:
            limitation_reasons.append(str(value))
    for value in list(report.get("warnings", []) or []) + list(parser_report.get("warnings", []) or []):
        if value and value not in limitation_reasons:
            limitation_reasons.append(str(value))

    file_info = report.get("file") if isinstance(report.get("file"), dict) else {}
    file_type = str(file_info.get("file_type") or "").strip().lower()
    format_recognized = bool(file_type) and not file_type.startswith("unknown")
    if not format_recognized:
        unknown_format_reason = (
            "Input format was not recognized as a supported format; fallback byte-oriented observations "
            "are not a format-specific parse."
        )
        if unknown_format_reason not in limitation_reasons:
            limitation_reasons.append(unknown_format_reason)

    coverage_complete = (
        format_recognized
        and parser_status not in incomplete_statuses
        and not truncated
    )
    feature_assessments = _feature_assessments(report)
    report["analysis_coverage"] = {
        "schema_version": 1,
        "parser_section": section_name,
        "parser_status": parser_status,
        "truncated": truncated,
        "complete_for_declared_static_scope": coverage_complete,
        "semantic_validation_performed": False,
        "dynamic_analysis_performed": False,
        "cve_file_attribution_performed": False,
        "implemented_scope": list(scope.get("implemented", []) or []),
        "not_implemented_scope": list(scope.get("not_implemented", []) or []),
        "limitation_reasons": limitation_reasons,
        "absence_of_findings_means": _ABSENCE_CAVEAT,
        "interpretation": "Coverage status describes the declared static inspection only; it is not a safety determination.",
        "feature_assessments": feature_assessments,
    }

    # The normal Markdown/HTML report already renders warnings. Add concise coverage
    # caveats there too, while retaining the structured machine-readable coverage block.
    warnings = report.setdefault("warnings", [])
    if _ABSENCE_CAVEAT not in warnings:
        warnings.append(_ABSENCE_CAVEAT)
    not_implemented = scope.get("not_implemented", []) or []
    if not_implemented:
        scope_warning = "Not inspected by the declared scope: " + "; ".join(map(str, not_implemented)) + "."
        if scope_warning not in warnings:
            warnings.append(scope_warning)
