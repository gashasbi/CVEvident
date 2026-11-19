from __future__ import annotations

from typing import Any


PARSER_SECTIONS = (
    "office_analysis",
    "odf_analysis",
    "legacy_office_analysis",
    "rtf_analysis",
    "structural_analysis",
)

STATUS_MAP = {
    "parsed": "complete",
    "partial": "partial",
    "failed": "failed",
    "unavailable": "unavailable",
    "unsupported": "unsupported",
    "skipped_not_pdf": "unsupported",
    "encrypted": "not_inspected",
}

DOMAIN_SCOPES = {
    "pdf": {
        "container_structure": "PDF catalog and object-graph traversal within configured object and depth budgets.",
        "content_inspection": "Lexical byte markers and parsed object dictionaries; page content streams are not decoded or rendered.",
        "embedded_object_inventory": "Embedded-file name-tree, file-specification, associated-file, and file-attachment annotation indicators; payloads are not extracted.",
        "external_reference_inventory": "Parsed URI, link, remote-go-to, and embedded-go-to indicators; targets are not followed.",
        "active_content_indicators": "Parsed action and JavaScript indicators; actions are never executed.",
    },
    "ooxml": {
        "container_structure": "ZIP member inventory, content types, and selected package relationships within configured limits.",
        "content_inspection": "Selected XML and relationship parts within configured limits; full document rendering is not performed.",
        "embedded_object_inventory": "Embedded package members and linked OLE metadata; payloads are not extracted or executed.",
        "external_reference_inventory": "External relationship, attached-template, external workbook-link, connection, hyperlink, and formula indicators; targets are not fetched.",
        "active_content_indicators": "VBA, ActiveX, macro-sheet, field, and formula indicators; content is not executed.",
    },
    "odf": {
        "container_structure": "ZIP member inventory and OpenDocument package metadata within configured limits.",
        "content_inspection": "Selected XML parts within configured limits; full document rendering is not performed.",
        "embedded_object_inventory": "Embedded-object package members and XML indicators; payloads are not extracted or executed.",
        "external_reference_inventory": "External-reference URI schemes and external script-reference indicators in inspected XML; targets are not fetched.",
        "active_content_indicators": "Script, Basic macro, event-listener, macro-field, and formula indicators; content is not executed.",
    },
    "legacy_office": {
        "container_structure": "OLE/CFB header, allocation tables, directory, and bounded stream-chain structure.",
        "content_inspection": "Bounded stream reads for structural validation and file signatures only; stream bodies and VBA source are not interpreted.",
        "embedded_object_inventory": "CFB directory-name and storage indicators; embedded payloads are not extracted or interpreted.",
        "external_reference_inventory": "Legacy Office external-link stream-name indicators; targets are not resolved.",
        "active_content_indicators": "VBA storage and project-stream directory-name indicators only; VBA source is not parsed or executed.",
    },
    "rtf": {
        "container_structure": "RTF group and control-word scan within configured byte, depth, and control-word budgets.",
        "content_inspection": "Bounded lexical inspection of control words, field instructions, and binary payload boundaries; rendering is not performed.",
        "embedded_object_inventory": "RTF object and picture group indicators; payloads are not decoded.",
        "external_reference_inventory": "External target strings found in scanned field instructions; targets are not opened.",
        "active_content_indicators": "Field-instruction keyword and object-group indicators; instructions and objects are not executed.",
    },
}

DOMAIN_COUNT_SPECS = {
    "pdf": {
        "container_structure": ("containers_inspected", "PDF object containers"),
        "content_inspection": ("containers_inspected", "PDF object containers"),
        "embedded_object_inventory": ("containers_inspected", "PDF object containers"),
        "external_reference_inventory": ("containers_inspected", "PDF object containers"),
        "active_content_indicators": ("containers_inspected", "PDF object containers"),
    },
    "ooxml": {
        "container_structure": ("container_entry_count", "ZIP entries"),
        "content_inspection": ("xml_parts_inspected", "XML parts"),
        "embedded_object_inventory": ("container_entry_count", "ZIP entries"),
        "external_reference_inventory": ("xml_parts_inspected", "XML parts"),
        "active_content_indicators": ("xml_parts_inspected", "XML parts"),
    },
    "odf": {
        "container_structure": ("container_entry_count", "ZIP entries"),
        "content_inspection": ("xml_parts_inspected", "XML parts"),
        "embedded_object_inventory": ("container_entry_count", "ZIP entries"),
        "external_reference_inventory": ("xml_parts_inspected", "XML parts"),
        "active_content_indicators": ("xml_parts_inspected", "XML parts"),
    },
    "legacy_office": {
        "container_structure": ("directory_entry_count", "CFB directory entries"),
        "content_inspection": ("stream_read_count", "CFB streams"),
        "embedded_object_inventory": ("directory_entry_count", "CFB directory entries"),
        "external_reference_inventory": ("directory_entry_count", "CFB directory entries"),
        "active_content_indicators": ("directory_entry_count", "CFB directory entries"),
    },
    "rtf": {
        "container_structure": ("bytes_scanned", "bytes"),
        "content_inspection": ("bytes_scanned", "bytes"),
        "embedded_object_inventory": ("bytes_scanned", "bytes"),
        "external_reference_inventory": ("bytes_scanned", "bytes"),
        "active_content_indicators": ("bytes_scanned", "bytes"),
    },
}

DOMAIN_OBSERVED_KEYS = {
    "pdf": {
        "embedded_object_inventory": (
            "embedded_files_name_tree_count",
            "file_specifications_with_embedded_data",
            "associated_file_entries", "file_attachment_annotations",
        ),
        "external_reference_inventory": (
            "uri_action_count", "remote_goto_action_count", "link_annotations",
            "embedded_goto_action_count",
        ),
        "active_content_indicators": (
            "javascript_action_count", "launch_action_count", "submit_form_action_count",
            "import_data_action_count", "reset_form_action_count", "rich_media_execute_action_count",
            "embedded_goto_action_count", "optional_content_state_action_count",
            "goto_3d_view_action_count", "xfa_present",
        ),
    },
    "ooxml": {
        "embedded_object_inventory": (
            "embedded_object_part_count", "ole_object_element_count", "activex_part_count",
        ),
        "external_reference_inventory": (
            "external_relationship_count", "external_link_part_count", "hyperlink_element_count",
            "external_formula_reference_count", "external_attached_template_relationship_count",
            "external_hyperlink_relationship_count", "external_link_relationship_count",
            "external_connection_part_count", "query_table_part_count",
        ),
        "active_content_indicators": (
            "vba_project_present", "activex_part_count", "macro_sheet_part_count",
            "field_instruction_count", "formula_network_function_count",
        ),
    },
    "odf": {
        "embedded_object_inventory": ("embedded_object_member_count", "embedded_object_element_count"),
        "external_reference_inventory": ("external_reference_count", "external_script_reference_count"),
        "active_content_indicators": (
            "script_or_basic_member_count", "script_element_count", "script_event_listener_count",
            "macro_execution_field_count", "external_script_reference_count", "macro_named_member_count",
        ),
    },
    "legacy_office": {
        "embedded_object_inventory": ("embedded_object_indicator_count",),
        "external_reference_inventory": ("external_link_stream_name_count",),
        "active_content_indicators": (
            "vba_project_present", "vba_related_directory_entry_count",
            "vba_project_stream_name_present", "vba_directory_stream_name_present",
            "vba_project_metadata_stream_name_present", "vba_storage_name_present",
            "vba_project_workspace_stream_name_present", "vba_project_link_stream_name_present",
        ),
    },
    "rtf": {
        "embedded_object_inventory": ("object_group_indicator_count", "picture_group_indicator_count"),
        "external_reference_inventory": ("external_target_count",),
        "active_content_indicators": (
            "field_instruction_group_count", "field_instruction_indicator_count",
            "field_instruction_ddeauto_count", "field_instruction_dde_count",
            "field_instruction_includetext_count", "field_instruction_includepicture_count",
            "field_instruction_hyperlink_count", "field_instruction_database_count",
            "field_instruction_import_count", "field_instruction_link_count",
        ),
    },
}

DOMAIN_TRUNCATION_KEYS = {
    "container_structure": (
        "truncated", "inventory_truncated", "directory_chain_truncated",
        "directory_inventory_truncated", "mini_fat_truncated",
        "root_mini_stream_truncated", "stream_inventory_truncated",
        "stream_read_partial", "depth_limit_reached", "control_word_limit_reached",
    ),
    "content_inspection": (
        "truncated", "findings_truncated", "inventory_truncated",
        "stream_read_partial", "binary_payload_truncated",
        "depth_limit_reached", "control_word_limit_reached",
    ),
    "embedded_object_inventory": (
        "truncated", "findings_truncated", "inventory_truncated",
        "ole_object_references_truncated", "directory_inventory_truncated",
        "stream_inventory_truncated",
    ),
    "external_reference_inventory": (
        "truncated", "findings_truncated", "inventory_truncated",
        "ole_relationship_inventory_truncated",
    ),
    "active_content_indicators": (
        "truncated", "findings_truncated", "inventory_truncated",
        "binary_payload_truncated", "depth_limit_reached",
        "control_word_limit_reached",
    ),
}


def _integer(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _count_features(features: Any, keys: tuple[str, ...]) -> int:
    if not isinstance(features, dict):
        return 0
    total = 0
    for key in keys:
        value = features.get(key)
        if isinstance(value, bool):
            total += int(value)
        elif isinstance(value, (int, float)):
            total += max(0, int(value))
    return total


def _parser_family(section: str | None) -> str:
    return {
        "structural_analysis": "pdf",
        "office_analysis": "ooxml",
        "odf_analysis": "odf",
        "legacy_office_analysis": "legacy_office",
        "rtf_analysis": "rtf",
    }.get(section or "", "unknown")


def _normalized_status(status: str) -> str:
    return STATUS_MAP.get(status, "unknown")


def _truncated(parser: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(bool(parser.get(key)) for key in keys)


def _observed_count(family: str, domain: str, parser: dict[str, Any]) -> int | None:
    keys = DOMAIN_OBSERVED_KEYS.get(family, {}).get(domain)
    if keys is None:
        return None
    return _count_features(parser.get("features"), keys)


def _domain_record(
    family: str,
    domain: str,
    parser: dict[str, Any],
    parser_status: str,
) -> dict[str, Any]:
    if domain == "semantic_interpretation":
        return {
            "status": "not_inspected",
            "in_declared_scope": False,
            "inspected_count": 0,
            "inspected_unit": "semantic document models",
            "observed_count": None,
            "limit_reached": False,
            "scope": "Full semantic document interpretation and rendering are outside the current static-analysis scope.",
            "limitations": ["Full semantic document interpretation and rendering are outside the current static-analysis scope."],
        }

    raw_status = _normalized_status(parser_status)
    count_key, unit = DOMAIN_COUNT_SPECS[family][domain]
    inspected_count = _integer(parser.get(count_key))
    truncation_keys = DOMAIN_TRUNCATION_KEYS[domain]
    limit_reached = _truncated(parser, truncation_keys)
    status = raw_status
    limitations: list[str] = []

    if parser_status == "encrypted":
        status = "not_inspected"
        limitations.append("The relevant content is encrypted and was not decrypted or inspected.")
    elif raw_status == "complete" and limit_reached:
        status = "partial"
        limitations.append("A parser output or resource limit was reached for this inspection domain.")
    elif raw_status in {"partial", "failed", "unavailable", "unsupported", "unknown"}:
        limitations.extend(
            str(value) for value in parser.get("warnings", [])[:4] if value
        )
        if not limitations:
            limitations.append(f"The parser reported status '{parser_status}'.")

    if domain == "content_inspection" and family == "legacy_office":
        if inspected_count == 0 and status == "complete":
            status = "not_inspected"
            limitations.append("No CFB stream bodies were read for bounded signature inspection.")
        else:
            limitations.append(
                "Stream reads are bounded and used for structural validation and signatures; stream semantics are not interpreted."
            )

    if not limitations and status == "complete":
        limitations.append("The parser completed this domain within its declared static inspection scope.")

    return {
        "status": status,
        "in_declared_scope": domain != "semantic_interpretation",
        "inspected_count": inspected_count,
        "inspected_unit": unit,
        "observed_count": _observed_count(family, domain, parser),
        "observed_count_semantics": (
            "Sum of configured parser indicator counters; counters can overlap and do not represent unique objects."
            if domain in DOMAIN_OBSERVED_KEYS.get(family, {})
            else "No direct indicator count is exposed for this domain."
        ),
        "limit_reached": limit_reached,
        "scope": DOMAIN_SCOPES.get(family, {}).get(domain, "Not defined for this parser."),
        "limitations": list(dict.fromkeys(limitations)),
    }


def build_parser_coverage(
    report: dict[str, Any],
    parser_section: str | None = None,
    parser_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    section = parser_section
    if section is None:
        section = next(
            (name for name in PARSER_SECTIONS if isinstance(report.get(name), dict)),
            None,
        )
    parser = parser_report if isinstance(parser_report, dict) else report.get(section, {})
    if not isinstance(parser, dict):
        parser = {}

    family = _parser_family(section)
    raw_status = str(parser.get("status") or "unknown").strip().lower()
    file_info = report.get("file") if isinstance(report.get("file"), dict) else {}
    file_type = str(file_info.get("file_type") or "").strip().lower()
    format_recognized = bool(file_type) and not file_type.startswith("unknown")
    format_status = "complete" if format_recognized else "unknown"
    format_limitations = [] if format_recognized else [
        "The input was not identified as a supported document format."
    ]

    domains: dict[str, dict[str, Any]] = {
        "format_identification": {
            "status": format_status,
            "in_declared_scope": True,
            "inspected_count": 1 if format_recognized else 0,
            "inspected_unit": "format identification result",
            "observed_count": 1 if format_recognized else 0,
            "observed_count_semantics": "One recognized format result; this is not a content finding.",
            "limit_reached": False,
            "scope": "Content-signature and package-metadata format identification with filename-extension cross-checks where available.",
            "limitations": format_limitations,
        }
    }

    if family in DOMAIN_SCOPES:
        for domain in (
            "container_structure",
            "content_inspection",
            "embedded_object_inventory",
            "external_reference_inventory",
            "active_content_indicators",
        ):
            domains[domain] = _domain_record(family, domain, parser, raw_status)
        domains["semantic_interpretation"] = _domain_record(
            family, "semantic_interpretation", parser, raw_status
        )
    else:
        for domain in (
            "container_structure",
            "content_inspection",
            "embedded_object_inventory",
            "external_reference_inventory",
            "active_content_indicators",
            "semantic_interpretation",
        ):
            domains[domain] = {
                "status": "not_inspected",
                "in_declared_scope": domain != "semantic_interpretation",
                "inspected_count": 0,
                "inspected_unit": "units",
                "observed_count": None,
                "observed_count_semantics": "No format-specific indicator count is available.",
                "limit_reached": False,
                "scope": "No format-specific parser was selected for this domain.",
                "limitations": ["No supported format-specific inspection was performed."],
            }

    in_scope_statuses = [
        item["status"] for item in domains.values() if item["in_declared_scope"]
    ]
    if "failed" in in_scope_statuses:
        overall_status = "failed"
    elif "unavailable" in in_scope_statuses:
        overall_status = "unavailable"
    elif "unsupported" in in_scope_statuses:
        overall_status = "unsupported"
    elif "unknown" in in_scope_statuses:
        overall_status = "unknown"
    elif "partial" in in_scope_statuses or "not_inspected" in in_scope_statuses:
        overall_status = "partial"
    else:
        overall_status = "complete"

    counts = {status: sum(item["status"] == status for item in domains.values()) for status in (
        "complete", "partial", "not_inspected", "not_applicable", "failed", "unavailable", "unsupported", "unknown"
    )}

    return {
        "schema_version": 1,
        "model": "cvevident-parser-coverage",
        "parser_section": section,
        "parser_family": family,
        "parser_status": raw_status,
        "overall_status": overall_status,
        "status_counts": counts,
        "domains": domains,
        "interpretation": (
            "Coverage statuses describe completion of each declared static inspection domain. "
            "Complete does not mean semantic validation, safety, or exploitability was established."
        ),
    }
