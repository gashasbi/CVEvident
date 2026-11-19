"""Human-readable report rendering; statements remain evidence-bounded."""
from __future__ import annotations

import html
import json
from typing import Any


def _report_single_line(value: Any) -> str:
    """Keep source-provided values on one report line and prevent inline-code delimiter breaks."""
    return " ".join(str(value if value is not None else "").split()).replace("`", "ʼ")


def to_markdown(report: dict[str, Any]) -> str:
    file_info = report.get("file", {})
    assessment = report.get("assessment", {})
    metrics = report.get("metrics", {})
    lines = [
        "# CVEvident Analysis Report",
        "",
        f"- **Analysis ID:** {report.get('analysis_id', 'not persisted')}",
        f"- **Created:** {report.get('created_at', 'unknown')}",
        f"- **Tool version:** {report.get('tool_version', report.get('tool', 'unknown'))}",
        f"- **File:** `{_report_single_line(file_info.get('filename', 'unknown'))}`",
        f"- **File type:** `{_report_single_line(file_info.get('file_type', 'unknown'))}`",
        f"- **Size:** {file_info.get('size_bytes', 'unknown')} bytes",
        f"- **SHA-256:** `{file_info.get('sha256', 'unknown')}`",
        f"- **Verdict:** **{assessment.get('verdict', 'not_assessed')}**",
        "",
        "> This report is static triage, not a malware verdict or proof of CVE exploitation.",
        "",
        "## Metrics",
        "",
    ]
    office = report.get("office_analysis", {})
    legacy_office = report.get("legacy_office_analysis", {})
    rtf = report.get("rtf_analysis", {})
    odf = report.get("odf_analysis", {})
    non_pdf_analysis = bool(office or legacy_office or rtf or odf)
    if office:
        lines += [
            f"- ZIP entries declared: `{office.get('container_entry_count', 0)}`",
            f"- Declared uncompressed bytes: `{office.get('declared_uncompressed_bytes', 0)}`",
            f"- XML parts inspected: `{office.get('xml_parts_inspected', 0)}`",
            f"- XML bytes inspected: `{office.get('xml_bytes_inspected', 0)}`",
            "",
            "## Office package analysis",
            "",
            f"- Package status: `{office.get('status', 'unknown')}`",
            f"- Detected format: `{office.get('format_id', 'unknown')}`",
            f"- Office family: `{office.get('family', 'unknown')}`",
            f"- Main part: `{_report_single_line(office.get('main_part', 'unknown'))}`",
            f"- Macro-enabled format: `{office.get('macro_enabled_format')}`",
            f"- VBA project binary present: `{office.get('vba_project_present')}`",
            f"- Analysis truncated: `{office.get('truncated', False)}`",
            "",
            "Office package indicators are static observations, not a malware verdict. No macro or external target was executed or opened.",
        ]
        features = office.get("features", {})
        if features:
            lines += ["", "| Office feature | Observed value |", "|---|---:|"]
            for key in sorted(features):
                value = features[key]
                if value is True or (isinstance(value, int) and not isinstance(value, bool) and value > 0):
                    lines.append(f"| `{_report_single_line(key)}` | `{_report_single_line(value)}` |")
        relationships = office.get("external_relationships", [])
        if relationships:
            lines += [
                "", "### External relationships (targets not opened)", "",
                "| Source part | Relationship kind | Relationship type | Target kind | Target scheme | Target |",
                "|---|---|---|---|---|---|",
            ]
            for relation in relationships[:25]:
                cells = [
                    _report_single_line(relation.get("source_part", "")),
                    _report_single_line(relation.get("relationship_kind", "other")),
                    _report_single_line(relation.get("relationship_type", "")),
                    _report_single_line(relation.get("target_kind", "unknown")),
                    _report_single_line(relation.get("target_scheme") or "—"),
                    _report_single_line(relation.get("target", "")),
                ]
                cells = [cell.replace("|", "\\|") for cell in cells]
                lines.append("| " + " | ".join(cells) + " |")
        ole_references = office.get("ole_object_references", [])
        if ole_references:
            lines += [
                "", "### OLE object references (bounded payload signature inspection)", "",
                "| Source part | Relationship ID | ProgID | Relationship status | Embedded package part | Embedded content status | Skip reason | Embedded content kind | Embedded content signature | Bytes inspected |",
                "|---|---|---|---|---|---|---|---|---|---|",
            ]
            for reference in ole_references[:25]:
                cells = [
                    _report_single_line(reference.get("source_part", "")),
                    _report_single_line(reference.get("relationship_id", "")),
                    _report_single_line(reference.get("prog_id", "")),
                    _report_single_line(reference.get("relationship_status", "unknown")),
                    _report_single_line(reference.get("embedded_part", "")),
                    _report_single_line(reference.get("embedded_content_status", "not_inspected")),
                    _report_single_line(reference.get("embedded_content_skip_reason") or "—"),
                    _report_single_line(reference.get("embedded_content_kind") or "—"),
                    _report_single_line(reference.get("embedded_content_signature") or "—"),
                    str(reference.get("embedded_content_bytes_inspected", 0)),
                ]
                cells = [cell.replace("|", "\\|") for cell in cells]
                lines.append("| " + " | ".join(cells) + " |")
        parts = office.get("parts_inventory", [])
        if parts:
            lines += ["", "### XML parts inspected", ""]
            lines.extend(f"- `{_report_single_line(part)}`" for part in parts[:80])
        if office.get("warnings"):
            lines += ["", "### Office parser notes", ""]
            lines.extend(f"- {_report_single_line(warning)}" for warning in office["warnings"])
    elif legacy_office:
        lines += [
            f"- OLE/CFB sector size: `{legacy_office.get('sector_size')}`",
            f"- Directory entries: `{legacy_office.get('directory_entry_count', 0)}`",
            f"- Streams: `{legacy_office.get('stream_count', 0)}`",
            f"- Storages: `{legacy_office.get('storage_count', 0)}`",
            "",
            "## Legacy Office (OLE/CFB) analysis",
            "",
            f"- Parser status: `{legacy_office.get('status', 'unknown')}`",
            f"- Detected family: `{legacy_office.get('family', 'unknown')}`",
            f"- Detected format: `{legacy_office.get('format_id', 'unknown')}`",
            f"- Macro/VBA indicators present: `{legacy_office.get('vba_project_present')}`",
            f"- Encrypted Office container indicated: `{legacy_office.get('encrypted_content_present')}`",
            f"- Analysis truncated: `{legacy_office.get('truncated', False)}`",
            "",
            "Only bounded OLE/CFB header and directory metadata were inspected. Stream bodies and VBA source were not parsed or executed.",
        ]
        features = legacy_office.get("features", {})
        if features:
            lines += ["", "| Legacy Office indicator | Observed value |", "|---|---:|"]
            for key, value in sorted(features.items()):
                if value:
                    lines.append(f"| `{_report_single_line(key)}` | `{_report_single_line(value)}` |")
        inventory = legacy_office.get("directory_inventory", [])
        if inventory:
            lines += ["", "### OLE/CFB directory inventory (bounded)", "", "| Name | Type | Declared size |", "|---|---|---:|"]
            for entry in inventory[:100]:
                name = _report_single_line(entry.get("name", "")).replace("|", "\\|")
                lines.append(f"| `{name}` | `{entry.get('type', 'unknown')}` | `{entry.get('declared_size_bytes', 0)}` |")
        if legacy_office.get("warnings"):
            lines += ["", "### Legacy Office parser notes", ""]
            lines.extend(f"- {_report_single_line(warning)}" for warning in legacy_office["warnings"])
    elif rtf:
        lines += [
            f"- RTF bytes scanned: `{rtf.get('bytes_scanned', 0)}`",
            f"- Maximum group nesting: `{rtf.get('maximum_group_depth', 0)}`",
            "",
            "## RTF analysis",
            "",
            f"- Parser status: `{rtf.get('status', 'unknown')}`",
            f"- RTF header found: `{rtf.get('header_found')}`",
            f"- RTF version: `{rtf.get('rtf_version')}`",
            f"- Group balance value: `{rtf.get('group_balance')}`",
            f"- Analysis truncated: `{rtf.get('truncated', False)}`",
            "",
            "RTF control words and field instructions are lexical/context indicators. Embedded objects and field targets are not opened or executed.",
        ]
        features = rtf.get("features", {})
        if features:
            lines += ["", "| RTF indicator | Observed value |", "|---|---:|"]
            for key, value in sorted(features.items()):
                if value:
                    lines.append(f"| `{_report_single_line(key)}` | `{_report_single_line(value)}` |")
        examples = rtf.get("field_instruction_examples", [])
        if examples:
            lines += ["", "### Field-instruction text examples (not executed)", ""]
            lines.extend(f"- `{_report_single_line(example)}`" for example in examples[:10])
        if rtf.get("warnings"):
            lines += ["", "### RTF parser notes", ""]
            lines.extend(f"- {_report_single_line(warning)}" for warning in rtf["warnings"])
    elif odf:
        lines += [
            f"- ZIP entries declared: `{odf.get('container_entry_count', 0)}`",
            f"- Declared uncompressed bytes: `{odf.get('declared_uncompressed_bytes', 0)}`",
            f"- XML parts inspected: `{odf.get('xml_parts_inspected', 0)}`",
            f"- XML bytes inspected: `{odf.get('xml_bytes_inspected', 0)}`",
            "",
            "## OpenDocument package analysis",
            "",
            f"- Parser status: `{odf.get('status', 'unknown')}`",
            f"- Detected format: `{odf.get('format_id', 'unknown')}`",
            f"- Family: `{odf.get('family', 'unknown')}`",
            f"- Mimetype: `{_report_single_line(odf.get('mimetype', 'unknown'))}`",
            f"- Main part: `{_report_single_line(odf.get('main_part', 'content.xml'))}`",
            f"- Mimetype first and uncompressed: `{odf.get('mimetype_first_and_uncompressed')}`",
            f"- Analysis truncated: `{odf.get('truncated', False)}`",
            "",
            "OpenDocument scripts, macros, external references and embedded objects are contextual observations only.",
        ]
        features = odf.get("features", {})
        if features:
            lines += ["", "| OpenDocument indicator | Observed value |", "|---|---:|"]
            for key, value in sorted(features.items()):
                if value:
                    lines.append(f"| `{_report_single_line(key)}` | `{_report_single_line(value)}` |")
        refs = odf.get("external_references", [])
        if refs:
            lines += ["", "### External references (not opened/fetched)", "", "| Part | Element | Target |", "|---|---|---|"]
            for ref in refs[:25]:
                part = _report_single_line(ref.get("part", "")).replace("|", "\\|")
                element = _report_single_line(ref.get("element", "")).replace("|", "\\|")
                target = _report_single_line(ref.get("target", "")).replace("|", "\\|")
                lines.append(f"| `{part}` | `{element}` | `{target}` |")
        if odf.get("warnings"):
            lines += ["", "### OpenDocument parser notes", ""]
            lines.extend(f"- {_report_single_line(warning)}" for warning in odf["warnings"])
    else:
        lines += [
            f"- PDF header found: `{metrics.get('pdf_header_found')}`",
            f"- Global byte entropy (bits/byte): `{metrics.get('global_byte_entropy_bits_per_byte')}`",
        ]
    structural = report.get("structural_analysis", {})
    if structural:
        lines += [
            "",
            "## PDF structural analysis",
            "",
            f"- Parser status: `{structural.get('status', 'unknown')}`",
            f"- Parser/version: `{structural.get('parser', 'unknown')}` / `{structural.get('parser_version', 'unknown')}`",
            f"- Declared page count: `{structural.get('page_count_declared')}`",
            f"- Encrypted: `{structural.get('encrypted')}`",
            f"- Containers inspected: `{structural.get('containers_inspected', 0)}`",
            f"- Traversal truncated: `{structural.get('truncated', False)}`",
            "",
            "Structural indicators are contextual observations, not a malware verdict.",
        ]
        features = structural.get("features", {})
        selected = (
            "javascript_action_count", "launch_action_count", "uri_action_count",
            "remote_goto_action_count", "embedded_goto_action_count",
            "optional_content_state_action_count", "goto_3d_view_action_count",
            "annotations_total", "link_annotations", "file_attachment_annotations",
            "embedded_files_name_tree_count", "file_specifications_with_embedded_data",
            "associated_file_entries", "acroform_present", "xfa_present", "rich_media_indicators",
        )
        lines += ["", "| Structural feature | Observed value |", "|---|---:|"]
        for key in selected:
            if key in features:
                lines.append(f"| `{key}` | `{features[key]}` |")
    if not non_pdf_analysis:
        local = metrics.get("local_byte_entropy", {})
        lines += [
            f"- Local entropy mean / max / min: `{local.get('mean')}` / `{local.get('max')}` / `{local.get('min')}`",
        ]
    lines += ["", "## Evidence", ""]
    for index, item in enumerate(report.get("evidence", []), start=1):
        details = item.get("details", {})
        lines.append(
            f"{index}. **{_report_single_line(item.get('key', 'unknown'))}** — "
            f"`{_report_single_line(item.get('value'))}` "
            f"({_report_single_line(item.get('severity', 'info'))})"
        )
        traceability = details.get("traceability")
        if isinstance(traceability, dict):
            extraction_method = traceability.get("extraction_method")
            if extraction_method:
                lines.append(
                    f"   - Extraction method: `{_report_single_line(extraction_method)}`"
                )
            if "observed_value" in traceability:
                observed_text = json.dumps(
                    traceability["observed_value"], ensure_ascii=False, sort_keys=True
                )
                lines.append(
                    f"   - Traceable observed value: `{_report_single_line(observed_text)}`"
                )
            limitations = traceability.get("analysis_limitations") or []
            if limitations:
                rendered_limitations = "; ".join(
                    _report_single_line(value) for value in limitations
                )
                lines.append(f"   - Analysis limitations: {rendered_limitations}")

        if details.get("description"):
            lines.append(f"   - {_report_single_line(details['description'])}")
        if details.get("interpretation"):
            lines.append(f"   - Interpretation: {_report_single_line(details['interpretation'])}")
        # Structural locations are part of the evidence provenance. They are logical
        # object-graph paths, not byte offsets, and should remain visible in reports.
        object_path = details.get("object_path")
        if isinstance(object_path, str) and object_path:
            lines.append(f"   - Object path: `{object_path}`")
        object_reference = details.get("object_reference")
        if isinstance(object_reference, str) and object_reference:
            lines.append(f"   - Object reference: `{object_reference}`")
        evidence_id = item.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id:
            lines.append(f"   - Evidence ID: `{evidence_id}` (report-local reference)")
        evidence_class = item.get("evidence_class")
        if isinstance(evidence_class, str) and evidence_class:
            lines.append(f"   - Evidence class: `{evidence_class}`; origin: `{item.get('evidence_origin', 'unknown')}`")
        locator = item.get("source_locator")
        if isinstance(locator, dict):
            locator_kind = _report_single_line(locator.get("kind", "unknown"))
            locator_precision = _report_single_line(locator.get("precision", "unknown"))
            locator_value = None
            if locator.get("byte_offsets") is not None:
                locator_value = f"byte offsets {locator.get('byte_offsets')}"
                if locator.get("offsets_truncated"):
                    locator_value += " (additional occurrences omitted)"
            elif locator.get("object_path") or locator.get("object_reference"):
                locator_value = f"{locator.get('object_path') or '(path unavailable)'}; object {locator.get('object_reference') or '(reference unavailable)'}"
            elif locator.get("member_names"):
                locator_value = ", ".join(str(name) for name in locator.get("member_names", [])[:10])
                if locator.get("member_list_is_bounded"):
                    locator_value += ", … (member list bounded)"
            elif locator.get("package_member"):
                locator_value = str(locator.get("package_member"))
                if locator.get("element"):
                    locator_value += f"; element {locator.get('element')}"
                if locator.get("target"):
                    locator_value += f"; target {locator.get('target')}"
            elif locator.get("cve_id"):
                locator_value = f"{locator.get('cve_id')} via {locator.get('retrieval_method') or 'unknown retrieval method'}"
                if locator.get("target_product"):
                    locator_value += f"; target product: {locator.get('target_product')}"
                if locator.get("matched_criteria"):
                    locator_value += f"; matched criteria: {str(locator.get('matched_criteria'))[:300]}"
                query_terms = locator.get("matching_query_terms") or []
                if query_terms:
                    locator_value += "; query terms: " + ", ".join(str(term) for term in query_terms[:10])
            elif locator.get("sample_id"):
                locator_value = str(locator.get("sample_id"))
                if locator.get("source_name"):
                    locator_value += f"; source: {locator.get('source_name')}"
                if locator.get("label_basis"):
                    locator_value += f"; label basis: {locator.get('label_basis')}"
                if locator.get("source_url"):
                    locator_value += f"; source URL: {str(locator.get('source_url'))[:240]}"
            elif locator.get("inventory_ordinal") is not None:
                locator_value = f"inventory entry {locator.get('inventory_ordinal')}: {locator.get('name')}"
                if locator.get("entry_type"):
                    locator_value += f"; type: {locator.get('entry_type')}"
                if locator.get("declared_size_bytes") is not None:
                    locator_value += f"; declared size: {locator.get('declared_size_bytes')} bytes"
            elif locator.get("byte_range_end_exclusive") is not None:
                locator_value = f"bytes [0, {locator.get('byte_range_end_exclusive')})"
            else:
                locator_value = _report_single_line(locator.get("limitation", "No narrower location was emitted."))
            lines.append(f"   - Source locator: `{locator_kind}`; precision: `{locator_precision}`; {_report_single_line(locator_value)}")
            locator_limitation = locator.get("limitation")
            if locator_limitation:
                lines.append(f"      - Locator limitation: {_report_single_line(locator_limitation)}")
        if details.get("path_truncated") is True:
            lines.append("   - Object path was truncated to the configured reporting limit.")
    context = report.get("target_context", {})
    lines += ["", "## Product-context CVE candidates", ""]
    lines.append(
        f"Target product: `{_report_single_line(context.get('target_product') or 'not supplied')}`"
    )
    if context.get("target_vendor"):
        lines.append(f"Target vendor filter: `{_report_single_line(context.get('target_vendor'))}`")
    if context.get("target_version"):
        lines.append(f"Target version context: `{_report_single_line(context.get('target_version'))}`")
    if context.get("normalized_target_product"):
        lines.append(f"Normalized product query: `{_report_single_line(context.get('normalized_target_product'))}`")
    lines.append("")
    lines.append(
        _report_single_line(
            context.get("interpretation", "No product-context search was performed.")
        )
    )
    discovery = context.get("product_identity_discovery") or report.get("product_identity_discovery") or {}
    if discovery:
        lines.append(
            f"Product identity discovery: `{_report_single_line(discovery.get('status', 'unknown'))}`; "
            f"{_report_single_line(discovery.get('interpretation', ''))}"
        )
    retrieval = context.get("retrieval_completeness") or {}
    if retrieval:
        lines.append(
            f"Product candidate retrieval: `{_report_single_line(retrieval.get('status', 'unknown'))}`; "
            f"{_report_single_line(retrieval.get('interpretation', ''))}"
        )
    ambiguity = context.get("product_identity_ambiguity") or {}
    if ambiguity:
        lines.append("")
        lines.append(
            f"Product identity ambiguity: `{_report_single_line(ambiguity.get('status', 'unknown'))}`; "
            f"distinct matched identities: `{ambiguity.get('distinct_matched_product_identity_count', 0)}`."
        )
        if ambiguity.get("matched_product_identities"):
            labels = [
                f"{identity.get('vendor') or 'unknown-vendor'}:{identity.get('product') or 'unknown-product'}"
                for identity in ambiguity["matched_product_identities"][:20]
            ]
            lines.append("Matched identities: " + ", ".join(f"`{_report_single_line(label)}`" for label in labels))
    freshness = context.get("source_freshness", {}).get("sources", {})
    if freshness:
        lines += ["", "### Local vulnerability-data freshness", "", "Freshness measures time since successful local import, not upstream completeness.", ""]
        lines += ["| Source | Local state | Freshness | Last successful import (UTC) |", "|---|---|---|---|"]
        for source_name in ("NVD", "CISA KEV", "FIRST EPSS"):
            status = freshness.get(source_name, {})
            lines.append(
                f"| `{source_name}` | `{_report_single_line(status.get('state', 'unknown'))}` "
                f"| `{_report_single_line(status.get('freshness_class', 'unknown'))}` "
                f"| `{_report_single_line(status.get('last_success_at') or 'unknown')}` |"
            )
        annual = freshness.get("NVD", {}).get("annual_feed_coverage") or {}
        if annual:
            imported_years = ", ".join(str(year) for year in annual.get("successfully_imported_years", [])) or "none recorded"
            incomplete_years = ", ".join(str(year) for year in annual.get("failed_or_partial_years", [])) or "none recorded"
            lines.append(f"NVD annual feeds successfully imported: {imported_years}.")
            lines.append(f"NVD annual feeds failed or partial: {incomplete_years}.")
            lines.append(_report_single_line(annual.get("interpretation", "")))
    candidates = context.get("candidate_cves", [])
    if not candidates:
        lines.append("")
        lines.append("No candidate CVEs were retrieved from the local product database.")
    else:
        lines += ["", "| CVE | Product match | CVSS | KEV | EPSS |", "|---|---:|---:|:---:|---:|"]
        for item in candidates:
            lines.append(
                f"| {item.get('cve_id')} | {item.get('product_relevance_score')} | {item.get('cvss_score') or '—'} "
                f"({item.get('cvss_severity') or 'unknown'}) | {'yes' if item.get('cisa_kev') else 'no'} | {item.get('epss_score') if item.get('epss_score') is not None else '—'} |"
            )
    lines += ["", "## CVE association candidates", ""]
    association_policy = report.get("cve_association_policy")
    if association_policy:
        lines.append(str(association_policy).replace("\r", " ").replace("\n", " "))
    associations = report.get("cve_associations", [])
    if not associations:
        lines += ["", "No CVE association candidates were generated from the available sample links, product context, environment CPEs, or parser evidence rules."]
    else:
        for candidate in associations:
            cve_id = _report_single_line(candidate.get("cve_id", "unknown"))
            assessment_text = _report_single_line(candidate.get("assessment", "candidate_not_file_attribution"))
            correlation_status = _report_single_line(candidate.get("correlation_status", "UNKNOWN"))
            lines.append(f"- **{cve_id}** — association: `{assessment_text}`; correlation: `{correlation_status}`")
            interpretation = _report_single_line(candidate.get("correlation_interpretation", ""))
            if interpretation:
                lines.append(f"  - {interpretation}")
            description = _report_single_line(candidate.get("description", ""))
            if description:
                lines.append(f"  - Description: {description[:400]}{'…' if len(description) > 400 else ''}")
            if candidate.get("cvss_score") is not None:
                lines.append(
                    f"  - CVSS: {_report_single_line(candidate.get('cvss_score'))} "
                    f"({_report_single_line(candidate.get('cvss_severity') or 'unknown')})"
                )
            kev_value = candidate.get("cisa_kev")
            kev_status = "yes" if kev_value is True else "no" if kev_value is False else "unknown"
            product_basis = next(
                (basis for basis in candidate.get("association_bases", []) if basis.get("type") == "product_context"),
                {},
            )
            source_signals = product_basis.get("local_source_signals") or {}
            kev_signal = source_signals.get("CISA KEV", {})
            epss_signal = source_signals.get("FIRST EPSS", {})
            if kev_signal.get("state"):
                kev_status = str(kev_signal["state"])
            epss_text = (
                str(candidate.get("epss_score"))
                if candidate.get("epss_score") is not None else str(epss_signal.get("state", "unknown"))
            )
            lines.append(f"  - CISA KEV: {kev_status}; EPSS score: {_report_single_line(epss_text)}")
            if candidate.get("published") or candidate.get("modified"):
                lines.append(
                    f"  - NVD published/modified: `{_report_single_line(candidate.get('published') or 'unknown')}` / "
                    f"`{_report_single_line(candidate.get('modified') or 'unknown')}`"
                )
            if epss_signal.get("percentile") is not None:
                lines.append(f"  - EPSS percentile: `{_report_single_line(epss_signal.get('percentile'))}`")
            for basis in candidate.get("association_bases", []):
                basis_type = basis.get("type")
                if basis_type == "exact_sha256_sample_match":
                    lines.append(
                        "  - Basis: exact SHA-256 match to registered sample "
                        f"`{_report_single_line(basis.get('sample_id', 'unknown'))}`."
                    )
                    lines.append(
                        "    - Sample label/confidence: "
                        f"{_report_single_line(basis.get('sample_label', 'unknown'))} / "
                        f"{_report_single_line(basis.get('sample_confidence', 'unknown'))}; "
                        f"CVE-link confidence: {_report_single_line(basis.get('link_confidence', 'unknown'))}; "
                        f"link verified: {'yes' if basis.get('link_verified') else 'no'}."
                    )
                    if basis.get("link_association_type"):
                        lines.append(f"    - Link type: {_report_single_line(basis['link_association_type'])}.")
                    if basis.get("link_evidence_basis"):
                        lines.append(f"    - Link evidence basis: {_report_single_line(basis['link_evidence_basis'])}")
                    if basis.get("sample_source_name"):
                        lines.append(f"    - Sample source: {_report_single_line(basis['sample_source_name'])}")
                    if basis.get("link_source_url") or basis.get("sample_source_url"):
                        source_url = basis.get("link_source_url") or basis.get("sample_source_url")
                        lines.append(f"    - Source URL: {_report_single_line(source_url)}")
                elif basis_type == "product_context":
                    lines.append(
                        "  - Basis: product context; target product "
                        f"`{_report_single_line(basis.get('target_product') or 'unspecified')}`; matched "
                        f"{_report_single_line(basis.get('matched_vendor') or 'unknown')}:"
                        f"{_report_single_line(basis.get('matched_product') or 'unknown')}; "
                        f"lexical retrieval score {_report_single_line(basis.get('product_relevance_score'))} "
                        "(not a probability)."
                    )
                    if basis.get("matched_criteria"):
                        lines.append(f"    - Matched CPE: `{_report_single_line(basis['matched_criteria'])}`")
                    if basis.get("name_match_class"):
                        lines.append(f"    - Name-match class: `{_report_single_line(basis.get('name_match_class'))}`")
                    if basis.get("candidate_relevance"):
                        lines.append(f"    - Candidate relevance: `{_report_single_line(basis.get('candidate_relevance'))}`")
                    version_context = basis.get("version_context") or {}
                    if version_context:
                        lines.append(
                            f"    - Version context: `{_report_single_line(version_context.get('status', 'unknown'))}` "
                            f"via `{_report_single_line(version_context.get('comparison_method', 'unknown'))}`"
                        )
                        lines.append(f"      - {_report_single_line(version_context.get('interpretation', 'No version interpretation available.'))}")
                    if basis.get("query_normalization"):
                        normalized_query = basis["query_normalization"].get("normalized_product_query")
                        query_terms = basis["query_normalization"].get("query_terms") or []
                        lines.append(
                            f"    - Normalized query: `{_report_single_line(normalized_query or 'unknown')}`; "
                            f"matched terms: `{_report_single_line(', '.join(str(term) for term in basis.get('matching_query_terms', []) or []))}`"
                        )
                    source_signals = basis.get("local_source_signals") or {}
                    for source_name in ("NVD", "CISA KEV", "FIRST EPSS"):
                        signal = source_signals.get(source_name) or {}
                        if signal:
                            state = signal.get("state", signal.get("freshness_class", "unknown"))
                            lines.append(f"    - {source_name} local signal: `{_report_single_line(state)}`")
                if basis.get("interpretation"):
                    lines.append(f"    - Interpretation: {_report_single_line(basis['interpretation'])}")
    lines += ["", "Association ordering is for review only; it is not a calibrated probability or proof of exploitability."]
    parser_coverage = (report.get("analysis_coverage") or {}).get("parser_coverage") or {}
    if parser_coverage:
        lines += ["", "## Parser coverage", ""]
        lines.append(
            f"- Parser: `{_report_single_line(parser_coverage.get('parser_section') or 'unknown')}`; "
            f"family: `{_report_single_line(parser_coverage.get('parser_family') or 'unknown')}`; "
            f"overall coverage: `{_report_single_line(parser_coverage.get('overall_status') or 'unknown')}`."
        )
        lines += ["", "| Domain | Status | Inspected | Observed | Limit reached |", "|---|---|---:|---:|---|"]
        coverage_notes: list[str] = []
        for domain, details in (parser_coverage.get("domains") or {}).items():
            inspected = _report_single_line(
                f"{details.get('inspected_count', 0)} {details.get('inspected_unit', 'units')}"
            )
            observed = details.get("observed_count")
            observed_text = "not reported" if observed is None else str(observed)
            lines.append(
                f"| `{_report_single_line(domain)}` | "
                f"`{_report_single_line(details.get('status') or 'unknown')}` | "
                f"{inspected} | {_report_single_line(observed_text)} | "
                f"{str(bool(details.get('limit_reached'))).lower()} |"
            )
            for limitation in details.get("limitations", []) or []:
                coverage_notes.append(
                    f"- `{_report_single_line(domain)}`: {_report_single_line(limitation)}"
                )
        if coverage_notes:
            lines += ["", *coverage_notes]
        lines.append(
            "Coverage describes completion within each declared static inspection scope; "
            "it is not a safety or exploitability determination."
        )

    feature_assessments = (report.get("analysis_coverage") or {}).get(
        "feature_assessments", []
    )
    if feature_assessments:
        lines += ["", "## Feature assessment", ""]
        for assessment in feature_assessments:
            section = _report_single_line(assessment.get("parser_section", "unknown"))
            feature = _report_single_line(assessment.get("feature", "unknown"))
            status = _report_single_line(assessment.get("status", "not_assessed"))
            method = _report_single_line(assessment.get("extraction_method", "unknown"))
            observed_text = _report_single_line(
                json.dumps(assessment.get("observed_value"), ensure_ascii=False, sort_keys=True)
            )
            scope = assessment.get("inspected_scope") or {}
            scope_text = _report_single_line(
                f"{scope.get('count', 0)} {scope.get('unit', 'units')}"
            )
            lines.append(
                f"- `{section}.{feature}` — status: `{status}`; "
                f"observed value: `{observed_text}`; method: `{method}`; "
                f"inspected scope: `{scope_text}`."
            )
            for limitation in assessment.get("analysis_limitations", []) or []:
                lines.append(f"  - Limitation: {_report_single_line(limitation)}")

    environment_context = report.get("environment_context") or {}
    environment_cpes = environment_context.get("environment_cpes", []) or []
    lines += ["", "## Environment CPE applicability", ""]
    if not environment_cpes:
        lines.append("No environment CPE was supplied; platform applicability remains unknown.")
    else:
        lines.extend(f"- `{_report_single_line(value)}`" for value in environment_cpes)
        retrieval = environment_context.get("retrieval_completeness") or {}
        if retrieval:
            lines.append(
                f"Candidate retrieval: `{_report_single_line(retrieval.get('status', 'unknown'))}`; "
                f"{_report_single_line(retrieval.get('interpretation', ''))}"
            )
        if environment_context.get("invalid_environment_cpes"):
            lines.append("Invalid CPE values: " + ", ".join(
                f"`{_report_single_line(value)}`" for value in environment_context["invalid_environment_cpes"]
            ))
        for candidate in environment_context.get("candidate_cves", []) or []:
            applicability = candidate.get("applicability") or {}
            lines.append(
                f"- **{_report_single_line(candidate.get('cve_id'))}** — "
                f"`{_report_single_line(applicability.get('status', 'unknown'))}`: "
                f"{_report_single_line(applicability.get('interpretation', ''))}"
            )

    correlation = report.get("evidence_correlation") or {}
    lines += ["", "## Source-backed parser evidence correlation", ""]
    lines.append(_report_single_line(correlation.get("interpretation", "No evidence-rule evaluation was available.")))
    rule_results = correlation.get("cve_results", []) or []
    if not rule_results:
        lines.append("No imported evidence rules applied to this parser family.")
    else:
        for result in rule_results:
            lines.append(
                f"- **{_report_single_line(result.get('cve_id'))}** — "
                f"`{_report_single_line(result.get('status', 'UNKNOWN'))}` "
                f"(validation: `{_report_single_line(result.get('validation_status', 'not_assessed'))}`); "
                f"{len(result.get('matched_rules', []) or [])} matched rule(s), "
                f"{len(result.get('unmatched_rules', []) or [])} unmatched rule(s)."
            )
            for group in result.get("rule_groups", []) or []:
                lines.append(
                    f"  - Rule group `{_report_single_line(group.get('group_id') or 'independent-rule')}` "
                    f"(`{_report_single_line(group.get('operator', 'OR'))}`) — "
                    f"`{_report_single_line(group.get('status', 'UNKNOWN'))}`; "
                    f"{group.get('matched_rule_count', 0)}/{group.get('member_count', 0)} member(s) matched."
                )
            for rule in result.get("matched_rules", []) or []:
                lines.append(
                    f"  - Rule `{_report_single_line(rule.get('rule_id'))}` matched "
                    f"evidence `{_report_single_line(rule.get('evidence_id') or 'unlinked')}`; "
                    f"source: {_report_single_line(rule.get('source_name'))}; "
                    f"confidence: `{_report_single_line(rule.get('confidence'))}`; "
                    f"verified: `{bool(rule.get('verified'))}`."
                )
                if rule.get("source_url"):
                    lines.append(f"  Source URL: `{_report_single_line(rule.get('source_url'))}`")
                if rule.get("evidence_basis"):
                    lines.append(f"  Evidence basis: {_report_single_line(rule.get('evidence_basis'))}")

    lines += ["", "## Warnings", ""]
    lines.extend(
        f"- {_report_single_line(warning)}"
        for warning in report.get("warnings", [])
    )
    lines += ["", "---", "Generated by CVEvident. Candidate ranking scores are retrieval scores, not probabilities.", ""]
    return "\n".join(lines)


def _split_markdown_table_row(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]

    cells: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == chr(92) and index + 1 < len(text) and text[index + 1] == "|":
            current.append("|")
            index += 2
            continue
        if char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    cells.append("".join(current).strip())
    return cells


def to_html(report: dict[str, Any]) -> str:
    """Render a self-contained, escaped HTML report without a Markdown dependency."""
    import re

    markdown = to_markdown(report)
    lines = markdown.splitlines()
    rendered: list[str] = []
    list_kind: str | None = None

    def close_list() -> None:
        nonlocal list_kind
        if list_kind:
            rendered.append(f"</{list_kind}>")
            list_kind = None

    def inline(text: str) -> str:
        escaped = html.escape(text)
        escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
        escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
        escaped = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", escaped)
        return escaped

    index = 0
    while index < len(lines):
        line = lines[index].rstrip()
        if not line.strip():
            close_list()
            index += 1
            continue
        if line.startswith("|"):
            close_list()
            table_rows: list[list[str]] = []
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                cells = _split_markdown_table_row(lines[index])
                if not cells or all(re.fullmatch(r"[:\- ]+", cell or " ") for cell in cells):
                    index += 1
                    continue
                table_rows.append(cells)
                index += 1
            if table_rows:
                rendered.append("<table><thead><tr>" + "".join(f"<th>{inline(cell)}</th>" for cell in table_rows[0]) + "</tr></thead><tbody>")
                for row in table_rows[1:]:
                    rendered.append("<tr>" + "".join(f"<td>{inline(cell)}</td>" for cell in row) + "</tr>")
                rendered.append("</tbody></table>")
            continue
        if line.startswith("# "):
            close_list(); rendered.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("### "):
            close_list(); rendered.append(f"<h3>{inline(line[4:])}</h3>")
        elif line.startswith("## "):
            close_list(); rendered.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("- "):
            if list_kind != "ul":
                close_list(); rendered.append("<ul>"); list_kind = "ul"
            rendered.append(f"<li>{inline(line[2:])}</li>")
        elif re.match(r"^\d+\. ", line):
            if list_kind != "ol":
                close_list(); rendered.append("<ol>"); list_kind = "ol"
            item_text = re.sub(r"^\d+\. ", "", line)
            rendered.append(f"<li>{inline(item_text)}</li>")
        elif line.startswith("> "):
            close_list(); rendered.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif line.strip() == "---":
            close_list(); rendered.append("<hr>")
        else:
            close_list(); rendered.append(f"<p>{inline(line)}</p>")
        index += 1
    close_list()
    css = "body{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;line-height:1.55;color:#17202a}h1,h2,h3{line-height:1.2}li{margin:.35rem 0}blockquote{border-left:4px solid #bbb;padding-left:1rem;color:#555}code{overflow-wrap:anywhere;background:#f4f4f4;padding:.1em .25em}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ddd;padding:.45rem;text-align:left;vertical-align:top}th{background:#f5f5f5}"
    return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CVEvident Report</title><style>" + css + "</style></head><body>" + "\n".join(rendered) + "</body></html>"


def serialize_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
