"""Human-readable report rendering; statements remain evidence-bounded."""
from __future__ import annotations

import html
import json
from typing import Any


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
        f"- **File:** `{file_info.get('filename', 'unknown')}`",
        f"- **File type:** `{file_info.get('file_type', 'unknown')}`",
        f"- **Size:** {file_info.get('size_bytes', 'unknown')} bytes",
        f"- **SHA-256:** `{file_info.get('sha256', 'unknown')}`",
        f"- **Verdict:** **{assessment.get('verdict', 'not_assessed')}**",
        "",
        "> This report is static triage, not a malware verdict or proof of CVE exploitation.",
        "",
        "## Metrics",
        "",
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
            "remote_goto_action_count", "annotations_total", "link_annotations",
            "embedded_files_name_tree_count", "file_specifications_with_embedded_data",
            "acroform_present", "rich_media_indicators",
        )
        lines += ["", "| Structural feature | Observed value |", "|---|---:|"]
        for key in selected:
            if key in features:
                lines.append(f"| `{key}` | `{features[key]}` |")
    local = metrics.get("local_byte_entropy", {})
    lines += [
        f"- Local entropy mean / max / min: `{local.get('mean')}` / `{local.get('max')}` / `{local.get('min')}`",
        "",
        "## Evidence",
        "",
    ]
    for index, item in enumerate(report.get("evidence", []), start=1):
        details = item.get("details", {})
        lines.append(f"{index}. **{item.get('key', 'unknown')}** — `{item.get('value')}` ({item.get('severity', 'info')})")
        if details.get("description"):
            lines.append(f"   - {details['description']}")
        if details.get("interpretation"):
            lines.append(f"   - Interpretation: {details['interpretation']}")
        # Structural locations are part of the evidence provenance. They are logical
        # object-graph paths, not byte offsets, and should remain visible in reports.
        object_path = details.get("object_path")
        if isinstance(object_path, str) and object_path:
            lines.append(f"   - Object path: `{object_path}`")
        object_reference = details.get("object_reference")
        if isinstance(object_reference, str) and object_reference:
            lines.append(f"   - Object reference: `{object_reference}`")
        if details.get("path_truncated") is True:
            lines.append("   - Object path was truncated to the configured reporting limit.")
    context = report.get("target_context", {})
    lines += ["", "## Product-context CVE candidates", ""]
    lines.append(f"Target product: `{context.get('target_product') or 'not supplied'}`")
    lines.append("")
    lines.append(context.get("interpretation", "No product-context search was performed."))
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
    lines += ["", "## Warnings", ""]
    lines.extend(f"- {warning}" for warning in report.get("warnings", []))
    lines += ["", "---", "Generated by CVEvident. Candidate ranking scores are retrieval scores, not probabilities.", ""]
    return "\n".join(lines)


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
                cells = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
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
        elif line.startswith("## "):
            close_list(); rendered.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("- "):
            if list_kind != "ul":
                close_list(); rendered.append("<ul>"); list_kind = "ul"
            rendered.append(f"<li>{inline(line[2:])}</li>")
        elif re.match(r"^\d+\. ", line):
            if list_kind != "ol":
                close_list(); rendered.append("<ol>"); list_kind = "ol"
            rendered.append(f"<li>{inline(re.sub(r'^\d+\. ', '', line))}</li>")
        elif line.startswith("> "):
            close_list(); rendered.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif line.strip() == "---":
            close_list(); rendered.append("<hr>")
        else:
            close_list(); rendered.append(f"<p>{inline(line)}</p>")
        index += 1
    close_list()
    css = "body{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;line-height:1.55;color:#17202a}h1,h2{line-height:1.2}li{margin:.35rem 0}blockquote{border-left:4px solid #bbb;padding-left:1rem;color:#555}code{overflow-wrap:anywhere;background:#f4f4f4;padding:.1em .25em}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ddd;padding:.45rem;text-align:left;vertical-align:top}th{background:#f5f5f5}"
    return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CVEvident Report</title><style>" + css + "</style></head><body>" + "\n".join(rendered) + "</body></html>"


def serialize_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
