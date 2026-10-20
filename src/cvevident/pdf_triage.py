"""Conservative byte-level PDF triage. No document code is executed."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .pdf_structure import analyze_pdf_structure

# These are PDF names / lexical indicators, not signatures of maliciousness.
PDF_MARKERS: dict[bytes, tuple[str, str]] = {
    b"/JavaScript": ("pdf.javascript_name", "JavaScript name in PDF bytes"),
    b"/JS": ("pdf.js_name", "JS name in PDF bytes"),
    b"/OpenAction": ("pdf.open_action_name", "OpenAction name in PDF bytes"),
    b"/AA": ("pdf.additional_actions_name", "Additional-actions name in PDF bytes"),
    b"/Launch": ("pdf.launch_action_name", "Launch-action name in PDF bytes"),
    b"/EmbeddedFile": ("pdf.embedded_file_name", "EmbeddedFile name in PDF bytes"),
    b"/RichMedia": ("pdf.rich_media_name", "RichMedia name in PDF bytes"),
    b"/XFA": ("pdf.xfa_name", "XFA name in PDF bytes"),
    b"/AcroForm": ("pdf.acroform_name", "AcroForm name in PDF bytes"),
    b"/GoToR": ("pdf.remote_goto_name", "Remote GoTo name in PDF bytes"),
    b"/Encrypt": ("pdf.encrypt_name", "Encrypt name in PDF bytes"),
    b"/ObjStm": ("pdf.object_stream_name", "Object-stream name in PDF bytes"),
    b"/RichMediaExecute": ("pdf.rich_media_execute_name", "RichMediaExecute name in PDF bytes"),
}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8); an empty input has entropy 0."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _window_entropy(data: bytes, window_size: int = 4096) -> dict[str, float | int]:
    if not data:
        return {"window_size": window_size, "window_count": 0, "mean": 0.0, "max": 0.0, "min": 0.0}
    values = [shannon_entropy(data[i:i + window_size]) for i in range(0, len(data), window_size)]
    return {
        "window_size": window_size,
        "window_count": len(values),
        "mean": round(sum(values) / len(values), 4),
        "max": round(max(values), 4),
        "min": round(min(values), 4),
    }


def _count_pdf_name(data: bytes, name: bytes) -> int:
    # Avoid the /JS substring inside /JavaScript; PDF names end at a delimiter.
    # This is still lexical scanning and does not decode escaped PDF names.
    pattern = re.escape(name) + rb"(?=$|[\x00\x09\x0a\x0c\x0d\x20\x28\x29<>\[\]{}/%])"
    return len(re.findall(pattern, data))


def analyze_pdf(path: str | Path, max_bytes: int = 100 * 1024 * 1024) -> dict[str, Any]:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    file_path = Path(path).expanduser()
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"Input file not found or not a regular file: {file_path}")
    try:
        with file_path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise OSError(f"Could not read input file: {exc}") from exc
    if len(data) > max_bytes:
        raise ValueError(
            f"Input exceeds the configured limit ({max_bytes} bytes). Use --max-bytes to raise the limit deliberately."
        )

    header_offset = data[:1024].find(b"%PDF-")
    is_pdf = header_offset >= 0
    sha256 = hashlib.sha256(data).hexdigest()
    marker_counts = {key: _count_pdf_name(data, marker) for marker, (key, _) in PDF_MARKERS.items()}
    evidence: list[dict[str, Any]] = [
        {
            "evidence_type": "file_identity", "key": "sha256", "value": sha256,
            "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"},
        },
        {
            "evidence_type": "file_identity", "key": "file_size_bytes", "value": len(data),
            "severity": "info", "details": {"meaning": "size of bytes read"},
        },
        {
            "evidence_type": "format_check", "key": "pdf_header",
            "value": "found" if is_pdf else "not_found",
            "severity": "info" if is_pdf else "warning",
            "details": {"bytes_examined": min(len(data), 1024), "offset": header_offset if is_pdf else None},
        },
    ]
    for marker, (key, description) in PDF_MARKERS.items():
        count = marker_counts[key]
        if count:
            evidence.append({
                "evidence_type": "pdf_lexical_marker", "key": key, "value": count,
                "severity": "info",
                "details": {
                    "description": description,
                    "marker_hex": marker.hex(),
                    "interpretation": "presence is contextual only; the name can occur in benign PDFs",
                },
            })

    structural_analysis = analyze_pdf_structure(data, is_pdf)
    structural_features = structural_analysis.get("features", {})
    structural_evidence: list[dict[str, Any]] = [{
        "evidence_type": "pdf_parser",
        "key": "pdf_structure_parser_status",
        "value": structural_analysis.get("status", "unknown"),
        "severity": "warning" if structural_analysis.get("status") in {"failed", "unavailable", "partial"} else "info",
        "details": {
            "parser": structural_analysis.get("parser"),
            "parser_version": structural_analysis.get("parser_version"),
            "containers_inspected": structural_analysis.get("containers_inspected"),
            "truncated": structural_analysis.get("truncated"),
            "interpretation": "Parser status describes structural-analysis coverage, not file safety.",
        },
    }]
    if structural_analysis.get("page_count_declared") is not None:
        structural_evidence.append({
            "evidence_type": "pdf_structural_feature", "key": "pdf.page_count_declared",
            "value": structural_analysis["page_count_declared"], "severity": "info",
            "details": {"interpretation": "Declared page count from the PDF page tree; not independently validated by rendering."},
        })
    feature_meanings = {
        "catalog_open_action_present": "The catalog contains an /OpenAction entry; its meaning is contextual.",
        "catalog_additional_actions_present": "The catalog contains an /AA entry; its meaning is contextual.",
        "javascript_action_count": "Parsed action dictionaries whose /S value is /JavaScript.",
        "launch_action_count": "Parsed action dictionaries whose /S value is /Launch.",
        "uri_action_count": "Parsed action dictionaries whose /S value is /URI.",
        "remote_goto_action_count": "Parsed action dictionaries whose /S value is /GoToR.",
        "submit_form_action_count": "Parsed action dictionaries whose /S value is /SubmitForm.",
        "import_data_action_count": "Parsed action dictionaries whose /S value is /ImportData.",
        "reset_form_action_count": "Parsed action dictionaries whose /S value is /ResetForm.",
        "rendition_action_count": "Parsed action dictionaries whose /S value is /Rendition.",
        "rich_media_execute_action_count": "Parsed action dictionaries whose /S value is /RichMediaExecute.",
        "javascript_name_tree_present": "A JavaScript name-tree entry was observed in the parsed object graph.",
        "embedded_files_name_tree_count": "Parsed dictionaries containing an /EmbeddedFiles key.",
        "file_specifications_with_embedded_data": "Parsed dictionaries containing an /EF entry associated with embedded-file data.",
        "annotations_total": "Parsed dictionaries with a recognized PDF annotation subtype.",
        "link_annotations": "Parsed link annotation dictionaries; link targets are not visited or opened.",
        "acroform_present": "The catalog contains an /AcroForm entry.",
        "rich_media_indicators": "Parsed dictionaries contain /RichMedia-related entries.",
    }
    for key, meaning in feature_meanings.items():
        value = structural_features.get(key)
        if value is True or (isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0):
            structural_evidence.append({
                "evidence_type": "pdf_structural_feature", "key": f"pdf.structure.{key}",
                "value": value, "severity": "info",
                "details": {"interpretation": meaning, "context_only": True},
            })

    warnings = [
        "Static triage observations are not a malware verdict or proof of CVE exploitation.",
        "Lexical marker counts may miss escaped or compressed names; structural parsing may also be incomplete.",
        "Entropy describes byte distribution, not semantic similarity or maliciousness.",
        "The tool did not execute the file, its JavaScript, launch actions, links, or emulate a PDF reader.",
    ]
    warnings.extend(structural_analysis.get("warnings", []))
    if not is_pdf:
        warnings.insert(0, "No %PDF- header was found in the first 1024 bytes; PDF-specific markers may not be meaningful.")
    if file_path.suffix.lower() != ".pdf":
        warnings.insert(0, f"File extension is {file_path.suffix or '(none)'}, but this command performs PDF-oriented triage.")

    metrics = {
        "file_size_bytes": len(data),
        "sha256": sha256,
        "pdf_header_found": is_pdf,
        "pdf_header_offset": header_offset if is_pdf else None,
        "global_byte_entropy_bits_per_byte": round(shannon_entropy(data), 4),
        "local_byte_entropy": _window_entropy(data),
        "marker_counts": marker_counts,
    }
    return {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {
            "filename": file_path.name,
            "size_bytes": len(data),
            "sha256": sha256,
            "file_type": "pdf" if is_pdf else "unknown_or_non_pdf",
        },
        "assessment": {
            "verdict": "not_assessed",
            "reason": "Available features are triage observations only; no malware verdict or CVE attribution is made.",
        },
        "metrics": metrics,
        "structural_analysis": structural_analysis,
        "evidence": evidence + structural_evidence,
        "warnings": list(dict.fromkeys(warnings)),
    }
