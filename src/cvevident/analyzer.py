"""Coordinates static file triage, contextual CVE retrieval, and persistence."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .db import connect
from .evidence_engine import build_cve_associations, build_product_context, evidence_summary
from .evidence_trace import append_product_context_evidence, append_reported_source_evidence, finalize_evidence_traceability
from .pdf_triage import analyze_pdf
from .office_triage import LEGACY_OFFICE_EXTENSIONS, OFFICE_EXTENSIONS, analyze_office
from .legacy_office_triage import OLE_SIGNATURE, analyze_legacy_office
from .odf_triage import ODF_EXTENSIONS, analyze_opendocument
from .rtf_triage import RTF_EXTENSIONS, analyze_rtf, has_rtf_signature
from .store import lookup_reference_samples


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def analyze_file(path: str | Path, db_path: str | Path | None = None,
                 target_product: str | None = None, max_bytes: int = 100 * 1024 * 1024,
                 candidate_limit: int = 10, target_vendor: str | None = None,
                 target_version: str | None = None) -> dict[str, Any]:
    input_path = Path(path).expanduser()
    suffix = input_path.suffix.lower()
    try:
        with input_path.open("rb") as handle:
            prefix = handle.read(1024)
    except OSError:
        # Let the selected analyzer provide the established missing/unreadable-file error.
        prefix = b""

    # Select a parser using content signatures first and suffixes only as a fallback.
    # Every format-specific parser remains static and bounded; none executes content.
    is_zip = prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    if b"%PDF-" in prefix[:1024]:
        report = analyze_pdf(input_path, max_bytes=max_bytes)
    elif prefix.startswith(OLE_SIGNATURE):
        report = analyze_legacy_office(str(input_path), max_bytes=max_bytes)
    elif has_rtf_signature(prefix):
        report = analyze_rtf(str(input_path), max_bytes=max_bytes)
    elif is_zip:
        report = analyze_office(str(input_path), max_bytes=max_bytes)
        # OpenDocument is ZIP-based but uses a mimetype member instead of the OOXML
        # [Content_Types].xml manifest. An unsupported OOXML probe can fall back to ODF;
        # a corrupt OOXML package (status=failed) is not silently reinterpreted.
        office_analysis = report.get("office_analysis", {})
        office_status = office_analysis.get("status")
        office_container_open_failed = office_status == "failed" and any(
            "Office package container could not be opened" in warning
            for warning in office_analysis.get("warnings", [])
        )
        # Unsupported ZIP packages may be ODF. Also let a malformed ZIP with an
        # explicit ODF extension receive an ODF failure report; do not generally
        # reinterpret failed OOXML manifests or relationships as OpenDocument.
        should_try_odf = office_status == "unsupported" or (
            suffix in ODF_EXTENSIONS and office_container_open_failed
        )
        if should_try_odf:
            odf_report = analyze_opendocument(str(input_path), max_bytes=max_bytes)
            if odf_report.get("odf_analysis", {}).get("status") != "unsupported":
                report = odf_report
    elif suffix in RTF_EXTENSIONS:
        report = analyze_rtf(str(input_path), max_bytes=max_bytes)
    elif suffix in ODF_EXTENSIONS:
        report = analyze_opendocument(str(input_path), max_bytes=max_bytes)
    elif suffix in LEGACY_OFFICE_EXTENSIONS:
        report = analyze_legacy_office(str(input_path), max_bytes=max_bytes)
    elif suffix in OFFICE_EXTENSIONS:
        report = analyze_office(str(input_path), max_bytes=max_bytes)
    else:
        # Preserve the previous behavior for unknown/non-document inputs. The PDF
        # analyzer will identify them as unknown_or_non_pdf and keeps legacy CLI stable.
        report = analyze_pdf(input_path, max_bytes=max_bytes)

    report["tool_version"] = __version__
    report["created_at"] = _now()
    if report.get("office_analysis") is not None:
        report["scope"] = {
            "implemented": [
                "SHA-256 and bounded input read", "OOXML content-type-based format identification",
                "bounded ZIP member inventory", "bounded XML and package relationship inspection",
                "VBA/ActiveX/embedded-object/external-link structural indicators",
                "Office formula/field/link indicators when present in inspected XML parts",
            ],
            "not_implemented": [
                "legacy binary OLE/CFB stream-body parsing", "VBA decompilation or execution",
                "full semantic Word/Excel/PowerPoint parsing", "opening/fetching external targets",
                "embedded-object extraction or execution", "dynamic analysis", "exploit detection",
                "definitive CVE attribution",
            ],
        }
    elif report.get("legacy_office_analysis") is not None:
        report["scope"] = {
            "implemented": ["SHA-256 and bounded input read", "OLE/CFB header and FAT/directory metadata inspection", "legacy Office family indicators from directory stream names", "macro/embedded-object/external-link name indicators"],
            "not_implemented": ["interpreting document stream bodies", "VBA source extraction/decompilation/execution", "full semantic Word/Excel/PowerPoint parsing", "embedded-object extraction", "dynamic analysis", "exploit detection", "definitive CVE attribution"],
        }
    elif report.get("rtf_analysis") is not None:
        report["scope"] = {
            "implemented": ["SHA-256 and bounded input read", "bounded RTF control-word/group scan", "field instruction and external-target string indicators", "bounded binary payload skipping"],
            "not_implemented": ["full RTF semantic rendering", "executing field instructions", "opening external targets", "decoding/interpreting embedded OLE payloads", "dynamic analysis", "exploit detection", "definitive CVE attribution"],
        }
    elif report.get("odf_analysis") is not None:
        report["scope"] = {
            "implemented": ["SHA-256 and bounded input read", "ODF mimetype-based format identification", "bounded ZIP package inventory", "bounded XML inspection", "script/macro/embedded-object/external-reference indicators"],
            "not_implemented": ["full semantic Writer/Calc/Impress parsing", "macro/script execution", "opening/fetching external targets", "embedded-object extraction", "dynamic analysis", "exploit detection", "definitive CVE attribution"],
        }
    else:
        report["scope"] = {
            "implemented": ["sha256", "PDF header check", "byte entropy", "local entropy", "PDF-name lexical counts", "bounded pypdf object-graph inspection", "PDF action/annotation/form/embedded-file structural indicators"],
            "not_implemented": ["complete semantic PDF validation", "arbitrary stream-content extraction", "dynamic analysis", "exploit detection", "definitive CVE attribution"],
        }
    report["reference_sample_matches"] = lookup_reference_samples(report["file"]["sha256"], db_path)
    for sample in report["reference_sample_matches"]:
        report["evidence"].append({
            "evidence_type": "reference_sample_match",
            "key": sample["sample_id"],
            "value": "exact_sha256_match",
            "severity": "info",
            "details": {
                "label": sample["label"],
                "confidence": sample["confidence"],
                "source_name": sample["source_name"],
                "source_url": sample["source_url"],
                "label_basis": sample["label_basis"],
                "linked_cves": sample["cve_links"],
                "interpretation": sample["interpretation"],
            },
        })
    report["target_context"] = build_product_context(
        target_product, str(db_path) if db_path else None, candidate_limit,
        target_vendor=target_vendor, target_version=target_version,
    )
    append_product_context_evidence(report)
    append_reported_source_evidence(report)
    finalize_evidence_traceability(report)
    report["cve_associations"] = build_cve_associations(
        report["reference_sample_matches"], report["target_context"]
    )
    report["cve_association_policy"] = (
        "Candidate relations are separated by basis. Exact SHA-256 matches identify registered sample bytes; "
        "linked CVEs retain the sample metadata's provenance and verification status. Product-context matches "
        "are lexical retrieval results only. None of these relations alone proves exploitability."
    )
    report["evidence_summary"] = evidence_summary(report["evidence"])
    # Store full report context as well as normalized evidence rows. This supports later report replay.
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO analysis_runs(filename,sha256,file_type,size_bytes,verdict,target_product,created_at,summary_json)
               VALUES(?,?,?,?,?,?,?,?)""",
            (report["file"]["filename"], report["file"]["sha256"], report["file"]["file_type"],
             report["file"]["size_bytes"], report["assessment"]["verdict"], target_product,
             report["created_at"], json.dumps(report, ensure_ascii=False, separators=(",", ":"))),
        )
        analysis_id = int(cur.lastrowid)
        for item in report["evidence"]:
            conn.execute(
                """INSERT INTO evidence(analysis_id,evidence_type,evidence_key,value_text,severity,details_json)
                   VALUES(?,?,?,?,?,?)""",
                (analysis_id, item["evidence_type"], item["key"], json.dumps(item["value"], ensure_ascii=False),
                 item.get("severity", "info"), json.dumps(item.get("details", {}), ensure_ascii=False)),
            )
        for rank, candidate in enumerate(report["cve_associations"], start=1):
            bases = candidate["association_bases"]
            has_exact_sample_match = any(
                basis["type"] == "exact_sha256_sample_match" for basis in bases
            )
            product_scores = [
                float(basis.get("product_relevance_score") or 0.0)
                for basis in bases if basis["type"] == "product_context"
            ]
            score = 100.0 if has_exact_sample_match else max(product_scores, default=0.0)
            score_semantics = (
                "exact_sha256_sample_retrieval_score_not_cve_link_confidence"
                if has_exact_sample_match
                else "lexical_product_retrieval_score_not_probability"
            )
            conn.execute(
                """INSERT OR IGNORE INTO candidate_associations(analysis_id,cve_id,rank,score,assessment,rationale_json)
                   VALUES(?,?,?,?,?,?)""",
                (analysis_id, candidate["cve_id"], rank, score, candidate["assessment"],
                 json.dumps({
                     "association_basis_types": candidate["association_basis_types"],
                     "association_bases": bases,
                     "score_semantics": score_semantics,
                     "score_is_probability": False,
                 }, ensure_ascii=False)),
            )
    report["analysis_id"] = analysis_id
    return report
