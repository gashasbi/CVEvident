"""Bounded, static triage for OpenDocument text, spreadsheet and presentation packages."""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from collections import Counter
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree

from .file_input import read_file
from .archive_limits import bounded_zip_data, ensure_zip_entry_limit
from .office_triage import (
    MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO, MAX_PART_EXAMPLES,
    MAX_TOTAL_UNCOMPRESSED_BYTES, MAX_TOTAL_XML_BYTES, MAX_XML_PART_BYTES,
    MAX_XML_PARTS, _is_unsafe_member_name, _local_name, _parse_xml, _safe_text,
)

ODF_EXTENSIONS: dict[str, str] = {
    ".odt": "text", ".ott": "text",
    ".ods": "spreadsheet", ".ots": "spreadsheet",
    ".odp": "presentation", ".otp": "presentation",
}
ODF_MIME_TYPES: dict[str, tuple[str, str]] = {
    "application/vnd.oasis.opendocument.text": ("odt", "text"),
    "application/vnd.oasis.opendocument.text-template": ("ott", "text"),
    "application/vnd.oasis.opendocument.spreadsheet": ("ods", "spreadsheet"),
    "application/vnd.oasis.opendocument.spreadsheet-template": ("ots", "spreadsheet"),
    "application/vnd.oasis.opendocument.presentation": ("odp", "presentation"),
    "application/vnd.oasis.opendocument.presentation-template": ("otp", "presentation"),
}
MAX_EXTERNAL_EXAMPLES = 25
_EXTERNAL_FORMULA = re.compile(r"(?i)(?:WEBSERVICE|DDE|HYPERLINK|COM\.MICROSOFT\.WEBSERVICE|RTD)\s*\(")
_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)


def is_opendocument_package(data: bytes) -> bool:
    """Return True only when a ZIP has a recognized ODF mimetype part."""
    try:
        ensure_zip_entry_limit(data, MAX_ARCHIVE_ENTRIES)
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if not infos or infos[0].filename != "mimetype":
                # The package may still be malformed ODF, but do not classify it based
                # only on a later member named mimetype.
                return False
            info = infos[0]
            if info.file_size > 256 or info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 0x1:
                return False
            with archive.open(info, "r") as stream:
                mimetype_data = stream.read(257)
            if len(mimetype_data) > 256:
                return False
            return mimetype_data.decode("ascii", errors="strict").strip() in ODF_MIME_TYPES
    except (zipfile.BadZipFile, OSError, ValueError, UnicodeDecodeError, RuntimeError, NotImplementedError, zlib.error, EOFError):
        return False


def _base_report(file_input: Any, status: str, message: str, file_type: str = "unknown_or_non_odf") -> dict[str, Any]:
    return {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                 "sha256": file_input.sha256, "file_type": file_type},
        "assessment": {"verdict": "not_assessed",
                       "reason": "OpenDocument package observations are static context only; no document code or external resources are executed or fetched."},
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256},
        "odf_analysis": {"status": status, "family": None, "format_id": None,
                         "mimetype": None, "main_part": "content.xml", "mimetype_first_and_uncompressed": None,
                         "container_entry_count": 0, "declared_uncompressed_bytes": 0,
                         "xml_parts_inspected": 0, "xml_bytes_inspected": 0, "truncated": False,
                         "features": {}, "external_references": [], "parts_inventory": [], "warnings": [message]},
        "evidence": [
            {"evidence_type": "file_identity", "key": "sha256", "value": file_input.sha256,
             "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"}},
            {"evidence_type": "file_identity", "key": "file_size_bytes", "value": file_input.size_bytes,
             "severity": "info", "details": {"meaning": "input bytes read within configured limit"}},
            {"evidence_type": "odf_package_status", "key": "odf.package_status", "value": status,
             "severity": "warning", "details": {"interpretation": message}},
        ],
        "warnings": [message, "OpenDocument indicators are static observations, not a malware verdict. Scripts, macros, links and embedded objects are not executed, opened, extracted or fetched."],
    }


def _is_external_target(value: str) -> bool:
    target = value.strip()
    if not target or target.startswith(("#", "./", "../")):
        return False
    parsed = urlsplit(target)
    return bool(parsed.scheme or parsed.netloc or target.startswith("//"))


def analyze_opendocument(path: str, max_bytes: int = 100 * 1024 * 1024,
                         *, max_archive_entries: int = MAX_ARCHIVE_ENTRIES,
                         max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
                         max_xml_part_bytes: int = MAX_XML_PART_BYTES,
                         max_total_xml_bytes: int = MAX_TOTAL_XML_BYTES,
                         max_xml_parts: int = MAX_XML_PARTS) -> dict[str, Any]:
    """Inspect ODF package metadata and selected XML under strict size/count caps."""
    if min(max_archive_entries, max_total_uncompressed_bytes, max_xml_part_bytes,
           max_total_xml_bytes, max_xml_parts) < 1:
        raise ValueError("OpenDocument analysis limits must be positive")
    file_input = read_file(path, max_bytes=max_bytes)
    data = file_input.data
    suffix = file_input.path.suffix.lower()
    try:
        bounded_data, entry_count, declared_bytes, entry_limit_reached = bounded_zip_data(
            data, max_archive_entries
        )
        archive = zipfile.ZipFile(io.BytesIO(bounded_data), "r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        message = f"OpenDocument ZIP package could not be opened: {_safe_text(exc)}"
        return _base_report(file_input, "failed" if suffix in ODF_EXTENSIONS else "unsupported", message)

    warnings: list[str] = []
    partial = False
    with archive:
        all_infos = archive.infolist()
        if entry_limit_reached:
            warnings.append(f"Package has {entry_count} entries; only the first {max_archive_entries} were considered.")
            partial = True
        if declared_bytes > max_total_uncompressed_bytes:
            warnings.append("Declared uncompressed package size exceeds the configured analysis budget.")
            partial = True

        name_counts = Counter(info.filename for info in all_infos)
        duplicate_names = {name for name, count in name_counts.items() if count > 1}
        if duplicate_names:
            warnings.append(f"Package contains {len(duplicate_names)} duplicate member name(s); ambiguous members were not parsed.")
            partial = True
        unsafe_names = {info.filename for info in all_infos if _is_unsafe_member_name(info.filename)}
        if unsafe_names:
            warnings.append(f"Package contains {len(unsafe_names)} absolute or traversal-like member name(s); no member was extracted.")
            partial = True
        encrypted_names = {info.filename for info in all_infos if info.flag_bits & 0x1}
        if encrypted_names:
            warnings.append(f"Package contains {len(encrypted_names)} encrypted member(s); encrypted content was not read.")
            partial = True

        usable = [i for i in all_infos if not i.is_dir() and i.filename not in duplicate_names
                  and i.filename not in unsafe_names and i.filename not in encrypted_names]
        by_name = {i.filename: i for i in usable}
        mime_info = by_name.get("mimetype")
        if mime_info is None:
            message = "ZIP container does not contain an accessible OpenDocument mimetype member."
            report = _base_report(file_input, "unsupported", message)
            report["odf_analysis"].update({"container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_bytes, "truncated": partial,
                "warnings": warnings + [message]})
            report["warnings"].extend(warnings)
            return report

        mimetype_first = bool(all_infos and all_infos[0].filename == "mimetype" and mime_info.compress_type == zipfile.ZIP_STORED)
        if not mimetype_first:
            warnings.append("ODF package does not place an uncompressed mimetype member first as expected by the package convention.")
            partial = True
        try:
            if mime_info.file_size > 256 or (mime_info.compress_size and mime_info.file_size / mime_info.compress_size > MAX_COMPRESSION_RATIO):
                raise ValueError("ODF mimetype member exceeds size or compression-ratio limits")
            with archive.open(mime_info, "r") as stream:
                mimetype_data = stream.read(257)
            if len(mimetype_data) > 256:
                raise ValueError("ODF mimetype member exceeds the 256-byte read limit")
            mimetype = mimetype_data.decode("ascii", errors="strict").strip()
        except (ValueError, UnicodeDecodeError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError) as exc:
            message = f"ODF mimetype member is invalid or unreadable: {_safe_text(exc)}"
            report = _base_report(file_input, "failed", message)
            report["odf_analysis"].update({"container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_bytes, "truncated": True,
                "warnings": warnings + [message]})
            report["warnings"].extend(warnings)
            return report

        mime_record = ODF_MIME_TYPES.get(mimetype)
        if not mime_record:
            message = "ZIP mimetype does not identify a supported OpenDocument text, spreadsheet or presentation package."
            report = _base_report(file_input, "unsupported", message)
            report["odf_analysis"].update({"mimetype": _safe_text(mimetype),
                "container_entry_count": entry_count, "declared_uncompressed_bytes": declared_bytes,
                "mimetype_first_and_uncompressed": mimetype_first, "truncated": partial,
                "warnings": warnings + [message]})
            report["warnings"].extend(warnings)
            return report

        format_id, family = mime_record
        extension_matches = suffix == "." + format_id or (format_id == "ott" and suffix == ".ott") or (format_id == "ots" and suffix == ".ots") or (format_id == "otp" and suffix == ".otp")
        if not extension_matches:
            warnings.append(f"Filename extension {suffix or '(none)'} does not match detected OpenDocument format {format_id}.")
            partial = True

        selected_xml = [name for name in (
            "content.xml", "styles.xml", "settings.xml", "meta.xml", "META-INF/manifest.xml",
            "META-INF/documentsignatures.xml", "META-INF/macrosignatures.xml",
        ) if name in by_name]
        xml_bytes_total = 0
        inspected: list[str] = []
        feature_counts: Counter[str] = Counter()
        external_refs: list[dict[str, str]] = []
        macro_members = [n for n in by_name if n.casefold().startswith(("basic/", "scripts/"))]
        embedded_members = [n for n in by_name if n.casefold().startswith(("objects/", "objectreplacements/"))]
        if macro_members:
            feature_counts["script_or_basic_member_count"] = len(macro_members)
        if embedded_members:
            feature_counts["embedded_object_member_count"] = len(embedded_members)
        if "META-INF/documentsignatures.xml" in by_name or "META-INF/macrosignatures.xml" in by_name:
            feature_counts["digital_signature_part_present"] = 1

        for name in selected_xml[:max_xml_parts]:
            info = by_name[name]
            if info.file_size > max_xml_part_bytes:
                warnings.append(f"XML part {name} exceeds the per-part size limit and was skipped.")
                partial = True
                continue
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                warnings.append(f"XML part {name} exceeds the compression-ratio limit and was skipped.")
                partial = True
                continue
            if xml_bytes_total + info.file_size > max_total_xml_bytes:
                warnings.append("Total XML inspection byte limit reached; remaining selected XML parts were skipped.")
                partial = True
                break
            remaining_xml_budget = max_total_xml_bytes - xml_bytes_total
            read_limit = min(max_xml_part_bytes, remaining_xml_budget)
            try:
                # Never decompress an XML member without a read bound. Read one
                # extra byte only to detect a violated per-part or total budget.
                with archive.open(info, "r") as stream:
                    xml_data = stream.read(read_limit + 1)
                if len(xml_data) > read_limit:
                    if remaining_xml_budget <= max_xml_part_bytes:
                        warnings.append(
                            f"Total XML inspection byte limit reached while reading {name}; the part and remaining selected XML were skipped."
                        )
                        partial = True
                        break
                    warnings.append(f"XML part {name} expanded beyond the per-part read limit and was skipped.")
                    partial = True
                    continue
                # Count bytes supplied to the XML parser even if parsing the
                # document itself fails, so malformed XML cannot reset the budget.
                xml_bytes_total += len(xml_data)
                root = _parse_xml(xml_data)
            except (ValueError, ElementTree.ParseError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError) as exc:
                warnings.append(f"XML part {name} could not be safely parsed: {_safe_text(exc)}")
                partial = True
                continue
            inspected.append(name)
            for node in root.iter():
                local = _local_name(node.tag).casefold()
                if local in {"event-listener", "eventlistener"}:
                    feature_counts["script_event_listener_count"] += 1
                elif local in {"script", "scripts"}:
                    feature_counts["script_element_count"] += 1
                elif local in {"object", "object-ole"}:
                    feature_counts["embedded_object_element_count"] += 1
                elif local in {"dde-link", "dde-link-ref"}:
                    feature_counts["dde_element_count"] += 1
                elif local in {"database-range", "database-source-sql"}:
                    feature_counts["database_related_element_count"] += 1
                elif local == "encryption-data":
                    feature_counts["encrypted_member_manifest_entry_count"] += 1

                for attr_name, attr_value in node.attrib.items():
                    attr_local = _local_name(attr_name).casefold()
                    attr_val = _safe_text(attr_value, 2048)
                    if attr_local == "href" and attr_val and _is_external_target(attr_val):
                        feature_counts["external_reference_count"] += 1
                        if len(external_refs) < MAX_EXTERNAL_EXAMPLES:
                            external_refs.append({"part": name, "element": _safe_text(local, 100), "target": attr_val})
                    if attr_local == "formula" and attr_val:
                        feature_counts["formula_attribute_count"] += 1
                        if _EXTERNAL_FORMULA.search(attr_val):
                            feature_counts["external_or_network_formula_count"] += 1

        if feature_counts.get("encrypted_member_manifest_entry_count", 0):
            warnings.append("Manifest declares encrypted OpenDocument member(s); content was not decrypted or interpreted.")
            partial = True
        if "content.xml" not in by_name:
            warnings.append("Required OpenDocument content.xml member is missing.")
            partial = True
        manifest_info = by_name.get("META-INF/manifest.xml")
        if manifest_info is None:
            warnings.append("META-INF/manifest.xml is missing; package inventory may be incomplete.")
            partial = True

        # Count all ZIP members with script/macro-like names, including paths beyond the
        # XML inspection selection. Their presence is a static indicator only.
        feature_counts["script_or_basic_member_count"] = max(feature_counts.get("script_or_basic_member_count", 0), len(macro_members))
        feature_counts["embedded_object_member_count"] = max(feature_counts.get("embedded_object_member_count", 0), len(embedded_members))
        if any("macro" in n.casefold() for n in by_name):
            feature_counts["macro_named_member_count"] = sum(1 for n in by_name if "macro" in n.casefold())
        if any("database" in n.casefold() for n in by_name):
            feature_counts["database_named_member_count"] = sum(1 for n in by_name if "database" in n.casefold())

        if partial:
            status = "partial"
        else:
            status = "parsed"
        if len(selected_xml) > max_xml_parts:
            warnings.append("Selected XML parts exceeded the inspection count cap.")
            status = "partial"
            partial = True

        report = {
            "report_schema_version": 2, "tool": "CVEvident",
            "file": {"filename": file_input.path.name, "size_bytes": file_input.size_bytes,
                     "sha256": file_input.sha256, "file_type": format_id},
            "assessment": {"verdict": "not_assessed",
                           "reason": "OpenDocument package structure and references are contextual observations only; scripts/macros are not executed."},
            "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256,
                        "odf_container_entry_count": entry_count, "odf_xml_parts_inspected": len(inspected)},
            "odf_analysis": {
                "status": status, "family": family, "format_id": format_id, "mimetype": mimetype,
                "main_part": "content.xml", "mimetype_first_and_uncompressed": mimetype_first,
                "extension_matches_detected_format": extension_matches,
                "container_entry_count": entry_count, "declared_uncompressed_bytes": declared_bytes,
                "xml_parts_inspected": len(inspected), "xml_bytes_inspected": xml_bytes_total,
                "truncated": bool(partial), "features": dict(feature_counts),
                "external_references": external_refs, "parts_inventory": inspected[:MAX_PART_EXAMPLES],
                "macro_or_script_members": [_safe_text(n, 240) for n in macro_members[:MAX_PART_EXAMPLES]],
                "embedded_object_members": [_safe_text(n, 240) for n in embedded_members[:MAX_PART_EXAMPLES]],
                "warnings": list(dict.fromkeys(warnings)),
            },
            "evidence": [
                {"evidence_type": "odf_package", "key": "odf.package_status", "value": status,
                 "severity": "warning" if status != "parsed" else "info",
                 "details": {"format_id": format_id, "family": family, "mimetype": mimetype}},
                {"evidence_type": "odf_package", "key": "odf.mimetype", "value": mimetype,
                 "severity": "info", "details": {"context_only": True}},
            ],
            "warnings": list(dict.fromkeys([
                "OpenDocument script, formula, external-link and embedded-object indicators are context only; this is not a malware verdict.",
                "Scripts, macros, hyperlinks, external references and embedded objects are never executed, opened, extracted or fetched.", *warnings,
            ])),
        }
        for key, value in feature_counts.items():
            if value:
                report["evidence"].append({"evidence_type": "odf_indicator", "key": f"odf.{key}", "value": value,
                    "severity": "info", "details": {"context_only": True,
                    "interpretation": "Static OpenDocument package/XML indicator; not proof of maliciousness."}})
        if external_refs:
            report["evidence"].append({"evidence_type": "odf_external_reference", "key": "odf.external_references",
                "value": len(external_refs), "severity": "info",
                "details": {"examples": external_refs, "interpretation": "Targets are reported but never opened or fetched."}})
        return report
