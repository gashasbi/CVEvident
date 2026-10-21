"""Bounded, static triage for modern Microsoft Office Open XML packages.

No macros, scripts, hyperlinks, external relationships, or embedded objects are
executed, opened, extracted to disk, or fetched over the network. This module
records structural observations; it is not a full Office parser or malware verdict.
"""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from collections import Counter
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree

from .file_input import read_file

# The first OOXML families CVEvident supports. The old binary CFB formats (.doc,
# .xls, .ppt) are deliberately not accepted as OOXML and need a separate analyzer.
OFFICE_EXTENSIONS: dict[str, str] = {
    ".docx": "word", ".docm": "word", ".dotx": "word", ".dotm": "word",
    ".xlsx": "excel", ".xlsm": "excel", ".xltx": "excel", ".xltm": "excel",
    ".xlsb": "excel", ".xlam": "excel",
    ".pptx": "powerpoint", ".pptm": "powerpoint", ".ppsx": "powerpoint",
    ".ppsm": "powerpoint", ".potx": "powerpoint", ".potm": "powerpoint",
    ".ppam": "powerpoint", ".sldx": "powerpoint", ".sldm": "powerpoint",
}
LEGACY_OFFICE_EXTENSIONS = {".doc", ".xls", ".ppt", ".pps", ".pot", ".xlt", ".xla"}

# These types identify the package's main part rather than trusting the filename.
MAIN_CONTENT_TYPES: dict[str, tuple[str, str, bool]] = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": ("docx", "word", False),
    "application/vnd.ms-word.document.macroenabled.main+xml": ("docm", "word", True),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": ("dotx", "word", False),
    "application/vnd.ms-word.template.macroenabledtemplate.main+xml": ("dotm", "word", True),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": ("xlsx", "excel", False),
    "application/vnd.ms-excel.sheet.macroenabled.main+xml": ("xlsm", "excel", True),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": ("xltx", "excel", False),
    "application/vnd.ms-excel.template.macroenabled.main+xml": ("xltm", "excel", True),
    "application/vnd.ms-excel.sheet.binary.macroenabled.main": ("xlsb", "excel", True),
    "application/vnd.ms-excel.addin.macroenabled.main+xml": ("xlam", "excel", True),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": ("pptx", "powerpoint", False),
    "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml": ("pptm", "powerpoint", True),
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": ("ppsx", "powerpoint", False),
    "application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml": ("ppsm", "powerpoint", True),
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": ("potx", "powerpoint", False),
    "application/vnd.ms-powerpoint.template.macroenabled.main+xml": ("potm", "powerpoint", True),
    "application/vnd.ms-powerpoint.addin.macroenabled.main+xml": ("ppam", "powerpoint", True),
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml": ("sldx", "powerpoint", False),
    "application/vnd.ms-powerpoint.slide.macroenabled.main+xml": ("sldm", "powerpoint", True),
}

MAX_ARCHIVE_ENTRIES = 10_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_XML_PART_BYTES = 4 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 32 * 1024 * 1024
MAX_XML_PARTS = 300
MAX_COMPRESSION_RATIO = 1_000
MAX_RELATIONSHIP_EXAMPLES = 25
MAX_PART_EXAMPLES = 80

_EXTERNAL_CONTENT_FUNCTIONS = re.compile(r"\b(?:WEBSERVICE|RTD|DDE|HYPERLINK|FILTERXML)\s*\(", re.I)
_FIELD_INSTRUCTIONS = re.compile(r"\b(?:DDEAUTO|DDE|INCLUDETEXT|INCLUDEPICTURE|HYPERLINK)\b", re.I)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _safe_text(value: Any, limit: int = 500) -> str:
    text = "" if value is None else str(value)
    # Keep control characters out of reports/logs; never render source values as markup.
    text = "".join(ch if ch >= " " and ch not in "\x7f" else " " for ch in text)
    return " ".join(text.split())[:limit]


def _is_unsafe_member_name(name: str) -> bool:
    normal = name.replace("\\", "/")
    if normal.startswith("/") or (len(normal) >= 2 and normal[1] == ":"):
        return True
    return any(part in {".", ".."} for part in normal.split("/") if part)


def _relationship_source(rels_name: str) -> str:
    if rels_name == "_rels/.rels":
        return "/"
    path = PurePosixPath(rels_name)
    parts = list(path.parts)
    try:
        rels_index = parts.index("_rels")
    except ValueError:
        return _safe_text(rels_name, 300)
    source_name = path.name[:-5] if path.name.endswith(".rels") else path.name
    return _safe_text("/".join(parts[:rels_index] + [source_name]), 300)


def _resolve_package_relationship_target(target: str) -> str | None:
    """Resolve a root relationship target to a safe package member name."""
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    path = unquote(parsed.path)
    if not path or "\\" in path or "\x00" in path:
        return None
    segments = path.lstrip("/").split("/")
    if not segments or any(segment in {"", ".", ".."} for segment in segments):
        return None
    return "/".join(segments)


def _parse_xml(data: bytes) -> ElementTree.Element:
    # Office package XML should not need DTDs/entities. Reject them before parsing to
    # avoid entity-expansion risks; the finding remains a partial-analysis condition.
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("DTD/entity declarations are not processed")
    return ElementTree.fromstring(data)


def _base_report(file_input: Any, status: str, warning: str) -> dict[str, Any]:
    filename = file_input.path.name
    return {
        "report_schema_version": 2,
        "tool": "CVEvident",
        "file": {
            "filename": filename,
            "size_bytes": file_input.size_bytes,
            "sha256": file_input.sha256,
            "file_type": "unknown_or_non_office",
        },
        "assessment": {
            "verdict": "not_assessed",
            "reason": "Office package observations are static context only; no malware verdict or CVE attribution is made.",
        },
        "metrics": {"file_size_bytes": file_input.size_bytes, "sha256": file_input.sha256},
        "office_analysis": {
            "status": status,
            "family": None,
            "format_id": None,
            "main_content_type": None,
            "main_part": None,
            "macro_enabled_format": None,
            "vba_project_present": False,
            "container_entry_count": 0,
            "declared_uncompressed_bytes": 0,
            "xml_parts_inspected": 0,
            "truncated": False,
            "features": {},
            "external_relationships": [],
            "parts_inventory": [],
            "warnings": [warning],
        },
        "evidence": [
            {
                "evidence_type": "file_identity", "key": "sha256", "value": file_input.sha256,
                "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"},
            },
            {
                "evidence_type": "file_identity", "key": "file_size_bytes", "value": file_input.size_bytes,
                "severity": "info", "details": {"meaning": "size of bytes read"},
            },
            {
                "evidence_type": "office_package_status", "key": "office.package_status", "value": status,
                "severity": "warning", "details": {"interpretation": warning},
            },
        ],
        "warnings": [warning, "Static Office triage does not execute macros, scripts, hyperlinks, external relationships, or embedded objects."],
    }


def analyze_office(
    path: str,
    max_bytes: int = 100 * 1024 * 1024,
    *,
    max_archive_entries: int = MAX_ARCHIVE_ENTRIES,
    max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
    max_xml_part_bytes: int = MAX_XML_PART_BYTES,
    max_total_xml_bytes: int = MAX_TOTAL_XML_BYTES,
    max_xml_parts: int = MAX_XML_PARTS,
) -> dict[str, Any]:
    """Analyze an Office Open XML package with bounded, no-extraction inspection.

    Supports Word (DOCX/DOCM/DOTX/DOTM), Excel (XLSX/XLSM/XLTX/XLTM/XLSB/XLAM),
    and PowerPoint (PPTX/PPTM/PPSX/PPSM/POTX/POTM/SLDX/SLDM) package families.
    This is package/structure triage, not full document semantics, VBA decompilation,
    legacy CFB parsing, or proof of maliciousness.
    """
    if min(max_archive_entries, max_total_uncompressed_bytes, max_xml_part_bytes,
           max_total_xml_bytes, max_xml_parts) < 1:
        raise ValueError("Office analysis limits must be positive")

    file_input = read_file(path, max_bytes=max_bytes)
    suffix = file_input.path.suffix.lower()
    data = file_input.data
    is_zip_signature = data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    if not is_zip_signature:
        if suffix in LEGACY_OFFICE_EXTENSIONS:
            message = "Legacy binary Office formats (OLE/CFB) are not supported by the OOXML analyzer yet."
            return _base_report(file_input, "unsupported", message)
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            message = (
                "Input is an OLE/CFB container rather than an unencrypted OOXML ZIP package; "
                "it may be a password-protected Office document. Encrypted content is not decrypted or parsed."
            )
            return _base_report(file_input, "unsupported", message)
        message = "Input is not a ZIP-based Office Open XML package; no Office structure was parsed."
        return _base_report(file_input, "failed" if suffix in OFFICE_EXTENSIONS else "unsupported", message)

    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return _base_report(file_input, "failed", f"Office package container could not be opened: {_safe_text(exc, 240)}")

    warnings: list[str] = []
    partial = False
    with archive:
        all_infos = archive.infolist()
        entry_count = len(all_infos)
        declared_uncompressed = sum(max(0, int(info.file_size)) for info in all_infos)
        if entry_count > max_archive_entries:
            warnings.append(f"Archive has {entry_count} entries; only the first {max_archive_entries} entries were considered.")
            all_infos = all_infos[:max_archive_entries]
            partial = True
        if declared_uncompressed > max_total_uncompressed_bytes:
            warnings.append(
                f"Declared uncompressed package size ({declared_uncompressed} bytes) exceeds the configured analysis budget."
            )
            partial = True

        exact_name_counts = Counter(info.filename for info in all_infos)
        duplicate_names = {name for name, count in exact_name_counts.items() if count > 1}
        if duplicate_names:
            warnings.append(f"Package contains {len(duplicate_names)} duplicate member name(s); ambiguous names were not parsed.")
            partial = True

        unsafe_names = {info.filename for info in all_infos if _is_unsafe_member_name(info.filename)}
        if unsafe_names:
            warnings.append(f"Package contains {len(unsafe_names)} absolute or traversal-like member name(s); no members were extracted.")
            partial = True

        encrypted_names = {info.filename for info in all_infos if info.flag_bits & 0x1}
        if encrypted_names:
            warnings.append(f"Package contains {len(encrypted_names)} encrypted member(s); encrypted content was not read.")
            partial = True

        usable_infos = [
            info for info in all_infos
            if not info.is_dir()
            and info.filename not in duplicate_names
            and info.filename not in unsafe_names
            and info.filename not in encrypted_names
        ]
        info_by_name = {info.filename: info for info in usable_infos}
        content_types_info = info_by_name.get("[Content_Types].xml")
        if content_types_info is None:
            message = "ZIP container does not contain a readable [Content_Types].xml Office package manifest."
            report = _base_report(file_input, "unsupported", message)
            report["office_analysis"].update({
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "truncated": partial,
                "warnings": warnings + [message],
            })
            report["warnings"].extend(warnings)
            return report

        # The XML inspection budget includes every parser input, including the
        # manifest and root relationships required to identify the package format.
        class _OfficeXmlInspectionLimit(Exception):
            pass

        xml_parser_bytes = 0
        xml_parser_parts = 0
        xml_bytes_inspected = 0
        xml_parts_inspected = 0
        pre_parsed_roots: dict[str, ElementTree.Element] = {}

        def parse_xml_member(info: zipfile.ZipInfo, label: str) -> ElementTree.Element:
            nonlocal xml_parser_bytes, xml_parser_parts
            nonlocal xml_bytes_inspected, xml_parts_inspected

            if info.file_size > max_xml_part_bytes:
                raise ValueError(f"{label} exceeds the per-part limit ({max_xml_part_bytes} bytes)")
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise ValueError(f"{label} exceeds the compression-ratio limit")
            if xml_parser_parts >= max_xml_parts:
                raise _OfficeXmlInspectionLimit(
                    f"XML part-count limit ({max_xml_parts}) reached before parsing {label}."
                )

            remaining = max_total_xml_bytes - xml_parser_bytes
            if remaining <= 0 or info.file_size > remaining:
                raise _OfficeXmlInspectionLimit(
                    f"Total XML inspection budget ({max_total_xml_bytes} bytes) reached before parsing {label}."
                )

            # Read no more than the declared member size plus one byte. The extra
            # byte detects a ZIP member whose actual expansion exceeds its metadata.
            read_limit = min(max_xml_part_bytes, remaining, max(0, int(info.file_size)))
            with archive.open(info, "r") as stream:
                part_data = stream.read(read_limit + 1)
            if len(part_data) > max_xml_part_bytes:
                raise ValueError(f"{label} expanded beyond the per-part limit")
            if len(part_data) > info.file_size:
                raise ValueError(f"{label} expanded beyond its declared ZIP member size")
            if len(part_data) > remaining:
                raise _OfficeXmlInspectionLimit(
                    f"Total XML inspection budget ({max_total_xml_bytes} bytes) reached while reading {label}."
                )

            # Charge bytes and parts before XML parsing, so malformed XML cannot be
            # used to repeatedly exceed the configured parser-input budget.
            xml_parser_bytes += len(part_data)
            xml_parser_parts += 1
            root = _parse_xml(part_data)
            xml_bytes_inspected += len(part_data)
            xml_parts_inspected += 1
            return root

        def budget_limited_report(exc: _OfficeXmlInspectionLimit) -> dict[str, Any]:
            message = (
                "Office package XML inspection budget prevented complete analysis: "
                f"{_safe_text(exc, 220)}"
            )
            report = _base_report(file_input, "partial", message)
            report["office_analysis"].update({
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "xml_parts_inspected": xml_parts_inspected,
                "xml_bytes_inspected": xml_bytes_inspected,
                "truncated": True,
                "warnings": warnings + [message],
            })
            report["warnings"].extend(warnings)
            return report

        content_types: dict[str, str] = {}
        selected_main: tuple[str, str, bool, str] | None = None
        try:
            manifest_root = parse_xml_member(content_types_info, "[Content_Types].xml")
            for node in manifest_root.iter():
                if _local_name(node.tag) == "Override":
                    part_name = _safe_text(node.attrib.get("PartName", ""), 500).lstrip("/")
                    content_type = _safe_text(node.attrib.get("ContentType", ""), 300).lower()
                    if part_name and content_type:
                        content_types[part_name] = content_type
            del manifest_root
        except _OfficeXmlInspectionLimit as exc:
            return budget_limited_report(exc)
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, ElementTree.ParseError, zlib.error, EOFError) as exc:
            message = f"Office package content-type manifest could not be parsed safely: {_safe_text(exc, 220)}"
            report = _base_report(file_input, "failed", message)
            report["office_analysis"].update({
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "truncated": True,
                "warnings": warnings + [message],
            })
            report["warnings"].extend(warnings)
            return report

        # Valid packages can declare content types for slides and other parts that
        # also resemble standalone Office formats. The root officeDocument
        # relationship—not every matching Override—selects the actual package main part.
        root_rels_info = info_by_name.get("_rels/.rels")
        if root_rels_info is None:
            message = "Office package lacks the root relationships part needed to identify its main document."
            report = _base_report(file_input, "unsupported", message)
            report["office_analysis"].update({
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "truncated": partial,
                "warnings": warnings + [message],
                "content_types_count": len(content_types),
            })
            report["warnings"].extend(warnings)
            return report

        try:
            root_rels_root = parse_xml_member(root_rels_info, "root relationships part")
            pre_parsed_roots[root_rels_info.filename] = root_rels_root
            office_relationships = [
                node for node in root_rels_root.iter()
                if _local_name(node.tag) == "Relationship"
                and node.attrib.get("Type", "").rstrip("/").casefold().endswith("/officedocument")
            ]
            recognized_main_parts: list[tuple[str, str, bool, str]] = []
            for relation in office_relationships:
                if relation.attrib.get("TargetMode", "").casefold() == "external":
                    warnings.append("Root officeDocument relationship is external; external targets are never fetched.")
                    partial = True
                    continue
                target = _resolve_package_relationship_target(relation.attrib.get("Target", ""))
                if target is None:
                    warnings.append("Root officeDocument relationship has an unsafe or unsupported target path.")
                    partial = True
                    continue
                mapped = MAIN_CONTENT_TYPES.get(content_types.get(target, ""))
                if mapped is None:
                    warnings.append("Root officeDocument relationship target has no supported Office main-part content type.")
                    partial = True
                    continue
                recognized_main_parts.append((mapped[0], mapped[1], mapped[2], target))
        except _OfficeXmlInspectionLimit as exc:
            return budget_limited_report(exc)
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, ElementTree.ParseError, zlib.error, EOFError) as exc:
            message = f"Office package root relationships could not be parsed safely: {_safe_text(exc, 220)}"
            report = _base_report(file_input, "failed", message)
            report["office_analysis"].update({
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "truncated": True,
                "warnings": warnings + [message],
            })
            report["warnings"].extend(warnings)
            return report

        if not recognized_main_parts:
            message = "Root relationships did not identify a supported Word, Excel, or PowerPoint OOXML main part."
            report = _base_report(file_input, "unsupported", message)
            report["office_analysis"].update({
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "truncated": partial,
                "warnings": warnings + [message],
                "content_types_count": len(content_types),
            })
            report["warnings"].extend(warnings)
            return report

        selected_main = recognized_main_parts[0]
        if len(set(recognized_main_parts)) > 1:
            warnings.append("Root relationships declare multiple conflicting Office main parts; only the first was used.")
            partial = True
        format_id, family, macro_enabled_format, main_part = selected_main
        if main_part not in info_by_name:
            warnings.append(f"Declared Office main part {_safe_text(main_part, 180)} is missing from the ZIP member list.")
            partial = True
        extension_matches = suffix == f".{format_id}"
        if not extension_matches:
            warnings.append(
                f"Filename extension {suffix or '(none)'} does not match the package format detected from its content types ({format_id})."
            )

        # Select only bounded XML parts. Binary media, VBA project binaries, and embedded
        # objects are inventoried by name and never extracted or interpreted as executable.
        xml_infos = [
            info for info in usable_infos
            if info.filename == "[Content_Types].xml"
            or info.filename.lower().endswith((".xml", ".rels"))
        ]
        main_rels = str(PurePosixPath(main_part).parent / "_rels" / (PurePosixPath(main_part).name + ".rels"))
        priority = {"[Content_Types].xml": 0, "_rels/.rels": 1, main_part: 2, main_rels: 3}
        xml_infos.sort(key=lambda info: (priority.get(info.filename, 4 if info.filename.endswith(".rels") else 5), info.filename))
        if len(xml_infos) > max_xml_parts:
            warnings.append(f"XML part count exceeds the limit ({max_xml_parts}); some parts were not inspected.")
            xml_infos = xml_infos[:max_xml_parts]
            partial = True

        features: dict[str, int | bool] = {
            "vba_project_present": any(PurePosixPath(name).name.casefold() == "vbaproject.bin" for name in info_by_name),
            "embedded_object_part_count": sum("/embeddings/" in f"/{name.casefold()}" for name in info_by_name),
            "activex_part_count": sum("/activex/" in f"/{name.casefold()}" for name in info_by_name),
            "external_link_part_count": sum("/externallinks/" in f"/{name.casefold()}" for name in info_by_name),
            "custom_ui_part_count": sum("/customui/" in f"/{name.casefold()}" for name in info_by_name),
            "macro_sheet_part_count": sum("/macrosheets/" in f"/{name.casefold()}" for name in info_by_name),
            "digital_signature_part_count": sum(name.casefold().startswith("_xmlsignatures/") for name in info_by_name),
            "ole_object_element_count": 0,
            "activex_element_count": 0,
            "altchunk_element_count": 0,
            "hyperlink_element_count": 0,
            "external_formula_reference_count": 0,
            "formula_network_function_count": 0,
            "field_instruction_count": 0,
            "external_relationship_count": 0,
            "encrypted_member_count": len(encrypted_names),
            "unsafe_member_name_count": len(unsafe_names),
            "duplicate_member_name_count": len(duplicate_names),
        }
        relationships: list[dict[str, str]] = []
        inspected_part_names: list[str] = []
        for info in xml_infos:
            if info.filename in duplicate_names or info.filename in unsafe_names or info.filename in encrypted_names:
                continue
            if info.filename == "[Content_Types].xml":
                # Already parsed for format identification and included in the shared budget.
                inspected_part_names.append(_safe_text(info.filename, 240))
                continue
            if info.filename in pre_parsed_roots:
                root = pre_parsed_roots.pop(info.filename)
            else:
                try:
                    root = parse_xml_member(info, f"XML part {_safe_text(info.filename, 180)}")
                except _OfficeXmlInspectionLimit as exc:
                    warnings.append(_safe_text(exc, 240) + " Remaining XML parts were skipped.")
                    partial = True
                    break
                except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, ElementTree.ParseError, zlib.error, EOFError) as exc:
                    warnings.append(f"XML part {_safe_text(info.filename, 180)} could not be safely parsed: {_safe_text(exc, 160)}")
                    partial = True
                    continue
            inspected_part_names.append(_safe_text(info.filename, 240))

            # Process a part immediately and discard its tree before reading the next
            # part. This keeps memory bounded by one XML tree instead of retaining all
            # parsed trees from a potentially large Office package.
            is_relationship_part = info.filename.lower().endswith(".rels")
            source_part = _relationship_source(info.filename) if is_relationship_part else ""
            part_marker = f"/{info.filename.casefold()}"
            for node in root.iter():
                local = _local_name(node.tag).casefold()
                if is_relationship_part and local == "relationship":
                    target_mode = node.attrib.get("TargetMode", "")
                    if target_mode.casefold() == "external":
                        features["external_relationship_count"] = int(features["external_relationship_count"]) + 1
                        if len(relationships) < MAX_RELATIONSHIP_EXAMPLES:
                            relationships.append({
                                "source_part": _safe_text(source_part, 300),
                                "relationship_type": _safe_text(node.attrib.get("Type", ""), 240),
                                "target": _safe_text(node.attrib.get("Target", ""), 500),
                            })
                if local in {"oleobject", "oleobj"}:
                    # OOXML commonly spells the DrawingML element as oleObj;
                    # older/alternate markup can use OLEObject.
                    features["ole_object_element_count"] = int(features["ole_object_element_count"]) + 1
                elif local in {"activex", "activexcontrol"}:
                    features["activex_element_count"] = int(features["activex_element_count"]) + 1
                elif local == "altchunk":
                    features["altchunk_element_count"] = int(features["altchunk_element_count"]) + 1
                elif local in {"hyperlink", "hlinkclick", "hlinkmouseover"}:
                    # Word uses hyperlink; DrawingML uses hlinkClick/hlinkMouseOver.
                    features["hyperlink_element_count"] = int(features["hyperlink_element_count"]) + 1
                elif local == "f" and "/worksheets/" in part_marker:
                    formula = _safe_text(node.text, 2_000)
                    if "[" in formula and "]" in formula:
                        features["external_formula_reference_count"] = int(features["external_formula_reference_count"]) + 1
                    if _EXTERNAL_CONTENT_FUNCTIONS.search(formula):
                        features["formula_network_function_count"] = int(features["formula_network_function_count"]) + 1
                elif local == "instrtext" and _FIELD_INSTRUCTIONS.search(node.text or ""):
                    features["field_instruction_count"] = int(features["field_instruction_count"]) + 1
            del root

        package_status = "partial" if partial else "parsed"
        warnings.append("Office structure and relationships are contextual observations; they are not a malware verdict.")
        warnings.append("Macros, scripts, hyperlinks, external relationships, and embedded objects were not executed, opened, extracted to disk, or fetched.")
        if features["vba_project_present"]:
            warnings.append("A VBA project binary is present; its code was not executed or decompiled by this analyzer.")
            if not macro_enabled_format:
                warnings.append("A VBA project binary was found in a package whose main content type is not marked macro-enabled.")
        if int(features["external_relationship_count"]) > 0:
            warnings.append("External package relationships were recorded; targets were not opened or fetched.")

        evidence: list[dict[str, Any]] = [
            {
                "evidence_type": "file_identity", "key": "sha256", "value": file_input.sha256,
                "severity": "info", "details": {"algorithm": "SHA-256", "meaning": "exact file fingerprint"},
            },
            {
                "evidence_type": "file_identity", "key": "file_size_bytes", "value": file_input.size_bytes,
                "severity": "info", "details": {"meaning": "compressed package size in bytes"},
            },
            {
                "evidence_type": "office_package_status", "key": "office.package_status", "value": package_status,
                "severity": "warning" if partial else "info",
                "details": {"interpretation": "Package parser coverage status; it does not indicate whether the file is safe."},
            },
            {
                "evidence_type": "office_format", "key": "office.detected_format", "value": format_id,
                "severity": "info",
                "details": {
                    "family": family, "main_content_type": _safe_text(selected_main and next(
                        (ct for ct, entry in MAIN_CONTENT_TYPES.items() if entry[0] == format_id), ""), 300),
                    "main_part": _safe_text(main_part, 300),
                    "interpretation": "Format was inferred from the package content-type manifest, not only the extension.",
                },
            },
        ]
        feature_meanings = {
            "vba_project_present": "A vbaProject.bin package part is present; its code was not executed or decompiled.",
            "embedded_object_part_count": "Package contains one or more embedded-object parts.",
            "activex_part_count": "Package contains ActiveX-related package parts.",
            "external_link_part_count": "Package contains external-link parts, often associated with linked workbook data.",
            "custom_ui_part_count": "Package contains custom Office UI parts.",
            "macro_sheet_part_count": "Package contains Excel macro-sheet parts.",
            "digital_signature_part_count": "Package contains XML signature parts; signature validity was not evaluated.",
            "ole_object_element_count": "Parsed XML contains OLE-object elements.",
            "activex_element_count": "Parsed XML contains ActiveX-related elements.",
            "altchunk_element_count": "Parsed Word XML contains altChunk elements that may refer to imported content.",
            "hyperlink_element_count": "Parsed XML contains hyperlink elements; targets were not opened.",
            "external_formula_reference_count": "Parsed worksheet formulas contain bracketed external-workbook references.",
            "formula_network_function_count": "Parsed worksheet formulas contain selected external/dynamic-data functions.",
            "field_instruction_count": "Parsed Word field instructions contain link/import/DDE-related keywords.",
            "external_relationship_count": "Package relationships point to external targets; targets were not fetched.",
            "encrypted_member_count": "Package contains encrypted ZIP members that were not read.",
            "unsafe_member_name_count": "Package contains absolute or traversal-like member names; no extraction was performed.",
            "duplicate_member_name_count": "Package contains duplicate ZIP member names; ambiguous entries were skipped.",
        }
        for key, meaning in feature_meanings.items():
            value = features.get(key)
            if value is True or (isinstance(value, int) and not isinstance(value, bool) and value > 0):
                evidence.append({
                    "evidence_type": "office_structural_feature", "key": f"office.structure.{key}",
                    "value": value, "severity": "info",
                    "details": {"interpretation": meaning, "context_only": True},
                })
        if not extension_matches:
            evidence.append({
                "evidence_type": "format_check", "key": "office.extension_mismatch",
                "value": {"extension": suffix or None, "detected_format": format_id},
                "severity": "warning",
                "details": {"interpretation": "The package's declared main content type differs from its filename extension."},
            })

        report = {
            "report_schema_version": 2,
            "tool": "CVEvident",
            "file": {
                "filename": file_input.path.name,
                "size_bytes": file_input.size_bytes,
                "sha256": file_input.sha256,
                "file_type": format_id,
            },
            "assessment": {
                "verdict": "not_assessed",
                "reason": "Available Office package observations are static context only; no malware verdict or CVE attribution is made.",
            },
            "metrics": {
                "file_size_bytes": file_input.size_bytes,
                "sha256": file_input.sha256,
                "zip_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "xml_parts_inspected": xml_parts_inspected,
                "xml_bytes_inspected": xml_bytes_inspected,
            },
            "office_analysis": {
                "status": package_status,
                "family": family,
                "format_id": format_id,
                "main_content_type": next((ct for ct, entry in MAIN_CONTENT_TYPES.items() if entry[0] == format_id), None),
                "main_part": _safe_text(main_part, 300),
                "macro_enabled_format": macro_enabled_format,
                "vba_project_present": bool(features["vba_project_present"]),
                "container_entry_count": entry_count,
                "declared_uncompressed_bytes": declared_uncompressed,
                "xml_parts_inspected": xml_parts_inspected,
                "xml_bytes_inspected": xml_bytes_inspected,
                "truncated": partial,
                "extension_matches_detected_format": extension_matches,
                "features": features,
                "external_relationships": relationships,
                "parts_inventory": inspected_part_names[:MAX_PART_EXAMPLES],
                "warnings": list(dict.fromkeys(warnings)),
            },
            "evidence": evidence,
            "warnings": list(dict.fromkeys(warnings)),
        }
        return report
