"""Bounded, non-executing structural inspection of PDF object graphs via pypdf.

No page content is rendered and no JavaScript/action is executed. PDF parsing still
processes untrusted input, so run this tool with OS-level resource limits for hostile files.
"""
from __future__ import annotations

import inspect
import io
import logging
import threading
from collections import Counter
from functools import wraps
from typing import Any

_MAX_CONTAINERS = 20_000
_MAX_DEPTH = 64
_MAX_FINDINGS = 500
_MAX_PATH_LENGTH = 1_024

# CVEvident only needs a bounded structural view, not unrestricted PDF content
# extraction. These limits apply to pypdf's parser and lazy object resolution too.
_PDF_RESOURCE_LIMITS: dict[str, int | None | bool] = {
    "maximum_declared_stream_length": 16 * 1024 * 1024,
    "array_based_stream_maximum_output_length": 16 * 1024 * 1024,
    "array_maximum_element_count": 50_000,
    "dictionary_maximum_element_count": 50_000,
    "jbig2_maximum_output_length": 16 * 1024 * 1024,
    "lzw_maximum_output_length": 16 * 1024 * 1024,
    "run_length_maximum_output_length": 16 * 1024 * 1024,
    "zlib_maximum_output_length": 16 * 1024 * 1024,
    "zlib_maximum_recovery_input_length": 2 * 1024 * 1024,
    "brotli_maximum_output_length": 16 * 1024 * 1024,
    "flate_maximum_columns": 250_000,
    "flate_maximum_row_length": 4 * 1024 * 1024,
    "image_maximum_buffer_size": 16 * 1024 * 1024,
    "stream_filters_maximum_length": 8,
    "stream_decoding_work_maximum_length": 64 * 1024 * 1024,
    "stream_parsing_work_maximum_count": 500_000,
    "xmp_maximum_input_length": 2 * 1024 * 1024,
    "xmp_maximum_element_count": 25_000,
    "outline_maximum_entries": 25_000,
    "outline_maximum_depth": 64,
    "page_tree_maximum_entries": 50_000,
    "page_tree_maximum_depth": 64,
    "form_fields_maximum_entries": 25_000,
    "form_fields_maximum_depth": 64,
    "xform_maximum_invocations_per_extraction": 1_000,
    # Structural triage does not need the external JBIG2 executable.
    "jbig2dec_binary": None,
    "disable_legacy_handling": True,
}

_REQUIRED_PDF_RESOURCE_LIMITS = frozenset({
    "maximum_declared_stream_length",
    "array_based_stream_maximum_output_length",
    "array_maximum_element_count",
    "dictionary_maximum_element_count",
    "jbig2_maximum_output_length",
    "lzw_maximum_output_length",
    "run_length_maximum_output_length",
    "zlib_maximum_output_length",
    "stream_filters_maximum_length",
    "stream_decoding_work_maximum_length",
    "stream_parsing_work_maximum_count",
})


def _with_pdf_resource_limits(function):
    """Apply pypdf budgets for the full lifetime of structural parsing."""
    @wraps(function)
    def wrapped(data: bytes, is_pdf: bool) -> dict[str, Any]:
        if not is_pdf:
            return function(data, is_pdf)

        try:
            import pypdf
        except Exception:
            # Preserve analyze_pdf_structure's usual unavailable-parser result.
            return function(data, is_pdf)

        version = getattr(pypdf, "__version__", "unknown")
        apply_configuration = getattr(pypdf, "apply_configuration", None)
        configuration_type = getattr(pypdf, "Configuration", None)
        if not callable(apply_configuration) or configuration_type is None:
            result = _base_result("failed", version)
            result["warnings"].append(
                "PDF structural parsing was skipped because pypdf does not expose "
                "the required resource-limit configuration API."
            )
            return result

        try:
            supported = set(inspect.signature(configuration_type).parameters)
        except (TypeError, ValueError):
            result = _base_result("failed", version)
            result["warnings"].append(
                "PDF structural parsing was skipped because pypdf resource-limit "
                "support could not be verified."
            )
            return result

        missing = _REQUIRED_PDF_RESOURCE_LIMITS - supported
        if missing:
            result = _base_result("failed", version)
            result["warnings"].append(
                "PDF structural parsing was skipped because pypdf is missing required "
                "resource limits: " + ", ".join(sorted(missing)) + "."
            )
            return result

        overrides = {
            name: value for name, value in _PDF_RESOURCE_LIMITS.items()
            if name in supported
        }
        try:
            context = apply_configuration(**overrides)
            # Separate context setup errors from parser failures. The analyzer below
            # already translates parser failures into its normal failed result.
            context.__enter__()
        except Exception as exc:
            result = _base_result("failed", version)
            result["warnings"].append(
                "PDF structural parsing was skipped because its resource limits "
                f"could not be applied ({type(exc).__name__})."
            )
            return result

        try:
            return function(data, is_pdf)
        finally:
            # pypdf's context manager resets its context-local configuration here.
            context.__exit__(None, None, None)

    return wrapped


_MAX_CAPTURED_PYPDF_DIAGNOSTICS = 12


class _PypdfDiagnosticCapture(logging.Handler):
    """Capture bounded warning-level pypdf diagnostics for the current thread."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.owner_thread = threading.get_ident()
        self.count = 0
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        # A handler temporarily attached to the pypdf logger may also see records
        # from concurrent analyses. Keep only the current analysis thread's logs.
        if record.thread != self.owner_thread:
            return
        self.count += 1
        if len(self.messages) >= _MAX_CAPTURED_PYPDF_DIAGNOSTICS:
            return
        try:
            message = " ".join(record.getMessage().split())
        except Exception:
            message = "pypdf emitted an unreadable diagnostic message"
        message = "".join(
            character for character in message
            if character == "\t" or ord(character) >= 32
        )[:300]
        if message and message not in self.messages:
            self.messages.append(message)


def _capture_pypdf_diagnostics(function):
    """Record pypdf recovery warnings and downgrade otherwise-clean parses."""
    @wraps(function)
    def wrapped(data: bytes, is_pdf: bool) -> dict[str, Any]:
        if not is_pdf:
            return function(data, is_pdf)

        logger = logging.getLogger("pypdf")
        capture = _PypdfDiagnosticCapture()
        logger.addHandler(capture)
        try:
            result = function(data, is_pdf)
        finally:
            logger.removeHandler(capture)

        result["parser_diagnostics_count"] = capture.count
        result["parser_diagnostics"] = list(capture.messages)
        if result.get("page_count_declared") == 0:
            warnings = result.setdefault("warnings", [])
            zero_page_warning = (
                "The PDF page tree declares zero pages; this can be structurally valid, "
                "but no page-level content is available for inspection."
            )
            if zero_page_warning not in warnings:
                warnings.append(zero_page_warning)
        if capture.count:
            if result.get("status") == "parsed":
                result["status"] = "partial"

            warnings = result.setdefault("warnings", [])
            summary = (
                f"pypdf emitted {capture.count} warning-or-higher diagnostic(s) "
                "during structural parsing; recovery or non-standard structure "
                "may affect completeness."
            )
            if summary not in warnings:
                warnings.append(summary)
            for message in capture.messages[:5]:
                note = f"pypdf diagnostic: {message}"
                if note not in warnings:
                    warnings.append(note)
            if len(capture.messages) > 5:
                warnings.append(
                    "Additional distinct pypdf diagnostics were retained in "
                    "parser_diagnostics but omitted from the warning list."
                )
        return result
    return wrapped

_ANNOTATION_SUBTYPES = {
    "/Text", "/Link", "/FreeText", "/Line", "/Square", "/Circle", "/Polygon",
    "/PolyLine", "/Highlight", "/Underline", "/Squiggly", "/StrikeOut", "/Caret",
    "/Stamp", "/Ink", "/Popup", "/FileAttachment", "/Sound", "/Movie", "/Screen",
    "/Widget", "/PrinterMark", "/TrapNet", "/Watermark", "/3D", "/Redact", "/Projection",
}

_ACTION_TYPES = {
    "/JavaScript": "javascript_action_count",
    "/Launch": "launch_action_count",
    "/URI": "uri_action_count",
    "/GoToR": "remote_goto_action_count",
    "/SubmitForm": "submit_form_action_count",
    "/ImportData": "import_data_action_count",
    "/ResetForm": "reset_form_action_count",
    "/Rendition": "rendition_action_count",
    "/RichMediaExecute": "rich_media_execute_action_count",
    "/Sound": "sound_action_count",
    "/Movie": "movie_action_count",
    "/Hide": "hide_action_count",
    "/GoTo": "goto_action_count",
    "/Named": "named_action_count",
}


def _base_result(status: str, parser_version: str | None = None) -> dict[str, Any]:
    return {
        "parser": "pypdf",
        "parser_version": parser_version,
        "status": status,
        "strict_mode": False,
        "page_count_declared": None,
        "encrypted": None,
        "containers_inspected": 0,
        "indirect_references_resolved": 0,
        "truncated": False,
        "resolution_errors": 0,
        "resolution_error_types": [],
        "parser_diagnostics_count": 0,
        "parser_diagnostics": [],
        "findings": [],
        "findings_truncated": False,
        "location_semantics": (
            "object_path is a best-effort path through parsed PDF dictionaries and arrays, "
            "not a byte offset. object_reference identifies the containing indirect object "
            "when available; direct objects may have no object reference."
        ),
        "features": {
            "open_action_entries": 0,
            "additional_action_entries": 0,
            "javascript_action_count": 0,
            "launch_action_count": 0,
            "uri_action_count": 0,
            "remote_goto_action_count": 0,
            "submit_form_action_count": 0,
            "import_data_action_count": 0,
            "reset_form_action_count": 0,
            "rendition_action_count": 0,
            "rich_media_execute_action_count": 0,
            "sound_action_count": 0,
            "movie_action_count": 0,
            "hide_action_count": 0,
            "goto_action_count": 0,
            "named_action_count": 0,
            "unknown_action_count": 0,
            "javascript_name_tree_present": False,
            "embedded_files_name_tree_count": 0,
            "file_specifications_with_embedded_data": 0,
            "annotations_total": 0,
            "link_annotations": 0,
            "acroform_present": False,
            "rich_media_indicators": 0,
            "stream_objects_seen": 0,
            "catalog_open_action_present": False,
            "catalog_additional_actions_present": False,
        },
        "warnings": [],
    }


def _reference_label(obj: Any) -> str | None:
    """Return a stable human-readable label for a pypdf indirect reference."""
    if getattr(obj, "idnum", None) is None or getattr(obj, "generation", None) is None:
        return None
    try:
        return f"{int(obj.idnum)} {int(obj.generation)} R"
    except (TypeError, ValueError):
        return None


def _join_object_path(parent: str, segment: str, inherited_truncation: bool) -> tuple[str, bool]:
    """Append a dictionary key/array index while keeping report paths bounded."""
    path = f"{parent}{segment}"
    if len(path) <= _MAX_PATH_LENGTH:
        return path, inherited_truncation
    return path[: _MAX_PATH_LENGTH - 3] + "...", True


@_capture_pypdf_diagnostics
@_with_pdf_resource_limits
def analyze_pdf_structure(data: bytes, is_pdf: bool) -> dict[str, Any]:
    """Inspect PDF object dictionaries without executing actions or extracting stream bytes.

    Traversal is capped by a maximum number of containers and depth. Library-level PDF
    parsing has its own cost, so this is not a substitute for an OS sandbox.
    """
    if not is_pdf:
        result = _base_result("skipped_not_pdf")
        result["warnings"].append("Structural parsing was skipped because no PDF header was detected in the first 1024 bytes.")
        return result

    try:
        import pypdf
        from pypdf import PdfReader
        from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject
    except Exception as exc:  # pragma: no cover - dependency is declared, defensive fallback
        result = _base_result("unavailable")
        result["warnings"].append(f"Structural parser unavailable ({type(exc).__name__}); lexical byte-level triage remains available.")
        return result

    result = _base_result("failed", getattr(pypdf, "__version__", "unknown"))
    try:
        reader_kwargs: dict[str, Any] = {"strict": False}
        # Recent pypdf versions expose a recovery cap for root-object recovery. Keep
        # compatibility with older versions during development, while pyproject pins a hardened release.
        try:
            if "root_object_recovery_limit" in inspect.signature(PdfReader).parameters:
                reader_kwargs["root_object_recovery_limit"] = 10_000
        except (TypeError, ValueError):
            pass
        reader = PdfReader(io.BytesIO(data), **reader_kwargs)
        encrypted = bool(reader.is_encrypted)
        result["encrypted"] = encrypted
        if encrypted:
            result["status"] = "encrypted"
            result["warnings"].append("The PDF is encrypted. Object-graph inspection was skipped without a password.")
            return result
        try:
            trailer = reader.trailer
            root_obj = trailer.get("/Root")
            root_reference = _reference_label(root_obj) if isinstance(root_obj, IndirectObject) else None
            if isinstance(root_obj, IndirectObject):
                root_obj = root_obj.get_object()
            if not isinstance(root_obj, DictionaryObject):
                result["status"] = "failed"
                result["warnings"].append("PDF trailer did not expose a readable catalog dictionary.")
                return result
        except Exception as exc:
            result["status"] = "failed"
            result["warnings"].append(f"PDF catalog could not be resolved ({type(exc).__name__}).")
            return result

        features = result["features"]
        features["catalog_open_action_present"] = "/OpenAction" in root_obj
        features["catalog_additional_actions_present"] = "/AA" in root_obj
        features["acroform_present"] = "/AcroForm" in root_obj

        # /Count is a declared page count. It is recorded as a declaration, not used to
        # iterate through every page, avoiding unbounded page-tree traversal here.
        try:
            pages_obj = root_obj.get("/Pages")
            if isinstance(pages_obj, IndirectObject):
                pages_obj = pages_obj.get_object()
            declared = pages_obj.get("/Count") if isinstance(pages_obj, DictionaryObject) else None
            if declared is not None:
                declared_int = int(declared)
                result["page_count_declared"] = declared_int if 0 <= declared_int <= 10_000_000 else None
                if result["page_count_declared"] is None:
                    result["warnings"].append("The declared page count was outside the reporting range and was not trusted.")
        except Exception as exc:
            result["resolution_errors"] += 1
            result["resolution_error_types"].append(type(exc).__name__)

        findings: list[dict[str, Any]] = result["findings"]
        findings_truncated = False

        def record_finding(
            feature: str,
            value: Any,
            object_path: str,
            object_reference: str | None,
            details: dict[str, Any] | None = None,
            path_truncated: bool = False,
        ) -> None:
            nonlocal findings_truncated
            if len(findings) >= _MAX_FINDINGS:
                findings_truncated = True
                return
            finding = {
                "feature": feature,
                "value": value,
                "object_path": object_path,
                "object_reference": object_reference,
                "path_truncated": path_truncated,
                "details": details or {},
            }
            findings.append(finding)

        stack: list[tuple[Any, int, str, str | None, bool]] = [
            (root_obj, 0, "/Root", root_reference, False)
        ]
        seen_refs: set[tuple[int, int]] = set()
        seen_containers: set[int] = set()
        action_counts: Counter[str] = Counter()
        error_types: set[str] = set()
        truncated = False

        while stack:
            if result["containers_inspected"] >= _MAX_CONTAINERS:
                truncated = True
                break
            obj, depth, object_path, object_reference, path_truncated = stack.pop()
            if depth > _MAX_DEPTH:
                truncated = True
                continue

            if isinstance(obj, IndirectObject):
                ref_key = (int(obj.idnum), int(obj.generation))
                if ref_key in seen_refs:
                    continue
                seen_refs.add(ref_key)
                object_reference = _reference_label(obj) or object_reference
                try:
                    obj = obj.get_object()
                    result["indirect_references_resolved"] += 1
                except Exception as exc:
                    result["resolution_errors"] += 1
                    error_types.add(type(exc).__name__)
                    continue

            if not isinstance(obj, (DictionaryObject, ArrayObject)):
                continue
            container_id = id(obj)
            if container_id in seen_containers:
                continue
            seen_containers.add(container_id)
            result["containers_inspected"] += 1

            if isinstance(obj, DictionaryObject):
                features["stream_objects_seen"] += int(isinstance(obj, StreamObject))
                if object_path == "/Root" and "/AcroForm" in obj:
                    acroform_path, acroform_path_truncated = _join_object_path(object_path, "/AcroForm", path_truncated)
                    record_finding("acroform_entry", True, acroform_path, object_reference,
                                   {"containing_dictionary_path": object_path}, acroform_path_truncated)
                features["open_action_entries"] += int("/OpenAction" in obj)
                if "/OpenAction" in obj:
                    finding_path, finding_path_truncated = _join_object_path(object_path, "/OpenAction", path_truncated)
                    record_finding("open_action_entry", True, finding_path, object_reference,
                                   {"containing_dictionary_path": object_path}, finding_path_truncated)
                features["additional_action_entries"] += int("/AA" in obj)
                if "/AA" in obj:
                    finding_path, finding_path_truncated = _join_object_path(object_path, "/AA", path_truncated)
                    record_finding("additional_action_entry", True, finding_path, object_reference,
                                   {"containing_dictionary_path": object_path}, finding_path_truncated)
                features["embedded_files_name_tree_count"] += int("/EmbeddedFiles" in obj)
                if "/EmbeddedFiles" in obj:
                    finding_path, finding_path_truncated = _join_object_path(object_path, "/EmbeddedFiles", path_truncated)
                    record_finding("embedded_files_name_tree", True, finding_path, object_reference,
                                   {"containing_dictionary_path": object_path}, finding_path_truncated)
                features["file_specifications_with_embedded_data"] += int("/EF" in obj)
                if "/EF" in obj:
                    finding_path, finding_path_truncated = _join_object_path(object_path, "/EF", path_truncated)
                    record_finding("embedded_file_data_entry", True, finding_path, object_reference,
                                   {"containing_dictionary_path": object_path}, finding_path_truncated)
                has_rich_media = "/RichMedia" in obj or "/RichMediaContent" in obj
                features["rich_media_indicators"] += int(has_rich_media)
                if has_rich_media:
                    rich_key = "/RichMedia" if "/RichMedia" in obj else "/RichMediaContent"
                    finding_path, finding_path_truncated = _join_object_path(object_path, rich_key, path_truncated)
                    record_finding("rich_media_indicator", rich_key, finding_path, object_reference,
                                   {"containing_dictionary_path": object_path}, finding_path_truncated)
                # JavaScript actions can be referenced in the catalog's /Names dictionary;
                # check that relationship explicitly rather than treating any key named
                # /JavaScript elsewhere as a name-tree finding.
                names_obj = obj.get("/Names")
                try:
                    names_reference = _reference_label(names_obj) if isinstance(names_obj, IndirectObject) else None
                    if isinstance(names_obj, IndirectObject):
                        names_obj = names_obj.get_object()
                    if isinstance(names_obj, DictionaryObject) and "/JavaScript" in names_obj:
                        features["javascript_name_tree_present"] = True
                        names_path, names_path_truncated = _join_object_path(object_path, "/Names/JavaScript", path_truncated)
                        record_finding("javascript_name_tree", True, names_path, names_reference,
                                       {"catalog_path": object_path, "names_dictionary_reference": names_reference},
                                       names_path_truncated)
                except Exception as exc:
                    result["resolution_errors"] += 1
                    error_types.add(type(exc).__name__)

                subtype = str(obj.get("/Subtype", ""))
                if subtype in _ANNOTATION_SUBTYPES:
                    features["annotations_total"] += 1
                    subtype_path, subtype_path_truncated = _join_object_path(object_path, "/Subtype", path_truncated)
                    record_finding("annotation_subtype", subtype, subtype_path, object_reference,
                                   {"annotation_subtype": subtype}, subtype_path_truncated)
                    if subtype == "/Link":
                        features["link_annotations"] += 1

                action_type = str(obj.get("/S", ""))
                if action_type in _ACTION_TYPES:
                    action_counts[action_type] += 1
                    action_path, action_path_truncated = _join_object_path(object_path, "/S", path_truncated)
                    record_finding("action_type", action_type, action_path, object_reference,
                                   {"feature_counter": _ACTION_TYPES[action_type]}, action_path_truncated)
                elif action_type.startswith("/") and "/S" in obj:
                    features["unknown_action_count"] += 1
                    action_path, action_path_truncated = _join_object_path(object_path, "/S", path_truncated)
                    record_finding("unknown_action_type", action_type, action_path, object_reference,
                                   {}, action_path_truncated)

                # Only traverse object/container references. Strings and stream bytes are
                # deliberately never decoded or interpreted as code.
                remaining_capacity = _MAX_CONTAINERS - result["containers_inspected"] - len(stack)
                if remaining_capacity <= 0:
                    truncated = True
                else:
                    children = reversed(list(obj.items()))
                    for key, child in children:
                        if not isinstance(child, (DictionaryObject, ArrayObject, IndirectObject)):
                            continue
                        if len(stack) >= remaining_capacity:
                            truncated = True
                            break
                        child_path, child_path_truncated = _join_object_path(object_path, str(key), path_truncated)
                        stack.append((child, depth + 1, child_path, None, child_path_truncated))
            else:
                remaining_capacity = _MAX_CONTAINERS - result["containers_inspected"] - len(stack)
                if remaining_capacity <= 0:
                    truncated = True
                else:
                    for index in range(len(obj) - 1, -1, -1):
                        child = obj[index]
                        if not isinstance(child, (DictionaryObject, ArrayObject, IndirectObject)):
                            continue
                        if len(stack) >= remaining_capacity:
                            truncated = True
                            break
                        child_path, child_path_truncated = _join_object_path(object_path, f"[{index}]", path_truncated)
                        stack.append((child, depth + 1, child_path, None, child_path_truncated))

        for action, key in _ACTION_TYPES.items():
            features[key] = action_counts[action]
        features["unknown_action_count"] += 0
        result["truncated"] = truncated
        result["findings_truncated"] = findings_truncated
        result["status"] = "partial" if (truncated or findings_truncated or result["resolution_errors"] > 0) else "parsed"
        result["resolution_error_types"] = sorted(set(result["resolution_error_types"]) | error_types)
        if findings_truncated:
            result["warnings"].append(
                f"Structural finding details reached their reporting limit ({_MAX_FINDINGS}); additional findings were omitted."
            )
        if truncated:
            result["warnings"].append(
                f"Object-graph traversal reached its safety budget (max {_MAX_CONTAINERS} containers, depth {_MAX_DEPTH}); results may be incomplete."
            )
        if result["resolution_errors"]:
            result["warnings"].append("Some indirect objects could not be resolved; structural results may be incomplete.")
        result["warnings"].append("Structural parsing is static: no PDF JavaScript, launch action, link target, or other document action was executed.")
        result["warnings"].append("Parsing untrusted PDFs can still consume resources; use an isolated process with OS resource limits for hostile samples.")
        return result
    except Exception as exc:
        result["status"] = "failed"
        result["error_type"] = type(exc).__name__
        # Do not surface partially traversed structural findings as validated findings
        # when the parser failed. Lexical observations remain available in pdf_triage.
        result["findings"] = []
        result["findings_truncated"] = False
        result["features"] = _base_result(
            "failed", result.get("parser_version")
        )["features"]
        result["page_count_declared"] = None
        result["warnings"].append(
            f"The structural PDF parser could not complete ({type(exc).__name__}); lexical observations are retained, not treated as a structural finding."
        )
        return result
