"""Conservative product-name and optional version context for NVD CPE rows.

This module deliberately does not implement the full NVD applicability logic.  It
classifies lexical name matches and, only for exact CPE versions or simple numeric
 dotted versions, provides a version-context hint that remains separate from CVE
attribution and from the NVD configuration tree's AND/OR evaluation.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

_NUMERIC_VERSION_RE = re.compile(r"^[vV]?(\d+(?:\.\d+)*)$")
_TRAILING_VERSION_RE = re.compile(
    r"(?:\s+|@|,|;)\s*(v?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.-]+)?)\s*$",
    re.IGNORECASE,
)
_CPE_SPECIAL_VERSION = {"", "*", "-"}


def normalize_product_text(value: str | None) -> str:
    """Normalize Unicode, case, and punctuation into stable lexical word tokens."""
    if not value:
        return ""
    normalized = unicodedata.normalize("NFKC", str(value)).casefold()
    # CPE products often use underscores while command-line input uses spaces or
    # hyphens. Treat punctuation as separators but preserve alphanumeric boundaries.
    pieces: list[str] = []
    in_separator = False
    for char in normalized:
        if char.isalnum():
            pieces.append(char)
            in_separator = False
        elif not in_separator:
            pieces.append(" ")
            in_separator = True
    return " ".join("".join(pieces).split())


def product_tokens(value: str | None) -> list[str]:
    normalized = normalize_product_text(value)
    return [token for token in normalized.split() if len(token) >= 2]


def split_product_version(query: str, version: str | None = None) -> tuple[str, str | None, str]:
    """Separate an explicitly supplied or clear trailing dotted version from a name."""
    original = unicodedata.normalize("NFKC", query or "").strip()
    if version is not None and str(version).strip():
        explicit_version = str(version).strip()
        trailing_match = _TRAILING_VERSION_RE.search(original)
        if trailing_match and trailing_match.group(1).casefold() == explicit_version.casefold():
            stripped_name = original[: trailing_match.start()].strip()
            if stripped_name:
                original = stripped_name
        return original, explicit_version, "explicit_option"
    match = _TRAILING_VERSION_RE.search(original)
    if match:
        name = original[: match.start()].strip()
        if name:
            return name, match.group(1).strip(), "trailing_version_in_query"
    return original, None, "not_supplied"


def _split_cpe23(criteria: str | None) -> list[str]:
    """Split formatted CPE 2.3 fields on unescaped colons; keep original escapes."""
    if not isinstance(criteria, str):
        return []
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in criteria:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def cpe23_components(criteria: str | None) -> dict[str, str | None]:
    """Extract CPE vendor/product/version fields without changing stored criteria."""
    parts = _split_cpe23(criteria)
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return {"part": None, "vendor": None, "product": None, "version": None}
    def ordinary(field: str) -> str | None:
        if field in {"", "*", "-"}:
            return None
        # CPE backslash escaping makes punctuation literal; decode only the escaped
        # character for comparison while retaining the original criteria separately.
        return re.sub(r"\\(.)", r"\1", field)
    return {
        "part": ordinary(parts[2]),
        "vendor": ordinary(parts[3]),
        "product": ordinary(parts[4]),
        "version": parts[5],
    }


def _numeric_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    match = _NUMERIC_VERSION_RE.fullmatch(value.strip())
    if not match:
        return None
    try:
        return tuple(int(piece) for piece in match.group(1).split("."))
    except ValueError:
        return None


def _compare_numeric_versions(left: str, right: str) -> int | None:
    lhs = _numeric_version(left)
    rhs = _numeric_version(right)
    if lhs is None or rhs is None:
        return None
    width = max(len(lhs), len(rhs))
    lhs += (0,) * (width - len(lhs))
    rhs += (0,) * (width - len(rhs))
    return (lhs > rhs) - (lhs < rhs)


def _version_display_bounds(row: dict[str, Any]) -> dict[str, str | None]:
    return {
        "start_including": row.get("version_start_including"),
        "start_excluding": row.get("version_start_excluding"),
        "end_including": row.get("version_end_including"),
        "end_excluding": row.get("version_end_excluding"),
    }


def assess_version_context(target_version: str | None, row: dict[str, Any]) -> dict[str, Any]:
    """Classify exact/range context without claiming full vulnerability applicability."""
    components = cpe23_components(row.get("matched_criteria") or row.get("criteria"))
    criteria_version = components.get("version")
    bounds = _version_display_bounds(row)
    has_bounds = any(value not in (None, "") for value in bounds.values())

    base = {
        "target_version": target_version,
        "cpe_version_component": criteria_version,
        "declared_version_bounds": bounds,
        "comparison_method": "not_performed",
        "status": "not_evaluated_no_target_version",
        "interpretation": "No target version was supplied; version applicability was not evaluated.",
        "full_nvd_configuration_evaluated": False,
    }
    if not target_version:
        if has_bounds:
            base["status"] = "range_metadata_available_target_version_missing"
            base["interpretation"] = "NVD version bounds are present, but no target version was supplied for comparison."
        elif criteria_version not in _CPE_SPECIAL_VERSION:
            base["status"] = "exact_cpe_version_present_target_version_missing"
            base["interpretation"] = "The CPE criteria encodes a concrete version, but no target version was supplied."
        return base

    if has_bounds and criteria_version in {None, "", "*"}:
        comparisons: list[tuple[str, str, int]] = []
        checks = (
            ("version_start_including", "ge"),
            ("version_start_excluding", "gt"),
            ("version_end_including", "le"),
            ("version_end_excluding", "lt"),
        )
        for key, operator in checks:
            boundary = row.get(key)
            if boundary in (None, ""):
                continue
            comparison = _compare_numeric_versions(target_version, str(boundary))
            if comparison is None:
                base.update({
                    "status": "range_comparison_indeterminate",
                    "comparison_method": "unsupported_version_syntax",
                    "interpretation": (
                        "A declared NVD version bound uses syntax outside the supported numeric dotted-version "
                        "comparison. The version was not classified as inside or outside the range."
                    ),
                })
                return base
            is_inside = {
                "ge": comparison >= 0,
                "gt": comparison > 0,
                "le": comparison <= 0,
                "lt": comparison < 0,
            }[operator]
            if not is_inside:
                base.update({
                    "status": "outside_declared_numeric_version_bounds",
                    "comparison_method": "numeric_dotted_components_with_zero_padding",
                    "interpretation": (
                        "The target version falls outside at least one declared simple numeric NVD boundary. "
                        "This is a range-context result only; full configuration logic was not evaluated."
                    ),
                })
                return base
        base.update({
            "status": "within_declared_numeric_version_bounds",
            "comparison_method": "numeric_dotted_components_with_zero_padding",
            "interpretation": (
                "The target version satisfies the stored simple numeric bounds. This is not a vulnerability "
                "verdict: the complete NVD configuration tree and platform conditions were not evaluated."
            ),
        })
        return base

    if criteria_version == "*":
        base.update({
            "status": "wildcard_cpe_version",
            "comparison_method": "cpe_component_inspection",
            "interpretation": (
                "The CPE criteria uses a wildcard version. The row does not establish applicability to this "
                "specific installed version, and NVD configuration logic was not evaluated."
            ),
        })
        return base
    if criteria_version == "-":
        base.update({
            "status": "not_applicable_cpe_version_component",
            "comparison_method": "cpe_component_inspection",
            "interpretation": "The CPE version component is not-applicable; no installed-version conclusion is made.",
        })
        return base
    if criteria_version is None:
        base.update({
            "status": "cpe_version_component_unavailable",
            "comparison_method": "cpe_component_inspection",
            "interpretation": "The stored CPE version component could not be parsed; no version conclusion is made.",
        })
        return base

    decoded_version = re.sub(r"\\(.)", r"\1", criteria_version)
    comparison = _compare_numeric_versions(target_version, decoded_version)
    equal = (unicodedata.normalize("NFKC", target_version).casefold() == decoded_version.casefold())
    if comparison == 0:
        equal = True
    if equal:
        base.update({
            "status": "exact_cpe_version_match",
            "comparison_method": "normalized_exact_or_numeric_dotted_equality",
            "interpretation": (
                "The target version matches the concrete version in the CPE criteria. The NVD applicability "
                "tree is not evaluated, so this is not by itself proof that the CVE applies."
            ),
        })
    else:
        base.update({
            "status": "exact_cpe_version_mismatch",
            "comparison_method": "normalized_exact_or_numeric_dotted_equality",
            "interpretation": (
                "The concrete CPE version differs from the supplied target version. This row is retained as "
                "name context but should not be treated as a version match."
            ),
        })
    return base


def classify_name_match(query: str, vendor: str | None, product: str | None) -> dict[str, Any]:
    """Classify name overlap independently from optional version context."""
    query_normalized = normalize_product_text(query)
    vendor_normalized = normalize_product_text(vendor)
    product_normalized = normalize_product_text(product)
    query_terms = product_tokens(query)
    identity = normalize_product_text(f"{vendor or ''} {product or ''}")
    identity_terms = set(identity.split())
    matched_terms = [term for term in query_terms if term in identity_terms]
    if query_normalized and query_normalized == identity:
        match_class = "exact_normalized_vendor_product"
    elif query_terms and len(matched_terms) == len(query_terms):
        match_class = "all_query_terms_match"
    else:
        match_class = "partial_query_term_match"
    return {
        "normalized_query": query_normalized,
        "normalized_vendor": vendor_normalized,
        "normalized_product": product_normalized,
        "query_terms": query_terms,
        "matching_query_terms": matched_terms,
        "name_match_class": match_class,
        "name_match_score": round(100.0 * len(matched_terms) / len(query_terms), 2) if query_terms else 0.0,
    }
