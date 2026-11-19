from __future__ import annotations

import re
import unicodedata
from typing import Any


_FIELDS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_NUMERIC_VERSION = re.compile(r"^[vV]?(\d+(?:\.\d+)*)$")


def _split_cpe(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
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


def _decode(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


_CPE_UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._"
)
_CPE_PUNCTUATION = set("!\"#$%&'()+,/:;<=>@[]^") | {chr(96), "{", "|", "}", "~"}
_CPE_QUOTED = _CPE_PUNCTUATION | {"\\", "*", "?"}
_LANGUAGE_TAG = re.compile(r"^(?:[A-Za-z]{2,3}(?:-(?:[A-Za-z]{2}|[0-9]{3}))?|[*-])$")


def _consume_special(value: str, index: int) -> int:
    """Skip one CPE wildcard group at the start or end of a component."""
    if index < len(value) and value[index] == "*":
        return index + 1
    while index < len(value) and value[index] == "?":
        index += 1
    return index


def _valid_cpe_component(value: str) -> bool:
    """Check the simple CPE 2.3 formatted-string component syntax."""
    if value in {"*", "-"}:
        return True
    if not value or not value.isascii():
        return False

    index = _consume_special(value, 0)
    body_start = index
    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value) or value[index + 1] not in _CPE_QUOTED:
                return False
            index += 2
        elif char in _CPE_UNRESERVED:
            index += 1
        else:
            break

    if index == body_start:
        return False

    return _consume_special(value, index) == len(value)


def parse_cpe23(value: str) -> dict[str, str] | None:
    """Parse a well-formed CPE 2.3 formatted string, or return None."""
    if not isinstance(value, str) or not value.startswith("cpe:2.3:"):
        return None

    parts = _split_cpe(value)
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return None

    components = parts[2:]
    if any(not _valid_cpe_component(component) for component in components):
        return None
    if components[0] not in {"a", "o", "h", "*", "-"}:
        return None
    if not _LANGUAGE_TAG.fullmatch(components[6]):
        return None

    return dict(zip(_FIELDS, components))


def _compare_versions(left: str, right: str) -> int | None:
    left_match = _NUMERIC_VERSION.fullmatch(left.strip())
    right_match = _NUMERIC_VERSION.fullmatch(right.strip())
    if not left_match or not right_match:
        return None
    left_parts = tuple(int(part) for part in left_match.group(1).split("."))
    right_parts = tuple(int(part) for part in right_match.group(1).split("."))
    width = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (width - len(left_parts))
    right_parts += (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def _has_unescaped_wildcard(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] == "\\":
            index += 2
        elif value[index] in {"*", "?"}:
            return True
        else:
            index += 1
    return False


def _wildcard_matches(pattern: str, value: str) -> bool:
    """Match a CPE source value against one concrete target value."""
    expression: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 1
            expression.append(re.escape(pattern[index]))
        elif char == "*":
            expression.append(".*")
        elif char == "?":
            expression.append(".?")
        else:
            expression.append(re.escape(char))
        index += 1
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.fullmatch("".join(expression), normalized, flags=re.DOTALL) is not None


def _attribute_relation(source: str, target: str) -> str | None:
    """Return the NIST CPE 2.3 relation from source attribute to target."""
    if target != "*" and _has_unescaped_wildcard(target):
        return None
    if source == target:
        return "equal"
    if source == "*":
        return "superset"
    if target == "*":
        return "subset"
    if source == "-" or target == "-":
        return "disjoint"
    if _has_unescaped_wildcard(source):
        return "superset" if _wildcard_matches(source, _decode(target)) else "disjoint"
    source_value = unicodedata.normalize("NFKC", _decode(source)).casefold()
    target_value = unicodedata.normalize("NFKC", _decode(target)).casefold()
    return "equal" if source_value == target_value else "disjoint"


def _version_matches(criteria: dict[str, str], match: dict[str, Any], target: dict[str, str]) -> bool | None:
    target_version = _decode(target["version"])
    criteria_version = criteria["version"]
    if target["version"] == "*" and criteria_version != "*":
        return None
    bounds = (
        ("versionStartIncluding", "ge"),
        ("versionStartExcluding", "gt"),
        ("versionEndIncluding", "le"),
        ("versionEndExcluding", "lt"),
    )
    declared = [(key, operator, match.get(key)) for key, operator in bounds if match.get(key) not in (None, "")]
    if declared:
        if criteria_version != "*" or criteria["update"] != "*":
            return None
        for _, operator, boundary in declared:
            comparison = _compare_versions(target_version, str(boundary))
            if comparison is None:
                return None
            inside = {
                "ge": comparison >= 0,
                "gt": comparison > 0,
                "le": comparison <= 0,
                "lt": comparison < 0,
            }[operator]
            if not inside:
                return False
        return True
    if target["version"] == "*" and criteria_version != "*":
        return None
    relation = _attribute_relation(criteria_version, target["version"])
    if relation is None:
        return None
    return relation in {"equal", "superset"}


def compare_cpe23(source_text: str, target_text: str) -> dict[str, Any]:
    """Compare two CPE 2.3 names using the NISTIR 7696 set relations."""
    source = parse_cpe23(source_text)
    target = parse_cpe23(target_text)
    if source is None or target is None:
        return {
            "relation": "undefined",
            "reason": "invalid_cpe_2_3",
            "attribute_relations": {},
        }

    relations = {
        field: _attribute_relation(source[field], target[field])
        for field in _FIELDS
    }
    values = list(relations.values())
    if "disjoint" in values:
        relation = "disjoint"
    elif None in values:
        relation = "undefined"
    elif all(value == "equal" for value in values):
        relation = "equal"
    elif all(value in {"subset", "equal"} for value in values):
        relation = "subset"
    elif all(value in {"superset", "equal"} for value in values):
        relation = "superset"
    else:
        relation = "undefined"

    return {
        "relation": relation,
        "attribute_relations": relations,
    }


def _match_cpe(
    criteria_text: str, match: dict[str, Any], target_text: str
) -> tuple[bool | None, dict[str, Any]]:
    criteria = parse_cpe23(criteria_text)
    target = parse_cpe23(target_text)
    if criteria is None or target is None:
        return None, {"status": "unknown", "reason": "invalid_cpe_2_3"}

    comparison = compare_cpe23(criteria_text, target_text)
    relation = comparison["relation"]
    relations = comparison["attribute_relations"]
    if relation == "disjoint":
        field = next(
            name for name, value in relations.items() if value == "disjoint"
        )
        return False, {
            "status": "not_matched",
            "field": field,
            "name_relation": relation,
            "attribute_relations": relations,
        }
    if relation == "undefined":
        return None, {
            "status": "unknown",
            "reason": "unsupported_cpe_wildcard",
            "name_relation": relation,
            "attribute_relations": relations,
        }
    if relation == "subset":
        if any(
            target[field] == "*" and criteria[field] != "*"
            for field in _FIELDS
        ):
            return None, {
                "status": "unknown",
                "reason": "incomplete_environment_cpe",
                "name_relation": relation,
                "attribute_relations": relations,
            }
        return False, {
            "status": "not_matched",
            "reason": "criteria_is_narrower_than_environment",
            "name_relation": relation,
            "attribute_relations": relations,
        }

    version_result = _version_matches(criteria, match, target)
    if version_result is None:
        return None, {
            "status": "unknown",
            "reason": "unsupported_version_range",
            "name_relation": relation,
            "attribute_relations": relations,
        }
    if not version_result:
        return False, {
            "status": "not_matched",
            "field": "version",
            "name_relation": relation,
            "attribute_relations": relations,
        }
    return True, {
        "status": "matched",
        "criteria": criteria_text,
        "environment_cpe": target_text,
        "vulnerable": bool(match.get("vulnerable", False)),
        "name_relation": relation,
        "attribute_relations": relations,
    }


def _combine(values: list[bool | None], operator: str) -> bool | None:
    if not values:
        return None
    if operator == "AND":
        if False in values:
            return False
        return True if all(value is True for value in values) else None
    if True in values:
        return True
    return False if all(value is False for value in values) else None


def _evaluate_node(node: Any, environment_cpes: list[str], matches: list[dict[str, Any]]) -> bool | None:
    if not isinstance(node, dict):
        return None
    operator = str(node.get("operator") or "OR").upper()
    if operator not in {"AND", "OR"}:
        return None
    values: list[bool | None] = []
    cpe_matches = node.get("cpeMatch")
    if isinstance(cpe_matches, list):
        for entry in cpe_matches:
            if not isinstance(entry, dict):
                values.append(None)
                continue
            criteria = entry.get("criteria") or entry.get("cpe23Uri")
            if not isinstance(criteria, str):
                values.append(None)
                continue
            results = [
                _match_cpe(criteria, entry, environment_cpe)
                for environment_cpe in environment_cpes
            ]
            matched = next((detail for result, detail in results if result is True), None)
            if matched is not None:
                values.append(True)
                matches.append(matched)
            elif any(result is None for result, _ in results):
                values.append(None)
                matches.extend(detail for result, detail in results if result is None)
            else:
                values.append(False)
    children = node.get("nodes")
    if not isinstance(children, list):
        children = node.get("children")
    if isinstance(children, list):
        for child in children:
            values.append(_evaluate_node(child, environment_cpes, matches))
    result = _combine(values, operator)
    if node.get("negate") is True:
        return None if result is None else not result
    return result


def evaluate_nvd_configurations(raw_cve: dict[str, Any] | None, environment_cpes: list[str] | None) -> dict[str, Any]:
    supplied = [value.strip() for value in environment_cpes or [] if isinstance(value, str) and value.strip()]
    if not supplied:
        return {
            "status": "unknown",
            "result": "not_evaluated_no_environment_cpe",
            "environment_cpes": [],
            "matched_conditions": [],
            "interpretation": "No target environment CPE was supplied, so NVD platform applicability was not evaluated.",
        }
    if any(parse_cpe23(value) is None for value in supplied):
        invalid = [value for value in supplied if parse_cpe23(value) is None]
        return {
            "status": "unknown",
            "result": "invalid_environment_cpe",
            "environment_cpes": supplied,
            "invalid_environment_cpes": invalid,
            "matched_conditions": [],
            "interpretation": "At least one supplied environment identifier is not a valid formatted CPE 2.3 string.",
        }
    configurations = (raw_cve or {}).get("configurations")
    if not isinstance(configurations, list) or not configurations:
        return {
            "status": "unknown",
            "result": "nvd_configurations_unavailable",
            "environment_cpes": supplied,
            "matched_conditions": [],
            "interpretation": "The local CVE record does not contain an evaluable NVD configuration tree.",
        }
    matches: list[dict[str, Any]] = []
    results = [_evaluate_node(configuration, supplied, matches) for configuration in configurations]
    result = _combine(results, "OR")
    status = "applicable" if result is True else "not_applicable" if result is False else "unknown"
    return {
        "status": status,
        "result": "configuration_match" if result is True else "configuration_no_match" if result is False else "configuration_indeterminate",
        "environment_cpes": supplied,
        "matched_conditions": matches,
        "configuration_count": len(configurations),
        "interpretation": (
            "The supplied environment CPE set satisfies the locally stored NVD configuration tree. This evaluates platform applicability only; it does not prove the file contains or triggers the vulnerable component."
            if result is True else
            "The supplied environment CPE set does not satisfy the locally stored NVD configuration tree."
            if result is False else
            "NVD configuration evaluation is indeterminate because required configuration data or supported version syntax is unavailable."
        ),
    }
