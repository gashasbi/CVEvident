from __future__ import annotations

import json
import sqlite3
from typing import Any

from .db import connect


def _same_value(expected: Any, observed: Any) -> bool:
    return json.dumps(expected, sort_keys=True, ensure_ascii=False) == json.dumps(
        observed, sort_keys=True, ensure_ascii=False
    )


def _parser_family(report: dict[str, Any]) -> str:
    for section, family in (
        ("structural_analysis", "pdf"),
        ("office_analysis", "ooxml"),
        ("legacy_office_analysis", "legacy_office"),
        ("odf_analysis", "odf"),
        ("rtf_analysis", "rtf"),
    ):
        if isinstance(report.get(section), dict):
            return family
    return "unknown"


def _coverage_status(report: dict[str, Any], domain: str | None) -> str:
    if not domain:
        return "unknown"
    parser_coverage = (report.get("analysis_coverage") or {}).get("parser_coverage") or {}
    domains = parser_coverage.get("domains") or {}
    record = domains.get(domain)
    return str(record.get("status", "unknown")) if isinstance(record, dict) else "unknown"


def correlate_evidence_rules(report: dict[str, Any], db_path: str | None = None) -> dict[str, Any]:
    """Evaluate exact evidence rules and optional AND/OR groups with coverage-aware logic."""
    family = _parser_family(report)
    evidence = report.get("evidence") or []
    observed = {
        (str(item.get("evidence_type")), str(item.get("key"))): item
        for item in evidence if isinstance(item, dict)
    }
    try:
        with connect(db_path) as conn:
            rows = conn.execute(
                "SELECT rule_id,cve_id,parser_family,evidence_type,evidence_key,value_equals_json,"
                "coverage_domain,source_name,source_url,evidence_basis,confidence,verified,group_id,group_operator "
                "FROM evidence_rules WHERE enabled=1 ORDER BY cve_id,group_id,rule_id"
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table: evidence_rules" not in str(exc).lower():
            raise
        return {
            "parser_family": family, "rule_count": 0, "cve_results": [],
            "status": "rule_store_unavailable",
            "interpretation": "The local database has not been upgraded to the evidence-rule schema. Run init-db or use the CLI, which performs the schema upgrade.",
        }

    by_cve: dict[str, dict[str, Any]] = {}
    applicable_rows = [dict(row) for row in rows if row["parser_family"] == family]
    for rule in applicable_rows:
        item = by_cve.setdefault(rule["cve_id"], {
            "cve_id": rule["cve_id"], "status": "NO_MATCH", "matched_rules": [],
            "unmatched_rules": [], "coverage": {}, "_groups": {},
        })
        key = (rule["evidence_type"], rule["evidence_key"])
        observation = observed.get(key)
        expected_text = rule.get("value_equals_json")
        expected = json.loads(expected_text) if expected_text is not None else None
        matches = observation is not None and (
            expected_text is None or _same_value(expected, observation.get("value"))
        )
        group_id = rule.get("group_id")
        group_key = str(group_id) if group_id else f"__single_rule__:{rule['rule_id']}"
        group_operator = str(rule.get("group_operator") or "OR").upper()
        group = item["_groups"].setdefault(group_key, {
            "group_id": group_id, "operator": group_operator, "members": [],
        })
        if matches:
            item["matched_rules"].append({
                "rule_id": rule["rule_id"], "group_id": group_id,
                "group_operator": group_operator if group_id else None,
                "evidence_id": observation.get("evidence_id"),
                "evidence_type": rule["evidence_type"], "evidence_key": rule["evidence_key"],
                "observed_value": observation.get("value"), "source_name": rule["source_name"],
                "source_url": rule["source_url"], "evidence_basis": rule["evidence_basis"],
                "confidence": rule["confidence"], "verified": bool(rule["verified"]),
            })
            group["members"].append({"rule_id": rule["rule_id"], "matched": True, "coverage_status": "observed"})
        else:
            coverage = _coverage_status(report, rule.get("coverage_domain"))
            item["coverage"][rule["coverage_domain"] or "unspecified"] = coverage
            item["unmatched_rules"].append({
                "rule_id": rule["rule_id"], "group_id": group_id,
                "group_operator": group_operator if group_id else None,
                "evidence_type": rule["evidence_type"], "evidence_key": rule["evidence_key"],
                "coverage_domain": rule["coverage_domain"], "coverage_status": coverage,
            })
            group["members"].append({"rule_id": rule["rule_id"], "matched": False, "coverage_status": coverage})

    for item in by_cve.values():
        group_results = []
        for group in item["_groups"].values():
            members = group["members"]
            matched_count = sum(1 for member in members if member["matched"])
            unmatched = [member for member in members if not member["matched"]]
            if group["operator"] == "AND":
                if matched_count == len(members):
                    group_status = "MATCH"
                elif any(member["coverage_status"] == "complete" for member in unmatched):
                    group_status = "NO_MATCH"
                else:
                    group_status = "UNKNOWN"
            elif matched_count:
                group_status = "MATCH"
            elif unmatched and all(member["coverage_status"] == "complete" for member in unmatched):
                group_status = "NO_MATCH"
            else:
                group_status = "UNKNOWN"
            group_results.append({
                "group_id": group["group_id"], "operator": group["operator"],
                "status": group_status, "member_count": len(members),
                "matched_rule_count": matched_count, "unmatched_rule_count": len(unmatched),
                "members": members,
            })
        item["rule_groups"] = group_results
        if any(group["status"] == "MATCH" for group in group_results):
            item["status"] = "MATCH"
        elif any(group["status"] == "UNKNOWN" for group in group_results):
            item["status"] = "UNKNOWN"
        else:
            item["status"] = "NO_MATCH"
        matched = item["matched_rules"]
        successful_group_keys = {
            str(group["group_id"]) if group.get("group_id") else
            f"__single_rule__:{group['members'][0]['rule_id']}"
            for group in group_results
            if group["status"] == "MATCH"
        }
        validated_matches = [
            rule for rule in matched
            if (
                str(rule.get("group_id")) if rule.get("group_id") else
                f"__single_rule__:{rule['rule_id']}"
            ) in successful_group_keys
        ]
        verified_matches = [rule for rule in validated_matches if rule.get("verified") is True]
        unverified_matches = [rule for rule in validated_matches if rule.get("verified") is not True]
        item["validation_status"] = (
            "mixed_verified_and_unverified" if verified_matches and unverified_matches else
            "verified" if verified_matches else "unverified" if unverified_matches else "not_applicable"
        )
        item["verified_match_count"] = len(verified_matches)
        item["unverified_match_count"] = len(unverified_matches)
        item.pop("_groups", None)
        item["interpretation"] = (
            (
                "One or more configured evidence groups matched. At least one matching rule is independently marked verified; this is not proof of exploitability."
                if verified_matches else
                "One or more configured evidence groups matched, but none of the matching rules is independently marked verified. Treat this as an unverified configured match, not a validated CVE relationship."
            ) if item["status"] == "MATCH" else
            "No configured evidence group matched, and at least one required observation had incomplete or unavailable parser coverage; absence is not established."
            if item["status"] == "UNKNOWN" else
            "No configured evidence group matched and all required absent observations were within declared complete parser coverage."
        )
    return {
        "parser_family": family, "rule_count": len(applicable_rows),
        "cve_results": sorted(by_cve.values(), key=lambda item: item["cve_id"]),
        "interpretation": "Rules are analyst-curated source-backed relationships. Optional rule groups support explicit AND/OR observation logic; they do not infer CVE relevance from generic document features.",
    }
