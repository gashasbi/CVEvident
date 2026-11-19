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
                "coverage_domain,source_name,source_url,evidence_basis,confidence,verified "
                "FROM evidence_rules WHERE enabled=1 ORDER BY cve_id,rule_id"
            ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table: evidence_rules" not in str(exc).lower():
            raise
        return {
            "parser_family": family,
            "rule_count": 0,
            "cve_results": [],
            "status": "rule_store_unavailable",
            "interpretation": "The local database has not been upgraded to the evidence-rule schema. Run init-db or use the CLI, which performs the schema upgrade.",
        }
    by_cve: dict[str, dict[str, Any]] = {}
    for row in rows:
        rule = dict(row)
        if rule["parser_family"] != family:
            continue
        item = by_cve.setdefault(rule["cve_id"], {
            "cve_id": rule["cve_id"],
            "status": "NO_MATCH",
            "matched_rules": [],
            "unmatched_rules": [],
            "coverage": {},
        })
        key = (rule["evidence_type"], rule["evidence_key"])
        observation = observed.get(key)
        expected_text = rule.get("value_equals_json")
        expected = json.loads(expected_text) if expected_text is not None else None
        matches = observation is not None and (
            expected_text is None or _same_value(expected, observation.get("value"))
        )
        if matches:
            item["matched_rules"].append({
                "rule_id": rule["rule_id"],
                "evidence_id": observation.get("evidence_id"),
                "evidence_type": rule["evidence_type"],
                "evidence_key": rule["evidence_key"],
                "observed_value": observation.get("value"),
                "source_name": rule["source_name"],
                "source_url": rule["source_url"],
                "evidence_basis": rule["evidence_basis"],
                "confidence": rule["confidence"],
                "verified": bool(rule["verified"]),
            })
            item["status"] = "MATCH"
        else:
            coverage = _coverage_status(report, rule.get("coverage_domain"))
            item["coverage"][rule["coverage_domain"] or "unspecified"] = coverage
            item["unmatched_rules"].append({
                "rule_id": rule["rule_id"],
                "evidence_type": rule["evidence_type"],
                "evidence_key": rule["evidence_key"],
                "coverage_domain": rule["coverage_domain"],
                "coverage_status": coverage,
            })
            if coverage != "complete" and item["status"] != "MATCH":
                item["status"] = "UNKNOWN"
    for item in by_cve.values():
        matched = item["matched_rules"]
        verified_matches = [rule for rule in matched if rule.get("verified") is True]
        unverified_matches = [rule for rule in matched if rule.get("verified") is not True]
        item["validation_status"] = (
            "mixed_verified_and_unverified"
            if verified_matches and unverified_matches else
            "verified"
            if verified_matches else
            "unverified"
            if matched else
            "not_applicable"
        )
        item["verified_match_count"] = len(verified_matches)
        item["unverified_match_count"] = len(unverified_matches)
        item["interpretation"] = (
            (
                "One or more exact source-backed parser rules matched. At least one matching rule is independently marked verified; this is not proof of exploitability."
                if verified_matches else
                "One or more exact parser rules matched, but none is independently marked verified. Treat this as an unverified configured match, not a validated CVE relationship."
            )
            if item["status"] == "MATCH" else
            "No configured rule matched, and parser coverage is incomplete or unavailable; absence of the observation is not established."
            if item["status"] == "UNKNOWN" else
            "No configured rule matched and the declared parser coverage for the configured rule domains is complete."
        )
    return {
        "parser_family": family,
        "rule_count": len(rows),
        "cve_results": sorted(by_cve.values(), key=lambda item: item["cve_id"]),
        "interpretation": "Rules are analyst-curated source-backed relationships. They do not infer CVE relevance from generic document features.",
    }
