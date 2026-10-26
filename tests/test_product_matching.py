from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvevident.cli import build_parser, main
from cvevident.db import connect, init_db
from cvevident.evidence_engine import build_cve_associations, build_product_context
from cvevident.product_matching import (
    assess_version_context,
    cpe23_components,
    normalize_product_text,
    split_product_version,
)
from cvevident.store import (
    get_source_freshness,
    import_epss_csv,
    import_kev_json,
    import_nvd_json,
    search_product_cves,
)


class ProductMatchingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "match.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def nvd_payload(self, *, cve_id="CVE-2099-12345", vendor="apache", product="log4j",
                    criteria_version="*", start_including=None, start_excluding=None,
                    end_including="2.0", end_excluding=None, vulnerable=True):
        match = {
            "criteria": f"cpe:2.3:a:{vendor}:{product}:{criteria_version}:*:*:*:*:*:*:*",
            "vulnerable": vulnerable,
        }
        for key, value in (
            ("versionStartIncluding", start_including),
            ("versionStartExcluding", start_excluding),
            ("versionEndIncluding", end_including),
            ("versionEndExcluding", end_excluding),
        ):
            if value is not None:
                match[key] = value
        return {"vulnerabilities": [{"cve": {
            "id": cve_id,
            "published": "2099-01-01T00:00:00.000Z",
            "lastModified": "2099-01-02T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Synthetic product matching test"}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}],
        }}]}

    def import_payload(self, name: str, payload: object) -> int:
        return import_nvd_json(self.write_json(name, payload), self.db)

    def test_product_normalization_is_case_and_punctuation_insensitive(self):
        self.assertEqual(normalize_product_text("  Apache_Log4J-Core "), "apache log4j core")
        name, version, method = split_product_version("Apache Log4J 2.14.1")
        self.assertEqual(name, "Apache Log4J")
        self.assertEqual(version, "2.14.1")
        self.assertEqual(method, "trailing_version_in_query")
        name2, version2, method2 = split_product_version("Apache Log4J 2.14.1", "2.14.1")
        self.assertEqual(name2, "Apache Log4J")
        self.assertEqual(version2, "2.14.1")
        self.assertEqual(method2, "explicit_option")

    def test_cpe23_parser_handles_escaped_colon_in_component(self):
        parsed = cpe23_components(r"cpe:2.3:a:acme:log\:manager:1.2:*:*:*:*:*:*:*")
        self.assertEqual(parsed["vendor"], "acme")
        self.assertEqual(parsed["product"], "log:manager")
        self.assertEqual(parsed["version"], "1.2")

    def test_exact_vendor_product_and_token_boundaries(self):
        payload = {"vulnerabilities": []}
        payload["vulnerabilities"].extend(self.nvd_payload(
            cve_id="CVE-2099-12345", vendor="acme", product="app", criteria_version="*"
        )["vulnerabilities"])
        payload["vulnerabilities"].extend(self.nvd_payload(
            cve_id="CVE-2099-12346", vendor="acme", product="application", criteria_version="*"
        )["vulnerabilities"])
        self.import_payload("tokens.json", payload)

        results = search_product_cves("APP", self.db)
        self.assertEqual([row["cve_id"] for row in results], ["CVE-2099-12345"])
        self.assertEqual(results[0]["name_match_class"], "all_query_terms_match")

    def test_search_finds_product_with_escaped_colon_in_cpe_name(self):
        payload = self.nvd_payload(
            vendor="acme", product=r"log\:manager", criteria_version="*"
        )
        self.import_payload("escaped-product.json", payload)

        results = search_product_cves("log manager", self.db)
        self.assertEqual([row["cve_id"] for row in results], ["CVE-2099-12345"])
        self.assertEqual(results[0]["name_match_class"], "all_query_terms_match")

    def test_vendor_only_overlap_remains_context_not_file_attribution(self):
        self.import_payload(
            "vendor-only.json",
            self.nvd_payload(vendor="apache", product="log4j", criteria_version="*"),
        )

        results = search_product_cves("apache", self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name_match_class"], "vendor_only_match")
        self.assertEqual(
            results[0]["assessment"],
            "product_context_candidate_not_file_attribution",
        )

    def test_vendor_filter_disambiguates_same_product_name(self):
        payload = {"vulnerabilities": []}
        payload["vulnerabilities"].extend(self.nvd_payload(
            cve_id="CVE-2099-12345", vendor="apache", product="log4j", criteria_version="*"
        )["vulnerabilities"])
        payload["vulnerabilities"].extend(self.nvd_payload(
            cve_id="CVE-2099-12346", vendor="example", product="log4j", criteria_version="*"
        )["vulnerabilities"])
        self.import_payload("vendors.json", payload)

        all_results = search_product_cves("log4j", self.db)
        self.assertEqual(len(all_results), 2)
        self.assertEqual(all_results[0]["query_ambiguity"]["status"], "ambiguous_multiple_product_identities")
        narrowed = search_product_cves("log4j", self.db, vendor="Apache")
        self.assertEqual([row["cve_id"] for row in narrowed], ["CVE-2099-12345"])

    def test_explicit_version_inside_numeric_range_is_classified_not_attributed(self):
        payload = self.nvd_payload(
            criteria_version="*", start_including="1.0", end_excluding="2.0"
        )
        self.import_payload("range.json", payload)

        result = search_product_cves("apache log4j", self.db, version="1.5")[0]
        self.assertEqual(result["version_match_status"], "within_declared_numeric_version_bounds")
        self.assertFalse(result["version_context"]["full_nvd_configuration_evaluated"])
        self.assertEqual(result["assessment"], "product_context_candidate_not_file_attribution")

    def test_version_outside_declared_range_is_reported_as_context(self):
        payload = self.nvd_payload(
            criteria_version="*", start_including="1.0", end_excluding="2.0"
        )
        self.import_payload("range.json", payload)

        result = search_product_cves("apache log4j", self.db, version="2.0")[0]
        self.assertEqual(result["version_match_status"], "outside_declared_numeric_version_bounds")
        self.assertIn("outside", result["version_context"]["interpretation"])

    def test_exact_cpe_version_mismatch_does_not_get_called_a_version_match(self):
        payload = self.nvd_payload(criteria_version="1.0", end_including=None)
        self.import_payload("exact.json", payload)
        result = search_product_cves("apache log4j", self.db, version="1.5")[0]
        self.assertEqual(result["version_match_status"], "exact_cpe_version_mismatch")

    def test_equivalent_numeric_versions_with_trailing_zero_components_match(self):
        self.import_payload("equivalent-versions.json", self.nvd_payload(criteria_version="2.0"))
        result = search_product_cves("apache log4j", self.db, version="2.0.0")[0]
        self.assertEqual(result["version_match_status"], "exact_cpe_version_match")

    def test_unsupported_version_syntax_is_indeterminate(self):
        payload = self.nvd_payload(
            criteria_version="*", start_including="1.0-beta", end_excluding="2.0"
        )
        self.import_payload("unsupported-version.json", payload)
        result = search_product_cves("apache log4j", self.db, version="1.5")[0]
        self.assertEqual(result["version_match_status"], "range_comparison_indeterminate")

    def test_no_version_is_explicitly_reported_as_not_evaluated(self):
        self.import_payload("no-version.json", self.nvd_payload(criteria_version="*"))
        result = search_product_cves("apache log4j", self.db)[0]
        self.assertEqual(result["version_match_status"], "range_metadata_available_target_version_missing")
        self.assertIn("no target version was supplied", result["version_context"]["interpretation"])

    def test_version_equal_to_inclusive_lower_bound_is_within_declared_range(self):
        payload = self.nvd_payload(
            criteria_version="*", start_including="1.0", end_excluding="2.0"
        )
        self.import_payload("inclusive-lower.json", payload)
        result = search_product_cves("apache log4j", self.db, version="1.0")[0]
        self.assertEqual(result["version_match_status"], "within_declared_numeric_version_bounds")

    def test_version_equal_to_exclusive_lower_bound_is_outside_declared_range(self):
        payload = self.nvd_payload(
            criteria_version="*", start_excluding="1.0", end_including="2.0"
        )
        self.import_payload("exclusive-lower.json", payload)
        result = search_product_cves("apache log4j", self.db, version="1.0")[0]
        self.assertEqual(result["version_match_status"], "outside_declared_numeric_version_bounds")

    def test_version_equal_to_inclusive_upper_bound_is_within_declared_range(self):
        payload = self.nvd_payload(
            criteria_version="*", start_including="1.0", end_including="2.0"
        )
        self.import_payload("inclusive-upper.json", payload)
        result = search_product_cves("apache log4j", self.db, version="2.0")[0]
        self.assertEqual(result["version_match_status"], "within_declared_numeric_version_bounds")

    def test_source_freshness_separates_nvd_kev_and_epss(self):
        self.import_payload("nvd.json", self.nvd_payload(criteria_version="*"))
        kev = self.write_json("kev.json", {"vulnerabilities": [{
            "cveID": "CVE-2099-12345", "dateAdded": "2099-01-03",
            "shortDescription": "Synthetic KEV entry", "requiredAction": "Patch"
        }]})
        import_kev_json(kev, self.db)
        epss = self.root / "epss.csv"
        epss.write_text("cve,epss,percentile\nCVE-2099-12345,0.42,0.91\n", encoding="utf-8")
        import_epss_csv(epss, self.db)

        freshness = get_source_freshness(self.db)
        self.assertEqual(freshness["sources"]["NVD"]["state"], "available_from_local_import")
        self.assertEqual(freshness["sources"]["CISA KEV"]["state"], "available_from_local_import")
        self.assertEqual(freshness["sources"]["FIRST EPSS"]["state"], "available_from_local_import")
        result = search_product_cves("apache log4j", self.db)[0]
        self.assertEqual(result["local_source_signals"]["CISA KEV"]["state"], "listed_in_local_kev_snapshot")
        self.assertEqual(result["local_source_signals"]["FIRST EPSS"]["score"], 0.42)

    def test_missing_kev_epss_imports_are_unknown_not_a_negative_claim(self):
        self.import_payload("nvd.json", self.nvd_payload(criteria_version="*"))
        result = search_product_cves("apache log4j", self.db)[0]
        signals = result["local_source_signals"]
        self.assertEqual(signals["CISA KEV"]["state"], "unknown_no_successful_local_kev_import")
        self.assertEqual(signals["FIRST EPSS"]["state"], "unknown_no_successful_local_epss_import")

    def test_product_context_explains_ranking_signals_and_order(self):
        self.import_payload(
            "ranking-explanation.json",
            self.nvd_payload(vendor="apache", product="log4j", criteria_version="*"),
        )
        result = search_product_cves("apache log4j", self.db)[0]
        explanation = result["ranking_explanation"]
        self.assertEqual(explanation["name_match_class"], result["name_match_class"])
        self.assertEqual(explanation["matching_vendor_terms"], result["matching_vendor_terms"])
        self.assertEqual(explanation["matching_product_terms"], result["matching_product_terms"])
        self.assertEqual(explanation["product_relevance_score"], result["product_relevance_score"])
        self.assertEqual(
            explanation["ordered_by"],
            ["name_match_class_desc", "product_relevance_score_desc",
             "cisa_kev_true_first", "epss_score_desc", "cve_id_asc"],
        )
        self.assertIn("retrieval relevance", explanation["interpretation"])

    def test_applicability_context_separates_nvd_flag_from_file_vulnerability(self):
        self.import_payload(
            "applicability-context.json",
            self.nvd_payload(vendor="apache", product="log4j", criteria_version="*"),
        )
        result = search_product_cves("apache log4j", self.db)[0]
        context = result["applicability_context"]
        self.assertTrue(context["nvd_cpe_vulnerable_flag"])
        self.assertFalse(context["nested_configuration_evaluated"])
        self.assertFalse(context["file_vulnerability_established"])
        self.assertEqual(
            result["assessment"],
            "product_context_candidate_not_file_attribution",
        )

    def test_product_context_carries_query_version_ambiguity_and_freshness(self):
        self.import_payload("range.json", self.nvd_payload(criteria_version="*", start_including="1.0", end_excluding="2.0"))
        context = build_product_context("Apache Log4j 1.5", str(self.db), 10)
        self.assertEqual(context["target_product"], "Apache Log4j")
        self.assertEqual(context["target_version"], "1.5")
        self.assertEqual(context["version_input_method"], "trailing_version_in_query")
        self.assertIn("sources", context["source_freshness"])
        self.assertIn("not_performed_nested_NVD_AND_OR_logic_and_platform_conditions_not_evaluated", context["configuration_evaluation"])

    def test_same_cve_keeps_multiple_matching_cpe_rows_and_version_context(self):
        wildcard = self.nvd_payload(criteria_version="*", end_including=None)["vulnerabilities"][0]
        concrete = self.nvd_payload(criteria_version="1.0", end_including=None)["vulnerabilities"][0]
        concrete_match = concrete["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
        wildcard["cve"]["configurations"][0]["nodes"][0]["cpeMatch"].append(concrete_match)
        self.import_payload("multiple-rows.json", {"vulnerabilities": [wildcard]})

        result = search_product_cves("apache log4j", self.db, version="1.0")[0]
        self.assertEqual(result["matched_cpe_row_count"], 2)
        self.assertEqual(
            {row["version_match_status"] for row in result["matching_product_rows"]},
            {"wildcard_cpe_version", "exact_cpe_version_match"},
        )
        self.assertEqual(result["version_match_status"], "exact_cpe_version_match")

    def test_exact_sample_and_product_context_keep_distinct_association_bases(self):
        sample_matches = [{
            "sample_id": "SAMPLE-1",
            "label": "reported-exploit-sample",
            "confidence": "medium",
            "label_basis": "source report",
            "source_name": "Synthetic source",
            "source_url": "https://example.invalid/sample-source",
            "cve_links": [{
                "cve_id": "CVE-2021-44228",
                "association_type": "reported",
                "confidence": "low",
                "verified": False,
                "evidence_basis": "reported mapping",
                "source_url": "https://example.invalid/cve-mapping",
            }],
        }]
        target_context = {
            "target_product": "log4j",
            "retrieval_method": "normalized_vendor_product_token_overlap_against_local_NVD_CPE_rows",
            "candidate_cves": [{
                "cve_id": "CVE-2021-44228",
                "matched_vendor": "apache",
                "matched_product": "log4j",
                "matched_criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                "matching_query_terms": ["log4j"],
                "product_relevance_score": 100.0,
                "cpe_vulnerable": True,
                "version_context": {"status": "wildcard_cpe_version"},
                "version_match_status": "wildcard_cpe_version",
                "local_source_signals": {},
            }],
        }
        association = build_cve_associations(sample_matches, target_context)[0]
        bases = {item["type"]: item for item in association["association_bases"]}

        self.assertEqual(set(bases), {"exact_sha256_sample_match", "product_context"})
        self.assertFalse(bases["exact_sha256_sample_match"]["link_verified"])
        self.assertEqual(bases["product_context"]["score_semantics"], "lexical_product_retrieval_score_not_probability")
        self.assertEqual(association["assessment"], "exact_sample_link_and_product_context_not_proof_of_exploitability")

    def test_analyze_and_batch_cli_accept_explicit_vendor_and_version(self):
        parser = build_parser()
        analyze_args = parser.parse_args([
            "analyze", "sample.pdf", "--target-product", "log4j",
            "--target-vendor", "apache", "--target-version", "1.5",
        ])
        self.assertEqual(analyze_args.target_vendor, "apache")
        self.assertEqual(analyze_args.target_version, "1.5")

        batch_args = parser.parse_args([
            "analyze-batch", "sample.pdf", "--target-product", "log4j",
            "--target-vendor", "apache", "--target-version", "1.5",
        ])
        self.assertEqual(batch_args.target_vendor, "apache")
        self.assertEqual(batch_args.target_version, "1.5")

    def test_search_product_cli_exposes_version_vendor_and_freshness(self):
        self.import_payload("range.json", self.nvd_payload(criteria_version="*", start_including="1.0", end_excluding="2.0"))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main([
                "--db", str(self.db), "search-product", "log4j",
                "--vendor", "apache", "--version", "1.5",
            ])
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["vendor_filter"], "apache")
        self.assertEqual(payload["results"][0]["version_match_status"], "within_declared_numeric_version_bounds")
        self.assertIn("source_freshness", payload)


if __name__ == "__main__":
    unittest.main()
