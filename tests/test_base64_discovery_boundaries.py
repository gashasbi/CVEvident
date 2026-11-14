import base64
import unittest
from types import SimpleNamespace

from cvevident.base64_discovery import (
    Base64XmlEvidenceScanner,
    discover_base64_candidates,
)


class Base64ChunkBoundaryTests(unittest.TestCase):
    def test_padding_starting_at_chunk_boundary_is_preserved(self):
        chunk_size = 4096

        for padding_count in (1, 2):
            with self.subTest(padding_count=padding_count):
                payload = None
                encoded = None

                for filler_length in range(128):
                    candidate_payload = b"%PDF-1.7\n" + b"A" * filler_length
                    candidate_encoded = base64.b64encode(candidate_payload)
                    actual_padding = len(candidate_encoded) - len(
                        candidate_encoded.rstrip(b"=")
                    )

                    if actual_padding == padding_count and len(candidate_encoded) >= 32:
                        payload = candidate_payload
                        encoded = candidate_encoded
                        break

                self.assertIsNotNone(payload)
                self.assertIsNotNone(encoded)

                candidate_start = chunk_size - (
                    len(encoded) - padding_count
                )
                data = b"!" * candidate_start + encoded + b"!"

                results = discover_base64_candidates(data)

                self.assertEqual(len(results), 1)
                self.assertEqual(
                    results[0]["source_offset_start"],
                    candidate_start,
                )
                self.assertEqual(
                    results[0]["source_offset_end"],
                    candidate_start + len(encoded),
                )
                self.assertEqual(
                    results[0]["encoded_length"],
                    len(encoded),
                )
                self.assertEqual(
                    results[0]["decoded_length"],
                    len(payload),
                )
                self.assertEqual(results[0]["decode_status"], "decoded")

    def test_crlf_crossing_chunk_boundary_is_preserved(self):
        chunk_size = 4096
        payload = b"%PDF-1.7\n" + b"C" * 80
        encoded = base64.b64encode(payload)

        candidate_start = 4000
        split_offset = chunk_size - candidate_start - 1

        self.assertGreater(split_offset, 0)
        self.assertLess(split_offset, len(encoded))

        data = (
            b"!" * candidate_start
            + encoded[:split_offset]
            + b"\r\n"
            + encoded[split_offset:]
            + b"!"
        )

        results = discover_base64_candidates(data)

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["source_offset_start"],
            candidate_start,
        )
        self.assertEqual(
            results[0]["source_offset_end"],
            candidate_start + len(encoded) + 2,
        )
        self.assertEqual(results[0]["encoded_length"], len(encoded))
        self.assertEqual(results[0]["decoded_length"], len(payload))
        self.assertEqual(results[0]["decode_status"], "decoded")

    def test_candidate_limit_counts_merged_candidates(self):
        payloads = (
            b"%PDF-1.7\n" + b"A" * 60,
            b"{\\rtf1 " + b"B" * 60,
            b"\x7fELF" + b"C" * 60,
        )

        encoded_candidates = [
            base64.b64encode(payload)
            for payload in payloads
        ]
        data = b"!" + b"!".join(encoded_candidates) + b"!"

        results = discover_base64_candidates(
            data,
            max_candidates=2,
        )

        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(item["decode_status"] == "decoded" for item in results)
        )

    def test_normal_document_prose_does_not_create_candidates(self):
        data = (
            b"This document contains ordinary prose. "
            b"It discusses application behavior, configuration, "
            b"security requirements, and deployment procedures. "
            b"No encoded attachment or binary payload is included."
        )

        results = discover_base64_candidates(data)

        self.assertEqual(results, [])


class Base64XmlUtf8BoundaryTests(unittest.TestCase):
    def test_utf8_byte_budget_truncation_is_detected(self):
        scanner = Base64XmlEvidenceScanner()
        scanner._scanned_bytes = 16 * 1024 * 1024 - 100
        node = SimpleNamespace(
            tag="{urn:test}text",
            text="é" * 80,
            tail=None,
            attrib={},
        )

        scanner.scan_node("word/document.xml", node)

        self.assertTrue(scanner.truncated)

    def test_utf8_value_within_byte_budget_is_not_truncated(self):
        scanner = Base64XmlEvidenceScanner()
        scanner._scanned_bytes = 16 * 1024 * 1024 - 200
        node = SimpleNamespace(
            tag="{urn:test}text",
            text="é" * 80,
            tail=None,
            attrib={},
        )

        scanner.scan_node("word/document.xml", node)

        self.assertFalse(scanner.truncated)


    def test_mmap_xml_scan_preserves_utf8_offsets_and_payload_evidence(self):
        payload = b"%PDF-1.7\\n" + b"A" * 256
        encoded = base64.b64encode(payload).decode("ascii")

        prefix = "é-prefix:"
        value = prefix + encoded + ":suffix"

        node = SimpleNamespace(
            tag="{urn:test}text",
            text=value,
            tail=None,
            attrib={},
        )

        scanner = Base64XmlEvidenceScanner()
        scanner.scan_node("word/document.xml", node)

        self.assertEqual(len(scanner.evidence), 1)

        evidence = scanner.evidence[0]
        details = evidence["details"]
        locator = details["source_locator"]

        expected_start = len(prefix.encode("utf-8"))
        expected_end = expected_start + len(encoded)

        self.assertEqual(
            evidence["evidence_type"],
            "embedded_base64_payload",
        )
        self.assertEqual(details["decode_status"], "decoded")
        self.assertEqual(details["payload_kind"], "pdf")
        self.assertEqual(
            locator["value_offset_start"],
            expected_start,
        )
        self.assertEqual(
            locator["value_offset_end"],
            expected_end,
        )
        self.assertEqual(
            locator["offset_basis"],
            "UTF-8 byte offsets within this XML text or attribute "
            "value, not offsets in the original package file.",
        )
        self.assertEqual(
            details["encoded_length"],
            len(encoded),
        )
        self.assertEqual(
            details["decoded_length"],
            len(payload),
        )


if __name__ == "__main__":
    unittest.main()
