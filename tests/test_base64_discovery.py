import base64
import hashlib
import unittest

from cvevident.base64_discovery import discover_base64_candidates


class Base64DiscoveryTests(unittest.TestCase):
    def test_decodes_embedded_pdf_candidate_and_reports_source_offsets(self):
        payload = b"%PDF-1.7\\n" + bytes(range(64))
        encoded = base64.b64encode(payload)
        prefix = b"prefix:"
        suffix = b":suffix"
        data = prefix + encoded + suffix

        candidates = discover_base64_candidates(data)

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]

        self.assertEqual(candidate["decode_status"], "decoded")
        self.assertEqual(candidate["source_offset_start"], len(prefix))
        self.assertEqual(
            candidate["source_offset_end"],
            len(prefix) + len(encoded),
        )
        self.assertEqual(candidate["encoded_length"], len(encoded))
        self.assertEqual(candidate["decoded_length"], len(payload))
        self.assertEqual(candidate["payload_kind"], "pdf")
        self.assertEqual(candidate["payload_signature"], "%PDF-")
        self.assertEqual(
            candidate["decoded_sha256"],
            hashlib.sha256(payload).hexdigest(),
        )


    def test_unpadded_candidate_enforces_decoded_size_limit(self):
        payload = b"X" * 65
        encoded = base64.b64encode(payload).rstrip(b"=")

        candidates = discover_base64_candidates(
            encoded,
            max_decoded_bytes=64,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["decode_status"],
            "skipped_decoded_size_limit",
        )
        self.assertIsNone(candidates[0]["decoded_length"])


    def test_decodes_urlsafe_base64_candidate(self):
        payload = bytes(range(256))
        encoded = base64.urlsafe_b64encode(payload)
        self.assertTrue(b"-" in encoded or b"_" in encoded)

        candidates = discover_base64_candidates(
            b"prefix:" + encoded + b":suffix"
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["decode_status"], "decoded")
        self.assertEqual(candidates[0]["encoding"], "base64url")
        self.assertEqual(
            candidates[0]["decoded_sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(
            candidates[0]["payload_identification_status"],
            "unrecognized",
        )

    def test_decodes_base64_with_line_breaks_and_tabs(self):
        payload = b"%PDF-1.7\n" + bytes(range(64))
        encoded = base64.b64encode(payload)
        prefix = b"data:\t"
        wrapped = b"\r\n".join(
            encoded[index:index + 20]
            for index in range(0, len(encoded), 20)
        )
        candidates = discover_base64_candidates(prefix + wrapped)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["decode_status"], "decoded")
        self.assertEqual(candidates[0]["payload_kind"], "pdf")
        self.assertEqual(candidates[0]["source_offset_start"], len(prefix))
        self.assertEqual(
            candidates[0]["source_offset_end"],
            len(prefix) + len(wrapped),
        )

    def test_rejects_candidate_with_excessive_padding(self):
        candidates = discover_base64_candidates(b"A" * 32 + b"===")

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["decode_status"],
            "invalid_base64",
        )

    def test_rejects_mixed_standard_and_urlsafe_alphabets(self):
        standard = base64.b64encode(bytes(range(256)))
        self.assertIn(b"+", standard)
        mixed = standard.replace(b"+", b"-", 1)
        self.assertIn(b"/", mixed)

        candidates = discover_base64_candidates(mixed)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["decode_status"],
            "invalid_base64",
        )

    def test_enforces_candidate_count_limit(self):
        data = b"A" * 64 + b"!" + b"B" * 64

        candidates = discover_base64_candidates(
            data,
            max_candidates=1,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["candidate_index"], 1)

    def test_enforces_encoded_size_limit(self):
        candidates = discover_base64_candidates(
            b"A" * 64,
            max_encoded_bytes=32,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["decode_status"],
            "skipped_encoded_size_limit",
        )
        self.assertIsNone(candidates[0]["decoded_sha256"])

    def test_enforces_total_decoded_size_limit(self):
        encoded = base64.b64encode(b"\x00" * 48)
        candidates = discover_base64_candidates(
            encoded + b"!" + encoded,
            max_total_decoded_bytes=64,
        )

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0]["decode_status"], "decoded")
        self.assertEqual(candidates[0]["decoded_length"], 48)
        self.assertEqual(
            candidates[1]["decode_status"],
            "skipped_total_decode_limit",
        )


    def test_rejects_oversized_candidate_before_copying_its_bytes(self):
        import tracemalloc

        data = b"A" * (4 * 1024 * 1024)
        view = memoryview(data)

        tracemalloc.start()
        try:
            candidates = discover_base64_candidates(
                view,
                max_encoded_bytes=64,
            )
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["decode_status"],
            "skipped_encoded_size_limit",
        )
        self.assertLess(peak_bytes, 1024 * 1024)


    def test_preserves_candidates_across_chunk_boundaries(self):
        payload = b"X" * 6000
        encoded = base64.b64encode(payload)

        cases = (
            (
                b"!" * 4096 + encoded + b"!",
                4096,
                4096 + len(encoded),
            ),
            (
                b"prefix:" + encoded[:4088] + b"\r\n"
                + encoded[4088:] + b":suffix",
                7,
                7 + len(encoded) + 2,
            ),
        )

        for data, expected_start, expected_end in cases:
            with self.subTest(expected_start=expected_start):
                candidates = discover_base64_candidates(data)

                self.assertEqual(len(candidates), 1)
                self.assertEqual(
                    candidates[0]["source_offset_start"],
                    expected_start,
                )
                self.assertEqual(
                    candidates[0]["source_offset_end"],
                    expected_end,
                )
                self.assertEqual(
                    candidates[0]["encoded_length"],
                    len(encoded),
                )
                self.assertEqual(
                    candidates[0]["decode_status"],
                    "decoded",
                )
                self.assertEqual(
                    candidates[0]["decoded_length"],
                    len(payload),
                )


if __name__ == "__main__":
    unittest.main()
