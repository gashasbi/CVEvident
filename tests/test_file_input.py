from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from cvevident.file_input import get_file_identity, read_file, read_prefix_with_identity


class SharedFileInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reads_bytes_and_computes_identity(self):
        path = self.root / "sample.bin"
        payload = b"static sample bytes\x00"
        path.write_bytes(payload)

        result = read_file(path, max_bytes=1024)

        self.assertEqual(result.path, path)
        self.assertEqual(result.data, payload)
        self.assertEqual(result.size_bytes, len(payload))
        self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())

    def test_prefix_read_returns_the_opened_file_identity(self):
        path = self.root / "sample.bin"
        payload = b"static sample bytes"
        path.write_bytes(payload)

        prefix, identity = read_prefix_with_identity(path, size=6)

        self.assertEqual(prefix, payload[:6])
        self.assertEqual(identity, get_file_identity(path))

    def test_rejects_input_over_size_limit(self):
        path = self.root / "large.bin"
        path.write_bytes(b"A" * 10)

        with self.assertRaisesRegex(ValueError, "configured limit"):
            read_file(path, max_bytes=9)

    def test_rejects_nonpositive_limit(self):
        path = self.root / "sample.bin"
        path.write_bytes(b"A")

        with self.assertRaisesRegex(ValueError, "max_bytes must be positive"):
            read_file(path, max_bytes=0)

    def test_missing_file_is_reported(self):
        with self.assertRaises(FileNotFoundError):
            read_file(self.root / "missing.bin")


if __name__ == "__main__":
    unittest.main()
