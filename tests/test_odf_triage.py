import tempfile
import unittest
import zipfile
from pathlib import Path

from cvevident.odf_triage import analyze_opendocument, is_opendocument_package

MIME = "application/vnd.oasis.opendocument.text"
MANIFEST = '''<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>'''
CONTENT = '''<office:document-content
 xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
 xmlns:xlink="http://www.w3.org/1999/xlink"
 xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"
 xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0">
 <office:scripts><script:event-listener script:event-name="dom:load"/></office:scripts>
 <office:body><office:text><text:p><text:a xlink:href="https://example.test/remote">link</text:a></text:p></office:text>
 <table:table><table:table-cell table:formula="of:=WEBSERVICE(&quot;https://example.test/data&quot;)"/></table:table></office:body>
</office:document-content>'''


def build_odf(mimetype=MIME, content=CONTENT, *, manifest=MANIFEST, extra_members=(), unsafe_name=None, compress_mimetype=False):
    import io
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("mimetype", mimetype,
                         compress_type=zipfile.ZIP_DEFLATED if compress_mimetype else zipfile.ZIP_STORED)
        archive.writestr("META-INF/manifest.xml", manifest, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("content.xml", content, compress_type=zipfile.ZIP_DEFLATED)
        for name, value in extra_members:
            archive.writestr(name, value, compress_type=zipfile.ZIP_DEFLATED)
        if unsafe_name:
            archive.writestr(unsafe_name, b"not extracted", compress_type=zipfile.ZIP_DEFLATED)
    return stream.getvalue()


class OdfTriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, name, data, **kwargs):
        path = self.root / name
        path.write_bytes(data)
        return analyze_opendocument(str(path), **kwargs)

    def test_detects_odt_and_static_indicators(self):
        data = build_odf(extra_members=[("Basic/Standard/Module1.xml", b"synthetic macro text"),
                                        ("Objects/Object 1/content.xml", b"<object/>")])
        report = self.analyze("sample.odt", data)
        self.assertTrue(is_opendocument_package(data))
        self.assertEqual(report["file"]["file_type"], "odt")
        self.assertEqual(report["odf_analysis"]["status"], "parsed")
        self.assertGreater(report["odf_analysis"]["features"]["script_event_listener_count"], 0)
        self.assertGreater(report["odf_analysis"]["features"]["external_reference_count"], 0)
        self.assertTrue(any(key.startswith("odf.external_references") for key in [e["key"] for e in report["evidence"]]))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_supports_spreadsheet_and_presentation_mimetypes(self):
        for extension, mime in (("ods", "application/vnd.oasis.opendocument.spreadsheet"),
                                ("ots", "application/vnd.oasis.opendocument.spreadsheet-template"),
                                ("odp", "application/vnd.oasis.opendocument.presentation"),
                                ("otp", "application/vnd.oasis.opendocument.presentation-template"),
                                ("ott", "application/vnd.oasis.opendocument.text-template")):
            with self.subTest(extension=extension):
                report = self.analyze(f"sample.{extension}", build_odf(mimetype=mime))
                self.assertEqual(report["file"]["file_type"], extension)
                self.assertEqual(report["odf_analysis"]["status"], "parsed")

    def test_extension_mismatch_is_reported(self):
        report = self.analyze("misnamed.ods", build_odf(mimetype=MIME))
        self.assertEqual(report["file"]["file_type"], "odt")
        self.assertFalse(report["odf_analysis"]["extension_matches_detected_format"])
        self.assertEqual(report["odf_analysis"]["status"], "partial")

    def test_corrupt_odf_is_failed(self):
        report = self.analyze("bad.odt", b"not a zip file")
        self.assertEqual(report["odf_analysis"]["status"], "failed")

    def test_missing_mimetype_is_unsupported(self):
        import io
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("content.xml", CONTENT)
        report = self.analyze("no-mimetype.odt", stream.getvalue())
        self.assertEqual(report["odf_analysis"]["status"], "unsupported")

    def test_unsafe_path_marks_partial_without_extraction(self):
        report = self.analyze("unsafe.odt", build_odf(unsafe_name="../escape.txt"))
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("traversal-like" in warning for warning in report["warnings"]))

    def test_compressed_mimetype_marks_partial(self):
        report = self.analyze("compressed-mimetype.odt", build_odf(compress_mimetype=True))
        self.assertEqual(report["odf_analysis"]["status"], "partial")

    def test_dtd_entity_content_is_not_parsed(self):
        hostile_xml = b'<!DOCTYPE x [<!ENTITY e "expanded">]><office:document-content>&e;</office:document-content>'
        report = self.analyze("entity.odt", build_odf(content=hostile_xml))
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertTrue(any("DTD/entity declarations" in warning for warning in report["warnings"]))

    def test_manifest_declared_encryption_is_reported_not_decrypted(self):
        manifest_xml = (
            '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml">'
            '<manifest:encryption-data manifest:checksum="synthetic"/>'
            '</manifest:file-entry></manifest:manifest>'
        )
        report = self.analyze("encrypted.odt", build_odf(manifest=manifest_xml))
        self.assertEqual(report["odf_analysis"]["status"], "partial")
        self.assertGreater(report["odf_analysis"]["features"]["encrypted_member_manifest_entry_count"], 0)
        self.assertTrue(any("not decrypted" in warning for warning in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
