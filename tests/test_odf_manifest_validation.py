from __future__ import annotations

import io
import zipfile

from cvevident.odf_triage import analyze_opendocument

MIME = "application/vnd.oasis.opendocument.text"
NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
CONTENT = (
    '<office:document-content '
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'
)


def _manifest(paths: tuple[str, ...]) -> str:
    entries = "".join(
        f'<manifest:file-entry manifest:full-path="{path}" manifest:media-type="application/xml"/>'
        for path in paths
    )
    return f'<manifest:manifest xmlns:manifest="{NS}">{entries}</manifest:manifest>'


def _package(
    manifest: str,
    extra_members: tuple[tuple[str, bytes], ...] = (),
    content: str = CONTENT,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("mimetype", MIME, compress_type=zipfile.ZIP_STORED)
        archive.writestr("META-INF/manifest.xml", manifest)
        archive.writestr("content.xml", content)
        for name, data in extra_members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _analyze(tmp_path, data: bytes):
    path = tmp_path / "sample.odt"
    path.write_bytes(data)
    return analyze_opendocument(str(path))


def test_manifest_inventory_matches_package_members(tmp_path):
    data = _package(_manifest(("content.xml", "styles.xml")), (("styles.xml", b"<styles/>"),))
    report = _analyze(tmp_path, data)
    validation = report["odf_analysis"]["manifest_validation"]
    assert validation["parsed"] is True
    assert validation["unlisted_package_file_count"] == 0
    assert validation["missing_package_file_count"] == 0
    assert validation["duplicate_path_count"] == 0


def test_manifest_reports_unlisted_package_members(tmp_path):
    data = _package(_manifest(("content.xml",)), (("Basic/Standard/Module1.xml", b"module"),))
    report = _analyze(tmp_path, data)
    validation = report["odf_analysis"]["manifest_validation"]
    assert validation["unlisted_package_file_count"] == 1
    assert validation["package_files_missing_from_manifest"] == ["Basic/Standard/Module1.xml"]
    assert report["odf_analysis"]["status"] == "parsed"
    evidence = next(item for item in report["evidence"] if item["key"] == "odf.manifest_validation")
    assert evidence["severity"] == "warning"


def test_manifest_reports_references_to_missing_members(tmp_path):
    data = _package(_manifest(("content.xml", "Pictures/missing.png")))
    report = _analyze(tmp_path, data)
    validation = report["odf_analysis"]["manifest_validation"]
    assert validation["missing_package_file_count"] == 1
    assert validation["manifest_paths_missing_from_package"] == ["Pictures/missing.png"]


def test_manifest_reports_duplicate_file_entry_paths(tmp_path):
    data = _package(_manifest(("content.xml", "content.xml")))
    report = _analyze(tmp_path, data)
    validation = report["odf_analysis"]["manifest_validation"]
    assert validation["duplicate_path_count"] == 1


def test_odf_script_event_listener_metadata_is_preserved(tmp_path):
    content = (
        '<office:document-content '
        'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<office:scripts><script:event-listener '
        'script:event-name="dom:load" script:language="ooo:Basic" '
        'script:macro-name="Standard.Module1.Main" '
        'xlink:href="vnd.sun.star.script:Standard.Module1.Main"/>'
        '</office:scripts></office:document-content>'
    )
    report = _analyze(tmp_path, _package(_manifest(("content.xml",)), content=content.encode()))
    listeners = report["odf_analysis"]["script_event_listeners"]
    assert listeners == [{
        "part": "content.xml",
        "event_name": "dom:load",
        "macro_name": "Standard.Module1.Main",
        "language": "ooo:Basic",
        "href": "vnd.sun.star.script:Standard.Module1.Main",
    }]
    evidence = next(item for item in report["evidence"] if item["key"] == "odf.script_event_listeners")
    assert evidence["severity"] == "info"
