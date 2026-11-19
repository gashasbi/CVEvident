from __future__ import annotations

import zipfile

from cvevident.office_triage import MAIN_CONTENT_TYPES, analyze_office


def _package(tmp_path, manifest: str, extra_parts: dict[str, bytes] | None = None):
    main_type = next(key for key, value in MAIN_CONTENT_TYPES.items() if value[0] == "docx")
    parts = {
        "[Content_Types].xml": manifest.encode(),
        "_rels/.rels": (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>'
        ).encode(),
        "word/document.xml": b'<w:document xmlns:w="urn:test"><w:body/></w:document>',
    }
    parts.update(extra_parts or {})
    path = tmp_path / "sample.docx"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return analyze_office(str(path))


def _manifest(extra: str = "") -> str:
    main_type = next(key for key, value in MAIN_CONTENT_TYPES.items() if value[0] == "docx")
    return (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        f'<Override PartName="/word/document.xml" ContentType="{main_type}"/>'
        f'{extra}</Types>'
    )


def test_default_content_type_covers_package_part(tmp_path):
    report = _package(
        tmp_path,
        _manifest('<Default Extension="xml" ContentType="application/xml"/>'),
        {"custom/data.xml": b"<data/>"},
    )
    validation = report["office_analysis"]["content_type_validation"]
    assert validation["parts_without_declared_content_type_count"] == 0
    assert validation["overrides_without_package_part_count"] == 0


def test_untyped_package_part_is_reported(tmp_path):
    report = _package(tmp_path, _manifest(), {"custom/data.bin": b"data"})
    validation = report["office_analysis"]["content_type_validation"]
    assert validation["parts_without_declared_content_type"] == ["custom/data.bin"]
    assert validation["parts_without_declared_content_type_count"] == 1
    evidence = next(item for item in report["evidence"] if item["key"] == "office.content_type_validation")
    assert evidence["severity"] == "warning"


def test_dangling_override_is_reported(tmp_path):
    report = _package(
        tmp_path,
        _manifest('<Override PartName="/missing/part.xml" ContentType="application/xml"/>'),
    )
    validation = report["office_analysis"]["content_type_validation"]
    assert validation["overrides_without_package_part"] == ["missing/part.xml"]
    assert validation["overrides_without_package_part_count"] == 1


def test_duplicate_override_is_reported(tmp_path):
    main_type = next(key for key, value in MAIN_CONTENT_TYPES.items() if value[0] == "docx")
    extra = f'<Override PartName="/word/document.xml" ContentType="{main_type}"/>'
    report = _package(tmp_path, _manifest(extra))
    validation = report["office_analysis"]["content_type_validation"]
    assert validation["duplicate_override_part_count"] == 1


def test_override_part_name_matching_is_ascii_case_insensitive(tmp_path):
    main_type = next(key for key, value in MAIN_CONTENT_TYPES.items() if value[0] == "docx")
    manifest = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        f'<Override PartName="/WORD/DOCUMENT.XML" ContentType="{main_type}"/>'
        '</Types>'
    )
    report = _package(tmp_path, manifest)
    assert report["office_analysis"]["format_id"] == "docx"


def test_duplicate_default_extension_is_reported(tmp_path):
    extra = (
        '<Default Extension="bin" ContentType="application/octet-stream"/>'
        '<Default Extension="BIN" ContentType="application/x-binary"/>'
    )
    report = _package(tmp_path, _manifest(extra), {"custom/data.bin": b"data"})
    validation = report["office_analysis"]["content_type_validation"]
    assert validation["duplicate_default_extension_count"] == 1



def test_custom_ui_callback_references_are_recorded_without_execution(tmp_path):
    custom_ui = (
        '<customUI xmlns="http://schemas.microsoft.com/office/2006/01/customui" onLoad="InitializeRibbon">'
        '<ribbon><tabs><tab id="Tab1"><group id="Group1">'
        '<button id="Button1" label="Open" onAction="OpenDocument" getEnabled="CanOpen"/>'
        '</group></tab></tabs></ribbon></customUI>'
    ).encode()
    manifest = _manifest('<Default Extension="xml" ContentType="application/xml"/>')
    report = _package(tmp_path, manifest, {"customUI/customUI.xml": custom_ui})
    analysis = report["office_analysis"]
    assert analysis["features"]["custom_ui_callback_count"] == 3
    assert {item["callback_name"] for item in analysis["custom_ui_callbacks"]} == {
        "InitializeRibbon", "OpenDocument", "CanOpen"
    }
    evidence = next(
        item for item in report["evidence"]
        if item["key"] == "office.structure.custom_ui_callback_count"
    )
    assert evidence["severity"] == "info"


def test_callback_like_attributes_outside_custom_ui_are_not_counted(tmp_path):
    document = (
        '<w:document xmlns:w="urn:test" onLoad="NotARibbonCallback">'
        '<w:body><w:p onAction="NotARibbonAction"/></w:body></w:document>'
    ).encode()
    report = _package(tmp_path, _manifest(), {"word/extra.xml": document})
    assert report["office_analysis"]["features"]["custom_ui_callback_count"] == 0


def test_custom_ui_path_without_recognized_namespace_is_not_counted(tmp_path):
    custom_ui = (
        '<customUI xmlns="urn:unrelated:customui" onLoad="NotAnOfficeCallback"/>'
    ).encode()
    manifest = _manifest('<Default Extension="xml" ContentType="application/xml"/>')
    report = _package(tmp_path, manifest, {"customUI/customUI.xml": custom_ui})
    assert report["office_analysis"]["features"]["custom_ui_callback_count"] == 0
