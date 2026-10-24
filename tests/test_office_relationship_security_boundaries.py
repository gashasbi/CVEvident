from pathlib import Path

import pytest

from cvevident.office_triage import (
    _is_unsafe_member_name,
    _relationship_source,
    _resolve_package_relationship_target,
    analyze_office,
)


class TestOfficeMemberPathBoundaries:
    @pytest.mark.parametrize(
        "name",
        [
            "../outside.xml",
            "word/../outside.xml",
            "word/./document.xml",
            "/absolute/document.xml",
            "C:/outside/document.xml",
            "C:\\outside\\document.xml",
            "..\\outside.xml",
        ],
    )
    def test_rejects_absolute_or_traversal_member_names(self, name):
        assert _is_unsafe_member_name(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "word/document.xml",
            "xl/workbook.xml",
            "ppt/slides/slide1.xml",
            "word\\document.xml",
            "custom/parts/item.xml",
        ],
    )
    def test_accepts_normal_relative_member_names(self, name):
        assert _is_unsafe_member_name(name) is False


class TestOfficeRelationshipSourceBoundaries:
    @pytest.mark.parametrize(
        ("relationship_part", "expected_source"),
        [
            ("word/_rels/document.xml.rels", "word/document.xml"),
            ("word/_rels/header1.xml.rels", "word/header1.xml"),
            ("ppt/slides/_rels/slide1.xml.rels", "ppt/slides/slide1.xml"),
        ],
    )
    def test_maps_relationship_part_to_source_part(
        self, relationship_part, expected_source
    ):
        assert _relationship_source(relationship_part) == expected_source

    def test_preserves_relationship_name_without_rels_directory(self):
        name = "word/document.xml.rels"
        assert _relationship_source(name) == name


class TestOfficeRelationshipTargetBoundaries:
    @pytest.mark.parametrize(
        "target",
        [
            "https://example.invalid/document.xml",
            "http://example.invalid/document.xml",
            "//example.invalid/document.xml",
            "word/document.xml?query=1",
            "word/document.xml#fragment",
            "",
            "\\word\\document.xml",
            "word\\document.xml",
            "word/../document.xml",
            "../document.xml",
            "word/./document.xml",
            "word//document.xml",
            "word/%2e%2e/document.xml",
            "word/%00document.xml",
        ],
    )
    def test_rejects_unsafe_or_unsupported_relationship_targets(self, target):
        assert _resolve_package_relationship_target(target) is None

    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("word/document.xml", "word/document.xml"),
            ("/word/document.xml", "word/document.xml"),
            ("xl/worksheets/sheet1.xml", "xl/worksheets/sheet1.xml"),
            ("word/My%20Document.xml", "word/My Document.xml"),
        ],
    )
    def test_resolves_supported_relative_targets(self, target, expected):
        assert _resolve_package_relationship_target(target) == expected


class TestOfficeAnalysisLimitBoundaries:
    @pytest.mark.parametrize(
        "option",
        [
            "max_archive_entries",
            "max_total_uncompressed_bytes",
            "max_xml_part_bytes",
            "max_total_xml_bytes",
            "max_xml_parts",
        ],
    )
    def test_rejects_nonpositive_resource_limits_before_reading_file(self, option):
        with pytest.raises(ValueError, match="positive"):
            analyze_office(
                Path("this-file-is-not-read.docx"),
                **{option: 0},
            )
