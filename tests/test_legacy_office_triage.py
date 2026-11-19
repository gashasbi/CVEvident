import struct
import tempfile
import unittest
from pathlib import Path

from cvevident.legacy_office_triage import OLE_SIGNATURE, analyze_legacy_office

FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def build_cfb(names, *, major=3):
    """Build a minimal synthetic CFB directory with named streams; no stream data."""
    sector_size = 512 if major == 3 else 4096
    entries = []
    for index, (name, entry_type) in enumerate(names):
        raw = bytearray(128)
        encoded = name.encode("utf-16le") + b"\x00\x00"
        if len(encoded) > 64:
            raise ValueError("test name too long")
        raw[:len(encoded)] = encoded
        struct.pack_into("<H", raw, 64, len(encoded))
        raw[66] = entry_type
        raw[67] = 1
        struct.pack_into("<III", raw, 68, FREE, FREE, FREE)
        struct.pack_into("<I", raw, 116, EOC)
        struct.pack_into("<Q", raw, 120, 0)
        entries.append(bytes(raw))
    per_sector = sector_size // 128
    directory_sector_count = max(1, (len(entries) + per_sector - 1) // per_sector)
    directory_sector_ids = list(range(directory_sector_count))
    fat_sector_id = directory_sector_count

    header = bytearray(sector_size)
    header[:8] = OLE_SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, major)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9 if major == 3 else 12)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 40, 0 if major == 3 else directory_sector_count)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, directory_sector_ids[0])
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<I", header, 60, EOC)
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, EOC)
    struct.pack_into("<I", header, 72, 0)
    difat = [fat_sector_id] + [FREE] * 108
    struct.pack_into("<109I", header, 76, *difat)

    dir_stream = b"".join(entries)
    dir_stream = dir_stream.ljust(directory_sector_count * sector_size, b"\x00")
    fat_words = [FREE] * (sector_size // 4)
    for idx, sector_id in enumerate(directory_sector_ids):
        fat_words[sector_id] = directory_sector_ids[idx + 1] if idx + 1 < len(directory_sector_ids) else EOC
    fat_words[fat_sector_id] = FATSECT
    fat_sector = struct.pack(f"<{sector_size // 4}I", *fat_words)
    return bytes(header) + dir_stream + fat_sector


def build_cfb_with_root_tree(names, *, major=3):
    data = bytearray(build_cfb(names, major=major))
    if not names or names[0][1] != 5:
        raise ValueError("The first directory entry must be Root Entry.")

    def name_key(index):
        encoded = names[index][0].encode("utf-16le")
        units = struct.unpack(f"<{len(encoded) // 2}H", encoded)
        uppercase_units = []
        for unit in units:
            if 0xD800 <= unit <= 0xDFFF:
                uppercase_units.append(unit)
                continue
            transformed = chr(unit).upper()
            if len(transformed) == 1:
                uppercase_units.append(ord(transformed))
                continue
            titlecase = chr(unit).title()
            uppercase_units.append(
                ord(titlecase) if len(titlecase) == 1 else unit
            )
        return len(encoded) + 2, tuple(uppercase_units)

    ordered = sorted(
        range(1, len(names)),
        key=lambda index: (name_key(index), index),
    )
    left = {}
    right = {}
    parent = {}
    color = {}
    root = [None]

    def rotate_left(node):
        pivot = right[node]
        right[node] = left[pivot]
        if left[pivot] is not None:
            parent[left[pivot]] = node
        parent[pivot] = parent[node]
        if parent[node] is None:
            root[0] = pivot
        elif node == left[parent[node]]:
            left[parent[node]] = pivot
        else:
            right[parent[node]] = pivot
        left[pivot] = node
        parent[node] = pivot

    def rotate_right(node):
        pivot = left[node]
        left[node] = right[pivot]
        if right[pivot] is not None:
            parent[right[pivot]] = node
        parent[pivot] = parent[node]
        if parent[node] is None:
            root[0] = pivot
        elif node == right[parent[node]]:
            right[parent[node]] = pivot
        else:
            left[parent[node]] = pivot
        right[pivot] = node
        parent[node] = pivot

    for node in ordered:
        left[node] = None
        right[node] = None
        parent[node] = None
        color[node] = 0

        cursor = root[0]
        insertion_parent = None
        node_key = (name_key(node), node)

        while cursor is not None:
            insertion_parent = cursor
            if node_key < (name_key(cursor), cursor):
                cursor = left[cursor]
            else:
                cursor = right[cursor]

        parent[node] = insertion_parent
        if insertion_parent is None:
            root[0] = node
        elif node_key < (name_key(insertion_parent), insertion_parent):
            left[insertion_parent] = node
        else:
            right[insertion_parent] = node

        while node != root[0] and color[parent[node]] == 0:
            grandparent = parent[parent[node]]
            if parent[node] == left[grandparent]:
                uncle = right[grandparent]
                if uncle is not None and color[uncle] == 0:
                    color[parent[node]] = 1
                    color[uncle] = 1
                    color[grandparent] = 0
                    node = grandparent
                else:
                    if node == right[parent[node]]:
                        node = parent[node]
                        rotate_left(node)
                    color[parent[node]] = 1
                    color[grandparent] = 0
                    rotate_right(grandparent)
            else:
                uncle = left[grandparent]
                if uncle is not None and color[uncle] == 0:
                    color[parent[node]] = 1
                    color[uncle] = 1
                    color[grandparent] = 0
                    node = grandparent
                else:
                    if node == left[parent[node]]:
                        node = parent[node]
                        rotate_right(node)
                    color[parent[node]] = 1
                    color[grandparent] = 0
                    rotate_left(grandparent)

        color[root[0]] = 1

    directory_offset = 512 if major == 3 else 4096
    struct.pack_into(
        "<I",
        data,
        directory_offset + 76,
        root[0] if root[0] is not None else FREE,
    )

    for node in ordered:
        entry_offset = directory_offset + node * 128
        struct.pack_into(
            "<II",
            data,
            entry_offset + 68,
            left[node] if left[node] is not None else FREE,
            right[node] if right[node] is not None else FREE,
        )
        data[entry_offset + 67] = color[node]

    return bytes(data)


class LegacyOfficeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return analyze_legacy_office(str(path))

    def test_detects_legacy_word_and_vba_directory_indicators(self):
        data = build_cfb_with_root_tree([
            ("Root Entry", 5), ("WordDocument", 2), ("0Table", 2),
            ("VBA", 1), ("dir", 2), ("_VBA_PROJECT", 2), ("PROJECT", 2),
            ("PROJECTwm", 2), ("PROJECTlk", 2),
        ])
        report = self.analyze("sample.doc", data)
        self.assertEqual(report["file"]["file_type"], "doc")
        self.assertEqual(report["legacy_office_analysis"]["family"], "word")
        self.assertEqual(report["legacy_office_analysis"]["status"], "parsed")
        self.assertIs(report["legacy_office_analysis"]["root_directory_entry_valid"], True)
        self.assertTrue(report["legacy_office_analysis"]["vba_project_present"])
        features = report["legacy_office_analysis"]["features"]
        self.assertTrue(features["vba_storage_name_present"])
        self.assertTrue(features["vba_project_stream_name_present"])
        self.assertTrue(features["vba_directory_stream_name_present"])
        self.assertTrue(features["vba_project_metadata_stream_name_present"])
        self.assertTrue(features["vba_project_workspace_stream_name_present"])
        self.assertTrue(features["vba_project_link_stream_name_present"])
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_detects_excel_and_powerpoint_stream_families(self):
        excel = self.analyze("sample.xls", build_cfb([("Root Entry", 5), ("Workbook", 2)]))
        power = self.analyze("sample.ppt", build_cfb([("Root Entry", 5), ("PowerPoint Document", 2)]))
        self.assertEqual(excel["legacy_office_analysis"]["family"], "excel")
        self.assertEqual(power["legacy_office_analysis"]["family"], "powerpoint")
        self.assertEqual(excel["file"]["file_type"], "xls")
        self.assertEqual(power["file"]["file_type"], "ppt")

    def test_requires_valid_root_directory_entry_before_detecting_office_family(self):
        cases = [
            ("missing-root", [("WordDocument", 2)]),
            ("wrong-root-name", [("Invalid Root", 5), ("WordDocument", 2)]),
            ("root-not-first", [("WordDocument", 2), ("Root Entry", 5)]),
            ("multiple-roots", [
                ("Root Entry", 5),
                ("Another Root", 5),
                ("WordDocument", 2),
            ]),
        ]

        for case_name, entries in cases:
            with self.subTest(case=case_name):
                report = self.analyze(
                    f"{case_name}.doc",
                    build_cfb(entries),
                )
                analysis = report["legacy_office_analysis"]

                self.assertEqual(analysis["status"], "failed")
                self.assertIs(analysis["root_directory_entry_valid"], False)
                self.assertIsNone(analysis["family"])
                self.assertEqual(report["file"]["file_type"], "unknown_ole_cfb")
                self.assertTrue(
                    any("required Root Entry" in warning for warning in report["warnings"])
                )

    def test_directory_tree_rejects_child_reference_outside_directory(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
        ]))
        struct.pack_into("<I", data, 512 + 76, 999)

        report = self.analyze("invalid-directory-child.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "directory tree" in warning.casefold()
            and "outside" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_rejects_entry_referenced_from_multiple_parents(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("StorageA", 1),
            ("StorageB", 1),
            ("SharedStream", 2),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 2)
        struct.pack_into("<I", data, directory_offset + 128 + 76, 3)
        struct.pack_into("<I", data, directory_offset + 256 + 76, 3)

        report = self.analyze("directory-multiple-parents.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "referenced more than once" in warning
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_accepts_balanced_black_root_with_red_children(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("ABCDEFGHIJKLM", 1),
            ("WordDocument", 2),
            ("AdditionalStream", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 68, 2)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 3)

        data[directory_offset + 128 + 67] = 1
        data[directory_offset + 256 + 67] = 0
        data[directory_offset + 384 + 67] = 0

        report = self.analyze("balanced-red-black-tree.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "parsed")
        self.assertIs(analysis["directory_tree_valid"], True)
        self.assertEqual(analysis["family"], "word")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_accepts_unequal_black_height_when_other_rules_hold(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("StorageA", 1),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 2)

        data[directory_offset + 128 + 67] = 1
        data[directory_offset + 256 + 67] = 1

        report = self.analyze("unequal-black-height.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "parsed")
        self.assertIs(analysis["directory_tree_valid"], True)
        self.assertEqual(analysis["family"], "word")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_rejects_consecutive_red_sibling_nodes(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("StorageA", 1),
            ("RedNodeA", 2),
            ("RedNodeB", 2),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 2)
        struct.pack_into("<I", data, directory_offset + 256 + 72, 3)

        data[directory_offset + 128 + 67] = 1
        data[directory_offset + 256 + 67] = 0
        data[directory_offset + 384 + 67] = 0

        report = self.analyze("consecutive-red-directory-nodes.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "red" in warning.casefold()
            and ("child" in warning.casefold() or "consecutive" in warning.casefold())
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_rejects_red_root_of_sibling_tree(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("StorageA", 1),
            ("WordDocument", 2),
        ]))

        struct.pack_into("<I", data, 512 + 76, 1)
        data[512 + 128 + 67] = 0

        report = self.analyze("red-directory-tree-root.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "root" in warning.casefold() and "black" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_accepts_valid_two_node_sibling_tree(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("StorageA", 1),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 2)
        data[directory_offset + 128 + 67] = 1
        data[directory_offset + 256 + 67] = 0

        report = self.analyze("valid-directory-tree.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "parsed")
        self.assertIs(analysis["directory_tree_valid"], True)
        self.assertEqual(analysis["family"], "word")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_uses_name_length_before_lexical_order(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("Z", 1),
            ("AA", 2),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 2)
        struct.pack_into("<I", data, directory_offset + 256 + 72, 3)

        data[directory_offset + 128 + 67] = 1
        data[directory_offset + 256 + 67] = 1
        data[directory_offset + 384 + 67] = 0

        report = self.analyze("cfb-name-length-order.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "parsed")
        self.assertIs(analysis["directory_tree_valid"], True)
        self.assertEqual(analysis["family"], "word")

    def test_directory_tree_rejects_case_insensitive_duplicate_sibling_names(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("Alpha", 1),
            ("ALPHA", 2),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 2)

        data[directory_offset + 128 + 67] = 1
        data[directory_offset + 256 + 67] = 0

        report = self.analyze("cfb-duplicate-sibling-names.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "ordering" in warning.casefold()
            or "uniqueness" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_rejects_forbidden_name_characters(self):
        for index, character in enumerate(("/", "\\\\", ":", "!")):
            with self.subTest(character=character):
                invalid_name = f"Bad{character}Name"
                data = bytearray(build_cfb([
                    ("Root Entry", 5),
                    (invalid_name, 2),
                    ("WordDocument", 2),
                ]))
                struct.pack_into("<I", data, 512 + 76, 1)

                report = self.analyze(
                    f"forbidden-directory-name-{index}.doc", bytes(data)
                )
                analysis = report["legacy_office_analysis"]

                self.assertEqual(analysis["status"], "partial")
                self.assertIs(analysis["directory_tree_valid"], False)
                self.assertTrue(any(
                    "forbidden" in warning.casefold()
                    for warning in analysis["warnings"]
                ))
                self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_rejects_names_equal_under_simple_unicode_uppercase(self):
        names = [
            ("Root Entry", 5),
            (chr(0x1F80), 2),
            (chr(0x1F88), 2),
            ("WordDocument", 2),
        ]
        data = build_cfb_with_root_tree(names)
        report = self.analyze("unicode-uppercase-duplicate.doc", data)
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "ordering" in warning.casefold()
            or "uniqueness" in warning.casefold()
            for warning in analysis["warnings"]
        ))

    def test_directory_tree_accepts_nonforbidden_control_characters(self):
        for codepoint in (1, 9, 13, 31):
            with self.subTest(codepoint=codepoint):
                names = [
                    ("Root Entry", 5),
                    (f"Control{chr(codepoint)}", 2),
                    ("WordDocument", 2),
                ]
                data = build_cfb_with_root_tree(names)
                report = self.analyze(
                    f"control-character-{codepoint}.doc", data
                )
                analysis = report["legacy_office_analysis"]

                self.assertEqual(analysis["status"], "parsed")
                self.assertIs(analysis["directory_tree_valid"], True)


    def test_directory_tree_rejects_names_outside_binary_search_order(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("M", 2),
            ("Z", 2),
            ("A", 2),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 68, 2)
        struct.pack_into("<I", data, directory_offset + 128 + 72, 3)

        report = self.analyze("invalid-directory-name-order.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "ordering" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_root_directory_entry_rejects_sibling_references(self):
        for field_name, field_offset in (
            ("left_sibling_id", 68),
            ("right_sibling_id", 72),
        ):
            with self.subTest(field=field_name):
                data = bytearray(build_cfb([
                    ("Root Entry", 5),
                    ("WordDocument", 2),
                ]))
                struct.pack_into(
                    "<I",
                    data,
                    512 + field_offset,
                    1,
                )

                report = self.analyze(
                    f"root-has-{field_name}.doc", bytes(data)
                )
                analysis = report["legacy_office_analysis"]

                self.assertEqual(analysis["status"], "partial")
                self.assertIs(analysis["directory_tree_valid"], False)
                self.assertTrue(any(
                    "root" in warning.casefold()
                    and "sibling" in warning.casefold()
                    for warning in analysis["warnings"]
                ))
                self.assertEqual(
                    report["assessment"]["verdict"], "not_assessed"
                )

    def test_directory_tree_checks_reachability_when_color_flag_is_invalid(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
            ("OrphanStream", 2),
        ]))
        struct.pack_into("<I", data, 512 + 76, 1)
        data[512 + 2 * 128 + 67] = 2

        report = self.analyze(
            "invalid-color-with-orphan.doc", bytes(data)
        )
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "invalid color flag" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertTrue(any(
            "unreachable" in warning.casefold()
            for warning in analysis["warnings"]
        ))

    def test_directory_tree_rejects_unreachable_active_entries(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
        ]))
        struct.pack_into("<I", data, 512 + 76, 0xFFFFFFFF)

        report = self.analyze(
            "orphan-directory-entry.doc", bytes(data)
        )
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "unreachable" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(
            report["assessment"]["verdict"], "not_assessed"
        )

    def test_directory_tree_rejects_invalid_red_black_color_flag(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
        ]))
        data[512 + 128 + 67] = 2

        report = self.analyze("invalid-directory-color.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "color" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_reports_name_ordering_when_cycle_exists(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("M", 2),
            ("Z", 2),
            ("WordDocument", 2),
        ]))

        directory_offset = 512
        struct.pack_into("<I", data, directory_offset + 76, 1)
        struct.pack_into("<I", data, directory_offset + 128 + 68, 2)
        struct.pack_into("<I", data, directory_offset + 256 + 68, 1)

        report = self.analyze(
            "directory-cycle-and-invalid-order.doc", bytes(data)
        )
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "cycle" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertTrue(any(
            "ordering" in warning.casefold()
            or "uniqueness" in warning.casefold()
            for warning in analysis["warnings"]
        ))

    def test_directory_tree_rejects_cycle_in_sibling_links(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
        ]))

        struct.pack_into("<I", data, 512 + 76, 1)
        struct.pack_into("<I", data, 512 + 128 + 68, 1)

        report = self.analyze("directory-sibling-cycle.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "directory tree" in warning.casefold()
            and "cycle" in warning.casefold()
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_directory_tree_rejects_sibling_references_outside_directory(self):
        for field_name, field_offset in (
            ("left_sibling_id", 68),
            ("right_sibling_id", 72),
        ):
            with self.subTest(field=field_name):
                data = bytearray(build_cfb([
                    ("Root Entry", 5),
                    ("WordDocument", 2),
                ]))
                struct.pack_into(
                    "<I",
                    data,
                    512 + 128 + field_offset,
                    999,
                )

                report = self.analyze(
                    f"invalid-{field_name}.doc", bytes(data)
                )
                analysis = report["legacy_office_analysis"]

                self.assertEqual(analysis["status"], "partial")
                self.assertIs(analysis["directory_tree_valid"], False)
                self.assertTrue(any(
                    field_name in warning and "outside" in warning
                    for warning in analysis["warnings"]
                ))
                self.assertEqual(
                    report["assessment"]["verdict"], "not_assessed"
                )

    def test_directory_tree_rejects_reference_to_unused_directory_slot(self):
        data = bytearray(build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
        ]))
        empty_slot = 2
        struct.pack_into(
            "<I",
            data,
            512 + 128 + 68,
            empty_slot,
        )

        report = self.analyze("unused-directory-slot.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertIs(analysis["directory_tree_valid"], False)
        self.assertTrue(any(
            "does not identify a storage or stream entry" in warning
            for warning in analysis["warnings"]
        ))
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_incomplete_directory_does_not_claim_root_entry_invalid(self):
        from unittest.mock import patch

        data = build_cfb([
            ("Root Entry", 5),
            ("WordDocument", 2),
        ])

        with patch("cvevident.legacy_office_triage._MAX_DIRECTORY_BYTES", 64):
            report = self.analyze("incomplete-root.doc", data)

        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertIsNone(analysis["root_directory_entry_valid"])
        self.assertTrue(analysis["truncated"])
        self.assertTrue(
            any("could not be validated" in warning for warning in analysis["warnings"])
        )

    def test_wrong_extension_reports_family_mismatch(self):
        report = self.analyze("mistyped.xls", build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        self.assertEqual(report["legacy_office_analysis"]["family"], "word")
        self.assertFalse(report["legacy_office_analysis"]["extension_matches_detected_family"])
        self.assertIn("does not match", " ".join(report["warnings"]))

    def test_non_cfb_with_doc_suffix_fails_explicitly(self):
        report = self.analyze("not-really.doc", b"not a compound file")
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")

    def test_truncated_cfb_does_not_claim_parsed(self):
        report = self.analyze("truncated.doc", OLE_SIGNATURE + b"\x00" * 64)
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")

    def test_supports_version_four_cfb_sector_size(self):
        report = self.analyze("version4.doc", build_cfb_with_root_tree([("Root Entry", 5), ("WordDocument", 2)], major=4))
        self.assertEqual(report["legacy_office_analysis"]["status"], "parsed")
        self.assertEqual(report["legacy_office_analysis"]["sector_size"], 4096)

    def test_directory_chain_cycle_is_partial_not_trusted(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        # In the generated CFB, the FAT sector follows the single directory sector.
        struct.pack_into("<I", data, 1024, 0)
        report = self.analyze("cycle.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "partial")
        self.assertIsNone(report["legacy_office_analysis"]["root_directory_entry_valid"])
        self.assertTrue(any("cycle" in warning for warning in report["warnings"]))

    def test_directory_inventory_is_bounded(self):
        names = [("Root Entry", 5), ("WordDocument", 2)]
        names.extend((f"ExtraStream{i:03d}", 2) for i in range(299))
        report = self.analyze("many.doc", build_cfb(names))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["directory_entry_count"], 301)
        self.assertEqual(len(analysis["directory_inventory"]), 300)
        self.assertEqual(analysis["status"], "partial")
        self.assertTrue(analysis["truncated"])
        self.assertTrue(analysis["features"]["directory_inventory_truncated"])

        warning = "Directory inventory was capped at 300 entries."
        self.assertIn(warning, analysis["warnings"])
        self.assertIn(warning, report["warnings"])

    def test_empty_directory_chain_preserves_error_and_truncation(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        struct.pack_into("<I", data, 48, 2)

        report = self.analyze("bad-start.doc", bytes(data))
        analysis = report["legacy_office_analysis"]

        self.assertEqual(analysis["status"], "failed")
        self.assertTrue(analysis["truncated"])
        self.assertTrue(analysis["features"]["directory_chain_truncated"])
        self.assertTrue(any("Directory chain:" in warning for warning in analysis["warnings"]))
        self.assertTrue(any("invalid or unavailable FAT entry" in warning for warning in analysis["warnings"]))
        self.assertTrue(any("Directory chain:" in warning for warning in report["warnings"]))


    def test_invalid_cfb_header_fields_fail_closed(self):
        mutations = [
            ("byte order", 28, "<H", 0x0000),
            ("major version", 26, "<H", 5),
            ("sector shift", 30, "<H", 10),
            ("mini-sector shift", 32, "<H", 5),
        ]
        for label, offset, fmt, value in mutations:
            with self.subTest(field=label):
                data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
                struct.pack_into(fmt, data, offset, value)
                report = self.analyze("invalid-header.doc", bytes(data))
                self.assertEqual(report["legacy_office_analysis"]["status"], "failed")

    def test_non_sector_aligned_cfb_is_reported_partial(self):
        data = build_cfb([("Root Entry", 5), ("WordDocument", 2)]) + b"\x00"
        report = self.analyze("misaligned.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertTrue(any("not aligned" in warning for warning in analysis["warnings"]))

    def test_fat_reference_outside_file_is_reported_without_trusting_directory(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        struct.pack_into("<I", data, 76, 99)
        report = self.analyze("bad-fat-reference.doc", bytes(data))
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "failed")
        self.assertTrue(any("FAT references a sector outside the file" in warning for warning in analysis["warnings"]))
        self.assertTrue(any("directory stream is unavailable or empty" in warning.lower() for warning in analysis["warnings"]))

    def test_fat_sector_not_marked_as_fat_makes_analysis_partial(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        # The first FAT word describes directory sector 0; the second marks FAT sector 1.
        struct.pack_into("<I", data, 1028, EOC)
        report = self.analyze("bad-fat-marker.doc", bytes(data))
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertTrue(any("is not marked as a FAT sector" in warning for warning in analysis["warnings"]))

    def test_fat_sector_count_cap_fails_before_chain_traversal(self):
        from unittest.mock import patch
        data = build_cfb([("Root Entry", 5), ("WordDocument", 2)])
        with patch("cvevident.legacy_office_triage._MAX_FAT_SECTORS", 0):
            report = self.analyze("fat-cap.doc", data)
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("FAT or DIFAT count exceeds" in warning for warning in report["warnings"]))

    def test_encrypted_ooxml_wrapper_is_unsupported_not_decrypted(self):
        data = build_cfb([("Root Entry", 5), ("EncryptedPackage", 2), ("EncryptionInfo", 2)])
        report = self.analyze("encrypted.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "unsupported")
        self.assertEqual(analysis["format_id"], "encrypted_office_container")
        self.assertTrue(analysis["encrypted_content_present"])
        self.assertTrue(any("not decrypted" in warning for warning in analysis["warnings"]))

    def test_unknown_ole_directory_is_unsupported_without_inventing_family(self):
        data = build_cfb([("Root Entry", 5), ("UnrecognizedStream", 2)])
        report = self.analyze("unknown-ole.bin", data)
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "unsupported")
        self.assertIsNone(analysis["family"])
        self.assertEqual(analysis["format_id"], "unknown_ole_cfb")

if __name__ == "__main__":
    unittest.main()
