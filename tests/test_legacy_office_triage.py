import struct
import tempfile
import unittest
from pathlib import Path

from cvevident.legacy_office_triage import (
    OLE_SIGNATURE,
    _decompress_vba_container,
    _parse_vba_module_block,
    analyze_legacy_office,
)

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


def build_cfb_with_hierarchy(names, parents, *, major=3):
    data = bytearray(build_cfb(names, major=major))
    if not names or names[0][1] != 5:
        raise ValueError("The first directory entry must be Root Entry.")

    indexes = {name: index for index, (name, _) in enumerate(names)}
    groups = {index: [] for index, (_, entry_type) in enumerate(names) if entry_type in (1, 5)}
    for child_name, parent_name in parents.items():
        child_id = indexes[child_name]
        parent_id = indexes[parent_name]
        if parent_id not in groups:
            raise ValueError("Parent entry must be a storage.")
        groups[parent_id].append(child_id)

    directory_offset = 512 if major == 3 else 4096
    for parent_id, child_ids in groups.items():
        child_ids.sort(key=lambda index: (
            len(names[index][0].encode("utf-16le")) + 2,
            tuple(
                ord(char.upper()) if len(char.upper()) == 1 else ord(char)
                for char in names[index][0]
            ),
        ))

        def build_tree(items):
            if not items:
                return FREE
            middle = len(items) // 2
            node = items[middle]
            left_id = build_tree(items[:middle])
            right_id = build_tree(items[middle + 1:])
            offset = directory_offset + node * 128
            struct.pack_into("<II", data, offset + 68, left_id, right_id)
            data[offset + 67] = 1
            return node

        child_root = build_tree(child_ids)
        struct.pack_into("<I", data, directory_offset + parent_id * 128 + 76, child_root)

    return bytes(data)


def make_vba_record(record_id, payload):
    return struct.pack("<HI", record_id, len(payload)) + payload


def make_vba_module_block(stream_name="Module1", module_name="Module1", source_offset=0):
    stream_bytes = stream_name.encode("cp1252")
    name_bytes = module_name.encode("cp1252")
    unicode_bytes = stream_name.encode("utf-16le")
    module = b"".join([
        make_vba_record(0x0019, name_bytes),
        make_vba_record(0x001A, stream_bytes),
        make_vba_record(0x0032, unicode_bytes),
        make_vba_record(0x0031, struct.pack("<I", source_offset)),
        make_vba_record(0x001E, struct.pack("<I", 0)),
        make_vba_record(0x002C, struct.pack("<H", 1)),
        make_vba_record(0x0021, b""),
        make_vba_record(0x002B, b""),
        b"\x00\x00\x00\x00",
    ])
    return b"".join([
        make_vba_record(0x000F, struct.pack("<H", 1)),
        make_vba_record(0x0013, struct.pack("<H", 1)),
        module,
        make_vba_record(0x0010, b""),
        b"\x00\x00\x00\x00",
    ])


def make_vba_raw_container(data):
    if len(data) > 4096:
        raise ValueError("VBA raw test chunk is too large")
    chunk = data.ljust(4096, b"\x00")
    return b"\x01" + struct.pack("<H", 0x3FFF) + chunk


def make_vba_compressed_container(data):
    if len(data) > 4096:
        raise ValueError("VBA test data is too large")
    encoded = bytearray()
    for offset in range(0, len(data), 8):
        encoded.append(0)
        encoded.extend(data[offset:offset + 8])
    chunk_size = len(encoded) + 2
    if chunk_size < 3 or chunk_size > 4098:
        raise ValueError("VBA compressed test chunk size is invalid")
    header = 0xB000 | (chunk_size - 3)
    return b"\x01" + struct.pack("<H", header) + bytes(encoded)


def build_cfb_with_mini_streams(names, parents, stream_data):
    data = bytearray(build_cfb_with_hierarchy(names, parents))
    sector_size = 512
    directory_sector_count = max(1, (len(names) * 128 + sector_size - 1) // sector_size)
    directory_end = sector_size + directory_sector_count * sector_size
    data = data[:directory_end]
    mini_stream = bytearray()
    mini_fat = [EOC] * (sector_size // 4)
    stream_starts = {}
    for name, payload in stream_data.items():
        if not payload:
            stream_starts[name] = EOC
            continue
        first = len(mini_stream) // 64
        chunks = [payload[offset:offset + 64] for offset in range(0, len(payload), 64)]
        for index, chunk in enumerate(chunks):
            mini_stream.extend(chunk.ljust(64, b"\x00"))
            mini_id = first + index
            mini_fat[mini_id] = mini_id + 1 if index + 1 < len(chunks) else EOC
        stream_starts[name] = first
    root_mini_size = len(mini_stream)
    mini_stream = mini_stream.ljust(sector_size, b"\x00")
    mini_fat_sector_id = directory_sector_count
    root_mini_sector_id = directory_sector_count + 1
    fat_sector_id = directory_sector_count + 2
    mini_fat_bytes = struct.pack(f"<{sector_size // 4}I", *mini_fat)
    fat_words = [FREE] * (sector_size // 4)
    for sector_id in range(directory_sector_count):
        fat_words[sector_id] = sector_id + 1 if sector_id + 1 < directory_sector_count else EOC
    fat_words[mini_fat_sector_id] = EOC
    fat_words[root_mini_sector_id] = EOC
    fat_words[fat_sector_id] = FATSECT
    data.extend(mini_fat_bytes)
    data.extend(mini_stream)
    data.extend(struct.pack(f"<{sector_size // 4}I", *fat_words))
    struct.pack_into("<I", data, 44, 1)
    struct.pack_into("<I", data, 60, mini_fat_sector_id)
    struct.pack_into("<I", data, 64, 1)
    struct.pack_into("<I", data, 68, EOC)
    struct.pack_into("<I", data, 72, 0)
    difat = [fat_sector_id] + [FREE] * 108
    struct.pack_into("<109I", data, 76, *difat)
    for index, (name, entry_type) in enumerate(names):
        offset = sector_size + index * 128
        if entry_type == 5:
            struct.pack_into("<I", data, offset + 116, root_mini_sector_id)
            struct.pack_into("<Q", data, offset + 120, root_mini_size)
        elif entry_type == 2:
            payload = stream_data.get(name, b"")
            struct.pack_into("<I", data, offset + 116, stream_starts.get(name, EOC))
            struct.pack_into("<Q", data, offset + 120, len(payload))
    return bytes(data)


class VbaDirParsingTests(unittest.TestCase):
    def test_decompresses_raw_vba_chunk(self):
        payload = b"VBA dir test"
        result = _decompress_vba_container(make_vba_raw_container(payload))
        self.assertEqual(result[:len(payload)], payload)
        self.assertEqual(len(result), 4096)

    def test_decompresses_literal_compressed_chunk(self):
        payload = b"VBA-DIR!"
        header = struct.pack("<H", 0xB008)
        result = _decompress_vba_container(b"\x01" + header + b"\x00" + payload)
        self.assertEqual(result, payload)

    def test_decompresses_overlapping_copy_token(self):
        payload = b"\x10ABCD" + struct.pack("<H", 0x3000)
        result = _decompress_vba_container(b"\x01" + struct.pack("<H", 0xB006) + payload)
        self.assertEqual(result, b"ABCDABC")

    def test_rejects_copy_token_before_chunk_output(self):
        payload = b"\x01" + struct.pack("<H", 0x0000)
        with self.assertRaises(ValueError):
            _decompress_vba_container(b"\x01" + struct.pack("<H", 0xB002) + payload)

    def test_enforces_decompressed_output_limit(self):
        chunk = b"\x01" + struct.pack("<H", 0x3FFF) + b"A" * 4096
        with self.assertRaises(ValueError):
            _decompress_vba_container(chunk + chunk, max_output=4096)

    def test_rejects_invalid_compressed_container_signature(self):
        with self.assertRaises(ValueError):
            _decompress_vba_container(b"\x00\x00\x00")

    def test_rejects_truncated_compressed_chunk(self):
        with self.assertRaises(ValueError):
            _decompress_vba_container(b"\x01\xFF\x3Fshort")

    def test_parses_module_name_stream_name_offset_and_type(self):
        modules = _parse_vba_module_block(make_vba_module_block("ThisWorkbook", "Workbook", 17))
        self.assertEqual(modules, [{
            "name": "Workbook",
            "stream_name": "ThisWorkbook",
            "source_offset": 17,
            "module_type": "procedural",
        }])

    def test_rejects_missing_module_terminator(self):
        data = make_vba_module_block()
        data = data.replace(make_vba_record(0x002B, b"") + b"\x00\x00\x00\x00", b"", 1)
        with self.assertRaises(ValueError):
            _parse_vba_module_block(data)

    def test_rejects_duplicate_module_stream_names(self):
        module = make_vba_module_block()
        module_block = module[module.find(b"\x0f\x00\x02\x00\x00\x00"):]
        count_record = make_vba_record(0x000F, struct.pack("<H", 2))
        cookie = make_vba_record(0x0013, struct.pack("<H", 1))
        one_module_start = module.find(make_vba_record(0x0019, b"Module1"))
        one_module_end = module.find(make_vba_record(0x0010, b""))
        one_module = module[one_module_start:one_module_end]
        data = count_record + cookie + one_module + one_module + make_vba_record(0x0010, b"") + b"\x00\x00\x00\x00"
        with self.assertRaises(ValueError):
            _parse_vba_module_block(data)


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

    def test_detects_legacy_word_and_nested_vba_storage(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("0Table", 2),
            ("vBa", 1), ("dIr", 2), ("_VBA_PROJECT", 2), ("Module1", 2),
            ("PROJECT", 2), ("PROJECTwm", 2), ("PROJECTlk", 2),
        ]
        data = build_cfb_with_hierarchy(
            names,
            {
                "WordDocument": "Root Entry", "0Table": "Root Entry",
                "vBa": "Root Entry", "dIr": "vBa",
                "_VBA_PROJECT": "vBa", "Module1": "vBa",
                "PROJECT": "Root Entry", "PROJECTwm": "Root Entry",
                "PROJECTlk": "Root Entry",
            },
        )
        report = self.analyze("sample.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertEqual(report["file"]["file_type"], "doc")
        self.assertEqual(analysis["family"], "word")
        self.assertEqual(analysis["status"], "parsed")
        self.assertIs(analysis["root_directory_entry_valid"], True)
        self.assertTrue(analysis["vba_project_present"])
        self.assertEqual(analysis["vba_project_structure_status"], "required_entries_present")
        features = analysis["features"]
        self.assertTrue(features["vba_storage_name_present"])
        self.assertTrue(features["vba_storage_at_root_present"])
        self.assertTrue(features["vba_required_streams_present"])
        self.assertTrue(features["vba_root_project_stream_present"])
        self.assertTrue(features["vba_project_stream_name_present"])
        self.assertTrue(features["vba_directory_stream_name_present"])
        self.assertTrue(features["vba_project_metadata_stream_name_present"])
        self.assertTrue(features["vba_project_workspace_stream_name_present"])
        self.assertTrue(features["vba_project_link_stream_name_present"])
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_vba_name_indicators_outside_storage_do_not_confirm_project(self):
        data = build_cfb_with_root_tree([
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("dir", 2), ("_VBA_PROJECT", 2),
        ])
        report = self.analyze("decoy-vba-names.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertFalse(analysis["vba_project_present"])
        self.assertEqual(analysis["vba_project_structure_status"], "incomplete")
        self.assertTrue(analysis["features"]["vba_project_stream_name_present"])
        self.assertTrue(analysis["features"]["vba_directory_stream_name_present"])
        self.assertFalse(analysis["features"]["vba_required_streams_present"])
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_vba_required_streams_must_both_be_children_of_vba_storage(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("dir", 2), ("_VBA_PROJECT", 2),
        ]
        data = build_cfb_with_hierarchy(
            names,
            {"WordDocument": "Root Entry", "VBA": "Root Entry",
             "dir": "VBA", "_VBA_PROJECT": "Root Entry"},
        )
        report = self.analyze("split-vba-streams.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertFalse(analysis["vba_project_present"])
        self.assertEqual(analysis["vba_project_structure_status"], "incomplete")
        self.assertFalse(analysis["features"]["vba_required_streams_present"])

    def test_vba_project_requires_project_stream_at_root(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("dir", 2), ("_VBA_PROJECT", 2),
        ]
        data = build_cfb_with_hierarchy(
            names,
            {"WordDocument": "Root Entry", "VBA": "Root Entry",
             "dir": "VBA", "_VBA_PROJECT": "VBA"},
        )
        report = self.analyze("missing-root-project-stream.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertFalse(analysis["vba_project_present"])
        self.assertEqual(analysis["vba_project_structure_status"], "incomplete")
        self.assertFalse(analysis["features"]["vba_root_project_stream_present"])

    def test_vba_structure_is_indeterminate_when_directory_tree_is_invalid(self):
        data = bytearray(build_cfb_with_root_tree([
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("dir", 2), ("_VBA_PROJECT", 2),
        ]))
        struct.pack_into("<I", data, 512 + 76, 999)
        report = self.analyze("invalid-vba-tree.doc", bytes(data))
        analysis = report["legacy_office_analysis"]
        self.assertFalse(analysis["vba_project_present"])
        self.assertEqual(analysis["vba_project_structure_status"], "indeterminate")

    def test_parses_vba_dir_and_confirms_module_stream_mapping(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("_VBA_PROJECT", 2), ("dir", 2), ("ThisWorkbook", 2),
            ("PROJECT", 2),
        ]
        dir_payload = make_vba_module_block("ThisWorkbook", "Workbook", 0)
        stream_data = {
            "_VBA_PROJECT": b"\x00",
            "dir": make_vba_compressed_container(dir_payload),
            "ThisWorkbook": b"\x01\x02\x03",
            "PROJECT": b"Project=Sample",
        }
        data = build_cfb_with_mini_streams(
            names,
            {
                "WordDocument": "Root Entry", "VBA": "Root Entry",
                "_VBA_PROJECT": "VBA", "dir": "VBA",
                "ThisWorkbook": "VBA", "PROJECT": "Root Entry",
            },
            stream_data,
        )
        report = self.analyze("vba-modules.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["vba_dir_stream_status"], "parsed")
        self.assertEqual(analysis["vba_project_validation_status"], "module_streams_confirmed")
        self.assertEqual(analysis["vba_module_count"], 1)
        self.assertTrue(analysis["features"]["vba_module_streams_present"])
        self.assertTrue(analysis["features"]["vba_module_streams_complete"])
        self.assertEqual(analysis["vba_modules"][0]["name"], "Workbook")
        self.assertEqual(analysis["vba_modules"][0]["stream_name"], "ThisWorkbook")
        self.assertEqual(report["assessment"]["verdict"], "not_assessed")

    def test_invalid_vba_dir_stream_is_reported_without_confirming_project(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("_VBA_PROJECT", 2), ("dir", 2), ("PROJECT", 2),
        ]
        data = build_cfb_with_mini_streams(
            names,
            {
                "WordDocument": "Root Entry", "VBA": "Root Entry",
                "_VBA_PROJECT": "VBA", "dir": "VBA", "PROJECT": "Root Entry",
            },
            {"_VBA_PROJECT": b"\x00", "dir": b"\x00invalid", "PROJECT": b"Project=Sample"},
        )
        report = self.analyze("vba-invalid-dir.doc", data)
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["vba_dir_stream_status"], "invalid")
        self.assertEqual(analysis["vba_project_validation_status"], "invalid_dir_stream")
        self.assertFalse(analysis["features"]["vba_project_metadata_validated"])

    def test_vba_module_stream_name_matching_is_case_insensitive(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("_VBA_PROJECT", 2), ("dir", 2), ("thisworkbook", 2),
            ("PROJECT", 2),
        ]
        data = build_cfb_with_mini_streams(
            names,
            {
                "WordDocument": "Root Entry", "VBA": "Root Entry",
                "_VBA_PROJECT": "VBA", "dir": "VBA",
                "thisworkbook": "VBA", "PROJECT": "Root Entry",
            },
            {
                "_VBA_PROJECT": b"\x00",
                "dir": make_vba_compressed_container(make_vba_module_block("ThisWorkbook", "Workbook", 0)),
                "thisworkbook": b"\x01\x02\x03",
                "PROJECT": b"Project=Sample",
            },
        )
        report = self.analyze("vba-case-insensitive.doc", data)
        features = report["legacy_office_analysis"]["features"]
        self.assertTrue(features["vba_module_streams_present"])
        self.assertTrue(features["vba_module_streams_complete"])
        self.assertEqual(
            report["legacy_office_analysis"]["vba_project_validation_status"],
            "module_streams_confirmed",
        )

    def test_vba_module_stream_presence_is_separate_from_source_validation(self):
        names = [
            ("Root Entry", 5), ("WordDocument", 2), ("VBA", 1),
            ("_VBA_PROJECT", 2), ("dir", 2), ("ThisWorkbook", 2),
            ("PROJECT", 2),
        ]
        data = build_cfb_with_mini_streams(
            names,
            {
                "WordDocument": "Root Entry", "VBA": "Root Entry",
                "_VBA_PROJECT": "VBA", "dir": "VBA",
                "ThisWorkbook": "VBA", "PROJECT": "Root Entry",
            },
            {
                "_VBA_PROJECT": b"\x00",
                "dir": make_vba_compressed_container(make_vba_module_block("ThisWorkbook", "Workbook", 99)),
                "ThisWorkbook": b"\x01\x02\x03",
                "PROJECT": b"Project=Sample",
            },
        )
        report = self.analyze("vba-invalid-source-offset.doc", data)
        features = report["legacy_office_analysis"]["features"]
        self.assertTrue(features["vba_module_streams_present"])
        self.assertFalse(features["vba_module_streams_complete"])
        self.assertEqual(
            report["legacy_office_analysis"]["vba_project_validation_status"],
            "module_streams_unverified",
        )

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

    def test_header_clsid_must_be_zero(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        data[8] = 1
        report = self.analyze("header-clsid.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("header CLSID" in warning for warning in report["warnings"]))

    def test_reserved_header_bytes_must_be_zero(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        data[34] = 1
        report = self.analyze("reserved-header.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("reserved header bytes" in warning for warning in report["warnings"]))

    def test_version_three_directory_sector_count_must_be_zero(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        struct.pack_into("<I", data, 40, 1)
        report = self.analyze("version3-directory-count.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("version 3 directory-sector count" in warning for warning in report["warnings"]))

    def test_version_four_directory_sector_count_must_match_chain(self):
        data = bytearray(build_cfb_with_root_tree(
            [("Root Entry", 5), ("WordDocument", 2)], major=4
        ))
        struct.pack_into("<I", data, 40, 2)
        report = self.analyze("version4-directory-count.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("does not match the directory chain" in warning for warning in report["warnings"]))

    def test_version_four_header_padding_must_be_zero(self):
        data = bytearray(build_cfb_with_root_tree(
            [("Root Entry", 5), ("WordDocument", 2)], major=4
        ))
        data[512] = 1
        report = self.analyze("version4-padding.doc", bytes(data))
        self.assertEqual(report["legacy_office_analysis"]["status"], "failed")
        self.assertTrue(any("header padding" in warning for warning in report["warnings"]))

    def test_unexpected_minor_version_is_reported_as_partial(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        struct.pack_into("<H", data, 24, 0x003D)
        report = self.analyze("minor-version.doc", bytes(data))
        analysis = report["legacy_office_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertEqual(analysis["minor_version"], 0x003D)
        self.assertTrue(any("minor version" in warning for warning in analysis["warnings"]))

    def test_nonzero_transaction_signature_is_not_rejected(self):
        data = bytearray(build_cfb([("Root Entry", 5), ("WordDocument", 2)]))
        struct.pack_into("<I", data, 52, 123)
        report = self.analyze("transaction-signature.doc", bytes(data))
        self.assertNotEqual(report["legacy_office_analysis"]["status"], "failed")

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
