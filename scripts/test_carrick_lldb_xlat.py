#!/usr/bin/env python3
"""Pure tests for the pending-translation live/core export reader."""

import hashlib
import json
import os
import struct
import tempfile
import unittest

import carrick_lldb_xlat as xlat


ROOT = 0x1000
UNIT = 0x2000
CHUNK = 0x3000
KEY = 0x4000
CODE = 0x5000
HOT = 0x6000
COLD = 0x7000


class SparseMemory:
    def __init__(self):
        self.ranges = {}

    def put(self, address, data):
        self.ranges[address] = bytes(data)

    def read(self, address, length):
        for start, data in self.ranges.items():
            offset = address - start
            if 0 <= offset and offset + length <= len(data):
                return data[offset : offset + length]
        raise xlat.MemoryReadError(address, length, "fixture page absent")


def fixture(*, committed=1, next_chunk=0, committed_chunks=1):
    memory = SparseMemory()
    key = b'{"translator_abi":9}'
    code, hot, cold = b"CODE", b"HOT", b"COLD"
    root = struct.pack(
        "<8sIIi4xQQQQ",
        b"CXLATP1\0", 1, 56, 42, 0x1122, 0x3344, UNIT, 1,
    )
    unit = struct.pack(
        "<8sIIQQQQIiQQQQQ",
        b"CXLATU1\0", 1, 96, KEY, len(key), 0x400000, 0x404000,
        3, 42, 0x1122, 0x3344, CHUNK, committed_chunks, 0,
    )
    record = struct.pack(
        "<QQQIIQQQQQQ",
        0x400100, 0x400108, 0, 0, 0,
        CODE, len(code), HOT, len(hot), COLD, len(cold),
    )
    empty = bytes(80 * 15)
    chunk = struct.pack("<8sIIQII", b"CXLATC1\0", 1, 1312, next_chunk, committed, 16)
    memory.put(ROOT, root)
    memory.put(UNIT, unit)
    memory.put(CHUNK, chunk + record + empty)
    memory.put(KEY, key)
    memory.put(CODE, code)
    memory.put(HOT, hot)
    memory.put(COLD, cold)
    return memory


class PendingTranslationReaderTests(unittest.TestCase):
    def read(self, memory):
        return xlat.read_pending(
            memory.read,
            ROOT,
            source_identity="core:/tmp/carrick.core",
            mach_o_uuid="AABB-CCDD",
            executable_sha256="11" * 32,
        )

    def test_complete_live_prefix_round_trips(self):
        export = self.read(fixture())
        self.assertTrue(export.summary["complete"])
        self.assertEqual(export.summary["record_count"], 1)
        self.assertEqual(export.summary["pid"], 42)
        self.assertEqual(export.summary["mach_o_uuid"], "AABB-CCDD")
        self.assertEqual(export.summary["executable_sha256"], "11" * 32)
        self.assertEqual(export.summary["binary_sha256"], hashlib.sha256(export.binary).hexdigest())
        self.assertEqual(export.binary[:8], b"CXLATE1\0")

    def test_torn_uncommitted_record_is_excluded(self):
        export = self.read(fixture(committed=0))
        self.assertTrue(export.summary["complete"])
        self.assertEqual(export.summary["record_count"], 0)
        self.assertNotIn(b"CODE", export.binary)

    def test_missing_later_chunk_exports_partial_prefix_and_address(self):
        missing = 0x9000
        export = self.read(fixture(next_chunk=missing, committed_chunks=2))
        self.assertFalse(export.summary["complete"])
        self.assertEqual(export.summary["first_unreadable_address"], hex(missing))
        self.assertEqual(export.summary["record_count"], 1)

    def test_missing_root_refuses_stack_only_core_by_name(self):
        memory = SparseMemory()
        with self.assertRaisesRegex(xlat.PendingReadError, "stack-only core.*modified-memory"):
            self.read(memory)

    def test_bad_magic_schema_pointer_count_offset_and_length_fail_closed(self):
        mutations = []
        memory = fixture()
        mutations.append((memory, ROOT, b"BADMAGIC"))
        memory = fixture()
        mutations.append((memory, ROOT + 8, struct.pack("<I", 99)))
        memory = fixture()
        mutations.append((memory, ROOT + 40, struct.pack("<Q", 0xffff_ffff_ffff_ffff)))
        memory = fixture(committed=17)
        mutations.append((memory, 0, b""))
        memory = fixture()
        mutations.append((memory, CHUNK + 12, struct.pack("<I", 12)))
        memory = fixture()
        mutations.append((memory, CHUNK + 32 + 40, struct.pack("<Q", 1 << 40)))
        for memory, address, data in mutations:
            if address:
                original = next(blob for start, blob in memory.ranges.items() if start <= address < start + len(blob))
                start = next(start for start, blob in memory.ranges.items() if blob is original)
                patched = bytearray(original)
                patched[address - start : address - start + len(data)] = data
                memory.ranges[start] = bytes(patched)
            with self.subTest(address=hex(address)):
                with self.assertRaises(xlat.PendingReadError):
                    self.read(memory)

    def test_export_files_are_mode_0600_atomic_and_hash_bound(self):
        export = self.read(fixture())
        with tempfile.TemporaryDirectory() as directory:
            base = os.path.join(directory, "pending")
            json_path, bin_path = xlat.write_export(export, base)
            self.assertEqual(os.stat(json_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(bin_path).st_mode & 0o777, 0o600)
            with open(bin_path, "rb") as handle:
                binary = handle.read()
            with open(json_path, encoding="utf-8") as handle:
                summary = json.load(handle)
            self.assertEqual(summary["binary_sha256"], hashlib.sha256(binary).hexdigest())
            self.assertFalse(any(".tmp" in name for name in os.listdir(directory)))

    def test_export_magic_cannot_be_parsed_as_store_bundle(self):
        export = self.read(fixture())
        self.assertNotEqual(export.binary[:8], b"CUNITB1\0")


if __name__ == "__main__":
    unittest.main()
