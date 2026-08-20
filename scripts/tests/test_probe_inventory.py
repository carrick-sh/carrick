#!/usr/bin/env python3

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "probe-inventory.py"
SPEC = importlib.util.spec_from_file_location("probe_inventory", MODULE_PATH)
probe_inventory = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(probe_inventory)


class ProbeInventoryTest(unittest.TestCase):
    def test_probe_inventory_partitions_all_461_sources(self):
        inventory = probe_inventory.load_inventory()
        sources = probe_inventory.source_names()
        self.assertEqual(set(inventory), sources)
        self.assertEqual(len(inventory), 461)
        self.assertEqual(
            {name for name, row in inventory.items() if row["class"] == "performance"},
            {name for name in sources if name.startswith("perf_")},
        )
        self.assertEqual(
            {name for name, row in inventory.items() if row["class"] == "helper"},
            {"probeinit"},
        )
        self.assertEqual(
            sum(row["class"] == "performance" for row in inventory.values()), 25
        )
        self.assertTrue(all(row["excluded"] is False for row in inventory.values()))

    def test_missing_arm64_binary_is_a_closure_failure(self):
        inventory = {
            "kernelidentity": {
                "class": "conformance",
                "runner": "generic",
                "excluded": False,
            },
            "probeinit": {
                "class": "helper",
                "runner": "generic",
                "excluded": False,
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            helper = target / "probeinit"
            helper.write_bytes(b"elf")
            helper.chmod(helper.stat().st_mode | 0o111)
            with self.assertRaises(probe_inventory.ProbeInventoryError):
                probe_inventory.check_binaries(inventory, target, "arm64-musl")

    def test_inventory_rejects_rows_absent_from_disk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir)
            (source_dir / "present.rs").write_text("fn main() {}\n", encoding="utf-8")
            inventory = {
                "present": {
                    "class": "conformance",
                    "runner": "generic",
                    "excluded": False,
                },
                "missing": {
                    "class": "conformance",
                    "runner": "generic",
                    "excluded": False,
                },
            }
            with self.assertRaises(probe_inventory.ProbeInventoryError):
                probe_inventory.validate_inventory(inventory, source_dir)


if __name__ == "__main__":
    unittest.main()
