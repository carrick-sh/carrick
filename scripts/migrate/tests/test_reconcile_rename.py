#!/usr/bin/env python3
"""Tests for --rename / --rename-only on the line-pinned inventory reconciler.

pytest is not installed on this host, so this is stdlib unittest rather than
the pytest-style test in the plan brief (tmp_path fixture -> TemporaryDirectory,
bare `def test_...(tmp_path)` -> a TestCase method); the assertions are the
same.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "reconcile-line-pinned-inventories.py"


class RenamePrefixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rename_prefix_rewrites_paths(self) -> None:
        inv = self.root / "inv.json"
        inv.write_text(
            json.dumps(
                [
                    {
                        "path": "crates/carrick-runtime/src/vfs/mount.rs",
                        "line": 10,
                        "fingerprint": "x",
                    },
                    {
                        "path": "crates/carrick-runtime/src/kernel/mod.rs",
                        "line": 3,
                        "fingerprint": "y",
                    },
                ]
            )
        )
        out = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--rename-only",
                str(inv),
                "--rename",
                "crates/carrick-runtime/src/vfs/=crates/carrick-vfs/src/",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = json.loads(inv.read_text())
        self.assertEqual(rows[0]["path"], "crates/carrick-vfs/src/mount.rs")
        self.assertEqual(rows[1]["path"], "crates/carrick-runtime/src/kernel/mod.rs")


if __name__ == "__main__":
    unittest.main()
