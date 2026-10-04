#!/usr/bin/env python3
"""Tests for --rename / --rename-only on the line-pinned inventory reconciler.

pytest is not installed on this host, so this is stdlib unittest rather than
the pytest-style test in the plan brief (tmp_path fixture -> TemporaryDirectory,
bare `def test_...(tmp_path)` -> a TestCase method); the assertions are the
same.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "reconcile-line-pinned-inventories.py"


def _load_reconciler():
    """Import reconcile-line-pinned-inventories.py as a module (not a
    subprocess) so tests can call its functions directly and inject a fake
    `runner` -- the same technique the module itself uses to load its sibling
    checker scripts."""
    spec = importlib.util.spec_from_file_location("reconcile_line_pinned_inventories", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


OLD_FILE = "crates/carrick-runtime/src/vfs/mount.rs"
NEW_FILE = "crates/carrick-vfs/src/mount.rs"
RENAME = f"crates/carrick-runtime/src/vfs/={('crates/carrick-vfs/src/')}"


def _host_authority_row(file_: str, line: int = 10) -> dict:
    return {
        "catalog_id": "HA-TEST",
        "classification": "declared_substrate",
        "evidence": {"authority": "authenticated_carrier", "resource": "the live thing"},
        "expansion": None,
        "operation": "test_op",
        "profiles": ["macos-cli-default"],
        "rationale": f"At {file_}:{line} in `foo`, test_op acts only on its own thing.",
        "review_id": "HA-000001",
        "source": {
            "byte_end": 20,
            "byte_start": 10,
            "column": 5,
            "column_end": 8,
            "column_start": 5,
            "file": file_,
            "line": line,
            "line_end": line,
            "line_start": line,
        },
    }


class HostAuthorityRenameTests(unittest.TestCase):
    """Covers review-round-1 findings 1 and 2 on `reconcile_host_authority`."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = _load_reconciler()

    def _write(self, name: str, value) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def test_rename_rebinds_rationale_file_line_binding(self) -> None:
        """Finding 1: a rename must not leave `rationale` naming the OLD file
        while `source.file` already names the NEW one -- that combination is
        exactly what `validate_source_specific_reviews` rejects."""
        inv_path = self._write("inv.json", [_host_authority_row(OLD_FILE)])
        cap_path = self._write("cap.json", {"kind": "test-capture", "rows": []})
        candidate_path = self._write(
            "candidate.json",
            {
                "rows": [
                    {
                        "catalog_id": "HA-TEST",
                        "operation": "test_op",
                        "source": _host_authority_row(NEW_FILE)["source"],
                    }
                ],
                "executed_profiles": ["macos-cli-default"],
                "capture_receipt": {"rows": []},
            },
        )

        rebound = self.module.reconcile_host_authority(
            rehome=True,
            renames=[RENAME],
            candidate_path=candidate_path,
            inventory_path=inv_path,
            capture_path=cap_path,
        )

        rows = json.loads(inv_path.read_text())
        self.assertEqual(rows[0]["source"]["file"], NEW_FILE)
        # The exact substring `check-host-authority-transitions.py` requires.
        self.assertIn(f"{NEW_FILE}:10", rows[0]["rationale"])
        self.assertNotIn(OLD_FILE, rows[0]["rationale"])
        # source spans were identical apart from the file, so rha's own
        # position pass found nothing left to move -- proving the rationale
        # fix is ours, not a side effect of the delegate's line rebinder.
        self.assertEqual(rebound, 0)

    def test_capture_runs_before_rename_write(self) -> None:
        """Finding 2: the tracked inventory must not be rewritten until AFTER
        the authoritative `--refresh-candidate` capture has run, since that
        capture requires a clean tracked tree under `scripts/` and our own
        rewrite would otherwise dirty it first."""
        inv_path = self._write("inv.json", [_host_authority_row(OLD_FILE)])
        cap_path = self._write("cap.json", {"kind": "test-capture", "rows": []})

        observed_inventory_at_capture_time: list[str] = []

        def fake_runner(cmd, check=False, stdout=None, stderr=None):
            observed_inventory_at_capture_time.append(inv_path.read_text())
            idx = cmd.index("--refresh-candidate")
            candidate_out = Path(cmd[idx + 1])
            candidate_out.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "catalog_id": "HA-TEST",
                                "operation": "test_op",
                                "source": _host_authority_row(NEW_FILE)["source"],
                            }
                        ],
                        "executed_profiles": ["macos-cli-default"],
                        "capture_receipt": {"rows": []},
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0)

        self.module.reconcile_host_authority(
            rehome=True,
            renames=[RENAME],
            inventory_path=inv_path,
            capture_path=cap_path,
            runner=fake_runner,
        )

        self.assertEqual(len(observed_inventory_at_capture_time), 1)
        self.assertIn(OLD_FILE, observed_inventory_at_capture_time[0])
        self.assertNotIn(NEW_FILE, observed_inventory_at_capture_time[0])

        rows = json.loads(inv_path.read_text())
        self.assertEqual(rows[0]["source"]["file"], NEW_FILE)
        self.assertIn(f"{NEW_FILE}:10", rows[0]["rationale"])


class HostAuthorityProfileTests(unittest.TestCase):
    """Keep host-specific drift checks in the tests run by lint-domains."""

    def setUp(self) -> None:
        checker = SCRIPT.with_name("check-host-authority-transitions.py")
        spec = importlib.util.spec_from_file_location("host_authority_profiles", checker)
        self.checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checker)
        self.inventory = self.checker.load_inventory(self.checker.INVENTORY_PATH)
        self.matrix = self.checker.load_matrix(self.checker.MATRIX_PATH)

    def project(self, profiles: list[str]) -> list[dict]:
        rows = []
        for reviewed in self.inventory:
            projected = sorted(set(reviewed["profiles"]) & set(profiles))
            if projected:
                rows.append({
                    field: projected if field == "profiles" else reviewed[field]
                    for field in self.checker.ACTUAL_FIELDS
                })
        return rows

    def test_linux_projection_rejects_added_removed_and_changed_sites(self) -> None:
        profiles = self.checker.select_profiles(self.matrix, None, current_host="linux")
        self.assertEqual(profiles, ["linux-cli", "linux-runtime"])
        actual = self.project(profiles)
        self.assertTrue(actual, "Linux must have reviewed rows")
        self.checker.validate(actual, self.inventory, profiles, self.matrix.required_profiles)

        # A fake new Linux-only call must fail even when the macOS receipt's
        # projection is unchanged. The live compiler breaker also exercises
        # this with a real added std::process::id call in an isolated checkout.
        new_site = {
            **actual[0],
            "catalog_id": "HA-CATALOG-PROCESS-ID",
            "operation": "std::process::id",
            "source": {**actual[0]["source"], "file": "crates/fake/src/linux.rs"},
            "expansion": None,
            "profiles": profiles,
        }
        changed = [{**actual[0], "profiles": ["linux-cli"]}, *actual[1:]]
        for label, drift in (
            ("new", [*actual, new_site]),
            ("removed", actual[1:]),
            ("changed", changed),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(self.checker.InventoryError, "inventory drift"):
                    self.checker.validate(
                        drift, self.inventory, profiles, self.matrix.required_profiles
                    )

    def test_macos_receipt_checks_shared_projection_and_all_reviews(self) -> None:
        catalog = self.checker.load_catalog_manifest(self.checker.CATALOG_MANIFEST_PATH)
        receipt = self.checker.load_capture_receipt(
            self.checker.MACOS_CAPTURE_PATH, self.matrix, catalog
        )
        self.checker.validate_inventory_against_receipt(self.inventory, receipt)
        linux_only = next(
            row for row in self.inventory
            if not set(row["profiles"]) & set(receipt["executed_profiles"])
        )
        malformed = [
            {**row, "classification": "unreviewed"} if row is linux_only else row
            for row in self.inventory
        ]
        with self.assertRaises(self.checker.InventoryError):
            self.checker.validate_inventory_against_receipt(malformed, receipt)
        profiles = list(receipt["executed_profiles"])
        self.checker.validate(
            self.project(profiles), self.inventory, profiles, self.matrix.required_profiles
        )

    def test_foreign_profile_selection_fails_explicitly(self) -> None:
        with self.assertRaisesRegex(self.checker.InventoryError, "unavailable on current host"):
            self.checker.select_profiles(self.matrix, "macos-*", current_host="linux")


if __name__ == "__main__":
    unittest.main()
