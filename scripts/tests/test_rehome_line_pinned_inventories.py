#!/usr/bin/env python3
"""Tests for re-homing line-pinned inventories when functions move files."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts/migrate/reconcile-line-pinned-inventories.py"

SPEC = importlib.util.spec_from_file_location("reconcile_line_pinned_inventories", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
RECONCILE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECONCILE
SPEC.loader.exec_module(RECONCILE)

RefusedError = RECONCILE.RefusedError


class RehomeInventoriesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        # Create synthetic directory structure
        self.migrate_dir = self.root / "scripts" / "migrate"
        self.aborts_dir = self.migrate_dir / "runtime-aborts"
        self.aborts_dir.mkdir(parents=True)

        self.runtime_src = self.root / "crates" / "carrick-runtime" / "src"
        self.hvf_src = self.root / "crates" / "carrick-vmm-hvf" / "src"
        self.runtime_src.mkdir(parents=True)
        self.hvf_src.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def _init_empty_shards(self, skip: str | None = None):
        cra = RECONCILE.load_script("check-runtime-aborts.py")
        for shard in cra.SHARD_NAMES:
            if shard == skip:
                continue
            path = self.aborts_dir / shard
            path.write_text(json.dumps({"schema": 1, "shard": shard, "rows": []}, indent=2) + "\n")

    def test_function_moved_verbatim_rehomes_exactly_its_rows(self):
        """A function moved verbatim to a new file re-homes exactly its rows."""
        cra = RECONCILE.load_script("check-runtime-aborts.py")
        self._init_empty_shards(skip="hvf.json")

        fn_code = (
            "pub fn moved_worker() {\n"
            "    carrick_fatal!(\"test::domain\", \"something failed\");\n"
            "}\n"
        )
        file_b = self.hvf_src / "target_worker.rs"
        file_b.write_text(fn_code, encoding="utf-8")

        rel_a = "crates/carrick-vmm-hvf/src/source_worker.rs"
        rel_b = "crates/carrick-vmm-hvf/src/target_worker.rs"

        findings_b = cra.scan_abort_source(rel_b, fn_code)
        self.assertEqual(len(findings_b), 1)
        finding = findings_b[0]

        # In hvf.json, the row was recorded under file_a
        hvf_shard = self.aborts_dir / "hvf.json"
        row = {
            "file": rel_a,
            "function": "moved_worker",
            "ordinal_in_function": 1,
            "fingerprint": finding.fingerprint,
            "verdict": "carrier_fault",
            "failure_domain": "test::domain",
            "rationale": "Reviewed rationale that must be preserved.",
            "sink": "fatal",
            "domain": "test::domain",
        }
        hvf_shard.write_text(json.dumps({"schema": 1, "shard": "hvf.json", "rows": [row]}, indent=2) + "\n")

        # Without rehome, this must be refused
        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_runtime_aborts(rehome=False, root=self.root)

        # With rehome, the row re-homes to rel_b
        rebound = RECONCILE.reconcile_runtime_aborts(rehome=True, root=self.root)
        self.assertEqual(rebound, 1)

        updated_ledger = json.loads(hvf_shard.read_text())
        self.assertEqual(len(updated_ledger["rows"]), 1)
        updated_row = updated_ledger["rows"][0]
        self.assertEqual(updated_row["file"], rel_b)
        self.assertEqual(updated_row["function"], "moved_worker")
        self.assertEqual(updated_row["ordinal_in_function"], 1)
        self.assertEqual(updated_row["fingerprint"], finding.fingerprint)
        self.assertEqual(updated_row["rationale"], "Reviewed rationale that must be preserved.")
        self.assertEqual(updated_row["verdict"], "carrier_fault")

    def test_moved_and_edited_function_fingerprint_differs_is_refused(self):
        """A moved-and-edited function (fingerprint differs) is refused."""
        cra = RECONCILE.load_script("check-runtime-aborts.py")
        self._init_empty_shards(skip="hvf.json")

        fn_code_edited = (
            "pub fn moved_worker() {\n"
            "    let x = 42;\n"
            "    if x > 0 {\n"
            "        carrick_fatal!(\"test::domain\", \"something failed\");\n"
            "    }\n"
            "}\n"
        )
        file_b = self.hvf_src / "target_worker.rs"
        file_b.write_text(fn_code_edited, encoding="utf-8")

        rel_a = "crates/carrick-vmm-hvf/src/source_worker.rs"
        hvf_shard = self.aborts_dir / "hvf.json"
        row = {
            "file": rel_a,
            "function": "moved_worker",
            "ordinal_in_function": 1,
            "fingerprint": "0" * 64,  # old fingerprint does not match edited
            "verdict": "carrier_fault",
            "failure_domain": "test::domain",
            "rationale": "Reviewed rationale.",
            "sink": "fatal",
            "domain": "test::domain",
        }
        hvf_shard.write_text(json.dumps({"schema": 1, "shard": "hvf.json", "rows": [row]}, indent=2) + "\n")

        with self.assertRaises(RefusedError) as ctx:
            RECONCILE.reconcile_runtime_aborts(rehome=True, root=self.root)
        self.assertIn("refused", str(ctx.exception).lower())

    def test_two_candidates_with_the_same_identity_are_refused(self):
        """Two candidates with the same identity are refused."""
        cra = RECONCILE.load_script("check-runtime-aborts.py")
        self._init_empty_shards(skip="hvf.json")

        fn_code = (
            "pub fn duplicate_worker() {\n"
            "    carrick_fatal!(\"test::domain\", \"duplicate site\");\n"
            "}\n"
        )
        file_b1 = self.hvf_src / "candidate_one.rs"
        file_b2 = self.hvf_src / "candidate_two.rs"
        file_b1.write_text(fn_code, encoding="utf-8")
        file_b2.write_text(fn_code, encoding="utf-8")

        findings_b1 = cra.scan_abort_source("crates/carrick-vmm-hvf/src/candidate_one.rs", fn_code)
        self.assertEqual(len(findings_b1), 1)

        rel_a = "crates/carrick-vmm-hvf/src/source_worker.rs"
        hvf_shard = self.aborts_dir / "hvf.json"
        row = {
            "file": rel_a,
            "function": "duplicate_worker",
            "ordinal_in_function": 1,
            "fingerprint": findings_b1[0].fingerprint,
            "verdict": "carrier_fault",
            "failure_domain": "test::domain",
            "rationale": "Reviewed rationale.",
            "sink": "fatal",
            "domain": "test::domain",
        }
        hvf_shard.write_text(json.dumps({"schema": 1, "shard": "hvf.json", "rows": [row]}, indent=2) + "\n")

        with self.assertRaises(RefusedError) as ctx:
            RECONCILE.reconcile_runtime_aborts(rehome=True, root=self.root)
        self.assertTrue(
            "ambiguous" in str(ctx.exception).lower() or "added" in str(ctx.exception).lower()
        )

    def test_row_whose_site_vanished_is_refused(self):
        """A row whose site vanished is refused."""
        self._init_empty_shards(skip="hvf.json")

        rel_a = "crates/carrick-vmm-hvf/src/source_worker.rs"
        hvf_shard = self.aborts_dir / "hvf.json"
        row = {
            "file": rel_a,
            "function": "vanished_worker",
            "ordinal_in_function": 1,
            "fingerprint": "1" * 64,
            "verdict": "carrier_fault",
            "failure_domain": "test::domain",
            "rationale": "Reviewed rationale.",
            "sink": "fatal",
            "domain": "test::domain",
        }
        hvf_shard.write_text(json.dumps({"schema": 1, "shard": "hvf.json", "rows": [row]}, indent=2) + "\n")

        with self.assertRaises(RefusedError) as ctx:
            RECONCILE.reconcile_runtime_aborts(rehome=True, root=self.root)
        self.assertIn("removed", str(ctx.exception).lower())

    def test_module_path_insensitive_function_matching(self):
        """A function inside inline `mod helper` moved to `helper.rs` root matches."""
        cra = RECONCILE.load_script("check-runtime-aborts.py")
        self._init_empty_shards(skip="hvf.json")

        old_fn_code = (
            "mod helper {\n"
            "    pub fn reset() {\n"
            "        carrick_fatal!(\"test::domain\", \"reset failed\");\n"
            "    }\n"
            "}\n"
        )
        findings_old = cra.scan_abort_source("crates/carrick-vmm-hvf/src/trap.rs", old_fn_code)
        self.assertEqual(len(findings_old), 1)
        self.assertEqual(findings_old[0].function, "helper::reset")

        new_fn_code = (
            "pub fn reset() {\n"
            "    carrick_fatal!(\"test::domain\", \"reset failed\");\n"
            "}\n"
        )
        file_b = self.hvf_src / "trap" / "helper.rs"
        file_b.parent.mkdir(parents=True, exist_ok=True)
        file_b.write_text(new_fn_code, encoding="utf-8")

        rel_a = "crates/carrick-vmm-hvf/src/trap.rs"
        rel_b = "crates/carrick-vmm-hvf/src/trap/helper.rs"

        hvf_shard = self.aborts_dir / "hvf.json"
        row = {
            "file": rel_a,
            "function": "helper::reset",
            "ordinal_in_function": 1,
            "fingerprint": findings_old[0].fingerprint,
            "verdict": "carrier_fault",
            "failure_domain": "test::domain",
            "rationale": "Reviewed rationale.",
            "sink": "fatal",
            "domain": "test::domain",
        }
        hvf_shard.write_text(json.dumps({"schema": 1, "shard": "hvf.json", "rows": [row]}, indent=2) + "\n")

        rebound = RECONCILE.reconcile_runtime_aborts(rehome=True, root=self.root)
        self.assertEqual(rebound, 1)

        updated = json.loads(hvf_shard.read_text())
        self.assertEqual(updated["rows"][0]["file"], rel_b)
        self.assertEqual(updated["rows"][0]["function"], "reset")

    # --- Host Authority Tests ---

    def test_host_authority_moved_verbatim_rehomes(self):
        """Host authority row moved verbatim re-homes when enclosing function matches."""
        target_file = self.hvf_src / "target_ha.rs"
        target_file.write_text(
            "pub fn moved_ha_fn() {\n"
            "    unsafe { libc::geteuid(); }\n"
            "}\n",
            encoding="utf-8",
        )
        rel_a = "crates/carrick-vmm-hvf/src/source_ha.rs"
        rel_b = "crates/carrick-vmm-hvf/src/target_ha.rs"

        cand_data = {
            "capture_receipt": {"kind": "macos_hvf", "rows": []},
            "rows": [
                {
                    "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
                    "operation": "libc::geteuid",
                    "source": {
                        "file": rel_b,
                        "line": 2,
                        "column": 14,
                        "column_start": 14,
                        "column_end": 27,
                        "line_start": 2,
                        "line_end": 2,
                        "byte_start": 35,
                        "byte_end": 48,
                    },
                    "expansion": None,
                    "profiles": ["macos-hvf-default"],
                }
            ],
        }
        cand_path = self.root / "candidate.json"
        cand_path.write_text(json.dumps(cand_data, indent=2) + "\n")

        inv_path = self.migrate_dir / "host-authority-transition-inventory.json"
        cap_path = self.migrate_dir / "host-authority-macos-capture.json"
        cap_path.write_text(json.dumps({"kind": "macos_hvf", "rows": []}, indent=2) + "\n")

        row = {
            "review_id": "HA-000001",
            "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
            "operation": "libc::geteuid",
            "classification": "declared_substrate",
            "evidence": {"authority": "carrier", "resource": "res"},
            "expansion": None,
            "profiles": ["macos-hvf-default"],
            "rationale": f"At {rel_a}:10 in `moved_ha_fn`, libc::geteuid is checked.",
            "source": {
                "file": rel_a,
                "line": 10,
                "column": 14,
                "column_start": 14,
                "column_end": 27,
                "line_start": 10,
                "line_end": 10,
                "byte_start": 120,
                "byte_end": 133,
            },
        }
        inv_path.write_text(json.dumps([row], indent=2) + "\n")

        # Without rehome, group is dropped or refused
        rebound = RECONCILE.reconcile_host_authority(
            candidate_path=cand_path,
            inventory_path=inv_path,
            capture_path=cap_path,
            rehome=False,
            root=self.root,
        )
        self.assertEqual(rebound, 0)
        # Should not have rebound to rel_b when rehome=False
        inv_check = json.loads(inv_path.read_text())
        self.assertFalse(any(r["source"]["file"] == rel_b for r in inv_check))

        # Reset inventory for rehome=True
        inv_path.write_text(json.dumps([row], indent=2) + "\n")
        rebound = RECONCILE.reconcile_host_authority(
            candidate_path=cand_path,
            inventory_path=inv_path,
            capture_path=cap_path,
            rehome=True,
            root=self.root,
        )
        self.assertEqual(rebound, 1)

        updated_inv = json.loads(inv_path.read_text())
        self.assertEqual(len(updated_inv), 1)
        up_row = updated_inv[0]
        self.assertEqual(up_row["source"]["file"], rel_b)
        self.assertEqual(up_row["source"]["line"], 2)
        self.assertIn(f"At {rel_b}:2 in `moved_ha_fn`", up_row["rationale"])

    def test_host_authority_aliased_function_rehomes(self):
        """Host authority row with aliased historical function name re-homes properly."""
        target_file = self.hvf_src / "target_ha.rs"
        target_file.write_text(
            "pub fn discover_orphans() {\n"
            "    let _ = std::fs::read_dir(\"/tmp\");\n"
            "}\n",
            encoding="utf-8",
        )
        rel_a = "crates/carrick-vmm-hvf/src/source_ha.rs"
        rel_b = "crates/carrick-vmm-hvf/src/target_ha.rs"

        cand_data = {
            "capture_receipt": {"kind": "macos_hvf", "rows": []},
            "rows": [
                {
                    "catalog_id": "HA-CATALOG-FS-READ-DIR",
                    "operation": "std::fs::read_dir",
                    "source": {
                        "file": rel_b,
                        "line": 2,
                        "column": 13,
                        "column_start": 13,
                        "column_end": 38,
                        "line_start": 2,
                        "line_end": 2,
                        "byte_start": 40,
                        "byte_end": 65,
                    },
                    "expansion": None,
                    "profiles": ["macos-hvf-default"],
                }
            ],
        }
        cand_path = self.root / "candidate.json"
        cand_path.write_text(json.dumps(cand_data, indent=2) + "\n")

        inv_path = self.migrate_dir / "host-authority-transition-inventory.json"
        cap_path = self.migrate_dir / "host-authority-macos-capture.json"
        cap_path.write_text(json.dumps({"kind": "macos_hvf", "rows": []}, indent=2) + "\n")

        row = {
            "catalog_id": "HA-CATALOG-FS-READ-DIR",
            "operation": "std::fs::read_dir",
            "classification": "reviewed",
            "rationale": f"At {rel_a}:10 in `sweep_orphans`, std::fs::read_dir accesses only scratch directory.",
            "review_id": "HA-000260",
            "profiles": ["macos-hvf-default"],
            "evidence": {"authority": "authorized_backing", "resource": "scratch tree used by `sweep_orphans`"},
            "expansion": None,
            "source": {
                "file": rel_a,
                "line": 10,
                "column": 13,
                "column_start": 13,
                "column_end": 38,
                "line_start": 10,
                "line_end": 10,
                "byte_start": 150,
                "byte_end": 175,
            },
        }
        inv_path.write_text(json.dumps([row], indent=2) + "\n")
        rebound = RECONCILE.reconcile_host_authority(
            candidate_path=cand_path,
            inventory_path=inv_path,
            capture_path=cap_path,
            rehome=True,
            root=self.root,
        )
        self.assertEqual(rebound, 1)

        updated_inv = json.loads(inv_path.read_text())
        self.assertEqual(len(updated_inv), 1)
        up_row = updated_inv[0]
        self.assertEqual(up_row["source"]["file"], rel_b)
        self.assertEqual(up_row["source"]["line"], 2)
        self.assertIn(f"At {rel_b}:2 in `discover_orphans`", up_row["rationale"])
        self.assertIn("used by `discover_orphans`", up_row["evidence"]["resource"])

    def test_host_authority_different_operation_refused(self):
        """Host authority candidate with different operation is refused."""
        target_file = self.hvf_src / "target_ha.rs"
        target_file.write_text("pub fn moved_ha_fn() { unsafe { libc::getpid(); } }\n", encoding="utf-8")
        rel_a = "crates/carrick-vmm-hvf/src/source_ha.rs"
        rel_b = "crates/carrick-vmm-hvf/src/target_ha.rs"

        cand_data = {
            "capture_receipt": {"kind": "macos_hvf", "rows": []},
            "rows": [
                {
                    "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
                    "operation": "libc::getpid",  # differs from libc::geteuid
                    "source": {"file": rel_b, "line": 1, "column": 1, "column_start": 1, "column_end": 10, "line_start": 1, "line_end": 1, "byte_start": 1, "byte_end": 10},
                    "expansion": None,
                    "profiles": ["macos-hvf-default"],
                }
            ],
        }
        cand_path = self.root / "candidate.json"
        cand_path.write_text(json.dumps(cand_data, indent=2) + "\n")
        inv_path = self.migrate_dir / "host-authority-transition-inventory.json"
        cap_path = self.migrate_dir / "host-authority-macos-capture.json"
        cap_path.write_text(json.dumps({"kind": "macos_hvf", "rows": []}, indent=2) + "\n")

        row = {
            "review_id": "HA-000001",
            "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
            "operation": "libc::geteuid",
            "classification": "declared_substrate",
            "evidence": {"authority": "carrier", "resource": "res"},
            "expansion": None,
            "profiles": ["macos-hvf-default"],
            "rationale": f"At {rel_a}:10 in `moved_ha_fn`, libc::geteuid is checked.",
            "source": {"file": rel_a, "line": 10, "column": 1, "column_start": 1, "column_end": 10, "line_start": 10, "line_end": 10, "byte_start": 1, "byte_end": 10},
        }
        inv_path.write_text(json.dumps([row], indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_host_authority(
                candidate_path=cand_path,
                inventory_path=inv_path,
                capture_path=cap_path,
                rehome=True,
                root=self.root,
            )

    def test_host_authority_two_duplicate_candidates_refused(self):
        """Host authority with two duplicate candidate sites is refused (ambiguous)."""
        target_file = self.hvf_src / "target_ha.rs"
        target_file.write_text("pub fn moved_ha_fn() { unsafe { libc::geteuid(); libc::geteuid(); } }\n", encoding="utf-8")
        rel_a = "crates/carrick-vmm-hvf/src/source_ha.rs"
        rel_b = "crates/carrick-vmm-hvf/src/target_ha.rs"

        cand_data = {
            "capture_receipt": {"kind": "macos_hvf", "rows": []},
            "rows": [
                {
                    "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
                    "operation": "libc::geteuid",
                    "source": {"file": rel_b, "line": 1, "column": 1, "column_start": 1, "column_end": 10, "line_start": 1, "line_end": 1, "byte_start": 1, "byte_end": 10},
                    "expansion": None,
                    "profiles": ["macos-hvf-default"],
                },
                {
                    "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
                    "operation": "libc::geteuid",
                    "source": {"file": rel_b, "line": 1, "column": 20, "column_start": 20, "column_end": 30, "line_start": 1, "line_end": 1, "byte_start": 20, "byte_end": 30},
                    "expansion": None,
                    "profiles": ["macos-hvf-default"],
                },
            ],
        }
        cand_path = self.root / "candidate.json"
        cand_path.write_text(json.dumps(cand_data, indent=2) + "\n")
        inv_path = self.migrate_dir / "host-authority-transition-inventory.json"
        cap_path = self.migrate_dir / "host-authority-macos-capture.json"
        cap_path.write_text(json.dumps({"kind": "macos_hvf", "rows": []}, indent=2) + "\n")

        row = {
            "review_id": "HA-000001",
            "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
            "operation": "libc::geteuid",
            "classification": "declared_substrate",
            "evidence": {"authority": "carrier", "resource": "res"},
            "expansion": None,
            "profiles": ["macos-hvf-default"],
            "rationale": f"At {rel_a}:10 in `moved_ha_fn`, libc::geteuid is checked.",
            "source": {"file": rel_a, "line": 10, "column": 1, "column_start": 1, "column_end": 10, "line_start": 10, "line_end": 10, "byte_start": 1, "byte_end": 10},
        }
        inv_path.write_text(json.dumps([row], indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_host_authority(
                candidate_path=cand_path,
                inventory_path=inv_path,
                capture_path=cap_path,
                rehome=True,
                root=self.root,
            )

    def test_host_authority_vanished_site_refused(self):
        """Host authority row with no candidates is refused when rehome=True."""
        cand_data = {
            "capture_receipt": {"kind": "macos_hvf", "rows": []},
            "rows": [],
        }
        cand_path = self.root / "candidate.json"
        cand_path.write_text(json.dumps(cand_data, indent=2) + "\n")
        inv_path = self.migrate_dir / "host-authority-transition-inventory.json"
        cap_path = self.migrate_dir / "host-authority-macos-capture.json"
        cap_path.write_text(json.dumps({"kind": "macos_hvf", "rows": []}, indent=2) + "\n")

        rel_a = "crates/carrick-vmm-hvf/src/source_ha.rs"
        row = {
            "review_id": "HA-000001",
            "catalog_id": "HA-CATALOG-PROCESS-GETEUID",
            "operation": "libc::geteuid",
            "classification": "declared_substrate",
            "evidence": {"authority": "carrier", "resource": "res"},
            "expansion": None,
            "profiles": ["macos-hvf-default"],
            "rationale": f"At {rel_a}:10 in `moved_ha_fn`, libc::geteuid is checked.",
            "source": {"file": rel_a, "line": 10, "column": 1, "column_start": 1, "column_end": 10, "line_start": 10, "line_end": 10, "byte_start": 1, "byte_end": 10},
        }
        inv_path.write_text(json.dumps([row], indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_host_authority(
                candidate_path=cand_path,
                inventory_path=inv_path,
                capture_path=cap_path,
                rehome=True,
                root=self.root,
            )

    # --- Dispatch Lock Authority Tests ---

    def test_dispatch_lock_moved_verbatim_rehomes(self):
        """Dispatch lock site moved verbatim to a new file re-homes its row."""
        rel_a = "crates/carrick-runtime/src/dispatch/source_mod.rs"
        rel_b = "crates/carrick-runtime/src/dispatch/target_mod.rs"

        old_id = f"{rel_a}::SyscallDispatcher::moved_lock_fn::proc#1"
        new_id = f"{rel_b}::SyscallDispatcher::moved_lock_fn::proc#1"

        inv_path = self.migrate_dir / "dispatch-lock-authority.json"
        row = {
            "id": old_id,
            "file": rel_a,
            "line": 10,
            "item": "SyscallDispatcher::moved_lock_fn",
            "category": "proc",
            "expression": "self.proc.lock()",
            "ordinal": 1,
        }
        inv_path.write_text(json.dumps({"schema": 1, "sites": [row]}, indent=2) + "\n")

        cand_row = {
            "id": new_id,
            "file": rel_b,
            "line": 25,
            "item": "SyscallDispatcher::moved_lock_fn",
            "category": "proc",
            "expression": "self.proc.lock()",
            "ordinal": 1,
        }
        cand_path = self.root / "cand_locks.json"
        cand_path.write_text(json.dumps({"schema": 1, "sites": [cand_row]}, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_dispatch_locks(
                candidate_path=cand_path,
                inventory_path=inv_path,
                rehome=False,
                root=self.root,
            )

        rebound = RECONCILE.reconcile_dispatch_locks(
            candidate_path=cand_path,
            inventory_path=inv_path,
            rehome=True,
            root=self.root,
        )
        self.assertEqual(rebound, 1)

        updated_inv = json.loads(inv_path.read_text())
        up_row = updated_inv["sites"][0]
        self.assertEqual(up_row["id"], new_id)
        self.assertEqual(up_row["file"], rel_b)
        self.assertEqual(up_row["line"], 25)

    def test_dispatch_lock_expression_differs_refused(self):
        """Dispatch lock site with expression changed is refused."""
        rel_a = "crates/carrick-runtime/src/dispatch/source_mod.rs"
        rel_b = "crates/carrick-runtime/src/dispatch/target_mod.rs"

        old_id = f"{rel_a}::SyscallDispatcher::moved_lock_fn::proc#1"
        new_id = f"{rel_b}::SyscallDispatcher::moved_lock_fn::proc#1"

        inv_path = self.migrate_dir / "dispatch-lock-authority.json"
        row = {
            "id": old_id,
            "file": rel_a,
            "line": 10,
            "item": "SyscallDispatcher::moved_lock_fn",
            "category": "proc",
            "expression": "self.proc.lock()",
            "ordinal": 1,
        }
        inv_path.write_text(json.dumps({"schema": 1, "sites": [row]}, indent=2) + "\n")

        cand_row = {
            "id": new_id,
            "file": rel_b,
            "line": 25,
            "item": "SyscallDispatcher::moved_lock_fn",
            "category": "proc",
            "expression": "self.proc.try_lock()",  # differs!
            "ordinal": 1,
        }
        cand_path = self.root / "cand_locks.json"
        cand_path.write_text(json.dumps({"schema": 1, "sites": [cand_row]}, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_dispatch_locks(
                candidate_path=cand_path,
                inventory_path=inv_path,
                rehome=True,
                root=self.root,
            )

    def test_dispatch_lock_two_duplicate_candidates_refused(self):
        """Two duplicate candidates for dispatch lock are refused."""
        rel_a = "crates/carrick-runtime/src/dispatch/source_mod.rs"
        rel_b1 = "crates/carrick-runtime/src/dispatch/target_mod1.rs"
        rel_b2 = "crates/carrick-runtime/src/dispatch/target_mod2.rs"

        old_id = f"{rel_a}::SyscallDispatcher::moved_lock_fn::proc#1"
        new_id1 = f"{rel_b1}::SyscallDispatcher::moved_lock_fn::proc#1"
        new_id2 = f"{rel_b2}::SyscallDispatcher::moved_lock_fn::proc#1"

        inv_path = self.migrate_dir / "dispatch-lock-authority.json"
        row = {
            "id": old_id,
            "file": rel_a,
            "line": 10,
            "item": "SyscallDispatcher::moved_lock_fn",
            "category": "proc",
            "expression": "self.proc.lock()",
            "ordinal": 1,
        }
        inv_path.write_text(json.dumps({"schema": 1, "sites": [row]}, indent=2) + "\n")

        cand_rows = [
            {"id": new_id1, "file": rel_b1, "line": 25, "item": "SyscallDispatcher::moved_lock_fn", "category": "proc", "expression": "self.proc.lock()", "ordinal": 1},
            {"id": new_id2, "file": rel_b2, "line": 25, "item": "SyscallDispatcher::moved_lock_fn", "category": "proc", "expression": "self.proc.lock()", "ordinal": 1},
        ]
        cand_path = self.root / "cand_locks.json"
        cand_path.write_text(json.dumps({"schema": 1, "sites": cand_rows}, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_dispatch_locks(
                candidate_path=cand_path,
                inventory_path=inv_path,
                rehome=True,
                root=self.root,
            )

    def test_dispatch_lock_vanished_site_refused(self):
        """Dispatch lock site with no candidates is refused."""
        rel_a = "crates/carrick-runtime/src/dispatch/source_mod.rs"
        old_id = f"{rel_a}::SyscallDispatcher::moved_lock_fn::proc#1"

        inv_path = self.migrate_dir / "dispatch-lock-authority.json"
        row = {
            "id": old_id,
            "file": rel_a,
            "line": 10,
            "item": "SyscallDispatcher::moved_lock_fn",
            "category": "proc",
            "expression": "self.proc.lock()",
            "ordinal": 1,
        }
        inv_path.write_text(json.dumps({"schema": 1, "sites": [row]}, indent=2) + "\n")

        cand_path = self.root / "cand_locks.json"
        cand_path.write_text(json.dumps({"schema": 1, "sites": []}, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_dispatch_locks(
                candidate_path=cand_path,
                inventory_path=inv_path,
                rehome=True,
                root=self.root,
            )

    # --- K1 Taxonomy Tests ---

    def test_k1_taxonomy_moved_verbatim_rehomes(self):
        """K1 taxonomy entry moved verbatim to a new file re-homes its row."""
        rel_a = "crates/carrick-runtime/src/source_k1.rs"
        rel_b = "crates/carrick-runtime/src/target_k1.rs"

        target_file = self.root / rel_b
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            "pub fn moved_k1_fn() {\n"
            "    let open = open_file.description.read().ok_or(LINUX_EINVAL)?;\n"
            "}\n",
            encoding="utf-8",
        )

        inv_path = self.migrate_dir / "k1-file-authority-operation-inventory.json"
        inv_data = {
            "schema": 1,
            "counts": {"description_guard": 1},
            "entries": [
                {
                    "file": rel_b,
                    "line": 2,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                }
            ],
        }
        inv_path.write_text(json.dumps(inv_data, indent=2) + "\n")

        tax_path = self.migrate_dir / "k1-file-authority-callsite-taxonomy.json"
        tax_data = {
            "schema": 1,
            "counts": {"inspect_misc": 1},
            "entries": [
                {
                    "file": rel_a,
                    "line": 10,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                    "enclosing_function": "moved_k1_fn",
                    "migration_family": "inspect_misc",
                }
            ],
        }
        tax_path.write_text(json.dumps(tax_data, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_k1_taxonomy(
                inventory_path=inv_path,
                taxonomy_path=tax_path,
                rehome=False,
                root=self.root,
            )

        rebound = RECONCILE.reconcile_k1_taxonomy(
            inventory_path=inv_path,
            taxonomy_path=tax_path,
            rehome=True,
            root=self.root,
        )
        self.assertEqual(rebound, 1)

        updated_tax = json.loads(tax_path.read_text())
        up_entry = updated_tax["entries"][0]
        self.assertEqual(up_entry["file"], rel_b)
        self.assertEqual(up_entry["line"], 2)
        self.assertEqual(up_entry["enclosing_function"], "moved_k1_fn")

    def test_k1_taxonomy_text_differs_refused(self):
        """K1 taxonomy candidate with different text is refused."""
        rel_a = "crates/carrick-runtime/src/source_k1.rs"
        rel_b = "crates/carrick-runtime/src/target_k1.rs"

        target_file = self.root / rel_b
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("pub fn moved_k1_fn() { let open = foo; }\n", encoding="utf-8")

        inv_path = self.migrate_dir / "k1-file-authority-operation-inventory.json"
        inv_data = {
            "schema": 1,
            "counts": {"description_guard": 1},
            "entries": [
                {
                    "file": rel_b,
                    "line": 1,
                    "categories": ["description_guard"],
                    "text": "let open = foo;",  # differs!
                    "scope_kind": "production_callsite",
                }
            ],
        }
        inv_path.write_text(json.dumps(inv_data, indent=2) + "\n")

        tax_path = self.migrate_dir / "k1-file-authority-callsite-taxonomy.json"
        tax_data = {
            "schema": 1,
            "counts": {"inspect_misc": 1},
            "entries": [
                {
                    "file": rel_a,
                    "line": 10,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                    "enclosing_function": "moved_k1_fn",
                    "migration_family": "inspect_misc",
                }
            ],
        }
        tax_path.write_text(json.dumps(tax_data, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_k1_taxonomy(
                inventory_path=inv_path,
                taxonomy_path=tax_path,
                rehome=True,
                root=self.root,
            )

    def test_k1_taxonomy_two_duplicate_candidates_refused(self):
        """Two duplicate K1 candidates are refused (ambiguous)."""
        rel_a = "crates/carrick-runtime/src/source_k1.rs"
        rel_b = "crates/carrick-runtime/src/target_k1.rs"

        target_file = self.root / rel_b
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            "pub fn moved_k1_fn() {\n"
            "    let open = open_file.description.read().ok_or(LINUX_EINVAL)?;\n"
            "    let open2 = open_file.description.read().ok_or(LINUX_EINVAL)?;\n"
            "}\n",
            encoding="utf-8",
        )

        inv_path = self.migrate_dir / "k1-file-authority-operation-inventory.json"
        inv_data = {
            "schema": 1,
            "counts": {"description_guard": 2},
            "entries": [
                {
                    "file": rel_b,
                    "line": 2,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                },
                {
                    "file": rel_b,
                    "line": 3,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                },
            ],
        }
        inv_path.write_text(json.dumps(inv_data, indent=2) + "\n")

        tax_path = self.migrate_dir / "k1-file-authority-callsite-taxonomy.json"
        tax_data = {
            "schema": 1,
            "counts": {"inspect_misc": 1},
            "entries": [
                {
                    "file": rel_a,
                    "line": 10,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                    "enclosing_function": "moved_k1_fn",
                    "migration_family": "inspect_misc",
                }
            ],
        }
        tax_path.write_text(json.dumps(tax_data, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_k1_taxonomy(
                inventory_path=inv_path,
                taxonomy_path=tax_path,
                rehome=True,
                root=self.root,
            )

    def test_k1_taxonomy_vanished_site_refused(self):
        """K1 taxonomy entry with no candidates in inventory is refused."""
        rel_a = "crates/carrick-runtime/src/source_k1.rs"

        inv_path = self.migrate_dir / "k1-file-authority-operation-inventory.json"
        inv_data = {
            "schema": 1,
            "counts": {},
            "entries": [],
        }
        inv_path.write_text(json.dumps(inv_data, indent=2) + "\n")

        tax_path = self.migrate_dir / "k1-file-authority-callsite-taxonomy.json"
        tax_data = {
            "schema": 1,
            "counts": {"inspect_misc": 1},
            "entries": [
                {
                    "file": rel_a,
                    "line": 10,
                    "categories": ["description_guard"],
                    "text": "let open = open_file.description.read().ok_or(LINUX_EINVAL)?;",
                    "scope_kind": "production_callsite",
                    "enclosing_function": "moved_k1_fn",
                    "migration_family": "inspect_misc",
                }
            ],
        }
        tax_path.write_text(json.dumps(tax_data, indent=2) + "\n")

        with self.assertRaises(RefusedError):
            RECONCILE.reconcile_k1_taxonomy(
                inventory_path=inv_path,
                taxonomy_path=tax_path,
                rehome=True,
                root=self.root,
            )


if __name__ == "__main__":
    unittest.main()
