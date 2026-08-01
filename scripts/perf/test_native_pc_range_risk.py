#!/usr/bin/env python3
"""Tests for authenticated paired native owner-risk classification."""

from __future__ import annotations

import hashlib
import json
import pathlib
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.perf import native_pc_range_risk as risk


def artifact(path: pathlib.Path) -> dict[str, object]:
    absolute = path.resolve()
    payload = absolute.read_bytes()
    return {
        "bytes": len(payload),
        "path": str(absolute),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def analysis(*, offset: int, owner_count: int, kernel: int = 10) -> dict[str, object]:
    return {
        "completion": {"target_exit": 1, "timed_out": 0},
        "host_binary_offsets": [{"count": owner_count, "offset": f"0x{offset:x}"}],
        "host_leaves": [],
        "host_text_ranges": {"reported": 1},
        "kernel_stack_capture": {
            "kernel_samples": kernel,
            "per_catalog_exact": True,
            "stack_samples": kernel,
        },
        "kernel_stacks": [{"count": kernel, "frames": ["kernel`vm_fault"]}],
        "leaf_capture": {
            "expected_outside_private_samples": owner_count,
            "observed_outside_private_samples": owner_count,
        },
        "ranges": {"private_reported": 1, "resets": 1, "shared_reported": 1},
        "samples": {"all": 100, "kernel": kernel, "user": 90},
        "schema": "carrick.native-pc-range-directional.v2",
        "warnings": [],
    }


class Campaign:
    def __init__(self, root: pathlib.Path, deltas: list[int] | None = None):
        self.root = root
        self.binary_path = root / "carrick"
        self.binary_path.write_bytes(b"exact signed binary")
        self.trace_script = root / "native-pc-range-directional.d"
        self.analyzer_path = root / "native_pc_range_directional.py"
        self.trace_script.write_text("dtrace program\n")
        self.analyzer_path.write_text("directional analyzer\n")
        self.binary = {
            **artifact(self.binary_path),
            "dof": {"address": 0x100400000, "offset": 40, "segment": "__TEXT", "size": 99},
            "entitlements": {"com.apple.security.hypervisor": True},
            "entitlements_sha256": "e" * 64,
            "macho_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            "text": {"fileoff": 0, "filesize": 4096, "vmaddr": 0x100000000, "vmsize": 4096},
        }
        self.output = root / "risk.json"
        self.paths: dict[str, list[pathlib.Path]] = {
            key: [] for key in ("v2_raw", "v2_analysis", "v2_capture", "v3_raw", "v3_analysis", "v3_capture")
        }
        for ordinal, delta in enumerate(deltas or [10, 10, 10, 10, 10], start=1):
            for mode, arm, offset, count in (
                ("v2", "control", 0x10, 1),
                ("mapped", "candidate", 0x20 if delta >= 0 else 0x10, 1 + abs(delta)),
            ):
                prefix = "v2" if mode == "v2" else "v3"
                raw = root / f"p{ordinal}-{prefix}.raw"
                analyzed = root / f"p{ordinal}-{prefix}.json"
                capture = root / f"p{ordinal}-{prefix}.capture.json"
                driver_stdout = root / f"p{ordinal}-{prefix}.driver.out"
                driver_stderr = root / f"p{ordinal}-{prefix}.driver.err"
                raw.write_text(f"unique raw pair={ordinal} mode={mode}\n", encoding="utf-8")
                analyzed.write_text(json.dumps(analysis(offset=offset, owner_count=count)), encoding="utf-8")
                driver_stdout.write_text(f"WORKLOAD_NS={ordinal}{0 if mode == 'v2' else 1}\nBUILD_OK\n")
                driver_stderr.write_text(f"TRACECHILD1|pair={ordinal}|mode={mode}\nok\n")
                overlay = {
                    "CARRICK_DSR_DIRECT_BINDINGS": "1",
                    "CARRICK_DSR_SHARED_MAPPED_METADATA": "0" if mode == "v2" else None,
                    "CARRICK_DSR_SHARED_TRANSLATION": "1",
                }
                identity = {"egid": 20, "euid": 501, "supplementary_gids": [12, 20]}
                receipt = {
                    "analyzer": {**artifact(self.analyzer_path), "schema": "carrick.native-pc-range-directional.v2"},
                    "artifacts": {
                        "analysis": artifact(analyzed),
                        "driver_stderr": artifact(driver_stderr),
                        "driver_stdout": artifact(driver_stdout),
                        "raw": artifact(raw),
                    },
                    "binary": self.binary,
                    "expected_effective_identity": identity,
                    "metadata_mode": mode,
                    "natural_completion": True,
                    "normalized_overlay": overlay,
                    "observed_effective_identity": identity,
                    "pair": {"arm": arm, "id": f"pair-{ordinal}", "order": 0 if arm == "control" else 1, "ordinal": ordinal},
                    "required_streams": {
                        "host_range": True,
                        "identity": True,
                        "kernel_pc_stack_per_catalog_exact": True,
                        "leaf_pc_exact": True,
                        "private_range": True,
                        "reset": True,
                        "shared_range": True,
                        "user_and_kernel_samples": True,
                    },
                    "run_id": f"run-p{ordinal}-{prefix}",
                    "schema": risk.CAPTURE_SCHEMA,
                    "status": "passed",
                    "trace_script": artifact(self.trace_script),
                    "workload": {"guest_script_sha256": "w" * 64, "image": "localhost:5005/carrick-go-conformance:1.24"},
                }
                capture.write_text(json.dumps(receipt), encoding="utf-8")
                self.paths[f"{prefix}_raw"].append(raw)
                self.paths[f"{prefix}_analysis"].append(analyzed)
                self.paths[f"{prefix}_capture"].append(capture)

    def argv(self) -> list[str]:
        argv: list[str] = []
        for index in range(5):
            for arm in ("v2", "v3"):
                for kind in ("raw", "analysis", "capture"):
                    argv.extend((f"--{arm}-{kind}", str(self.paths[f"{arm}_{kind}"][index])))
        argv.extend(("--binary", str(self.binary_path), "--output", str(self.output)))
        return argv


class NativePcRangeRiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def symbolizer(self, _binary, offsets):
        return {
            offset: {
                "absolute_address": f"0x{0x100000000 + offset:x}",
                "atos": (
                    "pthread_mutex_lock (in carrick)"
                    if offset == 0x20
                    else "ordinary (in carrick)"
                ),
                "module": "carrick",
                "offset": f"0x{offset:x}",
                "symbol": "pthread_mutex_lock" if offset == 0x20 else "ordinary",
            }
            for offset in offsets
        }

    def run_campaign(self, campaign: Campaign) -> tuple[int, dict[str, object] | None]:
        with (
            mock.patch.object(risk, "inspect_binary_identity", return_value=campaign.binary),
            mock.patch.object(risk, "symbolize_host_binary_offsets", side_effect=self.symbolizer),
        ):
            status = risk.main(campaign.argv())
        payload = json.loads(campaign.output.read_text()) if campaign.output.exists() else None
        return status, payload

    def test_inspects_exact_macho_text_uuid_dof_and_entitlement(self) -> None:
        binary = self.root / "carrick"
        binary.write_bytes(b"macho")
        otool = """cmd LC_SEGMENT_64
  cmdsize 72
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000004000
  fileoff 0
 filesize 16384
     cmd LC_UUID
 cmdsize 24
    uuid aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  sectname __dof_carrick
   segname __TEXT
      addr 0x0000000100002000
      size 0x0000000000000100
    offset 8192
"""
        entitlements = plistlib.dumps({"com.apple.security.hypervisor": True}).decode()
        results = [
            subprocess.CompletedProcess([], 0, otool, ""),
            subprocess.CompletedProcess(
                [], 0, entitlements, "Executable=x\nwarning: codesign diagnostic\n"
            ),
        ]
        with mock.patch.object(risk, "_run", side_effect=results) as run:
            identity = risk.inspect_binary_identity(binary)
        self.assertEqual(identity["macho_uuid"], "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        self.assertEqual(identity["text"]["vmaddr"], 0x100000000)
        self.assertEqual(identity["dof"]["offset"], 8192)
        self.assertEqual(run.call_args_list[0].args[0], ["/usr/bin/otool", "-l", str(binary.resolve())])

    def test_symbolization_uses_exact_text_load_address_and_fails_unresolved(self) -> None:
        binary = {"path": "/exact/carrick", "text": {"vmaddr": 0x100000000, "vmsize": 0x1000}}
        completed = subprocess.CompletedProcess([], 0, "leaf_a (in carrick)\nleaf_b (in carrick)\n", "")
        with mock.patch.object(risk, "_run", return_value=completed) as run:
            rows = risk.symbolize_host_binary_offsets(binary, [0x20, 0x10, 0x20])
        self.assertEqual(list(rows), [0x10, 0x20])
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/bin/atos", "-o", "/exact/carrick", "-l", "0x100000000", "0x100000010", "0x100000020"],
        )
        with mock.patch.object(risk, "_run", return_value=subprocess.CompletedProcess([], 0, "0x100000010\n", "")):
            with self.assertRaisesRegex(ValueError, "unresolved"):
                risk.symbolize_host_binary_offsets(binary, [0x10])

    def test_owner_visible_only_in_raw_offsets_changes_five_pair_verdict(self) -> None:
        status, receipt = self.run_campaign(Campaign(self.root))
        assert receipt is not None
        self.assertEqual(status, 2)
        self.assertEqual(receipt["status"], "failed")
        locks = receipt["comparisons"]["locks"]
        self.assertEqual(locks["permutations"], 32)
        self.assertEqual(locks["one_sided_p_value"]["fraction"], "1/32")
        self.assertTrue(locks["supported_v3_increase"])
        self.assertEqual(receipt["supported_v3_owner_increases"], ["locks"])
        self.assertTrue(all(not row["host_binary_offset_symbolizations"] == [] for row in receipt["v3"]["captures_detail"]))
        self.assertEqual(receipt["regression_method"], risk.REGRESSION_METHOD)

    def test_mixed_pair_deltas_preserve_point_delta_without_support(self) -> None:
        campaign = Campaign(self.root, deltas=[10, -10, 10, -10, 10])
        status, receipt = self.run_campaign(campaign)
        assert receipt is not None
        self.assertEqual(status, 0)
        locks = receipt["comparisons"]["locks"]
        self.assertGreater(locks["mean_delta_per_1000"], 0)
        self.assertFalse(locks["supported_v3_increase"])
        self.assertEqual(len(locks["pair_deltas"]), 5)

    def test_rejects_swaps_duplicates_pair_drift_and_determinant_drift(self) -> None:
        mutations = ("legacy", "swap", "duplicate", "pair", "trace")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as directory:
                campaign = Campaign(pathlib.Path(directory))
                target = campaign.paths["v3_capture"][0]
                payload = json.loads(target.read_text())
                if mutation == "legacy":
                    payload["schema"] = "carrick.native-go-dtrace-capture.v1"
                elif mutation == "swap":
                    payload["pair"]["arm"] = "control"
                elif mutation == "duplicate":
                    duplicate_raw = campaign.paths["v3_raw"][0]
                    duplicate_raw.write_bytes(campaign.paths["v2_raw"][0].read_bytes())
                    payload["artifacts"]["raw"] = artifact(duplicate_raw)
                elif mutation == "pair":
                    payload["pair"]["id"] = "wrong-pair"
                else:
                    payload["trace_script"]["sha256"] = "f" * 64
                target.write_text(json.dumps(payload))
                status, receipt = self.run_campaign(campaign)
                self.assertEqual(status, 2)
                self.assertIsNone(receipt)


if __name__ == "__main__":
    unittest.main()
