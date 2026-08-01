#!/usr/bin/env python3
"""Tests for authenticated paired native owner-risk classification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import marshal
import os
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.perf import native_pc_range_risk as risk


def artifact(path: pathlib.Path) -> dict[str, object]:
    absolute = path.resolve()
    payload = absolute.read_bytes()
    stat = absolute.stat()
    return {
        "bytes": len(payload),
        "path": str(absolute),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "stat": {
            "ctime_ns": stat.st_ctime_ns,
            "device": stat.st_dev,
            "inode": stat.st_ino,
            "mode": stat.st_mode,
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
        },
    }


def loaded_source_identity(path: pathlib.Path) -> dict[str, object]:
    filename = str(path.resolve())
    code = compile(
        path.read_bytes(),
        filename,
        "exec",
        flags=0,
        dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    return {
        "loaded_code": {
            "digest_method": "sha256-canonical-marshal-roundtrip-v1",
            "filename": filename,
            "flags": code.co_flags,
            "marshal_sha256": hashlib.sha256(
                marshal.dumps(marshal.loads(marshal.dumps(code)))
            ).hexdigest(),
            "marshal_version": marshal.version,
            "optimize": sys.flags.optimize,
            "python_cache_tag": sys.implementation.cache_tag,
        },
        "source": artifact(path),
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
        self.launcher_path = root / "native_go_dtrace_target.py"
        self.trace_script.write_text("dtrace program\n")
        self.analyzer_path.write_text("DIRECTIONAL_ANALYZER = True\n")
        self.launcher_path.write_text("CAPTURE_LAUNCHER = True\n")
        analyzer_identity = {
            **loaded_source_identity(self.analyzer_path),
            "schema": "carrick.native-pc-range-directional.v2",
        }
        launcher_identity = loaded_source_identity(self.launcher_path)
        self.binary = {
            **artifact(self.binary_path),
            "dof": {"address": 0x100400000, "offset": 40, "segment": "__TEXT", "size": 99},
            "entitlements": {"com.apple.security.hypervisor": True},
            "entitlements_sha256": "e" * 64,
            "macho_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            "text": {"fileoff": 0, "filesize": 4096, "vmaddr": 0x100000000, "vmsize": 4096},
        }
        self.sections = [
            {
                "address": 0x100000000,
                "flags": 0x80000400,
                "instruction": True,
                "name": "__text",
                "offset": 0,
                "segment": "__TEXT",
                "size": 4096,
            }
        ]
        self.output = root / "risk.json"
        self.campaign_id = "campaign-unit"
        self.paths: dict[str, list[pathlib.Path]] = {
            key: [] for key in ("v2_raw", "v2_analysis", "v2_capture", "v3_raw", "v3_analysis", "v3_capture")
        }
        predecessor: pathlib.Path | None = None
        chronology_index = 0
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
                analyzed_payload = analysis(offset=offset, owner_count=count)
                analyzed_payload["input_artifact"] = artifact(raw)
                analyzed.write_text(json.dumps(analyzed_payload), encoding="utf-8")
                driver_stdout.write_text(f"WORKLOAD_NS={ordinal}{0 if mode == 'v2' else 1}\nBUILD_OK\n")
                driver_stderr.write_text(f"TRACECHILD1|pair={ordinal}|mode={mode}\nok\n")
                overlay_path = risk.OVERLAY_PATHS[mode]
                overlay_source = json.loads(overlay_path.read_text())
                overlay = {**overlay_source, "CARRICK_DSR_PROFILE": "1"}
                identity = {"egid": 20, "euid": 501, "supplementary_gids": [12, 20]}
                chronology_index += 1
                receipt = {
                    "analyzer": analyzer_identity,
                    "artifacts": {
                        "analysis": artifact(analyzed),
                        "driver_stderr": artifact(driver_stderr),
                        "driver_stdout": artifact(driver_stdout),
                        "raw": artifact(raw),
                    },
                    "binary": self.binary,
                    "campaign_id": self.campaign_id,
                    "chronology": {
                        "completed_unix_ns": chronology_index * 10 + 5,
                        "predecessor": (
                            None
                            if predecessor is None
                            else {
                                "artifact": artifact(predecessor),
                                "campaign_id": self.campaign_id,
                                "completed_unix_ns": json.loads(predecessor.read_text())["chronology"]["completed_unix_ns"],
                                "pair": json.loads(predecessor.read_text())["pair"],
                                "run_id": json.loads(predecessor.read_text())["run_id"],
                                "status": "passed",
                            }
                        ),
                        "started_unix_ns": chronology_index * 10,
                    },
                    "execution_identity": {
                        "post": {
                            "analyzer": analyzer_identity,
                            "binary": self.binary,
                            "launcher": launcher_identity,
                            "overlay_source": artifact(overlay_path),
                            "trace_script": artifact(self.trace_script),
                        },
                        "pre": {
                            "analyzer": analyzer_identity,
                            "binary": self.binary,
                            "launcher": launcher_identity,
                            "overlay_source": artifact(overlay_path),
                            "trace_script": artifact(self.trace_script),
                        },
                    },
                    "expected_effective_identity": identity,
                    "metadata_mode": mode,
                    "natural_completion": True,
                    "normalized_overlay": overlay,
                    "overlay_source": {
                        "artifact": artifact(overlay_path),
                        "normalized_overlay": overlay_source,
                    },
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
                predecessor = capture
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
                "owner_kind": "instruction_symbol",
                "symbol": "pthread_mutex_lock" if offset == 0x20 else "ordinary",
            }
            for offset in offsets
        }

    def run_campaign(self, campaign: Campaign) -> tuple[int, dict[str, object] | None]:
        with (
            mock.patch.object(risk, "inspect_binary_identity", return_value=campaign.binary),
            mock.patch.object(risk, "inspect_macho_sections", return_value=campaign.sections),
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

    def test_inspects_typed_macho_instruction_and_non_instruction_sections(self) -> None:
        binary = self.root / "carrick"
        binary.write_bytes(b"macho")
        otool = """Section
  sectname __text
   segname __TEXT
      addr 0x0000000100001000
      size 0x0000000000000200
    offset 4096
     align 2^2 (4)
    reloff 0
    nreloc 0
     flags 0x80000400
 reserved1 0
 reserved2 0
Section
  sectname __eh_frame
   segname __TEXT
      addr 0x0000000100001200
      size 0x0000000000000100
    offset 4608
     align 2^3 (8)
    reloff 0
    nreloc 0
     flags 0x6800000b
 reserved1 0
 reserved2 0
"""
        with mock.patch.object(
            risk,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, otool, ""),
        ):
            sections = risk.inspect_macho_sections(binary)
        self.assertEqual([section["name"] for section in sections], ["__text", "__eh_frame"])
        self.assertEqual([section["instruction"] for section in sections], [True, False])

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

    def test_non_instruction_section_is_exact_typed_owner_without_atos_guess(self) -> None:
        binary = {
            "path": "/exact/carrick",
            "text": {"vmaddr": 0x100000000, "vmsize": 0x2000},
            "sections": [
                {
                    "address": 0x100001000,
                    "flags": 0x6800000B,
                    "instruction": False,
                    "name": "__eh_frame",
                    "offset": 4096,
                    "segment": "__TEXT",
                    "size": 0x100,
                }
            ],
        }
        with mock.patch.object(risk, "_run") as run:
            rows = risk.symbolize_host_binary_offsets(binary, [0x1040])
        run.assert_not_called()
        self.assertEqual(
            rows[0x1040],
            {
                "absolute_address": "0x100001040",
                "module": "carrick",
                "offset": "0x1040",
                "owner_kind": "non_instruction_section",
                "section": "__eh_frame",
                "section_offset": "0x40",
                "segment": "__TEXT",
                "symbol": "__TEXT,__eh_frame+0x40",
            },
        )
        classified = risk.classify(
            analysis(offset=0x1040, owner_count=3), rows
        )
        self.assertEqual(classified["non_instruction_section_offsets"], 1)
        self.assertEqual(classified["non_instruction_section_samples"], 3)
        self.assertTrue(
            all(
                classified["categories"][name]["count"] == (10 if name == "kernel" else 0)
                for name in risk.PREDICATES
            )
        )

    def test_non_instruction_section_names_never_enter_owner_predicates(self) -> None:
        names = ("__lock_shared", "__mmap", "__malloc", "__dyld")
        symbolizations = {
            index: {
                "absolute_address": f"0x{0x100000000 + index:x}",
                "module": "carrick",
                "offset": f"0x{index:x}",
                "owner_kind": "non_instruction_section",
                "section": name,
                "section_offset": "0x0",
                "segment": "__TEXT",
                "symbol": f"__TEXT,{name}+0x0",
            }
            for index, name in enumerate(names, start=1)
        }
        payload = analysis(offset=1, owner_count=3)
        payload["host_binary_offsets"] = [
            {"count": 3, "offset": f"0x{offset:x}"}
            for offset in symbolizations
        ]
        classified = risk.classify(payload, symbolizations)
        self.assertEqual(
            {
                name: classified["categories"][name]["count"]
                for name in ("dyld", "locks", "malloc", "mmap_fault")
            },
            {"dyld": 0, "locks": 0, "malloc": 0, "mmap_fault": 0},
        )
        self.assertEqual(classified["non_instruction_section_offsets"], 4)
        self.assertEqual(classified["non_instruction_section_samples"], 12)
        self.assertEqual(
            [row["section"] for row in classified["non_instruction_section_owners"]],
            list(names),
        )

    def test_bare_atos_address_in_instruction_section_still_fails(self) -> None:
        binary = {
            "path": "/exact/carrick",
            "text": {"vmaddr": 0x100000000, "vmsize": 0x2000},
            "sections": [
                {
                    "address": 0x100000000,
                    "flags": 0x80000400,
                    "instruction": True,
                    "name": "__text",
                    "offset": 0,
                    "segment": "__TEXT",
                    "size": 0x1000,
                }
            ],
        }
        with mock.patch.object(
            risk,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, "0x100000010\n", ""),
        ):
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
        self.assertEqual(
            receipt["artifacts"]["risk_analyzer"],
            risk.authenticate_loaded_module_source(
                pathlib.Path(risk.__file__), risk.LOADED_MODULE_CODE
            ),
        )

    def test_mixed_pair_deltas_preserve_point_delta_without_support(self) -> None:
        campaign = Campaign(self.root, deltas=[10, -10, 10, -10, 10])
        status, receipt = self.run_campaign(campaign)
        assert receipt is not None
        self.assertEqual(status, 0)
        locks = receipt["comparisons"]["locks"]
        self.assertGreater(locks["mean_delta_per_1000"], 0)
        self.assertFalse(locks["supported_v3_increase"])
        self.assertEqual(len(locks["pair_deltas"]), 5)

    def test_rejects_missing_exact_profile_and_direct_controls(self) -> None:
        for key in ("CARRICK_DSR_PROFILE", "CARRICK_DSR_DIRECT_BINDINGS"):
            with self.subTest(key=key), tempfile.TemporaryDirectory(dir=self.root) as directory:
                campaign = Campaign(pathlib.Path(directory), deltas=[10, -10, 10, -10, 10])
                for capture in campaign.paths["v2_capture"] + campaign.paths["v3_capture"]:
                    payload = json.loads(capture.read_text())
                    payload["normalized_overlay"][key] = None
                    capture.write_text(json.dumps(payload))
                status, receipt = self.run_campaign(campaign)
                self.assertEqual(status, 2)
                assert receipt is not None
                self.assertEqual(receipt["status"], "failed")

    def test_rejects_missing_authenticated_predecessor_chain(self) -> None:
        campaign = Campaign(self.root, deltas=[10, -10, 10, -10, 10])
        for capture in campaign.paths["v2_capture"] + campaign.paths["v3_capture"]:
            payload = json.loads(capture.read_text())
            payload.pop("chronology")
            capture.write_text(json.dumps(payload))
        status, receipt = self.run_campaign(campaign)
        self.assertEqual(status, 2)
        assert receipt is not None
        self.assertEqual(receipt["status"], "failed")

    def test_rejects_broken_reordered_cross_campaign_and_duplicate_predecessors(self) -> None:
        for mutation in ("broken", "reordered", "cross-campaign", "duplicate", "v3-first"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as directory:
                campaign = Campaign(pathlib.Path(directory), deltas=[10, -10, 10, -10, 10])
                if mutation == "reordered":
                    for kind in ("raw", "analysis", "capture"):
                        paths = campaign.paths[f"v3_{kind}"]
                        paths[0], paths[1] = paths[1], paths[0]
                elif mutation == "v3-first":
                    target = campaign.paths["v2_capture"][0]
                    payload = json.loads(target.read_text())
                    payload["pair"]["arm"] = "candidate"
                    target.write_text(json.dumps(payload))
                else:
                    target = campaign.paths["v2_capture"][1]
                    payload = json.loads(target.read_text())
                    if mutation == "broken":
                        payload["chronology"]["predecessor"]["artifact"]["sha256"] = "0" * 64
                    elif mutation == "cross-campaign":
                        payload["campaign_id"] = "foreign-campaign"
                    else:
                        root_control = campaign.paths["v2_capture"][0]
                        root_payload = json.loads(root_control.read_text())
                        payload["chronology"]["predecessor"] = risk.predecessor_binding(
                            root_control, root_payload
                        )
                    target.write_text(json.dumps(payload))
                status, receipt = self.run_campaign(campaign)
                self.assertEqual(status, 2)
                assert receipt is not None
                self.assertEqual(receipt["status"], "failed")

    def test_rejects_pre_post_execution_identity_drift(self) -> None:
        campaign = Campaign(self.root, deltas=[10, -10, 10, -10, 10])
        target = campaign.paths["v3_capture"][2]
        payload = json.loads(target.read_text())
        payload["execution_identity"]["post"]["trace_script"]["sha256"] = "d" * 64
        target.write_text(json.dumps(payload))
        status, receipt = self.run_campaign(campaign)
        self.assertEqual(status, 2)
        assert receipt is not None
        self.assertEqual(receipt["status"], "failed")

    def test_failed_validation_replaces_prior_pass_with_atomic_failed_receipt(self) -> None:
        campaign = Campaign(self.root, deltas=[10, -10, 10, -10, 10])
        campaign.output.write_text(json.dumps({"schema": risk.SCHEMA, "status": "passed"}))
        target = campaign.paths["v3_capture"][0]
        payload = json.loads(target.read_text())
        payload["schema"] = "obsolete"
        target.write_text(json.dumps(payload))
        status, receipt = self.run_campaign(campaign)
        self.assertEqual(status, 2)
        assert receipt is not None
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("authenticated", " ".join(receipt["failures"]))

    def test_atomic_publication_cleans_partial_temp_on_replace_error(self) -> None:
        output = self.root / "atomic.json"
        output.write_text('{"status":"passed"}\n')
        risk.invalidate_output(output)
        with mock.patch.object(risk.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                risk.atomic_write_json(output, {"schema": risk.SCHEMA, "status": "failed"})
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".atomic.json.*.tmp")), [])

    def test_atomic_publication_revokes_pass_after_directory_fsync_error(self) -> None:
        output = self.root / "atomic-post-replace.json"
        fsync_calls = 0

        def fail_directory_fsync(_fd: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError("directory fsync failed")

        with mock.patch.object(risk.os, "fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(OSError, "directory fsync failed"):
                risk.atomic_write_json(
                    output, {"schema": risk.SCHEMA, "status": "passed"}
                )
        if output.exists():
            self.assertNotEqual(json.loads(output.read_text())["status"], "passed")
        self.assertEqual(list(self.root.glob(".atomic-post-replace.json.*.tmp")), [])

    def test_stable_json_read_rejects_replacement_between_read_and_hash(self) -> None:
        stable_json = getattr(risk, "stable_read_json", None)
        self.assertIsNotNone(stable_json, "stable JSON read primitive is required")
        source = self.root / "stable.json"
        replacement = self.root / "replacement.json"
        source.write_text('{"generation":"old"}\n', encoding="utf-8")
        replacement.write_text('{"generation":"new"}\n', encoding="utf-8")
        original_digest = risk._sha256_bytes

        def replace_during_digest(payload: bytes) -> str:
            os.replace(replacement, source)
            return original_digest(payload)

        with mock.patch.object(
            risk, "_sha256_bytes", side_effect=replace_during_digest
        ):
            with self.assertRaisesRegex(ValueError, "replaced|drifted"):
                stable_json(source)

    def test_loaded_module_source_change_after_import_fails_preflight(self) -> None:
        authenticate = getattr(risk, "authenticate_loaded_module_source", None)
        self.assertIsNotNone(authenticate, "loaded-code authentication is required")
        source = self.root / "loaded_fixture.py"
        source.write_text(
            "from __future__ import annotations\n"
            "import hashlib, marshal, sys\n"
            "_frame = sys._getframe()\n"
            "LOADED_MODULE_CODE = {\n"
            "    'digest_method': 'sha256-canonical-marshal-roundtrip-v1',\n"
            "    'filename': _frame.f_code.co_filename,\n"
            "    'flags': _frame.f_code.co_flags,\n"
            "    'marshal_sha256': hashlib.sha256(marshal.dumps(marshal.loads(marshal.dumps(_frame.f_code)))).hexdigest(),\n"
            "    'optimize': sys.flags.optimize,\n"
            "}\n"
            "del _frame\n"
            "VALUE = 1\n",
            encoding="utf-8",
        )
        spec = importlib.util.spec_from_file_location("loaded_fixture", source)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source.write_text(source.read_text().replace("VALUE = 1", "VALUE = 2"))
        with self.assertRaisesRegex(ValueError, "loaded module code"):
            authenticate(source, module.LOADED_MODULE_CODE)

    def test_risk_preflight_rejects_unauthenticated_loaded_analyzer(self) -> None:
        campaign = Campaign(self.root, deltas=[10, -10, 10, -10, 10])
        with mock.patch.object(
            risk,
            "authenticate_loaded_module_source",
            create=True,
            side_effect=ValueError("loaded module code does not match source"),
        ):
            status, receipt = self.run_campaign(campaign)
        self.assertEqual(status, 2)
        assert receipt is not None
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("loaded module code", " ".join(receipt["failures"]))

    def test_rejects_swaps_duplicates_pair_drift_and_determinant_drift(self) -> None:
        mutations = ("legacy", "swap", "duplicate", "pair", "trace")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as directory:
                campaign = Campaign(pathlib.Path(directory))
                target = campaign.paths["v3_capture"][0]
                payload = json.loads(target.read_text())
                if mutation == "legacy":
                    payload["schema"] = "carrick.native-go-dtrace-capture.v2"
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
                assert receipt is not None
                self.assertEqual(receipt["status"], "failed")


if __name__ == "__main__":
    unittest.main()
