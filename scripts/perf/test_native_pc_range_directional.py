#!/usr/bin/env python3
"""Tests for directional native PC/range attribution."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest

from scripts.perf import native_pc_range_directional as directional
from scripts.perf.native_pc_range_directional import ProfileError, analyze_raw


class NativePcRangeDirectionalTests(unittest.TestCase):
    def analyze(self, raw: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "profile.raw"
            path.write_text(raw, encoding="utf-8")
            return analyze_raw(path)

    def complete_strict_capture(self) -> str:
        return "\n".join(
            (
                "PCPROFILE1|config|sample_hz=197",
                "PCPROFILE1|reset|pid=41|epoch=1",
                "PCPROFILE1|identity|pid=41|epoch=1|euid=501|egid=20",
                "PCPROFILE1|range|kind=private|pid=41|epoch=1|sequence=1|start=0x1000|end=0x2000",
                "PCPROFILE1|range|kind=shared|pid=41|epoch=1|sequence=2|start=0x4000|end=0x5000",
                "PCPROFILE1|host-range|pid=41|epoch=1|start=0x8000|end=0xa000",
                "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x1100|count=7",
                "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x4400|count=11",
                "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x9000|count=5",
                "PCPROFILE1|sample|kind=kernel|pid=41|epoch=1|count=3",
                "PCKSTACK1|begin|pid=41|epoch=1|count=3",
                "kernel`vm_fault+0x10",
                "kernel`arm_fast_fault+0x20",
                "PCKSTACK1|end",
                "PCLEAF2|pid=41|epoch=1|pc=0x4400|module=unit.dylib|symbol=unit.dylib`block_4|count=11",
                "PCLEAF2|pid=41|epoch=1|pc=0x9000|module=carrick|symbol=carrick`host_leaf|count=5",
                "PCPROFILE1|completion|target_exit=1|timed_out=0",
            )
        )

    def test_strict_gate_accepts_identity_and_every_required_stream(self) -> None:
        result = self.analyze(self.complete_strict_capture())
        directional.validate_strict_capture(
            result, expected_euid=501, expected_egid=20
        )
        self.assertEqual(
            result["effective_identity"],
            {"egids": [20], "euids": [501], "reported": 1},
        )

    def test_analysis_binds_the_exact_stable_raw_input_generation(self) -> None:
        raw = self.complete_strict_capture()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "profile.raw"
            payload = raw.encode()
            path.write_bytes(payload)
            result = analyze_raw(path)
        self.assertEqual(result["input_artifact"]["bytes"], len(payload))
        self.assertEqual(
            result["input_artifact"]["sha256"],
            hashlib.sha256(payload).hexdigest(),
        )

    def test_strict_gate_rejects_zero_usdt_provider_capture(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=197",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )
        with self.assertRaisesRegex(ProfileError, "reset stream"):
            directional.validate_strict_capture(
                result, expected_euid=501, expected_egid=20
            )

    def test_strict_gate_rejects_kernel_samples_without_reconciled_stacks(self) -> None:
        raw = "\n".join(
            line
            for line in self.complete_strict_capture().splitlines()
            if not line.startswith("PCKSTACK1|")
            and not line.startswith("kernel`")
        )
        result = self.analyze(raw)
        with self.assertRaisesRegex(ProfileError, "kernel PC/stack"):
            directional.validate_strict_capture(
                result, expected_euid=501, expected_egid=20
            )

    def test_strict_gate_rejects_counterbalanced_kernel_catalog_mismatches(self) -> None:
        raw = self.complete_strict_capture().replace(
            "PCPROFILE1|sample|kind=kernel|pid=41|epoch=1|count=3\n"
            "PCKSTACK1|begin|pid=41|epoch=1|count=3",
            "PCPROFILE1|sample|kind=kernel|pid=41|epoch=1|count=2\n"
            "PCPROFILE1|sample|kind=kernel|pid=42|epoch=7|count=4\n"
            "PCKSTACK1|begin|pid=41|epoch=1|count=4",
        ).replace(
            "PCKSTACK1|end\nPCLEAF2|",
            "PCKSTACK1|end\n"
            "PCKSTACK1|begin|pid=42|epoch=7|count=2\n"
            "kernel`exception_return+0x8\n"
            "PCKSTACK1|end\nPCLEAF2|",
        )
        result = self.analyze(raw)
        self.assertEqual(result["kernel_stack_capture"]["kernel_samples"], 6)
        self.assertEqual(result["kernel_stack_capture"]["stack_samples"], 6)
        with self.assertRaisesRegex(ProfileError, "per-catalog"):
            directional.validate_strict_capture(
                result, expected_euid=501, expected_egid=20
            )

    def test_strict_gate_rejects_root_identity_for_non_root_caller(self) -> None:
        result = self.analyze(
            self.complete_strict_capture().replace("euid=501|egid=20", "euid=0|egid=0")
        )
        with self.assertRaisesRegex(ProfileError, "effective identity"):
            directional.validate_strict_capture(
                result, expected_euid=501, expected_egid=20
            )

    def test_strict_cli_writes_json_only_after_all_gates_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            raw = root / "profile.raw"
            output = root / "profile.json"
            raw.write_text(self.complete_strict_capture(), encoding="utf-8")
            self.assertEqual(
                directional.main(
                    [
                        "--input",
                        str(raw),
                        "--output",
                        str(output),
                        "--strict",
                        "--expected-euid",
                        "501",
                        "--expected-egid",
                        "20",
                    ]
                ),
                0,
            )
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["warnings"], []
            )

    def test_strict_cli_fails_nonzero_without_usdt_streams(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            raw = root / "profile.raw"
            output = root / "profile.json"
            raw.write_text(
                "PCPROFILE1|config|sample_hz=197\n"
                "PCPROFILE1|completion|target_exit=1|timed_out=0\n",
                encoding="utf-8",
            )
            self.assertEqual(
                directional.main(
                    [
                        "--input",
                        str(raw),
                        "--output",
                        str(output),
                        "--strict",
                        "--expected-euid",
                        "501",
                        "--expected-egid",
                        "20",
                    ]
                ),
                2,
            )
            self.assertFalse(output.exists())

    def test_joins_user_samples_to_private_shared_and_host_ranges(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=197",
                    "PCPROFILE1|reset|pid=41|epoch=1",
                    "PCPROFILE1|range|kind=private|pid=41|epoch=1|sequence=1|start=0x1000|end=0x2000",
                    "PCPROFILE1|range|kind=shared|pid=41|epoch=1|sequence=2|start=0x4000|end=0x5000",
                    "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x1100|count=7",
                    "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x4400|count=11",
                    "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x9000|count=5",
                    "PCPROFILE1|sample|kind=kernel|pid=41|epoch=1|count=3",
                    "PCLEAF2|pid=41|epoch=1|pc=0x4400|module=unit.dylib|symbol=unit.dylib`block_4|count=11",
                    "PCLEAF2|pid=41|epoch=1|pc=0x9000|module=carrick|symbol=carrick`host_leaf|count=5",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(result["schema"], "carrick.native-pc-range-directional.v2")
        self.assertFalse(result["gating_eligible"])
        self.assertEqual(
            result["samples"],
            {
                "all": 26,
                "host": 5,
                "kernel": 3,
                "private_jit": 7,
                "shared_jit": 11,
                "user": 23,
            },
        )
        self.assertEqual(result["ranges"]["private_unique"], 1)
        self.assertEqual(result["ranges"]["shared_unique"], 1)
        self.assertEqual(
            result["hot_host_global_pcs"], [{"count": 5, "pc": "0x9000"}]
        )
        self.assertEqual(
            result["host_leaves"],
            [
                {
                    "all_cpu_share": 5 / 26,
                    "count": 5,
                    "host_user_share": 1.0,
                    "module": "carrick",
                    "symbol": "carrick`host_leaf",
                }
            ],
        )
        self.assertEqual(
            result["leaf_capture"],
            {
                "expected_outside_private_samples": 16,
                "host_binary_raw_samples": 0,
                "host_named_samples": 5,
                "host_raw_samples": 0,
                "observed_outside_private_samples": 16,
                "shared_translated_samples": 11,
            },
        )
        self.assertEqual(result["completion"], {"target_exit": 1, "timed_out": 0})
        self.assertEqual(result["warnings"], [])

    def test_parses_and_reconciles_exact_kernel_stacks(self) -> None:
        result = self.analyze(self.complete_strict_capture())
        self.assertEqual(
            result["kernel_stack_capture"],
            {
                "catalogs": [
                    {
                        "epoch": 1,
                        "kernel_samples": 3,
                        "pid": 41,
                        "stack_samples": 3,
                    }
                ],
                "kernel_samples": 3,
                "per_catalog_exact": True,
                "stack_samples": 3,
                "stacks": 1,
            },
        )
        self.assertEqual(
            result["kernel_stacks"],
            [
                {
                    "count": 3,
                    "frames": [
                        "kernel`vm_fault+0x10",
                        "kernel`arm_fast_fault+0x20",
                    ],
                }
            ],
        )

    def test_joins_raw_host_pc_to_exact_process_image_offset(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=197",
                    "PCPROFILE1|range|kind=private|pid=7|epoch=1|sequence=1|start=0x1000|end=0x2000",
                    "PCPROFILE1|host-range|pid=7|epoch=1|start=0x8000|end=0xa000",
                    "PCPROFILE1|sample|kind=user|pid=7|epoch=1|pc=0x9120|count=4",
                    "PCLEAF2|pid=7|epoch=1|pc=0x9120|module=0x9120|symbol=0x9120|count=4",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(
            result["host_binary_offsets"], [{"count": 4, "offset": "0x1120"}]
        )
        self.assertEqual(result["leaf_capture"]["host_binary_raw_samples"], 4)
        self.assertEqual(
            result["host_text_ranges"],
            {"process_epochs": 1, "reported": 1, "unique": 1},
        )
        self.assertEqual(result["warnings"], [])

    def test_treats_module_qualified_hex_symbol_as_raw(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=197",
                    "PCPROFILE1|range|kind=private|pid=7|epoch=1|sequence=1|start=0x1000|end=0x2000",
                    "PCPROFILE1|host-range|pid=7|epoch=1|start=0x8000|end=0xa000",
                    "PCPROFILE1|sample|kind=user|pid=7|epoch=1|pc=0x9340|count=3",
                    "PCLEAF2|pid=7|epoch=1|pc=0x9340|module=carrick|symbol=carrick`0x9340|count=3",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(result["host_leaves"], [])
        self.assertEqual(
            result["host_binary_offsets"], [{"count": 3, "offset": "0x1340"}]
        )

    def test_rejects_conflicting_host_text_ranges_for_one_epoch(self) -> None:
        with self.assertRaisesRegex(ProfileError, "conflicting host text ranges"):
            self.analyze(
                "\n".join(
                    (
                        "PCPROFILE1|config|sample_hz=197",
                        "PCPROFILE1|host-range|pid=7|epoch=1|start=0x8000|end=0xa000",
                        "PCPROFILE1|host-range|pid=7|epoch=1|start=0x9000|end=0xb000",
                        "PCPROFILE1|completion|target_exit=1|timed_out=0",
                    )
                )
            )

    def test_aggregates_same_host_leaf_across_processes_after_exact_pc_join(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=197",
                    "PCPROFILE1|range|kind=private|pid=7|epoch=1|sequence=1|start=0x1000|end=0x2000",
                    "PCPROFILE1|range|kind=private|pid=8|epoch=1|sequence=1|start=0x3000|end=0x4000",
                    "PCPROFILE1|sample|kind=user|pid=7|epoch=1|pc=0x9000|count=3",
                    "PCPROFILE1|sample|kind=user|pid=8|epoch=1|pc=0xa000|count=5",
                    "PCLEAF2|pid=7|epoch=1|pc=0x9000|module=libsystem_platform.dylib|symbol=libsystem_platform.dylib`_platform_memmove|count=3",
                    "PCLEAF2|pid=8|epoch=1|pc=0xa000|module=libsystem_platform.dylib|symbol=libsystem_platform.dylib`_platform_memmove|count=5",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(result["host_leaves"][0]["count"], 8)
        self.assertEqual(result["host_leaves"][0]["host_user_share"], 1.0)
        self.assertEqual(result["warnings"], [])

    def test_rejects_leaf_population_that_does_not_match_pc_histogram(self) -> None:
        with self.assertRaisesRegex(ProfileError, "leaf sample count"):
            self.analyze(
                "\n".join(
                    (
                        "PCPROFILE1|config|sample_hz=197",
                        "PCPROFILE1|sample|kind=user|pid=5|epoch=1|pc=0x5000|count=2",
                        "PCLEAF2|pid=5|epoch=1|pc=0x5000|module=carrick|symbol=carrick`leaf|count=1",
                        "PCPROFILE1|completion|target_exit=1|timed_out=0",
                    )
                )
            )

    def test_rejects_leaf_record_for_private_translated_pc(self) -> None:
        with self.assertRaisesRegex(ProfileError, "private translated PC"):
            self.analyze(
                "\n".join(
                    (
                        "PCPROFILE1|config|sample_hz=197",
                        "PCPROFILE1|range|kind=private|pid=5|epoch=1|sequence=1|start=0x5000|end=0x6000",
                        "PCPROFILE1|sample|kind=user|pid=5|epoch=1|pc=0x5100|count=2",
                        "PCLEAF2|pid=5|epoch=1|pc=0x5100|module=0x5100|symbol=0x5100|count=2",
                        "PCPROFILE1|completion|target_exit=1|timed_out=0",
                    )
                )
            )

    def test_dtrace_program_is_bounded_and_pc_binds_each_leaf(self) -> None:
        script = (
            pathlib.Path(__file__).resolve().parents[2]
            / "scripts/dtrace/native-pc-range-directional.d"
        ).read_text(encoding="utf-8")

        self.assertIn("#pragma D option zdefs", script)
        self.assertIn("profile-197", script)
        self.assertNotIn("profile-997", script)
        self.assertIn("PCPROFILE1|config|sample_hz=197", script)
        self.assertIn("carrick*:::host-image-text-range", script)
        self.assertIn(
            "PCPROFILE1|host-range|pid=%d|epoch=%d|start=%#x|end=%#x",
            script,
        )
        self.assertNotIn("host_start[args[0]->pr_pid]", script)
        self.assertIn(
            "PCLEAF2|pid=%d|epoch=%d|pc=%#x|module=%A|symbol=%A|count=%@u",
            script,
        )
        self.assertIn("stack(24)", script)
        self.assertIn("PCKSTACK1|begin|pid=%d|epoch=%d|count=%@u", script)
        self.assertNotIn("trunc(@kernel_stack", script)
        self.assertNotIn("@user_pc[", script)
        self.assertNotIn("trunc(@outside_leaf", script)

    def test_dtrace_profile_snapshots_epoch_once_for_each_paired_stream(self) -> None:
        script = (
            pathlib.Path(__file__).resolve().parents[2]
            / "scripts/dtrace/native-pc-range-directional.d"
        ).read_text(encoding="utf-8")

        def action_block(marker: str) -> str:
            marker_offset = script.index(marker)
            start = script.rfind("{", 0, marker_offset)
            end = script.index("}", marker_offset)
            return script[start : end + 1]

        outside = action_block("@outside_user_pc[")
        self.assertEqual(outside.count("current_epoch["), 1)
        self.assertIn(
            "this->sample_epoch = current_epoch[this->sample_pid];", outside
        )
        self.assertIn(
            "@outside_user_pc[this->sample_pid, this->sample_epoch,", outside
        )
        self.assertIn(
            "@outside_leaf[this->sample_pid, this->sample_epoch,", outside
        )

        kernel = action_block("@kernel_pid[")
        self.assertEqual(kernel.count("current_epoch["), 1)
        self.assertIn(
            "this->sample_epoch = current_epoch[this->sample_pid];", kernel
        )
        self.assertIn("@kernel_pid[this->sample_pid, this->sample_epoch]", kernel)
        self.assertIn(
            "@kernel_stack[this->sample_pid, this->sample_epoch, stack(24)]",
            kernel,
        )

    def test_deduplicates_exact_fork_replay_ranges(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=997",
                    "PCPROFILE1|reset|pid=7|epoch=2",
                    "PCPROFILE1|range|kind=shared|pid=7|epoch=2|sequence=2|start=0x8000|end=0x9000",
                    "PCPROFILE1|range|kind=shared|pid=7|epoch=2|sequence=2|start=0x8000|end=0x9000",
                    "PCPROFILE1|sample|kind=user|pid=7|epoch=2|pc=0x8100|count=13",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(result["ranges"]["shared_reported"], 2)
        self.assertEqual(result["ranges"]["shared_unique"], 1)
        self.assertEqual(result["samples"]["shared_jit"], 13)

    def test_rejects_overlapping_ownership_instead_of_guessing(self) -> None:
        with self.assertRaisesRegex(ProfileError, "overlapping translated ranges"):
            self.analyze(
                "\n".join(
                    (
                        "PCPROFILE1|config|sample_hz=997",
                        "PCPROFILE1|range|kind=private|pid=9|epoch=1|sequence=1|start=0x1000|end=0x3000",
                        "PCPROFILE1|range|kind=shared|pid=9|epoch=1|sequence=2|start=0x2000|end=0x4000",
                        "PCPROFILE1|completion|target_exit=1|timed_out=0",
                    )
                )
            )

    def test_exec_epoch_can_reuse_an_old_private_address_for_shared_code(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=997",
                    "PCPROFILE1|range|kind=private|pid=12|epoch=1|sequence=1|start=0x1000|end=0x3000",
                    "PCPROFILE1|range|kind=shared|pid=12|epoch=2|sequence=2|start=0x1000|end=0x3000",
                    "PCPROFILE1|sample|kind=user|pid=12|epoch=1|pc=0x1800|count=5",
                    "PCPROFILE1|sample|kind=user|pid=12|epoch=2|pc=0x1800|count=7",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(result["samples"]["private_jit"], 5)
        self.assertEqual(result["samples"]["shared_jit"], 7)

    def test_marks_an_incomplete_capture_directional_and_warns(self) -> None:
        result = self.analyze(
            "\n".join(
                (
                    "PCPROFILE1|config|sample_hz=997",
                    "PCPROFILE1|sample|kind=user|pid=5|epoch=1|pc=0x5000|count=2",
                )
            )
        )

        self.assertFalse(result["gating_eligible"])
        self.assertEqual(result["samples"]["host"], 2)
        self.assertIn("capture has no completion record", result["warnings"])


if __name__ == "__main__":
    unittest.main()
