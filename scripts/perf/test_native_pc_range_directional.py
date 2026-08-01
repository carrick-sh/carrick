#!/usr/bin/env python3
"""Tests for directional native PC/range attribution."""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from scripts.perf.native_pc_range_directional import ProfileError, analyze_raw


class NativePcRangeDirectionalTests(unittest.TestCase):
    def analyze(self, raw: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "profile.raw"
            path.write_text(raw, encoding="utf-8")
            return analyze_raw(path)

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
        self.assertIn("@outside_user_pc[(pid_t)pid, current_epoch[pid]", script)
        self.assertIn("@private_user_pc[(pid_t)pid, current_epoch[pid]", script)
        self.assertNotIn("@user_pc[", script)
        self.assertNotIn("trunc(@outside_leaf", script)

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
