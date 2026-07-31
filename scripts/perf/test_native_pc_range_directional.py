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
                    "PCPROFILE1|config|sample_hz=997",
                    "PCPROFILE1|reset|pid=41|epoch=1",
                    "PCPROFILE1|range|kind=private|pid=41|epoch=1|sequence=1|start=0x1000|end=0x2000",
                    "PCPROFILE1|range|kind=shared|pid=41|epoch=1|sequence=2|start=0x4000|end=0x5000",
                    "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x1100|count=7",
                    "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x4400|count=11",
                    "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x9000|count=5",
                    "PCPROFILE1|sample|kind=kernel|pid=41|epoch=1|count=3",
                    "PCPROFILE1|completion|target_exit=1|timed_out=0",
                )
            )
        )

        self.assertEqual(result["schema"], "carrick.native-pc-range-directional.v1")
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
        self.assertEqual(result["completion"], {"target_exit": 1, "timed_out": 0})
        self.assertEqual(result["warnings"], [])

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
