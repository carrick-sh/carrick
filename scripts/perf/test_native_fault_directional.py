#!/usr/bin/env python3
"""Tests for the directional native fault-page census."""

from __future__ import annotations

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import native_fault_directional


class NativeFaultDirectionalTests(unittest.TestCase):
    def test_reports_repeat_factor_without_promoting_an_incomplete_census(self) -> None:
        summary = native_fault_directional.analyze_lines(
            [
                "NFAULT1|config|page_sample_modulus=1",
                "NFAULT1|page|outcome=as_fault|pid=10|page=0x10000|count=3",
                "NFAULT1|page|outcome=as_fault|pid=10|page=0x14000|count=1",
                "NFAULT1|page|outcome=as_fault|pid=11|page=0x10000|count=2",
                "NFAULT1|page|outcome=zfod|pid=10|page=0x10000|count=2",
                "NFAULT1|page|outcome=zfod|pid=10|page=0x14000|count=1",
                "NFAULT1|total|outcome=as_fault|count=7",
                "NFAULT1|total|outcome=zfod|count=3",
                "NFAULT1|complete|target_exit=1|timed_out=0",
            ],
            page_size=16_384,
        )

        self.assertEqual(summary["schema"], "carrick.native-fault-directional.v1")
        self.assertFalse(summary["gating_eligible"])
        self.assertEqual(
            summary["outcomes"]["as_fault"],
            {
                "reported_events": 7,
                "sampled_events": 6,
                "rejected_address_events": 0,
                "sampled_event_share": 6 / 7,
                "sampled_distinct_process_pages": 3,
                "sampled_repeat_excess": 3,
                "sampled_repeat_factor": 2.0,
                "estimated_addressed_events": 6,
                "estimated_distinct_process_pages": 3,
            },
        )
        self.assertEqual(
            summary["outcomes"]["zfod"],
            {
                "reported_events": 3,
                "sampled_events": 3,
                "rejected_address_events": 0,
                "sampled_event_share": 1.0,
                "sampled_distinct_process_pages": 2,
                "sampled_repeat_excess": 1,
                "sampled_repeat_factor": 1.5,
                "estimated_addressed_events": 3,
                "estimated_distinct_process_pages": 2,
            },
        )
        self.assertEqual(
            summary["warnings"],
            ["as_fault addressed 6 of 7 reported events"],
        )
        self.assertEqual(summary["completion"], {"target_exit": 1, "timed_out": 0})

    def test_quarantines_unaligned_private_provider_values_without_masking(self) -> None:
        summary = native_fault_directional.analyze_lines(
            [
                "NFAULT1|config|page_sample_modulus=1",
                "NFAULT1|page|outcome=zfod|pid=10|page=0x10001|count=1",
                "NFAULT1|total|outcome=zfod|count=1",
                "NFAULT1|complete|target_exit=1|timed_out=0",
            ],
            page_size=16_384,
        )

        self.assertEqual(
            summary["outcomes"]["zfod"],
            {
                "reported_events": 1,
                "sampled_events": 0,
                "rejected_address_events": 1,
                "sampled_event_share": 0.0,
                "sampled_distinct_process_pages": 0,
                "sampled_repeat_excess": 0,
                "sampled_repeat_factor": None,
                "estimated_addressed_events": 0,
                "estimated_distinct_process_pages": 0,
            },
        )
        self.assertIn(
            "zfod quarantined 1 event with zero, kernel, or unaligned page values",
            summary["warnings"],
        )

    def test_scales_a_deterministic_page_sample_without_calling_it_complete(self) -> None:
        summary = native_fault_directional.analyze_lines(
            [
                "NFAULT1|config|page_sample_modulus=4",
                "NFAULT1|page|outcome=as_fault|pid=10|page=0x10000|count=3",
                "NFAULT1|page|outcome=as_fault|pid=10|page=0x14000|count=1",
                "NFAULT1|total|outcome=as_fault|count=20",
                "NFAULT1|total|outcome=zfod|count=0",
                "NFAULT1|complete|target_exit=1|timed_out=0",
            ],
            page_size=16_384,
        )

        self.assertEqual(summary["page_sample_modulus"], 4)
        self.assertEqual(
            summary["outcomes"]["as_fault"],
            {
                "reported_events": 20,
                "sampled_events": 4,
                "rejected_address_events": 0,
                "sampled_event_share": 0.2,
                "sampled_distinct_process_pages": 2,
                "sampled_repeat_excess": 2,
                "sampled_repeat_factor": 2.0,
                "estimated_addressed_events": 16,
                "estimated_distinct_process_pages": 8,
            },
        )
        self.assertIn(
            "page identities are a deterministic 1/4 sample",
            summary["warnings"],
        )


if __name__ == "__main__":
    unittest.main()
