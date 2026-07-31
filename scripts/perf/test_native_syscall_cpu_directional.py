#!/usr/bin/env python3
"""Tests for the low-overhead native syscall CPU census."""

from __future__ import annotations

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import native_syscall_cpu_directional


class NativeSyscallCpuDirectionalTests(unittest.TestCase):
    def test_summarizes_kernel_cpu_without_stack_aggregation(self) -> None:
        summary = native_syscall_cpu_directional.analyze_lines(
            [
                "SYSCALLCPU2|config|sample_hz=997",
                "SYSCALLCPU2|total|mode=kernel|samples=12",
                "SYSCALLCPU2|total|mode=user|samples=28",
                "SYSCALLCPU2|syscall-cpu|host=openat|reason=0|cpu_ns=5000000",
                "SYSCALLCPU2|syscall-cpu|host=psynch_cvwait|reason=1|cpu_ns=3000000",
                "SYSCALLCPU2|syscall-cpu|host=__ulock_wait|reason=2|cpu_ns=2000000",
                "SYSCALLCPU2|syscall-calls|host=openat|reason=0|calls=5",
                "SYSCALLCPU2|syscall-calls|host=psynch_cvwait|reason=1|calls=3",
                "SYSCALLCPU2|syscall-calls|host=__ulock_wait|reason=2|calls=2",
                "SYSCALLCPU2|complete|target_exit=1|timed_out=0",
            ]
        )

        self.assertEqual(summary["schema"], "carrick.native-syscall-cpu-directional.v1")
        self.assertFalse(summary["gating_eligible"])
        self.assertEqual(summary["samples"], {"all": 40, "kernel": 12, "user": 28})
        self.assertEqual(summary["estimated_cpu_seconds"]["kernel"], 12 / 997)
        self.assertEqual(summary["kernel_sample_share"], 0.3)
        self.assertEqual(summary["syscall_cpu_ns"], 10_000_000)
        self.assertEqual(
            summary["kernel_by_host"][0],
            {
                "calls": 5,
                "cpu_ns": 5_000_000,
                "cpu_seconds": 0.005,
                "host": "openat",
                "share": 0.5,
            },
        )
        self.assertEqual(
            summary["kernel_by_reason"],
            [
                {"calls": 5, "cpu_ns": 5_000_000, "reason": 0, "share": 0.5},
                {"calls": 3, "cpu_ns": 3_000_000, "reason": 1, "share": 0.3},
                {"calls": 2, "cpu_ns": 2_000_000, "reason": 2, "share": 0.2},
            ],
        )
        self.assertEqual(summary["warnings"], [])

    def test_rejects_syscall_cpu_without_a_matching_call_count(self) -> None:
        with self.assertRaisesRegex(
            native_syscall_cpu_directional.SyscallCpuError,
            "syscall CPU and call-count keys differ",
        ):
            native_syscall_cpu_directional.analyze_lines(
                [
                    "SYSCALLCPU2|config|sample_hz=997",
                    "SYSCALLCPU2|total|mode=kernel|samples=5",
                    "SYSCALLCPU2|total|mode=user|samples=7",
                    "SYSCALLCPU2|syscall-cpu|host=openat|reason=0|cpu_ns=4000000",
                    "SYSCALLCPU2|complete|target_exit=1|timed_out=0",
                ]
            )

    def test_compares_completed_workloads_at_the_same_frequency(self) -> None:
        baseline = native_syscall_cpu_directional.analyze_lines(
            [
                "SYSCALLCPU2|config|sample_hz=997",
                "SYSCALLCPU2|total|mode=kernel|samples=10",
                "SYSCALLCPU2|total|mode=user|samples=20",
                "SYSCALLCPU2|syscall-cpu|host=openat|reason=0|cpu_ns=6000000",
                "SYSCALLCPU2|syscall-cpu|host=mprotect|reason=0|cpu_ns=4000000",
                "SYSCALLCPU2|syscall-calls|host=openat|reason=0|calls=6",
                "SYSCALLCPU2|syscall-calls|host=mprotect|reason=0|calls=4",
                "SYSCALLCPU2|complete|target_exit=1|timed_out=0",
            ]
        )
        candidate = native_syscall_cpu_directional.analyze_lines(
            [
                "SYSCALLCPU2|config|sample_hz=997",
                "SYSCALLCPU2|total|mode=kernel|samples=12",
                "SYSCALLCPU2|total|mode=user|samples=21",
                "SYSCALLCPU2|syscall-cpu|host=openat|reason=0|cpu_ns=9000000",
                "SYSCALLCPU2|syscall-cpu|host=mprotect|reason=0|cpu_ns=3000000",
                "SYSCALLCPU2|syscall-calls|host=openat|reason=0|calls=9",
                "SYSCALLCPU2|syscall-calls|host=mprotect|reason=0|calls=3",
                "SYSCALLCPU2|complete|target_exit=1|timed_out=0",
            ]
        )

        comparison = native_syscall_cpu_directional.compare(baseline, candidate)

        self.assertEqual(
            comparison["schema"],
            "carrick.native-syscall-cpu-comparison.v1",
        )
        self.assertFalse(comparison["gating_eligible"])
        self.assertEqual(
            comparison["sample_deltas"]["kernel"],
            {"absolute": 2, "fraction": 0.2},
        )
        self.assertEqual(
            comparison["kernel_host_deltas"][0],
            {
                "baseline_calls": 6,
                "baseline_cpu_ns": 6_000_000,
                "candidate_calls": 9,
                "candidate_cpu_ns": 9_000_000,
                "cpu_delta_ns": 3_000_000,
                "fraction": 0.5,
                "host": "openat",
            },
        )


if __name__ == "__main__":
    unittest.main()
