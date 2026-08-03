#!/usr/bin/env python3

import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_wall_attribution


SCHEMA = "carrick.dsr-profile.v1"


def completion(drops: int = 0) -> dict[str, object]:
    return {
        "complete": drops == 0,
        "bounded": False,
        "target_exit_reason": 1,
        "high_cardinality_overflow": False,
        "incomplete_pairs": 0,
        "cardinality": {
            "indirect_sources": 0,
            "indirect_pairs": 0,
        },
        "drops": {
            "principal_drops": drops,
            "aggregation_drops": 0,
            "dynamic_drops": 0,
            "other_drops": 0,
            "interrupted": False,
        },
    }


def row(
    phase: str | None,
    metric: dict[str, object],
    *,
    kind: str | None = None,
    pid: int | None = None,
    source_pc: int | None = None,
    drops: int = 0,
) -> dict[str, object]:
    scope: dict[str, object] = {}
    if phase is not None:
        scope["phase"] = phase
    if kind is not None:
        scope["kind"] = kind
    if pid is not None:
        scope["pid"] = pid
    if source_pc is not None:
        scope["source_pc"] = source_pc
    return {
        "schema": SCHEMA,
        "profile": "native-wall",
        "run_id": "synthetic-run",
        "git_sha": "abc123",
        "git_dirty": False,
        "binary_sha256": "def456",
        "command": ["run", "--exec-backend", "native"],
        "host": "test-host",
        "scope": scope,
        "metric": metric,
        "completion": completion(drops),
    }


def exact(*, count: int | None = None, total_ns: int | None = None):
    metric: dict[str, object] = {"type": "exact"}
    if count is not None:
        metric["count"] = count
    if total_ns is not None:
        metric["total_ns"] = total_ns
    return metric


def profile_rows(
    *,
    wall_samples: int = 197,
    wall_on_cpu: int = 120,
    wall_runnable: int = 40,
    wall_sleeping: int = 35,
    wall_transition: int = 2,
    jit_samples: int = 450,
    unresolved_samples: int = 0,
    kernel_samples: int = 49,
    voluntary_ns: int = 1000,
    stack_ns: int = 900,
    live_at_end: int = 0,
    drops: int = 0,
) -> list[dict[str, object]]:
    pid = 42
    rows = [
        row("wall-state", exact(count=wall_on_cpu), kind="on-cpu", drops=drops),
        row(
            "wall-state",
            exact(count=wall_runnable),
            kind="runnable-descheduled",
            drops=drops,
        ),
        row(
            "wall-state",
            exact(count=wall_sleeping),
            kind="all-sleeping",
            drops=drops,
        ),
        row(
            "wall-state",
            exact(count=wall_transition),
            kind="transition",
            drops=drops,
        ),
        row("wall-samples", exact(count=wall_samples), drops=drops),
        row("elapsed", exact(total_ns=1_000_000_000), drops=drops),
        row(
            "process-lifecycle",
            exact(count=live_at_end),
            kind="live-at-end",
            drops=drops,
        ),
        row(
            "image-base",
            exact(count=1),
            kind="jit-start",
            pid=pid,
            source_pc=0x1000,
            drops=drops,
        ),
        row(
            "image-base",
            exact(count=1),
            kind="jit-end",
            pid=pid,
            source_pc=0x2000,
            drops=drops,
        ),
        row(
            "cpu-user-pc",
            exact(count=jit_samples),
            pid=pid,
            source_pc=0x1800,
            drops=drops,
        ),
        row(
            "cpu-kernel-pc",
            exact(count=kernel_samples),
            source_pc=0xFFFF_0000,
            drops=drops,
        ),
        row(
            "offcpu-voluntary-total",
            exact(total_ns=voluntary_ns),
            drops=drops,
        ),
        row(
            "offcpu-runnable-total",
            exact(total_ns=500),
            drops=drops,
        ),
        row(
            "offcpu-voluntary-stack",
            {
                "type": "stack-trace",
                "state": "voluntary",
                "pid": pid,
                "value_ns": stack_ns,
                "frames": ["0x3000", "0x4000"],
            },
            kind="voluntary",
            pid=pid,
            drops=drops,
        ),
    ]
    if unresolved_samples:
        rows.append(
            row(
                "cpu-user-pc",
                exact(count=unresolved_samples),
                pid=pid,
                source_pc=0x9000,
                drops=drops,
            )
        )
    rows.append(row(None, {"type": "completion"}, drops=drops))
    return rows


class NativeWallAttributionTest(unittest.TestCase):
    def setUp(self):
        self.directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.directory, ignore_errors=True))

    def write_profile(
        self, rows: list[dict[str, object]], name: str = "profile.jsonl"
    ) -> pathlib.Path:
        path = self.directory / name
        path.write_text("".join(json.dumps(value) + "\n" for value in rows))
        return path

    def test_reconciles_wall_cpu_and_blocking_stack_coverage(self):
        profile = native_wall_attribution.load_profile(
            self.write_profile(profile_rows())
        )

        summary = native_wall_attribution.summarize(
            profile, pathlib.Path("/unused/carrick")
        )

        self.assertAlmostEqual(summary["wall_state"]["on-cpu"]["share"], 120 / 197)
        self.assertEqual(summary["reconciliation"]["wall_samples"], 197)
        self.assertAlmostEqual(summary["cpu"]["translated-guest"]["share"], 450 / 499)
        self.assertEqual(summary["cpu"]["unresolved"]["samples"], 0)
        self.assertAlmostEqual(summary["offcpu"]["top_stack_coverage"], 0.9)
        self.assertTrue(summary["accepted"])

    def test_host_symbol_categories_are_explicit(self):
        cases = {
            "carrick_dsr_aarch64::translator::ProcessTranslator::translate": "translation",
            "carrick_runtime::native_darwin::prepare_dsr_entry": "gateway",
            "carrick_runtime::dispatch::SyscallDispatcher::dispatch": "dispatch",
            "carrick_runtime::native_exec_capsule::restore": "process-setup",
            "parking_lot::raw_mutex::RawMutex::lock_slow": "other-carrick",
        }

        for symbol, expected in cases.items():
            self.assertEqual(
                native_wall_attribution.classify_host_symbol(symbol),
                expected,
                symbol,
            )

    def test_exact_dyld_image_range_resolves_darwin_userspace(self):
        rows = profile_rows(jit_samples=400)
        rows.insert(
            -1,
            row(
                "image-catalog",
                {
                    "type": "image-catalog",
                    "pid": 42,
                    "ranges": [
                        {
                            "start": 0x8000,
                            "end": 0xA000,
                            "path": "/usr/lib/libSystem.B.dylib",
                        }
                    ],
                },
                pid=42,
            ),
        )
        rows.insert(
            -1,
            row(
                "cpu-user-pc",
                exact(count=50),
                pid=42,
                source_pc=0x9000,
            ),
        )

        summary = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(self.write_profile(rows)),
            pathlib.Path("/unused/carrick"),
        )

        self.assertAlmostEqual(summary["cpu"]["darwin-userspace"]["share"], 50 / 499)
        self.assertEqual(
            summary["cpu"]["darwin-user-images"][0]["path"],
            "/usr/lib/libSystem.B.dylib",
        )
        self.assertTrue(summary["accepted"])

    def test_exact_host_range_without_symbol_is_other_carrick(self):
        rows = profile_rows(jit_samples=400)
        rows.insert(
            -1,
            row(
                "image-base",
                exact(count=1),
                kind="host",
                pid=42,
                source_pc=0x8000,
            ),
        )
        rows.insert(
            -1,
            row(
                "cpu-user-pc",
                exact(count=50),
                pid=42,
                source_pc=0x8800,
            ),
        )
        binary = self.directory / "carrick"
        binary.touch()

        with (
            mock.patch.object(
                native_wall_attribution, "image_text_size", return_value=0x1000
            ),
            mock.patch.object(
                native_wall_attribution, "atos_batch", return_value={}
            ),
        ):
            summary = native_wall_attribution.summarize(
                native_wall_attribution.load_profile(self.write_profile(rows)),
                binary,
            )

        self.assertEqual(summary["cpu"]["other-carrick"]["samples"], 50)
        self.assertEqual(summary["cpu"]["unresolved"]["samples"], 0)
        self.assertTrue(summary["accepted"])

    def test_v2_jit_range_classifies_translated_user_pcs(self):
        rows = [
            value
            for value in profile_rows()
            if not (
                value["scope"].get("phase") == "image-base"
                and value["scope"].get("kind") in {"jit-start", "jit-end"}
            )
        ]
        rows.insert(
            -1,
            {
                **row(
                    "jit-range",
                    exact(count=1),
                    kind="private",
                    pid=42,
                    source_pc=0x1000,
                ),
                "scope": {
                    "phase": "jit-range",
                    "kind": "private",
                    "pid": 42,
                    "source_pc": 0x1000,
                    "target_pc": 0x2000,
                },
            },
        )

        summary = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(self.write_profile(rows)),
            pathlib.Path("/unused/carrick"),
        )

        self.assertEqual(summary["cpu"]["translated-guest"]["samples"], 450)
        self.assertEqual(summary["cpu"]["unresolved"]["samples"], 0)
        self.assertTrue(summary["accepted"])

    def test_accepts_profile_with_no_offcpu_aggregations(self):
        rows = [
            value
            for value in profile_rows()
            if value["scope"].get("phase")
            not in {
                "offcpu-voluntary-total",
                "offcpu-runnable-total",
                "offcpu-voluntary-stack",
            }
        ]

        summary = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(self.write_profile(rows)),
            pathlib.Path("/unused/carrick"),
        )

        self.assertEqual(summary["offcpu"]["voluntary_ns"], 0)
        self.assertEqual(summary["offcpu"]["runnable_ns"], 0)
        self.assertEqual(summary["offcpu"]["top_stack_coverage"], 1.0)
        self.assertTrue(summary["accepted"])

    def test_kernel_stacks_do_not_enter_offcpu_duration_coverage(self):
        rows = profile_rows()
        rows.insert(
            -1,
            row(
                "cpu-kernel-stack",
                {
                    "type": "stack-trace",
                    "state": "kernel-named-syscall",
                    "pid": 42,
                    "count": 49,
                    "frames": ["0xfffffe0010010010", "0xfffffe0010020020"],
                },
                kind="kernel-named-syscall",
                pid=42,
            ),
        )

        summary = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(self.write_profile(rows)),
            pathlib.Path("/unused/carrick"),
        )

        self.assertEqual(summary["offcpu"]["top_stack_coverage"], 0.9)
        self.assertEqual(len(summary["offcpu"]["top_stacks"]), 1)
        self.assertTrue(summary["accepted"])

    def test_rejects_duplicate_exact_publisher_row(self):
        rows = profile_rows()
        rows.insert(1, rows[0])

        with self.assertRaisesRegex(ValueError, "duplicate metric scope"):
            native_wall_attribution.load_profile(self.write_profile(rows))

    def test_rejects_invalid_capture_and_coverage(self):
        cases = {
            "drops": profile_rows(drops=1),
            "wall timer coverage": profile_rows(
                wall_samples=190,
                wall_on_cpu=115,
                wall_runnable=38,
                wall_sleeping=35,
                wall_transition=2,
            ),
            "unresolved CPU": profile_rows(
                jit_samples=395,
                unresolved_samples=90,
            ),
            "blocking stack coverage": profile_rows(stack_ns=790),
            "live process": profile_rows(live_at_end=1),
        }

        for name, rows in cases.items():
            path = self.write_profile(rows, f"{name.replace(' ', '-')}.jsonl")
            if name == "drops":
                with self.assertRaisesRegex(ValueError, "drop|complete"):
                    native_wall_attribution.load_profile(path)
                continue
            profile = native_wall_attribution.load_profile(path)
            summary = native_wall_attribution.summarize(
                profile, pathlib.Path("/unused/carrick")
            )
            self.assertFalse(summary["accepted"], name)

    def test_accepts_stable_cpu_classification_above_eighty_five_percent(self):
        summary = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(
                self.write_profile(
                    profile_rows(jit_samples=395, unresolved_samples=70),
                    "eighty-five-percent.jsonl",
                )
            ),
            pathlib.Path("/unused/carrick"),
        )

        self.assertGreaterEqual(
            summary["reconciliation"]["resolved_cpu_coverage"],
            native_wall_attribution.MIN_CPU_COVERAGE,
        )
        self.assertTrue(summary["accepted"])

    def test_comparison_rejects_dominant_category_instability(self):
        stable_a = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(
                self.write_profile(profile_rows(), "a.jsonl")
            ),
            pathlib.Path("/unused/carrick"),
        )
        unstable_b = native_wall_attribution.summarize(
            native_wall_attribution.load_profile(
                self.write_profile(
                    profile_rows(jit_samples=400, kernel_samples=99),
                    "b.jsonl",
                )
            ),
            pathlib.Path("/unused/carrick"),
        )

        comparison = native_wall_attribution.compare(stable_a, unstable_b)

        self.assertFalse(comparison["accepted"])
        self.assertTrue(
            any("percentage points" in reason for reason in comparison["failures"])
        )


if __name__ == "__main__":
    unittest.main()
