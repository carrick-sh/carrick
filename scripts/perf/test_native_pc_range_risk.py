#!/usr/bin/env python3
"""Tests for hash-bound V2/V3 directional risk classification."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest

import native_pc_range_risk


def analysis(
    *,
    all_samples: int,
    kernel: int,
    leaves: list[tuple[str, str, int]],
    kernel_stacks: list[dict[str, object]] | None = None,
):
    return {
        "schema": "carrick.native-pc-range-directional.v2",
        "samples": {"all": all_samples, "kernel": kernel},
        "host_leaves": [
            {"module": module, "symbol": symbol, "count": count}
            for module, symbol, count in leaves
        ],
        "kernel_stacks": kernel_stacks or [],
    }


def artifact(path: pathlib.Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "bytes": len(raw),
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


class NativePcRangeRiskTests(unittest.TestCase):
    def test_classifies_exact_persisted_owner_predicates(self) -> None:
        result = native_pc_range_risk.classify(
            analysis(
                all_samples=41,
                kernel=13,
                leaves=[
                    ("dyld", "dyld`resolve", 2),
                    ("libsystem_malloc.dylib", "libsystem_malloc.dylib`malloc", 3),
                    ("libsystem_pthread.dylib", "libsystem_pthread.dylib`__psynch_mutexwait", 5),
                    ("carrick", "carrick`map_with_linking", 7),
                    ("carrick", "carrick`other", 11),
                ],
                kernel_stacks=[
                    {"count": 13, "frames": ["kernel`vm_fault", "kernel`exception"]}
                ],
            )
        )
        self.assertEqual(
            {name: category["count"] for name, category in result["categories"].items()},
            {"dyld": 2, "kernel": 13, "locks": 5, "malloc": 3, "mmap_fault": 7},
        )
        self.assertEqual(result["all_samples"], 41)
        self.assertEqual(
            result["categories"]["locks"]["leaves"],
            [
                {
                    "count": 5,
                    "module": "libsystem_pthread.dylib",
                    "symbol": "libsystem_pthread.dylib`__psynch_mutexwait",
                }
            ],
        )
        self.assertEqual(
            result["categories"]["kernel"]["stacks"],
            [
                {
                    "count": 13,
                    "frames": ["kernel`vm_fault", "kernel`exception"],
                }
            ],
        )
        self.assertEqual(result["categories"]["kernel"]["stack_samples"], 13)
        self.assertEqual(
            native_pc_range_risk.PREDICATES["dyld"],
            "module in {'dyld', 'libdyld.dylib'}",
        )

    def test_repeated_arm_binds_and_aggregates_every_capture_identity(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        raws: list[pathlib.Path] = []
        analyses: list[pathlib.Path] = []
        captures: list[pathlib.Path] = []
        for index, kernel in enumerate((20, 30), start=1):
            raw = root / f"v2-{index}.raw"
            analysis_path = root / f"v2-{index}.json"
            capture = root / f"v2-{index}.capture.json"
            raw.write_text(f"raw {index}\n", encoding="utf-8")
            analysis_path.write_text(
                json.dumps(analysis(all_samples=100, kernel=kernel, leaves=[])),
                encoding="utf-8",
            )
            capture.write_text(
                json.dumps(
                    {
                        "artifacts": {
                            raw.name: artifact(raw),
                            analysis_path.name: artifact(analysis_path),
                        },
                        "status": "passed",
                        "expected_effective_identity": {"euid": 501, "egid": 20},
                        "observed_effective_identity": {
                            "euids": [501],
                            "egids": [20],
                            "reported": index,
                        },
                    }
                ),
                encoding="utf-8",
            )
            raws.append(raw)
            analyses.append(analysis_path)
            captures.append(capture)
        aggregate, artifacts = native_pc_range_risk._load_arm(
            raws=raws, analyses=analyses, captures=captures
        )
        self.assertEqual(aggregate["captures"], 2)
        self.assertEqual(aggregate["all_samples"], 200)
        self.assertEqual(aggregate["categories"]["kernel"]["count"], 50)
        self.assertEqual(len(artifacts), 2)
        self.assertNotEqual(
            artifacts[0]["raw"]["sha256"], artifacts[1]["raw"]["sha256"]
        )

    def test_rejects_capture_receipt_not_bound_to_supplied_raw(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        raw = root / "capture.raw"
        analysis_path = root / "capture.json"
        capture = root / "capture.capture.json"
        raw.write_text("raw\n", encoding="utf-8")
        analysis_path.write_text(
            json.dumps(analysis(all_samples=100, kernel=20, leaves=[])),
            encoding="utf-8",
        )
        capture.write_text(
            json.dumps(
                {
                    "artifacts": {
                        raw.name: {**artifact(raw), "sha256": "0" * 64},
                        analysis_path.name: artifact(analysis_path),
                    },
                    "status": "passed",
                    "expected_effective_identity": {"euid": 501, "egid": 20},
                    "observed_effective_identity": {
                        "euids": [501],
                        "egids": [20],
                        "reported": 1,
                    },
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "does not bind"):
            native_pc_range_risk._load_arm(
                raws=[raw], analyses=[analysis_path], captures=[capture]
            )

    def run_comparison(self, *, v3_kernel: int) -> tuple[int, dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        paths = {
            name: root / name
            for name in (
                "v2.raw",
                "v2.json",
                "v2.capture.json",
                "v3.raw",
                "v3.json",
                "v3.capture.json",
                "carrick",
                "risk.json",
            )
        }
        paths["v2.raw"].write_text("v2 raw\n", encoding="utf-8")
        paths["v3.raw"].write_text("v3 raw\n", encoding="utf-8")
        paths["carrick"].write_bytes(b"signed binary")
        v2 = analysis(
            all_samples=100,
            kernel=20,
            leaves=[("dyld", "dyld`resolve", 10)],
        )
        v3 = analysis(
            all_samples=200,
            kernel=v3_kernel,
            leaves=[("dyld", "dyld`resolve", 10)],
        )
        paths["v2.json"].write_text(json.dumps(v2), encoding="utf-8")
        paths["v3.json"].write_text(json.dumps(v3), encoding="utf-8")
        for arm in ("v2", "v3"):
            paths[f"{arm}.capture.json"].write_text(
                json.dumps(
                    {
                        "artifacts": {
                            paths[f"{arm}.raw"].name: artifact(paths[f"{arm}.raw"]),
                            paths[f"{arm}.json"].name: artifact(paths[f"{arm}.json"]),
                        },
                        "status": "passed",
                        "expected_effective_identity": {"euid": 501, "egid": 20},
                        "observed_effective_identity": {
                            "euids": [501],
                            "egids": [20],
                            "reported": 2,
                        },
                    }
                ),
                encoding="utf-8",
            )
        result = native_pc_range_risk.main(
            [
                "--v2-raw",
                str(paths["v2.raw"]),
                "--v2-analysis",
                str(paths["v2.json"]),
                "--v2-capture",
                str(paths["v2.capture.json"]),
                "--v3-raw",
                str(paths["v3.raw"]),
                "--v3-analysis",
                str(paths["v3.json"]),
                "--v3-capture",
                str(paths["v3.capture.json"]),
                "--binary",
                str(paths["carrick"]),
                "--output",
                str(paths["risk.json"]),
            ]
        )
        receipt = json.loads(paths["risk.json"].read_text(encoding="utf-8"))
        self.assertEqual(
            receipt["artifacts"]["binary"]["sha256"],
            hashlib.sha256(b"signed binary").hexdigest(),
        )
        self.assertEqual(receipt["predicates"], native_pc_range_risk.PREDICATES)
        return result, receipt

    def test_writes_passing_hash_bound_receipt_when_no_v3_owner_is_larger(self) -> None:
        result, receipt = self.run_comparison(v3_kernel=30)
        self.assertEqual(result, 0)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["comparisons"]["dyld"]["v2_per_1000"], 100.0)
        self.assertEqual(receipt["comparisons"]["dyld"]["v3_per_1000"], 50.0)
        self.assertFalse(receipt["comparisons"]["kernel"]["v3_larger"])
        self.assertEqual(receipt["capture_pairs"], 1)
        self.assertEqual(
            receipt["artifacts"]["v2"][0]["identity"]["expected"],
            {"egid": 20, "euid": 501},
        )

    def test_weak_upward_point_estimate_is_preserved_but_not_supported(self) -> None:
        result, receipt = self.run_comparison(v3_kernel=50)
        self.assertEqual(result, 0)
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["comparisons"]["kernel"]["v3_larger"])
        self.assertFalse(
            receipt["comparisons"]["kernel"]["supported_v3_increase"]
        )
        self.assertEqual(
            receipt["regression_method"],
            "one-sided pooled two-proportion z test; H0 p_v3 <= p_v2; alpha=0.05",
        )
        self.assertEqual(
            receipt["comparisons"]["kernel"]["one_sided_p_value"],
            0.167213765834,
        )
        self.assertEqual(
            receipt["comparisons"]["kernel"][
                "one_sided_95_lower_delta_per_1000"
            ],
            -32.857205569,
        )
        self.assertEqual(receipt["larger_v3_owners"], ["kernel"])
        self.assertEqual(receipt["supported_v3_owner_increases"], [])

    def test_strong_synthetic_increase_fails_one_sided_regression_test(self) -> None:
        result, receipt = self.run_comparison(v3_kernel=150)
        self.assertEqual(result, 2)
        self.assertEqual(receipt["status"], "failed")
        self.assertTrue(receipt["comparisons"]["kernel"]["v3_larger"])
        self.assertEqual(receipt["larger_v3_owners"], ["kernel"])
        self.assertEqual(receipt["supported_v3_owner_increases"], ["kernel"])
        self.assertLess(receipt["comparisons"]["kernel"]["one_sided_p_value"], 0.05)
        self.assertGreater(
            receipt["comparisons"]["kernel"]["one_sided_95_lower_delta_per_1000"],
            0.0,
        )


if __name__ == "__main__":
    unittest.main()
