#!/usr/bin/env python3

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_go_build
import native_go_build_screen


class NativeGoBuildScreenTest(unittest.TestCase):
    def test_palindromic_order_is_precursor_default_candidate_then_reverse(self):
        self.assertEqual(
            native_go_build_screen.PALINDROMIC,
            (
                "precursor",
                "default",
                "candidate",
                "candidate",
                "default",
                "precursor",
            ),
        )

    def test_default_drift_over_five_percent_discards_the_screen(self):
        result = native_go_build_screen.evaluate_screen(
            [
                {"variant": "precursor", "elapsed_ms": 100},
                {"variant": "default", "elapsed_ms": 100},
                {"variant": "candidate", "elapsed_ms": 90},
                {"variant": "candidate", "elapsed_ms": 90},
                {"variant": "default", "elapsed_ms": 106},
                {"variant": "precursor", "elapsed_ms": 100},
            ]
        )

        self.assertFalse(result["accepted"])
        self.assertIn("default drift exceeds 1.05", result["rejection_reasons"])

    def test_candidate_must_beat_c0_both_defaults_and_precursor(self):
        result = native_go_build_screen.evaluate_screen(
            [
                {"variant": "precursor", "elapsed_ms": 100},
                {"variant": "default", "elapsed_ms": 100},
                {"variant": "candidate", "elapsed_ms": 101},
                {"variant": "candidate", "elapsed_ms": 90},
                {"variant": "default", "elapsed_ms": 100},
                {"variant": "precursor", "elapsed_ms": 100},
            ]
        )

        self.assertFalse(result["accepted"])
        self.assertIn(
            "candidate position 3 did not beat paired default position 2",
            result["rejection_reasons"],
        )

    def test_candidate_default_median_ratio_must_be_at_most_point_97(self):
        result = native_go_build_screen.evaluate_screen(
            [
                {"variant": "precursor", "elapsed_ms": 103},
                {"variant": "default", "elapsed_ms": 100},
                {"variant": "candidate", "elapsed_ms": 98},
                {"variant": "candidate", "elapsed_ms": 97},
                {"variant": "default", "elapsed_ms": 100},
                {"variant": "precursor", "elapsed_ms": 103},
            ]
        )

        self.assertFalse(result["accepted"])
        self.assertEqual(result["candidate_default_ratio"], 0.975)

    def test_retention_bootstrap_is_seeded_and_reproducible(self):
        first = native_go_build_screen.bootstrap_ratio(
            [100, 101, 99, 100, 102],
            [90, 91, 89, 90, 92],
        )
        second = native_go_build_screen.bootstrap_ratio(
            [100, 101, 99, 100, 102],
            [90, 91, 89, 90, 92],
        )

        self.assertEqual(first, second)
        self.assertEqual(first["seed"], 0)
        self.assertEqual(first["draws"], 100_000)
        self.assertEqual(first["one_sided_95_ratio"], 91 / 99)

    def test_retention_requires_candidate_median_below_c0(self):
        rows = []
        for index, elapsed in enumerate(
            [19_400, 19_000, 19_500, 19_100, 19_600], start=1
        ):
            rows.append(
                {"variant": "default", "elapsed_ms": 20_000 + index, "index": index}
            )
            rows.append(
                {"variant": "candidate", "elapsed_ms": elapsed, "index": index}
            )

        result = native_go_build_screen.evaluate_retention(rows)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["candidate_median_ms"], 19_400)
        self.assertIn(
            "candidate median is not below C0=19375 ms",
            result["rejection_reasons"],
        )

    def test_variant_environment_removes_control_variables_for_default(self):
        ambient = {
            "PATH": "/bin",
            "CARRICK_DSR_ARTIFACT_SPIKE": "1",
            "CARRICK_DSR_DIRECT_BINDINGS": "1",
        }

        environment, normalized = native_go_build.variant_environment(
            ambient, "default", native_go_build.ENGINE_CARRICK
        )

        self.assertEqual(environment["PATH"], "/bin")
        self.assertNotIn("CARRICK_DSR_ARTIFACT_SPIKE", environment)
        self.assertNotIn("CARRICK_DSR_DIRECT_BINDINGS", environment)
        self.assertTrue(all(value is None for value in normalized.values()))

    def test_profile_and_container_cache_cannot_leak_into_default(self):
        ambient = {
            "PATH": "/bin",
            "CARRICK_DSR_PROFILE": "1",
            "CARRICK_DSR_KEEP_CONTAINER_CACHE": "1",
        }

        environment, _ = native_go_build.variant_environment(
            ambient, "default", native_go_build.ENGINE_CARRICK
        )

        self.assertNotIn("CARRICK_DSR_PROFILE", environment)
        self.assertNotIn("CARRICK_DSR_KEEP_CONTAINER_CACHE", environment)

    def test_candidate_cli_uses_only_the_fixed_candidate_overlay(self):
        with mock.patch.dict(
            os.environ,
            {
                "CARRICK_DSR_PROFILE": "1",
                "CARRICK_DSR_KEEP_CONTAINER_CACHE": "1",
            },
            clear=False,
        ):
            environment, normalized = native_go_build.variant_environment(
                os.environ, "candidate", native_go_build.ENGINE_CARRICK
            )

        enabled = {
            key for key, value in normalized.items() if value is not None
        }
        self.assertEqual(
            enabled,
            {
                "CARRICK_DSR_ARTIFACT_SPIKE",
                "CARRICK_DSR_SHARED_TRANSLATION",
                "CARRICK_DSR_DIRECT_BINDINGS",
            },
        )
        self.assertNotIn("CARRICK_DSR_PROFILE", environment)
        self.assertNotIn("CARRICK_DSR_KEEP_CONTAINER_CACHE", environment)
        self.assertEqual(
            native_go_build.parse_args(["--variant", "candidate"]).variant,
            "candidate",
        )

    def test_drift_formula_pairs_and_nearest_rank_are_exact(self):
        result = native_go_build_screen.evaluate_screen(
            [
                {"variant": "precursor", "elapsed_ms": 104},
                {"variant": "default", "elapsed_ms": 100},
                {"variant": "candidate", "elapsed_ms": 95},
                {"variant": "candidate", "elapsed_ms": 94},
                {"variant": "default", "elapsed_ms": 105},
                {"variant": "precursor", "elapsed_ms": 102},
            ]
        )

        self.assertEqual(result["default_drift_ratio"], 1.05)
        self.assertEqual(
            result["contemporaneous_pairs"],
            [
                {"candidate_position": 3, "default_position": 2, "ratio": 0.95},
                {
                    "candidate_position": 4,
                    "default_position": 5,
                    "ratio": 94 / 105,
                },
            ],
        )
        fixture = native_go_build_screen.bootstrap_ratio(
            [10, 20, 30, 40, 50],
            [5, 10, 15, 20, 25],
            draws=10,
            seed=0,
        )
        self.assertEqual(fixture["nearest_rank_index"], 10)
        self.assertEqual(fixture["one_sided_95_ratio"], 1.5)

    def test_rejected_screen_is_written_atomically_with_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "screen.json"
            rows = [
                {"variant": variant, "elapsed_ms": elapsed}
                for variant, elapsed in zip(
                    native_go_build_screen.PALINDROMIC,
                    [100, 100, 99, 99, 106, 100],
                    strict=True,
                )
            ]

            payload = native_go_build_screen.publish_screen(output, rows)

            stored = json.loads(output.read_text())
            self.assertFalse(payload["accepted"])
            self.assertEqual(stored["samples"], rows)
            self.assertFalse(stored["accepted"])
            self.assertEqual(list(output.parent.glob(f".{output.name}.*")), [])

    def test_failed_current_sample_is_included_in_atomic_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "screen.json"
            failed_row = {
                "engine": "carrick",
                "index": 1,
                "run_id": "native-go-build-carrick-fixture-1",
                "elapsed_ms": 12,
                "stdout": "BUILD_OK\n",
                "stderr": "diagnostic\n",
                "command": {"status": 0, "build_ok": True},
                "cleanup": {
                    "status": 3,
                    "stdout": "cleanup stdout\n",
                    "stderr": "cleanup stderr\n",
                },
            }
            failure = native_go_build.SampleEvidenceError(
                "cleanup status is nonzero",
                failed_row,
            )

            result = native_go_build_screen.run_campaign(
                pathlib.Path(directory),
                "screen",
                output,
                5,
                sample_runner=mock.Mock(side_effect=failure),
            )

            self.assertFalse(result["accepted"])
            self.assertEqual(result["samples"], [{**failed_row, "variant": "precursor"}])
            self.assertEqual(json.loads(output.read_text()), result)
            self.assertEqual(list(output.parent.glob(f".{output.name}.*")), [])


if __name__ == "__main__":
    unittest.main()
