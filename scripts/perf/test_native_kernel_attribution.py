#!/usr/bin/env python3
"""Behavioral tests for exact native kernel-family selection."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))


SCHEMA = "carrick.dsr-profile.v1"
PROFILE = "native-wall"
U64_MAX = (1 << 64) - 1


def completion() -> dict[str, object]:
    return {
        "complete": True,
        "bounded": False,
        "target_exit_reason": 1,
        "high_cardinality_overflow": False,
        "incomplete_pairs": 0,
        "drops": {
            "interrupted": False,
            "principal_drops": 0,
            "aggregation_drops": 0,
            "dynamic_drops": 0,
            "other_drops": 0,
        },
    }


def base_row(run_id: str) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "run_id": run_id,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "binary_sha256": "b" * 64,
        "command": ["target/release/carrick", "run", "fixture"],
        "host": "fixture-host",
        "sampling_interval": None,
        "completion": completion(),
    }


def pc_row(run_id: str, count: int, source_pc: int) -> dict[str, object]:
    return {
        **base_row(run_id),
        "scope": {
            "phase": "cpu-kernel-pc",
            "pid": None,
            "tid": None,
            "kind": None,
            "source_pc": source_pc,
            "target_pc": None,
        },
        "metric": {
            "type": "exact",
            "count": count,
            "total_ns": None,
            "minimum_ns": None,
            "maximum_ns": None,
        },
    }


def family_frames(name: str, suffix: str = "") -> list[str]:
    return [
        f"kernel`{name}_leaf+0x10",
        f"com.apple.driver.{name}`entry+0x2a",
        "kernel`thread_call_run+0x4",
        "kernel`machine_idle+0x8",
        f"kernel`tail{suffix}+0x1",
    ]


def stack_row(
    run_id: str,
    count: int,
    frames: list[str],
) -> dict[str, object]:
    return {
        **base_row(run_id),
        "scope": {
            "phase": "cpu-kernel-stack",
            "pid": None,
            "tid": None,
            "kind": "kernel-oncpu",
            "source_pc": None,
            "target_pc": None,
        },
        "metric": {
            "type": "stack-trace",
            "state": "kernel-oncpu",
            "count": count,
            "frames": frames,
        },
    }


def completion_row(run_id: str) -> dict[str, object]:
    return {
        **base_row(run_id),
        "scope": {
            "phase": None,
            "pid": None,
            "tid": None,
            "kind": None,
            "source_pc": None,
            "target_pc": None,
        },
        "metric": {"type": "completion"},
    }


def profile_rows(
    run_id: str,
    families: list[tuple[str, int]],
    *,
    pc_counts: list[int] | None = None,
    extra_stacks: list[tuple[int, list[str]]] | None = None,
) -> list[dict[str, object]]:
    total = sum(count for _, count in families)
    total += sum(count for count, _ in extra_stacks or [])
    counts = pc_counts if pc_counts is not None else [total]
    rows = [
        pc_row(run_id, count, 0xFFFFFE0000000000 + index)
        for index, count in enumerate(counts)
    ]
    rows.extend(
        stack_row(run_id, count, family_frames(name))
        for name, count in families
    )
    rows.extend(
        stack_row(run_id, count, frames)
        for count, frames in extra_stacks or []
    )
    rows.append(completion_row(run_id))
    return rows


class NativeKernelAttributionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.tool = importlib.import_module("native_kernel_attribution")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_rows(self, name: str, rows: list[dict[str, object]]) -> pathlib.Path:
        path = self.root / name
        path.write_text(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            )
        )
        return path

    def analyze_rows(
        self,
        first: list[dict[str, object]],
        second: list[dict[str, object]],
    ) -> dict[str, object]:
        first_path = self.write_rows("first.jsonl", first)
        second_path = self.write_rows("second.jsonl", second)
        return self.tool.analyze_profiles((first_path, second_path))

    @staticmethod
    def candidate(document: dict[str, object], prefix: str) -> dict[str, object]:
        candidates = document["candidates"]
        assert isinstance(candidates, list)
        return next(
            candidate
            for candidate in candidates
            if candidate["family"].startswith(f"kernel`{prefix}_leaf")
        )

    def test_exact_five_point_drift_passes_and_offsets_only_are_removed(self) -> None:
        first = profile_rows(
            "run-a",
            [("alpha", 15), ("common", 65), ("tail", 20)],
        )
        second = profile_rows(
            "run-b",
            [("alpha", 10), ("common", 65), ("tail", 25)],
        )

        document = self.analyze_rows(first, second)

        alpha = self.candidate(document, "alpha")
        self.assertTrue(alpha["gates"]["drift_at_most_five_points"])
        self.assertEqual(alpha["absolute_drift"], {"numerator": 1, "denominator": 20})
        self.assertEqual(
            alpha["family"],
            "kernel`alpha_leaf | com.apple.driver.alpha`entry | "
            "kernel`thread_call_run | kernel`machine_idle",
        )
        self.assertEqual(document["result"], "selectable")

    def test_just_over_five_point_drift_fails_exactly(self) -> None:
        first = profile_rows(
            "run-a",
            [("alpha", 1501), ("common", 6000), ("tail", 2499)],
        )
        second = profile_rows(
            "run-b",
            [("alpha", 999), ("common", 6000), ("tail", 3001)],
        )

        alpha = self.candidate(self.analyze_rows(first, second), "alpha")

        self.assertFalse(alpha["gates"]["drift_at_most_five_points"])
        self.assertEqual(
            alpha["absolute_drift"],
            {"numerator": 251, "denominator": 5000},
        )

    def test_exact_and_just_below_five_percent_membership_are_distinct(self) -> None:
        exact = self.analyze_rows(
            profile_rows("run-a", [("alpha", 5), ("common", 95)]),
            profile_rows("run-b", [("alpha", 10), ("common", 90)]),
        )
        below = self.analyze_rows(
            profile_rows("run-a", [("alpha", 499), ("common", 9501)]),
            profile_rows("run-b", [("alpha", 1000), ("common", 9000)]),
        )

        self.assertTrue(
            self.candidate(exact, "alpha")["gates"]["at_least_five_percent_each"]
        )
        self.assertFalse(
            self.candidate(below, "alpha")["gates"]["at_least_five_percent_each"]
        )

    def test_mean_share_and_shared_coverage_failures_are_independent(self) -> None:
        under_ten = [(f"family{index:02}", 9) for index in range(11)]
        under_ten.append(("remainder", 1))
        mean_failure = self.analyze_rows(
            profile_rows("run-a", under_ten),
            profile_rows("run-b", under_ten),
        )
        coverage_failure = self.analyze_rows(
            profile_rows(
                "run-a",
                [("common", 20)]
                + [(f"only_a{index:02}", 8) for index in range(10)],
            ),
            profile_rows(
                "run-b",
                [("common", 20)]
                + [(f"only_b{index:02}", 8) for index in range(10)],
            ),
        )

        self.assertEqual(mean_failure["result"], "diffuse")
        self.assertEqual(
            mean_failure["diffuse_reasons"],
            ["no-family-has-ten-percent-mean-share"],
        )
        self.assertEqual(coverage_failure["result"], "diffuse")
        self.assertEqual(
            coverage_failure["diffuse_reasons"],
            ["shared-top-ten-coverage-below-sixty-percent"],
        )

    def test_mean_and_shared_coverage_failures_can_conjoin(self) -> None:
        first = [(f"only_a{index:02}", 9) for index in range(10)]
        first.extend([("common", 9), ("a_remainder", 1)])
        second = [(f"only_b{index:02}", 9) for index in range(10)]
        second.extend([("common", 9), ("b_remainder", 1)])

        document = self.analyze_rows(
            profile_rows("run-a", first),
            profile_rows("run-b", second),
        )

        self.assertEqual(document["result"], "diffuse")
        self.assertEqual(
            document["diffuse_reasons"],
            [
                "no-family-has-ten-percent-mean-share",
                "shared-top-ten-coverage-below-sixty-percent",
            ],
        )

    def test_unresolved_leaf_is_not_replaced_by_a_symbolized_caller(self) -> None:
        unresolved = [
            "0xfffffe0012345678",
            "kernel`caller_must_not_become_leaf+0x10",
            "kernel`thread_call_run+0x4",
            "kernel`machine_idle+0x8",
        ]
        first = profile_rows(
            "run-a",
            [("resolved", 94)],
            extra_stacks=[(6, unresolved)],
        )
        second = profile_rows(
            "run-b",
            [("resolved", 94)],
            extra_stacks=[(6, unresolved)],
        )

        document = self.analyze_rows(first, second)

        self.assertEqual(document["result"], "rejected")
        self.assertEqual(
            document["evidence_errors"],
            [
                "run 1 symbolized kernel leaf coverage 47/50 is below 19/20",
                "run 2 symbolized kernel leaf coverage 47/50 is below 19/20",
            ],
        )

    def test_pc_and_stack_counts_reconcile_independently_per_run(self) -> None:
        document = self.analyze_rows(
            profile_rows("run-a", [("alpha", 99)], pc_counts=[100]),
            profile_rows("run-b", [("alpha", 100)]),
        )

        self.assertEqual(document["result"], "rejected")
        self.assertEqual(
            document["evidence_errors"],
            ["run 1 kernel PC count 100 does not equal kernel stack count 99"],
        )

    def test_checked_u64_addition_rejects_max_plus_one(self) -> None:
        overflowing = profile_rows(
            "run-a",
            [],
            pc_counts=[U64_MAX, 1],
            extra_stacks=[
                (U64_MAX, family_frames("alpha", "-max")),
                (1, family_frames("alpha", "-one")),
            ],
        )

        document = self.analyze_rows(
            overflowing,
            profile_rows("run-b", [("alpha", 1)]),
        )

        self.assertEqual(document["result"], "rejected")
        self.assertEqual(
            document["evidence_errors"],
            ["run 1 kernel PC count addition exceeds u64"],
        )

    def test_exact_fraction_ordering_beats_float_equivalence(self) -> None:
        total = 1 << 54
        larger = 1 << 53
        smaller = larger - 1
        rows = profile_rows(
            "run-a",
            [("larger", larger), ("smaller", smaller), ("tail", 1)],
        )
        other_rows = copy.deepcopy(rows)
        for row in other_rows:
            row["run_id"] = "run-b"

        document = self.analyze_rows(rows, other_rows)

        selected = document["selected_family"]
        self.assertIsInstance(selected, dict)
        self.assertTrue(selected["family"].startswith("kernel`larger_leaf"))
        self.assertEqual(
            selected["mean_share"],
            {"numerator": 1, "denominator": 2},
        )
        self.assertEqual(selected["total_count"], 1 << 54)

    def test_equal_fraction_and_count_ties_use_normalized_family_text(self) -> None:
        rows_a = profile_rows("run-a", [("zeta", 50), ("alpha", 50)])
        rows_b = profile_rows("run-b", [("zeta", 50), ("alpha", 50)])

        document = self.analyze_rows(rows_a, rows_b)

        selected = document["selected_family"]
        self.assertIsInstance(selected, dict)
        self.assertTrue(selected["family"].startswith("kernel`alpha_leaf"))

    def test_malformed_incomplete_dropped_bounded_and_nonnatural_reject(self) -> None:
        good_a = profile_rows("run-a", [("alpha", 100)])
        good_b = profile_rows("run-b", [("alpha", 100)])
        cases = {
            "malformed count": lambda rows: rows[0]["metric"].__setitem__(
                "count", True
            ),
            "incomplete": lambda rows: rows[0]["completion"].__setitem__(
                "complete", False
            ),
            "dropped": lambda rows: rows[0]["completion"]["drops"].__setitem__(
                "principal_drops", 1
            ),
            "bounded": lambda rows: rows[0]["completion"].__setitem__(
                "bounded", True
            ),
            "nonnatural": lambda rows: rows[0]["completion"].__setitem__(
                "target_exit_reason", 2
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                bad = copy.deepcopy(good_a)
                mutate(bad)
                document = self.analyze_rows(bad, good_b)
                self.assertEqual(document["result"], "rejected")
                self.assertTrue(document["evidence_errors"])

    def test_boolean_completion_counts_are_malformed_not_natural_numbers(self) -> None:
        good_b = profile_rows("run-b", [("alpha", 100)])
        for field, value in (
            ("target_exit_reason", True),
            ("incomplete_pairs", False),
        ):
            with self.subTest(field=field):
                bad = profile_rows("run-a", [("alpha", 100)])
                for row in bad:
                    row["completion"][field] = value

                document = self.analyze_rows(bad, good_b)

                self.assertEqual(document["result"], "rejected")
                self.assertTrue(document["evidence_errors"])

    def test_document_has_source_hashes_exact_counts_and_exact_fractions(self) -> None:
        first_path = self.write_rows(
            "first.jsonl",
            profile_rows("run-a", [("alpha", 60), ("beta", 40)]),
        )
        second_path = self.write_rows(
            "second.jsonl",
            profile_rows("run-b", [("alpha", 60), ("beta", 40)]),
        )

        document = self.tool.analyze_profiles((first_path, second_path))

        self.assertEqual(document["schema"], "carrick.native-kernel-attribution.v1")
        self.assertEqual(
            document["sources"][0]["sha256"],
            hashlib.sha256(first_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(document["runs"][0]["kernel_pc_count"], 100)
        self.assertEqual(document["runs"][0]["kernel_stack_count"], 100)
        self.assertEqual(
            document["runs"][0]["symbolized_leaf_share"],
            {"numerator": 1, "denominator": 1},
        )
        self.assertEqual(
            document["shared_top_ten"]["coverage"],
            [
                {"numerator": 1, "denominator": 1},
                {"numerator": 1, "denominator": 1},
            ],
        )
        self.assertNotIn("H006", json.dumps(document))

    def test_cli_writes_one_atomic_document_and_fails_closed_on_rejection(self) -> None:
        first_path = self.write_rows(
            "first.jsonl",
            profile_rows("run-a", [("alpha", 99)], pc_counts=[100]),
        )
        second_path = self.write_rows(
            "second.jsonl",
            profile_rows("run-b", [("alpha", 100)]),
        )
        output = self.root / "result.json"
        output.write_text("old incomplete data")

        status = self.tool.main(
            [
                "--profile",
                str(first_path),
                "--profile",
                str(second_path),
                "--output",
                str(output),
            ]
        )

        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.read_text())["result"], "rejected")
        self.assertEqual(
            list(self.root.glob(f".{output.name}.*.tmp")),
            [],
        )

    def test_cli_replaces_stale_selectable_output_for_one_or_three_profiles(
        self,
    ) -> None:
        profile = self.write_rows(
            "profile.jsonl",
            profile_rows("run-a", [("alpha", 100)]),
        )
        for count in (1, 3):
            with self.subTest(profile_count=count):
                output = self.root / f"cardinality-{count}.json"
                output.write_text('{"result":"selectable","stale":true}\n')
                command = [
                    sys.executable,
                    str(SCRIPT_DIR / "native_kernel_attribution.py"),
                ]
                for _ in range(count):
                    command.extend(["--profile", str(profile)])
                command.extend(["--output", str(output)])

                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(
                    json.loads(output.read_text())["result"],
                    "rejected",
                )
                self.assertEqual(
                    json.loads(output.read_text())["evidence_errors"],
                    ["exactly two profiles are required"],
                )
                self.assertEqual(
                    list(self.root.glob(f".{output.name}.*.tmp")),
                    [],
                )

    def test_same_profile_twice_rejects_every_duplicate_identity(self) -> None:
        profile = self.write_rows(
            "profile.jsonl",
            profile_rows("run-a", [("alpha", 100)]),
        )

        document = self.tool.analyze_profiles((profile, profile))

        self.assertEqual(document["result"], "rejected")
        self.assertEqual(
            document["evidence_errors"],
            [
                "profile paths must be distinct",
                "profile source hashes must be distinct",
                "profile run_id values must be distinct",
            ],
        )

    def test_duplicate_run_id_rejects_distinct_profile_sources(self) -> None:
        first = self.write_rows(
            "first.jsonl",
            profile_rows("same-run", [("alpha", 100)]),
        )
        second_rows = profile_rows("same-run", [("alpha", 100)])
        for row in second_rows:
            row["command"] = ["target/release/carrick", "run", "other-fixture"]
        second = self.write_rows("second.jsonl", second_rows)

        document = self.tool.analyze_profiles((first, second))

        self.assertEqual(document["result"], "rejected")
        self.assertEqual(
            document["evidence_errors"],
            ["profile run_id values must be distinct"],
        )


if __name__ == "__main__":
    unittest.main()
