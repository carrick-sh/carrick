#!/usr/bin/env python3

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import el1_workload_ab as ab
import native_go_build


SUITES = ab.load_suites(ab.REPO / "scripts/conformance/suites.toml")
BINARY = pathlib.Path("/opt/carrick")


class ArmTest(unittest.TestCase):
    def test_default_arms_are_the_lane_hatch_and_the_binary_default(self):
        control, candidate = ab.parse_arms(ab.DEFAULT_ARMS)
        self.assertEqual(control.label, "lane-off")
        self.assertEqual(control.env(), {"CARRICK_EL1_DESCRIPTOR_LANE": "0"})
        self.assertEqual(candidate.label, "lane-on")
        self.assertEqual(candidate.env(), {})

    def test_arms_reject_non_carrick_keys_run_id_and_bad_counts(self):
        for spec in ("x:PATH=/bin", "x:CARRICK_RUN_ID=1", "x:CARRICK_A", "x:CARRICK_A=1,CARRICK_A=2", "bad label"):
            with self.assertRaises(ValueError, msg=spec):
                ab.parse_arm(spec)
        with self.assertRaises(ValueError):
            ab.parse_arms(["a"])
        with self.assertRaises(ValueError):
            ab.parse_arms(["a", "a:CARRICK_X=1"])

    def test_each_arm_scrubs_the_other_arms_keys(self):
        arms = ab.parse_arms(ab.DEFAULT_ARMS)
        with mock.patch.dict(ab.os.environ, {"HOME": "/h"}, clear=True):
            on = ab.arm_environment(arms[1], arms, "rid")
            off = ab.arm_environment(arms[0], arms, "rid")
        self.assertNotIn(ab.LANE_ENV, on)
        self.assertEqual(off[ab.LANE_ENV], "0")
        self.assertEqual(on["CARRICK_RUN_ID"], "rid")

    def test_ambient_carrick_controls_are_refused(self):
        arms = ab.parse_arms(ab.DEFAULT_ARMS)
        with mock.patch.dict(ab.os.environ, {ab.LANE_ENV: "1"}, clear=True):
            with self.assertRaises(RuntimeError):
                ab.arm_environment(arms[1], arms, "rid")


class WorkloadArgvTest(unittest.TestCase):
    def test_go_build_is_native_go_build_byte_for_byte(self):
        workload = ab.resolve_workload("go-build", SUITES)
        self.assertTrue(workload.has_window)
        self.assertEqual(
            ab.carrick_argv(workload, BINARY, "rid"),
            native_go_build.build_carrick_command(ab.REPO, "rid", binary=BINARY),
        )
        self.assertEqual(
            ab.docker_argv(workload, "rid"),
            native_go_build.build_command(ab.REPO, native_go_build.ENGINE_DOCKER, "rid"),
        )

    def test_node_suite_follows_the_harness_argv_rules(self):
        workload = ab.resolve_workload("node-app-smoke", SUITES)
        argv = ab.carrick_argv(workload, BINARY, "rid")
        self.assertEqual(argv[:6], [str(BINARY), "run", "--name", "rid", "--max-traps", str((1 << 64) - 1)])
        self.assertIn("--fs", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/usr/local/bin/nodejs-conformance")
        self.assertIn("NODEJS_CONFORMANCE_EFFECTIVE_RUNNER=carrick", argv)
        self.assertIn("NODEJS_CONFORMANCE_IN_IMAGE=1", argv)
        self.assertEqual(argv[-len(SUITES["node-app-smoke"]["cmd"]):], SUITES["node-app-smoke"]["cmd"])
        docker = ab.docker_argv(workload, "rid")
        self.assertEqual(docker[:6], ["docker", "run", "--name", "rid", "--platform", "linux/arm64"])
        self.assertIn("NODEJS_CONFORMANCE_EFFECTIVE_RUNNER=docker", docker)
        self.assertNotIn("--max-traps", docker)

    def test_cpython_threading_is_the_suite_command(self):
        workload = ab.resolve_workload("cpython-threading", SUITES)
        self.assertFalse(workload.has_window)
        argv = ab.carrick_argv(workload, BINARY, "rid")
        self.assertEqual(argv[-1], "test_threading")
        self.assertEqual(workload.timeout_s, SUITES["cpython-threading"]["timeout_s"])

    def test_unknown_workloads_are_refused(self):
        with self.assertRaises(ValueError):
            ab.resolve_workload("not-a-suite", SUITES)

    def test_harness_check_normalizes_run_ids_and_detects_drift(self):
        workload = ab.resolve_workload("node-app-smoke", SUITES)
        carrick = " ".join(ab.carrick_argv(workload, BINARY, "conf-1-cN"))
        docker = " ".join(ab.docker_argv(workload, "conf-1-dN"))
        with mock.patch.object(ab, "harness_dry_run_lines", return_value=(carrick, docker)):
            ab.check_against_harness(workload, BINARY)
        with mock.patch.object(ab, "harness_dry_run_lines", return_value=(carrick + " extra", docker)):
            with self.assertRaises(RuntimeError):
                ab.check_against_harness(workload, BINARY)


class StatisticsTest(unittest.TestCase):
    def rows(self, a, b):
        rows = []
        for quad, ((a1, a2), (b1, b2)) in enumerate(zip(a, b), start=1):
            for letter, value in (("A", a1), ("B", b1), ("B", b2), ("A", a2)):
                rows.append({"quad": quad, "arm_letter": letter, "cpu_s": value, "ok": True})
        rows.append({"quad": None, "arm_letter": "A", "cpu_s": 99.0, "ok": True})
        return rows

    def test_abba_positions_warm_up_then_quads(self):
        positions = ab.abba_positions(2)
        self.assertEqual([p[2] for p in positions], ["A", "B", "A", "B", "B", "A", "A", "B", "B", "A"])
        self.assertIsNone(positions[0][1])
        with self.assertRaises(ValueError):
            ab.abba_positions(1)

    def test_summary_is_candidate_over_control_per_quad(self):
        summary = ab.summarize_abba(self.rows([(10, 10), (12, 12), (11, 11)], [(5, 5), (6, 6), (5.5, 5.5)]), "cpu_s")
        self.assertEqual(summary["quads"], 3)
        self.assertAlmostEqual(summary["median_ratio_candidate_over_control"], 0.5)
        self.assertEqual(summary["candidate_wins"], 3)
        self.assertEqual(summary["control_median"], 11)

    def test_summary_refuses_missing_metrics_or_short_quads(self):
        rows = self.rows([(10, 10), (12, 12)], [(5, 5), (6, 6)])
        rows[0]["cpu_s"] = None
        self.assertIsNone(ab.summarize_abba(rows, "cpu_s"))
        self.assertIsNone(ab.summarize_abba(self.rows([(10, 10)], [(5, 5)]), "cpu_s"))

    def test_attribution_bound_is_in_profile_granularity(self):
        self.assertEqual(ab.attribution_bound(180), 360)
        self.assertEqual(ab.attribution_bound(5), 30)
        self.assertEqual(ab.attribution_bound(10**6), 21_600)
        self.assertEqual(ab.attribution_bound(301) % 10, 0)


class SampleTest(unittest.TestCase):
    def test_go_build_needs_its_window_and_marker(self):
        workload = ab.resolve_workload("go-build", SUITES)
        good = {"timed_out": False, "return_code": 0, "workload_ms": 5, "stdout_tail": "BUILD_OK\n"}
        self.assertTrue(ab.sample_ok(workload, good, False))
        self.assertFalse(ab.sample_ok(workload, {**good, "workload_ms": None}, False))
        self.assertFalse(ab.sample_ok(workload, {**good, "timed_out": True}, False))

    def test_suites_accept_nonzero_only_when_asked(self):
        workload = ab.resolve_workload("node-app-smoke", SUITES)
        failed = {"timed_out": False, "return_code": 1, "workload_ms": None, "stdout_tail": ""}
        self.assertFalse(ab.sample_ok(workload, failed, False))
        self.assertTrue(ab.sample_ok(workload, failed, True))

    def test_trace_argv_forwards_the_run_and_profile(self):
        argv = ab.trace_argv(BINARY, "hvpatch-exit-attribution", pathlib.Path("r"), pathlib.Path("s"), 60, [str(BINARY), "run", "img"])
        self.assertEqual(argv[:4], [str(BINARY), "trace", "--profile", "hvpatch-exit-attribution"])
        self.assertEqual(argv[-3:], ["--", "run", "img"])
        self.assertIn("--summary-jsonl", argv)

    def test_preflight_refuses_docker_even_when_busy_is_allowed(self):
        with mock.patch.object(ab.native_go_build, "busy_host_reasons", return_value=[]), \
             mock.patch.object(ab.native_go_build, "foreign_workload_census", return_value=[]), \
             mock.patch.object(ab, "docker_oracles_or_absent", return_value=["abc conf-1 img"]):
            with self.assertRaises(RuntimeError):
                ab.preflight(BINARY, allow_busy=True)
        with mock.patch.object(ab.native_go_build, "busy_host_reasons", return_value=["load"]), \
             mock.patch.object(ab.native_go_build, "foreign_workload_census", return_value=[]), \
             mock.patch.object(ab, "docker_oracles_or_absent", return_value=[]):
            with self.assertRaises(RuntimeError):
                ab.preflight(BINARY, allow_busy=False)
            self.assertEqual(ab.preflight(BINARY, allow_busy=True)["busy_reasons"], ["load"])


class ReportTest(unittest.TestCase):
    def test_report_joins_timing_attribution_and_docker(self):
        rows = []
        for quad in (1, 2):
            for letter, value in (("A", 20.0), ("B", 10.0), ("B", 10.0), ("A", 20.0)):
                rows.append({"quad": quad, "arm_letter": letter, "ok": True, "elapsed_ms": value * 100, "workload_ms": value * 50, "cpu_s": value})
        carrick = {
            "binary": {"sha256": "x"},
            "arms": {"A": {"label": "lane-off"}, "B": {"label": "lane-on"}},
            "workloads": {"go-build": {"samples": rows, "all_ok": True, "summary": None}},
        }
        bucket = lambda n: {"exits": n, "host_oncpu_ns": n * 1e6}  # noqa: E731
        exit_summary = {
            "by_bucket": {"syscall": bucket(4), "fault": bucket(3), "kick-idle": bucket(2), "other": bucket(1)},
            "guest_oncpu_ns": 3, "host_oncpu_ns": 1,
            "forwarded": [{"nr": 98, "name": "futex", "count": 7}],
        }
        attribution = {"workloads": {"go-build": {"lane-on": {"hvpatch-exit-attribution": {"summary": exit_summary}}}}}
        docker = {"workloads": {"go-build": {"median_elapsed_ms": 500.0, "median_workload_ms": 250.0}}}
        report = ab.build_report(carrick, attribution, docker)
        on = report["workloads"]["go-build"]["lane-on"]
        self.assertEqual(on["median_elapsed_ms"], 1000.0)
        self.assertEqual(on["elapsed_over_docker"], 2.0)
        self.assertEqual(on["workload_over_docker"], 2.0)
        self.assertEqual(on["exits_by_bucket"]["fault"], 3)
        self.assertEqual(on["executor_guest_oncpu_share"], 0.75)
        self.assertEqual(report["workloads"]["go-build"]["lane-off"]["elapsed_over_docker"], 4.0)
        table = ab.render_report(report)
        self.assertIn("| go-build | lane-on | 1000 | 500 | 10.00 | 2.00x | 2.00x | 4/3/2/1 |", table)


if __name__ == "__main__":
    unittest.main()
