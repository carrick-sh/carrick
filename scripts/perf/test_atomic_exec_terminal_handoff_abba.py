#!/usr/bin/env python3
"""Focused contracts for the atomic exec-terminal ABBA receipt runner."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import atomic_exec_terminal_handoff_abba as runner


class AbbaRunnerTest(unittest.TestCase):
    def test_launcher_shell_is_not_another_reducer(self):
        self.assertFalse(
            runner.matches_foreign_process(
                "/bin/zsh -c python3 scripts/perf/"
                "atomic_exec_terminal_handoff_abba.py --single HEAD"
            )
        )
        self.assertTrue(
            runner.matches_foreign_process(
                "/opt/homebrew/bin/python3 scripts/perf/"
                "atomic_exec_terminal_handoff_abba.py --single HEAD"
            )
        )

    def test_underscore_conformance_compile_is_foreign_workload(self):
        self.assertTrue(
            runner.matches_foreign_process(
                "rustc --crate-name carrick_conformance_next output.o"
            )
        )

    def test_conformance_worktree_compile_is_foreign_workload(self):
        self.assertTrue(
            runner.matches_foreign_process(
                "clippy-driver rustc --out-dir "
                "/Volumes/CaseSensitive/carrick/.worktrees/"
                "conformance-next-landing/target/debug/deps"
            )
        )

    def test_path_qualified_carrick_run_is_foreign_workload(self):
        self.assertTrue(
            runner.matches_foreign_process(
                "/tmp/carrick/target/release/carrick run ubuntu:24.04 /bin/true"
            )
        )

    def test_reducer_name_in_monitoring_shell_is_not_a_reducer(self):
        self.assertFalse(
            runner.matches_foreign_process(
                "zsh -c ps -axo pid,command | rg "
                "'clone_admission_terminal_claim_cost_receipt'"
            )
        )
        self.assertTrue(
            runner.matches_foreign_process(
                "/tmp/source/target/release/deps/carrick_runtime-d84348e87b2d541e "
                "vcpu_loop::tests::clone_admission_terminal_claim_cost_receipt "
                "--ignored --nocapture --exact"
            )
        )

    def test_uses_system_dwarfdump_for_macho_uuid(self):
        self.assertEqual(runner.dwarfdump_path(), pathlib.Path("/usr/bin/dwarfdump"))

    def test_macho_uuid_resolves_executable_before_changing_directory(self):
        executable = pathlib.Path("target/release/deps/fixture")
        with mock.patch.object(
            runner,
            "require_command",
            return_value=subprocess.CompletedProcess(
                [], 0, "UUID: 11111111-2222-3333-4444-555555555555 (arm64) fixture\n", ""
            ),
        ) as command:
            runner.macho_uuid(executable)
        self.assertEqual(command.call_args.args[0][-1], str(executable.resolve()))
        self.assertEqual(command.call_args.kwargs["cwd"], executable.resolve().parent)

    def test_abba_order_is_exact(self):
        self.assertEqual(
            runner.abba_refs("base", "fixed"),
            [("A1", "base"), ("B1", "fixed"), ("B2", "fixed"), ("A2", "base")],
        )

    def test_reducer_command_targets_the_discovered_ignored_test(self):
        executable = pathlib.Path("/tmp/carrick_runtime-test")
        self.assertEqual(
            runner.reducer_command(
                executable, "vcpu_loop::tests::renamed_terminal_claim_cost_receipt"
            ),
            [
                str(executable),
                "vcpu_loop::tests::renamed_terminal_claim_cost_receipt",
                "--ignored",
                "--nocapture",
                "--exact",
            ],
        )

    def test_discovers_one_full_reducer_test_name(self):
        executable = pathlib.Path("/tmp/carrick_runtime-test")
        listing = (
            "other::test: test\n"
            "vcpu_loop::tests::clone_admission_terminal_claim_cost_receipt: test\n"
        )
        with mock.patch.object(
            runner,
            "require_command",
            return_value=subprocess.CompletedProcess([], 0, listing, ""),
        ):
            self.assertEqual(
                runner.discover_reducer_test_name(executable),
                "vcpu_loop::tests::clone_admission_terminal_claim_cost_receipt",
            )

    def test_discovery_rejects_ambiguous_reducer_test_names(self):
        executable = pathlib.Path("/tmp/carrick_runtime-test")
        listing = (
            "first::clone_admission_terminal_claim_cost_receipt: test\n"
            "second::clone_admission_terminal_claim_cost_receipt: test\n"
        )
        with mock.patch.object(
            runner,
            "require_command",
            return_value=subprocess.CompletedProcess([], 0, listing, ""),
        ):
            with self.assertRaisesRegex(ValueError, "exactly one reducer test"):
                runner.discover_reducer_test_name(executable)

    def test_monitor_censuses_while_child_is_alive_and_at_completion(self):
        class FakeChild:
            def __init__(self):
                self.pid = 4242
                self.polls = iter([None, 0])

            def poll(self):
                return next(self.polls)

        with (
            mock.patch.object(runner, "foreign_processes", side_effect=[[], []]),
            mock.patch.object(runner.time, "sleep"),
        ):
            self.assertEqual(
                runner.monitor_child_census(FakeChild(), "build"),
                {"phase": "build", "observations": 2, "matches": []},
            )

    def test_monitored_command_drains_output_larger_than_a_pipe_while_censusing(self):
        payload_size = 256 * 1024
        command = [
            sys.executable,
            "-c",
            "import sys; "
            f"sys.stdout.write('o' * {payload_size}); "
            f"sys.stderr.write('e' * {payload_size})",
        ]
        with mock.patch.object(runner, "foreign_processes", return_value=[]):
            completed, census = runner.monitored_command(
                command, cwd=pathlib.Path.cwd(), env=None, phase="build"
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "o" * payload_size)
        self.assertEqual(completed.stderr, "e" * payload_size)
        self.assertGreaterEqual(census["observations"], 1)

    def _resistant_descendant_command(self, ready_file: pathlib.Path, *, leader_exits: bool) -> list[str]:
        grandchild = (
            "import os, signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print(f'{os.getpgrp()}:{os.getpid()}', flush=True); "
            "time.sleep(30)"
        )
        leader = (
            "import pathlib, subprocess, sys, time; "
            "grandchild = subprocess.Popen([sys.executable, '-c', sys.argv[2]], "
            "stdout=subprocess.PIPE, text=True); "
            "pathlib.Path(sys.argv[1]).write_text(grandchild.stdout.readline().strip()); "
            + ("sys.exit(0)" if leader_exits else "time.sleep(30)")
        )
        return [sys.executable, "-c", leader, str(ready_file), grandchild]

    def _ready_process_group(self, ready_file: pathlib.Path) -> tuple[int, int]:
        for _ in range(100):
            if ready_file.exists():
                return tuple(map(int, ready_file.read_text().split(":")))
            time.sleep(0.01)
        self.fail("SIGTERM-resistant descendant did not acknowledge readiness")

    def _cleanup_process_group(self, process_group_id: int, descendant_pid: int | None) -> None:
        try:
            os.killpg(process_group_id, 9)
        except ProcessLookupError:
            pass
        if descendant_pid is not None:
            try:
                os.kill(descendant_pid, 9)
            except ProcessLookupError:
                pass
        for _ in range(100):
            if not runner.process_group_exists(process_group_id):
                return
            time.sleep(0.01)

    def test_monitored_command_preserves_invalidation_with_cleanup_failure(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]

        def cleanup_then_fail(monitored):
            try:
                os.killpg(monitored.process_group_id, 9)
            except ProcessLookupError:
                pass
            monitored.child.wait()
            raise RuntimeError("cleanup failed")

        with (
            mock.patch.object(
                runner,
                "monitor_child_census",
                side_effect=ValueError("foreign workload present during build"),
            ),
            mock.patch.object(
                runner.MonitoredChild, "finalize", autospec=True, side_effect=cleanup_then_fail
            ),
        ):
            with self.assertRaises(BaseExceptionGroup) as raised:
                runner.monitored_command(command, cwd=pathlib.Path.cwd(), env=None, phase="build")
        self.assertEqual(
            [str(error) for error in raised.exception.exceptions],
            ["foreign workload present during build", "cleanup failed"],
        )

    def test_monitored_command_groups_nonzero_output_with_cleanup_failure(self):
        command = [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('distinct stdout'); "
            "sys.stderr.write('distinct stderr'); raise SystemExit(23)",
        ]

        def cleanup_then_fail(monitored):
            monitored.child.wait()
            raise RuntimeError("cleanup failed")

        with mock.patch.object(
            runner.MonitoredChild, "finalize", autospec=True, side_effect=cleanup_then_fail
        ):
            with self.assertRaises(BaseExceptionGroup) as raised:
                runner.monitored_command(command, cwd=pathlib.Path.cwd(), env=None, phase="build")
        failures = [str(error) for error in raised.exception.exceptions]
        self.assertIn("command failed (23)", failures[0])
        self.assertIn("distinct stdout", failures[0])
        self.assertIn("distinct stderr", failures[0])
        self.assertEqual(failures[1], "cleanup failed")

    def test_monitored_command_reports_nonzero_output_after_successful_cleanup(self):
        command = [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('ordinary stdout'); "
            "sys.stderr.write('ordinary stderr'); raise SystemExit(23)",
        ]
        with self.assertRaisesRegex(ValueError, "command failed \\(23\\)") as raised:
            runner.monitored_command(command, cwd=pathlib.Path.cwd(), env=None, phase="build")
        self.assertIn("ordinary stdout", str(raised.exception))
        self.assertIn("ordinary stderr", str(raised.exception))

    def test_monitored_command_preserves_invalidation_after_successful_cleanup(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]

        with (
            mock.patch.object(
                runner,
                "monitor_child_census",
                side_effect=ValueError("foreign workload present during build"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "foreign workload present during build"):
                runner.monitored_command(command, cwd=pathlib.Path.cwd(), env=None, phase="build")

    def test_monitored_command_escalates_a_ready_sigterm_resistant_group_on_invalidation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready_file = pathlib.Path(temporary) / "ready"
            signals: list[tuple[int, int]] = []
            spawned: list[subprocess.Popen[str]] = []
            real_killpg = os.killpg
            real_popen = subprocess.Popen

            def record_killpg(process_group_id: int, signum: int) -> None:
                signals.append((process_group_id, signum))
                real_killpg(process_group_id, signum)

            def record_popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                spawned.append(child)
                return child

            process_group_id: int | None = None
            descendant_pid: int | None = None
            try:
                with (
                    mock.patch.object(
                        runner,
                        "foreign_processes",
                        side_effect=lambda _excluded: []
                        if not ready_file.exists()
                        else [{"pid": 1, "command": "foreign"}],
                    ),
                    mock.patch.object(runner.subprocess, "Popen", side_effect=record_popen),
                    mock.patch.object(runner.os, "getpgid", side_effect=AssertionError("must not query leader PGID")),
                    mock.patch.object(runner.os, "killpg", side_effect=record_killpg),
                    mock.patch.object(runner, "PROCESS_GROUP_GRACE_SECONDS", 0.05),
                ):
                    with self.assertRaisesRegex(ValueError, "foreign workload present during build"):
                        runner.monitored_command(
                            self._resistant_descendant_command(ready_file, leader_exits=False),
                            cwd=pathlib.Path.cwd(),
                            env=None,
                            phase="build",
                        )
                process_group_id, descendant_pid = self._ready_process_group(ready_file)
                self.assertIn((process_group_id, runner.signal.SIGKILL), signals)
                self.assertFalse(runner.process_group_exists(process_group_id))
            finally:
                if process_group_id is None and spawned:
                    process_group_id = spawned[0].pid
                if ready_file.exists():
                    process_group_id, descendant_pid = self._ready_process_group(ready_file)
                if process_group_id is not None:
                    self._cleanup_process_group(process_group_id, descendant_pid)

    def test_monitored_command_uses_child_pid_group_after_ready_leader_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready_file = pathlib.Path(temporary) / "ready"
            signals: list[tuple[int, int]] = []
            spawned: list[subprocess.Popen[str]] = []
            real_killpg = os.killpg
            real_popen = subprocess.Popen

            def record_killpg(process_group_id: int, signum: int) -> None:
                signals.append((process_group_id, signum))
                real_killpg(process_group_id, signum)

            def record_popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                spawned.append(child)
                return child

            process_group_id: int | None = None
            descendant_pid: int | None = None
            try:
                with (
                    mock.patch.object(runner, "foreign_processes", return_value=[]),
                    mock.patch.object(runner.subprocess, "Popen", side_effect=record_popen),
                    mock.patch.object(runner.os, "getpgid", side_effect=AssertionError("must not query leader PGID")),
                    mock.patch.object(runner.os, "killpg", side_effect=record_killpg),
                    mock.patch.object(runner, "PROCESS_GROUP_GRACE_SECONDS", 0.05),
                ):
                    _, census = runner.monitored_command(
                        self._resistant_descendant_command(ready_file, leader_exits=True),
                        cwd=pathlib.Path.cwd(),
                        env=None,
                        phase="build",
                    )
                process_group_id, descendant_pid = self._ready_process_group(ready_file)
                self.assertTrue(census["cleanup"]["escalated"])
                self.assertIn((process_group_id, runner.signal.SIGKILL), signals)
                self.assertFalse(runner.process_group_exists(process_group_id))
            finally:
                if process_group_id is None and spawned:
                    process_group_id = spawned[0].pid
                if ready_file.exists():
                    process_group_id, descendant_pid = self._ready_process_group(ready_file)
                if process_group_id is not None:
                    self._cleanup_process_group(process_group_id, descendant_pid)

    def test_power_state_parser_requires_stable_observable_fields(self):
        self.assertEqual(
            runner.parse_power_state(
                "Now drawing from 'AC Power'\n",
                """Note: No thermal warning level has been recorded
Note: No performance warning level has been recorded
Note: No CPU power status has been recorded
""",
                """AC Power:
 lowpowermode         0
""",
            ),
            {
                "power_source": "AC Power",
                "low_power_mode": "0",
                "thermal_warning": "No thermal warning level has been recorded",
                "performance_warning": "No performance warning level has been recorded",
                "cpu_power_status": "No CPU power status has been recorded",
            },
        )

    def test_power_state_change_invalidates_an_arm(self):
        before = {
            "power_source": "AC Power",
            "low_power_mode": "0",
            "thermal_warning": "No thermal warning level has been recorded",
            "performance_warning": "No performance warning level has been recorded",
            "cpu_power_status": "No CPU power status has been recorded",
        }
        after = {**before, "low_power_mode": "1"}
        with self.assertRaisesRegex(ValueError, "power state changed during S1"):
            runner.validate_stable_power_state("S1", before, after)

    def test_parse_prefixed_samples_rejects_foreign_output(self):
        row = {
            "operation": "generic_exit_claim",
            "sample": 0,
            "iterations": 100_000,
            "elapsed_ns": 12_000,
            "ns_per_transition": 0.12,
            "contender_admissions": 0,
        }
        parsed = runner.parse_samples(
            "noise\nCARRICK_EXEC_TERMINAL_PERF|" + json.dumps(row) + "\n"
        )
        self.assertEqual(parsed, [row])

    def test_parse_prefixed_samples_accepts_test_harness_prefix(self):
        row = {
            "operation": "generic_exit_claim",
            "sample": 0,
            "iterations": 100_000,
            "elapsed_ns": 12_000,
            "ns_per_transition": 0.12,
            "contender_admissions": 0,
        }
        parsed = runner.parse_samples(
            "test vcpu_loop::tests::clone_admission_terminal_claim_cost_receipt ... "
            "CARRICK_EXEC_TERMINAL_PERF|"
            + json.dumps(row)
            + "\n"
        )
        self.assertEqual(parsed, [row])

    def test_sample_validation_requires_each_operation_and_cardinality(self):
        rows = [
            {
                "operation": "generic_exit_claim",
                "sample": index,
                "iterations": 100_000,
                "elapsed_ns": 10_000,
                "ns_per_transition": 0.1,
                "contender_admissions": 0,
            }
            for index in range(2)
        ]
        with self.assertRaisesRegex(ValueError, "exec_error_to_terminal"):
            runner.validate_samples(rows, iterations=100_000, samples=2)

    def test_sample_validation_requires_the_exact_finite_timing_schema(self):
        def rows():
            return [
                {
                    "operation": operation,
                    "sample": 0,
                    "iterations": 100_000,
                    "elapsed_ns": 12_000,
                    "ns_per_transition": 0.12,
                    "contender_admissions": 0,
                }
                for operation in runner.OPERATIONS
            ]

        malformed_rows = []
        missing = rows()
        del missing[0]["elapsed_ns"]
        malformed_rows.append(("missing", missing))
        extra = rows()
        extra[0]["unexpected"] = "drift"
        malformed_rows.append(("schema", extra))
        boolean = rows()
        boolean[0]["sample"] = True
        malformed_rows.append(("sample", boolean))
        nan = rows()
        nan[0]["ns_per_transition"] = float("nan")
        malformed_rows.append(("timing", nan))
        infinity = rows()
        infinity[0]["ns_per_transition"] = float("inf")
        malformed_rows.append(("timing", infinity))
        negative = rows()
        negative[0]["elapsed_ns"] = -1
        malformed_rows.append(("elapsed", negative))
        zero = rows()
        zero[0]["ns_per_transition"] = 0.0
        malformed_rows.append(("timing", zero))
        mismatch = rows()
        mismatch[0]["ns_per_transition"] = 0.11
        malformed_rows.append(("does not match", mismatch))

        for expected, malformed in malformed_rows:
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                runner.validate_samples(malformed, iterations=100_000, samples=1)

    def test_performance_verdict_rejects_non_finite_or_non_positive_timings(self):
        for invalid in (float("nan"), float("inf"), -1.0, 0.0):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError, "finite and positive"
            ):
                runner.performance_verdict(
                    baseline_median=10.0,
                    baseline_p95=12.0,
                    candidate_median=invalid,
                    candidate_p95=12.0,
                    contender_admissions=0,
                )

    def test_paired_mode_rejects_refs_resolving_to_the_same_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = runner.argparse.Namespace(
                repo=pathlib.Path.cwd(),
                single=None,
                baseline="baseline",
                candidate="candidate",
                output=pathlib.Path(temporary) / "receipt.json",
                iterations=100_000,
                warmups=5,
                samples=30,
            )
            with (
                mock.patch.object(runner, "parse_args", return_value=args),
                mock.patch.object(runner, "resolve_ref", side_effect=["same", "same"]),
            ):
                self.assertEqual(runner.main([]), 2)

    def test_paired_mode_reuses_one_isolated_worktree_per_ref(self):
        baseline = "baseline"
        candidate = "candidate"
        with tempfile.TemporaryDirectory() as temporary:
            args = runner.argparse.Namespace(
                repo=pathlib.Path.cwd(),
                single=None,
                baseline=baseline,
                candidate=candidate,
                output=pathlib.Path(temporary) / "receipt.json",
                iterations=100_000,
                warmups=5,
                samples=30,
            )
            arms = []

            @contextmanager
            def fake_worktree(_repo, commit):
                yield pathlib.Path(temporary) / commit

            def fake_arm(**kwargs):
                arms.append(kwargs)
                return {"source_commit": kwargs["commit"], "rows": []}

            with (
                mock.patch.object(runner, "parse_args", return_value=args),
                mock.patch.object(runner, "resolve_ref", side_effect=[baseline, candidate]),
                mock.patch.object(runner, "temporary_worktree", fake_worktree, create=True),
                mock.patch.object(runner, "build_and_run_arm", side_effect=fake_arm),
                mock.patch.object(
                    runner,
                    "aggregate",
                    return_value={
                        operation: {
                            "median_ns_per_transition": 1.0,
                            "p95_ns_per_transition": 1.0,
                        }
                        for operation in runner.OPERATIONS
                    },
                ),
                mock.patch.object(
                    runner,
                    "performance_verdict",
                    return_value={
                        "generic_median_ratio": 1.0,
                        "generic_p95_ratio": 1.0,
                        "contender_admissions": 0,
                        "accepted": True,
                    },
                ),
                mock.patch.object(runner, "host_identity", return_value={"host": "fixture"}),
            ):
                self.assertEqual(runner.main([]), 0)

        self.assertEqual([arm["label"] for arm in arms], ["A1", "B1", "B2", "A2"])
        self.assertTrue(all(arm.get("worktree") is not None for arm in arms))
        self.assertIs(arms[0]["worktree"], arms[3]["worktree"])
        self.assertIs(arms[1]["worktree"], arms[2]["worktree"])

    def _paired_args(self, output: pathlib.Path):
        return runner.argparse.Namespace(
            repo=pathlib.Path.cwd(),
            single=None,
            baseline="baseline",
            candidate="candidate",
            output=output,
            iterations=100_000,
            warmups=5,
            samples=30,
        )

    def _run_paired_main(
        self,
        output: pathlib.Path,
        *,
        arm_failure: BaseException | None = None,
        verdict: dict | None = None,
        worktree_finalizers: list[str] | None = None,
    ) -> int:
        baseline = "baseline"
        candidate = "candidate"

        @contextmanager
        def fake_worktree(_repo, commit):
            try:
                yield output.parent / commit
            finally:
                if worktree_finalizers is not None:
                    worktree_finalizers.append(commit)

        def fake_arm(**kwargs):
            if arm_failure is not None:
                raise arm_failure
            return {"source_commit": kwargs["commit"], "rows": []}

        if verdict is None:
            verdict = {
                "generic_median_ratio": 1.0,
                "generic_p95_ratio": 1.0,
                "contender_admissions": 0,
                "accepted": True,
            }
        aggregate = {
            operation: {
                "median_ns_per_transition": 1.0,
                "p95_ns_per_transition": 1.0,
            }
            for operation in runner.OPERATIONS
        }
        with (
            mock.patch.object(runner, "parse_args", return_value=self._paired_args(output)),
            mock.patch.object(runner, "resolve_ref", side_effect=[baseline, candidate]),
            mock.patch.object(runner, "temporary_worktree", fake_worktree),
            mock.patch.object(runner, "build_and_run_arm", side_effect=fake_arm),
            mock.patch.object(runner, "aggregate", return_value=aggregate),
            mock.patch.object(runner, "performance_verdict", return_value=verdict),
            mock.patch.object(runner, "host_identity", return_value={"host": "fixture"}),
        ):
            return runner.main([])

    def _normal_exit_status(self, operation) -> int:
        try:
            return operation()
        except Exception:
            return 1

    def test_top_level_runtime_error_is_invalid_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            self.assertEqual(
                self._normal_exit_status(
                    lambda: self._run_paired_main(output, arm_failure=RuntimeError("containment failed"))
                ),
                2,
            )

    def test_top_level_grouped_body_and_cleanup_failure_is_invalid_receipt(self):
        grouped = ExceptionGroup(
            "measurement and cleanup failed",
            [RuntimeError("body failed"), RuntimeError("cleanup failed")],
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            self.assertEqual(
                self._normal_exit_status(
                    lambda: self._run_paired_main(output, arm_failure=grouped)
                ),
                2,
            )

    def test_invalid_rerun_removes_a_stale_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            output.write_text('{"stale": true}\n')
            self.assertEqual(
                self._normal_exit_status(
                    lambda: self._run_paired_main(output, arm_failure=RuntimeError("containment failed"))
                ),
                2,
            )
            self.assertFalse(output.exists())

    def test_successful_receipt_is_atomically_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            output.write_text('{"stale": true}\n')
            real_replace = os.replace
            with mock.patch.object(runner.os, "replace", wraps=real_replace) as replace:
                self.assertEqual(self._run_paired_main(output), 0)
            self.assertEqual(replace.call_count, 1)
            self.assertTrue(json.loads(output.read_text())["accepted"])

    def test_threshold_miss_returns_one_with_a_valid_receipt(self):
        verdict = {
            "generic_median_ratio": 1.06,
            "generic_p95_ratio": 1.0,
            "contender_admissions": 0,
            "accepted": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            self.assertEqual(self._run_paired_main(output, verdict=verdict), 1)
            self.assertFalse(json.loads(output.read_text())["accepted"])

    def test_top_level_preserves_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            output.write_text('{"stale": true}\n')
            interrupt = KeyboardInterrupt("stop benchmark")
            finalizers: list[str] = []
            with self.assertRaises(KeyboardInterrupt) as raised:
                self._run_paired_main(
                    output,
                    arm_failure=interrupt,
                    worktree_finalizers=finalizers,
                )
            self.assertIs(raised.exception, interrupt)
            self.assertFalse(output.exists())
            self.assertEqual(finalizers, ["candidate", "baseline"])

    def test_top_level_preserves_system_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipt.json"
            output.write_text('{"stale": true}\n')
            interrupt = SystemExit(73)
            finalizers: list[str] = []
            with self.assertRaises(SystemExit) as raised:
                self._run_paired_main(
                    output,
                    arm_failure=interrupt,
                    worktree_finalizers=finalizers,
                )
            self.assertIs(raised.exception, interrupt)
            self.assertFalse(output.exists())
            self.assertEqual(finalizers, ["candidate", "baseline"])

    def test_monitored_command_finalizes_live_group_when_keyboard_interrupts(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]
        interrupt = KeyboardInterrupt("stop benchmark")
        spawned: list[subprocess.Popen[str]] = []
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        signals: list[tuple[int, int]] = []
        verified_group_id: int | None = None

        def record_popen(*args, **kwargs):
            nonlocal verified_group_id
            child = real_popen(*args, **kwargs)
            spawned.append(child)
            self.assertIsNone(child.poll())
            self.assertEqual(os.getpgid(child.pid), child.pid)
            self.assertEqual(os.getsid(child.pid), child.pid)
            verified_group_id = child.pid
            return child

        def record_killpg(process_group_id: int, signum: int) -> None:
            signals.append((process_group_id, signum))
            real_killpg(process_group_id, signum)

        try:
            with (
                mock.patch.object(runner, "monitor_child_census", side_effect=interrupt),
                mock.patch.object(runner.subprocess, "Popen", side_effect=record_popen),
                mock.patch.object(runner.os, "killpg", side_effect=record_killpg),
                mock.patch.object(runner, "PROCESS_GROUP_GRACE_SECONDS", 0.05),
            ):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    runner.monitored_command(
                        command,
                        cwd=pathlib.Path.cwd(),
                        env=None,
                        phase="build",
                    )
            self.assertIs(raised.exception, interrupt)
            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(verified_group_id)
            self.assertIn((verified_group_id, runner.signal.SIGTERM), signals)
            self.assertTrue(all(group_id == verified_group_id for group_id, _ in signals))
            self.assertFalse(runner.process_group_exists(verified_group_id))
        finally:
            if verified_group_id is not None:
                if runner.process_group_exists(verified_group_id):
                    try:
                        real_killpg(verified_group_id, runner.signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    if not runner.wait_for_process_group_exit(
                        spawned[0], verified_group_id, 0.05
                    ):
                        try:
                            real_killpg(verified_group_id, runner.signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        self.assertTrue(
                            runner.wait_for_process_group_exit(
                                spawned[0], verified_group_id, 1.0
                            ),
                            "verified test-owned process group survived defensive SIGKILL",
                        )
                self.assertFalse(runner.process_group_exists(verified_group_id))
            elif spawned:
                # The ownership assertion itself failed; only reap the direct,
                # test-owned child and never signal an unverified group.
                child = spawned[0]
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=1.0)
                self.assertIsNotNone(child.poll())

    def test_same_ref_identity_drift_is_rejected(self):
        identities = {}
        runner.record_executable_identity(
            identities,
            "base",
            {"sha256": "a" * 64, "macho_uuid": "one"},
        )
        with self.assertRaisesRegex(ValueError, "identity changed"):
            runner.record_executable_identity(
                identities,
                "base",
                {"sha256": "b" * 64, "macho_uuid": "one"},
            )

    def test_threshold_rejects_slow_median(self):
        verdict = runner.performance_verdict(
            baseline_median=10.0,
            baseline_p95=12.0,
            candidate_median=10.6,
            candidate_p95=12.0,
            contender_admissions=0,
        )
        self.assertFalse(verdict["accepted"])

    def test_threshold_accepts_boundary(self):
        verdict = runner.performance_verdict(
            baseline_median=10.0,
            baseline_p95=12.0,
            candidate_median=10.5,
            candidate_p95=13.2,
            contender_admissions=0,
        )
        self.assertTrue(verdict["accepted"])


if __name__ == "__main__":
    unittest.main()
