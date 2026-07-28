from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


PERF_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PERF_DIR))

import native_kernel_capture  # noqa: E402


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


def metric_row(
    run_id: str,
    git_sha: str,
    binary_sha256: str,
    command: list[str],
    phase: str | None,
    kind: str | None,
    metric: dict[str, object],
    *,
    source_pc: int | None = None,
) -> dict[str, object]:
    return {
        "schema": "carrick.dsr-profile.v1",
        "profile": "native-wall",
        "run_id": run_id,
        "git_sha": git_sha,
        "git_dirty": False,
        "binary_sha256": binary_sha256,
        "command": command,
        "host": "fixture-host",
        "sampling_interval": None,
        "completion": completion(),
        "scope": {
            "phase": phase,
            "pid": None,
            "tid": None,
            "kind": kind,
            "source_pc": source_pc,
            "target_pc": None,
        },
        "metric": metric,
    }


def summary_rows(
    run_id: str,
    git_sha: str,
    binary_sha256: str,
    command: list[str],
    *,
    source_pc: int,
) -> list[dict[str, object]]:
    return [
        metric_row(
            run_id,
            git_sha,
            binary_sha256,
            command,
            "process-lifecycle",
            "create",
            {"type": "exact", "count": 2},
        ),
        metric_row(
            run_id,
            git_sha,
            binary_sha256,
            command,
            "process-lifecycle",
            "exit",
            {"type": "exact", "count": 2},
        ),
        metric_row(
            run_id,
            git_sha,
            binary_sha256,
            command,
            "process-lifecycle",
            "live-at-end",
            {"type": "exact", "count": 0},
        ),
        metric_row(
            run_id,
            git_sha,
            binary_sha256,
            command,
            "cpu-kernel-pc",
            None,
            {"type": "exact", "count": 100},
            source_pc=source_pc,
        ),
        metric_row(
            run_id,
            git_sha,
            binary_sha256,
            command,
            "cpu-kernel-stack",
            "kernel-oncpu",
            {
                "type": "stack-trace",
                "state": "kernel-oncpu",
                "count": 100,
                "frames": [
                    "kernel`fixture_leaf+0x10",
                    "kernel`fixture_parent+0x20",
                    "kernel`thread_call_run+0x30",
                    "kernel`machine_idle+0x40",
                ],
            },
        ),
        metric_row(
            run_id,
            git_sha,
            binary_sha256,
            command,
            None,
            None,
            {"type": "completion"},
        ),
    ]


class ExternalBoundary:
    HEAD = "a" * 40

    def __init__(
        self,
        binary: Path,
        *,
        trace_outcome: str = "success",
        process_listing: str | None = None,
        process_listings: tuple[str, ...] | None = None,
        docker_listing: str = "",
        transient_overlap: str | None = None,
        monitor_poll_failure: bool = False,
        initial_monitor_failure: bool = False,
        runner_children: str | None = None,
    ) -> None:
        self.binary = binary
        self.binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.trace_outcome = trace_outcome
        self.process_listing = process_listing or (
            f"{os.getpid()} 500 python3 native_kernel_capture.py\n"
            "500 1 zsh task-launcher\n"
            "1 0 /sbin/launchd\n"
        )
        self.process_listings = process_listings
        self.process_poll_count = 0
        self.docker_listing = docker_listing
        self.transient_overlap = transient_overlap
        self.monitor_poll_failure = monitor_poll_failure
        self.initial_monitor_failure = initial_monitor_failure
        self.runner_children = runner_children
        self.after_trace: object = None
        self.events: list[tuple[str, str]] = []
        self.trace_index = 0
        self.trace_active = threading.Event()
        self.active_trace_command: list[str] | None = None
        self.active_process_polls = 0
        self.active_docker_polls = 0
        self.total_process_polls = 0
        self.lock = threading.Lock()

    def popen(
        self,
        command: list[str],
        **kwargs: object,
    ) -> FakeTraceProcess:
        return FakeTraceProcess(self, command, kwargs)

    @staticmethod
    def _result(
        command: list[str],
        status: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, status, stdout, stderr)

    def __call__(self, command: list[str], **kwargs: object):
        rendered = [str(part) for part in command]
        if rendered[:3] == ["git", "status", "--porcelain"]:
            return self._result(rendered)
        if rendered[:3] == ["git", "rev-parse", "HEAD"]:
            return self._result(rendered, stdout=f"{self.HEAD}\n")
        if rendered[:2] == ["codesign", "--verify"]:
            return self._result(rendered)
        if rendered[:2] == ["otool", "-l"]:
            return self._result(rendered, stdout="sectname __dof_carrick\n")
        if rendered[:3] == ["docker", "image", "inspect"]:
            return self._result(
                rendered,
                stdout=(
                    '"arm64"\n'
                    '"sha256:fixture-image"\n'
                    '["localhost:5005/carrick-go-conformance@sha256:fixture"]\n'
                ),
            )
        if rendered[:2] == ["docker", "ps"]:
            if self.trace_active.is_set():
                with self.lock:
                    self.active_docker_polls += 1
                    active_poll = self.active_docker_polls
                if self.transient_overlap == "docker" and active_poll == 2:
                    return self._result(
                        rendered,
                        stdout=(
                            "abc transient-oracle "
                            "localhost:5005/carrick-go-conformance:1.24\n"
                        ),
                    )
            return self._result(rendered, stdout=self.docker_listing)
        if rendered[:3] == ["ps", "-eo", "pid=,ppid=,args="]:
            with self.lock:
                self.total_process_polls += 1
                total_poll = self.total_process_polls
            if self.initial_monitor_failure and total_poll == 2:
                return self._result(
                    rendered,
                    status=9,
                    stderr="fixture initial monitor failure\n",
                )
            if self.trace_active.is_set():
                with self.lock:
                    self.active_process_polls += 1
                    active_poll = self.active_process_polls
                if self.runner_children is not None:
                    assert self.active_trace_command is not None
                    guest_run_id = next(
                        token.removeprefix("CARRICK_RUN_ID=")
                        for token in self.active_trace_command
                        if token.startswith("CARRICK_RUN_ID=")
                    )
                    children = (
                        f"700 {os.getpid()} "
                        f"{shlex.join(self.active_trace_command)}\n"
                        "701 700 /usr/local/bin/carrick run "
                        f"-e CARRICK_RUN_ID={guest_run_id} fixture\n"
                    )
                    if self.runner_children == "owned-and-foreign":
                        children += (
                            f"900 {os.getpid()} "
                            "/usr/local/go/bin/go build -o foreign ./foreign.go\n"
                        )
                    if (
                        self.runner_children
                        == "owned-lineage-and-foreign"
                        and active_poll >= 2
                    ):
                        children = (
                            "700 1 /usr/bin/sudo /usr/local/bin/carrick "
                            "trace --reexec\n"
                            "701 1 /usr/local/bin/carrick run reparented\n"
                            f"900 {os.getpid()} /usr/local/go/bin/go "
                            "build -o foreign ./foreign.go\n"
                        )
                    return self._result(
                        rendered,
                        stdout=self.process_listing + children,
                    )
                if self.monitor_poll_failure and active_poll == 2:
                    return self._result(
                        rendered,
                        status=9,
                        stderr="fixture ps failure\n",
                    )
                if self.transient_overlap == "foreign" and active_poll == 2:
                    return self._result(
                        rendered,
                        stdout=(
                            self.process_listing
                            + "900 1 /usr/local/bin/carrick run transient\n"
                        ),
                    )
            if self.process_listings is not None:
                with self.lock:
                    index = min(
                        self.process_poll_count,
                        len(self.process_listings) - 1,
                    )
                    self.process_poll_count += 1
                listing = self.process_listings[index]
            else:
                listing = self.process_listing
            return self._result(rendered, stdout=listing)
        if len(rendered) > 2 and rendered[1:3] == ["trace", "--profile"]:
            environment = kwargs["env"]
            assert isinstance(environment, dict)
            host_run_id = environment["CARRICK_RUN_ID"]
            self.events.append(("trace", host_run_id))
            self.trace_index += 1
            raw_path = Path(rendered[rendered.index("--trace-out") + 1])
            summary_path = Path(rendered[rendered.index("--summary-jsonl") + 1])
            target = rendered[rendered.index("--") + 1 :]
            self.active_trace_command = rendered
            self.trace_active.set()
            if (
                self.transient_overlap is not None
                or self.monitor_poll_failure
                or self.runner_children is not None
            ):
                time.sleep(0.08)
            if self.trace_outcome == "timeout":
                self.trace_active.clear()
                raise subprocess.TimeoutExpired(
                    rendered,
                    kwargs["timeout"],
                    output="partial stdout\n",
                    stderr="partial stderr\n",
                )
            if self.trace_outcome == "exception":
                self.trace_active.clear()
                raise OSError("fixture launch failed")
            raw_path.write_text(f"raw trace {host_run_id}\n")
            rows = summary_rows(
                host_run_id,
                self.HEAD,
                self.binary_sha256,
                target,
                source_pc=0xFFFFFE0000000000 + self.trace_index,
            )
            summary_path.write_text(
                "".join(
                    json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                    for row in rows
                )
            )
            status = 7 if self.trace_outcome == "nonzero" else 0
            self.trace_active.clear()
            return self._result(
                rendered,
                status=status,
                stdout="BUILD_OK\n",
                stderr="trace diagnostic\n",
            )
        if rendered and rendered[0].endswith("scripts/sudo/kill.sh"):
            run_id = rendered[1]
            self.events.append(("cleanup", run_id))
            return self._result(
                rendered,
                stdout=f"cleaned {run_id}\n",
                stderr="cleanup diagnostic\n",
            )
        raise AssertionError(f"unexpected external command: {rendered!r}")


class FakeTraceProcess:
    def __init__(
        self,
        boundary: ExternalBoundary,
        command: list[str],
        kwargs: dict[str, object],
    ) -> None:
        self.boundary = boundary
        self.args = [str(part) for part in command]
        self.pid = 700
        self.returncode: int | None = None
        self._completed = False
        self._killed = False
        self._timeout_raised = False
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        self.host_run_id = environment["CARRICK_RUN_ID"]
        boundary.events.append(("trace", self.host_run_id))
        boundary.trace_index += 1
        self.raw_path = Path(
            self.args[self.args.index("--trace-out") + 1]
        )
        self.summary_path = Path(
            self.args[self.args.index("--summary-jsonl") + 1]
        )
        self.target = self.args[self.args.index("--") + 1 :]
        boundary.active_trace_command = self.args
        if boundary.trace_outcome == "exception":
            raise OSError("fixture launch failed")
        boundary.trace_active.set()

    def communicate(
        self,
        input: object = None,
        timeout: int | None = None,
    ) -> tuple[str, str]:
        del input
        if (
            self.boundary.trace_outcome == "timeout"
            and not self._timeout_raised
            and not self._killed
        ):
            self._timeout_raised = True
            raise subprocess.TimeoutExpired(
                self.args,
                timeout,
                output="partial stdout\n",
                stderr="partial stderr\n",
            )
        if not self._completed and not self._killed:
            if (
                self.boundary.transient_overlap is not None
                or self.boundary.monitor_poll_failure
                or self.boundary.runner_children is not None
            ):
                time.sleep(0.08)
            self.raw_path.write_text(f"raw trace {self.host_run_id}\n")
            rows = summary_rows(
                self.host_run_id,
                self.boundary.HEAD,
                self.boundary.binary_sha256,
                self.target,
                source_pc=(
                    0xFFFFFE0000000000 + self.boundary.trace_index
                ),
            )
            self.summary_path.write_text(
                "".join(
                    json.dumps(
                        row,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                    for row in rows
                )
            )
            self.returncode = (
                7 if self.boundary.trace_outcome == "nonzero" else 0
            )
            self._completed = True
            self.boundary.trace_active.clear()
            if callable(self.boundary.after_trace):
                self.boundary.after_trace()
        if self._killed:
            return ("", "")
        return ("BUILD_OK\n", "trace diagnostic\n")

    def kill(self) -> None:
        self._killed = True
        self.returncode = -9
        self.boundary.trace_active.clear()

    terminate = kill

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = -9 if self._killed else 0
        return self.returncode


class NativeKernelCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "scripts/sudo").mkdir(parents=True)
        self.binary = self.repo / "target/release/carrick"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"signed fixture carrick")
        self.artifacts = self.root / "artifacts"
        self.config = native_kernel_capture.CaptureConfig(
            repo=self.repo,
            binary=self.binary,
            artifact_dir=self.artifacts,
            run_id="kernel-fixture",
            image="localhost:5005/carrick-go-conformance:1.24",
            timeout_seconds=30,
        )
        self.popen_patch = mock.patch.object(
            native_kernel_capture.subprocess,
            "Popen",
            side_effect=self.dispatch_popen,
        )
        self.popen_patch.start()
        self.addCleanup(self.popen_patch.stop)

    @staticmethod
    def dispatch_popen(
        command: list[str],
        **kwargs: object,
    ) -> FakeTraceProcess:
        run_side_effect = getattr(
            native_kernel_capture.subprocess.run,
            "side_effect",
            None,
        )
        boundary = getattr(
            run_side_effect,
            "external_boundary",
            run_side_effect,
        )
        if not isinstance(boundary, ExternalBoundary):
            raise AssertionError("trace Popen lacks an ExternalBoundary")
        return boundary.popen(command, **kwargs)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_evidence_error_is_a_runtime_error(self) -> None:
        self.assertTrue(issubclass(native_kernel_capture.EvidenceError, RuntimeError))

    def test_config_rejects_nonpositive_timeout_with_exact_error_type(self) -> None:
        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "timeout must be positive",
        ):
            native_kernel_capture.CaptureConfig(
                repo=self.repo,
                binary=self.binary,
                artifact_dir=self.artifacts,
                run_id="kernel-fixture",
                image="fixture",
                timeout_seconds=0,
            )

    def test_environment_determinant_hash_binds_the_effective_environment(
        self,
    ) -> None:
        with mock.patch.dict(os.environ, {"PATH": "/first"}, clear=True):
            _, first = native_kernel_capture._controlled_environment(
                "kernel-fixture-a-host"
            )
        with mock.patch.dict(os.environ, {"PATH": "/second"}, clear=True):
            _, second = native_kernel_capture._controlled_environment(
                "kernel-fixture-b-host"
            )

        self.assertNotEqual(
            first["effective_environment_sha256"],
            second["effective_environment_sha256"],
        )
        self.assertNotIn("/first", json.dumps(first))
        self.assertNotIn("/second", json.dumps(second))

    def test_cli_surface_has_capture_and_exactly_two_receipt_analyze(self) -> None:
        capture = native_kernel_capture.parse_args(
            [
                "capture",
                "--repo",
                str(self.repo),
                "--binary",
                str(self.binary),
                "--artifact-dir",
                str(self.artifacts),
                "--run-id",
                "kernel-fixture",
                "--image",
                "fixture",
                "--timeout",
                "5",
            ]
        )
        analyze = native_kernel_capture.parse_args(
            [
                "analyze",
                "--receipt",
                "a.receipt.json",
                "--receipt",
                "b.receipt.json",
                "--output",
                "analysis.json",
            ]
        )

        self.assertEqual(capture.command, "capture")
        self.assertEqual(capture.timeout, 5)
        self.assertEqual(
            analyze.receipt,
            [Path("a.receipt.json"), Path("b.receipt.json")],
        )

        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            native_kernel_capture.parse_args(
                [
                    "analyze",
                    "--receipt",
                    "a.receipt.json",
                    "--output",
                    "analysis.json",
                ]
            )

    def test_layout_preflight_rejects_every_existing_derived_path_unchanged(
        self,
    ) -> None:
        planned = native_kernel_capture.planned_paths(self.artifacts)
        for label, path in planned.all_outputs().items():
            with self.subTest(label=label):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                self.artifacts.mkdir()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"sentinel-{label}".encode())
                before = path.read_bytes()
                boundary = mock.Mock()

                with (
                    mock.patch.object(
                        native_kernel_capture.subprocess,
                        "run",
                        boundary,
                    ),
                    self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        "planned output already exists",
                    ),
                ):
                    native_kernel_capture.capture_pair(self.config)

                self.assertEqual(path.read_bytes(), before)
                boundary.assert_not_called()

    def test_dangling_a_b_and_analysis_entries_are_never_followed_or_mutated(
        self,
    ) -> None:
        planned = native_kernel_capture.planned_paths(self.artifacts)
        collisions = {
            "a": planned.runs["a"]["summary_jsonl"],
            "b": planned.runs["b"]["summary_jsonl"],
            "analysis": planned.analysis,
        }
        for label, path in collisions.items():
            with self.subTest(label=label):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                self.artifacts.mkdir()
                os.symlink(f"missing-{label}", path)
                before = (os.lstat(path), os.readlink(path))
                boundary = mock.Mock()

                with (
                    mock.patch.object(
                        native_kernel_capture.subprocess,
                        "run",
                        boundary,
                    ),
                    self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        "planned output already exists",
                    ),
                ):
                    native_kernel_capture.capture_pair(self.config)

                after = (os.lstat(path), os.readlink(path))
                self.assertEqual(after[0].st_ino, before[0].st_ino)
                self.assertEqual(after[0].st_mode, before[0].st_mode)
                self.assertEqual(after[1], before[1])
                boundary.assert_not_called()

    def test_one_snapshot_resolves_real_ancestry_and_keeps_named_peer_foreign(
        self,
    ) -> None:
        listing = (
            "100 50 python3 scripts/perf/native_kernel_capture.py capture\n"
            "50 1 python3 scripts/perf/native_go_build.py launcher\n"
            "1 0 /sbin/launchd\n"
            "400 1 python3 scripts/perf/native_go_build.py independent\n"
            "401 1 target/release/carrick trace --profile native-wall\n"
            "402 1 /usr/local/go/bin/go build -o h ./h.go\n"
            "403 1 /usr/local/bin/carrick run fixture\n"
            "404 1 /usr/sbin/dtrace -s scripts/dtrace/native-wall.d\n"
        )

        snapshot = native_kernel_capture.classify_process_snapshot(
            listing,
            self_pid=100,
        )

        self.assertEqual(
            snapshot["launcher_ancestry"],
            [
                {
                    "depth": 0,
                    "executable": "python3",
                    "script": "native_kernel_capture.py",
                },
                {
                    "depth": 1,
                    "executable": "python3",
                    "script": "native_go_build.py",
                },
                {
                    "depth": 2,
                    "executable": "launchd",
                    "script": None,
                },
            ],
        )
        self.assertEqual(
            [row["pid"] for row in snapshot["foreign_workloads"]],
            [400, 401, 402, 403, 404],
        )

    def test_monitor_allows_owned_trace_tree_but_rejects_unrelated_runner_child(
        self,
    ) -> None:
        owned = ExternalBoundary(
            self.binary,
            runner_children="owned",
        )
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=owned,
        ):
            native_kernel_capture.capture_pair(self.config)

        shutil.rmtree(self.artifacts)
        mixed = ExternalBoundary(
            self.binary,
            runner_children="owned-and-foreign",
        )
        caught: Exception | None = None
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=mixed,
        ):
            try:
                native_kernel_capture.capture_pair(self.config)
            except Exception as error:
                caught = error

        self.assertIs(type(caught), native_kernel_capture.EvidenceError)
        self.assertIn("contamination monitor observed overlap", str(caught))
        receipt = native_kernel_capture.planned_paths(
            self.artifacts
        ).runs["a"]["receipt"]
        payload = json.loads(receipt.read_text())
        self.assertTrue(payload["monitor"]["contaminated"])
        self.assertEqual(
            {
                category
                for sample in payload["monitor"]["samples"]
                for category in sample["foreign_workload_categories"]
            },
            {"go-build"},
        )

    def test_owned_pid_lineage_survives_reexec_and_reparenting(self) -> None:
        boundary = ExternalBoundary(
            self.binary,
            runner_children="owned-lineage-and-foreign",
        )
        caught: Exception | None = None
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=boundary,
        ):
            try:
                native_kernel_capture.capture_pair(self.config)
            except Exception as error:
                caught = error

        self.assertIs(type(caught), native_kernel_capture.EvidenceError)
        self.assertIn("contamination monitor observed overlap", str(caught))
        receipt = native_kernel_capture.planned_paths(
            self.artifacts
        ).runs["a"]["receipt"]
        payload = json.loads(receipt.read_text())
        categories = {
            category
            for sample in payload["monitor"]["samples"]
            for category in sample["foreign_workload_categories"]
        }
        self.assertEqual(categories, {"go-build"})

    def test_go_build_classification_tokenizes_basenames_without_shell_eval(
        self,
    ) -> None:
        cases = (
            ("bare script", "native_go_build.py capture", True),
            (
                "absolute script",
                "/opt/perf/native_go_build.py capture",
                True,
            ),
            (
                "interpreter script",
                "/usr/bin/python3 /repo/scripts/perf/native_go_build.py",
                True,
            ),
            (
                "module",
                "python3 -m scripts.perf.native_go_build capture",
                True,
            ),
            ("bare go", "go build -o h ./h.go", True),
            (
                "absolute go",
                "/usr/local/go/bin/go build -o h ./h.go",
                True,
            ),
            ("echo near miss", "echo native_go_build.py", False),
            (
                "module near miss",
                "python3 -m scripts.perf.native_go_builder capture",
                False,
            ),
            (
                "suffix near miss",
                "/opt/perf/native_go_build.py.backup capture",
                False,
            ),
            (
                "python argument near miss",
                "python3 -c 'print(1)' native_go_build.py",
                False,
            ),
            ("go near miss", "gofmt build ./...", False),
        )
        for label, command, expected in cases:
            with self.subTest(label=label):
                self.assertIs(
                    native_kernel_capture._looks_like_foreign_workload(command),
                    expected,
                )

    def test_broken_or_cyclic_launcher_ancestry_rejects(self) -> None:
        for label, listing, fragment in (
            (
                "broken",
                "100 50 python native_kernel_capture.py\n",
                "broken launcher ancestry",
            ),
            (
                "cyclic",
                (
                    "100 50 python native_kernel_capture.py\n"
                    "50 100 python launcher.py\n"
                ),
                "cyclic launcher ancestry",
            ),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                native_kernel_capture.EvidenceError,
                fragment,
            ):
                native_kernel_capture.classify_process_snapshot(
                    listing,
                    self_pid=100,
                )

    def test_receipts_redact_volatile_ancestry_pids_paths_and_arguments(
        self,
    ) -> None:
        secret = "secret-like-value-must-not-persist"
        listings = (
            (
                f"{os.getpid()} 500 python3 native_kernel_capture.py "
                f"--run-id first --token {secret}\n"
                "500 1 zsh /private/tmp/first-artifact\n"
                "1 0 /sbin/launchd\n"
            ),
            (
                f"{os.getpid()} 600 python3 native_kernel_capture.py "
                "--run-id second --token another-secret\n"
                "600 1 zsh /private/tmp/second-artifact\n"
                "1 0 /sbin/launchd\n"
            ),
        )
        boundary = ExternalBoundary(
            self.binary,
            process_listings=listings,
        )
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=boundary,
        ):
            native_kernel_capture.capture_pair(self.config)

        receipt = native_kernel_capture.planned_paths(
            self.artifacts
        ).runs["a"]["receipt"]
        payload = json.loads(receipt.read_text())
        serialized = receipt.read_text()
        self.assertNotIn(secret, serialized)
        self.assertNotIn("another-secret", serialized)
        self.assertNotIn("/private/tmp", serialized)
        self.assertNotIn('"pid"', serialized)
        self.assertEqual(
            payload["provenance"]["pre"]["launcher_ancestry"],
            payload["provenance"]["post"]["launcher_ancestry"],
        )

    def test_foreign_workload_and_real_docker_oracle_reject_before_capture(
        self,
    ) -> None:
        cases = (
            (
                "process",
                (
                    f"{os.getpid()} 500 python native_kernel_capture.py\n"
                    "500 1 zsh launcher\n"
                    "1 0 /sbin/launchd\n"
                    "900 1 target/release/carrick trace --profile native-wall\n"
                ),
                "",
                "foreign workload census",
            ),
            (
                "docker",
                None,
                (
                    "abc native-go-build-oracle "
                    "localhost:5005/carrick-go-conformance:1.24\n"
                ),
                "Docker oracle census",
            ),
        )
        for label, process_listing, docker_listing, fragment in cases:
            with self.subTest(label=label):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                boundary = ExternalBoundary(
                    self.binary,
                    process_listing=process_listing,
                    docker_listing=docker_listing,
                )
                with (
                    mock.patch.object(
                        native_kernel_capture.subprocess,
                        "run",
                        side_effect=boundary,
                    ),
                    self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        fragment,
                    ),
                ):
                    native_kernel_capture.capture_pair(self.config)

                self.assertFalse(self.artifacts.exists())
                self.assertFalse(any(event[0] == "trace" for event in boundary.events))

    def capture_success(
        self,
    ) -> tuple[ExternalBoundary, Path, Path, Path]:
        boundary = ExternalBoundary(self.binary)
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=boundary,
        ):
            analysis = native_kernel_capture.capture_pair(self.config)
        planned = native_kernel_capture.planned_paths(self.artifacts)
        return (
            boundary,
            planned.runs["a"]["receipt"],
            planned.runs["b"]["receipt"],
            analysis,
        )

    def test_pair_rejects_receipts_from_different_capture_roots(self) -> None:
        _, receipt_a, _, _ = self.capture_success()
        other_artifacts = self.root / "other-artifacts"
        other_config = native_kernel_capture.CaptureConfig(
            repo=self.repo,
            binary=self.binary,
            artifact_dir=other_artifacts,
            run_id="kernel-fixture",
            image=self.config.image,
            timeout_seconds=self.config.timeout_seconds,
        )
        boundary = ExternalBoundary(self.binary)
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=boundary,
        ):
            native_kernel_capture.capture_pair(other_config)
        receipt_b = native_kernel_capture.planned_paths(
            other_artifacts
        ).runs["b"]["receipt"]

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "receipt determinant changed: capture root",
        ):
            native_kernel_capture.compare_receipts((receipt_a, receipt_b))

    def test_pair_rejects_changed_capture_identifier_and_run_derivation(
        self,
    ) -> None:
        _, receipt_a, receipt_b, _ = self.capture_success()
        originals = {
            receipt_a: receipt_a.read_bytes(),
            receipt_b: receipt_b.read_bytes(),
        }

        payload_a = json.loads(originals[receipt_a])
        payload_b = json.loads(originals[receipt_b])
        payload_a["capture_id"] = "first-base"
        payload_b["capture_id"] = "second-base"
        receipt_a.write_text(json.dumps(payload_a))
        receipt_b.write_text(json.dumps(payload_b))
        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "receipt determinant changed: capture identifier",
        ):
            native_kernel_capture.compare_receipts((receipt_a, receipt_b))

        for path, raw in originals.items():
            path.write_bytes(raw)
        payload_b = json.loads(originals[receipt_b])
        payload_b["host_run_id"] = "wrong-b-host"
        receipt_b.write_text(json.dumps(payload_b))
        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "receipt run IDs do not use exact capture derivation",
        ):
            native_kernel_capture.validate_receipt(receipt_b)

    def test_continuous_monitor_rejects_transient_overlap(self) -> None:
        for overlap in ("foreign", "docker"):
            with self.subTest(overlap=overlap):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                boundary = ExternalBoundary(
                    self.binary,
                    transient_overlap=overlap,
                )
                with (
                    mock.patch.object(
                        native_kernel_capture.subprocess,
                        "run",
                        side_effect=boundary,
                    ),
                    self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        "contamination monitor observed overlap",
                    ),
                ):
                    native_kernel_capture.capture_pair(self.config)

                receipt = native_kernel_capture.planned_paths(
                    self.artifacts
                ).runs["a"]["receipt"]
                payload = json.loads(receipt.read_text())
                self.assertEqual(payload["outcome"], "rejected")
                self.assertTrue(payload["monitor"]["contaminated"])
                self.assertGreaterEqual(payload["monitor"]["sample_count"], 2)
                serialized = receipt.read_text()
                self.assertNotIn("transient-oracle", serialized)
                self.assertNotIn("carrick run transient", serialized)

    def test_contamination_monitor_poll_failure_is_receipt_bound(self) -> None:
        boundary = ExternalBoundary(
            self.binary,
            monitor_poll_failure=True,
        )
        with (
            mock.patch.object(
                native_kernel_capture.subprocess,
                "run",
                side_effect=boundary,
            ),
            self.assertRaisesRegex(
                native_kernel_capture.EvidenceError,
                "contamination monitor poll failed",
            ),
        ):
            native_kernel_capture.capture_pair(self.config)

        planned = native_kernel_capture.planned_paths(self.artifacts)
        payload = json.loads(planned.runs["a"]["receipt"].read_text())
        self.assertEqual(payload["outcome"], "rejected")
        self.assertIsNotNone(payload["monitor"]["poll_error"])
        self.assertTrue(payload["monitor"]["stopped"])
        self.assertFalse(planned.analysis.exists())

    def test_initial_monitor_failure_rejects_without_command_result(self) -> None:
        boundary = ExternalBoundary(
            self.binary,
            initial_monitor_failure=True,
        )
        caught: Exception | None = None
        with mock.patch.object(
            native_kernel_capture.subprocess,
            "run",
            side_effect=boundary,
        ):
            try:
                native_kernel_capture.capture_pair(self.config)
            except Exception as error:
                caught = error

        self.assertIs(type(caught), native_kernel_capture.EvidenceError)
        self.assertIn("contamination monitor poll failed", str(caught))
        self.assertEqual(
            boundary.events,
            [("cleanup", "kernel-fixture-a-host")],
        )
        planned = native_kernel_capture.planned_paths(self.artifacts)
        payload = json.loads(planned.runs["a"]["receipt"].read_text())
        self.assertEqual(payload["outcome"], "rejected")
        self.assertIsNone(payload["command"]["status"])
        self.assertEqual(
            payload["monitor"]["poll_error"],
            "monitor poll failed",
        )
        self.assertFalse(planned.analysis.exists())

    def test_fast_trace_binds_launch_and_post_cleanup_monitor_boundaries(
        self,
    ) -> None:
        _, receipt_a, _, _ = self.capture_success()
        monitor = json.loads(receipt_a.read_text())["monitor"]
        phases = [sample.get("phase") for sample in monitor["samples"]]

        self.assertEqual(phases.count("launch-boundary"), 1)
        self.assertEqual(phases.count("post-cleanup-boundary"), 1)
        self.assertLess(
            phases.index("launch-boundary"),
            phases.index("post-cleanup-boundary"),
        )
        launch_index = phases.index("launch-boundary")
        cleanup_index = phases.index("post-cleanup-boundary")
        self.assertTrue(
            any(
                phase == "interval"
                for phase in phases[launch_index + 1 : cleanup_index]
            )
        )

    def test_receipt_rejects_missing_or_reordered_execution_interval(
        self,
    ) -> None:
        _, receipt_a, _, _ = self.capture_success()
        original = receipt_a.read_bytes()
        for mutation in ("remove", "before-launch", "after-cleanup"):
            with self.subTest(mutation=mutation):
                payload = json.loads(original)
                samples = payload["monitor"]["samples"]
                launch_index = next(
                    index
                    for index, sample in enumerate(samples)
                    if sample.get("phase") == "launch-boundary"
                )
                cleanup_index = next(
                    index
                    for index, sample in enumerate(samples)
                    if sample.get("phase") == "post-cleanup-boundary"
                )
                execution_indices = [
                    index
                    for index in range(launch_index + 1, cleanup_index)
                    if samples[index].get("phase") == "interval"
                ]
                chosen_indices = (
                    execution_indices
                    if execution_indices
                    else [
                        next(
                            index
                            for index, sample in enumerate(samples)
                            if sample.get("phase") == "interval"
                        )
                    ]
                )
                chosen = [
                    samples[index] for index in chosen_indices
                ]
                for index in reversed(chosen_indices):
                    samples.pop(index)
                if mutation == "before-launch":
                    samples[0:0] = chosen
                elif mutation == "after-cleanup":
                    samples.extend(chosen)
                for sequence, sample in enumerate(samples, 1):
                    sample["sequence"] = sequence
                payload["monitor"]["sample_count"] = len(samples)
                receipt_a.write_text(json.dumps(payload))

                with self.assertRaisesRegex(
                    native_kernel_capture.EvidenceError,
                    "receipt monitor lacks execution interval sample",
                ):
                    native_kernel_capture.validate_receipt(receipt_a)
                receipt_a.write_bytes(original)

    def test_receipt_rejects_missing_monitor_boundary_phase(self) -> None:
        _, receipt_a, _, _ = self.capture_success()
        original = receipt_a.read_bytes()
        for phase, fragment in (
            ("launch-boundary", "receipt monitor lacks launch boundary"),
            (
                "post-cleanup-boundary",
                "receipt monitor lacks post-cleanup boundary",
            ),
        ):
            with self.subTest(phase=phase):
                payload = json.loads(original)
                payload["monitor"]["samples"] = [
                    sample
                    for sample in payload["monitor"]["samples"]
                    if sample.get("phase") != phase
                ]
                for sequence, sample in enumerate(
                    payload["monitor"]["samples"],
                    1,
                ):
                    sample["sequence"] = sequence
                payload["monitor"]["sample_count"] = len(
                    payload["monitor"]["samples"]
                )
                receipt_a.write_text(json.dumps(payload))
                with self.assertRaisesRegex(
                    native_kernel_capture.EvidenceError,
                    fragment,
                ):
                    native_kernel_capture.validate_receipt(receipt_a)
                receipt_a.write_bytes(original)

    def test_success_captures_serial_bound_receipts_then_atomic_analysis(
        self,
    ) -> None:
        boundary, receipt_a, receipt_b, analysis = self.capture_success()

        self.assertEqual(
            [event[0] for event in boundary.events],
            ["trace", "cleanup", "trace", "cleanup"],
        )
        self.assertEqual(
            boundary.events,
            [
                ("trace", "kernel-fixture-a-host"),
                ("cleanup", "kernel-fixture-a-host"),
                ("trace", "kernel-fixture-b-host"),
                ("cleanup", "kernel-fixture-b-host"),
            ],
        )
        self.assertTrue(receipt_a.is_file())
        self.assertTrue(receipt_b.is_file())
        document = json.loads(analysis.read_text())
        self.assertEqual(document["schema"], "carrick.native-kernel-attribution.v1")
        self.assertEqual(document["result"], "selectable")
        self.assertEqual(len(document["receipt_sources"]), 2)
        self.assertEqual(list(self.artifacts.glob(f".{analysis.name}.*.tmp")), [])

        payload = json.loads(receipt_a.read_text())
        self.assertEqual(payload["schema"], "carrick.native-kernel-capture.v2")
        self.assertEqual(payload["outcome"], "accepted")
        self.assertEqual(payload["capture_id"], "kernel-fixture")
        self.assertEqual(payload["capture_root"], str(self.artifacts))
        self.assertEqual(payload["host_run_id"], "kernel-fixture-a-host")
        self.assertEqual(payload["guest_run_id"], "kernel-fixture-a-guest")
        self.assertEqual(payload["command"]["status"], 0)
        self.assertFalse(payload["command"]["timed_out"])
        self.assertEqual(payload["command"]["build_ok_count"], 1)
        self.assertEqual(
            payload["descendant_census"],
            {"create": 2, "exit": 2, "live-at-end": 0},
        )
        self.assertEqual(
            payload["reconciliation"],
            {
                "completion_rows": 1,
                "kernel_pc_count": 100,
                "kernel_stack_count": 100,
            },
        )
        self.assertEqual(payload["provenance"]["pre"], payload["provenance"]["post"])
        self.assertTrue(payload["monitor"]["started"])
        self.assertTrue(payload["monitor"]["stopped"])
        self.assertFalse(payload["monitor"]["contaminated"])
        self.assertIsNone(payload["monitor"]["poll_error"])
        self.assertGreaterEqual(payload["monitor"]["sample_count"], 1)
        self.assertEqual(
            payload["monitor"]["sample_count"],
            len(payload["monitor"]["samples"]),
        )
        self.assertEqual(
            payload["cleanup"]["argv"][-1],
            payload["host_run_id"],
        )

        expected_artifacts = {
            "raw_trace",
            "summary_jsonl",
            "command_stdout",
            "command_stderr",
            "command_status",
            "cleanup_stdout",
            "cleanup_stderr",
        }
        self.assertEqual(set(payload["artifacts"]), expected_artifacts)
        for binding in payload["artifacts"].values():
            path = Path(binding["path"])
            self.assertTrue(path.is_absolute())
            self.assertEqual(binding["size"], path.stat().st_size)
            self.assertEqual(
                binding["sha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        self.assertEqual(
            payload["cleanup"]["stdout_sha256"],
            payload["artifacts"]["cleanup_stdout"]["sha256"],
        )
        self.assertEqual(
            payload["cleanup"]["stderr_sha256"],
            payload["artifacts"]["cleanup_stderr"]["sha256"],
        )

    def test_cleanup_runs_in_finally_for_every_command_outcome(self) -> None:
        for outcome, fragment in (
            ("nonzero", "trace command failed"),
            ("timeout", "trace command timed out"),
            ("exception", "trace command raised"),
        ):
            with self.subTest(outcome=outcome):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                boundary = ExternalBoundary(
                    self.binary,
                    trace_outcome=outcome,
                )
                with (
                    mock.patch.object(
                        native_kernel_capture.subprocess,
                        "run",
                        side_effect=boundary,
                    ),
                    self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        fragment,
                    ),
                ):
                    native_kernel_capture.capture_pair(self.config)

                self.assertEqual(
                    boundary.events,
                    [
                        ("trace", "kernel-fixture-a-host"),
                        ("cleanup", "kernel-fixture-a-host"),
                    ],
                )
                planned = native_kernel_capture.planned_paths(self.artifacts)
                receipt = planned.runs["a"]["receipt"]
                self.assertTrue(receipt.is_file())
                self.assertFalse(planned.runs["b"]["receipt"].exists())
                self.assertFalse(planned.analysis.exists())
                rejection = json.loads(receipt.read_text())
                self.assertEqual(rejection["outcome"], "rejected")
                self.assertEqual(
                    rejection["cleanup"]["argv"][-1],
                    "kernel-fixture-a-host",
                )

    def test_environment_drift_during_a_marks_its_receipt_rejected(self) -> None:
        boundary = ExternalBoundary(self.binary)

        def mutating_boundary(command: list[str], **kwargs: object):
            result = boundary(command, **kwargs)
            rendered = [str(part) for part in command]
            if len(rendered) > 2 and rendered[1:3] == ["trace", "--profile"]:
                os.environ["NATIVE_KERNEL_CAPTURE_DRIFT"] = "changed"
            return result

        mutating_boundary.external_boundary = boundary
        boundary.after_trace = lambda: os.environ.__setitem__(
            "NATIVE_KERNEL_CAPTURE_DRIFT",
            "changed",
        )

        with (
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch.object(
                native_kernel_capture.subprocess,
                "run",
                side_effect=mutating_boundary,
            ),
            self.assertRaisesRegex(
                native_kernel_capture.EvidenceError,
                "controlled environment changed during capture",
            ),
        ):
            native_kernel_capture.capture_pair(self.config)

        receipt = native_kernel_capture.planned_paths(
            self.artifacts
        ).runs["a"]["receipt"]
        self.assertEqual(json.loads(receipt.read_text())["outcome"], "rejected")

    def test_preflight_and_untrusted_provenance_have_no_conditional_receipt(
        self,
    ) -> None:
        self.artifacts.mkdir()
        planned = native_kernel_capture.planned_paths(self.artifacts)
        planned.analysis.write_text("sentinel")
        with self.assertRaises(native_kernel_capture.EvidenceError):
            native_kernel_capture.capture_pair(self.config)
        self.assertFalse(planned.runs["a"]["receipt"].exists())

        shutil.rmtree(self.artifacts)
        boundary = ExternalBoundary(
            self.binary,
            process_listing=(
                f"{os.getpid()} 500 python native_kernel_capture.py\n"
                "500 1 zsh launcher\n"
                "1 0 /sbin/launchd\n"
                "900 1 target/release/carrick run fixture\n"
            ),
        )
        with (
            mock.patch.object(
                native_kernel_capture.subprocess,
                "run",
                side_effect=boundary,
            ),
            self.assertRaises(native_kernel_capture.EvidenceError),
        ):
            native_kernel_capture.capture_pair(self.config)
        self.assertFalse(self.artifacts.exists())

    def test_receipt_validation_rejects_artifact_and_acceptance_corruption(
        self,
    ) -> None:
        _, receipt_a, _, _ = self.capture_success()
        original_receipt = receipt_a.read_bytes()
        payload = json.loads(original_receipt)
        stdout = Path(payload["artifacts"]["command_stdout"]["path"])
        original_stdout = stdout.read_bytes()
        stdout.write_text("BUILD_OK\nBUILD_OK\n")

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "artifact command_stdout",
        ):
            native_kernel_capture.validate_receipt(receipt_a)

        receipt_a.write_bytes(original_receipt)
        stdout.write_bytes(original_stdout)
        payload = json.loads(original_receipt)
        payload["command"]["build_ok_count"] = 2
        receipt_a.write_text(json.dumps(payload))
        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "exactly one BUILD_OK",
        ):
            native_kernel_capture.validate_receipt(receipt_a)

    def test_malformed_status_artifact_is_a_typed_evidence_rejection(
        self,
    ) -> None:
        _, receipt_a, _, _ = self.capture_success()
        payload = json.loads(receipt_a.read_text())
        status = Path(payload["artifacts"]["command_status"]["path"])
        status.write_bytes(b"{not-json")
        self.rebind_artifact(receipt_a, payload, "command_status")

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "command status artifact is invalid JSON",
        ):
            native_kernel_capture.validate_receipt(receipt_a)

    def test_cleanup_argv_must_name_the_fixed_exact_run_id_helper(self) -> None:
        _, receipt_a, _, _ = self.capture_success()
        payload = json.loads(receipt_a.read_text())
        payload["cleanup"]["argv"][0] = "/tmp/not-the-cleanup-helper"
        payload["cleanup"]["argv_sha256"] = hashlib.sha256(
            json.dumps(
                payload["cleanup"]["argv"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        receipt_a.write_text(json.dumps(payload))

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "cleanup argv does not name the fixed helper and exact run ID",
        ):
            native_kernel_capture.validate_receipt(receipt_a)

    def test_comparison_rejects_every_binding_determinant(self) -> None:
        _, receipt_a, receipt_b, _ = self.capture_success()
        original = receipt_b.read_bytes()
        mutations = {
            "ancestry": lambda payload: [
                payload["provenance"][when].__setitem__(
                    "launcher_ancestry",
                    [
                        {
                            **payload["provenance"][when][
                                "launcher_ancestry"
                            ][0],
                            "executable": "different-python",
                        },
                        *payload["provenance"][when][
                            "launcher_ancestry"
                        ][1:],
                    ],
                )
                for when in ("pre", "post")
            ],
            "HEAD": lambda payload: [
                payload["provenance"][when].__setitem__("head", "f" * 40)
                for when in ("pre", "post")
            ],
            "binary": lambda payload: [
                payload["provenance"][when]["binary"].__setitem__(
                    "sha256",
                    "e" * 64,
                )
                for when in ("pre", "post")
            ],
            "image": lambda payload: [
                payload["provenance"][when]["image"].__setitem__(
                    "id",
                    "sha256:different",
                )
                for when in ("pre", "post")
            ],
            "invocation": lambda payload: payload["determinants"][
                "invocation"
            ].__setitem__("profile", "wrong-profile"),
            "environment": lambda payload: payload["determinants"][
                "environment"
            ].__setitem__("CARRICK_DSR_PROFILE", "foreign"),
            "timeout": lambda payload: payload["determinants"][
                "timeout_policy"
            ].__setitem__("seconds", 31),
            "producer": lambda payload: payload["determinants"].__setitem__(
                "producer_sha256",
                "d" * 64,
            ),
            "acceptance": lambda payload: payload["determinants"].__setitem__(
                "acceptance_sha256",
                "c" * 64,
            ),
            "host": lambda payload: [
                payload["provenance"][when]["host"].__setitem__(
                    "nodename",
                    "different-host",
                )
                for when in ("pre", "post")
            ],
            "repository": lambda payload: [
                payload["provenance"][when].__setitem__(
                    "repo",
                    str(self.root / "different-repo"),
                )
                for when in ("pre", "post")
            ]
            + [
                payload["cleanup"].__setitem__(
                    "argv",
                    [
                        str(
                            self.root
                            / "different-repo/scripts/sudo/kill.sh"
                        ),
                        payload["host_run_id"],
                    ],
                ),
                payload["cleanup"].__setitem__(
                    "argv_sha256",
                    hashlib.sha256(
                        json.dumps(
                            [
                                str(
                                    self.root
                                    / "different-repo/scripts/sudo/kill.sh"
                                ),
                                payload["host_run_id"],
                            ],
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest(),
                ),
            ],
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                payload = json.loads(original)
                mutate(payload)
                receipt_b.write_text(json.dumps(payload))
                with self.assertRaisesRegex(
                    native_kernel_capture.EvidenceError,
                    f"receipt determinant changed: {label}",
                ):
                    native_kernel_capture.compare_receipts(
                        (receipt_a, receipt_b)
                    )
                receipt_b.write_bytes(original)

    def test_identical_pair_tampering_does_not_evade_fixed_determinants(
        self,
    ) -> None:
        _, receipt_a, receipt_b, _ = self.capture_success()
        originals = {
            receipt_a: receipt_a.read_bytes(),
            receipt_b: receipt_b.read_bytes(),
        }
        mutations = {
            "invocation": lambda payload: payload["determinants"][
                "invocation"
            ].__setitem__("profile", "wrong-profile"),
            "environment": lambda payload: payload["determinants"][
                "environment"
            ].__setitem__("CARRICK_DSR_PROFILE", "foreign"),
            "timeout": lambda payload: payload["determinants"][
                "timeout_policy"
            ].__setitem__("seconds", 0),
            "image": lambda payload: [
                payload["provenance"][when]["image"].__setitem__(
                    "architecture",
                    "amd64",
                )
                for when in ("pre", "post")
            ],
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                for path, raw in originals.items():
                    payload = json.loads(raw)
                    mutate(payload)
                    path.write_text(json.dumps(payload))
                with self.assertRaisesRegex(
                    native_kernel_capture.EvidenceError,
                    f"receipt {label}",
                ):
                    native_kernel_capture.compare_receipts(
                        (receipt_a, receipt_b)
                    )
                for path, raw in originals.items():
                    path.write_bytes(raw)

    def test_receipt_path_alias_is_not_capture_authority(self) -> None:
        _, receipt_a, _, _ = self.capture_success()
        alias = receipt_a.parent / "copied-a.receipt.json"
        alias.write_bytes(receipt_a.read_bytes())

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "receipt path differs from fixed layout",
        ):
            native_kernel_capture.validate_receipt(alias)

    def rebind_artifact(
        self,
        receipt: Path,
        payload: dict[str, object],
        name: str,
    ) -> None:
        path = Path(payload["artifacts"][name]["path"])
        payload["artifacts"][name] = {
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        receipt.write_text(json.dumps(payload))

    def test_boolean_status_and_completion_values_are_rejected_as_malformed(
        self,
    ) -> None:
        _, receipt_a, _, _ = self.capture_success()
        original_receipt = receipt_a.read_bytes()
        original_payload = json.loads(original_receipt)
        status_path = Path(
            original_payload["artifacts"]["command_status"]["path"]
        )
        summary_path = Path(
            original_payload["artifacts"]["summary_jsonl"]["path"]
        )
        original_status = status_path.read_bytes()
        original_summary = summary_path.read_bytes()

        cases = (
            ("command.status", "command", "status", False),
            ("command.build_ok_count", "command", "build_ok_count", True),
            ("cleanup.status", "cleanup", "status", False),
        )
        for fragment, section, field, value in cases:
            with self.subTest(fragment=fragment):
                try:
                    payload = json.loads(original_receipt)
                    payload[section][field] = value
                    if section == "command":
                        status = json.loads(original_status)
                        status[field] = value
                        status_path.write_text(json.dumps(status))
                        self.rebind_artifact(
                            receipt_a,
                            payload,
                            "command_status",
                        )
                    else:
                        receipt_a.write_text(json.dumps(payload))
                    with self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        f"{fragment} must be an integer",
                    ):
                        native_kernel_capture.validate_receipt(receipt_a)
                finally:
                    receipt_a.write_bytes(original_receipt)
                    status_path.write_bytes(original_status)

        payload = json.loads(original_receipt)
        rows = [
            json.loads(line)
            for line in original_summary.decode().splitlines()
        ]
        for row in rows:
            row["completion"]["target_exit_reason"] = True
        summary_path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows)
        )
        payload["completion"]["target_exit_reason"] = True
        self.rebind_artifact(receipt_a, payload, "summary_jsonl")

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "completion target_exit_reason must be an integer",
        ):
            native_kernel_capture.validate_receipt(receipt_a)

    def test_every_numeric_receipt_field_rejects_boolean_values(self) -> None:
        _, receipt_a, _, _ = self.capture_success()
        original = receipt_a.read_bytes()
        payload = json.loads(original)

        cases: list[tuple[str, tuple[object, ...]]] = [
            (
                f"artifact {name}.size",
                ("artifacts", name, "size"),
            )
            for name in sorted(payload["artifacts"])
        ]
        cases.extend(
            [
                ("command.status", ("command", "status")),
                ("command.build_ok_count", ("command", "build_ok_count")),
                ("cleanup.status", ("cleanup", "status")),
                (
                    "completion target_exit_reason",
                    ("completion", "target_exit_reason"),
                ),
                (
                    "completion incomplete_pairs",
                    ("completion", "incomplete_pairs"),
                ),
                *[
                    (
                        f"completion drops.{name}",
                        ("completion", "drops", name),
                    )
                    for name in (
                        "principal_drops",
                        "aggregation_drops",
                        "dynamic_drops",
                        "other_drops",
                    )
                ],
                *[
                    (
                        f"descendant_census.{name}",
                        ("descendant_census", name),
                    )
                    for name in ("create", "exit", "live-at-end")
                ],
                *[
                    (
                        f"reconciliation.{name}",
                        ("reconciliation", name),
                    )
                    for name in (
                        "completion_rows",
                        "kernel_pc_count",
                        "kernel_stack_count",
                    )
                ],
                (
                    "provenance.pre.binary.size",
                    ("provenance", "pre", "binary", "size"),
                ),
                (
                    "provenance.post.binary.size",
                    ("provenance", "post", "binary", "size"),
                ),
                (
                    "provenance.pre.launcher_ancestry[0].depth",
                    (
                        "provenance",
                        "pre",
                        "launcher_ancestry",
                        0,
                        "depth",
                    ),
                ),
                (
                    "provenance.post.launcher_ancestry[0].depth",
                    (
                        "provenance",
                        "post",
                        "launcher_ancestry",
                        0,
                        "depth",
                    ),
                ),
                (
                    "determinants.timeout_policy.seconds",
                    ("determinants", "timeout_policy", "seconds"),
                ),
                (
                    "determinants.timeout_policy.cleanup_seconds",
                    ("determinants", "timeout_policy", "cleanup_seconds"),
                ),
                (
                    "monitor.interval_milliseconds",
                    ("monitor", "interval_milliseconds"),
                ),
                ("monitor.sample_count", ("monitor", "sample_count")),
                (
                    "monitor.samples[0].sequence",
                    ("monitor", "samples", 0, "sequence"),
                ),
                (
                    "monitor.samples[0].docker_oracle_count",
                    ("monitor", "samples", 0, "docker_oracle_count"),
                ),
                (
                    "monitor.samples[0].foreign_workload_count",
                    ("monitor", "samples", 0, "foreign_workload_count"),
                ),
            ]
        )

        for fragment, path in cases:
            with self.subTest(field=fragment):
                try:
                    mutated = json.loads(original)
                    parent: object = mutated
                    for part in path[:-1]:
                        parent = parent[part]
                    parent[path[-1]] = True
                    receipt_a.write_text(json.dumps(mutated))
                    with self.assertRaisesRegex(
                        native_kernel_capture.EvidenceError,
                        re.escape(f"{fragment} must be an integer"),
                    ):
                        native_kernel_capture.validate_receipt(receipt_a)
                finally:
                    receipt_a.write_bytes(original)

    def test_unknown_drop_counter_cannot_hide_unaccepted_loss(self) -> None:
        _, receipt_a, _, _ = self.capture_success()
        payload = json.loads(receipt_a.read_text())
        summary_path = Path(payload["artifacts"]["summary_jsonl"]["path"])
        rows = [
            json.loads(line)
            for line in summary_path.read_text().splitlines()
        ]
        for row in rows:
            row["completion"]["drops"]["future_drops"] = 1
        summary_path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows)
        )
        payload["completion"]["drops"]["future_drops"] = 1
        self.rebind_artifact(receipt_a, payload, "summary_jsonl")

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "unknown drop counter",
        ):
            native_kernel_capture.validate_receipt(receipt_a)

    def test_analysis_requires_absent_output_and_valid_receipts(self) -> None:
        _, receipt_a, receipt_b, _ = self.capture_success()
        output = self.root / "separate-analysis.json"
        os.symlink("missing-analysis-target", output)
        before = (os.lstat(output), os.readlink(output))

        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "analysis output already exists",
        ):
            native_kernel_capture.analyze_receipts(
                (receipt_a, receipt_b),
                output,
            )

        after = (os.lstat(output), os.readlink(output))
        self.assertEqual(after[0].st_ino, before[0].st_ino)
        self.assertEqual(after[1], before[1])

        output.unlink()
        receipt_b.write_text('{"schema":"wrong"}\n')
        with self.assertRaisesRegex(
            native_kernel_capture.EvidenceError,
            "receipt schema",
        ):
            native_kernel_capture.analyze_receipts(
                (receipt_a, receipt_b),
                output,
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
