from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
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
        docker_listing: str = "",
    ) -> None:
        self.binary = binary
        self.binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.trace_outcome = trace_outcome
        self.process_listing = process_listing or (
            f"{os.getpid()} 500 python3 native_kernel_capture.py\n"
            "500 1 zsh task-launcher\n"
            "1 0 /sbin/launchd\n"
        )
        self.docker_listing = docker_listing
        self.events: list[tuple[str, str]] = []
        self.trace_index = 0

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
            return self._result(rendered, stdout=self.docker_listing)
        if rendered[:3] == ["ps", "-eo", "pid=,ppid=,args="]:
            return self._result(rendered, stdout=self.process_listing)
        if len(rendered) > 2 and rendered[1:3] == ["trace", "--profile"]:
            environment = kwargs["env"]
            assert isinstance(environment, dict)
            host_run_id = environment["CARRICK_RUN_ID"]
            self.events.append(("trace", host_run_id))
            self.trace_index += 1
            raw_path = Path(rendered[rendered.index("--trace-out") + 1])
            summary_path = Path(rendered[rendered.index("--summary-jsonl") + 1])
            target = rendered[rendered.index("--") + 1 :]
            if self.trace_outcome == "timeout":
                raise subprocess.TimeoutExpired(
                    rendered,
                    kwargs["timeout"],
                    output="partial stdout\n",
                    stderr="partial stderr\n",
                )
            if self.trace_outcome == "exception":
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
            [row["pid"] for row in snapshot["launcher_ancestry"]],
            [100, 50, 1],
        )
        self.assertEqual(
            [row["pid"] for row in snapshot["foreign_workloads"]],
            [400, 401, 402, 403, 404],
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
        self.assertEqual(payload["schema"], "carrick.native-kernel-capture.v1")
        self.assertEqual(payload["outcome"], "accepted")
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
                            "pid": 999,
                            "ppid": 1,
                            "command": "different launcher",
                        }
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
