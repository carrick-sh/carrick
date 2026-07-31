#!/usr/bin/env python3
"""Fail-closed fixtures for the M2 native lifecycle capture."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
MODULE_PATH = HERE / "native_wall_capture.py"


def load_capture_module():
    if not MODULE_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("native_wall_capture", MODULE_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GOOD_EVENTS = [
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=1|kind=target-birth|pid=100|incarnation=1|generation=1|epoch=0",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=2|kind=parent-reset|pid=100|incarnation=1|generation=1|epoch=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=3|kind=parent-private|pid=100|incarnation=1|generation=1|epoch=1|sequence=1|start=0x1000|end=0x2000",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=4|kind=parent-ready|pid=100|incarnation=1|generation=1|epoch=1|frontier=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=5|kind=parent-first-run|pid=100|incarnation=1|generation=1|epoch=1|cache_pc=0x1100",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=6|kind=child-birth|pid=101|incarnation=1|generation=1|epoch=1|parent_pid=100",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=7|kind=fork-repair-begin|pid=101|incarnation=1|generation=1|epoch=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=8|kind=child-preexec-reset|pid=101|incarnation=1|generation=1|epoch=2",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=9|kind=child-preexec-private|pid=101|incarnation=1|generation=1|epoch=2|sequence=1|start=0x1000|end=0x2000",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=10|kind=child-preexec-ready|pid=101|incarnation=1|generation=1|epoch=2|frontier=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=11|kind=fork-repair-end|pid=101|incarnation=1|generation=1|epoch=2",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=12|kind=child-fork-post|pid=101|incarnation=1|generation=1|epoch=2",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=13|kind=child-preexec-first-run|pid=101|incarnation=1|generation=1|epoch=2|cache_pc=0x1100",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=14|kind=reexec-preflight-begin|pid=101|incarnation=1|generation=1|epoch=2",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=15|kind=reexec-begin|pid=101|incarnation=1|generation=1|epoch=2",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=16|kind=exec|pid=101|incarnation=1|generation=1|epoch=2",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=17|kind=exec-success|pid=101|incarnation=1|generation=2|epoch=0",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=18|kind=reexec-end|pid=101|incarnation=1|generation=2|epoch=0",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=19|kind=child-postexec-reset|pid=101|incarnation=1|generation=2|epoch=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=20|kind=child-postexec-private|pid=101|incarnation=1|generation=2|epoch=1|sequence=1|start=0x3000|end=0x4000",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=21|kind=child-postexec-ready|pid=101|incarnation=1|generation=2|epoch=1|frontier=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=22|kind=host-image-base|pid=101|incarnation=1|generation=2|epoch=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=23|kind=host-image-catalog|pid=101|incarnation=1|generation=2|epoch=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=24|kind=guest-image-base|pid=101|incarnation=1|generation=2|epoch=1",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=25|kind=host-jit-range|pid=101|incarnation=1|generation=2|epoch=1|start=0x3000|end=0x4000",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=26|kind=child-postexec-first-run|pid=101|incarnation=1|generation=2|epoch=1|cache_pc=0x3100",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=27|kind=child-exit|pid=101|incarnation=1|generation=2|epoch=1|status=0",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=28|kind=parent-wait4|pid=100|incarnation=1|generation=1|epoch=1|child_pid=101|retval=101|errno=0",
    "TRANSLATED_LIFECYCLE|schema=1|ordinal=29|kind=root-exit|pid=100|incarnation=1|generation=1|epoch=1|status=0",
]

GOOD_SUMMARY = (
    "TRANSLATED_LIFECYCLE_SUMMARY|schema=1|complete=1|lifecycle_ok=1|"
    "root_exit_status=0|target_birth=1|child_birth=1|parent_catalog_ok=1|"
    "child_preexec_catalog_ok=1|child_postexec_catalog_ok=1|parent_run=1|"
    "child_preexec_run=1|child_postexec_run=1|fork_repair_begin=1|"
    "fork_repair_end=1|child_fork_post=1|preflight=1|reexec_begin=1|exec=1|"
    "exec_success=1|exec_failure=0|reexec_end=1|metadata_ok=1|child_exit=1|"
    "child_exit_status=0|wait4_success=1|unexpected_events=0|"
    "identity_violations=0|catalog_violations=0|metadata_violations=0|"
    "run_violations=0|pending=0|dtrace_drops=0|dtrace_errors=0"
)


def good_trace(events: list[str] | None = None, summary: str = GOOD_SUMMARY) -> str:
    return "\n".join([*(GOOD_EVENTS if events is None else events), summary, ""])


REAL_LD64_TEXT_DOF_LISTING = b"""\
target/perf/native-m2-lifecycle-arm-15345cf2/carrick:
Load command 1
      cmd LC_SEGMENT_64
  cmdsize 792
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000fb4000
  fileoff 0
 filesize 16465920
  maxprot 0x00000005
 initprot 0x00000005
   nsects 9
    flags 0x0
Section
  sectname __dof_carrick
   segname __TEXT
      addr 0x0000000100dc6f22
      size 0x0000000000008f3e
    offset 14446370
     align 2^0 (1)
    reloff 0
    nreloc 0
     flags 0x0000000f
 reserved1 0
 reserved2 0
"""


def dof_listing(
    *,
    segment: str = "__TEXT",
    size: str = "0x0000000000000040",
    section_segment: str | None = None,
    section_marker: str = "Section",
) -> bytes:
    actual_section_segment = segment if section_segment is None else section_segment
    return (
        "fixture-carrick:\n"
        "Load command 7\n"
        "      cmd LC_SEGMENT_64\n"
        "  cmdsize 152\n"
        f"  segname {segment}\n"
        "   vmaddr 0x0000000100000000\n"
        "   vmsize 0x0000000000004000\n"
        "  fileoff 0\n"
        " filesize 16384\n"
        "  maxprot 0x00000005\n"
        " initprot 0x00000005\n"
        "   nsects 1\n"
        "    flags 0x0\n"
        f"{section_marker}\n"
        "  sectname __dof_carrick\n"
        f"   segname {actual_section_segment}\n"
        "      addr 0x0000000100001000\n"
        f"      size {size}\n"
        "    offset 4096\n"
        "     align 2^0 (1)\n"
        "    reloff 0\n"
        "    nreloc 0\n"
        "     flags 0x0000000f\n"
        " reserved1 0\n"
        " reserved2 0\n"
    ).encode()


class LifecycleTraceFixtureTests(unittest.TestCase):
    def module(self):
        module = load_capture_module()
        self.assertIsNotNone(
            module,
            "native_wall_capture.py is absent at the immutable 9c2494ec base",
        )
        return module

    def test_capture_lifecycle_cli_surface_exists(self) -> None:
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "capture-lifecycle", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_one_complete_ordered_lifecycle(self) -> None:
        parsed = self.module().parse_lifecycle_trace(good_trace())
        self.assertEqual(parsed["lifecycle_ok"], 1)
        self.assertEqual(parsed["child_pid"], 101)
        self.assertEqual(parsed["event_count"], 29)

    def test_rejects_missing_duplicate_and_reordered_milestones(self) -> None:
        module = self.module()
        for index, event in enumerate(GOOD_EVENTS):
            kind = event.split("|kind=", 1)[1].split("|", 1)[0]
            with self.subTest(kind=kind, mutation="missing"):
                mutated = GOOD_EVENTS[:index] + GOOD_EVENTS[index + 1 :]
                with self.assertRaisesRegex(module.EvidenceError, kind):
                    module.parse_lifecycle_trace(good_trace(mutated))
            with self.subTest(kind=kind, mutation="duplicate"):
                mutated = GOOD_EVENTS[:index] + [event, event] + GOOD_EVENTS[index + 1 :]
                with self.assertRaisesRegex(module.EvidenceError, kind):
                    module.parse_lifecycle_trace(good_trace(mutated))
            if index:
                with self.subTest(kind=kind, mutation="reordered"):
                    mutated = list(GOOD_EVENTS)
                    mutated[index - 1], mutated[index] = mutated[index], mutated[index - 1]
                    with self.assertRaisesRegex(module.EvidenceError, "order|ordinal"):
                        module.parse_lifecycle_trace(good_trace(mutated))

    def test_rejects_stale_postexec_metadata_generation(self) -> None:
        module = self.module()
        events = [
            line.replace("generation=2", "generation=1")
            if "kind=host-image-catalog" in line
            else line
            for line in GOOD_EVENTS
        ]
        with self.assertRaisesRegex(module.EvidenceError, "generation"):
            module.parse_lifecycle_trace(good_trace(events))

    def test_rejects_out_of_range_and_disarmed_samples(self) -> None:
        module = self.module()
        out_of_range = [
            line.replace("cache_pc=0x3100", "cache_pc=0x5000")
            if "child-postexec-first-run" in line
            else line
            for line in GOOD_EVENTS
        ]
        with self.assertRaisesRegex(module.EvidenceError, "range"):
            module.parse_lifecycle_trace(good_trace(out_of_range))

        disarmed = list(GOOD_EVENTS)
        disarmed.insert(
            16,
            "TRANSLATED_LIFECYCLE|schema=1|ordinal=17|kind=disarmed-run|pid=101|incarnation=1|generation=1|epoch=2|cache_pc=0x1100",
        )
        for index in range(17, len(disarmed)):
            prefix, ordinal_and_rest = disarmed[index].split("|ordinal=", 1)
            _old, rest = ordinal_and_rest.split("|", 1)
            disarmed[index] = f"{prefix}|ordinal={index + 1}|{rest}"
        with self.assertRaisesRegex(module.EvidenceError, "disarmed"):
            module.parse_lifecycle_trace(good_trace(disarmed))

    def test_requires_exactly_one_clean_summary(self) -> None:
        module = self.module()
        cases = {
            "missing": "\n".join(GOOD_EVENTS) + "\n",
            "duplicate": good_trace() + GOOD_SUMMARY + "\n",
            "violation": good_trace(
                summary=GOOD_SUMMARY.replace(
                    "catalog_violations=0", "catalog_violations=1"
                )
            ),
            "drop": good_trace(
                summary=GOOD_SUMMARY.replace("dtrace_drops=0", "dtrace_drops=1")
            ),
            "error": good_trace(
                summary=GOOD_SUMMARY.replace("dtrace_errors=0", "dtrace_errors=1")
            ),
            "pending": good_trace(
                summary=GOOD_SUMMARY.replace("pending=0", "pending=1")
            ),
        }
        for label, raw in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(module.EvidenceError):
                    module.parse_lifecycle_trace(raw)

    def test_rejects_nonzero_child_or_root_guest_exit(self) -> None:
        module = self.module()
        for kind in ("child-exit", "root-exit"):
            with self.subTest(kind=kind):
                events = [
                    line.replace("status=0", "status=9")
                    if f"kind={kind}" in line
                    else line
                    for line in GOOD_EVENTS
                ]
                with self.assertRaisesRegex(module.EvidenceError, "exit status"):
                    module.parse_lifecycle_trace(good_trace(events))


class RunIdCensusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_capture_module()
        self.assertIsNotNone(self.module)
        self.binary = pathlib.Path("/immutable/arm/carrick")
        self.run_id = "native-m2-lifecycle-42345678-1234-4678-9234-567812345678"

    def test_matches_every_scoped_kill_shape_and_only_exact_identity(self) -> None:
        run_id = self.run_id
        records = [
            (11, f"carrick:{run_id}: /bin/sh"),
            (
                12,
                f"{self.binary} trace --forward-env CARRICK_RUN_ID={run_id} -- run",
            ),
            (13, f"{self.binary} trace --name {run_id} -- run"),
            (14, f"sudo {self.binary} trace run_id={run_id}"),
            (15, f"carrick:{run_id}-other: /bin/sh"),
            (16, f"other trace CARRICK_RUN_ID={run_id}"),
            (17, f"{self.binary} trace CARRICK_RUN_ID={run_id}-other"),
            (
                18,
                "/other/worktree/target/release/carrick trace "
                f"CARRICK_RUN_ID={run_id}",
            ),
        ]
        matches = self.module.matching_run_processes(
            records, run_id=run_id
        )
        self.assertEqual(
            [pid for pid, _command in matches], [11, 12, 13, 14, 18]
        )


class FixtureBoundary:
    """External boundary double; file parsing and publication remain real."""

    def __init__(self, arm, trace_out: pathlib.Path):
        self.arm = arm
        self.trace_out = trace_out
        self.uuid = uuid.UUID("12345678-1234-4678-9234-567812345678")
        self.dof = {
            "section": "__dof_carrick",
            "segment": "__TEXT",
            "size": 0x40,
            "otool_listing_sha256": hashlib.sha256(
                b"fixture otool listing"
            ).hexdigest(),
        }
        self.docker_results: list[list[str]] = [[], []]
        self.presence_results: list[bool] = [False, False]
        self.process_results: list[list[tuple[int, str]]] = [[], []]
        self.reap_statuses: list[int] = [0, 0]
        self.reap_exceptions: list[BaseException | None] = []
        self.launch_status = 0
        self.launch_stdout = "CHILD_EXEC_OK\nPARENT_WAIT_OK\n"
        self.launch_stderr = ""
        self.trace_text = good_trace()
        self.launch_exception: BaseException | None = None
        self.checkpoint_exceptions: dict[str, BaseException] = {}
        self.checkpoint_mutations: dict[str, tuple[pathlib.Path, bytes]] = {}
        self.events: list[tuple[str, object]] = []
        self.launch_argv: list[str] | None = None
        self.launch_env: dict[str, str] | None = None
        self.launch_timeout: int | None = None

    def verify_arm(self, receipt: pathlib.Path):
        self.events.append(("verify-arm", receipt))
        return self.arm

    def inspect_dof(self, binary: pathlib.Path) -> dict[str, object]:
        self.events.append(("inspect-dof", binary))
        return dict(self.dof)

    def running_docker_oracles(self) -> list[str]:
        self.events.append(("docker", None))
        return self.docker_results.pop(0) if self.docker_results else []

    def run_id_present(self, run_id: str, binary: pathlib.Path) -> bool:
        self.events.append(("census", run_id))
        return self.presence_results.pop(0) if self.presence_results else False

    def process_records(self) -> list[tuple[int, str]]:
        self.events.append(("process-records", None))
        return self.process_results.pop(0) if self.process_results else []

    def uuid4(self) -> uuid.UUID:
        self.events.append(("uuid", str(self.uuid)))
        return self.uuid

    def reap(self, repo: pathlib.Path, run_id: str) -> subprocess.CompletedProcess[str]:
        self.events.append(("reap", run_id))
        if self.reap_exceptions:
            error = self.reap_exceptions.pop(0)
            if error is not None:
                raise error
        status = self.reap_statuses.pop(0) if self.reap_statuses else 0
        return subprocess.CompletedProcess(
            [str(repo / "scripts/sudo/kill.sh"), run_id],
            status,
            "fixture reap stdout\n",
            "fixture reap stderr\n" if status else "",
        )

    def checkpoint(self, phase: str) -> None:
        self.events.append(("checkpoint", phase))
        mutation = self.checkpoint_mutations.get(phase)
        if mutation is not None:
            path, content = mutation
            path.write_bytes(content)
        error = self.checkpoint_exceptions.get(phase)
        if error is not None:
            raise error

    def launch(
        self,
        argv: list[str],
        *,
        cwd: pathlib.Path,
        env: dict[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        self.events.append(("launch", tuple(argv)))
        self.launch_argv = list(argv)
        self.launch_env = dict(env)
        self.launch_timeout = timeout
        if self.launch_exception is not None:
            raise self.launch_exception
        if self.trace_text is not None:
            trace_index = argv.index("--trace-out") + 1
            pathlib.Path(argv[trace_index]).write_text(self.trace_text)
        return subprocess.CompletedProcess(
            argv,
            self.launch_status,
            self.launch_stdout,
            self.launch_stderr,
        )


class LifecycleCaptureFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts/dtrace").mkdir(parents=True)
        (self.repo / "scripts/sudo").mkdir(parents=True)
        (self.repo / "scripts/sudo/kill.sh").write_text("fixture helper\n")
        self.script = self.repo / "scripts/dtrace/native-translated-range-catalog.d"
        self.script.write_text(
            (HERE.parent / "dtrace/native-translated-range-catalog.d").read_text()
        )
        self.arm_dir = self.root / "arm"
        self.arm_dir.mkdir()
        self.binary = self.arm_dir / "carrick"
        self.binary.write_bytes(b"immutable signed fixture with DATA DOF")
        self.receipt = self.arm_dir / "arm.json"
        self.receipt.write_text('{"schema":"fixture-arm"}\n')
        self.overlay = self.root / "native-default.json"
        self.module = load_capture_module()
        self.assertIsNotNone(
            self.module,
            "native_wall_capture.py is absent at the immutable 9c2494ec base",
        )
        self.overlay.write_text(
            json.dumps(
                {
                    key: None
                    for key in self.module.native_go_build.PERFORMANCE_CONTROL_KEYS
                },
                indent=2,
            )
            + "\n"
        )
        self.trace_out = self.root / "capture.raw"
        self.summary = self.root / "capture.jsonl"
        self.stdout = self.root / "capture.stdout"
        self.capture_receipt = self.root / "capture.receipt.json"
        self.arm = types.SimpleNamespace(
            path=self.receipt.resolve(),
            role="candidate",
            binary_path=self.binary.resolve(),
            binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            image_ref="localhost:5005/carrick-go-conformance:1.24",
            image_id="sha256:" + "a" * 64,
            image_repo_digests=(
                "localhost:5005/carrick-go-conformance@sha256:" + "b" * 64,
            ),
        )
        self.boundary = FixtureBoundary(self.arm, self.trace_out)
        self.attempt = 0

    def config(self, **changes):
        values = {
            "repo": self.repo,
            "receipt": self.receipt,
            "overlay": self.overlay,
            "timeout_seconds": 120,
            "trace_out": self.trace_out,
            "summary_jsonl": self.summary,
            "stdout": self.stdout,
            "capture_receipt": self.capture_receipt,
            "script": self.script,
        }
        values.update(changes)
        return self.module.LifecycleCaptureConfig(**values)

    def capture(self, **changes):
        return self.module.capture_lifecycle(
            self.config(**changes), boundary=self.boundary
        )

    def next_attempt(self, trace_out: pathlib.Path | None = None) -> None:
        self.attempt += 1
        for path in (
            self.trace_out,
            self.summary,
            self.stdout,
            self.capture_receipt,
        ):
            path.unlink(missing_ok=True)
        selected_trace = self.trace_out if trace_out is None else trace_out
        selected_trace.unlink(missing_ok=True)
        self.boundary = FixtureBoundary(self.arm, selected_trace)
        self.boundary.uuid = uuid.UUID(
            f"12345678-1234-4678-9234-{self.attempt:012x}"
        )

    def test_success_uses_fixed_launch_environment_and_closed_receipt(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CARRICK_DSR_SHARED_TRANSLATION": "1",
                "CARRICK_DSR_DIRECT_BINDINGS": "1",
                "CARRICK_DSR_PROFILE": "ambient",
                "CARRICK_FUTURE_CONTROL": "must-not-leak",
                "FIXTURE_KEEP": "yes",
            },
            clear=False,
        ):
            payload = self.capture()

        run_id = "native-m2-lifecycle-12345678-1234-4678-9234-567812345678"
        self.assertEqual(payload["run_id"], run_id)
        self.assertEqual(
            payload["schema"], "carrick.native-m2-lifecycle-capture.v2"
        )
        self.assertEqual(payload["dof"], self.boundary.dof)
        self.assertEqual(
            [event for event in self.boundary.events if event[0] == "reap"],
            [("reap", run_id), ("reap", run_id)],
        )
        self.assertEqual(self.boundary.launch_timeout, 120)
        trace_index = self.boundary.launch_argv.index("--trace-out") + 1
        temporary_trace = self.boundary.launch_argv[trace_index]
        self.assertEqual(
            self.boundary.launch_argv,
            [
                str(self.binary.resolve()),
                "trace",
                "--script",
                str(self.script.resolve()),
                "--trace-out",
                temporary_trace,
                "--",
                "run",
                "--exec-backend",
                "native",
                "--pull",
                "never",
                "localhost:5005/carrick-go-conformance@sha256:" + "b" * 64,
                "/bin/sh",
                "-c",
                self.module.LIFECYCLE_REDUCER,
            ],
        )
        self.assertNotIn("sudo", self.boundary.launch_argv)
        self.assertNotIn("--profile", self.boundary.launch_argv)
        self.assertNotIn("--summary-jsonl", self.boundary.launch_argv)
        self.assertEqual(self.boundary.launch_env["CARRICK_RUN_ID"], run_id)
        self.assertEqual(self.boundary.launch_env["CARRICK_DSR_PROFILE"], "1")
        self.assertNotIn("CARRICK_FUTURE_CONTROL", self.boundary.launch_env)
        for key in self.module.native_go_build.PERFORMANCE_CONTROL_KEYS:
            if key != "CARRICK_DSR_PROFILE":
                self.assertNotIn(key, self.boundary.launch_env)
        self.assertNotIn("FIXTURE_KEEP", self.boundary.launch_env)
        self.assertEqual(
            payload["environment"]["launch_environment"],
            self.boundary.launch_env,
        )
        self.assertNotEqual(
            pathlib.Path(temporary_trace),
            self.trace_out.resolve(),
        )
        self.assertEqual(
            pathlib.Path(temporary_trace).parent,
            self.trace_out.resolve().parent,
        )
        self.assertEqual(self.stdout.read_text(), self.boundary.launch_stdout)
        self.assertEqual(len(self.summary.read_text().splitlines()), 1)
        validated = self.module.validate_capture_receipt(
            self.capture_receipt, boundary=self.boundary
        )
        self.assertEqual(validated["outcome"], "accepted")
        self.assertTrue(validated["observability_only"])
        self.assertFalse(validated["cpu_evidence"])

    def test_arm_script_and_overlay_drift_fail_before_launch(self) -> None:
        targets = {
            "arm receipt": self.receipt,
            "arm binary": self.binary,
            "DTrace script": self.script,
            "overlay": self.overlay,
        }
        for label, path in targets.items():
            with self.subTest(label=label):
                original = path.read_bytes()
                self.boundary.checkpoint_mutations = {
                    "before-launch": (path, original + b"drift")
                }
                with self.assertRaisesRegex(self.module.EvidenceError, "drift"):
                    self.capture()
                self.assertNotIn("launch", [event[0] for event in self.boundary.events])
                path.write_bytes(original)
                self.next_attempt()

    def test_dof_parser_and_nondefault_overlay_fail_closed(self) -> None:
        current = self.module._parse_dof_otool_listing(
            REAL_LD64_TEXT_DOF_LISTING
        )
        self.assertEqual(
            current,
            {
                "section": "__dof_carrick",
                "segment": "__TEXT",
                "size": 0x8F3E,
                "otool_listing_sha256": hashlib.sha256(
                    REAL_LD64_TEXT_DOF_LISTING
                ).hexdigest(),
            },
        )
        for segment in ("__TEXT", "__DATA"):
            with self.subTest(accepted_segment=segment):
                listing = dof_listing(segment=segment)
                parsed = self.module._parse_dof_otool_listing(listing)
                self.assertEqual(parsed["segment"], segment)
                self.assertEqual(parsed["size"], 0x40)
                self.assertEqual(
                    parsed["otool_listing_sha256"],
                    hashlib.sha256(listing).hexdigest(),
                )

        malformed = dof_listing(section_marker="Not a section")
        duplicate = dof_listing() + dof_listing(segment="__DATA")
        missing = dof_listing().replace(b"__dof_carrick", b"__not_dof_here")
        cases = {
            "unsupported segment": dof_listing(segment="__OTHER"),
            "zero size": dof_listing(size="0x0"),
            "duplicate section": duplicate,
            "missing section": missing,
            "malformed section": malformed,
            "mismatched segment": dof_listing(section_segment="__DATA"),
            "malformed size": dof_listing(size="not-a-number"),
        }
        for label, listing in cases.items():
            with self.subTest(rejected=label):
                with self.assertRaisesRegex(
                    self.module.EvidenceError,
                    "DOF|__dof_carrick|segment|size|malformed",
                ):
                    self.module._parse_dof_otool_listing(listing)

        self.boundary.dof = {}
        with self.assertRaisesRegex(self.module.EvidenceError, "DOF"):
            self.capture()

        self.next_attempt()
        overlay = json.loads(self.overlay.read_text())
        overlay["CARRICK_DSR_SHARED_TRANSLATION"] = "1"
        self.overlay.write_text(json.dumps(overlay))
        with self.assertRaisesRegex(self.module.EvidenceError, "sharing-disabled"):
            self.capture()

    def test_duplicate_and_noncanonical_overlay_reject(self) -> None:
        keys = self.module.native_go_build.PERFORMANCE_CONTROL_KEYS
        duplicate = [f'"{key}":null' for key in keys]
        duplicate.append(f'"{keys[-1]}":null')
        self.overlay.write_text("{" + ",".join(duplicate) + "}\n")
        with self.assertRaisesRegex(
            self.module.EvidenceError, "exactly once|canonical order"
        ):
            self.capture()

        self.next_attempt()
        reversed_overlay = {key: None for key in reversed(keys)}
        self.overlay.write_text(json.dumps(reversed_overlay) + "\n")
        with self.assertRaisesRegex(self.module.EvidenceError, "canonical order"):
            self.capture()

    def test_exact_campaign_image_and_maintained_script_are_required(self) -> None:
        self.arm.image_ref = "localhost:5005/other-image:1.24"
        self.arm.image_repo_digests = (
            "localhost:5005/other-image@sha256:" + "b" * 64,
        )
        with self.assertRaisesRegex(self.module.EvidenceError, "exact.*image"):
            self.capture()

        self.arm.image_ref = "localhost:5005/carrick-go-conformance:1.24"
        self.arm.image_repo_digests = (
            "localhost:5005/carrick-go-conformance@sha256:" + "b" * 64,
        )
        self.next_attempt()
        self.script.write_text("/* provider names in a comment are not a program */\n")
        with self.assertRaisesRegex(
            self.module.EvidenceError, "maintained lifecycle script"
        ):
            self.capture()

    def test_uuid_collision_and_reuse_reject_without_launch(self) -> None:
        run_id = "native-m2-lifecycle-12345678-1234-4678-9234-567812345678"
        self.boundary.process_results = [[(99, f"carrick:{run_id}: /bin/sh")]]
        with self.assertRaisesRegex(self.module.EvidenceError, "already present"):
            self.capture()
        self.assertNotIn("launch", [event[0] for event in self.boundary.events])
        self.assertNotIn("reap", [event[0] for event in self.boundary.events])

        self.boundary = FixtureBoundary(self.arm, self.trace_out)
        self.boundary.uuid = uuid.UUID("22345678-1234-4678-9234-567812345678")
        self.capture(
            trace_out=self.root / "first.raw",
            summary_jsonl=self.root / "first.jsonl",
            stdout=self.root / "first.stdout",
            capture_receipt=self.root / "first.receipt.json",
        )
        self.boundary = FixtureBoundary(self.arm, self.root / "second.raw")
        self.boundary.uuid = uuid.UUID("22345678-1234-4678-9234-567812345678")
        with self.assertRaisesRegex(self.module.EvidenceError, "reused"):
            self.capture(
                trace_out=self.root / "second.raw",
                summary_jsonl=self.root / "second.jsonl",
                stdout=self.root / "second.stdout",
                capture_receipt=self.root / "second.receipt.json",
            )

    def test_durable_run_id_reservation_survives_module_reload(self) -> None:
        run_id = "native-m2-lifecycle-32345678-1234-4678-9234-567812345678"
        reservation = self.module.reserve_run_id(self.repo, run_id)
        self.assertTrue(reservation.is_file())
        reloaded = load_capture_module()
        self.assertIsNotNone(reloaded)
        with self.assertRaisesRegex(reloaded.EvidenceError, "reserved|reused"):
            reloaded.reserve_run_id(self.repo, run_id)

    def test_pre_reap_and_final_cleanup_failure_are_fatal(self) -> None:
        for statuses, message in [([1, 0], "pre-launch reap"), ([0, 1], "final reap")]:
            with self.subTest(statuses=statuses):
                self.boundary.reap_statuses = list(statuses)
                with self.assertRaisesRegex(self.module.EvidenceError, message):
                    self.capture()
                self.assertEqual(
                    len([event for event in self.boundary.events if event[0] == "reap"]),
                    2 if statuses == [1, 0] else 3,
                )
                self.next_attempt()

    def test_interruptions_and_timeout_always_run_final_cleanup(self) -> None:
        cases: list[tuple[str, BaseException, type[BaseException]]] = [
            ("after-pre-reap", RuntimeError("fixture interruption"), RuntimeError),
            ("before-launch", KeyboardInterrupt(), KeyboardInterrupt),
            ("after-launch", RuntimeError("fixture interruption"), RuntimeError),
            ("before-publish", KeyboardInterrupt(), KeyboardInterrupt),
        ]
        for phase, error, expected in cases:
            with self.subTest(phase=phase):
                self.boundary.checkpoint_exceptions[phase] = error
                with self.assertRaises(expected):
                    self.capture()
                self.assertEqual(
                    len([event for event in self.boundary.events if event[0] == "reap"]),
                    2,
                )
                self.next_attempt()

        self.boundary.launch_exception = subprocess.TimeoutExpired(
            ["fixture trace"], 120
        )
        with self.assertRaisesRegex(self.module.EvidenceError, "timed out"):
            self.capture()
        self.assertEqual(
            len([event for event in self.boundary.events if event[0] == "reap"]),
            2,
        )

    def test_final_reap_interrupt_retries_and_always_censuses(self) -> None:
        self.boundary.reap_exceptions = [None, KeyboardInterrupt(), None]
        with self.assertRaises(KeyboardInterrupt):
            self.capture()
        self.assertEqual(
            len([event for event in self.boundary.events if event[0] == "reap"]),
            3,
        )
        self.assertIn("process-records", [event[0] for event in self.boundary.events])

    def test_compile_failure_and_empty_trace_reject(self) -> None:
        self.boundary.launch_status = 1
        self.boundary.launch_stderr = "dtrace_program_strcompile failed"
        self.boundary.trace_text = ""
        with self.assertRaisesRegex(self.module.EvidenceError, "trace command failed"):
            self.capture()

        self.next_attempt()
        self.boundary.trace_text = ""
        with self.assertRaisesRegex(self.module.EvidenceError, "empty trace"):
            self.capture()

    def test_failed_trace_leaves_no_partial_final_raw_artifact(self) -> None:
        self.boundary.launch_status = 1
        self.boundary.launch_stderr = "fixture compile failure"
        with self.assertRaisesRegex(self.module.EvidenceError, "trace command failed"):
            self.capture()
        self.assertFalse(self.trace_out.exists())
        self.assertEqual(
            list(self.trace_out.parent.glob(f".{self.trace_out.name}.*.capture")),
            [],
        )

    def test_raw_trace_publication_never_overwrites_a_racing_destination(self) -> None:
        self.boundary.checkpoint_mutations = {
            "before-publish": (self.trace_out, b"racing owner\n")
        }
        with self.assertRaisesRegex(self.module.EvidenceError, "already exists"):
            self.capture()
        self.assertEqual(self.trace_out.read_bytes(), b"racing owner\n")

    def test_marker_and_status_mismatch_reject(self) -> None:
        cases = [
            (0, "PARENT_WAIT_OK\nCHILD_EXEC_OK\n", "order"),
            (0, "CHILD_EXEC_OK\nCHILD_EXEC_OK\nPARENT_WAIT_OK\n", "exactly once"),
            (0, "CHILD_EXEC_OK\n", "exactly once"),
            (7, "CHILD_EXEC_OK\nPARENT_WAIT_OK\n", "status 7"),
        ]
        for status, stdout, message in cases:
            with self.subTest(status=status, stdout=stdout):
                self.boundary.launch_status = status
                self.boundary.launch_stdout = stdout
                with self.assertRaisesRegex(self.module.EvidenceError, message):
                    self.capture()
                self.next_attempt()

    def test_post_cleanup_leftover_and_post_docker_oracle_reject(self) -> None:
        run_id = "native-m2-lifecycle-12345678-1234-4678-9234-567812345678"
        self.boundary.process_results = [[], [(99, f"carrick:{run_id}: /bin/sh")]]
        with self.assertRaisesRegex(self.module.EvidenceError, "leftover"):
            self.capture()

        self.next_attempt()
        self.boundary.docker_results = [[], ["fixture oracle"]]
        with self.assertRaisesRegex(self.module.EvidenceError, "Docker oracle"):
            self.capture()

    def test_receipt_hash_closure_rejects_artifact_and_payload_tampering(self) -> None:
        self.capture()
        original_receipt = self.capture_receipt.read_bytes()
        original_stdout = self.stdout.read_bytes()
        self.stdout.write_bytes(original_stdout + b"tamper")
        with self.assertRaisesRegex(self.module.EvidenceError, "stdout.*hash"):
            self.module.validate_capture_receipt(
                self.capture_receipt, boundary=self.boundary
            )
        self.stdout.write_bytes(original_stdout)

        payload = json.loads(original_receipt)
        payload["observability_only"] = False
        self.capture_receipt.write_text(json.dumps(payload))
        with self.assertRaisesRegex(self.module.EvidenceError, "closure"):
            self.module.validate_capture_receipt(
                self.capture_receipt, boundary=self.boundary
            )

    def test_recomputed_closure_cannot_hide_semantic_receipt_tampering(self) -> None:
        self.capture()
        payload = json.loads(self.capture_receipt.read_text())
        payload["markers"]["ordered"] = False
        payload["environment"]["carrick_environment"][
            "CARRICK_UNKNOWN_CONTROL"
        ] = "1"
        payload["closure"]["sha256"] = self.module._sha256_json(
            {key: value for key, value in payload.items() if key != "closure"}
        )
        self.capture_receipt.write_text(json.dumps(payload))
        with self.assertRaisesRegex(
            self.module.EvidenceError, "marker|environment|Carrick"
        ):
            self.module.validate_capture_receipt(
                self.capture_receipt, boundary=self.boundary
            )

    def test_recomputed_closure_rejects_independently_verified_fields(self) -> None:
        self.capture()
        original = json.loads(self.capture_receipt.read_text())
        cases = (
            ("environment", "effective_environment_sha256", "0" * 64),
            ("cleanup", "stdout_sha256", "0" * 64),
            ("dof", "segment", "__DATA"),
            ("dof", "size", original["dof"]["size"] + 1),
            ("dof", "otool_listing_sha256", "0" * 64),
        )
        for section, field, replacement in cases:
            with self.subTest(section=section, field=field):
                payload = json.loads(json.dumps(original))
                payload[section][field] = replacement
                if section == "environment":
                    environment = dict(payload["environment"])
                    environment.pop("sha256")
                    payload["environment"]["sha256"] = self.module._sha256_json(
                        environment
                    )
                payload["closure"]["sha256"] = self.module._sha256_json(
                    {
                        key: value
                        for key, value in payload.items()
                        if key != "closure"
                    }
                )
                self.capture_receipt.write_text(json.dumps(payload))
                with self.assertRaisesRegex(
                    self.module.EvidenceError,
                    f"{section}.*hash|hash.*{section}|DOF.*drifted",
                ):
                    self.module.validate_capture_receipt(
                        self.capture_receipt, boundary=self.boundary
                    )


class DTraceSourceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_capture_module()
        self.assertIsNotNone(self.module)
        self.script = (
            HERE.parent
            / "dtrace/native-translated-range-catalog.d"
        )
        self.source = self.script.read_text()

    def test_maintained_script_has_one_legacy_and_one_lifecycle_summary(self) -> None:
        contract = self.module.validate_dtrace_source(self.source)
        self.assertEqual(contract["schema2_summaries"], 1)
        self.assertEqual(contract["lifecycle_summaries"], 1)
        self.assertEqual(contract["self_bound_seconds"], 30)

    def test_static_contract_rejects_each_missing_lifecycle_provider(self) -> None:
        required = (
            "proc:::create",
            "proc:::exec",
            "proc:::exec-success",
            "proc:::exec-failure",
            "proc:::exit",
            "carrick*:::dsr-cache-lifecycle",
            "carrick*:::host-image-base",
            "carrick*:::host-image-catalog",
            "carrick*:::guest-image-base",
            "carrick*:::host-jit-range",
            "carrick*:::syscall-return",
            "carrick*:::guest-exit",
        )
        for provider in required:
            with self.subTest(provider=provider):
                mutated = (
                    self.source.replace(provider, "fixture:::removed")
                    + f"\n/* {provider} is not an executable clause */\n"
                )
                with self.assertRaisesRegex(
                    self.module.EvidenceError, "provider|probe"
                ):
                    self.module.validate_dtrace_source(mutated)

    def test_static_contract_rejects_duplicate_or_wrong_bound(self) -> None:
        with self.assertRaisesRegex(self.module.EvidenceError, "exactly one"):
            self.module.validate_dtrace_source(
                self.source
                + '\nprintf("TRANSLATED_LIFECYCLE_SUMMARY|schema=1|");\n'
            )
        with self.assertRaisesRegex(self.module.EvidenceError, "30 seconds"):
            self.module.validate_dtrace_source(
                self.source.replace("tick-30s", "tick-29s")
            )

    def test_static_contract_rejects_deleted_milestone_and_miskeyed_tuple(self) -> None:
        with self.assertRaisesRegex(
            self.module.EvidenceError, "milestone|child-exit|clause"
        ):
            self.module.validate_dtrace_source(
                self.source.replace(
                    "|kind=child-exit|", "|kind=fixture-child-exit|", 1
                )
            )

        keyed = (
            "catalog_live[pid, incarnation[pid],\n"
            "        image_generation[pid, incarnation[pid]],\n"
            "        runtime_epoch[pid, incarnation[pid]]]"
        )
        self.assertIn(keyed, self.source)
        miskeyed = self.source.replace(
            keyed,
            (
                "catalog_live[pid, incarnation[pid],\n"
                "        runtime_epoch[pid, incarnation[pid]]]"
            ),
            1,
        )
        with self.assertRaisesRegex(self.module.EvidenceError, "arity|identity|tuple"):
            self.module.validate_dtrace_source(miskeyed)

    def test_static_contract_binds_identity_slots_and_milestone_stage(self) -> None:
        keyed = (
            "catalog_live[pid, incarnation[pid],\n"
            "        image_generation[pid, incarnation[pid]],\n"
            "        runtime_epoch[pid, incarnation[pid]]]"
        )
        same_arity_wrong_identity = self.source.replace(
            keyed,
            (
                "catalog_live[pid, incarnation[pid],\n"
                "        runtime_epoch[pid, incarnation[pid]],\n"
                "        runtime_epoch[pid, incarnation[pid]]]"
            ),
            1,
        )
        self.assertNotEqual(same_arity_wrong_identity, self.source)
        with self.assertRaisesRegex(
            self.module.EvidenceError, "identity|generation|tuple"
        ):
            self.module.validate_dtrace_source(same_arity_wrong_identity)

        parent_ready = (
            "carrick*:::host-translated-range-ready\n"
            "/pid == $target && tracked[pid] &&\n"
            "    lifecycle_stage[pid, incarnation[pid]] == 3 &&"
        )
        wrong_stage = self.source.replace(
            parent_ready,
            parent_ready.replace("== 3", "== 99"),
            1,
        )
        self.assertNotEqual(wrong_stage, self.source)
        with self.assertRaisesRegex(
            self.module.EvidenceError, "parent-ready|milestone|stage"
        ):
            self.module.validate_dtrace_source(wrong_stage)

    def test_static_contract_requires_general_exec_and_early_metadata_guards(self) -> None:
        weak_exec = self.source.replace(
            "proc:::exec\n/tracked[pid]/",
            "proc:::exec\n/pid == lifecycle_child_pid && tracked[pid]/",
            1,
        )
        with self.assertRaisesRegex(self.module.EvidenceError, "exec|tracked owner"):
            self.module.validate_dtrace_source(weak_exec)

        weak_metadata = self.source.replace(
            "lifecycle_stage[pid, incarnation[pid]] >= 10",
            "lifecycle_stage[pid, incarnation[pid]] >= 11",
        )
        with self.assertRaisesRegex(self.module.EvidenceError, "metadata|reexec"):
            self.module.validate_dtrace_source(weak_metadata)

    def test_guest_exit_is_status_authority_and_nonzero_is_rejected(self) -> None:
        contract = self.module.validate_dtrace_source(self.source)
        self.assertEqual(contract["guest_exit_authority"], 1)
        weakened = self.source.replace("(int)arg1 != 0", "(int)arg1 == 0", 1)
        with self.assertRaisesRegex(
            self.module.EvidenceError, "guest-exit|nonzero|exit code"
        ):
            self.module.validate_dtrace_source(weakened)


if __name__ == "__main__":
    unittest.main()
