#!/usr/bin/env python3
"""Tests for the stable native DTrace target launcher."""

from __future__ import annotations

import base64
import io
import json
import os
import pathlib
import shlex
import sys
import tempfile
import unittest
from unittest import mock

import native_go_build
import native_go_dtrace_target
from native_go_dtrace_target import _has_carrick_proctitle


class NativeGoDtraceTargetTests(unittest.TestCase):
    def binary_identity(self) -> dict[str, object]:
        return {
            "bytes": 1,
            "dof": {"address": 3, "offset": 4, "segment": "__TEXT", "size": 5},
            "entitlements": {"com.apple.security.hypervisor": True},
            "entitlements_sha256": "e" * 64,
            "macho_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            "path": str((native_go_dtrace_target.REPO / "target/release/carrick").resolve()),
            "sha256": "b" * 64,
            "text": {"fileoff": 0, "filesize": 10, "vmaddr": 0x100000000, "vmsize": 10},
        }

    def strict_raw(self) -> str:
        return "\n".join(
            (
                "PCPROFILE1|config|sample_hz=197",
                "PCPROFILE1|reset|pid=41|epoch=1",
                "PCPROFILE1|identity|pid=41|epoch=1|euid=501|egid=20",
                "PCPROFILE1|range|kind=private|pid=41|epoch=1|sequence=1|start=0x1000|end=0x2000",
                "PCPROFILE1|range|kind=shared|pid=41|epoch=1|sequence=2|start=0x4000|end=0x5000",
                "PCPROFILE1|host-range|pid=41|epoch=1|start=0x8000|end=0xa000",
                "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x1100|count=7",
                "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x4400|count=11",
                "PCPROFILE1|sample|kind=user|pid=41|epoch=1|pc=0x9000|count=5",
                "PCPROFILE1|sample|kind=kernel|pid=41|epoch=1|count=3",
                "PCKSTACK1|begin|pid=41|epoch=1|count=3",
                "kernel`vm_fault+0x10",
                "PCKSTACK1|end",
                "PCLEAF2|pid=41|epoch=1|pc=0x4400|module=unit.dylib|symbol=unit.dylib`block_4|count=11",
                "PCLEAF2|pid=41|epoch=1|pc=0x9000|module=carrick|symbol=carrick`host_leaf|count=5",
                "PCPROFILE1|completion|target_exit=1|timed_out=0",
            )
        )

    def run_standalone_fixture(
        self, raw: str, stdout: bytes, stderr: bytes, *, dtrace_status: int = 0
    ) -> tuple[int, pathlib.Path, tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory()
        raw_path = pathlib.Path(temporary.name) / "capture.raw"

        class CapturedProcess:
            returncode = dtrace_status

            def __init__(self, command, *, cwd, env, **kwargs):
                del cwd, env, kwargs
                output = pathlib.Path(command[command.index("-o") + 1])
                output.write_text(raw, encoding="utf-8")

            def communicate(self):
                return (
                    stdout,
                    b"TRACECHILD1|euid=501|egid=20|groups=12,20\n" + stderr,
                )

            def wait(self) -> int:
                return self.returncode

        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "native_go_dtrace_target.py",
                    "--variant",
                    "shared",
                    "--metadata-mode",
                    "v2",
                    "--run-id",
                    "capture-test",
                    "--pair-id",
                    "capture-pair",
                    "--pair-ordinal",
                    "1",
                    "--trace-script",
                    "scripts/dtrace/native-pc-range-directional.d",
                    "--trace-output",
                    str(raw_path),
                    "--trace-launcher",
                    "standalone",
                ],
            ),
            mock.patch.object(
                native_go_dtrace_target.subprocess,
                "Popen",
                side_effect=CapturedProcess,
            ),
            mock.patch.object(native_go_dtrace_target.os, "geteuid", return_value=501),
            mock.patch.object(native_go_dtrace_target.os, "getegid", return_value=20),
            mock.patch.object(
                native_go_dtrace_target.os, "getgroups", return_value=[20, 12]
            ),
            mock.patch.object(
                native_go_dtrace_target.native_pc_range_risk,
                "inspect_binary_identity",
                return_value=self.binary_identity(),
            ),
            mock.patch("sys.stdout", io.StringIO()),
            mock.patch("sys.stderr", io.StringIO()),
        ):
            result = native_go_dtrace_target.main()
        return result, raw_path, temporary

    def test_metadata_mode_routes_exact_control(self) -> None:
        mapped = native_go_dtrace_target.environment_for(metadata_mode="mapped")
        control = native_go_dtrace_target.environment_for(metadata_mode="v2")
        self.assertIsNone(mapped["CARRICK_DSR_SHARED_MAPPED_METADATA"])
        self.assertEqual(control["CARRICK_DSR_SHARED_MAPPED_METADATA"], "0")

    def test_cli_records_metadata_mode_in_target_provenance(self) -> None:
        class CompletedProcess:
            def __init__(self, _command, *, cwd, env):
                del cwd, env

            def wait(self) -> int:
                return 0

        output = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "native_go_dtrace_target.py",
                    "--variant",
                    "shared",
                    "--metadata-mode",
                    "v2",
                    "--run-id",
                    "metadata-v2-test",
                ],
            ),
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                native_go_dtrace_target.subprocess,
                "Popen",
                side_effect=CompletedProcess,
            ),
            mock.patch("sys.stdout", output),
        ):
            self.assertEqual(native_go_dtrace_target.main(), 0)

        line = output.getvalue().strip()
        prefix = "TARGET_PROVENANCE="
        self.assertTrue(line.startswith(prefix))
        provenance = json.loads(line.removeprefix(prefix))
        self.assertEqual(provenance["metadata_mode"], "v2")
        self.assertEqual(
            provenance["environment_overlay"][
                "CARRICK_DSR_SHARED_MAPPED_METADATA"
            ],
            "0",
        )

    def test_carrick_trace_mode_preserves_run_and_forwards_exact_controls(self) -> None:
        captured_command: list[str] = []

        class RecordingProcess:
            def __init__(self, command, *, cwd, env):
                del cwd, env
                captured_command.extend(command)

            def wait(self) -> int:
                return 0

        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "native_go_dtrace_target.py",
                    "--variant",
                    "shared",
                    "--metadata-mode",
                    "v2",
                    "--run-id",
                    "metadata-v2-trace",
                    "--pair-id",
                    "trace-pair",
                    "--pair-ordinal",
                    "1",
                    "--trace-script",
                    "scripts/dtrace/native-pc-range-directional.d",
                    "--trace-output",
                    "target/perf/native-metadata-v3-v2.raw",
                    "--trace-launcher",
                    "carrick-trace",
                ],
            ),
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                native_go_dtrace_target.subprocess,
                "Popen",
                side_effect=RecordingProcess,
            ),
        ):
            self.assertEqual(native_go_dtrace_target.main(), 0)

        separator = captured_command.index("--")
        trace_command = captured_command[:separator]
        run_command = captured_command[separator + 1 :]
        self.assertEqual(trace_command[1:3], ["trace", "--script"])
        self.assertIn(
            "scripts/dtrace/native-pc-range-directional.d", trace_command
        )
        self.assertIn("--trace-out", trace_command)
        self.assertIn(
            "target/perf/native-metadata-v3-v2.raw", trace_command
        )
        forwarded = {
            trace_command[index + 1]
            for index, value in enumerate(trace_command)
            if value == "--forward-env"
        }
        self.assertIn("CARRICK_RUN_ID=metadata-v2-trace", forwarded)
        self.assertIn("CARRICK_DSR_SHARED_TRANSLATION=1", forwarded)
        self.assertIn("CARRICK_DSR_DIRECT_BINDINGS=1", forwarded)
        self.assertIn("CARRICK_DSR_SHARED_MAPPED_METADATA=0", forwarded)
        self.assertEqual(run_command[0:3], ["run", "--exec-backend", "native"])
        self.assertIn("CARRICK_RUN_ID=metadata-v2-trace", run_command)

    def test_standalone_trace_targets_carrick_and_forwards_exact_controls(self) -> None:
        captured_command: list[str] = []
        output = io.StringIO()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        raw_path = pathlib.Path(temporary.name) / "standalone.raw"

        class RecordingProcess:
            returncode = 0

            def __init__(self, command, *, cwd, env, **kwargs):
                del cwd, env, kwargs
                captured_command.extend(command)

            def communicate(self) -> tuple[bytes, bytes]:
                raw_path.write_text(
                    NativeGoDtraceTargetTests().strict_raw(), encoding="utf-8"
                )
                return (
                    b"WORKLOAD_NS=123\nBUILD_OK\n",
                    b"TRACECHILD1|euid=501|egid=20|groups=12,20\nok\n",
                )

        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "native_go_dtrace_target.py",
                    "--variant",
                    "shared",
                    "--metadata-mode",
                    "v2",
                    "--mechanism-profile",
                    "--run-id",
                    "metadata-v2-standalone-trace",
                    "--pair-id",
                    "standalone-pair",
                    "--pair-ordinal",
                    "1",
                    "--trace-script",
                    "scripts/dtrace/native-pc-range-directional.d",
                    "--trace-output",
                    str(raw_path),
                    "--trace-launcher",
                    "standalone",
                ],
            ),
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                native_go_dtrace_target.subprocess,
                "Popen",
                side_effect=RecordingProcess,
            ),
            mock.patch.object(native_go_dtrace_target.os, "geteuid", return_value=501),
            mock.patch.object(native_go_dtrace_target.os, "getegid", return_value=20),
            mock.patch.object(
                native_go_dtrace_target.os, "getgroups", return_value=[20, 12]
            ),
            mock.patch.object(
                native_go_dtrace_target.native_pc_range_risk,
                "inspect_binary_identity",
                return_value=self.binary_identity(),
            ),
            mock.patch("sys.stdout", output),
        ):
            self.assertEqual(native_go_dtrace_target.main(), 0)

        provenance_lines = output.getvalue().splitlines()
        self.assertEqual(provenance_lines[-2:], ["WORKLOAD_NS=123", "BUILD_OK"])
        self.assertTrue(provenance_lines[0].startswith("TARGET_PROVENANCE="))
        self.assertEqual(
            captured_command[:6],
            [
                "sudo",
                "-n",
                "/usr/sbin/dtrace",
                "-q",
                "-s",
                "scripts/dtrace/native-pc-range-directional.d",
            ],
        )
        self.assertEqual(
            captured_command[6:8],
            ["-o", str(raw_path)],
        )
        self.assertEqual(captured_command[8], "-c")
        self.assertNotIn("'", captured_command[9])
        direct_run = shlex.split(captured_command[9])
        self.assertTrue(direct_run[0].endswith("target/release/carrick"))
        self.assertEqual(
            direct_run[1:11],
            [
                "__trace-child",
                "--trace-uid",
                "501",
                "--trace-gid",
                "20",
                "--trace-groups",
                "20,12",
                "--",
                "run",
                "--forward-env",
            ],
        )
        forwarded = {
            direct_run[index + 1]
            for index, value in enumerate(direct_run)
            if value == "--forward-env"
        }
        self.assertIn(
            "CARRICK_RUN_ID=metadata-v2-standalone-trace", forwarded
        )
        self.assertIn("CARRICK_DSR_SHARED_TRANSLATION=1", forwarded)
        self.assertIn("CARRICK_DSR_DIRECT_BINDINGS=1", forwarded)
        self.assertIn("CARRICK_DSR_SHARED_MAPPED_METADATA=0", forwarded)
        self.assertIn("CARRICK_DSR_PROFILE=1", forwarded)
        encoded_shell = direct_run[-1]
        self.assertFalse(any(character.isspace() for character in encoded_shell))
        prefix = "eval${IFS}$(printf${IFS}%s${IFS}"
        suffix = "|base64${IFS}-d)"
        self.assertTrue(encoded_shell.startswith(prefix))
        self.assertTrue(encoded_shell.endswith(suffix))
        payload = encoded_shell.removeprefix(prefix).removesuffix(suffix)
        self.assertEqual(base64.b64decode(payload), native_go_build.guest_script().encode())

        provenance = json.loads(
            provenance_lines[0].removeprefix("TARGET_PROVENANCE=")
        )
        self.assertEqual(
            provenance["expected_effective_identity"],
            {"egid": 20, "euid": 501, "supplementary_gids": [12, 20]},
        )

    def test_run_id_uses_the_established_conservative_capture_grammar(self) -> None:
        for accepted in ("a", "mapped-v2-directional", "A0-9"):
            self.assertEqual(
                native_go_dtrace_target.validate_run_id(accepted), accepted
            )
        for rejected in (
            "",
            "-leading",
            "has space",
            "has'quote",
            'has"quote',
            r"has\backslash",
            "has$dollar",
            "has;semicolon",
            "a" * 41,
        ):
            with self.subTest(run_id=rejected):
                with self.assertRaisesRegex(ValueError, "run ID"):
                    native_go_dtrace_target.validate_run_id(rejected)

    def test_direct_target_rejects_any_unencoded_dynamic_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "direct DTrace argv"):
            native_go_dtrace_target.standalone_dtrace_command(
                ["/tmp/carrick'bad", "run", "/bin/sh", "-c", "echo BUILD_OK"],
                run_id="safe-id",
                overlay={},
                trace_script=native_go_dtrace_target.pathlib.Path("trace.d"),
                trace_output=native_go_dtrace_target.pathlib.Path("trace.raw"),
            )

    def test_standalone_capture_fails_without_exact_build_marker(self) -> None:
        result, raw, temporary = self.run_standalone_fixture(
            self.strict_raw(), b"WORKLOAD_NS=123\n", b"ok\n"
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result, 2)
        receipt = json.loads(raw.with_suffix(".capture.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("BUILD_OK", receipt["failures"][0])

    def test_standalone_capture_fails_on_zero_usdt_provider_stream(self) -> None:
        result, raw, temporary = self.run_standalone_fixture(
            "PCPROFILE1|config|sample_hz=197\n"
            "PCPROFILE1|completion|target_exit=1|timed_out=0\n",
            b"WORKLOAD_NS=123\nBUILD_OK\n",
            b"ok\n",
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result, 2)
        self.assertFalse(raw.with_suffix(".json").exists())

    def test_standalone_capture_rejects_dtrace_notification_diagnostic(self) -> None:
        result, raw, temporary = self.run_standalone_fixture(
            self.strict_raw(),
            b"WORKLOAD_NS=123\nBUILD_OK\n",
            b"ok\nFailed to start process notifications for pid 7 (5)\n",
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result, 2)
        receipt = json.loads(raw.with_suffix(".capture.json").read_text())
        self.assertIn("DTrace diagnostics", " ".join(receipt["failures"]))

    def test_standalone_capture_writes_all_fail_closed_receipts_on_success(self) -> None:
        result, raw, temporary = self.run_standalone_fixture(
            self.strict_raw(),
            b"WORKLOAD_NS=123\nBUILD_OK\n",
            b"ok\n",
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result, 0)
        self.assertTrue(raw.with_suffix(".json").is_file())
        self.assertEqual(
            raw.with_suffix(".driver.out").read_bytes(),
            b"WORKLOAD_NS=123\nBUILD_OK\n",
        )
        self.assertEqual(
            raw.with_suffix(".driver.err").read_bytes(),
            b"TRACECHILD1|euid=501|egid=20|groups=12,20\nok\n",
        )
        receipt = json.loads(raw.with_suffix(".capture.json").read_text())
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["schema"], "carrick.native-go-dtrace-capture.v2")
        self.assertEqual(
            receipt["expected_effective_identity"],
            {"egid": 20, "euid": 501, "supplementary_gids": [12, 20]},
        )
        self.assertEqual(
            receipt["observed_effective_identity"],
            receipt["expected_effective_identity"],
        )
        self.assertEqual(
            receipt["pair"],
            {"arm": "control", "id": "capture-pair", "order": 0, "ordinal": 1},
        )
        self.assertTrue(receipt["natural_completion"])
        self.assertTrue(all(receipt["required_streams"].values()))
        self.assertEqual(
            receipt["binary"]["macho_uuid"],
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        )

    def test_standalone_capture_accepts_real_nativeperf1_mechanism_stream(self) -> None:
        result, _raw, temporary = self.run_standalone_fixture(
            self.strict_raw(),
            b"WORKLOAD_NS=123\nBUILD_OK\n",
            b"NATIVEPERF1|supervisor|self_cpu_ns=1|children_cpu_ns=2\nok\n",
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result, 0)

    def test_direct_target_forwards_exact_controls(self) -> None:
        command = native_go_dtrace_target.direct_carrick_command(
            ["/tmp/carrick", "run", "--exec-backend", "native"],
            run_id="metadata-v2-exec",
            overlay={
                "CARRICK_DSR_SHARED_TRANSLATION": "1",
                "CARRICK_DSR_SHARED_MAPPED_METADATA": "0",
                "CARRICK_DSR_PROFILE": "1",
                "CARRICK_DSR_SHARED_MANIFEST_ARC": None,
            },
            identity=native_go_dtrace_target.TraceIdentity(501, 20, (20, 12)),
        )
        self.assertEqual(
            command[:10],
            [
                "/tmp/carrick",
                "__trace-child",
                "--trace-uid",
                "501",
                "--trace-gid",
                "20",
                "--trace-groups",
                "20,12",
                "--",
                "run",
            ],
        )
        forwarded = {
            command[index + 1]
            for index, value in enumerate(command)
            if value == "--forward-env"
        }
        self.assertEqual(
            forwarded,
            {
                "CARRICK_RUN_ID=metadata-v2-exec",
                "CARRICK_DSR_SHARED_TRANSLATION=1",
                "CARRICK_DSR_SHARED_MAPPED_METADATA=0",
                "CARRICK_DSR_PROFILE=1",
            },
        )
        self.assertEqual(command[-2:], ["--exec-backend", "native"])

    def test_entries_recovery_wire_passes_exact_opt_out_to_child(self) -> None:
        captured_environment: dict[str, str] = {}

        class RecordingProcess:
            def __init__(self, _command, *, cwd, env):
                del cwd
                captured_environment.update(env)

            def wait(self) -> int:
                return 0

        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "native_go_dtrace_target.py",
                    "--variant",
                    "shared",
                    "--recovery-wire",
                    "entries",
                    "--run-id",
                    "recovery-entries-test",
                ],
            ),
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                native_go_dtrace_target.subprocess,
                "Popen",
                side_effect=RecordingProcess,
            ),
        ):
            try:
                result = native_go_dtrace_target.main()
            except SystemExit as error:
                result = int(error.code)

        self.assertEqual(result, 0)
        self.assertEqual(
            captured_environment["CARRICK_DSR_SHARED_RECOVERY_RUNS"],
            "0",
        )

    def test_traceable_child_requires_the_exact_run_id_proctitle(self) -> None:
        self.assertTrue(
            _has_carrick_proctitle(
                "carrick:nperf-source-trace: /bin/sh -c go build",
                "nperf-source-trace",
            )
        )
        self.assertFalse(
            _has_carrick_proctitle(
                "/path/to/carrick run -e CARRICK_RUN_ID=nperf-source-trace",
                "nperf-source-trace",
            )
        )
        self.assertFalse(
            _has_carrick_proctitle(
                "carrick:nperf-source-trace-other: /bin/sh",
                "nperf-source-trace",
            )
        )


if __name__ == "__main__":
    unittest.main()
