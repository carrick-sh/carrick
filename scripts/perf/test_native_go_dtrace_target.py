#!/usr/bin/env python3
"""Tests for the stable native DTrace target launcher."""

from __future__ import annotations

import base64
import io
import json
import os
import shlex
import sys
import unittest
from unittest import mock

import native_go_dtrace_target
from native_go_dtrace_target import _has_carrick_proctitle


class NativeGoDtraceTargetTests(unittest.TestCase):
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
                    "--trace-script",
                    "scripts/dtrace/native-pc-range-directional.d",
                    "--trace-output",
                    "target/perf/native-metadata-v3-v2.raw",
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
                    "--mechanism-profile",
                    "--run-id",
                    "metadata-v2-standalone-trace",
                    "--trace-script",
                    "scripts/dtrace/native-pc-range-directional.d",
                    "--trace-output",
                    "target/perf/native-metadata-v3-v2.raw",
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
            mock.patch("sys.stdout", output),
        ):
            self.assertEqual(native_go_dtrace_target.main(), 0)

        provenance_lines = output.getvalue().splitlines()
        self.assertEqual(len(provenance_lines), 1)
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
            ["-o", "target/perf/native-metadata-v3-v2.raw"],
        )
        self.assertEqual(captured_command[8], "-c")
        self.assertNotIn("'", captured_command[9])
        direct_run = shlex.split(captured_command[9])
        self.assertTrue(direct_run[0].endswith("target/release/carrick"))
        self.assertEqual(direct_run[1], "run")
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
        guest_script = base64.b64decode(payload).decode()
        self.assertIn("set -eu", guest_script)
        self.assertIn("echo BUILD_OK", guest_script)

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
        )
        self.assertEqual(command[:2], ["/tmp/carrick", "run"])
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
