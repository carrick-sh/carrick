#!/usr/bin/env python3
"""Tests for the stable native DTrace target launcher."""

from __future__ import annotations

import io
import json
import os
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
