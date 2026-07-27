#!/usr/bin/env python3

import contextlib
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_go_build


class NativeGoBuildTest(unittest.TestCase):
    def install_fake_docker(
        self, architecture: str
    ) -> tuple[pathlib.Path, pathlib.Path]:
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        log = directory / "docker.log"
        executable = directory / "docker"
        executable.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "image" ]; then\n'
            f"  printf '\"{architecture}\"\\n'\n"
            "  printf '\"sha256:fake-image\"\\n'\n"
            "  printf "
            "'[\"localhost:5005/carrick-go-conformance@sha256:fake-digest\"]\\n'\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = "run" ]; then\n'
            "  echo BUILD_OK\n"
            "  exit 0\n"
            "fi\n"
            'printf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"\n'
        )
        executable.chmod(0o755)
        old_path = os.environ.get("PATH")
        old_log = os.environ.get("FAKE_DOCKER_LOG")
        os.environ["PATH"] = f"{directory}:{old_path or ''}"
        os.environ["FAKE_DOCKER_LOG"] = str(log)

        def restore_environment():
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path
            if old_log is None:
                os.environ.pop("FAKE_DOCKER_LOG", None)
            else:
                os.environ["FAKE_DOCKER_LOG"] = old_log

        self.addCleanup(restore_environment)
        return directory, log

    def test_command_is_native_and_cold_cache(self):
        cmd = native_go_build.build_carrick_command(
            pathlib.Path("/repo"), "perf-test-1"
        )

        rendered = "\0".join(cmd)
        self.assertIn("--exec-backend\0native", rendered)
        self.assertIn('GOCACHE="/tmp/gc-$CARRICK_RUN_ID"', rendered)
        self.assertNotIn("docker", rendered.lower())

    def test_five_sample_median_is_middle_value(self):
        self.assertEqual(native_go_build.median_ms([21, 18, 30, 19, 20]), 20)

    def test_carrick_and_docker_share_guest_script(self):
        repo = pathlib.Path("/repo")
        carrick = native_go_build.build_command(repo, "carrick", "run-c")
        docker = native_go_build.build_command(repo, "docker", "run-d")

        self.assertEqual(carrick[-1], docker[-1])

    def test_docker_command_requires_native_arm64(self):
        docker = native_go_build.build_command(
            pathlib.Path("/repo"), "docker", "run-d"
        )

        rendered = "\0".join(docker)
        self.assertIn("--platform\0linux/arm64", rendered)
        self.assertNotIn("--exec-backend", docker)

    def test_both_mode_is_two_ordered_phases(self):
        self.assertEqual(
            native_go_build.requested_engines("both"),
            ("carrick", "docker"),
        )

    def test_ratio_uses_phase_medians(self):
        self.assertAlmostEqual(
            native_go_build.carrick_over_docker_ratio(
                [20, 19, 21],
                [2, 1, 3],
            ),
            10.0,
        )

    def test_docker_phase_rejects_non_arm64_image(self):
        self.install_fake_docker("amd64")

        with self.assertRaisesRegex(RuntimeError, "arm64"):
            native_go_build.validate_docker_image()

    def test_docker_image_provenance_records_identity(self):
        self.install_fake_docker("arm64")

        provenance = native_go_build.docker_image_provenance()

        self.assertEqual(
            provenance,
            {
                "architecture": "arm64",
                "id": "sha256:fake-image",
                "repo_digests": [
                    "localhost:5005/carrick-go-conformance@sha256:fake-digest"
                ],
            },
        )

    def test_docker_sample_cleans_only_its_named_container(self):
        directory, log = self.install_fake_docker("arm64")

        sample = native_go_build.run_sample(
            directory,
            "docker",
            index=1,
            timeout_seconds=5,
        )

        self.assertEqual(log.read_text().splitlines(), [f"rm -f {sample['run_id']}"])

    def test_sample_can_retain_complete_captured_output(self):
        directory, _ = self.install_fake_docker("arm64")
        captured = directory / "profile" / "docker-1.log"

        native_go_build.run_sample(
            directory,
            "docker",
            index=1,
            timeout_seconds=5,
            captured_output=captured,
        )

        self.assertEqual(captured.read_text(), "BUILD_OK\n")

    def test_phase_summary_keeps_engine_boundaries(self):
        summary = native_go_build.summarize_phases(
            {
                "carrick": [
                    {"elapsed_ms": 20},
                    {"elapsed_ms": 18},
                    {"elapsed_ms": 19},
                ],
                "docker": [
                    {"elapsed_ms": 2},
                    {"elapsed_ms": 1},
                    {"elapsed_ms": 3},
                ],
            }
        )

        self.assertEqual(summary["carrick"]["median_ms"], 19)
        self.assertEqual(summary["docker"]["median_ms"], 2)
        self.assertEqual(summary["carrick"]["sample_count"], 3)
        self.assertEqual(summary["docker"]["sample_count"], 3)

    def test_docker_cli_writes_v2_phase_artifact(self):
        directory, _ = self.install_fake_docker("arm64")
        output = directory / "result.json"

        with contextlib.redirect_stdout(io.StringIO()):
            return_code = native_go_build.main(
                [
                    "--engine",
                    "docker",
                    "--samples",
                    "1",
                    "--allow-busy",
                    "--output",
                    str(output),
                ]
            )

        payload = json.loads(output.read_text())
        self.assertEqual(return_code, 0)
        self.assertEqual(payload["schema"], "carrick.native-go-build.v2")
        self.assertEqual(list(payload["phases"]), ["docker"])
        self.assertEqual(payload["phases"]["docker"]["sample_count"], 1)
        self.assertNotIn("ratio", payload)


if __name__ == "__main__":
    unittest.main()
