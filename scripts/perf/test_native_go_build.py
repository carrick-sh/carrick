#!/usr/bin/env python3

import contextlib
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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
            "'[\"localhost:5005/carrick-go-conformance@sha256:"
            + "4" * 64
            + "\"]\\n'\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = "run" ]; then\n'
            "  echo WORKLOAD_NS=1200000000\n"
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

    def test_carrick_command_forwards_one_auditable_insecure_registry(self):
        image = (
            "localhost:5005/carrick-go-conformance@sha256:" + "4" * 64
        )
        transport = native_go_build.RegistryTransport(
            registry="localhost:5005",
            insecure=True,
        )

        command = native_go_build.build_command(
            pathlib.Path("/repo"),
            "carrick",
            "run-c",
            binary=pathlib.Path("/immutable/carrick"),
            image=image,
            registry_transport=transport,
        )

        self.assertEqual(
            command,
            [
                "/immutable/carrick",
                "run",
                "--exec-backend",
                "native",
                "--forward-env",
                "CARRICK_INSECURE_REGISTRIES=localhost:5005",
                "-e",
                "CARRICK_RUN_ID=run-c",
                "-w",
                "/tmp",
                image,
                "/bin/sh",
                "-c",
                native_go_build.guest_script(),
            ],
        )
        self.assertEqual(command.count("--forward-env"), 1)

    def test_five_sample_median_is_middle_value(self):
        self.assertEqual(native_go_build.median_ms([21, 18, 30, 19, 20]), 20)

    def test_carrick_and_docker_share_guest_script(self):
        repo = pathlib.Path("/repo")
        carrick = native_go_build.build_command(repo, "carrick", "run-c")
        docker = native_go_build.build_command(repo, "docker", "run-d")

        self.assertEqual(carrick[-1], docker[-1])

    def test_compatibility_command_uses_harness_binary_without_override(self):
        repo = pathlib.Path("/harness")

        command = native_go_build.build_command(repo, "carrick", "run-c")

        self.assertEqual(command[0], "/harness/target/release/carrick")

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

    def test_atomic_json_exclusive_create_and_replaces_sync_directory(self):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        output = directory / "campaign.json"
        sync_modes = []

        def record_sync(descriptor):
            sync_modes.append(os.fstat(descriptor).st_mode)

        with mock.patch.object(
            native_go_build.os,
            "fsync",
            side_effect=record_sync,
        ):
            native_go_build.write_json_atomic(
                output,
                {"generation": 1},
                exclusive=True,
            )
            native_go_build.write_json_atomic(output, {"generation": 2})

        self.assertEqual(json.loads(output.read_text()), {"generation": 2})
        self.assertEqual(
            sum(stat.S_ISREG(mode) for mode in sync_modes),
            2,
        )
        self.assertEqual(
            sum(stat.S_ISDIR(mode) for mode in sync_modes),
            2,
        )
        with self.assertRaises(FileExistsError):
            native_go_build.write_json_atomic(
                output,
                {"generation": 3},
                exclusive=True,
            )
        self.assertEqual(json.loads(output.read_text()), {"generation": 2})

    def test_atomic_json_exclusive_create_rejects_temp_name_substitution(self):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        output = directory / "campaign.json"
        foreign = b'{"attacker":true}\n'
        real_link = os.link
        swapped_name = None

        def substitute_before_link(
            source,
            destination,
            *,
            src_dir_fd,
            dst_dir_fd,
        ):
            nonlocal swapped_name
            swapped_name = source
            os.unlink(source, dir_fd=src_dir_fd)
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            try:
                os.write(descriptor, foreign)
            finally:
                os.close(descriptor)
            return real_link(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        with (
            mock.patch.object(
                native_go_build.os,
                "link",
                side_effect=substitute_before_link,
            ),
            self.assertRaisesRegex(RuntimeError, "identity"),
        ):
            native_go_build.write_json_atomic(
                output,
                {"accepted": True},
                exclusive=True,
            )

        self.assertIsNotNone(swapped_name)
        self.assertEqual(output.read_bytes(), foreign)
        self.assertEqual((directory / swapped_name).read_bytes(), foreign)

    def test_atomic_json_replace_rejects_temp_name_substitution(self):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        output = directory / "campaign.json"
        output.write_text('{"generation":0}\n')
        foreign = b'{"attacker":true}\n'
        real_replace = os.replace

        def substitute_before_replace(
            source,
            destination,
            *,
            src_dir_fd,
            dst_dir_fd,
        ):
            os.unlink(source, dir_fd=src_dir_fd)
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            try:
                os.write(descriptor, foreign)
            finally:
                os.close(descriptor)
            return real_replace(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        with (
            mock.patch.object(
                native_go_build.os,
                "replace",
                side_effect=substitute_before_replace,
            ),
            self.assertRaisesRegex(RuntimeError, "identity"),
        ):
            native_go_build.write_json_atomic(
                output,
                {"generation": 1},
            )

        self.assertEqual(output.read_bytes(), foreign)

    def test_owned_temp_cleanup_tolerates_concurrent_name_disappearance(self):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        temporary = directory / ".campaign.json.tmp"
        temporary.write_text("{}\n")
        directory_descriptor = os.open(directory, os.O_RDONLY)
        temporary_descriptor = os.open(temporary, os.O_RDONLY)
        self.addCleanup(os.close, directory_descriptor)
        self.addCleanup(os.close, temporary_descriptor)

        with mock.patch.object(
            native_go_build.os,
            "unlink",
            side_effect=FileNotFoundError,
        ):
            native_go_build._unlink_name_if_owned(
                directory_descriptor,
                temporary.name,
                temporary_descriptor,
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
                    "localhost:5005/carrick-go-conformance@sha256:"
                    + "4" * 64
                ],
            },
        )

    def test_docker_census_ignores_registry_but_rejects_real_oracle(self):
        listing = subprocess.CompletedProcess(
            ["docker", "ps"],
            0,
            (
                "aaa carrick-registry-5050 registry:2\n"
                "bbb native-go-build-oracle "
                "localhost:5005/carrick-go-conformance:1.24\n"
                "ccc unrelated redis:7\n"
            ),
            "",
        )
        with mock.patch.object(
            native_go_build.subprocess,
            "run",
            return_value=listing,
        ):
            oracles = native_go_build.running_docker_oracles()

        self.assertEqual(
            oracles,
            [
                "bbb native-go-build-oracle "
                "localhost:5005/carrick-go-conformance:1.24"
            ],
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

        self.assertEqual(
            captured.read_text(), "WORKLOAD_NS=1200000000\nBUILD_OK\n"
        )

    def test_explicit_sample_identity_binds_command_and_provenance(self):
        harness, _ = self.install_fake_docker("arm64")
        subprocess.run(
            ["git", "init", "-q"], cwd=harness, check=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=harness,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Native Go Build Test"],
            cwd=harness,
            check=True,
        )
        (harness / "README").write_text("fixture\n")
        subprocess.run(["git", "add", "-A"], cwd=harness, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "fixture"], cwd=harness, check=True
        )
        binary = pathlib.Path("/immutable/A/carrick")
        image = "localhost:5005/carrick-go-conformance:immutable-a"
        transport = native_go_build.RegistryTransport(
            registry="localhost:5005",
            insecure=True,
        )
        transport_evidence = {
            "schema": "carrick.registry-transport.v1",
            "registry": "localhost:5005",
            "protocol": "http",
            "forward_env": "CARRICK_INSECURE_REGISTRIES=localhost:5005",
        }
        default_binary = harness / "target/release/carrick"
        original_run = native_go_build.subprocess.run
        workload_environments = []

        def run_workload_or_real(*args, **kwargs):
            command = args[0]
            if command[0] == str(binary.resolve()):
                workload_environments.append(dict(kwargs["env"]))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "WORKLOAD_NS=1200000000\nBUILD_OK\n",
                    "",
                )
            return original_run(*args, **kwargs)

        def hash_explicit_binary(path):
            self.assertNotEqual(path, default_binary)
            self.assertEqual(path, binary.resolve())
            return "a" * 64

        with (
            mock.patch.object(
                native_go_build, "foreign_workload_census", return_value=[]
            ),
            mock.patch.object(
                native_go_build, "running_docker_oracles", return_value=[]
            ),
            mock.patch.object(native_go_build, "sha256_file", side_effect=hash_explicit_binary),
            mock.patch.object(native_go_build.subprocess, "run", side_effect=run_workload_or_real),
            mock.patch.object(
                native_go_build,
                "carrick_cleanup",
                return_value={"status": 0, "stdout": "", "stderr": ""},
            ),
        ):
            sample = native_go_build.run_sample(
                harness,
                "carrick",
                index=1,
                timeout_seconds=5,
                binary=binary,
                image=image,
                registry_transport=transport,
                current_run_id="run-c1",
            )

        self.assertEqual(sample["run_id"], "run-c1")
        self.assertEqual(sample["command"]["argv"][0], str(binary.resolve()))
        self.assertEqual(sample["command"]["argv"][4:6], [
            "--forward-env",
            "CARRICK_INSECURE_REGISTRIES=localhost:5005",
        ])
        self.assertEqual(sample["command"]["argv"][10], image)
        self.assertEqual(sample["registry_transport"], transport_evidence)
        self.assertEqual(sample["binary_path"], str(binary.resolve()))
        self.assertEqual(sample["binary_sha256"], "a" * 64)
        self.assertEqual(len(workload_environments), 1)
        self.assertNotIn(
            "CARRICK_INSECURE_REGISTRIES",
            workload_environments[0],
        )
        for provenance in (
            sample["provenance"]["pre"],
            sample["provenance"]["post"],
        ):
            self.assertEqual(provenance["binary_path"], str(binary.resolve()))
            self.assertEqual(provenance["binary_sha256"], "a" * 64)
            self.assertEqual(provenance["image_ref"], image)
            self.assertEqual(
                provenance["registry_transport"],
                transport_evidence,
            )

    def test_timeout_becomes_complete_sample_evidence_after_cleanup(self):
        directory, _ = self.install_fake_docker("arm64")
        captured = directory / "profile" / "docker-1.log"
        binary = directory / "immutable-arm" / "carrick"
        binary.parent.mkdir()
        binary.write_bytes(b"immutable arm\n")
        run_id = "native-go-build-carrick-123-456-1"
        timeout = subprocess.TimeoutExpired(
            [str(binary), "run"],
            5,
            output="partial stdout\n",
            stderr="partial stderr\n",
        )
        pre = {"stage": "pre", "binary_sha256": "a" * 64}
        post = {"stage": "post", "binary_sha256": "a" * 64}
        cleanup_evidence = {
            "status": 0,
            "stdout": "cleanup stdout\n",
            "stderr": "",
        }
        diagnostics_evidence = {
            "status": 0,
            "stdout": "snapshot complete\n",
            "stderr": "",
            "out_dir": str(directory / "target" / "perf" / "lldb-timeouts"),
        }
        timeout_order = []

        def capture_timeout(*_args):
            timeout_order.append("diagnostics")
            return diagnostics_evidence

        def cleanup_timeout(*_args):
            timeout_order.append("cleanup")
            return cleanup_evidence

        with (
            mock.patch.object(native_go_build.os, "getpid", return_value=123),
            mock.patch.object(native_go_build.time, "time_ns", return_value=456),
            mock.patch.object(
                native_go_build,
                "repository_is_git",
                return_value=True,
            ),
            mock.patch.object(
                native_go_build,
                "sample_provenance",
                side_effect=(pre, post),
            ),
            mock.patch.object(
                native_go_build.subprocess, "run", side_effect=timeout
            ),
            mock.patch.object(
                native_go_build,
                "carrick_timeout_diagnostics",
                create=True,
                side_effect=capture_timeout,
            ) as diagnostics,
            mock.patch.object(
                native_go_build,
                "carrick_cleanup",
                side_effect=cleanup_timeout,
            ) as cleanup,
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "carrick",
                index=1,
                timeout_seconds=5,
                captured_output=captured,
                binary=binary,
                current_run_id=run_id,
            )

        self.assertEqual(captured.read_text(), "partial stdout\npartial stderr\n")
        diagnostics.assert_called_once_with(directory, binary.resolve(), run_id)
        cleanup.assert_called_once_with(directory, run_id)
        self.assertEqual(timeout_order, ["diagnostics", "cleanup"])
        row = caught.exception.sample
        self.assertEqual(row["run_id"], run_id)
        self.assertEqual(row["command"]["argv"][0], str(binary.resolve()))
        self.assertIsNone(row["command"]["status"])
        self.assertIsNone(row["return_code"])
        self.assertTrue(row["timed_out"])
        self.assertFalse(row["build_ok"])
        self.assertEqual(row["stdout"], "partial stdout\n")
        self.assertEqual(row["stderr"], "partial stderr\n")
        self.assertEqual(row["timeout_diagnostics"], diagnostics_evidence)
        self.assertEqual(row["cleanup"], cleanup_evidence)
        self.assertEqual(row["provenance"], {"pre": pre, "post": post})
        self.assertGreaterEqual(row["elapsed_ms"], 0)
        self.assertIn("cpu_user_s", row)
        self.assertIn("cpu_sys_s", row)
        self.assertIn("cpu_s", row)

    def test_timeout_normalizes_cleanup_launch_failure_without_masking_sample(self):
        directory, _ = self.install_fake_docker("arm64")
        timeout = subprocess.TimeoutExpired(
            ["docker", "run"],
            5,
            output=b"partial stdout\n",
            stderr=b"partial stderr\n",
        )
        cleanup_timeout = subprocess.TimeoutExpired(["docker", "rm"], 30)

        with (
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                side_effect=timeout,
            ),
            mock.patch.object(
                native_go_build,
                "docker_cleanup",
                side_effect=cleanup_timeout,
            ),
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "docker",
                index=1,
                timeout_seconds=5,
            )

        row = caught.exception.sample
        self.assertTrue(row["timed_out"])
        self.assertEqual(row["stdout"], "partial stdout\n")
        self.assertEqual(row["stderr"], "partial stderr\n")
        self.assertEqual(row["cleanup"]["status"], 125)
        self.assertIn("cleanup launch failed", row["cleanup"]["stderr"])

    def test_timeout_lldb_snapshot_has_an_exact_programmatic_opt_out(self):
        directory, _ = self.install_fake_docker("arm64")
        binary = directory / "immutable-arm" / "carrick"
        binary.parent.mkdir()
        binary.write_bytes(b"immutable arm\n")
        timeout = subprocess.TimeoutExpired([str(binary), "run"], 5)
        cleanup_evidence = {"status": 0, "stdout": "", "stderr": ""}

        with (
            mock.patch.object(
                native_go_build,
                "repository_is_git",
                return_value=False,
            ),
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                side_effect=timeout,
            ),
            mock.patch.object(
                native_go_build,
                "carrick_timeout_diagnostics",
            ) as diagnostics,
            mock.patch.object(
                native_go_build,
                "carrick_cleanup",
                return_value=cleanup_evidence,
            ),
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "carrick",
                index=1,
                timeout_seconds=5,
                binary=binary,
                current_run_id="native-timeout-opt-out",
                capture_timeout_diagnostics=False,
            )

        diagnostics.assert_not_called()
        self.assertIsNone(caught.exception.sample["timeout_diagnostics"])

    def test_non_timeout_execution_exception_retains_current_sample_evidence(self):
        directory, _ = self.install_fake_docker("arm64")
        execution_error = UnicodeDecodeError(
            "utf-8",
            b"\xff",
            0,
            1,
            "invalid start byte",
        )
        cleanup_evidence = {
            "status": 0,
            "stdout": "cleanup stdout\n",
            "stderr": "",
        }

        with (
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                side_effect=execution_error,
            ),
            mock.patch.object(
                native_go_build,
                "docker_cleanup",
                return_value=cleanup_evidence,
            ),
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "docker",
                index=1,
                timeout_seconds=5,
                current_run_id="execution-error-run",
            )

        row = caught.exception.sample
        self.assertEqual(row["run_id"], "execution-error-run")
        self.assertIsNone(row["return_code"])
        self.assertFalse(row["timed_out"])
        self.assertFalse(row["build_ok"])
        self.assertEqual(row["stdout"], "")
        self.assertEqual(row["stderr"], "")
        self.assertEqual(row["cleanup"], cleanup_evidence)
        self.assertEqual(
            row["execution_error"],
            {
                "type": "UnicodeDecodeError",
                "message": str(execution_error),
            },
        )

    def test_captured_output_exception_retains_current_sample_evidence(self):
        directory, _ = self.install_fake_docker("arm64")
        captured = directory / "profile" / "docker-1.log"
        result = subprocess.CompletedProcess(
            ["docker", "run"],
            0,
            "WORKLOAD_NS=1200000000\nBUILD_OK\n",
            "",
        )
        capture_error = OSError("injected capture write failure")

        with (
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                return_value=result,
            ),
            mock.patch.object(
                native_go_build,
                "docker_cleanup",
                return_value={"status": 0, "stdout": "", "stderr": ""},
            ),
            mock.patch.object(
                pathlib.Path,
                "write_text",
                side_effect=capture_error,
            ),
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "docker",
                index=1,
                timeout_seconds=5,
                captured_output=captured,
                current_run_id="capture-error-run",
            )

        row = caught.exception.sample
        self.assertEqual(row["run_id"], "capture-error-run")
        self.assertEqual(row["return_code"], 0)
        self.assertTrue(row["build_ok"])
        self.assertEqual(
            row["capture_error"],
            {
                "type": "OSError",
                "message": str(capture_error),
            },
        )

    def test_cleanup_failure_does_not_suppress_failed_sample_capture(self):
        directory, _ = self.install_fake_docker("arm64")
        captured = directory / "profile" / "docker-1.log"
        run_id = "native-go-build-docker-123-456-1"
        result = subprocess.CompletedProcess(
            ["docker", "run"], 1, "sample stdout\n", "sample stderr\n"
        )

        with (
            mock.patch.object(native_go_build.os, "getpid", return_value=123),
            mock.patch.object(native_go_build.time, "time_ns", return_value=456),
            mock.patch.object(native_go_build.subprocess, "run", return_value=result),
            mock.patch.object(
                native_go_build,
                "docker_cleanup",
                side_effect=subprocess.TimeoutExpired(["docker", "rm"], 30),
            ) as cleanup,
            self.assertRaisesRegex(RuntimeError, "go-build sample 1 failed"),
        ):
            native_go_build.run_sample(
                directory,
                "docker",
                index=1,
                timeout_seconds=5,
                captured_output=captured,
            )

        self.assertEqual(captured.read_text(), "sample stdout\nsample stderr\n")
        cleanup.assert_called_once_with(run_id)

    def test_failed_current_sample_retains_separate_streams_and_cleanup(self):
        directory, _ = self.install_fake_docker("arm64")
        result = subprocess.CompletedProcess(
            ["docker", "run"],
            0,
            "BUILD_OK\nsample stdout\n",
            "sample stderr\n",
        )
        cleanup = {
            "status": 3,
            "stdout": "cleanup stdout\n",
            "stderr": "cleanup stderr\n",
        }
        with (
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                return_value=result,
            ),
            mock.patch.object(
                native_go_build,
                "docker_cleanup",
                return_value=cleanup,
            ),
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "docker",
                index=1,
                timeout_seconds=5,
            )

        row = caught.exception.sample
        self.assertEqual(row["stdout"], "BUILD_OK\nsample stdout\n")
        self.assertEqual(row["stderr"], "sample stderr\n")
        self.assertEqual(row["command"]["status"], 0)
        self.assertEqual(row["cleanup"], cleanup)

    def test_post_provenance_drift_retains_both_snapshots_in_failed_sample(self):
        directory, _ = self.install_fake_docker("arm64")
        binary = directory / "arm" / "carrick"
        binary.parent.mkdir()
        binary.write_bytes(b"arm\n")
        result = subprocess.CompletedProcess(
            [str(binary), "run"],
            0,
            "WORKLOAD_NS=1200000000\nBUILD_OK\n",
            "",
        )
        pre = {"binary_sha256": "a" * 64}
        post = {"binary_sha256": "b" * 64}

        with (
            mock.patch.object(
                native_go_build,
                "repository_is_git",
                return_value=True,
            ),
            mock.patch.object(
                native_go_build,
                "sample_provenance",
                side_effect=(pre, post),
            ),
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                return_value=result,
            ),
            mock.patch.object(
                native_go_build,
                "carrick_cleanup",
                return_value={"status": 0, "stdout": "", "stderr": ""},
            ),
            self.assertRaises(native_go_build.SampleEvidenceError) as caught,
        ):
            native_go_build.run_sample(
                directory,
                "carrick",
                index=1,
                timeout_seconds=5,
                binary=binary,
            )

        self.assertIn("provenance drifted", str(caught.exception))
        self.assertEqual(
            caught.exception.sample["provenance"],
            {"pre": pre, "post": post},
        )

    def test_phase_names_each_captured_output_by_engine_and_sample(self):
        directory, _ = self.install_fake_docker("arm64")
        captures = directory / "profile"

        with mock.patch.object(native_go_build, "run_sample", return_value={}) as run:
            native_go_build.run_phase(
                directory,
                "carrick",
                samples=2,
                timeout_seconds=5,
                captured_output_dir=captures,
            )

        self.assertEqual(
            [call.args[4] for call in run.call_args_list],
            [captures / "carrick-1.log", captures / "carrick-2.log"],
        )

    def test_phase_summary_keeps_engine_boundaries(self):
        summary = native_go_build.summarize_phases(
            {
                "carrick": [
                    {"elapsed_ms": 20, "workload_ms": 15},
                    {"elapsed_ms": 18, "workload_ms": 13},
                    {"elapsed_ms": 19, "workload_ms": 14},
                ],
                "docker": [
                    {"elapsed_ms": 2, "workload_ms": 1},
                    {"elapsed_ms": 1, "workload_ms": 1},
                    {"elapsed_ms": 3, "workload_ms": 2},
                ],
            }
        )

        self.assertEqual(summary["carrick"]["median_ms"], 19)
        self.assertEqual(summary["docker"]["median_ms"], 2)
        self.assertEqual(summary["carrick"]["sample_count"], 3)
        self.assertEqual(summary["docker"]["sample_count"], 3)

    def test_guest_script_brackets_the_workload_window(self):
        script = native_go_build.guest_script()

        self.assertEqual(script.count("date +%s%N"), 2)
        start = script.index("date +%s%N")
        build = script.index("go build")
        end = script.rindex("date +%s%N")
        marker = script.index("WORKLOAD_NS=")
        self.assertLess(start, build)
        self.assertLess(build, end)
        self.assertLess(end, marker)
        self.assertLess(marker, script.index("BUILD_OK"))

    def test_workload_window_requires_exactly_one_positive_marker(self):
        self.assertEqual(
            native_go_build.workload_ns_from_stdout(
                "hello\nWORKLOAD_NS=1500000000\nBUILD_OK\n"
            ),
            1_500_000_000,
        )
        for stdout in (
            "BUILD_OK\n",
            "WORKLOAD_NS=1\nWORKLOAD_NS=2\nBUILD_OK\n",
            "WORKLOAD_NS=12N34\nBUILD_OK\n",
            "WORKLOAD_NS=0\nBUILD_OK\n",
            "WORKLOAD_NS=-5\nBUILD_OK\n",
        ):
            with self.assertRaises(ValueError):
                native_go_build.workload_ns_from_stdout(stdout)

    def test_census_skips_own_ancestors_but_keeps_foreign_matches(self):
        rows = [
            (10, "/bin/zsh -c eval 'python3 scripts/perf/native_go_build.py'"),
            (20, "python3 scripts/perf/native_go_build.py --engine both"),
            (30, "target/release/carrick run --exec-backend native sh"),
            (
                40,
                "python3 scripts/perf/native_go_build_abba.py run "
                "--output /tmp/other.json",
            ),
        ]

        foreign = native_go_build.foreign_rows(
            rows, own_pid=20, ancestor_pids={10, 1}
        )

        self.assertEqual(len(foreign), 2)
        self.assertIn("pid=30", foreign[0])
        self.assertIn("pid=40", foreign[1])

    def test_census_uses_delimited_titles_and_receipt_binaries(self):
        rows = [
            (101, "carrick:native-go-build-carrick-old-1:go"),
            (102, "/tmp/carrick:native-go-build-carrick-old-2:compile"),
            (103, "carrick:run-c1: go"),
            (104, "carrick:run-c10: go"),
            (105, "/var/tmp/native-m1/arm/carrick run --exec-backend native"),
            (106, "python3 -c 'print(\"carrick is just text\")'"),
            (107, "python3 scripts/perf/native_go_build.py --engine carrick"),
            (108, "/Volumes/carrick/target/release/carrick run native"),
            (109, "./target/release/carrick run native"),
            (110, "/Volumes/carrick/scripts/perf/native_go_build.py --engine carrick"),
            (111, "./scripts/perf/native_go_build.py --engine carrick"),
            (
                112,
                "/var/tmp/native m1/arm/carrick run --exec-backend native",
            ),
        ]

        foreign = native_go_build.foreign_rows(
            rows,
            own_pid=20,
            ancestor_pids={1},
            current_run_id="run-c1",
            known_receipt_binaries=(
                pathlib.Path("/var/tmp/native-m1/arm/carrick"),
                pathlib.Path("/var/tmp/native m1/arm/carrick"),
            ),
        )

        self.assertEqual(
            foreign,
            [
                "pid=101 command=carrick:native-go-build-carrick-old-1:go",
                "pid=102 command=/tmp/carrick:native-go-build-carrick-old-2:compile",
                "pid=104 command=carrick:run-c10: go",
                (
                    "pid=105 command=/var/tmp/native-m1/arm/carrick run "
                    "--exec-backend native"
                ),
                "pid=107 command=python3 scripts/perf/native_go_build.py --engine carrick",
                "pid=108 command=/Volumes/carrick/target/release/carrick run native",
                "pid=109 command=./target/release/carrick run native",
                (
                    "pid=110 command=/Volumes/carrick/scripts/perf/"
                    "native_go_build.py --engine carrick"
                ),
                "pid=111 command=./scripts/perf/native_go_build.py --engine carrick",
                (
                    "pid=112 command=/var/tmp/native m1/arm/carrick run "
                    "--exec-backend native"
                ),
            ],
        )

    def test_census_uses_kill_script_process_listing_grammar(self):
        listing = subprocess.CompletedProcess(
            ["ps"], 0, "101 carrick:old-run:go\n", ""
        )
        with (
            mock.patch.object(native_go_build.subprocess, "run", return_value=listing) as run,
            mock.patch.object(native_go_build, "own_ancestor_pids", return_value={1}),
            mock.patch.object(native_go_build.os, "getpid", return_value=20),
        ):
            foreign = native_go_build.foreign_workload_census(current_run_id="run-c1")

        self.assertEqual(foreign, ["pid=101 command=carrick:old-run:go"])
        run.assert_called_once_with(
            ["ps", "-axww", "-o", "pid=", "-o", "command="],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_busy_host_census_uses_full_width_process_commands(self):
        listing = subprocess.CompletedProcess(
            ["ps"],
            0,
            "101 cargo build --release\n"
            "102 /bin/sh -c while :; do :; done\n",
            "",
        )
        with (
            mock.patch.object(
                native_go_build.subprocess,
                "run",
                return_value=listing,
            ) as run,
            mock.patch.object(native_go_build.os, "getpid", return_value=20),
            mock.patch.object(native_go_build.os, "cpu_count", return_value=8),
            mock.patch.object(
                native_go_build.os,
                "getloadavg",
                return_value=(1.0, 1.0, 1.0),
            ),
        ):
            reasons = native_go_build.busy_host_reasons()

        self.assertTrue(any("active compiler" in reason for reason in reasons))
        self.assertTrue(any("spin loop" in reason for reason in reasons))
        run.assert_called_once_with(
            ["ps", "-axww", "-o", "pid=", "-o", "command="],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_phase_summary_reports_workload_median(self):
        summary = native_go_build.summarize_phases(
            {
                "carrick": [
                    {"elapsed_ms": 20, "workload_ms": 15},
                    {"elapsed_ms": 18, "workload_ms": 13},
                    {"elapsed_ms": 19, "workload_ms": 14},
                ],
            }
        )

        self.assertEqual(summary["carrick"]["workload_median_ms"], 14)

    def test_checked_in_semantic_overlays_are_complete_and_authoritative(self):
        overlay_directory = pathlib.Path(native_go_build.__file__).parent / "overlays"
        default = json.loads((overlay_directory / "native-default.json").read_text())
        shared = json.loads((overlay_directory / "native-shared.json").read_text())
        expected_metadata_modes = {
            "native-shared-manifest-clone.json": "0",
            "native-shared-manifest-varint.json": "0",
            "native-shared-metadata-v2.json": "0",
        }
        observed_overlay_names = set()

        for overlay_path in sorted(overlay_directory.glob("native-*.json")):
            with self.subTest(overlay=overlay_path.name):
                observed_overlay_names.add(overlay_path.name)
                overlay = json.loads(overlay_path.read_text())
                self.assertIn(
                    "CARRICK_DSR_SHARED_MAPPED_METADATA",
                    overlay,
                )
                self.assertEqual(
                    tuple(overlay),
                    native_go_build.PERFORMANCE_CONTROL_KEYS,
                )
                self.assertEqual(
                    overlay["CARRICK_DSR_SHARED_MAPPED_METADATA"],
                    expected_metadata_modes.get(overlay_path.name),
                )
        self.assertLessEqual(
            set(expected_metadata_modes),
            observed_overlay_names,
        )

        self.assertEqual(
            tuple(default),
            native_go_build.PERFORMANCE_CONTROL_KEYS,
        )
        self.assertEqual(tuple(shared), native_go_build.PERFORMANCE_CONTROL_KEYS)
        self.assertTrue(all(value is None for value in default.values()))
        self.assertEqual(
            {
                key: value
                for key, value in shared.items()
                if value is not None
            },
            {
                "CARRICK_DSR_PERSISTENT_STORE": "1",
                "CARRICK_DSR_DIRECT_BINDINGS": "1",
            },
        )
        self.assertIsNone(shared["CARRICK_DSR_ARTIFACT_SPIKE"])
        self.assertIsNone(shared["CARRICK_DSR_SHARED_MAPPED_METADATA"])
        self.assertEqual(
            native_go_build.fixed_variant_overlay(
                native_go_build.VARIANT_DEFAULT
            ),
            default,
        )
        self.assertEqual(
            native_go_build.fixed_variant_overlay(
                native_go_build.VARIANT_SHARED
            ),
            shared,
        )

    def test_docker_cli_writes_v3_phase_artifact(self):
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
        self.assertEqual(payload["schema"], "carrick.native-go-build.v3")
        self.assertEqual(list(payload["phases"]), ["docker"])
        self.assertEqual(payload["phases"]["docker"]["sample_count"], 1)
        self.assertIn("workload_median_ms", payload["phases"]["docker"])
        self.assertNotIn("ratio", payload)


if __name__ == "__main__":
    unittest.main()
