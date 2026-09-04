#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


PERF_DIR = pathlib.Path(__file__).resolve().parents[1] / "perf"
sys.path.insert(0, str(PERF_DIR))

import embed_go_build_abba
import native_go_build


class EmbedArmPreparationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.source = self.root / "source"
        self.harness = self.root / "harness"
        self.destination = self.root / "arms" / "candidate"
        (self.source / "crates/carrick-embed").mkdir(parents=True)
        (self.source / "scripts/lib").mkdir(parents=True)
        (self.source / "scripts").mkdir(exist_ok=True)
        (self.source / "scripts/lib/post-link-sign.sh").write_text("# fixture\n")
        (self.source / "scripts/entitlements.plist").write_text("fixture\n")
        (self.source / "Cargo.lock").write_text("# exact fixture lock\n")
        driver = self.harness / "scripts/perf/embed_implicit_driver/src"
        driver.mkdir(parents=True)
        (driver / "main.rs").write_text("fn main() {}\n")
        (driver.parent / "Cargo.toml.in").write_text(
            '[package]\nname="carrick-embed-implicit-driver"\n'
            '[dependencies]\ncarrick-embed={path="@CARRICK_EMBED_PATH@"}\n'
        )
        self.commits = {
            self.source: "1" * 40,
            self.harness: "2" * 40,
        }
        self.host = {
            "platform": "macOS-fixture",
            "machine": "arm64",
            "node": "fixture-host",
            "os_build": "fixture-build",
        }
        self.commands: list[list[str]] = []
        self.rustc_cwds: list[pathlib.Path] = []
        self.mutate_private_main_during_build = False

    def fake_git_output(self, repo: pathlib.Path, *args: str, **_kwargs) -> str:
        if args == ("rev-parse", "HEAD"):
            return self.commits[pathlib.Path(repo).resolve()]
        if args == ("branch", "--show-current"):
            return "fixture-branch"
        raise AssertionError((repo, args))

    def fake_run(self, command, **kwargs):
        argv = [str(value) for value in command]
        self.commands.append(argv)
        if argv[:2] == ["cargo", "generate-lockfile"]:
            self.assertIn("--offline", argv)
            return subprocess.CompletedProcess(argv, 0, "locked driver", "")
        if argv[:2] == ["cargo", "build"]:
            if self.mutate_private_main_during_build:
                private_main = pathlib.Path(kwargs["cwd"]) / "src/main.rs"
                private_main.write_text("fn main() { panic!(\"different\") }\n")
            target = pathlib.Path(argv[argv.index("--target-dir") + 1])
            binary = target / "release/carrick-embed-implicit-driver"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"standalone signed driver fixture")
            binary.chmod(0o755)
            return subprocess.CompletedProcess(argv, 0, "built driver", "")
        if argv[:2] == ["/bin/bash", "-c"]:
            self.assertIn("carrick_post_link_sign", argv[2])
            self.assertTrue(argv[-2].endswith("carrick-embed-implicit-driver"))
            return subprocess.CompletedProcess(argv, 0, "signed driver", "")
        raise AssertionError((argv, kwargs))

    def fake_rustc_version(self, cwd: pathlib.Path) -> str:
        resolved = pathlib.Path(cwd).resolve()
        self.rustc_cwds.append(resolved)
        if resolved == (self.destination / "driver-src").resolve():
            return "rustc private-build-cwd"
        return "rustc source-cwd"

    def prepare(self):
        patches = (
            mock.patch.object(embed_go_build_abba, "git_output", self.fake_git_output),
            mock.patch.object(embed_go_build_abba, "_source_status", return_value=[]),
            mock.patch.object(embed_go_build_abba.subprocess, "run", self.fake_run),
            mock.patch.object(embed_go_build_abba, "verify_codesign"),
            mock.patch.object(
                embed_go_build_abba, "codesign_cdhash", return_value="c" * 40
            ),
            mock.patch.object(
                embed_go_build_abba, "macho_uuid", return_value="A" * 36
            ),
            mock.patch.object(
                embed_go_build_abba, "entitlement_digest", return_value="3" * 64
            ),
            mock.patch.object(
                embed_go_build_abba, "has_dof_carrick", return_value=True
            ),
            mock.patch.object(
                embed_go_build_abba, "host_receipt", return_value=self.host
            ),
            mock.patch.object(
                embed_go_build_abba,
                "_image_receipt",
                return_value={
                    "architecture": "arm64",
                    "id": "sha256:" + "4" * 64,
                    "repo_digests": ["repo@sha256:" + "5" * 64],
                },
            ),
            mock.patch.object(
                embed_go_build_abba, "rustc_version", self.fake_rustc_version
            ),
        )
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
            patches[8],
            patches[9],
            patches[10],
        ):
            return embed_go_build_abba.prepare_arm(
                self.source,
                self.destination,
                harness_repo=self.harness,
                label="candidate",
                role="candidate",
                image_ref="repo:tag",
            )

    def test_prepare_binds_exact_source_harness_driver_and_signed_artifact(self):
        receipt = self.prepare()

        self.assertEqual(receipt["source_commit"], "1" * 40)
        self.assertEqual(receipt["harness_commit"], "2" * 40)
        self.assertRegex(receipt["driver_source_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(pathlib.Path(receipt["binary_path"]).name, "embed-driver")
        self.assertTrue(receipt["codesign_verified"])
        self.assertEqual(receipt["cdhash"], "c" * 40)
        self.assertTrue(receipt["has_dof_carrick"])
        self.assertEqual(receipt["entitlement_sha256"], "3" * 64)
        private_main = self.destination / "driver-src/src/main.rs"
        self.assertEqual(pathlib.Path(receipt["driver_main_path"]), private_main)
        self.assertEqual(
            receipt["driver_main_sha256"],
            "536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4",
        )
        self.assertEqual(receipt["rust_toolchain"], "rustc private-build-cwd")
        self.assertTrue(self.rustc_cwds)
        self.assertTrue(all(cwd == private_main.parent.parent for cwd in self.rustc_cwds))
        self.assertFalse(
            any(
                pathlib.Path(argument).name == "carrick"
                for row in self.commands
                for argument in row
            )
        )
        manifest = self.destination / "driver-src/Cargo.toml"
        self.assertIn(
            str((self.source / "crates/carrick-embed").resolve()),
            manifest.read_text(),
        )
        self.assertNotIn("@CARRICK_EMBED_PATH@", manifest.read_text())
        self.assertEqual(
            (self.destination / "driver-src/Cargo.lock").read_text(),
            "# exact fixture lock\n",
        )
        cargo_command = next(
            row for row in self.commands if row[:2] == ["cargo", "build"]
        )
        self.assertIn("--locked", cargo_command)
        lock_command = next(
            row for row in self.commands if row[:2] == ["cargo", "generate-lockfile"]
        )
        self.assertIn("--offline", lock_command)

    def test_prepare_rejects_private_main_changed_during_build(self):
        self.mutate_private_main_during_build = True

        with self.assertRaisesRegex(RuntimeError, "private driver main changed"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_verify_rejects_source_harness_and_artifact_identity_drift(self):
        self.prepare()
        receipt_path = self.destination / "arm.json"
        with mock.patch.object(
            embed_go_build_abba, "git_output", self.fake_git_output
        ), mock.patch.object(
            embed_go_build_abba, "_source_status", return_value=[]
        ), mock.patch.object(
            embed_go_build_abba, "verify_codesign"
        ), mock.patch.object(
            embed_go_build_abba, "codesign_cdhash", return_value="c" * 40
        ), mock.patch.object(
            embed_go_build_abba, "macho_uuid", return_value="A" * 36
        ), mock.patch.object(
            embed_go_build_abba, "entitlement_digest", return_value="3" * 64
        ), mock.patch.object(
            embed_go_build_abba, "has_dof_carrick", return_value=True
        ), mock.patch.object(
            embed_go_build_abba, "host_receipt", return_value=self.host
        ), mock.patch.object(
            embed_go_build_abba,
            "_image_receipt",
            return_value={
                "architecture": "arm64",
                "id": "sha256:" + "4" * 64,
                "repo_digests": ["repo@sha256:" + "5" * 64],
            },
        ), mock.patch.object(
            embed_go_build_abba, "rustc_version", self.fake_rustc_version
        ):
            embed_go_build_abba.load_and_verify_arm(receipt_path)
            self.commits[self.source] = "7" * 40
            with self.assertRaisesRegex(RuntimeError, "source commit identity changed"):
                embed_go_build_abba.load_and_verify_arm(receipt_path)
            self.commits[self.source] = "1" * 40
            self.commits[self.harness] = "6" * 40
            with self.assertRaisesRegex(RuntimeError, "harness commit identity changed"):
                embed_go_build_abba.load_and_verify_arm(receipt_path)
            self.commits[self.harness] = "2" * 40
            with mock.patch.object(
                embed_go_build_abba, "codesign_cdhash", return_value="d" * 40
            ):
                with self.assertRaisesRegex(RuntimeError, "binary CDHash changed"):
                    embed_go_build_abba.load_and_verify_arm(receipt_path)
            binary = self.destination / "embed-driver"
            original = binary.read_bytes()
            binary.chmod(0o755)
            binary.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
            binary.chmod(0o555)
            with self.assertRaisesRegex(RuntimeError, "binary sha256 changed"):
                embed_go_build_abba.load_and_verify_arm(receipt_path)

    def test_verify_rejects_private_main_identity_drift(self):
        self.prepare()
        receipt_path = self.destination / "arm.json"
        private_main = self.destination / "driver-src/src/main.rs"
        private_main.chmod(0o644)
        private_main.write_text("fn main() { panic!(\"tampered\") }\n")
        private_main.chmod(0o444)

        with mock.patch.object(
            embed_go_build_abba, "git_output", self.fake_git_output
        ), mock.patch.object(
            embed_go_build_abba, "_source_status", return_value=[]
        ), mock.patch.object(
            embed_go_build_abba, "rustc_version", self.fake_rustc_version
        ):
            with self.assertRaisesRegex(RuntimeError, "private driver main"):
                embed_go_build_abba.load_and_verify_arm(receipt_path)

    def test_receipt_schema_rejects_unknown_fields(self):
        receipt = self.prepare()
        receipt["untrusted_extension"] = True
        receipt_path = self.destination / "arm.json"
        receipt_path.chmod(0o644)
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o444)

        with self.assertRaisesRegex(ValueError, "fields are invalid"):
            embed_go_build_abba.load_recorded_arm(receipt_path)

    def test_receipt_must_remain_read_only(self):
        self.prepare()
        receipt_path = self.destination / "arm.json"
        receipt_path.chmod(0o644)

        with self.assertRaisesRegex(RuntimeError, "receipt mode changed"):
            embed_go_build_abba.load_recorded_arm(receipt_path)

    def test_receipt_rejects_wrong_build_artifact_contract(self):
        receipt = self.prepare()
        receipt["build"]["command"] = ["cargo", "build", "--locked"]
        receipt_path = self.destination / "arm.json"
        receipt_path.chmod(0o644)
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o444)

        with self.assertRaisesRegex(ValueError, "build command"):
            embed_go_build_abba.load_recorded_arm(receipt_path)

    def test_receipt_rejects_non_absolute_source_and_malformed_image(self):
        receipt = self.prepare()
        receipt_path = self.destination / "arm.json"
        for field, value, message in (
            ("source_repo", "relative/source", "repository paths"),
            (
                "image",
                {
                    "architecture": "arm64",
                    "id": "sha256:" + "4" * 64,
                    "repo_digests": ["mutable:tag"],
                },
                "image RepoDigests",
            ),
        ):
            with self.subTest(field=field):
                altered = dict(receipt)
                altered[field] = value
                receipt_path.chmod(0o644)
                receipt_path.write_text(json.dumps(altered))
                receipt_path.chmod(0o444)
                with self.assertRaisesRegex(ValueError, message):
                    embed_go_build_abba.load_recorded_arm(receipt_path)


class ExecutionContractTest(unittest.TestCase):
    def neutral_environment(self):
        return tuple((key, None) for key in native_go_build.PERFORMANCE_CONTROL_KEYS)

    def arm_receipt(
        self,
        root: pathlib.Path,
        role: str,
        *,
        harness: pathlib.Path,
        harness_commit: str = "2" * 40,
        driver_hash: str = "3" * 64,
        rust_toolchain: str = "rustc exact",
    ):
        return types.SimpleNamespace(
            path=root / role / "arm.json",
            label=role,
            role=role,
            source_repo=root / role / "source",
            source_commit=("4" if role == "control" else "5") * 40,
            harness_repo=harness,
            harness_commit=harness_commit,
            driver_source_sha256=driver_hash,
            rust_toolchain=rust_toolchain,
            binary_path=root / role / "embed-driver",
            binary_sha256=("8" if role == "control" else "9") * 64,
        )

    def campaign_receipt(
        self,
        root: pathlib.Path,
        role: str,
        *,
        harness: pathlib.Path,
    ):
        receipt = self.arm_receipt(root, role, harness=harness)
        receipt.driver_main_path = root / role / "driver-src/src/main.rs"
        receipt.driver_main_sha256 = "6" * 64
        receipt.cdhash = ("a" if role == "control" else "b") * 40
        receipt.macho_uuid = ("A" if role == "control" else "B") * 36
        receipt.entitlement_sha256 = "7" * 64
        receipt.image_ref = native_go_build.DEFAULT_IMAGE
        receipt.image_id = "sha256:" + "c" * 64
        receipt.image_repo_digests = ("repo@sha256:" + "d" * 64,)
        return receipt

    def test_campaign_quad_evidence_classes_are_disjoint(self):
        self.assertEqual(
            embed_go_build_abba._validate_campaign_quads(1, pilot=True),
            "directional-pilot",
        )
        self.assertEqual(
            embed_go_build_abba._validate_campaign_quads(7, pilot=True),
            "directional-pilot",
        )
        self.assertEqual(
            embed_go_build_abba._validate_campaign_quads(8, pilot=False),
            "official",
        )
        self.assertEqual(
            embed_go_build_abba._validate_campaign_quads(127, pilot=False),
            "official",
        )
        for quads, pilot in ((0, True), (8, True), (7, False), (128, False)):
            with self.subTest(quads=quads, pilot=pilot):
                with self.assertRaises(ValueError):
                    embed_go_build_abba._validate_campaign_quads(
                        quads, pilot=pilot
                    )

    def test_completed_pilot_is_directional_success_but_never_accepted(self):
        root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        harness = root / "harness"
        harness.mkdir()
        control = embed_go_build_abba.ArmSpec(
            "control",
            self.campaign_receipt(root, "control", harness=harness),
            self.neutral_environment(),
        )
        candidate = embed_go_build_abba.ArmSpec(
            "candidate",
            self.campaign_receipt(root, "candidate", harness=harness),
            self.neutral_environment(),
        )
        harness_identity = {
            "harness_repo": str(harness),
            "harness_commit": "2" * 40,
            "driver_source_sha256": "3" * 64,
            "harness_status": [],
        }
        preflight = {
            "status": "passed",
            "source_artifacts_authenticated": True,
            "harness": harness_identity,
            "executed_image_ref": "repo@sha256:" + "d" * 64,
        }
        output = root / "pilot.json"

        with mock.patch.object(
            embed_go_build_abba,
            "_campaign_harness_identity",
            return_value=harness_identity,
        ), mock.patch.object(
            embed_go_build_abba, "_campaign_preflight", return_value=preflight
        ), mock.patch.object(
            embed_go_build_abba,
            "run_sample",
            side_effect=lambda *_args, **_kwargs: {
                "provenance": {"authenticated": True}
            },
        ), mock.patch.object(
            embed_go_build_abba,
            "_samples_authenticated",
            return_value=True,
        ), mock.patch.object(
            embed_go_build_abba,
            "_summarize_quads",
            return_value=statistics_payload(
                primary_median=1.05,
                primary_lower=1.01,
                sign_numerator=1,
                sign_denominator=2,
                quads=1,
            ),
        ), mock.patch.object(embed_go_build_abba.time, "sleep"):
            artifact = embed_go_build_abba.run_campaign(
                harness,
                control,
                candidate,
                output,
                quads=1,
                cooldown_seconds=0,
                pilot=True,
            )

        self.assertEqual(artifact["evidence_class"], "directional-pilot")
        self.assertEqual(artifact["decision"]["status"], "directional")
        self.assertFalse(artifact["decision"]["eligible"])
        self.assertFalse(artifact["accepted"])
        self.assertEqual(embed_go_build_abba._decision_exit_code(artifact), 0)

    def test_cli_requires_explicit_pilot_selection(self):
        common = [
            "run",
            "--harness-repo",
            "/harness",
            "--control-receipt",
            "/arms/control.json",
            "--candidate-receipt",
            "/arms/candidate.json",
            "--control-overlay",
            "/arms/control.env",
            "--candidate-overlay",
            "/arms/candidate.env",
            "--output",
            "/tmp/output.json",
        ]

        self.assertFalse(embed_go_build_abba.parse_args(common).pilot)
        self.assertTrue(embed_go_build_abba.parse_args([*common, "--pilot"]).pilot)

    def test_driver_argv_is_implicit_embed_and_never_cli_run(self):
        argv = embed_go_build_abba.build_driver_command(
            pathlib.Path("/arms/control/embed-driver"),
            "sample-7",
            image="repo@sha256:" + "7" * 64,
        )
        self.assertEqual(argv[0], "/arms/control/embed-driver")
        self.assertNotIn("run", argv)
        self.assertEqual(
            argv[1:7],
            [
                "--image",
                "repo@sha256:" + "7" * 64,
                "--run-id",
                "sample-7",
                "--workdir",
                "/tmp",
            ],
        )
        self.assertEqual(argv[-3:-1], ["/bin/sh", "-c"])
        self.assertEqual(argv[-1], native_go_build.guest_script())

    def test_execution_environment_sets_same_host_and_guest_run_identity(self):
        neutral = {key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS}
        environment, transport = embed_go_build_abba._execution_environment(
            {},
            neutral,
            run_id="sample-identity",
            image="localhost:5005/carrick-go@sha256:" + "9" * 64,
        )

        self.assertEqual(environment["CARRICK_RUN_ID"], "sample-identity")
        self.assertEqual(
            environment["CARRICK_INSECURE_REGISTRIES"], "localhost:5005"
        )
        self.assertEqual(transport["protocol"], "http")

    def test_failed_scoped_cleanup_fails_the_sample(self):
        root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        binary = root / "embed-driver"
        binary.write_bytes(b"driver")
        binary.chmod(0o555)
        completed = subprocess.CompletedProcess(
            ["embed-driver"],
            0,
            "WORKLOAD_NS=1000000\nBUILD_OK\n",
            "",
        )
        with mock.patch.object(
            embed_go_build_abba.subprocess, "run", return_value=completed
        ), mock.patch.object(
            embed_go_build_abba,
            "_sample_provenance",
            return_value={"authenticated": True},
        ), mock.patch.object(
            embed_go_build_abba,
            "_scoped_cleanup",
            return_value={"status": 1, "remaining_processes": 1},
        ):
            with self.assertRaisesRegex(native_go_build.SampleEvidenceError, "cleanup"):
                embed_go_build_abba.run_sample(
                    binary,
                    root,
                    1,
                    10,
                    environment_overlay={
                        key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS
                    },
                    image="repo@sha256:" + "8" * 64,
                    current_run_id="sample-cleanup-fail",
                )

    def test_abba_requires_identical_canonical_controls(self):
        neutral = tuple((key, None) for key in native_go_build.PERFORMANCE_CONTROL_KEYS)
        changed = tuple(
            (key, "1" if key == "CARRICK_DSR_DIRECT_BINDINGS" else None)
            for key in native_go_build.PERFORMANCE_CONTROL_KEYS
        )
        control = embed_go_build_abba.ArmSpec("control", mock.sentinel.control, neutral)
        candidate = embed_go_build_abba.ArmSpec("candidate", mock.sentinel.candidate, changed)
        with self.assertRaisesRegex(ValueError, "environment dimensions cannot both change"):
            embed_go_build_abba.validate_arm_mode(control, candidate)

    def test_campaign_executes_the_receipted_immutable_image(self):
        digest = "example.com/carrick/go@sha256:" + "a" * 64
        receipt = types.SimpleNamespace(
            image_ref="example.com/carrick/go:1.24",
            image_id="sha256:" + "b" * 64,
            image_repo_digests=(digest,),
        )
        expected_image = {
            "architecture": "arm64",
            "id": receipt.image_id,
            "repo_digests": [digest],
        }
        with mock.patch.object(
            embed_go_build_abba, "_image_receipt", return_value=expected_image
        ):
            executed = embed_go_build_abba._immutable_execution_ref(
                receipt,
                receipt,
                "example.com/carrick/go:1.24",
            )

        self.assertEqual(executed, digest)

    def test_abba_rejects_different_harness_paths_and_toolchains(self):
        root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        harness = root / "harness"
        other_harness = root / "other-harness"
        control = embed_go_build_abba.ArmSpec(
            "control",
            self.arm_receipt(root, "control", harness=harness),
            self.neutral_environment(),
        )
        for candidate_receipt, message in (
            (
                self.arm_receipt(root, "candidate", harness=other_harness),
                "exact harness path",
            ),
            (
                self.arm_receipt(
                    root,
                    "candidate",
                    harness=harness,
                    rust_toolchain="rustc different",
                ),
                "toolchain",
            ),
        ):
            with self.subTest(message=message):
                candidate = embed_go_build_abba.ArmSpec(
                    "candidate", candidate_receipt, self.neutral_environment()
                )
                with self.assertRaisesRegex(ValueError, message):
                    embed_go_build_abba.validate_arm_mode(control, candidate)

    def test_campaign_harness_identity_rejects_path_commit_hash_and_status_drift(self):
        root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        harness = root / "harness"
        harness.mkdir()
        other_harness = root / "other-harness"
        other_harness.mkdir()
        control = self.arm_receipt(root, "control", harness=harness)
        candidate = self.arm_receipt(root, "candidate", harness=harness)

        with self.assertRaisesRegex(RuntimeError, "campaign harness path"):
            embed_go_build_abba._campaign_harness_identity(
                other_harness, control, candidate
            )
        for commit, driver_hash, status, message in (
            ("6" * 40, "3" * 64, [], "commit"),
            ("2" * 40, "7" * 64, [], "driver source"),
            ("2" * 40, "3" * 64, [" M scripts/perf"], "clean"),
        ):
            with self.subTest(message=message), mock.patch.object(
                embed_go_build_abba, "_source_status", return_value=status
            ), mock.patch.object(
                embed_go_build_abba, "git_output", return_value=commit
            ), mock.patch.object(
                embed_go_build_abba,
                "driver_source_sha256",
                return_value=driver_hash,
            ):
                with self.assertRaisesRegex(RuntimeError, message):
                    embed_go_build_abba._campaign_harness_identity(
                        harness, control, candidate
                    )

    def test_sample_provenance_records_both_arm_identity_and_workload_census(self):
        root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        harness = root / "harness"
        harness.mkdir()
        control = self.arm_receipt(root, "control", harness=harness)
        candidate = self.arm_receipt(root, "candidate", harness=harness)
        for receipt in (control, candidate):
            receipt.binary_path.parent.mkdir(parents=True)
            receipt.binary_path.write_bytes(receipt.role.encode())
        owned = (control.binary_path, candidate.binary_path)

        with mock.patch.object(
            embed_go_build_abba,
            "load_and_verify_arm",
            side_effect=(control, candidate),
        ), mock.patch.object(
            embed_go_build_abba,
            "_campaign_harness_identity",
            return_value={
                "harness_repo": str(harness),
                "harness_commit": "2" * 40,
                "driver_source_sha256": "3" * 64,
                "harness_status": [],
            },
        ), mock.patch.object(
            embed_go_build_abba,
            "_image_receipt",
            return_value={"id": "image"},
        ), mock.patch.object(
            native_go_build, "busy_host_reasons", return_value=["busy-build"]
        ), mock.patch.object(
            native_go_build,
            "foreign_workload_census",
            return_value=[{"pid": 99}],
        ) as foreign, mock.patch.object(
            native_go_build, "running_docker_oracles", return_value=[{"pid": 100}]
        ):
            evidence = embed_go_build_abba._sample_provenance(
                control.binary_path,
                harness,
                image="repo@sha256:" + "8" * 64,
                controlled_environment={},
                registry_transport=None,
                receipt=control,
                campaign_receipts=(control, candidate),
                owned_binaries=owned,
            )

        foreign.assert_called_once_with(known_receipt_binaries=owned)
        self.assertTrue(evidence["arms_authenticated"])
        self.assertEqual(evidence["owned_driver_binaries"], [str(p) for p in owned])
        self.assertEqual(evidence["busy_host_reasons"], ["busy-build"])
        self.assertEqual(evidence["foreign_processes"], [{"pid": 99}])
        self.assertEqual(evidence["docker_oracles"], [{"pid": 100}])
        self.assertFalse(evidence["workload_isolation_clean"])

    def test_contamination_after_non_a1_sample_is_rejected(self):
        root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        binary = root / "control-driver"
        other_binary = root / "candidate-driver"
        binary.write_bytes(b"driver")
        other_binary.write_bytes(b"driver")
        for path in (binary, other_binary):
            path.chmod(0o555)
        completed = subprocess.CompletedProcess(
            [str(binary)], 0, "WORKLOAD_NS=1000000\nBUILD_OK\n", ""
        )
        clean = {"authenticated": True, "workload_isolation_clean": True}
        contaminated = {
            "authenticated": True,
            "workload_isolation_clean": False,
            "foreign_processes": [{"pid": 99}],
        }
        with mock.patch.object(
            embed_go_build_abba.subprocess, "run", return_value=completed
        ), mock.patch.object(
            embed_go_build_abba,
            "_sample_provenance",
            side_effect=(clean, contaminated),
        ), mock.patch.object(
            embed_go_build_abba,
            "_scoped_cleanup",
            return_value={"status": 0, "remaining_processes": 0},
        ):
            with self.assertRaisesRegex(
                native_go_build.SampleEvidenceError, "workload contamination"
            ):
                embed_go_build_abba.run_sample(
                    binary,
                    root,
                    7,
                    10,
                    environment_overlay={
                        key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS
                    },
                    image="repo@sha256:" + "8" * 64,
                    current_run_id="quad-2-b1",
                    receipt=mock.sentinel.receipt,
                    campaign_receipts=(mock.sentinel.control, mock.sentinel.candidate),
                    owned_binaries=(binary, other_binary),
                )

    def test_completed_gate_acceptance_and_exit_status_follow_tri_state(self):
        for status, accepted, exit_code in (
            ("pass", True, 0),
            ("fail", False, 2),
            ("unresolved", False, 3),
        ):
            with self.subTest(status=status):
                artifact = {"complete": True, "accepted": False, "decision": None}
                embed_go_build_abba._record_decision(
                    artifact, {"status": status, "eligible": status != "unresolved"}
                )
                self.assertIs(artifact["accepted"], accepted)
                self.assertEqual(
                    embed_go_build_abba._decision_exit_code(artifact), exit_code
                )

    def test_non_a1_contamination_makes_campaign_decision_ineligible(self):
        harness = {
            "harness_repo": "/harness",
            "harness_commit": "2" * 40,
            "driver_source_sha256": "3" * 64,
            "harness_status": [],
        }
        owned = (pathlib.Path("/arms/control"), pathlib.Path("/arms/candidate"))

        def snapshot(clean: bool):
            return {
                "authenticated": True,
                "arms_authenticated": True,
                "harness": harness,
                "owned_driver_binaries": [str(path) for path in owned],
                "workload_isolation_clean": clean,
            }

        samples = []
        for position in ("a1", "b1", "b2", "a2"):
            clean = position != "b1"
            samples.append(
                {
                    "position": position,
                    "provenance": {
                        "pre": snapshot(True),
                        "post": snapshot(clean),
                    },
                }
            )
        authenticated = embed_go_build_abba._samples_authenticated(
            samples,
            harness_identity=harness,
            owned_binaries=owned,
        )
        decision = embed_go_build_abba._no_regression_decision(
            statistics_payload(
                primary_median=1.0,
                primary_lower=1.0,
                sign_numerator=128,
                sign_denominator=256,
            ),
            complete=True,
            artifacts_authenticated=authenticated,
            preflights_passed=True,
        )

        self.assertFalse(authenticated)
        self.assertEqual(decision["status"], "unresolved")
        self.assertFalse(decision["eligible"])


def statistics_payload(
    *,
    primary_median: float,
    primary_lower: float,
    sign_numerator: int,
    sign_denominator: int,
    secondary_median: float = 1.0,
    secondary_lower: float = 1.0,
    quads: int = 8,
) -> dict[str, object]:
    return {
        "quad_count": quads,
        "primary_metric": "cpu_s",
        "metrics": {
            "cpu_s": {
                "median_quad_ratio": primary_median,
                "bootstrap": {"one_sided_lower": primary_lower},
                "regression_sign_test": {
                    "probability": {
                        "numerator": sign_numerator,
                        "denominator": sign_denominator,
                    }
                },
            },
            "elapsed_ms": {
                "median_quad_ratio": secondary_median,
                "bootstrap": {"two_sided_lower": secondary_lower},
            },
        },
    }


class NoRegressionDecisionTest(unittest.TestCase):
    def decision(self, payload, *, complete=True, artifacts=True, preflights=True):
        return embed_go_build_abba._no_regression_decision(
            payload,
            complete=complete,
            artifacts_authenticated=artifacts,
            preflights_passed=preflights,
        )

    def test_exact_threshold_and_neutral_ratios_pass(self):
        exact = self.decision(
            statistics_payload(
                primary_median=1.0,
                primary_lower=1.0,
                sign_numerator=1,
                sign_denominator=256,
            )
        )
        neutral = self.decision(
            statistics_payload(
                primary_median=0.99,
                primary_lower=0.98,
                sign_numerator=255,
                sign_denominator=256,
                secondary_median=0.97,
                secondary_lower=0.96,
            )
        )
        self.assertEqual(exact["status"], "pass")
        self.assertEqual(neutral["status"], "pass")
        self.assertTrue(exact["no_regression_pass"])
        self.assertFalse(exact["supported_regression_fail"])

    def test_noisy_ratio_above_one_is_unresolved(self):
        decision = self.decision(
            statistics_payload(
                primary_median=1.02,
                primary_lower=0.99,
                sign_numerator=30,
                sign_denominator=256,
            )
        )
        self.assertEqual(decision["status"], "unresolved")
        self.assertFalse(decision["no_regression_pass"])
        self.assertFalse(decision["supported_regression_fail"])

    def test_supported_primary_regression_fails(self):
        decision = self.decision(
            statistics_payload(
                primary_median=1.05,
                primary_lower=1.01,
                sign_numerator=9,
                sign_denominator=256,
            )
        )
        self.assertEqual(decision["status"], "fail")
        self.assertTrue(decision["supported_regression_fail"])

    def test_supported_secondary_regression_fails(self):
        decision = self.decision(
            statistics_payload(
                primary_median=1.0,
                primary_lower=0.99,
                sign_numerator=128,
                sign_denominator=256,
                secondary_median=1.03,
                secondary_lower=1.01,
            )
        )
        self.assertEqual(decision["status"], "fail")
        self.assertTrue(decision["secondary"]["elapsed_ms"]["supported_regression"])

    def test_ineligible_evidence_is_unresolved(self):
        eligible = statistics_payload(
            primary_median=1.0,
            primary_lower=1.0,
            sign_numerator=128,
            sign_denominator=256,
        )
        for kwargs in (
            {"complete": False},
            {"artifacts": False},
            {"preflights": False},
        ):
            with self.subTest(kwargs=kwargs):
                decision = self.decision(eligible, **kwargs)
                self.assertEqual(decision["status"], "unresolved")
                self.assertFalse(decision["eligible"])
        insufficient = self.decision(
            statistics_payload(
                primary_median=1.0,
                primary_lower=1.0,
                sign_numerator=1,
                sign_denominator=2,
                quads=7,
            )
        )
        self.assertEqual(insufficient["status"], "unresolved")
        self.assertFalse(insufficient["eligible"])

    def test_decision_records_every_boolean_and_numeric_input(self):
        decision = self.decision(
            statistics_payload(
                primary_median=1.02,
                primary_lower=0.99,
                sign_numerator=30,
                sign_denominator=256,
                secondary_median=1.01,
                secondary_lower=0.98,
            )
        )
        self.assertEqual(
            decision["eligibility_inputs"],
            {
                "complete": True,
                "quad_count": 8,
                "minimum_quads": 8,
                "evidence_class": "official",
                "artifacts_authenticated": True,
                "preflights_passed": True,
            },
        )
        self.assertEqual(decision["primary"]["median_quad_ratio"], 1.02)
        self.assertEqual(decision["primary"]["bootstrap_one_sided_lower"], 0.99)
        self.assertEqual(decision["primary"]["sign_probability_numerator"], 30)
        self.assertEqual(decision["primary"]["sign_probability_denominator"], 256)
        self.assertEqual(decision["threshold"], 1.0)

    def test_regression_statistics_use_ratios_above_one_and_lower_bound(self):
        evidence = embed_go_build_abba._regression_statistics([1.1] * 8)

        self.assertEqual(evidence["sign_test"]["wins_above_one"], 8)
        self.assertEqual(evidence["sign_test"]["probability"]["numerator"], 1)
        self.assertEqual(evidence["sign_test"]["probability"]["denominator"], 256)
        self.assertAlmostEqual(evidence["bootstrap_one_sided_lower"], 1.1)


if __name__ == "__main__":
    unittest.main()
