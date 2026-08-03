#!/usr/bin/env python3

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import plistlib
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_go_build
import native_go_build_abba


class MachOUuidTest(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_uses_system_dwarfdump_when_path_has_failing_shadow(self):
        shadow_dir = self.root / "shadow-bin"
        shadow_dir.mkdir()
        marker = self.root / "shadow-invoked"
        shadow = shadow_dir / "dwarfdump"
        shadow.write_text(
            "#!/bin/sh\n"
            'printf shadow > "$DWARFDUMP_SHADOW_MARKER"\n'
            "exit 71\n"
        )
        shadow.chmod(0o755)

        with mock.patch.dict(
            os.environ,
            {
                "PATH": f"{shadow_dir}{os.pathsep}{os.environ['PATH']}",
                "DWARFDUMP_SHADOW_MARKER": str(marker),
            },
        ):
            uuid = native_go_build_abba.macho_uuid(pathlib.Path(sys.executable))

        self.assertRegex(
            uuid,
            r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
        )
        self.assertFalse(marker.exists(), "PATH shadow dwarfdump was invoked")


class ArmReceiptTest(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.source = self.root / "source"
        self.binary = self.source / "target/release/carrick"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"fixture-carrick-binary\n")
        self.binary.chmod(0o755)
        self.destination_index = 0
        self.real_subprocess_run = subprocess.run
        self.use_real_git = False

        self.commit = "1" * 40
        self.branch = "codex/native-performance-m1"
        self.status_outputs = []
        self.build_status = 0
        self.build_stdout = "signed release binary\n"
        self.build_stderr = ""
        self.machine = "arm64"
        self.host_platform = "macOS-15.5-arm64-arm-64bit"
        self.host_node = "fixture-host"
        self.host_version = "Darwin Kernel Version fixture"
        self.macho_uuid = "11111111-2222-3333-4444-555555555555"
        self.signature_status = 0
        self.entitlements = plistlib.dumps(
            {"com.apple.security.hypervisor": True},
            fmt=plistlib.FMT_XML,
            sort_keys=True,
        )
        self.has_dof = True
        self.dof_segment = "__DATA"
        self.image_architecture = "arm64"
        self.image_id = "sha256:" + "2" * 64
        self.image_repo_digests = [
            "localhost:5005/carrick-go-conformance@sha256:" + "3" * 64
        ]

    def destination(self) -> pathlib.Path:
        self.destination_index += 1
        return self.root / "arms" / f"arm-{self.destination_index}"

    def fake_run(self, command, **kwargs):
        argv = [str(value) for value in command]
        if argv[0] == "git" and self.use_real_git:
            return self.real_subprocess_run(command, **kwargs)
        if argv[:4] == [
            "git",
            "--no-optional-locks",
            "status",
            "--porcelain",
        ]:
            self.assertEqual(pathlib.Path(kwargs["cwd"]), self.source.resolve())
            output = self.status_outputs.pop(0) if self.status_outputs else ""
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            self.assertEqual(pathlib.Path(kwargs["cwd"]), self.source.resolve())
            return subprocess.CompletedProcess(argv, 0, self.commit + "\n", "")
        if argv[:3] == ["git", "branch", "--show-current"]:
            self.assertEqual(pathlib.Path(kwargs["cwd"]), self.source.resolve())
            return subprocess.CompletedProcess(argv, 0, self.branch + "\n", "")
        if argv == ["just", "build"]:
            self.assertEqual(pathlib.Path(kwargs["cwd"]), self.source.resolve())
            return subprocess.CompletedProcess(
                argv,
                self.build_status,
                self.build_stdout,
                self.build_stderr,
            )
        if argv == ["rustc", "--version"]:
            self.assertEqual(pathlib.Path(kwargs["cwd"]), self.source.resolve())
            return subprocess.CompletedProcess(
                argv, 0, "rustc 1.88.0 (fixture 2026-06-23)\n", ""
            )
        if argv[:3] == ["codesign", "--verify", "--strict"]:
            self.assertEqual(pathlib.Path(argv[-1]).name, "carrick")
            return subprocess.CompletedProcess(
                argv, self.signature_status, b"", b"invalid signature"
            )
        if argv[:3] == ["codesign", "-d", "--entitlements"]:
            self.assertEqual(pathlib.Path(argv[-1]).name, "carrick")
            return subprocess.CompletedProcess(argv, 0, self.entitlements, b"")
        if argv[:2] == ["/usr/bin/dwarfdump", "--uuid"]:
            self.assertEqual(pathlib.Path(argv[-1]).name, "carrick")
            output = (
                f"UUID: {self.macho_uuid} (arm64) {argv[-1]}\n"
            ).encode()
            return subprocess.CompletedProcess(argv, 0, output, b"")
        if argv[:2] == ["otool", "-l"]:
            self.assertEqual(pathlib.Path(argv[-1]).name, "carrick")
            output = (
                "Load command 9\n"
                "      cmd LC_SEGMENT_64\n"
                "  sectname __dof_carrick\n"
                f"   segname {self.dof_segment}\n"
                if self.has_dof
                else "Load command 9\n  sectname __text\n   segname __TEXT\n"
            )
            return subprocess.CompletedProcess(argv, 0, output.encode(), b"")
        if argv[:3] == ["docker", "image", "inspect"]:
            self.assertEqual(
                argv[-1],
                "localhost:5005/carrick-go-conformance:1.24",
            )
            output = "\n".join(
                (
                    json.dumps(self.image_architecture),
                    json.dumps(self.image_id),
                    json.dumps(self.image_repo_digests),
                )
            )
            return subprocess.CompletedProcess(argv, 0, output + "\n", "")
        raise AssertionError(f"unexpected command: {argv!r}; kwargs={kwargs!r}")

    @contextlib.contextmanager
    def command_fixtures(self, *, real_git=False):
        previous_real_git = self.use_real_git
        self.use_real_git = real_git
        with (
            mock.patch.object(
                native_go_build_abba.subprocess,
                "run",
                side_effect=self.fake_run,
            ),
            mock.patch.object(
                native_go_build_abba.platform,
                "machine",
                side_effect=lambda: self.machine,
            ),
            mock.patch.object(
                native_go_build_abba.platform,
                "platform",
                side_effect=lambda: self.host_platform,
            ),
            mock.patch.object(
                native_go_build_abba.platform,
                "node",
                side_effect=lambda: self.host_node,
            ),
            mock.patch.object(
                native_go_build_abba.platform,
                "version",
                side_effect=lambda: self.host_version,
            ),
        ):
            try:
                yield
            finally:
                self.use_real_git = previous_real_git

    def prepare(
        self,
        *,
        destination=None,
        label="control",
        role="control",
    ):
        selected_destination = destination or self.destination()
        selected_destination.parent.mkdir(parents=True, exist_ok=True)
        with self.command_fixtures():
            receipt = native_go_build_abba.prepare_arm(
                self.source,
                selected_destination,
                label=label,
                role=role,
                image_ref="localhost:5005/carrick-go-conformance:1.24",
            )
        return selected_destination, receipt

    def load(self, receipt_path):
        with self.command_fixtures():
            return native_go_build_abba.load_and_verify_arm(receipt_path)

    def rewrite_receipt(self, path, mutate):
        path.chmod(0o644)
        payload = json.loads(path.read_text())
        mutate(payload)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        path.chmod(0o444)

    def initialize_real_source_repository(self):
        (self.source / ".gitignore").write_text("target/\n")
        tracked = self.source / "README"
        tracked.write_text("fixture\n")
        for command in (
            ["git", "init", "-q"],
            ["git", "config", "user.email", "test@example.invalid"],
            ["git", "config", "user.name", "Arm Receipt Test"],
            ["git", "add", ".gitignore", "README"],
            ["git", "commit", "-qm", "fixture"],
        ):
            self.real_subprocess_run(command, cwd=self.source, check=True)
        return tracked

    def load_receipt_in_bounded_child(self, receipt, timeout_seconds=0.5):
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                native_go_build_abba.load_and_verify_arm(receipt)
                result = "accepted"
            except BaseException as error:
                result = f"{type(error).__name__}: {error}"
            try:
                os.write(write_fd, result.encode())
            finally:
                os.close(write_fd)
            os._exit(0)

        os.close(write_fd)
        deadline = time.monotonic() + timeout_seconds
        status = None
        while time.monotonic() < deadline:
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                break
            time.sleep(0.01)
        else:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            os.close(read_fd)
            self.fail("child blocked while opening FIFO arm receipt")
        try:
            output = os.read(read_fd, 4096).decode()
        finally:
            os.close(read_fd)
        self.assertEqual(status, 0)
        return output

    def test_rejects_role_outside_control_and_candidate(self):
        with self.assertRaisesRegex(ValueError, "role"):
            self.prepare(role="baseline")

    def test_rejects_dirty_source_before_build(self):
        self.status_outputs = ["?? untracked\n"]

        with self.assertRaisesRegex(RuntimeError, "clean"):
            self.prepare()

    def test_rejects_source_dirtied_by_build(self):
        self.status_outputs = ["", " M crates/carrick-runtime/src/lib.rs\n"]

        with self.assertRaisesRegex(RuntimeError, "clean"):
            self.prepare()

    def test_rejects_failed_signed_build_and_missing_copied_binary(self):
        self.build_status = 7
        with self.assertRaisesRegex(RuntimeError, "just build"):
            self.prepare()

        self.build_status = 0
        with (
            mock.patch.object(
                native_go_build_abba.shutil,
                "copy2",
                return_value=None,
            ),
            self.assertRaisesRegex(RuntimeError, "missing.*binary"),
        ):
            self.prepare()

    def test_named_branch_receipt_is_exclusive_fsynced_and_has_no_neighbor(self):
        fsynced_types = []
        real_fsync = os.fsync

        def track_fsync(fd):
            fsynced_types.append(stat.S_IFMT(os.fstat(fd).st_mode))
            real_fsync(fd)

        with mock.patch.object(
            native_go_build_abba.os, "fsync", side_effect=track_fsync
        ):
            destination, payload = self.prepare()

        receipt_path = destination / "arm.json"
        copied = destination / "carrick"
        self.assertEqual(payload["source_branch"], self.branch)
        self.assertIs(payload["source_detached"], False)
        self.assertEqual(payload["source_status"], [])
        self.assertEqual(payload["build"]["command"], ["just", "build"])
        self.assertEqual(payload["build"]["status"], 0)
        self.assertTrue(payload["codesign_verified"])
        self.assertTrue(payload["has_dof_carrick"])
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode) & 0o222, 0)
        self.assertEqual(fsynced_types[-2:], [stat.S_IFREG, stat.S_IFDIR])
        self.assertEqual(
            sorted(path.name for path in destination.iterdir()),
            ["arm.json", "carrick"],
        )

        loaded = self.load(receipt_path)
        self.assertEqual(loaded.path, receipt_path)
        self.assertEqual(loaded.source_branch, self.branch)
        self.assertFalse(loaded.source_detached)

    def test_detached_head_encoding_is_exact(self):
        self.branch = ""
        destination, payload = self.prepare(label="candidate", role="candidate")

        self.assertIsNone(payload["source_branch"])
        self.assertIs(payload["source_detached"], True)
        loaded = self.load(destination / "arm.json")
        self.assertIsNone(loaded.source_branch)
        self.assertTrue(loaded.source_detached)

    def test_rejects_destination_collision_and_dangling_symlink(self):
        collision = self.destination()
        collision.parent.mkdir(parents=True)
        collision.mkdir()
        with self.assertRaises(FileExistsError):
            self.prepare(destination=collision)

        dangling = self.destination()
        dangling.symlink_to(self.root / "absent")
        with self.assertRaises(FileExistsError):
            self.prepare(destination=dangling)

    def test_reverification_rejects_missing_binary_and_symlinks(self):
        destination, _ = self.prepare()
        receipt = destination / "arm.json"
        copied = destination / "carrick"
        copied.unlink()
        with self.assertRaisesRegex(RuntimeError, "binary"):
            self.load(receipt)

        destination, _ = self.prepare()
        receipt = destination / "arm.json"
        copied = destination / "carrick"
        original = destination / "original"
        copied.rename(original)
        copied.symlink_to(original)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.load(receipt)

        destination, _ = self.prepare()
        linked_receipt = self.root / "linked-arm.json"
        linked_receipt.symlink_to(destination / "arm.json")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.load(linked_receipt)

    def test_reverification_rejects_intermediate_directory_symlink(self):
        destination, _ = self.prepare()
        arms = destination.parent
        real_arms = self.root / "real-arms"
        arms.rename(real_arms)
        arms.symlink_to(real_arms, target_is_directory=True)

        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.load(destination / "arm.json")

    def test_reverification_rejects_fifo_receipt_without_blocking(self):
        destination, _ = self.prepare()
        receipt = destination / "arm.json"
        receipt.unlink()
        os.mkfifo(receipt, 0o444)

        result = self.load_receipt_in_bounded_child(receipt)

        self.assertIn("RuntimeError", result)
        self.assertIn("regular file", result)

    def test_reverification_does_not_refresh_git_index(self):
        tracked = self.initialize_real_source_repository()
        destination = self.destination()
        destination.parent.mkdir(parents=True)
        with self.command_fixtures(real_git=True):
            native_go_build_abba.prepare_arm(
                self.source,
                destination,
                label="control",
                role="control",
                image_ref="localhost:5005/carrick-go-conformance:1.24",
            )

        tracked_stat = tracked.stat()
        os.utime(
            tracked,
            ns=(
                tracked_stat.st_atime_ns,
                tracked_stat.st_mtime_ns + 2_000_000_000,
            ),
        )
        index = self.source / ".git/index"
        before = (
            hashlib.sha256(index.read_bytes()).hexdigest(),
            index.stat().st_mtime_ns,
        )

        with self.command_fixtures(real_git=True):
            native_go_build_abba.load_and_verify_arm(destination / "arm.json")

        after = (
            hashlib.sha256(index.read_bytes()).hexdigest(),
            index.stat().st_mtime_ns,
        )
        self.assertEqual(after, before)

    def test_reverification_rejects_size_mode_and_sha256_drift(self):
        for drift in ("size", "mode", "sha256"):
            with self.subTest(drift=drift):
                destination, _ = self.prepare()
                copied = destination / "carrick"
                if drift == "size":
                    copied.chmod(0o755)
                    with copied.open("ab") as stream:
                        stream.write(b"x")
                    copied.chmod(0o555)
                elif drift == "mode":
                    copied.chmod(0o500)
                else:
                    copied.chmod(0o755)
                    data = copied.read_bytes()
                    copied.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                    copied.chmod(0o555)
                with self.assertRaisesRegex(RuntimeError, drift):
                    self.load(destination / "arm.json")

    def test_reverification_rejects_uuid_signature_entitlement_and_dof_drift(self):
        cases = (
            (
                "UUID",
                lambda: setattr(
                    self,
                    "macho_uuid",
                    "99999999-8888-7777-6666-555555555555",
                ),
            ),
            ("signature", lambda: setattr(self, "signature_status", 1)),
            (
                "entitlement",
                lambda: setattr(
                    self,
                    "entitlements",
                    plistlib.dumps(
                        {"com.apple.security.hypervisor": False},
                        fmt=plistlib.FMT_XML,
                        sort_keys=True,
                    ),
                ),
            ),
            ("DOF", lambda: setattr(self, "has_dof", False)),
        )
        for expected, mutate in cases:
            with self.subTest(drift=expected):
                destination, _ = self.prepare()
                mutate()
                with self.assertRaisesRegex(RuntimeError, expected):
                    self.load(destination / "arm.json")
                self.macho_uuid = "11111111-2222-3333-4444-555555555555"
                self.signature_status = 0
                self.entitlements = plistlib.dumps(
                    {"com.apple.security.hypervisor": True},
                    fmt=plistlib.FMT_XML,
                    sort_keys=True,
                )
                self.has_dof = True

    def test_dof_verification_accepts_real_text_or_data_section_only(self):
        for segment in ("__TEXT", "__DATA"):
            with self.subTest(segment=segment):
                self.dof_segment = segment
                destination, _payload = self.prepare()
                self.load(destination / "arm.json")

        self.dof_segment = "__LINKEDIT"
        with self.assertRaisesRegex(RuntimeError, "DOF"):
            self.prepare()

    def test_rejects_wrong_host_or_image_architecture(self):
        self.machine = "x86_64"
        with self.assertRaisesRegex(RuntimeError, "arm64"):
            self.prepare()

        self.machine = "arm64"
        self.image_architecture = "amd64"
        with self.assertRaisesRegex(RuntimeError, "arm64"):
            self.prepare()

        self.image_architecture = "arm64"
        destination, _ = self.prepare()
        self.machine = "x86_64"
        with self.assertRaisesRegex(RuntimeError, "host"):
            self.load(destination / "arm.json")

    def test_rejects_empty_or_changed_image_identity(self):
        self.image_repo_digests = []
        with self.assertRaisesRegex(RuntimeError, "RepoDigests"):
            self.prepare()

        self.image_repo_digests = [
            "localhost:5005/carrick-go-conformance@sha256:" + "3" * 64
        ]
        destination, _ = self.prepare()
        self.image_id = "sha256:" + "4" * 64
        with self.assertRaisesRegex(RuntimeError, "image"):
            self.load(destination / "arm.json")

        self.image_id = "sha256:" + "2" * 64
        destination, _ = self.prepare()
        self.image_repo_digests = [
            "localhost:5005/carrick-go-conformance@sha256:" + "5" * 64
        ]
        with self.assertRaisesRegex(RuntimeError, "image"):
            self.load(destination / "arm.json")

    def test_rejects_unknown_fields_at_every_receipt_layer(self):
        for layer in ("top", "build", "host", "image"):
            with self.subTest(layer=layer):
                destination, _ = self.prepare()
                receipt = destination / "arm.json"

                def add_unknown(payload):
                    target = payload if layer == "top" else payload[layer]
                    target["unexpected"] = True

                self.rewrite_receipt(receipt, add_unknown)
                with self.assertRaisesRegex(ValueError, "unknown"):
                    self.load(receipt)

    def test_rejects_invalid_branch_encodings_and_empty_recorded_digests(self):
        mutations = (
            lambda payload: payload.update(
                {"source_branch": self.branch, "source_detached": True}
            ),
            lambda payload: payload.update(
                {"source_branch": None, "source_detached": False}
            ),
            lambda payload: payload["image"].update({"repo_digests": []}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                destination, _ = self.prepare()
                receipt = destination / "arm.json"
                self.rewrite_receipt(receipt, mutate)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.load(receipt)

    def test_reverification_rejects_source_identity_or_cleanliness_drift(self):
        destination, _ = self.prepare()
        self.status_outputs = [" M README.md\n"]
        with self.assertRaisesRegex(RuntimeError, "source"):
            self.load(destination / "arm.json")

        destination, _ = self.prepare()
        self.commit = "8" * 40
        with self.assertRaisesRegex(RuntimeError, "source"):
            self.load(destination / "arm.json")


class CampaignContractTest(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def receipt(self, name: str) -> native_go_build_abba.ArmReceipt:
        arm = self.root / name
        return native_go_build_abba.ArmReceipt(
            path=arm / "arm.json",
            label=name,
            role="control" if name == "control" else "candidate",
            source_repo=self.root / f"{name}-source",
            source_commit=("1" if name == "control" else "2") * 40,
            source_branch=f"codex/{name}",
            source_detached=False,
            binary_path=arm / "carrick",
            binary_size=1024,
            binary_mode=0o555,
            binary_sha256=("a" if name == "control" else "b") * 64,
            macho_uuid=(
                "11111111-2222-3333-4444-555555555555"
                if name == "control"
                else "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
            ),
            entitlement_sha256="e" * 64,
            image_ref=native_go_build.DEFAULT_IMAGE,
            image_id="sha256:" + "3" * 64,
            image_repo_digests=(
                "localhost:5005/carrick-go-conformance@sha256:" + "4" * 64,
            ),
        )

    def overlay(self, **changes: str | None) -> tuple[tuple[str, str | None], ...]:
        values = {
            key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS
        }
        values.update(changes)
        return tuple(
            (key, values[key])
            for key in native_go_build.PERFORMANCE_CONTROL_KEYS
        )

    def arm(
        self,
        label: str,
        receipt: native_go_build_abba.ArmReceipt,
        overlay: tuple[tuple[str, str | None], ...] | None = None,
    ) -> native_go_build_abba.ArmSpec:
        return native_go_build_abba.ArmSpec(
            label=label,
            receipt=receipt,
            environment=self.overlay() if overlay is None else overlay,
        )

    def image_identity(
        self,
        receipt: native_go_build_abba.ArmReceipt,
    ) -> dict[str, object]:
        return {
            "architecture": "arm64",
            "id": receipt.image_id,
            "repo_digests": list(receipt.image_repo_digests),
        }

    def sample(
        self,
        arm: native_go_build_abba.ArmSpec,
        *,
        index: int,
        run_id: str,
        value: float = 100.0,
        build_ok: bool = True,
        image_ref: str | None = None,
        registry_transport: native_go_build.RegistryTransport | None = None,
    ) -> dict[str, object]:
        receipt = arm.receipt
        environment = dict(arm.environment)
        executed_image_ref = (
            receipt.image_repo_digests[0]
            if image_ref is None
            else image_ref
        )
        transport = (
            native_go_build_abba._registry_transport_for_image(
                executed_image_ref
            )
            if registry_transport is None
            else registry_transport
        )
        transport_evidence = native_go_build.registry_transport_evidence(
            transport
        )
        assert transport_evidence is not None
        provenance = {
            "git_commit": "9" * 40,
            "git_status": [],
            "binary_path": str(receipt.binary_path.resolve()),
            "binary_sha256": receipt.binary_sha256,
            "host": {
                "platform": "macOS-fixture",
                "machine": "arm64",
                "node": "fixture-host",
            },
            "image_ref": executed_image_ref,
            "image": self.image_identity(receipt),
            "controlled_environment": environment,
            "foreign_processes": [],
            "docker_oracles": [],
            "engine": native_go_build.ENGINE_CARRICK,
        }
        stdout = "WORKLOAD_NS=100000000\nBUILD_OK\n" if build_ok else "no marker\n"
        return {
            "engine": native_go_build.ENGINE_CARRICK,
            "index": index,
            "run_id": run_id,
            "binary_path": str(receipt.binary_path.resolve()),
            "binary_sha256": receipt.binary_sha256,
            "elapsed_ms": value,
            "cpu_user_s": value * 0.6,
            "cpu_sys_s": value * 0.4,
            "cpu_s": value,
            "workload_ns": int(value * 1_000_000),
            "workload_ms": value,
            "return_code": 0,
            "timed_out": False,
            "build_ok": build_ok,
            "command": {
                "argv": native_go_build.build_command(
                    self.root,
                    native_go_build.ENGINE_CARRICK,
                    run_id,
                    binary=receipt.binary_path.resolve(),
                    image=executed_image_ref,
                    registry_transport=transport,
                ),
                "status": 0,
                "build_ok": build_ok,
            },
            "environment_overlay": environment,
            "controlled_environment": environment,
            "registry_transport": dict(transport_evidence),
            "provenance": {
                "pre": {
                    **provenance,
                    "registry_transport": dict(transport_evidence),
                },
                "post": {
                    **provenance,
                    "registry_transport": dict(transport_evidence),
                },
            },
            "cleanup": {"status": 0, "stdout": "", "stderr": ""},
            "stdout": stdout,
            "stderr": "",
            "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        }

    @contextlib.contextmanager
    def campaign_fixtures(
        self,
        control: native_go_build_abba.ArmSpec,
        candidate: native_go_build_abba.ArmSpec,
        run_sample,
        *,
        receipt_failure_call: int | None = None,
        foreign: list[str] | None = None,
        docker: list[str] | None = None,
        busy: list[str] | None = None,
        battery: str = "Now drawing from 'AC Power'\n",
        thermal: str = (
            "No thermal warning\n"
            "No performance warning\n"
            "No CPU power status\n"
        ),
        current_image: dict[str, object] | None = None,
        sleep=None,
    ):
        receipt_calls = 0
        receipts = {
            control.receipt.path.resolve(): control.receipt,
            candidate.receipt.path.resolve(): candidate.receipt,
        }

        def load_receipt(path):
            nonlocal receipt_calls
            receipt_calls += 1
            if receipt_failure_call == receipt_calls:
                raise RuntimeError("receipt drift before quad")
            return receipts[path.resolve()]

        def command(command, **_kwargs):
            if command == ["pmset", "-g", "batt"]:
                return subprocess.CompletedProcess(command, 0, battery, "")
            if command == ["pmset", "-g", "therm"]:
                return subprocess.CompletedProcess(command, 0, thermal, "")
            raise AssertionError(f"unexpected preflight command: {command!r}")

        with (
            mock.patch.object(
                native_go_build_abba,
                "load_and_verify_arm",
                side_effect=load_receipt,
            ),
            mock.patch.object(
                native_go_build_abba,
                "_image_receipt",
                return_value=(
                    self.image_identity(control.receipt)
                    if current_image is None
                    else current_image
                ),
            ),
            mock.patch.object(
                native_go_build,
                "foreign_workload_census",
                return_value=[] if foreign is None else foreign,
            ),
            mock.patch.object(
                native_go_build,
                "running_docker_oracles",
                return_value=[] if docker is None else docker,
            ),
            mock.patch.object(
                native_go_build,
                "busy_host_reasons",
                return_value=[] if busy is None else busy,
            ),
            mock.patch.object(
                native_go_build_abba.subprocess,
                "run",
                side_effect=command,
            ),
            mock.patch.object(
                native_go_build,
                "run_sample",
                side_effect=run_sample,
            ) as sample_mock,
            mock.patch.object(
                native_go_build_abba.time,
                "sleep",
                side_effect=sleep,
            ),
        ):
            yield sample_mock

    def test_schedule_is_excluded_ab_warmups_then_serial_abba_quads(self):
        calls = native_go_build_abba._campaign_positions(1)

        self.assertEqual(
            [(row["phase"], row["arm"]) for row in calls],
            [
                ("warmup", "A"),
                ("warmup", "B"),
                ("quad-1-a1", "A"),
                ("quad-1-b1", "B"),
                ("quad-1-b2", "B"),
                ("quad-1-a2", "A"),
            ],
        )
        self.assertEqual(
            [row["excluded"] for row in calls],
            [True, True, False, False, False, False],
        )

    def test_arm_modes_accept_only_one_controlled_dimension(self):
        control_receipt = self.receipt("control")
        candidate_receipt = self.receipt("candidate")
        default = self.overlay()
        shared = self.overlay(
            CARRICK_DSR_PERSISTENT_STORE="1",
            CARRICK_DSR_DIRECT_BINDINGS="1",
        )

        self.assertEqual(
            native_go_build_abba.validate_arm_mode(
                self.arm("A", control_receipt, default),
                self.arm("B", control_receipt, default),
            ),
            "same-binary",
        )
        self.assertEqual(
            native_go_build_abba.validate_arm_mode(
                self.arm("A", control_receipt, default),
                self.arm("B", control_receipt, shared),
            ),
            "same-binary",
        )
        self.assertEqual(
            native_go_build_abba.validate_arm_mode(
                self.arm("A", control_receipt, default),
                self.arm("B", candidate_receipt, default),
            ),
            "two-binary",
        )

        with self.assertRaisesRegex(ValueError, "binary.*environment"):
            native_go_build_abba.validate_arm_mode(
                self.arm("A", control_receipt, default),
                self.arm("B", candidate_receipt, shared),
            )

    def test_two_binary_mode_rejects_equal_legacy_candidate_overlays(self):
        legacy_candidate = self.overlay(
            CARRICK_DSR_ARTIFACT_SPIKE="1",
            CARRICK_DSR_PERSISTENT_STORE="1",
            CARRICK_DSR_DIRECT_BINDINGS="1",
        )

        with self.assertRaisesRegex(ValueError, "legacy candidate"):
            native_go_build_abba.validate_arm_mode(
                self.arm("A", self.receipt("control"), legacy_candidate),
                self.arm("B", self.receipt("candidate"), legacy_candidate),
            )

    def test_timing_perturbing_overlays_are_rejected_in_every_arm_mode(self):
        control_receipt = self.receipt("control")
        candidate_receipt = self.receipt("candidate")
        for key in (
            "CARRICK_DSR_PROFILE",
            "CARRICK_NATIVE_TRACE_SYSCALLS",
        ):
            environment = self.overlay(**{key: "1"})
            for mode, candidate in (
                ("same-binary", control_receipt),
                ("two-binary", candidate_receipt),
            ):
                with (
                    self.subTest(key=key, mode=mode),
                    self.assertRaisesRegex(
                        ValueError,
                        rf"timing-perturbing.*{key}",
                    ),
                ):
                    native_go_build_abba.validate_arm_mode(
                        self.arm("A", control_receipt, environment),
                        self.arm("B", candidate, environment),
                    )

    def test_same_binary_rejects_identity_drift_and_legacy_candidate(self):
        receipt = self.receipt("control")
        drifted = dataclasses.replace(receipt, binary_sha256="f" * 64)
        legacy_candidate = self.overlay(
            CARRICK_DSR_ARTIFACT_SPIKE="1",
            CARRICK_DSR_PERSISTENT_STORE="1",
            CARRICK_DSR_DIRECT_BINDINGS="1",
        )

        with self.assertRaisesRegex(ValueError, "identity"):
            native_go_build_abba.validate_arm_mode(
                self.arm("A", receipt),
                self.arm("B", drifted),
            )
        with self.assertRaisesRegex(ValueError, "legacy candidate"):
            native_go_build_abba.validate_arm_mode(
                self.arm("A", receipt),
                self.arm("B", receipt, legacy_candidate),
            )

    def test_same_binary_accepts_equal_complete_overlay_for_null_proof(self):
        receipt = self.receipt("control")
        shared = self.overlay(
            CARRICK_DSR_PERSISTENT_STORE="1",
            CARRICK_DSR_DIRECT_BINDINGS="1",
        )

        self.assertEqual(
            native_go_build_abba.validate_arm_mode(
                self.arm("A", receipt, shared),
                self.arm("B", receipt, shared),
            ),
            "same-binary",
        )

    def test_same_binary_accepts_only_declared_disable_opt_out(self):
        receipt = self.receipt("control")
        candidate = self.overlay()
        control = self.overlay(CARRICK_DISABLE_VDSO="1")

        self.assertEqual(
            native_go_build_abba.validate_arm_mode(
                self.arm("A", receipt, control),
                self.arm("B", receipt, candidate),
            ),
            "same-binary",
        )

        invalid_control = list(control)
        invalid_control[
            native_go_build.PERFORMANCE_CONTROL_KEYS.index(
                "CARRICK_DISABLE_VDSO"
            )
        ] = ("CARRICK_DISABLE_VDSO", "0")
        with self.assertRaisesRegex(ValueError, "declared variant"):
            native_go_build_abba.validate_arm_mode(
                self.arm("A", receipt, tuple(invalid_control)),
                self.arm("B", receipt, candidate),
            )

    def test_same_binary_accepts_declared_default_on_zero_opt_outs(self):
        receipt = self.receipt("control")
        candidate = self.overlay(
            CARRICK_DSR_PERSISTENT_STORE="1",
            CARRICK_DSR_DIRECT_BINDINGS="1",
        )

        for key in (
            "CARRICK_DSR_DIRECT_BYTES",
            "CARRICK_DSR_SHARED_MAPPED_METADATA",
            "CARRICK_DSR_SHARED_MANIFEST_ARC",
            "CARRICK_DSR_SHARED_MANIFEST_FIXED",
            "CARRICK_DSR_SHARED_SOURCE_FINGERPRINT_REUSE",
            "CARRICK_DSR_SHARED_DYLIB_KEYED_IDENTITY",
            "CARRICK_DSR_SHARED_RECOVERY_LAZY",
            "CARRICK_DSR_SHARED_RECOVERY_RUNS",
        ):
            with self.subTest(key=key):
                control = self.overlay(
                    CARRICK_DSR_PERSISTENT_STORE="1",
                    CARRICK_DSR_DIRECT_BINDINGS="1",
                    **{key: "0"},
                )
                self.assertEqual(
                    native_go_build_abba.validate_arm_mode(
                        self.arm("A", receipt, control),
                        self.arm("B", receipt, candidate),
                    ),
                    "same-binary",
                )

    def test_same_binary_accepts_declared_default_off_one_opt_in(self):
        receipt = self.receipt("control")
        control = self.overlay()
        candidate = self.overlay(CARRICK_DSR_PERSISTENT_STORE="1")

        self.assertEqual(
            native_go_build_abba.validate_arm_mode(
                self.arm("A", receipt, control),
                self.arm("B", receipt, candidate),
            ),
            "same-binary",
        )

        for invalid_candidate in (
            self.overlay(CARRICK_DSR_PERSISTENT_STORE="0"),
            self.overlay(CARRICK_DSR_DIRECT_BINDINGS="1"),
        ):
            with self.assertRaisesRegex(ValueError, "declared variant"):
                native_go_build_abba.validate_arm_mode(
                    self.arm("A", receipt, control),
                    self.arm("B", receipt, invalid_candidate),
                )

    def test_two_binary_mode_requires_separate_source_worktrees(self):
        control_receipt = self.receipt("control")
        candidate_receipt = dataclasses.replace(
            self.receipt("candidate"),
            source_repo=control_receipt.source_repo,
        )

        with self.assertRaisesRegex(ValueError, "separate source worktrees"):
            native_go_build_abba.validate_arm_mode(
                self.arm("A", control_receipt),
                self.arm("B", candidate_receipt),
            )

    def test_arm_overlay_requires_the_complete_unique_control_key_set(self):
        receipt = self.receipt("control")
        incomplete = self.overlay()[:-1]
        duplicate = list(self.overlay())
        duplicate[-1] = duplicate[0]
        unknown_opt_out = tuple(
            (
                "CARRICK_DISABLE_UNDECLARED"
                if key == "CARRICK_DISABLE_VDSO"
                else key,
                value,
            )
            for key, value in self.overlay()
        )

        for environment in (incomplete, tuple(duplicate), unknown_opt_out):
            with (
                self.subTest(environment=environment),
                self.assertRaisesRegex(ValueError, "PERFORMANCE_CONTROL_KEYS"),
            ):
                native_go_build_abba.validate_arm_mode(
                    self.arm("A", receipt, environment),
                    self.arm("B", receipt),
                )

    def test_quad_summary_uses_abba_means_and_tie_aware_paired_statistics(self):
        ratios = (0.8, 0.9, 1.0, 0.95, 1.0, 0.85, 0.9, 0.8)
        metrics = (
            "cpu_s",
            "cpu_user_s",
            "cpu_sys_s",
            "elapsed_ms",
            "workload_ms",
        )
        quads = []
        for index, ratio in enumerate(ratios, start=1):
            rows = {}
            for position in ("a1", "b1", "b2", "a2"):
                rows[position] = {}
            for scale, metric in enumerate(metrics, start=1):
                control_quad = 100.0 * scale
                candidate_quad = control_quad * ratio
                rows["a1"][metric] = control_quad - 10.0 * scale
                rows["a2"][metric] = control_quad + 10.0 * scale
                rows["b1"][metric] = candidate_quad - 5.0 * scale
                rows["b2"][metric] = candidate_quad + 5.0 * scale
            quads.append(
                native_go_build_abba.Quad(
                    index=index,
                    a1=rows["a1"],
                    b1=rows["b1"],
                    b2=rows["b2"],
                    a2=rows["a2"],
                )
            )

        result = native_go_build_abba.summarize_quads(quads)

        self.assertEqual(result["quad_count"], 8)
        self.assertEqual(result["primary_metric"], "cpu_s")
        for scale, metric in enumerate(metrics, start=1):
            with self.subTest(metric=metric):
                summary = result["metrics"][metric]
                first = summary["quads"][0]
                self.assertEqual(first["a1"], 90.0 * scale)
                self.assertEqual(first["a2"], 110.0 * scale)
                self.assertEqual(first["control_quad"], 100.0 * scale)
                self.assertEqual(first["b1"], 75.0 * scale)
                self.assertEqual(first["b2"], 85.0 * scale)
                self.assertEqual(first["candidate_quad"], 80.0 * scale)
                self.assertEqual(first["ratio"], 0.8)
                self.assertEqual(summary["control_median"], 100.0 * scale)
                self.assertEqual(summary["candidate_median"], 90.0 * scale)
                self.assertEqual(summary["median_quad_ratio"], 0.9)
                self.assertEqual(summary["candidate_wins"], 6)
                self.assertEqual(summary["ties"], 2)
                self.assertEqual(
                    summary["sign_test"],
                    {
                        "trials": 6,
                        "candidate_wins": 6,
                        "probability": {
                            "numerator": 1,
                            "denominator": 64,
                            "probability": 0.015625,
                        },
                    },
                )
                self.assertEqual(
                    summary["arithmetic_ratio_sd"],
                    0.0801783725737273,
                )
                self.assertEqual(
                    summary["log_ratio_sd"],
                    0.08947478339778714,
                )
                self.assertEqual(
                    summary["bootstrap"]["two_sided_lower"],
                    0.8,
                )
                self.assertEqual(
                    summary["bootstrap"]["two_sided_upper"],
                    1.0,
                )
                self.assertEqual(
                    summary["bootstrap"]["one_sided_upper"],
                    0.975,
                )
                self.assertEqual(
                    summary["bootstrap"]["accepted_indices"],
                    800_000,
                )
                self.assertEqual(
                    summary["resolution"]["resolution_fraction"],
                    0.04662721757160218,
                )
                self.assertEqual(
                    [
                        (row["quad_index"], row["position"], row["arm"])
                        for row in summary["raw_samples"][:4]
                    ],
                    [
                        (1, "a1", "A"),
                        (1, "b1", "B"),
                        (1, "b2", "B"),
                        (1, "a2", "A"),
                    ],
                )

    def test_timeout_and_minimum_quad_inputs_fail_before_execution(self):
        receipt = self.receipt("control")
        arm = self.arm("A", receipt)
        output = self.root / "invalid.json"

        with self.assertRaisesRegex(ValueError, "at least eight"):
            native_go_build_abba.run_campaign(
                self.root,
                arm,
                self.arm("B", receipt),
                output,
                quads=7,
            )
        with self.assertRaisesRegex(ValueError, "timeout_seconds"):
            native_go_build_abba.run_campaign(
                self.root,
                arm,
                self.arm("B", receipt),
                output,
                timeout_seconds=0,
            )
        with self.assertRaisesRegex(ValueError, "at most 127"):
            native_go_build_abba.run_campaign(
                self.root,
                arm,
                self.arm("B", receipt),
                output,
                quads=128,
            )
        self.assertFalse(output.exists())

    def test_run_parser_has_no_resume_state(self):
        receipt = self.root / "arm.json"
        overlay = self.root / "overlay.json"
        argv = [
            "run",
            "--harness-repo",
            str(self.root),
            "--control-receipt",
            str(receipt),
            "--candidate-receipt",
            str(receipt),
            "--control-overlay",
            str(overlay),
            "--candidate-overlay",
            str(overlay),
            "--output",
            str(self.root / "campaign.json"),
        ]
        args = native_go_build_abba.parse_args(argv)

        self.assertEqual(args.command, "run")
        self.assertFalse(hasattr(args, "resume"))
        self.assertFalse(args.allow_battery)
        self.assertTrue(
            native_go_build_abba.parse_args([*argv, "--allow-battery"]).allow_battery
        )

    def test_existing_campaign_output_cannot_be_resumed_or_overwritten(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "existing.json"
        sentinel = b"existing partial evidence\n"
        output.write_bytes(sentinel)

        with self.assertRaisesRegex(FileExistsError, "cannot resume"):
            native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        self.assertEqual(output.read_bytes(), sentinel)

    def test_initial_campaign_publication_requests_exclusive_creation(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "exclusive-initial.json"

        with (
            mock.patch.object(
                native_go_build,
                "write_json_atomic",
                side_effect=RuntimeError("stop after initial publication"),
            ) as writer,
            self.assertRaisesRegex(RuntimeError, "stop after initial"),
        ):
            native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        writer.assert_called_once()
        self.assertEqual(writer.call_args.args[0], output)
        self.assertTrue(writer.call_args.kwargs["exclusive"])

    def test_cli_receipt_drift_is_published_after_recorded_input_decode(self):
        receipt = self.receipt("control")
        overlay = self.root / "overlay.json"
        output = self.root / "cli-receipt-drift.json"

        with (
            mock.patch.object(
                native_go_build_abba,
                "load_recorded_arm",
                side_effect=(receipt, receipt),
                create=True,
            ),
            mock.patch.object(
                native_go_build_abba,
                "load_and_verify_arm",
                side_effect=RuntimeError("receipt source drift"),
            ),
            mock.patch.object(
                native_go_build_abba,
                "_load_overlay",
                return_value=self.overlay(),
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status = native_go_build_abba.main(
                [
                    "run",
                    "--harness-repo",
                    str(self.root),
                    "--control-receipt",
                    str(receipt.path),
                    "--candidate-receipt",
                    str(receipt.path),
                    "--control-overlay",
                    str(overlay),
                    "--candidate-overlay",
                    str(overlay),
                    "--output",
                    str(output),
                ]
            )

        self.assertEqual(status, 1)
        artifact = json.loads(output.read_text())
        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["accepted"])
        self.assertEqual(artifact["samples"], [])
        self.assertIsNone(artifact["failure"]["sample"])
        self.assertIn("receipt source drift", artifact["failure"]["reason"])

    def test_power_preflight_accepts_only_explicit_unlimited_ac_states(self):
        accepted_thermal = (
            "No thermal warning\n"
            "No performance warning\n"
            "No CPU power status\n"
        )
        numeric_thermal = (
            "CPU_Speed_Limit = 100\n"
            "Scheduler_Limit = 100\n"
            "CPU_Available = 1\n"
        )
        for thermal in (accepted_thermal, numeric_thermal):
            with self.subTest(thermal=thermal):
                calls = iter(
                    (
                        subprocess.CompletedProcess(
                            ["pmset", "-g", "batt"],
                            0,
                            "Now drawing from 'AC Power'\n",
                            "",
                        ),
                        subprocess.CompletedProcess(
                            ["pmset", "-g", "therm"],
                            0,
                            thermal,
                            "",
                        ),
                    )
                )
                with mock.patch.object(
                    native_go_build_abba.subprocess,
                    "run",
                    side_effect=lambda *_args, **_kwargs: next(calls),
                ):
                    result = native_go_build_abba._darwin_power_preflight()
                self.assertEqual(result["power_source"], "AC Power")
                self.assertEqual(result["thermal_output"], thermal)

        battery_calls = iter(
            (
                subprocess.CompletedProcess(
                    ["pmset", "-g", "batt"],
                    0,
                    "Now drawing from 'Battery Power'\n",
                    "",
                ),
                subprocess.CompletedProcess(
                    ["pmset", "-g", "therm"],
                    0,
                    accepted_thermal,
                    "",
                ),
            )
        )
        with mock.patch.object(
            native_go_build_abba.subprocess,
            "run",
            side_effect=lambda *_args, **_kwargs: next(battery_calls),
        ):
            battery_result = native_go_build_abba._darwin_power_preflight(
                allow_battery=True
            )
        self.assertEqual(battery_result["power_source"], "Battery Power")
        self.assertTrue(battery_result["battery_authorized"])
        self.assertIn("Battery Power", battery_result["battery_output"])

        rejected = (
            (
                "Now drawing from 'Battery Power'\n",
                accepted_thermal,
                "AC Power",
            ),
            (
                "Now drawing from 'AC Power'\n",
                "CPU_Speed_Limit = 99\nScheduler_Limit = 100\nCPU_Available = 1\n",
                "thermal",
            ),
            (
                "Now drawing from 'AC Power'\n",
                "unrecognized thermal state\n",
                "thermal",
            ),
            (
                "Now drawing from 'AC Power'\n",
                accepted_thermal + "CPU_Speed_Limit = 75\n",
                "thermal",
            ),
            (
                "Now drawing from 'AC Power'\n",
                "CPU_Speed_Limit = 50\n"
                "CPU_Speed_Limit = 100\n"
                "Scheduler_Limit = 100\n"
                "CPU_Available = 1\n",
                "thermal",
            ),
        )
        for battery, thermal, reason in rejected:
            with self.subTest(reason=reason):
                calls = iter(
                    (
                        subprocess.CompletedProcess(
                            ["pmset", "-g", "batt"], 0, battery, ""
                        ),
                        subprocess.CompletedProcess(
                            ["pmset", "-g", "therm"], 0, thermal, ""
                        ),
                    )
                )
                with (
                    mock.patch.object(
                        native_go_build_abba.subprocess,
                        "run",
                        side_effect=lambda *_args, **_kwargs: next(calls),
                    ),
                    self.assertRaisesRegex(RuntimeError, reason),
                ):
                    native_go_build_abba._darwin_power_preflight()

    def test_initial_artifact_retains_each_preflight_failure_with_null_sample(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        scenarios = (
            {
                "name": "battery power",
                "kwargs": {"battery": "Now drawing from 'Battery Power'\n"},
                "reason": "AC Power",
            },
            {
                "name": "thermal warning",
                "kwargs": {"thermal": "CPU_Speed_Limit = 75\n"},
                "reason": "thermal",
            },
            {
                "name": "high load",
                "kwargs": {"busy": ["one-minute load exceeds logical CPUs"]},
                "reason": "one-minute load",
            },
            {
                "name": "active compiler",
                "kwargs": {"busy": ["active compiler: pid=7 args=rustc"]},
                "reason": "active compiler",
            },
            {
                "name": "spin loop",
                "kwargs": {"busy": ["orphaned spin loop: pid=8"]},
                "reason": "spin loop",
            },
            {
                "name": "Docker oracle",
                "kwargs": {"docker": ["abc conformance oracle"]},
                "reason": "Docker",
            },
            {
                "name": "rewritten proctitle",
                "kwargs": {
                    "foreign": ["pid=9 command=carrick:stale-run:compile"]
                },
                "reason": "foreign",
            },
        )
        for scenario in scenarios:
            with self.subTest(name=scenario["name"]):
                output = self.root / f"{scenario['name'].replace(' ', '-')}.json"
                with (
                    self.campaign_fixtures(
                        control,
                        candidate,
                        lambda *_args, **_kwargs: self.fail(
                            "sample launched after failed preflight"
                        ),
                        **scenario["kwargs"],
                    ),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        scenario["reason"],
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                    )
                artifact = json.loads(output.read_text())
                self.assertFalse(artifact["complete"])
                self.assertFalse(artifact["accepted"])
                self.assertIsNone(artifact["failure"]["sample"])
                self.assertIn(scenario["reason"], artifact["failure"]["reason"])
                self.assertEqual(artifact["samples"], [])

    def test_unknown_ambient_carrick_control_is_published_as_preflight_failure(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "ambient.json"
        for key in (
            "CARRICK_UNDECLARED_CONTROL",
            "CARRICK_INSECURE_REGISTRIES",
        ):
            with self.subTest(key=key):
                output = self.root / f"ambient-{key.lower()}.json"
                with (
                    mock.patch.dict(
                        native_go_build_abba.os.environ,
                        {key: "attacker.invalid:5000"},
                        clear=True,
                    ),
                    self.campaign_fixtures(
                        control,
                        candidate,
                        lambda *_args, **_kwargs: self.fail(
                            "sample launched after ambient contamination"
                        ),
                    ),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        "ambient Carrick",
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                    )

                artifact = json.loads(output.read_text())
                self.assertIsNone(artifact["failure"]["sample"])
                self.assertIn(key, artifact["failure"]["reason"])
                self.assertEqual(
                    artifact["identity"]["registry_transport"],
                    {
                        "schema": "carrick.registry-transport.v1",
                        "registry": "localhost:5005",
                        "protocol": "http",
                        "forward_env": (
                            "CARRICK_INSECURE_REGISTRIES=localhost:5005"
                        ),
                    },
                )

    def test_receipt_drift_before_first_quad_keeps_both_completed_warmups(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "receipt-drift.json"
        positions = native_go_build_abba._campaign_positions(8)
        next_call = 0

        def run_sample(_repo, _engine, index, _timeout, **kwargs):
            nonlocal next_call
            position = positions[next_call]
            next_call += 1
            arm = control if position["arm"] == "A" else candidate
            return self.sample(
                arm,
                index=index,
                run_id=kwargs["current_run_id"],
            )

        with (
            self.campaign_fixtures(
                control,
                candidate,
                run_sample,
                receipt_failure_call=3,
            ),
            self.assertRaisesRegex(
                native_go_build_abba.CampaignEvidenceError,
                "receipt drift before quad",
            ),
        ):
            native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        artifact = json.loads(output.read_text())
        self.assertEqual(
            [sample["phase"] for sample in artifact["samples"]],
            ["warmup", "warmup"],
        )
        self.assertIsNone(artifact["failure"]["sample"])

    def test_preflight_registry_transport_drift_preserves_partial_artifact(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        original_preflight = native_go_build_abba._campaign_preflight
        expected_transport = {
            "schema": "carrick.registry-transport.v1",
            "registry": "localhost:5005",
            "protocol": "http",
            "forward_env": "CARRICK_INSECURE_REGISTRIES=localhost:5005",
        }
        scenarios = (
            {
                "name": "initial",
                "drift_call": 1,
                "reason": (
                    "registry transport drifted from campaign image identity"
                ),
                "sample_phases": [],
                "recorded_preflight_registry": "attacker.invalid:5000",
            },
            {
                "name": "quad",
                "drift_call": 2,
                "reason": "registry transport drifted before quad",
                "sample_phases": ["warmup", "warmup"],
                "recorded_preflight_registry": "localhost:5005",
            },
        )
        for scenario in scenarios:
            with self.subTest(name=scenario["name"]):
                output = self.root / f"preflight-{scenario['name']}-drift.json"
                positions = native_go_build_abba._campaign_positions(8)
                preflight_calls = 0
                sample_calls = 0

                def preflight_with_drift(*args, **kwargs):
                    nonlocal preflight_calls
                    preflight_calls += 1
                    result = original_preflight(*args, **kwargs)
                    if preflight_calls != scenario["drift_call"]:
                        return result
                    return {
                        **result,
                        "registry_transport": {
                            **result["registry_transport"],
                            "registry": "attacker.invalid:5000",
                        },
                    }

                def run_sample(_repo, _engine, index, _timeout, **kwargs):
                    nonlocal sample_calls
                    position = positions[sample_calls]
                    sample_calls += 1
                    arm = control if position["arm"] == "A" else candidate
                    return self.sample(
                        arm,
                        index=index,
                        run_id=kwargs["current_run_id"],
                        image_ref=kwargs["image"],
                        registry_transport=kwargs["registry_transport"],
                    )

                with (
                    self.campaign_fixtures(control, candidate, run_sample),
                    mock.patch.object(
                        native_go_build_abba,
                        "_campaign_preflight",
                        side_effect=preflight_with_drift,
                    ),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        scenario["reason"],
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                    )

                artifact = json.loads(output.read_text())
                self.assertFalse(artifact["complete"])
                self.assertFalse(artifact["accepted"])
                self.assertEqual(
                    artifact["identity"]["registry_transport"],
                    expected_transport,
                )
                self.assertEqual(
                    [sample["phase"] for sample in artifact["samples"]],
                    scenario["sample_phases"],
                )
                self.assertIsNone(artifact["failure"]["sample"])
                self.assertEqual(
                    artifact["failure"]["reason"],
                    scenario["reason"],
                )
                self.assertEqual(len(artifact["preflights"]), 1)
                self.assertEqual(
                    artifact["preflights"][0]["registry_transport"][
                        "registry"
                    ],
                    scenario["recorded_preflight_registry"],
                )

    def test_run_image_reference_id_and_digest_must_match_both_receipts(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        matching = self.image_identity(receipt)
        scenarios = (
            {
                "name": "image-ref",
                "image_ref": "localhost:5005/carrick-go-conformance:other",
                "current_image": matching,
                "reason": "image_ref",
            },
            {
                "name": "image-id",
                "image_ref": receipt.image_ref,
                "current_image": {
                    **matching,
                    "id": "sha256:" + "8" * 64,
                },
                "reason": "image identity",
            },
            {
                "name": "image-digest",
                "image_ref": receipt.image_ref,
                "current_image": {
                    **matching,
                    "repo_digests": [
                        "localhost:5005/carrick-go-conformance@sha256:"
                        + "7" * 64
                    ],
                },
                "reason": "image identity",
            },
        )
        for scenario in scenarios:
            with self.subTest(name=scenario["name"]):
                output = self.root / f"{scenario['name']}.json"
                with (
                    self.campaign_fixtures(
                        control,
                        candidate,
                        lambda *_args, **_kwargs: self.fail(
                            "sample launched with mismatched image"
                        ),
                        current_image=scenario["current_image"],
                    ),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        scenario["reason"],
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                        image_ref=scenario["image_ref"],
                    )
                artifact = json.loads(output.read_text())
                self.assertEqual(artifact["samples"], [])
                self.assertIsNone(artifact["failure"]["sample"])

    def test_failure_after_every_schedule_position_retains_all_prior_samples(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        positions = native_go_build_abba._campaign_positions(8)

        for failure_index in range(len(positions)):
            with self.subTest(failure_index=failure_index):
                output = self.root / f"failed-{failure_index}.json"
                call_index = 0

                def run_sample(_repo, _engine, index, _timeout, **kwargs):
                    nonlocal call_index
                    position = positions[call_index]
                    arm = control if position["arm"] == "A" else candidate
                    row = self.sample(
                        arm,
                        index=index,
                        run_id=kwargs["current_run_id"],
                        build_ok=call_index != failure_index,
                    )
                    current = call_index
                    call_index += 1
                    if current == failure_index:
                        raise native_go_build.SampleEvidenceError(
                            f"injected marker failure at {failure_index}",
                            row,
                        )
                    return row

                with (
                    self.campaign_fixtures(control, candidate, run_sample),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        f"injected marker failure at {failure_index}",
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                    )

                artifact = json.loads(output.read_text())
                self.assertFalse(artifact["complete"])
                self.assertFalse(artifact["accepted"])
                self.assertEqual(
                    len(artifact["samples"]),
                    failure_index,
                )
                self.assertEqual(
                    [sample["phase"] for sample in artifact["samples"]],
                    [
                        position["phase"]
                        for position in positions[:failure_index]
                    ],
                )
                self.assertEqual(
                    artifact["failure"]["reason"],
                    f"injected marker failure at {failure_index}",
                )
                self.assertEqual(
                    artifact["failure"]["sample"]["phase"],
                    positions[failure_index]["phase"],
                )

    def test_each_successful_sample_is_published_before_its_cooldown(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "control-control.json"
        positions = native_go_build_abba._campaign_positions(8)
        call_index = 0
        published_counts = []

        def run_sample(_repo, _engine, index, _timeout, **kwargs):
            nonlocal call_index
            position = positions[call_index]
            call_index += 1
            arm = control if position["arm"] == "A" else candidate
            return self.sample(
                arm,
                index=index,
                run_id=kwargs["current_run_id"],
            )

        def cooldown(_seconds):
            artifact = json.loads(output.read_text())
            published_counts.append(len(artifact["samples"]))
            self.assertFalse(artifact["complete"])
            self.assertFalse(artifact["accepted"])

        with self.campaign_fixtures(
            control,
            candidate,
            run_sample,
            sleep=cooldown,
        ) as sample_mock:
            artifact = native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        self.assertEqual(published_counts, list(range(1, 35)))
        self.assertEqual(
            [(row["phase"], row["arm"]) for row in artifact["samples"][:6]],
            [
                ("warmup", "A"),
                ("warmup", "B"),
                ("quad-1-a1", "A"),
                ("quad-1-b1", "B"),
                ("quad-1-b2", "B"),
                ("quad-1-a2", "A"),
            ],
        )
        self.assertEqual(len(sample_mock.call_args_list), 34)
        self.assertTrue(artifact["complete"])
        self.assertTrue(artifact["accepted"])
        self.assertFalse(artifact["decision"]["statistical_pass"])
        self.assertFalse(artifact["decision"]["retained"])
        self.assertEqual(
            artifact["decision"]["reason"],
            "total CPU statistical gates did not establish an improvement",
        )
        self.assertEqual(
            artifact["mechanism"]["status"],
            "external_gate_required",
        )
        self.assertEqual(
            artifact["correctness"]["status"],
            "external_gate_required",
        )

    def test_null_control_control_is_ineligible_even_when_b_is_faster(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "faster-null-control.json"
        positions = native_go_build_abba._campaign_positions(8)
        call_index = 0

        def run_sample(_repo, _engine, index, _timeout, **kwargs):
            nonlocal call_index
            position = positions[call_index]
            call_index += 1
            value = 100.0 if position["arm"] == "A" else 80.0
            return self.sample(
                control,
                index=index,
                run_id=kwargs["current_run_id"],
                value=value,
            )

        with self.campaign_fixtures(
            control,
            candidate,
            run_sample,
        ):
            artifact = native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        self.assertTrue(artifact["accepted"])
        self.assertFalse(artifact["decision"]["statistical_pass"])
        self.assertFalse(artifact["decision"]["retained"])
        self.assertEqual(
            artifact["decision"]["reason"],
            "total CPU statistical gates did not establish an improvement",
        )

    def test_same_binary_real_variant_remains_statistically_eligible(self):
        receipt = self.receipt("control")
        control = self.arm(
            "A",
            receipt,
            self.overlay(CARRICK_DISABLE_VDSO="1"),
        )
        candidate = self.arm("B", receipt)
        output = self.root / "faster-same-binary-variant.json"
        positions = native_go_build_abba._campaign_positions(8)
        call_index = 0

        def run_sample(_repo, _engine, index, _timeout, **kwargs):
            nonlocal call_index
            position = positions[call_index]
            call_index += 1
            arm = control if position["arm"] == "A" else candidate
            value = 100.0 if position["arm"] == "A" else 80.0
            return self.sample(
                arm,
                index=index,
                run_id=kwargs["current_run_id"],
                value=value,
            )

        with self.campaign_fixtures(
            control,
            candidate,
            run_sample,
        ):
            artifact = native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        self.assertTrue(artifact["accepted"])
        self.assertTrue(artifact["decision"]["statistical_pass"])
        self.assertFalse(artifact["decision"]["retained"])

    def test_campaign_executes_receipt_digest_and_records_human_tag(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "digest-bound.json"
        positions = native_go_build_abba._campaign_positions(8)
        call_index = 0
        observed_images = []
        observed_transports = []

        def run_sample(_repo, _engine, index, _timeout, **kwargs):
            nonlocal call_index
            call_index += 1
            observed_images.append(kwargs["image"])
            observed_transports.append(kwargs["registry_transport"])
            return self.sample(
                control,
                index=index,
                run_id=kwargs["current_run_id"],
                image_ref=kwargs["image"],
                registry_transport=kwargs["registry_transport"],
            )

        with self.campaign_fixtures(
            control,
            candidate,
            run_sample,
        ):
            artifact = native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        executed = receipt.image_repo_digests[0]
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
        self.assertEqual(observed_images, [executed] * len(positions))
        self.assertEqual(
            observed_transports,
            [transport] * len(positions),
        )
        self.assertEqual(artifact["identity"]["image_ref"], receipt.image_ref)
        self.assertEqual(
            artifact["identity"]["executed_image_ref"],
            executed,
        )
        self.assertEqual(
            artifact["identity"]["registry_transport"],
            transport_evidence,
        )
        self.assertTrue(
            all(
                preflight["registry_transport"] == transport_evidence
                for preflight in artifact["preflights"]
            )
        )
        self.assertTrue(
            all(
                sample["command"]["argv"][4:6]
                == [
                    "--forward-env",
                    "CARRICK_INSECURE_REGISTRIES=localhost:5005",
                ]
                and sample["command"]["argv"][10] == executed
                and sample["registry_transport"] == transport_evidence
                and sample["provenance"]["pre"]["image_ref"] == executed
                and sample["provenance"]["post"]["image_ref"] == executed
                and sample["provenance"]["pre"]["registry_transport"]
                == transport_evidence
                and sample["provenance"]["post"]["registry_transport"]
                == transport_evidence
                for sample in artifact["samples"]
            )
        )

    def test_registry_transport_authorizes_only_the_approved_loopback(self):
        approved = native_go_build_abba._registry_transport_for_image(
            "localhost:5005/carrick-go-conformance@sha256:" + "4" * 64
        )
        secure_remote = native_go_build_abba._registry_transport_for_image(
            "ghcr.io/carrick-sh/conformance@sha256:" + "5" * 64
        )

        self.assertEqual(
            approved,
            native_go_build.RegistryTransport(
                registry="localhost:5005",
                insecure=True,
            ),
        )
        self.assertEqual(
            secure_remote,
            native_go_build.RegistryTransport(
                registry="ghcr.io",
                insecure=False,
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "not approved"):
            native_go_build_abba._registry_transport_for_image(
                "localhost:5443/carrick-go-conformance@sha256:" + "6" * 64
            )

    def test_campaign_rejects_receipt_digest_from_another_repository(self):
        receipt = dataclasses.replace(
            self.receipt("control"),
            image_repo_digests=(
                "localhost:5005/other-image@sha256:" + "4" * 64,
            ),
        )
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        output = self.root / "mismatched-digest.json"

        with (
            self.campaign_fixtures(
                control,
                candidate,
                lambda *_args, **_kwargs: self.fail(
                    "sample launched with a mismatched repository digest"
                ),
            ),
            self.assertRaisesRegex(
                native_go_build_abba.CampaignEvidenceError,
                "matching immutable repo digest",
            ),
        ):
            native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        artifact = json.loads(output.read_text())
        self.assertFalse(artifact["accepted"])
        self.assertEqual(artifact["samples"], [])
        self.assertIsNone(artifact["failure"]["sample"])

    def test_executed_image_ref_normalizes_repository_and_rejects_ambiguity(self):
        receipt = self.receipt("control")
        matching = receipt.image_repo_digests[0]
        unrelated_first = dataclasses.replace(
            receipt,
            image_repo_digests=(
                "localhost:5005/unrelated@sha256:" + "3" * 64,
                matching,
            ),
        )
        self.assertEqual(
            native_go_build_abba._executed_image_ref(
                receipt.image_ref,
                unrelated_first,
            ),
            matching,
        )

        docker_hub = dataclasses.replace(
            receipt,
            image_ref="index.docker.io/ubuntu:24.04",
            image_repo_digests=(
                "registry-1.docker.io/library/ubuntu@sha256:" + "6" * 64,
            ),
        )
        self.assertEqual(
            native_go_build_abba._executed_image_ref(
                docker_hub.image_ref,
                docker_hub,
            ),
            docker_hub.image_repo_digests[0],
        )

        ambiguous = dataclasses.replace(
            receipt,
            image_repo_digests=(
                "localhost:5005/carrick-go-conformance@sha256:"
                + "4" * 64,
                "localhost:5005/carrick-go-conformance@sha256:"
                + "5" * 64,
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            native_go_build_abba._executed_image_ref(
                ambiguous.image_ref,
                ambiguous,
            )

        for malformed in (
            "localhost:5005/carrick-go-conformance:latest",
            "localhost:5005/carrick-go-conformance@sha256:fake-digest",
            "localhost:5005/carrick-go-conformance@sha256:" + "7" * 63,
            "localhost:5005/carrick-go-conformance@sha256:" + "A" * 64,
        ):
            with (
                self.subTest(malformed=malformed),
                self.assertRaisesRegex(
                    RuntimeError,
                    "no matching immutable repo digest",
                ),
            ):
                invalid = dataclasses.replace(
                    receipt,
                    image_repo_digests=(malformed,),
                )
                native_go_build_abba._executed_image_ref(
                    invalid.image_ref,
                    invalid,
                )

    def test_two_binary_campaign_passes_full_binary_set_and_can_pass_statistics(self):
        control_receipt = self.receipt("control")
        candidate_receipt = self.receipt("candidate")
        control = self.arm("A", control_receipt)
        candidate = self.arm("B", candidate_receipt)
        output = self.root / "two-binary.json"
        positions = native_go_build_abba._campaign_positions(8)
        call_index = 0
        expected_binaries = tuple(
            sorted(
                {
                    control_receipt.binary_path.resolve(),
                    candidate_receipt.binary_path.resolve(),
                }
            )
        )

        def run_sample(_repo, _engine, index, _timeout, **kwargs):
            nonlocal call_index
            position = positions[call_index]
            call_index += 1
            arm = control if position["arm"] == "A" else candidate
            value = 100.0 if position["arm"] == "A" else 80.0
            self.assertEqual(
                kwargs["known_receipt_binaries"],
                expected_binaries,
            )
            self.assertEqual(kwargs["binary"], arm.receipt.binary_path)
            return self.sample(
                arm,
                index=index,
                run_id=kwargs["current_run_id"],
                value=value,
            )

        with (
            self.campaign_fixtures(
                control,
                candidate,
                run_sample,
            ),
            mock.patch.object(
                native_go_build,
                "foreign_workload_census",
                return_value=[],
            ) as census,
        ):
            artifact = native_go_build_abba.run_campaign(
                self.root,
                control,
                candidate,
                output,
            )

        self.assertEqual(len(census.call_args_list), 9)
        for call in census.call_args_list:
            self.assertEqual(
                call.kwargs["known_receipt_binaries"],
                expected_binaries,
            )
        self.assertTrue(artifact["accepted"])
        self.assertTrue(artifact["decision"]["statistical_pass"])
        self.assertFalse(artifact["decision"]["retained"])
        self.assertEqual(
            artifact["decision"]["reason"],
            "statistical gates passed; external mechanism and correctness gates remain required",
        )

    def test_statistical_decision_uses_exact_sign_probability_authority(self):
        denominator = 1 << 127
        numerator = denominator // 20
        self.assertEqual(float(numerator / denominator), 0.05)
        metric = {
            "median_quad_ratio": 0.8,
            "bootstrap": {
                "one_sided_upper": 0.9,
                "two_sided_lower": 0.7,
            },
            "sign_test": {
                "probability": {
                    "numerator": numerator,
                    "denominator": denominator,
                    "probability": 0.05,
                }
            },
        }
        statistics_payload = {
            "quad_count": 8,
            "metrics": {
                "cpu_s": metric,
                "cpu_user_s": dict(metric),
                "cpu_sys_s": dict(metric),
                "elapsed_ms": dict(metric),
                "workload_ms": dict(metric),
            },
        }

        decision = native_go_build_abba._campaign_decision(
            statistics_payload,
            complete=True,
        )

        self.assertTrue(decision["statistical_pass"])
        self.assertTrue(
            decision["criteria"]["total_cpu_sign_probability_below_0_05"]
        )

    def test_campaign_rejects_sample_identity_and_provenance_drift(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        mutations = {
            "binary path": lambda row: row.update(
                {"binary_path": str(self.root / "other-carrick")}
            ),
            "binary sha256": lambda row: row.update(
                {"binary_sha256": "0" * 64}
            ),
            "command binary": lambda row: row["command"]["argv"].__setitem__(
                0, str(self.root / "other-carrick")
            ),
            "command image": lambda row: row["command"]["argv"].__setitem__(
                10,
                "localhost:5005/carrick-go-conformance@sha256:" + "0" * 64,
            ),
            "overlay": lambda row: row["environment_overlay"].update(
                {"CARRICK_DSR_PROFILE": "1"}
            ),
            "run ID": lambda row: row.update({"run_id": "foreign-run"}),
            "engine": lambda row: row.update({"engine": "docker"}),
            "sample index": lambda row: row.update({"index": 999}),
            "pre provenance": lambda row: row["provenance"]["pre"].update(
                {"binary_sha256": "0" * 64}
            ),
            "post provenance": lambda row: row["provenance"]["post"].update(
                {"binary_sha256": "0" * 64}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                output = self.root / f"drift-{name.replace(' ', '-')}.json"

                def run_sample(_repo, _engine, index, _timeout, **kwargs):
                    row = self.sample(
                        control,
                        index=index,
                        run_id=kwargs["current_run_id"],
                    )
                    mutate(row)
                    return row

                with (
                    self.campaign_fixtures(control, candidate, run_sample),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        "sample evidence",
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                    )

                artifact = json.loads(output.read_text())
                self.assertEqual(artifact["samples"], [])
                self.assertIsNotNone(artifact["failure"]["sample"])

    def test_campaign_reconciles_each_registry_transport_evidence_location(self):
        receipt = self.receipt("control")
        control = self.arm("A", receipt)
        candidate = self.arm("B", receipt)
        mutations = (
            (
                "sample",
                lambda row: row["registry_transport"].update(
                    {"registry": "attacker.invalid:5000"}
                ),
                "registry transport",
            ),
            (
                "pre",
                lambda row: row["provenance"]["pre"][
                    "registry_transport"
                ].update({"registry": "attacker.invalid:5000"}),
                "pre/post provenance drift, pre provenance registry transport",
            ),
            (
                "post",
                lambda row: row["provenance"]["post"][
                    "registry_transport"
                ].update({"registry": "attacker.invalid:5000"}),
                "pre/post provenance drift, post provenance registry transport",
            ),
        )
        for location, mutate, expected_reason in mutations:
            with self.subTest(location=location):
                output = self.root / f"registry-{location}-drift.json"

                def run_sample(_repo, _engine, index, _timeout, **kwargs):
                    row = self.sample(
                        control,
                        index=index,
                        run_id=kwargs["current_run_id"],
                    )
                    mutate(row)
                    return row

                with (
                    self.campaign_fixtures(control, candidate, run_sample),
                    self.assertRaisesRegex(
                        native_go_build_abba.CampaignEvidenceError,
                        "sample evidence",
                    ),
                ):
                    native_go_build_abba.run_campaign(
                        self.root,
                        control,
                        candidate,
                        output,
                    )

                artifact = json.loads(output.read_text())
                self.assertEqual(artifact["samples"], [])
                self.assertIsNotNone(artifact["failure"]["sample"])
                self.assertEqual(
                    artifact["failure"]["reason"],
                    f"sample evidence did not reconcile: {expected_reason}",
                )

    def accepted_source(
        self,
        name: str = "accepted.json",
        *,
        complete: bool = True,
        accepted: bool = True,
    ) -> tuple[pathlib.Path, dict[str, object]]:
        source = self.root / name
        payload = {
            "schema": native_go_build_abba.CAMPAIGN_SCHEMA,
            "complete": complete,
            "accepted": accepted,
            "decision": {
                "statistical_pass": False,
                "retained": False,
            },
        }
        source.write_text(json.dumps(payload, sort_keys=True) + "\n")
        return source, payload

    def test_accepted_publication_is_exclusive_fsynced_and_allows_null_result(self):
        source, payload = self.accepted_source()
        destination = self.root / "evidence" / "accepted.json"
        destination.parent.mkdir()

        with (
            mock.patch.object(
                native_go_build_abba.os,
                "replace",
                side_effect=AssertionError("overwrite-capable replace used"),
            ),
            mock.patch.object(
                native_go_build_abba.shutil,
                "copyfile",
                side_effect=AssertionError("overwrite-capable copy used"),
            ),
        ):
            published = native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

        self.assertEqual(published, payload)
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(
            sorted(path.name for path in destination.parent.iterdir()),
            ["accepted.json"],
        )

        with self.assertRaisesRegex(FileExistsError, "destination"):
            native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

    def test_accepted_publication_rejects_partial_unaccepted_and_dangling_collision(self):
        destination = self.root / "published.json"
        for complete, accepted in ((False, True), (True, False)):
            source, _payload = self.accepted_source(
                f"source-{complete}-{accepted}.json",
                complete=complete,
                accepted=accepted,
            )
            with self.assertRaisesRegex(ValueError, "complete.*accepted"):
                native_go_build_abba.publish_accepted_artifact(
                    source,
                    destination,
                )

        dangling = self.root / "dangling.json"
        dangling.symlink_to(self.root / "absent")
        source, _payload = self.accepted_source("collision-source.json")
        with self.assertRaisesRegex(FileExistsError, "destination"):
            native_go_build_abba.publish_accepted_artifact(source, dangling)

    def test_accepted_publication_rejects_source_drift_before_copy(self):
        source, _payload = self.accepted_source()
        destination = self.root / "published.json"
        real_open = native_go_build_abba._open_path_no_symlinks
        source_open_count = 0

        def drift_before_second_open(path, description, **kwargs):
            nonlocal source_open_count
            if pathlib.Path(path) == source:
                source_open_count += 1
                if source_open_count == 2:
                    source.write_text(
                        json.dumps(
                            {
                                "schema": native_go_build_abba.CAMPAIGN_SCHEMA,
                                "complete": True,
                                "accepted": False,
                                "decision": {},
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
            return real_open(path, description, **kwargs)

        with (
            mock.patch.object(
                native_go_build_abba,
                "_open_path_no_symlinks",
                side_effect=drift_before_second_open,
            ),
            self.assertRaisesRegex(RuntimeError, "source drift"),
        ):
            native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

        self.assertFalse(destination.exists())

    def test_accepted_publication_rejects_truncated_temp_before_link(self):
        source, _payload = self.accepted_source()
        destination = self.root / "published.json"
        real_write_all = native_go_build_abba._write_all

        def truncate(descriptor, payload):
            return real_write_all(descriptor, payload[:-1])

        with (
            mock.patch.object(
                native_go_build_abba,
                "_write_all",
                side_effect=truncate,
            ),
            self.assertRaisesRegex(RuntimeError, "temporary"),
        ):
            native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

        self.assertFalse(destination.exists())
        self.assertEqual(
            [path for path in self.root.iterdir() if path.name.startswith(".published.json.")],
            [],
        )

    def test_accepted_publication_rejects_temp_name_substitution(self):
        source, _payload = self.accepted_source()
        destination = self.root / "published.json"
        foreign = b'{"attacker":true}\n'
        real_link = os.link
        swapped_name = None

        def substitute_before_link(
            temporary_name,
            destination_name,
            *,
            src_dir_fd,
            dst_dir_fd,
            follow_symlinks,
        ):
            nonlocal swapped_name
            swapped_name = temporary_name
            os.unlink(temporary_name, dir_fd=src_dir_fd)
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            try:
                os.write(descriptor, foreign)
            finally:
                os.close(descriptor)
            return real_link(
                temporary_name,
                destination_name,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )

        with (
            mock.patch.object(
                native_go_build_abba.os,
                "link",
                side_effect=substitute_before_link,
            ),
            self.assertRaisesRegex(RuntimeError, "identity"),
        ):
            native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

        self.assertIsNotNone(swapped_name)
        self.assertEqual(destination.read_bytes(), foreign)
        self.assertEqual((self.root / swapped_name).read_bytes(), foreign)

    def test_owned_publication_temp_cleanup_tolerates_name_disappearance(self):
        temporary = self.root / ".published.json.tmp"
        temporary.write_text("{}\n")
        directory_descriptor = os.open(self.root, os.O_RDONLY)
        temporary_descriptor = os.open(temporary, os.O_RDONLY)
        self.addCleanup(os.close, directory_descriptor)
        self.addCleanup(os.close, temporary_descriptor)

        with mock.patch.object(
            native_go_build_abba.os,
            "unlink",
            side_effect=FileNotFoundError,
        ):
            native_go_build_abba._unlink_directory_name_if_owned(
                directory_descriptor,
                temporary.name,
                temporary_descriptor,
            )

    def test_parent_sync_failure_is_reported_after_nonoverwriting_link(self):
        source, _payload = self.accepted_source()
        destination = self.root / "published.json"
        real_fsync = os.fsync

        def fail_parent_sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("injected parent sync failure")
            return real_fsync(descriptor)

        with (
            mock.patch.object(
                native_go_build_abba.os,
                "fsync",
                side_effect=fail_parent_sync,
            ),
            self.assertRaisesRegex(OSError, "parent sync"),
        ):
            native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(
            [path for path in self.root.iterdir() if path.name.startswith(".published.json.")],
            [],
        )

    def test_parent_path_swap_cannot_redirect_or_leak_publication(self):
        source, _payload = self.accepted_source()
        parent = self.root / "publication"
        parent.mkdir()
        relocated = self.root / "publication-original"
        destination = parent / "published.json"
        real_write_all = native_go_build_abba._write_all

        def swap_parent_after_write(descriptor, payload):
            written = real_write_all(descriptor, payload)
            parent.rename(relocated)
            parent.mkdir()
            return written

        with (
            mock.patch.object(
                native_go_build_abba,
                "_write_all",
                side_effect=swap_parent_after_write,
            ),
            self.assertRaisesRegex(RuntimeError, "destination parent.*changed"),
        ):
            native_go_build_abba.publish_accepted_artifact(
                source,
                destination,
            )

        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual(list(relocated.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
