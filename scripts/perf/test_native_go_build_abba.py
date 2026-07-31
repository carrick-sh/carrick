#!/usr/bin/env python3

import contextlib
import hashlib
import json
import os
import pathlib
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_go_build_abba


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
        if argv[:2] == ["dwarfdump", "--uuid"]:
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
                "   segname __DATA\n"
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


if __name__ == "__main__":
    unittest.main()
