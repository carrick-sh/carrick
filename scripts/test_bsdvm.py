#!/usr/bin/env python3

import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("bsdvm.py")
SPEC = importlib.util.spec_from_file_location("bsdvm", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BSDVM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BSDVM
SPEC.loader.exec_module(BSDVM)


_HAVE_QEMU_IMG = shutil.which("qemu-img") is not None
_needs_qemu_img = unittest.skipUnless(_HAVE_QEMU_IMG, "qemu-img not installed")


def _mkqcow2(path: Path, size: str = "64M", backing: Path | None = None) -> Path:
    """Create a REAL (tiny, sparse) qcow2 at `path`.

    The golden-rotation tests deal in qcow2 backing-chain structure -- which
    file references which -- so they have to operate on images qemu-img can
    actually parse. A byte-blob stand-in cannot express a backing pointer at
    all, and so cannot reproduce the 2026-07-25 corruption. These are
    kilobytes on disk.
    """
    argv = ["qemu-img", "create", "-f", "qcow2"]
    if backing is not None:
        argv += ["-F", "qcow2", "-b", str(backing)]
    argv += [str(path)]
    if backing is None:
        argv += [size]
    subprocess.run(argv, check=True, capture_output=True)
    return path


def _img_info(path: Path) -> dict:
    p = subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(path)],
        check=True, capture_output=True, text=True,
    )
    return json.loads(p.stdout)


def _virtual_size(path: Path) -> int:
    return int(_img_info(path)["virtual-size"])


def _backing_of(path: Path) -> str | None:
    return _img_info(path).get("backing-filename")


def _virtual_size_of_literal(size: str) -> int:
    return int(size[:-1]) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[size[-1]]


class ConfigTests(unittest.TestCase):
    def test_inventory_matches_spec(self) -> None:
        self.assertEqual(sorted(BSDVM.VMS), ["freebsd-arm64", "netbsd-arm64"])
        fb = BSDVM.VMS["freebsd-arm64"]
        nb = BSDVM.VMS["netbsd-arm64"]
        self.assertEqual(fb.ssh_port, 2201)
        self.assertEqual(nb.ssh_port, 2202)
        self.assertEqual(fb.remote, "fbsd-arm")
        self.assertEqual(nb.remote, "nbsd-arm")
        # NetBSD non-login ssh PATH gotcha must be baked into config, and both
        # guests must pin the libclang bindgen (bad64-sys) loads.
        self.assertIn("/usr/pkg/bin", nb.remote_env_prefix)
        self.assertIn("LIBCLANG_PATH=/usr/pkg/lib", nb.remote_env_prefix)
        self.assertIn("LIBCLANG_PATH=/usr/local/llvm19/lib", fb.remote_env_prefix)

    def test_state_dir_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                d = BSDVM.state_dir("freebsd-arm64")
                self.assertEqual(d, Path(td) / "freebsd-arm64")

    def test_state_dir_default_is_under_home(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "CARRICK_BSDVM_STATE"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                BSDVM.state_root(), Path.home() / ".carrick" / "bsdvm"
            )

    def test_unknown_vm_is_an_error(self) -> None:
        rc = BSDVM.main(["ps", "no-such-vm"])
        self.assertEqual(rc, 2)


class FetchLogicTests(unittest.TestCase):
    def test_parse_checksum_bsd_format(self) -> None:
        text = (
            "SHA512 (FreeBSD-15.1-RELEASE-arm64-aarch64-ufs.qcow2.xz) = " + "ab" * 64 + "\n"
            "SHA512 (other.img) = " + "cd" * 64 + "\n"
        )
        self.assertEqual(
            BSDVM.parse_checksum(text, "FreeBSD-15.1-RELEASE-arm64-aarch64-ufs.qcow2.xz"),
            "ab" * 64,
        )
        with self.assertRaises(KeyError):
            BSDVM.parse_checksum(text, "missing.xz")

    def test_pick_candidate_first_live_url(self) -> None:
        cands = ["https://x/one", "https://x/two", "https://x/three"]
        picked = BSDVM.pick_candidate(cands, probe=lambda u: u.endswith("two"))
        self.assertEqual(picked, "https://x/two")
        with self.assertRaises(SystemExit):
            BSDVM.pick_candidate(cands, probe=lambda u: False)

    def test_fetch_checksum_text_none_when_manifest_unreachable(self) -> None:
        # NetBSD publishes no checksum manifest for gzimg images (verified against
        # cdn.netbsd.org/ftp.netbsd.org across 9.4/10.0/10.1); the raw-text fetch
        # must report None on an unreachable manifest, not raise. What happens
        # next (pinned fallback vs fail-closed) is resolve_expected_sha512's job,
        # covered by ChecksumPolicyTests below.
        with mock.patch.object(BSDVM.urllib.request, "urlopen", side_effect=OSError("404")):
            self.assertIsNone(BSDVM._fetch_checksum_text(BSDVM.VMS["netbsd-arm64"]))

    def test_fetch_checksum_text_returns_raw_text_when_manifest_reachable(self) -> None:
        text = "SHA512 (arm64.img.gz) = " + "ab" * 64 + "\n"
        cm = mock.MagicMock()
        cm.read.return_value = text.encode()
        cm.__enter__.return_value = cm
        with mock.patch.object(BSDVM.urllib.request, "urlopen", return_value=cm):
            self.assertEqual(BSDVM._fetch_checksum_text(BSDVM.VMS["netbsd-arm64"]), text)

    def test_fetch_is_idempotent_when_base_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("netbsd-arm64")
                st.mkdir(parents=True)
                (st / "base.qcow2").write_bytes(b"x")
                ns = mock.Mock(vm="netbsd-arm64", force=False)
                with mock.patch.object(BSDVM, "url_exists") as probe:
                    self.assertEqual(BSDVM.cmd_fetch(ns), 0)
                    probe.assert_not_called()  # no network when base exists

    def test_fetch_removes_stale_part_on_idempotent_skip(self) -> None:
        # A prior interrupted --force refetch can leave base.part.qcow2 behind
        # even though the old base.qcow2 is still intact and trusted. cmd_fetch
        # must sweep the stale part at start regardless of which path it takes.
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("netbsd-arm64")
                st.mkdir(parents=True)
                (st / "base.qcow2").write_bytes(b"x")
                (st / "base.part.qcow2").write_bytes(b"stale-partial-from-interrupted-run")
                ns = mock.Mock(vm="netbsd-arm64", force=False)
                with mock.patch.object(BSDVM, "url_exists") as probe:
                    self.assertEqual(BSDVM.cmd_fetch(ns), 0)
                    probe.assert_not_called()
                self.assertFalse((st / "base.part.qcow2").exists())
                self.assertEqual((st / "base.qcow2").read_bytes(), b"x")  # untouched

    def test_fetch_force_refuses_when_golden_exists(self) -> None:
        # A forced base refetch beneath a live golden chain reproduces the
        # stale-backing corruption class: golden.qcow2 (and every overlay
        # built against it) still points at base.qcow2's path, so rewriting
        # that path's contents in place corrupts every descendant.
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("netbsd-arm64")
                st.mkdir(parents=True)
                (st / "base.qcow2").write_bytes(b"x")
                (st / "golden.qcow2").write_bytes(b"y")
                ns = mock.Mock(vm="netbsd-arm64", force=True)
                with mock.patch.object(BSDVM, "url_exists") as probe:
                    with self.assertRaises(SystemExit) as ctx:
                        BSDVM.cmd_fetch(ns)
                    probe.assert_not_called()  # refused before any network activity
                self.assertIn("golden.qcow2", str(ctx.exception))
                self.assertIn("provision --force", str(ctx.exception))
                # Neither file was touched by the refused refetch.
                self.assertEqual((st / "base.qcow2").read_bytes(), b"x")
                self.assertEqual((st / "golden.qcow2").read_bytes(), b"y")

    def test_fetch_force_proceeds_when_only_base_exists(self) -> None:
        # No golden chain yet -- a forced base refetch is safe and must still
        # proceed exactly as it did before the golden-guard was added.
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("netbsd-arm64")
                st.mkdir(parents=True)
                (st / "base.qcow2").write_bytes(b"x")
                ns = mock.Mock(vm="netbsd-arm64", force=True)
                with mock.patch.object(BSDVM, "url_exists", return_value=False):
                    with self.assertRaises(SystemExit) as ctx:
                        BSDVM.cmd_fetch(ns)
                # Got past the golden guard and into the real fetch flow,
                # which fails later for an unrelated reason (no live
                # candidate URL) -- proof the golden-guard itself didn't fire.
                self.assertNotIn("golden.qcow2", str(ctx.exception))


class AtomicFinalizeTests(unittest.TestCase):
    """`_convert_and_finalize` must never leave a corrupt/partial file at the
    `base.qcow2` name -- it only ever gets there via a rename of a fully
    converted+resized `base.part.qcow2`.
    """

    def test_convert_failure_leaves_no_base_and_no_part(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            src = st / "image.raw"
            src.write_bytes(b"fake-decompressed-bytes")
            part = st / "base.part.qcow2"
            base = st / "base.qcow2"
            vm = BSDVM.VMS["netbsd-arm64"]
            with mock.patch.object(
                BSDVM.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, ["qemu-img", "convert"]),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    BSDVM._convert_and_finalize(vm, src, part, base)
            self.assertFalse(base.exists())
            self.assertFalse(part.exists())  # qemu-img convert never ran for real

    def test_resize_failure_leaves_no_base_even_though_part_was_written(self) -> None:
        # convert "succeeds" (writes `part`), resize fails -> exception must
        # propagate before the rename, so `base` must still not exist even
        # though a (corrupt/partial) file sits at the `.part.qcow2` name.
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            src = st / "image.raw"
            src.write_bytes(b"fake-decompressed-bytes")
            part = st / "base.part.qcow2"
            base = st / "base.qcow2"
            vm = BSDVM.VMS["netbsd-arm64"]

            def fake_run(cmd, check=True):
                if cmd[1] == "convert":
                    Path(cmd[-1]).write_bytes(b"partial-qcow2-from-convert")
                    return mock.Mock(returncode=0)
                raise subprocess.CalledProcessError(1, cmd)

            with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
                with self.assertRaises(subprocess.CalledProcessError):
                    BSDVM._convert_and_finalize(vm, src, part, base)
            self.assertFalse(base.exists())
            self.assertTrue(part.exists())  # partial file stranded at .part, never at base

    def test_success_renames_part_onto_base(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            src = st / "image.raw"
            src.write_bytes(b"fake-decompressed-bytes")
            part = st / "base.part.qcow2"
            base = st / "base.qcow2"
            vm = BSDVM.VMS["freebsd-arm64"]

            def fake_run(cmd, check=True):
                if cmd[1] == "convert":
                    Path(cmd[-1]).write_bytes(b"converted-qcow2")
                elif cmd[1] == "resize":
                    Path(cmd[-2]).write_bytes(b"resized-qcow2")
                return mock.Mock(returncode=0)

            with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
                BSDVM._convert_and_finalize(vm, src, part, base)
            self.assertTrue(base.exists())
            self.assertFalse(part.exists())
            self.assertEqual(base.read_bytes(), b"resized-qcow2")


class FetchIntegrationTests(unittest.TestCase):
    """Drives `cmd_fetch` fully end-to-end against mocked network/subprocess
    boundaries, proving the checksum-policy wiring and the atomic finalize
    actually compose correctly -- not just their unit-tested pieces in
    isolation.
    """

    def test_cmd_fetch_happy_path_mocked(self) -> None:
        vm_name = "freebsd-arm64"
        vm = BSDVM.VMS[vm_name]
        fname = vm.image_candidates[0].rsplit("/", 1)[1]
        raw_bytes = b"pretend-decompressed-disk-image-bytes"
        compressed_bytes = lzma.compress(raw_bytes)  # real xz so _decompress works
        sha = hashlib.sha512(compressed_bytes).hexdigest()
        checksum_text = f"SHA512 ({fname}) = {sha}\n"

        def fake_download(url: str, dst: Path) -> None:
            dst.write_bytes(compressed_bytes)

        def fake_run(cmd: list[str], check: bool = True):
            if cmd[1] == "convert":
                Path(cmd[-1]).write_bytes(b"fake-converted-qcow2")
            elif cmd[1] == "resize":
                Path(cmd[-2]).write_bytes(b"fake-resized-qcow2")
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir(vm_name)
                ns = mock.Mock(vm=vm_name, force=False)
                with (
                    mock.patch.object(BSDVM, "url_exists", return_value=True),
                    mock.patch.object(BSDVM, "_download", side_effect=fake_download),
                    mock.patch.object(
                        BSDVM, "_fetch_checksum_text", return_value=checksum_text
                    ),
                    mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
                ):
                    rc = BSDVM.cmd_fetch(ns)
                self.assertEqual(rc, 0)

                base = st / "base.qcow2"
                self.assertTrue(base.exists())
                self.assertEqual(base.read_bytes(), b"fake-resized-qcow2")
                self.assertFalse((st / "base.part.qcow2").exists())
                # no leftover intermediates
                self.assertFalse((st / fname).exists())
                self.assertFalse((st / "image.raw").exists())
                self.assertFalse((st / "image.qcow2").exists())

                manifest = json.loads((st / "manifest.json").read_text())
                self.assertEqual(manifest["checksum_method"], "upstream")
                self.assertIs(manifest["checksum_verified"], True)
                self.assertEqual(manifest["sha512"], sha)


class ChecksumPolicyTests(unittest.TestCase):
    """Pinned-hash + fail-closed verification policy (resolve_expected_sha512).

    Project policy is fail-closed: an ever-unverified path is not acceptable.
    NetBSD's gzimg tree publishes no checksum file, so netbsd-arm64 carries a
    pinned_sha512 fallback; every other VM (and any future one without a pin)
    must fail closed rather than proceed unverified.
    """

    def test_upstream_hit_wins_over_pinned(self) -> None:
        vm = BSDVM.VMS["netbsd-arm64"]
        text = "SHA512 (arm64.img.gz) = " + "ab" * 64 + "\n"
        got, method = BSDVM.resolve_expected_sha512(vm, text, "arm64.img.gz")
        self.assertEqual(got, "ab" * 64)
        self.assertEqual(method, "upstream")

    def test_falls_back_to_pinned_when_filename_missing_from_upstream(self) -> None:
        vm = BSDVM.VMS["netbsd-arm64"]
        text = "SHA512 (some-other-file.img) = " + "cd" * 64 + "\n"
        got, method = BSDVM.resolve_expected_sha512(vm, text, "arm64.img.gz")
        self.assertEqual(got, vm.pinned_sha512)
        self.assertEqual(method, "pinned")

    def test_falls_back_to_pinned_when_upstream_manifest_unreachable(self) -> None:
        vm = BSDVM.VMS["netbsd-arm64"]
        got, method = BSDVM.resolve_expected_sha512(vm, None, "arm64.img.gz")
        self.assertEqual(got, vm.pinned_sha512)
        self.assertEqual(method, "pinned")

    def test_fails_closed_when_no_upstream_and_no_pin(self) -> None:
        # freebsd-arm64 has a real upstream CHECKSUM.SHA512 and carries no pin;
        # if that manifest is ever unreachable/missing the entry, there is no
        # unverified fallback -- it must raise, not warn-and-proceed.
        vm = BSDVM.VMS["freebsd-arm64"]
        self.assertIsNone(vm.pinned_sha512)
        with self.assertRaises(SystemExit):
            BSDVM.resolve_expected_sha512(vm, None, "whatever.qcow2.xz")
        with self.assertRaises(SystemExit):
            BSDVM.resolve_expected_sha512(
                vm, "SHA512 (other.qcow2.xz) = " + "ef" * 64, "whatever.qcow2.xz"
            )

    def test_pinned_sha512_is_well_formed(self) -> None:
        # Coherence check on the constant itself: 128 lowercase hex chars
        # (a SHA-512 digest), not a placeholder or truncated value.
        nb = BSDVM.VMS["netbsd-arm64"]
        self.assertIsNotNone(nb.pinned_sha512)
        assert nb.pinned_sha512 is not None  # narrow for mypy/type-checkers
        self.assertEqual(len(nb.pinned_sha512), 128)
        self.assertRegex(nb.pinned_sha512, r"^[0-9a-f]{128}$")


class QemuArgsTests(unittest.TestCase):
    def _args(self) -> list[str]:
        vm = BSDVM.VMS["netbsd-arm64"]
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(
                os.environ,
                {"CARRICK_BSDVM_STATE": td, "CARRICK_BSDVM_FW_DIR": td},
            ):
                (Path(td) / "edk2-aarch64-code.fd").touch()
                (Path(td) / "edk2-arm-vars.fd").write_bytes(b"vars")
                return BSDVM.qemu_args(vm, Path(td) / "netbsd-arm64" / "dev.qcow2")

    def test_qemu_args_core_shape(self) -> None:
        args = self._args()
        joined = " ".join(args)
        self.assertEqual(args[0], "qemu-system-aarch64")
        self.assertIn("virt,gic-version=3", joined)
        self.assertIn("-accel hvf -cpu host", joined)
        self.assertIn("-smp 4 -m 6144", joined)
        self.assertIn("virtio-rng-pci", joined)  # NetBSD entropy: mandatory
        self.assertIn("hostfwd=tcp:127.0.0.1:2202-:22", joined)
        self.assertIn("logfile=", joined)
        self.assertIn("-daemonize", joined)
        self.assertIn("qemu.pid", joined)

    def test_efivars_copied_once(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(
                os.environ,
                {"CARRICK_BSDVM_STATE": td, "CARRICK_BSDVM_FW_DIR": td},
            ):
                (Path(td) / "edk2-aarch64-code.fd").touch()
                (Path(td) / "edk2-arm-vars.fd").write_bytes(b"vars")
                p1 = BSDVM.ensure_efivars("freebsd-arm64")
                p1.write_bytes(b"mutated")
                p2 = BSDVM.ensure_efivars("freebsd-arm64")
                self.assertEqual(p2.read_bytes(), b"mutated")  # no re-copy


class InteractiveSshTests(unittest.TestCase):
    """`bsdvm ssh` exists so nobody hand-rolls `ssh -p 220x root@127.0.0.1`:
    that path uses ~/.ssh/known_hosts, which breaks with "Host key
    verification failed" the moment a guest is re-provisioned (new overlay =>
    new host key), and it silently drops the guest's toolchain env prefix."""

    def _argv(self, vm_name: str, command: list[str]) -> list[str]:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                return BSDVM.interactive_ssh_argv(BSDVM.VMS[vm_name], command)

    def test_pins_bsdvm_known_hosts_not_the_users(self) -> None:
        argv = self._argv("netbsd-arm64", ["true"])
        joined = " ".join(argv)
        self.assertIn("UserKnownHostsFile=", joined)
        self.assertNotIn(str(Path.home() / ".ssh"), joined)
        self.assertIn("StrictHostKeyChecking=accept-new", joined)
        self.assertIn("-p", argv)
        self.assertIn("2202", argv)

    def test_remote_command_carries_the_guest_env_prefix(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        argv = self._argv("freebsd-arm64", ["cargo", "build", "-p", "carrick-mem"])
        self.assertTrue(argv[-1].startswith(vm.remote_env_prefix))
        self.assertTrue(argv[-1].endswith("cargo build -p carrick-mem"))

    def test_remote_command_is_quoted_not_concatenated(self) -> None:
        argv = self._argv("netbsd-arm64", ["sh", "-c", "echo a b"])
        # shlex.join keeps the multi-word argument one argument on the guest.
        self.assertIn("'echo a b'", argv[-1])

    def test_no_command_means_interactive_shell_with_no_env_prefix(self) -> None:
        argv = self._argv("netbsd-arm64", [])
        self.assertEqual(argv[-1], "root@127.0.0.1")


class LifecycleTests(unittest.TestCase):
    def test_stop_pid_escalates_to_kill(self) -> None:
        calls: list[tuple[int, int]] = []

        def fake_kill(pid: int, sig: int) -> None:
            calls.append((pid, sig))
            if sig == 0:  # "still alive" while probing until KILL sent
                if any(s == 9 for _, s in calls):
                    raise ProcessLookupError
                return

        BSDVM.stop_pid(42, term_wait_s=0.05, kill=fake_kill, sleep=lambda s: None)
        sigs = [s for _, s in calls]
        self.assertIn(15, sigs)
        self.assertIn(9, sigs)

    def test_stop_pid_no_kill_if_term_works(self) -> None:
        state = {"alive": True}

        def fake_kill(pid: int, sig: int) -> None:
            if sig == 15:
                state["alive"] = False
                return
            if sig == 0:
                if not state["alive"]:
                    raise ProcessLookupError
                return
            self.fail(f"unexpected signal {sig}")

        BSDVM.stop_pid(42, term_wait_s=1.0, kill=fake_kill, sleep=lambda s: None)

    def test_stop_pid_bounded_when_sigkill_never_kills(self) -> None:
        # If SIGKILL itself never manages to kill the process (kill(pid, 0)
        # always succeeds), the post-KILL wait must still be bounded -- it
        # must raise SystemExit rather than loop forever.
        def fake_kill(pid: int, sig: int) -> None:
            return  # every signal "succeeds"; process never looks dead

        with self.assertRaises(SystemExit):
            BSDVM.stop_pid(
                42,
                term_wait_s=0.05,
                kill_wait_s=0.05,
                kill=fake_kill,
                sleep=lambda s: None,
            )

    def test_destroy_protects_base_and_golden(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("freebsd-arm64")
                st.mkdir(parents=True)
                for n in ("base.qcow2", "golden.qcow2", "dev.qcow2", "gate-1.qcow2"):
                    (st / n).write_bytes(b"x")
                ns = mock.Mock(vm="freebsd-arm64", all=False)
                with mock.patch.object(BSDVM, "read_pid", return_value=None):
                    BSDVM.cmd_destroy(ns)
                self.assertTrue((st / "base.qcow2").exists())
                self.assertTrue((st / "golden.qcow2").exists())
                self.assertFalse((st / "dev.qcow2").exists())
                self.assertFalse((st / "gate-1.qcow2").exists())


class PidAliveTests(unittest.TestCase):
    """`pid_alive` is the single probe read_pid/cmd_ps both centralize on."""

    def test_permission_error_is_treated_as_dead(self) -> None:
        # We spawned qemu as this user; an unsignalable pid means the pid
        # was recycled by a foreign process -- accepted pidfile-scheme
        # limitation (see pid_alive's docstring/comment for the caveat).
        with mock.patch.object(BSDVM.os, "kill", side_effect=PermissionError):
            self.assertFalse(BSDVM.pid_alive(42))

    def test_process_lookup_error_is_dead(self) -> None:
        with mock.patch.object(BSDVM.os, "kill", side_effect=ProcessLookupError):
            self.assertFalse(BSDVM.pid_alive(42))

    def test_successful_probe_is_alive(self) -> None:
        with mock.patch.object(BSDVM.os, "kill", return_value=None):
            self.assertTrue(BSDVM.pid_alive(42))


class PsDisplayTests(unittest.TestCase):
    def test_cmd_ps_malformed_pidfile_reports_orphan_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("freebsd-arm64")
                st.mkdir(parents=True)
                (st / "qemu.pid").write_text("garbage")
                ns = mock.Mock(vm="freebsd-arm64")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = BSDVM.cmd_ps(ns)
                self.assertEqual(rc, 0)
                self.assertIn("orphan-pidfile", out.getvalue())


class SerialConsoleTests(unittest.TestCase):
    def test_expect_and_sendline_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "serial.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            srv.listen(1)
            got: list[bytes] = []

            def server() -> None:
                conn, _ = srv.accept()
                conn.sendall(b"NetBSD/evbarm (netbsd) (constty)\n\nlogin: ")
                got.append(conn.recv(64))
                conn.sendall(b"# ")
                conn.close()

            t = threading.Thread(target=server)
            t.daemon = True
            t.start()
            try:
                con = BSDVM.SerialConsole(sock_path)
                pre = con.expect(b"login: ", timeout_s=5)
                self.assertIn(b"NetBSD", pre)
                con.sendline("root")
                con.expect(b"# ", timeout_s=5)
                con._sock.close()
                t.join(timeout=5)
                self.assertEqual(got[0], b"root\n")
            finally:
                srv.close()

    def test_expect_raises_connectionerror_not_timeout_on_eof(self) -> None:
        # The peer (qemu) closing the connection before the pattern arrives
        # must surface as ConnectionError, distinct from a real TimeoutError
        # (and must not silently return) -- see expect()'s EOF-vs-timeout
        # comment: recv() on a closed socket returns b"" immediately rather
        # than raising, so this is the busy-loop bug's regression coverage.
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "serial.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            srv.listen(1)

            def server() -> None:
                conn, _ = srv.accept()
                conn.close()  # EOF before the pattern ever arrives

            t = threading.Thread(target=server)
            t.daemon = True
            t.start()
            try:
                con = BSDVM.SerialConsole(sock_path)
                with self.assertRaises(ConnectionError):
                    con.expect(b"login: ", timeout_s=5)
            finally:
                con._sock.close()
                t.join(timeout=5)
                srv.close()

    def test_expect_timeout_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "serial.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            srv.listen(1)
            accepted: list[socket.socket] = []

            def server() -> None:
                conn, _ = srv.accept()
                accepted.append(conn)

            t = threading.Thread(target=server)
            t.daemon = True
            t.start()
            try:
                con = BSDVM.SerialConsole(sock_path)
                with self.assertRaises(TimeoutError):
                    con.expect(b"never", timeout_s=0.2)
                con._sock.close()
                t.join(timeout=5)
            finally:
                for conn in accepted:
                    conn.close()
                srv.close()


class ProvisionDataTests(unittest.TestCase):
    def test_freebsd_commands_cover_spec_steps(self) -> None:
        cmds = " && ".join(
            c for c, _ in BSDVM.provision_commands(BSDVM.VMS["freebsd-arm64"], "ssh-ed25519 KEY x")
        )
        for needle in (
            "authorized_keys", "sshd_enable=YES", "pkg install",
            "git", "rust",
            # libclang for bad64-sys's bindgen; FreeBSD base ships none.
            "llvm19",
            "receive.denyCurrentBranch updateInstead",
            "shutdown -p now",
        ):
            self.assertIn(needle, cmds)

    def test_netbsd_commands_cover_spec_steps(self) -> None:
        cmds = " && ".join(
            c for c, _ in BSDVM.provision_commands(BSDVM.VMS["netbsd-arm64"], "ssh-ed25519 KEY x")
        )
        for needle in (
            "authorized_keys", "sshd=YES", "pkg_add",
            "receive.denyCurrentBranch updateInstead", "shutdown -p now",
        ):
            self.assertIn(needle, cmds)


class PathExportShapeTests(unittest.TestCase):
    """Regression coverage for the `PATH=... cmd1 && cmd2` footgun (Task 6
    report bug #2): a bare prefix assignment only scopes PATH to the single
    command immediately following it, so anything after a `&&` on the same
    line silently runs without it. Behavior assertion over every actual
    provisioning command for both VMs, not a snapshot of specific strings.
    """

    _BARE_PREFIX_WITH_AND = re.compile(r"^PATH=\S+ .*&&")

    def _all_commands(self) -> list[str]:
        pubkey = "ssh-ed25519 AAAA test"
        cmds: list[str] = []
        for vm_name in ("freebsd-arm64", "netbsd-arm64"):
            cmds += [c for c, _ in BSDVM.provision_commands(BSDVM.VMS[vm_name], pubkey)]
        return cmds

    def test_no_command_uses_broken_bare_prefix_with_compound_shape(self) -> None:
        for cmd in self._all_commands():
            self.assertNotRegex(
                cmd,
                self._BARE_PREFIX_WITH_AND,
                msg=(
                    "a bare `PATH=... ` prefix combined with `&&` only scopes "
                    f"PATH to the first command: {cmd!r}"
                ),
            )

    def test_remote_env_prefix_uses_export_not_a_bare_assignment(self) -> None:
        """The SAME footgun, in the one place it went unnoticed for longer: the
        per-VM env prefix is prepended to command strings of the shape
        `cd /root/carrick && cargo ...`, so a bare `VAR=value ` prefix would
        scope the variable to the `cd` and never reach cargo (measured on both
        guests). It must be a terminated `export ...; ` statement.
        """
        for vm_name in ("freebsd-arm64", "netbsd-arm64"):
            prefix = BSDVM.VMS[vm_name].remote_env_prefix
            self.assertTrue(prefix, f"{vm_name}: expected a non-empty env prefix")
            self.assertRegex(
                prefix,
                r"^export \S+=.*; $",
                msg=(
                    f"{vm_name}: env prefix must be `export ...; ` — a bare "
                    f"`VAR=value ` prefix dies at the first `&&`: {prefix!r}"
                ),
            )
            # And it must actually survive a compound command in a real shell.
            probe = subprocess.run(
                ["/bin/sh", "-c", prefix + "cd / && env"],
                capture_output=True,
                text=True,
            )
            self.assertIn("LIBCLANG_PATH=", probe.stdout)

    def test_git_setup_command_uses_export_path(self) -> None:
        for vm_name in ("freebsd-arm64", "netbsd-arm64"):
            cmds = [
                c for c, _ in BSDVM.provision_commands(BSDVM.VMS[vm_name], "ssh-ed25519 AAAA test")
            ]
            git_setup_cmds = [c for c in cmds if "receive.denyCurrentBranch" in c]
            self.assertEqual(len(git_setup_cmds), 1, f"{vm_name}: expected exactly one git-setup command")
            self.assertRegex(git_setup_cmds[0], r"^export PATH=[^;]+;")


# A pubkey whose trailing user@host comment embeds a literal `'`; this is
# exactly the shape that broke naive `echo '{pubkey}'` interpolation.
_TRICKY_PUBKEY = "ssh-ed25519 AAAA test's-mac"


class ShQuoteTests(unittest.TestCase):
    """`_sh_squote` must produce a POSIX single-quoted token that a real
    `/bin/sh` hands back byte-for-byte -- proven by actually invoking the
    shell (a safe, local, instant call), not just by inspecting the string.
    """

    def _round_trip(self, escaped: str, original: str) -> None:
        result = subprocess.run(
            ["/bin/sh", "-c", f"printf %s {escaped}"],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout, original)

    def test_sh_squote_escapes_embedded_quote_and_round_trips(self) -> None:
        escaped = BSDVM._sh_squote(_TRICKY_PUBKEY)
        self.assertIn("'\\''", escaped)  # POSIX-escaped form present
        self._round_trip(escaped, _TRICKY_PUBKEY)

    def test_provision_commands_key_cmd_is_squoted_and_round_trips(self) -> None:
        # Exercise the actual call site, not just the helper in isolation.
        key_cmd = BSDVM.provision_commands(BSDVM.VMS["freebsd-arm64"], _TRICKY_PUBKEY)[0][0]
        escaped = BSDVM._sh_squote(_TRICKY_PUBKEY)
        self.assertIn(escaped, key_cmd)
        self._round_trip(escaped, _TRICKY_PUBKEY)


class CloudInitSeedTests(unittest.TestCase):
    """`write_cloudinit_seed` must derive its `runcmd` list from
    `provision_commands` (the single source of truth) rather than
    hand-duplicating commands that can drift out of sync.
    """

    def test_netbsd_name_raises_systemexit(self) -> None:
        with self.assertRaises(SystemExit):
            BSDVM.write_cloudinit_seed("netbsd-arm64", _TRICKY_PUBKEY)

    def test_freebsd_seed_user_data_matches_provision_commands_no_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                with mock.patch.object(
                    BSDVM.subprocess, "run", return_value=mock.Mock(returncode=0)
                ) as run_mock:
                    BSDVM.write_cloudinit_seed("freebsd-arm64", _TRICKY_PUBKEY)
                run_mock.assert_called_once()  # only the hdiutil packing call
                st = BSDVM.state_dir("freebsd-arm64")
                user_data = (st / "seed" / "user-data").read_text()

                cmds = BSDVM.provision_commands(BSDVM.VMS["freebsd-arm64"], _TRICKY_PUBKEY)
                key_cmd, pkg_install_cmd = cmds[0][0], cmds[3][0]
                self.assertIn("pkg install", pkg_install_cmd)  # sanity on the index

                expected_line = f"  - {BSDVM._yaml_dquote(pkg_install_cmd)}\n"
                self.assertIn(expected_line, user_data)  # exact-equality derivation, no drift

                self.assertNotIn(key_cmd, user_data)  # authorized_keys step not re-run via runcmd
                self.assertIn(BSDVM._yaml_dquote(_TRICKY_PUBKEY), user_data)  # ssh_authorized_keys


class ProvisionOrchestrationTests(unittest.TestCase):
    """cmd_provision's replace-then-invalidate orchestration around --force:
    the previous golden must survive untouched until a replacement fully
    lands (boot/provision/shutdown all succeed), and any stale consumer
    overlay (dev.qcow2, gate-*.qcow2) must not survive a golden replacement.
    All boundaries (boot, serial console, subprocess) are mocked; only real
    filesystem operations run, against a tmpdir state root.
    """

    # Distinct virtual sizes are how these tests tell one image from another
    # after the renames: a qcow2's identity here is structural (its size and
    # its backing pointer), not a byte blob.
    BASE_SIZE = "64M"
    OLD_GOLDEN_SIZE = "128M"

    @staticmethod
    def _fake_create_overlay(vm_name: str, name: str, backing: str) -> Path:
        # A REAL overlay (see _mkqcow2): the rotation logic under test is
        # about backing-chain structure, so the fixture has to have one.
        st = BSDVM.state_dir(vm_name)
        overlay = st / name
        if not overlay.exists():
            _mkqcow2(overlay, backing=st / backing)
        return overlay

    @_needs_qemu_img
    def test_provision_force_success_rotates_golden_and_invalidates_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = BSDVM.state_dir(vm_name)
                st.mkdir(parents=True)
                _mkqcow2(st / "base.qcow2", size=self.BASE_SIZE)
                _mkqcow2(st / "golden.qcow2", size=self.OLD_GOLDEN_SIZE)
                _mkqcow2(st / "dev.qcow2", backing=st / "golden.qcow2")
                _mkqcow2(st / "gate-9.qcow2", backing=st / "golden.qcow2")

                ns = mock.Mock(vm=vm_name, force=True)
                with (
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(BSDVM, "_run_serial_provision", return_value=None),
                    mock.patch.object(BSDVM, "wait_for_shutdown", return_value=None),
                    mock.patch.object(BSDVM, "read_pubkey", return_value="ssh-ed25519 AAAA test"),
                    mock.patch.object(BSDVM, "create_overlay", side_effect=self._fake_create_overlay),
                    mock.patch.object(BSDVM, "ensure_dev_remote") as ensure_remote,
                ):
                    rc = BSDVM.cmd_provision(ns)
                self.assertEqual(rc, 0)

                # The old golden was rotated aside intact (identified by its
                # distinct virtual size), and the new golden is the work
                # overlay -- still backed by base.qcow2, never by itself.
                self.assertEqual(
                    _virtual_size(st / "golden.prev.qcow2"),
                    _virtual_size_of_literal(self.OLD_GOLDEN_SIZE),
                )
                self.assertTrue((st / "golden.qcow2").exists())
                self.assertEqual(
                    Path(_backing_of(st / "golden.qcow2") or "").resolve(),
                    (st / "base.qcow2").resolve(),
                )
                # And the published golden is openable end to end -- the check
                # the 2026-07-25 incident had no equivalent of.
                BSDVM._assert_openable(st / "golden.qcow2")
                # dev.qcow2 is moved aside (a human's working disk), gate
                # overlays are destroyed (machine scratch).
                self.assertFalse((st / "dev.qcow2").exists())
                stale = sorted(st.glob("dev.stale-*.qcow2"))
                self.assertEqual(len(stale), 1, f"expected dev.qcow2 preserved aside, got {stale}")
                self.assertFalse((st / "gate-9.qcow2").exists())
                # ensure_dev_remote is called after the golden lands (never
                # against the real repo's .git/config from this test).
                ensure_remote.assert_called_once_with(BSDVM.VMS[vm_name])

    @_needs_qemu_img
    def test_provision_failure_leaves_old_golden_untouched_and_stops_vm(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = BSDVM.state_dir(vm_name)
                st.mkdir(parents=True)
                _mkqcow2(st / "base.qcow2", size=self.BASE_SIZE)
                _mkqcow2(st / "golden.qcow2", size=self.OLD_GOLDEN_SIZE)

                stop_calls: list[int] = []
                ns = mock.Mock(vm=vm_name, force=True)
                with (
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "_run_serial_provision",
                        side_effect=RuntimeError("serial boom"),
                    ),
                    mock.patch.object(BSDVM, "wait_for_shutdown", return_value=None),
                    mock.patch.object(BSDVM, "read_pubkey", return_value="ssh-ed25519 AAAA test"),
                    mock.patch.object(BSDVM, "create_overlay", side_effect=self._fake_create_overlay),
                    mock.patch.object(BSDVM, "read_pid", return_value=12345),
                    mock.patch.object(
                        BSDVM, "stop_pid", side_effect=lambda pid: stop_calls.append(pid)
                    ),
                ):
                    with self.assertRaises(RuntimeError):
                        BSDVM.cmd_provision(ns)

                self.assertEqual(stop_calls, [12345])
                self.assertEqual(
                    _virtual_size(st / "golden.qcow2"),
                    _virtual_size_of_literal(self.OLD_GOLDEN_SIZE),
                )
                self.assertFalse((st / "golden.prev.qcow2").exists())
                # The work overlay was created but never renamed onto golden.
                self.assertTrue((st / "provision.qcow2").exists())
                self.assertEqual(
                    Path(_backing_of(st / "provision.qcow2") or "").resolve(),
                    (st / "base.qcow2").resolve(),
                )


class RunSerialProvisionLoginFallbackTests(unittest.TestCase):
    """`_run_serial_provision`'s login-fallback branch: some images (seen on
    NetBSD gzimg first boot per the Task 6 report) drop straight to a bare
    shell prompt and never present a `login: ` prompt at all. `LOGIN_TIMEOUT_S`
    is patched small so this test doesn't wait out the production 600s
    budget.
    """

    def test_falls_back_to_bare_prompt_and_sends_first_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm = BSDVM.VMS["netbsd-arm64"]
                st = BSDVM.state_dir(vm.name)
                st.mkdir(parents=True)
                sock_path = st / "serial.sock"
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                srv.bind(str(sock_path))
                srv.listen(1)
                received: list[bytes] = []
                pubkey = "ssh-ed25519 AAAA test"
                real_first_cmd = BSDVM.provision_commands(vm, pubkey)[0]

                def server() -> None:
                    conn, _ = srv.accept()
                    # Never send "login: " at all -- only respond once the
                    # client's post-timeout nudge newline (the fallback
                    # branch) arrives, with a bare shell prompt.
                    received.append(conn.recv(64))  # sendline("") nudge
                    conn.sendall(b"# ")
                    # The function should now proceed into the provisioning
                    # loop and send its first real command, which it will only
                    # consider done once a step sentinel carrying an exit
                    # status comes back.
                    received.append(conn.recv(8192))
                    conn.sendall(b"__BSDVM_STEP_1_RC_0_END__\n# ")
                    received.append(conn.recv(8192))  # the shutdown command
                    conn.close()

                t = threading.Thread(target=server)
                t.daemon = True
                t.start()
                # Capture the SerialConsole _run_serial_provision creates
                # internally, purely so this test can close its client
                # socket explicitly afterward instead of leaving cleanup to
                # the GC.
                created: list[BSDVM.SerialConsole] = []
                real_serial_console = BSDVM.SerialConsole

                def capturing_serial_console(sock_path_arg):
                    con = real_serial_console(sock_path_arg)
                    created.append(con)
                    return con

                try:
                    with (
                        mock.patch.object(BSDVM, "LOGIN_TIMEOUT_S", 0.4),
                        mock.patch.object(
                            BSDVM, "provision_commands",
                            return_value=[real_first_cmd, ("shutdown -p now", 5)],
                        ),
                        mock.patch.object(BSDVM, "provision_postconditions", return_value=[]),
                        mock.patch.object(
                            BSDVM, "SerialConsole", side_effect=capturing_serial_console
                        ),
                    ):
                        BSDVM._run_serial_provision(vm, pubkey)
                finally:
                    for con in created:
                        con._sock.close()
                    t.join(timeout=5)
                    srv.close()

                self.assertEqual(received[0], b"\n")  # sendline("") nudge
                self.assertTrue(
                    received[1].startswith(real_first_cmd[0].encode()),
                    f"expected the real first command, got {received[1]!r}",
                )
                self.assertEqual(received[2], b"shutdown -p now\n")


class ParseSymrefHeadTests(unittest.TestCase):
    """`parse_symref_head` is pure string parsing of `git ls-remote --symref
    <url> HEAD` output -- unit tested directly, no subprocess/network.
    """

    def test_happy_path_extracts_branch_name(self) -> None:
        text = "ref: refs/heads/master\tHEAD\nabc123\tHEAD\n"
        self.assertEqual(BSDVM.parse_symref_head(text), "master")

    def test_happy_path_extracts_main(self) -> None:
        text = "ref: refs/heads/main\tHEAD\n" + "f" * 40 + "\tHEAD\n"
        self.assertEqual(BSDVM.parse_symref_head(text), "main")

    def test_missing_symref_raises_systemexit(self) -> None:
        # e.g. a brand-new empty repo with no commits yet: ls-remote --symref
        # reports nothing at all (see push_head's empty-repo fallback path).
        with self.assertRaises(SystemExit):
            BSDVM.parse_symref_head("")


class GitSetupDataTests(unittest.TestCase):
    def test_git_setup_pins_default_branch_to_main(self) -> None:
        # Plain `git init` defaults to whatever the local git's
        # init.defaultBranch happens to be (commonly "master"); pin it
        # explicitly so future golden images check out "main", matching
        # push_head's own fallback for a brand-new (still-empty) guest repo.
        self.assertIn("init -b main", BSDVM._GIT_SETUP)


class SshGitTests(unittest.TestCase):
    def test_ssh_base_pins_port_and_known_hosts(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                base = BSDVM.ssh_base(vm)
        joined = " ".join(base)
        self.assertIn("-p 2201", joined)
        self.assertIn("known_hosts", joined)
        self.assertIn("root@127.0.0.1", joined)

    def test_ssh_run_applies_the_env_prefix(self) -> None:
        """Every remote command carries its VM's env prefix, in the `export`
        form that survives the `&&` in a real gate command (see
        `PathExportShapeTests`)."""
        for vm_name, needles in (
            ("netbsd-arm64", ("export PATH=/usr/pkg/bin", "LIBCLANG_PATH=/usr/pkg/lib")),
            ("freebsd-arm64", ("export LIBCLANG_PATH=/usr/local/llvm19/lib",)),
        ):
            vm = BSDVM.VMS[vm_name]
            with mock.patch.object(BSDVM.subprocess, "run") as run:
                run.return_value = mock.Mock(returncode=0)
                BSDVM.ssh_run(vm, "cd /root/carrick && cargo --version", timeout_s=10)
            remote_cmd = run.call_args.args[0][-1]
            self.assertTrue(
                remote_cmd.startswith("export "), f"{vm_name}: {remote_cmd!r}"
            )
            for needle in needles:
                self.assertIn(needle, remote_cmd, f"{vm_name}: {remote_cmd!r}")
            self.assertTrue(remote_cmd.endswith("cargo --version"))

    def test_git_url(self) -> None:
        self.assertEqual(
            BSDVM.git_url(BSDVM.VMS["netbsd-arm64"]),
            "ssh://root@127.0.0.1:2202/root/carrick",
        )

    def test_ssh_wait_succeeds_once_ssh_run_returns_zero(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        with mock.patch.object(
            BSDVM, "ssh_run", return_value=mock.Mock(returncode=0)
        ) as run:
            BSDVM.ssh_wait(vm, timeout_s=30)
        run.assert_called_once_with(vm, "true", timeout_s=10)

    def test_ssh_wait_retries_through_timeout_and_nonzero_then_succeeds(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        results: list = [
            subprocess.TimeoutExpired(cmd="ssh", timeout=10),
            mock.Mock(returncode=255),
            mock.Mock(returncode=0),
        ]

        def fake_ssh_run(vm_arg, cmd, timeout_s):
            r = results.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

        with (
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
            mock.patch.object(BSDVM.time, "sleep", return_value=None),
        ):
            BSDVM.ssh_wait(vm, timeout_s=30)
        self.assertEqual(results, [])  # all three attempts consumed

    def test_ssh_wait_raises_systemexit_after_deadline(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        with (
            mock.patch.object(
                BSDVM, "ssh_run", return_value=mock.Mock(returncode=255)
            ),
            mock.patch.object(BSDVM.time, "sleep", return_value=None),
        ):
            with self.assertRaises(SystemExit):
                BSDVM.ssh_wait(vm, timeout_s=0)

    def test_git_ssh_env_command_matches_ssh_base_options(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                base = BSDVM.ssh_base(vm)
                env = BSDVM.git_ssh_env(vm)
        self.assertIn("GIT_SSH_COMMAND", env)
        # The three -o options from ssh_base must all appear verbatim.
        for opt in base[3:-1]:
            self.assertIn(opt, env["GIT_SSH_COMMAND"])
        # host/port must NOT be baked into the command (the ssh:// URL
        # carries those instead).
        self.assertNotIn("root@127.0.0.1", env["GIT_SSH_COMMAND"])
        self.assertNotIn(f"-p {vm.ssh_port}", env["GIT_SSH_COMMAND"])

    def _push_head_fake_run(self, rev_parse_sha="deadbeef1234\n", ls_remote_stdout=None):
        """Build a `subprocess.run` side_effect covering push_head's
        non-ssh_run calls (`git rev-parse`, the `ls-remote --symref`
        fallback, and `git push`), plus the list `push_calls` it appends to.
        `ls_remote_stdout=None` means the ls-remote fallback must NOT be
        reached at all (any call raises AssertionError) -- used by tests
        where the ssh_run symbolic-ref probe alone must resolve the branch.
        """
        rev_parse = mock.Mock(returncode=0, stdout=rev_parse_sha)
        ls_remote = (
            None if ls_remote_stdout is None else mock.Mock(returncode=0, stdout=ls_remote_stdout)
        )
        push = mock.Mock(returncode=0)
        push_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["git", "rev-parse"]:
                return rev_parse
            if cmd[:3] == ["git", "ls-remote", "--symref"]:
                if ls_remote is None:
                    raise AssertionError(
                        "ls-remote fallback must not run when the ssh "
                        "symbolic-ref probe already resolved the branch"
                    )
                return ls_remote
            if cmd[:2] == ["git", "push"]:
                push_calls.append(cmd)
                return push
            raise AssertionError(f"unexpected command: {cmd}")

        return fake_run, push_calls

    @staticmethod
    def _push_head_fake_ssh_run(probe_result, materialized_ok=True, checkout_fixes_it=True):
        """Build an `ssh_run` side_effect covering push_head's guest-side
        calls: the `symbolic-ref --short HEAD` branch probe, the post-push
        `test -f Cargo.toml` materialization check, and (if that check fails)
        the forced-checkout recovery attempt.

        `probe_result` is either a str (the branch the probe reports, rc=0),
        a `subprocess.TimeoutExpired` instance to raise, or `None`/anything
        falsy meaning the probe returns rc=1 with empty stdout (inconclusive,
        e.g. not a git worktree yet).
        """
        checkout_calls: list[str] = []

        def fake_ssh_run(vm_arg, cmd, timeout_s):
            if "symbolic-ref" in cmd:
                if isinstance(probe_result, BaseException):
                    raise probe_result
                if probe_result:
                    return mock.Mock(returncode=0, stdout=f"{probe_result}\n")
                return mock.Mock(returncode=1, stdout="")
            if cmd == "test -f /root/carrick/Cargo.toml":
                if not checkout_calls:
                    return mock.Mock(returncode=0 if materialized_ok else 1)
                # This is the post-checkout recheck.
                return mock.Mock(returncode=0 if checkout_fixes_it else 1)
            if "checkout -f" in cmd:
                checkout_calls.append(cmd)
                return mock.Mock(returncode=0)
            raise AssertionError(f"unexpected ssh_run command: {cmd!r}")

        return fake_ssh_run, checkout_calls

    def test_push_head_resolves_branch_via_ssh_symbolic_ref_probe(self) -> None:
        # Primary path: `git symbolic-ref --short HEAD` over ssh resolves the
        # guest's checked-out branch directly, without ever needing
        # `ls-remote --symref` (which cannot distinguish an unborn HEAD from
        # no repo at all -- see push_head's docstring comment).
        vm = BSDVM.VMS["freebsd-arm64"]
        fake_run, push_calls = self._push_head_fake_run(ls_remote_stdout=None)
        fake_ssh_run, _ = self._push_head_fake_ssh_run("main")

        with (
            mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
        ):
            sha = BSDVM.push_head(vm)
        self.assertEqual(sha, "deadbeef1234")
        self.assertEqual(len(push_calls), 1)
        self.assertIn(BSDVM.git_url(vm), push_calls[0])
        self.assertIn("HEAD:refs/heads/main", push_calls[0])

    def test_push_head_targets_unborn_master_via_ssh_symbolic_ref_probe(self) -> None:
        # The exact bug this fixup addresses: a golden provisioned before
        # `_GIT_SETUP` pinned `-b main` has an UNBORN `master` HEAD. Plain
        # `git ls-remote --symref` prints nothing at all for that (so the old
        # code defaulted to "main", pushing an orphan branch the checked-out
        # `master` worktree never saw). `git symbolic-ref --short HEAD` over
        # ssh resolves an unborn HEAD just fine -- it reports "master" here.
        vm = BSDVM.VMS["freebsd-arm64"]
        fake_run, push_calls = self._push_head_fake_run(ls_remote_stdout=None)
        fake_ssh_run, _ = self._push_head_fake_ssh_run("master")

        with (
            mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
        ):
            BSDVM.push_head(vm)
        self.assertEqual(len(push_calls), 1)
        self.assertIn("HEAD:refs/heads/master", push_calls[0])
        self.assertNotIn("HEAD:refs/heads/main", push_calls[0])

    def test_push_head_falls_back_to_ls_remote_when_ssh_probe_fails(self) -> None:
        # The ssh symbolic-ref probe can itself be inconclusive (e.g. ssh
        # flaked, or `/root/carrick` isn't a git worktree yet); push_head
        # must still work by falling back to `ls-remote --symref`.
        vm = BSDVM.VMS["freebsd-arm64"]
        fake_run, push_calls = self._push_head_fake_run(
            ls_remote_stdout="ref: refs/heads/master\tHEAD\n" + "a" * 40 + "\tHEAD\n"
        )
        fake_ssh_run, _ = self._push_head_fake_ssh_run(None)

        with (
            mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
        ):
            BSDVM.push_head(vm)
        self.assertEqual(len(push_calls), 1)
        self.assertIn("HEAD:refs/heads/master", push_calls[0])

    def test_push_head_falls_back_to_main_when_probe_and_ls_remote_both_empty(self) -> None:
        # A brand-new guest repo (`git init`, zero commits) with the ssh
        # probe ALSO inconclusive: `ls-remote --symref ... HEAD` reports
        # nothing at all (confirmed empirically -- see parse_symref_head's
        # docstring). The very first push is the one that establishes the
        # branch, so push_head must fall back to "main" rather than raising.
        vm = BSDVM.VMS["freebsd-arm64"]
        fake_run, push_calls = self._push_head_fake_run(ls_remote_stdout="")
        fake_ssh_run, _ = self._push_head_fake_ssh_run(None)

        with (
            mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
        ):
            BSDVM.push_head(vm)
        self.assertEqual(len(push_calls), 1)
        self.assertIn("HEAD:refs/heads/main", push_calls[0])

    def test_push_head_recovers_via_forced_checkout_when_worktree_still_empty(self) -> None:
        # Materialization guard: even with the right branch name, a stale or
        # oddly-configured guest worktree can stay empty after the push.
        # push_head must retry with a forced checkout and succeed if that
        # fixes it.
        vm = BSDVM.VMS["freebsd-arm64"]
        fake_run, push_calls = self._push_head_fake_run(ls_remote_stdout=None)
        fake_ssh_run, checkout_calls = self._push_head_fake_ssh_run(
            "main", materialized_ok=False, checkout_fixes_it=True
        )

        with (
            mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
        ):
            sha = BSDVM.push_head(vm)
        self.assertEqual(sha, "deadbeef1234")
        self.assertEqual(len(push_calls), 1)
        self.assertEqual(len(checkout_calls), 1)
        self.assertIn("checkout -f main", checkout_calls[0])

    def test_push_head_raises_when_worktree_stays_empty_after_forced_checkout(self) -> None:
        # If the forced checkout doesn't fix it either, push_head must raise
        # rather than silently reporting a pushed-but-empty guest as success.
        vm = BSDVM.VMS["freebsd-arm64"]
        fake_run, push_calls = self._push_head_fake_run(ls_remote_stdout=None)
        fake_ssh_run, checkout_calls = self._push_head_fake_ssh_run(
            "main", materialized_ok=False, checkout_fixes_it=False
        )

        with (
            mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run),
            mock.patch.object(BSDVM, "ssh_run", side_effect=fake_ssh_run),
        ):
            with self.assertRaises(SystemExit) as ctx:
                BSDVM.push_head(vm)
        self.assertEqual(len(checkout_calls), 1)
        self.assertIn("main", str(ctx.exception))

    def test_ensure_dev_remote_is_idempotent(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]

        def fake_run(cmd, **kwargs):
            if cmd == ["git", "remote"]:
                return mock.Mock(returncode=0, stdout=f"origin\n{vm.remote}\n")
            raise AssertionError(f"remote add should not run when already present: {cmd}")

        with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
            BSDVM.ensure_dev_remote(vm)  # must not raise / must not add again

    def test_ensure_dev_remote_adds_when_missing(self) -> None:
        vm = BSDVM.VMS["freebsd-arm64"]
        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd == ["git", "remote"]:
                return mock.Mock(returncode=0, stdout="origin\n")
            if cmd[:3] == ["git", "remote", "add"]:
                return mock.Mock(returncode=0)
            raise AssertionError(f"unexpected command: {cmd}")

        with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
            BSDVM.ensure_dev_remote(vm)
        self.assertIn(["git", "remote", "add", vm.remote, BSDVM.git_url(vm)], calls)

    def test_git_ssh_env_shell_quotes_options_with_spaces(self) -> None:
        """GIT_SSH_COMMAND must be shell-parseable even with spaces in known_hosts path.

        When CARRICK_BSDVM_STATE contains a space, the known_hosts path will too.
        The GIT_SSH_COMMAND string is later shell-parsed (by git's ssh wrapper logic),
        so shlex.join must quote tokens that contain special characters.
        """
        vm = BSDVM.VMS["freebsd-arm64"]
        with tempfile.TemporaryDirectory() as root_td:
            # Create a state dir with a space in its path.
            space_dir = Path(root_td) / "with space"
            space_dir.mkdir()
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": str(space_dir)}):
                env = BSDVM.git_ssh_env(vm)

        self.assertIn("GIT_SSH_COMMAND", env)
        git_ssh_cmd = env["GIT_SSH_COMMAND"]

        # Parse the GIT_SSH_COMMAND string with shlex to verify it yields correct tokens.
        # This is exactly what the shell will do when git invokes the command.
        parsed = shlex.split(git_ssh_cmd)

        # First token must be "ssh"
        self.assertEqual(parsed[0], "ssh")

        # The known_hosts path must be embedded in the UserKnownHostsFile option.
        # After shlex.split, it should appear as a single option value that contains the space.
        known_hosts_path = str(space_dir / vm.name / "known_hosts")
        known_hosts_opt = f"UserKnownHostsFile={known_hosts_path}"
        self.assertIn(known_hosts_opt, parsed)

        # Verify the three -o pairs are present and intact.
        # After shlex.split, we should have: ["ssh", "-o", "opt1=val1", "-o", "opt2=val2", "-o", "opt3=val3"]
        self.assertIn("-o", parsed)
        self.assertIn("StrictHostKeyChecking=accept-new", parsed)
        self.assertIn("ConnectTimeout=5", parsed)


class GateTests(unittest.TestCase):
    def test_stage_table_matches_spec_ladder(self) -> None:
        self.assertEqual(list(BSDVM.STAGES), ["stage0", "stage1", "stage2", "stage3"])
        s0 = BSDVM.STAGES["stage0"]
        self.assertTrue(s0.available and not s0.report_only)
        self.assertIn("carrick-portable", s0.cmds[0])
        self.assertIn("carrick-hal", s0.cmds[0])
        self.assertIn("carrick-host", s0.cmds[0])
        self.assertIn("carrick-mem", s0.cmds[0])
        s1 = BSDVM.STAGES["stage1"]
        self.assertTrue(s1.available and s1.report_only)
        # stage1 measures the ACCEPTANCE PATH, not `--workspace`: a default-feature
        # workspace build on a BSD selects platform-macos and fails on carrick-vmm-hvf
        # / carrick-cli's build.rs, which is pure artifact (scout spec V12).
        self.assertNotIn("--workspace", s1.cmds[0])
        self.assertIn("--no-default-features", s1.cmds[0])
        self.assertIn("{platform_feature}", s1.cmds[0])

    def test_every_vm_names_the_platform_feature_stage1_substitutes(self) -> None:
        # The placeholder is useless if a VM leaves it empty: the command would
        # degrade to a bare `--features` and fail with a confusing cargo error.
        for vm_name, vm in BSDVM.VMS.items():
            self.assertTrue(
                vm.platform_feature.startswith("platform-"),
                f"{vm_name}: platform_feature={vm.platform_feature!r}",
            )

    def test_stage_cmds_substitute_the_vms_platform_feature(self) -> None:
        self.assertEqual(
            BSDVM.STAGES["stage1"].cmds[0].replace(
                "{platform_feature}", BSDVM.VMS["netbsd-arm64"].platform_feature
            ),
            "cd /root/carrick && cargo build -p carrick-cli "
            "--no-default-features --features platform-netbsd",
        )

    def test_stage_cmds_with_braces_survive_substitution(self) -> None:
        # Substitution is a plain `str.replace`, not `str.format`: a stage command
        # is a shell line and may legitimately contain braces (brace expansion, awk).
        stage = BSDVM.Stage(
            cmds=["echo {a,b} && awk '{print $1}' {platform_feature}"],
            report_only=True,
            available=True,
        )
        vm = BSDVM.VMS["freebsd-arm64"]
        rendered = [
            cmd.replace("{platform_feature}", vm.platform_feature) for cmd in stage.cmds
        ]
        self.assertEqual(
            rendered, ["echo {a,b} && awk '{print $1}' platform-freebsd"]
        )
        self.assertFalse(BSDVM.STAGES["stage2"].available)
        self.assertIn("NativeLane", BSDVM.STAGES["stage2"].note)
        self.assertFalse(BSDVM.STAGES["stage3"].available)

    def test_unavailable_stage_is_a_clear_error(self) -> None:
        ns = mock.Mock(vm="freebsd-arm64", stage="stage2", boot_retries=0)
        with self.assertRaises(SystemExit) as ctx:
            BSDVM.cmd_gate(ns)
        self.assertIn("NativeLane", str(ctx.exception))

    def test_write_report_renders_json_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = {
                "vm": "freebsd-arm64", "stage": "stage0", "head": "abc123",
                "rustc": "rustc 1.96.0", "wall_s": 12.5, "report_only": False,
                "steps": [{"cmd": "cargo test", "rc": 0, "tail": "ok"}],
                "pass": True,
            }
            BSDVM.write_report(Path(td), report)
            data = json.loads((Path(td) / "report.json").read_text())
            self.assertTrue(data["pass"])
            txt = (Path(td) / "report.txt").read_text()
            self.assertIn("stage0", txt)
            self.assertIn("PASS", txt)


class GateReportGuaranteeTests(unittest.TestCase):
    """cmd_gate must always emit report.json (even on a mid-flow exception or
    a hung ssh command) and cleanup must never mask the exception that sent
    it into the `finally` clause in the first place. All boundaries (boot,
    ssh_wait, push_head, ssh_run, read_pid, stop_pid, create_overlay) are
    mocked; only real filesystem operations run, against a tmpdir state root.
    """

    @staticmethod
    def _fake_create_overlay(vm_name: str, name: str, backing: str) -> Path:
        st = BSDVM.state_dir(vm_name)
        overlay = st / name
        if not overlay.exists():
            overlay.write_bytes(b"gate-overlay")
        return overlay

    def _make_golden(self, vm_name: str) -> Path:
        st = BSDVM.state_dir(vm_name)
        st.mkdir(parents=True, exist_ok=True)
        (st / "golden.qcow2").write_bytes(b"golden")
        return st

    def _report_dir(self, vm_name: str, stage: str) -> Path:
        dirs = list((BSDVM.state_root() / "results").glob(f"*-{vm_name}-{stage}"))
        self.assertEqual(len(dirs), 1, f"expected exactly one report dir, got {dirs}")
        return dirs[0]

    def test_ssh_wait_systemexit_still_writes_report_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = self._make_golden(vm_name)
                (st / "qemu.pid").write_text("555")

                ns = mock.Mock(vm=vm_name, stage="stage0", boot_retries=0)
                stop_calls: list[int] = []
                with (
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "ssh_wait",
                        side_effect=SystemExit("freebsd-arm64: ssh not reachable after 300s"),
                    ),
                    # First call is cmd_gate's own not-already-running guard
                    # (must be None so the run gets past it); second is the
                    # cleanup lookup in `finally`, which should find the pid
                    # this run's mocked `boot` would have started.
                    mock.patch.object(BSDVM, "read_pid", side_effect=[None, 555]),
                    mock.patch.object(
                        BSDVM, "stop_pid", side_effect=lambda pid: stop_calls.append(pid)
                    ),
                ):
                    with self.assertRaises(SystemExit) as ctx:
                        BSDVM.cmd_gate(ns)
                self.assertIn("ssh not reachable", str(ctx.exception))

                self.assertEqual(stop_calls, [555])
                self.assertFalse((st / "qemu.pid").exists())
                self.assertEqual(list(st.glob("gate-*.qcow2")), [])

                report = json.loads(
                    (self._report_dir(vm_name, "stage0") / "report.json").read_text()
                )
                self.assertFalse(report["pass"])
                self.assertIsNotNone(report["error"])
                self.assertIn("ssh not reachable", report["error"])

    def test_first_stage_cmd_timeout_skips_remaining_and_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                self._make_golden(vm_name)

                test_stage = BSDVM.Stage(
                    cmds=["cmd-a", "cmd-b", "cmd-c"], report_only=False, available=True,
                )
                ns = mock.Mock(vm=vm_name, stage="stage0", boot_retries=0)
                timeout_exc = subprocess.TimeoutExpired(
                    cmd="cmd-a", timeout=7200, output=b"partial-out", stderr=b"partial-err"
                )
                with (
                    mock.patch.dict(BSDVM.STAGES, {"stage0": test_stage}),
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(BSDVM, "ssh_wait", return_value=None),
                    mock.patch.object(BSDVM, "push_head", return_value="deadbeef"),
                    mock.patch.object(
                        BSDVM, "ssh_run",
                        side_effect=[mock.Mock(stdout="rustc 1.99.0\n"), timeout_exc],
                    ),
                    mock.patch.object(BSDVM, "read_pid", return_value=None),
                    mock.patch.object(BSDVM, "stop_pid") as stop_pid,
                ):
                    rc = BSDVM.cmd_gate(ns)

                self.assertEqual(rc, 1)
                stop_pid.assert_not_called()
                self.assertEqual(list(BSDVM.state_dir(vm_name).glob("gate-*.qcow2")), [])

                report = json.loads(
                    (self._report_dir(vm_name, "stage0") / "report.json").read_text()
                )
                self.assertIsNone(report["error"])
                self.assertFalse(report["pass"])
                steps = report["steps"]
                self.assertEqual(len(steps), 3)
                self.assertIsNone(steps[0]["rc"])
                self.assertIn("<timeout after 7200s>", steps[0]["tail"])
                self.assertIn("partial-out", steps[0]["tail"])
                self.assertIn("partial-err", steps[0]["tail"])
                self.assertEqual(
                    steps[1],
                    {"cmd": "cmd-b", "rc": None, "tail": "<skipped: prior step timed out>"},
                )
                self.assertEqual(
                    steps[2],
                    {"cmd": "cmd-c", "rc": None, "tail": "<skipped: prior step timed out>"},
                )

    def test_cleanup_failure_does_not_mask_original_exception(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                self._make_golden(vm_name)

                ns = mock.Mock(vm=vm_name, stage="stage0", boot_retries=0)
                stderr_buf = io.StringIO()
                with (
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "ssh_wait",
                        side_effect=SystemExit("root cause: ssh unreachable"),
                    ),
                    # See the parallel comment in the ssh_wait test above:
                    # None for the not-already-running guard, then a real pid
                    # for the `finally` cleanup lookup.
                    mock.patch.object(BSDVM, "read_pid", side_effect=[None, 999]),
                    mock.patch.object(
                        BSDVM, "stop_pid", side_effect=SystemExit("kill failed")
                    ),
                    contextlib.redirect_stderr(stderr_buf),
                ):
                    with self.assertRaises(SystemExit) as ctx:
                        BSDVM.cmd_gate(ns)

                self.assertIn("root cause: ssh unreachable", str(ctx.exception))
                self.assertIn("warning: cleanup failed", stderr_buf.getvalue())
                self.assertIn("kill failed", stderr_buf.getvalue())


class BootRetryTests(unittest.TestCase):
    """`run_gate`'s boot-retry loop: the boot/ssh_wait phase (before any stage
    cmd has run) gets torn down and retried with a FRESH ephemeral overlay,
    up to `boot_retries` times. Boundaries (create_overlay, boot, ssh_wait,
    push_head, ssh_run, read_pid, stop_pid) are mocked; only real filesystem
    operations run, against a tmpdir state root.
    """

    @staticmethod
    def _fake_create_overlay(vm_name: str, name: str, backing: str) -> Path:
        st = BSDVM.state_dir(vm_name)
        overlay = st / name
        if not overlay.exists():
            overlay.write_bytes(b"gate-overlay")
        return overlay

    def _make_golden(self, vm_name: str) -> Path:
        st = BSDVM.state_dir(vm_name)
        st.mkdir(parents=True, exist_ok=True)
        (st / "golden.qcow2").write_bytes(b"golden")
        return st

    def test_boot_retry_succeeds_on_second_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = self._make_golden(vm_name)
                vm = BSDVM.VMS[vm_name]

                boot_calls: list[str] = []

                def fake_boot(vm_arg, overlay, extra_drives=None) -> None:
                    boot_calls.append(overlay.name)

                ssh_wait_calls = {"n": 0}

                def fake_ssh_wait(vm_arg, timeout_s=300) -> None:
                    ssh_wait_calls["n"] += 1
                    if ssh_wait_calls["n"] == 1:
                        (st / "serial.log").write_text("attempt-1 boot output\n")
                        raise SystemExit(f"{vm_name}: ssh not reachable after 300s")
                    (st / "serial.log").write_text("attempt-2 boot output\n")

                with (
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", side_effect=fake_boot),
                    mock.patch.object(BSDVM, "ssh_wait", side_effect=fake_ssh_wait),
                    mock.patch.object(BSDVM, "push_head", return_value="deadbeef"),
                    mock.patch.object(
                        BSDVM, "ssh_run",
                        return_value=mock.Mock(returncode=0, stdout="rustc 1.99.0\n", stderr=""),
                    ),
                    mock.patch.object(BSDVM, "read_pid", return_value=None),
                    mock.patch.object(BSDVM, "stop_pid"),
                ):
                    outcome = BSDVM.run_gate(vm, "stage0", boot_retries=1)

                self.assertIsNone(outcome["exc"])
                self.assertEqual(outcome["rc"], 0)
                self.assertEqual(outcome["report"]["boot_retries_used"], 1)
                self.assertEqual(len(boot_calls), 2)
                self.assertNotEqual(
                    boot_calls[0], boot_calls[1], "each attempt must use a fresh overlay name"
                )

                out_dir = outcome["report_dir"]
                archived = out_dir / "serial-attempt1.log"
                self.assertTrue(archived.exists())
                self.assertIn("attempt-1 boot output", archived.read_text())
                # attempt 2 succeeded: no serial-attempt2.log archived for it.
                self.assertFalse((out_dir / "serial-attempt2.log").exists())

    def test_boot_retry_exhausted_raises_and_reports_retries_used(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = self._make_golden(vm_name)
                vm = BSDVM.VMS[vm_name]

                with (
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "ssh_wait",
                        side_effect=SystemExit(f"{vm_name}: ssh not reachable after 300s"),
                    ),
                    mock.patch.object(BSDVM, "read_pid", return_value=None),
                    mock.patch.object(BSDVM, "stop_pid"),
                ):
                    outcome = BSDVM.run_gate(vm, "stage0", boot_retries=2)

                self.assertIsInstance(outcome["exc"], SystemExit)
                self.assertEqual(outcome["report"]["boot_retries_used"], 2)
                # rc hardening: a whole-flow exception (boot-retry exhaustion
                # here) is never a pass, even though `ok` sits at its
                # loop-top default of True (the exception fired in the boot
                # phase, before any stage.cmds step could set it False).
                self.assertEqual(outcome["rc"], 1)
                # 3 total attempts (1 initial + 2 retries): 3 overlays created and
                # cleaned up, none left behind.
                self.assertEqual(list(st.glob("gate-*.qcow2")), [])

    def test_archives_serial_log_on_boot_failure_even_without_retries(self) -> None:
        # This is the general evidence-loss fix: archiving must happen on ANY
        # boot-phase failure, not only when boot_retries > 0 -- otherwise the
        # next gate's boot silently overwrites the only evidence of why this
        # one failed.
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = self._make_golden(vm_name)
                (st / "serial.log").write_text("boot output before failure\n")
                vm = BSDVM.VMS[vm_name]

                with (
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "ssh_wait",
                        side_effect=SystemExit(f"{vm_name}: ssh not reachable after 300s"),
                    ),
                    mock.patch.object(BSDVM, "read_pid", return_value=None),
                    mock.patch.object(BSDVM, "stop_pid"),
                ):
                    outcome = BSDVM.run_gate(vm, "stage0", boot_retries=0)

                self.assertIsInstance(outcome["exc"], SystemExit)
                out_dir = outcome["report_dir"]
                archived = out_dir / "serial-attempt1.log"
                self.assertTrue(archived.exists())
                self.assertIn("boot output before failure", archived.read_text())

    def test_cmd_gate_reraises_run_gate_exception_unchanged(self) -> None:
        # cmd_gate must remain a thin CLI wrapper: on an unrecoverable
        # boot-phase failure it re-raises the exact same exception run_gate
        # saw, preserving today's external cmd_gate contract.
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                self._make_golden(vm_name)

                ns = mock.Mock(vm=vm_name, stage="stage0", boot_retries=0)
                with (
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "ssh_wait",
                        side_effect=SystemExit("freebsd-arm64: ssh not reachable after 300s"),
                    ),
                    mock.patch.object(BSDVM, "read_pid", return_value=None),
                    mock.patch.object(BSDVM, "stop_pid"),
                ):
                    with self.assertRaises(SystemExit) as ctx:
                        BSDVM.cmd_gate(ns)
                self.assertIn("ssh not reachable", str(ctx.exception))


class ParseGateSpecTests(unittest.TestCase):
    """`parse_gate_spec` is pure `vm:stage` parsing/validation used by
    `ladder` -- unit tested directly, no subprocess/network.
    """

    def test_splits_vm_and_stage(self) -> None:
        self.assertEqual(
            BSDVM.parse_gate_spec("freebsd-arm64:stage0"), ("freebsd-arm64", "stage0")
        )

    def test_unknown_vm_raises_systemexit(self) -> None:
        with self.assertRaises(SystemExit):
            BSDVM.parse_gate_spec("bogus-vm:stage0")

    def test_unknown_stage_raises_systemexit(self) -> None:
        with self.assertRaises(SystemExit):
            BSDVM.parse_gate_spec("freebsd-arm64:stageX")

    def test_missing_colon_raises_systemexit(self) -> None:
        with self.assertRaises(SystemExit):
            BSDVM.parse_gate_spec("freebsd-arm64")


class CmdLadderTests(unittest.TestCase):
    """`cmd_ladder` reuses `run_gate` (no duplicated orchestration), runs
    every gate spec sequentially in this one process with boot-retries=1,
    writes a ladder-<ts>.json summary, and exits 0 iff every gate
    passed-or-report-only.
    """

    def test_validates_all_specs_before_running_any(self) -> None:
        ns = mock.Mock(gates=["freebsd-arm64:stage0", "bogus-vm:stage0"])
        with mock.patch.object(BSDVM, "run_gate") as run_gate:
            with self.assertRaises(SystemExit):
                BSDVM.cmd_ladder(ns)
            run_gate.assert_not_called()

    def test_writes_summary_and_uses_boot_retries_one(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                boot_retries_seen: list[int] = []

                def fake_run_gate(vm, stage_name, boot_retries=0):
                    boot_retries_seen.append(boot_retries)
                    out_dir = BSDVM.state_root() / "results" / f"fake-{vm.name}-{stage_name}"
                    return {
                        "report": {"boot_retries_used": 0, "pass": True},
                        "report_dir": out_dir,
                        "rc": 0,
                        "exc": None,
                    }

                ns = mock.Mock(gates=["freebsd-arm64:stage0", "netbsd-arm64:stage0"])
                with mock.patch.object(BSDVM, "run_gate", side_effect=fake_run_gate):
                    rc = BSDVM.cmd_ladder(ns)
                self.assertEqual(rc, 0)
                self.assertEqual(boot_retries_seen, [1, 1])

                summaries = list((BSDVM.state_root() / "results").glob("ladder-*.json"))
                self.assertEqual(len(summaries), 1)
                data = json.loads(summaries[0].read_text())
                self.assertEqual(len(data["results"]), 2)
                self.assertEqual(data["results"][0]["vm"], "freebsd-arm64")
                self.assertEqual(data["results"][0]["stage"], "stage0")
                self.assertTrue(data["results"][0]["steps_ok"])
                self.assertTrue(data["results"][0]["exit_ok"])
                self.assertEqual(data["results"][1]["vm"], "netbsd-arm64")

    def test_exit_code_zero_when_report_only_stage_fails(self) -> None:
        # report-only stage with failing steps: the per-gate summary must
        # show the two signals split apart -- steps_ok:false (the report's
        # own `pass` says the steps failed) but exit_ok:true (run_gate/
        # cmd_gate's own contract already folds "failed but report-only"
        # into rc=0) -- and the ladder's exit code follows exit_ok, not
        # steps_ok.
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                def fake_run_gate(vm, stage_name, boot_retries=0):
                    return {
                        "report": {"boot_retries_used": 0, "pass": False},
                        "report_dir": BSDVM.state_root() / "results" / "fake",
                        "rc": 0,
                        "exc": None,
                    }

                ns = mock.Mock(gates=["freebsd-arm64:stage1"])
                with mock.patch.object(BSDVM, "run_gate", side_effect=fake_run_gate):
                    rc = BSDVM.cmd_ladder(ns)
                self.assertEqual(rc, 0)

                summaries = list((BSDVM.state_root() / "results").glob("ladder-*.json"))
                data = json.loads(summaries[0].read_text())
                self.assertFalse(data["results"][0]["steps_ok"])
                self.assertTrue(data["results"][0]["exit_ok"])

    def test_exit_code_nonzero_when_stage0_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                def fake_run_gate(vm, stage_name, boot_retries=0):
                    return {
                        "report": {"boot_retries_used": 0, "pass": False},
                        "report_dir": BSDVM.state_root() / "results" / "fake",
                        "rc": 1,
                        "exc": None,
                    }

                ns = mock.Mock(gates=["freebsd-arm64:stage0"])
                with mock.patch.object(BSDVM, "run_gate", side_effect=fake_run_gate):
                    rc = BSDVM.cmd_ladder(ns)
                self.assertEqual(rc, 1)

    def test_continues_past_a_gate_whose_run_gate_call_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                calls: list[tuple[str, str]] = []

                def fake_run_gate(vm, stage_name, boot_retries=0):
                    calls.append((vm.name, stage_name))
                    if vm.name == "freebsd-arm64":
                        raise SystemExit("no golden image; run: bsdvm.py provision freebsd-arm64")
                    return {
                        "report": {"boot_retries_used": 0, "pass": True},
                        "report_dir": BSDVM.state_root() / "results" / "fake",
                        "rc": 0,
                        "exc": None,
                    }

                ns = mock.Mock(gates=["freebsd-arm64:stage0", "netbsd-arm64:stage0"])
                with mock.patch.object(BSDVM, "run_gate", side_effect=fake_run_gate):
                    rc = BSDVM.cmd_ladder(ns)
                # Both gates attempted despite the first one raising.
                self.assertEqual(len(calls), 2)
                self.assertEqual(rc, 1)

                summaries = list((BSDVM.state_root() / "results").glob("ladder-*.json"))
                data = json.loads(summaries[0].read_text())
                self.assertFalse(data["results"][0]["steps_ok"])
                self.assertFalse(data["results"][0]["exit_ok"])
                self.assertIsNotNone(data["results"][0]["error"])
                self.assertIn("no golden image", data["results"][0]["error"])
                self.assertTrue(data["results"][1]["steps_ok"])
                self.assertTrue(data["results"][1]["exit_ok"])


def _recv_line(conn: socket.socket, timeout_s: float = 5.0) -> bytes:
    """Read until a full newline-terminated line has arrived.

    A single `recv` can return a partial line (or two coalesced ones), so the
    scripted fake consoles below cannot assume one recv == one command.
    """
    conn.settimeout(timeout_s)
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(8192)
        if not chunk:
            break
        buf += chunk
    return buf


class _ScriptedConsole:
    """A fake qemu serial chardev that replies to each received line from a
    scripted list, recording everything it was sent.

    `preload` is written the instant the client connects -- that is how the
    stale-buffer scenarios below get junk sitting in the console buffer
    BEFORE any command is issued.
    """

    def __init__(self, sock_path: Path, replies: list[bytes], preload: bytes = b"") -> None:
        self.received: list[bytes] = []
        self._replies = replies
        self._preload = preload
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(str(sock_path))
        self._srv.listen(1)
        self._conn: socket.socket | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        self._conn = conn
        try:
            if self._preload:
                conn.sendall(self._preload)
            for reply in self._replies:
                line = _recv_line(conn)
                if not line:
                    return
                self.received.append(line)
                if reply:
                    conn.sendall(reply)
            # Stay connected so a client still waiting sees a timeout rather
            # than an EOF (ConnectionError), which is a different failure.
            with contextlib.suppress(OSError):
                _recv_line(conn, timeout_s=3.0)
        except OSError:
            pass

    def close(self) -> None:
        self._thread.join(timeout=5)
        for s in (self._conn, self._srv):
            if s is not None:
                with contextlib.suppress(OSError):
                    s.close()


def _sentinel(idx: int, rc: int) -> bytes:
    """What a real guest shell emits when step `idx` exits with `rc`."""
    return f"__BSDVM_STEP_{idx}_RC_{rc}_END__\r\n# ".encode()


class ProvisionStepExitStatusTests(unittest.TestCase):
    """`_run_step` must PROVE each provisioning command succeeded.

    The 2026-07-25 refresh-golden incident was misread as a silent
    provisioning no-op, and while the real cause turned out to be the golden
    rotation, the investigation confirmed the tool genuinely could not tell
    the two apart: `_run_serial_provision` waited for a shell PROMPT and
    never for an exit status, so a command that failed instantly and a
    command that worked produced identical, successful-looking runs. These
    tests pin the exit-status contract that closes that.
    """

    @contextlib.contextmanager
    def _console(self, replies: list[bytes], preload: bytes = b""):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                st = BSDVM.state_dir("freebsd-arm64")
                st.mkdir(parents=True)
                server = _ScriptedConsole(st / "serial.sock", replies, preload=preload)
                con = BSDVM.SerialConsole(st / "serial.sock")
                try:
                    with mock.patch.object(BSDVM, "DRAIN_QUIET_S", 0.05):
                        yield con, server
                finally:
                    con._sock.close()
                    server.close()

    def test_nonzero_exit_status_fails_provisioning(self) -> None:
        with self._console([_sentinel(1, 1)]) as (con, server):
            with self.assertRaises(SystemExit) as cm:
                BSDVM._run_step(con, "freebsd-arm64", "pkg install -y llvm19", 5, 1)
        msg = str(cm.exception)
        self.assertIn("rc=1", msg)
        self.assertIn("pkg install -y llvm19", msg)

    def test_zero_exit_status_passes(self) -> None:
        with self._console([_sentinel(1, 0)]) as (con, server):
            BSDVM._run_step(con, "freebsd-arm64", "true", 5, 1)
        self.assertTrue(server.received[0].startswith(b"true; echo "))

    def test_stale_prompts_in_buffer_do_not_skip_the_command(self) -> None:
        """A prompt already sitting in the buffer must not be mistaken for
        this command's completion.

        Under the old PROMPT-based wait, the preloaded prompts below would
        have satisfied the expect immediately and the loop would have marched
        on -- possibly without the command having run at all. Here the step
        must still send its command AND still wait for that command's own
        sentinel.
        """
        preload = b"\r\nsome banner text # \r\n# \r\n# "
        with self._console([_sentinel(1, 0)], preload=preload) as (con, server):
            BSDVM._run_step(con, "freebsd-arm64", "pkg bootstrap -f", 5, 1)
        self.assertEqual(len(server.received), 1, "the command must actually be sent")
        self.assertTrue(server.received[0].startswith(b"pkg bootstrap -f; echo "))

    def test_stale_prompt_cannot_mask_a_failing_command(self) -> None:
        # Same stale buffer, but the command genuinely fails: the stale
        # prompts must not turn that into a pass.
        preload = b"# \r\n# \r\n# "
        with self._console([_sentinel(1, 127)], preload=preload) as (con, server):
            with self.assertRaises(SystemExit) as cm:
                BSDVM._run_step(con, "freebsd-arm64", "pkg install -y llvm19", 5, 1)
        self.assertIn("rc=127", str(cm.exception))

    def test_command_echo_is_not_mistaken_for_the_result(self) -> None:
        """The serial tty echoes the command line back, and that echo contains
        the sentinel with a LITERAL `$?` in it.

        If the pattern did not require digits, this echo would match and every
        step would "succeed" the instant it was sent -- the original bug,
        reintroduced one layer down. So: reply with the echo alone and nothing
        else, and require that the step does NOT accept it.
        """
        cmd = "pkg install -y llvm19"
        echo_only = f'{cmd}; echo "__BSDVM_STEP_1_RC_$?_END__"\r\n'.encode()
        with self._console([echo_only]) as (con, server):
            with self.assertRaises(SystemExit) as cm:
                BSDVM._run_step(con, "freebsd-arm64", cmd, 0.7, 1)
        self.assertIn("never reported an exit status", str(cm.exception))

    def test_sentinel_pattern_does_not_cross_match_between_steps(self) -> None:
        # Step 1's pattern must not match step 10's sentinel (a plain
        # `__BSDVM_STEP_1` prefix would).
        self.assertIsNone(BSDVM._step_sentinel_re(1).search(b"__BSDVM_STEP_10_RC_0_END__"))
        self.assertIsNotNone(BSDVM._step_sentinel_re(10).search(b"__BSDVM_STEP_10_RC_0_END__"))
        # And a literal `$?` (the echo) never matches, at any index.
        self.assertIsNone(BSDVM._step_sentinel_re(3).search(b"__BSDVM_STEP_3_RC_$?_END__"))

    def test_expect_re_consumes_through_the_match(self) -> None:
        # Leftovers from step N must not be able to satisfy step N+1.
        with self._console([_sentinel(1, 0) + _sentinel(2, 0)]) as (con, server):
            BSDVM._run_step(con, "freebsd-arm64", "true", 5, 1)
            self.assertNotIn(b"__BSDVM_STEP_1_RC_", con._buf)


class ProvisionPostconditionTests(unittest.TestCase):
    """`refresh-golden` must refuse to rotate a golden whose toolchain is not
    actually there. This is the check that would have caught the 2026-07-25
    incident had provisioning genuinely no-opped, which is what it looked
    like for the first several hours of the investigation.
    """

    def _install_packages(self, vm_name: str) -> set[str]:
        """Package names on the install lines of the real provisioning data."""
        pkgs: set[str] = set()
        for cmd, _ in BSDVM.provision_commands(BSDVM.VMS[vm_name], "ssh-ed25519 AAAA test"):
            for m in re.finditer(r"(?:pkg install -y|pkg_add -U)\s+([^|&;]+)", cmd):
                pkgs.update(m.group(1).split())
        return pkgs

    def test_every_installed_package_has_a_postcondition_entry(self) -> None:
        for vm_name, proofs in (
            ("freebsd-arm64", BSDVM._FREEBSD_PKG_PROOFS),
            ("netbsd-arm64", BSDVM._NETBSD_PKG_PROOFS),
        ):
            installed = self._install_packages(vm_name)
            self.assertTrue(installed, f"{vm_name}: parsed no packages from the install lines")
            missing = installed - set(proofs)
            self.assertEqual(
                missing, set(),
                f"{vm_name}: package(s) {sorted(missing)} are installed by "
                "provision_commands but have no post-condition proof -- add one to "
                "the *_PKG_PROOFS table (None if genuinely optional), or a future "
                "golden can ship without them and nothing will notice",
            )

    def test_postconditions_prove_the_libclang_path_the_env_prefix_pins(self) -> None:
        """bindgen dlopens libclang via LIBCLANG_PATH; if the golden lacks it
        the acceptance lane dies at build time. Prove the exact path the gate
        will use, not merely that a package is registered.
        """
        for vm_name in ("freebsd-arm64", "netbsd-arm64"):
            vm = BSDVM.VMS[vm_name]
            m = re.search(r"LIBCLANG_PATH=(\S+?)[;\s]", vm.remote_env_prefix)
            self.assertIsNotNone(m, f"{vm_name}: no LIBCLANG_PATH in remote_env_prefix")
            libdir = m.group(1)
            checks = " ; ".join(c for c, _ in BSDVM.provision_postconditions(vm))
            self.assertIn(
                f"{libdir}/libclang.so", checks,
                f"{vm_name}: post-conditions must prove the libclang the gate loads",
            )

    def test_postconditions_prove_the_repo_and_ssh_key(self) -> None:
        for vm_name in ("freebsd-arm64", "netbsd-arm64"):
            checks = " ; ".join(
                c for c, _ in BSDVM.provision_postconditions(BSDVM.VMS[vm_name])
            )
            self.assertIn("/root/carrick/.git", checks)
            self.assertIn("authorized_keys", checks)

    def test_provision_commands_end_with_shutdown(self) -> None:
        # _run_serial_provision splices the post-conditions in ahead of the
        # terminal shutdown, so that terminal position is a contract.
        for vm_name in ("freebsd-arm64", "netbsd-arm64"):
            cmds = BSDVM.provision_commands(BSDVM.VMS[vm_name], "ssh-ed25519 AAAA test")
            self.assertTrue(cmds[-1][0].startswith("shutdown"))
            self.assertEqual(
                [c for c, _ in cmds if c.startswith("shutdown")], [cmds[-1][0]],
                f"{vm_name}: exactly one shutdown, and it must be last",
            )


class RunSerialProvisionPostconditionOrderTests(unittest.TestCase):
    """End-to-end over a scripted console: post-conditions run BEFORE the
    guest powers off, and a failing one aborts the run with the shutdown
    never sent -- so the caller's except-block stops the VM and the existing
    golden is never rotated.
    """

    @contextlib.contextmanager
    def _run(self, replies: list[bytes]):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm = BSDVM.VMS["freebsd-arm64"]
                st = BSDVM.state_dir(vm.name)
                st.mkdir(parents=True)
                # login handshake ("root") then the scripted step replies
                server = _ScriptedConsole(st / "serial.sock", [b"# "] + replies, preload=b"login: ")
                created: list[BSDVM.SerialConsole] = []
                real_ctor = BSDVM.SerialConsole

                def capturing(sock_path_arg):
                    con = real_ctor(sock_path_arg)
                    created.append(con)
                    return con

                try:
                    with (
                        mock.patch.object(BSDVM, "DRAIN_QUIET_S", 0.05),
                        mock.patch.object(BSDVM, "SerialConsole", side_effect=capturing),
                        mock.patch.object(
                            BSDVM, "provision_commands",
                            return_value=[("install-everything", 5), ("shutdown -p now", 5)],
                        ),
                        mock.patch.object(
                            BSDVM, "provision_postconditions",
                            return_value=[("prove-llvm", 5), ("prove-rust", 5)],
                        ),
                    ):
                        yield vm, server
                finally:
                    for con in created:
                        con._sock.close()
                    server.close()

    def test_postconditions_run_between_provisioning_and_shutdown(self) -> None:
        replies = [_sentinel(1, 0), _sentinel(2, 0), _sentinel(3, 0), b""]
        with self._run(replies) as (vm, server):
            BSDVM._run_serial_provision(vm, "ssh-ed25519 AAAA test")
        sent = [line.split(b";")[0].strip() for line in server.received]
        self.assertEqual(
            sent,
            [b"root", b"install-everything", b"prove-llvm", b"prove-rust", b"shutdown -p now"],
        )

    def test_failing_postcondition_aborts_before_shutdown_is_sent(self) -> None:
        # Provisioning "succeeds", but the toolchain it was supposed to
        # install is not there. The run must die, and the guest must NOT be
        # powered off behind a success message.
        replies = [_sentinel(1, 0), _sentinel(2, 1), b""]
        with self._run(replies) as (vm, server):
            with self.assertRaises(SystemExit) as cm:
                BSDVM._run_serial_provision(vm, "ssh-ed25519 AAAA test")
            self.assertIn("rc=1", str(cm.exception))
            self.assertIn("prove-llvm", str(cm.exception))
            sent = [line.split(b";")[0].strip() for line in server.received]
        self.assertNotIn(b"shutdown -p now", sent)


@_needs_qemu_img
class GoldenPublishGuardTests(unittest.TestCase):
    """The 2026-07-25 corruption, reproduced against real qemu-img, and the
    guards that now refuse to publish it.

    Reproduction is the OLD `cmd_refresh_golden` sequence exactly: flatten,
    rotate, stack a provision overlay on the flattened golden, unlink that
    golden, rename the overlay onto it. The result is a qcow2 whose backing
    file is its own path.
    """

    @staticmethod
    def _corrupt_golden(st: Path) -> Path:
        _mkqcow2(st / "base.qcow2")
        _mkqcow2(st / "golden.qcow2", backing=st / "base.qcow2")
        subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2",
             str(st / "golden.qcow2"), str(st / "golden.flat.qcow2")],
            check=True, capture_output=True,
        )
        (st / "golden.qcow2").rename(st / "golden.prev.qcow2")
        (st / "golden.flat.qcow2").rename(st / "golden.qcow2")
        _mkqcow2(st / "provision.qcow2", backing=st / "golden.qcow2")
        (st / "golden.qcow2").unlink()               # the bug
        (st / "provision.qcow2").rename(st / "golden.qcow2")  # the bug
        return st / "golden.qcow2"

    def test_the_corruption_reproduces_and_is_consumer_fatal(self) -> None:
        # Pins that this really is the failure mode -- if a future qemu-img
        # stops exploding here, the guards below are still right but this
        # test's premise needs revisiting.
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            golden = self._corrupt_golden(st)
            self.assertEqual(
                Path(_img_info(golden)["backing-filename"]).resolve(), golden.resolve()
            )
            # Creating a consumer overlay on it (what `up`, `gate` and
            # `ladder` all do) does not fail cleanly: qemu-img recurses the
            # backing chain until it dies of stack exhaustion. Measured
            # unbounded it takes ~67s to reach SIGSEGV (rc=139) -- far too
            # slow for a unit suite -- so bound it and accept "did not
            # succeed", timeout included, as the property under test.
            try:
                made = subprocess.run(
                    ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                     "-b", str(golden), str(st / "dev.qcow2")],
                    capture_output=True, timeout=5,
                )
            except subprocess.TimeoutExpired:
                return
            self.assertNotEqual(made.returncode, 0, "a self-backed golden must not be usable")

    def test_assert_publishable_refuses_a_candidate_backed_by_its_destination(self) -> None:
        # The guard runs BEFORE the rename, which is the only point at which
        # the corruption is both detectable and still harmless.
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            _mkqcow2(st / "base.qcow2")
            _mkqcow2(st / "golden.qcow2", backing=st / "base.qcow2")
            _mkqcow2(st / "provision.qcow2", backing=st / "golden.qcow2")
            with self.assertRaises(SystemExit) as cm:
                BSDVM._assert_publishable(st / "provision.qcow2", st / "golden.qcow2")
            self.assertIn("reference itself", str(cm.exception))

    def test_assert_publishable_allows_a_legitimately_backed_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            _mkqcow2(st / "base.qcow2")
            _mkqcow2(st / "provision.qcow2", backing=st / "base.qcow2")
            BSDVM._assert_publishable(st / "provision.qcow2", st / "golden.qcow2")

    def test_assert_publishable_allows_a_standalone_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            _mkqcow2(st / "golden.new.qcow2")
            BSDVM._assert_publishable(st / "golden.new.qcow2", st / "golden.qcow2")

    def test_assert_publishable_refuses_a_non_qcow2_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = Path(td)
            (st / "provision.qcow2").write_bytes(b"truncated-or-garbage")
            with self.assertRaises(SystemExit) as cm:
                BSDVM._assert_publishable(st / "provision.qcow2", st / "golden.qcow2")
            self.assertIn("cannot open it as qcow2", str(cm.exception))

    def test_assert_openable_rejects_a_self_referential_image_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            golden = self._corrupt_golden(Path(td))
            with self.assertRaises(SystemExit):
                BSDVM._assert_openable(golden)


@_needs_qemu_img
class RefreshGoldenOrchestrationTests(unittest.TestCase):
    """`cmd_refresh_golden`'s rotation, which had ZERO coverage when it
    corrupted the freebsd-arm64 golden on 2026-07-25.

    All VM boundaries are mocked; the qcow2 files are real, because backing
    chain structure is precisely what went wrong.
    """

    OLD_GOLDEN_SIZE = "128M"

    @staticmethod
    def _fake_create_overlay(vm_name: str, name: str, backing: str) -> Path:
        st = BSDVM.state_dir(vm_name)
        overlay = st / name
        if not overlay.exists():
            _mkqcow2(overlay, backing=st / backing)
        return overlay

    @contextlib.contextmanager
    def _fixture(self, provision_side_effect=None):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = BSDVM.state_dir(vm_name)
                st.mkdir(parents=True)
                _mkqcow2(st / "base.qcow2")
                _mkqcow2(st / "golden.qcow2", size=self.OLD_GOLDEN_SIZE)
                _mkqcow2(st / "dev.qcow2", backing=st / "golden.qcow2")
                with (
                    mock.patch.object(BSDVM, "boot", return_value=None),
                    mock.patch.object(
                        BSDVM, "_run_serial_provision",
                        side_effect=provision_side_effect, return_value=None,
                    ),
                    mock.patch.object(BSDVM, "wait_for_shutdown", return_value=None),
                    mock.patch.object(BSDVM, "read_pubkey", return_value="ssh-ed25519 AAAA test"),
                    mock.patch.object(
                        BSDVM, "create_overlay", side_effect=self._fake_create_overlay
                    ),
                    mock.patch.object(BSDVM, "ensure_dev_remote"),
                    mock.patch.object(BSDVM, "read_pid", return_value=None),
                ):
                    yield st, mock.Mock(vm=vm_name)

    def test_refresh_publishes_a_standalone_openable_golden(self) -> None:
        with self._fixture() as (st, ns):
            rc = BSDVM.cmd_refresh_golden(ns)
            self.assertEqual(rc, 0)
            golden = st / "golden.qcow2"
            # Standalone: the flatten happens at the END, into a third name,
            # so the published golden chains onto nothing at all -- it cannot
            # reference itself and does not even depend on base.qcow2.
            self.assertIsNone(_backing_of(golden))
            BSDVM._assert_openable(golden)
            # The property that actually broke: a consumer overlay can be made.
            made = subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                 "-b", str(golden), str(st / "consumer.qcow2")],
                capture_output=True,
            )
            self.assertEqual(made.returncode, 0, made.stderr.decode(errors="replace"))
            # Scratch is cleaned up.
            self.assertFalse((st / "provision.qcow2").exists())
            self.assertFalse((st / "golden.new.qcow2").exists())
            self.assertFalse((st / "golden.flat.qcow2").exists())

    def test_refresh_rotates_the_old_golden_by_rename_never_unlink(self) -> None:
        """`golden.prev.qcow2` must be the SAME FILE the refresh started with.

        Comparing inode numbers is the point: the old code destroyed a full
        disk image with `golden.unlink()` while an overlay still referenced
        it. A rename preserves the inode; an unlink-and-recreate cannot.
        """
        with self._fixture() as (st, ns):
            before_ino = (st / "golden.qcow2").stat().st_ino
            rc = BSDVM.cmd_refresh_golden(ns)
            self.assertEqual(rc, 0)
            prev = st / "golden.prev.qcow2"
            self.assertTrue(prev.exists(), "the only rollback must survive the refresh")
            self.assertEqual(prev.stat().st_ino, before_ino)
            self.assertEqual(_virtual_size(prev), _virtual_size_of_literal(self.OLD_GOLDEN_SIZE))

    def test_refresh_keeps_the_golden_in_place_while_provisioning_on_top_of_it(self) -> None:
        """Nothing may unlink the image the provision overlay is stacked on.

        This is the incident's mechanism stated directly. The old code stacked
        `work` on a freshly flattened golden.qcow2 and then ran
        `golden.unlink()` -- destroying that full disk image while `work`'s
        header still named it, which is what turned the rename into a
        self-reference. So: note the inode of the overlay's backing file
        during provisioning, and require that the very same inode is still
        present on disk when the command returns.
        """
        seen: list[tuple[int, str | None]] = []

        def during_provision(vm, pubkey):
            st = BSDVM.state_dir(vm.name)
            golden = st / "golden.qcow2"
            work = st / "provision.qcow2"
            self.assertTrue(golden.exists(), "golden.qcow2 vanished mid-provision")
            seen.append((golden.stat().st_ino, _backing_of(work)))

        with self._fixture(provision_side_effect=during_provision) as (st, ns):
            BSDVM.cmd_refresh_golden(ns)
            self.assertEqual(len(seen), 1)
            backing_ino, work_backing = seen[0]
            self.assertEqual(
                Path(work_backing or "").resolve(), (st / "golden.qcow2").resolve(),
                "the work overlay must be stacked on golden.qcow2",
            )
            survivors = {p.stat().st_ino for p in st.iterdir() if p.is_file()}
            self.assertIn(
                backing_ino, survivors,
                "the image the provision overlay was stacked on was UNLINKED during "
                "the refresh -- that is the 2026-07-25 corruption's mechanism",
            )

    def test_refresh_failure_leaves_the_existing_golden_untouched(self) -> None:
        with self._fixture(provision_side_effect=RuntimeError("provisioning boom")) as (st, ns):
            with self.assertRaises(RuntimeError):
                BSDVM.cmd_refresh_golden(ns)
            # The golden is still the original, still openable, still usable.
            self.assertEqual(
                _virtual_size(st / "golden.qcow2"),
                _virtual_size_of_literal(self.OLD_GOLDEN_SIZE),
            )
            BSDVM._assert_openable(st / "golden.qcow2")
            self.assertFalse((st / "golden.prev.qcow2").exists())
            # And the human's working overlay is untouched on a failed run.
            self.assertTrue((st / "dev.qcow2").exists())

    def test_refresh_moves_the_dev_overlay_aside_rather_than_destroying_it(self) -> None:
        # The incident deleted a dev.qcow2 carrying a hand-installed
        # toolchain. Invalidation is still mandatory (its backing changed
        # underneath it), but it must not be destructive.
        with self._fixture() as (st, ns):
            BSDVM.cmd_refresh_golden(ns)
            self.assertFalse((st / "dev.qcow2").exists())
            stale = sorted(st.glob("dev.stale-*.qcow2"))
            self.assertEqual(len(stale), 1, f"expected the dev overlay kept aside, got {stale}")

    def test_refresh_without_a_golden_is_refused(self) -> None:
        with self._fixture() as (st, ns):
            (st / "golden.qcow2").unlink()
            with self.assertRaises(SystemExit) as cm:
                BSDVM.cmd_refresh_golden(ns)
            self.assertIn("nothing to refresh", str(cm.exception))


class GracefulPoweroffTests(unittest.TestCase):
    """`down` must ask the guest to power itself off before cutting power.

    `stop_pid` signals QEMU, not the guest -- a hard power cut. NetBSD does
    not survive one: its root FFS comes back dirty and the next boot aborts
    in fsck (`UNEXPECTED INCONSISTENCY; RUN fsck_ffs MANUALLY`). Measured
    2026-07-25, when a single up/down cycle destroyed a freshly created
    netbsd-arm64 dev.qcow2.
    """

    def _down(self, *, pids: list[int | None], ssh=None):
        """Run cmd_down with read_pid scripted, returning the stop_pid calls."""
        stop_calls: list[int] = []
        ssh = ssh if ssh is not None else mock.DEFAULT
        with (
            mock.patch.object(BSDVM, "POWEROFF_TIMEOUT_S", 0.3),
            mock.patch.object(BSDVM, "read_pid", side_effect=pids),
            mock.patch.object(BSDVM, "ssh_run", side_effect=ssh) as ssh_mock,
            mock.patch.object(BSDVM, "stop_pid", side_effect=stop_calls.append),
            mock.patch.object(BSDVM, "pidfile_path", return_value=Path("/nonexistent/qemu.pid")),
        ):
            rc = BSDVM.cmd_down(mock.Mock(vm="netbsd-arm64"))
        return rc, stop_calls, ssh_mock

    def test_down_asks_the_guest_to_power_off_and_does_not_pull_the_plug(self) -> None:
        # read_pid: once for cmd_down's "is it running", then gone -- the
        # guest powered itself off.
        rc, stop_calls, ssh_mock = self._down(
            pids=[4242, None], ssh=lambda *a, **k: subprocess.CompletedProcess([], 0, "", "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stop_calls, [], "the plug must not be pulled on a clean poweroff")
        sent = ssh_mock.call_args[0][1]
        self.assertIn("shutdown -p now", sent)

    def test_down_pulls_the_plug_when_the_guest_ignores_the_request(self) -> None:
        rc, stop_calls, _ = self._down(
            pids=[4242] + [4242] * 40,
            ssh=lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stop_calls, [4242], "a guest that will not power off must still be stopped")

    def test_down_pulls_the_plug_when_ssh_is_unreachable(self) -> None:
        # A guest still booting (or wedged) has no ssh route; falling back is
        # no worse than the old unconditional behaviour.
        rc, stop_calls, _ = self._down(
            pids=[4242] + [4242] * 40,
            ssh=subprocess.TimeoutExpired(cmd="ssh", timeout=30),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stop_calls, [4242])

    def test_down_on_a_stopped_vm_does_nothing(self) -> None:
        rc, stop_calls, ssh_mock = self._down(pids=[None])
        self.assertEqual(rc, 0)
        self.assertEqual(stop_calls, [])
        ssh_mock.assert_not_called()

    def test_graceful_poweroff_reports_failure_without_raising(self) -> None:
        with (
            mock.patch.object(BSDVM, "POWEROFF_TIMEOUT_S", 0.2),
            mock.patch.object(BSDVM, "read_pid", return_value=999),
            mock.patch.object(
                BSDVM, "ssh_run", side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=30)
            ),
        ):
            self.assertFalse(BSDVM.graceful_poweroff(BSDVM.VMS["netbsd-arm64"]))


if __name__ == "__main__":
    unittest.main()
