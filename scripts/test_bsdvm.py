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


class ConfigTests(unittest.TestCase):
    def test_inventory_matches_spec(self) -> None:
        self.assertEqual(sorted(BSDVM.VMS), ["freebsd-arm64", "netbsd-arm64"])
        fb = BSDVM.VMS["freebsd-arm64"]
        nb = BSDVM.VMS["netbsd-arm64"]
        self.assertEqual(fb.ssh_port, 2201)
        self.assertEqual(nb.ssh_port, 2202)
        self.assertEqual(fb.remote, "fbsd-arm")
        self.assertEqual(nb.remote, "nbsd-arm")
        # NetBSD non-login ssh PATH gotcha must be baked into config.
        self.assertIn("/usr/pkg/bin", nb.remote_path_prefix)
        self.assertEqual(fb.remote_path_prefix, "")

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
            "git", "rust", "receive.denyCurrentBranch updateInstead",
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

    @staticmethod
    def _fake_create_overlay(vm_name: str, name: str, backing: str) -> Path:
        # Simpler than mocking subprocess.run's qemu-img argv shape: just
        # materialize the overlay file the real create_overlay would have
        # produced, so the real rename/unlink calls downstream have
        # something real to operate on.
        st = BSDVM.state_dir(vm_name)
        overlay = st / name
        if not overlay.exists():
            overlay.write_bytes(b"work-product")
        return overlay

    def test_provision_force_success_rotates_golden_and_invalidates_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = BSDVM.state_dir(vm_name)
                st.mkdir(parents=True)
                (st / "base.qcow2").write_bytes(b"base")
                (st / "golden.qcow2").write_bytes(b"old")
                (st / "dev.qcow2").write_bytes(b"stale-dev")
                (st / "gate-9.qcow2").write_bytes(b"stale-gate")

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

                self.assertEqual((st / "golden.prev.qcow2").read_bytes(), b"old")
                self.assertTrue((st / "golden.qcow2").exists())
                self.assertEqual((st / "golden.qcow2").read_bytes(), b"work-product")
                self.assertFalse((st / "dev.qcow2").exists())
                self.assertFalse((st / "gate-9.qcow2").exists())
                # ensure_dev_remote is called after the golden lands (never
                # against the real repo's .git/config from this test).
                ensure_remote.assert_called_once_with(BSDVM.VMS[vm_name])

    def test_provision_failure_leaves_old_golden_untouched_and_stops_vm(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                vm_name = "freebsd-arm64"
                st = BSDVM.state_dir(vm_name)
                st.mkdir(parents=True)
                (st / "base.qcow2").write_bytes(b"base")
                (st / "golden.qcow2").write_bytes(b"old")

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
                self.assertEqual((st / "golden.qcow2").read_bytes(), b"old")
                self.assertFalse((st / "golden.prev.qcow2").exists())
                # The work overlay was created but never renamed onto golden.
                self.assertTrue((st / "provision.qcow2").exists())
                self.assertEqual((st / "provision.qcow2").read_bytes(), b"work-product")


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
                    # loop and send its first real command.
                    received.append(conn.recv(4096))
                    conn.sendall(b"# ")
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
                            BSDVM, "provision_commands", return_value=[real_first_cmd]
                        ),
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
                self.assertEqual(received[1], real_first_cmd[0].encode() + b"\n")


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

    def test_ssh_run_applies_netbsd_path_prefix(self) -> None:
        vm = BSDVM.VMS["netbsd-arm64"]
        with mock.patch.object(BSDVM.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0)
            BSDVM.ssh_run(vm, "cargo --version", timeout_s=10)
        remote_cmd = run.call_args.args[0][-1]
        self.assertTrue(remote_cmd.startswith("PATH=/usr/pkg/bin"))

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

    def test_push_head_returns_local_head_sha_and_pushes_via_git_url(self) -> None:
        # Guest's checked-out branch (per ls-remote --symref) is "main" here --
        # what a freshly `_GIT_SETUP`-provisioned (`git init -b main`) guest
        # reports once it has at least one commit.
        vm = BSDVM.VMS["freebsd-arm64"]
        rev_parse = mock.Mock(returncode=0, stdout="deadbeef1234\n")
        ls_remote = mock.Mock(
            returncode=0, stdout="ref: refs/heads/main\tHEAD\n" + "a" * 40 + "\tHEAD\n"
        )
        push = mock.Mock(returncode=0)
        push_calls: list[tuple[list[str], dict]] = []

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["git", "rev-parse"]:
                return rev_parse
            if cmd[:3] == ["git", "ls-remote", "--symref"]:
                return ls_remote
            if cmd[:2] == ["git", "push"]:
                push_calls.append((cmd, kwargs))
                return push
            raise AssertionError(f"unexpected command: {cmd}")

        with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
            sha = BSDVM.push_head(vm)
        self.assertEqual(sha, "deadbeef1234")
        self.assertEqual(len(push_calls), 1)
        push_cmd, push_kwargs = push_calls[0]
        self.assertEqual(push_cmd[:2], ["git", "push"])
        self.assertIn(BSDVM.git_url(vm), push_cmd)
        self.assertIn("HEAD:refs/heads/main", push_cmd)
        self.assertIn("GIT_SSH_COMMAND", push_kwargs.get("env", {}))

    def test_push_head_targets_checked_out_branch_from_ls_remote(self) -> None:
        # Reviewer finding: guest repos provisioned by plain `git init` (the
        # pre-fix _GIT_SETUP) default to `master`; updateInstead only updates
        # the working tree when the push targets the CHECKED-OUT branch, so
        # push_head must ask ls-remote what that branch actually is rather
        # than hardcoding "main".
        vm = BSDVM.VMS["freebsd-arm64"]
        rev_parse = mock.Mock(returncode=0, stdout="deadbeef1234\n")
        ls_remote = mock.Mock(
            returncode=0, stdout="ref: refs/heads/master\tHEAD\n" + "a" * 40 + "\tHEAD\n"
        )
        push = mock.Mock(returncode=0)
        push_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["git", "rev-parse"]:
                return rev_parse
            if cmd[:3] == ["git", "ls-remote", "--symref"]:
                return ls_remote
            if cmd[:2] == ["git", "push"]:
                push_calls.append(cmd)
                return push
            raise AssertionError(f"unexpected command: {cmd}")

        with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
            BSDVM.push_head(vm)
        self.assertEqual(len(push_calls), 1)
        self.assertIn("HEAD:refs/heads/master", push_calls[0])
        self.assertNotIn("HEAD:refs/heads/main", push_calls[0])

    def test_push_head_falls_back_to_main_when_remote_repo_is_empty(self) -> None:
        # A brand-new guest repo (`git init`, zero commits) has an unborn HEAD:
        # `ls-remote --symref ... HEAD` reports nothing at all (confirmed
        # empirically -- see parse_symref_head's docstring). The very first
        # push is the one that establishes the branch, so push_head must fall
        # back to "main" rather than raising.
        vm = BSDVM.VMS["freebsd-arm64"]
        rev_parse = mock.Mock(returncode=0, stdout="deadbeef1234\n")
        ls_remote = mock.Mock(returncode=0, stdout="")
        push = mock.Mock(returncode=0)
        push_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["git", "rev-parse"]:
                return rev_parse
            if cmd[:3] == ["git", "ls-remote", "--symref"]:
                return ls_remote
            if cmd[:2] == ["git", "push"]:
                push_calls.append(cmd)
                return push
            raise AssertionError(f"unexpected command: {cmd}")

        with mock.patch.object(BSDVM.subprocess, "run", side_effect=fake_run):
            BSDVM.push_head(vm)
        self.assertEqual(len(push_calls), 1)
        self.assertIn("HEAD:refs/heads/main", push_calls[0])

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


if __name__ == "__main__":
    unittest.main()
