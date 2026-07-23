#!/usr/bin/env python3

import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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


if __name__ == "__main__":
    unittest.main()
