#!/usr/bin/env python3
"""bsdvm: QEMU/HVF FreeBSD+NetBSD aarch64 test VMs on the Mac.

Spec: docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md
Subcommands: fetch provision up down destroy ps gate ladder refresh-golden
"""

import argparse
from dataclasses import dataclass
import gzip
import hashlib
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
import time
import urllib.request


@dataclass(frozen=True)
class VmConfig:
    name: str
    ssh_port: int
    remote: str
    image_candidates: list[str]
    checksum_url: str
    image_format: str  # "qcow2.xz" | "img.gz"
    # Environment prepended to EVERY `ssh_run` command string. It must be an
    # `export ...; ` statement, never a bare `VAR=value ` prefix: a prefix
    # assignment scopes the variable to the single command it precedes, and
    # every gate command has the shape `cd /root/carrick && cargo ...`, so a
    # prefix would apply to the `cd` and NOT to cargo. Measured on both guests
    # (`ssh <box> 'V=x cd /tmp && env | grep -c V'` -> 0). This was inert for
    # the whole life of the NetBSD PATH prefix; it only ever appeared to work
    # because NetBSD's non-login ssh PATH already contains /usr/pkg/bin.
    # `PathExportShapeTests` covers the shape.
    remote_env_prefix: str = ""
    pinned_sha512: str | None = None
    # The `carrick-runtime`/`carrick-cli` platform feature that selects this
    # guest's host backend. Substituted into a stage command as
    # `{platform_feature}` -- see STAGES["stage1"].
    platform_feature: str = ""


@dataclass(frozen=True)
class Stage:
    cmds: list[str]
    report_only: bool
    available: bool
    note: str = ""


_FB_BASE = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/aarch64/Latest"
_FB_RC_BASE = "https://download.freebsd.org/releases/VM-IMAGES/15.1-RC3/aarch64/Latest"
_NB_BASE = "https://cdn.netbsd.org/pub/NetBSD/NetBSD-10.1/evbarm-aarch64/binary/gzimg"

VMS: dict[str, VmConfig] = {
    "freebsd-arm64": VmConfig(
        name="freebsd-arm64",
        ssh_port=2201,
        remote="fbsd-arm",
        platform_feature="platform-freebsd",
        image_candidates=[
            # Preferred: cloud-init capable image (provision goes NoCloud).
            f"{_FB_BASE}/FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
            f"{_FB_BASE}/FreeBSD-15.1-RELEASE-arm64-aarch64-ufs.qcow2.xz",
            # RC fallback, matching the x86 fleet's major (spec: fixed decision).
            f"{_FB_RC_BASE}/FreeBSD-15.1-RC3-arm64-aarch64-ufs.qcow2.xz",
        ],
        checksum_url=f"{_FB_BASE}/CHECKSUM.SHA512",
        image_format="qcow2.xz",
        # Pin the libclang bindgen (bad64-sys) loads to the llvm19 the
        # provisioning step installs. MEASURED: not strictly required today —
        # with LIBCLANG_PATH unset, a clean `cargo build -p bad64-sys` succeeds
        # on this guest because clang-sys globs `/usr/local/llvm*/lib` on
        # FreeBSD, and that llvm19 tree is the only libclang on the box (there
        # is no /usr/local/lib/libclang* or /usr/lib/libclang*). Pinned anyway
        # so the gate does not depend on a build script's glob ORDER once a
        # second llvm lands in /usr/local.
        remote_env_prefix="export LIBCLANG_PATH=/usr/local/llvm19/lib; ",
    ),
    "netbsd-arm64": VmConfig(
        name="netbsd-arm64",
        ssh_port=2202,
        remote="nbsd-arm",
        platform_feature="platform-netbsd",
        image_candidates=[f"{_NB_BASE}/arm64.img.gz"],
        checksum_url=f"{_NB_BASE}/SHA512",
        image_format="img.gz",
        # Non-login ssh on NetBSD lacks /usr/pkg/bin (fleet-wide gotcha) — on
        # THIS guest it happens to be present already, but keep it explicit
        # rather than resting on an image's default PATH. LIBCLANG_PATH is the
        # same determinism pin as the FreeBSD entry; MEASURED not required here
        # either, because the pkgsrc `clang` package pulls `llvm`, whose
        # /usr/pkg/bin/llvm-config clang-sys falls back to for the libdir (a
        # clean `cargo build -p bad64-sys` with it unset succeeds).
        remote_env_prefix=(
            "export PATH=/usr/pkg/bin:/usr/pkg/sbin:$PATH LIBCLANG_PATH=/usr/pkg/lib; "
        ),
        # pinned: no upstream checksum published for gzimg (verified 2026-07-22); update when bumping NetBSD version
        pinned_sha512=(
            "9cd92b45c6efa43cc01ce6ecf6452ff71eda94f98458bcd0f0c16730eb48e86"
            "cabcddd96bbf91e8fcf10bd62c6a2eb2edc9cd79138761ea789ffd21426e531cb"
        ),
    ),
}


_HOST_CRATES = "-p carrick-portable -p carrick-hal -p carrick-host -p carrick-mem"

STAGES: dict[str, Stage] = {
    "stage0": Stage(
        cmds=[f"cd /root/carrick && cargo test {_HOST_CRATES}"],
        report_only=False,
        available=True,
    ),
    "stage1": Stage(
        # The ACCEPTANCE-PATH compile, not `--workspace`.
        #
        # `cargo build --workspace` builds every member with DEFAULT features,
        # which on a BSD means `carrick-runtime`'s `default = ["platform-macos"]`
        # -- so it drags in `carrick-vmm-hvf` (a macOS crate with no crate-level
        # `#![cfg]`) and then fails `carrick-cli`'s own build.rs assertion that
        # platform-macos requires `target_os = "macos"`. That red list is pure
        # artifact: neither crate is on the aarch64 BSD acceptance path (scout
        # spec V12). Selecting the guest's real platform feature measures what
        # the campaign actually needs -- the CLI, engine and runtime built
        # against this host's backend.
        cmds=[
            "cd /root/carrick && cargo build -p carrick-cli "
            "--no-default-features --features {platform_feature}"
        ],
        report_only=True,  # red list IS the bring-up worklist (spec)
        available=True,
    ),
    "stage2": Stage(
        cmds=[], report_only=True, available=False,
        note="requires NativeLane aarch64 host lanes (seam extraction) — "
             "see 2026-07-17-native-backend-portability-seams-design.md",
    ),
    "stage3": Stage(
        cmds=[], report_only=True, available=False,
        note="requires stage2 + LTP gate tooling (native-x86-ltp-gate lineage)",
    ),
}


def state_root() -> Path:
    return Path(os.environ.get("CARRICK_BSDVM_STATE", Path.home() / ".carrick" / "bsdvm"))


def state_dir(vm_name: str) -> Path:
    return state_root() / vm_name


def firmware_paths() -> tuple[Path, Path]:
    override = os.environ.get("CARRICK_BSDVM_FW_DIR")
    if override:
        base = Path(override)
    else:
        qemu = shutil.which("qemu-system-aarch64")
        if qemu is None:
            raise SystemExit("qemu-system-aarch64 not found (brew install qemu)")
        base = Path(qemu).resolve().parent.parent / "share" / "qemu"
    code = base / "edk2-aarch64-code.fd"
    vars_tpl = base / "edk2-arm-vars.fd"
    for p in (code, vars_tpl):
        if not p.exists():
            raise SystemExit(f"missing firmware file: {p}")
    return code, vars_tpl


def ensure_efivars(vm_name: str) -> Path:
    _, vars_tpl = firmware_paths()
    dst = state_dir(vm_name) / "efivars.fd"
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(vars_tpl, dst)
    return dst


def qemu_args(vm: VmConfig, overlay: Path, extra_drives: list[str] | None = None) -> list[str]:
    code, _ = firmware_paths()
    st = state_dir(vm.name)
    args = [
        "qemu-system-aarch64",
        "-M", "virt,gic-version=3",
        "-accel", "hvf",
        "-cpu", "host",
        "-smp", "4",
        "-m", "6144",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={ensure_efivars(vm.name)}",
        # `cache.direct=on` keeps the guest's disk image out of the HOST page
        # cache. Without it the host caches qcow2 contents that the guest is
        # already caching in its own RAM -- pure duplication on a machine that
        # is also holding the guest's `-m` allocation.
        #
        # Measured on this Mac (netbsd-arm64, read-only `tar -cf /dev/null
        # /usr /var`, cold boot per variant): host file-backed pages grew
        # +1.76 GiB during the run WITHOUT this flag and +0.00 GiB WITH it,
        # while guest RSS was unchanged (6.76 vs 6.60 GiB). Two loaded guests
        # already drive this 32 GiB host to ~0.1 GiB free, so the saving is
        # not academic.
        #
        # No speed cost to weigh: macOS has no O_DIRECT, so QEMU implements
        # this as fcntl(F_NOCACHE), and QEMU issue #642 found cache modes make
        # no measurable I/O difference on macOS hosts. Note F_NOCACHE only
        # stops FURTHER caching -- it cannot purge an already-warm cache -- so
        # the benefit accrues from boot.
        "-drive", f"if=virtio,format=qcow2,file={overlay},cache.direct=on",
        "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{vm.ssh_port}-:22",
        "-device", "virtio-net-pci,netdev=n0",
        "-device", "virtio-rng-pci",
        "-chardev",
        f"socket,id=ser0,path={st / 'serial.sock'},server=on,wait=off,logfile={st / 'serial.log'}",
        "-serial", "chardev:ser0",
        "-display", "none",
        "-daemonize",
        "-pidfile", str(st / "qemu.pid"),
    ]
    for d in extra_drives or []:
        args += ["-drive", d]
    return args


def _resolve_vm(name: str) -> VmConfig | None:
    return VMS.get(name)


def url_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def pick_candidate(candidates: list[str], probe) -> str:
    for url in candidates:
        if probe(url):
            return url
    raise SystemExit(f"no image candidate reachable: {candidates}")


def parse_checksum(text: str, filename: str) -> str:
    # BSD md-style: "SHA512 (name) = hex"
    pat = re.compile(r"^SHA512 \((?P<name>[^)]+)\) = (?P<hex>[0-9a-f]{128})$", re.M)
    table = {m.group("name"): m.group("hex") for m in pat.finditer(text)}
    return table[filename]


def _fetch_checksum_text(vm: VmConfig) -> str | None:
    """Best-effort fetch of the raw upstream checksum manifest text.

    Some upstream trees (NetBSD's evbarm gzimg images, confirmed absent across
    cdn.netbsd.org and ftp.netbsd.org for 9.4/10.0/10.1) publish no checksum
    manifest at all for this artifact type -- only binary/sets/ and
    binary/kernel/ get one. An unreachable manifest is reported as None; the
    caller (resolve_expected_sha512) decides what to do about it -- fall back
    to a pinned hash if one is configured, or fail closed if not. This
    function does no parsing and no policy: it is pure network I/O.
    """
    try:
        with urllib.request.urlopen(vm.checksum_url, timeout=60) as resp:
            return resp.read().decode()
    except Exception as exc:
        print(f"warning: checksum manifest unreachable ({vm.checksum_url}): {exc}")
        return None


def resolve_expected_sha512(
    vm: VmConfig, upstream_text: str | None, filename: str
) -> tuple[str, str]:
    """Decide which sha512 a fetched image must match, and how.

    Pure decision logic (no network I/O) so it can be unit tested directly:
      (a) upstream manifest text is present and lists `filename` -> verify
          against that hash, method "upstream".
      (b) otherwise, if the VM config carries a pinned_sha512 -> verify
          against that hash, method "pinned".
      (c) otherwise -> fail closed: raise SystemExit. There is no
          unverified/trust-on-first-use path.
    """
    if upstream_text is not None:
        try:
            return parse_checksum(upstream_text, filename), "upstream"
        except KeyError:
            pass
    if vm.pinned_sha512:
        return vm.pinned_sha512, "pinned"
    raise SystemExit(
        f"no checksum verification source for {filename}: not listed in upstream "
        f"manifest {vm.checksum_url} and no pinned_sha512 configured for "
        f"{vm.name}; refusing to fetch unverified (fail-closed policy)"
    )


def _download(url: str, dst: Path) -> None:
    part = dst.with_suffix(dst.suffix + ".part")
    with urllib.request.urlopen(url, timeout=60) as resp, open(part, "wb") as out:
        shutil.copyfileobj(resp, out, length=1 << 20)
    part.rename(dst)


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _decompress(src: Path, dst: Path) -> None:
    opener = lzma.open if src.suffix == ".xz" else gzip.open
    with opener(src, "rb") as f, open(dst, "wb") as out:
        shutil.copyfileobj(f, out, length=1 << 20)


def _convert_and_finalize(vm: VmConfig, src: Path, part: Path, base: Path) -> None:
    """Convert `src` into `part` (a `base.part.qcow2` sibling of `base`), resize
    *that* file, and only then atomically rename it onto `base`.

    Mirrors `_download`'s .part+rename pattern: `base` only ever exists as a
    fully converted+resized qcow2, never a partial one. If `qemu-img convert`
    or `qemu-img resize` raises (process killed, ENOSPC, ...), the exception
    propagates before the rename, so `base` is left completely untouched --
    there is no window where a half-written file lands at the name every
    future `cmd_fetch` trusts via `base.exists()`.
    """
    if vm.image_format == "qcow2.xz":
        subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2", str(src), str(part)],
            check=True,
        )
    else:  # img.gz: raw disk image
        subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(src), str(part)],
            check=True,
        )
    subprocess.run(["qemu-img", "resize", str(part), "+20G"], check=True)
    part.rename(base)


def cmd_fetch(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    st = state_dir(vm.name)
    base = st / "base.qcow2"
    part = st / "base.part.qcow2"
    golden = st / "golden.qcow2"
    if getattr(args, "force", False) and golden.exists():
        # A forced base refetch out from under a live golden chain reproduces
        # the stale-backing corruption class: golden.qcow2 (and every overlay
        # created against it) still points at the OLD base.qcow2 by path, so
        # rewriting that path's contents in place corrupts every descendant
        # the moment it next reads a not-yet-COW'd cluster.
        raise SystemExit(
            f"{golden} exists; refusing --force (would refetch the base image "
            "backing a live golden chain). Run `provision --force` to rebuild "
            f"the golden on top of a fresh base first, or `destroy {vm.name} "
            "--all` to clear this VM's state entirely."
        )
    part.unlink(missing_ok=True)  # stale partial finalize from an interrupted prior run
    if base.exists() and not getattr(args, "force", False):
        print(f"{base} exists; skipping (use --force to refetch)")
        return 0
    st.mkdir(parents=True, exist_ok=True)
    url = pick_candidate(vm.image_candidates, probe=url_exists)
    fname = url.rsplit("/", 1)[1]
    compressed = st / fname
    print(f"fetching {url}")
    _download(url, compressed)
    upstream_text = _fetch_checksum_text(vm)
    try:
        want, method = resolve_expected_sha512(vm, upstream_text, fname)
    except SystemExit:
        compressed.unlink(missing_ok=True)
        raise
    got = _sha512_file(compressed)
    if got != want:
        compressed.unlink()
        raise SystemExit(f"checksum mismatch for {fname}: got {got[:16]}… want {want[:16]}…")
    raw = st / "image.raw"
    _decompress(compressed, raw)
    if vm.image_format == "qcow2.xz":
        raw.rename(st / "image.qcow2")
        src = st / "image.qcow2"
    else:  # img.gz: raw disk image
        src = raw
    _convert_and_finalize(vm, src, part, base)
    src.unlink()
    compressed.unlink()
    (st / "manifest.json").write_text(
        json.dumps(
            {
                "image_url": url,
                "cloudinit": "CLOUDINIT" in url,
                "sha512": got,
                "checksum_verified": True,
                "checksum_method": method,
            }
        )
        + "\n"
    )
    print(f"wrote {base}")
    return 0


def cmd_ps(args: argparse.Namespace) -> int:
    names = [args.vm] if args.vm else sorted(VMS)
    for name in names:
        pidfile = pidfile_path(name)
        status = "down"
        if pidfile.exists():
            try:
                pid = int(pidfile.read_text().strip())
            except ValueError:
                pid = None
            if pid is None:
                status = "orphan-pidfile pid=?"
            elif pid_alive(pid):
                status = f"up pid={pid}"
            else:
                status = f"orphan-pidfile pid={pid}"
        print(f"{name}\t{status}")
    return 0


def create_overlay(vm_name: str, name: str, backing: str) -> Path:
    st = state_dir(vm_name)
    overlay = st / name
    if not overlay.exists():
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
             "-b", str(st / backing), str(overlay)],
            check=True,
        )
    return overlay


def pidfile_path(vm_name: str) -> Path:
    return state_dir(vm_name) / "qemu.pid"


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # We spawned qemu as this user, so an unsignalable pid means the pid
        # was recycled by a foreign process -- an accepted pidfile-scheme
        # limitation. This cannot distinguish "our qemu now owned by someone
        # else" from "a stale pid reused by an unrelated process"; treat both
        # as not-ours-anymore (dead), same identity-check caveat as read_pid.
        return False


def read_pid(vm_name: str) -> int | None:
    pidfile = pidfile_path(vm_name)
    if not pidfile.exists():
        return None
    try:
        pid = int(pidfile.read_text().strip())
    except ValueError:
        return None
    return pid if pid_alive(pid) else None


def boot(vm: VmConfig, overlay: Path, extra_drives: list[str] | None = None) -> None:
    if read_pid(vm.name) is not None:
        raise SystemExit(f"{vm.name} already running (bsdvm.py down {vm.name} first)")
    subprocess.run(qemu_args(vm, overlay, extra_drives or []), check=True)
    print(f"{vm.name}: booted {overlay.name} (ssh -p {vm.ssh_port} root@127.0.0.1)")


def stop_pid(
    pid: int,
    term_wait_s: float = 10.0,
    kill_wait_s: float = 5.0,
    kill=os.kill,
    sleep=time.sleep,
) -> None:
    try:
        kill(pid, 15)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + term_wait_s
    while time.monotonic() < deadline:
        try:
            kill(pid, 0)
        except ProcessLookupError:
            return
        sleep(0.2)
    try:
        kill(pid, 9)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + kill_wait_s
    while time.monotonic() < deadline:
        try:
            kill(pid, 0)
        except ProcessLookupError:
            return
        sleep(0.1)
    raise SystemExit(f"pid {pid} did not exit after SIGKILL; inspect manually")


# How long the console must be quiet before `SerialConsole.drain` calls the
# buffer clear. Module-level so tests can shrink it (mock.patch.object)
# instead of paying it on every step, same as LOGIN_TIMEOUT_S.
DRAIN_QUIET_S = 0.3


class SerialConsole:
    """Line-oriented expect over the qemu chardev unix socket."""

    def __init__(self, sock_path: Path):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(str(sock_path))
        self._sock.settimeout(0.25)
        self._buf = b""
        self._log_hint = sock_path.with_name("serial.log")

    def expect(self, pattern: bytes, timeout_s: float) -> bytes:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            idx = self._buf.find(pattern)
            if idx >= 0:
                out, self._buf = self._buf[: idx + len(pattern)], self._buf[idx + len(pattern):]
                return out
            try:
                chunk = self._sock.recv(4096)
                if not chunk:
                    # Peer (qemu) closed the connection: recv() on a closed
                    # socket returns b"" immediately rather than raising, so
                    # without this check the loop would spin at 100% CPU
                    # doing nothing until `deadline` -- observed in practice
                    # as an orphaned bsdvm.py process still burning a full
                    # core minutes after the VM under it was torn down.
                    raise ConnectionError(
                        f"serial connection closed while waiting for {pattern!r} "
                        f"(see {self._log_hint})"
                    )
                self._buf += chunk
            except socket.timeout:
                pass
        raise TimeoutError(
            f"serial expect timed out waiting for {pattern!r} "
            f"(see {self._log_hint})"
        )

    def expect_re(self, pattern: "re.Pattern[bytes]", timeout_s: float) -> "re.Match[bytes]":
        """`expect`, but matching a compiled regex instead of a literal.

        Same consume-through-the-match semantics as `expect`: everything up to
        and including the match is removed from the buffer, so a later call
        can never re-match an earlier command's output. This is what makes the
        exit-status sentinel in `_run_step` reliable -- see its comment for
        why the pattern must require a digit rather than match a fixed string.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            m = pattern.search(self._buf)
            if m is not None:
                self._buf = self._buf[m.end():]
                return m
            try:
                chunk = self._sock.recv(4096)
                if not chunk:
                    raise ConnectionError(
                        f"serial connection closed while waiting for {pattern.pattern!r} "
                        f"(see {self._log_hint})"
                    )
                self._buf += chunk
            except socket.timeout:
                pass
        raise TimeoutError(
            f"serial expect timed out waiting for {pattern.pattern!r} "
            f"(see {self._log_hint})"
        )

    def drain(self, quiet_s: float | None = None) -> bytes:
        """Discard everything currently buffered or in flight, returning it.

        Called immediately before each provisioning command is sent so that
        nothing already sitting in the buffer -- a late-arriving prompt, a
        package manager's post-install trigger output, a login banner that
        happens to contain "# " -- can be mistaken for that command's own
        response. Reads until the socket has been quiet for `quiet_s`.
        """
        if quiet_s is None:
            quiet_s = DRAIN_QUIET_S
        dropped = self._buf
        self._buf = b""
        deadline = time.monotonic() + quiet_s
        while time.monotonic() < deadline:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            dropped += chunk
            deadline = time.monotonic() + quiet_s
        return dropped

    def sendline(self, s: str) -> None:
        self._sock.sendall(s.encode() + b"\n")


def read_pubkey() -> str:
    override = os.environ.get("CARRICK_BSDVM_PUBKEY")
    candidates = [Path(override)] if override else [
        Path.home() / ".ssh" / "id_ed25519.pub",
        Path.home() / ".ssh" / "id_rsa.pub",
    ]
    for c in candidates:
        if c.exists():
            return c.read_text().strip()
    raise SystemExit("no ssh public key found (set CARRICK_BSDVM_PUBKEY)")


def _sh_squote(s: str) -> str:
    """POSIX single-quoted shell escaping for a value embedded verbatim in a
    shell command string built by this module (e.g. the ssh pubkey, whose
    trailing user@host comment can contain a literal `'`). The standard
    close-quote/escaped-quote/reopen-quote trick: `'\\''`.
    """
    return "'" + s.replace("'", "'\\''") + "'"


def _yaml_dquote(s: str) -> str:
    """Double-quoted YAML scalar escaping (no yaml lib): backslash must be
    escaped before double-quote, or an embedded `\\` would be re-escaped by
    the `"` substitution.
    """
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


_GIT_SETUP = (
    "git init -b main /root/carrick && "
    "git -C /root/carrick config receive.denyCurrentBranch updateInstead"
)


def provision_commands(vm: VmConfig, pubkey: str) -> list[tuple[str, float]]:
    key_cmd = (
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
        f"echo {_sh_squote(pubkey)} >> /root/.ssh/authorized_keys && "
        "chmod 600 /root/.ssh/authorized_keys"
    )
    if vm.name == "freebsd-arm64":
        return [
            (key_cmd, 30),
            ("sysrc sshd_enable=YES && "
             "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config && "
             "service sshd restart", 120),
            ("env ASSUME_ALWAYS_YES=yes pkg bootstrap -f", 600),
            # `llvm19` is NOT optional tooling, it is a BUILD dependency of the
            # aarch64 acceptance path: carrick-dsr-aarch64 -> bad64 -> bad64-sys
            # runs `bindgen` in its build script, and bindgen dlopens libclang.
            # FreeBSD base ships none (no /usr/lib/libclang*, no
            # /usr/local/lib/libclang*), so without this the stage1 gate dies
            # with `Unable to find libclang`. The package puts it at
            # /usr/local/llvm19/lib, which `remote_env_prefix` pins as
            # LIBCLANG_PATH. Mirrors the NetBSD `clang` line below.
            ("env ASSUME_ALWAYS_YES=yes pkg install -y git just rust python3 llvm19", 3600),
            # A login shell's PATH already includes /usr/local/bin, but
            # `export` (not a plain prefix assignment) still matters here:
            # a bare `PATH=... cmd1 && cmd2` only scopes PATH to cmd1,
            # leaving cmd2 (after the `&&` in _GIT_SETUP) to fail the same
            # way it would under a PATH-less environment.
            (f"export PATH=/usr/local/bin:/usr/local/sbin:$PATH; {_GIT_SETUP}", 30),
            ("shutdown -p now", 120),
        ]
    return [  # netbsd-arm64
        (key_cmd, 30),
        ("printf 'sshd=YES\\ndhcpcd=YES\\n' >> /etc/rc.conf && "
         "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config && "
         "/etc/rc.d/sshd start", 300),
        # Purely local (never blocks on the network) visibility into whether
        # dhcpcd actually got a lease before the network-dependent pkg_add
        # step below -- kept for diagnosis after the DAD hang below was found
        # via exactly this output.
        ("ifconfig -a; netstat -rn", 30),
        # dhcpcd's IPv4 duplicate-address-detection (ARP probe) never
        # resolves over qemu's usermode/slirp network -- there is no real
        # peer to ARP against, so the interface's address is left
        # permanently in "tentative" state and no default route is
        # installed. Symptom: pkg_add hangs forever with zero packets sent
        # and no error. `sysctl ... && dhcpcd restart` alone was NOT
        # sufficient (the already-bound address stayed tentative), and a
        # manual `ifconfig ... delete` follow-up hung the shell outright
        # (likely a syntax/argument-order issue with this ifconfig's
        # `delete` verb) -- so instead fully stop dhcpcd first (releasing
        # its lease/address cleanly through its own codepath), set the
        # sysctl, then start it fresh: a brand new lease acquired after
        # dad_count=0 is set should skip DAD from the start rather than
        # needing to un-stick an already-tentative one.
        ("/etc/rc.d/dhcpcd stop; sysctl -w net.inet.ip.dad_count=0; "
         "/etc/rc.d/dhcpcd start; sleep 5; ifconfig -a; netstat -rn", 60),
        # dhcpcd never wrote a resolver config from this DHCP server either
        # (confirmed by ntpd's own background "Temporary failure in name
        # resolution" log lines) -- write it directly. 10.0.2.3 is qemu
        # usermode-network's fixed built-in DNS relay, deterministic given
        # this module's own -netdev user config (matches the 10.0.2.2
        # gateway used above). Resolution STILL failed after this alone
        # (ntpd kept logging the same error against a correct resolv.conf),
        # so also check whether npf (NetBSD's default packet filter) is the
        # thing actually eating the UDP/53 replies, and lay in a static
        # /etc/hosts entry for the pkgsrc CDN host as a belt-and-braces
        # fallback that doesn't depend on the relay working at all. The IP
        # is a Fastly edge (may rotate over time -- if this ever goes stale,
        # `host cdn.netbsd.org` from the Mac host gets a current one).
        ("echo 'nameserver 10.0.2.3' > /etc/resolv.conf; cat /etc/resolv.conf; "
         "/etc/rc.d/npf status; npfctl show 2>&1 | head -20; "
         "echo '151.101.1.6 cdn.netbsd.org' >> /etc/hosts", 30),
        # cdn.netbsd.org/.../10.1/All/ 302-redirects (at the CDN/varnish
        # layer) to .../10.0_2026Q1/All/ -- there is no real 10.1 aarch64
        # binary bulk-build tree, just a rolling "current quarter" one under
        # the 10.0 branch name. NetBSD's pkg_add doesn't follow that
        # redirect; it just hangs with no output and no timeout. Point
        # PKG_PATH at the resolved location directly (empirically confirmed
        # to carry git-2.53.0 and rust-1.91.1nb1 as of 2026-07-22).
        #
        # `clang` is NOT optional tooling here, it is a BUILD dependency of the
        # aarch64 acceptance path: carrick-dsr-aarch64 -> bad64 -> bad64-sys runs
        # `bindgen` in its build script, and bindgen dlopens libclang. NetBSD
        # base ships no libclang, so without this the stage1 gate dies with
        # `Unable to find libclang: "couldn't find any valid shared libraries
        # matching: ['libclang.so', 'libclang.so.*']"`. Installing the pkgsrc
        # `clang` package puts it at /usr/pkg/lib and pulls `llvm`, whose
        # /usr/pkg/bin/llvm-config is what clang-sys falls back to for the
        # libdir -- so LIBCLANG_PATH is not REQUIRED here (re-verified on-box
        # 2026-07-25: a clean bad64-sys rebuild succeeds with the env var
        # unset). `remote_env_prefix` pins it anyway, for the determinism
        # reason stated there, not because the build needs it. This was
        # invisible while stage1 was `cargo build --workspace`, which died on
        # carrick-vmm-hvf long before reaching a bad64-sys compile.
        ("export PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/10.0_2026Q1/All; "
         "/usr/sbin/pkg_add -U git rust clang || /usr/sbin/pkg_add -U git rust clang", 3600),
        # `just` may be absent from pkgsrc aarch64; gates call cargo directly.
        ("export PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/10.0_2026Q1/All; "
         "/usr/sbin/pkg_add -U just || echo 'just unavailable (ok)'", 600),
        # `export` (not a bare prefix assignment) so PATH survives across the
        # `&&` in _GIT_SETUP -- see the matching freebsd comment above. 30s
        # was NOT enough here in practice: pkgsrc post-install trigger
        # output (git-base's template/hook file copies, xmlcatmgr catalog
        # registration, etc.) can still be draining to the console for a
        # while after the shell prompt has nominally returned, delaying
        # this command's own completion echo.
        (f"export PATH=/usr/pkg/bin:$PATH; {_GIT_SETUP}", 180),
        ("shutdown -p now", 120),
    ]


# Per-package proof that the package's payload is actually usable on the
# guest, keyed by the package name as it appears on the install line in
# `provision_commands`. `provision_postconditions` is built from these, and
# `ProvisionPostconditionDataTests` asserts every installed package has an
# entry -- so adding a package to the install line without a proof is a test
# failure rather than a silently unverified golden image.
#
# These exist because of the 2026-07-25 refresh-golden incident: provisioning
# was believed to have installed llvm19 and nothing in the tool ever checked.
# (In that incident the install genuinely worked and the golden ROTATION is
# what corrupted the image -- but the tool could not have told the difference,
# which is the defect these close. `_assert_openable` closes the other half.)
_FREEBSD_PKG_PROOFS: dict[str, str | None] = {
    "git": "command -v git",
    "just": "command -v just",
    # The `rust` package is the one whose name does not match its payload.
    "rust": "command -v rustc && command -v cargo",
    "python3": "command -v python3",
    # bindgen (bad64-sys, on the aarch64 acceptance path) dlopens libclang;
    # `VMS[...].remote_env_prefix` pins LIBCLANG_PATH at exactly this libdir,
    # so prove the file that variable points at, not merely that pkg thinks
    # the package is registered.
    "llvm19": "test -x /usr/local/llvm19/bin/clang && test -r /usr/local/llvm19/lib/libclang.so",
}
_NETBSD_PKG_PROOFS: dict[str, str | None] = {
    "git": "command -v git",
    "rust": "command -v rustc && command -v cargo",
    "clang": "test -r /usr/pkg/lib/libclang.so",
    # `just` is genuinely best-effort on pkgsrc/aarch64 -- its install line
    # tolerates absence (`|| echo 'just unavailable (ok)'`) and gates call
    # cargo directly -- so it gets no post-condition. Explicit None rather
    # than a missing key so the drift test can tell "deliberately optional"
    # from "someone forgot".
    "just": None,
}


def provision_postconditions(vm: VmConfig) -> list[tuple[str, float]]:
    """Checks run over the serial console, through the same exit-status-verified
    path as provisioning itself, IMMEDIATELY BEFORE the guest powers off.

    Running them here rather than over ssh after a reboot is deliberate: a
    failure raises while the caller is still inside its try/except, so the VM
    is stopped and the existing golden.qcow2 is never rotated. There is no
    extra boot.
    """
    if vm.name == "freebsd-arm64":
        env, proofs = "export PATH=/usr/local/bin:/usr/local/sbin:$PATH; ", _FREEBSD_PKG_PROOFS
    else:
        env, proofs = "export PATH=/usr/pkg/bin:/usr/pkg/sbin:$PATH; ", _NETBSD_PKG_PROOFS
    # One step per package so a failure names the package that is missing.
    steps: list[tuple[str, float]] = [
        (env + proof, 60) for proof in proofs.values() if proof is not None
    ]
    steps.append(("test -d /root/carrick/.git", 30))
    steps.append(("test -s /root/.ssh/authorized_keys", 30))
    return steps


def write_cloudinit_seed(vm_name: str, pubkey: str) -> Path:
    """Write the FreeBSD NoCloud seed (meta-data + user-data) and pack it into
    seed.iso. `provision_commands` is the single source of truth for what
    gets run: the `runcmd` list here is derived from it directly (minus the
    first entry, which `ssh_authorized_keys` already covers) rather than
    hand-duplicated, so the two provisioning paths cannot drift apart.
    """
    if vm_name != "freebsd-arm64":
        raise SystemExit("cloud-init seed is only used for the FreeBSD lane")
    st = state_dir(vm_name)
    cmds = provision_commands(VMS[vm_name], pubkey)[1:]  # drop authorized_keys step
    seed_dir = st / "seed"
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "meta-data").write_text(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")
    runcmd_lines = "".join(f"  - {_yaml_dquote(cmd)}\n" for cmd, _ in cmds)
    (seed_dir / "user-data").write_text(
        "#cloud-config\n"
        "disable_root: false\n"
        "ssh_authorized_keys:\n"
        f"  - {_yaml_dquote(pubkey)}\n"
        "runcmd:\n"
        f"{runcmd_lines}"
    )
    iso = st / "seed.iso"
    iso.unlink(missing_ok=True)
    subprocess.run(
        ["hdiutil", "makehybrid", "-iso", "-joliet",
         "-default-volume-name", "cidata", "-o", str(iso), str(seed_dir)],
        check=True,
    )
    return iso


PROMPT = b"# "

# Module-level so tests can shrink it (mock.patch.object) instead of actually
# waiting out a slow-boot budget; production callers get the full 600s.
LOGIN_TIMEOUT_S = 600


def wait_for_shutdown(vm_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if read_pid(vm_name) is None:
            return
        time.sleep(2)
    raise SystemExit(f"{vm_name}: qemu did not exit after guest shutdown (see serial.log)")


def _step_sentinel_re(idx: int) -> "re.Pattern[bytes]":
    """The pattern `_run_step` waits for, for step number `idx`.

    It must require DIGITS where the exit status goes. The serial tty echoes
    the command line back verbatim, and that echo contains the literal `$?`,
    so a fixed-string match (or a `.*` here) would match the ECHO instead of
    the output -- reintroducing exactly the "returned without running" bug
    this whole mechanism exists to close, one layer down. `_RC_` immediately
    after the index also keeps step 1's pattern from matching step 10's
    sentinel.
    """
    return re.compile(rb"__BSDVM_STEP_" + str(idx).encode() + rb"_RC_(\d+)_END__")


def _run_step(con: SerialConsole, vm_name: str, cmd: str, timeout_s: float, idx: int) -> None:
    """Send one provisioning command and PROVE it succeeded.

    Waiting for a shell PROMPT (what this used to do) cannot distinguish "the
    command ran and worked" from "the command failed instantly and the shell
    came back", nor from "a prompt was already sitting in the buffer and the
    command was never even sent". Both were live silent-success paths. The
    sentinel carries the command's own `$?`, so neither is possible: a
    nonzero status is a hard failure, and a missing sentinel is a timeout.
    """
    label = f"{cmd[:70]}…" if len(cmd) > 70 else cmd
    print(f"[provision {vm_name}] {label}")
    # Drop anything already buffered (a late prompt, a package manager's
    # trailing trigger output, a banner containing "# ") so this step can
    # only ever match its own sentinel.
    con.drain()
    con.sendline(f'{cmd}; echo "__BSDVM_STEP_{idx}_RC_$?_END__"')
    try:
        m = con.expect_re(_step_sentinel_re(idx), timeout_s=timeout_s)
    except TimeoutError as exc:
        raise SystemExit(
            f"{vm_name}: provisioning step {idx} never reported an exit status "
            f"within {timeout_s}s: {cmd!r} ({exc})"
        ) from exc
    rc = int(m.group(1))
    if rc != 0:
        raise SystemExit(
            f"{vm_name}: provisioning step {idx} FAILED rc={rc}: {cmd!r} "
            f"(see {state_dir(vm_name) / 'serial.log'})"
        )


def _run_serial_provision(vm: VmConfig, pubkey: str) -> None:
    st = state_dir(vm.name)
    con = SerialConsole(st / "serial.sock")
    try:
        con.expect(b"login: ", timeout_s=LOGIN_TIMEOUT_S)  # first boot: fsck/resize can be slow
    except TimeoutError:
        # Some images (seen on NetBSD gzimg first boot) drop straight to a
        # root shell instead of presenting a login prompt. Nudge with a
        # newline and look for the shell prompt directly instead.
        con.sendline("")
        con.expect(PROMPT, timeout_s=120)
    else:
        con.sendline("root")
        con.expect(PROMPT, timeout_s=120)
    # Note that neither PROMPT match above is load-bearing for correctness:
    # if either matched something that was not really a shell prompt, step 1
    # below still has to produce a real sentinel or the run fails loudly.

    steps = list(provision_commands(vm, pubkey))
    # `shutdown` is the one command that legitimately never returns to a
    # prompt, so it cannot be exit-status checked; splice the post-conditions
    # in AHEAD of it. Asserting the terminal step's identity (rather than
    # `break`ing on the first command that happens to start with "shutdown")
    # means a data change that moves or drops it fails here instead of
    # silently skipping every later step.
    if not steps or not steps[-1][0].startswith("shutdown"):
        raise SystemExit(
            f"{vm.name}: provision_commands must end with a shutdown step; "
            f"got {steps[-1][0]!r} if any"
        )
    shutdown_cmd = steps.pop()[0]
    steps.extend(provision_postconditions(vm))

    for idx, (cmd, timeout_s) in enumerate(steps, start=1):
        _run_step(con, vm.name, cmd, timeout_s, idx)

    print(f"[provision {vm.name}] {shutdown_cmd}")
    con.drain()
    con.sendline(shutdown_cmd)


def _image_backing_file(img: Path) -> str | None:
    """The qcow2 backing-file path recorded in `img`'s header, or None.

    `-f qcow2` is deliberate throughout this pair of helpers: without it
    qemu-img probes the format and happily reports a truncated or garbage
    file as `raw` with no backing file, so a corrupt candidate would sail
    through the very checks meant to stop it.
    """
    p = subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(img)],
        capture_output=True, text=True,
    )
    if p.returncode != 0:
        raise SystemExit(
            f"refusing to publish {img.name}: qemu-img cannot open it as qcow2 "
            f"(rc={p.returncode}): {p.stderr.strip() or p.stdout.strip()}"
        )
    return json.loads(p.stdout).get("backing-filename")


def _assert_publishable(candidate: Path, dest: Path) -> None:
    """Check `candidate` BEFORE it is renamed onto `dest`.

    Self-reference is a property of a qcow2's PATH, not of its bytes: the
    2026-07-25 incident's image was perfectly loadable right up until the
    rename that moved it on top of the path its own header named as its
    backing file. So this has to be checked against the DESTINATION path,
    before the rename -- checking the candidate where it currently sits
    cannot see it (measured: the same corrupt file passes `qemu-img info
    --backing-chain` under any name other than its backing file's).

    Doing it before the rename is what keeps the failure non-destructive:
    the existing golden.qcow2 is still in place and still openable.
    """
    backing = _image_backing_file(candidate)  # raises if not an openable qcow2
    if backing is not None and Path(backing).resolve() == dest.resolve():
        raise SystemExit(
            f"refusing to publish {candidate.name} as {dest.name}: its qcow2 "
            f"backing file is {backing}, so the rename would make it reference "
            "itself (an unopenable infinite backing chain -- this is the "
            "2026-07-25 refresh-golden corruption)"
        )


def _assert_openable(img: Path) -> None:
    """Confirm a just-published image really opens, chain and all.

    `--backing-chain` is what actually walks the chain, so it is what detects
    a loop; `_assert_publishable` should have made that unreachable, and this
    is the belt-and-braces check that the artifact consumers will open is the
    artifact we think we published.
    """
    p = subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--backing-chain", str(img)],
        capture_output=True, text=True,
    )
    if p.returncode != 0:
        raise SystemExit(
            f"published {img.name} but qemu-img cannot open it "
            f"(rc={p.returncode}): {p.stderr.strip() or p.stdout.strip()}"
        )


def _invalidate_consumer_overlays(vm_name: str) -> None:
    """Unlink every overlay backed by golden.qcow2 (dev.qcow2 and any
    gate-*.qcow2) after a new golden lands.

    qcow2 overlays reference their backing file by path, not by content or
    generation: once golden.qcow2 is replaced, an existing consumer overlay
    would silently read backing blocks from a DIFFERENT disk image than the
    one it was created against -- corruption-like reads, not an error. This
    exact foot-gun cost most of the Task 6 session's wall clock (see the
    cmd_provision call-site comment). Call this immediately after the rename
    that lands a new golden.qcow2, in both cmd_provision and
    cmd_refresh_golden.
    """
    st = state_dir(vm_name)
    # dev.qcow2 is a human's working disk (the 2026-07-25 incident deleted one
    # carrying a hand-installed toolchain), so move it aside under a name
    # nothing consumes instead of destroying it. gate-*.qcow2 are machine-made
    # per-run scratch and are regenerated on demand, so those are unlinked --
    # and renaming them "aside" would leave them matching the same glob.
    dev = st / "dev.qcow2"
    if dev.exists():
        stale = st / f"dev.stale-{int(time.time())}.qcow2"
        dev.rename(stale)
        print(f"moved stale overlay dev.qcow2 -> {stale.name} (backing golden replaced)")
    for overlay in sorted(st.glob("gate-*.qcow2")):
        if overlay.exists():
            overlay.unlink()
            print(f"removed stale overlay {overlay.name} (backing golden replaced)")


def cmd_provision(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    st = state_dir(vm.name)
    if not (st / "base.qcow2").exists():
        raise SystemExit(f"no base image; run: bsdvm.py fetch {vm.name}")
    golden = st / "golden.qcow2"
    if golden.exists() and not args.force:
        raise SystemExit(f"{golden} exists (use --force to reprovision)")
    # A failed earlier run may have left a partially-provisioned overlay: start
    # fresh. The old golden (if any) is deliberately left alone here -- `work`
    # is backed by base.qcow2, not golden.qcow2, so it is not in this
    # overlay's chain and does not need to move before boot/provision
    # succeeds. It only gets rotated to golden.prev.qcow2 once a replacement
    # has actually landed, below.
    (st / "provision.qcow2").unlink(missing_ok=True)
    work = create_overlay(vm.name, "provision.qcow2", "base.qcow2")
    pubkey = read_pubkey()
    # manifest.json's cloudinit=True (set at fetch time for the FreeBSD
    # BASIC-CLOUDINIT image) originally meant "drive provisioning via a
    # NoCloud seed.iso, hands-off". That path is deliberately NOT taken here:
    # while chasing what looked like reproducible /boot/kernel corruption on
    # golden images built via cloud-init, this project's own `up` reuses an
    # existing dev.qcow2 overlay rather than recreating it (by design, so a
    # dev session's disk state survives across up/down) -- across this
    # session's many `provision --force` reruns, every `up` verification was
    # unknowingly reading a STALE dev.qcow2 overlay still backed by an
    # earlier golden.qcow2 generation, which is what actually explains the
    # observed "missing kernel" (confirmed by deleting dev.qcow2 before
    # re-testing: the very first cloud-init-built golden this session was
    # never actually re-checked with a fresh overlay). So the cloud-init path
    # was very likely fine all along. This serial-expect path is kept
    # anyway -- it's the plan's own documented fallback, it's now proven
    # end-to-end (ssh + rustc + git config all verified), and reverting to
    # re-validate cloud-init would cost another full provisioning run for a
    # single-source-of-truth code-cleanliness win, not a correctness one.
    # Future maintainer: if you want cloud-init back, `write_cloudinit_seed`
    # is untouched and still unit-tested; just re-wire this call site -- the
    # stale-overlay foot-gun described above is now enforced shut by
    # _invalidate_consumer_overlays (called below once the new golden
    # lands), so there is no more manual `rm dev.qcow2` step to remember.
    try:
        boot(vm, work)
        _run_serial_provision(vm, pubkey)
        wait_for_shutdown(vm.name, timeout_s=4200)
    except BaseException:
        pid = read_pid(vm.name)
        if pid is not None:
            stop_pid(pid)
        raise
    _assert_publishable(work, golden)
    prev = st / "golden.prev.qcow2"
    if golden.exists():
        prev.unlink(missing_ok=True)
        golden.rename(prev)
    work.rename(golden)
    _assert_openable(golden)
    _invalidate_consumer_overlays(vm.name)
    ensure_dev_remote(vm)
    print(f"golden image ready: {golden}")
    return 0


def cmd_refresh_golden(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    st = state_dir(vm.name)
    golden = st / "golden.qcow2"
    if not golden.exists():
        raise SystemExit(f"nothing to refresh; run: bsdvm.py provision {vm.name}")
    prev = st / "golden.prev.qcow2"
    # Reprovision on top of the CURRENT golden. golden.qcow2 is not moved,
    # renamed or unlinked anywhere between here and the rotation at the
    # bottom, which is the whole point:
    #
    # This function used to flatten UP FRONT (golden -> golden.prev, flat ->
    # golden), stack `work` on that flattened golden, and then -- after
    # provisioning -- `golden.unlink()` followed by `work.rename(golden)`.
    # `create_overlay` records an ABSOLUTE backing path, so that unlink
    # destroyed the full disk image `work` depended on and the rename dropped
    # `work` onto the exact path its own header still named as its backing
    # file. The result was a self-referential qcow2 that no consumer can open
    # (`qemu-img create -b` on it exits SIGSEGV walking an infinite chain) --
    # published with a success message, on 2026-07-25, taking the freebsd
    # lane's golden and its dev overlay out together.
    #
    # Flattening at the END into a THIRD name instead makes that class of bug
    # unrepresentable: nothing is ever unlinked while something references it,
    # the new golden is standalone (it does not even chain onto base.qcow2),
    # and if anything below fails the existing golden is still in place.
    (st / "provision.qcow2").unlink(missing_ok=True)
    work = create_overlay(vm.name, "provision.qcow2", "golden.qcow2")
    pubkey = read_pubkey()
    try:
        boot(vm, work)
        _run_serial_provision(vm, pubkey)
        wait_for_shutdown(vm.name, timeout_s=4200)
    except BaseException:
        pid = read_pid(vm.name)
        if pid is not None:
            stop_pid(pid)
        raise
    fresh = st / "golden.new.qcow2"
    fresh.unlink(missing_ok=True)
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(work), str(fresh)], check=True)
    _assert_publishable(fresh, golden)
    prev.unlink(missing_ok=True)
    golden.rename(prev)  # rename, never unlink -- mirrors cmd_provision
    fresh.rename(golden)
    _assert_openable(golden)
    work.unlink(missing_ok=True)
    # The just-flattened/reprovisioned golden.qcow2 has entirely different
    # content at the same path than what any pre-existing dev.qcow2/gate-*.qcow2
    # was created against -- see _invalidate_consumer_overlays.
    _invalidate_consumer_overlays(vm.name)
    ensure_dev_remote(vm)
    print(f"golden refreshed (previous kept at {prev})")
    return 0


def ssh_base(vm: VmConfig) -> list[str]:
    st = state_dir(vm.name)
    st.mkdir(parents=True, exist_ok=True)
    return [
        "ssh",
        "-p", str(vm.ssh_port),
        "-o", f"UserKnownHostsFile={st / 'known_hosts'}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=5",
        "root@127.0.0.1",
    ]


def ssh_run(vm: VmConfig, cmd: str, timeout_s: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        ssh_base(vm) + [vm.remote_env_prefix + cmd],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def interactive_ssh_argv(vm: VmConfig, command: list[str]) -> list[str]:
    """argv for `bsdvm ssh <vm> [cmd...]`.

    Pure (no I/O beyond `ssh_base`'s state-dir mkdir) so it can be unit tested
    directly, like `parse_symref_head`.

    Two properties matter, and both are why this subcommand exists rather than
    everyone hand-rolling `ssh -p 2201 root@127.0.0.1`:

    * it inherits `ssh_base`'s per-state-dir `UserKnownHostsFile` +
      `StrictHostKeyChecking=accept-new`, so re-provisioning a guest (new
      overlay => new host key) can never wedge callers with
      "Host key verification failed" against `~/.ssh/known_hosts`; and
    * it applies `remote_env_prefix`, so a remote command gets the guest's
      toolchain environment (cargo on PATH, `LIBCLANG_PATH`) without every
      caller remembering to prefix it.

    An empty `command` means an interactive login shell, which takes no env
    prefix (the login shell sources the profile itself).
    """
    base = ssh_base(vm)
    if not command:
        return base
    return base + [vm.remote_env_prefix + shlex.join(command)]


def cmd_ssh(args: argparse.Namespace) -> int:
    vm = _resolve_vm(args.vm)
    assert vm is not None  # main() validated it
    return subprocess.call(interactive_ssh_argv(vm, list(args.command)))


def ssh_wait(vm: VmConfig, timeout_s: float = 300) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if ssh_run(vm, "true", timeout_s=10).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(5)
    raise SystemExit(
        f"{vm.name}: ssh not reachable after {timeout_s}s "
        f"(see {state_dir(vm.name) / 'serial.log'})"
    )


def git_url(vm: VmConfig) -> str:
    return f"ssh://root@127.0.0.1:{vm.ssh_port}/root/carrick"


def git_ssh_env(vm: VmConfig) -> dict[str, str]:
    base = ssh_base(vm)
    # GIT_SSH_COMMAND takes the options but not host/port (URL carries those).
    # Use shlex.join to properly quote option tokens (especially paths with spaces).
    opts = shlex.join(base[3:-1])  # the three -o pairs
    env = dict(os.environ)
    env["GIT_SSH_COMMAND"] = f"ssh {opts}"
    return env


def parse_symref_head(text: str) -> str:
    """Parse `git ls-remote --symref <url> HEAD` output and return the branch
    name the remote's HEAD is a symref to (e.g. "main" from the line
    `ref: refs/heads/main\tHEAD`).

    Pure string parsing, no I/O, so it can be unit tested directly. Raises
    SystemExit if no symref line is present -- this happens for a genuinely
    empty repo (`git init`, zero commits): HEAD is an unborn symref and git's
    ref-advertisement protocol emits nothing at all for `ls-remote --symref`
    against it (confirmed empirically against a real `git init -b main` repo
    with no commits: exit 0, empty stdout). Callers that have a sensible
    default for that specific case (the very first push, which establishes
    the branch) should catch SystemExit themselves -- this function has no
    opinion on what a missing symref should fall back to.
    """
    m = re.search(r"^ref: refs/heads/(\S+)\tHEAD$", text, re.M)
    if not m:
        raise SystemExit(
            f"no symref HEAD line found in ls-remote --symref output: {text!r}"
        )
    return m.group(1)


def push_head(vm: VmConfig) -> str:
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    # Guest-side truth first: `git symbolic-ref --short HEAD` reports the
    # branch name a checked-out HEAD points to whether or not that branch has
    # any commits yet (an *unborn* HEAD, e.g. a golden provisioned by a plain
    # `git init` before `_GIT_SETUP` pinned `-b main`, still resolves this to
    # e.g. "master"). `git ls-remote --symref` cannot make that distinction --
    # for an unborn HEAD it prints nothing at all -- so it previously caused
    # push_head to default to "main" even when the guest's actual checked-out
    # branch was "master", pushing an orphan `main` ref that
    # receive.denyCurrentBranch=updateInstead never applied to the (still
    # empty) worktree.
    branch: str | None = None
    try:
        probe = ssh_run(vm, "git -C /root/carrick symbolic-ref --short HEAD", timeout_s=30)
        if probe.returncode == 0 and probe.stdout.strip():
            branch = probe.stdout.strip()
    except subprocess.TimeoutExpired:
        branch = None

    if branch is None:
        # ssh probe unreachable or inconclusive: fall back to the
        # ls-remote --symref based detection.
        ls_remote = subprocess.run(
            ["git", "ls-remote", "--symref", git_url(vm), "HEAD"],
            capture_output=True,
            text=True,
            env=git_ssh_env(vm),
            check=True,
        )
        try:
            branch = parse_symref_head(ls_remote.stdout)
        except SystemExit:
            # Empty guest repo, no HEAD yet (see parse_symref_head's
            # docstring), AND the ssh symbolic-ref probe was also
            # inconclusive: this push is the one that establishes the
            # branch. Guests are provisioned via `git init -b main`
            # (_GIT_SETUP), so "main" is what the guest's checked-out branch
            # will actually be once this push creates its first commit.
            branch = "main"
            print(
                f"{vm.name}: no symref HEAD from ls-remote (empty repo); "
                "defaulting first push to refs/heads/main"
            )

    subprocess.run(
        ["git", "push", "--force", git_url(vm), f"HEAD:refs/heads/{branch}"],
        env=git_ssh_env(vm),
        check=True,
    )

    # Verify the push actually materialized into the guest's worktree (this
    # is exactly the check that would have caught the bug above): a push to
    # the wrong ref, or a guest with denyCurrentBranch misconfigured, leaves
    # /root/carrick looking pushed-to but empty. One forced checkout retry
    # before giving up -- if the branch name is right this always succeeds.
    materialized = ssh_run(vm, "test -f /root/carrick/Cargo.toml", timeout_s=30)
    if materialized.returncode != 0:
        ssh_run(
            vm,
            f"git -C /root/carrick checkout -f {branch} -- . || "
            f"git -C /root/carrick checkout -f {branch}",
            timeout_s=60,
        )
        recheck = ssh_run(vm, "test -f /root/carrick/Cargo.toml", timeout_s=30)
        if recheck.returncode != 0:
            raise SystemExit(
                f"{vm.name}: pushed HEAD to refs/heads/{branch} but "
                "/root/carrick/Cargo.toml is still missing after a forced "
                f"checkout -- inspect the guest repo (branch={branch!r})"
            )

    return sha


def ensure_dev_remote(vm: VmConfig) -> None:
    have = subprocess.run(
        ["git", "remote"], capture_output=True, text=True, check=True
    ).stdout.split()
    if vm.remote not in have:
        subprocess.run(["git", "remote", "add", vm.remote, git_url(vm)], check=True)
        print(f"added git remote {vm.remote} -> {git_url(vm)}")


def write_report(out_dir: Path, report: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        f"bsdvm gate {report['stage']} on {report['vm']}: "
        + ("PASS" if report["pass"] else "FAIL")
        + (" (report-only)" if report["report_only"] else ""),
        f"head={report['head']} rustc={report['rustc']} wall={report['wall_s']:.1f}s",
    ]
    for step in report["steps"]:
        lines.append(f"  rc={step['rc']} :: {step['cmd']}")
        for tail_line in step["tail"].splitlines()[-10:]:
            lines.append(f"    | {tail_line}")
    (out_dir / "report.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def _decode_partial(x: bytes | str | None) -> str:
    """Decode a `subprocess.TimeoutExpired` partial-output attribute (its
    `.stdout` or `.stderr`).

    CPython's `subprocess.run(..., timeout=...)` re-raises the
    `TimeoutExpired` straight out of `Popen.communicate()` on POSIX without a
    second decode pass, so even when `subprocess.run` was called with
    `text=True` these attributes carry raw bytes (confirmed empirically: a
    killed process's captured-so-far output on the exception is `bytes`, not
    `str`) -- and either may be `None` if nothing had been captured yet at
    the point of the kill.
    """
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode(errors="replace")
    return x


def run_gate(vm: VmConfig, stage_name: str, boot_retries: int = 0) -> dict:
    """Runs one (vm, stage) gate, retrying the boot/ssh_wait phase (the part
    of the flow before any stage cmd has run) up to `boot_retries` times,
    each retry against a FRESH ephemeral overlay -- never a reused one, so a
    flaky boot never inherits half-booted disk state from the attempt before
    it.

    Never raises for a whole-flow failure that a caller might want to
    recover from (e.g. `cmd_ladder`, which must keep going to the next gate
    spec): the exception, if any, is returned as `result["exc"]` rather than
    propagated, so callers decide for themselves whether to re-raise
    (`cmd_gate` does, to preserve its existing CLI contract) or record it and
    move on (`cmd_ladder` does). Pre-flight validation errors (unknown stage,
    no golden image, VM already running) are the one exception to this: they
    happen before any attempt/overlay/report exists at all, so they still
    raise directly, exactly as before this function existed.

    Returns a dict: {"report": <the same dict write_report renders>,
    "report_dir": Path, "rc": 0|1, "exc": BaseException | None}.
    """
    stage = STAGES.get(stage_name)
    if stage is None:
        raise SystemExit(f"unknown stage {stage_name} (known: {', '.join(STAGES)})")
    if not stage.available:
        raise SystemExit(f"{stage_name} not available yet: {stage.note}")
    if not (state_dir(vm.name) / "golden.qcow2").exists():
        raise SystemExit(f"no golden image; run: bsdvm.py provision {vm.name}")
    if read_pid(vm.name) is not None:
        raise SystemExit(f"{vm.name} is running; bsdvm.py down {vm.name} first")

    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out_dir = state_root() / "results" / f"{ts}-{vm.name}-{stage_name}"

    attempt = 0
    final_exc: BaseException | None = None
    report: dict = {}
    ok = True
    while True:
        attempt += 1
        overlay_path = state_dir(vm.name) / f"gate-{os.getpid()}-{attempt}.qcow2"
        overlay_path.unlink(missing_ok=True)  # guarantee a genuinely fresh overlay
        overlay = create_overlay(vm.name, overlay_path.name, "golden.qcow2")
        started = time.monotonic()
        steps: list[dict] = []
        head = ""
        rustc = ""
        ok = True
        error: str | None = None
        boot_phase_failed = False
        exc_caught: BaseException | None = None
        try:
            try:
                boot(vm, overlay)
                ssh_wait(vm)
            except BaseException:
                boot_phase_failed = True
                raise
            head = push_head(vm)
            rustc = ssh_run(vm, "rustc --version", timeout_s=30).stdout.strip()
            # Plain substitution, not `str.format`: a stage command is a shell
            # line and may legitimately contain braces.
            remaining = [
                cmd.replace("{platform_feature}", vm.platform_feature)
                for cmd in stage.cmds
            ]
            while remaining:
                cmd = remaining.pop(0)
                try:
                    proc = ssh_run(vm, cmd, timeout_s=7200)
                except subprocess.TimeoutExpired as exc:
                    # The exact case the 7200s bound exists for: a hung cargo
                    # command. Record what we can (partial captured output, if
                    # any) and stop -- running further stage.cmds after one has
                    # already wedged the guest would just wait out their own
                    # timeouts for no benefit, so skip and record them instead.
                    partial = (_decode_partial(exc.stdout) + _decode_partial(exc.stderr))[-4000:]
                    steps.append(
                        {"cmd": cmd, "rc": None, "tail": "<timeout after 7200s>" + partial}
                    )
                    ok = False
                    for skipped in remaining:
                        steps.append(
                            {"cmd": skipped, "rc": None, "tail": "<skipped: prior step timed out>"}
                        )
                    break
                tail = (proc.stdout + proc.stderr)[-4000:]
                steps.append({"cmd": cmd, "rc": proc.returncode, "tail": tail})
                ok = ok and proc.returncode == 0
        except BaseException as exc:
            # Whole-flow failure: boot, ssh_wait, push_head, the rustc probe, or
            # anything else not already handled by the per-step TimeoutExpired
            # catch above (e.g. ssh_wait's SystemExit after its own deadline).
            # Remember it so the report below still gets written with the real
            # cause; whether it ultimately propagates is decided once the
            # finally clause (and any retry) has run.
            error = repr(exc)
            exc_caught = exc
        finally:
            report = {
                "vm": vm.name, "stage": stage_name, "head": head, "rustc": rustc,
                "wall_s": time.monotonic() - started,
                "report_only": stage.report_only, "steps": steps,
                "pass": ok and error is None, "error": error,
                "boot_retries_used": attempt - 1,
            }
            # Report write FIRST, before any cleanup: cleanup below can itself
            # fail (stop_pid raising SystemExit on a SIGKILL survivor) and must
            # not get a chance to prevent the report from landing.
            try:
                write_report(out_dir, report)
            except Exception as report_exc:
                # A broken report write (disk full, permissions, ...) must never
                # mask whatever the gate run itself was doing.
                print(f"warning: failed to write report: {report_exc}", file=sys.stderr)
            # Archive this attempt's serial.log into the results dir BEFORE
            # the next boot (a retry, or some unrelated later gate) overwrites
            # it -- otherwise a boot-phase failure's only evidence is silently
            # lost the moment anything reboots this VM again. Done for every
            # boot-phase failure, independent of whether boot_retries > 0.
            if boot_phase_failed:
                serial_log = state_dir(vm.name) / "serial.log"
                if serial_log.exists():
                    try:
                        shutil.copyfile(serial_log, out_dir / f"serial-attempt{attempt}.log")
                    except OSError as copy_exc:
                        print(f"warning: failed to archive serial log: {copy_exc}", file=sys.stderr)
            # Cleanup: each action gets its own guard. stop_pid can itself raise
            # SystemExit (SIGKILL survivor -- see stop_pid's docstring), and that
            # must not eclipse the root cause of why this attempt is unwinding in
            # the first place (e.g. the ssh_wait SystemExit above).
            try:
                pid = read_pid(vm.name)
                if pid is not None:
                    stop_pid(pid)
            except BaseException as cleanup_exc:
                print(f"warning: cleanup failed: {cleanup_exc}", file=sys.stderr)
            try:
                pidfile_path(vm.name).unlink(missing_ok=True)
            except BaseException as cleanup_exc:
                print(f"warning: cleanup failed: {cleanup_exc}", file=sys.stderr)
            try:
                overlay.unlink(missing_ok=True)
            except BaseException as cleanup_exc:
                print(f"warning: cleanup failed: {cleanup_exc}", file=sys.stderr)

        if exc_caught is None:
            break  # this attempt ran to completion (pass, or ok=False stage failure)
        if boot_phase_failed and attempt <= boot_retries:
            print(
                f"{vm.name}: boot/ssh_wait attempt {attempt} failed ({error}); "
                f"retrying with a fresh overlay ({attempt}/{boot_retries} retries used)"
            )
            continue
        final_exc = exc_caught
        break

    rc = 0 if (ok or stage.report_only) else 1
    if final_exc is not None:
        # A whole-flow exception (boot-retry exhaustion, ssh_wait's own
        # SystemExit, ...) is never a pass, no matter what `ok` and
        # `report_only` say -- `ok` still holds its loop-top default of True
        # when the exception fires before any stage.cmds step ran, which
        # previously produced rc=0 alongside a non-None `exc`.
        rc = 1
    return {
        "report": report,
        "report_dir": out_dir,
        "rc": rc,
        "exc": final_exc,
    }


def cmd_gate(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    outcome = run_gate(vm, args.stage, boot_retries=args.boot_retries)
    if outcome["exc"] is not None:
        # Preserve today's CLI contract exactly: cmd_gate propagates the
        # original exception, unchanged, rather than reporting a bare rc.
        raise outcome["exc"]
    return outcome["rc"]


def parse_gate_spec(spec: str) -> tuple[str, str]:
    """Parse a `vm:stage` token used by `ladder`. Pure parsing/validation, no
    I/O, so it is unit tested directly. Raises SystemExit (not ValueError)
    for any malformed spec or unknown vm/stage, matching this module's
    existing fail-fast CLI error convention.
    """
    if ":" not in spec:
        raise SystemExit(f"invalid gate spec {spec!r} (expected vm:stage)")
    vm_name, stage_name = spec.split(":", 1)
    if vm_name not in VMS:
        raise SystemExit(f"unknown vm: {vm_name} (known: {', '.join(sorted(VMS))})")
    if stage_name not in STAGES:
        raise SystemExit(f"unknown stage: {stage_name} (known: {', '.join(STAGES)})")
    return vm_name, stage_name


def cmd_ladder(args: argparse.Namespace) -> int:
    """Runs each `vm:stage` gate spec sequentially, in this one process, with
    boot-retries=1 -- the harness-tracked alternative to a human parking a
    Monitor across a multi-hour multi-gate acceptance run. Reuses run_gate
    for all orchestration (no duplicated boot/report/cleanup logic): a gate
    spec whose precondition fails (no golden image, VM already running, ...)
    or whose run_gate call raises for any other reason is recorded as a
    failed entry and the ladder continues to the next spec rather than
    aborting the whole run.
    """
    specs = [parse_gate_spec(g) for g in args.gates]  # validate all before running any
    results: list[dict] = []
    for vm_name, stage_name in specs:
        vm = VMS[vm_name]
        started = time.monotonic()
        error: str | None = None
        # Two distinct signals, kept separate rather than conflated into one
        # `pass`: `steps_ok` is the gate report's own `pass` (did every
        # stage.cmds step return 0, with no whole-flow exception?);
        # `exit_ok` is run_gate's rc (0 iff steps_ok, OR the stage is
        # report-only and never gates on step failure -- see run_gate's rc
        # hardening above for the exc-not-None case). A report-only stage
        # with failing steps is exactly `steps_ok=False, exit_ok=True`.
        steps_ok = False
        exit_ok = False
        report_dir: Path | None = None
        boot_retries_used = 0
        try:
            outcome = run_gate(vm, stage_name, boot_retries=1)
            report_dir = outcome["report_dir"]
            boot_retries_used = outcome["report"].get("boot_retries_used", 0)
            steps_ok = bool(outcome["report"].get("pass"))
            exit_ok = outcome["rc"] == 0
            if outcome["exc"] is not None:
                error = repr(outcome["exc"])
        except BaseException as exc:
            # Precondition failure (no golden, already running, ...) or any
            # other exception run_gate itself couldn't recover from -- record
            # it and keep going to the next gate spec instead of aborting the
            # whole ladder. No report/rc exists in this path, so both fields
            # stay at their False default.
            error = repr(exc)
        wall_s = time.monotonic() - started
        results.append({
            "vm": vm_name, "stage": stage_name,
            "steps_ok": steps_ok, "exit_ok": exit_ok,
            "report_dir": str(report_dir) if report_dir is not None else None,
            "wall_s": wall_s, "boot_retries_used": boot_retries_used, "error": error,
        })
        status = "PASS" if exit_ok else "FAIL"
        extra = f" error={error}" if error else ""
        print(
            f"ladder {vm_name}:{stage_name}: {status} wall={wall_s:.1f}s "
            f"boot_retries_used={boot_retries_used}{extra}"
        )

    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out = state_root() / "results" / f"ladder-{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"results": results}, indent=2) + "\n")
    print(f"ladder summary: {out}")

    return 0 if all(r["exit_ok"] for r in results) else 1


def cmd_up(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    if not (state_dir(vm.name) / "golden.qcow2").exists():
        raise SystemExit(f"no golden image; run: bsdvm.py provision {vm.name}")
    boot(vm, create_overlay(vm.name, "dev.qcow2", "golden.qcow2"))
    return 0


# How long to wait for a guest to power itself off before pulling the plug.
# Module-level so tests can shrink it, same as LOGIN_TIMEOUT_S.
POWEROFF_TIMEOUT_S = 120


def graceful_poweroff(vm: VmConfig, timeout_s: float | None = None) -> bool:
    """Ask the guest to power itself off. True if qemu exited on its own.

    `stop_pid` alone is a HARD power cut: it signals qemu, not the guest. A
    NetBSD guest does not survive that -- its root FFS comes back dirty and
    the next boot dies in fsck with `UNEXPECTED INCONSISTENCY; RUN fsck_ffs
    MANUALLY` / `ABORTING BOOT`, which is unrecoverable without hand-repair
    (MEASURED 2026-07-25: two netbsd-arm64 dev.qcow2 overlays destroyed this
    way, one of them by a single `up`/`down` cycle). So try the guest's own
    shutdown path first and only fall back to the plug.

    Best-effort by construction: a wedged or pre-ssh guest just returns False
    and the caller pulls the plug, which is no worse than before.
    """
    if timeout_s is None:
        timeout_s = POWEROFF_TIMEOUT_S
    try:
        # The connection dies underneath this as the guest goes down, so its
        # exit status is meaningless -- what matters is whether qemu exits.
        ssh_run(vm, "shutdown -p now", timeout_s=30)
    except (subprocess.TimeoutExpired, OSError):
        return False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if read_pid(vm.name) is None:
            return True
        time.sleep(1)
    return False


def cmd_down(args: argparse.Namespace) -> int:
    pid = read_pid(args.vm)
    if pid is None:
        print(f"{args.vm}: not running")
    else:
        vm = _resolve_vm(args.vm)
        if vm is not None and graceful_poweroff(vm):
            print(f"{args.vm}: powered off cleanly")
        else:
            # Either there is no ssh route to this guest or it ignored the
            # request. Pull the plug -- and say so, because on a
            # journal-less guest this is the step that can cost the overlay.
            print(f"{args.vm}: guest did not power off; pulling the plug (disk may need fsck)")
            stop_pid(pid)
            print(f"{args.vm}: stopped")
    pidfile_path(args.vm).unlink(missing_ok=True)
    return 0


PROTECTED = {"base.qcow2", "golden.qcow2", "golden.prev.qcow2"}


def cmd_destroy(args: argparse.Namespace) -> int:
    if read_pid(args.vm) is not None:
        raise SystemExit(f"{args.vm} is running; bsdvm.py down {args.vm} first")
    st = state_dir(args.vm)
    for q in sorted(st.glob("*.qcow2")):
        if q.name in PROTECTED and not args.all:
            continue
        q.unlink()
        print(f"removed {q}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="bsdvm.py", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("ps")
    ps.add_argument("vm", nargs="?")
    ps.set_defaults(func=cmd_ps)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("vm")
    fetch.add_argument("--force", action="store_true")
    fetch.set_defaults(func=cmd_fetch)
    up = sub.add_parser("up")
    up.add_argument("vm")
    up.set_defaults(func=cmd_up)
    down = sub.add_parser("down")
    down.add_argument("vm")
    down.set_defaults(func=cmd_down)
    destroy = sub.add_parser("destroy")
    destroy.add_argument("vm")
    destroy.add_argument("--all", action="store_true")
    destroy.set_defaults(func=cmd_destroy)
    provision = sub.add_parser("provision")
    provision.add_argument("vm")
    provision.add_argument("--force", action="store_true")
    provision.set_defaults(func=cmd_provision)
    refresh_golden = sub.add_parser("refresh-golden")
    refresh_golden.add_argument("vm")
    refresh_golden.set_defaults(func=cmd_refresh_golden)
    ssh_p = sub.add_parser("ssh")
    ssh_p.add_argument("vm")
    # REMAINDER so the remote command's own flags reach the guest instead of
    # being parsed here (e.g. `bsdvm ssh netbsd-arm64 cargo build -p foo`).
    ssh_p.add_argument("command", nargs=argparse.REMAINDER)
    ssh_p.set_defaults(func=cmd_ssh)
    gate = sub.add_parser("gate")
    gate.add_argument("vm")
    gate.add_argument("stage")
    gate.add_argument("--boot-retries", type=int, default=0)
    gate.set_defaults(func=cmd_gate)
    ladder = sub.add_parser("ladder")
    ladder.add_argument("gates", nargs="+", metavar="vm:stage")
    ladder.set_defaults(func=cmd_ladder)
    args = parser.parse_args(argv)
    if getattr(args, "vm", None) is not None and _resolve_vm(args.vm) is None:
        print(f"unknown vm: {args.vm} (known: {', '.join(sorted(VMS))})", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
