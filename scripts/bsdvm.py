#!/usr/bin/env python3
"""bsdvm: QEMU/HVF FreeBSD+NetBSD aarch64 test VMs on the Mac.

Spec: docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md
Subcommands: fetch provision up down destroy ps gate refresh-golden
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
    remote_path_prefix: str = ""
    pinned_sha512: str | None = None


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
        image_candidates=[
            # Preferred: cloud-init capable image (provision goes NoCloud).
            f"{_FB_BASE}/FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
            f"{_FB_BASE}/FreeBSD-15.1-RELEASE-arm64-aarch64-ufs.qcow2.xz",
            # RC fallback, matching the x86 fleet's major (spec: fixed decision).
            f"{_FB_RC_BASE}/FreeBSD-15.1-RC3-arm64-aarch64-ufs.qcow2.xz",
        ],
        checksum_url=f"{_FB_BASE}/CHECKSUM.SHA512",
        image_format="qcow2.xz",
    ),
    "netbsd-arm64": VmConfig(
        name="netbsd-arm64",
        ssh_port=2202,
        remote="nbsd-arm",
        image_candidates=[f"{_NB_BASE}/arm64.img.gz"],
        checksum_url=f"{_NB_BASE}/SHA512",
        image_format="img.gz",
        # Non-login ssh on NetBSD lacks /usr/pkg/bin (fleet-wide gotcha).
        remote_path_prefix="PATH=/usr/pkg/bin:/usr/pkg/sbin:$PATH ",
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
        cmds=["cd /root/carrick && cargo build --workspace"],
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
        "-drive", f"if=virtio,format=qcow2,file={overlay}",
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
            ("env ASSUME_ALWAYS_YES=yes pkg install -y git just rust python3", 3600),
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
        ("export PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/10.0_2026Q1/All; "
         "/usr/sbin/pkg_add -U git rust || /usr/sbin/pkg_add -U git rust", 3600),
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
    for cmd, timeout_s in provision_commands(vm, pubkey):
        print(f"[provision {vm.name}] {cmd[:70]}…" if len(cmd) > 70 else f"[provision {vm.name}] {cmd}")
        con.sendline(cmd)
        if cmd.startswith("shutdown"):
            break
        con.expect(PROMPT, timeout_s=timeout_s)


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
    candidates = [st / "dev.qcow2"] + sorted(st.glob("gate-*.qcow2"))
    for overlay in candidates:
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
    prev = st / "golden.prev.qcow2"
    if golden.exists():
        prev.unlink(missing_ok=True)
        golden.rename(prev)
    work.rename(golden)
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
    prev.unlink(missing_ok=True)
    # Flatten first so the new golden does not chain onto the rotated file.
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(golden), str(st / "golden.flat.qcow2")], check=True)
    golden.rename(prev)
    (st / "golden.flat.qcow2").rename(golden)
    # Reprovision on top of the flattened golden as the new base for update cmds.
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
    golden.unlink()
    work.rename(golden)
    # The just-flattened/reprovisioned golden.qcow2 has entirely different
    # content at the same path than what any pre-existing dev.qcow2/gate-*.qcow2
    # was created against -- see _invalidate_consumer_overlays.
    _invalidate_consumer_overlays(vm.name)
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
        ssh_base(vm) + [vm.remote_path_prefix + cmd],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


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
        # Empty guest repo, no HEAD yet (see parse_symref_head's docstring):
        # this push is the one that establishes the branch. Guests are
        # provisioned via `git init -b main` (_GIT_SETUP), so "main" is what
        # the guest's checked-out branch will actually be once this push
        # creates its first commit.
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


def cmd_gate(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    stage = STAGES.get(args.stage)
    if stage is None:
        raise SystemExit(f"unknown stage {args.stage} (known: {', '.join(STAGES)})")
    if not stage.available:
        raise SystemExit(f"{args.stage} not available yet: {stage.note}")
    if not (state_dir(vm.name) / "golden.qcow2").exists():
        raise SystemExit(f"no golden image; run: bsdvm.py provision {vm.name}")
    if read_pid(vm.name) is not None:
        raise SystemExit(f"{vm.name} is running; bsdvm.py down {vm.name} first")
    overlay = create_overlay(vm.name, f"gate-{os.getpid()}.qcow2", "golden.qcow2")
    started = time.monotonic()
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out_dir = state_root() / "results" / f"{ts}-{vm.name}-{args.stage}"
    steps: list[dict] = []
    head = ""
    rustc = ""
    ok = True
    error: str | None = None
    try:
        boot(vm, overlay)
        ssh_wait(vm)
        head = push_head(vm)
        rustc = ssh_run(vm, "rustc --version", timeout_s=30).stdout.strip()
        remaining = list(stage.cmds)
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
        # cause, then re-raise once the finally clause has run -- callers and
        # the exit code still see the original failure, unmasked.
        error = repr(exc)
        raise
    finally:
        report = {
            "vm": vm.name, "stage": args.stage, "head": head, "rustc": rustc,
            "wall_s": time.monotonic() - started,
            "report_only": stage.report_only, "steps": steps,
            "pass": ok and error is None, "error": error,
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
        # Cleanup: each action gets its own guard. stop_pid can itself raise
        # SystemExit (SIGKILL survivor -- see stop_pid's docstring), and that
        # must not eclipse the root cause of why cmd_gate is unwinding in the
        # first place (e.g. the ssh_wait SystemExit above).
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
    return 0 if (ok or stage.report_only) else 1


def cmd_up(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    if not (state_dir(vm.name) / "golden.qcow2").exists():
        raise SystemExit(f"no golden image; run: bsdvm.py provision {vm.name}")
    boot(vm, create_overlay(vm.name, "dev.qcow2", "golden.qcow2"))
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    pid = read_pid(args.vm)
    if pid is None:
        print(f"{args.vm}: not running")
    else:
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
    gate = sub.add_parser("gate")
    gate.add_argument("vm")
    gate.add_argument("stage")
    gate.set_defaults(func=cmd_gate)
    args = parser.parse_args(argv)
    if getattr(args, "vm", None) is not None and _resolve_vm(args.vm) is None:
        print(f"unknown vm: {args.vm} (known: {', '.join(sorted(VMS))})", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
