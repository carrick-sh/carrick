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
                if chunk:
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
    "git init /root/carrick && "
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
            (_GIT_SETUP, 30),
            ("shutdown -p now", 120),
        ]
    return [  # netbsd-arm64
        (key_cmd, 30),
        ("printf 'sshd=YES\\ndhcpcd=YES\\n' >> /etc/rc.conf && "
         "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config && "
         "/etc/rc.d/sshd start", 300),
        ("export PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/10.1/All; "
         "/usr/sbin/pkg_add -U git rust || /usr/sbin/pkg_add -U git rust", 3600),
        # `just` may be absent from pkgsrc aarch64; gates call cargo directly.
        ("export PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/10.1/All; "
         "/usr/sbin/pkg_add -U just || echo 'just unavailable (ok)'", 600),
        (f"PATH=/usr/pkg/bin:$PATH {_GIT_SETUP}", 30),
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
    args = parser.parse_args(argv)
    if getattr(args, "vm", None) is not None and _resolve_vm(args.vm) is None:
        print(f"unknown vm: {args.vm} (known: {', '.join(sorted(VMS))})", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
