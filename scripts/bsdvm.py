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
import subprocess
import sys
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
        pidfile = state_dir(name) / "qemu.pid"
        status = "down"
        if pidfile.exists():
            pid = int(pidfile.read_text().strip())
            try:
                os.kill(pid, 0)
                status = f"up pid={pid}"
            except ProcessLookupError:
                status = f"orphan-pidfile pid={pid}"
        print(f"{name}\t{status}")
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
    args = parser.parse_args(argv)
    if getattr(args, "vm", None) is not None and _resolve_vm(args.vm) is None:
        print(f"unknown vm: {args.vm} (known: {', '.join(sorted(VMS))})", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
