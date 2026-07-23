# aarch64 BSD VM Test Lanes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Local QEMU/HVF FreeBSD-15.1 and NetBSD-10.1 aarch64 VMs on this Mac with one golden-image provisioning path serving both interactive dev-box use and a scripted gate ladder, stage0 green on both.

**Architecture:** A single stdlib-only Python driver `scripts/bsdvm.py` (repo script convention) with subcommands `fetch/provision/up/down/destroy/ps/gate/refresh-golden`, a qcow2 golden-image lifecycle under `~/.carrick/bsdvm/<vm>/`, a serial-expect provisioning engine (cloud-init seed for FreeBSD only if the BASIC-CLOUDINIT image is published), and per-stage gate execution over ssh with push-to-checkout git remotes.

**Tech Stack:** Python 3 stdlib only (urllib, hashlib, lzma, gzip, socket, subprocess, unittest), qemu-system-aarch64 + qemu-img (Homebrew), edk2 firmware shipped with brew qemu, ssh/git.

**Spec:** `docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md`

## Global Constraints

- Python: stdlib only, no pip deps; scripts follow the `scripts/native-x86-ltp-gate.py` + `scripts/test_native_x86_ltp_gate.py` conventions (`unittest`, tests runnable via `python3 scripts/test_bsdvm.py`).
- VM state root: `~/.carrick/bsdvm` overridable via `CARRICK_BSDVM_STATE`. Never store images in the repo.
- Inventory (exact values): `freebsd-arm64` ssh `127.0.0.1:2201` remote `fbsd-arm`; `netbsd-arm64` ssh `127.0.0.1:2202` remote `nbsd-arm`.
- QEMU: `-M virt,gic-version=3 -accel hvf -cpu host -smp 4 -m 6144`, virtio-blk/net/rng, `virtio-rng-pci` MANDATORY (NetBSD entropy), chardev serial socket with `logfile=`, `-display none -daemonize -pidfile`.
- `down` = TERM → wait ≤10 s → KILL. `destroy` never removes `base.qcow2`/`golden.qcow2` without `--all`.
- Gates: one VM at a time (no parallel flag in v1 — YAGNI), 300 s ssh-wait backstop, trap/finally cleanup so failures never leak a qemu, report-only stages exit 0.
- NetBSD remote PATH gotcha: non-login ssh lacks `/usr/pkg/bin` — every NetBSD remote command must be prefixed `PATH=/usr/pkg/bin:/usr/pkg/sbin:$PATH`.
- Commit at the end of every task (logical commits along the way — maintainer requirement). NEVER `git commit --no-verify`.

## File Structure

- `scripts/bsdvm.py` — the whole driver (single file, repo convention). Sections in order: VM config table → state paths → qemu argv → fetch → overlay/lifecycle → serial expect → provisioning data → ssh/git helpers → gate → CLI dispatch.
- `scripts/test_bsdvm.py` — unit tests, pure logic only (no VM boots, no network).
- `justfile` — `bsdvm-*` recipes appended at the end.

---

### Task 1: Driver skeleton — config table, state paths, CLI dispatch, `ps`

**Files:**
- Create: `scripts/bsdvm.py`
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Produces: `VMS: dict[str, VmConfig]`; `VmConfig` dataclass with fields `name:str, ssh_port:int, remote:str, image_candidates:list[str], checksum_url:str, image_format:str, remote_path_prefix:str`; `state_dir(vm_name:str)->Path`; `state_root()->Path`; `main(argv)->int`; `cmd_ps(args)->int`.

- [ ] **Step 1: Write the failing test**

```python
#!/usr/bin/env python3

import importlib.util
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py`
Expected: FAIL (`FileNotFoundError` loading `bsdvm.py` — create an empty file first if importlib errors confuse, then AttributeError on `VMS`).

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""bsdvm: QEMU/HVF FreeBSD+NetBSD aarch64 test VMs on the Mac.

Spec: docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md
Subcommands: fetch provision up down destroy ps gate refresh-golden
"""

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import sys


@dataclass(frozen=True)
class VmConfig:
    name: str
    ssh_port: int
    remote: str
    image_candidates: list[str]
    checksum_url: str
    image_format: str  # "qcow2.xz" | "img.gz"
    remote_path_prefix: str = ""


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
    ),
}


def state_root() -> Path:
    return Path(os.environ.get("CARRICK_BSDVM_STATE", Path.home() / ".carrick" / "bsdvm"))


def state_dir(vm_name: str) -> Path:
    return state_root() / vm_name


def _resolve_vm(name: str) -> VmConfig | None:
    return VMS.get(name)


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
    args = parser.parse_args(argv)
    if getattr(args, "vm", None) is not None and _resolve_vm(args.vm) is None:
        print(f"unknown vm: {args.vm} (known: {', '.join(sorted(VMS))})", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

`chmod +x scripts/bsdvm.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test_bsdvm.py`
Expected: `OK` (4 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): driver skeleton with VM inventory and ps"
```

---

### Task 2: QEMU argv assembly + firmware/efivars resolution

**Files:**
- Modify: `scripts/bsdvm.py` (append after `state_dir`)
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Consumes: `VmConfig`, `state_dir`.
- Produces: `firmware_paths()->tuple[Path,Path]` (code, vars-template; env override `CARRICK_BSDVM_FW_DIR`); `ensure_efivars(vm_name)->Path`; `qemu_args(vm:VmConfig, overlay:Path, extra_drives:list[str]|None=None)->list[str]`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py`
Expected: FAIL `AttributeError: ... 'qemu_args'`.

- [ ] **Step 3: Write minimal implementation**

```python
import shutil
import subprocess


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test_bsdvm.py`
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): qemu argv assembly with firmware/efivars handling"
```

---

### Task 3: `fetch` — download, checksum, decompress, convert/resize

**Files:**
- Modify: `scripts/bsdvm.py`
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Consumes: `VmConfig`, `state_dir`.
- Produces: `parse_checksum(text:str, filename:str)->str` (hex or raises `KeyError`); `pick_candidate(candidates:list[str], probe)->str` (`probe: Callable[[str],bool]`, returns first URL where probe is True, raises `SystemExit` if none); `cmd_fetch(args)->int` producing `<state>/base.qcow2` + `<state>/manifest.json` (`{"image_url":..., "cloudinit": bool}`); `url_exists(url:str)->bool` (HEAD request).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py`
Expected: FAIL `AttributeError: ... 'parse_checksum'`.

- [ ] **Step 3: Write minimal implementation**

```python
import gzip
import hashlib
import json
import lzma
import re
import urllib.request


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


def cmd_fetch(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    st = state_dir(vm.name)
    base = st / "base.qcow2"
    if base.exists() and not getattr(args, "force", False):
        print(f"{base} exists; skipping (use --force to refetch)")
        return 0
    st.mkdir(parents=True, exist_ok=True)
    url = pick_candidate(vm.image_candidates, probe=url_exists)
    fname = url.rsplit("/", 1)[1]
    compressed = st / fname
    print(f"fetching {url}")
    _download(url, compressed)
    with urllib.request.urlopen(vm.checksum_url, timeout=60) as resp:
        want = parse_checksum(resp.read().decode(), fname)
    got = _sha512_file(compressed)
    if got != want:
        compressed.unlink()
        raise SystemExit(f"checksum mismatch for {fname}: got {got[:16]}… want {want[:16]}…")
    raw = st / "image.raw"
    _decompress(compressed, raw)
    if vm.image_format == "qcow2.xz":
        raw.rename(st / "image.qcow2")
        subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2", str(st / "image.qcow2"), str(base)],
            check=True,
        )
        (st / "image.qcow2").unlink()
    else:  # img.gz: raw disk image
        subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(base)],
            check=True,
        )
        raw.unlink()
    subprocess.run(["qemu-img", "resize", str(base), "+20G"], check=True)
    compressed.unlink()
    (st / "manifest.json").write_text(
        json.dumps({"image_url": url, "cloudinit": "CLOUDINIT" in url}) + "\n"
    )
    print(f"wrote {base}")
    return 0
```

Wire into `main`: add subparser `fetch` with `vm` positional + `--force`, `set_defaults(func=cmd_fetch)`.

- [ ] **Step 4: Run unit tests**

Run: `python3 scripts/test_bsdvm.py` — Expected: `OK`.

- [ ] **Step 5: Probe the real URLs and correct candidates if needed**

Run (network, no downloads):
```bash
python3 - <<'EOF'
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("bsdvm", Path("scripts/bsdvm.py"))
m = importlib.util.module_from_spec(spec); sys.modules["bsdvm"]=m; spec.loader.exec_module(m)
for vm in m.VMS.values():
    for u in vm.image_candidates + [vm.checksum_url]:
        print(m.url_exists(u), u)
EOF
```
Expected: at least one `True` image candidate per VM and `True` for both checksum URLs. If FreeBSD 15.1-RELEASE aarch64 is not yet published, the RC candidate must be `True`; if the actual published filenames differ (e.g. no BASIC-CLOUDINIT aarch64 build), EDIT the `image_candidates`/`checksum_url` constants to the real URLs found by browsing `https://download.freebsd.org/releases/VM-IMAGES/` and `https://cdn.netbsd.org/pub/NetBSD/NetBSD-10.1/evbarm-aarch64/binary/gzimg/`, and update the Task 1 test if a port/name did not change (inventory values must NOT change).

- [ ] **Step 6: Real fetch, both VMs**

Run: `python3 scripts/bsdvm.py fetch freebsd-arm64 && python3 scripts/bsdvm.py fetch netbsd-arm64`
Expected: `wrote …/base.qcow2` twice; `qemu-img info ~/.carrick/bsdvm/freebsd-arm64/base.qcow2` shows qcow2 with ≥20 G virtual size.

- [ ] **Step 7: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): image fetch with checksum verify and qcow2 conversion"
```

---

### Task 4: Overlay chain + `up`/`down`/`destroy` lifecycle

**Files:**
- Modify: `scripts/bsdvm.py`
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Consumes: `qemu_args`, `state_dir`.
- Produces: `create_overlay(vm_name:str, name:str, backing:str)->Path` (qemu-img create -F qcow2 -b); `boot(vm:VmConfig, overlay:Path, extra_drives=None)->None` (runs qemu, raises on rc≠0); `read_pid(vm_name)->int|None`; `cmd_up(args)`, `cmd_down(args)` (TERM→wait≤10s→KILL, removes pidfile), `cmd_destroy(args)` (`--all` gate for base/golden). `stop_pid(pid:int, term_wait_s:float=10.0, kill=os.kill, sleep=time.sleep)->None` is a pure-injectable helper.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py`
Expected: FAIL `AttributeError: ... 'stop_pid'`.

- [ ] **Step 3: Write minimal implementation**

```python
import time


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


def read_pid(vm_name: str) -> int | None:
    pidfile = state_dir(vm_name) / "qemu.pid"
    if not pidfile.exists():
        return None
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError):
        return None


def boot(vm: VmConfig, overlay: Path, extra_drives: list[str] | None = None) -> None:
    if read_pid(vm.name) is not None:
        raise SystemExit(f"{vm.name} already running (bsdvm.py down {vm.name} first)")
    subprocess.run(qemu_args(vm, overlay, extra_drives or []), check=True)
    print(f"{vm.name}: booted {overlay.name} (ssh -p {vm.ssh_port} root@127.0.0.1)")


def stop_pid(pid: int, term_wait_s: float = 10.0, kill=os.kill, sleep=time.sleep) -> None:
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
        while True:
            kill(pid, 0)
            sleep(0.1)
    except ProcessLookupError:
        return


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
    pidfile = state_dir(args.vm) / "qemu.pid"
    pidfile.unlink(missing_ok=True)
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
```

Wire subparsers: `up <vm>`, `down <vm>`, `destroy <vm> [--all]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test_bsdvm.py` — Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): overlay chain and up/down/destroy lifecycle"
```

---

### Task 5: Serial-expect engine + provisioning step data

**Files:**
- Modify: `scripts/bsdvm.py`
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Consumes: nothing new (pure).
- Produces: `SerialConsole(sock_path:Path)` with `.expect(pattern:bytes, timeout_s:float)->bytes` (raises `TimeoutError` naming the serial log) and `.sendline(s:str)`; `provision_commands(vm:VmConfig, pubkey:str)->list[tuple[str,float]]` (command, timeout_s) per-OS lists; `read_pubkey()->str` (env `CARRICK_BSDVM_PUBKEY` path override, else first of `~/.ssh/id_ed25519.pub`, `~/.ssh/id_rsa.pub`); `write_cloudinit_seed(vm_name:str, pubkey:str)->Path` (seed.iso via `hdiutil makehybrid`, NoCloud user-data/meta-data).

- [ ] **Step 1: Write the failing test**

```python
import socket
import threading


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
            t.start()
            con = BSDVM.SerialConsole(sock_path)
            pre = con.expect(b"login: ", timeout_s=5)
            self.assertIn(b"NetBSD", pre)
            con.sendline("root")
            con.expect(b"# ", timeout_s=5)
            t.join(timeout=5)
            self.assertEqual(got[0], b"root\n")

    def test_expect_timeout_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "serial.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            srv.listen(1)
            threading.Thread(target=lambda: srv.accept()).start()
            con = BSDVM.SerialConsole(sock_path)
            with self.assertRaises(TimeoutError):
                con.expect(b"never", timeout_s=0.2)


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py`
Expected: FAIL `AttributeError: ... 'SerialConsole'`.

- [ ] **Step 3: Write minimal implementation**

```python
import socket


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


_GIT_SETUP = (
    "git init /root/carrick && "
    "git -C /root/carrick config receive.denyCurrentBranch updateInstead"
)


def provision_commands(vm: VmConfig, pubkey: str) -> list[tuple[str, float]]:
    key_cmd = (
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
        f"echo '{pubkey}' >> /root/.ssh/authorized_keys && "
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
    st = state_dir(vm_name)
    seed_dir = st / "seed"
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "meta-data").write_text(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")
    (seed_dir / "user-data").write_text(
        "#cloud-config\n"
        "disable_root: false\n"
        "ssh_authorized_keys:\n"
        f"  - {pubkey}\n"
        "runcmd:\n"
        "  - sysrc sshd_enable=YES\n"
        "  - printf 'PermitRootLogin prohibit-password\\n' >> /etc/ssh/sshd_config\n"
        "  - service sshd restart\n"
        "  - env ASSUME_ALWAYS_YES=yes pkg bootstrap -f\n"
        "  - env ASSUME_ALWAYS_YES=yes pkg install -y git just rust python3\n"
        f"  - {_GIT_SETUP}\n"
        "  - shutdown -p now\n"
    )
    iso = st / "seed.iso"
    iso.unlink(missing_ok=True)
    subprocess.run(
        ["hdiutil", "makehybrid", "-iso", "-joliet",
         "-default-volume-name", "cidata", "-o", str(iso), str(seed_dir)],
        check=True,
    )
    return iso
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test_bsdvm.py` — Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): serial-expect engine and per-OS provisioning data"
```

---

### Task 6: `provision` command — real boots, golden images for both VMs

**Files:**
- Modify: `scripts/bsdvm.py`

**Interfaces:**
- Consumes: `boot`, `create_overlay`, `SerialConsole`, `provision_commands`, `write_cloudinit_seed`, `read_pid`, `stop_pid`, manifest from Task 3.
- Produces: `cmd_provision(args)->int` → `<state>/golden.qcow2`; `cmd_refresh_golden(args)->int` (rotate `golden.qcow2`→`golden.prev.qcow2`, rerun pkg-update commands on a fresh overlay); `wait_for_shutdown(vm_name:str, timeout_s:float)->None`.

- [ ] **Step 1: Implement `cmd_provision`**

```python
PROMPT = b"# "


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
    con.expect(b"login: ", timeout_s=600)  # first boot: fsck/resize can be slow
    con.sendline("root")
    con.expect(PROMPT, timeout_s=120)
    for cmd, timeout_s in provision_commands(vm, pubkey):
        print(f"[provision {vm.name}] {cmd[:70]}…" if len(cmd) > 70 else f"[provision {vm.name}] {cmd}")
        con.sendline(cmd)
        if cmd.startswith("shutdown"):
            break
        con.expect(PROMPT, timeout_s=timeout_s)


def cmd_provision(args: argparse.Namespace) -> int:
    vm = VMS[args.vm]
    st = state_dir(vm.name)
    if not (st / "base.qcow2").exists():
        raise SystemExit(f"no base image; run: bsdvm.py fetch {vm.name}")
    golden = st / "golden.qcow2"
    if golden.exists() and not args.force:
        raise SystemExit(f"{golden} exists (use --force to reprovision)")
    golden.unlink(missing_ok=True)
    # A failed earlier run may have left a partially-provisioned overlay: start fresh.
    (st / "provision.qcow2").unlink(missing_ok=True)
    work = create_overlay(vm.name, "provision.qcow2", "base.qcow2")
    pubkey = read_pubkey()
    manifest = json.loads((st / "manifest.json").read_text())
    extra = []
    if manifest.get("cloudinit"):
        extra = [f"if=virtio,format=raw,readonly=on,file={write_cloudinit_seed(vm.name, pubkey)}"]
    try:
        boot(vm, work, extra_drives=extra)
        if manifest.get("cloudinit"):
            print(f"[provision {vm.name}] cloud-init driving first boot; waiting for self-shutdown")
        else:
            _run_serial_provision(vm, pubkey)
        wait_for_shutdown(vm.name, timeout_s=4200)
    except BaseException:
        pid = read_pid(vm.name)
        if pid is not None:
            stop_pid(pid)
        raise
    work.rename(golden)
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
    print(f"golden refreshed (previous kept at {prev})")
    return 0
```

Wire subparsers: `provision <vm> [--force]`, `refresh-golden <vm>`.

- [ ] **Step 2: Unit tests still green**

Run: `python3 scripts/test_bsdvm.py` — Expected: `OK`.

- [ ] **Step 3: Provision FreeBSD for real**

Run: `python3 scripts/bsdvm.py provision freebsd-arm64`
Expected: boot + provisioning output, `golden image ready: …/freebsd-arm64/golden.qcow2` (pkg install of rust takes tens of minutes). On failure the error names `serial.log` — read `~/.carrick/bsdvm/freebsd-arm64/serial.log` to triage (login prompt string mismatches are fixed by adjusting the expect patterns in `_run_serial_provision`/`provision_commands`, e.g. FreeBSD may present `login:` without trailing space; adjust to `b"login:"` if so).

- [ ] **Step 4: Provision NetBSD for real**

Run: `python3 scripts/bsdvm.py provision netbsd-arm64`
Expected: same shape. Known NetBSD gzimg first-boot behaviors: root-fs auto-resize then reboot once before `login:` (the 600 s expect covers it); if the image boots to `#` directly (no login), the `login:` expect times out — handle by trying `expect(b"login: ")` and on TimeoutError falling back to sending a bare newline and expecting `PROMPT`. If `pkg_add rust` reports an unsatisfiable version, record the pkgsrc rustc version — the spec's risk item — and continue; stage0 will confirm whether it builds the four host crates.

- [ ] **Step 5: Verify ssh keys work on both**

Run: `ssh -p 2201 root@127.0.0.1 uname -a` after `python3 scripts/bsdvm.py up freebsd-arm64`, then `python3 scripts/bsdvm.py down freebsd-arm64`; same with 2202/netbsd.
Expected: `FreeBSD … arm64` and `NetBSD … evbarm aarch64`.

- [ ] **Step 6: Commit**

```bash
git add scripts/bsdvm.py
git commit -m "feat(bsdvm): provision command producing golden images"
```

---

### Task 7: ssh helpers, ssh-wait, git remotes + push-to-checkout

**Files:**
- Modify: `scripts/bsdvm.py`
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Consumes: `VmConfig`, `state_dir`.
- Produces: `ssh_base(vm:VmConfig)->list[str]` (port, `UserKnownHostsFile=<state>/known_hosts`, `StrictHostKeyChecking=accept-new`, `ConnectTimeout=5`); `ssh_run(vm, cmd:str, timeout_s:float)->subprocess.CompletedProcess` (applies `vm.remote_path_prefix`); `ssh_wait(vm, timeout_s:float=300)->None`; `git_url(vm)->str` = `ssh://root@127.0.0.1:<port>/root/carrick`; `git_ssh_env(vm)->dict` (GIT_SSH_COMMAND matching ssh_base); `push_head(vm)->str` (returns pushed sha; pushes `HEAD:refs/heads/main` then remote `git -C /root/carrick reset --hard` is NOT needed — updateInstead handles the worktree); `ensure_dev_remote(vm)->None` (idempotent `git remote add`).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py` — Expected: FAIL `AttributeError: ... 'ssh_base'`.

- [ ] **Step 3: Write minimal implementation**

```python
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
    opts = " ".join(base[3:-1])  # the three -o pairs
    env = dict(os.environ)
    env["GIT_SSH_COMMAND"] = f"ssh {opts}"
    return env


def push_head(vm: VmConfig) -> str:
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    subprocess.run(
        ["git", "push", "--force", git_url(vm), "HEAD:refs/heads/main"],
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
```

Call `ensure_dev_remote(vm)` at the end of `cmd_provision` (after golden rename).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test_bsdvm.py` — Expected: `OK`.

- [ ] **Step 5: Integration: push to the FreeBSD box**

Run:
```bash
python3 scripts/bsdvm.py up freebsd-arm64
python3 - <<'EOF'
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("bsdvm", Path("scripts/bsdvm.py"))
m = importlib.util.module_from_spec(spec); sys.modules["bsdvm"]=m; spec.loader.exec_module(m)
vm = m.VMS["freebsd-arm64"]
m.ssh_wait(vm)
print("pushed", m.push_head(vm))
print(m.ssh_run(vm, "git -C /root/carrick log --oneline -1", 30).stdout)
EOF
python3 scripts/bsdvm.py down freebsd-arm64
```
Expected: pushed sha printed, remote `log --oneline -1` shows the same commit subject.

- [ ] **Step 6: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): ssh helpers and push-to-checkout git remotes"
```

---

### Task 8: `gate` — stage table, ephemeral run, report, cleanup

**Files:**
- Modify: `scripts/bsdvm.py`
- Test: `scripts/test_bsdvm.py`

**Interfaces:**
- Consumes: everything prior.
- Produces: `STAGES: dict[str, Stage]` (`Stage(cmds:list[str], report_only:bool, available:bool, note:str)`); `cmd_gate(args)->int`; `write_report(dir:Path, report:dict)->None` (report.json + report.txt); results under `<state-root>/results/<UTC ts>-<vm>-<stage>/`.

- [ ] **Step 1: Write the failing test**

```python
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
        self.assertFalse(BSDVM.STAGES["stage2"].available)
        self.assertIn("NativeLane", BSDVM.STAGES["stage2"].note)
        self.assertFalse(BSDVM.STAGES["stage3"].available)

    def test_unavailable_stage_is_a_clear_error(self) -> None:
        ns = mock.Mock(vm="freebsd-arm64", stage="stage2")
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
```

Add `import json` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test_bsdvm.py` — Expected: FAIL `AttributeError: ... 'STAGES'`.

- [ ] **Step 3: Write minimal implementation**

```python
@dataclass(frozen=True)
class Stage:
    cmds: list[str]
    report_only: bool
    available: bool
    note: str = ""


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
    try:
        boot(vm, overlay)
        ssh_wait(vm)
        head = push_head(vm)
        rustc = ssh_run(vm, "rustc --version", timeout_s=30).stdout.strip()
        ok = True
        for cmd in stage.cmds:
            proc = ssh_run(vm, cmd, timeout_s=7200)
            tail = (proc.stdout + proc.stderr)[-4000:]
            steps.append({"cmd": cmd, "rc": proc.returncode, "tail": tail})
            ok = ok and proc.returncode == 0
        report = {
            "vm": vm.name, "stage": args.stage, "head": head, "rustc": rustc,
            "wall_s": time.monotonic() - started,
            "report_only": stage.report_only, "steps": steps, "pass": ok,
        }
        write_report(out_dir, report)
        return 0 if (ok or stage.report_only) else 1
    finally:
        pid = read_pid(vm.name)
        if pid is not None:
            stop_pid(pid)
        (state_dir(vm.name) / "qemu.pid").unlink(missing_ok=True)
        overlay.unlink(missing_ok=True)
```

Wire subparser: `gate <vm> <stage>`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test_bsdvm.py` — Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add scripts/bsdvm.py scripts/test_bsdvm.py
git commit -m "feat(bsdvm): gate command with stage ladder, reports, cleanup"
```

---

### Task 9: just recipes

**Files:**
- Modify: `justfile` (append at end)

**Interfaces:**
- Consumes: `scripts/bsdvm.py` CLI.
- Produces: recipes `bsdvm-fetch`, `bsdvm-provision`, `bsdvm-up`, `bsdvm-down`, `bsdvm-ps`, `bsdvm-gate`.

- [ ] **Step 1: Append recipes**

```make
# aarch64 BSD test VMs on this Mac (spec: docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md)
bsdvm-fetch VM:
    python3 scripts/bsdvm.py fetch {{VM}}

bsdvm-provision VM *ARGS:
    python3 scripts/bsdvm.py provision {{VM}} {{ARGS}}

bsdvm-up VM:
    python3 scripts/bsdvm.py up {{VM}}

bsdvm-down VM:
    python3 scripts/bsdvm.py down {{VM}}

bsdvm-ps:
    python3 scripts/bsdvm.py ps

bsdvm-gate VM STAGE="stage0":
    python3 scripts/bsdvm.py gate {{VM}} {{STAGE}}
```

(Match the file's existing indentation style — check whether recipes use tabs or 4 spaces and copy it.)

- [ ] **Step 2: Verify recipes parse**

Run: `just --list | grep bsdvm`
Expected: the six recipes listed.

- [ ] **Step 3: Commit**

```bash
git add justfile
git commit -m "chore(just): bsdvm recipes"
```

---

### Task 10: Acceptance — stage0 green on both VMs

**Files:** none (runs only).

- [ ] **Step 1: FreeBSD stage0**

Run: `just bsdvm-gate freebsd-arm64 stage0`
Expected: `bsdvm gate stage0 on freebsd-arm64: PASS`, exit 0, report under `~/.carrick/bsdvm/results/`. If cargo fails on missing system deps (e.g. linker), fix via a `refresh-golden` provisioning command addition and re-run — record what was added.

- [ ] **Step 2: NetBSD stage0**

Run: `just bsdvm-gate netbsd-arm64 stage0`
Expected: PASS. If pkgsrc rustc is too old to build the four host crates (spec risk), record the failing crate + rustc version in the report, and STOP for maintainer decision (options per spec: pkgsrc-current or build-once-into-golden).

- [ ] **Step 3: Stage1 report-only snapshot (both VMs)**

Run: `just bsdvm-gate freebsd-arm64 stage1 && just bsdvm-gate netbsd-arm64 stage1`
Expected: exit 0 regardless of build result (report-only); the report.txt red list is the aarch64×BSD bring-up worklist — attach both report paths to the completion summary.

- [ ] **Step 4: Leak check**

Run: `python3 scripts/bsdvm.py ps; pgrep -fl qemu-system-aarch64 || echo "no stray qemu"`
Expected: both VMs `down`, no stray qemu.

- [ ] **Step 5: Final commit (if any fixups landed during acceptance)**

```bash
git add -A scripts/bsdvm.py scripts/test_bsdvm.py justfile
git commit -m "fix(bsdvm): acceptance-run fixups" # only if there are changes
```
