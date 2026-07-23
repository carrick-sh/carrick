# aarch64 BSD VM test lanes on the Mac (FreeBSD + NetBSD) design

**Date:** 2026-07-22

**Status:** approved

**Scope:** Local QEMU/HVF virtual machines on the Apple Silicon development
Mac providing FreeBSD/aarch64 and NetBSD/aarch64 hosts for the native (DSR)
backend, with one provisioning path serving both interactive dev-box use and
scripted conformance gates from day one.

## Purpose

The native backend is being promoted to primary stable backend; the VMM path
is abandoned for now (maintainer ruling 2026-07-22) though it remains in-tree.
The forward host matrix for the native lane is (guest ISA == host ISA):

| | Darwin | FreeBSD | NetBSD |
|---|---|---|---|
| aarch64 | live (reference lane) | **this design (test host)** | **this design (test host)** |
| x86_64 | — | live (fbsd box, 10.14.14.189) | planned (after stable state) |

The existing fleet covers only x86_64 BSD hosts (willow VMs 200/201). Nothing
exercises `carrick-dsr-aarch64` on a non-Darwin host. Two properties make the
aarch64×BSD lanes valuable beyond raw coverage:

- **4K pages.** FreeBSD/NetBSD arm64 are 4K-page hosts vs Darwin's 16K. These
  lanes run the aarch64 DSR translator in a 4K world for the first time —
  closer to the Linux guest ABI, and they separate "aarch64 behavior" from
  "Darwin 16K artifact" in the native lane.
- **Seam forcing function.** Each new (host, ISA) pair must arrive as a
  `NativeLane` host-glue implementation, not another per-lane monolith (see
  `2026-07-17-native-backend-portability-seams-design.md` and the 2026-07-22
  range review). These VMs are where that acceptance test runs.

A consequence of native-as-primary: carrick runs no longer consume HVF, so
long-lived QEMU/HVF guest VMs on this Mac no longer contend with the runtime
(the old Docker/LinuxKit-vs-HVF starvation constraint applied to the VMM era).

## Fixed decisions

- QEMU + HVF (`qemu-system-aarch64`, already installed via Homebrew), not
  lima (no NetBSD support) and not vfkit/Virtualization.framework (NetBSD
  poorly traveled, no qcow2-grade COW/snapshot story).
- Both modes (dev box + gate driver) share ONE provisioning path via a
  golden-image lifecycle.
- VM state lives outside the repo in `~/.carrick/bsdvm/<vm>/` (override:
  `CARRICK_BSDVM_STATE`). ~25 GB total budget.
- Guest toolchains are pkg (FreeBSD) / pkgsrc (NetBSD) rust: both
  `aarch64-unknown-freebsd` and `aarch64-unknown-netbsd` are Tier 3 with no
  rustup host builds. Non-rustup cargo ignores `rust-toolchain.toml`
  mechanically, so the repo's pin needs no relaxation; gate reports record the
  box's `rustc --version`.
- Gates run one VM at a time by default (`--parallel` opt-in): the Mac is
  10-core/32 GiB and also builds carrick.

## Inventory

| VM | Image | ssh | git remote |
|---|---|---|---|
| `freebsd-arm64` | FreeBSD 15.1 aarch64 official VM-IMAGE (fall back to newest published RC if 15.1-RELEASE aarch64 is absent; match the x86 box's major) | `127.0.0.1:2201` | `fbsd-arm` |
| `netbsd-arm64` | NetBSD 10.1 evbarm-aarch64 gzimg (matches willow VM 201's version) | `127.0.0.1:2202` | `nbsd-arm` |

## Components

- `scripts/bsdvm.py` — single driver. Subcommands: `fetch`, `provision`,
  `up`, `down`, `destroy`, `ps`, `gate`, `refresh-golden`.
- `scripts/test_bsdvm.py` — unit tests for config/overlay-chain/argument
  logic; no VM boot required (same convention as `test_native_x86_*.py`).
- `just` recipes wrapping the common flows (`just bsdvm-up freebsd-arm64`,
  `just bsdvm-gate netbsd-arm64 stage0`, ...).

## QEMU invocation

```
qemu-system-aarch64 -M virt,gic-version=3 -accel hvf -cpu host \
  -smp 4 -m 6144 \
  -drive if=pflash,format=raw,readonly=on,file=<brew>/share/qemu/edk2-aarch64-code.fd \
  -drive if=pflash,format=raw,file=<state>/efivars.fd \
  -drive if=virtio,format=qcow2,file=<overlay>.qcow2 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:<port>-:22 -device virtio-net-pci,netdev=n0 \
  -device virtio-rng-pci \
  -chardev socket,id=ser0,path=<state>/serial.sock,server=on,wait=off,logfile=<state>/serial.log \
  -serial chardev:ser0 \
  -display none -daemonize -pidfile <state>/qemu.pid
```

Notes:
- `virtio-rng-pci` is mandatory: NetBSD 10 blocks on entropy at first boot
  (ssh host key generation) without it.
- The serial chardev doubles as the interactive provisioning channel and the
  persisted boot log from one device.
- Per-VM writable `efivars.fd` copy; the code flash stays read-only from the
  brew install.

## Golden-image lifecycle

1. **fetch** — download the official image, verify the published checksum,
   convert raw→qcow2 where needed (NetBSD gzimg), resize +20 G →
   `base.qcow2`. Idempotent.
2. **provision** — boot base with a fresh overlay and drive first-boot setup:
   - FreeBSD: cloud-init NoCloud seed ISO if the BASIC-CLOUDINIT aarch64
     image is published; otherwise the serial-expect driver (below).
   - NetBSD: serial-expect over the chardev socket (no cloud-init in stock
     images).
   - Steps: root ssh key + sshd enable (key-only), `pkg`/`pkgsrc` install of
     git, just, rust, python; dtrace sanity check; `git init /root/carrick`
     with `receive.denyCurrentBranch=updateInstead` (push-to-checkout, same
     pattern as the fbsd x86 box).
   - Clean shutdown → freeze the overlay as **`golden.qcow2`**.
3. **dev mode** (`up`) — boots a persistent `dev.qcow2` backed by golden;
   interactive ssh work exactly like the x86 fleet.
4. **gate mode** (`gate <vm> <stage>`) — ephemeral COW overlay from golden →
   boot → ssh-wait (300 s backstop) → `git push` HEAD to the box → run the
   stage → collect results to a local results dir → destroy the overlay.
   The remote exit code propagates. The serial log is preserved on failure.
   Trap-based cleanup: a failed gate never leaks a running qemu.
5. **refresh-golden** — rerun provisioning steps on top of golden for pkg
   updates; keep exactly one prior golden for rollback.

## Gate ladder

Stages are report-only until the code they exercise exists (the x86-lane
convention). The gate report records stage, VM, rustc version, HEAD sha,
wall time, and pass/fail per step.

- **Stage 0 (day one, expected green):**
  `cargo test -p carrick-portable -p carrick-hal -p carrick-host -p carrick-mem`.
  These crates build on BSD today; the NetBSD `port_alias!` arms landed in
  June (ea72e207).
- **Stage 1 (report-only initially):** full workspace `cargo build`. The red
  list on netbsd/aarch64 IS the bring-up worklist.
- **Stage 2:** native-lane hello smoke once `NativeLane` × aarch64 ×
  {freebsd,netbsd} exists post-seam-extraction.
- **Stage 3:** LTP subset via the existing native gate pattern
  (`scripts/native-x86-ltp-gate.py` lineage).

## Error handling

- `down`: pidfile TERM → wait → KILL; `destroy` additionally removes
  overlays (never `base.qcow2`/`golden.qcow2` without `--all`).
- `ps`: pidfile scan; flags orphaned qemu processes.
- ssh-wait timeout and provisioning expect timeouts fail the command with the
  serial log path in the error message.
- Checksum mismatch on fetch is fatal (no partial-image reuse).

## Testing

- `scripts/test_bsdvm.py`: pure-logic unit tests (overlay chain construction,
  port/name mapping, qemu argv assembly, gate-stage selection, cleanup-on-
  error paths via injected fakes).
- Acceptance: `just bsdvm-gate freebsd-arm64 stage0` and
  `just bsdvm-gate netbsd-arm64 stage0` green end-to-end on this Mac.

## Risks / open items

- pkgsrc rust version on NetBSD/aarch64 must be new enough for the workspace
  (VM 201 precedent: pkgsrc 1.91 built it). Verify on-box during
  implementation; if too old, options are pkgsrc-current or building a
  pinned rust once and snapshotting it into golden.
- FreeBSD aarch64 BASIC-CLOUDINIT availability — serial-expect fallback
  covers either outcome.
- HVF `-cpu host` + NetBSD guest quirks (GIC, PSCI) — smoke-tested first in
  provisioning bring-up; known-good combination is qemu 8+/`gic-version=3`.
- Mass-parallel qemu churn is out of scope (one or two long-lived VMs; the
  historical WindowServer/Finder crash applied to mass carrick-HVF loops).
