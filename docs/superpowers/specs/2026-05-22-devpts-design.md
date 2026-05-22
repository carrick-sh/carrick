# devpts / PTY support for carrick

**Date:** 2026-05-22
**Status:** Phase A COMPLETE (merged to main). Phase B COMPLETE (`feat/devpts-phase-b`) with documented limitations — see "Phase B status" below.
**Approach:** Host-PTY-backed devpts with ioctl passthrough (Approach 1)

## Phase B status (2026-05-22)

`carrick run -t <image> <cmd>` allocates a host pty, hands the guest the slave
as fds 0/1/2, and relays bytes between the user's terminal and the pty master
(raw mode + relay thread + SIGWINCH wiring). Implemented per
`docs/superpowers/plans/2026-05-22-devpts-phase-b.md` (PB1–PB9).

**Verified working (automated):**
- Real pty with live line discipline — the e2e test (`tests/interactive_tty.rs`,
  `#[ignore]`, run against the SIGNED release binary) types a marker and sees it
  echoed by the pty line discipline AND by `cat` (appears twice). This is the
  definitive proof of a functional interactive tty.
- `isatty(0/1/2)` is true under `-t`; the guest shell runs interactively.
- Bidirectional relay (guest output → terminal, typed input → guest), EINTR-safe.
- Initial window size propagates at start (guest `stty size` reflects the pty
  size).
- Gates green: 148 lib tests (incl. `pty_relay`), 59 `syscall_fs`, 46 `cli`,
  38/38 conformance (no devpts regression), clippy unwrap-gate clean, fmt clean.

**Both original limitations are now FIXED** (verified by the comprehensive
`#[ignore]` e2e in `tests/interactive_tty.rs`, run against the signed binary):

- **`ttyname()` / `tty(1)` / `/dev/tty` — FIXED.** The `-t` pty is registered as
  the guest's controlling terminal (`PtyTable::controlling_index` via
  `SyscallDispatcher::register_controlling_pty`). `/dev/tty` opens that pts slave
  (DevVfs, ENXIO when non-interactive); `stat`/`statx`/`newfstatat` now route
  through the VFS mounts so `/dev/ptmx`, `/dev/pts/N`, `/dev/tty` resolve and
  report **S_IFCHR** (`vfs_entry_kind_mode`); `readlinkat` maps
  `/proc/self/fd/{0,1,2}` → `/dev/pts/N`; and the controlling-tty stdio `fstat`
  labels itself `/dev/pts/N` so its `st_ino` matches `stat("/dev/pts/N")` — the
  equality glibc `ttyname(3)` checks. `tty(1)` now prints `/dev/pts/0`.
- **Live `SIGWINCH` resize — FIXED.** Root-caused via dtrace: the SIGWINCH
  handler doesn't fire in carrick's HVF context (vCPU threads run with signals
  effectively masked), BUT the kernel keeps the inherited terminal fd's winsize
  current. So the relay polls every 250ms and re-reads the size, propagating
  `TIOCSWINSZ` on change — signal-independent. Verified: resizing updates the
  guest's `stty size`.

**Remaining follow-ups (non-blocking):**
- **Job control (Ctrl-C):** stdio pgrp ioctls passthrough to the host tty (PB7)
  and guest pgrps are real macOS pgrps, so the mechanism is in place; full
  Ctrl-C-in-`bash` is a manual check not yet confirmed via automation.
- `write_fd_statx` lacks the stdio fast-path that `write_fd_stat` has, so
  `statx(fd, AT_EMPTY_PATH)` on a controlling-tty stdio fd returns EBADF
  (pre-existing; `ttyname`/`isatty` use `fstat`, which works).
- `-t` is `run`-only; `shell`/`exec` are follow-ups.

The original design and Phase A content follow.

## Problem

Guest programs that allocate a pseudo-terminal fail under carrick because
there is no `/dev/ptmx` and no `/dev/pts`. The most visible symptom is
`apt-get install`/`update` printing:

```
E: Can not write log (Is /dev/pts mounted?) - posix_openpt (2: No such file or directory)
```

apt falls back gracefully (the install still completes), but the warning is
the last remaining "apt cosmetic", and the missing PTY layer also blocks
`script`, `tmux`, `expect`, and any interactive shell.

## Goals

Two use-cases, sequenced **A before B**:

- **A — self-contained devpts.** Apps that allocate their own pty pair
  internally (apt/dpkg, `script`, `tmux`, `expect`). Both master and slave
  live inside the guest. This unblocks the apt cosmetic and is fully
  self-testable.
- **B — interactive host shell.** `carrick run -it bash` / `carrick shell`,
  where the guest's controlling tty is wired to carrick's own stdin/stdout on
  the Mac, with working job control (Ctrl-C → SIGINT to the foreground
  process group), window resize, and line editing.

## Non-goals

- Reimplementing a terminal line discipline in carrick (canonical mode, echo,
  signal characters). The host macOS kernel already does this correctly; we
  lean on it.
- Multiple independent devpts instances / mount namespaces. A single global
  `/dev/pts` instance is sufficient.
- Packet mode (`TIOCPKT`) and other rarely-used master ioctls beyond what the
  target workloads exercise; these fall through to the existing
  `unhandled_ioctl` reporter + `ENOTTY` path and can be added on demand.

## Key enabling fact

Guest process groups and sessions are **real macOS pgrps/sessions**:
`setpgid`/`setsid`/`getpgid`/`getsid` call `libc::setpgid`/`libc::setsid`
directly (`src/dispatch/proc.rs:505-560`), `getpid` returns the real host pid,
and guest processes are real forked macOS processes that carrick already
signal-translates (Linux↔macOS signum). Therefore, if the PTY slave is backed
by a **real macOS pty**, the host kernel's line discipline delivers
job-control signals to the correct real foreground pgrp — which contains the
real guest processes — *for free*. carrick only has to translate names and
synthesize the one or two ioctls macOS lacks.

## Architecture

### New module: `src/vfs/devpts.rs`

A `Vfs` mount (sibling to `src/vfs/dev.rs`) registered at `/dev/pts`, plus the
`/dev/ptmx` node. Responsibilities:

- `lookup("/dev/pts")` → directory; `lookup("/dev/pts/N")` → char device if N
  is live in the `PtyTable`, else ENOENT; `lookup("/dev/ptmx")` → char device.
- `readdir("/dev/pts")` → live N's from the `PtyTable` (plus the conventional
  `ptmx` entry).
- `open("/dev/ptmx")` → allocate a master (see flow below).
- `open("/dev/pts/N")` → open the slave for N (see flow below).

`/dev/ptmx` is owned by this mount, not the existing `DevVfs` passthrough.

### `PtyTable` (dispatcher state)

Lives in `SyscallDispatcher` behind a `Mutex` (consistent with the other
per-subsystem state post-BKL-retirement). It is the single source of truth
for slave lookup and `/dev/pts` readdir.

```
PtyTable {
    next_index: u32,                 // monotonic N allocator, starts at 0
    entries: HashMap<u32, PtyEntry>, // N -> entry
}
PtyEntry {
    host_master_fd: i32,
    host_slave_name: String,         // macOS slave path, e.g. "/dev/ttys003"
    locked: bool,                    // TIOCSPTLCK state (default true)
}
```

### Two `OpenDescription` variants

Host-fd-backed, modeled on the existing `HostPipe`:

```
PtyMaster { host_fd: i32, pts_index: u32, status_flags: u64 }
PtySlave  { host_fd: i32, pts_index: u32, status_flags: u64 }
```

Read/write route through the host fd exactly like `HostPipe`; blocking waits
use the existing lockless `WaitOnFds` path on the host fd.

## Flows

### `open("/dev/ptmx")`

1. Host `posix_openpt(O_RDWR | O_NOCTTY)` → master fd; on failure translate
   errno (`dev.rs::host_open_errno`).
2. `grantpt(master)` and `unlockpt(master)` on the host.
3. `ptsname(master)` → macOS slave name (e.g. `/dev/ttys003`).
4. Allocate `N = next_index++`; insert `PtyEntry { host_master_fd: master,
   host_slave_name, locked: true }`.
5. Return `PtyMaster { host_fd: master, pts_index: N, .. }`.

The guest's libc `ptsname()` will `ioctl(master, TIOCGPTN, &n)` then format
`/dev/pts/<n>` — see ioctl routing.

### `open("/dev/pts/N")`

1. Parse N from the path; look up in `PtyTable` (ENOENT if absent).
2. Host `open(host_slave_name, flags)` → slave fd.
3. Return `PtySlave { host_fd: slave, pts_index: N, .. }`.

### ioctl routing (extend `src/dispatch/fs.rs:918`)

`PtyMaster`/`PtySlave` fds are recognized as ttys (so `isatty()`/`TCGETS`
succeed instead of returning `ENOTTY`). For these fds:

| ioctl | behaviour |
|-------|-----------|
| `TIOCGPTN` | synthesize: write `pts_index` (macOS has no equivalent; this is what guest `ptsname()` reads) |
| `TIOCSPTLCK` | synthesize: set/clear `locked`, return 0 (guest `unlockpt`) |
| `TCGETS` / `TCSETS{,W,F}` | passthrough to host fd (real `tcgetattr`/`tcsetattr`) |
| `TIOCGWINSZ` / `TIOCSWINSZ` | passthrough to host fd |
| `TIOCGPGRP` / `TIOCSPGRP` | passthrough to host fd (`tcgetpgrp`/`tcsetpgrp`) — real host pgrps |
| `TIOCSCTTY` / `TIOCNOTTY` / `TIOCGSID` | passthrough to host fd |
| anything else | existing `unhandled_ioctl` reporter + `ENOTTY` |

Passthrough copies the guest's ioctl arg struct in, issues the real host
`libc::ioctl`, and copies results back, reusing the existing termios/winsize
ABI structs in `src/linux_abi.rs` (`LinuxTermios` = 36 bytes, `LinuxWinsize` =
8 bytes). The existing stdio-tty ioctl handling is unchanged.

## Fork coherence & lifecycle

- **Fork:** host-fd-backed descriptions already survive `libc::fork`
  natively (the kernel fd is inherited), and real fork copies the dispatcher's
  address space, so a `PtyTable` entry comes along into the child for free. A
  pty allocated by a parent (apt) and used by a forked child (dpkg) works with
  no special snapshot logic — same model as `HostPipe`/`HostSocket`.
- **Close:** closing a `PtyMaster` closes the host master fd and removes the N
  entry from `PtyTable` (mirrors Linux, where `/dev/pts/N` disappears when the
  master closes). Closing a `PtySlave` closes its host fd. macOS reclaims the
  pty once both ends are closed.
- **CLOEXEC:** pty fds honor `O_CLOEXEC`/`FD_CLOEXEC` like every other host-fd
  description; `close_cloexec_fds()` already runs post-fork/exec.

## Case B: `carrick run -it`

Built after A, reusing `PtyMaster`/`PtySlave` and the ioctl passthrough:

1. A `-it` / `--tty` CLI flag makes carrick allocate a pty on the host side.
2. The guest gets the **slave** as fd 0/1/2 (its controlling tty).
3. carrick runs a relay loop copying bytes between the **master** and its own
   stdin/stdout, with the Mac terminal put in raw mode for the duration.
4. `SIGWINCH` on carrick → `TIOCSWINSZ` on the master so the guest sees
   resizes.
5. Job control inside the guest rides the host slave's line discipline (real
   host pgrps), so Ctrl-C delivers SIGINT to the guest's foreground pgrp.

## Error handling

- `posix_openpt`/`grantpt`/`unlockpt`/host slave `open` failures → translate
  errno via `dev.rs::host_open_errno` (EMFILE when out of host ptys, etc.).
- Unknown `/dev/pts/N` → ENOENT.
- Unhandled pty ioctls → existing `unhandled_ioctl` reporter + `ENOTTY`.

## Testing

1. **Unit:** `PtyTable` alloc/lookup/free; devpts `lookup`/`readdir`;
   `TIOCGPTN`/`TIOCSPTLCK` synthesis.
2. **Conformance probe:** new `conformance-probes` binary `ptypair` doing the
   full `posix_openpt` → `grantpt` → `unlockpt` → `ptsname` → open-slave →
   write-master/read-slave (and the reverse) round-trip, diffed against
   Docker `ubuntu:24.04`.
3. **End-to-end:** `apt-get install -y hello` shows **zero** `/dev/pts`
   warnings and still prints `Hello, world!`.
4. **Case B smoke:** `carrick run -it … /bin/sh -c 'tty; test -t 0 && echo
   ISATTY'` reports a `/dev/pts/N` path and `ISATTY`.

## Sequencing

- **Phase A (this spec's priority):** devpts module + `PtyTable` + the two
  `OpenDescription` variants + ioctl routing + unit/probe/e2e tests. Closes
  the apt cosmetic and unblocks `script`/`tmux`/`expect`.
- **Phase B:** the `-it` CLI flag + host-side relay loop + raw-mode + SIGWINCH.

## Risks

- **macOS pty quirks:** `ptsname`/`grantpt` semantics and slave naming differ
  from Linux; the translation layer is the crux. Mitigated by the `ptypair`
  conformance probe diffing against real Linux.
- **Passthrough ABI mismatch:** Linux vs macOS `termios`/`winsize` struct
  layouts differ; we already carry kernel-ABI structs in `linux_abi.rs` and
  must marshal field-by-field rather than blind-copy where layouts diverge.
- **Phase B raw-mode/relay** is the higher-risk half (terminal state
  restoration on exit/panic); isolated from Phase A so the apt fix lands
  independently.
