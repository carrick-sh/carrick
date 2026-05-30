# LTP cheap-cluster execution plan (M4, session 2026-05-28)

Digested + API-confirmed specs from the `ltp-cheap-cluster-specs` workflow
(full specs persisted in the session task output; this is the actionable
distillation). Execute SERIAL: edit → `./scripts/build-signed.sh` → verify the
cluster's LTP tests under `carrick run --fs host` → write/extend its probe →
`cargo test --release --test conformance conformance_probes` (the gate) →
commit. NEVER rebuild while a sweep runs (sweep re-reads the binary per test).

Registry localhost:5050; `export CARRICK_INSECURE_REGISTRIES=localhost:5050`.
Pause any sweep (shared HVF + kill.sh) before building/verifying.

## Order (highest confidence / lowest risk first)

### 1. proc-errno-remainder (#10 remainder) — high conf, ZERO regression risk
- **pidfd CLOEXEC**: `proc.rs:290` `self.install_fd(description, 0)` → `install_fd(description, LINUX_FD_CLOEXEC)`. (LINUX_FD_CLOEXEC imported mod.rs:126.) → pidfd_open01.
- **fadvise64** (`mem.rs:169`, currently ignores `_advice`, returns 0): add `if advice > 5 { EINVAL }`; detect pipe fds (`OpenDescription::{PipeReader,PipeWriter,HostPipe}`) → ESPIPE. → posix_fadvise03 (EINVAL), posix_fadvise04 (ESPIPE).
- **ftruncate RO-fd EINVAL** (`fs.rs:2196` File arm `if !*writable { EBADF }` → EINVAL). ⚠️ ftruncate03 runs `--fs host` → ALSO find+fix the **HostFile arm** (the spec only flagged the File arm). → ftruncate03.
- **fdatasync char-dev EINVAL**: DEFERRED — first confirm Docker `fdatasync(/dev/null)`==EINVAL; if not, LTP-only, no probe.
- Probe `cluster10_pidfd_fadvise_ftrunc`: pidfd FD_CLOEXEC set; fadvise bad-advice→EINVAL; fadvise pipe→ESPIPE; ftruncate(ro)→EINVAL (and !=EBADF).

### 2. signalfd4 (#4) — high conf, small
- New syscall `74 => signalfd4` in mod.rs normalized dispatch (signal section).
- Add `SignalFd { base: OpenDescriptionBase, mask: u64 }` to `OpenDescription` enum (fd_table.rs:164). Adding a variant WILL surface exhaustive-match errors (fcntl/close/poll/stat) — compiler-guided; handle minimally (SignalFd is pollable-but-flag-only).
- Handler (mirror eventfd2/timerfd_create; `define_syscall!`): validate `flags & !(O_NONBLOCK|O_CLOEXEC)` → EINVAL; read mask (sizemask 1..=8 else EINVAL, EFAULT on bad ptr); fd==-1 → install_fd(SignalFd, linux_fd_flags_from_open_flags(flags) @ mod.rs:2321); fd>=0 → reassign mask in place, return same fd; else EBADF. F_GETFD/F_GETFL read base flags (no change needed).
- Probe `signalfd4`: SFD_CLOEXEC→F_GETFD has FD_CLOEXEC; SFD_NONBLOCK→F_GETFL has O_NONBLOCK; bad flag→EINVAL. → signalfd4_01/02.

### 3. flock + removexattr (#17) — high conf, medium
- **flock** (`fs.rs:2045`, no-op): if `regular_host_file_fd(fd)` Some(host_fd) → `libc::flock(host_fd, op as i32)`, map EWOULDBLOCK/EAGAIN→LINUX_EAGAIN; else keep no-op. Keep EBADF/EINVAL validation. → flock04/06.
- **removexattr family** (14/15/16, currently → `sys_xattr_unsupported` ENOTSUP):
  - add `FsBackend::remove_xattr` default ENOTSUP (fs_backend.rs trait ~236);
  - HostFsBackend impl via `libc::fremovexattr`, map macOS ENOATTR(93)→LINUX_ENODATA (mirror getxattr d9b1822 @ fs_backend.rs);
  - dispatcher `removexattr(memory, XattrTarget, name_ptr)` in fs/xattr.rs mirroring setxattr;
  - dispatch arms 14|15→path, 16→fd. ⚠️ f-variant: HostFile has no cached path (xattr_target_path returns ENOTSUP) — may leave fremovexattr unsupported unless path cached. → removexattr/lremovexattr/fremovexattr 01/02.
- Probe `flock_removexattr`: flock SH/EX/UN→0, LOCK_NB on locked→EAGAIN, bad fd→EBADF, bad op→EINVAL; setxattr→removexattr→getxattr ENODATA; removexattr-absent→ENODATA.

### 4. sched-errno (#13) — high conf, small. ⚠️ VERIFY live class first
- If live re-sweep shows sched_*01 as TBROK (broken=1, framework blocker) not DIFF, errno fixes won't move the verdict (still probe-gated + correct). The sched handlers are otherwise complete.
- `proc.rs` sched_getscheduler(731)/getparam(741)/setscheduler(764)/setparam(787): add `if (pid as i64) < 0 { EINVAL }` at start. Distinguish NULL param (EINVAL) from bad-ptr (EFAULT). Rewrite `sched_read_param_priority`(proc.rs:76) → `Result<i32,DispatchError>` (NULL→caller EINVAL, read err→Fault/EFAULT); update 3 call sites.
- `creds.rs` getpriority(241)/setpriority(230): negative `who`(Pid=i32)→EINVAL for PRIO_PROCESS/PRIO_PGRP; PRIO_PGRP/PRIO_USER existence→ESRCH.
- Probe `schedprio_negativepid_edges`: see spec (14 asserts: negative-pid EINVAL, NULL EINVAL, bad-ptr EFAULT, negative-who EINVAL).

### 5. chmod-setgid (#11) — MEDIUM conf, medium. SPLIT, do last
- (A cheap, do first) fchmod(4013)/fchmodat(4122): owner-EPERM (euid!=0 && file_uid!=euid → EPERM, via fget_owner_xattr); clear S_ISGID when egid!=file_gid; **fchmodat2 (nr 452) ONLY** validate `flags & !AT_SYMLINK_NOFOLLOW` → EINVAL (keep nr 53 tolerant — apt). Add `90 => chmod` → fchmodat(AT_FDCWD,...).
- (B) mkdirat(3968): inherit parent gid + S_ISGID when parent setgid.
- (C, DEFER) mknod FIFO: needs `OverlayEntry::Fifo` threaded through both backends + create_fifo trait method. mknod tests only make S_IFIFO / assert EINVAL(bad S_IFMT); none char/block/socket; mknod09 wants EINVAL not EPERM.
- ⚠️ chmod06/fchmod06/fchmodat02 also need EACCES/EROFS/ELOOP/ENOTDIR — full MATCH gated on ELOOP (separate). Expect partial advance.
- Probe `chmod_setgid_owner_fifo` (drop priv via setresuid/gid then assert).

## Confirmed APIs
- `Pid(pub i32)` (abi_args.rs:9) — signed. `DispatchError` (mod.rs:777) has `Fault`.
- `install_fd(desc, fd_flags: u64)`; `linux_fd_flags_from_open_flags` (mod.rs:2321).
- `regular_host_file_fd`/`_write_fd` (fs/fd_helpers.rs:91/103).
- `fget_owner_xattr(fd)->(Option<u32>,Option<u32>)` (fs_backend.rs:827); `clear_setid_on_chown` (fs.rs:1007); `cred_snapshot` (creds.rs:144).
- Probe idiom: `conformance_probes::{errno, report}`, raw `libc::syscall`, `report!(label = boolexpr, ...)`; built by `./scripts/build-probes.sh` (docker rust:alpine, no HVF).

## SESSION PROGRESS (2026-05-28) — 5 clusters LANDED, 20 LTP tests DIFF→MATCH

All probe-gated; `cargo test --release --test conformance conformance_probes`
green at 89 probes. Commits on `main`:
- `33122d4` #10: pidfd CLOEXEC + fadvise advice/ESPIPE + ftruncate RO-fd EINVAL
  (pidfd_open01, posix_fadvise03/04, ftruncate03/03_64). Probe `cluster10errno`.
- `ebb2411` docs: live tally 52% (462/896).
- `2c02bf1` #10: fsync/fdatasync on pipe/socket/chardev → EINVAL (fdatasync01/02).
- `dfd6b86` #4: signalfd4 (syscall 74) emulated fd-flag surface (signalfd4_01/02).
  Probe `signalfd4`; added SignalFd OpenDescription variant.
- `5e1f1a8` #13: sched negative-pid EINVAL + bad-param-ptr EFAULT + priority ESRCH
  (sched_getparam03, sched_setparam04, sched_setscheduler01, getpriority02).
  Probe `schedprio`.
- `a345a80` #17: flock host-forward + removexattr family (flock04/06,
  removexattr01/02). Probes `flocklock` + `fsx` extended; added
  FsBackend::remove_xattr.
- `6c2c7e4` #11 (partial): chmod setgid-clear + fchmodat2 flag EINVAL
  (chmod05, fchmodat02, fchmodat2_02). Probe `chmodsetgid`; added
  FsBackend::get_owner.

### Follow-up backlog (tracked, NOT yet done)
- **#11 remainder**: fchmod04/fchmod05 — fchmod on a DIRECTORY fd doesn't
  persist the mode (stat shows 040755 = creation mode, not the fchmod'd value);
  a separate fd-on-dir set_mode bug. mkdir02/mkdir04 — parent-setgid + gid
  inheritance in mkdirat.
- **#13 remainder**: setpriority02 EACCES (unprivileged nice-lowering) + EPERM
  (cross-uid target) — needs a fuller priority/uid model.
- **capget probe gap** (task #2): capget02 fix shipped "no new probe"; add the
  pid<0→EINVAL / nonexistent→ESRCH / preferred-version-writeback edges to a probe.
- Docker-LinuxKit artifacts EXCLUDED from probes (carrick matches mainline,
  Docker disagrees): flock bad-operation→EINVAL.

### Next round
After the consolidating re-sweep (task #8) refreshes BASELINE + diffs.json:
re-run the ltp-diff-triage workflow on the new DIFF set; design ELOOP (the
resolve_following Vfs-trait change) via a judge-panel before coding. Bigger
remaining levers from the live DIFF tally: fs (113 DIFF + 41 TBROK), mm (32+22),
process (31+41), the tst_test variant-switching framework blocker.

## Probe gaps to backfill (DoD #3)
- capget pid-errno edges (capget02 shipped "no new probe") — extend `sysinfo` or new `capgetedge`.
