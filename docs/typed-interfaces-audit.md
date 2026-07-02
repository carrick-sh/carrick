# Typed-interfaces audit: raw integers crossing semantic boundaries

2026-07-01. Full-workspace survey of `u32`/`u64`/`i32`/`i64` values that carry
domain meaning (fds, pids, signals, addresses, time, errnos, syscall numbers,
flag words), ranked by the likelihood that a domain mixup compiles silently and
ships a wrong-behavior bug. Weighting is EVIDENCE-FIRST: domains that have
already produced a real bug outrank hypothetical ones.

## Why now — the three bugs that motivated this

1. **`rt_sigtimedwait(set=∅)` wedged forever** — a signal *wait set* and a park
   *block mask* are the same `u64` with opposite polarity; `!wait_set` compiled
   fine and blocked everything (fixed bd824605; `SigSet`/`SigBlockMask` types
   introduced c178dfc3).
2. **`alarm(2)` dispatched as `epoll_create`** — two hand-numbered private
   syscall constants collided at `u64::MAX - 0x2a` (fixed bd62a25c; ordinal
   enum 0f42c596).
3. **x86 `poll(2)`'s int-milliseconds timeout read as a timespec pointer** —
   an int and a pointer share the `u64` argument slot (fixed 6d95ea01 via a
   private number; the reinterpretation still lives in one handler keyed only
   on the syscall number).

The pattern that already works: `dispatch/abi_args.rs` (`Fd`, `NsPid`/`HostPid`
with documented translation discipline, `Signal`, `GuestPtr`, `GuestLen`) and
the `bitflags` types in carrick-abi (`LinuxCloneFlags`, `LinuxMmapFlags`,
`LinuxProtFlags`, …). The systemic gap: those types stop at the syscall entry —
one call below, everything re-rawifies (`fd.0`, `GuestMemory::read_bytes(address:
u64)`, `mask: u64`).

## Ranked findings

### P0 — confirmed-bug shapes with remaining raw surfaces

**P0.1 Signal mask polarity (the `!wait_set` family).** `SigSet`/`SigBlockMask`
exist but only `WaitOnSignals` uses them. Still raw, in polarity-sensitive
positions:
- `SignalState` root fields: `masks`/`pendings`/`process_pending`/
  `restore_masks: u64` (`dispatch/signal.rs:113-165`) — a pending SET and a
  block MASK are assignment-compatible today.
- `has_unblocked_pending_for(tid, block_mask: u64)` ×4 copies (signal-core
  `lib.rs:243`, xsig.rs:154, hvf `host_signal.rs:394`, runtime `lib.rs:1489`)
  and `signal_unblocked_by_mask` — the exact `!mask` polarity shape, untyped,
  replicated in five files.
- The io_wait waiter chains: ~10 fns in runtime `lib.rs:1813-2103` + ~12 sites
  in hvf `io_wait.rs` all take `block_mask: u64`.
- `WaitOnFds`/`WaitOnFdsSelect`/`WaitOnPollFds`/`WaitOnProcExit.block_signals:
  u64` — siblings of the already-typed `WaitOnSignals.block_mask`, so identical-
  looking outcomes now disagree on typing.
- **Off-by-one landmine:** the execve `ignored_mask` uses bit=signum (bit 0
  unused) — the ONLY raw-signum-convention mask in the tree — and
  `host_glue.rs:154-170` mixes it with bit=signum-1 (`installed_mask`) in one
  function. Self-consistent today; one new caller away from a silent off-by-one.

**P0.2 `mask_replaces: bool` boolean blindness.** The bool selects whether
`block_signals` REPLACES the thread mask (ppoll/pselect/epoll_pwait temp
sigmask) or ADDS to it (plain blocking read). This axis produced the
`ppollunblock` vs `maskfork` bug pair. 8 construction sites, one real consumer
(`has_deliverable_dispatch_pending_for_wait`, `dispatch/signal.rs:741`).
→ fold `(block_signals, mask_replaces)` into one enum (`WaitSigMask::Replace(
SigSet) | ::Additive(SigSet)`), unrepresentable half-set state.

**P0.3 Syscall-number domains.** `SyscallRequest.number` (canonical) and
`.native_number` (guest-ISA) are two adjacent bare `u64` fields
(hal `trap.rs:26`, dispatch `mod.rs:756`); `SyscallRemap::Direct(u64)` targets
are only test-guarded (historical `uname(63)`→`read`, `mkdir(83)`→`fdatasync`
collisions are documented in syscall_x86_64.rs). The private-number ordinal
enum (0f42c596) fixed constant collisions; the canonical/native swap remains
type-invisible.

**P0.4 Match-arm const shadowing has no deny.** The AGENTS.md footgun (an
unimported `LINUX_*` in a match arm becomes a catch-all binding) is only a
default-warn. Function-local `const LINUX_*` still exist (`fs.rs:286`,
`mod.rs:2872`, `fs.rs:679`). → deny `unreachable_patterns` +
`bindings_with_variant_name` workspace-wide; it turns the footgun into a build
failure.

### P1 — silent cross-domain mixups with no bug yet (blast radius ordered)

**P1.1 Guest fd vs host fd.** No `HostFd` type exists. The fd_helpers
accessors are guest-in/host-out with both bare `i32`
(`host_socket_fd`, `regular_host_file_fd(_write)`, `host_pipe_read_fd`,
`host_pipe_end`, `host_socket_lookup -> (i32, i32)`), and splice/tee/sendfile
juggle both domains under the SAME variable names (`tee_host_passthrough(
in_fd, out_fd)` takes host fds; its caller's `in_fd`/`out_fd` are guest fds).
Passing a guest fd to libc compiles clean and operates on an unrelated
descriptor.

**P1.2 `NsPid` stuffed with host pids.** wait4 (`proc.rs:2010`) and ptrace
(`proc.rs:1673`) construct `NsPid(host_pid)` — deliberately defeating the one
newtype built to prevent exactly this; any downstream `.to_host()`/
`.names_self()` double-translates. Also `bootstrap_signal_send(target: i64)`
is a host pid from `kill` but a guest tid from `tkill`, disambiguated by a
bool.

**P1.3 `ThreadId = i32` alias + tid seeded from host pid.** tids, ns-pids,
host pids and signums are mutually assignment-compatible; guest pids are cast
straight to `ThreadId` for registry lookups (`proc.rs:259`, `creds.rs:499`,
`mod.rs:2390`), correct only because main-thread tid == host pid in the
identity namespace.

**P1.4 va/gpa/host-VA as adjacent `u64`s.** `map_aliased(va, gpa, len)`
(pml4.rs:586), `map_host_alias(va, ipa, len, …)` (both engines), the
`shared_futex_host_addr` chain (guest VA → GPA → host `usize`, then raw
pointer deref). Alignment guards cannot catch a va↔gpa transposition. The
`GuestMemory` trait itself is bare `u64` addresses end-to-end, which is why
`GuestPtr` protects only the outermost signature.

**P1.5 Errno as bare `i32`.** No `Errno` newtype; positive-errno convention is
purely disciplinary, with four separate `-(errno as i64)` negation sites and
`(-ret) as u32` re-derivations. A pre-negated value double-negates silently.
(Full newtype = the largest migration in this doc; interim: single negation
choke point + the `HostSyscallError` wrapper already returns positive Linux
errnos.)

**P1.6 Timer ns pairs.** `value_ns`/`interval_ns` adjacent `u64`s across ~6
public signatures and 3 backends (timer-core, hal `timer_delivery`, both VMM
impls), fed by saturating `as_nanos()` casts. A value/interval swap or ms-for-
ns error saturates instead of failing.

### P2 — flag words doing ad-hoc `& LINUX_*` tests

Typed already: clone/mmap/prot/open/at/futex-flags/socket-type/fd-flags.
Still raw (reject-unknown-bits semantics NOT enforced): epoll events (`u32`),
splice flags, eventfd2 flags, msg flags (`i32`), wait options, prctl option,
fcntl cmd, ioctl request. These are lower risk (validated per-site today) but
each new site re-implements the mask test by hand.

## Migration plan (staged, each stage independently green)

| Stage | Scope | Status |
|---|---|---|
| 1 | Audit (this doc) | done |
| 2 | Deny `unreachable_patterns` + `bindings_with_variant_name` workspace-wide | done (this series) |
| 3 | `WaitSigMask` enum replaces `block_signals + mask_replaces` on the fd-wait outcomes | done (this series) |
| 4 | `HostFd` newtype at the guest→host accessor seam (fd_helpers returns, splice/tee/sendfile plumbing) | done (this series) |
| 5 | Stop `NsPid` carrying host pids (wait4/ptrace → `HostPid`) | done (this series) |
| 6 | Fix the execve `ignored_mask` raw-signum convention → `SigSet` (bit=signum-1) on both ends | done (this series) |
| 7 | `SigSet`/`SigBlockMask` through signal-core + host_signal + io_wait chains + `SignalState` fields | TODO — mechanical, ~5 files, agent-mapped site list in this doc's source survey |
| 8 | `CanonicalNr`/`NativeNr` newtypes on `RawSyscall`/`SyscallRequest` | TODO |
| 9 | `GuestVa`/`Gpa`/`HostVa` in carrick-mem + engine translation chains | TODO — largest win for the memory subsystem, pairs with the durable-memory work |
| 10 | `Errno` newtype with a single negation choke point | done (this series) — `LinuxErrno` newtype + single negation choke point (`guest_retval`/`from_guest_retval`); `DispatchOutcome::Errno` field migration deferred |
| 11 | bitflags for epoll/splice/eventfd/msg/wait flag words; hoist function-local `LINUX_*` consts to carrick-abi | TODO — opportunistic per-file |

Ground rules for every stage: newtypes are `#[repr(transparent)]`-equivalent
zero-cost wrappers; constructors are NAMED for semantics (the `SigBlockMask::
for_signal_wait` pattern — no general `from_raw` where polarity matters); raw
escapes only at libc/wire boundaries via explicit `.raw()`/`.get()`; each stage
lands as one logical commit with `just ci` + the conformance probe gate green.
