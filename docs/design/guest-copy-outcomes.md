# Guest-copy outcomes: inventory and retirement plan

Part of #1684, slice 0. The owner decision on #1684 and the memory-contract
work in #1685 require one neutral interface, with ISA-specific mechanics only.
**#1677 owns the interface and in-ring signal migration.** This note and lint
introduce neither an outcome type nor a second implementation.

This is a census of admitted main `3478f3b9bf` (2026-11-05), not a claim that
these paths have been fixed. Locations below are requested review aids, not
pinned lint exemptions. Regenerate current diagnostics with
`just xtask guest-copy-debt --list`. Retirement removes these aids; policy
stores only per-file, per-kind monotone counts, never source lines or hashes.

## What can reach an ARM lazy page first

1. `carrick-el1-linux/src/lifecycle.rs:85,102`: `El1PendingFamilies` implements
   core `UserCopy` with `ValidatedCopy`; copy-in returns false on a failed
   translation. The non-ARM-scheduler output path can instead use
   `copy_out_owned`, but collapses its result with `is_ok()`.
2. `carrick-personality-linux/src/signal.rs` and `lifecycle.rs`: the shared
   rt_sigprocmask/sigpending/sigtimedwait and sigaltstack/clone-TID operations
   consume those booleans. A legitimate input not resident yet can become
   EFAULT (14), the #1677 glibc thread-creation failure. Clone TID publication
   also has ignored rollback writes (`lifecycle.rs:1051,1063`).
3. `carrick-el1/src/file.rs:354,362`: `ValidatedCopy` checks the whole range
   before guarded user access. Failure is false, with no materialization
   distinction. `carrick-el1-linux/src/file.rs:197,200` wraps this: input is
   passed through, output records `CopyoutRequest` for the owner's existing
   preparation protocol. That output asymmetry must not become another API.
4. `carrick-el1-linux/src/dispatch.rs:981,1061,1065,3771,3788`: host-file,
   file/IPC and scheduler adapters share those mechanics. Scheduler input's
   argument order is reversed relative to core `UserCopy`.
5. `carrick-kernel/src/dispatch/`: host handlers reach ARM lazy mappings through
   `CurrentMmMemory` as well. `read_kernel_prefix` (`mod.rs:2666`) erases
   `MemoryError` with `map_err(|_| LINUX_EFAULT)`. Direct `read_bytes` matches
   do the same, notably signal input at `signal.rs:1936,2055,2160,2242,2303`.
   Prepared `dispatch::copyout` output already carries refusal/continuation
   information; its callers are inventory, not all debt.

The same neutral callers can run on x86. `carrick-x86/src/cpl0_lifecycle.rs:668,679`
uses an eagerly provisioned aperture, range-checks and raw copies. It has no
native not-materialized state today. Green KVM therefore cannot stand in for
ARM demand-backing evidence. #1685 must either qualify eager backing against
the shared contract or change it, rather than introduce x86 syscall policy.

## Interface inventory

Locations use paths relative to `crates/`. A means AArch64, X means x86_64;
R means ring (EL1/CPL0), H means host. Generic code is A+X even where an
individual route is not admitted on both ISAs yet.

| Interface / adapter | Location | ISA / venue | Meaning of not yet today |
|---|---|---|---|
| `personality::UserCopy` | `carrick-core/src/personality.rs:300` | A+X R/H | bool loses distinction; default `read_val` is Option, `write_val` bool |
| `UserMemory` implementation | same file:458,462 | A+X R/H | typed service errors become `is_ok()` false |
| `&mut U` forwarding implementation | same file:444,449 | A+X R/H | passes bool through, cannot recover kind |
| `UserWriteVenue::copy` | `carrick-core/src/mm/transaction/user_write.rs:93,110` | A+X R | false becomes `UserWriteError::Fault` after owner preparation; preparation itself already typed |
| `file::UserCopy` | `carrick-el1/src/file.rs:305,341,343` | A+X R/H | false permits file fallback/recall, plus optional output-refusal side channel |
| `MemoryValidator` | same file:162 | A+X R/H | accessible prefix length; absent translation becomes zero/short prefix |
| `InitialFrameSource` | `carrick-el1/src/isa/x86/initial_mm.rs:295,298,305` | X R | physical copy/write false => `InitialMmError::FrameUnavailable` at :511; abort unpublished image, not a syscall EFAULT |
| `UserWord` | `carrick-el1/src/sched.rs:217` | A+X R | Option word read; None returns unavailable from EL1 wait admission (`sched.rs:373-375`), not a release dependency |
| `HostFileUser` | `carrick-personality-linux/src/native_host_file.rs:309` | A+X R | false input stages a read fault/supply; refused supply becomes EFAULT |
| `SchedVenue` copy methods | `carrick-personality-linux/src/sched.rs:157,158` | A+X R | false becomes EFAULT for affinity/time records |
| lifecycle UserCopy name | `carrick-personality-linux/src/lifecycle.rs:408` | A+X R/H | re-export of core, not a separate trait |
| `LifecycleNative`, `SignalNative`, `IdentityNative`, `SysinfoNative`, `IpcNative` | respective personality files:479,460,517,274,112 | A+X R | supertraits of that re-export; no independent copy contract |
| file UserCopy name | `carrick-el1-linux/src/file.rs:7` | A+X R | re-export of el1 file trait |
| `HostUserCopy` | `carrick-kernel/src/el1_delegation.rs:1850,1871,1882` | A+X H | input error/short read false; output queued, finish folds write errors into bool |
| `HostPreparedRead` | same file:1896,1903,1912 | A+X H | staged output bool; input always false (unsupported direction) |
| continuation IPC copy | `carrick-kernel/src/kernel/continuation/ipc.rs:482,498` | A+X H | host copies become bool; owner continuation surrounds the copy |
| native lane UserCopy | `carrick-x86/src/cpl0_lifecycle.rs:667` | X R | invalid range false; valid memory eagerly backed |

There are five defining bool-copy traits in this scope (core UserCopy,
UserWriteVenue, el1 file UserCopy, HostFileUser, SchedVenue), not a dozen
independent definitions. The broader syntax counter also counts the physical
`InitialFrameSource::copy_guest_data` method: a separate image-construction
boundary, not a sixth user-copy API. Re-exports, supertraits and implementations explain
some apparent duplicates. `UserWord` and `MemoryValidator` are additional
lossy user-access interfaces despite returning Option/length rather than bool.
`CowCopyWindow` (`carrick-el1/src/fault.rs:647`) and ISA `copy_user_chunk` /
`read_user_word` mechanics are below preparation, not new syscall-copy APIs.
They must preserve the neutral outcome when wired to it, without Linux policy.
The closure argument `copy_out` in native host-file reply completion
(`native_host_file.rs:1128`) is another bool interface, with false => EFAULT.

## Retirement order and witnesses

Each row is a separate reviewable slice with an estimated changed-line ceiling
of 1,500, including its tests. Split at the named family boundary if the
estimate fails; never migrate a whole large dispatcher file at once. Interface
names and outcome layout come from #1677, not this note.

| Order / budget | Retire | Production-entry red-first witness |
|---|---|---|
| Bottom layer, #1677 / 1,500 | neutral interface, ISA adapters, in-ring signal input/output | dispatch rt_sigprocmask with bad pointer => errno 14; valid file-backed read-only input not yet once then success; Busy once then holder release then success, no errno |
| 1 / 1,200 | host signal family and ABI record input helpers | `SyscallDispatcher` rt_sigprocmask, rt_sigpending, rt_sigtimedwait, sigaltstack; refuse each direction once, retain mask/pending signal/stack and complete exactly once |
| 2 / 1,500 | clone TID admission/publication, clear-child-TID, robust-list and signal frames (ARM and x86 adapters) | production clone/clone3 with two live tasks, TID destination not yet once then success; exit a non-last thread; no child birth replay or lost rollback |
| 3 / 1,200 | file and native-host-file staging plus el1 delegation adapters | production write/writev with lazy read-only source and read/readv with lazy destination; not yet once then success with same descriptor pin and byte cursor |
| 4 / 1,500 | pipe/eventfd/epoll/poll IPC, continuation IPC and UserWriteVenue seam | production pipe read across two pages: refuse second page once, release owner, success with no duplicated prefix and no second readiness observation |
| 5a / 1,200 | fd read/write/sendfile/transfer and directory output | production getdents64 and sendfile offset copy, not yet once then success without consuming entries/advancing offsets twice |
| 5b / 1,200 | ioctl/locks/stat/xattr/fs metadata | production ioctl output and fcntl lock input, not yet once then success with unchanged host effect count |
| 6a / 1,500 | sockets send/receive/message/iovec control copies | production recvmsg after packet arrival: not yet once then success retaining payload and SCM rights; sendmsg source similarly |
| 6b / 1,200 | socket options/address/lifecycle/netlink and epoll metadata | production getsockopt/getpeername, not yet once then success preserving length and endpoint identity |
| 7a / 1,200 | exec strings, argv/env, path readers and fork loans | production execve lazy argv page not yet once then success; no partially installed image and no lost input after parking |
| 7b / 1,200 | scheduler/futex/time/identity/sysinfo | production sched_setaffinity, clock_gettime, getresuid, uname: each record not yet once then success; futex word read uses owner release, not polling |
| 8a / 1,200 | SysV IPC and POSIX queues | production msgrcv/mq_receive output not yet once then success, message retained and dequeued once |
| 8b / 1,200 | bpf/perf/ioring/keys/mount and memory metadata remainder | production bpf attribute input and io_uring registration not yet once then success, no replayed allocation/publication |

Apply each production entry on both ISAs using the same neutral refusal
injection boundary. ISA tests qualify translation/fixup mechanics separately.
A fake inner helper that returns Busy does not prove dispatch retention.
For every row: enroll on the holder's existing release notification, probe once
after enrolling, release execution capacity, retain the owned operation and
rerun it. No retry loop, timeout increase, host readiness pipe or serialization.
True Fault alone lowers to EFAULT. Stale/Invalid/Quarantined remain broken
invariants, never aliases for Busy. A refusal must fire the central read/write
probe once; adapters must not add competing per-site probes.

Existing `kernel.memory.owner-wait` is the starting structural contract for
retained copies. Extend the exact family contract before each migration:
bounded transfers per page, no copied-prefix replay, no duplicate side effect,
no permit or editor held over a park. Linux authority is syscall/man-page
semantics and the Docker oracle, never host errno behavior. Director acceptance
still requires the signed Mac glibc thread census (started/finished population)
and unchanged or improved results; this note supplies no signed verdict.
If the interface requires more than a handful of per-site exceptions or signed
EL1 population regresses, stop migration and retain the lint only.

## Lint contract and limits

`guest-copy-debt` runs under `lint-source`, hence `just lint-domains`, with its
unit fixtures in the domain unit recipe. It separately counts bool copy trait
methods by file/trait/method and unclassified error collapses by file. It detects direct guest
copy match scrutinees with `Err(_)`, `Err(binding)` or catch-all arms and
copy expressions consumed by `map_err`, `or_else`, `ok`, `is_err`, `is_ok` or
`unwrap_or*`. It conservatively counts those consumers even if their closure
inspects the error. Explicit matching of error variants is not an unclassified
match collapse. The inventory also lists copy calls that propagate errors or
already use prepared output; those are **not** automatically lint violations.

The policy must equal discovered counts exactly, so retiring debt requires
lowering its ceiling in the same change. Each counter may only fall against
`CARRICK_AUTHORITY_BASE` (or `--base`), including the first introduction, which
scans base sources. Moving debt between files cannot buy headroom. No-base
local runs check current policy only; CI must provide its actual PR base.

This is a syntax lint, not Rust type inference or whole-program dataflow.
The explicit vocabulary includes byte/record/string copies and dispatcher
wrappers. Aliased functions, an error stored in an unrelated local before
matching, newly named wrappers, arbitrary callback names and custom macro DSLs
can escape that vocabulary. Review must reject those evasions and extend the
scanner when a new production copy spelling is introduced. Macro handler
bodies parse as Rust; opaque DSL syntax needs an explicit fixture before use.
Item-level test-only code is excluded using the existing authority classifier.
Expression-local test hooks are conservatively included; they are visible in
the consumer excerpts, not evidence that their branch runs in production.
No claim is made that a count of zero proves every memory path is correct.

## Call-site census

The following tables enumerate the source census by operation, including
passthroughs so an erased outcome can be followed back to its adapter. Each
listed number is a separate call site (or bool trait method), on admitted main.
The venue/disposition key applies to every site in its row; exceptional paths
are called out above. Prepared copyout sites retain typed refusal and are not
silently mapped to EFAULT merely because they appear here.

- **P**: A+X ring/host neutral personality: false/None normally EFAULT;
  lifecycle rollback explicitly ignores bool, and adapters pass it through.
- **R**: A+X ring: file false yields fallback/recall or partial count; owner
  output can retain a memory request. Guarded input does not itself supply it.
- **H**: A+X host dispatcher: raw read/write failure normally EFAULT or partial
  IO; string helpers propagate their errno; prepared copyout preserves refusal.
- **X**: x86 host engine/bringup: guest-memory Result propagated or collapsed
  to fault at caller; no lazy-backing state in the native aperture today.
- **M**: A+X neutral memory internals: typed service/owner result or local
  allocation/buffer IO, not necessarily a syscall copy (conservative census).

The consumer column quotes the actual branch or immediate source consumer,
so EFAULT, other errnos, ignored results and typed propagation stay distinct.
Long source consumers are excerpts (…); follow the location for the complete
expression. A helper pass-through carries its existing result to its caller;
it does not recover an already erased kind. Allocation zeroing and host file
copy calls caught by the conservative vocabulary are shown as source consumers
and are not claims of guest fault handling.

Initial lint ceiling: **249** obligations: **10** bool trait methods and
**239** unclassified error consumers, over **61** file/kind or trait-method
counters. These counts concern syntax, not 249 distinct syscall defects.

<details>
<summary>Per-file source census (including immediate consumers)</summary>

### `carrick-personality-linux/src/arch_prctl.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 35 `write_bytes` | X R/H | `is_err(); source consumer: if engine.write_bytes(addr, &base.to_le_bytes()).is_err() { Ok(LINUX_EFAULT.guest_retval()) } else { Ok(0) } } ARCH_SET_GS => { if addr >= 0x0000_8000_0000_0000 {` |
| 51 `write_bytes` | X R/H | `is_err(); source consumer: if engine.write_bytes(addr, &base.to_le_bytes()).is_err() { Ok(LINUX_EFAULT.guest_retval()) } else { Ok(0) } } ARCH_GET_CPUID => {` |

### `carrick-personality-linux/src/identity.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 565,566,613,616,619,633,636,639,731,803,817,970,990,1046 `copy_out` | A+X R/H | `{ return Some (SyscallResult :: new (EFAULT)) ; }` |
| 754,770,827,847,857,948 `copy_in` | A+X R/H | `{ return Some (SyscallResult :: new (EFAULT)) ; }` |
| 782,839 `copy_out` | A+X R/H | `ignored result (let _)` |

### `carrick-personality-linux/src/ipc.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 163,184,326 `write_val` | A+X R/H | `{ return ret_errno (LINUX_EFAULT) ; }` |
| 196,231,371,378,542 `read_val` | A+X R/H | `{ return ret_errno (LINUX_EFAULT) ; }` |
| 239,496,532 `copy_in` | A+X R/H | `{ return ret_errno (LINUX_EFAULT) ; }` |
| 272 `write_val` | A+X R/H | `source consumer: let copy_ok = (&mut native).write_val(msgp, &mtype) && (data.is_empty() &#124;&#124; native.copy_out(text_va, &data)); if !copy_ok { if let Some(venue) = native.process_ipc() { let _ = venue.msgrcv_restore(msqid, original_idx, mtype, data); } return ret_errno(LINUX_EFAULT);` |
| 273 `copy_out` | A+X R/H | `source consumer: && (data.is_empty() &#124;&#124; native.copy_out(text_va, &data)); if !copy_ok { if let Some(venue) = native.process_ipc() { let _ = venue.msgrcv_restore(msqid, original_idx, mtype, data); } return ret_errno(LINUX_EFAULT); }` |
| 350 `write_val` | A+X R/H | `source consumer: (&mut native).write_val(arg_ptr, &ds) } carrick_guest_arch::GuestIsa::Aarch64 => { (&mut native).write_val(arg_ptr, &ds.to_aarch64()) } }; if !ok { return ret_errno(LINUX_EFAULT);` |
| 353 `write_val` | A+X R/H | `source consumer: (&mut native).write_val(arg_ptr, &ds.to_aarch64()) } }; if !ok { return ret_errno(LINUX_EFAULT); } ret(val) }` |
| 470 `copy_out` | A+X R/H | `{ return ret_errno (LINUX_EFAULT) ; }` |

### `carrick-personality-linux/src/lifecycle.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 902 `copy_in` | A+X R/H | `{ return Some (Err ((carrick_syscall_abi :: LINUX_EFAULT , false))) ; }` |
| 927 `copy_out` | A+X R/H | `{ return Some (Err ((carrick_syscall_abi :: LINUX_EFAULT , work))) ; }` |
| 960 `copy_in` | A+X R/H | `{ return Some (Err (carrick_syscall_abi :: LINUX_EFAULT)) ; }` |
| 1002 `copy_out` | A+X R/H | `{ return Some (Err (carrick_syscall_abi :: LINUX_EFAULT)) ; }` |
| 1025 `copy_in` | A+X R/H | `then_some(Some (Self { address , preimage }))` |
| 1045 `copy_out` | A+X R/H | `{ return false ; }` |
| 1051,1063 `copy_out` | A+X R/H | `ignored result (let _)` |
| 1058 `copy_out` | A+X R/H | `source consumer: .is_none_or(&#124;child&#124; user.copy_out(UserVa::new(child.address), bytes)) }  fn rollback(&self, user: &mut (impl UserCopy + ?Sized)) { for output in [&self.parent, &self.child].into_iter().flatten() { let _ = user.copy_out(UserVa::new(output.address), &output.preimage); } }` |
| 1416 `copy_out` | A+X R/H | `source consumer: let copied = native.copy_out(UserVa::new(clear_child_tid), &CHILD_TID_CLEAR); let woken = copied && native.wake_child_tid(EntryMmKey::from_raw(mm), UserVa::new(clear_child_tid)); if !woken { native.set_result(status); return decline!(if copied {` |

### `carrick-personality-linux/src/native_host_file.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 310 `HostFileUser::copy_in` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 401 `copy_in` | A+X R/H | `{ return Path :: Stage (HostFileStage :: Fault { address : cursor , access : Access :: Read , }) ; }` |
| 562 `copy_in` | A+X R/H | `{ return Err (HostFileStage :: Fault { address : iov , access : Access :: Read , }) ; }` |
| 589 `copy_in` | A+X R/H | `{ return Err (HostFileStage :: Fault { address : base , access : Access :: Read , }) ; }` |
| 637 `copy_in` | A+X R/H | `{ return Err (HostFileStage :: Fault { address : buf , access : Access :: Read , }) ; }` |
| 1008 `copy_in` | A+X R/H | `{ return Some (HostFileStage :: Fault { address : timeout , access : Access :: Read , }) ; }` |
| 1024 `copy_in` | A+X R/H | `{ return Some (HostFileStage :: Fault { address : fds , access : Access :: Read , }) ; }` |
| 1128 `copy_out` | A+X R/H | `{ return SyscallResult :: from_errno (carrick_syscall_abi :: LINUX_EFAULT) ; }` |

### `carrick-personality-linux/src/sched.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 157 `SchedVenue::copy_out` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 158 `SchedVenue::copy_in` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 227 `copy_out` | A+X R/H | `{ return FamilyCompletion :: Forward ; }` |
| 252 `copy_out` | A+X R/H | `{ return FamilyCompletion :: Complete (LINUX_EFAULT . guest_retval ()) ; }` |
| 269 `copy_in` | A+X R/H | `{ return FamilyCompletion :: Complete (LINUX_EFAULT . guest_retval ()) ; }` |

### `carrick-personality-linux/src/signal.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 517,732,756,777,806,814 `copy_in` | A+X R/H | `{ return returned (LINUX_EFAULT . guest_retval () , false) ; }` |
| 604,623,849 `copy_out` | A+X R/H | `{ return returned (LINUX_EFAULT . guest_retval () , false) ; }` |

### `carrick-personality-linux/src/sysinfo.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 299,369,390 `copy_in` | A+X R/H | `{ return Some (SyscallResult :: new (EFAULT)) ; }` |
| 324,354,410,435,453,467 `copy_out` | A+X R/H | `{ return Some (SyscallResult :: new (EFAULT)) ; }` |

### `carrick-el1-linux/src/aarch64_process.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 1550 `copy_out` | A R | `source consumer: carrick_personality_linux::lifecycle::UserCopy::copy_out( &mut copy, UserVa::new(fence.selected().va.raw()), bytes, ) } } ` |
| 1637 `write_user_bytes` | A R | `source consumer: owner.write_user_bytes( UserWriteRequest { handle, address, bytes, slot: self.slot, }, &*live,` |
| 1668 `copy_out` | A R | `{ return Err (NativeProcessError :: Fault) ; }` |
| 2745 `copy_out` | A R | `{ Ok (()) }` |

### `carrick-el1-linux/src/arm_signal.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 265 `copy_in` | A R | `map_err(&#124; _ &#124; carrick_syscall_abi :: LINUX_EFAULT)` |
| 377 `copy_in` | A R | `{ return Err (ArchError :: InvalidFrame) ; }` |
| 417 `copy_out` | A R | `{ return Err (ArchError :: InvalidFrame) ; }` |

### `carrick-el1-linux/src/dispatch.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 982 `copy_in` | A+X R | `source consumer: file::UserCopy::copy_in(&mut self.0, dst, src) } fn writable(&mut self, dst: u64, len: usize) -> usize { self.0.validator.writable_bytes(dst, len) } } ` |
| 1062 `copy_out` | A+X R | `source consumer: self.inner.copy_out(dst_va, src) }  fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool { let copied = self.inner.copy_in(dst, src_va); if !copied && self.fault.is_none() { self.fault = Some(src_va); }` |
| 1066 `copy_in` | A+X R | `source consumer: let copied = self.inner.copy_in(dst, src_va); if !copied && self.fault.is_none() { self.fault = Some(src_va); } copied } } ` |
| 1256 `copy_out` | A+X R | `{ 0 }` |
| 2291 `copy_out` | A+X R | `{ FamilyCompletion :: Complete (result . raw ()) }` |
| 2500,2533 `copy_in` | A+X R | `{ return FamilyCompletion :: Complete (carrick_syscall_abi :: LINUX_EFAULT . guest_retval () ,) ; }` |
| 2589 `copy_in` | A+X R | `source consumer: user.copy_in(bytes, fds_ptr) }; if !copied { return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EFAULT.guest_retval()); } let host_entries = super::file_table::host_readiness_entries( self.fd_map, self.open_table,` |
| 3774 `copy_out` | A+X R | `source consumer: return user.copy_out(dst.raw(), src); } let Some(task) = self.current_tasks.get(self.frame.task_index()) else { return false; }; crate::file::UserCopy::copy_out( &mut crate::file::ValidatedCopy { task,` |
| 3779 `copy_out` | A+X R | `source consumer: crate::file::UserCopy::copy_out( &mut crate::file::ValidatedCopy { task, validator: &crate::file::HardwareValidator, }, dst.raw(), src, )` |
| 3791 `copy_in` | A+X R | `source consumer: return user.copy_in(dst, src.raw()); } let Some(task) = self.current_tasks.get(self.frame.task_index()) else { return false; }; crate::file::UserCopy::copy_in( &mut crate::file::ValidatedCopy { task,` |
| 3796 `copy_in` | A+X R | `source consumer: crate::file::UserCopy::copy_in( &mut crate::file::ValidatedCopy { task, validator: &crate::file::HardwareValidator, }, dst, src.raw(), )` |

### `carrick-el1-linux/src/exec_stage.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 44 `copy_in` | A+X R | `{ output . truncate (slice_start) ; return Ok (CopyStep :: Fault) ; }` |
| 152 `copy_in` | A+X R | `{ return Err (LINUX_EFAULT) ; }` |

### `carrick-el1-linux/src/file.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 198 `copy_in` | A+X R | `source consumer: self.inner.copy_in(dst, address) } fn copy_out(&mut self, address: u64, bytes: &[u8]) -> bool { if self.inner.copy_out(address, bytes) { return true; } if self.owner.is_some() { self.wait = Some(carrick_core::mm::transaction::CopyoutRequest {` |
| 201 `copy_out` | A+X R | `{ return true ; }` |

### `carrick-el1-linux/src/fork_loan.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 25 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes( loan.lifecycle.page.raw() as *mut u8, 0, core::mem::size_of::<ThreadLifecyclePage>(), ); core::ptr::write_bytes( loan.lifecycle.controls.raw() as *mut u8, 0,` |
| 30 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes( loan.lifecycle.controls.raw() as *mut u8, 0, core::mem::size_of::<ThreadControlSlot>() * (THREAD_POOL_ENTRIES + 1), ); } } ` |

### `carrick-el1-linux/src/inotify.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 58 `copy_from_user_guarded` | A+X R | `source consumer: copy_from_user_guarded( cur_task, path_buf.as_mut_ptr(), pathname_va as *const u8, to_copy, ) }; if !ok {` |
| 253 `copy_to_user_guarded` | A+X R | `source consumer: copy_to_user_guarded( cur_task, (buf_va + copied as u64) as *mut u8, temp.as_ptr(), drained, ) }; if !ok {` |

### `carrick-el1-linux/src/ipc.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 669 `copy_in` | A+X R | `{ release_pin (sched , OfdPin :: from_raw (op . pin) , region) ; return refuse (sched , IpcLeave :: CopyInFault) ; }` |

### `carrick-el1-linux/src/ipc/epoll.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 239 `copy_out` | A+X R | `{ let _ = region . epoll_restore (object , taken , & Finish) ; release_pin (sched , OfdPin :: from_raw (op . pin) , region) ; return leave (sched , IpcLeave :: EpollCopyOut , IpcServed :: Forward) ; }` |

### `carrick-el1-linux/src/lifecycle.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 88 `copy_in` | A+X R | `source consumer: return user.copy_in(dst, src.raw()); } let Some(task) = self.current_tasks.get(self.frame.task_index()) else { return false; }; crate::file::UserCopy::copy_in( &mut crate::file::ValidatedCopy { task,` |
| 93 `copy_in` | A+X R | `source consumer: crate::file::UserCopy::copy_in( &mut crate::file::ValidatedCopy { task, validator: &crate::file::HardwareValidator, }, dst, src.raw(), )` |
| 105 `copy_out` | A+X R | `source consumer: return user.copy_out(dst.raw(), src); } if !self.frame.arm_scheduler() && let Some(result) = self .process_venue() .and_then(&#124;venue&#124; venue.copy_out_owned(dst, src)) { return result.is_ok();` |
| 117 `copy_out` | A+X R | `source consumer: crate::file::UserCopy::copy_out( &mut crate::file::ValidatedCopy { task, validator: &crate::file::HardwareValidator, }, dst.raw(), src, )` |
| 874 `copy_out` | A+X R | `source consumer: self.0.copy_out(dst.raw(), src) } fn copy_in(&mut self, dst: &mut [u8], src: carrick_guest_arch::UserVa) -> bool { self.0.copy_in(dst, src.raw()) } } let mut adapter = Adapter(*user); return self.frame.restore_signal_frame(&mut adapter);` |
| 877 `copy_in` | A+X R | `source consumer: self.0.copy_in(dst, src.raw()) } } let mut adapter = Adapter(*user); return self.frame.restore_signal_frame(&mut adapter); } let Some(task) = self.current_tasks.get(task_idx) else { return Err(carrick_personality_linux::abi::signal::LINUX_EFAULT);` |
| 899 `copy_out` | A+X R | `source consumer: crate::file::UserCopy::copy_out(&mut self.0, dst.raw(), src) }  fn copy_in(&mut self, dst: &mut [u8], src: carrick_guest_arch::UserVa) -> bool { crate::file::UserCopy::copy_in(&mut self.0, dst, src.raw()) } } ` |
| 903 `copy_in` | A+X R | `source consumer: crate::file::UserCopy::copy_in(&mut self.0, dst, src.raw()) } }  #[cfg(test)] #[path = "lifecycle/tests.rs"] mod tests;` |

### `carrick-el1-linux/src/mm_portal/maintenance.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 410,420 `write_bytes` | A+X R | `map_err(&#124; _ &#124; MmError :: Core)` |

### `carrick-el1-linux/src/native_process_runtime.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 330 `write_bytes` | A+X R | `source consumer: self.0.as_mut_ptr().write_bytes(0, 1); self.0.set_len(1); Box::from_raw(Box::into_raw(self.0.into_boxed_slice()).cast::<T>()) } } }  pub fn try_box<T>(value: T) -> Result<Box<T>, NativeProcessError> {` |
| 5343 `copy_to_user_guarded` | A+X R | `source consumer: crate::file::copy_to_user_guarded( self.current, msgp.raw() as *mut u8, mtype_bytes.as_ptr(), 8, ) }; let text_ok = mtype_ok` |
| 5353 `copy_to_user_guarded` | A+X R | `source consumer: crate::file::copy_to_user_guarded( self.current, text_va.raw() as *mut u8, data.as_ptr(), data.len(), ) }); (mtype_ok, text_ok)` |
| 7416 `copyout_fault` | A+X R | `{ return CopyoutPreparation :: Unrouted (operation) ; }` |

### `carrick-el1-linux/src/native_process_runtime/service.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 578 `copyout_fault` | A+X R | `? propagates error to caller` |

### `carrick-el1-linux/src/x86_signal.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 139,140 `copy_out` | X R | `{ return Err (ArchError :: InvalidFrame) ; }` |
| 194,227,242 `copy_in` | X R | `{ return Err (ArchError :: InvalidFrame) ; }` |

### `carrick-el1/src/alloc.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 440 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes(ptr, (0xA0 + idx) as u8, 128); for j in 0..128 { if *ptr.add(j) != (0xA0 + idx) as u8 { GLOBAL_ALLOCATOR.deallocate(ptr, layout); return 130 + idx as u64; } } }` |
| 476 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes(ptr, 0x30, allocation_size); for offset in (0..allocation_size).step_by(4096) { if *ptr.add(offset) != 0x30 { GLOBAL_ALLOCATOR.deallocate(ptr, allocation_layout); return 202; } } }` |
| 503 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes(p, (0x50 + i) as u8, chunk_size); } *slot = p; }  let big_layout = match Layout::from_size_align(2 * 1024 * 1024, 64) { Ok(l) => l, Err(_) => return 302,` |
| 569 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes(retry_p, 0x88, 2 * 1024 * 1024); for j in (0..2 * 1024 * 1024).step_by(4096) { if *retry_p.add(j) != 0x88 { GLOBAL_ALLOCATOR.deallocate(retry_p, big_layout); for &to_free in ptrs.iter() { GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout); } return 306;` |
| 759 `copy_to_user_guarded` | A+X R | `source consumer: unsafe { crate::substrate::file::copy_to_user_guarded(task, guard as *mut u8, &byte, 1) }; u64::from(copied) }` |

### `carrick-el1/src/file.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 341 `UserCopy::copy_out` | A+X R | `bool: not-yet indistinguishable from fault; see interface table` |
| 343 `UserCopy::copy_in` | A+X R | `bool: not-yet indistinguishable from fault; see interface table` |
| 359 `copy_to_user_guarded` | A+X R | `source consumer: unsafe { copy_to_user_guarded(self.task, dst_va as *mut u8, src.as_ptr(), src.len()) } }  fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool { if self.validator.readable_bytes(src_va, dst.len()) < dst.len() { return false; }` |
| 368 `copy_from_user_guarded` | A+X R | `source consumer: copy_from_user_guarded(self.task, dst.as_mut_ptr(), src_va as *const u8, dst.len()) } } } ` |
| 433,470 `copy_out` | A+X R | `{ return Err (FileError :: Forward) ; }` |
| 560 `write_bytes` | A+X R | `source consumer: core::ptr::write_bytes( cache_base.add(old_size as usize), 0, (at - old_size) as usize, ); } mark_gap_zero_pages(file, old_size, at); }` |
| 608,649 `copy_in` | A+X R | `? propagates error to caller` |

### `carrick-el1/src/isa/aarch64.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 382 `copy_from_user_guarded` | A R | `source consumer: crate::substrate::file::copy_from_user_guarded( task, kptr, cur_user as *const u8, chunk_len, ) } }` |
| 396 `copy_to_user_guarded` | A R | `source consumer: crate::substrate::file::copy_to_user_guarded( task, cur_user as *mut u8, kptr, chunk_len, ) } }` |

### `carrick-el1/src/isa/x86/initial_mm.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 298 `InitialFrameSource::copy_guest_data` | X R | `bool: not-yet indistinguishable from fault; see interface table` |

### `carrick-el1/src/isa/x86/user_access.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 404,435 `read_user_word` | X R | `unwrap_or((- 14_i64) as u64)` |
| 412 `copy_from_user_guarded` | X R | `source consumer: crate::substrate::file::copy_from_user_guarded( task, (&raw mut word).cast(), address as *const u8, 8, ) }; if ok { word } else { (-14_i64) as u64 }` |
| 426 `copy_to_user_guarded` | X R | `source consumer: crate::substrate::file::copy_to_user_guarded( task, address as *mut u8, (&raw const word).cast(), 8, ) }; if ok { 0 } else { (-14_i64) as u64 }` |
| 478,509 `copy_user_chunk` | X R | `source consumer: let first = backend.copy_user_chunk(&mut transfer, GuestLen::new(4)); let second = backend.copy_user_chunk(&mut transfer, GuestLen::new(4)); match (first, second) { (Ok(a), Ok(b)) if a.completed.raw() == 4 && a.remaining.raw() == 4 && b.completed.raw() == 4 && b.remaining.raw() == 0 =>` |
| 479,510 `copy_user_chunk` | X R | `source consumer: let second = backend.copy_user_chunk(&mut transfer, GuestLen::new(4)); match (first, second) { (Ok(a), Ok(b)) if a.completed.raw() == 4 && a.remaining.raw() == 4 && b.completed.raw() == 4 && b.remaining.raw() == 0 => {` |
| 546 `copy_user_chunk` | X R | `is_err(); source consumer: let refused = super::X86Backend .copy_user_chunk(&mut transfer, GuestLen::new(8)) .is_err(); changed.store(old, Ordering::Release); if refused && word == 0 { 0 } else { (-14_i64) as u64` |
| 556 `read_user_word` | X R | `Err (ArchError :: Unbound) => 0 ,; _ => (- 14_i64) as u64 ,` |
| 560 `read_user_word` | X R | `Err (ArchError :: InvalidWidth) => 0 ,; _ => (- 14_i64) as u64 ,` |

### `carrick-el1/src/substrate/ipc.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 91 `copy_out` | A+X R | `source consumer: let n = Self::pieces(va, src.len(), &#124;at, r&#124; user.copy_out(at, &src[r])); self.copied += n; n }  pub fn copy_in(&mut self, dst: &mut [u8], va: u64) -> usize { let user = &mut *self.user;` |
| 100 `copy_in` | A+X R | `source consumer: let n = Self::pieces(va, len, &#124;at, r&#124; user.copy_in(&mut dst[r], at)); self.copied += n; n } }  #[derive(Clone, Copy, Debug, Eq, PartialEq)]` |
| 143 `copy_out` | A+X R | `source consumer: let n = copy.copy_out(base.wrapping_add(at), chunk); at += n as u64; n }); owe(step.wake); match step.result { Ok(0) => StepStatus::EndOfFile, Ok(n) => {` |
| 165 `copy_in` | A+X R | `source consumer: copy.copy_in(dst, buf.wrapping_add(at as u64)) }); owe(step.wake); match step.result { Ok(_) if op.progress.is_complete() => break StepStatus::Complete, Ok(_) => continue, Err(e) => break blocked_or(e)?, }` |
| 179 `copy_out` | A+X R | `source consumer: copy.copy_out(buf, &bytes) == bytes.len() }); owe(step.wake); match step.result { Ok(_) => { op.progress.written = op.progress.len; StepStatus::Complete }` |

### `carrick-core/src/file.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 220 `copy_out` | A+X R/H | `Err (_) => Err (IoError :: Fault) . into () ,` |
| 234 `copy_in` | A+X R/H | `is_err(); source consumer: if self.cx.user().copy_in(src, &mut bytes).is_err() { return Err(IoError::Fault).into(); } match self.cx.file_service.as_deref_mut() { Some(fs) => fs.write_at(pin, at, &bytes), None => Err(IoError::Unsupported).into(), } }` |

### `carrick-core/src/mm/reservation/root_storage.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 251 `write_bytes` | A+X R/H | `source consumer: unsafe { core::ptr::write_bytes(ptr, 0, bytes) }; self.storage .publishing .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) .map_err(&#124;_&#124; Refusal::Busy)?; if self.storage.capacity() != expected_capacity { self.storage.publishing.store(0, Ordering::Release); return Err(Refusal::Busy);` |

### `carrick-core/src/mm/transaction/user_write.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 110 `UserWriteVenue::copy` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 205 `copy` | A+X R/H | `{ return Err (UserWriteError :: Fault) ; }` |

### `carrick-core/src/personality.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 200,270 `copy_user_chunk` | A+X R/H | `? propagates error to caller` |
| 286 `copy_in` | A+X R/H | `source consumer: self.copy_in(src, dst) }  pub fn copy_out_bytes( &mut self, dst: UserVa, src: &[u8],` |
| 295 `copy_out` | A+X R/H | `source consumer: self.copy_out(dst, src) } }  pub trait UserCopy { fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool; fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool;` |
| 301 `UserCopy::copy_in` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 302 `UserCopy::copy_out` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 368 `copy_in` | A+X R/H | `then_some(val)` |
| 430 `UserCopy::write_val` | A+X R/H | `bool: not-yet indistinguishable from fault; see interface table` |
| 438 `copy_out` | A+X R/H | `source consumer: self.copy_out(dst, val.as_bytes()) } }  impl<U: UserCopy + ?Sized> UserCopy for &mut U { #[inline] fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool { (**self).copy_in(dst, src)` |
| 445 `copy_in` | A+X R/H | `source consumer: (**self).copy_in(dst, src) }  #[inline] fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool { (**self).copy_out(dst, src) } }` |
| 450 `copy_out` | A+X R/H | `source consumer: (**self).copy_out(dst, src) } }  impl<'a, A: MmuArch + DefaultMmOwner> UserCopy for UserMemory<'a, A> where ServiceError: From<A::Error>, {` |
| 459 `copy_in_bytes` | A+X R/H | `is_ok(); source consumer: self.copy_in_bytes(src, dst).is_ok() }  fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool { self.copy_out_bytes(dst, src).is_ok() } } ` |
| 463 `copy_out_bytes` | A+X R/H | `is_ok(); source consumer: self.copy_out_bytes(dst, src).is_ok() } }  pub trait PersonalityAbi<A: EntryArch>: Send + Sync { type Call;` |

### `carrick-kernel/src/dispatch/bpf.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 416,438,453,454,464,472,492 `read_bytes` | A+X H | `? propagates error to caller` |
| 440,474 `copyout_bpf_bytes` | A+X H | `Err (refusal) => Ok (refusal . into_outcome ()) ,` |
| 498 `read_guest_c_string_bytes` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/copyout.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 196 `read_bytes` | A+X H | `Err (error) => match CopyoutRefusal :: from_read_error (error) { Some (refusal) => Err (refusal) , None => Ok (Err (CopyoutFault)) , } ,` |
| 457 `write_bytes` | A+X H | `map_err(&#124; _ &#124; CopyoutFault)` |

### `carrick-kernel/src/dispatch/creds.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 1090 `read_bytes` | A+X H | `? propagates error to caller` |
| 1181,1194 `read_bytes` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |

### `carrick-kernel/src/dispatch/execution.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 423,662 `read_bytes` | A+X H | `{ let mut le = [0u8 ; 8] ; le . copy_from_slice (& bytes [.. 8]) ; crate :: probes :: mem_watch (request . number . raw () , addr , u64 :: from_le_bytes (le)) ; }` |

### `carrick-kernel/src/dispatch/format_stat.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 37,84,151 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/format_time.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 32 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 547 `read_kernel_struct` | A+X H | `Err (errno) => return DispatchOutcome :: Errno { errno } ,` |
| 556,573,590,856 `copyout_format_time_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 992 `read_kernel_struct` | A+X H | `source consumer: read_kernel_struct(memory, address) }  pub(super) fn read_itimerval( memory: &impl CurrentMmMemory, address: u64, ) -> Result<LinuxItimerval, LinuxErrno> { read_kernel_struct(memory, address)` |
| 999 `read_kernel_struct` | A+X H | `source consumer: read_kernel_struct(memory, address) }  pub(super) fn read_timespec( memory: &impl CurrentMmMemory, address: u64, ) -> Result<LinuxTimespec, LinuxErrno> { read_kernel_struct(memory, address)` |
| 1006 `read_kernel_struct` | A+X H | `source consumer: read_kernel_struct(memory, address) } ` |

### `carrick-kernel/src/dispatch/fs.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 417 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (Some (GatheredIovecOutcome :: Suspended { bytes , next_iovec : index + 1 , suspension , })) ; }; Err (_) => { faulted = true ; break ; }` |
| 873,977 `copyout_bytes_from_offset` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 1065,1086,2659 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 1623 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 2645 `read_bytes` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/fs/access.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 23 `read_guest_c_string` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/fs/attr.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 130,421,543,608 `read_guest_c_string` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/fs/directory.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 258 `write_bytes` | A+X H | `map_err(carrick_guest_mem :: MemoryPrepareError :: Fault)` |
| 584,585,848,986,1155,1302,1303,1493,1497,1595 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 979 `write_bytes` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/fs/ioctl.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 62,78,188,970,1123,1228,1322,1445,1564,1666,1791,1858,1894,1924,1949,2048,2067,2076,2109 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 176 `read_kernel_prefix` | A+X H | `Err (errno) => return DispatchOutcome :: errno (errno) ,` |
| 211 `read_kernel_struct` | A+X H | `Err (errno) => return DispatchOutcome :: errno (errno) ,` |
| 868,996,1548 `copyout_termios2` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 872,924,1000,1052,1505,1550 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 895,911,932,1023,1061,1622 `read_bytes` | A+X H | `Err (_) => DispatchOutcome :: errno (LINUX_EFAULT) ,` |
| 980,1140,1684 `read_bytes` | A+X H | `Err (_) => { return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 1279,1706 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 1339,1800,1838,1876,2031 `read_bytes` | A+X H | `{ return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 1972 `read_struct` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |

### `carrick-kernel/src/dispatch/fs/legacy_aio.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 133 `read_struct` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 326 `read_bytes` | A+X H | `is_err(); source consumer: &#124;&#124; cx.memory.read_bytes(result.0, 32).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } let Some(ctx) = LegacyAioContextId::from_guest(raw_ctx) else { return Ok(DispatchOutcome::errno(LINUX_EINVAL)); }; if !legacy_aio_context_exists(this, ctx) {` |

### `carrick-kernel/src/dispatch/fs/locks.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 138 `read_struct` | A+X H | `Err (_) => return DispatchOutcome :: errno (LINUX_EFAULT) ,` |
| 258 `read_struct` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 1156 `copyout_bytes` | A+X H | `{ return FsView :: copyout_bytes (context , memory , arg , & (LINUX_F_UNLCK as i16) . to_le_bytes () , DispatchOutcome :: Returned { value : 0 } ,) ; }` |
| 1192,2181 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 2155 `read_struct` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/fs/mount.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 81 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 92,103 `read_guest_c_string` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/fs/notify.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 299 `read_guest_c_string` | A+X H | `{ crate :: el1_inotify :: populate_name_cache (file_table_id . raw () , raw_path . as_bytes () , file_handle ,) ; if raw_path != path { crate :: el1_inotify :: populate_name_cache (file_table_id . raw () , path . as_bytes () , file_handle ,) ; } }` |
| 370,668 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 778 `write_bytes` | A+X H | `is_err(); source consumer: if req.memory.write_bytes(req.address, &bytes).is_err() { for fd in opened { this.close_fd_for_internal_rollback(fd); } req.group.requeue_front(events); return Ok(DispatchOutcome::errno(LINUX_EFAULT));` |

### `carrick-kernel/src/dispatch/fs/open.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 159,2516 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 2474,2565 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |

### `carrick-kernel/src/dispatch/fs/pipe.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 866 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address + offset as u64, bytes).is_err() { return 0; } offset += bytes.len(); bytes.len() }); match result { Ok(count) => DispatchOutcome::returned_len_or_errno(count),` |

### `carrick-kernel/src/dispatch/fs/rw.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 357 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (ReadIovecsOutcome :: Suspended { iovecs , total , suspension , }) ; }; Err (error) => return Err (IovecReadError :: Memory (Box :: new (error))) ,` |
| 421 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (PwritevPrepareOutcome :: Suspended { staged_iovecs , next_iovec : idx + 1 , suspension , }) ; }; Err (_) => return Err (LINUX_EFAULT) ,` |
| 734,1983 `write_bytes` | A+X H | `? propagates error to caller` |
| 1491 `read_bytes` | A+X H | `Err (_) => { drop (open) ; return Ok (DispatchOutcome :: errno (carrick_abi :: LINUX_EIO)) ; }` |
| 1589 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address, &bytes).is_err() { DispatchOutcome::errno(LINUX_EFAULT) } else { DispatchOutcome::returned_len_or_errno(bytes.len()) } } Err(errno) => DispatchOutcome::errno(errno), });` |
| 1670 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address, &staged).is_err() { self.restore_splice_pipe_bytes(task.fd.0, &staged); return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } return Ok(DispatchOutcome::returned_len_or_errno(staged.len())); } let outcome = read_host_pipe( task.kernel,` |
| 1772 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address, &buf[..read_len]).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } return Ok(DispatchOutcome::returned_len_or_errno(read_len)); } else { return Ok(DispatchOutcome::Returned { value: 0 }); } }` |
| 3300 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(iov.iov_base, &buf[..read_len]).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } total += read_len as i64; if read_len < len { break; } } else {` |
| 4945 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (self . suspend_write_copy_in (target , OwnedCopyInOperation :: Writev (WritevCopyInState { iovecs , nonblocking , phase : WritevCopyInPhase :: EventFd { state , index , total , } , }) , * suspension ,)) ; }; Err (_) => { return Ok (if total == 0 { DispatchOutcome :: errno (LINUX_EFAULT) } else { DispatchOutcome :: returned_len_or_errno (total) }) ; }` |
| 5067 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (self . suspend_write_copy_in (target , OwnedCopyInOperation :: Writev (WritevCopyInState { iovecs , nonblocking , phase : WritevCopyInPhase :: EventFdTail { state , first_value , tail , next_iovec : index + 1 , total , } , }) , * suspension ,)) ; }; Err (_) => break ,` |
| 5344 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (self . suspend_write_copy_in (target , OwnedCopyInOperation :: Writev (WritevCopyInState { iovecs , nonblocking , phase : WritevCopyInPhase :: PerIovec { iovec_index , total } , }) , * suspension ,)) ; }; Err (_) => { if total > 0 { return Ok (DispatchOutcome :: returned_len_or_errno (total)) ; } return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 5786 `read_bytes` | A+X H | `Err (MemoryError :: ReadSuspended (suspension)) => { return Ok (self . suspend_write_copy_in (target , OwnedCopyInOperation :: Writev (WritevCopyInState { iovecs , nonblocking , phase : WritevCopyInPhase :: BlockingWriteTail { write , current_iovec_len , tail , next_iovec : rem_index + 1 , total , } , }) , * suspension ,)) ; }; Err (_) => { let boundary = writev_pipe_fault_boundary (total , current_iovec_len , tail . len ()) ; let write = match & write . target { crate :: dispatch :: outcome :: BlockingWriteTarget :: InMemoryPipe (_) => { write . with_in_memory_pipe_writev_boundary (tail , total , boundary) } crate :: dispatch :: outcome :: BlockingWriteTarget :: Host (_) => { write . with_writev_tail (tail , total) } crate :: dispatch :: outcome :: BlockingWriteTarget :: EventFd (_) => write , } ; return Ok (DispatchOutcome :: BlockingWrite (write)) ; }` |

### `carrick-kernel/src/dispatch/fs/sendfile.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 418 `write_bytes` | A+X H | `is_err(); source consumer: } else if memory .write_bytes(offset_address, &(new_off as u64).to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } Ok(DispatchOutcome::returned_len_or_errno(sent)) };` |
| 537 `write_bytes` | A+X H | `is_err(); source consumer: } else if memory .write_bytes(offset_address, &(offset as u64).to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); }  Ok(DispatchOutcome::returned_len_or_errno(written_total))` |
| 655 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } n };` |
| 685 `write_bytes` | A+X H | `is_err(); source consumer: } else if memory .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); }  Ok(DispatchOutcome::returned_len_or_errno(written))` |

### `carrick-kernel/src/dispatch/fs/stat.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 308,751 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 337,362 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 587,603,630,659,691 `read_guest_c_string_before_effects` | A+X H | `Err (error) => return Ok (error . into_outcome ()) ,` |
| 779 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 792 `read_bytes` | A+X H | `is_err(); source consumer: if cx.memory.read_bytes(mount_id.0, mount_width).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); }  let mut encoded = [0u8; 24]; encoded[..4].copy_from_slice(&HANDLE_BYTES.to_le_bytes()); encoded[4..8].copy_from_slice(&HANDLE_TYPE_CARRICK_FID.to_le_bytes()); let filesystem = match record.fs_identity {` |

### `carrick-kernel/src/dispatch/fs/transfer.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 473 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes()) .is_err() { return DispatchOutcome::errno(LINUX_EFAULT); } DispatchOutcome::returned_len_or_errno(n) }` |
| 1628 `write_bytes` | A+X H | `is_err(); source consumer: } else if memory .write_bytes(off_in_address, &(offset as u64).to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); }  Ok(DispatchOutcome::Returned { value })` |
| 1784 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(v.iov_base, &bytes[off..off + len]) .is_err() { bytes.commit(off); return Ok(if off == 0 { DispatchOutcome::errno(LINUX_EFAULT) } else { DispatchOutcome::returned_len_or_errno(off) }); }` |

### `carrick-kernel/src/dispatch/fs/xattr.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 24,79,165,241 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 121 `read_bytes` | A+X H | `map_err(&#124; _ &#124; DispatchError :: Errno (LINUX_EFAULT))` |
| 175,220 `copyout_bytes_with_kind` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/futex.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 716 `read_bytes` | A+X H | `Err (_) => { return DispatchOutcome :: Errno { errno : LINUX_EFAULT , } ; }` |

### `carrick-kernel/src/dispatch/io_buffers.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 63 `write_bytes` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 72 `read_kernel_struct` | A+X H | `source consumer: read_kernel_struct(memory, address) }  pub(crate) fn read_iovecs( memory: &impl CurrentMmMemory, address: u64, count: usize, ) -> Result<Vec<LinuxIovec>, LinuxErrno> {` |
| 98 `read_kernel_struct` | A+X H | `? propagates error to caller` |
| 181 `write_bytes` | A+X H | `is_ok(); source consumer: return if memory.write_bytes(address, bytes).is_ok() { bytes.len() } else { 0 }; } let mut copied = 0usize; while copied < bytes.len() {` |
| 193 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(at, &bytes[copied..copied + step]) .is_err() { break; } copied += step; }` |
| 272 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(iovec.iov_base, &zeroes).is_err() { return Ok(total); } total += iov_len; } } SyntheticDeviceKind::Random &#124; SyntheticDeviceKind::Urandom => { for iovec in iovecs {` |
| 286 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(iovec.iov_base, &buf).is_err() { return Ok(total); } total += iov_len; } } } Ok(total)` |
| 347 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address, &buf[..read_len]).is_err() { return Ok(total); } offset += read_len; iov_done += read_len; total = total .checked_add(read_len) .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;` |

### `carrick-kernel/src/dispatch/io_pipe.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 384 `write_bytes` | A+X H | `is_err(); source consumer: if n_usize > 0 && memory.write_bytes(guest_addr, &buf[..n_usize]).is_err() { let delivered = deliver_writable_prefix(memory, guest_addr, &buf[..n_usize]);` |
| 424 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(cursor, &bytes[delivered..delivered + chunk]) .is_err() { break; } delivered += chunk; }` |

### `carrick-kernel/src/dispatch/ioring.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 513 `write_bytes` | A+X H | `source consumer: self.control_view.write_bytes(offset, value.as_bytes()) }  fn cross_process_lock(&self) -> Option<CrossProcessLock<'_>> { let mut lock: libc::flock = unsafe { core::mem::zeroed() }; lock.l_type = libc::F_WRLCK as libc::c_short; lock.l_whence = libc::SEEK_SET as i16; lock.l_start = 0;` |
| 711 `read_bytes` | A+X H | `ok(); source consumer: let bytes = memory .read_bytes(addr, core::mem::size_of::<LinuxMsghdr>()) .ok()?; let (mh, _) = LinuxMsghdr::read_from_prefix(&bytes).ok()?; let (iov, iovlen) = (mh.iov, mh.iovlen); // copy packed fields to locals read_iovecs(memory, iov, iovlen as usize) } ` |
| 755 `read_bytes` | A+X H | `ok(); source consumer: memory .read_bytes(addr, 4) .ok() .and_then(&#124;b&#124; <[u8; 4]>::try_from(b.as_slice()).ok()) .map(u32::from_ne_bytes) .unwrap_or(0) } ` |
| 764 `write_bytes` | A+X H | `ignored result (let _)` |
| 775 `read_bytes` | A+X H | `ok(); source consumer: let bytes = memory.read_bytes(addr + (i as u64) * 16, 16).ok()?; let (iov, _) = LinuxIovec::read_from_prefix(&bytes).ok()?; out.push(iov); } Some(out) } ` |
| 788 `read_bytes` | A+X H | `map_err(&#124; _ &#124; ())` |
| 810 `write_bytes` | A+X H | `map_err(&#124; _ &#124; ())` |
| 830 `read_bytes` | A+X H | `ok(); source consumer: let Some(user_params) = memory .read_bytes(params_ptr, core::mem::size_of::<LinuxIoUringParams>()) .ok() .and_then(&#124;b&#124; { LinuxIoUringParams::read_from_prefix(&b) .ok() .map(&#124;(params, _)&#124; params) })` |
| 850 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(params_ptr, params.as_bytes()).is_err() { return DispatchOutcome::errno(LINUX_EFAULT); }  let common = Arc::new(crate::kernel::DescriptionCommon::new(LINUX_O_RDWR)); let description = match crate::kernel::FileDescription::concrete_with_common(backing, common) { Ok(desc) => Arc::new(desc),` |
| 1034 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(sqe.addr, &buf[..got]).is_err() { return cqe_err(LINUX_EFAULT); } got as i32 } Err(e) => cqe_err(e), } }` |
| 1050 `read_bytes` | A+X H | `{ return cqe_err (LINUX_EFAULT) ; }` |
| 1226 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(sqe.addr, &buf[..got]).is_err() { return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT)); } AsyncOutcome::Ready(got as i32) } Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd.get(), libc::POLLIN), Err(e) => AsyncOutcome::Ready(cqe_err(e)), }` |
| 1239 `read_bytes` | A+X H | `{ return AsyncOutcome :: Ready (cqe_err (LINUX_EFAULT)) ; }` |

### `carrick-kernel/src/dispatch/keys.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 206 `read_guest_c_string_bytes` | A+X H | `? propagates error to caller` |
| 225 `read_bytes` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/mem.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 2216 `read_bytes_raw` | A+X H | `Err (_) => return Err (rollback (self , memory , LINUX_EFAULT)) ,` |

### `carrick-kernel/src/dispatch/mem/backing.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 1572 `read_bytes` | A+X H | `ok(); source consumer: memory.read_bytes(alloc.guest_addr, len).ok() }  pub(crate) fn writeback_shared_snapshot( &self,` |

### `carrick-kernel/src/dispatch/mem/host_first_touch.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 346 `copyout_grant_piece` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/mem/madvise.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 79 `read_bytes` | A+X H | `is_err(); source consumer: if memory.read_bytes(page, 1).is_err() { return Err(LINUX_ENOMEM); } page = page.checked_add(page_size).ok_or(LINUX_ENOMEM)?; } Ok(()) } ` |
| 483 `read_bytes` | A+X H | `is_err(); source consumer: if cx.memory.read_bytes(address.0, 1).is_err() { return Ok(DispatchOutcome::errno(LINUX_ENOMEM)); } Ok(DispatchOutcome::Returned { value: 0 }) }  mm_mutation fn mlock(this, cx, address: GuestPtr, length: u64) { let permit = cx.mm_mutation.host_alias_permit();` |
| 638 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/mem/mmap.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 1478 `read_bytes_raw` | A+X H | `is_ok(); source consumer: && memory.read_bytes_raw(address, 1).is_ok(); let owner_host_snapshot = memory.supports_lazy_anonymous_mmap() && this.mem().lock().delegated_root().is_some()` |
| 2795 `read_bytes` | A+X H | `is_err(); source consumer: if !source_in_arena && memory.read_bytes(old_address.0, 1).is_err() { return Ok(DispatchOutcome::errno(LINUX_EINVAL)); } let source_metadata = match this.mremap_mapping_metadata(memory, old_address.0, old_size) { Ok(metadata) => metadata, Err(errno) => return Ok(DispatchOutcome::errno(errno)), }; let is_shared_file_fixed = move_fixed` |
| 3324 `read_bytes` | A+X H | `is_err(); source consumer: if memory.read_bytes(old_address.0, 1).is_err() { return Ok(DispatchOutcome::errno(LINUX_EINVAL)); }` |
| 3991 `read_bytes_raw` | A+X H | `is_err(); source consumer: && cx.memory.read_bytes_raw(address.0, 1).is_err(); let hole_site = if metadata_says_unmapped { crate::mprotect_diag::MprotectEnomemSite::RegistryUnmapped } else if incomplete_backend_says_unmapped { crate::mprotect_diag::MprotectEnomemSite::BackendProbeUnmapped } else { crate::mprotect_diag::MprotectEnomemSite::LazyAliasNotCommitted };` |
| 4356 `read_bytes` | A+X H | `{ return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 4364 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/mod.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 2563 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address, bytes).is_err() { DispatchOutcome::Errno { errno: LINUX_EFAULT, } } else { DispatchOutcome::Returned { value: 0 } } }` |
| 2602 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(arg, &payload).is_err() { return Some(DispatchOutcome::Errno { errno: LINUX_EFAULT, }); } Some(DispatchOutcome::Returned { value: 0 }) } ` |
| 2621 `write_packed` | A+X H | `source consumer: write_packed(memory, address, value.abi_bytes()) } ` |
| 2634 `write_packed` | A+X H | `source consumer: write_packed(memory, address, zerocopy::IntoBytes::as_bytes(value)) }  #[cfg(test)]` |
| 2660 `read_kernel_prefix` | A+X H | `source consumer: read_kernel_prefix(memory, address, T::ABI_SIZE) }  fn read_kernel_prefix<T>( memory: &impl CurrentMmMemory,` |
| 2677 `read_bytes` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 2690 `write_kernel_struct` | A+X H | `source consumer: write_kernel_struct(memory, statfsbuf, statfs) }  fn linux_fd_flags_from_open_flags(flags: u64) -> u64 { let open_flags = LinuxOpenFlags::from_bits_retain(flags); if open_flags.contains(LinuxOpenFlags::CLOEXEC) { LinuxFdFlags::CLOEXEC.bits() } else {` |
| 3140 `write_bytes` | A+X H | `is_ok(); source consumer: memory .write_bytes(address, LinuxEventfdValue { value }.as_bytes()) .is_ok() }) { Ok(_) => DispatchOutcome::returned_len_or_errno(core::mem::size_of::<LinuxEventfdValue>()), Err(LINUX_EAGAIN) => would_block_outcome(-1, libc::POLLIN, nonblocking, None, authority), Err(errno) => DispatchOutcome::errno(errno), }` |

### `carrick-kernel/src/dispatch/mount_api.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 287,330,339,457,500,546,558,635 `read_guest_c_string` | A+X H | `Err (errno) => return Ok (DispatchOutcome :: errno (errno)) ,` |
| 378 `read_bytes` | A+X H | `is_err(); source consumer: if (*cx.memory).read_bytes(value.0, aux as usize).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } state.stage(StagedParam::Binary { key: key_str.unwrap_or_default(), len: aux as u64, }); }` |
| 602,608 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |

### `carrick-kernel/src/dispatch/mqueue.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 772,848 `read_guest_c_string` | A+X H | `Err (errno) => return Ok (DispatchOutcome :: errno (errno)) ,` |
| 802,1034 `read_kernel_struct` | A+X H | `Err (errno) => return Ok (DispatchOutcome :: errno (errno)) ,` |
| 894,1071 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 1123 `read_bytes` | A+X H | `Err (error) => { return Ok (match super :: copyout :: CopyoutRefusal :: from_read_error (error) { Some (refusal) => refusal . into_outcome () , None => DispatchOutcome :: errno (LINUX_EFAULT) , }) ; }` |
| 1371 `read_bytes` | A+X H | `map_err(&#124; error &#124; match super :: copyout :: CopyoutRefusal :: from_read_error (error) { Some (refusal) => MqueueDeadlineError :: Refusal (refusal) , None => MqueueDeadlineError :: Fault (LINUX_EFAULT) , } ,)` |
| 1597 `write_bytes` | A+X H | `is_err(); source consumer: memory .write_bytes(address, &message.prio.to_le_bytes()) .is_err() }) &#124;&#124; (!message.payload.is_empty() && memory.write_bytes(buffer, &message.payload).is_err()) { return BlockingMqueueStep::Done(DispatchOutcome::errno(LINUX_EFAULT)); }` |
| 1601 `write_bytes` | A+X H | `is_err(); source consumer: && memory.write_bytes(buffer, &message.payload).is_err()) { return BlockingMqueueStep::Done(DispatchOutcome::errno(LINUX_EFAULT)); } BlockingMqueueStep::Done( DispatchOutcome::returned_len(message.payload.len()) .unwrap_or_else(&#124;_&#124; DispatchOutcome::errno(LINUX_EINVAL)), )` |

### `carrick-kernel/src/dispatch/net.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 2955 `read_struct` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 2960,3385 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 2996,3019 `read_kernel_struct` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 3342 `read_kernel_struct` | A+X H | `_ => 0 ,` |
| 3522 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/net/epoll_ops.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 4660,4746 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 4769 `read_kernel_struct` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |

### `carrick-kernel/src/dispatch/net/lifecycle.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 242 `read_bytes` | A+X H | `ok(); source consumer: memory .read_bytes(addr, addrlen as usize) .ok() .and_then(&#124;raw&#124; { if raw.len() > 2 && raw[2] != 0 { let nul = raw[2..] .iter() .position(&#124;&b&#124; b == 0)` |
| 1428 `write_linux_sockaddr` | A+X H | `is_err(); source consumer: if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() { return DispatchOutcome::errno(carrick_abi::LINUX_EFAULT); } } let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK); let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC); let status_flags = carrick_abi::LINUX_O_RDWR` |
| 1624 `write_linux_sockaddr` | A+X H | `is_err(); source consumer: if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() { crate::event_ring::rec( crate::event_ring::ACCEPTERR, host_fd, new_host, LINUX_EFAULT.get(), ); unsafe { libc::close(new_host) };` |
| 1738 `read_linux_sockaddr` | A+X H | `Err (errno) => return DispatchOutcome :: errno (errno) ,` |
| 2178,2355,3077,3129 `read_linux_sockaddr` | A+X H | `? propagates error to caller` |
| 2313 `read_bytes` | A+X H | `{ let nul = raw [2 ..] . iter () . position (&#124; & b &#124; b == 0) . map (&#124; p &#124; 2 + p) . unwrap_or (raw . len ()) ; if raw [.. nul] . last () == Some (& b'/') { return Ok (DispatchOutcome :: errno (linux_errno :: EADDRINUSE)) ; } }` |
| 3620 `read_bytes` | A+X H | `ok(); source consumer: && memory .read_bytes(addr_addr, 2) .ok() .map(&#124;b&#124; u16::from_ne_bytes([b[0], b[1]]) as i32 == LINUX_AF_UNSPEC) .unwrap_or(false); if is_unspec_disconnect && this.socket_guest_type(fd) == Some(LINUX_SOCK_STREAM) { match this.reset_host_stream_socket_for_disconnect(fd) { Ok(()) => return Ok(DispatchOutcome::Returned { value: 0 }),` |
| 3843,3864,3894,3902,3913,3943,3970,4004,4008 `copyout_linux_sockaddr` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/net/netlink.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 123 `write_bytes` | A+X H | `is_err(); source consumer: if !chunk.is_empty() && memory.write_bytes(buf_addr, &chunk).is_err() { return DispatchOutcome::errno(LINUX_EFAULT); } DispatchOutcome::returned_len_or_errno(chunk.len()) } ` |

### `carrick-kernel/src/dispatch/net/packet.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 277 `write_bytes` | A+X H | `ignored result (let _)` |
| 297,324,424,444,465 `read_bytes` | A+X H | `Err (_) => return DispatchOutcome :: errno (LINUX_EFAULT) ,` |
| 376 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(buf_addr, &pkt[..copy_len]).is_err() { return DispatchOutcome::errno(LINUX_EFAULT); } DispatchOutcome::returned_len_or_errno(copy_len) }  pub(crate) fn getsockopt<M: CurrentMmMemory>( &self,` |
| 511 `copyout_linux_sockaddr` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |

### `carrick-kernel/src/dispatch/net/send_recv.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 302 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes()) .is_err() { if sent > 0 { return DispatchOutcome::returned_i32(sent); } return DispatchOutcome::errno(LINUX_EFAULT);` |
| 367 `read_kernel_struct` | A+X H | `Err (_) => return DispatchOutcome :: errno (LINUX_EFAULT) ,` |
| 410 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes()) .is_err() { return DispatchOutcome::errno(LINUX_EFAULT); } received += 1; }` |
| 456 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendto { len , flags , dest_addr , dest_len , phase : SendtoCopyInPhase :: Payload , } , suspension : * suspension , } ,))) ; }; Err (_) => { return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 504,560,598,1200 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendto { len , flags , dest_addr , dest_len , phase : SendtoCopyInPhase :: Payload , } , suspension : * suspension , } ,))) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 539 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendto { len , flags , dest_addr , dest_len , phase : SendtoCopyInPhase :: DestCheck { buf_addr } , } , suspension : * suspension , } ,))) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 649 `write_linux_sockaddr` | A+X H | `ignored result (let _)` |
| 719 `write_bytes` | A+X H | `is_err(); source consumer: && memory .write_bytes(buf_addr, &target_buf[..read_len]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } if src_addr != 0 { if src_len_addr == 0 {` |
| 729,760,1074 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 736 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(src_len_addr, &0u32.to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } this.notify_inmem_epoll();` |
| 752 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(buf_addr, &target_buf[..read_len]).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } if src_addr != 0 { if src_len_addr == 0 { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); }` |
| 770 `write_linux_sockaddr` | A+X H | `is_err(); source consumer: if write_linux_sockaddr( memory, src_addr, src_len_addr, &sockaddr_bytes, ) .is_err() {` |
| 780 `write_bytes` | A+X H | `is_err(); source consumer: } else if memory .write_bytes(src_len_addr, &0u32.to_ne_bytes()) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } return Ok(DispatchOutcome::returned_len(read_len)?);` |
| 817 `write_bytes` | A+X H | `is_err(); source consumer: if take > 0 && memory.write_bytes(buf_addr, &payload[..take]).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } if src_addr != 0 && src_len_addr != 0 && write_linux_sockaddr(memory, src_addr, src_len_addr, &source).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT));` |
| 822 `write_linux_sockaddr` | A+X H | `is_err(); source consumer: && write_linux_sockaddr(memory, src_addr, src_len_addr, &source).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } return Ok(DispatchOutcome::returned_len(take)?); }` |
| 1054 `write_bytes` | A+X H | `is_err(); source consumer: && memory .write_bytes(buf_addr, &b[..(n as usize).min(len)]) .is_err() { return Err(LINUX_EFAULT); } if used_addr && src_addr != 0 && src_len_addr != 0 { let used = (sa_len as usize).min(sa.len());` |
| 1094 `write_linux_sockaddr` | A+X H | `is_err(); source consumer: if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } else if memory.write_bytes(src_len_addr, &0u32.to_ne_bytes()).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } Ok(outcome)` |
| 1097 `write_bytes` | A+X H | `is_err(); source consumer: } else if memory.write_bytes(src_len_addr, &0u32.to_ne_bytes()).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } Ok(outcome) }  fn sendmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {` |
| 1418 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { let mut payload = vec ! [0u8 ; len] ; copy_send_payload (& zc_read , send_copy . as_deref () , & mut payload) ; return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendto { len , flags , dest_addr , dest_len , phase : SendtoCopyInPhase :: ConnectedDestCheck { payload , is_unix_stream : false , } , } , suspension : * suspension , } ,))) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 1446 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { let mut payload = vec ! [0u8 ; len] ; copy_send_payload (& zc_read , send_copy . as_deref () , & mut payload) ; return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendto { len , flags , dest_addr , dest_len , phase : SendtoCopyInPhase :: ConnectedDestCheck { payload , is_unix_stream : true , } , } , suspension : * suspension , } ,))) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 1473 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { let mut payload = vec ! [0u8 ; len] ; copy_send_payload (& zc_read , send_copy . as_deref () , & mut payload) ; return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendto { len , flags , dest_addr , dest_len , phase : SendtoCopyInPhase :: Sockaddr { payload , family } , } , suspension : * suspension , } ,))) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 1787 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { if let Some (ctx_ids) = suspend_ctx { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target : make_target (ctx_ids) , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendmsg { flags , phase : SendmsgCopyInPhase :: Msghdr , } , suspension : * suspension , } ,))) ; } return Err (DispatchError :: Errno (LINUX_EFAULT)) ; }; Err (_) => return Err (DispatchError :: Errno (LINUX_EFAULT)) ,` |
| 1884 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { if let Some ((thread , tid)) = suspend_ctx { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target : crate :: dispatch :: fs :: rw :: WriteTarget { fd , tid , thread , open_file , slot_authority , io_lease , stdio_was_closed : false , } , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendmsg { flags , phase : SendmsgCopyInPhase :: Iovecs { msg , iovecs , total } , } , suspension : * suspension , } ,))) ; } return Err (DispatchError :: Errno (LINUX_EFAULT)) ; }; Err (_) => return Err (DispatchError :: Errno (LINUX_EFAULT)) ,` |
| 1964 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { if let Some ((thread , tid)) = suspend_ctx { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target : crate :: dispatch :: fs :: rw :: WriteTarget { fd , tid , thread , open_file , slot_authority , io_lease , stdio_was_closed : false , } , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendmsg { flags , phase : SendmsgCopyInPhase :: Payload { msg , iovecs , next_iovec : idx + 1 , data , } , } , suspension : * suspension , } ,))) ; } return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 2203 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { if let Some ((thread , tid)) = suspend_ctx { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target : crate :: dispatch :: fs :: rw :: WriteTarget { fd , tid , thread , open_file , slot_authority , io_lease , stdio_was_closed : false , } , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendmsg { flags , phase : SendmsgCopyInPhase :: Sockaddr { msg , data , family } , } , suspension : * suspension , } ,))) ; } return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }; Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 2255 `read_bytes` | A+X H | `Err (carrick_guest_mem :: MemoryError :: ReadSuspended (suspension)) => { if let Some ((thread , tid)) = suspend_ctx { return Ok (DispatchOutcome :: WriteCopyInSuspended (Box :: new (crate :: dispatch :: fs :: rw :: OwnedWriteCopyIn { target : crate :: dispatch :: fs :: rw :: WriteTarget { fd , tid , thread , open_file , slot_authority , io_lease , stdio_was_closed : false , } , op : crate :: dispatch :: fs :: rw :: OwnedCopyInOperation :: Sendmsg { flags , phase : SendmsgCopyInPhase :: Control { msg , data , host_addr , } , } , suspension : * suspension , } ,))) ; } return Err (DispatchError :: Errno (LINUX_EFAULT)) ; }; Err (_) => return Err (DispatchError :: Errno (LINUX_EFAULT)) ,` |
| 2570 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(msg.name, &offender[..take]).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } let _ = memory.write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64, &(offender.len() as u32).to_ne_bytes(), ); }` |
| 2573,2591,2595,2802,2807,2811,2847,2852,2856,3195,3199 `write_bytes` | A+X H | `ignored result (let _)` |
| 2588 `write_bytes` | A+X H | `is_err(); source consumer: if !control.is_empty() && memory.write_bytes(msg.control, &control).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } let _ = memory.write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64, &(control.len() as u64).to_ne_bytes(), ); let _ = memory.write_bytes(` |
| 2655 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(iov.iov_base, &target_buf[cursor..cursor + take]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } cursor += take; remaining -= take;` |
| 2675 `write_bytes` | A+X H | `is_err(); source consumer: && memory .write_bytes(msg.name, &sockaddr_bytes[..take]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } } if memory` |
| 2682 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64, &name_len.to_ne_bytes(), ) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT));` |
| 2701 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64, &written_controllen.to_ne_bytes(), ) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT));` |
| 2710 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64, &linux_flags.to_ne_bytes(), ) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT));` |
| 2782 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(iov.iov_base, &chunk[cursor..cursor + take]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } cursor += take; remaining -= take;` |
| 2796 `write_bytes` | A+X H | `is_err(); source consumer: && memory .write_bytes(msg.name, &nl[..write_len as usize]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } let _ = memory.write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,` |
| 2828 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(iov.iov_base, &payload[cursor..cursor + take]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } cursor += take; remaining -= take;` |
| 2841 `write_bytes` | A+X H | `is_err(); source consumer: && memory .write_bytes(msg.name, &source[..write_len as usize]) .is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } let _ = memory.write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,` |
| 3056 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes(iov.iov_base, &buf[cursor..cursor + chunk]) .is_err() { return Err(LINUX_EFAULT); } cursor += chunk; remaining -= chunk;` |
| 3071 `write_bytes` | A+X H | `is_err(); source consumer: && memory .write_bytes(msg.name, &linux_bytes[..write_len as usize]) .is_err() { return Err(LINUX_EFAULT); } if memory` |
| 3078 `write_bytes` | A+X H | `is_err(); source consumer: if memory .write_bytes( msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64, &(linux_bytes.len() as u32).to_ne_bytes(), ) .is_err() { return Err(LINUX_EFAULT);` |
| 3186 `write_bytes` | A+X H | `is_err(); source consumer: if !ctrl.is_empty() && memory.write_bytes(msg.control, &ctrl).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } written_controllen = ctrl.len() as u64; if scm_trunc &#124;&#124; ipv6_trunc &#124;&#124; cred_trunc { linux_flags &#124;= crate::linux_abi::LINUX_MSG_CTRUNC; } }` |

### `carrick-kernel/src/dispatch/net/sockopt.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 141,159,170,181,192,204,236,262,273,284,295,315 `read_bytes` | A+X H | `{ return DispatchOutcome :: errno (LINUX_EFAULT) ; }` |
| 653,846 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 693 `read_bytes` | A+X H | `{ let v = i32 :: from_ne_bytes ([b [0] , b [1] , b [2] , b [3]]) ; if let Some (open_file) = this . open_file (fd) && let Some (mut open) = crate :: kernel :: FileDescription :: write_for_io (& open_file . description) && let OpenDescription :: HostSocket { base , .. } = & mut * open { if optname == LINUX_SO_REUSEADDR { base . set_so_reuseaddr (v != 0) ; } else if optname == LINUX_SO_REUSEPORT { base . set_so_reuseport (v != 0) ; } else if optname == LINUX_SO_RCVBUF { base . set_so_rcvbuf (v) ; } else { base . set_so_sndbuf (v) ; } } }` |
| 714 `read_bytes` | A+X H | `{ if let Err (errno) = host_authority . set_ipv6_v6only (i32 :: from_ne_bytes ([b [0] , b [1] , b [2] , b [3]]) != 0) { return Ok (DispatchOutcome :: errno (errno)) ; } }` |
| 731 `read_bytes` | A+X H | `source consumer: && memory.read_bytes(optval_addr, 4).is_ok_and(&#124;b&#124; { i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0 }); if on { recverr::enable(host_fd.get(), level == LINUX_SOL_IPV6); } return Ok(DispatchOutcome::Returned { value: 0 }); }` |
| 756 `read_bytes` | A+X H | `{ let index = u32 :: from_ne_bytes ([b [0] , b [1] , b [2] , b [3]]) ; if let Some (open_file) = this . open_file (fd) && let Some (mut open) = crate :: kernel :: FileDescription :: write_for_io (& open_file . description) && let OpenDescription :: HostSocket { base , .. } = & mut * open { base . set_ipv6_multicast_if (index) ; } if index == 0 { return Ok (DispatchOutcome :: Returned { value : 0 }) ; } }` |
| 775 `read_bytes` | A+X H | `source consumer: && memory.read_bytes(optval_addr, 4).is_ok_and(&#124;b&#124; { i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0 }); if let Some(open_file) = this.open_file(fd) && let Some(mut open) = crate::kernel::FileDescription::write_for_io(&open_file.description) && let OpenDescription::HostSocket { base, .. } = &mut *open { base.set_so_passcred(on);` |
| 806 `read_bytes` | A+X H | `{ return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 893 `read_bytes` | A+X H | `ok(); source consumer: && memory .read_bytes(optval_addr, 4) .ok() .map(&#124;b&#124; i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0) .unwrap_or(false); if enable { let one: i32 = 1; unsafe {` |
| 935 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (a :: LINUX_EFAULT)) ,` |
| 978 `read_bytes` | A+X H | `Err (_) => { return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |

### `carrick-kernel/src/dispatch/net/support.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 99 `read_kernel_struct` | A+X H | `source consumer: LinuxGuestAbi::Aarch64 => read_kernel_struct(memory, address), LinuxGuestAbi::X86_64 => { let event: LinuxX8664EpollEvent = read_kernel_struct(memory, address)?; let events = event.events; let data = event.data; Ok(LinuxEpollEvent { events, _pad: 0,` |
| 101 `read_kernel_struct` | A+X H | `? propagates error to caller` |
| 324 `read_kernel_struct` | A+X H | `source consumer: read_kernel_struct(memory, address) }  pub(super) fn read_fd_set( memory: &impl CurrentMmMemory, address: u64, nfds: usize, ) -> Result<Vec<u8>, LinuxErrno> {` |
| 333,1660 `read_bytes` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 634 `read_bytes` | A+X H | `Err (_) => (0 , 0) ,` |
| 666 `write_bytes` | A+X H | `is_err(); source consumer: if memory.write_bytes(address, &chunk).is_err() { return DispatchOutcome::errno(LINUX_EFAULT); } DispatchOutcome::returned_len_or_errno(chunk.len()) }  fn push_rtattr(buf: &mut Vec<u8>, rta_type: u16, payload: &[u8]) {` |
| 1932 `read_bytes` | A+X H | `map_err(&#124; _ &#124; ())` |
| 1936,1940 `write_bytes` | A+X H | `map_err(&#124; _ &#124; ())` |
| 1971 `read_kernel_struct` | A+X H | `source consumer: read_kernel_struct(memory, addr) }  #[derive(::core::clone::Clone, ::core::marker::Copy)] pub(super) enum IoDir { Read,` |

### `carrick-kernel/src/dispatch/perf.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 550,556 `read_bytes` | A+X H | `{ return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |

### `carrick-kernel/src/dispatch/proc.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 451 `read_bytes` | A+X H | `Err (_) => Err (LINUX_EFAULT) ,` |
| 938,945,958 `read_bytes` | A+X H | `{ return DispatchOutcome :: errno (LINUX_EFAULT) ; }` |
| 1289 `read_kernel_prefix` | A+X H | `Err (_) => { return DispatchOutcome :: errno (LINUX_EFAULT) ; }` |
| 1300 `read_bytes` | A+X H | `Err (_) => return DispatchOutcome :: errno (LINUX_EFAULT) ,` |
| 1458 `read_bytes` | A+X H | `{ return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 2102 `read_bytes` | A+X H | `? propagates error to caller` |
| 2310,2672 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 3488,3512 `read_guest_c_string` | A+X H | `? propagates error to caller` |
| 3492,3493,3543,3544 `read_guest_string_array_bytes` | A+X H | `? propagates error to caller` |
| 3782 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 4044 `read_bytes` | A+X H | `Err (error) => { if copied == 0 { if let Some (refusal) = super :: copyout :: CopyoutRefusal :: from_read_error (error) { return Err (refusal) ; } } return fault (copied) ; }` |

### `carrick-kernel/src/dispatch/rootfs_helpers.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 323 `read_bytes` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 491 `read_guest_c_string_bytes_bounded` | A+X H | `source consumer: read_guest_c_string_bytes_bounded(memory, address, MAX_GUEST_PATH, LINUX_ENAMETOOLONG) }  fn read_guest_exec_string_bytes( memory: &impl CurrentMmMemory, address: u64, ) -> Result<Vec<u8>, LinuxErrno> { read_guest_c_string_bytes_bounded(memory, address, MAX_EXEC_STRING_BYTES, LINUX_E2BIG)` |
| 498 `read_guest_c_string_bytes_bounded` | A+X H | `source consumer: read_guest_c_string_bytes_bounded(memory, address, MAX_EXEC_STRING_BYTES, LINUX_E2BIG) }  pub(super) enum PathReadError { Errno(LinuxErrno), Refused(super::copyout::CopyoutRefusal),` |
| 633 `read_guest_c_string_bytes` | A+X H | `? propagates error to caller` |

### `carrick-kernel/src/dispatch/signal.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 1936 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 2044,2190 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 2055,2160,2242,2303 `read_bytes` | A+X H | `Err (_) => { return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ; }` |
| 2095 `read_bytes` | A+X H | `? propagates error to caller` |
| 2262,2289 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 2566 `read_bytes` | A+X H | `{ return DispatchOutcome :: errno (LINUX_EFAULT) ; }` |

### `carrick-kernel/src/dispatch/sysv.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 2457,2552,2580,3413,3447,3518,4197,4353,4484,4534 `copyout_bytes` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 2483,2626,3991,4145,4399 `read_bytes` | A+X H | `Err (_) => return Ok (DispatchOutcome :: errno (LINUX_EFAULT)) ,` |
| 3337 `write_bytes` | A+X H | `is_err(); source consumer: if cx .memory .write_bytes(msgp, &message.msg_type.raw().to_le_bytes()) .is_err() { return Err(LINUX_EFAULT); } if copy_len > 0` |
| 3345 `write_bytes` | A+X H | `is_err(); source consumer: && cx .memory .write_bytes(text_addr, &message.payload[..copy_len]) .is_err() { return Err(LINUX_EFAULT); } if !flags.contains(MsgOpFlags::COPY) {` |
| 3537,3543 `read_bytes` | A+X H | `map_err(&#124; _ &#124; LINUX_EFAULT)` |
| 4362 `write_bytes` | A+X H | `is_err(); source consumer: if cx.memory.write_bytes(arg, &out).is_err() { return Ok(DispatchOutcome::errno(LINUX_EFAULT)); } Ok(DispatchOutcome::Returned { value: 0 }) } LINUX_SETALL => { struct SetallPrepareWitness { guest_semid: GuestSemId,` |

### `carrick-kernel/src/dispatch/time.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 137 `read_bytes` | A+X H | `source consumer: self.complete_copy(memory.read_bytes(address.0, LinuxTimespec::ABI_SIZE)) }  fn complete_copy(self, result: Result<Vec<u8>, MemoryError>) -> DispatchOutcome { let bytes = match result { Ok(bytes) => bytes, Err(MemoryError::ReadSuspended(suspension)) => { return DispatchOutcome::SleepCopyInSuspended(Box::new(OwnedSleepCopyIn {` |
| 328,364,381,456,1042,1070,1111,1125 `copyout_record` | A+X H | `prepared output: typed refusal / continuation (no blanket errno collapse here)` |
| 640,1005 `read_bytes` | A+X H | `? propagates error to caller` |
| 670 `read_bytes` | A+X H | `ok(); source consumer: let tid = memory .read_bytes(sevp.0 + 16, 4) .ok() .map(&#124;b&#124; i32::from_le_bytes([b[0], b[1], b[2], b[3]])) .unwrap_or(0); if tid <= 0 { return Ok(DispatchOutcome::errno(LINUX_EINVAL)); }` |
| 1166 `read_bytes` | A+X H | `Err (error) => { return Ok (super :: copyout :: CopyoutRefusal :: from_read_error (error) . map_or_else (&#124; &#124; DispatchOutcome :: errno (LINUX_EFAULT) , &#124; refusal &#124; refusal . into_outcome ())) ; }` |

### `carrick-kernel/src/el1_delegation.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 1862 `write_bytes` | A+X H | `is_ok(); source consumer: landed &= self.memory.write_bytes(dst_va, &bytes).is_ok(); } landed } }  impl<M: carrick_guest_mem::CurrentMmMemory> carrick_el1::substrate::file::UserCopy for HostUserCopy<'_, M>` |
| 1883 `read_bytes` | A+X H | `_ => false ,` |

### `carrick-kernel/src/kernel/continuation/ipc.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 527 `read_bytes` | A+X H | `Err (_) => break ,` |
| 552 `write_bytes` | A+X H | `is_ok(); source consumer: landed &= memory.write_bytes(va, &bytes).is_ok(); } (landed, None) } } } } ` |

### `carrick-kernel/src/kernel/continuation/output.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 484 `read_bytes` | A+X H | `source consumer: AddressPhase::Start => memory.read_bytes(self.addrlen.0, 4), AddressPhase::Write => unreachable!(), }; let bytes = match result { Ok(bytes) => bytes, Err(MemoryError::ReadSuspended(suspension)) => { self.phase = AddressPhase::Read(suspension.continuation); return RetainedOutputCompletion {` |

### `carrick-kernel/src/network/socket_namespace.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 2177 `copy` | A+X H | `source consumer: let copied = io::copy(&mut inbound_clone, &mut outbound); let _ = outbound.shutdown(std::net::Shutdown::Write); copied }); let right = thread::spawn(move &#124;&#124; { let copied = io::copy(&mut outbound_clone, &mut inbound); let _ = inbound.shutdown(std::net::Shutdown::Write); copied` |
| 2182 `copy` | A+X H | `source consumer: let copied = io::copy(&mut outbound_clone, &mut inbound); let _ = inbound.shutdown(std::net::Shutdown::Write); copied }); let _ = left.join(); let _ = right.join(); Ok(()) }` |

### `carrick-x86/src/bringup_fns.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 641 `read_bytes` | X H | `Err (e) => { eprintln ! ("carrick-x86 write: guest read error: {e}") ; NEG_EINVAL }` |
| 690,697 `write_bytes` | X H | `ignored result (let _)` |
| 753 `read_bytes` | X H | `map_err(&#124; e &#124; TrapError :: Hypervisor (format ! ("writev iov[{i}]: {e}")))` |
| 769 `read_bytes` | X H | `map_err(&#124; e &#124; TrapError :: Hypervisor (format ! ("writev buf[{i}]: {e}")))` |
| 795 `write_bytes` | X H | `map_err(&#124; e &#124; TrapError :: Hypervisor (format ! ("read: guest write: {e}")))` |
| 1223 `read_bytes` | X H | `Err (_) => return LINUX_EFAULT . guest_retval () ,` |
| 1329 `write_bytes` | X H | `is_err(); source consumer: if engine .write_bytes(fds.raw() + (index * 8 + 6) as u64, &revents.to_le_bytes()) .is_err() { return LINUX_EFAULT.guest_retval(); } ready += i64::from(revents != 0); }` |

### `carrick-x86/src/engine.rs`

| Line(s) / operation | ISA / venue | Consumer / not-yet handling today |
|---|---|---|
| 403 `write_bytes` | X H | `map_err(&#124; _ &#124; carrick_guest_arch :: UserMemoryFault)` |
| 545 `write_bytes_raw` | X H | `source consumer: self.write_bytes_raw(address, bytes) }  fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {` |

## Supplementary boundaries outside the named-call vocabulary

| Site | ISA / venue | Not-yet handling today |
|---|---|---|
| `carrick-el1/src/sched.rs:217` UserWord and `carrick-el1-linux/src/sched.rs:114` adapter | A+X R | missing word is None; EL1 wait admission returns None at sched.rs:373-375; no typed wait |
| `carrick-x86/src/cpl0_lifecycle.rs:668,679` | X R | direct guarded-range raw copies return false on invalid range; valid aperture is eagerly backed |
| `carrick-personality-linux/src/native_host_file.rs:1128` callback | A+X R | false reply output => EFAULT (14), not supply |
| `carrick-kernel/src/kernel/mm_access/current_read.rs:50,137` | A+X H | owner read preparation returns typed read error; follow through CurrentMmMemory consumers above; not an independent bool trait |

</details>
