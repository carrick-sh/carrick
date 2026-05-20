# Split `dispatch.rs` by Subsystem — Implementation Plan (Goal #2)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Checkbox steps.
> **PRECONDITION:** Plan A merged (uniform handler contract — there is now ONE recipe to split along). Strongly prefer Plan C merged first too (constants already lifted to `linux_abi.rs`, so the file is smaller and the split moves only logic, not ABI noise).
> **CONCURRENCY:** Edits `src/dispatch.rs` exclusively — must NOT run concurrently with Plan B or Plan C. Serialize after them.

**Goal:** Break the ~12.5k-line `dispatch.rs` god-file into a `src/dispatch/` module directory split by subsystem (`fs`, `mem`, `signal`, `creds`, `net`, `time`, `proc`), behind the uniform `SyscallCtx<M>` contract — killing both the merge-conflict pressure and the "every handler borrows the whole world" problem.

**Architecture (two stages, both shippable):**
- **Stage 1 — mechanical file split (low risk, high value):** convert `dispatch.rs` into `dispatch/mod.rs` + per-subsystem files. The `SyscallDispatcher` struct, the `normalized_dispatch!` macro table, `dispatch()`, and the core types (`SyscallCtx`, `DispatchOutcome`, `SyscallRequest`, `GuestMemory`, `MemoryError`, `DispatchError`) stay in `mod.rs`. Each subsystem's handler methods move into `dispatch/<subsystem>.rs` as additional `impl SyscallDispatcher` blocks (Rust permits `impl` blocks for a type across any module in the same crate). Handlers still take `&mut self`. Behaviour is byte-identical; this is pure code relocation.
- **Stage 2 — narrow the borrows (deeper fix, per-subsystem):** introduce owned sub-state structs and move each subsystem's fields into its struct, then migrate that subsystem's handlers to borrow only their sub-state. Done one subsystem at a time so the compiler/conformance guard each step.

**Field → subsystem map (from the current `SyscallDispatcher`):**
| Sub-state struct | Fields |
|---|---|
| `IoState` | `stdout`, `stderr`, `stream_stdio`, `open_files`, `next_fd`, `cwd` |
| `MemState` | `brk_current`, `mmap_next`, `shared_file_next`, `shared_file_maps`, `address_space_regions` |
| `CredState` | `cred_ruid/euid/suid/rgid/egid/sgid`, `umask` |
| `SignalState` | `signal_handlers`, `signal_mask`, `pending_signals`, `sig_altstack` |
| `ProcState` | `executable_path`, `personality`, `dumpable`, `task_name` |
| `FsState` | `vfs_mounts`, `rootfs_vfs` (and shares `cwd`/`open_files` from `IoState`) |

**Safety net:** `cargo build` + full `cargo test` + `cargo test --test conformance` after each task. The differential conformance suite is the ground-truth guard that the relocation changed nothing observable.

---

## STAGE 1 — Mechanical file split

### Task 1: Create the module skeleton

**Files:** rename `src/dispatch.rs` → `src/dispatch/mod.rs`; create empty `src/dispatch/{fs,mem,signal,creds,net,time,proc}.rs`.

- [ ] **Step 1:** `git mv src/dispatch.rs src/dispatch/mod.rs` (preserves history).
- [ ] **Step 2:** Create the seven empty subsystem files, each starting with:
```rust
//! <subsystem> syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;
```
- [ ] **Step 3:** Add to the top of `src/dispatch/mod.rs`:
```rust
mod fs;
mod mem;
mod signal;
mod creds;
mod net;
mod time;
mod proc;
```
- [ ] **Step 4:** `cargo build 2>&1 | grep -E 'error' | head` → no output (empty modules compile).
- [ ] **Step 5:** Commit: `git commit -am "dispatch: introduce dispatch/ module skeleton (no logic moved yet)"`.

### Tasks 2–8: Move each subsystem's handlers (one task per subsystem)

Repeat this recipe for each subsystem in {fs, mem, signal, creds, net, time, proc}. Assign handlers by what they operate on — use the `normalized_dispatch!` table as the index:
- **fs:** getcwd, openat, openat2, close, close_range, read, write, readv, writev, pread64/pwrite64, preadv/pwritev, lseek, dup/dup3, fcntl, ioctl, flock, getdents64, *xattr*, statfs/fstatfs/truncate/ftruncate, fallocate, faccessat/faccessat2, mkdirat, unlinkat, symlinkat, linkat, renameat/renameat2, chdir/fchdir, fchmod(at), fchown(at), readlinkat, newfstatat, fstat, statx, mknodat, sync/fsync/fdatasync/syncfs, sendfile, splice, copy_file_range, utimensat, pipe2.
- **mem:** brk, mmap, munmap, mremap, mprotect, msync, madvise, mlock/munlock/mlockall/munlockall, mincore, membarrier, fadvise64.
- **signal:** rt_sigaction, rt_sigprocmask, rt_sigpending, rt_sigsuspend, rt_sigtimedwait, rt_sigqueueinfo, rt_sigreturn, sigaltstack, kill, tkill, tgkill.
- **creds:** setuid/getuid, setgid/getgid, setre*id, setres*id/getres*id, setfsuid/setfsgid, getgroups/setgroups, getpid/getppid/gettid, umask, capget/capset, getpriority/setpriority.
- **net:** socket, socketpair, bind, listen, accept/accept4, connect, getsockname/getpeername, sendto/recvfrom, setsockopt/getsockopt, shutdown, sendmsg/recvmsg, sendmmsg/recvmmsg, eventfd2, epoll_create1/epoll_ctl/epoll_pwait, ppoll, pselect6.
- **time:** clock_gettime/settime/getres/nanosleep/adjtime, clock_nanosleep, nanosleep, gettimeofday/settimeofday, getitimer/setitimer, timerfd_create/settime/gettime, times, getrusage, adjtimex, sysinfo, prlimit64.
- **proc:** clone, clone3, execve, wait4, waitid, exit, set_tid_address, set_robust_list, rseq, prctl, personality, uname, sethostname/setdomainname, getcpu, sched_getaffinity/sched_yield, getsid/setsid/getpgid/setpgid, ptrace, reboot, getrandom, capget-adjacent process bits.

For EACH subsystem task:
- [ ] **Step 1:** Cut the handler methods + any subsystem-private free fns/consts/structs (e.g. `write_statfs`, socket ABI helpers) from `dispatch/mod.rs` and paste them into `dispatch/<subsystem>.rs` inside an `impl SyscallDispatcher { … }` block. Make any helper that `mod.rs` or another subsystem still needs `pub(super)` or `pub(crate)`.
- [ ] **Step 2:** `cargo build 2>&1 | grep -E 'error|warning: unused' | head` → resolve visibility errors (a method used cross-subsystem needs no change since it's a method on the shared type; a free fn needs `pub(super)`).
- [ ] **Step 3:** `cargo test 2>&1 | tail -5` → green.
- [ ] **Step 4:** Commit: `git commit -am "dispatch: move <subsystem> handlers into dispatch/<subsystem>.rs"`.

### Task 9: Verify mod.rs is now thin + conformance

- [ ] **Step 1:** `wc -l src/dispatch/*.rs` — `mod.rs` should hold only the struct, macro table, `dispatch()`, core types, and `new()`/state accessors. Report the line distribution.
- [ ] **Step 2:** `cargo test --test conformance 2>&1 | tail -20` → all PASS/XFAIL, zero FAIL.
- [ ] **Step 3:** Commit any final tidy.

---

## STAGE 2 — Narrow the borrows (per-subsystem, optional-but-recommended)

### Task 10+: For each subsystem, extract its sub-state struct

Repeat per subsystem (start with the most self-contained: `SignalState`, then `CredState`, `MemState`, `ProcState`, then `IoState`/`FsState` which are more entangled via `cwd`/`open_files`):
- [ ] **Step 1:** Define the sub-state struct (e.g. in `dispatch/signal.rs`):
```rust
pub(super) struct SignalState {
    pub handlers: HashMap<i32, LinuxSigaction>,
    pub mask: u64,
    pub pending: u64,
    pub altstack: Option<LinuxSigaltstack>,
}
impl SignalState { pub(super) fn new() -> Self { Self { handlers: HashMap::new(), mask: 0, pending: 0, altstack: None } } }
```
- [ ] **Step 2:** Replace the four loose fields on `SyscallDispatcher` with `signal: SignalState`, update `new()`.
- [ ] **Step 3:** Update that subsystem's handlers to go through `self.signal.*`. Where a handler ONLY touches its sub-state (+ ctx), change its receiver to `fn(state: &mut SignalState, ctx: &mut SyscallCtx<M>)` and have a one-line forwarder on `SyscallDispatcher` call it — this is the concrete "borrow narrowly" win. (Do this only for handlers that don't also need other subsystems' state; leave cross-cutting ones as `&mut self`.)
- [ ] **Step 4:** `cargo test` + `cargo test --test conformance` → green. Commit.

---

## Self-Review
- Spec coverage: goal #2 fully — subsystem files (Stage 1) + owned sub-structs with narrowed borrows (Stage 2). Stage 1 alone resolves the merge-conflict/god-file problem and is independently shippable; Stage 2 resolves "borrow the whole world."
- Risk control: Stage 1 is pure relocation (conformance proves zero behavioural change); Stage 2 is incremental per-subsystem with the same guard. No line numbers are used (they'd be invalidated by Plans A/C) — assignment is by handler identity via the macro table.
- Alignment with Plan E: the subsystem seams (fs/mem/net/time/signal/creds/proc) match the test-file split exactly, so code and tests share one taxonomy.
