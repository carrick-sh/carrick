# carrick USDT probes + DTrace arg reference

Probes are defined in `src/probes.rs` under the `carrick` provider; match them
as `carrick*:::<probe-name>` (the `*` matches the per-pid provider suffix, so it
works for forked children too). DTrace exposes each probe's fields as
`arg0..argN`. The wrappers in `probes.rs` that take a `pid`/`getpid()` first
arg expose it as `arg0`; the rest shift accordingly. Cast pointers/ints with
`(int)`/`(uint64_t)` as needed.

## Probe arg tables

| Probe | arg0 | arg1 | arg2 | arg3 | arg4 |
|---|---|---|---|---|---|
| `syscall-entry` | sysno (u64) | name (str) | args_addr (u64)¹ | — | — |
| `syscall-return` | sysno (u64) | name (str) | retval (i64) | errno (i32) | — |
| `unhandled-syscall` | sysno | name | args_addr | — | — |
| `unknown-syscall-flags` | sysno | name | flags (u32) | val (u64) | — |
| `fork-pre` | pc (u64) | elr (u64) | cpsr (u64) | — | — |
| `fork-post` | child_pid (i32)² | pc | cpsr | — | — |
| `host-pipe-io` | pid (u32) | host_fd (i32) | dir (i32)³ | n (i64) | — |
| `guest-exit` | pid (u32) | code (i32) | — | — | — |
| `path-open` | pid (u32) | path (str) | result_size (u64) | errno (i32) | — |
| `fs-op` | pid (u32) | op (str) | path (str) | errno (i32) | — |
| `execve-argv` | pid (u32) | path (str) | joined_argv (str) | — | — |
| `execve-loaded` | path (str) | entry (u64) | sp (u64) | … | — |
| `signal-inject` | signum (i32) | saved_pc (u64) | new_sp (u64) | handler (u64) | — |
| `signal-restore` | saved_pc (u64) | sp (u64) | magic (u64) | — | — |
| `vcpu-trap` | regs_addr (u64)⁴ | — | — | — | — |
| `sigaction-read` | signum (i32) | … (4 u64) | | | |
| `vcpu-fault` | esr (u64) | elr (u64) | far (u64) | x30 (u64) | sp (u64), tid (i32) |
| `vcpu-fault-regs` | esr (u64) | elr (u64) | far (u64) | insn (u64) | rn (u32), xrn (u64) |

`vcpu-fault` / `vcpu-fault-regs` fire ONLY on a guest EL0 synchronous fault
(instruction/data abort, undef) — never on the happy path, so they're free to
leave always-on. Use them to debug a guest SIGSEGV/SIGBUS/SIGILL: `far` is the
HW-latched faulting address, `insn` the faulting instruction word (read
host-side; you can't `copyin` a guest VA), `rn`/`xrn` the base register a
load/store dereferenced (`xrn` is best-effort — read after the EL1 trampoline;
trust `far`). Both pass SCALARS (not a copyin pointer) so they survive a fault
that kills the process before DTrace's action runs. Ready-made script:
`scripts/trace-guest-fault.d`.

¹ `args_addr` points at a contiguous `[u64; 6]` of syscall args:
`this->a = (uint64_t *)copyin(arg2, 48);` then `this->a[0..5]`.
² On `fork-post`, `(int)arg0 == 0` in the child, `>0` (the child pid) in the parent.
³ `host-pipe-io` dir: `0` = read, `1` = write. `n` < 0 means the host op failed.
⁴ `vcpu-trap` arg0 is the address of a `compat::GuestRegs` (`#[repr(C)]`) — used
by `guest_stack.d` to walk the guest frame chain via `copyin`.

## Native macOS providers (for the guest-vs-host comparison)

Standard DTrace providers, filtered to the carrick tree:

```d
syscall::pipe:return     /pid==$target||progenyof($target)/   { /* arg0/arg1 = the two fds */ }
syscall::write:return    /(pid==$target||progenyof($target)) && errno != 0/ { /* failed host writes */ }
syscall::close:entry     /(pid==$target||progenyof($target)) && arg0 < 16/  { /* arg0 = fd */ }
syscall::fcntl:entry     /(pid==$target||progenyof($target)) && arg1==67/   { /* F_DUPFD_CLOEXEC; arg2=minfd */ }
syscall::setrlimit:return /pid==$target||progenyof($target)/  { /* errno */ }
```

macOS `fcntl` cmd values worth knowing: `F_GETFL`=3, `F_SETFL`=4, `F_GETFD`=1,
`F_SETFD`=2, `F_DUPFD`=0, `F_DUPFD_CLOEXEC`=67.

## Linux aarch64 syscall-number cheat-sheet

Predicate on `arg0` of `carrick*:::syscall-entry`/`syscall-return`:

| nr | name | nr | name | nr | name |
|---|---|---|---|---|---|
| 23 | dup | 56 | openat | 98 | futex |
| 24 | dup3 | 57 | close | 129 | kill |
| 25 | fcntl | 59 | pipe2 | 130 | tkill |
| 35 | unlinkat | 63 | read | 131 | tgkill |
| 37 | linkat | 64 | write | 134 | rt_sigaction |
| 38 | renameat | 66 | writev | 139 | rt_sigreturn |
| 43 | statfs | 73 | ppoll | 220 | clone |
| 48 | faccessat | 78 | readlinkat | 221 | execve |
| 49 | chdir | 79 | newfstatat | 222 | mmap |
| 53 | fchmodat | 93 | exit | 260 | wait4 |
| 55 | fchown | 94 | exit_group | 206/207 | sendto/recvfrom |

(Authoritative list: `src/syscall.rs`. Use `carrick syscalls` to dump the
table if unsure.)

## Quick recipes

- **What's failing (errno sweep):**
  `carrick*:::syscall-return /(pid==$target||progenyof($target)) && (int)arg3 != 0/ { @[copyinstr(arg1),(int)arg3]=count(); }`
- **Map the fork tree:** print every `fork-post child=<arg0>`, then grep one pid.
- **Pipe disconnection:** correlate each `host-pipe-io` (writer `dir=1` host_fd, reader `dir=0` host_fd) with `syscall::pipe:return` fds — same numbers but EOF on read ⇒ disconnected ends.
- **Hang triage:** `profile-997` + a syscall-name `count()` aggregation; few syscalls + no profile samples in carrick = blocked in a host syscall.
