# NetBSD native-lane evidence (acceptance + red list)

Date: 2026-07-24 (gap found) → 2026-07-24 (fsbase seam landed, acceptance GREEN)
Branch: `feat/netbsd-native-lane`
Box: `root@10.14.14.136` — NetBSD 10.1 (GENERIC) amd64, VM 201, uncontended
Toolchain on box: rustc 1.96.0, `LIBCLANG_PATH=/usr/pkg/lib`

## Status: ACCEPTANCE ACHIEVED

Real, static x86_64 Linux ELFs run natively on NetBSD 10.1/amd64 through the
production `runtime::run_elf_native_dispatch` entry — the same `carrick-dsr-x86`
DSR gateway + shared `SyscallDispatcher` the FreeBSD native lane drives, with
**no VMM**. This is the first real guest execution on NetBSD.

The acceptance harness is
`crates/carrick-runtime/tests/native_netbsd_x86.rs`. All four fixtures pass
(commit `c2a2f9f5`, un-ignoring them once the blocking gap below was closed by
`b9dbfa0a`):

| Fixture | Assertion | Result |
| --- | --- | --- |
| `tinyguest-x86_64-linux` | `exit_code == 21` (`exit_group(0+1+..+6)`), `stdout == "native-elf ok\n"` | PASS |
| `identity-loop-x86_64-linux` | `exit_code == 0`, `traps == 1` (1000×getpid + 1000×gettid chain natively; only the final `exit_group` traps) | PASS |
| `computeloop-x86_64-linux` | `exit_code == 192` (50M-iteration chained compute loop), `traps == 1` (the back-edge never round-trips to Rust) | PASS |
| `hello-std-x86_64-linux` | `exit_code == 129` (`385 % 256`), `stdout` contains `"squares=[1, 4, 9, ...]"` and `"sum=385"` — a real std Rust binary (musl TLS/arch_prctl, sigaltstack, brk/mmap heap, buffered stdout) | PASS |

```
cargo test -p carrick-runtime --no-default-features --features platform-netbsd \
  --test native_netbsd_x86 -- --test-threads=1
# result: 4 passed; 0 failed
```

### Campaign thesis proven

The NetBSD native lane is **host-glue, not a monolith rewrite**: `carrick-dsr-x86`
(the JIT/translator/gateway) and the shared BSD run loop
(`carrick-runtime/src/native_freebsd.rs`, `#![cfg(any(freebsd, netbsd))]`) are
reused byte-for-byte across FreeBSD and NetBSD. Only host-OS seams are new —
JIT dual-map/W^X, the fault/kick mcontext shim, futex (`_umtx_op`/`__futex`),
and (this task) the fsbase swap. Nothing in the shared translator, dispatcher,
or gateway control flow changed to add a second BSD.

## The gap that blocked acceptance (now closed): NetBSD 10.1 does not enable ring-3 FSGSBASE

The shared gateway enter-trampoline (`carrick-dsr-x86/src/gateway_x86_64.S`)
swaps the hardware FS base on every guest↔host crossing with the FSGSBASE
instructions (`rdfsbase`/`wrfsbase`), so translated guest code can use
`%fs:`-relative TLS accesses directly. FreeBSD (and Linux ≥ 5.9) enable ring-3
`CR4.FSGSBASE`; **NetBSD 10.1/amd64 does not, and exposes no sysctl to turn it
on** — the CPU supports the feature (`CPUID.07H:EBX.FSGSBASE=1`), the kernel
simply gates the ring-3 CR4 bit. The first `rdfsbase` in the gateway prologue
raised `#UD` → SIGILL before a single guest instruction ran, upstream of every
fixture (gdb: `SIGILL … carrick_dsr_x86_enter_raw () at gateway_x86_64.S:56`).

### The fix: host-abstracted fsbase-swap seam

Design: `docs/superpowers/specs/2026-07-24-fsbase-swap-seam-design.md`.
Landed in two commits:

- **`b9dbfa0a` feat(dsr): host-abstracted fsbase-swap seam for NetBSD** — adds
  a host-agnostic `set_fsbase_fn: u64` field to `X86DsrContext`
  (`CTX_SET_FSBASE_FN`, appended into tail padding so `size_of` and every
  existing hot offset are unchanged). `gateway_x86_64.S` wraps fsbase sites
  1/2/3 in `#if defined(__NetBSD__)`; the `#else` branch is the **verbatim**
  original `rdfsbase`/`wrfsbase` sequence (proven byte-identical via
  `objdump -d` against `x86_64-unknown-freebsd` HEAD), so FreeBSD/Linux are
  untouched. Site 1 (host-base capture) is eliminated on NetBSD — the host FS
  base is invariant per host thread and captured once via
  `sysarch(X86_64_GET_FSBASE)` at run-loop setup. Sites 2 (install guest base,
  pre-XSAVE) and 3 (restore host base, post-XRSTOR) call the injected
  `set_fsbase_fn` — a TLS-free, pure-integer naked leaf in
  `carrick-native-netbsd/src/fsbase.rs` wrapping
  `sysarch(X86_64_SET_FSBASE, &base)`.
- **`c2a2f9f5` test(netbsd): un-ignore native x86 acceptance (fsbase seam)** —
  removes the four `#[ignore]`s once the gap was closed; verified 4 passed / 0
  failed on the box.

## What NetBSD does NOT yet do (red list / follow-on worklist)

Ordered roughly by priority; item 1 is the highest-priority gap because it is
the one place the fsbase seam's correctness is currently an *analysis*, not a
*measurement*.

1. **Mid-guest signal delivery + resume through the signal exit stub is
   UNEXERCISED — HIGHEST PRIORITY.** The design
   (`docs/superpowers/specs/2026-07-24-fsbase-swap-seam-design.md` §4) argues
   from the box's own `/usr/include/amd64/mcontext.h` that NetBSD carries the
   FS base as sigframe `_mc_tlsbase`, so a guest fault/signal round-trips the
   guest base through the kernel and the signal exit stub still hits gateway
   site 3 to restore the host base. That chain is **box-grounded but has never
   been run** — no acceptance fixture in this task delivers a signal to a
   running guest. Add a mid-guest-signal fixture (fault → handler → sigreturn →
   resume, or an async-delivered signal) before trusting this path in
   production.
2. **Async kick mid-guest** (the `native_kick_handler` cross-thread wake used
   for blocking-syscall interruption) is untested against the fsbase seam —
   same mcontext-only argument as (1), same "grounded, not measured" caveat.
3. **Multi-threaded (clone) guest fsbase capture.** All four fixtures are
   single-threaded. A new guest thread gets a new `X86DsrContext` and must
   capture its own host FS base (`fsbase::get()`) at thread setup; that path
   is unexercised end-to-end with a real `clone(CLONE_VM|CLONE_THREAD)` guest.
4. **Fork/clone with fsbase end-to-end.** Design invariant #5 requires the
   NetBSD host-base capture to run again on `fork_child_rebuild`
   (`native_freebsd.rs:9727`); no fixture here forks.
5. **`ARCH_SET_FS(0)`** (a real guest FS base of zero) is a documented edge
   case in the seam design but not covered by an acceptance fixture.
6. **Syscall-heavy and FP-heavy guests together.** Per-crossing fsbase-swap
   cost (item 11) and FP-clobber safety (Item 2 of the pre-merge cleanup —
   `set_fsbase_fn` must not touch FP/vector state) are each individually
   argued/measured, but no fixture stresses both a hot syscall loop and heavy
   FP/vector guest code at once.
7. **Exact `FUTEX_CMP_REQUEUE` woken+requeued count fidelity.** NetBSD's
   `__futex(FUTEX_CMP_REQUEUE)` reports the **woken** count only, not Linux's
   woken+requeued total (`carrick-native-netbsd/src/futex.rs`). Benign: glibc
   ignores the requeue-count return value.
8. **NetBSD unit-test coverage of the shared run loop.** The ~119 inline
   `#[cfg(test)]` tests in `native_freebsd.rs` are FreeBSD-gated only (this
   pre-merge cleanup: every top-level `#[cfg(test)]` in that file is now
   `#[cfg(all(test, target_os = "freebsd"))]`) — some (MAP_FIXED-collision
   fault-injection tests) SIGSEGV at runtime on NetBSD and were never designed
   against NetBSD's memory-mapping behavior. Porting the OS-agnostic subset to
   run on NetBSD too is a follow-on campaign, not done here.
9. **`procctl` subreaper capability gap.** NetBSD has no `procctl`/
   `PROC_REAP_ACQUIRE` analog, so guest double-forked orphans reparent to host
   init (not guest init) and guest `wait4(-1)` of an orphaned grandchild
   returns `ECHILD`; the run loop's subreaper bookkeeping
   (`native_freebsd.rs:12093-12103`) goes stale on NetBSD. Mechanism is
   lane-dispatchable (`become_guest_reaper()`); the *capability* has no NetBSD
   equivalent today.
10. **The LTP gate-ladder adaptation.** `scripts/native-x86-ltp-gate.py`
    targets a FreeBSD host; pointing it at a NetBSD host (or genericizing it)
    is a follow-on, not attempted here.
11. **fsbase perf tax.** Per-crossing cost is ~164 ns/guest-syscall naive
    (1 GET + 2 SET) or ~104 ns with the GET eliminated (host base cached once
    per host thread, already implemented). An optional SET-shadow cache
    (skip a SET when the target already equals the currently-installed
    hardware base) could shave the typical case further but is unmeasured
    against a real workload and not implemented.

## Reproduce

Sync (git archive misses uncommitted edits) + acceptance run:
```
cd /Volumes/CaseSensitive/carrick && COPYFILE_DISABLE=1 tar --no-xattrs \
  --exclude='./target' --exclude='./.git' --exclude='./.superpowers' -cf - . 2>/dev/null \
  | ssh root@10.14.14.136 'rm -rf /root/carrick && mkdir /root/carrick && tar -C /root/carrick -xf - 2>/dev/null'

ssh root@10.14.14.136 'cd /root/carrick && . ~/.cargo/env && \
  LIBCLANG_PATH=/usr/pkg/lib cargo test -p carrick-runtime --no-default-features \
  --features platform-netbsd --test native_netbsd_x86 -- --test-threads=1'
```

Full-suite `cargo test` (proves the run-loop's inline FreeBSD tests are now
absent from the NetBSD test binary rather than SIGSEGV-aborting it):
```
ssh root@10.14.14.136 'cd /root/carrick && . ~/.cargo/env && \
  LIBCLANG_PATH=/usr/pkg/lib cargo test -p carrick-runtime --no-default-features \
  --features platform-netbsd'
```

Under gdb, to re-capture the (now-fixed) original fault for reference:
```
gdb -batch -nx -ex 'handle SIGILL stop print nopass' -ex run \
  -ex 'x/2i $pc' -ex bt \
  --args target/debug/deps/native_netbsd_x86-* \
  tinyguest_runs_natively_through_the_real_dispatcher --test-threads=1
```

## Appendix: original gap-found evidence (Task 5, superseded)

Kept for context — this is what the acceptance run looked like *before*
`b9dbfa0a`/`c2a2f9f5` closed the gap.

### gdb caught the exact faulting instruction

```
Thread 2 received signal SIGILL, Illegal instruction.
carrick_dsr_x86_enter_raw () at src/gateway_x86_64.S:56
56          rdfsbase %rcx
rip  0xd42e6d5b <carrick_dsr_x86_enter_raw+59>
=> 0xd42e6d5b <carrick_dsr_x86_enter_raw+59>:   rdfsbase %rcx
   0xd42e6d67 <carrick_dsr_x86_enter_raw+71>:   wrfsbase %rax
#0 carrick_dsr_x86_enter_raw () at src/gateway_x86_64.S:56
#1 ...gateway::native_gateway::enter_translated (gateway.rs:1365)
#2 ...native_freebsd::run_x86_thread (native_freebsd.rs:9474)
#3 ...native_freebsd::run_static_x86_elf_bytes (native_freebsd.rs:8416)
...
#7 ...runtime::run_elf_native_dispatch (lib.rs:929)
#8 native_netbsd_x86::tinyguest_runs_natively_through_the_real_dispatcher
```

### Direct probe isolated the cause to OS policy, not the CPU

A standalone C probe on the box (`/root/fsgsprobe.c`):

```
CPUID.07H:EBX.FSGSBASE[bit0] = 1        <- CPU supports FSGSBASE
CPUID.01H:ECX.OSXSAVE[bit27] = 1
rdfsbase raised SIGILL (userspace FSGSBASE NOT enabled by OS)
```

`sysctl -a | grep -i fsgs|fsbase|gsbase` returned nothing — no runtime toggle
existed on NetBSD 10.1 GENERIC.
