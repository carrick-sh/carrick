# NetBSD native-lane acceptance evidence (Task 5)

Date: 2026-07-24
Branch: `feat/netbsd-native-lane`
Box: `root@10.14.14.136` — NetBSD 10.1 (GENERIC) amd64, VM 201, uncontended
Toolchain on box: rustc 1.96.0, `LIBCLANG_PATH=/usr/pkg/lib`

## Status: GAP-FOUND (acceptance BLOCKED at the shared gateway prologue)

The first real guest execution on NetBSD reached the production entry
(`carrick_runtime::runtime::run_elf_native_dispatch`), loaded the ELF, built
the DSR gateway, and entered the enter-trampoline — then died with **SIGILL
before a single guest instruction ran**. The failure is precise, reproducible,
and in a **shared seam** (the `carrick-dsr-x86` gateway assembly), not in the
NetBSD lane glue that Tasks 1–4 built.

The acceptance harness (`crates/carrick-runtime/tests/native_netbsd_x86.rs`) is
written, committed, and ready — every test is `#[ignore]`d with this gap as the
reason. Removing the four `#[ignore]`s is the acceptance step once the gap is
closed.

## The gap: NetBSD 10.1 does not enable ring-3 FSGSBASE

The shared gateway enter-trampoline swaps the hardware FS base around every
full entry so translated guest code can use `%fs:`-relative TLS accesses
directly. It does that with the FSGSBASE instructions:

`crates/carrick-dsr-x86/src/gateway_x86_64.S`
```
55:    movq CTX_GUEST_FSBASE(%r15), %rax
56:    rdfsbase %rcx                       <-- SIGILL here
57:    movq %rcx, CTX_HOST_FSBASE(%r15)
58:    wrfsbase %rax
...
273:   wrfsbase %rax                       (restore host base on full exit)
```

`rdfsbase`/`wrfsbase` require the OS to set `CR4.FSGSBASE` to be usable from
ring 3. FreeBSD (and Linux ≥ 5.9) enable it; **NetBSD 10.1/amd64 does not, and
exposes no sysctl to turn it on.** The CPU itself supports the feature — the
kernel simply gates the ring-3 CR4 bit.

### Evidence 1 — gdb caught the exact faulting instruction

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

RIP is in the **gateway trampoline** (`carrick_dsr_x86_enter_raw`), i.e. host
code that is not part of the JIT code cache. The fault-shim (`fault.rs`) only
redirects faults whose RIP lands inside the registered code cache; a fault in
the trampoline correctly stays fatal — the shim is behaving as designed, the
instruction is simply illegal on this OS.

### Evidence 2 — direct probe isolates the cause to OS policy, not the CPU

A standalone C probe on the box (`/root/fsgsprobe.c`):

```
CPUID.07H:EBX.FSGSBASE[bit0] = 1        <- CPU supports FSGSBASE
CPUID.01H:ECX.OSXSAVE[bit27] = 1
rdfsbase raised SIGILL (userspace FSGSBASE NOT enabled by OS)
```

`sysctl -a | grep -i fsgs|fsbase|gsbase` returns nothing — there is no runtime
toggle. This is a NetBSD 10.1 GENERIC kernel-policy decision.

## Pass-set / red-list

- **Pass-set: EMPTY.** The gap is in the gateway prologue, upstream of *any*
  guest instruction, so no fixture reaches guest code. Every fixture in
  `carrick-dsr-x86/tests/fixtures/` fails identically on the first
  `rdfsbase`, regardless of its syscall/xstate/fork surface.
- **Red-list: the single blocking item below.** There is no per-fixture red
  list yet — nothing downstream of the gateway has been reached, so no
  NetBSD-specific behavioral divergences (xstate/AVX512/pkru/signal/fork) have
  been observed. They become the *real* red list only after the gap is closed.

| Item | Subsystem | Symptom | Root cause |
| --- | --- | --- | --- |
| gateway fsbase swap | `carrick-dsr-x86` gateway asm (shared) | SIGILL at `carrick_dsr_x86_enter_raw+59` | `rdfsbase`/`wrfsbase` need ring-3 `CR4.FSGSBASE`, which NetBSD 10.1 does not set |

## What the NetBSD native lane DOES and does NOT do today

Does (verified by Tasks 1–4 + this task):
- Compiles and links end-to-end on NetBSD 10.1 with `platform-netbsd`.
- `run_elf_native_dispatch` is reachable and drives the shared BSD run loop
  (`native_freebsd::run_static_x86_elf`) through to `enter_translated`.
- Loads the ELF, builds the DSR gateway/context, maps the dual-map JIT code
  cache, installs the fault + kick redirects. (All the pre-guest machinery
  runs; the crash is the *first* fsbase instruction, after setup.)
- The NetBSD fault-shim's own in-crate tests (real fork + real SIGSEGV redirect
  and out-of-region fatal) pass — the mcontext `__gregs[]` reads/writes are
  correct.

Does NOT yet:
- Execute a single guest instruction, because the gateway's fsbase swap uses
  FSGSBASE instructions NetBSD 10.1 forbids in ring 3.
- Therefore: no acceptance fixture runs; no futex/signal/W^X-under-load paths
  have been exercised under a real guest.

## Follow-on (reshapes the plan): host-abstracted fsbase-swap seam

The gateway assembly was assumed BSD-portable but bakes in a FreeBSD/Linux CPU
capability. Closing the gap needs a **host-abstracted fsbase swap** in the
shared gateway, selected per host:

- FreeBSD/Linux: `rdfsbase`/`wrfsbase` (fast, current behavior).
- NetBSD: the syscall interface — grounded and present on the box:
  - `sysarch(X86_64_GET_FSBASE, &val)` / `sysarch(X86_64_SET_FSBASE, &val)`
    (`/usr/include/x86/sysarch.h:81-83`), and/or `_lwp_getprivate` /
    `_lwp_setprivate` (`/usr/include/lwp.h:52-53`).

Design tensions to resolve in the follow-on (these are why it reshapes the plan
rather than being a one-line swap):

1. **Hot path.** The swap runs on every *full* gateway entry and exit. Two
   `sysarch` syscalls per full entry/exit is correct but a real per-entry cost;
   measure vs the FSGSBASE path and consider caching (skip the save/restore
   when the guest fsbase is unchanged and no host TLS access intervenes).
2. **Signal-context correctness.** The trampoline currently does the swap
   inline in asm; a syscall-based swap changes what state is live across the
   swap and interacts with the fault/kick shim's assumption that the guest
   fsbase is installed for the whole translated run. The shim restores the host
   base from the saved context after a signal-stub exit — that path must be
   reconciled with a syscall-set base.
3. **Seam shape.** This belongs in the gateway's host-ops seam (the same seam
   the JIT map / icache flush / futex already cross), not in NetBSD lane glue —
   the `.S` prologue needs a host-selected variant (build-time `cfg`, or a
   context flag the trampoline branches on, or a callable host hook).

An alternative — running a custom NetBSD kernel with `CR4.FSGSBASE` enabled for
ring 3 — is out of scope for stock NetBSD 10.1 GENERIC and would not make the
lane work on unmodified NetBSD, so the seam is the right durable fix.

## Reproduce

Sync + run (the harness is `#[ignore]`d, so pass `--ignored` to hit the gap):
```
cargo test -p carrick-runtime --no-default-features --features platform-netbsd \
  --test native_netbsd_x86 -- --ignored --test-threads=1 --nocapture
```
Under gdb to re-capture the RIP:
```
gdb -batch -nx -ex 'handle SIGILL stop print nopass' -ex run \
  -ex 'x/2i $pc' -ex bt \
  --args target/debug/deps/native_netbsd_x86-* \
  tinyguest_runs_natively_through_the_real_dispatcher --ignored --test-threads=1
```

## Gate-ladder adaptation (secondary follow-on)

`scripts/native-x86-ltp-gate.py` targets a FreeBSD host; pointing it at a
NetBSD host is a follow-on that is moot until the FSGSBASE gap is closed and a
non-empty pass-set exists. Not done here.
