# x86_64 DSR execution lane (FreeBSD/amd64) design

**Date:** 2026-07-17

**Status:** approved (vertical-slice bring-up)

**Scope:** The M2 rung of the native-backend portability seams campaign
(`2026-07-17-native-backend-portability-seams-design.md`): make translated
x86_64 guest code actually EXECUTE and trap its syscalls on FreeBSD/amd64.
The decode rung (`carrick-dsr-x86::decode::classify`) and the host JIT
(`carrick-native-freebsd`, dual-mapped W^X) already exist. This adds the plan
IR, the gateway, and the emitter, proven by an in-crate integration test
before any runtime wiring.

## The mechanism (mirrors the AArch64 lane, simpler)

DSR is selective copy-through translation: a guest basic block's instructions
are copied verbatim into a JIT cache except sensitive/control-flow
instructions, which become typed GATEWAY EXITS. A guest thread enters the
cache through a hand-written asm trampoline that loads guest register state
and jumps to translated code; a block exits by branching to an exit stub that
saves guest state back and returns a typed reason to Rust.

x86_64 is simpler than the AArch64 reference lane in three load-bearing ways:
- **No W^X toggle in the hot path** — the dual-map JIT means writers use the
  RW alias; execution runs the RX alias. `flush_icache` is a no-op (coherent
  I-cache). Cross-modifying-code ordering at live direct-branch patch sites is
  handled with a single aligned store of the rel32 displacement (atomic on
  x86 when 4-byte aligned and not straddling a cache line — the emitter
  guarantees alignment).
- **No exclusive monitors** — `lock`-prefixed RMW and `cmpxchg` copy through
  verbatim; the whole exclusive-region/biased-fusion apparatus has no analog.
- **No custom-register ABI dance** — AArch64/Darwin needs the custom-x18/TPIDR
  transition (`enter_guest_abi`/`enter_host_abi`) because Darwin virtualizes
  x18 and loses it across signals. FreeBSD/amd64 has no such hazard; the only
  segment concern is guest `%fs` (TLS), addressed below.

## Fixed decisions

- **Context register.** Translated x86 code runs with **`%r15` pinned as the
  `DsrContext` pointer** (the x28 analog). Guest `%r15` lives in the snapshot
  and is materialized only where an instruction reads it (rare; deferred with
  the register-virtualization work — the vertical slice uses guests that don't
  touch r15). Rationale: r15 is the highest callee-saved GPR, least used by
  compiler-emitted hot code, and needs no REX-free encoding.
- **`DsrContext` is `#[repr(C, align(16))]`** with a fixed field order and
  `offset_of!` asserts, exactly like the AArch64 `DsrContext`; the
  `gateway_x86_64.S` `.equ` offsets mirror the asserts. The snapshot is a new
  `X86UcontextSnapshot` (16 GPRs in ABI order, rip, rflags, plus XMM/x87
  state via `fxsave`/`fxrstor` — a 512-byte 16-aligned area). No shared
  snapshot type with AArch64 (the register files are unrelated); the neutral
  cache/publication layer never names either.
- **Syscall exit.** The emitter replaces guest `syscall` (0f 05) with: stash
  the resume RIP (next-instruction VA) into the context, then `jmp` the
  syscall exit stub. Guest `syscall` is NEVER executed on the host — it would
  hit the FreeBSD kernel with Linux numbers. Rust services the Linux syscall
  through the shared dispatcher (runtime wiring, M2-runtime) or, in the
  vertical-slice test, a tiny in-test servicer, writes the result into
  `snapshot.rax`, and re-enters at the resume VA.
- **Block terminators (vertical slice).** The minimal slice ends a block at:
  `syscall`/`int 0x80` → Syscall exit; any control-flow → an INDIRECT-style
  exit that returns the computed next RIP to Rust, which translates that block
  and re-enters. Direct-branch CHAINING/patching (the fast path) is a
  follow-up; correctness does not depend on it. `cpuid`/`rdtsc`/fsbase/fs-gs
  → Sensitive exit (serviced later; the slice's guest avoids them).
- **`%fs` / TLS.** A Linux x86_64 guest keeps its thread pointer in `%fs`
  base (set via `arch_prctl(ARCH_SET_FS)`). The host also uses `%fs` for its
  own TLS. The gateway must therefore swap fsbase on enter/exit
  (`wrfsbase`/`rdfsbase`, or `arch_prctl` where FSGSBASE is unavailable). The
  vertical slice uses a guest with NO TLS access (hand-written asm) so fsbase
  swap can be a documented stub; the first real static-musl guest needs it and
  it lands with the runtime wiring.
- **Faults.** Guest SIGSEGV/SIGBUS/SIGFPE arrive as host signals. A
  `carrick-native-freebsd` sigaction shim reads the amd64 `mcontext_t`,
  snapshots guest state, and redirects to the signal exit stub (the AArch64
  `carrick_dsr_exit_signal` analog). The vertical slice's correct guest does
  not fault, so the shim lands with M2-runtime; the slice asserts clean exit,
  not fault handling.
- **The vertical slice does NOT touch carrick-runtime.** It is an integration
  test inside `carrick-dsr-x86`: hand-assemble a guest that does
  `write(1, "hi\n", 3); exit_group(7)`, map it through
  `carrick-native-freebsd`'s JIT, translate + run it through the gateway, and
  service the two syscalls in-test. Green means plan+emit+gateway+syscall-trap
  work on real FreeBSD/amd64 silicon. Runtime wiring (real dispatcher, TLS,
  faults, threads, fork) is the rung after.

## Components and order

1. **plan IR + block planner** (`carrick-dsr-x86::block`) — `X86Block`
   `{start, insts: Vec<PlannedInst{va, len, class}>, exit: X86Exit}` over a
   byte reader, using `classify`; variable-length stride, page-boundary and
   instruction-count limits. Pure, fully testable on FreeBSD now.
2. **snapshot + `DsrContext`** (`carrick-dsr-x86::gateway`) — `repr(C)` with
   offset asserts.
3. **`gateway_x86_64.S`** — `carrick_dsr_x86_enter_raw(ctx) -> i32` + exit
   stubs (`_syscall`, `_indirect`, `_sensitive`, `_signal`). build.rs
   assembles it on `target_arch = "x86_64"` (any OS — the asm is
   SysV-ABI-portable; FreeBSD is the first consumer).
4. **emitter** (`carrick-dsr-x86::emit`, dynasmrt x64) — copy-through +
   syscall/indirect exit lowering; writes through the JIT region's RW alias.
5. **integration test** — the hello-world proof above.

## Non-goals (this slice)

Direct-branch chaining, indirect target cache, register virtualization
(r15/fs-gs), counter/cpuid virtualization, fault handling, threads/fork,
artifact cache, and any performance work. Each is a named follow-up. The bar
is a single-threaded, fault-free, TLS-free guest running natively and exiting
with the right code and output.
