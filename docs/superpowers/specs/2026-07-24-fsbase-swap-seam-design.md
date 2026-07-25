# Host-abstracted fsbase-swap seam for the shared x86 DSR gateway

**Date:** 2026-07-24
**Branch:** `feat/netbsd-native-lane`
**Status:** DESIGN (read-only analysis; no carrick code changed by this task).
Reviewed → implemented by a separate implementer.
**Motivating blocker:** the shared x86 DSR gateway swaps the FS base with the
`rdfsbase`/`wrfsbase` (FSGSBASE) instructions on every guest entry/exit. NetBSD
10.1/amd64 does **not** enable ring-3 CR4.FSGSBASE, so the first gateway
instruction faults with SIGILL before any guest code runs. This unblocks NetBSD
native-lane acceptance.
**Host used for grounding:** willow VM 201 — `root@10.14.14.136`, NetBSD 10.1
amd64 (GENERIC). All probes were throwaway C compiled with `cc` on the box; no
carrick build was run there.

---

## 0. The premise, re-confirmed empirically

| Fact | Evidence |
|---|---|
| CPU/VM advertises FSGSBASE | `CPUID.07H:0.EBX=0xf1bf07ab`, **bit 0 (FSGSBASE) = 1** |
| `rdfsbase` still faults in ring 3 | SIGILL handler fired; probe exited 42 (its SIGILL branch) — "userland FSGSBASE disabled" |
| No sysctl toggle | `sysctl -a | grep -i fsgs` → empty |
| Kernel keeps the base in the per-LWP PCB | `sysarch(X86_64_SET_FSBASE)` / `_lwp_setprivate`; FS base is `__gregs`-adjacent `_mc_tlsbase` in the sigframe (`/usr/include/amd64/mcontext.h`) |

**Why NetBSD does this** (grounded via web + the FreeBSD D12023 discussion):
a kernel that does not set `CR4.FSGSBASE` makes every FSGSBASE instruction `#UD`
(→ SIGILL) in userland. NetBSD reloads the FS base from the per-LWP PCB on every
kernel entry/exit, so a userland `wrfsbase` would be silently reverted on the
next trap — which is exactly why NetBSD exposes the base only through the
`sysarch`/`_lwp_setprivate` syscall path (which updates the PCB, so it is
durable across traps and signal delivery). FreeBSD and Linux **do** enable
ring-3 CR4.FSGSBASE, so their inline `rdfsbase`/`wrfsbase` work and must stay
untouched.

NetBSD ABI constants (grounded from `/usr/include/x86/sysarch.h` +
`/usr/include/sys/syscall.h`):

```
SYS_sysarch        = 165
X86_64_GET_FSBASE  = X86_GET_FSBASE = 15
X86_64_SET_FSBASE  = X86_SET_FSBASE = 17
int sysarch(int number, void *args);   // args -> a void*-sized base slot
```

---

## 1. Complete fsbase-site inventory

### 1a. Hardware FSGSBASE instruction sites — the ONLY code the NetBSD gap breaks

All three live in `crates/carrick-dsr-x86/src/gateway_x86_64.S`. Nothing else in
the tree executes an FSGSBASE instruction.

| # | Site | Instruction | What it does | Why |
|---|---|---|---|---|
| 1 | `gateway_x86_64.S:56` (enter, `carrick_dsr_x86_enter_raw`) | `rdfsbase %rcx` → `CTX_HOST_FSBASE` | **Save** the host FS base | So the exit stub can put host TLS back before any Rust/libc runs |
| 2 | `gateway_x86_64.S:58` (enter) | `wrfsbase %rax` from `CTX_GUEST_FSBASE` | **Install** the guest FS base (incl. 0) | Guest `fs:`-prefixed TLS reads resolve against the guest thread pointer, with zero rewriting; installing 0 is deliberate (an `ARCH_SET_FS(0)` guest must not see host TLS) |
| 3 | `gateway_x86_64.S:273` (`.Lfull_exit` in `carrick_dsr_x86_exit_common`) | `wrfsbase %rax` from `CTX_HOST_FSBASE` | **Restore** the host FS base | Every full exit returns to Rust; host code needs host TLS |

Per round-trip that reaches Rust: **1 `rdfsbase` (site 1) + 2 `wrfsbase` (sites
2 and 3) = 1 GET + 2 SET.**

The monomorphic return-cache hit path (`.Lresume_guest`,
`gateway_x86_64.S:289`) deliberately **skips** all three — it stays
guest-resident, never returns to Rust, never swaps a base
(`gateway_x86_64.S:270-271` comment). This is load-bearing for the perf story in
§2 and for the caching design in §3.

### 1b. Software `guest_fsbase` sites — NOT hardware; already NetBSD-safe; DO NOT CHANGE

These read/write the software `u64` `X86DsrContext::guest_fsbase`
(`gateway.rs:915`) — the guest thread pointer as data, never an FSGSBASE
instruction. They work unchanged on NetBSD.

- `X86DsrContext::{guest_fsbase,host_fsbase}` context fields (`gateway.rs:915,919`) — plain `u64`s.
- `emit.rs:1047-1055` — emits a `mov` load of `CTX_GUEST_FSBASE` to compute a copied x87 `fs:`-memory instruction's data pointer (FDP). Software add, not `rdfsbase`.
- `xstate_address.rs:90` — `Register::FS => (guest_fsbase, false)` for xstate memory-operand address generation.
- `fxstate.rs:89`, `xstate_save.rs:111,147`, `xstate_restore.rs:109`, `legacy_x87.rs:101` — take `guest_fsbase` as a parameter for `fs:` effective-address math.
- Runtime `service_xstate_save` / `service_xstate_restore` / `service_legacy_state_transfer` pass `context.guest_fsbase` (`native_freebsd.rs:10257,10300,10344`).
- Runtime `arch_prctl(ARCH_SET_FS)` sets `context.guest_fsbase` via `service_syscall(&mut context.guest_fsbase, …)` (`native_freebsd.rs:9690`, `:10484` doc); `wrfsbase(0)`-style servicing sets `context.guest_fsbase = 0` (`:10053`).

### 1c. Guest's OWN segment-base instructions — Sensitive-emulated, never raw

`decode.rs:504-527` classifies guest `rd/wr fs/gs base` as
`X86SensitiveKind::SegmentBase` → a **Sensitive gateway exit**, serviced in Rust
(today the first-rung driver actually falls through to a "not serviced yet" fault
at `native_freebsd.rs:10419`, a pre-existing gap unrelated to this seam). They
are **never** raw-executed, so a guest `rdfsbase` produces a typed exit, not a
host SIGILL — the NetBSD gap does not touch them.

`decode.rs:530-534` classifies guest **`fs:`-prefixed memory operands** as
`Copy` (raw-executed). They rely on the hardware FS base being the guest's — i.e.
on site 2 having run. On NetBSD they work correctly once site 2 installs the
guest base via `sysarch`.

### 1d. Fault/kick shims — read only mcontext registers; NO FSGSBASE

`crates/carrick-native-freebsd/src/fault.rs` and
`crates/carrick-native-netbsd/src/fault.rs` **do not execute `rdfsbase`/`wrfsbase`**.
They read the pinned gateway context from the mcontext register file
(`mc_r15` / `__gregs[_REG_R15]`), record the `FaultRecord`, and rewrite RIP to
the signal (or kick) stub. See §4 for the signal-path interaction.

---

## 2. Swap frequency — the perf driver

**Verdict: PER-CROSSING.** The gateway swaps the FS base on every guest↔host
crossing that returns to Rust, not once per run.

Chain of evidence:

1. The run loop is `native_freebsd.rs:9022` `'run: while traps < max_traps { … }`
   (this module is shared for `target_os = "freebsd"` **and** `"netbsd"` —
   `lib.rs:163`).
2. Each iteration calls `carrick_dsr_x86::enter_translated(&mut context)`
   (`native_freebsd.rs:9474`), which runs the enter trampoline (sites 1+2), runs
   the guest to a terminator, and returns through an exit stub (site 3 on any
   full exit).
3. On a `Syscall` exit (`native_freebsd.rs:9682`) the loop services the syscall in
   Rust (`service_syscall`, which needs host TLS) and `continue`s → the next
   iteration re-enters the gateway. Same for `Sensitive`, chain-miss `Indirect`,
   `Signal`, and `Kicked`.

So the swap count scales with **(guest syscalls + sensitive instructions +
unresolved indirect branches + guest faults)**; on real workloads guest syscalls
dominate. Direct-chained branches and monomorphic return-cache hits stay in the
JIT and cost **zero** swaps.

On FreeBSD/Linux each swap is 1–2 cheap register instructions — negligible. On
NetBSD each becomes a `sysarch` **syscall**, so per guest syscall the naive
translation adds **1 GET + 2 SET = 3 extra host syscalls**.

### 2a. Measured `sysarch` cost (NetBSD 10.1, VM 201, idle box)

Raw-syscall micro-probe, 5×10⁶ iterations each, wall time via `/usr/bin/time`:

| Operation | ns/call |
|---|---|
| `getpid` (raw-syscall baseline) | ~52 |
| `sysarch(GET_FSBASE)` | ~60 |
| `sysarch(SET_FSBASE)` | ~52 |

`sysarch` FS-base ops are plain, cheap syscalls — essentially the cost of a
`getpid`. (A first probe run appeared to "hang"; the cause was an **orphaned
spinning probe** from an earlier ssh timeout loading the box — once killed, the
loops complete in ~0.3 s for 5×10⁶ calls. Real numbers above are from the idle
box.)

### 2b. Per-guest-syscall tax and the caching decision

| Scheme | sysarch calls / crossing | Added ns / guest syscall |
|---|---|---|
| Naive (1 GET + 2 SET) | 3 | ~164 ns |
| **GET-eliminated** (host base cached per host thread; 2 SET) | 2 | ~104 ns |
| + SET-shadow (skip a SET when target == current hardware base) | 2 typical (guest ≠ host) | ~104 ns typical |

**Does NetBSD need caching? — Not for correctness or basic usability**; at
~52–60 ns/op an uncached per-crossing swap is bounded and would run. **But one
cache is free and worth taking from day one:** the host FS base is **invariant
per host thread** (it is that host thread's libc/pthread TLS pointer; the runtime
never `sysarch(SET)`s its *own* host threads — only guest bases). So the enter-time
GET (site 1) captures a constant and can be captured **once per host thread**
instead of every crossing, removing ~1/3 of the tax with no risk.

The two SETs are fundamental: host Rust/libc runs between crossings and needs host
TLS, so the base genuinely must flip guest→host→guest. A per-thread **shadow** of
"what value is currently in the hardware base" additionally lets us skip a
redundant SET when guest == host (rare) or when the guest re-`ARCH_SET_FS`es the
same value; treat it as a nice-to-have, not a requirement.

**Recommendation:** implement GET-elimination (host base captured once per host
thread) as part of v1; SET-shadow is optional and can follow if profiling of a
syscall-heavy LTP lane shows it matters.

---

## 3. The seam shape

### 3a. Constraints that decide the shape

1. **FreeBSD/Linux must stay byte-identical** on the hot path — the inline
   `rdfsbase`/`wrfsbase` at `gateway_x86_64.S:56/58/273` must be emitted exactly
   as today (zero risk / zero perf delta to the proven lanes). This rules out any
   design that routes ALL lanes through a call or an indirect branch.
2. **`carrick-dsr-x86` is the shared, host-agnostic ISA engine.** Its
   dependencies are `carrick-abi`, `carrick-dsr`, `carrick-guest-mem`, `iced-x86`,
   `thiserror` (`Cargo.toml`) — it must **not** depend on
   `carrick-native-{freebsd,netbsd}`, and must not learn a NetBSD syscall ABI. The
   gateway is already "the ONE target boundary in this crate" (`gateway.rs:1296`).
3. The host-specific **body** belongs in the host layer, injected — mirroring the
   existing seams: the fault shim is handed `signal_stub_addr()` +
   `CTX_FAULT_RECORD` at runtime (`native_freebsd.rs:8278`); JIT/futex/kick-signal
   come from the cfg-selected host crate (`native_freebsd.rs:67-83,7473`).

### 3b. Options evaluated

- **(a) `#if defined(__NetBSD__)` calling a helper, inline instructions elsewhere.**
  Compile-time selection is the *only* way to keep FreeBSD/Linux byte-identical
  (the guarded path is not even assembled off-NetBSD). The open questions are
  *what* it calls and *where that lives* — resolved below.
- **(b) Move the swap out of the trampoline into a cfg-selected Rust/C function
  the gateway calls on every lane.** Rejected: adds a call + clobber to
  FreeBSD/Linux, violating constraint 1. Also **dangerous**: it would widen the
  window in which *Rust* runs with the guest FS base installed — today the asm
  installs the guest base *after* all host prep and restores it *before* returning,
  so Rust never executes on guest TLS. Moving the swap into Rust around the call
  risks stack-protector / thread-local reads on a poisoned TLS base.
- **(c) A host-ops function pointer / `NativeHost` trait method, selected by lane.**
  This is the right injection mechanism, but only correct if combined with (a) so
  FreeBSD/Linux never take the indirect path. `carrick-dsr-x86` cannot depend on
  the host crates, so the pointer must be **supplied by the runtime** and stored
  in the context (exactly like the exit-stub addresses are).

### 3c. Chosen design — (a) ∧ (c): compile-time-guarded, host-injected function pointer

**One-line layering rationale:** *the gateway declares WHERE the swap happens; the
host crate supplies HOW (the `sysarch` body), injected as a function pointer just
like the fault/JIT/exit-stub seams — so `carrick-dsr-x86` never learns a NetBSD
ABI and FreeBSD/Linux keep their exact inline instructions.*

Concretely:

1. **`carrick-dsr-x86` (`gateway.rs` / `X86DsrContext`)** gains one new field
   (a `u64` host-agnostic pointer), populated by `enter_translated` from a value
   the runtime supplies (the same way `exit_syscall_addr` etc. are filled at
   `gateway.rs:1359-1362`):
   - `set_fsbase_fn: u64` — address of an `extern "C" fn(base: u64)` that installs
     an FS base via the host's mechanism. `0` on FreeBSD/Linux/Darwin (unused).
   The existing `host_fsbase: u64` field doubles as the per-thread host-base cache
   (see step 4).

2. **`gateway_x86_64.S`** wraps sites 1/2/3 in `#if defined(__NetBSD__)`:
   - **Non-NetBSD (`#else`, the default):** the exact current instructions
     (`rdfsbase %rcx` / `wrfsbase %rax` ×2). **Byte-identical.**
   - **NetBSD:** *no* `rdfsbase` (host base is pre-cached — step 4); at sites 2
     and 3, `mov <base> → %rdi; call *CTX_SET_FSBASE_FN(%r15)` with correct SysV
     stack alignment. `%r15` (the context) is SysV-callee-saved and survives the
     call; at the enter site guest GPRs are not yet loaded and rax/rcx are dead
     (`gateway_x86_64.S:54`); at the exit site the host stack is already active and
     host callee-saved registers are restored from the context immediately after
     (`gateway_x86_64.S:277-282`), so a helper clobber is harmless. The
     return-cache hit path (`.Lresume_guest`) is untouched — it already bypasses
     `.Lfull_exit`.

3. **`carrick-native-netbsd`** gains a small `fsbase` module (host body):
   - `pub extern "C" fn set(base: u64)` — a **TLS-free leaf**: raw
     `sysarch(SYS_sysarch=165, X86_64_SET_FSBASE=17, &base)` via inline `syscall`,
     no libc, no errno, no stack canary. This is the pointer the runtime injects.
   - `pub fn get() -> u64` — `sysarch(…, X86_64_GET_FSBASE=15, &out)`, used **once
     per host thread** at setup (not on the hot path).

4. **Runtime (`native_freebsd.rs`, `#[cfg(target_os = "netbsd")]` arms only):**
   - Once, before the `'run` loop per host thread: `context.host_fsbase =
     carrick_native_netbsd::fsbase::get();` and
     `context.set_fsbase_fn = carrick_native_netbsd::fsbase::set as u64;`.
   - No change to the FreeBSD arm (it leaves `set_fsbase_fn = 0` and the gateway's
     `#else` inline path runs).

This keeps `carrick-dsr-x86` host-agnostic (a `u64` field + a `#if`-guarded call
site — **no** `sysarch` numbers, **no** host-crate dependency), keeps
FreeBSD/Linux byte-identical, and puts the syscall body in the host crate.

### 3d. Pragmatic fallback (document for the reviewer)

If the reviewer prefers the smallest possible surface over strict layering:
**(a1)** define the helper *inside* `carrick-dsr-x86` under
`#[cfg(target_os = "netbsd")]` (or a second `#if`-guarded asm block) as a
hardcoded raw-`sysarch` leaf, called by a fixed symbol name — no context field,
no runtime plumbing, a direct `call` instead of an indirect one. Cost: it embeds
the NetBSD `sysarch` ABI numbers in the "host-agnostic" ISA crate. **That is a
genuine seam-defect escalation** (see §6) and is the only reason (a1) is the
fallback rather than the recommendation.

---

## 4. Fault-shim interaction

No fault or kick shim executes an FSGSBASE instruction (§1d), so the seam does not
add a shim gap. The one host-fsbase restore in the signal path *is* gateway site 3
(the signal exit stub flows through `.Lfull_exit`), which the seam already covers.
The flow on NetBSD:

1. Guest runs with the guest FS base installed (via `sysarch` on NetBSD). A guest
   fault raises SIGSEGV/BUS/FPE/ILL.
2. `native_fault_handler` runs. NetBSD did **not** reset the LWP's FS base for the
   handler, so it runs on the **guest** base → host TLS is poison. This is exactly
   the discipline the NetBSD shim already documents and obeys
   (`carrick-native-netbsd/src/fault.rs:26-35`): no TLS, no allocation, straight-line
   reads of process-global atomics + raw stores through `__gregs[_REG_R15]`.
   **No `rdfsbase` needed** — the context pointer comes from the mcontext, not the
   FS base.
3. The handler rewrites `__gregs[_REG_RIP]` to the signal stub and returns.
4. `sigreturn` restores the interrupted register file. NetBSD carries the FS base
   as `_mc_tlsbase` in the sigframe (`/usr/include/amd64/mcontext.h`) and the base
   is PCB-backed, so the **guest** base is faithfully restored — the shim's
   "the kernel restores the fsbase itself" assumption (fault.rs:31-33,255-257) is
   **verified correct on NetBSD**.
5. The CPU resumes at the signal exit stub with the guest base live; the stub runs
   `.Lfull_exit`, which restores the host base via **site 3** — the seam. Rust then
   runs on host TLS.

The guest base is never lost across a fault: `CTX_GUEST_FSBASE` is authoritative
software state (only Rust writes it), and `CTX_HOST_FSBASE` was set at thread
setup (NetBSD) / last enter (FreeBSD). The kick handler
(`fault.rs` `native_kick_handler`) likewise touches only `__gregs` and needs no
FS-base access.

**Conclusion:** the fault shim needs **no change** for this seam. The only signal-
path fsbase operation that must go through the NetBSD mechanism is gateway site 3,
already handled by §3c step 2.

---

## 5. Correctness invariants (checklist for implementer + reviewer)

1. **Guest sees its own base during guest execution.** Between site 2 (install
   guest) and site 3 (restore host), the hardware FS base equals
   `CTX_GUEST_FSBASE` (including 0). Guest `fs:` `Copy` accesses depend on this.
2. **Host never runs on the guest base.** No Rust/libc instruction executes
   between site 3 and the next site 2. In particular the swap must stay **inside**
   the asm boundary (rejecting option (b)); on NetBSD the `set_fsbase_fn` helper
   must be TLS-free so it does not itself deref the (guest) base.
3. **Host base is restored on every full exit**, including the `Signal` exit stub
   and the `Kicked` exit stub. Only the return-cache hit (`.Lresume_guest`) may
   skip it, and it also skips re-entering Rust — the invariant holds.
4. **A mid-guest signal restores the host base before host handler *logic* runs.**
   The handler body itself runs on the guest base (poison TLS) and must remain
   signal-async-safe with no TLS (already true); host base is re-established at the
   signal stub (site 3), not in the handler.
5. **`CTX_HOST_FSBASE` is valid before the first enter on each host thread.** On
   NetBSD it is captured once via `fsbase::get()` at thread setup; on FreeBSD it is
   captured by the enter `rdfsbase`. A new guest thread → new `X86DsrContext` →
   fresh capture. After `fork`, the child host thread keeps the same FS base (fork
   preserves it), and the child rebuild re-establishes the context; the implementer
   must ensure the NetBSD host-base capture runs on the rebuilt child's run-loop
   entry (`fork_child_rebuild` path, `native_freebsd.rs:9727`).
6. **Host base is genuinely invariant per host thread** — the runtime must never
   `sysarch(SET_FSBASE)` for a host thread except to install a *guest* base inside
   the gateway boundary. If any future code sets the host thread's own base, the
   GET-elimination cache (§2b) is invalidated. (Guard: a debug assert that a fresh
   `get()` still equals the cached value at an occasional boundary.)
7. **`ARCH_SET_FS`/guest `wrfsbase` update software state only.** They write
   `CTX_GUEST_FSBASE`; the new base reaches hardware on the *next* enter (site 2).
   No change from today; unaffected by the seam.
8. **Byte-identical proof for the proven lanes.** The FreeBSD/Linux-selected
   assembly for `carrick_dsr_x86_enter_raw` / `carrick_dsr_x86_exit_common` must be
   byte-for-byte unchanged vs. `main` (see §7 verification).

---

## 6. Seam-defect / layering escalation

- **Chosen design (§3c):** the single host-conditional in `carrick-dsr-x86` is the
  `#if defined(__NetBSD__)` in `gateway_x86_64.S`, which selects *mechanism*
  (inline instruction vs. injected-pointer call) and embeds **no** host ABI. The
  new `set_fsbase_fn` field is a host-agnostic `u64`. The crate still compiles on
  any x86_64 host and gains no host-crate dependency. **This is defensible as
  within the gateway's pre-existing "single target boundary" and is NOT a
  seam-defect escalation.**
- **Fallback (§3d, a1):** defining the `sysarch` helper *in* `carrick-dsr-x86`
  embeds `SYS_sysarch`/`X86_64_SET_FSBASE` in the ISA crate. **That IS a seam-defect
  escalation** — flag it explicitly if the reviewer chooses it.
- **No change is required to `carrick-dsr`'s `NativeHost`/`GuestIsa`/`NativeLane`
  traits.** The pointer is injected via the runtime's existing per-context fill,
  not via a new trait method. (An *optional* tidy: expose the pointer through a
  defaulted `NativeHost::x86_fsbase_set_fn() -> Option<u64>` mirroring
  `vdso_tsc_calibration()` at `lane.rs:82`; this is a style choice, not a
  requirement, and is the only place a trait touch would even be considered.)

---

## 7. Implementation plan (ordered; each step independently verifiable)

**T1 — `carrick-native-netbsd::fsbase` (host body).**
Add `set(base: u64)` (raw `sysarch` SET, TLS-free leaf) and `get() -> u64`
(`sysarch` GET). Unit-test on the box: `get()` returns a plausible base;
`set(get())` round-trips; `set(x); get() == x` for a scratch page. *Verify:*
`cargo test -p carrick-native-netbsd` on VM 201.

**T2 — `carrick-dsr-x86` context field.**
Add `set_fsbase_fn: u64` to `X86DsrContext` (init 0), a `CTX_SET_FSBASE_FN`
offset const + `.equ`, and the `offset_of!` static-assert (mirror the existing
`CTX_*` asserts at `gateway.rs:1202-1257`). Fill it to 0 by default in
`enter_translated`/`prepare_entry` (runtime overrides on NetBSD). *Verify:*
`cargo build -p carrick-dsr-x86` on macOS/FreeBSD/NetBSD; the `size_of`/offset
asserts pass.

**T3 — `gateway_x86_64.S` compile-time seam.**
Wrap sites 1/2/3 in `#if defined(__NetBSD__)`. `#else` = today's exact
instructions. NetBSD branch = pointer-call at sites 2/3 (rdi = base), no rdfsbase
at site 1. Keep SysV 16-byte stack alignment at each call; preserve `%r15`.
*Verify (byte-identical, the key gate):* on macOS/FreeBSD, `objdump -d` the
`enter_raw`/`exit_common` symbols from a `main` build and from this branch and
`diff` — must be **empty**. (`__NetBSD__` is undefined there, so the `#else`
assembles unchanged.)

**T4 — runtime NetBSD wiring.**
In the `#[cfg(target_os = "netbsd")]` run-loop setup (per host thread, incl. the
`fork_child_rebuild` re-entry), set `context.host_fsbase = fsbase::get()` and
`context.set_fsbase_fn = fsbase::set as u64` before the first enter. No FreeBSD-arm
change. *Verify:* the FreeBSD lane still builds/runs unchanged.

**T5 — NetBSD end-to-end.**
Build carrick for `target_os = "netbsd"`, run the native lane on VM 201: a static
hello, a TLS-using binary (proves guest `fs:` reads hit the guest base), a
fork+exec, and a signal/fault fixture (proves the signal-stub host restore). Then
run the LTP native-lane subset the NetBSD plan uses. *Verify:* no SIGILL at
gateway entry; guest TLS correct; fault/signal fixtures pass.

**T6 — FreeBSD/Linux non-regression.**
Re-run the `carrick-dsr-x86` execution tests (`tests/native_execution.rs`,
`tests/native_static_elf.rs`) and the FreeBSD native lane. *Verify:* green +
the T3 byte-identical diff is empty.

**T7 (optional) — SET-shadow.**
Add a per-thread "current hardware base" shadow to skip a redundant SET when the
target already matches (guest == host, or `ARCH_SET_FS` to the same value). Gate
on a measured win in a syscall-heavy LTP run; otherwise drop.

---

## 8. Summary for the reviewer

- **Swap frequency:** PER-CROSSING (1 GET + 2 SET per guest↔host round-trip that
  reaches Rust; chained/return-cache stays in the JIT with zero swaps).
- **`sysarch` cost (NetBSD 10.1 VM, idle):** GET ≈ 60 ns, SET ≈ 52 ns (≈ `getpid`).
  Naive tax ≈ 164 ns/guest-syscall; GET-eliminated ≈ 104 ns.
- **Caching:** not required for correctness; **GET-elimination (host base cached
  once per host thread) is free and recommended for v1**; SET-shadow optional.
- **Seam shape:** `#if defined(__NetBSD__)` in `gateway_x86_64.S` calling a
  host-injected `set_fsbase_fn` pointer (body = raw `sysarch` in
  `carrick-native-netbsd`); FreeBSD/Linux keep the exact inline
  `rdfsbase`/`wrfsbase` (guarded path not assembled off-NetBSD → provably
  byte-identical).
- **Fault shim:** no change; NetBSD's PCB-backed `_mc_tlsbase` restores the guest
  base across signal delivery, and the signal stub restores the host base via
  gateway site 3.
- **Layering:** chosen design keeps `carrick-dsr-x86` host-agnostic (no `sysarch`
  ABI, no host-crate dep) — **not** a seam defect. Only the §3d fallback would be.
