# Guest-Side Syscall Shim — Vetting, Validation & Implementation

Status / progress (most recent first):

- **Tier 1 complete** — `gettid` serviced at EL1 via a per-vCPU `TPIDR_EL1` read
  (with a `cbz` trap-fallback guard), joining `getpid`/`getuid`/`geteuid`/
  `getgid`/`getegid`. Full-stack: `gettid` host traps 1000 → 0.
- **Phase 1 (EL1-vector identity fast path)** — the per-process identity reads.

Deferred with validated next steps (§6): Tier 2 (`futex` ring), Tier 3
(`write`/`read`), Phase 4 (LD_PRELOAD).

This document records the result of vetting the exploration in `goal.md` (the
LD_PRELOAD / shared-ring / EL1-vector shim) against the actual carrick codebase,
validates which parts are sound, and tracks the implementation as it lands.

---

## 1. What the exploration proposed

Eliminate the EL0→EL1→EL2→host round-trip (~2–5µs) for hot syscalls by servicing
them in the guest, generalising the vDSO. Five phases were sketched:

- **Phase 0** — extend the vDSO with `__kernel_getpid`/`gettid`/`getuid` and a
  process-identity vvar.
- **Phase 1** — replace the flat `hvc #2` EL1 vector stub with a bitmap check +
  fallthrough.
- **Phase 2** — `futex(FUTEX_WAKE)` via a shared-memory command ring.
- **Phase 3** — `write`/`read` via the ring with inline payloads.
- **Phase 4** — an `LD_PRELOAD` `carrick-shim.so` to pre-copy payloads.

Five open questions (Q1–Q5) asked which approach to prioritise, sync vs async
ring, first syscall, FEAT_PAN feasibility, and the cross-compile toolchain.

---

## 2. Vetting findings (claims checked against the code)

| Plan claim | Verdict | Evidence |
|---|---|---|
| Trap path `svc → EL1 hvc #2 → HVF exit → dispatch` | ✅ accurate | `el1_vectors_bytes` slot `0x400` = `hvc #2; eret` (`carrick-mem/src/memory.rs:1699`); `VBAR_EL1` ← `LINUX_EL1_VECTORS_BASE` (`carrick-hvf/src/trap.rs:1741`) |
| Identity-mapped memory; ring readable by host at same VA | ✅ accurate | identity IPA==VA; host writes the backing buffer via `write_guest_bytes` (`trap.rs:2845`) |
| **Phase 0: add `__kernel_getpid` etc. to the vDSO** | ❌ **unsound** | Real aarch64 Linux exports only `__kernel_{clock_gettime,gettimeofday,clock_getres,rt_sigreturn,getrandom}`. There is **no `__kernel_getpid`** — guest libc/Go never look one up, so the symbol would be dead code. See `crates/carrick-mem/src/vdso.rs` symbol set. |
| Identity calls are "trivial register returns" | ❌ **oversimplified** | Their values are **virtualised, mutable, and per-thread** — see §3. They cannot be a static stamp of `libc::getpid()`. |
| EL1 vector interception can service syscalls without a VM exit | ✅ feasible | The slot already runs EL1 code and `eret`s to EL0; a dispatcher that returns in `x0` is a clean extension (§4). |
| FEAT_PAN blocks EL1 access to guest *user* memory | ✅ confirmed, and avoided | HVF forces `PSTATE.PAN=1` (`memory.rs:1398`). The **kernel hole** (AP=00) is EL1-accessible regardless of PAN, so the identity data page lives there — no `ldtr`/PAN toggle needed. |

### The decisive correction

Phase 0 (vDSO) and Phase 1 (EL1 vector) are **not** complementary tiers for the
identity calls — Phase 0 simply does not work for them. The EL1-vector approach
is the *only* sound way to intercept arbitrary `svc #0` syscalls (it sees every
syscall regardless of how the guest issued it, including static Go/musl). It
therefore **subsumes** Phase 0. The implemented slice is Phase 1 done correctly.

---

## 3. Why identity syscalls are not constant (the trap that sinks Phase 0)

`getpid`/`getuid`/… do **not** return a host constant in carrick:

- **`getpid` (172)** → `namespace::pid::self_ns_pid()` — host pid, or the
  ns-local pid (1…N) inside a PID namespace (`dispatch/creds.rs:236`). Stable for
  a process's lifetime; set at create/fork/exec.
- **`getuid/geteuid/getgid/getegid` (174–177)** → `CredState.{ruid,euid,rgid,egid}`
  (`dispatch/creds.rs:78`), **mutable at runtime** by `setuid`/`setresuid`/… 
  (`creds.rs:444–511`).
- **`gettid` (178)** → `guest_visible_tid()` — **per-thread**, and depends on the
  process's live thread count and ns translation (`dispatch/mod.rs:670`).
- **`getppid` (173)** → ns ppid, bootstrap `1`, or a **live** `libc::getppid()`
  (`creds.rs:642`) — changes on reparenting.

Consequences for the design:

1. The correct values live in **`carrick-runtime`** (dispatch/namespace/creds).
   `carrick-hvf` deliberately has **no** dependency on the dispatcher
   (`trap.rs:169`). So the data page must be **stamped from the runtime layer**,
   which is the only layer holding both the values and an engine handle / a
   `GuestMemory` writer.
2. The page must be **re-stamped at every point a value changes**: boot, fork
   (child), exec, and each cred mutation. Lazy stamping is impossible because the
   EL1 fast path bypasses the dispatcher entirely.
3. `gettid` is per-thread; a single per-process page cannot serve it (all threads
   of a process share one VM / one stage-2 mapping). It needs **per-vCPU**
   addressing — deferred (§6).
4. `getppid` can go stale on reparenting — **excluded** from the fast path.

---

## 4. Implemented slice — EL1-vector identity fast path

### Data page (kernel hole)

A new boot-mapped region, `LINUX_IDENTITY_PAGE_BASE = LINUX_KERNEL_REGION_BASE +
0x1E4000` (immediately after the EL1 maintenance trampoline, still inside the
kernel-only first 2 MiB block, so it is **AP=00**: EL1 RW, EL0 no-access). Layout:

```
+0x00  pid    (u32)   — self_ns_pid()
+0x04  uid    (u32)   — CredState.ruid
+0x08  euid   (u32)   — CredState.euid
+0x0C  gid    (u32)   — CredState.rgid
+0x10  egid   (u32)   — CredState.egid
```

(`crate::memory::{LINUX_IDENTITY_PAGE_BASE, IDENTITY_OFF_*, IDENTITY_SYSCALLS}`.)
It is `shared:false`, so fork takes a private snapshot (like the vvar) and the
child re-stamps; exec rebuilds it fresh. The host stamps it via
`write_guest_bytes` (writes the host backing directly — works on a read-only
guest region, exactly as `populate_vdso_data_page` writes the read-only vvar).

### EL1 vector dispatcher

Slot `0x400` becomes a compare chain that **clobbers nothing except NZCV**
(restored by `eret`) before deciding to intercept:

```asm
cmp  x8, #172          ; getpid   — cmp only sets flags
b.eq h_pid
cmp  x8, #174          ; getuid
b.eq h_uid
cmp  x8, #175 …        ; geteuid/getgid/getegid
…
hvc  #2                ; not intercepted: x0..x5,x8 untouched → host dispatch
eret
```

There is deliberately **no in-page enable check**: testing a flag would need a
scratch register, and the only safe one (`x0`) is a live syscall arg on the
fallthrough path. The feature is instead a **build-time** choice
(`el1_vectors_bytes_shim` vs `el1_vectors_bytes`), selected per process from
`CARRICK_SYSCALL_SHIM` (default off) when the address space is built — so the
dispatcher only exists when the shim is on, and the legacy page is byte-identical
otherwise. Each handler (placed in the page's `nop` tail, branch-reachable) is:

```asm
h_pid:  movz x0,#lo ; movk x0,#mid,lsl#16 ; movk x0,#hi,lsl#32 ; ldr w0,[x0,#off] ; eret
```

It builds the page address **in `x0`** (the syscall return register — safe to
clobber) and loads the field. No EL1 stack, no scratch spill, no PAN issue. The
address is materialised inside the handler (after the eligibility decision) so
`x0` (= syscall arg0) is never corrupted on the fallthrough path. `ldr w0`
zero-extends — matching the kernel's 32-bit unsigned return for these calls.

**`gettid` (per-thread).** Unlike the per-process reads, `gettid` differs per
thread, and all threads of a process share one identity page (one VM). So its
handler reads the tid from the **per-vCPU `TPIDR_EL1`** instead, which carrick
stamps with the thread's guest-visible tid (`TPIDR_EL1` is EL1-only and unused by
carrick — the guest uses `TPIDR_EL0` for TLS):

```asm
h_gettid:  mrs x0, TPIDR_EL1 ; cbz x0, <fallthrough> ; eret
```

The `cbz` is defense-in-depth: a tid is never 0, so an unstamped `TPIDR_EL1`
(a missed per-vCPU stamp) traps to the host (correct, slow) rather than returning
a wrong `gettid()==0`.

Cost: a handful of EL1 `cmp`s added to every *trapped* syscall (negligible vs a
µs-scale VM exit); intercepted calls save the entire exit.

### Stamping points (runtime-driven)

- **Boot** — `stamp_identity_page` writes `dispatcher.identity_snapshot()`
  (ns-pid + creds) before the first vCPU run (in
  `run_address_space_with_hvf_and_dispatcher`).
- **Fork child** — re-stamp once the child's ns-pid is registered (both run
  loops; `ForkOutcome::Child`).
- **Exec** — re-stamp into the freshly rebuilt page after `execve_into`.
- **Cred mutations** — `creds.rs` `set*uid`/`set*gid` handlers re-stamp the cred
  fields via `cx.memory` (`stamp_identity_creds`) after mutating `CredState`,
  capturing the snapshot before dropping the lock to avoid re-entrancy.
- **Per-vCPU tid (`gettid`)** — `stamp_guest_tid` writes `TPIDR_EL1` via
  `HvfTrapEngine::set_guest_thread_id` at every vCPU (re)creation: thread entry
  (`run_vcpu_until_exit` — main at boot, each worker at spawn), fork child, and
  exec. The shim only ever runs under the threaded loop, so this one chokepoint
  covers it; the `cbz` guard backstops any gap.

### ptrace interaction

A fast-path syscall is invisible to a `PTRACE_SYSCALL` tracer. carrick emulates
**no syscall-entry/exit stops** today (only signal/exec stops — `dispatch/proc.rs`,
`dispatch/signal.rs`), and `gettid`/`clock_gettime` are *already* invisible, so
this introduces **no new divergence**. If syscall-stop emulation is ever added,
the build-time toggle (or skipping `with_el1_vectors_shim` for a traced process)
is the escape hatch.

---

## 5. Answers to the open questions

- **Q1 (which approach)** — EL1 vector interception, not LD_PRELOAD/extended-vDSO,
  for register-only calls. It covers static binaries and needs no guest toolchain.
- **Q2 (sync/async ring)** — N/A for Tier 1 (pure data-page reads, no host
  involvement). For Tier 2 the recommendation is fire-and-forget for
  `FUTEX_WAKE`/`close`/`madvise`, synchronous for value-returning calls.
- **Q3 (first syscall)** — `getpid` + the four credential reads: the safe set
  (per-process, single stamp path). `gettid`/`futex` follow once per-vCPU /
  the ring exist.
- **Q4 (FEAT_PAN / ldtr)** — **not needed**. Keeping the data page in the
  AP=00 kernel hole sidesteps PAN entirely. `ldtr`/PAN-toggle only become
  relevant for Tier 2/3 calls that touch guest *user* buffers from EL1.
- **Q5 (toolchain)** — **not needed** for the EL1-vector path; the dispatcher is
  hand-assembled raw bytes like the existing vDSO/vectors. A cross-compiler is
  only required for the (deferred) `LD_PRELOAD` `.so`.

---

## 6. Deferred — validated next steps (not implemented here)

- ~~**`gettid` via per-vCPU TPIDR_EL1.**~~ **DONE** — implemented as a direct
  `mrs x0, TPIDR_EL1` (the tid value lives in the sysreg, not a slot the doc
  originally sketched), with a `cbz` trap-fallback guard. See §4.
- **Tier 2 — `futex(FUTEX_WAKE)` / `close` / `madvise` via a command ring.**
  Ring in the boot-mapped shared aperture (`shared_aperture.rs`, satisfies the
  no-post-vCPU-`hv_vm_map` stage-2 stability invariant); fire-and-forget; a host
  service thread drains it. The ring **header/control** must be in the kernel hole
  (PAN), payloads pre-copied at EL0.
- **Tier 3 — `write`/`read` inline payloads.** Needs the LD_PRELOAD `.so` (Q5) or
  EL0 pre-copy to satisfy PAN.

---

## 7. Verification

Done:

- **Unit (`cargo test -p carrick-mem`)** — `el1_shim_tests` decode the generated
  dispatcher and assert it services exactly `IDENTITY_SYSCALLS`, each branching to
  a handler that builds `LINUX_IDENTITY_PAGE_BASE` and loads its field; plus the
  builder/region and kernel-hole placement invariants.
- **Unit (`cargo test -p carrick-runtime`)** — `identity_snapshot` reads the same
  sources as the `getpid`/`get*id` handlers (fast and trap paths can't disagree).
- **End-to-end on real HVF** (`trap_hvf.rs`, gated/self-skipping; run by
  ad-hoc-signing the test binary with the hypervisor entitlement — note HVF
  allows ONE VM per process, so run each `el1_*` test in its OWN process via
  `--exact`):
  - `el1_shim_services_getpid_at_el1_without_a_host_trap` runs a `getpid;
    exit_group` guest and asserts the FIRST host-visible trap is `exit_group`
    (94), not getpid (172), with `x0` == the stamped pid — proving the dispatcher
    executes correctly under `PSTATE.PAN=1`. `el1_legacy_vectors_trap_getpid_to_the_host`
    is the control (getpid DOES trap without the shim).
  - `el1_shim_services_gettid_from_tpidr_el1` asserts `gettid` returns the stamped
    `TPIDR_EL1` value with no host trap; `el1_shim_gettid_guard_traps_when_tpidr_el1_unstamped`
    asserts the `cbz` guard traps (x8=178) instead of returning 0 when unstamped.
- **Full-stack** — `CARRICK_TRACE_TRAPS=1 carrick run-elf <loop>` with the shim
  off vs `CARRICK_SYSCALL_SHIM=1` on: `getpid` host traps 1001 → 0 (value matches
  the real pid), and `gettid` host traps 1000 → 0 (value matches the tid).
- Compile + `cargo clippy` clean for the changed code; carrick-mem (56) +
  carrick-runtime lib (302) green (one PRE-EXISTING integration failure,
  `dispatch_declares_no_abi_constants` on `LINUX_PTRACE_PEEKTEXT` in
  `dispatch/proc.rs`, is unrelated to this change).

Pending (full rollout): the Docker-backed `just conformance` gate run with
`CARRICK_SYSCALL_SHIM=1` before flipping the default to on.
