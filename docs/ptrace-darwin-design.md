# Design: Linux `ptrace(2)` on carrick (Darwin / HVF)

Status: **Phase 1 IMPLEMENTED + verified (2026-05-26)**; Phases 2–4 remain
design. Author: research agent, 2026-05-26. Driven via the superpowers
`brainstorming` skill (context exploration → approach comparison →
recommendation → written design).

> **Phase 1 landed.** Guest `BRK`/step/HW-debug exceptions now deliver SIGTRAP
> (`el0_debug_signal` + `deliver_fault_signal`, `crates/carrick-runtime/src/runtime.rs`)
> instead of a fatal SIGSEGV. All six `TestDebugCall*` pass under carrick,
> matching the Docker linux/arm64 oracle, and the **entire `runtime` package now
> runs to completion (341 PASS / 0 FAIL, docker=341 carrick=341)** — the
> previously-assumed "runtime early hang" was this BRK bug killing the test
> binary mid-suite, *not* the stage-2 coherence bug it was attributed to. R-1
> (ELR points at the BRK) confirmed via `carrick trace` (EC=0x3c, ESR=0xf2000000)
> and proven by the passing GrowStack/Panic phases that step past BRKs with
> `set_pc(pc+4)`. `ptrace(2)` itself is unchanged (still ENOSYS — the test never
> calls it). Phases 2–4 (cross-process ptrace for gdb/Delve) remain unbuilt and
> are not exercised by the Go conformance harness.

Scope: make Go's `runtime.test` `TestDebugCall` family pass on carrick, and lay a
phased path to Delve/`gdb`/`lldb`-style debugging of guest processes. Deliverable
is this document; it changes no other code.

---

## 0. TL;DR

The headline result of the research is that **`TestDebugCall` does not use
`ptrace` at all** when it runs normally. It uses an *in-process*, signal-driven
protocol: a "tracer" goroutine sends `SIGTRAP` to a worker OS-thread via
`tgkill`, and the worker's own `SIGTRAP` signal handler reads/rewrites the
interrupted register context (PC, SP, LR, x0–x30, FP/SIMD) through the
`ucontext_t`, injects a call frame, and detects completion when the injected
call executes `BRK #0` (which re-enters the same `SIGTRAP` handler).

carrick already implements essentially every primitive this needs:

- `tgkill`/thread-directed signal routing (`dispatch/signal.rs`, `host_signal.rs`).
- A full Linux-aarch64 `ucontext_t`/`sigcontext` signal frame **built from live
  vCPU registers and restored on `rt_sigreturn`**, including FP/SIMD V0–V31
  (`trap.rs::inject_signal`/`restore_from_sigframe`, `linux_abi.rs`).
- `/proc/<pid>/status` already emits `TracerPid:\t0`, which is exactly what the
  test's `skipUnderDebugger` reads (`vfs/proc.rs`).

There is **one** real gap blocking `TestDebugCall`: a guest `BRK #0` currently
surfaces as a fatal `EL0Fault` → SIGSEGV-terminate instead of a `SIGTRAP`
delivered to the guest handler. Closing that — recognising the BRK/step/HW-debug
exception classes in the trap loop and delivering `SIGTRAP` with the right
`si_code` — is the **first milestone** and is small and self-contained.

Real `ptrace` (TRACEME/ATTACH/PEEK/POKE/GETREGSET/CONT/SINGLESTEP) is a *later*
phase needed for `TestGdb*`/`TestLldb*`/Delve, where the **tracer and tracee are
separate carrick host processes** with separate HVF VMs and address spaces. That
is the genuinely hard part, and the recommended architecture is an
**in-runtime ptrace state machine brokered between processes**, using the same
host-`wait4` + signal plumbing carrick already uses for the guest process tree,
rather than forwarding to Darwin's own (very limited) `ptrace(2)`.

---

## 1. What carrick is, and the primitives ptrace can build on

carrick runs unmodified Linux aarch64 ELF binaries on macOS/Apple-Silicon by
running the guest in Apple Hypervisor.framework (HVF) and emulating the Linux
syscall ABI in a Rust host runtime. Each guest **process** is a real macOS
process; each guest **thread** is a host thread driving one HVF vCPU. Relevant
facts established by reading the code:

### 1.1 Full guest register + memory control (within a process)

- GP/PC/SP/PSTATE/sysreg access: `applevisor` `Vcpu::get_reg`/`set_reg`/
  `get_sys_reg`/`set_sys_reg`, used pervasively in
  `crates/carrick-runtime/src/trap.rs` (e.g. the `Aarch64SyscallFrame` build at
  `trap.rs:1530`, the EL0Fault snapshot at `trap.rs:1457`).
- FP/SIMD V0–V31 + FPSR/FPCR: `save_fpsimd_into`/`restore_fpsimd_from`
  (`trap.rs:2079`, `trap.rs:2105`), routed through a C shim (`set_simd_fp_reg_v`,
  `trap.rs:344`) to work around an `applevisor` vector-class FFI bug
  (documented in memory: "SIMD/FP register restore ABI bug").
- Guest memory: `GuestMemory` trait + VFS; `read_guest_bytes`/`write_guest_bytes`
  on the engine; syscall handlers go through `cx.memory` (`dispatch/mem.rs`,
  `dispatch/mod.rs`).

### 1.2 The trap loop and how exceptions are classified

`HvfTrapEngine::run_until_syscall` (`trap.rs:1383`) is the core loop:

- `hv_vcpu_run` returns; on `ExitReason::EXCEPTION` it reads the syndrome.
- carrick installs an EL1 vector page that catches **all** lower-EL synchronous
  exceptions and re-traps them to the host via `hvc #0` (EC=0x16). So the loop
  sees EC=0x16, then reads `ESR_EL1` to find what *actually* trapped
  (`trap.rs:1451`).
- If `ESR_EL1` is an `svc #0` (EC=0x15) → it's a syscall; build the frame.
- Else if it's an emulatable EL0 system-register read (CNTVCT/CNTFRQ) → emulate
  and resume (`trap/sysreg.rs`).
- **Otherwise it returns `TrapError::EL0Fault { syndrome, elr, far, … }`**
  (`trap.rs:1485`).

`el0_fault_signal` (`runtime.rs:2007`) maps the EL0Fault ESR to a Linux
`(signum, si_code)`: instruction/data aborts → SIGSEGV/SIGBUS, **everything else
→ `None` → terminate with SIGSEGV** (`runtime.rs:2062`, `deliver_fault_signal`).

> Consequence: a guest `BRK #imm` (EC=`0x3c`), a software-step exception
> (EC=`0x32`/`0x33`), or a HW breakpoint/watchpoint (EC=`0x30`/`0x31`,
> `0x34`/`0x35`) currently lands in the "untranslatable fault" arm and **kills
> the guest with SIGSEGV**. This is the single concrete blocker for `TestDebugCall`.

### 1.3 The signal subsystem (intra-process delivery)

- Thread-directed and process-directed pending signals, with Linux↔macOS signum
  translation (`host_signal.rs`: `publish_pending_for`, `take_pending_for`,
  `linux_to_host_signum`/`host_to_linux_signum`, table at `host_signal.rs:48`).
- `tkill`/`tgkill` route to a specific guest tid via `route_thread_signal`
  (`dispatch/signal.rs:217`/`:237`); self-targeted raises queue for self-delivery.
- Delivery (`runtime.rs::deliver_pending_signal`, `:1854`+) injects a Linux
  signal frame and, for SA_SIGINFO, an accurate `siginfo`/`ucontext`.
- **`inject_signal` (`trap.rs:1867`) builds the frame from the *live* vCPU regs**:
  31 GP regs + SP + PC + PSTATE into `LinuxSignalContext`, FP/SIMD into
  `__reserved` (`save_fpsimd_into`), plus a `siginfo` whose
  `(si_code, si_addr)` come from a `fault_siginfo: Option<(i32,u64)>` parameter
  (`trap.rs:1942`). It sets x0=signum, x1=&siginfo, x2=&ucontext, x30=restorer.
- **`restore_from_sigframe` (`trap.rs:2150`) writes the (possibly handler-mutated)
  context back to the vCPU**: all 31 GP regs (`trap.rs:2175`), V0–V31+FPSR/FPCR
  (`restore_fpsimd_from`), PC←ELR_EL1, SP←SP_EL0, PSTATE←SPSR_EL1.

This build-from-live-regs / restore-mutated-context round trip is *exactly* the
kernel behaviour Go's debug-call protocol relies on (it mutates `uc_mcontext`
inside the handler, then `rt_sigreturn`s).

### 1.4 The process model and cross-process coordination

- Guest `fork`/`clone(!CLONE_THREAD)` → real `libc::fork` of the carrick host
  process; the host process tree mirrors the guest tree, and **guest pid == host
  pid** (`dispatch/proc.rs:22`–30 comment; `runtime.rs:608` Fork handling;
  `trap.rs::fork` at `:2199` rebuilds a fresh HVF VM in each side).
- Guest `wait4`/`waitid` forward to host `libc::wait4`/`waitid`, including
  `WUNTRACED`/`WSTOPPED`/`WCONTINUED`, with a Linux-status translation
  (`dispatch/proc.rs:724` `wait4`, `:624` `waitid`, `translate_wait_status`
  `:950`, `waitid_state_requested` `:987`). carrick **already adapts Darwin
  stop-state reporting to Linux `W*` semantics** (memory: "os/exec waitid
  stop-state bug DONE").
- Cross-process signals forward to `libc::kill` with signum translation
  (`dispatch/signal.rs:646`, `bootstrap_signal_send`).
- Cross-thread vCPU "kick": `hv_vcpus_exit` forces a sibling vCPU out of
  `hv_vcpu_run` so a pending signal can be delivered (`vcpu_kick.rs`,
  `VcpuKicker::kick`).
- **Stop-the-world Pause-Modify-Resume barrier** `PtQuiesce`/`pt_barrier`
  (`fork_quiesce.rs:144`+): one coordinator thread pauses every *other* vCPU
  thread of the same process at a lock-safe point, mutates shared guest state
  (today: stage-1 page tables), then resumes. This is the precise shape needed
  to freeze a multithreaded tracee while the tracer inspects/modifies it.
- Mach is available: per-thread Mach ports are recorded (`host_proc.rs`
  `ThreadPort`, `record_thread_port`), and `host_proc.rs` already uses Mach
  `proc_pidinfo`/thread state for `/proc` synthesis. So `task_for_pid` +
  `thread_get_state`/`mach_vm_read` against another carrick process is *possible*
  — but, as argued in §5, not the best tool here.

### 1.5 Current `ptrace` status

`ptrace` (nr **117**) is a bare stub returning `ENOSYS`
(`dispatch/proc.rs:571`), dispatched at `dispatch/mod.rs:1006`, classified
`SupportLevel::BringUp` (`syscall.rs:243`). A test asserts the ENOSYS
(`tests/syscall_process.rs:126`).

---

## 2. The actual `TestDebugCall` requirement (grounded in Go source)

Read: `src/runtime/debug_test.go`, `src/runtime/export_debug_arm64_test.go`,
`src/runtime/debugcall.go` (via raw.githubusercontent.com).

`TestDebugCall` and friends call `runtime.InjectDebugCall(g, fn, &regs, args,
debugCallTKill, false)`. Key facts:

1. **The stop mechanism is `tgkill(SIGTRAP)`, not ptrace.** The test's
   stopper is:
   ```go
   func debugCallTKill(tid int) error {
       return syscall.Tgkill(syscall.Getpid(), tid, syscall.SIGTRAP)
   }
   ```
   The "tracer" goroutine and the worker thread are in the **same process**
   (`debugCallWorker` does `runtime.LockOSThread()`).

2. **`skipUnderDebugger` is not a hard requirement.** It reads
   `/proc/<getpid>/status`, regex-matches `TracerPid:\s+([0-9]+)`; if the field
   is missing it only `t.Logf("couldn't find proc tracer PID")` and **returns
   (does not skip)**; if non-zero it `t.Skip`s ("deadlock under a debugger"). The
   "couldn't find proc tracer PID" line quoted in the task is a benign log, not a
   failure. carrick already serves `TracerPid:\t0`, so the test proceeds in the
   normal (non-skip) path.

3. **The SIGTRAP handler does the work, via the saved context.** On arm64
   (`export_debug_arm64_test.go`), the handler:
   - reads/writes GP regs via `ctxt.regs().regs[i]`, `ctxt.sp()/set_sp()`,
     `ctxt.pc()/set_pc()`, `ctxt.lr()/set_lr()` (the `sigcontext`);
   - sets up the call: `set_pc(fn)`, `set_lr(pc+4)` (return past a trap),
     `regs[26]=ctxt` (closure/context), copies args above SP, decrements SP;
   - detects completion by reading the faulting instruction:
     `*(*uint32)(sigpc) == 0xd4200000` i.e. **`BRK #0`**;
   - steps past BRKs with `set_pc(pc+4)` for the panic/unsafe/return phases.

4. **The completion trap is an in-guest `BRK #0` that re-enters the SIGTRAP
   handler.** The protocol is a state machine (`debugCallRun=0`,
   `debugCallReturn=1`, `debugCallPanicOut=2`, `debugCallUnsafe=8`,
   `debugCallSystem=16`) driven entirely by (a) the tracer's `tgkill(SIGTRAP)`
   to enter, and (b) the injected call hitting `BRK #0` to re-enter — all
   in-process, no ptrace.

**Therefore the requirement reduces to two carrick behaviours:**

- (A) `tgkill(SIGTRAP)` to a specific worker tid delivers a SIGTRAP whose
  injected `ucontext` accurately reflects the worker's PC/SP/LR/x*/FP, and whose
  handler-mutations are applied on `rt_sigreturn`. **Already implemented** —
  §1.3. (The only nuance: the handler is entered via the *kick* path
  (`interrupted_pc = Some(pc)`), where `inject_signal` redirects `Reg::PC`
  directly — `trap.rs:2045` — which is correct.)

- (B) An in-guest `BRK #0` is delivered to the worker's SIGTRAP handler (with
  `si_code = TRAP_BRKPT`, `si_addr = PC`), **not** turned into a fatal SIGSEGV.
  This is the **one missing piece**.

A subtlety for (B): the handler must observe `sigpc` (the saved PC) pointing at
the `BRK` instruction. On Linux, a `BRK`-generated SIGTRAP reports the PC *of*
the BRK (it is a fault, not a trap-after). The trap loop must therefore deliver
the signal with the saved PC = the BRK's `ELR_EL1` (which for a synchronous BRK
is the BRK instruction's own address), so `*(*uint32)(sigpc) == 0xd4200000`
holds. This must be verified against HVF's `ELR_EL1` semantics for BRK (see
§7 R-1).

---

## 3. The crux: tracer and tracee are separate host processes

For *real* ptrace (Phase 3+, Delve/gdb/lldb), the tracer is a different guest
process from the tracee. In carrick that means:

- Two **separate macOS processes**, each with its **own HVF VM**, its own
  `KernelState`/dispatcher, its own `ThreadRegistry`, its own guest RAM mapping.
- The tracer's carrick cannot call the tracee's `Vcpu::set_reg` or
  `engine.write_guest_bytes` directly — those live in another process.
- But: guest pid == host pid, `wait4` already forwards to the host, and signals
  already forward via `libc::kill`. So the *control-plane* (who-stopped-whom,
  wait reporting) can ride the existing host-process plumbing; only the
  *data-plane* (peek/poke/getregs/setregs/cont/step of another process's vCPU)
  needs a new cross-process mechanism.

This is the central design decision, addressed in §4–§5.

---

## 4. Approaches considered

### Approach A — Forward to Darwin `ptrace(2)` + Mach
Map Linux ptrace onto Darwin's `ptrace` (PT_TRACE_ME/PT_ATTACH/PT_CONTINUE/
PT_STEP/PT_KILL) plus Mach (`task_for_pid`, `thread_get_state`/`thread_set_state`,
`mach_vm_read`/`mach_vm_write`, `task_suspend`/`task_resume`, exception ports).

- Pros: reuses an OS-level tracing facility; Mach can read/write another task's
  memory and *host*-thread state.
- Cons (decisive): Darwin `ptrace` has **no** PEEK/POKE/GETREGS/SETREGS and is
  semantically far from Linux. More importantly, Mach `thread_get_state` returns
  the **host** thread's ARM state, which for a carrick vCPU thread is the state
  of the *Rust host code running `hv_vcpu_run`*, **not the guest vCPU registers**
  — those live inside the HVF VM and are only reachable via `hv_vcpu_get_reg` *on
  the owning thread of the owning process*. `mach_vm_read` of another carrick
  process reads the host address space, where guest RAM is a `MAP_SHARED`
  buffer at some host VA — usable in principle but requires replicating
  carrick's guest→host address translation cross-process. Net: Mach gives the
  wrong register file and an awkward memory path. **Rejected** as the primary
  mechanism (but see §5 for a narrow, optional use).

### Approach B — In-runtime Linux ptrace state machine, brokered between processes (RECOMMENDED)
carrick already fully controls each guest from *within that guest's own
process*. So implement the Linux ptrace state machine in the runtime, and when
the tracer needs to read/modify the tracee, **have the tracee's own carrick
perform the vCPU/memory operation on behalf of the tracer**, coordinated over a
small cross-process broker. The tracer process issues a request; the tracee
process (which owns the vCPU and the guest RAM) services it and replies.

- Pros: every operation runs where it is cheap and correct (the owning vCPU
  thread does `get_reg`/`set_reg`/`read_bytes`/`write_bytes`; single-step uses
  HVF on the owning vCPU). Reuses `wait4`/signal/quiesce plumbing for control.
  No dependence on Darwin ptrace quirks. Matches how carrick already does
  cross-process work (host pid identity, `pt_barrier` pause-modify-resume).
- Cons: needs an inter-process request/response channel and a tracee-side
  "ptrace-stopped" service state. This is new code, but conceptually small and
  uses mechanisms carrick already has (sockets/pipes/shared memory; the
  dispatcher already manages fds and `MAP_SHARED`).

### Approach C — Single-process emulation only (in-process tracer == tracee process)
Support only the in-process case (`PTRACE_TRACEME` where tracer and tracee end
up the same process, plus the no-ptrace `TestDebugCall` path), and `ENOSYS` the
cross-process case.

- Pros: trivial; unblocks `TestDebugCall` (which needs *no* ptrace) and any
  same-process self-tracing.
- Cons: does not support Delve/gdb/lldb (inherently cross-process). Fine as
  Phase 1/2, insufficient as the end state.

**Decision: B is the target architecture; we get there via C-shaped early phases.
Phase 1 (the `TestDebugCall` milestone) needs neither B nor C's tracer logic — it
is purely the BRK→SIGTRAP fix.** A narrow slice of Approach A's Mach memory read
is kept as an *optional* fast-path/fallback for cross-process PEEK (see §5).

---

## 5. Where Darwin/HVF-native facilities are actually needed

| Concern | Native facility | Needed? |
|---|---|---|
| Catch guest `BRK`/step/HW-debug as a host exit | HVF `set_trap_debug_exceptions(true)` (`applevisor` `Vcpu::set_trap_debug_exceptions`, vcpu.rs:611) | **Yes, for SINGLESTEP/HW-breakpoints** (Phase 3). For Phase 1's *software* `BRK #0` the existing EL1-vector→`hvc` path already delivers the exception to the trap loop; we only need to classify it. |
| Guest hardware single-step | `MDSCR_EL1.SS` + `PSTATE.SS` via `set_sys_reg(MDSCR_EL1, …)` / PSTATE; exits as a software-step exception (EC 0x32/0x33) once `set_trap_debug_exceptions(true)` | Yes, for `PTRACE_SINGLESTEP` (Phase 3). All registers exposed by `applevisor` (sys.rs MDSCR_EL1=0x8012). |
| Guest hardware breakpoints / watchpoints | `DBGBVR/DBGBCR` and `DBGWVR/DBGWCR` (applevisor get/set pairs vcpu.rs:915+) | Optional (Phase 4); software `BRK` patching covers gdb/Delve's default breakpoints. |
| Read/write another process's guest registers | None native that returns *guest* state — must be done by the tracee's vCPU thread via `hv_vcpu_get/set_reg` | Use Approach B (tracee services it). Mach `thread_get_state` returns host, not guest, state — **not usable**. |
| Read another process's guest memory | `mach_vm_read`/`mach_vm_write` on the tracee's task port (tracee guest RAM is a host `MAP_SHARED` buffer) | **Optional** fast-path for `PEEKDATA`/`POKEDATA` and bulk `PTRACE_GETREGSET`-of-memory-backed data, if we publish the guest→host base. Default path is still "ask the tracee" (Approach B), because POKE may need cache/TLB coherence the owning side handles. |
| Stop a running multithreaded tracee | `hv_vcpus_exit` kick (`vcpu_kick.rs`) + the `PtQuiesce` pause barrier (`fork_quiesce.rs`) | Yes — reuse for "ptrace-stop all threads of the tracee" (Phase 3 group-stop). |
| Mach exception ports (`task_set_exception_ports`, `catch_mach_exception_raise`) | Catches *host* (macOS) exceptions of a task | **Not needed.** Guest exceptions already exit via `hv_vcpu_run`/the EL1 vector; carrick is already the guest's exception handler. Mach exception ports would only matter if we traced a *real macOS* process, which carrick does not. |

**Summary:** HVF debug controls (`set_trap_debug_exceptions`, `MDSCR_EL1.SS`,
DBG* regs) are the right native tools for *single-step and hardware
breakpoints*. For cross-process register/memory access, the owning carrick
process is the right actor; Mach is at most an optional memory fast-path, and
Mach exception ports are not needed at all.

---

## 6. The ptrace-request → carrick-mechanism map

`P` = peer/tracee-side carrick (owns the vCPU + guest RAM). `T` = tracer-side
carrick. "Broker" = the cross-process request/response channel in Approach B.

| ptrace request | carrick mechanism | Status / phase |
|---|---|---|
| `PTRACE_TRACEME` | Tracee marks itself traced; its parent becomes tracer. Record in process state; affects stop-on-signal + stop-on-execve. | New (Phase 3) |
| `PTRACE_ATTACH` / `PTRACE_SEIZE` | T → broker → P: set `traced_by = tracer_pid`; P enters stop at next safe point (ATTACH also sends SIGSTOP-equivalent group-stop). | New (Phase 3) |
| `PTRACE_GETREGSET(NT_PRSTATUS)` / `GETREGS` | T → broker → P: P reads x0–x30, SP (`SP_EL0`), PC (`ELR_EL1`/`Reg::PC`), PSTATE via `get_reg`/`get_sys_reg`; marshals the Linux `user_regs_struct` (aarch64: `regs[31]`, `sp`, `pc`, `pstate`); replies. | New (Phase 3); reg read already exists per-process |
| `PTRACE_SETREGSET(NT_PRSTATUS)` / `SETREGS` | T → broker → P: P writes them back with `set_reg`/`set_sys_reg` (same regs `inject_signal`/`restore_from_sigframe` already drive). | New (Phase 3) |
| `PTRACE_GETREGSET(NT_FPREGSET)` / `NT_ARM_*` | P uses `get_simd_fp_reg`/FPSR/FPCR (existing `save_fpsimd_into` logic). HW-debug regsets (`NT_ARM_HW_BREAK`/`WATCH`) map to DBG* regs. | New (Phase 4 for HW regsets) |
| `PTRACE_PEEKTEXT`/`PEEKDATA` | T → broker → P: P `read_guest_bytes(addr, 8)`. *Optional* fast-path: Mach `mach_vm_read` of P's task at the published host VA. | New (Phase 3) |
| `PTRACE_POKETEXT`/`POKEDATA` | T → broker → P: P `write_guest_bytes(addr, 8)` (P owns coherence/`__clear_cache` for text writes — important for breakpoint insertion). | New (Phase 3) |
| Software breakpoint insert/remove (gdb/Delve) | POKETEXT writes `BRK #0` (`0xd4200000`); save original word; on hit, report SIGTRAP; on step-over, restore original, single-step, re-insert. P performs the write so I-cache is coherent. | New (Phase 3) |
| `PTRACE_CONT` (with optional injected signal) | T → broker → P: P leaves ptrace-stop and resumes its vCPU; if `data` is a signum, P delivers that signal first (reuse `inject_signal`). | New (Phase 3) |
| `PTRACE_SINGLESTEP` | T → broker → P: P sets `MDSCR_EL1.SS=1` + `PSTATE.SS=1`, ensures `set_trap_debug_exceptions(true)`, runs the vCPU once; the software-step exception (EC 0x32/0x33) exits → P re-enters ptrace-stop and reports SIGTRAP(`TRAP_TRACE`). | New (Phase 3) |
| `PTRACE_SYSCALL` | P resumes but stops at the next syscall entry/exit (carrick already traps every syscall in `run_until_syscall` — set a "syscall-stop" flag and report there). | New (Phase 4) |
| Stop reporting via `waitpid` (`WIFSTOPPED`, stopsig=SIGTRAP, `WSTOPPED`) | The tracee, in ptrace-stop, must look "stopped" to the tracer's `wait4`. Two sub-options — see §6.1. | New (Phase 3) |
| `PTRACE_GETSIGINFO` / `PTRACE_SETSIGINFO` | P returns/accepts the `siginfo` of the signal-delivery-stop it is parked in (carrick already builds Linux `siginfo` in `inject_signal`). | New (Phase 4) |
| `PTRACE_SETOPTIONS` (`PTRACE_O_TRACECLONE`/`FORK`/`VFORK`/`EXEC`/`EXITKILL`) | Recorded per-tracee; influence which events create new tracees and auto-stops (hook carrick's existing fork/clone/execve handling in `dispatch/proc.rs`). | New (Phase 4) |
| `PTRACE_KILL` / `PTRACE_DETACH` | Detach: clear trace state, resume; Kill: deliver SIGKILL. Forward via existing kill/resume paths. | New (Phase 3 detach, 4 kill) |

### 6.1 How a ptrace-stop is reported to the tracer's `waitpid`

Because guest pid == host pid and `wait4` forwards to host `libc::wait4`, there
are two viable designs (decision deferred to the Phase-3 plan; leaning toward
Option 2):

- **Option 1 — drive the real host stop state.** When the tracee enters
  ptrace-stop, it actually `SIGSTOP`s its host process (or parks in a state where
  the host reports `WIFSTOPPED`). The tracer's forwarded `libc::wait4(...,
  WUNTRACED/WSTOPPED)` then naturally returns a stopped status, which carrick
  already translates to Linux (`translate_wait_status`, `waitid_state_requested`
  — the os/exec stop-state adaptation is already in place). On `CONT`, the
  tracee is `SIGCONT`'d/un-parked. *Pro:* minimal new wait plumbing. *Con:* a
  raw host `SIGSTOP` is blunt (stops the whole process, not per-thread; fights
  with carrick's own signal model) and the stop *signal number* reported must be
  the ptrace-mandated value (SIGTRAP, or the delivered signal), not SIGSTOP —
  requiring careful status synthesis.

- **Option 2 — synthesise stop status in carrick's wait path (RECOMMENDED).**
  The broker tells the tracer-side carrick "tracee X is now in ptrace-stop with
  stopsig S and event E". carrick's `wait4`/`waitid` handler, when the caller is
  a tracer waiting on a traced child, returns a synthesised `WIFSTOPPED`/
  `W_STOPCODE(S)` (or the `PTRACE_EVENT_*` encoding) **without** consulting host
  `wait4` for that child. The tracee's vCPU is genuinely paused (it parks in its
  broker service loop), so nothing runs. *Pro:* exact Linux semantics (per-thread
  stop, correct stopsig, ptrace event bits) and no abuse of host SIGSTOP. *Con:*
  carrick's wait path must learn the "is this a traced child in ptrace-stop?"
  branch and merge it with normal child-exit waiting (including the
  `WaitOnProcExit` park at `dispatch/proc.rs:756`). This is the cleaner match to
  how carrick already adapts Darwin→Linux wait semantics.

### 6.2 The cross-process broker (Approach B mechanics)

Minimal viable broker, reusing carrick idioms:

- **Transport:** a per-tracee Unix-domain socketpair (or pipe pair) established
  when the trace relationship forms (TRACEME at fork, or ATTACH). The
  tracer-side holds one end; the tracee-side services the other in its run loop.
  Alternatively a small `MAP_SHARED` control region (carrick already maps shared
  memory and has cross-process futex via `__ulock`, `ulock.rs`) with a request
  word + payload and a futex wake — symmetric with the existing shared-aperture
  work. Socketpair is simpler to reason about for request/response; shared-mem is
  faster for bulk PEEK/POKE. Start with socketpair.
- **Tracee service point:** the tracee, when in ptrace-stop, runs a small
  service loop (not the vCPU): read request → perform `get_reg`/`set_reg`/
  `read_bytes`/`write_bytes`/arm-singlestep/resume → reply. Entering ptrace-stop
  from a *running* multithreaded tracee uses the existing kick
  (`hv_vcpus_exit`) + a pause barrier modeled on `PtQuiesce` to stop siblings.
- **Registry:** a process-global map (mirrors the durable, fork-coherent style
  in memory) of `tracee_pid → {tracer_pid, fd, options, stop_state}` and the
  inverse. Because pid==host pid, the same integers work in both processes.
- **Discovery / liveness:** trace relationships are parent/child or
  attach-by-pid; carrick already tracks the host process tree and pidfds
  (`open_pidfd`, `dispatch/proc.rs:180`), reusable for "tracee died" wake.

---

## 7. Risks / unknowns and how to resolve each

- **R-1 — BRK `ELR_EL1` semantics under HVF.** Phase 1 correctness hinges on the
  SIGTRAP's reported PC equalling the `BRK` instruction's address (so Go reads
  `0xd4200000` at `sigpc`). *Resolve:* write a tiny guest fixture that executes
  `brk #0` and, in the trap loop, log `ESR_EL1`/`ELR_EL1`; confirm EC=0x3c and
  ELR points at the BRK (ARM ARM says BRK is a synchronous exception with the
  preferred return address = the BRK itself). Verify with `carrick trace` (USDT)
  rather than eprintln (per project convention). If HVF advances ELR, subtract 4
  for the saved PC.

- **R-2 — Does the kick-path SIGTRAP injection interact badly with an in-flight
  BRK?** A `tgkill(SIGTRAP)` (kick path, `interrupted_pc=Some`) and a synchronous
  BRK exception are two different entry shapes. The Go protocol can have the
  worker hit BRK *inside* a state it entered via tgkill. *Resolve:* ensure BRK is
  handled on the synchronous exit path (EC=0x3c from `run_until_syscall`), and
  delivered with `inject_signal(..., interrupted_pc = None)` so PC redirection
  uses ELR_EL1 (the synchronous-fault shape, matching `deliver_fault_signal`'s
  current pattern at `runtime.rs:1625`). Add a focused test that drives a BRK and
  a handler that advances PC+4 and `rt_sigreturn`s.

- **R-3 — Re-arming after a software breakpoint (Phase 3).** Classic ptrace
  breakpoint dance: on hit, restore original instruction, single-step over it,
  re-insert `BRK`. Needs I-cache coherence on the write. *Resolve:* the *tracee*
  performs POKETEXT (it owns the mapping and any `__clear_cache`); add a probe to
  confirm the re-inserted byte is visible to the guest fetch (the project has
  prior art diagnosing stale text/PTE via `pt_fault_walk`).

- **R-4 — HVF single-step actually exits to host.** Unverified that
  `set_trap_debug_exceptions(true)` + `MDSCR_EL1.SS`/`PSTATE.SS` produces a
  software-step EXCEPTION exit (EC 0x32/0x33) rather than re-entering the guest.
  *Resolve:* spike a single guest instruction step in a unit/integration test on
  real hardware; inspect the exit syndrome. Fallback if unsupported: software
  single-step by decoding the next instruction and planting a temporary `BRK` at
  the next PC(s) (and both branch targets) — more complex but mechanism-complete.

- **R-5 — Multithreaded tracee group-stop & `PTRACE_O_TRACECLONE`.** Stopping all
  threads consistently and creating tracees for new clones. *Resolve:* reuse the
  `PtQuiesce` pause barrier for "stop all vCPU threads of the tracee"; hook
  `CloneThread`/`Fork` outcomes (`runtime.rs:608`, `:677`) to emit
  `PTRACE_EVENT_CLONE`/`FORK` and auto-attach per options. Defer full group-stop
  semantics to Phase 4; Phase 3 can target single-threaded tracees (Delve
  attaches per-thread; gdb on a simple program is single-threaded).

- **R-6 — `PTRACE_TRACEME`-then-`execve`.** TRACEME requires the next `execve` to
  stop the tracee with SIGTRAP before the new image runs. carrick's `execve`
  rebuilds the image in-process (`load_execve_image`, `runtime.rs:643`).
  *Resolve:* after `execve_into`, if traced, enter ptrace-stop (signal-delivery
  stop, SIGTRAP) before resuming the vCPU; report `PTRACE_EVENT_EXEC` if the
  option is set. The hook point is right after `runtime.execve_into(&new_image)`.

- **R-7 — Wait-path merge.** Folding ptrace-stop status into `wait4`/`waitid`
  without breaking the normal child-exit path (incl. the `WaitOnProcExit` park).
  *Resolve:* implement Option 2 (§6.1) behind an "is the target a traced child of
  the caller currently in ptrace-stop?" check evaluated *before* the host
  `wait4`; cover with tests mirroring the existing `TestWaitid`/os-exec
  stop-state cases.

- **R-8 — Signal-delivery-stop vs the existing signal pump.** Under ptrace, every
  signal to the tracee must first stop the tracee and notify the tracer (which
  may suppress/inject). This intercepts carrick's normal
  `deliver_pending_signal`. *Resolve:* add a "traced" branch in
  `deliver_pending_signal` (`runtime.rs:1854`): instead of injecting, enter
  signal-delivery-stop and hand the tracer the pending signum via the broker;
  resume with the tracer-chosen signal on `CONT`. Phase 3 can start with only
  SIGTRAP (breakpoints/steps), deferring general signal interception to Phase 4.

- **R-9 — Mach memory fast-path coherence (optional).** If we add
  `mach_vm_read`/`write` for PEEK/POKE, we must publish the tracee's guest→host
  base and avoid writing text that needs cache maintenance. *Resolve:* keep Mach
  read-only and only for PEEKDATA bulk reads; route all POKE through the tracee.
  This risk disappears if we skip the fast-path.

---

## 8. Phased implementation plan

### Phase 1 — Milestone: `TestDebugCall` passes (no ptrace at all) — ✅ DONE (2026-05-26)
Make a guest software breakpoint deliver SIGTRAP to the guest handler instead of
killing the process. Concretely:

1. In the trap loop's non-SVC EL0 branch (`trap.rs:1451`+), classify the
   underlying `ESR_EL1` EC:
   - EC `0x3c` (BRK from AArch64) → surface a new `TrapError`/path
     "debug exception" carrying ESR/ELR (don't fold it into `EL0Fault`).
   - (Prepare the same recognition for EC `0x30/0x31` HW breakpoint, `0x32/0x33`
     software-step, `0x34/0x35` watchpoint — used in Phase 3.)
2. Add `el0_debug_signal(esr) -> (SIGTRAP, si_code)` with `si_code`:
   `TRAP_BRKPT` (BRK), `TRAP_TRACE` (step), `TRAP_HWBKPT` (HW). Deliver via the
   existing `deliver_fault_signal`-shaped path → `inject_signal(SIGTRAP, …,
   fault_siginfo = Some((si_code, brk_pc)))`, with saved PC = the BRK address
   (see R-1). If no handler / blocked → default action for SIGTRAP is terminate
   (matches Linux core-dump), but Go installs a handler, so the happy path
   injects.
3. Verify `/proc/<pid>/status` `TracerPid:\t0` is served on the path the test
   reads (it is — `vfs/proc.rs:431`,`:570`); no change expected.
4. Keep `ptrace(117)` returning `ENOSYS` (the test never calls it). Optionally
   relax to "succeed for `PTRACE_TRACEME` no-op" only if a follow-on test needs
   it.

Verification (per project norms — Docker/LTP differential + `carrick trace`, not
log spam): run the Go `runtime` `TestDebugCall*` set under carrick via the
existing `scripts/go-conformance.sh`/docker harness; add a focused Rust
integration test that executes a guest `brk #0` with a SIGTRAP handler that
advances PC and `rt_sigreturn`s, asserting clean resume (mirrors the
`segv-recover` probe approach used for the EL0-fault work). Confirm the BRK
exception class + ELR via a one-shot trace.

Exit criteria: `TestDebugCall`, `TestDebugCallLarge`,
`TestDebugCallUnalignedStack`, etc. pass; no fatal SIGSEGV on guest `BRK`.

### Phase 2 — `ptrace` surface scaffolding + same-process self-trace
- Define Linux ptrace request constants + `user_regs_struct`/regset structs.
- Implement `PTRACE_TRACEME` bookkeeping and `PTRACE_SETOPTIONS` storage.
- Implement the *self/parent-in-same-tree* trivial cases and return precise
  errnos (`ESRCH`/`EPERM`/`EINVAL`) for the rest (replacing blanket `ENOSYS`),
  so traced programs get Linux-shaped failures rather than ENOSYS surprises.
- Stand up the broker transport (socketpair) and the tracee service-loop skeleton
  (no operations yet), plus the trace registry.

### Phase 3 — Cross-process core ptrace (gdb/Delve "stop, inspect, step, continue")
- `PTRACE_ATTACH`/`SEIZE`/`DETACH`, group-stop entry for single-threaded tracees.
- `GETREGSET`/`SETREGSET(NT_PRSTATUS)`, `PEEKDATA`/`POKEDATA` over the broker.
- Software breakpoints (POKETEXT `BRK`, save/restore, step-over).
- `PTRACE_CONT`, `PTRACE_SINGLESTEP` (HVF `set_trap_debug_exceptions` +
  `MDSCR_EL1.SS`; software-step fallback per R-4).
- Wait-path integration via Option 2 (§6.1): synthesise `WIFSTOPPED`/stopsig.
- `PTRACE_TRACEME`+`execve` stop (R-6).

Exit criteria: `gdb`/Delve can set a breakpoint, hit it, read/modify a variable,
single-step, and continue a simple single-threaded Go/C guest; `TestGdb*`/
`TestLldb*` that exercise this subset pass.

### Phase 4 — Breadth: multithreading, events, syscall-stop, signals
- `PTRACE_O_TRACECLONE/FORK/VFORK/EXEC/EXITKILL` + `PTRACE_EVENT_*`.
- Full group-stop for multithreaded tracees (PtQuiesce-based).
- `PTRACE_SYSCALL` (syscall-entry/exit stops via the existing syscall trap).
- General signal-delivery-stop interception (R-8), `GET/SETSIGINFO`.
- HW breakpoint/watchpoint regsets (`NT_ARM_HW_BREAK`/`WATCH` → DBG* regs).
- Optional Mach `mach_vm_read` PEEK fast-path (R-9), only if profiling warrants.

---

## 9. Files this work will touch (for the eventual plan)

Read during this research; cited as the integration points:

- `crates/carrick-runtime/src/trap.rs` — exception classification
  (`run_until_syscall` ~`:1451`), `inject_signal` (`:1867`),
  `restore_from_sigframe` (`:2150`), debug-reg/single-step (HVF) accessors;
  `aarch64_exception_class` (`:2750`).
- `crates/carrick-runtime/src/runtime.rs` — `el0_fault_signal` (`:2007`) →
  add `el0_debug_signal`; `deliver_fault_signal` (`:2040`); the EL0Fault arm
  (`:1619`); `deliver_pending_signal` (`:1854`) for ptrace signal-stop; Fork/
  Clone/Execve outcome handling (`:608`,`:635`,`:677`) for ptrace events.
- `crates/carrick-runtime/src/dispatch/proc.rs` — `ptrace` handler (`:571`);
  `wait4`/`waitid` (`:724`/`:624`) wait-path merge; `clone`/`fork`/`clone3`
  (`:833`/`:925`) for TRACECLONE; pidfd (`:180`) for liveness.
- `crates/carrick-runtime/src/dispatch/signal.rs` — `tkill`/`tgkill`
  (`:217`/`:237`), `route_thread_signal`, `bootstrap_signal_send` (`:646`).
- `crates/carrick-runtime/src/host_signal.rs` — pending/translation
  (`:48`,`:62`,`:162`,`:179`).
- `crates/carrick-runtime/src/fork_quiesce.rs` — `PtQuiesce`/`pt_barrier`
  (`:144`+) reused for tracee group-stop.
- `crates/carrick-runtime/src/vcpu_kick.rs` — `VcpuKicker::kick` to stop a
  running tracee.
- `crates/carrick-runtime/src/host_proc.rs` — Mach `ThreadPort` (`:384`),
  `pid_info` (`:209`) for the optional Mach fast-path / liveness.
- `crates/carrick-runtime/src/vfs/proc.rs` — `TracerPid` lines (`:431`,`:570`).
- `crates/carrick-runtime/src/linux_abi.rs` — `LinuxSignalContext`/
  `LinuxFpsimdContext`/`CarrickSigframe`/`LinuxSiginfo` (`:830`+) reused for
  regset marshalling; add ptrace structs.
- `crates/carrick-runtime/src/ulock.rs` — cross-process futex, candidate for a
  shared-memory broker variant.
- `crates/carrick-runtime/src/syscall.rs` — ptrace `SupportLevel` (`:243`).

External sources consulted:

- Go runtime: `src/runtime/debug_test.go` (`debugCallTKill` uses `tgkill`
  SIGTRAP; `skipUnderDebugger` reads `/proc/<pid>/status` `TracerPid`),
  `src/runtime/export_debug_arm64_test.go` (sigcontext reg/SP/LR manipulation;
  `BRK #0` = `0xd4200000` completion check; `set_pc(pc+4)` phase stepping),
  `src/runtime/debugcall.go` (goroutine/LockOSThread protocol layer).
  <https://go.dev/src/runtime/debug_test.go>
- ptrace(2) man page (GETREGSET/SETREGSET preferred on aarch64; PEEK/POKE;
  CONT/SINGLESTEP; stop reporting). <https://man7.org/linux/man-pages/man2/ptrace.2.html>
- Delve native backend (linux uses PTRACE_GETREGSET/SETREGSET, NT_PRSTATUS,
  PEEK/POKE, CONT, SINGLESTEP; tracer is a separate process).
  <https://github.com/go-delve/delve/tree/master/pkg/proc/native>
- Notes on hardware breakpoints/watchpoints on AArch64 (DBG* regs via
  GETREGSET `NT_ARM_HW_BREAK`/`WATCH`).
  <https://aarzilli.github.io/debugger-bibliography/hwbreak.html>
- Apple Hypervisor.framework: `hv_vcpu_set_trap_debug_exceptions`,
  `hv_vcpu_set_trap_debug_reg_accesses`, DBG*/MDSCR_EL1 sys-reg ids
  (`applevisor` 1.0.0 `src/vcpu.rs`, `applevisor-sys` 1.0.0 `src/lib.rs`).
  <https://developer.apple.com/documentation/hypervisor>
