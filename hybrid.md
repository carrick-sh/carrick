# Carrick Kernel-First Single-VM Architecture

**Revision date:** 2026-08-09

**Status:** This section is the controlling plan. The original HvPatch
prototype plan is retained below as historical context only. When the two
conflict, this kernel-first revision wins.

**Goal:** Build Carrick as a correct, observable Linux-compatible kernel in one
host process and one HVF VM. Mach and Hypervisor.framework are execution and
physical-memory HALs, not the source of Carrick process, address-space, fork,
exec, scheduler, fd, signal, or crash-dump semantics. Reach the shipped proof
surface of a cold `go build` below 2.3 CPU-s versus native-arm64 Docker while
preserving Linux behavior and keeping `native` and `vmm` as fallback/reference
backends.

**Architecture in one sentence:** One HVF VM contains a Carrick-managed global
physical-frame space; Linux tasks own independent ASID-tagged stage-1 address
spaces that map Linux virtual addresses to shared or private Carrick frames,
and Carrick implements task lifecycle, COW, faults, scheduling, files, signals,
waits, and diagnostics as kernel primitives.

## Reframing

The existing one-VM Phase 4 prototype proved that 68 forks, 67 execs, and 69
Linux processes can complete a cold Go build inside one HVF VM. It also exposed
the cost of mapping the previous backend's process lifecycle into the new
topology: coarse vCPU quiescence, a global topology lock, per-process IPA
banks, complete mapping inventories, Mach remaps, and flat page-table image
publication.

Those mechanisms are evidence, not compatibility contracts. The compatibility
contract is externally observable Linux behavior. Carrick is now allowed to
replace the prototype process and memory implementation substantially when a
new design is correct, robust, measurable, and keeps the one-VM invariant.

The `getattrlistat` scalar-metadata scout was abandoned and its uncommitted
implementation removed. Its workload-shape and rejection evidence remains
durable. Filesystem lowering is still important, but it must not distract from
the kernel memory and lifecycle model that every later subsystem depends on.

## Non-negotiable invariants

1. **One VM, not one VM per Linux process.** A workload creates exactly one
   `hv_vm_create`; Linux processes and threads are Carrick kernel objects.
2. **Linux semantics are authoritative.** Fork COW, shared mappings, open-file
   descriptions and offsets, close-on-exec, signals, waits, process groups,
   credentials, futexes, faults, and core contents match Linux observation.
3. **HVF is a HAL.** HVF owns vCPU execution and stage-2 mappings. It does not
   define Carrick task or address-space structure.
4. **Stage-2 represents physical frames, not process banks.** A Carrick physical
   frame receives a stable global IPA while live and is mapped into stage-2
   once. Multiple address spaces may map it through their own stage-1 tables.
5. **Isolation lives in stage-1 plus kernel ownership.** ASIDs tag TLB entries;
   per-mm stage-1 mappings and frame permissions prevent cross-process access.
6. **Writable fork state is real COW.** Parent and child initially share frames
   read-only. A permission fault allocates/copies only the affected compound
   frame, updates one mm, performs scoped TLB maintenance, and leaves the peer
   byte-identical.
7. **No global lifecycle serialization by default.** Task/mm-local locks and
   short physical-frame/HVF commit locks replace a global topology lock. Any
   broader lock must have a written invariant and measured necessity.
8. **Prepare then commit.** Exec and other address-space replacement work is
   built off to the side; the visible task transition is a short, atomic,
   rollback-safe commit. Old state is reclaimed after references drain.
9. **Correctness precedes fast paths.** No in-guest shortcut may approximate
   Linux blocking, memory ordering, signals, synchronous errors, fd offsets,
   or wake semantics.
10. **Observability is a kernel ABI.** Stable typed events carry Linux PID,
    TID, ASID/mm identity, operation, phase, and outcome. Empty or incomplete
    captures fail closed.
11. **Crash artifacts describe the guest kernel view.** Carrick writes Linux
    ELF core files with guest threads, registers, mappings, auxv, siginfo, and
    file-map notes; a Darwin host core remains a separate implementation-debug
    artifact.
12. **Measured performance authority remains clean.** DTrace/LLDB attribute;
    untraced same-binary ABBA and shipped workload comparisons decide retention.

## Kernel object model

Carrick will converge on explicit, independently testable objects rather than
one large dispatcher clone:

- `Task`: Linux process identity, parent/children, exit/wait state, process
  group/session, credentials, and references to shareable kernel objects.
- `Thread`: Linux TID, register/signal mask/TLS state, run state, and a lease on
  a vCPU worker while runnable.
- `Mm`: ASID, persistent VMA tree, stage-1 root, fault policy, and references to
  VM objects. `Mm` is replaced atomically on exec and reference-counted across
  in-flight kernel work.
- `VmObject`: anonymous, file-backed, shared, device/internal, or immutable
  image storage with page ownership and COW lineage.
- `FrameTable`: allocates global IPA-backed compound frames, tracks references,
  stage-2 state, dirty/COW state, and deferred reclamation. On a 16 KiB Darwin
  host, the first correct implementation may COW a 16 KiB compound frame for
  four 4 KiB Linux pages; later subpage refinement must preserve semantics.
- `PageTable`: persistent/refcounted stage-1 table pages. Mutation copies only
  the affected table path. Fork must not serialize or copy a flat complete
  page-table image.
- `FileTable` and `FileDescription`: COW fd-table structure plus shared Linux
  open-file descriptions so forked descriptors share offsets and status flags
  while fd flags remain per descriptor.
- `SignalState`: dispositions shared according to Linux clone rules, per-task
  pending queues, per-thread masks/pending state, and deterministic delivery.
- `Scheduler`: task/thread run state and vCPU leases. The initial implementation
  may keep a runnable thread pinned to one vCPU, but the interface must not bake
  in one permanent host thread per Linux thread.

The syscall layer accepts a `KernelContext` naming the current task, thread,
mm, files, credentials, and cancellation/signal state. Backend-specific process
semantics do not leak into general syscall implementations.

## Memory and lifecycle transactions

### Fork transaction

1. Validate Linux clone/fork flags and allocate child kernel identities.
2. Clone/share `Task` references according to Linux rules.
3. Clone the parent's persistent VMA root and stage-1 root.
4. Convert writable private mappings to COW by copying only affected page-table
   paths and applying the minimum safe permission/TLB barrier.
5. Share physical frames and VM objects by reference; do not recreate a full
   child stage-2 bank and do not remap the complete address space.
6. Seed the child thread context with Linux fork return values.
7. Publish the child atomically; unwind every allocation on pre-publication
   failure.

### COW fault transaction

1. Attribute the fault to task, thread, mm/ASID, VMA, object, and page.
2. Lock the object/page lineage and revalidate the PTE generation.
3. If exclusively owned, upgrade permissions; otherwise allocate a frame, copy
   the compound frame, and update only the faulting mm's stage-1 path.
4. Perform scoped TLB maintenance and resume the exact faulting instruction.
5. Publish a typed fault outcome suitable for live tracing and ELF-core notes.

### Exec transaction

1. Resolve and load the executable/interpreter into a new, unpublished `Mm`.
2. Reuse immutable image VM objects and patch manifests when provenance matches.
3. Build stage-1 tables, stack, auxv, credentials, and initial registers without
   holding a global topology lock.
4. Terminate/drain sibling threads according to Linux exec semantics.
5. Under the task/mm commit lock, apply close-on-exec and signal resets, swap the
   task's `Mm`, install the new ASID/root/register state, and publish success.
6. On failure before commit, leave the old image untouched. After commit,
   reclaim the old mm asynchronously when vCPU/kernel references reach zero.

## Revised phases and gates

### K0 — Architecture specification and decisive HAL probes

Deliver a committed design specification before production code. Add bounded,
signed probes that prove or kill:

- two ASID-tagged stage-1 roots can map one global IPA frame and observe shared
  bytes without additional VM creation;
- a write-protected shared frame faults, can be split, and leaves the peer
  address space unchanged byte-for-byte;
- persistent stage-1 table-path COW and scoped ASID TLB invalidation behave
  correctly;
- disjoint stage-2 map/unmap operations are either safely concurrent under HVF
  or explicitly serialized at the frame HAL;
- ASID switch, COW-fault, frame-map, and table-path-copy latency distributions.

**Gate:** GO only if shared-frame isolation and COW recovery are empirically
correct. Record source, signed binary, OS/HVF provenance, raw receipts, and
GO/KILL. A killed HAL assumption redirects the design before K1.

### K1 — Kernel object model and observability contract

Introduce typed task/thread/mm/files/signal/frame interfaces while adapting the
working one-VM prototype behind them. Establish stable ID allocation, ownership,
lock ordering, rollback rules, and typed CTF events. Add `carrick debug` readers
for task, thread, mm, VMA, frame, fd, and signal summaries from live state and
the always-on event ring.

**Gate:** model/property tests cover Linux sharing rules and failure rollback;
existing exact cold-build output and 68/67/69 lifecycle counts remain green;
`just ci` passes. No performance claim is required yet.

### K2 — Global physical frames and persistent stage-1 address spaces

Replace per-process IPA banks and flat table publication with global IPA-backed
frames, VM objects, persistent VMA roots, and COW stage-1 table paths. Implement
demand allocation, immutable file/image sharing, anonymous/private/shared map
semantics, scoped TLB maintenance, and deferred frame reclamation.

**Gate:** differential probes cover anonymous/file/private/shared mappings,
fork-write divergence, truncation/SIGBUS, `mprotect`, `munmap`, `brk`, and
concurrent faults. Fork work scales with writable table paths/touched frames,
not virtual span. No complete-address-space `mach_vm_remap` or flat page-table
publication remains in the fork path.

### K3 — Kernel-native fork/clone and wait lifecycle

Implement fork/clone/vfork-compatible task creation on the new objects,
including file-description sharing, signal/credential rules, pidfds, parent/TID
stores, exit, wait, groups, and sessions. Replace stop-the-world polling with a
minimal generation/permission barrier whose scope is proven by tests.

**Gate:** Docker-oracle probes and relevant LTP cases match; two concurrent cold
builds still use one VM each without the 127-VM ceiling; the canonical build
retains 68 forks/67 execs/69 processes. Mean fork critical path is below 0.5 ms
and p95 below 1 ms, with no work proportional to sparse virtual extent.

### K4 — Transactional exec

Build replacement address spaces outside lifecycle locks, cache immutable image
objects/patch manifests by authenticated provenance, atomically commit the new
mm, and defer teardown. Remove global fork/exec serialization; concurrent execs
in disjoint tasks may prepare independently.

**Gate:** exec failure leaves the old image valid; multithreaded exec, CLOEXEC,
signals, credentials, interpreter chains, `/proc/self/exe`, and dynamic ELF
behavior match Docker. The commit critical section is below 0.1 ms p95 and the
post-load replacement path averages below 1 ms on the cold-build fixture.

### K5 — Scheduler, synchronization, syscall lowering, and diagnostics

Complete scheduler/vCPU leases, futex wait queues, timekeeping, epoll, signal
delivery, pty/interactive behavior, and task cancellation without semantic
shortcuts. Continue lowering Linux operations to the smallest correct modern
Darwin primitive set, selected by workload shape rather than API novelty.

Extend `carrick trace`, typed CTF, durable D scripts, `carrick debug`, and LLDB
plugins with task/mm/frame/run-queue/futex identities. Add a low-perturbation
Carrick-own-code CPU profile that separates Carrick text, dylibs, HVF/kernel,
guest execution, and wait states; traced values rank work but do not authorize
retention.

**Gate:** cold-build VM exits below 5K only where removal preserves Linux
semantics; CPU below 2.5 s; `conformance-quick` passes; the hvpatch full-baseline
methodology is viable and all captures fail closed on missing identity/events.

### K6 — Linux ELF cores, conformance parity, and shipped proof

Write Linux-style ELF core files containing `PT_LOAD` memory plus per-thread
register notes, `NT_SIGINFO`, `NT_AUXV`, process identity, and file-mapping
notes. `carrick debug core` validates and summarizes them; LLDB tooling can
navigate guest tasks, threads, registers, mappings, frames, fds, signals, and
the event ring from live state or a core without treating host pointers as guest
virtual addresses.

Establish `baseline.hvpatch.jsonl`, close gaps to VMM-lane parity, retain native
and VMM fallbacks, and validate:

- cold `go build` below 2.3 CPU-s versus serialized native-arm64 Docker;
- CPython, Node.js, and Rust workloads within 2x Docker;
- correctness/conformance gates on the exact shipped backend and binary;
- one-VM topology, isolation stress, bounded failure, and crash-tool recovery.

**Gate:** the goal completes only when these measured results and diagnostic
artifacts exist. Green CI, a projected speedup, or an intermediate prototype is
not completion.

## Evidence and progress protocol

At every K-phase boundary publish a durable evidence document containing:

- exact commit, signed binary hash/UUID, host/OS/HVF provenance, image digest,
  fixture argv/environment, raw artifact hashes, and scoped run ID;
- measured results separated from projections and traced attribution separated
  from clean authority;
- Linux/Docker differential results, relevant conformance cases, concurrency,
  isolation, rollback, and bounded-failure results;
- task/thread/mm/ASID/frame populations and any missing/ambiguous events;
- performance totals, distributions, opportunity arithmetic, ABBA order, and
  perturbation declaration;
- GO/KILL/RED/GREEN decision, retained commits, rejected experiments, risks,
  and the next architectural question.

Never run Carrick and Docker concurrently. Build/sign through the repository
recipes, preserve durable D/LLDB/core artifacts, require a scoped
`CARRICK_RUN_ID`, and run `just ci` before committing an accepted phase.

## Historical evidence carried forward

| Prototype phase | Current decision |
|---|---|
| Phase 0 | GO: exit-free branch/island and compute assumptions proved; `TPIDR_EL0` patching rejected because native reads do not trap. |
| Phase 1 | Complete: distinct signed `hvpatch` backend runs static and dynamic ELF images. |
| Phase 2 | Closed no-go: 4.55 CPU-s passed, but listed fast paths could not reduce 68,276 exits below 20K. |
| Phase 3 | Closed no-go: mapped read/write batching mechanisms were semantically invalid or arithmetically unable to reach the exit gate. |
| Phase 4 prototype | One VM, correct 68/67/69 lifecycle and output; approximately 4.27 CPU-s and 2.728 ms post-load exec remain RED. |

Detailed receipts remain authoritative under `docs/perf-results/`. The revised
K-phases may reuse proven code and probes, but they do not inherit rejected
mechanisms or stale projections from the historical plan.

---

# Historical VMM + Dynamic Binary Patching Prototype Plan

The remainder of this file is preserved verbatim for provenance. It is not the
controlling implementation plan after the 2026-08-09 kernel-first revision.

**Goal:** A new `--exec-backend hvpatch` that combines an HVF stage-1 micro-vmm with dynamic binary patching to reach **1× native-arm64 Docker** on the cold `go build` workload (~2.16 CPU-s), from today's 10.18× (19.8 CPU-s).

**Architecture in one sentence:** Guest code runs unmodified at native low VAs inside a single HVF VM with Carrick-built stage-1 page tables; `svc #0` and `mrs tpidr_el0` are patched in static text to branch to in-guest EL0 islands that handle simple syscalls without VM exits; only I/O syscalls that need host resources actually trap to the hypervisor.

---

## Resolved Design Decisions

> [!IMPORTANT]
> **Relaxed process model (not 1:1).** HVF enforces a **127-VM system-wide ceiling** on `hv_vm_create`. A cold `go build` forks 68 times — two concurrent builds would exceed the limit. The single-VM architecture therefore requires **all Linux "processes" to live inside one host process**, with one `hv_vm_create`, one shared stage-2 arena, and per-process isolation via stage-1 ASIDs. This means fd-table isolation, signal delivery, and memory isolation must be reimplemented in-process by Carrick, not inherited from macOS process boundaries. This is the hardest engineering in the plan but is architecturally required, not optional.

> [!NOTE]
> **Third backend.** `hvpatch` coexists with `native` and `vmm` as a third `--exec-backend` option. It does not replace or deprecate either existing backend.

> [!NOTE]
> **Per-guest-process fd namespace.** Each guest "process" maintains its own fd table that maps guest fds (small integers starting at 0) to host fds via an indirection table. Guest fd 3 in process A and guest fd 3 in process B may point to different host fds. On `fork`, the child's fd table is cloned from the parent's. On `execve`, close-on-exec fds are removed. The host process holds all real fds; the guest never sees or uses host fd numbers directly.

---

## Open Questions

> [!WARNING]
> **Conformance.** The new backend will need its own conformance overlay (`baseline.hvpatch.jsonl`). Early phases will have significant gaps — which is fine as long as the gate methodology is established from phase 1.

---

## Phase 0 — Decisive probe experiments

**Goal:** Prove or kill the two load-bearing assumptions before writing any production code.

### Experiment 0a: Patched `bl` runs exit-free in the VM

Extend [`crates/carrick-vmm-hvf/src/bin/hvf_svc_tax_probe.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-vmm-hvf/src/bin/hvf_svc_tax_probe.rs):

1. Map two code pages in stage-1: a "guest" page with a tight loop, and an "island" page
2. Guest loop: `bl <island>; b loop` (no `svc`)
3. Island: `mov x0, #42; ret`
4. Run 100K iterations via `hv_vcpu_run`
5. **Measure:** Does the loop run with **zero VM exits** (the vCPU never returns to the host)?

If yes: the loop runs at native speed inside the VM, proving patched `bl` doesn't trap.
**Kill condition:** If `bl` to a different page causes an HVF exit (stage-2 permission check?), the patching architecture is dead.

Expected: `bl` is a normal EL0 instruction, stage-1 maps both pages RX, HVF should not exit. But verify empirically.

### Experiment 0b: `tpidr_el0` → memory load

Same probe:

1. Map an info page at a fixed VA in stage-1
2. Write a known value to offset 0 of the info page
3. Guest code: `ldr x0, [x20, #0]` (where x20 points to info page) — verifying this returns the correct value at EL0
4. Compare against `mrs x0, tpidr_el0` (which exits the VM)
5. **Measure:** latency of `ldr` (should be ~1ns) vs `mrs` exit (~680ns)

### Experiment 0c: vCPU run with no exits for compute

1. Map a compute-bound loop (e.g., fibonacci) in stage-1
2. Run it for ~1M iterations
3. Verify: the vCPU runs to completion with exactly ONE exit (the final `svc #0` to signal done)
4. **Measure:** wall time vs the same code running as a host-native process

This establishes the compute baseline: VMM overhead for exit-free execution.

### Deliverables
- Three committed probe binaries in `crates/carrick-vmm-hvf/src/bin/`
- Results doc in `docs/perf-results/` with latency distributions
- **Go/kill decision** documented

---

## Phase 1 — Minimal viable `hvpatch` backend

**Goal:** Run a statically-linked "hello world" ELF through `carrick run --exec-backend hvpatch`, with `svc` patching eliminating `write` exits for stdout.

### 1.1 Wire the new backend into the product path

#### [MODIFY] [`crates/carrick-spec/src/lib.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-spec/src/lib.rs#L237)
Add `HvPatch` variant to `ExecBackendRequest`:
```rust
pub enum ExecBackendRequest {
    #[default]
    Native,
    Vmm,
    HvPatch,  // NEW
}
```
Update `parse_value`, `value_variants`, `to_possible_value`, deserialization, and tests.

#### [MODIFY] [`crates/carrick-runtime/src/page_profile.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/page_profile.rs#L25)
Add `HvPatch` variant to `ExecutionBackend`. Add resolution in `resolve_execution_plan_for_request_for_host`:
```rust
ExecBackendRequest::HvPatch => Ok(ExecutionPlan {
    backend: ExecutionBackend::HvPatch,
    page_geometry: PageGeometry {
        host_page_size: DEFAULT_LINUX_PAGE_SIZE,
        linux_page_size: DEFAULT_LINUX_PAGE_SIZE,
        native_profile: None,
    },
    diagnostics: Vec::new(),
}),
```

#### [MODIFY] [`crates/carrick-runtime/src/runtime.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/runtime.rs#L301)
Add dispatch arm in `run_static_elf_with_backend_args_and_dispatcher_debug`:
```rust
crate::page_profile::ExecutionBackend::HvPatch => {
    crate::hvpatch::run_static_hvpatch(path, dispatcher, argv, env, max_traps, debug_state_path)
}
```

### 1.2 The hvpatch module

#### [NEW] `crates/carrick-runtime/src/hvpatch/mod.rs`
The new backend's entry point. Responsible for:
1. Loading ELF via `AddressSpace::load_elf_file`
2. Building stage-1 page tables (reuse [`stage1_identity_page_tables`](file:///Volumes/CaseSensitive/carrick/crates/carrick-mem/src/memory.rs))
3. **Scanning and patching** executable segments
4. Mapping an **info page** and **island code page** into stage-1
5. Mapping all regions into an HVF VM via `hv_vm_map`
6. Creating a vCPU, configuring sysregs (TTBR0, TCR, MAIR, SCTLR.M=1)
7. Running the vCPU loop: `hv_vcpu_run` → handle exits → call `SyscallDispatcher`

#### [NEW] `crates/carrick-runtime/src/hvpatch/patcher.rs`
Binary patcher. Scans executable regions for:
- `svc #0` (`0xd4000001`) → `bl <island_offset>` (compute relative offset, check ±128MB range)
- `mrs Xn, tpidr_el0` (`0xd53bd0{4n}`) → `ldr Xn, [x20, #TPIDR_OFF]`
- `mrs Xn, ctr_el0` → `ldr Xn, [x20, #CTR_OFF]`
- `mrs Xn, dczid_el0` → `ldr Xn, [x20, #DCZID_OFF]`

Patching operates on the host-side buffer **before** `hv_vm_map`, so no W^X issues. Returns a patch manifest (list of patched sites for debugging).

#### [NEW] `crates/carrick-runtime/src/hvpatch/island.rs`
Hand-assembled AArch64 island code (raw `u32` opcodes, like [`el0_trampoline_bytes`](file:///Volumes/CaseSensitive/carrick/crates/carrick-mem/src/memory.rs#L2493)). Phase 1 island:
```
// x8 = Linux syscall number (set by guest before patched bl)
// x20 = info page base (set at process start, callee-saved)
island_entry:
    svc #0          // Phase 1: ALL syscalls still exit, just through the island
    ret             // return to caller
```

Phase 1 island is a **passthrough** — it proves the wiring works. Fast paths added in phase 2.

#### [NEW] `crates/carrick-runtime/src/hvpatch/info_page.rs`
Info page layout (a `#[repr(C)]` struct mapped at a fixed VA):
```rust
#[repr(C)]
pub struct InfoPage {
    pub tpidr_el0: u64,      // guest TLS base
    pub pid: u32,
    pub tid: u32,
    pub ctr_el0: u64,        // cache type register
    pub dczid_el0: u64,      // data cache zero ID
    // Phase 2+: time data, sigaction shadow, etc.
}
```

### 1.3 The vCPU loop

#### [NEW] `crates/carrick-runtime/src/hvpatch/vcpu_loop.rs`
The trap loop. Structurally similar to [`carrick-vmm-hvf/src/trap.rs`](file:///Volumes/CaseSensitive/carrick/crates/carrick-vmm-hvf/src/trap.rs) but simpler:

```rust
loop {
    vcpu.run()?;
    match vcpu.exit_info() {
        // EC=0x15 (SVC from AArch64): guest hit a real svc #0
        // (either unpatched or island passthrough)
        ExitSvc { .. } => {
            let nr = vcpu.reg(X8)?;
            let args = [vcpu.reg(X0)?, vcpu.reg(X1)?, ...];
            let result = dispatcher.dispatch(nr, &args, &mut guest_mem)?;
            vcpu.set_reg(X0, result)?;
            // Advance PC past the svc
            vcpu.set_reg(PC, vcpu.reg(PC)? + 4)?;
        }
        // EC=0x16 (HVC): EL1 vector forwarding (same as current VMM)
        ExitHvc { .. } => { /* same dispatch path */ }
        // Other exits: data abort, instruction abort, etc.
        _ => { /* handle faults, kicks, etc. */ }
    }
}
```

### 1.4 Verification gate

- `carrick run --exec-backend hvpatch <static-hello-world>` prints "hello world" and exits 0
- `carrick run --exec-backend hvpatch ubuntu:24.04 -- /bin/echo hello` works (dynamic ELF with interpreter)
- DTrace confirmation: count VM exits during hello-world, verify `svc` exits come from the island (patched sites don't exit directly)
- `just clippy`, `just test`, `just ci` all pass

### Measured deliverable
Run the 20-exec `compile -V` micro-fixture. Measure CPU-s vs current VMM and native backends. This is the first real number for the new architecture.

---

## Phase 2 — In-guest fast paths

**Goal:** Eliminate VM exits for the syscalls that don't need host resources.

### 2.1 Island fast paths

#### [MODIFY] `crates/carrick-runtime/src/hvpatch/island.rs`
Expand the island with fast-path handlers:

| Fast path | Implementation | Exits saved (cold build) |
|---|---|---:|
| `getpid` / `gettid` / `getuid` / `getgid` | Load from info page | ~200 |
| `rt_sigaction` | Shadow sigaction table in info page extension | ~11,115 |
| `clock_gettime` | Seqlock-read from shared time page | ~hundreds |
| `tgkill(self)` | In-guest signal pending flag | ~2,033 |
| `brk` | Bump allocator on pre-mapped arena | ~hundreds |

Each fast path: compare `x8` against the syscall number, branch to handler, handler reads/writes the info page, `ret` to caller. Fallback: `svc #0` for unrecognized numbers.

### 2.2 Info page extensions

#### [MODIFY] `crates/carrick-runtime/src/hvpatch/info_page.rs`
Extend `InfoPage` with:
- `sigaction_table: [SigactionEntry; 64]` — shadow of guest's signal dispositions
- `time_seq: u64` / `time_sec: u64` / `time_nsec: u64` — seqlock time data
- `brk_current: u64` / `brk_limit: u64` — heap bump state
- `futex_spinlock_table: [AtomicU32; 256]` — for simple futex fast paths

### 2.3 Time page maintenance

#### [NEW] `crates/carrick-runtime/src/hvpatch/time_sync.rs`
A host thread that periodically updates the time fields on the info page via the host pointer (`HostVa`) to the mapped info page. Uses seqlock protocol:
```
seq++; barrier; write sec/nsec; barrier; seq++;
```
The island's `clock_gettime` reads: `repeat { seq1 = seq; sec = *sec; nsec = *nsec; seq2 = seq; } until seq1 == seq2 && seq1 % 2 == 0`.

Frequency: 1ms tick via `mach_absolute_time` timer thread. Cost: negligible.

### 2.4 `futex` fast path

For `FUTEX_WAIT`/`FUTEX_WAKE` on addresses within the guest's mapped memory:
- `FUTEX_WAIT`: atomically check the futex word, if mismatch return `EAGAIN`, if match use `wfe` (ARM wait-for-event) to park
- `FUTEX_WAKE`: `sev` (send event) to wake parked vCPUs
- Fallback to `svc #0` for `FUTEX_WAIT_BITSET`, `FUTEX_REQUEUE`, etc.

This eliminates the 258K `psynch_cvwait`/`psynch_cvsignal` host calls (0.38s kernel CPU) from the current architecture.

### 2.5 Verification gate

- Count VM exits during cold `go build` — target: **<20K** (down from 88K+ today)
- Measure CPU-s — target: **<6.5 CPU-s** (the 3× bar)
- All fast-path syscalls produce correct results (verified against Docker oracle)

---

## Phase 3 — Memory-mapped file I/O

**Goal:** Eliminate VM exits for `read` by memory-mapping file contents into stage-1.

### 3.1 In-guest `read` via mapped file views

When the host dispatch handles `openat` (which must still exit), in addition to returning an fd:
1. `mmap` the host file into the Carrick process
2. `hv_vm_map` the host mapping into the VM arena at a guest-visible VA
3. Record the mapping in the info page's fd-to-mapping table
4. On subsequent `read` calls to this fd, the island copies from the mapped view to the guest buffer — **no VM exit**

#### [NEW] `crates/carrick-runtime/src/hvpatch/mapped_io.rs`
File-mapping manager:
- `open_and_map(path) -> (fd, guest_va, len)` — opens host file, maps into stage-1
- `read_from_mapping(fd, buf, count) -> usize` — in-guest memcpy (island code)
- `close_and_unmap(fd)` — tear down on close

### 3.2 Write batching

For `write` syscalls (which must hit the host fd), implement a **submission ring**:
1. Island queues write requests in a shared ring buffer (mapped in stage-1)
2. When the ring is full or a sync point is reached, island does one `svc #0` to flush the batch
3. Host dispatch processes all queued writes in one exit

This divides write-exit count by the batch size.

### 3.3 HVF demand-paging for anonymous mappings

For `mmap(MAP_ANONYMOUS)`:
1. Pre-allocate a large arena of host memory
2. `hv_vm_map` the whole arena into stage-1
3. Island's `mmap` fast path returns VAs from this arena (bump allocator)
4. HVF demand-zeros pages on first touch — **no VM exit**

This eliminates the 553K `zfod` events and the ~1.94M `as_fault` events from the current architecture.

### 3.4 Verification gate

- Cold `go build` exits: target **<8K** (only `openat`, `close`, `exec`, `fork`, `wait`, `epoll`)
- CPU-s: target **<4.5 CPU-s** (approaching 2× Docker)
- File read correctness: byte-for-byte match with Docker oracle

---

## Phase 4 — Process lifecycle

**Goal:** Efficient fork/exec without the capsule re-exec chain, within a single host process.

### 4.1 In-process fork

When the island hits `clone(CLONE_CHILD)`:
1. Guest "fork" does NOT call host `fork()` — all Linux processes share one host process
2. Carrick allocates a new guest process descriptor (fd table, signal state, credentials, pid)
3. Builds a new stage-1 PT by COW-duplicating parent's PT entries (new ASID)
4. Allocates a vCPU from the pool for the child
5. Child's vCPU resumes with the child's ASID in TTBR0 and `x0 = 0` (fork return)

**Key simplification vs current architecture:** No host `fork()`, no capsule serialization/rebuild, no self-re-exec. The child is a lightweight in-process entity — a new stage-1 PT, a new fd table (cloned from parent), and a vCPU slot. This is closer to a thread than a process from the host's perspective.

**Key complexity vs current architecture:** Fd-table isolation, signal delivery, `wait`/`waitpid` semantics, process groups, and session leadership must all be managed in-process by Carrick. The current `SyscallDispatcher` already virtualizes much of this — but it assumes one dispatcher per host process. The hvpatch backend needs a **process table** mapping guest PIDs to their per-process state (fd table, signal masks, stage-1 PT, credentials).

#### [NEW] `crates/carrick-runtime/src/hvpatch/process_table.rs`
In-process guest process registry:
```rust
struct GuestProcess {
    pid: GuestPid,
    parent: GuestPid,
    fd_table: FdTable,
    signal_state: SignalState,
    stage1_pt: Stage1PageTable,
    asid: Asid,
    credentials: Credentials,
    // ...
}
```

### 4.2 In-process exec

When the island hits `execve`:
1. `svc #0` exits to the vCPU loop
2. Loads the new ELF binary (via `AddressSpace::load_elf_file`)
3. **Patches** the new binary's text (patcher from phase 1)
4. Tears down old stage-1 PT, builds new one for the new image's segments
5. Maps new regions into the shared VM arena via `hv_vm_map`
6. Resets the guest process's fd table (close-on-exec), signal state
7. Reconfigures the vCPU: new `TTBR0_EL1`, new `ELR_EL1` (entry point), new `SP_EL0`
8. Runs the EL0 trampoline to drop to the new guest code

**Measured target:** per-exec cost < 1ms (vs 7.2ms today, 8.5ms without ablation).

### 4.3 ASID management

#### [NEW] `crates/carrick-runtime/src/hvpatch/asid.rs`
- ASID allocator (16-bit ASID space → 65K concurrent processes)
- On fork: allocate new ASID, build child PT with parent's mappings
- On exec: reuse the ASID, rebuild PT from new ELF
- On exit: free the ASID
- TLB maintenance: `hv_vcpu_set_sys_reg(TTBR0_EL1, new_ttbr | asid << 48)` + `tlbi aside1is` via the EL1 vector

### 4.4 Verification gate

- `go build` runs to completion with correct output
- fork/exec count matches Docker oracle (68 forks, 67 execs)
- Per-exec cost measured < 1ms
- CPU-s: target **<3.5 CPU-s** (≈1.6× Docker)

---

## Phase 5 — Amplification collapse and 1×

**Goal:** Reach 1× Docker by eliminating remaining host-side amplification.

### 5.1 Direct dispatch (in-thread, no IPC)

Since all Linux processes share one host process, syscall dispatch is already in-thread — no IPC mailbox needed:
1. `hv_vcpu_run` returns with svc exit
2. **Same thread** reads registers, looks up the guest process's fd table/state, calls dispatch, writes result, resumes vCPU
3. Per-exit cost is **0.68µs** (the bare `hv_vcpu_run` round-trip), not 5.9µs

### 5.2 Reduce host syscall amplification to ~1:1

- **`openat` 27.64× → ~2×:** One host `openat` + one `fstat` (for mapping setup). Remove the 16K stat-cache `openat` calls.
- **`newfstatat` 12.13× → ~1×:** One host `fstatat64`. Remove the `openat`+`fgetxattr` probe chain.
- **`rt_sigaction` 9.21× → 0×:** Already handled in-guest (phase 2).
- **`mkdirat` 77.97× → ~2×:** One host `mkdirat` + one `openat` for dirfd. Remove the path-resolution chain.
- **`execve` 1,269× → ~10×:** No capsule. Load ELF + patch + map + configure vCPU.

### 5.3 `nanosleep` via HVF virtual timer

Instead of exiting to the host for `nanosleep`:
1. Island programs the HVF virtual timer (`CNTV_CTL_EL0`, `CNTV_CVAL_EL0`) via a shared sysreg page
2. Executes `wfe` — ARM low-power idle, wakes on timer interrupt
3. Timer interrupt handled by EL1 vectors (updates timer state, `eret` back to island)
4. Island returns to caller

This eliminates 16,277 nanosleep exits and their 34K host `kevent`/`waitid` calls.

### 5.4 Verification gate

- Cold `go build` VM exits: target **<5K**
- CPU-s: target **<2.5 CPU-s** (≈1.15× Docker)
- Full conformance-quick passes
- `just conformance` produces a viable baseline for the hvpatch lane

---

## Phase 6 — Polish and ship

**Goal:** Production-quality, conformance-gated, stable third backend.

### 6.1 Full conformance gate

- Establish `baseline.hvpatch.jsonl` from `just conformance --exec-backend hvpatch`
- Close gaps to match VMM lane's known excuses
- Signal correctness, pty relay, interactive mode

### 6.2 Dynamic code support

- JIT'd code (`mmap(PROT_EXEC)` from V8, etc.): leave unpatched, `svc #0` exits naturally
- `mprotect` to add PROT_EXEC: scan and patch the new region (or leave unpatched if V8-style byte-reading is detected)
- Dynamic linker (`ld-linux-aarch64.so.1`): patch static text of the interpreter, leave lazily-resolved PLT stubs to exit on first call

### 6.3 Performance validation

- Cold `go build`: **<2.3 CPU-s** (within Docker measurement variance)
- CPython test suite, Node.js app, Rust build: all within 2× Docker
- `just conformance` gate green

### 6.4 Maturation path

- Track conformance parity with VMM lane
- Evaluate whether hvpatch can eventually become the default based on conformance + performance evidence
- Keep `native` and `vmm` as fallbacks until hvpatch coverage is proven

---

## Crate impact summary

| Crate | Change |
|---|---|
| [`carrick-spec`](file:///Volumes/CaseSensitive/carrick/crates/carrick-spec/src/lib.rs) | Add `HvPatch` variant |
| [`carrick-runtime`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src) | New `hvpatch/` module (entry point, vcpu loop, patcher, island, info page, mapped I/O, ASID) |
| [`carrick-mem`](file:///Volumes/CaseSensitive/carrick/crates/carrick-mem/src/memory.rs) | Reuse `stage1_identity_page_tables`; possibly extend for per-process non-identity PT |
| [`carrick-vmm-hvf`](file:///Volumes/CaseSensitive/carrick/crates/carrick-vmm-hvf/src) | Reuse HVF bindings; new probe binaries for phase 0 |
| [`carrick-hal`](file:///Volumes/CaseSensitive/carrick/crates/carrick-hal/src) | May extend `HvVm`/`HvVcpu` traits for shared-VM semantics; or implement directly |
| [`carrick-dsr-aarch64`](file:///Volumes/CaseSensitive/carrick/crates/carrick-dsr-aarch64/src) | **Untouched.** Eventually deletable when hvpatch is default |
| [`carrick-dsr`](file:///Volumes/CaseSensitive/carrick/crates/carrick-dsr/src) | **Untouched.** Eventually deletable |
| [`carrick-native-darwin`](file:///Volumes/CaseSensitive/carrick/crates/carrick-native-darwin/src) | **Untouched.** Eventually deletable |

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Phase 0 probe fails (patched `bl` causes VM exit) | Low | Fatal — architecture is dead | Run probe FIRST, before any production code |
| Stage-1 PT management is expensive per-fork | Medium | Slows fork/exec, caps at ~2× Docker | Measure in phase 0c; COW PT trees bound cost |
| `wfe`/`sev` doesn't work as expected under HVF | Medium | nanosleep/futex fast paths don't work | Fall back to `svc #0` for these; ~0.15s impact |
| JIT code reads patched bytes as data (V8 issue) | Known | Must leave JIT unpatched | Already planned: only patch static ELF text |
| HVF `hv_vm_map` latency for per-file mappings | Low | Mapped I/O slower than expected | Measure in phase 3; fall back to `svc` exits for I/O |
| In-process fd isolation correctness | High | Subtle fd-leak or cross-process fd collision bugs | Extensive conformance testing; reuse existing fd-table logic where possible |
| In-process signal delivery correctness | High | Signals delivered to wrong guest "process" | Per-process signal masks + pending queues; conformance gate |
| Shared VM hits 127-VM HVF ceiling with many processes | N/A | **Dodged by design** — one VM, not one per process | ASID management handles multi-process in one VM |
