# macOS/HVF AArch64 syscall mailbox implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` to
> implement this plan task-by-task. Track progress with the checkboxes below.

**Goal:** Reduce the ordinary macOS/HVF AArch64 syscall boundary cost by moving
the syscall frame and return value through one generation-safe per-vCPU shared
mailbox, while preserving the current register path for faults and as a
diagnostic comparator.

**Architecture:** Add a portable AArch64 mailbox wire type below the VMM
backends, a 64 KiB EL1-only mailbox arena in Carrick's existing kernel hole,
and an HVF-owned slot lease per logical vCPU. The EL1 SVC vector publishes the
frame with release ordering, exits through the existing `hvc #2`, and consumes
the host response before `eret`. The host fast path decodes the mapped mailbox
without HVF register reads and completes without an HVF x0 write. Exceptional
paths retain live register preparation; `HvfAarch64Vcpu::run()` converts an
outstanding request to `RegistersPrepared` immediately before re-entry, making
signal, sigreturn, ptrace, and fork-child state safe without dispatcher hooks.

**Tech Stack:** Rust 1.96.0, AArch64 instruction encoding, atomics plus volatile
guest-memory access, Hypervisor.framework/applevisor, Carrick's shared
`Aarch64EngineCore`, USDT/DTrace through `carrick trace`, signed macOS helpers,
ABBA sampling and seeded bootstrap statistics.

## Frozen scope and thresholds

- Delivery gate: macOS/Apple Silicon/HVF/AArch64. KVM AArch64 and every x86 VMM
  keep their existing transport.
- No Linux kernel or other GPL implementation source.
- No live native/VMM migration and no automatic fallback.
- Production default after implementation is mailbox. The internal diagnostic
  environment `CARRICK_HVF_SYSCALL_TRANSPORT=legacy|mailbox` is validated before
  first guest entry and is never CLI or persisted container policy.
- Boundary promotion requires mailbox/legacy p50 at most `0.90` and seeded 95%
  ratio upper bound below `1.00`.
- End-to-end syscall floor/burst ratios require upper bound below `1.00`;
  blocking/direct-compute require upper bound at most `1.02`; fork and fork/exec
  require upper bound at most `1.05`.
- Warmup is ten ABBA blocks (twenty legs per mode). Measurement is thirty ABBA
  blocks (sixty samples per mode). Boundary legs execute 200 transitions and
  must be raised before the campaign if timer quantization is visible.
- Preserve unrelated `.codex/` and `last_1000_commits.txt` state.

## Fixed mailbox layout

Create `#[repr(C, align(64))] Aarch64SyscallMailbox` with exactly 256 bytes and
these byte offsets:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 8 | `magic` |
| 8 | 4 | `version` |
| 12 | 4 | `size` |
| 16 | 8 | `generation` |
| 24 | 8 | `sequence` |
| 32 | 4 | atomic `state` |
| 36 | 4 | `trap_kind` |
| 40 | 4 | `response_action` |
| 44 | 4 | `flags` |
| 48 | 8 | `native_nr` |
| 56 | 48 | `args` (`x0..x5`) |
| 104 | 8 | `x8` |
| 112 | 8 | `resume_pc` (`ELR_EL1`) |
| 120 | 8 | `spsr` |
| 128 | 8 | `fp` (`x29`) |
| 136 | 8 | `lr` (`x30`) |
| 144 | 8 | `sp` (`SP_EL0`) |
| 152 | 8 | `esr` |
| 160 | 8 | `return_value` |
| 168 | 8 | `resume_x16` |
| 176 | 8 | `resume_x17` |
| 184 | 72 | reserved zero bytes |

Constants:

```rust
pub const AARCH64_SYSCALL_MAILBOX_MAGIC: u64 = 0x4341_5252_4d42_4f58; // CARRMBOX
pub const AARCH64_SYSCALL_MAILBOX_VERSION: u32 = 1;
pub const AARCH64_SYSCALL_MAILBOX_SIZE: u64 = 0x100;
pub const LINUX_SYSCALL_MAILBOX_BASE: u64 = LINUX_IDENTITY_PAGE_BASE + LINUX_IDENTITY_PAGE_SIZE;
pub const LINUX_SYSCALL_MAILBOX_ARENA_SIZE: u64 = 0x1_0000;
pub const AARCH64_SYSCALL_MAILBOX_SLOTS: usize = 256;
```

The arena ends at `LINUX_KERNEL_REGION_BASE + 0x1F8000`, leaving 32 KiB before
the end of the existing EL1-only 2 MiB block. Compile-time assertions prove the
arena is 16 KiB aligned, slots tile it exactly, and it overlaps no trampoline,
vector, page-table, maintenance, or identity region.

Wire values are unique typed enums:

```rust
Idle = 0, RequestReady = 1, ResponseReady = 2
Syscall = 1
NormalReturn = 1, RegistersPrepared = 2
```

Only `state` publishes ownership. Guest request publication and host response
publication are release stores; consumers use acquire loads. Payload fields use
volatile access because a running guest is not a Rust thread.

## File map

- Create: `crates/carrick-aarch64/src/mailbox.rs` — wire layout, typed protocol
  vocabulary, compile-time assertions, and host-neutral protocol tests.
- Modify: `crates/carrick-aarch64/src/lib.rs`, `src/vmm.rs`, `src/engine.rs` —
  export layout and move completion behind a backend-overridable vCPU hook.
- Modify: `crates/carrick-mem/src/memory.rs` — arena mapping and mailbox SVC
  vector generation.
- Create: `crates/carrick-vmm-hvf/src/syscall_mailbox.rs` — transport parser,
  slot allocator/lease/binding, validation, publication, and malformed-state
  tests.
- Modify: `crates/carrick-vmm-hvf/src/{lib,trap,hvf_aarch64_engine}.rs` — map,
  bind, recreate, decode, complete, and re-entry integration.
- Modify: `crates/carrick-runtime/src/runtime.rs` and
  `crates/carrick-runtime/src/runtime/exec.rs` — install the arena/vector for
  macOS VMM initial load and execve load.
- Modify: `crates/carrick-runtime/tests/trap_hvf.rs` — signed real-HVF focused
  correctness tests.
- Create: `conformance-probes/src/bin/mailboxregs.rs` — guest-visible register
  preservation witness.
- Create: `crates/carrick-vmm-hvf/src/bin/hvf_syscall_mailbox_probe.rs` and
  `scripts/build-hvf-mailbox-probe.sh` — same-executable/same-VM boundary
  comparator and signing.
- Create: `crates/carrick-cli/tests/perf_support/hvf_mailbox_pair.rs`; modify
  `perf_runner.rs`, `invoke.rs`, `scripts/measure-perf.sh`, and `justfile` — ABBA
  end-to-end evidence.
- Modify: `crates/carrick-observability/src/probes.rs`; create a checked-in
  `carrick trace` consumer under `scripts/dtrace/` — explain removed register
  calls without debug prints.
- Create after measurement:
  `docs/perf-results/2026-07-13-hvf-syscall-mailbox.jsonl` and
  `docs/2026-07-13-hvf-syscall-mailbox-performance.md`.

---

### Task 1: Define and red-test the portable wire protocol

**Files:**

- Create: `crates/carrick-aarch64/src/mailbox.rs`
- Modify: `crates/carrick-aarch64/src/lib.rs`

- [ ] **Step 1: Add layout and value tests first**

Tests must assert size, alignment, every offset in the table above, enum raw
values, and uniqueness. Add protocol-model tests for:

- `Idle -> RequestReady -> ResponseReady -> Idle`;
- stale generation;
- duplicate/non-increasing sequence;
- payload written without request publication;
- wrong trap kind;
- unknown response action;
- response publication before request ownership;
- generation rollover skips zero.

The initial tests may define expected constants against missing production
items so they fail to compile. Confirm RED:

```sh
cargo test -p carrick-aarch64 mailbox --lib -- --nocapture
```

- [ ] **Step 2: Implement the wire type without backend dependencies**

Keep mutation methods out of the wire struct. Provide typed raw-value parsers
that return errors for unknown values. Use `std::sync::atomic::AtomicU32` only
for `state`; payload access belongs to the HVF binding module.

Add const assertions using `size_of`, `align_of`, and `offset_of`; do not rely
only on runtime tests.

- [ ] **Step 3: Run and commit**

```sh
cargo test -p carrick-aarch64 mailbox --lib -- --nocapture
cargo test -p carrick-aarch64 --lib
```

```sh
git add crates/carrick-aarch64/src/lib.rs crates/carrick-aarch64/src/mailbox.rs
git commit -m "feat(arch): define aarch64 syscall mailbox protocol" -m "Add a fixed, generation-stamped 256-byte wire contract with typed ownership and response states. Compile-time offsets and host-neutral malformed-state tests keep later VMM implementations from drifting.\n\nVerified with carrick-aarch64 mailbox and library tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Map the EL1-only arena and generate the mailbox vector

**Files:**

- Modify: `crates/carrick-mem/src/memory.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/runtime/exec.rs`

**Interfaces:**

- `AddressSpace::with_syscall_mailbox_arena()` adds one RW/non-executable 64 KiB
  region at the fixed base.
- `el1_vectors_bytes_mailbox(identity_fast_path: bool)` emits the mailbox SVC
  path while preserving the existing identity syscall handlers when requested.
- macOS VMM initial and execve image construction install the same vector and
  arena. Native DSR and non-macOS VMM image construction do not.

- [ ] **Step 1: Add red region and decoded-word tests**

Extend the current vector tests to prove:

- arena placement/alignment/no-overlap and exact 256-slot tiling;
- the region is present with zeroed bytes and survives every `AddressSpace`
  builder clone/reconstruction;
- lower-EL sync still guards `ESR_EL1.EC == SVC64`;
- identity syscalls still return at EL1 when enabled;
- ordinary SVC stores `x0..x5`, x8, ELR/SPSR/ESR, FP/LR/SP;
- sequence increments before the `stlr RequestReady` publication;
- the request path exits through `hvc #2`;
- continuation stores live x16/x17 before using them as scratch;
- `NormalReturn` loads only x0, both actions restore continuation x16/x17,
  release-store `Idle`, and `eret`;
- invalid response state/action branches to the existing fail-loud `hvc #3`.

Decode generated words using the existing instruction helpers; do not compare
only opaque byte arrays.

Run and confirm RED:

```sh
cargo test -p carrick-mem mailbox --lib -- --nocapture
cargo test -p carrick-mem el1_vectors --lib -- --nocapture
```

- [ ] **Step 2: Implement the arena builder**

Add constants directly after the identity-page constants. Update every
`AddressSpace` destructuring/reconstruction site so new metadata is not lost;
the fixed base means no new serialized control-register field is required.

- [ ] **Step 3: Implement vector emission**

Factor shared identity dispatch rather than duplicating its instruction table.
Use SP_EL1 as the slot base. At exception entry, save any scratch register
before its first use. At continuation, save the *current* x16/x17 values to
`resume_x16/resume_x17` before inspecting the response; this preserves
host-prepared signal or sigreturn registers under `RegistersPrepared`.

The vector never polls. It performs one request publication, one HVC, one
response validation, and one `eret`.

- [ ] **Step 4: Install only on the macOS VMM path**

In both initial image setup and `runtime/exec.rs`, select the mailbox vector and
arena under the macOS VMM build. Keep KVM AArch64 on the existing vector until
separate evidence. The `syscall-shim` feature controls identity handlers, not
whether the mailbox exists.

- [ ] **Step 5: Run and commit**

```sh
cargo test -p carrick-mem mailbox --lib -- --nocapture
cargo test -p carrick-mem el1_vectors --lib -- --nocapture
cargo check -p carrick-runtime
```

```sh
git add crates/carrick-mem/src/memory.rs crates/carrick-runtime/src/runtime.rs \
  crates/carrick-runtime/src/runtime/exec.rs
git commit -m "feat(arch): publish syscalls through an el1 mailbox" -m "Reserve a bounded EL1-only mailbox arena and emit an AArch64 SVC vector that publishes complete syscall frames before the existing HVC exit. The continuation preserves host-prepared registers and fails loud on malformed responses.\n\nVerified with decoded vector-word, address-space, and runtime compile tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Add Carrick-owned slot leases and generation-safe HVF bindings

**Files:**

- Create: `crates/carrick-vmm-hvf/src/syscall_mailbox.rs`
- Modify: `crates/carrick-vmm-hvf/src/lib.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`

**Interfaces:**

- `MailboxSlotId(u16)` is Carrick-owned; never derive it from opaque HVF
  `vcpu.id()`.
- `MailboxSlotAllocator` owns a 256-bit/entry used set behind a mutex and is
  shared by sibling thread states through `Arc`.
- `MailboxSlotLease` releases its slot on logical vCPU drop; vCPU
  destroy/recreate for reclaim retains the lease.
- `MailboxBinding` holds slot, host pointer, generation, last accepted sequence,
  and `HvfSyscallTransport`.
- A process-global monotonic atomic supplies nonzero generations on initial
  bind and every vCPU incarnation/rebind.

- [ ] **Step 1: Add red allocator and protocol-consumer tests**

Unit tests use an aligned in-memory mailbox and prove:

- 256 unique leases, deterministic exhaustion, and reuse only after drop;
- binding address is `base + slot * 256` and never outside the arena;
- generation changes on reuse/recreate and zero is skipped;
- acquire of `RequestReady` returns a frame only for matching magic/version/
  size/generation, `Syscall`, and a strictly newer sequence;
- partial/stale/duplicate/wrong-kind requests fail closed without dispatch;
- normal response writes payload then release-publishes `ResponseReady`;
- prepared response does not write `return_value`;
- `legacy`, `mailbox`, and unset transport parse as legacy/mailbox/mailbox;
  every other value fails with `CARRICK_HVF_SYSCALL_TRANSPORT` in the error.

Confirm RED:

```sh
cargo test -p carrick-vmm-hvf syscall_mailbox --lib -- --nocapture
```

- [ ] **Step 2: Implement allocator, lease, and volatile payload access**

The allocator may use `parking_lot::Mutex<[bool; 256]>`; this state is
thread-shared inside one process and COW-copied only after Carrick has quiesced
threads for host `fork`. Do not use a process-shared lock or an HVF-global ID.

Read/write non-atomic fields with `read_volatile`/`write_volatile`. Validate the
header before any frame conversion. Use the wire `state` atomic for
release/acquire publication.

- [ ] **Step 3: Expand `HvfAarch64Vcpu`**

Replace the tuple newtype with named fields:

```rust
pub struct HvfAarch64Vcpu {
    inner: ManuallyDrop<applevisor::vcpu::Vcpu>,
    mailbox: MailboxBinding,
}
```

Keep the existing no-op applevisor drop discipline. Dropping the binding must
release only the Carrick mailbox slot, not touch the already-destroyed HVF
vCPU.

Add the shared allocator to `HvfVmState` and `ThreadSpec`. Initial bring-up and
`add_vcpu`/`materialize_sibling` allocate a lease after mappings exist, resolve
the host pointer with `host_ptr(LINUX_SYSCALL_MAILBOX_BASE + offset, 256)`, stamp
the header, and set SP_EL1 to the slot guest address. Failure before first guest
entry returns `TrapError`, never a null binding.

- [ ] **Step 4: Rebind every vCPU lifecycle path**

Create one helper `rebind_mailbox_after_vcpu_create(vcpu, binding)` that:

1. resolves/refreshed host pointer after VM remap;
2. assigns a fresh nonzero generation;
3. preserves an in-flight `RequestReady` payload when fork restore resumes the
   trapped syscall, otherwise resets to `Idle`;
4. writes SP_EL1 to the slot guest address.

Call it after initial creation, sibling materialization, parent and child fork
rebuild, execve rebuild (fresh allocator/lease and `Idle`), reclaim resume,
shared-wait resume, and multithreaded-fork sibling rebuild. Replace every old
`SP_EL1 = guest SP` write; SP_EL0 continues to hold the guest stack.

Audit:

```sh
rg -n 'SP_EL1|create_vcpu|new_vcpu|replace\(vcpu' \
  crates/carrick-vmm-hvf/src/trap.rs \
  crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs
```

Every fresh vCPU must be followed by mailbox binding before it can run.

- [ ] **Step 5: Run and commit**

```sh
cargo test -p carrick-vmm-hvf syscall_mailbox --lib -- --nocapture
cargo test -p carrick-vmm-hvf --lib
cargo check -p carrick-aarch64 -p carrick-vmm-hvf -p carrick-runtime
```

```sh
git add crates/carrick-vmm-hvf/src/lib.rs \
  crates/carrick-vmm-hvf/src/syscall_mailbox.rs \
  crates/carrick-vmm-hvf/src/trap.rs \
  crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs
git commit -m "feat(hvf): bind a mailbox to each logical vcpu" -m "Allocate Carrick-owned mailbox slots independently of opaque HVF ids and refresh their generation and SP_EL1 binding across fork, exec, sibling creation, and reclaim. Malformed or stale publications fail before dispatch.\n\nVerified with allocator, protocol, HVF lifecycle, and library tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Move ordinary syscall decode and completion off HVF registers

**Files:**

- Modify: `crates/carrick-aarch64/src/vmm.rs`
- Modify: `crates/carrick-aarch64/src/engine.rs`
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`

**Interfaces:**

- Add `Aarch64Vcpu::complete_syscall_return(i64)` with the current x0/x9 logic
  as its default. KVM behavior remains byte-for-byte equivalent.
- `Aarch64EngineCore::complete_syscall` clears pending state and calls that
  vCPU hook.
- HVF mailbox mode overrides the hook to publish `NormalReturn`; it issues no
  `hv_vcpu_set_reg(x0)`.
- HVF legacy mode keeps the default register completion.
- `HvfAarch64Vcpu::run` calls `prepare_outstanding_request_for_reentry()` before
  `hv_vcpu_run`: `RequestReady` becomes `RegistersPrepared`, `ResponseReady` is
  left for the vector, and `Idle` is a normal EL0/kick entry.

- [ ] **Step 1: Add red shared-engine tests with a mock vCPU**

Extend `carrick-aarch64` mocks to prove generic completion delegates exactly
once and does not separately set x0. Keep a KVM/default-hook test proving x0 and
saved x9 behavior is unchanged.

In HVF mailbox tests, instrument register access closures/counters and assert:

- mailbox decode constructs `Aarch64SyscallFrame` and `resume_pc` with zero
  GPR/sysreg API reads;
- `vcpu_trap` fields come from the mailbox;
- mailbox completion performs zero register API writes;
- legacy diagnostic decode still calls the shared register-frame reader and
  legacy completion writes x0;
- a non-SVC HVC with mailbox `Idle` follows the existing ESR/fault path;
- a direct EL0 fault, sys64 emulation, maintenance HVC, kick, and HVC3 fail-loud
  never decode a mailbox syscall.

Confirm RED:

```sh
cargo test -p carrick-aarch64 complete_syscall --lib -- --nocapture
cargo test -p carrick-vmm-hvf mailbox_decode --lib -- --nocapture
```

- [ ] **Step 2: Implement the backend completion hook**

Move the current engine x0/x9 body into the trait default without changing its
ordering. Override only in HVF. Do not add a mailbox capability conditional to
the runtime dispatcher.

- [ ] **Step 3: Decode mailbox ownership at HVC2**

In `run_to_exit`, after identifying HVC2:

- mailbox mode + valid `RequestReady`: consume the frame and return
  `Aarch64Exit::Syscall`;
- legacy mode + valid request: deliberately use current register/sysreg reads;
- mailbox `Idle`: retain the current underlying ESR/fault/sys64 path;
- any malformed non-idle mailbox: fail closed with protocol fields in the
  error, never silently fall back and risk double dispatch.

Keep `hvc #3` fail-loud behavior distinct from protocol errors.

- [ ] **Step 4: Implement automatic `RegistersPrepared` re-entry**

Immediately before every `hv_vcpu_run`, inspect the binding. A still-owned
`RequestReady` means the runtime intentionally prepared live registers without
calling normal completion (signal handler entry, `rt_sigreturn`, ptrace stop/
resume, or fork-child state), so publish `RegistersPrepared`. This central
hook is the only exceptional response publication site.

This must happen after all host register edits and before guest entry. It must
not run while dispatch still owns the vCPU; the runtime calls `run` only after
an outcome is complete.

- [ ] **Step 5: Run and commit**

```sh
cargo test -p carrick-aarch64 complete_syscall --lib -- --nocapture
cargo test -p carrick-vmm-hvf mailbox --lib -- --nocapture
cargo test -p carrick-vmm-hvf --lib
cargo check -p carrick-vmm-kvm -p carrick-vmm-hvf -p carrick-runtime
```

```sh
git add crates/carrick-aarch64/src/vmm.rs crates/carrick-aarch64/src/engine.rs \
  crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs \
  crates/carrick-vmm-hvf/src/trap.rs
git commit -m "feat(hvf): complete ordinary syscalls through the mailbox" -m "Decode valid HVC2 syscall frames from shared memory and publish returns without Hypervisor.framework register calls. A single pre-entry hook marks host-prepared exceptional register state, while faults and the diagnostic legacy path retain their existing behavior.\n\nVerified with shared-engine, zero-register-access, fault-path, and HVF library tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 5: Prove register, interruption, and lifecycle correctness on real HVF

**Files:**

- Create: `conformance-probes/src/bin/mailboxregs.rs`
- Modify: `crates/carrick-runtime/tests/trap_hvf.rs`
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `docs/conformance-coverage.md`

- [ ] **Step 1: Add a red guest register witness**

`mailboxregs` uses an AArch64 assembly function to seed x1..x30 with distinct
nonzero sentinels, issue a non-identity syscall (`getppid`), and copy the
post-SVC registers to a Rust-owned output array. It prints one stable line with
the return and a mismatch mask. x0 is allowed to change; x1..x30 and SP must
match. Run it against the pre-mailbox signed binary to establish the probe
itself passes there, then temporarily force an intentionally clobbering vector
in the test branch and prove the mismatch is detected before restoring the
real implementation.

- [ ] **Step 2: Add focused signed HVF tests**

Add `trap_hvf` cases for mailbox and forced-legacy mode covering:

- `mailboxregs` normal return;
- `waitrestart` SA_RESTART;
- `signals`, `xsignal`, and `sigunblockpending` handler-entry syscalls;
- `rt_sigreturn` through the existing signal probes;
- `ptracesignalstop` and `traceexecstop`;
- `clonebasic`, `forkfpregs`, `forkfpreclaim`, `execfromthread`, and
  `execpermitchurn`;
- an M:N reclaim budget forced low enough to destroy/recreate vCPUs;
- invalid `CARRICK_HVF_SYSCALL_TRANSPORT` rejected before first run.

Use scoped `CARRICK_RUN_ID`; never run Docker concurrently with these HVF
tests.

- [ ] **Step 3: Implement the seven-phase interruption matrix**

Host-neutral protocol tests inject interruption at: before construction,
during payload, after request publication, during host ownership, after
response payload, after response publication, and after EL0 return. Each test
asserts one sequence dispatch, one response, and final `Idle`.

Real-HVF tests cover the observable phases possible without adding timing
sleep hooks: signal/kick before HVC, signal pending during host dispatch,
signal entry after request, and signal immediately after return. Use existing
signal injection facilities and the always-on event ring, not `eprintln!`.

- [ ] **Step 4: Run the red-first differential gate**

From the repository root, with Carrick and Docker phases separate:

```sh
just build
CARRICK_RUN_ID=mailbox-probes-red cargo test -p carrick-cli --test conformance \
  conformance_probes -- --nocapture
scripts/sudo/kill.sh mailbox-probes-red
```

Capture binary-safe logs with `grep -a`. First demonstrate `mailboxregs` detects
the deliberately broken register-preservation variant, then restore and prove
MATCH against Docker.

- [ ] **Step 5: Commit correctness coverage**

```sh
git add conformance-probes/src/bin/mailboxregs.rs \
  crates/carrick-runtime/tests/trap_hvf.rs \
  crates/carrick-cli/tests/conformance.rs docs/conformance-coverage.md
git commit -m "test(hvf): gate mailbox register and restart semantics" -m "Add a guest assembly witness for preserved AArch64 registers and exercise mailbox normal, signal, restart, ptrace, fork, exec, and vCPU-reclaim paths on signed HVF. The probe was proven red with an intentional continuation clobber before the correct vector matched Docker.\n\nVerified with focused signed HVF tests and the line-exact Docker differential probe gate.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 6: Add the same-VM boundary comparator and supported trace evidence

**Files:**

- Create: `crates/carrick-vmm-hvf/src/bin/hvf_syscall_mailbox_probe.rs`
- Create: `scripts/build-hvf-mailbox-probe.sh`
- Modify: `crates/carrick-observability/src/probes.rs`
- Create: `scripts/dtrace/hvf-syscall-transport.d`
- Modify: `docs/diagnostics-and-debugging.md`

**Interfaces:**

- Helper subcommand:
  `hvf_syscall_mailbox_probe compare --warmup-blocks 10 --sample-blocks 30
  --transitions 200 --seed 5634344305327363654`.
- One signed executable creates one VM and one vCPU, maps both protocol data and
  a synthetic SVC loop, and runs legacy/mailbox/mailbox/legacy legs without
  recreating the VM.
- The host service returns constant zero and performs no runtime dispatch or
  host syscall inside the timed transition loop.
- Output is versioned JSONL with raw per-transition nanoseconds and actual HVF
  register/sysreg read/write counters for each leg.

- [ ] **Step 1: Add parser/statistics tests before the live helper**

Test exact argument defaults, ABBA order, invalid zero transitions, timer
quantization rejection, and JSONL schema. Reuse
`crates/carrick-cli/src/perf_stats.rs` logic where dependency direction permits;
otherwise emit raw samples and let the CLI evidence layer summarize them.

- [ ] **Step 2: Implement and sign the helper**

Use the production mailbox layout and generated vector bytes; do not duplicate
offsets or encodings. The legacy leg reads the same published mailbox request
only to establish ownership, then obtains frame/return through HVF register
APIs. The mailbox leg uses volatile payload access. Both traverse the same SVC,
HVC2, and ERET instructions in the same VM.

`scripts/build-hvf-mailbox-probe.sh` builds release with Apple ld64, signs the
helper itself using `scripts/entitlements.plist`, verifies the hypervisor
entitlement, and prints the helper SHA-256. Signing `carrick` alone is not
sufficient.

- [ ] **Step 3: Add supported `carrick trace` transport attribution**

Add an always-available USDT probe reporting transport, sequence, and the
number of HVF register/sysreg reads/writes for that boundary. Add the checked-in
`hvf-syscall-transport.d` consumer and document its use through:

```sh
target/release/carrick trace --script scripts/dtrace/hvf-syscall-transport.d -- \
  run-elf --exec-backend vmm \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_trap_floor
```

This is a maintained tracer extension, not an ad-hoc D script or debug print.
Predicate on target/progeny and fail if DTrace drops records.

- [ ] **Step 4: Run focused verification and commit**

```sh
cargo test -p carrick-vmm-hvf --bin hvf_syscall_mailbox_probe
cargo test -p carrick-observability --lib
scripts/build-hvf-mailbox-probe.sh
target/release/hvf_syscall_mailbox_probe compare \
  --warmup-blocks 1 --sample-blocks 2 --transitions 200 \
  --seed 5634344305327363654
```

```sh
git add crates/carrick-vmm-hvf/src/bin/hvf_syscall_mailbox_probe.rs \
  scripts/build-hvf-mailbox-probe.sh \
  crates/carrick-observability/src/probes.rs \
  scripts/dtrace/hvf-syscall-transport.d docs/diagnostics-and-debugging.md
git commit -m "diagnostics(hvf): compare syscall transports in one vm" -m "Add a signed same-executable, same-VM boundary comparator and a maintained carrick-trace view of register API traffic. Both transports execute equal SVC/HVC work while the helper records raw samples and actual register-call counts.\n\nVerified with helper schema tests, signed smoke sampling, and observability library tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 7: Extend the ABBA harness and make the frozen promotion decision

**Files:**

- Create: `crates/carrick-cli/tests/perf_support/hvf_mailbox_pair.rs`
- Modify: `crates/carrick-cli/tests/perf_support/mod.rs`
- Modify: `crates/carrick-cli/tests/perf_support/invoke.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`
- Modify: `scripts/measure-perf.sh`
- Modify: `justfile`
- Create: `docs/perf-results/2026-07-13-hvf-syscall-mailbox.jsonl`
- Create: `docs/2026-07-13-hvf-syscall-mailbox-performance.md`

**Interfaces:**

- `HvfSyscallTransport::{Legacy,Mailbox}` evidence labels.
- Fixed order `[Legacy, Mailbox, Mailbox, Legacy]`.
- Both end-to-end legs invoke the same signed `target/release/carrick`, same
  `--exec-backend vmm`, same direct-ELF artifact and arguments; only
  `CARRICK_HVF_SYSCALL_TRANSPORT` differs.
- Report schema distinguishes `run`, `boundary_measurement`,
  `end_to_end_measurement`, `comparison`, `skip`, and `invalid`.

- [ ] **Step 1: Add red harness tests**

Prove schedule, twenty warmup legs/mode, sixty measured samples/mode, fixed
bootstrap seed/resamples, same binary/artifact hash validation, threshold
classification, invalid timeout/crash/leftover handling, and atomic report
writing. Assert the selected cases include:

- boundary helper;
- `trap_floor`;
- `stdio_burst` and `writev_burst`;
- `wait_pipe_pingpong` and `epoll_pipe_loop`;
- `fork` and `fork_exec`;
- one direct-compute case selected from the existing registry or added as a
  static probe that performs no syscall inside its timed loop.

- [ ] **Step 2: Implement deliberate runner and recipe**

Add ignored test `hvf_mailbox_report` and recipe:

```sh
just bench-hvf-mailbox full
```

The script builds/signs `carrick`, builds/signs the boundary helper, builds the
native-PIE guest probes, assigns `CARRICK_RUN_ID="mailbox-perf-$$"`, runs
serially, and always calls `scripts/sudo/kill.sh "$CARRICK_RUN_ID"` on exit. It
records codesign identity,
binary/helper/artifact hashes, git SHA/dirty state, OS/CPU/power facts, order,
transition count, bootstrap parameters, and cleanup result.

- [ ] **Step 3: Freeze and run the full campaign once**

Before sampling, commit the threshold constants and verify the machine is on
AC power with no Carrick/Docker overlap. Then:

```sh
CARRICK_HVF_MAILBOX_REPORT=docs/perf-results/2026-07-13-hvf-syscall-mailbox.jsonl \
  just bench-hvf-mailbox full
```

Do not rerun selectively to replace unfavorable rows. A failed/invalid run is
evidence and must be classified before a fresh complete campaign.

- [ ] **Step 4: Profile the same artifact in both modes**

Use the maintained `carrick trace` transport consumer on `perf_trap_floor` in
legacy and mailbox mode. Record register-call totals and DTrace drop counts in
the report. The mailbox ordinary path must show zero frame register/sysreg
reads and zero x0 writes; exceptional events are reported separately.

- [ ] **Step 5: Write the measured verdict**

`docs/2026-07-13-hvf-syscall-mailbox-performance.md` must include provenance,
raw-file link, exact thresholds, summaries/intervals, correctness gates,
register-call attribution, invalid/skipped rows, limitations, and one verdict:

- **promote** — every frozen correctness/performance threshold passes;
- **reject** — boundary win is below 10%, interval includes 1.0, or complexity
  fails an end-to-end/correctness guard; revert production mailbox selection
  while retaining the evidence;
- **inconclusive** — environmental invalidity requires a new complete campaign,
  with no threshold change.

Never state a universal workload speedup.

- [ ] **Step 6: Run full final gates and representative workloads**

```sh
just fmt-check
just clippy
just lint-domains
just ci
just build
```

Run explicit `--exec-backend vmm` representatives for Rust, Go, CPython,
Node/V8, fork-heavy, signal-heavy, and multithreaded workloads. Run Carrick
probe phase and Docker oracle phase separately. Verify scoped cleanup and no
leftover processes.

- [ ] **Step 7: Commit evidence and promotion/rejection**

```sh
git add crates/carrick-cli/tests/perf_support/hvf_mailbox_pair.rs \
  crates/carrick-cli/tests/perf_support/mod.rs \
  crates/carrick-cli/tests/perf_support/invoke.rs \
  crates/carrick-cli/tests/perf_runner.rs scripts/measure-perf.sh justfile \
  docs/perf-results/2026-07-13-hvf-syscall-mailbox.jsonl \
  docs/2026-07-13-hvf-syscall-mailbox-performance.md
git commit -m "test(hvf): publish syscall mailbox performance evidence" -m "Run the frozen same-binary ABBA campaign over the isolated boundary and end-to-end guard cases, with seeded bootstrap intervals and register-call attribution. The checked-in report records the measured promotion decision and all invalid or skipped rows without moving thresholds.\n\nVerified with the signed full mailbox campaign, representative VMM workloads, Docker differential probes, and the full local CI gate.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

## Completion evidence

Do not mark the mailbox implemented merely because it compiles. Completion
requires:

- fixed wire/layout assertions and malformed-state tests;
- no mailbox slot derived from `hv_vcpu_t`;
- every vCPU create/recreate installs generation and SP_EL1 binding;
- ordinary mailbox syscall decode performs no HVF frame reads and completion
  performs no x0 write;
- `RegistersPrepared` covers signal, sigreturn, ptrace, and fork-child resume;
- red-first register witness plus signed lifecycle/interruption tests pass;
- Docker differential probes match in a separate oracle phase;
- the same-VM boundary helper and end-to-end ABBA report are checked in;
- frozen thresholds produce an honest promote/reject/inconclusive verdict;
- `just ci`, signed representative workloads, and cleanup audit pass.
