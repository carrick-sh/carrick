# Darwin Native Syscall-to-Kernel Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce two accepted, receipt-bound Darwin/AArch64 native cold-GOCACHE
Go-build captures that join complete guest syscall service operations, Darwin
host syscalls, sampled kernel CPU, and non-overlapping quiescent wall time, then
publish either one stable evidence-qualified H006 candidate or `DIFFUSE`.

**Architecture:** Keep `native-wall` as the one launch-owned DTrace capture.
Add inert full-service USDT boundaries around the native driver, maintain all
join state in DTrace by `(pid, tid)` and operation ID, annotate the exact raw
kernel address population with an identity-free live-symbol overlay, and make
the Rust parser and Python analyzer reject every incomplete or unreconciled
population. Run Docker separately, with bpftrace inside a native-arm64 derived
oracle image, only after both Carrick captures have ended and exact-run cleanup
has succeeded.

**Tech Stack:** Rust, Serde JSONL, libdtrace/USDT, Darwin `proc`/`sched`/
`syscall`/`profile` providers, Python 3 exact-rational analysis, Docker
native-arm64, in-container bpftrace, signed Carrick release builds.

**Approved design:**
[`docs/superpowers/specs/2026-07-28-native-syscall-kernel-attribution-design.md`](../specs/2026-07-28-native-syscall-kernel-attribution-design.md)

**Supersedes for measurement selection:**
`2026-07-27-native-kernel-oncpu-attribution.md` and
`2026-07-28-native-kernel-attribution-compact-execution.md`. Their immutable
historical receipts and completed implementation commits remain evidence.

## Global Constraints

- The official untraced baseline remains `C0=19,375 ms`, `D0=1,007 ms`,
  `R0=19.2403x`; the first milestone is `R <= 9.6202x`, and the destination is
  `R <= 2.0x`.
- The only primary workload is `native_go_build.guest_script()` in
  `localhost:5005/carrick-go-conformance:1.24`, with native-arm64 image ID
  `sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
- Preserve all existing evidence JSON and raw captures. New evidence paths are
  exclusive and collision-checked with `lstat`/`lexists`; dangling symlinks
  count as occupied.
- Admit `$target` and descendants only through launch ownership and
  `proc:::create`. Never scope by `execname`, substring, or a wall-clock
  interval.
- DTrace profile probes join only through PID/TID associative arrays. They
  never read `self->` values set by another provider.
- `profile-499` remains the sole on-CPU sample clock. The existing kernel-PC
  count, the context count, and the context stack count increment in the same
  firing.
- Raw PCs and stacks are authority. Symbols are a checked annotation and do
  not rewrite raw records.
- Host syscall duration is resource time, not additive wall time. Voluntary
  off-CPU duration is resource time. Only quiescent intervals are accepted as
  non-overlapping blocking wall time.
- Carrick and Docker never overlap. The Docker phase starts only after both
  Carrick receipts prove exact cleanup and a fresh process census is clean.
- Do not use guest `strace`; Linux syscall shape comes from bpftrace inside the
  native-arm64 Docker oracle.
- Do not read Linux kernel or other GPL implementation source.
- Every counter and duration entering a decision uses checked unsigned 64-bit
  arithmetic in Rust and bounded non-negative integers plus `Fraction` in
  Python.
- Any DTrace drop, truncation, nested/unmatched window, invalid branch,
  unresolved weighted leaf, unknown record, overflow, non-natural exit,
  missing `BUILD_OK`, live descendant, cleanup failure, dirty/provenance drift,
  or denominator mismatch rejects the capture.
- Measurement code must not change guest semantics, cache policy, syscall
  results, default backend behavior, or the untraced benchmark.
- No runtime optimization is authorized by this plan. A selected H006 receives
  a mechanism-specific follow-on design and bounded spike; `DIFFUSE` creates no
  H006.

## Protocol and Type Contract

Use these exact context tokens throughout DTrace, Rust, and Python:

| Token | Guest service active | Darwin host syscall active |
| --- | --- | --- |
| `guest-host` | yes | yes |
| `carrick-host` | no | yes |
| `guest-outside-host` | yes | no |
| `carrick-outside-host` | no | no |

`ProfileScope` gains optional `guest_nr`, `guest_name`, `host_syscall`,
`context`, and `host_calls` fields. Names must match
`[A-Za-z0-9_]+`; context must be one of the four tokens above. A context-bearing
kernel stack requires the fields implied by the table and forbids the others.

The sampled-symbol overlay schema is
`carrick.sampled-kernel-symbols.v1`. Address-set hashes are SHA-256 over sorted
unique addresses encoded as eight-byte big-endian values; the empty set hashes
the empty byte string.

The final analysis schema is
`carrick.native-syscall-kernel-attribution.v1`. The new receipt schema is
`carrick.native-syscall-kernel-capture.v1`. Existing v2 receipt files remain
immutable historical evidence but are not inputs to the new analyzer.

---

## Task 1: Implement the Identity-Free Sampled Kernel Symbol Overlay

**Files:**

- Modify: `crates/carrick-runtime/src/dtrace_symbols.rs`

**Interfaces:**

- Add `LiveDtraceSymbolizer::sampled_overlay`.
- Preserve `LiveDtraceSymbolizer::snapshot` until Task 2 removes its native-wall
  caller; other tests may continue to exercise the historical object-bound
  contract.
- Add mandatory `bootsessionuuid` to `KernelIdentity` and every fixture.

- [ ] **Step 1: Add red overlay construction and validation tests**

Add focused tests for:

- exact resolved/unresolved disjoint union;
- duplicate requested, resolved, and unresolved addresses;
- a missing or extra address;
- sorted deterministic output and address-set hashes;
- valid range/offset;
- zero size, `start + size` overflow, out-of-range address, and wrong offset;
- empty identity fields, including `bootsessionuuid`;
- opaque `dts_object` changes producing byte-identical overlays;
- census status `(-1, 1015)` preserved as unresolved;
- any other census status preserved for Task 2 to reject by frame role.

Run:

```bash
cargo test -p carrick-runtime dtrace_symbols::tests::sampled_overlay -- --nocapture
```

Expected: compilation fails because the overlay types and constructor do not
exist.

- [ ] **Step 2: Add exact serializable overlay types**

Add:

```rust
pub const SAMPLED_KERNEL_SYMBOL_SCHEMA: &str =
    "carrick.sampled-kernel-symbols.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SampledKernelSymbol {
    pub address: u64,
    pub symbol: String,
    pub symbol_start: u64,
    pub symbol_size: u64,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct UnresolvedKernelAddress {
    pub address: u64,
    pub status: c_int,
    pub dtrace_errno: c_int,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SampledKernelSymbolOverlay {
    pub schema: String,
    pub identity: KernelIdentity,
    pub requested_sha256: String,
    pub requested_count: u64,
    pub resolved_sha256: String,
    pub resolved_count: u64,
    pub unresolved_sha256: String,
    pub unresolved_count: u64,
    pub symbols: Vec<SampledKernelSymbol>,
    pub unresolved: Vec<UnresolvedKernelAddress>,
}
```

Extend `KernelIdentity`:

```rust
pub struct KernelIdentity {
    pub osversion: String,
    pub version: String,
    pub uuid: String,
    pub machine: String,
    pub bootsessionuuid: String,
}
```

Use `sysctlbyname("kern.bootsessionuuid")` in the live identity read. Validate
all five fields as nonempty after trimming.

- [ ] **Step 3: Build the overlay from one sorted census**

Implement a constructor that:

1. sorts and deduplicates the requested input, rejecting a duplicate rather
   than silently removing it;
2. performs one public libdtrace lookup census;
3. ignores `dts_object` for all identity and grouping decisions;
4. converts successful lookups to `SampledKernelSymbol`;
5. converts lookup failures to `UnresolvedKernelAddress`;
6. validates the exact set partition and symbol ranges;
7. computes all three big-endian address hashes.

Expose:

```rust
pub fn sampled_overlay(
    &mut self,
    requested: Vec<u64>,
) -> Result<SampledKernelSymbolOverlay, KernelSymbolError>
```

The old object-owner mismatch must not run on this path.

- [ ] **Step 4: Prove green and commit**

Run:

```bash
cargo test -p carrick-runtime dtrace_symbols -- --nocapture
just fmt
cargo test -p carrick-runtime dtrace_symbols -- --nocapture
git diff --check
```

Commit:

```bash
git add crates/carrick-runtime/src/dtrace_symbols.rs
git commit -m "diagnostics(runtime): add sampled kernel symbol overlay" -m "Live libdtrace resolves sampled Darwin addresses, but its object label is not a stable object-catalog identity. Add a boot-bound, identity-free overlay that preserves exact requested, resolved, and unresolved address populations without grouping through that opaque label.

Verified with exact partition, deterministic hash, identity, symbol-range, overflow, duplicate, and public lookup-status tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 2: Attach the Overlay to Native-Wall Summaries Fail-Closed

**Files:**

- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/src/commands.rs`

**Interfaces:**

- Replace the native-wall callback's
  `LiveDtraceSymbolizer::snapshot` call with `sampled_overlay`.
- Publish one `ProfileMetric::SampledKernelSymbols` row immediately before
  completion.
- Remove the native-wall insertion of `KernelObjectCatalog` and
  `KernelSymbolMap`; retain deserialization compatibility only where existing
  historical tests need it.

- [ ] **Step 1: Add red role-aware acceptance tests**

Add fixtures that distinguish weighted leaves from caller-only frames. Prove
red for:

- all weighted leaves resolved and one caller unresolved as `(-1, 1015)`;
- a weighted leaf unresolved as `(-1, 1015)`;
- a caller unresolved with any other status;
- requested set not equal to all distinct raw kernel PC/stack addresses;
- duplicate overlay row;
- overlay after completion;
- boot identity mismatch;
- raw address rendered as a symbol;
- zero-size/range/offset failure;
- overlay set-hash disagreement.

Run:

```bash
cargo test -p carrick-cli trace_profile::tests::sampled_kernel -- --nocapture
```

Expected: compilation fails because `SampledKernelSymbols` and
`attach_sampled_kernel_overlay` do not exist.

- [ ] **Step 2: Add one summary metric and role-aware validation**

Add:

```rust
#[cfg(target_os = "macos")]
SampledKernelSymbols {
    overlay: SampledKernelSymbolOverlay,
},
```

Rename `kernel_stack_addresses_from_path` to
`kernel_sample_addresses_from_path`. It must return:

```rust
pub(crate) struct KernelSampleAddresses {
    pub requested: Vec<u64>,
    pub weighted_leaves: BTreeSet<u64>,
}
```

`requested` is the sorted union of every `cpu-kernel-pc` address and every raw
kernel stack frame. `weighted_leaves` is the exact `cpu-kernel-pc` key set.

Implement:

```rust
pub(crate) fn attach_sampled_kernel_overlay(
    &mut self,
    overlay: SampledKernelSymbolOverlay,
) -> Result<()>
```

It validates the overlay's own partition, requires every weighted leaf in
`symbols`, permits unresolved callers only for `status == -1` and
`dtrace_errno == 1015`, preserves raw stacks unchanged, and inserts one metric
before `Completion`.

- [ ] **Step 3: Switch the stopped-target callback**

In `commands.rs`, keep the existing stopped-target symbolization boundary:

```rust
let addresses = kernel_sample_addresses_from_path(raw_path)?;
let overlay = symbolizer.sampled_overlay(addresses.requested)?;
```

After parsing the summary:

```rust
summary.attach_sampled_kernel_overlay(overlay)?;
```

No symbol lookup may happen after the traced target resumes or exits.

- [ ] **Step 4: Prove green and commit**

Run:

```bash
cargo test -p carrick-cli trace_profile -- --nocapture
cargo test -p carrick-cli commands::tests::live_kernel_symbols -- --nocapture
just fmt
cargo test -p carrick-cli trace_profile -- --nocapture
git diff --check
```

Commit:

```bash
git add crates/carrick-cli/src/trace_profile.rs crates/carrick-cli/src/commands.rs
git commit -m "diagnostics(cli): bind sampled symbols to raw kernel frames" -m "Native-wall summaries need exact leaf-versus-caller acceptance without trusting libdtrace object labels. Bind the boot-scoped sampled overlay to the raw PC and stack population while the target is stopped, reject every unresolved weighted leaf, and retain raw frames as authority.

Verified with leaf/caller status, address partition, range, identity, ordering, and stopped-target callback tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 3: Add Typed Full-Service USDT Boundaries

**Files:**

- Modify: `crates/carrick-observability/src/probes.rs`

**Interfaces:**

- Add three provider probes and signature-identical stubs.
- Keep existing `syscall-entry`/`syscall-return` probes unchanged as the nested
  dispatcher-attempt plane.

- [ ] **Step 1: Add red ordinal and signature tests**

Add tests that enumerate every value and prove uniqueness for:

```rust
NativeSyscallBranchKind::{Process, Thread}
NativeSyscallServiceOutcome::{
    Resume,
    ThreadExit,
    InProcessExec,
    Aborted,
}
```

Add compile-time calls to all three wrapper signatures on both USDT and stub
closures.

Run:

```bash
cargo test -p carrick-observability native_syscall_service -- --nocapture
```

Expected: compilation fails because the types and wrappers do not exist.

- [ ] **Step 2: Add typed enums and provider declarations**

Use the existing `dsr_ordinal_enum!` macro:

```rust
dsr_ordinal_enum! {
    pub enum NativeSyscallBranchKind {
        Process = 1,
        Thread = 2,
    }
}

dsr_ordinal_enum! {
    pub enum NativeSyscallServiceOutcome {
        Resume = 1,
        ThreadExit = 2,
        InProcessExec = 3,
        Aborted = 4,
    }
}
```

Add provider declarations whose generated DTrace names are:

```rust
fn native__syscall__service__entry(_: u64, _: &str) {}
fn native__syscall__service__branch(_: u32) {}
fn native__syscall__service__end(_: u64, _: &str, _: u32) {}
```

Expose wrappers:

```rust
pub fn native_syscall_service_entry(number: u64, name: &str)
pub fn native_syscall_service_branch(kind: NativeSyscallBranchKind)
pub fn native_syscall_service_end(
    number: u64,
    name: &str,
    outcome: NativeSyscallServiceOutcome,
)
```

Mirror the exact signatures in the stub module.

- [ ] **Step 3: Prove green, verify DOF declaration text, and commit**

Run:

```bash
cargo test -p carrick-observability native_syscall_service -- --nocapture
just fmt
cargo test -p carrick-observability --lib
git diff --check
```

Commit:

```bash
git add crates/carrick-observability/src/probes.rs
git commit -m "diagnostics(observability): add native syscall service probes" -m "Dispatcher probes end before native outcome lowering, so they cannot identify the full guest-caused service window. Add typed inert entry, branch, and end boundaries while preserving the existing nested dispatcher-attempt probes.

Verified with ordinal uniqueness, USDT/stub signature, and observability library tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 4: Instrument Every Native AArch64 Service Outcome

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

- One service entry per translated guest syscall instruction.
- Service remains active through `dispatch_native_syscall_inner`, waits,
  `DispatchOutcome` lowering, mapping, register completion, and signal
  completion.
- Runtime carries only probe arguments needed for a cloned thread's inherited
  end event; operation IDs remain DTrace-owned.

- [ ] **Step 1: Add red lifecycle-state tests**

Add a small private state machine and tests before wiring it into the loop:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeSyscallServiceState {
    Open,
    TerminalHandoff,
    Closed,
}
```

Test:

- normal resume closes once;
- thread exit closes with `ThreadExit`;
- in-process exec closes with `InProcessExec`;
- process exit and successful host self-exec become `TerminalHandoff` and do
  not emit a normal end;
- process and thread branches can be announced only while open;
- a dropped open span emits `Aborted`;
- a closed or terminal span cannot end or branch twice;
- `NativeCloneThreadRequest` carries the inherited syscall number and static
  ABI name into the child closure.

Run:

```bash
cargo test -p carrick-runtime native_darwin::tests::native_syscall_service -- --nocapture
```

Expected: compilation fails because the span and state do not exist.

- [ ] **Step 2: Open the service at the true driver boundary**

After the translated exit becomes a complete `SyscallRequest`, construct:

```rust
let service_number = request.number.raw();
let service_name = carrick_abi::syscall::lookup_aarch64(service_number)
    .map_or("unknown", |syscall| syscall.name);
let mut service = NativeSyscallServiceSpan::open(service_number, service_name);
```

`open` emits `native_syscall_service_entry`. Its `Drop` emits
`NativeSyscallServiceOutcome::Aborted` only when state is still `Open`.

Do not open the span inside `dispatch_native_syscall` or around the existing
compat probes.

- [ ] **Step 3: Close ordinary return paths after guest state is ready**

For `Returned`, `Errno`, and `SigReturn`, call:

```rust
service.end(NativeSyscallServiceOutcome::Resume);
```

Place it after the final guest register/signal completion and immediately
before the loop resumes translated execution.

For `MapHostAlias`, keep the span open through the host map/protection
installation and close after the guest return value is installed.

For `SignalThread` and `SignalDeath`, keep it open through signal publication
and close at the actual resume or terminal boundary.

- [ ] **Step 4: Propagate process and thread branches**

Immediately before host process creation:

```rust
service.branch(NativeSyscallBranchKind::Process);
```

The parent and fork child each retain an open Rust span copy and emit
`Resume` only after their own guest fork return state is complete.

Immediately before `spawn_clone_thread`:

```rust
service.branch(NativeSyscallBranchKind::Thread);
```

Extend `NativeCloneThreadRequest` with:

```rust
service_number: u64,
service_name: &'static str,
```

The new host thread emits `native_syscall_service_end` with `Resume` only
after the child guest context, TID, and return value are ready. The parent
closes independently after its clone return value is ready.

- [ ] **Step 5: Wire terminal outcomes explicitly**

- `Exit` and process-wide exit: call `service.terminal_handoff()` before
  returning `ProcessExit`; `proc:::exit` closes the DTrace branch.
- `ThreadExit`: emit `ThreadExit` immediately before the host thread returns.
- successful in-process `Execve`: emit `InProcessExec` after the replacement
  image is ready and before translated execution resumes.
- successful host self-exec: call `terminal_handoff()` immediately before the
  non-returning host `execve`; `proc:::exec-success` closes it.
- every error/unwind path leaves the span open so `Drop` emits `Aborted` and
  the profile rejects rather than hiding the path.

- [ ] **Step 6: Prove behavior-inert green and commit**

Run:

```bash
cargo test -p carrick-runtime native_darwin::tests::native_syscall_service -- --nocapture
cargo test -p carrick-runtime --lib -- --test-threads=1
just fmt
cargo test -p carrick-runtime native_darwin::tests::native_syscall_service -- --nocapture
git diff --check
```

Commit:

```bash
git add crates/carrick-runtime/src/native_darwin.rs
git commit -m "diagnostics(native): bracket complete syscall service work" -m "The nested dispatcher probes exclude waits, fork and clone setup, mapping installation, and final guest-state completion. Bracket the full native AArch64 syscall service path, explicitly announce guest branches, and fail visible through an aborted end event on unwinding paths.

Verified with outcome, terminal-handoff, branch, clone-child, drop, and serialized runtime tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 5: Parse Joined Context and Quiescence Records

**Files:**

- Modify: `crates/carrick-cli/src/trace_profile.rs`

**Interfaces:**

- Extend `DSRPROF1` scopes with the fields in the protocol contract.
- Extend `NWSTACK1` kernel records with exact joined context.
- Add interleavable `NWQUIESCE1` begin/stack-end/end records keyed by interval
  ID.

- [ ] **Step 1: Add literal red parser fixtures**

Use literal raw lines, not a generated model. Add fixtures for every design
case:

- one completed service with several host calls;
- dispatcher retry attempts and post-dispatch host work;
- Carrick-only host work;
- all four kernel context classes;
- branch-propagated process and thread completion;
- guest exit, host exec-success, and child-side fork-return transitions;
- nested/mismatched service, dispatcher, and host windows;
- missing, duplicate, wrong-kind, and unconsumed branches;
- generic child with empty guest and host context;
- exact service, dispatcher, host, and four-way kernel reconciliation;
- sleep to wakeup to on-CPU;
- interleaved quiescence intervals joined by ID;
- duplicate/missing begin, stack-end, or end;
- quiescence duration greater than elapsed wall time;
- counter and duration overflow;
- drop, truncated completion, and unknown required record.

Run:

```bash
cargo test -p carrick-cli trace_profile::tests::joined_native -- --nocapture
```

Expected: tests fail because the new fields and `NWQUIESCE1` parser do not
exist.

- [ ] **Step 2: Extend the scope as one typed key**

Add:

```rust
pub(crate) struct ProfileScope {
    phase: String,
    pid: Option<u64>,
    tid: Option<u64>,
    kind: Option<String>,
    source_pc: Option<u64>,
    target_pc: Option<u64>,
    guest_nr: Option<u64>,
    guest_name: Option<String>,
    host_syscall: Option<String>,
    context: Option<String>,
    host_calls: Option<u64>,
}
```

Reject duplicate keys, unknown context tokens, illegal names, zero interval
IDs, and fields forbidden for a phase. Existing historical rows with none of
the new fields remain valid.

- [ ] **Step 3: Extend stack records and add quiescence output**

For joined kernel stacks, require:

```text
NWSTACK1|begin|state=kernel-oncpu|context=guest-host|guest_nr=98|guest_name=futex|host_syscall=__ulock_wait|value=7
```

The frames and `NWSTACK1|end` remain unchanged.

Add a parser table keyed by interval ID for:

```text
NWQUIESCE1|begin|interval=17|pid=220|tid=31|source_pc=0x1000|context=guest-host|guest_nr=98|guest_name=futex|host_syscall=__ulock_wait
NWQUIESCE1|stack-end|interval=17
NWQUIESCE1|end|interval=17|value_ns=3000
```

Frames occur between begin and stack-end. Other complete DSRPROF1, NWSTACK1,
and NWQUIESCE1 records may occur before the matching interval end.

Serialize one:

```rust
ProfileMetric::QuiescentInterval {
    interval: u64,
    pid: u64,
    tid: u64,
    source_pc: u64,
    value_ns: u64,
    frames: Vec<String>,
}
```

with the joined context in `ProfileScope`.

- [ ] **Step 4: Enforce all exact acceptance equations**

Add checked validation for:

```text
service_entries + created_branches
    = resumed_branches + terminal_branches + invalid_open
host_entries
    = host_returns + expected_exec + expected_exit + invalid_open
kernel_pc_samples
    = guest_host + carrick_host + guest_outside_host + carrick_outside_host
kernel_pc_samples = joined_kernel_stack_samples
sum(quiescent_interval_ns) <= elapsed_ns
```

Also require:

- zero invalid/open operations, branches, dispatchers, and host windows;
- one amplification observation per completed operation;
- every dispatcher attempt inside a matching service;
- every host entry in guest-service or Carrick-only context;
- every weighted kernel sample in exactly one context;
- nonnegative live state and zero live processes/threads at completion.

- [ ] **Step 5: Prove green and commit**

Run:

```bash
cargo test -p carrick-cli trace_profile -- --nocapture
just fmt
cargo test -p carrick-cli trace_profile -- --nocapture
git diff --check
```

Commit:

```bash
git add crates/carrick-cli/src/trace_profile.rs
git commit -m "diagnostics(cli): parse joined syscall and quiescence evidence" -m "The native-wall parser previously knew only aggregate CPU and thread resource time. Add strict joined syscall context and interval-ID quiescence framing, then reconcile full service, dispatcher, host, kernel, and wall populations without renormalizing omissions.

Verified with literal complete, branch, terminal, four-context, wakeup, interleaved-interval, malformed, drop, and overflow fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 6: Join Service, Host Syscall, Kernel, and Quiescent Wall in DTrace

**Files:**

- Modify: `scripts/dtrace/native-wall.d`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

**Interfaces:**

- Keep `$target` plus `proc:::create` ownership.
- Keep all high-frequency data aggregated.
- Permit per-interval output only for quiescent begin stack and end duration.
- Leave `scripts/dtrace/syscall-amplification.d` unchanged as historical
  diagnostic material.

- [ ] **Step 1: Add red script-contract tests**

Add source-contract tests that require:

- the three native service probes;
- old dispatcher probes nested but still present;
- Darwin `syscall:::entry` and `syscall:::return`;
- PID/TID-keyed `service_*`, `dispatch_*`, and `host_*` associative arrays;
- no `self->service`, `self->dispatch`, or `self->host` join state;
- `profile-499` increments raw PC, joined context, and joined stack in one
  clause;
- `sched:::wakeup` reads `args[0]->pr_pid` and `args[0]->pr_lwpid`;
- `NWQUIESCE1` begin, stack-end, and end;
- no `execname` predicate;
- no truncation of authority aggregates;
- completion after every aggregate print.

Run:

```bash
cargo test -p carrick-cli --test trace_profile native_wall_joined_script_contract -- --nocapture
```

Expected: the source-contract test fails against the current D program.

- [ ] **Step 2: Track service operations and explicit branches**

At service entry:

1. reject an already-active service on `(pid, tid)`;
2. increment `origin_sequence[pid, tid]`;
3. store origin PID, TID, and sequence on the thread;
4. store bounded guest number/name;
5. initialize operation open branches to one and host calls to zero;
6. count the exact service entry.

At `service-branch`, require one active service and no pending announcement,
increment operation open branches before creation, and save the branch kind.

Consume a process announcement only in the matching `proc:::create`. Consume a
thread announcement only in the matching `proc:::lwp-create`. Copy operation
and guest context to the child `(pid, tid)`. A generic descendant is tracked
but starts without service, dispatcher, or host context.

At service end, validate number/name, classify `Resume`, `ThreadExit`,
`InProcessExec`, or `Aborted`, decrement open branches, and publish the exact
host-call distribution only when open branches reach zero.

Close terminal exit and successful host self-exec branches from
`proc:::exit`/`proc:::exec-success`.

- [ ] **Step 3: Track nested dispatcher attempts**

On existing `syscall-entry`, require a matching active service and no active
dispatcher, then record number/name. On `syscall-return`, require the same
number/name and clear it.

Key host entries by `inside-dispatch` when a dispatcher is active and
`outcome-lowering` when the full service is active after dispatcher return.

- [ ] **Step 4: Track Darwin host syscall windows**

On `syscall:::entry`, store syscall name and timestamp by `(pid, tid)`, reject
nested entry, count the context and host pair, and increment the active
operation's cross-branch host-call count.

On return, require the matching name, add elapsed resource nanoseconds, and
clear the window. Close expected non-returning exec/exit windows through proc
events. Count a child-side fork return only when the matching parent call and
create event establish it; it is not a new host entry.

- [ ] **Step 5: Join every kernel sample in the same firing**

Replace the current kernel profile clause with one clause that computes one of
the four fixed contexts from PID/TID state and increments:

```text
@cpu_kernel[arg0]
@cpu_kernel_context[context, guest_nr, guest_name, host_syscall, arg0]
@cpu_kernel_stack[context, guest_nr, guest_name, host_syscall, stack(24)]
```

Use zero/empty sentinels only inside DTrace keys; printed records omit fields
for contexts where the protocol forbids them.

- [ ] **Step 6: Correct wakeup state and capture quiescent intervals**

Move off-CPU timestamps and PCs from `self->` to `(pid, tid)` associative
arrays. In `sched:::wakeup`, transition the target LWP from sleeping to
runnable using provider arguments and close an active quiescent interval at
wake time.

Start an interval only on the transition to:

```text
on_cpu_threads == 0
runnable_threads == 0
sleeping_threads > 0
```

Print a monotonic interval-ID begin with the last sleeper's user stack and a
matching stack-end marker. Close at the first wakeup, runnable/on-CPU
transition, process/thread create, or completion. Never sum per-thread sleeps
to form this duration.

- [ ] **Step 7: Emit every authority aggregate and reconciliation counter**

Emit service populations, dispatcher populations, host populations and
durations, amplification instances keyed by exact `host_calls`, four-way
kernel context PCs/stacks, state-transition errors, quiescent intervals,
original wall/CPU/resource rows, process lifecycle, elapsed time, and
completion.

Do not call `trunc` on any authority aggregation. The existing presentation
truncation for voluntary stacks must be removed because the accepted profile
requires at least 80% coverage from the full population.

- [ ] **Step 8: Compile the D program without launching a guest**

Run:

```bash
sudo dtrace -q -e -s scripts/dtrace/native-wall.d -c /usr/bin/true
```

Expected: DTrace accepts every provider, predicate, aggregation key, and
format. Stop immediately after compile; this is not live proof.

- [ ] **Step 9: Prove tests green and commit**

Run:

```bash
cargo test -p carrick-cli --test trace_profile -- --nocapture
cargo test -p carrick-cli trace_profile -- --nocapture
just fmt
git diff --check
```

Commit:

```bash
git add scripts/dtrace/native-wall.d crates/carrick-cli/tests/trace_profile.rs
git commit -m "diagnostics(native): join syscall work to kernel and wall time" -m "Kernel samples alone cannot distinguish guest-caused work from Carrick overhead, and thread sleep duration is not serial wall time. Join full guest services to Darwin host calls and sampled kernel contexts, correct sleeping-to-runnable wakeups, and frame non-overlapping tree-quiescent intervals.

Verified with DTrace compilation, provider/state source contracts, parser fixtures, and exact authority-aggregate checks.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 7: Build the Exact Joined Analyzer

**Files:**

- Add: `scripts/perf/native_syscall_kernel_attribution.py`
- Add: `scripts/perf/test_native_syscall_kernel_attribution.py`
- Modify: `scripts/perf/README.md`

**Interfaces:**

- Consume exactly two complete `carrick.dsr-profile.v1` native-wall summaries.
- Produce one deterministic
  `carrick.native-syscall-kernel-attribution.v1` document.
- Use the embedded sampled overlay to resolve raw stacks; do not consume the
  historical object-bound symbol rows.

- [ ] **Step 1: Add red hand-derived analyzer fixtures**

Add exact fixtures for:

- stable guest-emulation CPU context selected;
- stable Carrick-only CPU context selected;
- stable quiescent blocker selected;
- high call count without CPU or wall share rejected;
- high summed host duration without quiescent wall share rejected;
- exact 10%, 5%, and five-point boundaries;
- just-below/just-over each boundary;
- unchanged and changed dominant rank;
- grouped family preserving ungrouped rows and denominator;
- unresolved caller `(-1, 1015)` accepted;
- unresolved leaf and other status rejected;
- PC/context/stack/overlay mismatch;
- operation/branch/host/amplification mismatch;
- quiescence overlap or excess elapsed time;
- integer overflow;
- no qualifying context producing `DIFFUSE`;
- deterministic output under reversed input row order.

Run:

```bash
python3 -m unittest scripts/perf/test_native_syscall_kernel_attribution.py -v
```

Expected: import fails because the analyzer module does not exist.

- [ ] **Step 2: Load and reconcile each profile without threshold math**

Represent a context as:

```python
@dataclass(frozen=True, order=True)
class ContextKey:
    cause_class: str
    guest_nr: int | None
    guest_name: str | None
    host_syscall: str | None
    kernel_family: tuple[str, ...] | None
    blocking_family: tuple[str, ...] | None
```

Use bounded integer helpers for every addition. Validate completion,
provenance, drops, exact syscall populations, four-way kernel population,
overlay partition, leaf resolution, wall-state coverage, CPU classification,
voluntary-stack coverage, and non-overlapping quiescence before ranking.
Require at least 99% of wall samples in declared wall-state buckets, at least
85% of on-CPU samples in the existing category classifier, and at least 80% of
voluntary off-CPU resource time in the reported blocking stacks.

- [ ] **Step 3: Rank with exact rational rules**

Use `fractions.Fraction` for every share, threshold, ceiling, and sort key.
A context qualifies only when:

- mean relevant share is at least 10%;
- each run share is at least 5%;
- absolute drift is at most five percentage points;
- rank among contexts above 10% is unchanged.

CPU candidates use original kernel samples as their relevant denominator and
publish:

```text
zero_cost_oncpu_ceiling
    = context_kernel_samples / all_kernel_samples
    * all_kernel_samples / all_oncpu_samples
```

Blocking candidates use total non-overlapping quiescent nanoseconds over
elapsed wall nanoseconds. Amplification candidates additionally publish the
per-operation count, minimum, median, p90, p99, maximum, and total, and require
Docker evidence in Task 10 before H006 can be named.

- [ ] **Step 4: Emit deterministic selected, diffuse, or rejected output**

Include all provenance/hashes, exact populations, original denominators,
four-way contexts, ranked raw and grouped contexts, host resource time,
quiescent wall, symbol reconciliation, every threshold result, and
representative raw stacks.

`selected` means a CPU or blocking context qualifies from the Carrick pair.
An amplification-only candidate remains `oracle-required` until Task 10.
`DIFFUSE` means no candidate qualifies. Malformed evidence raises
`EvidenceError` and publishes no accepted report.

- [ ] **Step 5: Prove green and commit**

Run:

```bash
python3 -m unittest scripts/perf/test_native_syscall_kernel_attribution.py -v
python3 -m ruff check scripts/perf/native_syscall_kernel_attribution.py scripts/perf/test_native_syscall_kernel_attribution.py
git diff --check
```

If the repository environment has no `ruff` module, record that fact and run:

```bash
python3 -m py_compile scripts/perf/native_syscall_kernel_attribution.py scripts/perf/test_native_syscall_kernel_attribution.py
```

Commit:

```bash
git add scripts/perf/native_syscall_kernel_attribution.py scripts/perf/test_native_syscall_kernel_attribution.py scripts/perf/README.md
git commit -m "diagnostics(perf): rank joined syscall kernel contexts" -m "Counts and summed host durations cannot establish completion-path wall cost. Reconcile full service, host, kernel, symbol, and quiescent-wall populations, then apply exact two-run share and rank gates to CPU and blocking candidates while preserving original denominators.

Verified with hand-derived boundary, rank, amplification, symbol, population, overflow, diffuse, and deterministic-order fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 8: Upgrade the Receipt-Bound Pair Runner

**Files:**

- Modify: `scripts/perf/native_kernel_capture.py`
- Modify: `scripts/perf/test_native_kernel_capture.py`

**Interfaces:**

- Retain the existing signed launch, ancestry, contamination monitor,
  exclusive-path, atomic-publication, timeout, and exact-run cleanup machinery.
- Switch new outputs to `carrick.native-syscall-kernel-capture.v1`.
- Delegate accepted analysis only to
  `native_syscall_kernel_attribution.analyze_profiles`.

- [ ] **Step 1: Add red new-schema and overlay-binding tests**

Extend the current fake-boundary suite for:

- new receipt schema;
- exact analyzer module hash;
- embedded overlay canonical JSON SHA-256;
- sampled requested/resolved/unresolved counts and hashes;
- exact service/dispatcher/host/context/quiescence reconciliation totals;
- rejection when any receipt total differs from the summary;
- A/B boot-session mismatch;
- A/B overlay identity mismatch;
- analysis source hash differing from either receipt;
- rejection of an old v2 receipt as a new analyzer input;
- AC-power source, `pmset -g therm`, `vm.loadavg`, and clean foreign-workload
  preflight bound into each receipt;
- rejection when the power source changes or either run is not on AC power;
- clean process census before permitting a Docker phase;
- all existing collision, ancestry, timeout, cleanup, and atomic-publication
  guarantees unchanged.

Run:

```bash
python3 -m unittest scripts/perf/test_native_kernel_capture.py -v
```

Expected: new-schema assertions fail against the v2 kernel-only runner.

- [ ] **Step 2: Switch the receipt and analyzer contracts**

Set:

```python
RECEIPT_SCHEMA = "carrick.native-syscall-kernel-capture.v1"
```

Import `native_syscall_kernel_attribution`. Extend each receipt's
`reconciliation` section with exact service, branch, dispatcher, host,
four-context kernel, overlay, wall, and quiescence totals. Bind the canonical
embedded overlay JSON hash independently of the summary file hash.

- [ ] **Step 3: Preserve fail-closed pair execution**

Run A then exact cleanup/census, then B then exact cleanup/census. Reject
changed commit, dirty digest, binary, signature, DOF, image, command,
environment, host identity, boot session, launcher ancestry shape, timeout
policy, producer hash, acceptance hash, or analyzer hash.

Before each run, record canonical output and hashes for `pmset -g batt`,
`pmset -g therm`, `sysctl -n vm.loadavg`, and the existing process census.
Require AC power and unchanged power source. Load and thermal readings are
reported rather than used to renormalize samples.

Only after two accepted immutable receipts may `analyze_receipts` publish
`analysis.json` atomically.

- [ ] **Step 4: Prove green and commit**

Run:

```bash
python3 -m unittest scripts/perf/test_native_kernel_capture.py -v
python3 -m unittest scripts/perf/test_native_syscall_kernel_attribution.py -v
python3 -m py_compile scripts/perf/native_kernel_capture.py scripts/perf/test_native_kernel_capture.py
git diff --check
```

Commit:

```bash
git add scripts/perf/native_kernel_capture.py scripts/perf/test_native_kernel_capture.py
git commit -m "diagnostics(perf): bind joined profiles to paired receipts" -m "The existing pair runner binds launch and cleanup evidence but understands only kernel stack reconciliation. Version the receipt around the joined service, host, kernel, overlay, and quiescence populations and delegate publication to the exact joined analyzer.

Verified with schema, overlay hash, reconciliation drift, boot identity, source binding, A/B determinant, cleanup, collision, ancestry, and atomic-publication tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 9: Pass the Signed Live Smoke and Scope Gates

**Files:**

- Modify only if a live invariant exposes a defect:
  `scripts/dtrace/native-wall.d`,
  `crates/carrick-cli/src/trace_profile.rs`,
  `crates/carrick-runtime/src/dtrace_symbols.rs`,
  `crates/carrick-runtime/src/native_darwin.rs`,
  and their focused tests.
- Record: `docs/perf-results/native-wall-time-campaign.md`

- [ ] **Step 1: Build, sign, and verify the DOF**

Run:

```bash
just build
codesign -d --entitlements - target/release/carrick
otool -l target/release/carrick | grep -A2 __dof_carrick
```

Expected: signed release binary and a nonempty `__DATA,__dof_carrick` section.

- [ ] **Step 2: Run one unique native container smoke**

Run:

```bash
smoke_stamp="$(date +%Y%m%d%H%M%S)"
smoke_run_id="joined-smoke-${smoke_stamp}"
CARRICK_RUN_ID="${smoke_run_id}" target/release/carrick trace \
  --profile native-wall \
  --trace-out "target/perf/${smoke_run_id}.raw" \
  --summary-jsonl "target/perf/${smoke_run_id}.jsonl" -- \
  run --exec-backend native \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'echo TRACE_OK'
scripts/sudo/kill.sh "${smoke_run_id}"
```

Expected: exactly one `TRACE_OK`, natural exit, zero drops, zero live
processes/threads/windows/operations, all exact equations green, nonzero wall
and CPU samples, and every weighted kernel leaf resolved.

- [ ] **Step 3: Run branch and terminal live smokes**

Use the same signed trace command with fresh IDs for:

```bash
/bin/sh -c 'sh -c "exit 0" & wait; echo FORK_OK'
```

and:

```bash
/bin/sh -c 'exec /bin/echo EXEC_OK'
```

Expected: process branch, child-side host return, terminal exit, and
exec-success populations reconcile. Clean each exact run ID separately.

- [ ] **Step 4: Prove unrelated-run exclusion**

Start one unrelated uniquely stamped Carrick native `/bin/sleep 20`, run a
fresh joined smoke, and verify the unrelated PID appears in none of the raw
profile's CPU, service, host, kernel, image, or quiescence rows. Clean both run
IDs independently.

- [ ] **Step 5: Fix only demonstrated instrumentation defects**

For any failure:

1. preserve the rejected raw/summary paths;
2. record the exact failed invariant in the ledger;
3. add a red literal parser or script-contract fixture;
4. make the smallest instrumentation-only correction;
5. rerun focused tests and all three smokes;
6. commit a narrow `fix(native):` or `fix(perf):` change with the live receipt
   named in its body.

Do not weaken an acceptance threshold and do not change guest behavior.

- [ ] **Step 6: Record the accepted smoke receipt**

Add the exact run IDs, commit, binary hash, image ID, raw/summary hashes,
population totals, symbol overlay counts, and zero-cleanup census to
`docs/perf-results/native-wall-time-campaign.md`.

Commit:

```bash
git add docs/perf-results/native-wall-time-campaign.md
git commit -m "docs(perf): record joined native trace smoke" -m "The joined profiler now completes short native container, branch, exec, and adversarial scope lanes with exact service, host, kernel, symbol, wall, and cleanup reconciliation.

Record immutable run and artifact hashes before allowing the expensive cold-GOCACHE pair.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 10: Capture the Pair and Separate Docker Syscall Shape

**Files:**

- Add: `docker/go-conformance-bpftrace/Dockerfile`
- Add: `scripts/perf/native_docker_syscall_shape.py`
- Add: `scripts/perf/test_native_docker_syscall_shape.py`
- Produce under a new exclusive directory:
  `target/perf/native-syscall-kernel-*`

**Interfaces:**

- The derived Docker image changes only the debugging tool availability; it
  inherits the exact native-arm64 Go image and runs the exact
  `native_go_build.guest_script()` workload.
- bpftrace tracks its `-c` child and descendants through
  `sched_process_fork`; unrelated host/container PIDs are excluded.
- Docker output is a separate immutable artifact and is never merged into a
  Carrick receipt.

- [ ] **Step 1: Add red Docker evidence parser tests**

Test:

- native-arm64 platform and exact base image identity required;
- bpftrace version and `BEGIN` validation required;
- exactly one `BUILD_OK`;
- child/descendant process membership;
- syscall counts by syscall and process;
- create/exit populations;
- unknown/truncated bpftrace output;
- integer overflow;
- canonical source, image, command, and output hashes;
- refusal while any Carrick/native-wall workload is active.

Run:

```bash
python3 -m unittest scripts/perf/test_native_docker_syscall_shape.py -v
```

Expected: import fails because the module does not exist.

- [ ] **Step 2: Add the durable derived oracle image**

Use:

```dockerfile
ARG BASE_IMAGE=localhost:5005/carrick-go-conformance:1.24
FROM ${BASE_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends bpftrace \
    && rm -rf /var/lib/apt/lists/*
```

The evidence records both the exact base image ID and derived image ID.

- [ ] **Step 3: Implement the separate bpftrace controller**

The controller must:

1. reject active Carrick/native-wall work;
2. validate Docker architecture `arm64`;
3. mount tracefs inside the privileged oracle;
4. run `bpftrace -V`;
5. run `bpftrace -e 'BEGIN { printf("ok\n"); exit(); }'`;
6. use bpftrace `-c` for the exact cold-GOCACHE script;
7. seed ownership with `cpid`, propagate through
   `sched:sched_process_fork`, and count only owned
   `syscalls:sys_enter_*` events;
8. record process fork/exit and exact syscall distributions;
9. require one `BUILD_OK` and natural completion;
10. publish one exclusive canonical JSON artifact.

Its Docker invocation is exactly one native-arm64 privileged oracle:

```text
docker run --rm --platform linux/arm64 --privileged --pid=host
```

The controller appends the derived trace image and a `sh -lc` command that
mounts tracefs and `exec`s bpftrace. It does not launch a tracer sidecar or a
second workload container.

Use this ownership/counting program through `bpftrace -f json -e`:

```bpftrace
BEGIN
{
    @owned[cpid] = 1;
}

tracepoint:sched:sched_process_fork
/@owned[args->parent_pid] == 1/
{
    @owned[args->child_pid] = 1;
    @forks = count();
}

tracepoint:syscalls:sys_enter_*
/@owned[pid] == 1/
{
    @syscalls[probe] = count();
    @process_syscalls[pid, probe] = count();
}

tracepoint:sched:sched_process_exit
/@owned[pid] == 1/
{
    @exits = count();
    delete(@owned[pid]);
}

END
{
    print(@syscalls);
    print(@process_syscalls);
    print(@forks);
    print(@exits);
    clear(@syscalls);
    clear(@process_syscalls);
    clear(@forks);
    clear(@exits);
    clear(@owned);
}
```

The controller parses only bpftrace JSON map records and the exact child
markers; it rejects an unknown nonempty output line.

- [ ] **Step 4: Prove the controller green**

Run:

```bash
python3 -m unittest scripts/perf/test_native_docker_syscall_shape.py -v
python3 -m py_compile scripts/perf/native_docker_syscall_shape.py scripts/perf/test_native_docker_syscall_shape.py
git diff --check
```

- [ ] **Step 5: Commit the Docker evidence tooling**

Commit:

```bash
git add docker/go-conformance-bpftrace/Dockerfile scripts/perf/native_docker_syscall_shape.py scripts/perf/test_native_docker_syscall_shape.py
git commit -m "diagnostics(perf): capture Docker Go syscall shape" -m "Amplification claims require the Linux workload's syscall mix, but guest strace is perturbing and out of bounds. Add a native-arm64 derived oracle with in-container bpftrace, exact descendant ownership, and immutable command/image/output provenance.

Verified with architecture, tool validation, process ownership, syscall population, completion, overflow, and Carrick-overlap tests.

Co-Authored-By: Codex <codex@openai.com>"
```

- [ ] **Step 6: Capture two serial Carrick profiles**

Preflight:

```bash
git status --short
just build
profile_sha="$(git rev-parse --short=8 HEAD)"
profile_dir="$PWD/target/perf/native-syscall-kernel-${profile_sha}-v1"
profile_run_id="nativesys-${profile_sha}"
```

Require clean status. Then run:

```bash
python3 scripts/perf/native_kernel_capture.py capture \
  --repo "$PWD" \
  --binary "$PWD/target/release/carrick" \
  --artifact-dir "${profile_dir}" \
  --run-id "${profile_run_id}" \
  --image localhost:5005/carrick-go-conformance:1.24 \
  --timeout 240
```

Expected: A and B each contain exactly one `BUILD_OK`, natural zero-drop
completion, exact cleanup, an accepted v1 receipt, and one atomic
`analysis.json`.

- [ ] **Step 7: Regenerate analysis from immutable receipts**

Run:

```bash
python3 scripts/perf/native_kernel_capture.py analyze \
  --receipt "${profile_dir}/a.receipt.json" \
  --receipt "${profile_dir}/b.receipt.json" \
  --output "${profile_dir}/analysis-regenerated.json"
cmp "${profile_dir}/analysis.json" "${profile_dir}/analysis-regenerated.json"
```

Expected: byte-identical deterministic analysis.

- [ ] **Step 8: Run Docker only after Carrick cleanup**

Build and capture:

```bash
docker build --platform linux/arm64 \
  --build-arg BASE_IMAGE=localhost:5005/carrick-go-conformance:1.24 \
  -t carrick-go-oracle-bpftrace:1 \
  docker/go-conformance-bpftrace
python3 scripts/perf/native_docker_syscall_shape.py \
  --base-image localhost:5005/carrick-go-conformance:1.24 \
  --trace-image carrick-go-oracle-bpftrace:1 \
  --output "${profile_dir}/docker-syscall-shape.json"
```

Expected: native arm64, tool validation green, one `BUILD_OK`, natural exit,
and exact owned-process syscall/create/exit populations.

---

## Task 11: Publish H006 or DIFFUSE and Close the Measurement Wave

**Files:**

- Add: `scripts/perf/evidence/native-go-build-syscall-kernel-attribution-v1.json`
- Modify: `docs/perf-results/native-wall-time-campaign.md`
- Modify: `handoff.md`

- [ ] **Step 1: Create the durable evidence package**

Copy only the deterministic analysis document into the versioned evidence
path, then add a provenance section binding:

- A/B receipt paths, sizes, and hashes;
- A/B raw and summary paths, sizes, and hashes;
- Docker syscall-shape path, size, and hash;
- exact commit, dirty digest, binary hash, base and derived image IDs;
- sampled-symbol overlay hashes and kernel/boot identity;
- analyzer, capture-runner, DTrace script, and Docker-controller hashes.

Do not copy large raw traces into git.

- [ ] **Step 2: Apply the decision rule exactly**

If the Carrick report selects a stable CPU or blocking candidate, and any
amplification claim is supported by the Docker mix:

1. name it `H006`;
2. record cause class, guest syscall, Darwin syscall, resolved kernel/blocking
   family, two-run shares, drift, rank, original denominator, zero-cost ceiling,
   expected bounded-spike effect, and falsification condition;
3. mark its status `SELECTED FOR BOUNDED SPIKE`;
4. write a separate mechanism-specific design before source changes.

If none qualifies, record:

```text
H006: not created
joined result: DIFFUSE
next action: improve measurement resolution or choose a predeclared grouped
context; no source optimization is authorized from this capture
```

If evidence rejects, record `MEASUREMENT_REPAIR_REQUIRED`, preserve the failed
invariant and receipts, and return to the exact task that owns the invariant.

- [ ] **Step 3: Refresh controller state**

Update `handoff.md` with:

- current branch and HEAD;
- completed task/commit table;
- accepted/rejected run IDs and artifact hashes;
- exact report result;
- H006 identity or explicit absence;
- the next command;
- baseline and milestone unchanged;
- statement that no wall-clock improvement has yet been claimed.

- [ ] **Step 4: Run the full closeout gate**

Run:

```bash
just fmt-check
just clippy
just lint-domains
just test
just test-integration
just ci
git diff --check
git status --short
```

Expected: every gate green and only the three measurement-closeout files
modified.

- [ ] **Step 5: Commit the measurement decision**

For selected H006:

```bash
git add scripts/perf/evidence/native-go-build-syscall-kernel-attribution-v1.json docs/perf-results/native-wall-time-campaign.md handoff.md
git commit -m "diagnostics(perf): select H006 from joined native evidence" -m "Two receipt-bound native Go-build captures and a separate Docker syscall-shape oracle identify one stable CPU or non-overlapping wall context that satisfies the approved share, drift, rank, symbol, and population gates.

Record the original denominators, calculated ceiling, mechanism, bounded falsification spike, and immutable receipt hashes. No runtime optimization is included.

Verified with deterministic analysis regeneration, signed live captures, Docker bpftrace provenance, exact cleanup, and the full local CI gate.

Co-Authored-By: Codex <codex@openai.com>"
```

For `DIFFUSE`:

```bash
git add scripts/perf/evidence/native-go-build-syscall-kernel-attribution-v1.json docs/perf-results/native-wall-time-campaign.md handoff.md
git commit -m "diagnostics(perf): record diffuse native syscall attribution" -m "Two receipt-bound native Go-build captures and a separate Docker syscall-shape oracle reconcile, but no joined CPU or non-overlapping wall context satisfies the approved share, drift, and rank gates.

Preserve the original denominators and immutable receipt hashes without naming H006 or authorizing a source optimization.

Verified with deterministic analysis regeneration, signed live captures, Docker bpftrace provenance, exact cleanup, and the full local CI gate.

Co-Authored-By: Codex <codex@openai.com>"
```

## Completion Criteria

This plan is complete only when:

- all implementation and fixture gates are green;
- signed short, branch, exec, and adversarial scope smokes reconcile;
- two exact cold-GOCACHE Carrick captures are accepted and deterministic;
- Docker native-arm64 syscall shape is captured separately with in-container
  bpftrace;
- the durable report says either evidence-qualified H006 or `DIFFUSE`;
- `handoff.md` and the campaign ledger point to immutable hashes and the exact
  next action;
- `just ci` is green;
- no runtime optimization or wall-clock win is claimed from traced timings.

The next implementation plan is candidate-specific. If H006 exists, it defines
one bounded causal counter, one quick spike, a stop condition, correctness
proof, and the existing untraced five-sample retention gate. If the result is
`DIFFUSE`, the next plan improves resolution without editing runtime behavior.
