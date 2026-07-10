# Darwin-Native Thread Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute Linux `CLONE_THREAD` groups as host pthreads in Carrick's
Darwin-native backend while preserving one Linux process equals one macOS
process.

**Architecture:** Each guest thread gets thread-local native trap/ucontext state
and a host pthread, while the process shares one dispatcher, thread registry,
futex tables, and synchronized native-memory metadata. Memory metadata is locked
only while servicing a guest-memory operation; host waits never retain that
lock. Thread-directed signals use a targeted host trap to return a running guest
thread to its Rust loop.

**Tech Stack:** Rust 1.96, AArch64 Darwin `ucontext_t`, pthreads, Mach thread
ports, `parking_lot`, Carrick `ThreadRegistry`/`FutexTable`, signed native probe
campaigns, Docker arm64 oracle.

## Global Constraints

- Preserve one Linux process equals one macOS process; threads are pthreads, not
  helper processes.
- Keep native execution same-ISA and trusted-code-only.
- Do not route unsupported native behavior to HVF.
- Do not hold native-memory metadata locks across fd, signal, sleep, or futex
  waits.
- Reuse the shared/HVF `CloneThread` contract: Linux TID writes, inherited
  signal mask, child return value zero, stack/TLS setup, clear-child-tid, futex
  wake, and thread registry cleanup.
- Build and run through `just build`; the executed Carrick binary must remain
  codesigned.
- Carrick and Docker phases must remain disjoint.
- Commit each task independently with a Conventional Commit body and
  `Co-Authored-By: Codex <codex@openai.com>`.

---

### Task 1: Make the native trap bridge thread-local

**Files:**
- Modify: `crates/carrick-runtime/csrc/native_darwin.c`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Produces: `carrick_native_seed_ucontext(const
  carrick_native_ucontext_snapshot *) -> int`.
- Produces: independent trap, return, ucontext, signal-stack, host-TPIDR, and
  resume-pad state for every host thread.

- [ ] **Step 1: Add a failing thread-isolation unit test**

Add `native_bridge_context_is_thread_local` under `native_darwin::tests`. Seed
`x0=0x1111` on the test thread, seed and snapshot `x0=0x2222` on a spawned host
thread, then snapshot the test thread again and require `0x1111`.

```rust
assert_eq!(main_after.x[0], 0x1111);
assert_eq!(child_snapshot.x[0], 0x2222);
```

- [ ] **Step 2: Run the test and verify red**

Run:

```sh
cargo test -p carrick-runtime native_bridge_context_is_thread_local --lib -- --nocapture
```

Expected: link or assertion failure because the bridge has one process-global
ucontext and no seed API.

- [ ] **Step 3: Isolate bridge state**

In `native_darwin.c`, make these values `_Thread_local`: both `sigjmp_buf`
objects, `env_ready`, saved/pending ucontext, alternate signal stack,
`host_tpidr_el0`, last-signal fields, resume pages/cache/count, and per-thread
resume page size. Keep the resolved `update_tpidr` function process-global but
initialize it once with `pthread_once`.

Implement `carrick_native_seed_ucontext` by zeroing the thread-local
`ucontext_t`, installing its internal mcontext pointer, and copying every GPR,
SP, PC, PSTATE, vector register, FPSR, and FPCR from the wire snapshot.

- [ ] **Step 4: Verify green and bridge regressions**

Run:

```sh
cargo test -p carrick-runtime native_bridge_context_is_thread_local --lib -- --nocapture
cargo test -p carrick-runtime native_ --lib
```

Expected: the isolation test passes and the existing native bridge unit tests
remain green.

- [ ] **Step 5: Commit the bridge boundary**

```sh
git add crates/carrick-runtime/csrc/native_darwin.c crates/carrick-runtime/src/native_darwin.rs
git commit -m "fix(native): isolate trap state per host thread" ...
```

### Task 2: Share native-memory metadata without serializing waits

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Produces: `type SharedNativeMemory =
  Arc<parking_lot::Mutex<NativeMappedMemory>>`.
- Changes: `dispatch_native_syscall` accepts `&SharedNativeMemory` and locks only
  around `dispatch_threaded` or an explicit memory mutation.

- [ ] **Step 1: Capture the deadlock-sensitive red probes**

Run signed `native16k` `futexpingpong` and `epolloutxthread` through the bound
probe transport and retain their current `CloneThread` failures. These probes
require one thread to block while another acquires guest memory and wakes it.

- [ ] **Step 2: Introduce shared memory ownership**

Wrap `NativeMappedMemory` in `Arc<parking_lot::Mutex<_>>` after image mapping.
Change trap decode, guarded-fault emulation, `dc zva`, syscall dispatch, signal
frame operations, fork, exec replacement, host aliases, and protection changes
to take short scoped locks.

- [ ] **Step 3: Keep waits outside the memory lock**

In `dispatch_native_syscall`, obtain the `DispatchOutcome` in one scoped lock,
drop the guard, then execute `wait_native_fds`, `wait_native_signals`, futex
waits, process waits, and sleeps. Reacquire only for timeout buffer clearing or
remaining-time writes.

- [ ] **Step 4: Verify single-thread regressions**

Run:

```sh
cargo test -p carrick-runtime native_ --lib
cargo test -p carrick-cli --test conformance native_conformance_ -- --test-threads=1
```

Expected: all existing native reducers pass unchanged.

- [ ] **Step 5: Commit the shared-memory boundary**

```sh
git add crates/carrick-runtime/src/native_darwin.rs
git commit -m "refactor(native): share mapped memory across guest threads" ...
```

### Task 3: Materialize clone threads and clean up exits

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: `conformance-probes/src/bin/threadspawn.rs`
- Test: `conformance-probes/src/bin/threadrecycle.rs`

**Interfaces:**
- Produces: `NativeThreadRuntime::spawn_clone_thread(...) -> Result<ThreadId,
  RuntimeError>`.
- Produces: `NativeThreadRuntime::finish_thread(...)` that performs
  clear-child-tid, private futex wake, registry exit, host-signal cleanup, and
  dispatcher signal-state cleanup exactly once.
- Produces: a native loop start mode for initial ELF entry versus a seeded
  detached sibling context.

- [ ] **Step 1: Verify the exact red reducer**

Run `threadspawn` under `native16k` with the bound static PIE artifact.
Expected: exit 125 with `does not yet support dispatcher outcome CloneThread`.

- [ ] **Step 2: Construct the Linux child context**

On `DispatchOutcome::CloneThread`, allocate a registry TID, inherit the parent
signal mask, write `parent_tid_addr` and `child_tid_addr`, copy the trapped
snapshot, set child `x0=0`, set PC to the post-syscall resume PC, apply a nonzero
child stack, and carry `tls.unwrap_or(parent_guest_tpidr)`.

- [ ] **Step 3: Spawn and enter the sibling loop**

Start a named Rust host thread, record its Mach thread port, install its native
trap/altstack state, seed the copied context, and enter through
`carrick_native_resume_detached_context`. Run the same syscall/fault loop with a
per-thread `NativeThreadRuntime` sharing registry, futex, platform futex,
dispatcher, reporter, and memory.

- [ ] **Step 4: Implement thread exit semantics**

Handle `DispatchOutcome::ThreadExit` by zeroing a nonzero clear-child-tid word,
waking one private futex waiter, removing the TID, clearing run-state and host
signal state, and returning from only that host thread. Handle process-wide
`Exit`/`SignalDeath` from a sibling with `_exit`, because the native run already
lives in a dedicated forked macOS child.

- [ ] **Step 5: Verify green reducers**

Run `threadspawn` and `threadrecycle` on `native16k` and `linux4k`, then run each
three times. Expected: line-exact MATCH with Docker and no residual guest
processes.

- [ ] **Step 6: Commit basic native pthread lifecycle**

```sh
git add crates/carrick-runtime/src/native_darwin.rs
git commit -m "feat(native): execute Linux clone threads as pthreads" ...
```

### Task 4: Deliver thread-directed signals and wake blocked threads

**Files:**
- Modify: `crates/carrick-runtime/csrc/native_darwin.c`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: `conformance-probes/src/bin/xthreadsig.rs`
- Test: `conformance-probes/src/bin/sigwaitthread.rs`

**Interfaces:**
- Produces: a process-local `ThreadId -> pthread_t` native kick registry.
- Produces: a targeted host trap that captures an arbitrary guest PC without
  decoding it as a patched `brk` site.

- [ ] **Step 1: Verify red signal reducers**

Run `xthreadsig` and `sigwaitthread` on both profiles. Expected: thread creation
may succeed after Task 3, but delivery or wake still diverges.

- [ ] **Step 2: Add targeted native kicks**

Register each host `pthread_t`. For `SignalThread`, validate registry liveness,
publish the pending Linux signal, and `pthread_kill` only the target with the
native kick signal. Teach the C handler and Rust loop to classify that signal as
an interrupt trap whose resume PC is the captured PC.

- [ ] **Step 3: Deliver and resume**

At interrupt return, call `deliver_pending_signal` with the current guest TID,
commit the resulting sigframe/registers, and resume. Notify private/platform
futex waiters so blocked target threads observe pending signals without waiting
for the 50 ms backstop.

- [ ] **Step 4: Verify green signal/thread clusters**

Run `xthreadsig`, `sigwaitthread`, `sigsuspendxthread`, `mtsigrelease`, and
`preemptsigstorm` three times per profile. Expected: MATCH without global host
signals or cross-thread context corruption.

- [ ] **Step 5: Commit signal routing**

```sh
git add crates/carrick-runtime/csrc/native_darwin.c crates/carrick-runtime/src/native_darwin.rs
git commit -m "fix(native): route Linux signals to guest pthreads" ...
```

### Task 5: Quiesce thread groups for fork and exec

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: `conformance-probes/src/bin/execthreads.rs`
- Test: `conformance-probes/src/bin/forkfpreclaim.rs`

**Interfaces:**
- Produces: native thread-group stop/kick/drain operations used before mapping
  replacement or host `fork`.

- [ ] **Step 1: Verify red lifecycle reducers**

Run `execthreads` and `forkfpreclaim` on both profiles. Expected: the basic
thread path still diverges at sibling termination or fork quiescence.

- [ ] **Step 2: Implement exec replacement**

Mark every sibling except the execing TID for termination, target-kick each
running guest, wake all native waits, and wait with a five-second bound until
the registry contains only the execing TID. Only then replace mappings, reset
signals/CLOEXEC/TLS, and enter the new image.

- [ ] **Step 3: Implement fork quiescence**

Stop every sibling at its native loop, wait until no sibling is executing guest
instructions or holding native-memory metadata, perform `fork`, then resume the
parent group. In the child, rebuild a one-entry registry for the calling TID,
reset pthread kick state, and reinstall thread-local bridge state before guest
resume.

- [ ] **Step 4: Verify lifecycle clusters**

Run `execthreads`, `exitgroupthreads`, `forkfpreclaim`, `forkaltstack`, and
`threadstatuscount` three times per profile. Expected: MATCH and no fork-child
deadlock under `carrick debug lldb-run` deadlines.

- [ ] **Step 5: Commit fork/exec lifecycle**

```sh
git add crates/carrick-runtime/src/native_darwin.rs
git commit -m "fix(native): quiesce pthread groups for fork and exec" ...
```

### Task 6: Rebaseline full native conformance

**Files:**
- Modify: `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`

- [ ] **Step 1: Run focused gates**

Run native bridge units, native conformance reducers, formatter, targeted
clippy, and a fresh signed build.

- [ ] **Step 2: Run both complete musl lanes**

Run the complete native probe campaign under `native16k`, then `linux4k`, with
the bound static PIE transport. Count exact PASS/FAIL sets and verify no guests
or helper processes remain.

- [ ] **Step 3: Update the evidence ledger**

Record both denominators, the shared and profile-only failure sets, glibc loader
status, exact commands, and the next highest-leverage failure class. Do not
claim 100% unless all 373 gating probes MATCH in both profiles.

- [ ] **Step 4: Commit the verified baseline**

```sh
git add docs/2026-07-09-no-vmm-native-feasibility-evidence.md
git commit -m "docs(native): record pthread conformance baseline" ...
```
