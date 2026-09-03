# Typed Syscall Interception Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a public, typed, per-container syscall-interception seam that can
rewrite six scalar arguments or replace a syscall result without exposing guest
memory or weakening Carrick policy and seccomp enforcement.

**Architecture:** A new immutable interceptor chain runs once at the shared
dispatch envelope before launch policy, guest seccomp, and observers. It
produces an effective `SyscallRequest` plus an optional proposed result. Both
threaded and non-threaded dispatch consume that same envelope, publish one
entry, and publish exactly one return only if the syscall actually returns to
the guest. Interceptor panics are caught at the callback boundary and lowered
through `DispatchError`/`RuntimeError` into a typed `EmbedError` scoped to the
calling container.

**Tech Stack:** Rust, `thiserror`, `proptest`, Carrick's normalized syscall
dispatcher, `carrick-embed`, signed HVF guest tests.

**Spec:**
[`docs/superpowers/specs/2026-08-30-carrier-concurrency-and-syscall-interception-design.md`](../specs/2026-08-30-carrier-concurrency-and-syscall-interception-design.md)

## Global Constraints

- This plan lands before
  [`2026-08-30-explicit-carrier-concurrency.md`](2026-08-30-explicit-carrier-concurrency.md).
- Preserve the syscall number, guest ABI, native syscall number, and captured
  guest stack pointer. Only `SyscallRequest::args` may change.
- Treat all pointer-shaped values as opaque `u64`; the public interception API
  must not accept `GuestMemory`, `CurrentMmMemory`, `SyscallCtx`, raw host
  pointers, or guest read/write closures.
- Registration order is deterministic. Each interceptor sees the current
  effective arguments. The first `Return` or `Errno` action stops the chain.
- Launch policy and guest seccomp evaluate the effective request and can veto a
  proposed replacement. User observers then see only the effective request.
- Installing any custom interceptor disables/reroutes identity and clock fast
  paths for that container. There is no opt-out in this version.
- With no interceptor installed, dispatch adds only one predictable `Option`
  branch and performs no allocation, lock, virtual call, or formatting.
- Do not re-bless conformance baselines or oracle caches. A guest test that
  skips for missing entitlement is a failure.
- Use `just test-embed` for tests that create an HVF VM; never execute a bare
  Cargo test binary that calls `hv_vm_create`.
- Keep commits limited to the files named by each task and preserve unrelated
  worktree changes.

---

### Task 1: Add the Typed Scalar-Argument and Interceptor Contract

**Files:**

- Modify: `crates/carrick-observability/src/compat.rs:62`
- Create: `crates/carrick-runtime/src/observe/intercept.rs`
- Modify: `crates/carrick-runtime/src/observe/mod.rs:1-20`
- Modify: `crates/carrick-runtime/src/observe/tests.rs`
- Modify: `crates/carrick-embed/src/lib.rs:58-72`

**Interfaces:**

- Consumes: existing `carrick_observability::compat::SyscallArgs`,
  `SyscallRequest`, `ProcessInfo`, `CanonicalNr`, and `LinuxErrno`.
- Produces: `SyscallArgs` convenience methods, `InterceptedSyscall`,
  `InterceptAction`, and `SyscallInterceptor`; re-exported from
  `carrick_embed` with their `CanonicalNr` and `LinuxErrno` value types.

- [ ] **Step 1: Write red public-contract tests**

Add tests in `observe/tests.rs` that construct six words, replace indexes 0 and
5 immutably, reject index 6, and prove that `InterceptedSyscall` exposes the
same canonical/native numbers and original arguments while reporting rewritten
effective arguments. Add a compile-time trait assertion:

```rust
fn assert_interceptor_bounds<T: SyscallInterceptor + Send + Sync>() {}

#[test]
fn interceptor_contract_is_thread_safe() {
    assert_interceptor_bounds::<ContinueInterceptor>();
}
```

Run:

```bash
cargo test -p carrick-runtime observe::tests::syscall_args_are_immutable_six_words --lib
```

Expected: FAIL because the new methods and interception types do not exist.

- [ ] **Step 2: Extend the existing `SyscallArgs` value without duplicating it**

Keep the existing serialized tuple representation source-compatible and add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("syscall argument index {index} is outside 0..6")]
pub struct SyscallArgIndexError {
    pub index: usize,
}

impl SyscallArgs {
    pub const fn new(words: [u64; 6]) -> Self {
        Self(words)
    }

    pub const fn words(self) -> [u64; 6] {
        self.0
    }

    pub fn get(self, index: usize) -> Option<u64> {
        self.0.get(index).copied()
    }

    pub fn with_arg(
        mut self,
        index: usize,
        value: u64,
    ) -> Result<Self, SyscallArgIndexError> {
        let word = self
            .0
            .get_mut(index)
            .ok_or(SyscallArgIndexError { index })?;
        *word = value;
        Ok(self)
    }
}
```

Do not add a syscall-number field or a guest-memory handle.

- [ ] **Step 3: Define the public interception values and trait**

In `observe/intercept.rs`, implement this exact public surface:

```rust
use carrick_abi::{CanonicalNr, LinuxErrno};
use carrick_observability::compat::SyscallArgs;

use super::ProcessInfo;
use crate::dispatch::SyscallRequest;

#[derive(Debug, Clone, Copy)]
pub struct InterceptedSyscall<'a> {
    original: &'a SyscallRequest,
    effective_args: SyscallArgs,
}

impl<'a> InterceptedSyscall<'a> {
    pub(crate) const fn new(
        original: &'a SyscallRequest,
        effective_args: SyscallArgs,
    ) -> Self {
        Self {
            original,
            effective_args,
        }
    }

    pub const fn canonical_number(&self) -> CanonicalNr {
        self.original.number
    }

    pub fn name(&self) -> &'static str {
        carrick_abi::syscall::lookup_aarch64(self.original.number.raw())
            .map_or("unknown", |entry| entry.name)
    }

    pub const fn original_args(&self) -> SyscallArgs {
        self.original.args
    }

    pub const fn effective_args(&self) -> SyscallArgs {
        self.effective_args
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptAction {
    Continue,
    RewriteArgs(SyscallArgs),
    Return(i64),
    Errno(LinuxErrno),
}

pub trait SyscallInterceptor: Send + Sync {
    fn intercept(
        &self,
        process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction;
}
```

Also expose `native_number`, `guest_abi`, and `current_guest_sp` as read-only
accessors matching `SyscallInfo`; do not expose `SyscallRequest` itself.

- [ ] **Step 4: Re-export the contract**

Re-export `SyscallArgs` and `SyscallArgIndexError` from `observe/mod.rs`, export
the four interception types from the new module, and add those names to the
existing `carrick_embed` observer re-export list. Also re-export `ContainerId`
and `RunId` from `carrick_embed`, plus `CanonicalNr` and `LinuxErrno` from
`carrick_abi`, so callers can implement the public trait, inspect callback
identity, and match typed embedding errors without naming internal crates.

- [ ] **Step 5: Run the focused contract tests**

```bash
cargo test -p carrick-observability compat --lib
cargo test -p carrick-runtime observe::tests --lib
cargo check -p carrick-embed
```

Expected: PASS.

- [ ] **Step 6: Commit the public contract**

```bash
git add crates/carrick-observability/src/compat.rs \
  crates/carrick-runtime/src/observe/intercept.rs \
  crates/carrick-runtime/src/observe/mod.rs \
  crates/carrick-runtime/src/observe/tests.rs \
  crates/carrick-embed/src/lib.rs
git commit -m "embed: define typed syscall interception"
```

---

### Task 2: Implement the Ordered, Panic-Contained Interceptor Chain

**Files:**

- Modify: `crates/carrick-runtime/src/observe/intercept.rs`
- Modify: `crates/carrick-runtime/src/observe/tests.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:2195-2245`

**Interfaces:**

- Consumes: Task 1's public trait/action types and `ProcessInfo`.
- Produces: crate-private `InterceptorChain`, `Interception`, and typed
  `DispatchError::InterceptorPanicked { container_id }`.

- [ ] **Step 1: Write red deterministic-chain tests**

Add unit tests proving:

- two rewrites are observed cumulatively and the original words never change;
- `Return` stops later interceptors;
- `Errno` stops later interceptors;
- empty chains return the byte-identical request and no proposed result; and
- a panicking callback returns the exact calling `ContainerId`.

Use atomics or a `Mutex<Vec<[u64; 6]>>` to record call order; do not infer order
from nondeterministic logs.

Run:

```bash
cargo test -p carrick-runtime observe::tests::interceptor_chain --lib
```

Expected: FAIL because no chain exists.

- [ ] **Step 2: Add the crate-private chain result**

Implement:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Interception {
    pub effective_args: SyscallArgs,
    pub proposed: Option<SyscallOutcome>,
}

#[derive(Clone, Default)]
pub(crate) struct InterceptorChain {
    interceptors: Vec<Arc<dyn SyscallInterceptor>>,
}
```

`InterceptorChain::apply` must accept `&ProcessInfo` and `&SyscallRequest`, use
`std::panic::catch_unwind(AssertUnwindSafe(||
interceptor.intercept(process, &call)))` around each callback, and return
`Result<Interception, DispatchError>`. Lower actions as follows:

```rust
match action {
    InterceptAction::Continue => {}
    InterceptAction::RewriteArgs(args) => effective_args = args,
    InterceptAction::Return(value) => {
        proposed = Some(SyscallOutcome::returned(value));
        break;
    }
    InterceptAction::Errno(errno) => {
        proposed = Some(SyscallOutcome::errno(errno));
        break;
    }
}
```

On panic, return `DispatchError::InterceptorPanicked { container_id:
process.container_id() }`; never stringify the panic payload or resume unwind.

- [ ] **Step 3: Add property coverage for arbitrary six-word chains**

Use the workspace `proptest` dependency in `observe/tests.rs`. Generate an
original `[u64; 6]` and a vector of rewrite arrays, apply them through generated
interceptors, and assert:

```rust
prop_assert_eq!(result.effective_args.words(), expected_last);
prop_assert_eq!(request.args.words(), original);
prop_assert_eq!(request.number, original_number);
prop_assert_eq!(request.native_number, original_native_number);
```

Add a second property that inserts a terminal action at an arbitrary valid
position and proves no later interceptor runs.

- [ ] **Step 4: Run pure chain coverage**

```bash
cargo test -p carrick-runtime observe::tests::interceptor_chain --lib
cargo test -p carrick-runtime observe::tests::interceptor_rewrites_preserve_request_identity --lib
```

Expected: PASS.

- [ ] **Step 5: Commit the chain**

```bash
git add crates/carrick-runtime/src/observe/intercept.rs \
  crates/carrick-runtime/src/observe/tests.rs \
  crates/carrick-runtime/src/dispatch/mod.rs
git commit -m "runtime: order and contain syscall interceptors"
```

---

### Task 3: Add Container Identity and Install Interceptors Per Dispatcher

**Files:**

- Modify: `crates/carrick-runtime/src/observe/mod.rs:100-155`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:3246-3310`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:5075-5115`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:7200-7325`
- Modify: `crates/carrick-runtime/src/vdso_policy.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/runtime/exec.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- Modify: `crates/carrick-runtime/src/observe/tests.rs`
- Modify: `crates/carrick-runtime/src/dispatch/tests.rs`

**Interfaces:**

- Consumes: `KernelContext::task().container()`, `ContainerId`, `RunId`, and
  `InterceptorChain`.
- Produces: `ProcessInfo::container_id`, `ProcessInfo::run_id`, dispatcher
  installation/inheritance, and fail-closed fast-path visibility.

- [ ] **Step 1: Write red identity, inheritance, and fast-path tests**

Add tests that assert:

```rust
assert_eq!(process.container_id(), context.task().container().id());
assert_eq!(process.run_id(), context.task().container().run_id().clone());
```

Then install a recording interceptor and prove:

- `identity_fast_path_enabled()` is false;
- `identity_fast_path_word()` is `None`;
- the initial and post-`execve` vDSO image is the existing no-fastpaths image;
- `fork_clone` retains the exact same `Arc<InterceptorChain>`; and
- a dispatcher without interceptors preserves today's fast-path result.

Run:

```bash
cargo test -p carrick-runtime observe::tests::process_info_exposes_container_identity --lib
cargo test -p carrick-runtime dispatch::tests::interceptor_disables_identity_fast_path --lib
```

Expected: FAIL.

- [ ] **Step 2: Add read-only process identity accessors**

Add:

```rust
pub fn container_id(&self) -> crate::kernel::container::ContainerId {
    self.context.task().container().id()
}

pub fn run_id(&self) -> crate::kernel::container::RunId {
    self.context.task().container().run_id().clone()
}
```

The accessors must traverse the task's container edge; do not read process
environment, a thread-local, or a global current-container cell.

- [ ] **Step 3: Store and inherit the chain**

Add `interceptors: Option<Arc<InterceptorChain>>` beside `observers` in
`SyscallDispatcher`, initialize it to `None`, clone it in the fork dispatcher
construction, and add:

```rust
pub fn install_interceptor(&mut self, interceptor: Arc<dyn SyscallInterceptor>);
pub(crate) fn interceptors(&self) -> Option<&Arc<InterceptorChain>>;
```

Build a new immutable chain when installing before boot. Do not expose a live
mutation method once the dispatcher has entered execution.

- [ ] **Step 4: Fail closed on fast paths**

Change both identity fast-path methods so `self.interceptors.is_some()`
disables the path before consulting policy/observer visibility. Add a
`requires_syscall_traps()` query on the sealed dispatcher and thread it through
initial ELF construction and every exec path in `runtime.rs`,
`runtime/exec.rs`, `hvpatch/mod.rs`, and `vcpu_loop/exec.rs`. Extend
`vdso_policy` with an explicit visibility parameter: when traps are required,
attach `carrick_mem::vdso::vdso_image_bytes_without_fastpaths()` so clock,
gettimeofday, time, and getrandom resolve through real syscalls. Environment
debug controls may select an equally restrictive image, never a less
restrictive one.

Use this search as the completeness census:

```bash
rg -n "FastPathVisibility|identity_fast_path|vvar|vdso" \
  crates/carrick-runtime/src crates/carrick-vmm-hvf/src
```

The implementation must route accelerated calls through ordinary dispatch on
initial boot, fork inheritance, and `execve`; it must not merely add a
diagnostic blind-spot string.

- [ ] **Step 5: Run focused dispatcher tests**

```bash
cargo test -p carrick-runtime observe::tests --lib
cargo test -p carrick-runtime dispatch::tests::interceptor --lib
cargo test -p carrick-runtime dispatch::tests::dispatcher_fork_clone_splits_process_state_without_duping_descriptions --lib
cargo test -p carrick-runtime vdso_policy::tests::interceptor_requires_syscall_vdso --lib
```

Expected: PASS.

- [ ] **Step 6: Commit identity and installation**

```bash
git add crates/carrick-runtime/src/observe/mod.rs \
  crates/carrick-runtime/src/observe/tests.rs \
  crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/dispatch/tests.rs \
  crates/carrick-runtime/src/vdso_policy.rs \
  crates/carrick-runtime/src/runtime.rs \
  crates/carrick-runtime/src/runtime/exec.rs \
  crates/carrick-runtime/src/hvpatch/mod.rs \
  crates/carrick-runtime/src/vcpu_loop/exec.rs
git commit -m "runtime: bind interceptors to container dispatch"
```

---

### Task 4: Unify Pre-Policy Dispatch and Terminal Reporting

**Files:**

- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:7091-8105`
- Modify: `crates/carrick-runtime/src/dispatch/tests.rs`
- Modify: `crates/carrick-observability/src/compat.rs`
- Modify: `crates/carrick-runtime/src/observe/audit.rs`
- Modify: `crates/carrick-runtime/src/observe/mod.rs`
- Modify: `crates/carrick-runtime/src/observe/tests.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/continuation.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-conformance-next/src/lib.rs`

**Interfaces:**

- Consumes: interceptor result, launch-policy observer, seccomp state, user
  observers, normalized/independent/threaded handler routes, continuation
  completion.
- Produces: one shared dispatch envelope with the spec's exact ordering and one
  terminal callback/report event.

- [ ] **Step 1: Add red order and veto tests for both dispatch entry points**

Create a table-driven test that runs the same cases through `dispatch` and
`dispatch_threaded_for_test`:

1. rewrite argument 0, then verify policy sees the rewritten value;
2. propose `Return(7)`, then verify policy denial still yields its errno;
3. propose `Return(7)`, then verify guest seccomp denial still wins;
4. rewrite argument 2, then verify a user observer and the real handler see it;
5. replace with `Errno(EPERM)` and verify the handler is not invoked; and
6. verify exactly one observer return callback and one compat return count.

Run:

```bash
cargo test -p carrick-runtime dispatch::tests::interception_order --lib
```

Expected: FAIL against the duplicated current dispatch paths.

- [ ] **Step 2: Introduce one internal envelope value**

Add crate-private values near `SyscallRequest`:

```rust
#[derive(Clone, Copy)]
struct PreparedSyscall {
    original_args: SyscallArgs,
    request: SyscallRequest,
}

impl PreparedSyscall {
    fn effective_info(&self) -> crate::observe::SyscallInfo<'_> {
        crate::observe::SyscallInfo::new_effective(
            &self.request,
            self.original_args,
        )
    }
}

enum PreparedDispatch {
    Invoke(PreparedSyscall),
    Complete {
        syscall: PreparedSyscall,
        outcome: DispatchOutcome,
    },
}
```

Add `SyscallInfo::new_effective(&request, original_args)` and
`SyscallInfo::original_args()`. `SyscallInfo::new` remains source-compatible and
uses the request's args as both original and effective. Do not derive `Clone` or
`Copy` for `PreparedDispatch`: `DispatchOutcome` deliberately owns non-copyable
continuation and descriptor state.

- [ ] **Step 3: Implement the shared preflight in exact order**

Add one helper named `prepare_syscall`, used by both entry points, with these
arguments and result:

```rust
fn prepare_syscall(
    &self,
    kernel: &KernelContext,
    original: SyscallRequest,
    reporter: &CompatReporter,
) -> Result<PreparedDispatch, DispatchError>
```

Its body must:

1. copy `original.args`;
2. apply the interceptor chain and replace only `request.args`;
3. evaluate launch policy against effective `SyscallInfo`;
4. evaluate `seccomp_precheck(&request)`;
5. evaluate user observers against effective `SyscallInfo`;
6. apply `Short` only to the effective count word; and
7. publish one compat entry for the effective request; and
8. return either `PreparedDispatch::Complete { syscall, outcome }` or
   `PreparedDispatch::Invoke(syscall)`.

Launch-policy, seccomp, and user-observer `Deny`/`Kill` outcomes replace
`proposed`; a user-observer `Short` rewrites the handler's effective count and
does not turn a proposed terminal result back into handler execution. A
proposed result is returned only after every policy layer allows the call.
Lower the chain's small `SyscallOutcome` proposal explicitly into
`DispatchOutcome::Returned` or `DispatchOutcome::Errno`; never store a
`DispatchOutcome` in the copyable interceptor-chain result.

- [ ] **Step 4: Split one-time preflight from redispatchable handlers**

Make the production single-threaded and threaded trap entry points call
`prepare_syscall` exactly once, then route only `PreparedSyscall::request`
through a handler-only dispatch function. Readiness redispatch in
`runtime.rs`, threaded continuation redispatch, and a wait that blocks more
than once must call the handler-only function with the same prepared envelope;
they must not re-run interceptors, policy, seccomp, user observers, or entry
publication.

Remove duplicate preflight work from `dispatch_threaded_independent`,
`dispatch_threaded_shared`, `dispatch_threaded_captured`, and `dispatch_inner`.
Keep source-compatible test helpers only by making them perform one preflight
plus one handler dispatch; production wait loops use the separated functions.

- [ ] **Step 5: Publish returns only after actual guest completion**

Replace `ThreadRuntimeState<E>::current_syscall_request` with a completion token
holding the prepared request, original args, container identity, and observer
chain. Give the single-threaded loop in `runtime.rs` an equivalent local
completion-token owner; do not let either loop family publish directly from a
bare `SyscallRequest`.
Carry that token through fork, clone, exec failure, signal, blocking write,
wait, and continuation paths. `DispatchOutcome` is a request to the run loop,
not a terminal value: do not report it from dispatch or call its
`retval_errno()` as an observer result.

Create/install the token immediately after `prepare_syscall` for both
`PreparedDispatch::Invoke` and `PreparedDispatch::Complete`, before either arm
can enter a completion/non-returning branch. Handler redispatch borrows the
same token; it may not create a replacement token or refresh original args.

Refactor `ThreadRuntimeState<E>::complete_returned`/`complete_errno` and add the
same consume-and-publish helper around the single-threaded loop's
`runtime.complete_syscall(...)` calls so the sequence is:

1. perform the real `engine.complete_syscall(value)` or equivalent child/parent
   completion;
2. atomically consume the completion token;
3. emit one `CompatEvent::SyscallReturn`; and
4. invoke one `ObserverChain::on_syscall_return` with the effective request.

Every direct completion site in `runtime.rs`, including readiness, signal,
fork, exec, timeout, and error branches, must call that helper. Every threaded
alternative completion site, including the failed-exec path in
`vcpu_loop/exec.rs`, must consume the same token through the
`ThreadRuntimeState<E>` helper. A successful non-returning `execve`,
`rt_sigreturn`, thread exit, process exit, or signal death retires the token
without inventing a return event. A failed operation reports only its actual
returned errno. Add a debug assertion/error for duplicate consumption.

- [ ] **Step 6: Add rewrite diagnostics without taxing the no-rewrite path**

Extend `AuditEvent::Syscall` with `original_args: Option<[u64; 6]>`; store
`None` when original equals effective. Add a rare
`CompatEvent::SyscallRewrite { number, name, original_args, effective_args }`
record only when they differ, and add a bounded/deduplicated rewrite section to
`CompatReport`. Update the exhaustive probe match in
`crates/carrick-observability/src/probes.rs` and the conformance observer's
`AuditEvent::Syscall` constructor in
`crates/carrick-conformance-next/src/lib.rs` in the same commit.

Define `MAX_RECORDED_REWRITES: usize = 128`. The report retains the first 128
distinct `(number, original_args, effective_args)` keys without eviction and
uses saturating counters. Repeated retained keys continue incrementing after
capacity; every rewrite event for an unretained key beyond capacity increments
`dropped_rewrite_events: u64` instead of allocating. Do not allocate or lock
for an unchanged call. Add tests for deduplication, the 128-entry boundary, the
129th dropped key, continued counting of an existing key, and bounded memory.

- [ ] **Step 7: Prove all deferred terminal reporting**

Add focused tests for:

- a readiness wait that redispatches once and one that redispatches twice;
- timeout and interruption completion;
- blocking-write partial completion;
- fork parent and child completion;
- clone-thread completion;
- failed and successful exec; and
- `rt_sigreturn`, signal death, and a non-returning exit.

Assert one interceptor/policy/user-observer entry pass and one compat entry in
every case. Assert exactly one return callback with the actual guest value or
errno when the syscall returns, and zero return callbacks for a successful
non-returning outcome.

- [ ] **Step 8: Run dispatch and continuation tests**

```bash
cargo test -p carrick-runtime dispatch::tests::interception_order --lib
cargo test -p carrick-runtime observe::tests --lib
cargo test -p carrick-runtime runtime::tests::interception_redispatch --lib
cargo test -p carrick-runtime vcpu_loop::continuation --lib
```

Expected: PASS.

- [ ] **Step 9: Commit the shared dispatch envelope**

```bash
git add crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/dispatch/tests.rs \
  crates/carrick-runtime/src/observe/audit.rs \
  crates/carrick-runtime/src/observe/mod.rs \
  crates/carrick-runtime/src/observe/tests.rs \
  crates/carrick-runtime/src/runtime.rs \
  crates/carrick-runtime/src/vcpu_loop/continuation.rs \
  crates/carrick-runtime/src/vcpu_loop/exec.rs \
  crates/carrick-runtime/src/vcpu_loop/mod.rs \
  crates/carrick-observability/src/compat.rs \
  crates/carrick-observability/src/probes.rs \
  crates/carrick-conformance-next/src/lib.rs
git commit -m "runtime: intercept before policy and report once"
```

---

### Task 5: Wire Interceptors Through Preparation and the Embed Error Surface

**Files:**

- Modify: `crates/carrick-runtime/src/prepare.rs:102-155`
- Modify: `crates/carrick-runtime/src/prepare.rs:389-490`
- Modify: `crates/carrick-embed/src/builder.rs:107-160`
- Modify: `crates/carrick-embed/src/builder.rs:280-460`
- Modify: `crates/carrick-embed/src/error.rs`
- Modify: `crates/carrick-embed/src/lib.rs`
- Modify: `crates/carrick-embed/src/testing.rs`

**Interfaces:**

- Consumes: `RuntimeExtensions`, `ContainerBuilder`, dispatcher installation,
  and Task 2's typed panic error.
- Produces: `ContainerBuilder::interceptor` and
  `EmbedError::InterceptorPanicked { container_id }`.

- [ ] **Step 1: Write red builder and error-mapping tests**

Add tests proving repeated `.interceptor(interceptor)` calls preserve
registration order in `RuntimeExtensions`, preparation seals the list, and:

```rust
assert!(matches!(
    EmbedError::from_runtime(error, Phase::Execute),
    EmbedError::InterceptorPanicked { container_id } if container_id == expected
));
```

Run:

```bash
cargo test -p carrick-embed interceptor --lib
```

Expected: FAIL.

- [ ] **Step 2: Extend `RuntimeExtensions`**

Add a private vector of `Arc<dyn SyscallInterceptor>`, builder methods
`interceptor` and `interceptors`, destructure it in `Runtime::prepare`, and call
`dispatcher.install_interceptor` after launch policy is installed but before
the `PreparedRun` is returned.

- [ ] **Step 3: Extend `ContainerBuilder`**

Add the same private vector, initialize it empty, and expose:

```rust
pub fn interceptor(
    mut self,
    interceptor: Arc<dyn SyscallInterceptor>,
) -> Self {
    self.interceptors.push(interceptor);
    self
}
```

Move all registered values into `RuntimeExtensions` in `prepare`. Mirror the
field in `testing::TestContainer` and its existing lowering so host-only embed
tests exercise the same path.

- [ ] **Step 4: Add typed panic lowering**

Add the non-exhaustive public variant:

```rust
#[error("syscall interceptor panicked in container {container_id:?}")]
InterceptorPanicked { container_id: ContainerId },
```

Match only `RuntimeError::Dispatch(DispatchError::InterceptorPanicked { .. })`
in `EmbedError::from_runtime`; keep guest `Errno` actions as successful runtime
outcomes and preserve entitlement classification.

- [ ] **Step 5: Run focused embed tests**

```bash
cargo test -p carrick-embed interceptor --lib
cargo test -p carrick-embed error::tests --lib
cargo check -p carrick-embed --all-features
```

Expected: PASS.

- [ ] **Step 6: Commit embed wiring**

```bash
git add crates/carrick-runtime/src/prepare.rs \
  crates/carrick-embed/src/builder.rs \
  crates/carrick-embed/src/error.rs \
  crates/carrick-embed/src/lib.rs \
  crates/carrick-embed/src/testing.rs
git commit -m "embed: install per-container syscall interceptors"
```

---

### Task 6: Add a Compiled Single-Container Example and Correct API Docs

**Files:**

- Create: `crates/carrick-embed/examples/intercept_getuid.rs`
- Modify: `crates/carrick-embed/README.md`
- Modify: `crates/carrick-embed/src/lib.rs:1-38`
- Modify: `crates/carrick-embed/Cargo.toml`

**Interfaces:**

- Consumes: public `ContainerBuilder`, `SyscallInterceptor`,
  `InterceptedSyscall`, `InterceptAction`, `SyscallArgs`, and `LinuxErrno`.
- Produces: a compiled example and accurate observer-versus-interceptor support
  documentation.

- [ ] **Step 1: Add the example to the compile gate before its source exists**

Add an explicit example target:

```toml
[[example]]
name = "intercept_getuid"
path = "examples/intercept_getuid.rs"
```

Run:

```bash
cargo check -p carrick-embed --example intercept_getuid
```

Expected: FAIL because the source is absent.

- [ ] **Step 2: Implement the example with no guest-memory access**

The example defines an interceptor that returns uid 1000 for canonical
`getuid` and continues every other syscall, then runs `/usr/bin/id -ru` from the
documented Ubuntu image through `ContainerBuilder::from_image`. `-r` is
load-bearing: the public demonstration requests the real uid rather than the
effective uid. Keep the implementation complete and directly compilable; use
`anyhow::Result`, `Arc`, and `run_blocking`. The signed gate in Task 7—not this
human-facing example—provides raw-syscall proof.

- [ ] **Step 3: Correct crate rustdoc and the embed README**

Replace the stale claim that observers, VFS, networking, and time are not
exposed. Add a compact table that distinguishes:

- observers: inspect/filter and receive lifecycle/return callbacks;
- interceptors: rewrite six scalar words or return value/errno;
- VFS: custom mounted filesystem behavior; and
- unsupported: syscall-number changes and guest-memory mutation.

State that a custom interceptor disables accelerated syscall blind spots and
that panics are container-scoped typed errors.

- [ ] **Step 4: Compile docs and example**

```bash
cargo check -p carrick-embed --example intercept_getuid
RUSTDOCFLAGS="-D warnings" cargo doc -p carrick-embed --no-deps
```

Expected: PASS.

- [ ] **Step 5: Commit example and docs**

```bash
git add crates/carrick-embed/Cargo.toml \
  crates/carrick-embed/examples/intercept_getuid.rs \
  crates/carrick-embed/README.md \
  crates/carrick-embed/src/lib.rs
git commit -m "docs: demonstrate typed syscall interception"
```

---

### Task 7: Prove Interception in a Signed Guest

**Files:**

- Create: `fixtures/embed-interceptor-probe/probe.c`
- Create: `scripts/build-embed-interceptor-probe.sh`
- Modify: `scripts/test-signed.sh`
- Modify: `crates/carrick-embed/tests/guest_smoke.rs`
- Modify: `crates/carrick-embed/tests/common/mod.rs`

**Interfaces:**

- Consumes: signed `just test-embed`, captured stdio, audit observer, guest
  `getuid`, and guest `write`.
- Produces: end-to-end proof of return replacement, fd argument rewrite,
  effective observer events, fast-path visibility, and panic classification.

- [ ] **Step 1: Add one deterministic raw-syscall guest fixture**

Build a static aarch64 Linux fixture in a native arm64 Alpine container. The C
source has two modes:

- `identity`: call `syscall(SYS_getuid)` and `syscall(SYS_getpid)` directly,
  call libc `clock_gettime(CLOCK_REALTIME, &timespec)` so the ordinary vDSO route
  is exercised, and print labeled return/errno values; and
- `write`: call `syscall(SYS_write, 1, stdout_marker, stdout_len)` and
  `syscall(SYS_write, 2, stderr_marker, stderr_len)` with fixed distinct bytes.

The build script compiles only this fixture, verifies it is a static AArch64
ELF, and writes it under `target/embed-fixtures/`. Invoke it from
`scripts/test-signed.sh` before compiling the signed test executable, and let
the Docker build exit before any HVF guest begins. Add a common helper that
mounts those exact bytes into the guest through
`InMemoryFileVfs::add_file_with_metadata(..., 0o755, NsUid::ROOT,
NsGid::ROOT, 0)` (or its exact typed equivalent) so the mounted probe is
executable; do not depend on a mutable conformance image containing an
unreceipted probe.

Extend `scripts/test-signed.sh` to atomically replace—not append to—the
package-scoped receipt at
`target/test-results/<package>-signed-artifacts.jsonl` once per invocation
(`carrick-embed` therefore writes
`target/test-results/carrick-embed-signed-artifacts.jsonl`, while conformance
packages cannot overwrite it). Sanitize and validate the package component;
do not accept path separators. Write to a same-directory temporary file and
rename it only after the negative control and scoped cleanup pass. Use schema
`carrick.signed-embed-test.v1` with:

- one header row containing `source_head`, package, exact arguments, requested
  test filter, and scoped `CARRICK_RUN_ID`;
- one executable row per test binary actually signed and invoked, with an
  `executable_id` equal to its binary SHA-256 plus canonical path, SHA-256,
  CDHash, LC_UUID, entitlement digest/presence, and `__dof_carrick` presence;
- one execution row per resolved test name, linked by `executable_id` and
  containing the requested filter and terminal status;
- a separately typed unentitled-negative-control row linked to the exact
  stripped/copied executable identity; and
- one terminal cleanup row containing the run id and
  `remaining_processes: 0`.

Enumerate tests before execution. A filter used with `--exact` must resolve
exactly one test across the executable census. A non-exact filter must resolve
at least one test and records every match; this preserves the broad
`generic_probe_shard_` and `case_` conformance invocations. An unfiltered
full-suite invocation records every resolved test. Fail rather than publish a
receipt with zero matches, a missing identity field, failed negative control,
unlinked execution row, or nonzero cleanup count. A signed CLI binary is not a
substitute for this executable receipt.

- [ ] **Step 2: Write the red signed guest test**

Under one `common::guest_lock()`, run the fixture's `identity` mode with an
interceptor that returns 4242 for `getuid`, returns 31337 for `getpid`, returns
`EPERM` for `clock_gettime`, and continues every other syscall. Assert the raw
uid/pid values and the libc clock errno. These calls prove ordinary dispatch,
the accelerated identity shim, and the vDSO bypass are all covered.

Run the fixture's `write` mode with a separate interceptor rewriting `write`
argument 0 from fd 1 to fd 2. Retain an `AuditObserver` on both runs. Assert:

- the stdout marker appears only on captured stderr;
- the fixture's native stderr marker remains independent;
- no duplicate entry/return events occur; and
- audit entry args are the effective fd with original args preserved.

Run:

```bash
just test-embed syscall_interceptor_rewrites_and_replaces --exact --nocapture
```

Expected: FAIL before the runtime wiring is complete. `HV_DENIED` is a test
failure, not a skip.

- [ ] **Step 3: Add a separate panic-containment guest test**

Run the raw fixture in a container whose interceptor panics on `getuid`. Assert
`EmbedError::InterceptorPanicked` contains that prepared container's id and
that the process remains alive by running a host-only assertion after the
error. Do not start a sibling here; sibling survival belongs to the explicit
carrier plan.

- [ ] **Step 4: Run the signed focused tests**

```bash
just test-embed syscall_interceptor_rewrites_and_replaces --exact --nocapture
just test-embed syscall_interceptor_panic_is_contained --exact --nocapture
```

Expected: PASS.

- [ ] **Step 5: Commit the signed proof**

```bash
git add fixtures/embed-interceptor-probe/probe.c \
  scripts/build-embed-interceptor-probe.sh \
  scripts/test-signed.sh \
  crates/carrick-embed/tests/guest_smoke.rs \
  crates/carrick-embed/tests/common/mod.rs
git commit -m "test: prove embedded syscall interception"
```

---

### Task 8: Run the Interception Review Gate

**Files:**

- Modify only if a gate finds a defect: files already named in Tasks 1-7.
- Create: `docs/test-results/2026-08-30-syscall-interception.md`

**Interfaces:**

- Consumes: the complete interception implementation.
- Produces: source-bound correctness and no-extension performance receipts for
  Plan 2 to consume.

- [ ] **Step 1: Run formatting, lint, host, and documentation gates**

```bash
just fmt-check
cargo test -p carrick-observability --lib
cargo test -p carrick-runtime observe --lib
cargo test -p carrick-runtime dispatch::tests::interception --lib
cargo test -p carrick-embed --lib
cargo check -p carrick-embed --examples
RUST_TEST_THREADS=1 just ci
```

Expected: PASS.

- [ ] **Step 2: Run the complete signed embed suite**

```bash
RUST_TEST_THREADS=1 just test-embed
```

Expected: PASS, including the unentitled negative control. Validate the JSONL
receipt at `target/test-results/carrick-embed-signed-artifacts.jsonl` and
identify the exact signed test executable and execution rows for both
`syscall_interceptor_` tests; their linked artifact identity and scoped cleanup
row are part of the closure record. Copy the complete atomic receipt into the
closure record before a later invocation replaces it.

- [ ] **Step 3: Run cached and strict probe gates serially**

```bash
CARRICK_PROBE_WORKERS=1 just conformance-probes
CARRICK_PROBE_WORKERS=1 just conformance-probes-closure
just conformance-closure-scope
```

Expected: PASS with no skips in closure mode and a green scope check. Do not
run Carrick and Docker oracle phases concurrently.

- [ ] **Step 4: Build and smoke the still-shipped CLI/default path**

```bash
just build
shasum -a 256 target/release/carrick
codesign -dvvv --entitlements - target/release/carrick
otool -l target/release/carrick | rg "LC_UUID|uuid|__dof_carrick"
just conformance-quick
```

Record the exact CLI artifact identity separately from the signed embed test
identity. Run the README simple command on this binary, record stdout/stderr and
status, and use its `CARRICK_RUN_ID` cleanup path. A green embed test does not
replace the shipped CLI/default-lane smoke.

- [ ] **Step 5: Measure the no-interceptor path**

Record the commit before Task 1 as `INTERCEPTION_BASE`, ensure both source trees
are clean, and run the repository's HVPatch-default ABBA harness with the same
default overlay on both arms. Never use the caller's possibly dirty checkout as
either source or harness authority; materialize both exact commits as detached
worktrees:

```bash
test -n "$INTERCEPTION_BASE"
git check-ignore -q .worktrees
INTERCEPTION_CANDIDATE="$(git rev-parse HEAD)"
git worktree add --detach .worktrees/interception-control "$INTERCEPTION_BASE"
git worktree add --detach .worktrees/interception-candidate "$INTERCEPTION_CANDIDATE"
test -z "$(git -C .worktrees/interception-control status --porcelain)"
test -z "$(git -C .worktrees/interception-candidate status --porcelain)"
python3 .worktrees/interception-candidate/scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo .worktrees/interception-control \
  --destination target/perf/interception-abba/control \
  --label interception-control --role control \
  --image localhost:5005/carrick-go-conformance:1.24
python3 .worktrees/interception-candidate/scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo .worktrees/interception-candidate \
  --destination target/perf/interception-abba/candidate \
  --label interception-candidate --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
python3 .worktrees/interception-candidate/scripts/perf/native_go_build_abba.py run \
  --harness-repo .worktrees/interception-candidate \
  --control-receipt target/perf/interception-abba/control/arm.json \
  --candidate-receipt target/perf/interception-abba/candidate/arm.json \
  --control-overlay .worktrees/interception-candidate/scripts/perf/overlays/native-default.json \
  --candidate-overlay .worktrees/interception-candidate/scripts/perf/overlays/native-default.json \
  --quads 8 \
  --output target/perf/interception-abba/campaign.json
git worktree remove .worktrees/interception-control
git worktree remove .worktrees/interception-candidate
```

The B workload installs no interceptor. Record both source commits, arm
receipts, binary SHA-256/CDHash/LC_UUID/entitlement/DOF identities, samples,
confidence interval, and decision. Reject a supported regression; do not
explain it away with an interceptor-enabled measurement.

- [ ] **Step 6: Record the receipt and final commit**

Write the exact outputs and any non-completion conditions to the test-results
file, then:

```bash
git add docs/test-results/2026-08-30-syscall-interception.md
git commit -m "test: record syscall interception gates"
```

- [ ] **Step 7: Hand the exact public API to Plan 2**

Confirm Plan 2 consumes the shipped names and signatures from this plan. If the
implementation changed any public name, update Plan 2 before beginning it and
commit that plan-only correction separately.
