# Identity-memory + cache adoption precision map

**Date:** 2026-07-23
**Status:** binding input to Tasks 2-3 of `docs/superpowers/plans/2026-07-23-native-lane-seam-phase2.md`
**Scope:** read-only scouting (Task 1 of that plan). No code changed. All line refs are against `crates/carrick-runtime/src/native_freebsd.rs` at branch `feat/native-lane-seam-phase2`, HEAD `127bf605` (19,687 lines).

## 0. Headline finding — read this before the tables

Task 2's sketch (`IdentityGuestMemory` → `carrick_dsr::identity_memory`) is right in
shape but has one **mandatory, non-optional correction** the parent plan did not
anticipate: **`IdentityGuestMemory` cannot move to `carrick-dsr` as a concrete,
non-generic struct.**

Every mutating `GuestMemory` method on `IdentityGuestMemory` (`set_no_access`,
`set_no_write`, `set_mapping_protection`, `protect_range`, `write_bytes`,
`unmap_range`, `repoint_private`, `zero_anonymous_reuse`, …) routes through
`self.mapping_write_for_mutation`/`self.mapping_read_for_write`
(native_freebsd.rs:6400-6461), which calls `self.executable_epoch`'s
`begin_mutation(self: &Arc<Self>) -> Result<ExecutableMutationLease, ExecutableEpochError>`
(native_freebsd.rs:3266-3268). `ExecutableEpoch`/`ExecutableMutationLease`/
`ExecutableEpochError` are the x86 thread-loop's JIT-admission/quiescence
coordinator (native_freebsd.rs:2150-6378, ~4.2K lines) — explicitly **out of
scope** for Phase 2 (that's the Phase-3 loop merge) and not movable to
`carrick-dsr` (it is deeply coupled to `SharedRun`/`ExecutableThreadRegistration`/
host-fork lease machinery that stays put). If `IdentityGuestMemory` moves to
`carrick-dsr` as-is, its own field `executable_epoch: Option<Arc<ExecutableEpoch>>`
names a type that lives one crate *downstream* of `carrick-dsr` — `carrick-dsr`
would depend on `carrick-runtime`, inverting the entire crate graph. This is
not a hypothetical: I grepped every `ExecutableEpoch`/`ExecutableMutationLease`/
`ExecutableEpochError` reference inside the 6380-8350 span and there is exactly
**one** point of contact: the `begin_mutation()` call. That narrowness is what
makes this fixable additively rather than a plan-breaker.

**Required seam (new, not in the parent plan's sketch):** genericize
`IdentityGuestMemory` over a new minimal trait that abstracts "the executable
epoch, from the identity-memory model's point of view":

```rust
// crates/carrick-dsr/src/identity_memory.rs (or a small sibling module)

/// Executable-mutation coordination the identity-memory model needs to
/// serialize a guest-code WRITE against concurrently-running JIT'd
/// translations of the same (or overlapping) code region. One method,
/// because `mapping_write_for_mutation`/`mapping_read_for_write` are the
/// ONLY call sites — do not grow this past what they consume.
pub trait ExecutableMutationAuthority: Send + Sync {
    type Lease;
    type Error: std::fmt::Debug;

    /// Mirrors `ExecutableEpoch::begin_mutation`'s exact receiver: the lease
    /// holds its own `Arc<Self>` clone, so borrowing through the Arc (not
    /// `&self`) is required, not stylistic.
    fn begin_mutation(self: &std::sync::Arc<Self>) -> Result<Self::Lease, Self::Error>;
}

pub struct IdentityGuestMemory<A: ExecutableMutationAuthority> {
    executable_epoch: Option<std::sync::Arc<A>>,
    mapping_failure: Option<carrick_guest_mem::MemoryError>,
}
```

`ExecutableEpoch` (staying in native_freebsd.rs) gains one additive impl:
`impl ExecutableMutationAuthority for ExecutableEpoch { type Lease =
ExecutableMutationLease; type Error = ExecutableEpochError; fn begin_mutation
(self: &Arc<Self>) -> ... { self.begin_mutation(EXECUTABLE_QUIESCENCE_TIMEOUT) } }`
— zero changes to `ExecutableEpoch`'s own body. `native/mod.rs` (the
established single-wiring-point pattern — see `HostNativeLane` at
`crates/carrick-runtime/src/native/mod.rs:87-92`) gets one more alias:
`type NativeIdentityMemory = carrick_dsr::identity_memory::IdentityGuestMemory<ExecutableEpoch>`,
or the 13 call sites in §2 just spell the generic instantiation directly. This
is the SAME pattern already used for `HostNativeLane`/`NativeLane` — not a new
paradigm, just one generic parameter deeper.

**Propagation.** Genericity threads through every item that touches
`&IdentityGuestMemory`/its epoch: `identity_checked_write_exact`,
`identity_checked_write_sigframe` (both take `memory: &IdentityGuestMemory`),
and — because only the `ControlFlowMemory` impl moves to `carrick-dsr-x86` (see §0b),
while `IdentityXstateMemoryReader`/`IdentityXstateMemoryWriter` stay in
native_freebsd.rs — the `ControlFlowMemory` impl only. The write helpers become
`<A: ExecutableMutationAuthority>`.
Everything on the **read** path (`identity_checked_read_exact` and friends) is
already epoch-free (reads only ever take `IDENTITY_HOST_MAPPING_LOCK.read()`
directly — confirmed by grep, no `&IdentityGuestMemory` param) and needs no
generic parameter at all.

### 0b. Orphan-rule routing: `ControlFlowMemory` goes to `carrick-dsr-x86`; xstate impls STAY

`carrick-dsr-x86` depends on `carrick-dsr`; **`carrick-dsr` does not depend on
`carrick-dsr-x86`** (confirmed via both crates' `Cargo.toml`). One trait impl
in the closure implements a `carrick-dsr-x86`-defined trait for
`IdentityGuestMemory`:

- `impl cflow::ControlFlowMemory for IdentityGuestMemory` (native_freebsd.rs:8298-8339) — `cflow::ControlFlowMemory` is defined in `carrick-dsr-x86/src/cflow.rs:64`.

Today this compiles because `IdentityGuestMemory` is *local* to
`carrick-runtime` (the orphan rule needs only one of {trait, type} local to
the impl's crate). Once the type moves to `carrick-dsr`, **the trait becomes
foreign while the type becomes foreign to `carrick-runtime`** — `carrick-runtime`
could no longer host this impl (neither type nor trait local), and `carrick-dsr`
can't host it either (trait foreign, and no dependency edge to see it). The only
legal home is **`carrick-dsr-x86`**, which already depends on `carrick-dsr` and
already owns the trait. Concretely: `cflow_guest_memory_fault`/
`cflow_raw_memory_fault`/`cflow_memory_backend_error` (8261-8296) and the
`ControlFlowMemory` impl (8298-8339) move to **`crates/carrick-dsr-x86/src/cflow.rs`**
(or a new sibling file there), not to `carrick-dsr::identity_memory`. This is a
missing row in the parent plan's Task-2 file list — add it.

**CONTROLLER RULING (2026-07-23):** `IdentityXstateMemoryReader` and
`IdentityXstateMemoryWriter<'_>` (native_freebsd.rs:8239-8259) are *local wrapper
types* — the orphan rule does NOT force them anywhere because `IdentityGuestMemory`
is their only type, and they reference concrete `IdentityGuestMemory<ExecutableEpoch>`
directly (not genericized). **These impls STAY in native_freebsd.rs**, avoiding
the need to thread `A: ExecutableMutationAuthority` genericity through
`carrick-dsr-x86` for a type it does not need to own. Zero aarch64 impact:
`carrick-dsr-aarch64` has no `cflow` module and no `ControlFlowMemory`/
`X86XstateMemory*` usage at all (grepped, no hits).

---

## 1. `IdentityGuestMemory` closure inventory

All line numbers current-HEAD (`127bf605`), `crates/carrick-runtime/src/native_freebsd.rs`.

### 1a. MOVE-AS-IS → `carrick-dsr/src/identity_memory.rs` (generic over `A: ExecutableMutationAuthority` where the item touches the epoch; otherwise plain)

| Item | Lines | Notes |
|---|---|---|
| `struct IdentityGuestMemory` | 210-220 | becomes `IdentityGuestMemory<A>` |
| `impl IdentityGuestMemory` (ctors: `uncoordinated`/`for_run`/`record_mapping_failure`/`take_mapping_failure`/`abandon_inherited_epoch_after_fork`/`rebind_after_fork`) | 222-261 | generic over `A` |
| `X86_64_USER_END_EXCLUSIVE` const | 344 | rename/replace: see §1c, becomes `L::Isa::USER_VA_END_EXCLUSIVE` per Task-2's own sketch text |
| `LINUX_MMAP_MIN_ADDR` const | 347 | POSIX/Linux-ABI constant, ISA-independent (same value for x86_64 today; aarch64 lane doesn't use this module so no conflict) |
| `identity_raw_fault_address` / `identity_raw_range_valid` | 350-372 | needs the ISA VA-end swap above |
| `IDENTITY_PROTECTIONS` static (`LazyLock<MemoryProtections>`) | 1846-1849 | **stays process-global** per Phase-1 ruling — moves with the module, is not parameterized |
| `IDENTITY_HOST_MAPPING_LOCK` static + `identity_host_mapping_write_until` | 1853-1867 | same |
| `NativeMappingOperation` enum + `#[cfg(test)]` `impl` (`COUNT`/`index`) | 1869-1903 | POSIX-generic tagging enum |
| `InjectedMmapResult` / `NativeMappingFaultInjection` / `NATIVE_MAPPING_FAULTS` thread-local / `NativeMappingFaultGuard` (+ Drop) | 1905-2005 | fault-injection scaffold; **survives the move** — see §2 |
| `host_mmap` / `take_injected_mprotect_failure` / `host_mprotect` / `host_munmap` | 2007-2148 | MOVE-BEHIND-SEAM for exactly one bit — see §1c (MAP_EXCL) |
| `impl IdentityGuestMemory` block 2 (`epoch_error`/`begin_executable_mutation`/`mapping_write_for_mutation`/`mapping_read_for_write`) | 6380-6462 | generic over `A`; this is the block from §0 |
| `ensure_identity_backed_with_registry` / `ensure_identity_backed` | 6470-6569 | POSIX-generic; MAP_EXCL caveat at 6521, see §1c |
| `identity_read_bytes_raw_unlocked` / `identity_write_prevalidated_unlocked` / `identity_write_bytes_raw_unlocked` | 6571-6635 | pure POSIX copy helpers |
| `identity_apply_host_protection_preserving_bus` | 6637-6684 | POSIX-generic (bus-fault-preserving mprotect) |
| `impl GuestMemory for IdentityGuestMemory` | 6686-7219 | generic over `A`; every mutating method routes through `mapping_write_for_mutation`/`mapping_read_for_write` |
| `IDENTITY_KERNEL_COPY_{PIPE_BOUND,CHUNK,EINTR_LIMIT}` consts | 7236-7244 | POSIX-generic tuning constants |
| `IdentityCheckedReadError` / `IdentityCheckedWriteError` / `IdentityKernelCopyError` | 7246-7264 | POSIX-generic error vocabulary |
| `identity_checked_read_fault` / `identity_checked_write_fault` | 7266-7292 | POSIX-generic |
| `#[cfg(test)]` census thread-locals (`IDENTITY_KERNEL_COPY_PIPE_CENSUS`, `IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS`, `IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS`) + reset/getter fns | 7294-7332 | survives the move — see §2 |
| `identity_kernel_copy_pipe` / `identity_kernel_copy_chunk` | 7334-7401 | the pipe-based kernel-copyin/out trick (`pipe2`+`write`+`read` to get kernel fault containment) is **genuinely POSIX**, not FreeBSD-specific — verified: `libc::pipe2`/`write`/`read`/`EINTR`/`EAGAIN`/`EFAULT` all exist identically on Darwin |
| `identity_kernel_copyin_exact_using` / `identity_kernel_copyin_exact` | 7409-7576 | POSIX-generic |
| `identity_kernel_copyout_exact` | 7583-7742 | POSIX-generic |
| `identity_checked_read_exact` / `identity_checked_read_exact_under_mapping_lock` | 7753-7837 | POSIX-generic, **no epoch dependency** (reads only take the plain RwLock) |
| `identity_checked_write_exact` / `identity_checked_write_range_under_mapping_lock` / `identity_checked_write_exact_under_mapping_lock` | 8078-8172 | generic over `A` (the outer `identity_checked_write_exact` takes `&IdentityGuestMemory<A>`) |
| `identity_checked_read_sigframe` / `identity_checked_write_sigframe` | 8178-8237 | POSIX-generic chunked wrapper; `identity_checked_write_sigframe` generic over `A` |
| `NativeMapping` struct + `impl` + `Drop` | 9349-9512 | see §1c for the error-type note |
| `teardown_native_mappings_collect` / `teardown_native_mappings` | 9514-9531 | POSIX-generic |
| `NativeMappingTransaction` struct + `impl` | 9537-9658 | POSIX-generic |
| `map_prot_at` | 9322-9340 | MOVE-BEHIND-SEAM for MAP_EXCL, see §1c |
| `map_fixed_replacement` | 9660-9694 | POSIX-generic |

Rough new-module size once §1b/§1c seams are applied and the test split (§2)
lands: **~2.1-2.4K lines** of production code plus whatever subset of tests
moves (§2) — consistent with the parent plan's "≈−2K lines" expectation,
modulo the ~120 lines (cflow/xstate-reader glue) that land in
`carrick-dsr-x86` instead (§0b) and therefore don't count against
`carrick-dsr`'s own growth.

### 1b. STAY — explicitly out of this closure, with rationale

| Item | Lines | Why it stays |
|---|---|---|
| `ExecutableEpoch` + its entire admission/quiescence/host-fork-lease cluster (`ExecutableGeneration`, `ExecutableStopSequence`, `ExecutableAdmission`, `ExecutableThreadId/State/Record`, `ExecutableMutationOwner`, `ExecutableHostForkOwner/State`, `ExecutableTerminalPhase/Owner/State/Stop`, `ExecutableEpochError`, `ExecutableThreadRegistration`, `ExecutableHostWaitGuard`, `ExecutableHostForkLease`, `ExecutableTerminalRetirement/Reservation/Lease`, `JitAdmission`, `InJitGuard`, `ExecutableMutationLease`) + `mod executable_epoch_tests` | 2150-6378 (~4.2K lines) | The x86 thread-loop's own JIT-admission/quiescence coordinator. `IdentityGuestMemory` only *references* it (one Arc field, one method call — §0); the coordinator itself is deeply wired to `SharedRun`/host-fork/thread-registration machinery that is explicitly Phase-3 territory (the loop merge). Made reachable to the moved module only through `ExecutableMutationAuthority` (§0). |
| `identity_contiguous_executable_span_under_mapping_lock`, `identity_execute_fault_under_mapping_lock`, `identity_checked_read_executable_exact`, `identity_checked_fetch_x86_instruction_mutable_shared_under_mapping_lock`, `identity_checked_fetch_x86_instruction`, `X86_MAX_INSTRUCTION_LENGTH` | 7840-8070 | This is x86 **instruction-decode**-coupled: `identity_checked_fetch_x86_instruction[_mutable_shared_...]` calls `carrick_dsr_x86::decode::classify(...)` directly to find the true instruction length. `identity_execute_fault_under_mapping_lock`/`identity_contiguous_executable_span_under_mapping_lock` are technically ISA-neutral in their own bodies, but their only consumer is this x86-fetch cluster — splitting them out for zero present reuse just fragments one cohesive unit. A future NetBSD/aarch64-native-lane's equivalent instruction-fetch helper would be its own ISA-appropriate thing anyway (aarch64 has fixed 4-byte instructions and no "find the executable prefix up to N bytes" concept at all). |
| `cflow_guest_memory_fault`, `cflow_raw_memory_fault`, `cflow_memory_backend_error`, `impl cflow::ControlFlowMemory for IdentityGuestMemory` | 7221-7231, 8298-8339 | **MOVE to `carrick-dsr-x86`** (§0b). Orphan rule forces `ControlFlowMemory` there; the cflow helpers move with it. |
| `IdentityXstateMemoryReader`/`IdentityXstateMemoryWriter` + their `X86XstateMemory*` trait impls | 8239-8259 | **STAY in native_freebsd.rs** (§0b). Local wrapper types over concrete `IdentityGuestMemory<ExecutableEpoch>`; orphan rule does not force relocation. Avoids threading `ExecutableMutationAuthority` genericity through carrick-dsr-x86 unnecessarily. |
| `SigframeEngine` struct + `RegAccess`/`GuestMemory` impls, `deliver_x86_signal`, `synchronous_fault_*`, `deliver_synchronous_x86_fault`, `deliver_x86_instruction_fetch_error`, `restore_x86_sigreturn`, `NativeX86Trap` | 8348-8858ish | A *different* `GuestMemory` impl (over live register/xstate snapshot, not identity host memory) for x86 signal delivery. It **consumes** the moved `identity_checked_read_sigframe`/`identity_checked_write_sigframe` (cross-crate call after the move) but is not itself part of `IdentityGuestMemory`'s closure. |
| `native_minherit`, `NativeMinheritFailureGuard`, `exclude_vfork_shared_ranges`, `native_private_inheritance_ranges`, `NativeVforkShare`, `wait_native_vfork_completion` | 15568-15833 | vfork-inheritance machinery (`minherit(2)`/`FREEBSD_INHERIT_{SHARE,COPY}`, already portably wrapped in `carrick-portable::freebsd_minherit`, `crates/carrick-portable/src/lib.rs:1170-1182`). Operates on host memory ranges but has nothing to do with the `GuestMemory` trait or `IdentityGuestMemory` — it's `service_fork`'s vfork-sharing policy. Matches the parent plan's own text ("minherit vfork machinery stays"). |
| `GuestArenas`, `FixedRwReservation`, `reserve_fixed_rw`, `remap_exec_arenas` | 76-189 | Consumers of `NativeMapping`/`map_prot_at` (arena reservation at loader/exec time), not part of the type's own closure. See §2. |
| `LoadedImage`, `protect_existing_identity_range`, `reset_identity_vmas_with_registry`, `reset_identity_vmas` | 9067-9190 | Consumers (loader/exec-image lifecycle), not closure members. `protect_existing_identity_range` duplicates a local `USER_END_EXCLUSIVE: u64 = 1 << 47` const — a drift nit, not fixed here, but Task 2 should have it reference the same ISA-VA-end source once that's parameterized (§1c). |
| `freebsd_shared_waiter_key` — the FUNCTION itself | 270-342 | **Moves, but not to `identity_memory.rs`** — see §1c. Listed here to be explicit about the distinction between "the seam call site" (moves to identity_memory) and "the concrete FreeBSD implementation" (moves to `carrick-native-freebsd`). |

### 1c. MOVE-BEHIND-SEAM — exact proposed signatures

**(i) `freebsd_shared_waiter_key` — sysctl KERN_PROC_VMMAP vnode identity.**
Confirmed FreeBSD-only: `libc::KERN_PROC_VMMAP`/`libc::kinfo_vmentry` are FreeBSD-only ABI (checked the vendored `libc` 0.2.186 source: present under `src/unix/bsd/freebsdlike/freebsd/`, absent from `src/unix/bsd/apple/`). The 2026-07-17 design doc already named this exact gap: `crate::trap::shared_futex_waiter_key` was slated for a "neutral home... futex keys → carrick-guest-mem/carrick-thread as appropriate," and `carrick-dsr/src/address.rs:756-767` independently anticipates it: *"the FreeBSD native lane will need MAP_FIXED|MAP_EXCL probing through the NativeHost seam instead — M1 in the portability-seams design."*

Proposed seam, added to `carrick_dsr::lane::NativeHost` (`crates/carrick-dsr/src/lane.rs`):
```rust
pub trait NativeHost: 'static + Send + Sync {
    const NAME: &'static str;
    fn active_jit() -> &'static dyn NativeHostJit;
    /// Stable, fork-coherent waiter-key derivation for a guest MAP_SHARED
    /// futex word at `host_addr` (identity model: host VA == guest VA).
    /// `None` when the host cannot resolve a backing identity (falls back
    /// to `host_addr` itself, matching today's `.unwrap_or(host_addr)`).
    fn shared_futex_waiter_key(host_addr: usize) -> Option<usize> {
        None
    }
}
```
Given a default body, `carrick-native-darwin`'s `DarwinHost` needs **zero
changes** to compile (Darwin's native lane never calls `identity_memory`'s
`shared_futex_location` at all — that path belongs to its own, untouched
`NativeDispatchMemory`). `carrick-native-freebsd`'s `FreebsdHost` gets the real
override, moving `freebsd_shared_waiter_key`'s body verbatim into
`crates/carrick-native-freebsd/src/lib.rs` (or a new `waiter_key.rs`) as
`fn shared_futex_waiter_key(host_addr: usize) -> Option<usize>`. The call site
in the moved `shared_futex_location` becomes
`A::Host::shared_futex_waiter_key(host_addr)` if the identity-memory module is
also made generic over the host (it currently only needs `A:
ExecutableMutationAuthority`) — **simplest fix: thread this through as a
second, independent type parameter or as a plain associated fn parameter
passed in by the runtime's thin `impl GuestMemory` forwarding wrapper**, not by
also genericizing `IdentityGuestMemory` over `NativeHost` (that would be two
unrelated generic axes glued to one struct for no shared reason). Recommend:
keep `shared_futex_location`'s FreeBSD-specific key resolution as a small
closure/fn-pointer field passed into `IdentityGuestMemory::for_run`/`uncoordinated`,
OR — simpler still — leave `shared_futex_location` itself as a **default
`None`-returning trait method** on `GuestMemory` that `identity_memory.rs`
does NOT override, and have the *runtime* provide a thin newtype wrapper
around `IdentityGuestMemory<ExecutableEpoch>` in native_freebsd.rs whose own
`shared_futex_location` override calls `FreebsdHost::shared_futex_waiter_key`
directly. **This second option is lower-risk** (no new generic parameter,
no `identity_memory.rs` change beyond deleting the FreeBSD-specific override)
and is what I recommend Task 2 implement unless it discovers the wrapper adds
more boilerplate than it saves once it's mid-move.

**(ii) MAP_EXCL — POSIX mmap must not assume it exists.**
Confirmed FreeBSD/NetBSD-only (absent from Darwin's `libc`; matches the
`carrick-dsr/src/address.rs:756-767` comment quoted above). Two call sites in
the closure: `ensure_identity_backed_with_registry` (6521,
`MAP_FIXED|MAP_EXCL|MAP_ANON|MAP_SHARED`) and `map_prot_at` (9337, `flags |=
libc::MAP_EXCL`). Proposed seam — add to `NativeHost`:
```rust
pub trait NativeHost: 'static + Send + Sync {
    // ...
    /// Extra `mmap(2)` flag bits a host adds to a `MAP_FIXED` request to make
    /// it atomically fail rather than silently replace existing bytes when
    /// the target range is already occupied (FreeBSD/NetBSD: `MAP_EXCL`;
    /// Darwin has no such flag — a `MAP_FIXED` there always replaces, so the
    /// identity-memory model's own overlap bookkeeping — `NativeMappingTransaction`'s
    /// disjoint-range check — is the only protection on hosts where this
    /// returns 0. The x86/FreeBSD lane is a fixed-identity layout where a
    /// silent-replace bug is a real coherence hazard, so this must stay a
    /// real flag there, not a no-op probe).
    fn exclusive_fixed_map_flag() -> i32 {
        0
    }
}
```
`FreebsdHost::exclusive_fixed_map_flag() -> i32 { libc::MAP_EXCL }`;
`DarwinHost` keeps the default (`0`) — again a genuinely zero-behavior-change
addition on Darwin, since Darwin's native lane doesn't reach this code path.
`ensure_identity_backed_with_registry`/`map_prot_at` OR into
`host_mmap`/`reserve_fixed_rw`'s callers) replace the raw `libc::MAP_EXCL`
with `A::Host::exclusive_fixed_map_flag()` (or, if `identity_memory.rs` stays
generic only over `ExecutableMutationAuthority` per (i)'s recommendation, this
flag is threaded the same way — as a parameter the runtime's thin wrapper
supplies, not a second generic axis on the struct). **The shared module's own
`mmap` call sites end up with zero raw `MAP_EXCL`/`MAP_FIXED|MAP_EXCL`
literals** — this is the concrete, checkable acceptance criterion for "the
shared module contains ZERO `#[cfg(target_os)]`" as it applies to this flag.

**(iii) `NativeMapping`/`NativeMappingTransaction`'s error type.** Both
currently return `crate::run_result::RuntimeError` (native_freebsd.rs's own
error type) — which `carrick-dsr` cannot depend on (backwards). **Do not
invent a new error type**: `carrick-dsr::native_error::NativeMemoryError`
already exists for exactly this (`Unsupported(String)` / `Io{operation,
source}`), was built for the aarch64 mapped-memory extraction
(`crates/carrick-dsr/src/native_error.rs`, doc comment: *"mapped_memory.rs...
produces exactly two failure shapes"*), and `run_result.rs` already has
`impl From<carrick_dsr::native_error::NativeMemoryError> for RuntimeError`
preserving message format exactly. `NativeMapping`/`NativeMappingTransaction`/
`map_prot_at`/`map_fixed_replacement` should retarget their `Result<_,
RuntimeError>` to `Result<_, NativeMemoryError>`; the runtime call sites (§2)
get the conversion for free via the existing `?`/`.into()` path — **zero new
error-vocabulary code needed.**

**(iv) `X86_64_USER_END_EXCLUSIVE` → `GuestIsa::USER_VA_END_EXCLUSIVE`.**
Already anticipated verbatim by the parent plan's Task-2 mechanics text. One
nuance the plan didn't call out: `reset_identity_vmas_with_registry`
(native_freebsd.rs:9146) has its OWN duplicate local
`const USER_END_EXCLUSIVE: u64 = 1 << 47`, separate from the module-level
`X86_64_USER_END_EXCLUSIVE`. It's a STAY item (loader consumer, §1b) but
should be updated to read the same parameterized source so the two values
can't drift independently post-move — a one-line consumer fix, not a seam.

---

## 2. Consumer inventory + fault-injection survival

### 2a. Production call sites that will import from the new location(s)

All currently reference `IdentityGuestMemory` directly (grepped exhaustively);
post-move each becomes `use carrick_dsr::identity_memory::IdentityGuestMemory;`
plus (per §0) a concrete instantiation `IdentityGuestMemory<ExecutableEpoch>`:

| Function | Line | Role |
|---|---|---|
| `protect_existing_identity_range` | 9105 | loader: publish initial VMA protections |
| `reset_identity_vmas_with_registry` | 9141, 9149 | loader: reset syscall-pointer gate on exec |
| `spawn_clone_thread` | 11149, 11155 | `clone(2)`: per-thread memory handle |
| (fork-child rebuild path) | 11219 | fork-child's fresh memory handle |
| `run_x86_thread` | 12215, 12221, 11677 | the per-guest-thread run loop's memory instance |
| `service_syscall` | 13963, 13965 | single-thread dispatch |
| `service_syscall_threaded` | 15138, 15141 | multi-thread dispatch |
| `service_fork` | 15893, 15897 | `fork`/`vfork` servicing |
| `service_map_host_alias` | 16606, 16617 | host-alias mmap servicing |
| `service_arch_prctl` | 16800, 16805 | `arch_prctl` (FS/GS base) |
| `service_xstate_save` | 17071, 17077 | XSAVE state transfer |
| `service_legacy_state_transfer` | 17340, 17346 | legacy x87/FXSAVE transfer |

Every one of these takes `memory: &mut IdentityGuestMemory` or `&IdentityGuestMemory`
as a parameter today; post-move the parameter type is the generic
instantiation. None of these functions themselves move — they're the
x86-lane's own dispatch/thread/fork plumbing (Phase-3 loop-merge territory),
consuming the shared type across the crate boundary exactly like
`native_darwin.rs` already consumes `carrick_dsr::cache::TranslationCache` and
`carrick_dsr::address::OwnedHostMapping` today.

### 2b. `#[cfg(test)]` fault-injection thread-locals

Both survive the move unchanged because **they move with their production
functions**, per the brief's framing:

- `NATIVE_MAPPING_FAULTS: RefCell<NativeMappingFaultInjection>`
  (native_freebsd.rs:1939-1941) is read/written *inside* `host_mmap`/
  `take_injected_mprotect_failure`/`host_munmap` (2007-2148), which move
  verbatim (§1a). The thread-local declaration, `NativeMappingFaultGuard`, and
  the three fns move together — no behavior change, no new crate boundary to
  cross (the fault-injection API and its production call sites end up in the
  same module either way).
- `IDENTITY_KERNEL_COPY_PIPE_CENSUS` / `IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS` /
  `IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS` (7294-7332) are incremented
  inside `identity_kernel_copy_pipe`/`identity_kernel_copyin_exact_using`/
  the copyout loop, all of which move (§1a) — same reasoning.

Both scaffolds are already gated `#[cfg(test)]` only (not `test-hooks`
feature-gated); `carrick-dsr`'s existing `test-hooks` feature convention
(`Cargo.toml`: `test-hooks = []`, forwarded by `carrick-dsr-aarch64`) is for
cross-crate test access — check during Task 2 whether `native_freebsd.rs`'s
own `#[cfg(test)]` module (in-crate today) needs to become a `test-hooks`
consumer once it's calling into `carrick-dsr` across a crate boundary for
these; if any surviving test in native_freebsd.rs (§2c) still needs
`NativeMappingFaultGuard`, that's the trigger.

### 2c. Test-migration inventory — the parent plan's assumption needs correction

Task 2's sketch says `identity_raw_range_tests` (~1.5K lines) "moves with it."
**This is wrong as a blanket claim.** I read the module's `use super::{...}`
import list (native_freebsd.rs:376-379: it pulls in `PublishedFaultEntry`,
`SharedWaitAssignment`, `X86GatewayX87Witness`, `calibrate_x86_vvar_clock`,
`exclude_vfork_shared_ranges` alongside `IdentityGuestMemory`) and then
classified all 24 test fns by which non-identity subsystem, if any, each body
touches:

| Test fn (line) | Touches | Disposition |
|---|---|---|
| `accepts_low_canonical_guest_ranges` (396) | raw-range gate only | MOVE → identity_memory.rs |
| `rejects_null_wrapping_and_noncanonical_ranges` (402) | raw-range gate only | MOVE |
| `zero_length_access_never_forms_a_pointer` (411) | raw-range gate only | MOVE |
| `cflow_only_exposes_guest_access_failures_as_retryable_faults` (417) | `cflow::` | MOVE → **carrick-dsr-x86** (§0b) |
| `exact_checked_reader_uses_direct_materialized_copy_and_validates_before_mutation` (457) | `identity_checked_read_exact`, `repoint_private` | MOVE |
| `exact_checked_writer_uses_direct_materialized_copy_and_validates_before_mutation` (568) | `identity_checked_write_exact`, `repoint_private` | MOVE |
| `executable_private_repoint_isolates_fork_sibling_and_refreshes_direct_fetch` (685) | `repoint_private` **+** `identity_checked_fetch_x86_instruction` | STAY (mixed; needs the x86-fetch cluster which stays, §1b) |
| `middle_private_repoint_isolates_only_replaced_page_across_fork` (823) | `repoint_private` only | MOVE |
| `unflagged_private_overlay_futex_does_not_cross_wake_but_shared_does` (918) | `repoint_private` **+** `shared_futex_{wait,wake}_umtx` | STAY (umtx wait/wake machinery is native_freebsd.rs-local, separate from `shared_futex_location`'s `Direct{}` construction) |
| `exact_checked_reader_contains_readable_file_mapping_bus_faults` (1050) | `identity_checked_read_exact` | MOVE |
| `typed_x86_fetch_faults_at_cross_page_execute_boundary_and_retries` (1179) | `identity_checked_fetch_x86_instruction` | STAY |
| `typed_x86_fetch_contains_truncated_executable_backing_and_retries` (1284) | `identity_checked_fetch_x86_instruction` | STAY |
| `cflow_write_contains_truncated_shared_mapping_bus_faults` (1374) | `cflow::` | MOVE → carrick-dsr-x86 |
| `direct_host_pointer_validation_does_not_make_pages_resident` (1492) | `IdentityGuestMemory` only | MOVE |
| `shared_waiter_key_follows_vnode_offset_not_mapping_address` (1520) | `freebsd_shared_waiter_key` | MOVE → **carrick-native-freebsd** (§1c-i) |
| `shared_requeue_credit_survives_wake_before_destination_park` (1554) | `shared_futex_wake_umtx`/`SharedWaitAssignment` | STAY |
| `x86_fault_recovery_restores_guest_pc_and_spilled_register` (1614) | x87 | STAY |
| `x87_gateway_fip_normalization_*` (4 tests, 1648-1747) | x87/`X86GatewayX87Witness` | STAY |
| `calibrated_x86_vvar_tracks_host_clocks` (1786) | vvar clock | STAY |
| `elf_preflight_rejects_wrong_machine_and_non_executable_type` (1805) | `parse_loadable_elf` | STAY |
| `vfork_inheritance_excludes_existing_shared_vmas` (1820) | `exclude_vfork_shared_ranges` | STAY |

Net: **8 of 24** move to `identity_memory.rs`, **2 of 24** move to
`carrick-dsr-x86`, **1 of 24** moves to `carrick-native-freebsd`, **13 of 24**
stay in `native_freebsd.rs` as integration/consumer-pinning tests. The module
must be **split at Task-2 time**, not moved wholesale — the parent plan's
"~1.5K lines move with it" line is superseded by this table.

The trailing `mod tests` (17562-end, 53 test fns) was never claimed by the
parent plan to move wholesale, so no correction is owed there, but for
Task 2's estimating purposes: marker-based classification (verified by direct
read for the unambiguous cases) finds **9 clean move candidates** with no
loader/xstate/fork/signal coupling —
`reused_anonymous_backing_preserves_shared_and_private_fork_semantics` (18245),
`private_to_shared_anonymous_reuse_failure_preserves_bytes_and_metadata` (18305),
`private_repoint_mmap_failure_preserves_shared_backing_and_provenance` (18357),
`identity_backing_mmap_failure_keeps_metadata_unmapped` (18404),
`identity_mapping_setter_preserves_typed_backing_failure` (18423),
`identity_backing_wrong_address_is_rolled_back_before_metadata_change` (18444),
`fixed_reservation_wrong_address_reports_cleanup_and_retains_owner_until_retry` (18467),
`identity_backing_restores_only_holes_and_preserves_adjacent_live_bytes` (18497),
`mapping_drop_backstop_aborts_on_unmap_failure` (18900) — all exercise
`NativeMapping`/`ensure_identity_backed`/`zero_anonymous_reuse`/`repoint_private`
with no `LoadedImage`/xstate/fork/signal marker in their bodies. Task 2 should
re-verify each by attempting the compile, not trust this list blindly — it's
a heuristic pass over 55 functions, not a line-by-line read like the 23 above.

---

## 3. Cache capability matrix (Task 3 input)

### 3a. The architectural fact that governs every row

I read both sides in full before drawing conclusions, per the brief's
instruction. **aarch64 and x86 do not share the same concurrency shape today:**

- **aarch64** (`crates/carrick-dsr-aarch64/src/translator.rs:234-296`): ONE
  `ProcessTranslator { state: RwLock<ProcessState> }` is `Arc`-shared across
  **every** guest thread of a process. `ProcessState` holds ONE
  `cache: TranslationCache`, ONE `blocks: BTreeMap<(GuestVa, CodeGeneration),
  CacheVa>` (the block index — **shared**, not per-thread), ONE `pending:
  BTreeMap<..., Vec<LinkSite>>`, ONE `publications: ConcurrentPublicationIndex`
  (real cross-thread build-once dedup via Mutex+Condvar), ONE `dependencies:
  PageBlockDependencies`. Each `ThreadTranslator` is a thin per-thread cursor
  (`Arc<ProcessTranslator>` + small thread-local scratch); the translated-code
  corpus itself is genuinely shared and concurrently built by multiple guest
  threads.
- **x86** (`run_x86_thread`, native_freebsd.rs:12215-13963): each guest thread
  builds its **own private** `cache: HashMap<u64, CachedBlock, VaBuildHasher>`
  (line ~12274), its own `pending: HashMap<u64, Vec<PendingChainEdge>,
  VaBuildHasher>`, its own `cflow_plans`, its own `cursor`/`cursor_limit`
  bump-pointer into its own carved-out JIT slice
  (`SharedRun::alloc_slice`/`free_slice`, 10792-10804, handing out one of
  `JIT_SLICE_COUNT = 129` fixed `JIT_SLICE_LEN`-sized regions,
  10598-10604). **Nothing is shared across x86 guest threads at the
  block-index level.** Confirmed by direct read of `run_x86_thread`'s local
  variable declarations — no `Arc`, no lock, around `cache`/`pending`.

Full `ConcurrentPublicationIndex`/shared-`BTreeMap`-across-threads adoption
for x86 **is the Phase-3 thread-loop merge**, not a Task-3 data-structure
swap — the parent plan explicitly excludes the loop merge from Phase 2. The
matrix below is scoped to what's adoptable *without* that merge.

### 3b. Matrix

| x86 item | Lines | `carrick_dsr::cache` equivalent | Verdict |
|---|---|---|---|
| `cursor`/`cursor_limit` bump-pointer + inline capacity checks (`if cursor + linked.bytes.len() > cursor_limit {...}`) | inline in `run_x86_thread` | `TranslationCache::begin_write`/`CacheWriter`/`capacity_bytes`/typed `CacheError::Capacity` | **ADOPT**, via **EXTEND-SHARED**: `TranslationCache::new` currently calls `host.map_code_cache(capacity)` itself — it cannot wrap an *already-mapped* sub-range of `SharedRun`'s one big region. Add an additive constructor: `TranslationCache::from_region(region: JitRegion, host: &'static dyn NativeHostJit) -> Self` (skips the host map call, `cursor = 0`), plus `JitRegion::sub_region(&self, offset: usize, len: usize) -> Option<JitRegion>` (slices `exec_base`/`write_base` by offset, bounds-checked against `capacity`). Each x86 guest thread then gets a private `TranslationCache` over its own slice instead of hand-rolled bump arithmetic. Zero change to aarch64's existing `TranslationCache::new` path (`from_region` is a new sibling, not a replacement). |
| `CachedBlock` + `HashMap<u64, CachedBlock, VaBuildHasher>` (per-thread block index) | 11793-11800, `run_x86_thread` local | `ProcessState.blocks: BTreeMap` (shared, RwLock-protected) | **KEEP-LANE.** No cross-thread sharing exists in x86 today; adopting the shared/locked structure *is* the loop merge, and forcing a lock around a currently lock-free thread-private hot-path lookup would be a straight perf regression for zero behavioral gain before that merge happens. |
| `pending: HashMap<u64, Vec<PendingChainEdge>>` (per-thread) | 12269ish (declared in `run_x86_thread`) | `ProcessState.pending` + `PageBlockDependencies` (shared) | **KEEP-LANE**, same reasoning as above. |
| `VaHasher`/`VaBuildHasher` (FxHash-style u64-key hasher) | 10344-10370 | none — aarch64 uses `BTreeMap` (sorted), not a hash map at all | **KEEP-LANE.** No equivalent exists to adopt; x86-local perf optimization for a HashMap aarch64 doesn't have. Zero conflict. |
| `patch_slot`/`GuardedChainPatch`/`publish_guarded_chain_edge` (unaligned 4-byte rel32 patch inside a 5-byte jmp, **target-first** with a bare `Ordering::Release` fence, no atomic store) | 10379-10431 | `TranslationCache::patch_code_word` (**requires** `source.is_multiple_of(4)` alignment, does an `AtomicU32::store(..., Release)`) | **KEEP-LANE — this is the risk case the brief called out.** An x86 jmp's rel32 field is NOT guaranteed 4-byte aligned (it lands wherever the preceding variable-length instructions in the translated block put it); `patch_code_word`'s hard alignment check would reject many legitimate x86 patch sites outright, and even where alignment happens to line up, x86's chain-patch protocol is a **two-site, target-first, fence-ordered** publish (patch the guard's own far jump, fence, THEN patch the entry to point at the guard) — a fundamentally different publish shape than `patch_code_word`'s single aligned atomic word store. Already reaches the shared primitives it correctly should: `patch_slot` takes `region: &JitRegion, jit: &FreebsdHostJit` and calls `region.write_ptr_for`/`jit.flush_icache` directly — the *low-level* seam (write-alias translation + icache flush) is already shared; only the *patch protocol* (alignment contract, atomicity, ordering) is lane-specific, correctly so. Forcing unification here is exactly the "wrong call [that] corrupts JIT code under concurrency" the brief warned about. Matches the parent plan's own escape hatch verbatim. |
| `PublishedFaultEntry` (fault-shim scratch-restore side table: `host_start`/`host_end`/`guest_va`/`is_copied_x87`/`restores: Vec<ScratchRestore>`) | 11781-11787 | none | **KEEP-LANE.** Not a cache-scheme type at all — it's the x86 fault-shim's own bookkeeping for FPU-scratch restoration on a trapped instruction, no aarch64 analog attempted. |
| `PageGenerationTable`-style per-**page** fine-grained invalidation vs x86's coarse whole-`HashMap`-flush-on-any-`ExecutableGeneration`-bump (seen at the `cursor = 0; cursor_limit = JIT_SLICE_LEN;`-style resets in `run_x86_thread`) | n/a (x86 has no page-generation table at all; invalidation rides on `ExecutableEpoch`'s coarser epoch bump) | `PageGenerationTable` (`crates/carrick-dsr/src/cache.rs:53-200`) | **KEEP-LANE for Phase 2.** Adopting per-page granularity would be a genuine *behavior* change (finer cache retention across unrelated-page writes), not a plumbing swap — out of bounds for a behavior-preserving task. Worth flagging as a real Phase-3-adjacent opportunity once the loop merge makes a shared, page-tracked cache meaningful for x86 too; not a Task-3 action item. |
| `ConcurrentPublicationIndex` (cross-thread build-once dedup) | n/a | `crates/carrick-dsr/src/cache.rs:229-321` | **KEEP-LANE / not applicable.** x86 has no cross-thread cache sharing to deduplicate against today (§3a) — adopting the type without the sharing it exists to protect would just add unused synchronization. Becomes relevant exactly when the Phase-3 loop merge gives x86 guest threads a shared block index. |
| `JIT_SLICE_COUNT`/`JIT_SLICE_LEN`/`SharedRun::alloc_slice`/`free_slice` (carving ONE `JitRegion` into 129 fixed per-thread slices) | 10598-10604, 10792-10804 | none (aarch64 has ONE `TranslationCache` for the whole process, no slicing at all) | **KEEP-LANE** for the slice free-list mechanism itself (genuinely x86-lane-shaped: it exists *because* x86 doesn't share a cache across threads yet). What each slice **becomes** (a private `TranslationCache` instance via `from_region`) is the ADOPT target above — this row is about the carving/free-list bookkeeping, which stays. |

### 3c. Bottom line for Task 3

**ADOPT** the JIT-bytes bump-allocator layer only (`TranslationCache`/
`CacheWriter` via one additive `from_region` constructor + one additive
`JitRegion::sub_region` helper) — this genuinely replaces hand-rolled,
untyped cursor arithmetic with the audited, typed capacity-checking seam,
with **zero change to aarch64's existing construction path**. **KEEP-LANE**
everything that presumes cross-thread sharing (`ConcurrentPublicationIndex`,
the shared block/pending `BTreeMap`s) or presumes aligned-atomic single-word
patch semantics (`patch_code_word` vs x86's unaligned target-first guarded
chain patch) — both are correctly deferred to Phase 3, per the parent plan's
own "partial adoption with a documented boundary beats forced unification"
instruction. This is a **narrower** adoption than "adopt shared
`TranslationCache`" might suggest at first read of the plan title — the
capacity/publish machinery adopts; the concurrency model does not, because
x86 doesn't have one yet to unify with aarch64's.

---

## 4. STOP assessment

**No STOP.** Every finding above is resolvable additively, with zero required
changes to aarch64/shared-consumed *behavior*:

- The `ExecutableMutationAuthority` generic parameter (§0) is mandatory but
  purely additive — `ExecutableEpoch` gains one new trait impl, nothing about
  its existing body changes, and aarch64 never implements or touches this
  trait at all (its own lane has no equivalent coupling to route around).
- The `carrick-dsr-x86` routing correction for `ControlFlowMemory`/
  `X86XstateMemory{Reader,Writer}` (§0b) is a missing file in the parent
  plan's Task-2 list, not a design conflict — Rust's orphan rule forces the
  destination, and aarch64 has zero `cflow`/xstate-memory-reader-for-identity
  usage to disturb.
- The two `NativeHost` additions (§1c-i, §1c-ii) both ship with safe defaults
  (`None`/`0`); `DarwinHost` needs no override because Darwin's native lane
  never reaches `identity_memory`'s code at all. This is exactly the shape
  the parent plan pre-authorized ("lane.rs — MODIFIED: whatever minimal trait
  surface Task 2 actually consumes").
- The `identity_raw_range_tests` split (§2c) is a test-migration mechanics
  correction, zero production-code impact.
- The cache matrix's narrower-than-expected ADOPT scope (§3c) is explicitly
  sanctioned by the parent plan's own escape-hatch language for Task 3
  ("if the matrix says the x86 chain-edge publish protocol... can't map onto
  `ConcurrentPublicationIndex` without semantic change, KEEP-LANE that piece
  and adopt the rest").

**What Task 2 must NOT skip**, because getting any of these wrong compiles
clean and breaks fork/thread coherence or corrupts JIT code silently under
concurrency rather than failing to build:
1. Build `ExecutableMutationAuthority` and genericize `IdentityGuestMemory<A>`
   *before* attempting the mechanical move — attempting the move first will
   hit the backwards-dependency wall immediately (`cargo check -p
   carrick-dsr` cannot see `ExecutableEpoch`).
2. Route `ControlFlowMemory`/`X86XstateMemory{Reader,Writer}` to
   `carrick-dsr-x86`, not `carrick-dsr` (§0b) — the orphan rule will reject
   the wrong placement at compile time, but better to know now than mid-move.
3. Split `identity_raw_range_tests` per the table in §2c rather than moving
   it wholesale — a blind whole-module move will fail to compile against
   `identity_memory.rs` (references `LoadedImage`, `x87`, `parse_loadable_elf`,
   etc. that don't exist there) and the fix-by-deleting-failing-tests path is
   how real coverage quietly disappears.
4. For Task 3: do not attempt to force `patch_slot`/`publish_guarded_chain_edge`
   through `TranslationCache::patch_code_word`'s alignment-required atomic
   contract — per §3b this is architecturally unsound (rel32 patch sites are
   not guaranteed 4-byte aligned), and the brief's own warning ("a wrong call
   here corrupts JIT code under concurrency") is about exactly this move.
