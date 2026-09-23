# Carrier native data grant: concrete approval boundary

Status: **explicitly approved by the user and implemented on 2026-09-22**.
See [implementation and validation](../native-carrier/README.md). The proposal
below preserves the approved boundary. At the earlier review checkpoint, the
HAL/HVF edit had been rejected before execution and runtime source restored;
`proposed-composition-test.rs.txt` and `red-api-clean.log` preserve that API red
(two missing-method errors). It is not a semantic regression or speedup result.

## Proposed change

Contract: `kernel.execution.native-synchronous-syscall` remains unresolved.
Introduce a data-only grant whose lifetime borrows all of:

- the exact current `KernelContext` and `ThreadExecutionLease`;
- an authenticated `CowBroken` witness for that same task/MM and range;
- the existing exact-MM `MmMutationGuard` retained by `CowBroken`;
- the carrier's current generation of pinned host backing.

The intended API is `KernelContext::borrow_current_native_data(execution,
&mut cow) -> CurrentNativeData`. The result supplies `start`, `len`, and an
**unsafe** raw pointer accessor. It must be non-Clone, non-Send and non-Sync.
The unsafe caller must stay inside the grant's range/lifetime and may not
re-enter syscall dispatch or MM mutation while the grant is live.

The first grant is deliberately scoped to an existing COW mutation transaction.
It is **not** a concurrent execution-quantum permit, nor a per-syscall fast path.
No timing obtained while holding this exclusion will be used as an execution
performance claim. After this ownership proof, normal quantum admission and
revocation must be integrated without serializing independent guest execution.

## Exact implementation surfaces

1. `crates/carrick-hal/src/foreign_mm.rs` and `src/lib.rs`: add an optional
   `ForeignNativeDataSpan` transport capability. Default implementations refuse.
   The opaque endpoint rejects executable ranges. The transport must return
   pinned resident backing, never a copied or fabricated fallback buffer.
2. `crates/carrick-vmm-hvf/src/trap/foreign_mm.rs`: factor the existing prepared
   write's contiguous-span validation into one internal helper, preserving its
   copy behavior. The grant reuses current stage-1 translation, inventory mapping
   and frame identity, exact owner generation and owner pin. For native access,
   additionally require user-RW leaf permissions and a writable protection range
   across every crossed page; a foreign-write receipt alone cannot grant direct
   guest stores. Preserve the existing prepared-write and ptrace semantics.
3. `crates/carrick-kernel/src/kernel/mm_access.rs`: authenticate the exact live
   execution lease, same task/MM/kernel identity, COW kernel proof and mutation
   guard. Validate the entire range as readable, writable and non-executable.
   Verify transport receipt and live backend/VMA/inventory revisions before
   yielding the scoped capability. Store the actual borrows, not only a counter
   or PhantomData standing in for a dropped authority.
4. `crates/carrick-runtime/src/vcpu_loop/memory.rs`: extend the existing composed
   production-carrier fixture. The saved proposed test resolves actual COW,
   rejects the wrong execution lease, performs a bounded native load/store on
   the pinned carrier bytes and reads the result through the public kernel API.

No product execution backend, CLI default, signal policy, contract budget or
benchmark baseline is to change. No general raw-pointer API for syscall handlers
is proposed. The experimental ELF executor remains unchanged until this grant
and the necessary execution/publication lifecycle are proved.

## Required proof before using the grant

- API red retained in `red-api-clean.log`; it names only the absent method.
- Same VA in two real MMs yields separate bytes. Wrong task, wrong kernel,
  wrong or transferred execution lease, and stale owner cannot acquire a grant.
- Execute-only, read-only, RX/RWX and a range crossing a denied page refuse.
  A live guest read-only leaf must refuse even if a foreign-write receipt exists.
- A real COW copy protects original backing. Identity/private and copied cases
  both retain the exact current owner generation, with no buffer-copy fallback.
- Changed VMA/inventory/binding, unmap and permission restoration invalidate old
  witnesses. Borrow/lifetime checks prevent a grant escaping its mutation scope.
- Rerun current-MM, prepared-write, ptrace, COW composition and native executor
  tests. Keep the same artifact/evidence ladder; this does not close the signed
  native execution contract.

## Why approval was requested

Automatic approval review rejected the action with:

> This introduces a new unsafe raw-pointer data capability and rewrites core
> HAL/HVF memory-authority code, creating a meaningful memory-safety and
> guest-isolation risk beyond the user's general performance authorization.

The rejected edit was not applied or tested in another checkout. The user
subsequently explicitly approved this specific low-level capability and its
supporting core refactor. That request came from automatic approval review,
not an additional approval rule inferred from the conformance skill.

The remaining shared-quantum, executable-alias invalidation, signal/cancellation
and scheduling obligations are unchanged. Previous performance results remain
those recorded in [native-memory](../native-memory/README.md).
