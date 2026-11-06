# Native fork refusal: unresolved reproduction

Part of #1742. This investigation does not identify the signed crash's root
cause, change runtime behavior, or establish a passing Go population. The
admitted checkout already contained main's changes; rebasing onto the admitted
main ref required no replay or conflict resolution.

The director's signed trace files are on a Mac volume unavailable to this
Linux worker. The brief reports `ForkCustodyRefused`, `Mm(Stale)` at Prepare
or Publish, and occasional telemetry `bad address`. Those observations do not
identify one common stale authority.

## Distinguish the authorities before changing the checks

`ReservationRoot::incarnation` is stable for a live root occupancy, whereas
`generation` changes with policy edits
(`crates/carrick-core/src/mm/reservation/root.rs`, `incarnation`). The ARM
child's `AddressContext::generation` is constructed from the completion's
child **incarnation** (`aarch64_process.rs`, `prepare_mm`). It must not be
treated as the parent's mutable reservation generation.

The Prepare check at
`crates/carrick-el1-linux/src/mm_portal/fork.rs:302` compares the live parent
incarnation, reservation generation, and operation sequence with the loan's
request. Publish additionally compares every previously observed descriptor
word in `crates/carrick-core/src/mm/fork.rs:354`, then checks those three
parent identities. A `Stale` at either stage alone does not reveal which
comparison failed.

The later host custody check is different. `ForkStock::settlement_loan` at
`crates/carrick-hal/src/fork_stock.rs:2008` compares the loan's complete
`GrantExecution` with the currently observed execution. That includes CPU,
execution binding, root, MM, and context generation. HVF obtains a fresh
stopped execution for each crossing in `service_native_fork_stock`
(`crates/carrick-vmm-hvf/src/metadata_grant.rs`). A rejected Commit becomes
`ForkCustodyRefused` through `AdmittedCustodyToken::consume` and
`quarantine_born`; that fatal name alone does not identify its host refusal.

These are candidate refusal sites, not a diagnosis of the Go failure.
Removing generation authentication or translating every Stale to Busy would
also hide real reused-root or changed-execution errors.

## What the existing VM-free harness lacks

The existing tests exercise useful pieces but do not compose the requested
two-live-process schedule across the production physical boundary:

- `vfork_parent_stays_suspended_until_child_execs_or_exits` uses the generic
  `Physical` service. Its `prepare_mm` ignores the parked context, constructs
  a synthetic child root and initial context generation, and publishes a
  closed space. It does not run the ARM owner-fork preparation or the stock
  settlement authentication.
- `TestStockCrossing` normally accepts Reserve and Commit directly. Its
  optional `PhysicalStock` adapter does use the real HAL stock owner, but
  `PhysicalStock::loan` caches `GrantExecution` from the request.
  `reserve` and `commit` reuse that cached value. Unlike HVF, the adapter
  does not reread the stopped lane's binding, installed root and generation
  at each crossing. A lane identity drift is therefore invisible there.
- The test named
  `fork_reservation_refusal_from_concurrent_munmap_rolls_back_without_quarantine`
  injects `ForkStockRefusal::Inventory` through `refuse_reserve`. It does not
  perform munmap, change the parent's live reservation generation, or prove
  that the reported native-fork refusal is contention.
- The vfork model intentionally uses a distinct COW child MM. It verifies
  the supplied child stack pointer and parent release ordering; it does not
  execute Go's raw-vfork instruction sequence or share writable stack bytes.
  This is an existing implementation property, not a new reproduction.

## Next useful reduction

Extend the physical-stock adapter to observe the live stopped lane at every
crossing, retaining the existing immutable loan identity separately. Compose
that with an actual native parent and child, and a bounded checkpoint that
permits a real owner MM operation between fork census/loan and preparation
or publication. Assert the exact changed authority and unchanged peer MM;
injecting an errno or changing only a task atomic is insufficient.

First establish whether this schedule matches the director's trace. Capture
the request and current parent incarnation, reservation generation, operation
sequence and descriptor comparison, plus the loan/current execution at the
refused custody crossing. The existing Carrick trace workflow should carry
that evidence, rather than adding guest logging. The contracts implicated
are `kernel.el1.fork-cow`, `process.native.arm-admission`, and
`kernel.el1.mm-exclusive-owner`; none gains acceptance from this document.

No runtime fix is proposed without that red witness. Signed paired base/head
populations, ten Go verdicts per artifact, and signed artifact provenance
remain required on the director's Mac. Linux KVM availability cannot supply
the missing HVF evidence.
