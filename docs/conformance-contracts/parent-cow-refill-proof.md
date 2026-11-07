# Parent COW refill: outstanding signed proof (#1733 / #1805)

The confirming review's P1 remains open. The strengthened
`el1_fork_cow_parent_replenishes_used_grants` binding has no recorded signed
red/green result. Its existing contract is `kernel.el1.fork-cow`; this note
does not change that contract or confer acceptance.

The fixture writes 192 distinct compounds using two live sibling writers,
keeps the child alive to check isolation, and requires more than 64 grants,
at least 192 settlements and EL1 copies, and zero carrier stage-fault host
COW transactions. A passing output line alone does not satisfy those checks.

## Required execution

On an authorized macOS/ARM signed lane, retain the strengthened test and its
fixture while restoring the production fix files from the PR merge base.
Rebuild the signed executable and fixture through `scripts/test-signed.sh`,
selecting `CARRICK_TEST_TARGET=el1_sched` and the exact filter
`el1_fork_cow_parent_replenishes_used_grants --exact --nocapture`.
Record the actual assertion failure, complete output and executed population;
a build failure, unavailable platform or missing fixture is not red proof.

Restore the production files from the candidate, rebuild and run the same
binding. Record its success and all grant, pool and host-COW observations.
Keep source and fixture identity, binary hashes, signing identity and scoped
cleanup evidence for both artifacts. If the base passes, tighten the witness
and repeat the comparison rather than claiming it demonstrates the defect.

Also isolate the refill exclusion change in
`crates/carrick-runtime/src/vcpu_loop/binding.rs`: hold the remaining candidate
fixes constant and restore the pre-exclusion behavior at both fault entries.
This distinguishes failure caused by other fork fixes from proof that the
refill exclusion itself is necessary. Restore both entries before green.
The relevant correction retains the exact MM editor exclusion through
`resolve_frame_cow_fault`, including grant publication, instead of settling
USED records and releasing exclusion before provisioning.

Publish the measured red and green details in a commit body and PR evidence.
Until those runs exist, the review finding remains unresolved.

## Dispatch host limitation

The continuation runner is Linux x86_64. The signed runner rejects it with
`test-signed: macOS/HVF only` before executing a test. That refusal establishes
only an unavailable execution layer. A local KVM device cannot execute this
HVF/AArch64 binding, and cross-compilation cannot supply its runtime proof.
No red or green signed result is claimed by this continuation.
