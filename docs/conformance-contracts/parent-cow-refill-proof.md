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

## Portable exclusion component witness

`carrick-kernel::kernel::mm_occupancy::tests::cow_refill_excludes_sibling_through_publication`
reduces the refill exclusion schedule without a VM. Both runtime fault entries
now invoke `with_el1_editor_excluded`, the same scoped operation the witness
executes. The fixture owns aligned ABI storage, its settlement callback and
its grant pool; it does not replace the process-global carrier or settlement.

The initial editor consumes all 64 slots into USED records. Publication then
refuses once. Exact-MM exclusion settles all 64 records. A competing writer
tries to enter before publication; if admitted, it consumes the emptied chain
back into USED records. The host must publish a refill while that writer is
excluded, then release exclusion so the writer can retry and consume the
published grant. No timing, extra executor capacity or retry loop supplies the
ordering. The settlement callback frees real pool records; it does not perform
physical-frame inventory settlement or guest instruction execution.

The negative control restores the early guard-drop ordering that preceded
`fix(runtime): retain cow exclusion through grant refill`: settle, release,
then resolve. It isolates that ordering while keeping other candidate fork
fixes constant. This component control is distinct from executing the signed
binding against all merge-base fix files. The signed requirements above,
including original Python/Go workloads and core-based crash attribution, remain
unverified on this Linux runner.

Measured locally with `cargo test -p carrick-kernel --lib
cow_refill_excludes_sibling_through_publication -- --nocapture`:

- Negative control: insert `drop(_exclusion);` immediately before `resolve()`
  in `with_el1_editor_excluded`. One test executed; it panicked at
  `refill after Busy must publish`. Cargo exited 101:
  `FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3013 filtered out`.
- Restore the candidate function unchanged and rerun the same command. Cargo
  exited 0: `ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3013 filtered out`.

These are observed component results, not a claim that the unmodified merge
base or the strengthened signed fixture was executed. The old early-drop
ordering was read from both fault entries before the existing refill-scope fix.

The continuation also completed the focused kernel regular partition (2818
passed, one existing ignored), kernel serial partition (195 passed), and Linux
runtime library suite run serially (739 passed, six existing ignored). The
runtime population includes
`capture_core_gate_busy_once_then_reads_after_owner_release`. macOS cross-check
including Clippy, the freestanding x86 CPL0 release build, host `just clippy`,
contract-change coverage against admitted main, formatting and diff checks all
passed. Source authority debt passed both ceilings and the admitted-base range
ratchet (1266 source counters). These are host/component and compile results;
no signed artifact, native Docker comparison or KVM runtime result is claimed.
Whole-workspace lint-domains and test-kernel were left to CI as instructed.
