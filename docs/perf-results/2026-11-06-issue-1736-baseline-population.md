# Issue #1736 baseline signed population

**Historical evidence; issue acceptance remains open.** The populations below
belong to the two artifacts identified here. They are not populations for the
current PR head. The failure mode was inferred from fixture output, not named
from a captured core or event ring. The outstanding synchronous sibling
completion obligation is described in
[anonymous editor publication](../conformance-contracts/anonymous-editor-publication.md).

Source revision: `0d5dfaa508e5b92edbe2b18404cd2c7d4230f719`

Fixture bundle:
`de1c1bd060c311e46d9afd37adf53f835ac7bd5697d994e1ae6feda937d2aa9f.tar.gz`
(input identity
`1e769b2a8667733a568d456e233f99ea3369f46da83f8a036d78a86a6ffe16b1`).

The signed test executable was
`target/release/deps/el1_sched-24da1b99c955c4f7`, SHA-256
`085ff7de9ed8304b321282bf210c7a51c3b1055205b4868eb4e3b6167e70ca76`,
CDHash `5a558aee661a67f99856b62707353051eff3b3fb`, LC_UUID
`334C96A5-0A95-3968-9D8D-F2E5B97222F0`. It carried the hypervisor
entitlement and `__TEXT,__dof_carrick`.

Each invocation used an exact libtest filter under `just lease carrick`.
Every run completed its unentitled negative control and run-ID-scoped cleanup.
Raw logs are under `target/issue1736/population-before/`.

| Signed test | Pass | Fail | Failure mode |
|---|---:|---:|---|
| `el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation` | 20 | 0 | none observed |
| `el1_tlb_fork_and_exec_leave_no_stale_translation` | 19 | 1 | stale writable parent translation on run 16 |

The failing fork fixture completed normally: no alarm, command timeout, signal,
or Carrick panic fired. It reported `child_failures=1`,
`parent_failures=0`, `errors=0`, and `timeouts=0`. The child waits until the
parent's CPU-1 worker performs its post-fork write. A child failure therefore
means that write used a stale writable translation and modified the frame that
the child inherited, instead of faulting through the fork's COW-armed parent
descriptor. The enclosing Rust test then panicked only because the fixture
returned exit status 1.

## Diagnosis and negative control

The worker is pinned to guest CPU 1; the fork editor and invalidation run on
guest CPU 0. Bounded `hvpatch-mm-reuse-isolation` traces identified the live
parent as MM generation / architectural ASID 53. All 30 traced attempts
passed, so the trace perturbed the race; the untraced failure above is the
authoritative stale-translation witness.

The first hypothesis strengthened the barriers around CPU 0's `TLBI
ASIDE1IS` from `DSB ISHST` / `DSB ISH` to `DSB SY`. Its exact signed
population was still 19/20 for fork/exec, with the same
`child_failures=1` mode (run 10 under
`target/issue1736/population-after/fork-exec/`). The stronger barriers were
therefore removed rather than treated as closure.

The deterministic red witness was
`each_vcpu_covers_a_foreign_cow_publication_for_itself`. Slot 1 invalidated
publication 1 and advanced the address-space-global coverage word; slot 2's
production install then incorrectly returned `cow_owed=None`. The missed
operation was slot 2's own local invalidation of publication 1. A guest
broadcast invalidation was being recorded as coverage for virtual CPUs on
which it had not completed.

## Earlier candidate signed population

Fix revision: `e4b20d690ec64290157ab24c328b7ca719b5d437`.

The exact signed executable was
`target/release/deps/el1_sched-24da1b99c955c4f7`, SHA-256
`3fe8c2891f4cc8f3cf4b8a28ac5cdbd0ba98eae743f6043ca03dfd9113e32f63`,
CDHash `6e8975f3652c775eb8af460f1ce068ff5ed5169c`, LC_UUID
`DC6B1133-22CC-3924-9B93-8EECC339112A`. It carried the hypervisor entitlement.
Each run had a distinct `CARRICK_RUN_ID`; every post-run process census was
zero. Raw logs are under `target/issue1736/population-final/`.

| Signed test | Pass | Fail | Failure mode |
|---|---:|---:|---|
| `el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation` | 20 | 0 | none |
| `el1_tlb_fork_and_exec_leave_no_stale_translation` | 20 | 0 | none |

The fix retains a monotonic descriptor-publication generation per address
space but moves completed coverage to each vCPU slot. Fork, `mprotect`, and
`munmap` publish a generation. A slot entering that MM must perform
its own local invalidation before it may keep or install the root, and only
then records its own coverage.

This entry check cannot acknowledge an already-running sibling or an installer
holding an older grant. Consequently, the observed 20/20 candidate population
does not prove that synchronous permission changes or frame retirement wait
for those siblings. No fresh signed population was run on the Linux dispatch
runner, which cannot execute HVF guests.
