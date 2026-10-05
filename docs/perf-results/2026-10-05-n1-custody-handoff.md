# N1 structural custody and table-capacity retirement handoff

**Not review-ready: the signed gate is pending.** The structural lookup
omission and table-capacity retirement defects are repaired red-first in
VM-free production-path witnesses. The final code
and inventory snapshot is `5c8dba4288366b52b02e0e3376ac44ab65175e62` on
batch-seven main `80bc107de`.
This document's commit changes documentation only. No signed executable was
built or run in this turn; the preceding receipt's copyout **10/10** and
stage-six EBUSY remain evidence for that earlier artifact only.

## Fork physical custody: one authenticated authority

The preserved red overlay is now an active test:
`owner_fork_retains_live_structural_capacity_without_carrier_mm_alias_index`.
On predecessor `12c1c2bda` it fails 0/1 even though both selected physical
extents have live exact custody records. The legacy carrier-MM alias index
is empty, as it is for these structural backing owners.

`ForkPhysicalCustody::retain_extent` now resolves the **physical IPA** with
the existing `stage2_record_covering` authority. A global owner must match
that exact identity; structural backing is selected by its record ID.
The existing pin then authenticates the carrier VM and logical-owner
generation before any byte access. Existing extent and host-address checks
remain. There is no new index or guest-VA lookup.

All four owner-fork tests pass after the change. Original red/green commits
are `c0b3122de` / `b300c4fe0`; after the batch-seven rebase they are
`844dad6e1` / `ce442f619`. Live removal of stage-six EBUSY is not yet proven.

## Two live MMs: retire physical tables before returning capacity

Three production-path witnesses use two real pooled roots and retain the
peer's physical record while the first MM retires:

- `two_live_mm_bootstrap_retirement_releases_only_its_published_root_slot`:
  red because bootstrap teardown leaves its exact physical root live;
  green proves image revocation and exact slot reuse while the peer stays
  mapped, holds its slot, and preserves its sentinel byte.
- `two_live_mm_pinned_table_retirement_cannot_return_physical_capacity`:
  red because deferred pinned retirement returns success and releases the
  pool slot; green retains the exact owner and refuses capacity return.
- `two_live_mm_empty_inventory_releases_already_terminal_table_capacity`:
  red because physical-record removal is incorrectly treated as missing
  authority while MM metadata still owns the capacity; green releases
  that exact terminal capacity, including empty-data teardown, without
  changing the peer.

The first two are 0/2 red, the third 0/1 red. All three pass together after
the repairs. Original commits `64c335e4a`, `1c2411d87`, `37d07b989` rebased
to `230143c29`, `132a50527`, `a369a8502`.

`Stage1Authority::retire_table_capacity` holds its existing exclusion through
retirement of its published arenas, an optional exact root callback, and
terminal image/resolver/source revocation. Exec keeps the existing quiesced
image handoff. Task retirement also covers bootstrap roots without a child
root-slot receipt and MMs without data rows. Extension publication preserves
the relocated primary in the published-arena membership. A pinned record
cannot release a structural owner or pool slot; remaining capacity stays
quarantined on error. No carrier-wide walk or second retirement authority
was added. The bootstrap-table-custody contract names these witnesses.

The PR #56 investigation found separate parallel-fixture interference and
kept the normal runtime serial recipe. It did not prove that all shared
root-pool failures had one cause. These witnesses demonstrate physical
retirement defects; they do not claim full parallel runtime-test support.

## Validation and rebase

Before the rebase, clean `299b19ca1` passed full `just ci` and all eight
`just test-loom` models. Its HVF host suite passed 735 tests with three
existing ignores, including the four new witnesses. An earlier unsupported
parallel HVF invocation failed; the normal full serial suite exposed a test
fixture dropping the previously installed mapped pool. The fixture now
retains/restores that pool through an RAII guard. The documented serial
recipe is unchanged; no serialization was added as a symptom fix.

During fixture publication, the director reported batch seven on main and
requested a rebase. The complete N1 stack was rebased onto `80bc107de`.
Conflict resolution preserves both contract surfaces, N1's child owner
copyout, and PR #56's exact-task failpoint admission. The range diff was
reviewed. Clean reconciliation retains 663 authority rows and 621 compiler
capture rows, rebinding eight host sites, 32 K1 positions and 12 executor
abort fingerprints without classification or debt changes.

Final clean-tree **`just ci` passed**, including integration, and
**`just test-loom` passed 8/8** on `5c8dba428`. Its HVF host suite again
passed 735 tests with three existing ignores, including all four new
witnesses. No production source changes followed these checks. The final
push uses an exact force-with-lease from the verified pre-rebase remote
`299b19ca11756dab8444227970af12b6df9145f4`; it does not write to main.

Raw red/green logs, both CI/loom runs, rebase range diff, publisher/cleanup
receipts, the source patch and the prepared gate script are retained in
`target/n1g5/custody-handoff-5c8dba428/`, with `SHA256SUMS`.

## Pre-rebase bundle retained, not restored

The trusted native Linux VM ran
`just fixtures-publish 299b19ca11756dab8444227970af12b6df9145f4` in detached
`/home/carrick/dev/wt-n1g5-publish-299b19ca1`.

Manifest address:
`e6796cb59db805deb52ac89b61d489874149281bbdbdd1b87f4b864b792cb46d`.
Archive SHA-256 matches on VM and Mac:
`1b63229aa8a348c5d92d6e8fefc9dc694e09d3fbad3c87a213d0d36454ad25c4`.
It is retained in `target/fixtures/published/299b19ca11756dab8444227970af12b6df9145f4/`.
Only this turn's temporary VM worktree and fixture transport ref were
removed; the cleanup receipt lists no such worktree/ref. No Docker was
started or used. This bundle is not acceptance evidence for the rebased SHA.

## Director-reported fork diagnostic and ownership split

After the first handoff push, the director reported cloudmac results from
`n1-cm` on **pre-rebase `299b19ca1`**. VMA, MAP_FIXED-over-COW, ptrace and
spawn still fail at fork, with a reported `OWNERFORKREFUSAL1` EBUSY errno 16,
stage 6, parent MM 2, child MM 3, generation 12. That capture has
`bounded=1`: it is diagnostic only, not qualified acceptance. Fork-COW gets
past the former root-slot collision but fails fork round 0 at pages=16.
These are director-reported results; this Mac turn has not inspected the raw
cloudmac receipts or independently repeated them. The exact-record lookup
witness repairs one omission and does **not** close the live fork class.

The latest owner direction assigns all five fork-class tests and their
refusal probe to `n1-cm` on cloudmac. This Mac retains copyout, hello,
anonymous/brk and clear-child-tid. Do not re-edit the stage-six custodian
without notifying the director, to avoid overlapping the fork worker.
Integrate its fixes at a committed boundary before final acceptance. Its
`299b19ca1` results cannot be combined with this rebased HEAD as same-SHA
acceptance. The old bundle remains available at the local retained path
above even though its temporary publisher worktree was removed.

## Next exact-SHA gate

Publish a new bundle for the final pushed HEAD on the trusted Linux VM,
transfer and verify its archive hash, then restore it inside the one
exclusive `gate` host lease. The prepared foreground gate script is retained
with this turn's evidence. It performs `just fixtures-restore`, `just build`,
standard signed embed hello and its unentitled negative control, CLI hello,
the six comparisons, ten uninstrumented 300-round copyout runs and the two
fork refusal captures on unchanged retained signed artifacts. It records
SHA-256, CDHash, LC_UUID, hypervisor entitlement, DOF and per-run scoped
cleanup. It is the original full-gate script; adapt the invoked scope to
the director's split only after the fork worker covers the **same final
SHA**. No signed gate or partial signed retry was consumed in this Mac turn.

Report every comparison against the recorded main `51bfe67f4` failure mode
from the [batch-five receipt](2026-10-04-n1-batch5-gate.md), also summarized in
the [full-suite investigation](../2026-10-05-storm-full-suite-investigation.md):

| Test suffix (`el1_`) | Historical main failure mode | Current signed result |
|---|---|---|
| `anonymous_reservations_stay_in_guest` | Guest `ok=true`; zero EL1 mmap serves versus >=64 required. | Pending |
| `delegated_root_concurrent_vma_ops` | Parent and child `ok=true`; zero serves versus >=32 required. | Pending |
| `delegated_root_map_fixed_over_cow_pages` | Guest `fixed_maps=12 ok=true`; zero replacements versus >=12 required. | Pending |
| `fork_cow_resolves_in_guest` | Both sides verify 320 pages with isolation `ok=true`; exits exceed ceiling 144. | Pending |
| `thread_lifecycle_ptrace_traceclone` | Fork and initial stop work; SETOPTIONS returns ENOSYS 38. | Pending |
| `thread_lifecycle_spawn_slope` | Parent and child workloads work; clone forwarding slope exceeds 0.05. | Pending |

This is a historical comparison, not a fresh main control. No runtime
budgets were widened, concurrency reduced, or retries introduced. N1 can be
reported review-ready only after copyout is 10/10 on the final artifact and
none of the six fails worse than main. Serving/exit-budget work remains
N2/N3; earlier guest failures remain N1 blockers.
