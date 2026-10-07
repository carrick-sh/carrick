# x86 anonymous CPL0 handoff (partial, 2026-10-07)

## Current continuation checkpoint (2026-10-07)

Guest payload adapter d5157d2c2 and the exactly restored two-MM witness
d37570d90 are pushed to github/work/x86-process-owner. Shared numeric/serial
allocation extraction is committed at 89aefd595; checkpoint gate
receipts are appended below. The two-MM witness remains red at fork ENOSYS
(exit91), with native Q/exit7. No CPU1, two-MM green or review-ready claim.

The director confirmed two next-step authority choices: pure PID collision/
claim and serial allocation belong in sched-core with thin native/host
wrappers; the initial task/namespace/group/session/claims transfer from the
real host launch once via a typed, counted boot crossing. Then host identity
mutation for that VM refuses. Delete task41/generation11/thread101/PID41.
The director subsequently confirmed moving visible PID/TID selection into
the same shared owner; host NsSharedRegion retains publication only for HOST
lanes. After seed transfer CPL0 must not mutate host arena membership.
Guest-created nested PID namespaces must refuse with counted ENOSYS.

The director resolved allocation policy: one OWNER with both existing
policies. Internal collision-domain IDs recycle only after all roles release;
visible PID/TID IDs remain monotonic and burn aborted preparations. The
shared API uses distinct InternalIdentity and VisibleIdentity types.
The visible extraction now delegates to that owner: region adapters retain the exact
shared owner, refuse foreign allocators, and remove their cursor on exact
namespace retirement. The original missing-selection red is /tmp/x86-cont-visible-red.log.
The typed shared suite passes 165/0 in /tmp/x86-cont-visible-typed-green.log;
the exact host adapter test passes in /tmp/x86-cont-visible-const-adapter.log.
Typed accessors preserve the host wrappers' const API. Its first compile
failure is retained in /tmp/x86-cont-visible-typed-adapter.log; it is not
semantic evidence. Focused clippy and committed domain checks follow.

The MM scope decision is also resolved. CPL0 MM/object serials are VM-local;
any crossing into a host table shared by multiple VMs must use a typed
(VM instance, local identity) key. Leave process-global CARRIER_MM_IDS and
file-description serial counters untouched for ARM/HVPatch and other kernels.
Never clone a high-water mark or freeze those global allocators.
Current production boundaries: CarrierMemory owns one KvmVm plus private
roots, aliases and memslot maps; Cpl0Carrier constructs its own separate
FrameInventoryAuthority. These tables are not process-global. Audit public
physical capabilities (BackingHandle/SharedFrameEdge) and any future shared
inventory boundary for exact VM origin before permitting inherited frames.
Add two live/simulated VM scopes issuing the same local MM without collision.
Boot binding and the production two-MM witness remain open.

Native prerequisites still include ELF/stack VMA and initial residency
import, retained frame-level inheritance, per-MM InitialWords, real stack
COW and production ProcessNative/CPU1 execution. Keep InitialWords as the
sole descriptor editor and PR82's sole #PF. Do not substitute fixtures,
host process policy, invented claim custody or legacy mailboxV2 COW.
The arena prefork test remains a known pre-existing red, separately routed;
a passing host gate here does not close it. No Docker or signed/HVF run.

## Historical registry-foundation gate status: labelled work-branch push

PR102 follow-up 83364467d is pushed. The extraction registry foundation
through 6f1fa5b87 is pushed to github/work/x86-process-owner, and no extraction review-ready or two-live-MM
milestone is claimed. Full host, separate kernel-semantics, clippy and clean
Linux domain lint pass. N1's inherited ARM hvc #3 difference is unchanged;
comparison against imported shared-kernel 6d6bcf26c has zero failures.

The committed post-format KVM build first failed before VM execution because
nested Cargo build-script outputs retained linker script paths into deleted
/tmp/wt-x86-review-attribution. Targeted cargo clean of carrick-el1 and
carrick-x86-cpl0 in the three affected nested image target directories
removed those stale outputs (285.5 MiB). No source shim or fake linker script
was added. The fresh-image full KVM run then reports 127 passed, one failed,
and five existing ignores. The sole failure is the separately owned known
shootdown test: two_running_vcpus_drop_stale_translation_on_shootdown,
cpl0_entry.rs:1264, "running CPU must acknowledge shootdown". The earlier
same-code gate reported 128/0/5. This is not retry-until-green; the fresh
red gate is authoritative. The director explicitly authorized pushing this
work branch with this separately owned red labelled. Pure 7d6daf287 failed
22/50 runs; the independent review comparison failed 25/50. These A/B
numbers attribute the defect and do not claim closure. Shootdown code
was not edited. The director was notified with ref 09df94f4e.
Receipts: /tmp/x86-process-registry-{committed-kvm,clean-image-kvm}.log.

Continue the wait scan/consume/wake-generation extraction, then owned exit
transactions and production CPL0/CPU1 binding. The shared-lane shootdown
owner must close its gate; do not patch it here. The two-live-MM PRIVATE,
no-cross-MM-alias and exact-root-incarnation/generation witness remains red
at its pre-fix checkpoint and must go green before claiming the milestone.

## Shared wait transaction milestone

50cdc3aac moves the production wait selector and consuming reap into the
same scheduler-core registry. Host wait APIs delegate child/tracee matching,
clone classes, live/retiring population, wake sampling, zombie removal,
group retirement and subtree CPU charging. Host code retains primitive
resource access, wire rendering, namespace retirement and audit effects.
A consuming read precheck returns readiness without cloning a zombie;
write admission rescans and checks parent/child reservations and revision
capacity before any reap. Wake generation crosses the adapter as a named
type. Host serialized precheck/outcome wrappers do not select a population.

Red evidence: the shared API is absent before the extraction; PID-only
matching fails the stale-serial assertion. An isolated global-population
scan fails the unrelated-read budget at 1 versus 0. Its exact sources/base
and hashes are retained in /tmp/x86-process-wait-budget-red-source; the
scratch worktree was removed. Seven shared tests pass, covering two
children, observe/consume, exact serials, live retirement, clone versus
non-child tracee stops, admission failure, one CPU charge, non-Clone UID
prechecks and 1/8/32/128 children with 512 unrelated live processes.

Step verification: full just test and separate just test-kernel-semantics
pass. Full clippy, formatting and clean Linux domain lint pass. The two
existing child-reaping abort fingerprints were rebound, preserving their
classifications/domains/rationales. N1 comparison retains its inherited
ARM hvc #3 difference; comparison with 6f1fa5b87 is 114/114 blocks with
zero changes/failures. Required foreground KVM is 127 passed, one failed,
five existing ignores; its sole red is the separately owned shootdown
acknowledgement failure, covered by the director's work-branch push
permission and the 22/50 versus 25/50 attribution above. No retry, new
ignore, shootdown edit or second #PF entry was added.

Receipts: /tmp/x86-process-wait-{red,generation-red,budget-red,
final-style-unit,frozen-test,kernel-semantics,final-clippy,final-domains,
asm-n1,asm-parent,kvm,aborts}.log. The first development host run caught
one missing typed-wake-to-wire conversion; it was fixed before the frozen
host gate. Clippy's result-type/conditional findings were fixed without
allow attributes, and the focused tests and full clippy were rerun.
Signed HVF is unavailable here. Reserved exit/reparent transactions and
production CPL0 lifecycle/CPU1 binding remain next; the two-live-MM PRIVATE
witness is not green, and no PR or review-ready is claimed.

The fetched shared-kernel ab1655fcc adds another #PF in native_irq.rs.
The director was notified; merge its reworked single-production-entry fix
when available, without authoring shootdown changes in this lane.

## Latest process-owner continuation

PR102 follow-up 83364467d is pushed. Extraction identities were rebased onto
it as 28880ba48; b1331db4e repairs the stale neutral fault-owner assertion.
c75bf28d7 moves live/retiring/zombie/reservation and namespace-index storage
into scheduler core, with host resource payloads and a fatal-reporting
adapter. The host registry and group/session records are aliases of those
shared types, not duplicate maps. Host kernel compile-check and shared
scope/collision tests pass. Removing the namespace collision guard makes
its test fail; restoring it passes. Registry-step kernel-semantics passes.

Full host runs before shared-kernel integration remain red at the missing
embed-copyout input inventory; the earlier identity run also saw a pre-fork
record failure. Director-required sequential fixed-50 A/B reproduces that
same published-record/parent-zero assertion on pre-extraction 83364467d
(6/50) and extraction c75bf28d7 (5/50), with separate artifacts. Receipts:
/tmp/x86-prefork-{base,extraction}-fixed-50/{1..50}.log and status.txt;
/tmp/x86-prefork-ab-artifacts.sha256. This is attribution, not closure.
The director has been asked to route that defect. No arena test/code was
changed, and no retry-until-green or new ignore was added.

The director authorized merging shared-kernel 6d6bcf26c for its existing
fixture input and shootdown fixes. Its main rebase changes ancestry; the
71 initial conflicts resolved cleanly using previously merged 7d6daf287
content as the three-way base. This retains our reviewed changes and that
lane's fixes without editing its shootdown bodies. The merged host kernel
compile-check and fmt-check pass; full post-merge gates remain required.

Exact next step: finish post-merge host/kernel-semantics and push gates,
then extract the authoritative wait scan/consume and wake-generation sample,
followed by owned exit/reparent/SIGCHLD transactions. Registry storage alone
does not complete the owner. Production CPL0 lifecycle/CPU1 binding and the
two-live-MM PRIVATE witness remain open; no extraction review-ready is claimed.
Latest receipts: /tmp/x86-process-registry-{check,unit,collision-red,test,
kernel-semantics}.log and /tmp/x86-process-shared-{merge,check,fmt}.log.

Post-merge integration verification: just test and just test-kernel-semantics
pass; full required KVM passes 128 tests with five existing ignores (none
added). Clippy passes. The imported shared-kernel shootdown fix owns that
change; no new shootdown implementation was authored here. The director
accepted and routed the pre-existing pre-fork failure using the fixed-50
6/50-before and 5/50-after evidence above; a passing single host gate is not
closure of that defect. Assembly comparison against imported 6d6bcf26c has
zero failures/no new ARM drift; N1 retains its known inherited ARM block.
Domain lint initially caught an automatic merge duplicate signal-core
package in the scheduler fixture lockfile; the duplicate was removed and
Cargo refreshed its path closure, retaining root-locked dependency versions.
All seven fixture lockfiles validate. Receipts:
/tmp/x86-process-shared-{test,kernel-semantics,kvm,clippy,asm-n1,asm-import}.log
and /tmp/x86-process-fixture-lock-{update,pins,check}.log. Final clean-tree
lint and push remain to run; wait/exit/CPL0/two-live-MM remain unimplemented.

## Shared registry retirement continuation

The final-member group/session retirement decision now lives in the same
scheduler-core registry as its namespace indexes. The host helper delegates
its unchanged logic. The focused test refuses retirement by a stale task
serial and preserves another namespace's group/session after the real last
member retires. Both namespaces use distinct internal task keys. The missing
shared method is red at the prior checkpoint; replacing exact TaskKey removal
with PID-only removal is also red at the live-group assertion. Exact removal
passes all three shared registry tests. Full `just test` and separately
`just test-kernel-semantics` pass for the moved implementation; the final
unit test was rerun after giving the peer namespace its distinct task key.
The host-lease abnormal-fork negative control prints an intentional child
failure; its containing test and the complete host gate exit zero.
Receipts: /tmp/x86-process-group-retirement-{red,generation-red,green,
final-unit,test,kernel-semantics}.log.

Registry audit inventories retain classifications and family counts. The
only retired K1 mapping row was Zombie documentation moved outside that
inventory's source roots; no file-authority operation was removed. Seven
runtime aborts retain their domains/verdicts/rationales while their owning
function names are rebound. The guarded macOS compiler recapture for
cfc251a07ac0 refreshed moved source spans and receipt provenance. Static
validation agrees exactly; captured operations/profile memberships and
review classifications are unchanged. Patch/receipt:
target/remote-recapture/cfc251a07ac0-recapture-20261007-112329/recapture.patch;
/tmp/x86-process-registry-recapture.log. Signed ARM runtime tests did not run.

An overlapping next-step source edit caused the first post-recapture lint
attempt to refuse dirty compiler snapshot inputs. This is not a gate pass;
clean committed-tree lint and final push gates must run after this step.
The process registry's population payloads remain host adapters; the full
wait scan/consume/wake-generation and reserved exit/reparent transactions
remain in the host kernel. They must move before any production CPL0 fork,
wait, exit, CPU1 or two-live-MM PRIVATE witness can be claimed. Do not promote
the stopped lifecycle fixture in process.rs as production policy. Preserve
InitialWords as the only production descriptor-window authority.

## Registry checkpoint push evidence

Clean-tree `just lint-domains` passes after an explicit review-to-site repair:
partial-profile ordinal reconciliation had exchanged the common execve
argument event and the macOS-only image snapshot's PID call. The two existing
reviews are bound to the actual `execve_argv` (7541) and
`host_image_base_snapshot` (7587) sites, preserving operations,
classifications and profile sets. Their rationales now describe their exact
current-carrier diagnostic roles. The independent Linux compiler census and
stored live macOS capture both agree; the macOS receipt was not fabricated
or edited for this repair. Receipts:
/tmp/x86-process-final-linux-{candidate,reconcile}.log and
/tmp/x86-process-registry-qualified-lint.log.

The retirement step's full host and separate kernel-semantics gates pass.
Full KVM passes 128 tests with five existing ignores; clippy passes, with the
existing Linux-only unreachable macOS libc catalog warning. Formatting is
applied and pre-commit checks pass. Assembly against imported 6d6bcf26c has
zero failures; N1 reports only the inherited ARM fatal_entry_binding hvc #3
block (not new drift). Receipts:
/tmp/x86-process-registry-{final-kvm,final-clippy,asm-n1,asm-shared}.log.
The final post-format KVM run is recorded separately before the push.

This is a reviewable registry foundation, not the completed extraction or
PR102's two-live-MM milestone. Wait selection/consume/wake sampling, owned
exit/reparent/SIGCHLD transactions, production CPL0 lifecycle/CPU1 binding
and the PRIVATE/no-alias/exact-root-generation witness remain required.
The known pre-fork defect remains separately attributed: 6/50 before versus
5/50 after extraction. A passing single host gate is not closure of it.

## PR102 re-review follow-up

Named WRITE/EXECUTE flags replace grant-publication bit literals. Shared
anonymous editor boundaries now take AddressSpaceRegister, UserVa, GuestLen,
ReservationMm and UserRange; the register preserves ARM ASID bits. The
hardware COW busy callback accesses its pool only on ARM, refusing the x86
unbound venue without a pool read. InitialInventory has a foreign-MM test:
removing its MM guard yields "inventory frame missing" instead of the
required "inventory MM mismatch"; restoring it passes.

Receipts: /tmp/x86-anon-followup-mm-{red,green}.log and
/tmp/x86-anon-followup-doc.log (raw editor arguments rejected). The normal
worktree-target KVM gate reports 127 passed, one known shared-kernel
shootdown acknowledgement failure, and five existing ignores, none added:
/tmp/x86-anon-followup-worktree-kvm.log. The earlier external-target run
also failed its fixture lookup under /tmp/crates; the normal-target run
passes that fixture. Shootdown code is unchanged and belongs to another
lane. Clippy and fmt-check pass in /tmp/x86-anon-followup-final-{clippy,fmt}.log.
Production process-owner extraction and the two-live-MM green remain open.

Read the carrick-vm continuation at the end first; the original WIP
section below records the relocated checkpoint, not the current verdict.

The director stopped work on x86-w1 for relocation to carrick-vm because
this host has only about 2 GB free. This snapshot is not review-ready.

## Committed, verified foundation

- `6a9faafbe`, `40ca560bc`, `3be4cc0b7`: one guest-arch descriptor decode
  classifier, ARM implementation preserved, x86 PTE decoding, production
  empty-range classification through the shared implementation.
- `9ac4d5b64`: merge PR82 `f114c0777`, retaining the single user #PF entry,
  nested-fault guard, typed fault record, COW and shared fault owner.
- `e0379d3ae`: clean-tree Linux authority inventory position reconciliation.
- `41d1a9f76`: residency binding through native KernelLayout/KernelFaultVenues,
  removing the ARM-global pointer from memory, fault and portal users.

At `41d1a9f76`, `CARRICK_RUN_ID=x86-anon-residency-green just test-kvm`
passed (117 passed, six existing ignored); clippy passed. The merge's
asm-diff against github/work/n1 had its inherited x86 entry change and no
new ARM drift. Full lint needs rerunning after the position reconciliation.

Red first-touch witness on the foundation:

```
CARRICK_REQUIRE_KVM=1 CARRICK_RUN_ID=x86-anon-first-touch-red cargo test -p carrick-cli --test x86_kvm_run --no-default-features --features syscall-shim,platform-linux mounted_static_x86_elf_matches_native_anonymous_memory -- --ignored --exact
```

Native prints `M\n`; Carrick faulted on the first store to mmap's returned
0x40000000. No probe has been unignored. No first-touch green is claimed.
Logs named `/tmp/x86-anon-*.log` remain on x86-w1.

## Unverified WIP in this snapshot

- Shared fault admission distinguishes policy decline from busy/unavailable.
  OwnerFaultSupply selects a PortalGrantSlot with the shared root selector;
  ARM's existing mailbox path remains intact. CPL0 has no mailbox-v2 supply.
- Shared GrantTarget admission accepts the compact parked-context ABI.
- X86PreparedResolver uses borrowed InitialWords rather than another window.
- InitialWords captures the actual boot AddressContext. Local drain checks
  its receipt; a peer-active MM uses existing shootdown rendezvous. The
  production table write window has not been widened.
- X86Mmu::project_grant provides one native projection for guest execution
  and host receipt validation.
- New OWNER_GRANT_PORT physical service stages a fresh zero extent and exact
  inventory grant from the CPL0-selected window, submits the isolated slot,
  and accepts the checked receipt. Host does not select VMAs or edit leaves.
- CPL0 #PF production binding selects, crosses the physical port, applies
  core::mm::frames::apply_grant under its exact editor, and acknowledges.
- InitialInventory supports extent grants and checks exact receipt authority
  without a full inventory scan. Unused initial table grants supply edits.

## Exact next step

Compile the production and fixture CPL0 images on carrick-vm, then finish
and audit initialization/settlement of the owner grant path before running
the red-first command above for green. The last build on x86-w1 failed at
X86PreparedResolver::under_editor expecting NonZeroU64; the call was fixed
without rerunning. There may be further compile failures and warnings.
`cargo check -p carrick-mmu-core` passed before the final wiring; host-only
core/el1 checks had passed earlier. These do not validate the WIP image.

Before claiming first-touch:

- Explicitly initialize the mapped x86 FrameGrantResidencyTable (in-place
  initialization exists). Current boot has not added that initialization.
- Audit zero-initialized MmPortalSlots record validity and carrier binding;
  the retained_record unsafe API requires initialized atomic-only records.
- Audit all host grant refusal/indeterminate/error paths: no live physical
  custody may be rolled back or freed from an unverified completion. Current
  PendingGrant/InitialInventory Drop error handling needs attention.
- Check exact root incarnation/generation, prepared-page permission admission,
  real checked drain, slot completion and inventory publication end to end.
- Add a live PRIVATE-leaf witness, not just success output. Test neighbors'
  prepared commits, refusal, table exhaustion and another live CPU/MM.
- Audit existing diagnostic/fault policy: only actual Linux permission/hole
  declines return reason 6/SIGSEGV; unavailable owner paths return reason 9.
- Keep InitialWords as the only production descriptor window authority.

## Remaining goal after first-touch

Replace x86 anonymous.rs's reservation-only path with generic shared
memory::serve_delegated_anonymous (geometry and context parameterization),
and implement its ISA editor through native EditIntent/DescriptorTxn.
PROT_NONE must remove USER (or PRESENT) while retaining custody; RW->RO and
munmap must really fault. The shared owed-return journal needs physical
settlement, not indefinite retained backing. CLI currently exits 139 for a
fault; preserve cleanup then terminate with an actual host signal. Strengthen
native differential tests to require WIFSIGNALED and use anonymous pages,
including a usable lower-half CPL0-arena mmap. Unignore only semantic greens.

Commit each completed step with red/green evidence; post its SHA to the
mailbox. Final gates: CARRICK_RUN_ID just test-kvm, just clippy,
just fmt-check, clean-tree just lint-domains, asm-diff github/work/n1 with
no new failures, just ci before push, Linux portable and remote host
acceptance. HVF/signed gates cannot run on this host and need director
coordination. No Docker and no load generators were used.

## carrick-vm continuation (2026-10-07)

The mounted anonymous-memory binding now prints `M`, exits 7, and checks a
JSON receipt containing one live-authenticated PRIVATE page and exactly two
host dispatch forwards (write and exit). The test is no longer ignored.
This is a focused semantic green, not closure of every audit item.

Corrections after the relocated WIP:

- Construct residency and portal records before vCPU creation.
- Separate fresh physical mapping generation one from the guest operation
  sequence; the prior code failed inventory admission with generation 4.
- Retain unused initial table grants from the original grant partition,
  not the used-table receipt list; the prior code refused TablesExhausted.
- Retain inventory custody after guest exposure, including absent, refused
  or indeterminate completion. No unverified completion authorizes rollback.
- Parameterize shared anonymous serving by reservation geometry and parked
  context; CPL0 uses native EditIntent/DescriptorTxn for backed edits.
- Add PRIVATE-page receipt evidence after native live-descriptor validation.
- Move fixture-only imports under the fixture macro to satisfy clippy.

The initial full KVM run had one clock-fixture failure: a 256-row CPUID model
contained 64 populated rows and 192 exact-zero duplicate leaf-zero entries,
observed with gdb. The fixture now reuses only an exact vacant duplicate for
its synthetic clock; genuinely full tables still refuse. The focused clock
witness passes. GDB evidence: `/tmp/x86-anon-cpuid-gdb.log`.

The new native grant projection test covers table exhaustion and stale-root
refusal without mutation, a resident middle page, prepared PRIVATE neighbors,
and committing one neighbor without changing the other pages.

Still open before claiming the requested lane complete/review-ready:

- Production peer-active MM/CPU owner-grant witness. The current production
  InitialWords context is still one boot MM; fixture multi-MM and shootdown
  tests do not close this production binding.
- Physical settlement of the owed-return journal (not just retained custody
  through VM teardown). Do not acknowledge or reuse journaled ranges early.
- PROT_NONE lower-half private-leaf permission representation and subsequent
  retirement/restoration. The native privilege check currently refuses a
  lower-half supervisor leaf; preserve kernel-alias exclusion when fixing it.
- Real host signal termination after cleanup and anonymous NONE/RO/munmap
  native differential probes requiring WIFSIGNALED.
- Final full KVM, clippy, clean-tree inventory/lint and committed-head asm
  comparison. Inherited `a46e3a5a7` vs github/work/n1 reports one ARM addition:
  sched::hw::fatal_entry_binding `hvc #3`; no new ARM drift is claimed yet.

Do not push or post review-ready until the required final gates pass. No
Docker, HVF signed tests, load generators, or production traces ran here.

Latest verified KVM gate: 120 passed, zero failed, five existing ignored.
Log: `/tmp/x86-anon-test-kvm-final.log`. Native MMU suite: 244 passed,
zero failed (`/tmp/x86-anon-mmu-core.log`). Final lint/asm still pending.

Director milestone order (2026-10-07): finish gates and push this first-touch
milestone honestly scoped to one boot MM. Next bind production grants to a
second live MM: fork, both processes concurrently touch fresh anonymous
pages, PRIVATE witnesses per MM, and no cross-MM leaf. This lane does not
land until that witness is green. Then settle physical owed returns
red-first, followed by the anonymous NONE/RO/munmap real-signal probes.

The next production fork differential is red at this milestone: native
prints F and exits 7; Carrick exits 99 with no stdout. Evidence:
`/tmp/x86-anon-peer-mm-red.log`. This existing fixture does not yet supply
the requested concurrent fresh-pages witness.

Shared fault tests: 28 passed (`/tmp/x86-anon-shared-fault.log`). Final clippy
and fmt-check pass. ARM assembly has zero new drift versus verified
41d1a9f76 (`/tmp/x86-anon-asm-foundation.log`); against github/work/n1 the
single inherited fatal_entry_binding hvc addition remains. Inventory
reconciliation moved two Linux authority sites; the changed Drop abort
fingerprint has an explicitly updated custody rationale, not a move-only
claim. Final full lint passed on the clean tree. Receipt:
`/tmp/x86-anon-lint-domains-final.log`. Live authority execution covered
linux-cli and linux-runtime (569 reviewed rows); other host profiles remain
pending as expected on this Linux host.

## Independent review correction work (2026-10-07, not review-ready)

The current review branch starts at `710980f1c` and merges shared-kernel
`7d6daf287` in `5b9d8e2ab`. The two-live-process red probe is preserved in
`6d4905e12` on `work/x86-anon-step2-checkpoint`: native prints Q and exits 7;
710980f1c exits 91 because production fork is refused with ENOSYS. No
second-MM green is claimed. The extraction design is in `03fdb4a92` on
that branch. Unfinished extraction is isolated in local checkpoint
`aca49a046` on `work/x86-process-extraction-checkpoint`; it is not verified
or suitable for landing.

Review correction evidence on the current branch:

- Adjacent fixed mappings: `/tmp/x86-anon-adjacent-red-fixed-placement.log`
  records native A/7 versus Carrick 125, Occupied grant refusal. The green
  `/tmp/x86-anon-adjacent-green.log` keeps both bytes independent. The shared
  guest selector avoids a bulk window containing existing residency and
  falls back to the fault page; the host still supplies only selected stock.
- Physical owner-grant service crossings are typed and counted, including
  their contribution to total portal exits. The single-page and two-page
  probes require respectively two and four crossings. Red missing counts:
  `/tmp/x86-anon-crossing-count-red.log`; green:
  `/tmp/x86-anon-counted-grants-green.log`.
- Production COW now refuses before constructing another descriptor window
  or dereferencing the ARM pool. InitialWords remains the production
  descriptor authority. This is fail-closed partial coverage, not COW
  support. Fixture COW remains a fixture. Anonymous regression green after
  this change: `/tmp/x86-anon-fail-closed-green.log`.
- Grant target authentication compares the actual portal carrier identity.
  Inventory publication checks each exact GPA, length, MM and identity,
  rather than only the receipt's identity. The different-GPA test failed
  before and passed after restoring this check:
  `/tmp/x86-anon-inventory-gpa-{red,green}.log`.
- Window selection, descriptor edit ranges and the physical GPA cursor use
  domain types. Explicit production panic/unreachable sites named by the
  review have been replaced with named refusals/fatal entry binding.

The unique-operation binding test failed with zero bound IDs, then passed
with two distinct reservation-owner sequences. The production editor now
uses that sequence, not the root generation. Receipts:
`/tmp/x86-anon-operation-{red,green}.log`.

Still open: safe general grant-refusal recovery,
finite table stock/refill and exhaustion witness, physical owed-return
settlement, CPU1/second-MM production admission and exact incarnation checks,
concurrent busy recovery, and real-signal PROT_NONE/RO/munmap probes.
The adjacent-map green does not close these independent audit items.

Director policy confirmed after this correction: until process-owner
extraction binds task-local termination, infrastructure refusal reason 9
remains carrier-fail-closed. Indeterminate custody is retained or
quarantined, never freed. It must not become a false SIGSEGV; Linux policy
declines remain reason 6. The review correction can be pushed separately
with this limitation explicit; process extraction then resumes.

Correction gates: EL1 249 passed; requested asm comparison to github/work/n1
has its one inherited ARM fatal_entry_binding hvc difference. Comparison to
710980f1c passes with zero failures, including no new ARM drift. Receipts:
`/tmp/x86-anon-review-el1.log`, `/tmp/x86-anon-review-asm-n1.log`, and
`/tmp/x86-anon-review-asm-milestone.log`.

## Shared-kernel shootdown gate attribution (2026-10-07)

Final full KVM gate on the review correction was red at
`two_running_vcpus_drop_stale_translation_on_shootdown`: a running CPU's
acknowledgement lagged the published generation. Preserve
`/tmp/x86-anon-review-final-kvm.log`; do not call this gate green.

The director requested fixed 50-run samples on clean pure shared-kernel
and the review revision and authorized pushing review fixes if the pure
branch also failed, labelled with this evidence. Separate freshly built
artifacts, sampled sequentially with no concurrent guest workloads:

- Pure `7d6daf2873ce38dc7cfecb1d8a330a97c4759f1e`: 22 failures / 50.
- Review `8aa876fde48bd11af4364d647b0377dcae09c367`: 25 failures / 50.
- Same failure: `running CPU must acknowledge shootdown` (pure line 1249;
  review line 1264). Example: `/tmp/x86-shootdown-pure-fresh-50/4.log`.
- Raw logs and fixed sample exit statuses:
  `/tmp/x86-shootdown-pure-fresh-50/`,
  `/tmp/x86-shootdown-review-fresh-50/`; artifact SHA256s:
  `/tmp/x86-shootdown-fresh-artifacts.sha256`.

An initial attribution attempt reused a target directory across checkouts;
subsequent review compilation rejected stale nested CPL0 metadata. That
attempt is excluded from the comparison. Both authoritative artifacts
were rebuilt into separate new target directories. No retry-until-green,
new ignore, assertion weakening, shootdown-code fix or timeout change was
made. The director routes the shared-kernel defect to its owner. Review
correction gates otherwise passed: EL1 249, clippy, fmt-check and clean-tree
lint-domains. Signed HVF remains unavailable on this host.
## process owner extraction

Director-approved scope: this lane moves the authoritative process/wait
graph into `carrick-sched-core`, then makes both host `carrick-kernel` and
CPL0 consumers. The crate already owns exact task/thread execution and
object-wait notification; the process topology and its wait producer belong
beside that notification authority. It remains `no_std` with `alloc`.
`carrick-core` continues to own MM fork commit/abort/publication and COW.
No fixture lifecycle, host syscall forwarding, or second process table is
part of the implementation.

Move the process-only state and transitions, preserving existing typed
identities: `TaskId`/`TaskKey`, leader/tgid identity, `ChildExitSignal`,
parent/child links, live/retiring/zombie membership, `LinuxWaitStatus`,
CPU/children-rusage receipt, job-control/tracee wait selectors, and the
numeric claim retained until reap. Split host resource payloads from that
state; MM/files/credentials/namespace handles and subscriptions stay host
payloads keyed by the same process generation. They must not retain their
own parent/child or zombie authority. Namespace uid/pid rendering crosses
through typed adapter values, not host process identity.

Move `operations/wait.rs`'s `WaitMode`, `WaitChildClass`, `WaitTarget`,
`WaitJobControl`, `ChildWaitPrecheck`, `WaitOutcome`, the selection body of
`wait_child_matching`, and `sample_precheck`. Preserve consume-under-write
atomicity, clone-child partitioning, ptrace/job-control observations,
WNOWAIT/WNOHANG behavior, accumulated child CPU charging, and the wake
generation sampled by the scan. Wait4/waitid wire rendering remains in the
Linux personality, using the shared typed status and identity receipt.

Move process topology preparation/publication from `operations/exit.rs`'s
`prepare_task_exit_key_with_adopter`, `retire_task_exit_notifying`, and
zombie publication/reaping into owned shared transactions. Preserve reserved
topology versus live thread membership, subreaper/reparent selection,
autoreap (SIG_IGN/SA_NOCLDWAIT), exit_group membership cancellation, and
SIGCHLD producer ordering after committed exit. Host file/MM retirement and
ptrace/namespace transport remain adapter effects with preadmitted receipts;
the shared owner decides each effect and its exact target. No host adapter
may independently decide which child or zombie a wait sees.

Host call sites to change: `kernel/core.rs::RegistryState`, `TaskRecord` and
`ZombieRecord`; `objects/task.rs` parent/children/lifecycle/job-control and
identity accessors; `objects/process.rs` zombie/status/rusage capture;
`operations/{clone,exit,wait,session}.rs` and identity/ptrace mutations;
`dispatch/{wait,wait_source,wait_authority,wait_plan}.rs` and continuations;
`kernel/process_lifecycle.rs` public outcomes. Public host APIs delegate to
the shared owner so existing callers exercise the moved body. Host locks
and resource lifetimes adapt one graph, never mirror it. Inventory each
direct topology reader/writer before deleting the old authority.

CPL0 then binds `El1PendingFamilies::{process_fork,process_wait4,
process_exit_group}` to the same owner, generic over the existing parked
context. Save/load/CR3/trap projection stays in guest-arch adapters. Import
initial ELF/stack VMAs, admit the exact child MM through shared core fork,
publish child custody before CPU1 execution, and park waits through the
shared notification. Keep `InitialWords` as the sole descriptor window;
each borrow authenticates the selected MM, root incarnation and generation.
Stage-2 grant inventory is a counted physical crossing, never a VMA or
process decision. CPU0/CPU1 completion slots and pending grants are scoped
to exact execution identities.

Evidence before push: preserve `/tmp/x86-anon-two-mm-red.log` (710 fork
ENOSYS); shared VM-free red/green tests cover two children, stale/recycled
identity, observe/consume, WNOHANG, exit-before-enrollment, autoreap,
reparent and concurrent membership during exit. Run `just test`,
`just test-kernel-semantics`, EL1 lib tests, full required KVM, clippy,
fmt-check, clean-tree lint, and assembly comparison for no new ARM drift.
The director runs the signed ARM gate. The two-live-MM KVM receipt must
prove PRIVATE leaves per MM, no cross-MM alias and an active peer lane;
native output alone cannot close this extraction or make PR102 landable.

## Process extraction resumed after review push

Review correction `e9f18354532739575b88056d9b4d63518b997bd5` is pushed on
work/x86-anon-cpl0, draft PR102; review-ready was posted for that correction
only. The authorized shared-kernel shootdown exception is documented above.

Current local work is work/x86-process-owner-resume, based on that pushed
revision. The earlier extraction checkpoint was cherry-picked: canonical
process identities, lifecycle/wait status, zombie data and parent/child
storage now live in no_std carrick-sched-core; host callers consume them.
The final zombie move compile-check passed on the resumed tree. No guest
process graph, production fork/wait/exit binding, second-MM descriptor
window, or peer-MM green has been added. This branch is not push-ready.

Exact next step: move the authoritative live/retiring/zombie registry and
wait selection/consume body (including the wake generation sampled by that
scan), then the reserved exit/reparent/SIGCHLD transaction into the shared
owner. Keep host resource payloads and namespace rendering as adapters.
Do not leave a duplicate host graph or promote the fixture lifecycle.
After that move, run the planned host/kernel-semantics/EL1 gates, bind the
CPL0 consumer and import ELF/stack VMAs before attempting the preserved
red two-MM KVM probe. The earlier red test remains in 6d4905e12 on
work/x86-anon-step2-checkpoint; bring it into the implementation branch
when its production dependency is actually being closed, without ignores.

Resumed extraction preliminary checks: host kernel lib compile-check passed;
scheduler-core 136 tests passed; host wait suite 11 tests passed after fixing
a test-only import exposed by the zombie move. Receipts:
`/tmp/x86-anon-process-resume-check.log`,
`/tmp/x86-anon-process-resume-sched.log`, and
`/tmp/x86-anon-process-resume-wait.log`. These are preliminary movement
checks, not full host, signed, Linux-conformance or second-MM acceptance.

## Reserved exit topology extraction in progress

The shared owner now holds `TaskRevision`, participant membership admission,
owned topology revision credits, and exact adopter/autoreap selection,
validation and child-set publication. The host consumes a private-field
`PreparedExitTopology` over its actual registry payloads. Live and zombie
children are reparented by the shared owner; no mirrored graph was introduced.
Host revision-capacity, namespace, ptrace and terminal resource effects remain
consumer primitives. Zombie publication, membership cancellation and SIGCHLD
ordering extraction are the next part of this step; CPL0 is still unbound.

First API reds: `/tmp/x86-process-exit-red.log`,
`/tmp/x86-process-exit-credit-red.log`,
`/tmp/x86-process-exit-topology-red.log`,
`/tmp/x86-process-exit-publication-red.log`. A PID-only participant mutant
fails the exact-incarnation assertion in
`/tmp/x86-process-exit-incarnation-red.log` (3 passed, 1 failed); it was
restored before `/tmp/x86-process-exit-frozen-unit.log` (4 passed).
Do not treat these lower-layer receipts as the two-MM live green.

Reservation-set admission, validation, release and exact-transaction rollback
now delegate to the shared registry as well. Terminal zombie versus autoreap
publication authenticates the exact retiring key in that owner. The host
retains an autoreaped numeric claim until the end of terminal publication,
matching the original lifetime; namespace and transport remain effects.

A frozen host gate exposed an unchanged snapshot fixture race:
`mem_authority_snapshot_honors_deadline_contention` returned `Ok` instead of
`TimedOut` after its 40-ms lock holder released before a delayed test thread
started the operation. Pure b8d240335 with a controlled 50-ms pre-call delay
reproduces twice (2/2 red):
`/tmp/x86-process-exit-deadline-baseline-red{,-2}.log`.
The same baseline production with completion-coordinated lock release passes
with that delay: `/tmp/x86-process-exit-deadline-baseline-owned-green-final.log`.
The source patch, HEAD and source SHA256 are saved beside that receipt; the
scratch worktree was removed. The first exploratory owned-green receipt had
overlapping fixture edits and is not authoritative. The committed fixture
keeps the operation's 5-ms deadline and bounds both coordination waits; it
adds no retry or timeout increase. Current focused green:
`/tmp/x86-process-exit-deadline-owned-green.log`.

### Reserved topology checkpoint gates

Commits: snapshot fixture repair `98055b22d`, shared exit topology/receipt
extraction `32d5311f6`, position-only inventory rebind `949da8fbd`.
`just test`, `just test-kernel-semantics`, `just clippy` and clean-tree
`just lint-domains` all exit zero. Linux compiler census: 572 reviewed rows;
other host profiles remain pending, with their stored/static reviews intact.
Receipts: `/tmp/x86-process-exit-final-{unit,host,semantics,clippy,domains}.log`.
Reconciliation: `/tmp/x86-process-exit-reconcile.log` (zero host-authority
rebinds, 68 K1 operation positions, three taxonomy positions and three
unchanged-domain/rationale exit identity fingerprints).

Required full KVM: 127 passed, one failed, five existing ignores, no new
ignores. The only failure is the separately owned
`two_running_vcpus_drop_stale_translation_on_shootdown`, at cpl0_entry.rs:1264
("running CPU must acknowledge shootdown"). No retry or code change here.
The existing A/B attribution remains 22/50 on pure 7d6daf287, with the
independent review's 25/50; this run does not replace that attribution.
Receipt: `/tmp/x86-process-exit-final-kvm.log`, with
`CARRICK_REQUIRE_KVM=1 CARRICK_RUN_ID=x86-process-exit-owner-kvm`.

Assembly against github/work/n1 has the single inherited ARM
fatal_entry_binding hvc #3 difference. Against b8d240335, all 114 blocks
match, with zero drift/failures. Receipts:
`/tmp/x86-process-exit-asm-{n1,parent}.log`. Signed HVF cannot run on this
Linux host; no Docker or signed acceptance was run. No load generators
were started; pgrep found none. No shared-kernel change was merged.
Cancellation/notification ownership and CPL0/CPU1/two-MM binding remain
open. This is an intermediate work-branch milestone, not review-ready.


## Exit effects continuation (2026-10-07, host gates green)

The shared owner now selects exit-group members and retains cancellation
custody until its exact reservation release. Reservation rows, their set permit
and the release token share one opaque incarnation: reusing a transaction
number cannot release old effects, validate an old permit, or erase a rebound
reservation during rollback. Exit admission also requires this plan's exact
participant objects and every reserved ID before changing lifecycle state.
After member cancellation, the owner issues the only parent notification
permit, authenticates the parent's generation, and uses the existing portable
signal policy. Host signal locks remain outside the registry guard; host ptrace,
namespace, file retirement and vfork transport preserve their prior order.
File-table resource capture deduplicates typed IDs while preserving first-seen
order. `InitialWords` and the production page-fault entry are unchanged.

Red-first evidence:
- `/tmp/x86-process-exit-release-incarnation-red.log`: reused numeric transaction
  accepts another reservation's release; 3 pass / 1 fail. Opaque incarnation
  restores the four-test green.
- `/tmp/x86-process-exit-effects-admission-red.log`: unrelated reservation
  authorizes exit admission; 4 pass / 1 fail. Exact plan binding restores all
  five tests in `/tmp/x86-process-exit-effects-admission-green.log`.
- `/tmp/x86-process-exit-effects-budget-red.log`: deliberately scanning all
  processes violates the targeted-work budget; restored owner passes at
  1/8/32/128 members with 512 unrelated processes.

The first host gate was deliberately cancelled for the additional admission
check; its status 143 is retained separately and is not passing evidence.
Final-source `just test`, `just test-kernel-semantics` and `just clippy` exited
zero, recorded in `/tmp/x86-process-exit-effects-final-{host,semantics,clippy}.log`
and their `.status` files. Five shared tests passed in
`/tmp/x86-process-exit-effects-final-unit.log`. The result type alias fixes
clippy without allowing the lint. No review-ready,
CPU1 execution or two-live-MM green is claimed yet. No shared-kernel merge was
performed; the independently owned shootdown red remains labelled by the
previous receipt and its 22/50 versus 25/50 baseline observations.

At the next clean boundary, merge director-authorized shared-kernel 51236d3d5.
The director reports zero failures in 50 focused and 20 complete shootdown
runs. Retarget its IRQ #PF header to PR #82's existing user-fault entry, remove
its additional fault receiver, and put settlement and the fixture completion
suffix into the single entry. Then require zero failures in the full KVM gate.


## Shared-kernel integration at the exit-effects boundary (2026-10-07)

Director-authorized merge: shared-kernel 51236d3d5 after clean exit-effects
commits 7993539f3 and fcf245ed5. The exit-effects clean domain gate passed,
including the live Linux subset (572 reviewed rows); non-Linux compiler
profiles remain explicitly pending on this host.

The shared IRQ header now points to PR #82's `carrick_x86_user_page_fault`.
The additional `carrick_x86_page_fault` assembly and Rust receiver are removed;
there is one production user-fault path. Its shared-policy handler settles
published shootdown debt before handling/reporting a fault. The terminal
fixture suffix is retained in that same path, gated by `fixture_stmt!`;
production keeps its terminal halt. Check the live MM window before forming
production-region references, so cold fixtures do not borrow an unmapped region.
The automatic merge's duplicate fault-port declaration is removed.

Red: removing only this single entry's settlement call fails the held-IPI
KVM test with "running CPU must acknowledge shootdown", recorded in
`/tmp/x86-process-owner-single-pf-red.log`. The earlier compile failure for a
duplicate port declaration is separate in
`/tmp/x86-process-owner-single-pf-merge-build-red.log` and is not semantic red
proof. Green: all three `two_running_vcpus_` tests pass with the call restored,
in `/tmp/x86-process-owner-single-pf-green.log`. Full KVM, clean inventory,
clippy and assembly push gates follow; no two-MM witness green is claimed.


## Exit admission review follow-up (2026-10-07)

Read-only review identified a stale-serial admission when a live source has
zero members. The requested TaskKey now must equal the exact prepared task
revision key before member capture or exit_begin. The work-budget fixture
includes zero members and rejects a same-PID different-serial request at
every scale. Red: /tmp/x86-process-exit-empty-identity-red.log fails that
assertion. Green: /tmp/x86-process-exit-empty-identity-green.log passes all
five exit tests. This adds no population scan or identity read.

The authorized single-entry shootdown integration's full just test-kvm
finished zero: /tmp/x86-process-owner-single-pf-kvm.log. The formerly
separately owned shootdown red is closed on this merged artifact. Both
read-only reviewers found no blocking current-consumer defect; the exact-key
API finding above is fixed and the extra IRQ source EOF blank is removed.


## Reviewed exit checkpoint push receipts (2026-10-07)

Exit cancellation/notification: 7993539f3; line-position reconciliation:
fcf245ed5; authorized single-entry shootdown merge: 7af53d561; reviewed
exact-key follow-up: c161561b9. A read-only follow-up review confirms the
empty-member stale-serial finding is closed before any irreversible effect.

All foreground gates finished zero on the reviewed source:
- just test: /tmp/x86-process-exit-review-host.log and .status
- just test-kernel-semantics: /tmp/x86-process-exit-review-semantics.log
- just clippy: /tmp/x86-process-exit-review-clippy.log
- just fmt-check: /tmp/x86-process-exit-review-fmt.log
- just lint-domains: /tmp/x86-process-exit-review-domains.log
- CARRICK_REQUIRE_KVM=1 just test-kvm:
  /tmp/x86-process-exit-review-kvm.log and .status
- clean inventory reconciliation: /tmp/x86-process-exit-review-reconcile.log

Assembly comparison uses explicit --head HEAD. github/work/n1 retains its
previously recorded fatal_entry_binding hvc #3 difference (one failure),
/tmp/x86-process-exit-review-asm-n1.log. The pushed parent 1bbb69019 versus
reviewed source reports zero failures, /tmp/x86-process-exit-review-asm-parent.log;
there is no new ARM assembly drift. Linux compiler authority captures pass
572 reviewed rows; non-Linux profiles remain pending. Signed ARM/HVF gates
cannot run here, and no Docker was used. The two-live-MM PRIVATE witness is
still red (fork ENOSYS); production process binding is the next step.


## Process entry and fork-context bridge (2026-10-07)

The existing El1PendingFamilies process hooks now take exact native process
custody through a ProcessNative venue. The shared entry completion path is
retained. Every ARM caller passes None, preserving its previous behavior.
All four execution-binding components authenticate before native effects.
Red /tmp/x86-process-hooks-red.log fails the exactly-bound call before the
hooks delegate; green /tmp/x86-process-hooks-green.log passes 22 lifecycle tests.
The initial scaffold import error is separate and is not semantic red evidence.

The shared fork root traits previously forced ARM ThreadCtx. They now accept
the same parked-context parameter as Reservations, with no new fork owner.
The corrected TestEl1Region fixture fails against old core at 2565e74a9 with
expected ThreadCtx/found ParkedContextWords, in
/tmp/x86-process-fork-context-final-red.log. Generic custody clones the real
anonymous reservation in /tmp/x86-process-fork-context-green.log. The initial
separate-allocation fixture correctly failed same-region authentication;
the corrected fixture uses aligned records at the CPL0 offsets.

Focused verification: 97 core tests in /tmp/x86-process-hooks-core.log;
250 EL1 plus two creation-owner tests in /tmp/x86-process-hooks-final-el1.log;
22 wave-2 tests in /tmp/x86-process-hooks-wave2.log. Focused clippy is zero in
/tmp/x86-process-hooks-focused-clippy-green.log after removing an unnecessary
explicit drop from the new test. Production ProcessNative is not yet bound;
shared guest registry, CPU1, per-execution grants and two-MM green are next.

## Native bridge and rebased shared-kernel push receipts (2026-10-07)

b52aaf504 is pushed on work/x86-process-owner. Foreground KVM, clippy,
fmt-check, reconciliation and clean domains gates all exit zero in
/tmp/x86-process-hooks-{kvm,clippy,fmt,reconcile,domains}.log and .status.
KVM has 130 passed, zero failed, five pre-existing ignored cases, with no
new ignores. Explicit parent ASM comparison is zero; explicit N1 comparison
retains the previously recorded one fatal_entry_binding hvc difference.
Push and hook exit zero in /tmp/x86-process-hooks-push.log.

c695c98b1 merges the director-authorized rebased shared head d355743b2.
The ancestry rebase produces equivalent add/add conflicts. Reconcile the
actual tree delta from already merged 51236d3d5; preserve reviewed process
sources and PR82's single #PF entry and early settlement call. The incoming
source changes are fixture build/input tooling. Its 84 fixture tests and
foreground KVM, clippy, fmt, reconciliation and clean domains gates exit
zero: /tmp/x86-process-shared-rebased-{fixtures,kvm,clippy,fmt,reconcile,domains}.log.
Parent ASM is zero; N1 retains the same inherited difference. Hook/push zero
in /tmp/x86-process-shared-rebased-push.log. No ARM/HVF or Docker run here.

## Owner-selected stage-2 inventory MM (2026-10-07)

InitialInventory is still the one physical custody transaction, now taking
and retaining typed MmId. Initial-image callers select their admitted initial
MM; anonymous inventory uses the existing owner-selected operation's MM.
Publication authenticates the retained MM against its receipt and exact live
frame inventory rather than always charging INITIAL_MM_KEY. No host VMA,
process selection or descriptor store is added.

Red /tmp/x86-process-inventory-mm-red.log asserts the second live receipt
must name MM302 and gets MM301 from the old hardcoded implementation.
Green /tmp/x86-process-inventory-mm-green.log passes all six initial reply/
inventory tests, including two simultaneously retained MM transactions with
different GPA and mapping identities and the existing wrong-MM refusal.
This is physical custody proof only: production CPU1, process hooks, exact
per-execution pending grants and the two-MM PRIVATE live witness remain open.

## Owned consuming reap custody (2026-10-07)

5c80ffd1b extends the existing shared consume_wait result with the removed,
non-cloneable consumer zombie payload. No extra scan or shadow numeric claim
is needed. Host drops that payload under the existing registry write guard,
before reaped observers and namespace effects. Group/session cleanup and
parent CPU charging remain the same shared consuming body.

Red /tmp/x86-process-owner-adapter-reap-red.log observes a selected numeric
claim dropped before result release (one release, expected zero). Green
/tmp/x86-process-owner-adapter-reap-green.log passes all 152 sched-core tests;
focused clippy exits zero in /tmp/x86-process-owner-adapter-reap-clippy.log.
A read-only scoped review approves spec and quality with no findings.
Kernel semantics, KVM and workspace clippy exit zero in
/tmp/x86-process-owned-reap-{semantics,kvm,clippy}.log. Full just test is still
running at this documentation checkpoint; its final .status is authoritative.
N1 ASM retains the recorded single difference, parent comparison is zero.

The first reconciliation attempt started while the pre-commit hook still held
the staged source and correctly refused dirty inputs. Clean re-run
/tmp/x86-process-owned-reap-reconcile-clean.log exits zero and rebinds two
physical inventory positions only. No review verdict or rationale changes.
Guest birth admission/claim return/payload integration and the PRIVATE two-MM
runtime witness remain required. No review-ready claim or PR has been made.

## Native grant custody and shared birth checkpoint (2026-10-07)

64c68767f separates typed CPU identity from the exact bound CurrentTask in
shared x86 fault policy. Production grant crossings carry the real CPU slot;
physical service retains per-CPU pending custody with all four execution
binding words and the exact native root context, authenticated with live CR3
before submission and receipt consumption. Offered table stock leaves the
available pool before submission; only unused stock returns after receipt.
The host still supplies stage-2 inventory, with guest-selected windows/VMAs.

CPU1 fault red /tmp/x86-process-fault-slot-red.log returns Forward rather
than Served with one exact current task. Green /tmp/x86-process-fault-slot-green.log
passes 251 EL1 tests. Native CPL0 build exits zero in
/tmp/x86-process-fault-slot-cpl0-build.log. Grant custody scaffold red
/tmp/x86-process-grant-custody-red.log accepts a foreign task and offers the
same tables twice. Final green and focused clippy are
/tmp/x86-process-grant-custody-{final-green,clippy}.log. Scoped read-only
review finds no introduced defect. Service-level unused-stock/refusal tests
remain to be bound when the native CPU1 execution bridge is runnable.

d9adc7077 retains the shared registry write borrow across exact caller/parent
admission, PID membership commit, numeric claim commit and infallible topology
publication. It checks all live/retiring/zombie collisions, exact reservation
incarnation and exclusive scope, payload identity/session, and selected
parent/group/session custody. The host consumes this owner, preserving errors,
failpoints, external-peer-root behavior and ARM-side effect order. Existing
exit-participant thread membership rules are unchanged.

Birth scaffold red /tmp/x86-process-owner-adapter-birth-red.log has eight
failures. Genuine exit reservation red
/tmp/x86-process-owner-adapter-birth-scope-red.log is accepted instead of Busy(1).
Exclusive-scope fix passes all 161 sched-core tests in
/tmp/x86-process-owner-adapter-birth-suite.log; focused clippy and host check
pass in /tmp/x86-process-owner-adapter-birth-{clippy,host-check}.log. Birth
visits zero of 512 unrelated identities. Review found the scope hole and
confirmed the retained guard/PID/claim ordering otherwise.

Final foreground receipts: /tmp/x86-process-birth-{host,semantics,kvm,clippy,domains}.log
and corresponding .status files. Final committed source is frozen throughout.
Parent ASM /tmp/x86-process-birth-asm-parent.log has zero failures; one excluded
x86 change encodes the selected grant CPU. N1 retains the inherited single
fatal_entry_binding ARM difference, not a green N1 verdict. No signed/HVF or
Docker run is performed on Linux.

Reconciliation correctly refused the new BirthPayloadMismatch fatal site.
Register it as carrier_fault kernel::process_birth: payload/guard corruption
after irreversible identity publication cannot be recovered by guest errno.
Shift existing five fatal ordinals by one and refresh the same method
fingerprint, preserving their verdicts/rationales and the typed-error debt
ceiling. Remaining inventory changes only rebind source positions.

Director cannot extend the running 21600-second turn and requested a pushed
checkpoint around 21000 seconds, followed by a fresh continuation. This is a
watchdog handoff, not a runtime milestone or a new architectural blocker.

Next continuation starts by checking the final receipt status and pushed SHA,
then releasing guest_process_payload to apply the actual payload scratch under
/tmp/x86-process-owner-payload-draft.rs and sibling tests draft (if available).
Its report is .superpowers/sdd/process-native-owner-plan/task-1-report.md;
approved plan is /tmp/process-native-owner-plan.md. The native-MM read-only
review is .superpowers/sdd/process-native-owner-plan/native-mm-integration-review.md.
Scratch is unverified until real source red/green; preserve that distinction.

Native prerequisites remain: import ELF/stack VMAs and initial residency before
finish_import; retain exact frame-level inheritance edges (coarse share rejects
inventoried frames); provide unopened child table custody through per-MM
InitialWords; bind shared resolve_guest_cow through InitialWords and authenticated
supervisor data-copy aliases. PortalGrantSlot/apply_grant deliberately refuses
replacing live stack leaves and cannot substitute for COW. Then bind process
fork/wait4/exit_group and CPU1 park/restore/dispatch, exact completion identity,
and actual PRIVATE leaf witnesses per MM, no aliases and an active peer lane.
The preserved two-MM probe in 6d4905e12 remains red on 710980f1c with fork ENOSYS
(exit91); do not claim it is included or green in this checkpoint.

## Final watchdog blocker: arena host gate (2026-10-07)

Full just test exits one: fork_storm_never_exposes_incomplete_records sees
published host PID with parent zero at prefork_registration.rs:145.
/tmp/x86-process-birth-host.log:8728 records the actual gate failure. The nested
host_lease fork_without_exec_fixture failure later in the log is an intentional
SIGKILL negative fixture whose enclosing test passes; it is not another red.
KVM133/0/5, separate kernel-semantics, workspace clippy and clean domains exit
zero. Parent ASM is zero; N1 remains inherited one, with no new ARM drift.

Arena source/test/Cargo inputs are unchanged by this checkpoint; the crate
only depends on bitflags/libc. Pure pushed 3a81f3092 was git-archived into
/tmp/x86-process-arena-baseline-3a81 and built independently. Fixed quiet25
cohorts pass on both baseline and current. Fixed50 cohorts under the same
bounded eight-yes CPU load fail 2/50 on BOTH baseline and current, with the
same parent-zero assertion. Receipts /tmp/x86-process-arena-attribution.json,
/tmp/x86-process-arena-load-attribution.json and individual sample logs retain
all verdicts. This attributes a pre-existing timing-dependent arena/scanner
failure; it does not close that architectural defect or make the host gate green.
All eight load generators were terminated/reaped and pgrep yes/stress/stress-ng
reported none. No arena code, ignores, retries-to-green or timeouts were changed.

Normal push is held: the director's existing work-branch exception covers only
the separately owned shootdown red, not this newly attributed host-gate red.
Last remote checkpoint remains 3a81f3092 until an explicit labelled-push decision.
All new source is committed locally (64c68767f, d9adc7077 and inventory/docs
9abd66f48); the final documentation-only handoff commit records this blocker.
Director was notified with A/B counts. Do not rerun until green and call it closed.

Exact next step is the director's host-gate ownership/push decision, then apply
/tmp/x86-process-owner-payload-draft.rs and
/tmp/x86-process-owner-payload-tests-draft.rs. The implementer finished the actual
adapter and twelve tests outside the tracked tree; only rustfmt parsing ran.
They have not compiled or passed tests. Read its appended task-1-report.md
assumptions, run genuine red-first binding tests, review, commit and continue
native MM fork/COW/CPU1 integration. The two-MM PRIVATE witness remains open.

Director correction at watchdog boundary: this arena red is already known and
routed to a separate task, with earlier baseline/extraction counts 6/50 and
5/50. The director instructed recording the known pre-existing red and
continuing CPU1/fork then the two-MM witness. This supersedes the temporary
push hold above; push the committed work branch labelled with that red.
No further attribution or arena edits are needed. Source remains frozen;
resume the guest payload/native integration after the watchdog continuation.

## Guest payload adapter continuation (2026-10-07)

Inherited checkpoint 2a2ca03c0 is normally pushed with the known, separately
owned arena host-test red labelled. Shared-kernel d355743b2 was already
merged. The scratch payload adapter is now real source in
`personality/process_owner.rs`, with twelve concrete sibling tests. It uses
the sole scheduler-core registry for birth, wait and reserved exit; native
resources, context and non-Clone numeric claims remain row payloads.

First compile caught a borrow lifetime in the wrong-member negative test;
a lexical scope releases the failed pending-exit result before inspecting
the owner. This compile failure is not semantic red evidence. Removing the
exact TaskKey guards gives the recycled-PID assertion failure in
/tmp/x86-cont-payload-key-red.log. Restored custody passes twelve tests and
all 263 EL1 lib tests in /tmp/x86-cont-payload-final-tests.log. All-target
focused clippy passes in /tmp/x86-cont-payload-clippy-green.log, including
the nested ARM freestanding image build; its initial type-complexity finding
is corrected with a named selection alias. The one new host-only fail-stop
is classified as carrier_fault el1::process_owner, preserving the existing
freestanding fatal transport.

This is payload custody only. Production ProcessNative, initial ELF/stack
VMA and residency imports, frame-level inheritance, per-MM InitialWords,
real COW and CPU1 execution remain to bind. No two-MM green, new ignore,
Docker run, signed HVF result or review-ready milestone is claimed.

## Shared numeric/serial allocation continuation (2026-10-07)

The payload checkpoint d5157d2c2 and restored preserved witness d37570d90
are normally pushed. Clean domain lint, formatting and workspace push-hook
clippy pass. Explicit parent ARM ASM is 115/115 with zero differences.
Full required KVM is 133 passed, one failed, five existing ignores: the
restored two-MM fork witness is the sole red (exit91). No new ignore is added.
Receipts: /tmp/x86-cont-payload-{domains-clean,fmt,asm-parent,kvm,push}.log;
/tmp/x86-cont-two-mm-red.log records native Q/exit7 and Carrick exit91.
The earlier domain attempt overlapped witness restoration and correctly
refused dirty capture inputs in three orchestration fixtures; the committed
clean-source repeat passes.

Director confirmed moving pure PID collision/claim and serial allocation
logic to scheduler core. `identity_allocator` now owns NamespaceState, role
counters, IdError and SerialAllocator. Host IdRegistry retains its existing
parking_lot lock and role-preserving RAII tokens, delegating all selection
and counting. ObjectIdRegistry and the process-global file-description source
delegate monotonic allocation to the same shared serial code; kernel/carrier
and process-global scopes are preserved. Native RAII wrappers are still next.

A compiling missing-selection scaffold fails two numeric lifecycle tests
in /tmp/x86-cont-allocator-red.log. Returning constant serial1 fails reuse
and monotonicity assertions in /tmp/x86-cont-allocator-serial-red.log. The
restored shared owner passes all 164 scheduler-core tests in
/tmp/x86-cont-allocator-green.log. Nested-domain composition distinguishes
child-local numbers from retained ancestor claims; real namespace nesting
and host RAII behavior additionally remain in the existing host suites.
Applicable production contract is kernel.el1.creation-native-path, with
kernel.el1.fork-cow for private-MM inheritance. No budget is weakened.

Director resolved the seed boundary: transfer the real host launch
task/namespace/session/group/claims once in one typed, counted boot crossing.
Then the guest shared allocators are the VM's sole identity authority, and
post-handoff host allocation must refuse. Delete fixed task41/generation11/
thread101/PID41. Required red-first seed tests: namespace PID1 and requested
session/group match, plus host post-boot allocation refusal. This binding
and native MM/fork/COW/CPU1 remain open; no runtime milestone is claimed.

## Shared allocation checkpoint gate receipts (2026-10-07)

89aefd595 moves the pure allocation bodies; host parking_lot/RAII wrappers
retain role custody and existing identity/serial scopes. Full `just test`
and separate `just test-kernel-semantics` finish zero in
/tmp/x86-cont-allocator-{test,semantics}.log. Focused all-target core/kernel
clippy finishes zero in /tmp/x86-cont-allocator-clippy.log. Parent ARM ASM
is 115/115 with no differences in /tmp/x86-cont-allocator-asm-parent.log.
The host compile check and the shared 164-test suite are zero; raw abort
ledger remains 97/97 carrier faults with no new abort or debt.

Reconciliation rebinds no host-authority positions or abort fingerprints.
Its taxonomy rewriter only sorted 400 unchanged records (JSON multiset
equality); that unrelated ordering churn was restored. The global-state
gate correctly flags NEXT_FILE_DESCRIPTION_ID's changed initializer type.
Explicit review preserves its monotonic_allocator verdict and process-wide
scope, rebinding the actual shared SerialAllocator fingerprint and rationale.
The exact monotonic atomic allocation and restored high-water mark moved,
rather than being copied. /tmp/x86-cont-allocator-globals.log exits zero.
The initial reconciler's exit one is retained in
/tmp/x86-cont-allocator-reconcile.log, not called a pass.

Clean `just lint-domains` finishes zero in
/tmp/x86-cont-allocator-domains.log. Required fresh KVM finishes one in
/tmp/x86-cont-allocator-kvm.log: 133 passed, one failed, five existing ignores.
The sole failure is the restored two-MM witness at fork exit91; it remains
an explicit lane red. Normal push checks are recorded in
/tmp/x86-cont-allocator-push.log.
The actual real launch seed transfer, namespace visible identity/membership
binding, native claim wrappers, MM inheritance/COW and CPU1 remain open.
No extraction or runtime review-ready milestone is claimed.

## Exact visible namespace incarnation checkpoint (2026-10-07)

The visible-number key includes the live arena namespace incarnation, not
just its wrapping numeric namespace ID. A compiling mutation that ignores
incarnation fails with visible PID3 versus PID2 in
/tmp/x86-cont-visible-incarnation-red.log. Restored shared tests are 166/0;
all 20 host namespace tests pass, including stale-claim cursor reclamation.
Focused all-target core/kernel clippy passes in
/tmp/x86-cont-visible-incarnation-clippy.log. The earlier typed accessor
compile failures are retained separately; they are not semantic red proof.

First clean reconciliation rebound ten host-authority positions and four
K1 operation positions, without classification/body changes. The taxonomy
rewriter sorted 400 unchanged entries; JSON multiset equality was verified
and that ordering-only churn was restored. Namespace incarnation changes
require another clean positional reconciliation before the next push.

The director resolved file custody: retain host files behind opaque typed
FileTableId, never a task/PID. Forward file calls carry (FileTableId, fd).
Fork requests copy/share according to CLONE_FILES via one typed counted
host crossing; exit/exec close/unshare through the same venue. Required
witnesses: child writes select its own table, and post-fork opens distinguish
shared versus copied tables. Existing FileAuthorityRun registers its client
and canonical root table binding; model ForkCopy/ShareTable commands do not
import that live root table. Reuse the actual Kernel FileTable fork/descriptor
primitives rather than treating model commands as a live authority.
