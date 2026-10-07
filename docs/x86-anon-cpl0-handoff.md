# x86 anonymous CPL0 handoff (partial, 2026-10-07)

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
