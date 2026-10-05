# N1 cloudmac fork lane: bootstrap control refusal

Source: `299b19ca11756dab8444227970af12b6df9145f4`, branch `work/n1-cm`.
No Docker was used. The five tests ran separately through
`scripts/test-signed.sh` inside one exclusive host gate lease. Every signed
negative control passed; every scoped cleanup completed with zero remaining
processes. Failure runners do not publish their normal success receipt;
the custom evidence directory retains each signed executable and identity.

Evidence root on cloudmac:
`/Volumes/carrick-build/wt/wt-n1-cm/target/n1-cm/fork-299b19ca1/`.

## Exact inputs

Restored bundle:
`/Volumes/carrick-build/fixtures/published/299b19ca11756dab8444227970af12b6df9145f4/e6796cb59db805deb52ac89b61d489874149281bbdbdd1b87f4b864b792cb46d.tar.gz`.
Archive SHA-256:
`1b63229aa8a348c5d92d6e8fefc9dc694e09d3fbad3c87a213d0d36454ad25c4`.
Restore reported 1,133 executable fixtures. `fixture-installed.json`, image
manifest and verified layer hashes are retained. Hash verification after the
gate proved the CLI, fixture and retained executables unchanged.

| Artifact | SHA-256 | CDHash | LC_UUID |
|---|---|---|---|
| CLI | `6ba08911d05c29bf8c48853636fd8f463734b1be1b944795a575ba3e93a73f0b` | `4e70796a62ceddad43116e5eec9c32bf883c8e89` | `C859E16F-63B0-36A8-AED0-A1683BF8EBE1` |
| First VMA executable | `7a6147f0a95e0d8f5fa2ad800d6f58ca86ce171ed2713d82e7cc1136c94bce3d` | `d9513f9398f0b3431b724f69d336111d719cfaaf` | `97299DBA-DE83-3306-AC70-9646FFC6E315` |

The five separately re-signed scheduler executables each have their own
`sN-scheduler.{sha256,codesign.txt,entitlements.plist,load-commands.txt}`.
All carried the hypervisor entitlement and `__dof_carrick`.

## Signed results and historical main comparison

Run IDs: `n1-cm-299b19ca1-s1` through `s5`, in the order below. All returned
libtest 101 and signed runner 1. Main comparisons refer to the historical
`51bfe67f4` [batch-five receipt](2026-10-04-n1-batch5-gate.md), not a fresh
control on this host.

| Test suffix (`el1_`) | N1 result | Historical main |
|---|---|---|
| `delegated_root_concurrent_vma_ops` | Fork fails before parent/child workload; 335 exits, served mmap/munmap/mprotect 3/2/1. | Workload completes; zero serves fails serving budget. |
| `delegated_root_map_fixed_over_cow_pages` | Fork fails round 0; 332 exits. | Twelve fixed mappings and isolation complete; serving budget fails. |
| `thread_lifecycle_ptrace_traceclone` | Initial fork fails; 311 exits. | Fork and initial stop complete; SETOPTIONS fails ENOSYS 38. |
| `thread_lifecycle_spawn_slope` | First 4-thread/16-round fork fails; 323 exits. | Workload completes; clone forwarding slope 0.2682 exceeds 0.05. |
| `fork_cow_resolves_in_guest` | Root-slot collision removed; measured 16-page fork fails round 0 after warm-up. | 320-page isolation completes; 3,196 exits exceed ceiling 144. |

Thus the root-slot fix improved admission, but none of these five is a
functional pass or N1 closure. No budgets, waits, retries or concurrency
were changed.

## Refusal capture and LLDB attribution

The two VMA and ptrace retained executables ran under `carrick trace` with
`hvpatch-owner-fork-refusal.d`, run IDs `n1-cm-299b19ca1-trace1..3`.
All emitted two closed children and one refusal:

```
OWNERFORKREFUSAL1|refused|errno=16|stage=6|parent_mm=2|child_mm=3|generation=12|pid=14576
OWNERFORKREFUSAL1|refused|errno=16|stage=6|parent_mm=2|child_mm=3|generation=13|pid=14636
OWNERFORKREFUSAL1|refused|errno=16|stage=6|parent_mm=2|child_mm=3|generation=8|pid=14727
```

Each summary has `errors=0,bounded=1`. These are incomplete diagnostics,
not qualified captures. There is no stage-three refusal, so its check and
arena companion probes did not fire. Live listing of `proc:::exit` on this
Mac fails with "System Integrity Protection is on". With `-Z`, the absent
termination probe leaves the otherwise tiny capture running to its 45-second
bound. Raising a buffer cannot repair this missing provider.

Retained first-VMA artifact, run `n1-cm-299b19ca1-lldb4`:
`structural-copy-lldb.log`, `structural-copy.core`, and cleanup log.
The process was stopped on its executor's first bootstrap structural copy,
with all-thread stacks and `carrick eventring 8192` saved. The authoritative
ring reported 54/54 entries and zero errors. LLDB has observer effects; this
is attribution evidence, not timing evidence.

Exact selection: source IPA `0x2d00000000`, destination IPA `0x9a00400000`,
length 4096, executable true. Stepping `retain_extent(source,4096)` at the
exact-record lookup returns to the epilogue immediately, before allocation
lookup or pinning: no custody record covers this carrier trampoline page.

The owner traverses the coarse bootstrap kernel-hole descriptor, then asks
for private physical copies of every non-table control page. The trampoline
and other carrier control mappings intentionally retain carrier lifetime
and direct-unmap ownership. Gaps in the coarse descriptor also have no
stage-two allocation. Publishing those mappings as private MM custody would
confuse lifetime and still attempt to copy the gaps.

## VM-free red witness

The existing two-live-MM owner-fork witness now requires only four identity
page copies, preserving carrier outputs and rebinding the child table alias.
The fixture's two user frames give six total custody selections. On unchanged
implementation:

```
CARRICK_RUN_ID=n1-cm-owner-control-red just lease gate cargo test -p carrick-el1 --lib owner_fork_publishes_child_with_two_live_same_va_mms -- --nocapture
assertion failed: two user frames plus four identity pages, no carrier code or gaps
left: 66
right: 6
```

Complete log: `owner-control-red.log`. This is a deterministic witness for
`kernel.fork.stage1-image`; the five signed bindings remain red. The planned
correction belongs in owner fork selection, keeping carrier mappings and
their lifetime authority intact. Copyout, brk and clear-child-tid remain
outside this lane.

## Correction and qualified retained-artifact captures

The red witness is committed as `e3291bbcb`, on director-supplied base
`631785609`. `c4b1836c4` changes the owner census and copy selection to copy
only the named per-MM identity window. Carrier code, maintenance, mailbox
outputs and coarse stage-two gaps remain inherited; child table aliases
name the child's private root. The witness now passes, including physical
output checks, and all 278 EL1 lib tests pass. The existing host controls
also pass: `initial_carrier_control_mapping_keeps_direct_unmap_owner` and
`owner_structural_copy_publishes_selected_executable_bytes`.

`f7858e687` adds `trace-witness-exit(i32 raw_unix_wait_status)` after the
external launcher's wait completes. This closes the complete external test
on SIP-enabled macOS. The cached test carrier does not emit VM-destroy on
its guest roots' exits; a diagnostic attempt using that control remained
bounded and is not qualified. No bound was widened. `bdc151b36` reconciles
28 moved host-authority positions without changing reviewed classifications
or counts (663 inventory rows, 621 macOS capture rows).

Qualified old-artifact diagnostic run IDs:
`n1-cm-299b19ca1-qualified1..3`, using a new `bdc151b36` trace launcher with
unchanged retained `299b19ca1` scheduler executables and fixture. This is
explicitly a mixed-source diagnostic transport, not signed acceptance of
the correction. The three executable hashes still match their original
receipts. Launcher identity:

- SHA-256 `3d73a8acc81614d1812f838d178c9deb2ab436402a48d1d4fcb4a678de4570ae`
- CDHash `4df7815cd959fdf453bec358880d72c33668d1d2`
- LC_UUID `2ED68EEB-F431-392C-BE7D-4DDB8E32B858`
- Hypervisor entitlement and `__dof_carrick` present.

All three captures record two closed publications, one errno 16/stage 6
refusal, one guest result with code 1, and external wait status 25856
(libtest 101). They have `witness_closed=1,errors=0,bounded=0`; the trace CLI
returns zero and accepts its strict receipt with consumer drops rejected.
Capture qualification is separate from the failed workload verdict. Raw
DTrace lines can flush across CPUs out of chronology; do not infer ordering
from printed line order. Refusal records:

```
OWNERFORKREFUSAL1|refused|errno=16|stage=6|parent_mm=2|child_mm=3|generation=12|pid=36382
OWNERFORKREFUSAL1|refused|errno=16|stage=6|parent_mm=2|child_mm=3|generation=13|pid=36403
OWNERFORKREFUSAL1|refused|errno=16|stage=6|parent_mm=2|child_mm=3|generation=8|pid=36424
```

The `/usr/bin/true` empty-witness control emits the terminal record but no
closed publication or guest result. The script returns 3 and the trace CLI
rejects it with exit 1: an empty capture cannot qualify as zero refusals.
All four scoped cleanups report zero processes. Logs and identity metadata:
`qualified-gate.log`, `qualified1..3.{log,raw}`, `qualified-empty.{log,raw}`,
`trace-cli-bdc151b36.*` under the original evidence root.

Focused host checks on clean `bdc151b36` passed: `just clippy`,
`just fmt-check`, `just lint-domains`, and `git diff --check`. The live Mac
census explicitly leaves Linux, FreeBSD and NetBSD slices pending; this is
not a host-matrix or full acceptance claim. No Docker or full acceptance
runs were performed, as directed for this lane.

## Exact correction cycle: physical COW settlement remains red

Source `bdc151b36ba2146e381bd0a1ac1c8e97307fc6ed`; restored director bundle
`/Volumes/carrick-build/fixtures/published/bdc151b36ba2146e381bd0a1ac1c8e97307fc6ed/c70655da750972d702c8c6b54a12b5736a10759a2dc4edb29a2d517819c97d5f.tar.gz`,
SHA-256 `a4299627bc7109a1ecfaa043fadbe02933bac57f4ac0a4e24af6bde067a3fb0f`.
The restore and all five scoped input checks identify 1,133 exact fixtures.
Evidence root: `target/n1-cm/fork-bdc151b36/`. Retained CLI SHA-256
`3ecab3904afccb7e8812c23b191a8d791bc986be7cfde70aa22cbb6696cd363f`;
first VMA scheduler SHA-256
`606fb8f87dcc5bff151c8e8f3294c260c240fb1af1bbd340def23dcc49614dae`.
The directory retains each executable, CDHash, LC_UUID, entitlement, DOF,
fixture manifest, verified image layers and source SHA.

Runs `n1-cm-bdc151b36-s1..5` all advance beyond the old fork refusal but
abort with SIGABRT 6 in settlement of the child stack's EL1 COW:

```
carrick fatal [hvpatch::guest_cow]: settle EL1 COW of span 0xfffffec000+0x4000 (grant 0x9b00000000): hypervisor operation failed: span is not COW-armed
```

Every signed runner returns 1; its unentitled negative control passes.
All scoped cleanups report zero remaining processes. The three traces,
`n1-cm-bdc151b36-trace1..3`, terminate with external wait status 6 and
`children=2|refusals=0|guest_results=0|witness_closed=1|errors=0|bounded=0`.
They fail capture qualification (D script 3, CLI 1), because the abort
prevents a guest result. They cannot qualify as successful zero-refusal
workloads. There are no stage-three refusal check/arena companion lines.
Neither the five workload bindings nor N1 are closed; historical main's
completed VMA, spawn and COW workloads remain ahead of this result.

Retained-artifact LLDB run `n1-cm-bdc151b36-lldb-cow` stops at the host arm
lookup after exact grant extent, live generation and replacement-output
checks have succeeded. The grant extent names frame 344, mapping 345,
owner generation 5. The event ring has 70/70 records and zero errors,
including child PID 2 admission and execution. All-thread stacks and a
modified-memory core are retained in `cow-settlement-lldb.log` and
`cow-settlement.core`; scoped cleanup returns zero. The optimized state
parameter is unavailable in LLDB, so this capture alone does not inspect
the contents of the host arm map.

The owner physical-fork builder installs an empty `CowArmedRanges` for its
child: semantic COW arming belongs to the owner's live descriptor graph.
The composed VM-free witness
`an_owner_fork_cow_settles_without_host_arm_ranges` executes the real EL1
resolver on an adopted private stack/image leaf, with an empty host arm
map, copies bytes into its exact grant and then calls physical settlement.
Before the correction it fails with the same `span is not COW-armed`
error. Wrong-MM and wrong-output controls refuse before settlement. Log:
`owner-cow-red.log`; command:

```
CARRICK_RUN_ID=n1-cm-owner-cow-red just lease gate cargo test -p carrick-vmm-hvf --lib an_owner_fork_cow_settles_without_host_arm_ranges -- --nocapture --test-threads=1
```

The binding is recorded under `kernel.el1.fork-cow`. Its real-descriptor
and physical-inventory proof does not execute EL0 faults or concurrent
vCPUs; those remain the signed binding's responsibility.

The physical settlement correction reads permissions from the exact live
private replacement leaves, after authenticating the MM grant, inventory
extent, live owner generation and retained outputs. Resident replacements
must have lost their COW arm; prepared neighbors stay prepared. Host arm
metadata no longer authorizes this guest-owned completion. Existing host
arm cleanup remains harmless for the older host-armed path. The loop is
bounded by the completion ABI's four-page compound; no host semantic range
projection or extra guest exit is introduced.

The red witness passes with the correction and now also refuses an
unfinished live COW arm and preserves read-only and inaccessible neighbor
descriptors byte-for-byte. All 11 composed guest-COW tests pass, including
exact-MM exclusion, kernel/backend inventory publication and last-reference
retirement. Logs: `owner-cow-green.log` and `owner-cow-suite.log`. The first
focused green run exposed an unused candidate helper; it was removed before
the clean 11-test suite. Signed verification still needs a new exact bundle.

## Postmortem correction: the first settlement is the parent's

Reading the retained `bdc151b36` core corrects the earlier child-stack
attribution. The first completion belongs to parent PID 1/TID 1/MM 2/ASID 1,
not child MM 3. Its grant names MM 2, frame 344, mapping 345, generation 5.
Disassembly reads the arm Arc at the state-relative offset 728 plus its
16-byte Arc header; DWARF confirms the field offset and state identity.
The actual arm map has `ranges.len=0`, capacity zero and generation zero.
Logs: `cow-postmortem-identity.log` and `cow-postmortem-arm.log` in the
`fork-bdc151b36` evidence directory. Seeding only child arm metadata would
not have addressed this first failure. No timing claim comes from LLDB.

## Exact 7af3fdfb6 cycle: vvar, late retirement and clone copyout

Source `7af3fdfb6ab9f91e3ef34857f91e4f422594dc5c`; director bundle:
`/Volumes/carrick-build/fixtures/published/7af3fdfb6ab9f91e3ef34857f91e4f422594dc5c/3275604be5ed70ccaaaf68b8586afa9e3d6f2dbde63fcefcae03e6000a3b85db.tar.gz`.
Archive SHA-256:
`df5a3f9de57d96e2c2eebb2f6c32c7f2c1aceef65ce34e4d76ae63cf7b43d36e`.
Restore and all five scoped runners verify 1,133 executable inputs by
`input_identity`. The exclusive gate rebuilds the CLI and scheduler, records
each signed artifact identity, verifies unchanged hashes and image layers,
and leaves zero scoped processes after every signed/trace run.
Evidence directory: `target/n1-cm/fork-7af3fdfb6/`.

CLI SHA-256 `eeb780a6aa1fc7c44cbab403deea0918e9dcb2cf8e3bf4a4d1942c5927ee34d7`,
CDHash `1caf852cbd4db4b1f9533bc996324a84ed84239e`, LC_UUID
`2CFCE846-3945-3F3F-A4FD-A9CF31BA995A`; entitlement and DOF present.
Every scheduler identity is retained in `sN-scheduler.*` with its executable.

All five runners fail; every unentitled negative control passes:

| Case | Result after parent settlement correction | Historical main comparison |
|---|---|---|
| concurrent VMA | Child vvar generation requires absent host COW arm | Workload and isolation complete; serving budget red |
| MAP_FIXED/COW | User-write completion's live private leaf is retired before settlement; new guard rejects it | Twelve fixed mappings and isolation complete; serving budget red |
| ptrace TRACECLONE | Child vvar generation requires absent host COW arm | Fork/initial stop complete; SETOPTIONS ENOSYS 38 |
| spawn slope | Restore-failed clone TID copyout waits on owner Gate, MM 2/incarnation 1/revision 68 | Workload complete; clone forwarding slope red |
| fork COW | Child vvar generation requires absent host COW arm | Isolation complete; exit budget red |

There is progress beyond the original stage-six refusal and parent-stack
settlement, but no completed workload or N1 closure. Clone TID copyout was
reported to the director before any edit; it remains the owner worker's area.

The VMA and ptrace captures qualify as failure diagnostics with external
wait status 25856, one guest result code 1, two closed publications, zero
refusals, `witness_closed=1|errors=0|bounded=0`. The fixed-mapping capture
records wait status 6, no guest result, and correctly fails qualification.
No stage-three check/arena companion probes fire. The trace CLI's zero for
two qualified captures is not a workload pass. Raw files: `trace1..3.raw`.

Retained fixed-mapping LLDB run `n1-cm-7af3fdfb6-lldb-leaf2` proves the
rejected live descriptor at VA `0x60000c7000` is `0x03e0009b0001bf42`:
invalid, EL1-private, retired, retaining output `0x9b0001b000`. The exact
UserWrite completion names that same output and parent MM 2, with span
4096 and physical grant `0x9b00018000`, frame 611/mapping 612/generation 11.
This is a completed physical repoint followed by a legitimate owner
retirement, not an unfinished copy. The authoritative ring has 90/90
records and zero errors; all stacks, modified-memory core and cleanup zero
are retained in `rejected-leaf2-*` and `rejected-leaf2.core`.

An earlier source-line breakpoint stopped on an accepted stack leaf. Raw
absolute breakpoints in the next diagnostic did not relocate under ASLR.
Neither is attribution for the rejected leaf. The final capture uses
`BreakpointCreateBySBAddress(ResolveFileAddress(...))` on the disassembled
retirement/refusal branches; its actual register values and matching
completion establish the diagnosis.

Two new composed VM-free witnesses execute the real EL1 resolver followed
by the real descriptor retirement or fork-arm operation before settling
its still-pending physical completion. On `7af3fdfb6` both fail with
`live leaves are not completed private COW`, proving settlement cannot
require the current semantic state to equal its earlier write completion.
No serialization, retry or wider bound was introduced. Red log:
`owner-cow-later-red.log`. The existing negative control now removes private
ownership instead of simulating a later valid fork arm.

The late-edit correction accepts an authenticated private retained output
in prepared, resident or retired state, including a subsequent fork arm.
It reconciles physical inventory without changing any descriptor. The
replacement alias's write intent now follows current owner host-buffer
access, so retirement revokes it and a valid later COW arm keeps its Linux
write intent. Wrong-MM, well-formed wrong-output and missing-private-owner
controls still refuse. Both new red witnesses and all 13 composed guest-COW
tests pass (`owner-cow-later-green.log`); the vvar and clone-copyout failures
remain open for the next exact signed cycle.

## Child vvar authority: live COW leaf, no host arm

Retained VMA run `n1-cm-7af3fdfb6-lldb-vvar` stops before the vvar arm
lookup. The exact child identity is MM 3/ASID 2; its live descriptor owner
is Guest. The retained stage-2 root owner has physical base
`661427060736` (`0x9a00200000`), length 2 MiB and host base `0x110200000`;
record 20/logical owner 15/generation 15. An initial manual hexadecimal
conversion was wrong and its range assertion refused the walk. The
corrected walk stays inside that exact retained root owner at every level:
`0x9a00201003`, `0x9a00209003`, `0x9a0020a003`, then terminal
`0x07a0002e00000fc3` at VA `0x2e00000018`. The terminal is valid, private,
COW-tagged, AP read-only, and retains the structural vvar output. Logs and
core: `vvar-lldb.log`, `vvar-postmortem.log`, `vvar-leaf-walk.log`,
`vvar.core`; scoped cleanup is zero. LLDB provides authority attribution,
not timing.

`owner_fork_refreshes_readonly_vvar_without_host_arm_ranges` extends the
existing production fork-plan fixture with the owner lane. The fixture
prepares a real child inventory, publishes adopting COW leaves, binds live
tables, removes host arm ranges, and calls the real privileged refresh.
Its EL1 model copies through the retained source/new grant and executes
actual descriptor journal receipts. Parent generation and sentinel bytes
must survive, child generation must change, guest access must remain
read-only, a second fork must retain the exact new owner, and publication
must cost one guest transaction and zero host COW resolutions.
The first run executes one test and fails at the same missing-host-arm
check as signed VMA/ptrace/fork-COW (`target/n1-cm/vvar-red.log`).

The vvar core's authoritative ring contains 61/61 records, errors zero.
The strengthened VM-free input uses real `publish_private_pages` to seal
read-only resident vvar pages before fork arming. `map_private_aliased`
alone supplies ASID scope, not EL1 private authority; the earlier adopting
read-only setup did not establish that tag. Both final owner witnesses
assert actual private COW tagging and absent Linux write intent before
calling refresh. Against pre-fix `6bf726f87` `cow_engine.rs`, both fail at
`child vvar generation has no COW arm`; the existing host and custody
controls pass (`vvar-authenticated-red.log`: two pass, two fail). A prior
combined attempt collided because all three fixtures reused one root slot;
each fixture now owns distinct child/grandchild slots. That attempt is not
red evidence for the arm diagnosis.

The physical COW service now selects an owner span from live private COW
leaves and the exact output relation within one 16 KiB compound. It stops
at a page that is no longer armed or names another output. It does not
manufacture host arm metadata or re-arm a completed leaf from such metadata.
Privileged refresh still authenticates physical source/grant/inventory,
publishes through the driving EL1 vCPU and preserves guest read-only AP.
The one-page witness proves the unarmed neighbor retains its old backing;
parent bytes, child generation and the second fork's exact new-owner
inheritance remain checked. The existing host fixture also passes.

Focused verification: 131 foreign-MM tests pass, one pre-existing test is
ignored; all 22 COW-engine tests pass. This includes all 13 guest-COW
settlement witnesses and the lock census. The census exposed helper-held
locks in the earlier late-edit witnesses; guards now reside at test entry,
with the same fixture exclusion. Logs: `vvar-foreign-suite.log`,
`vvar-cow-engine-suite.log`, `vvar-focused-run3.log` in `target/n1-cm/`.
A new exact signed cycle is still required; clone TID copyout remains open
in the owner worker's area.
