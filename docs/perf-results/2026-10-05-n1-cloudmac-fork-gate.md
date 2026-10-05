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
