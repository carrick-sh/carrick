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
