# Ordinary syscall writes and instruction-content dependencies

2026-09-22. This continues the [resident native-region integration](../native-islands/design.md)
by binding ordinary syscall copies and raw host destinations to retained physical
backing and content invalidation. It does not enable native execution. There is
**no new inotify09 speedup**: the last accepted full comparison remains
21.885 s Carrick / 5.980 s Linux (3.66x), from [context-borrow](../context-borrow/README.md).
Keep matched native macOS I/O controls separate and retain the direct host-file path.

## Implementation

The checked and internal ordinary guest copiers now retain the selected exact
physical backing through each copy. A writer-only projection shares the existing
mapping selection with the scalar read path; ordinary reads acquire no new pin,
Arc or allocation. Copied writes revoke affected instruction dependencies before
bytes change. Alias fallback retains the selected owner before its temporary
registry projection expires. COW writes revoke the new backing without revoking
the unchanged source.

`HostWriteRange` carries the actual guest range and selected host address.
`HostWriteGuard` admission can fail before a host call consumes input and closes
partial admissions on error or unwind. The HVF adapter validates the exact host
pointer, live owner and every participating page, then retains one backing pin
per contiguous destination until the host call finishes. Its executor-local
scratch retains capacity across calls. A changed second leaf, stale pointer,
wrong global owner generation, missing global generation, permissions and bounds
are refusal cases. Structural backing also retains its exact stage-2 record.
Legacy control mappings without tracked ownership retain their existing access;
this is not executable-publication coverage for those mappings.

The existing readv/preadv and recvfrom guards now reach that carrier admission.
The large engine pread route also uses it and prepares COW through the normal
engine writable-pointer path. The signed large-read check proves bytes, not that
this particular fast route fired. No publication permit, direct link or native
entry is authorized by a content observation.

## Executed evidence

Three red controls are retained: ordinary copy changed bytes without revoking a
dependency; disabled host-write admission failed to revoke; and an unstamped
mapping incorrectly downgraded an existing tracked global owner. The final
focused content run passes 11 tests, including alias writes, COW isolation,
partial admission, unwind, structural pin lifetime and a changed second leaf.

The new `kernel.mm.syscall-code-write` contract passes at scales 1/8/32/128:
zero measured heap allocations after warm-up and exactly N subscribed physical
page visits for N one-page writes. A positive allocator control fires. These
are structural bounds, not a wall-time result or a claim of zero added syscall
latency. A cross-page destination retains one owner pin rather than one per page.

`just test-kernel` passes 2,377 tests with one existing ignore, within that recipe's
scope. The file syscall integration run passes 29 tests, including refusal before
host input consumption. Scoped changed-package Clippy and registry checks pass
(35 contracts, 84 surfaces). The inventory delta from this step changes only
read/readv/pread64/preadv/recvfrom. Whole-workspace CI and formatting are not
claimed; an unrelated pre-existing formatting hunk was preserved.

## Signed differential remains red

The final signed guest reports:

| Check | Carrick | Native ARM64 Linux |
| --- | --- | --- |
| Cross-page readv | Pass | Pass |
| preadv bytes and source offset | Pass | Pass |
| 8192-byte read | Pass | Pass |
| Cross-page clock_gettime copy | Pass | Pass |
| Read-only readv EFAULT preserves source offset | **Fail: 8192 becomes 8196** | Pass |
| Cross-page UDP recvfrom | Pass | Pass |
| Child readv preserves parent COW bytes | Pass | Pass |

The initial fixture stopped at the offset assertion. Restoring the exact
before-step compiled source and running that identical new fixture reproduced
the same assertion failure. All 14 restored source files were returned
byte-identically to the candidate afterward. The final fixture records the
failure, runs the remaining cases, and still fails globally. No assertion,
budget or acceptance condition was weakened. The staged read fallback's offset
semantics remain a separate open conformance issue; no product fix is claimed.

Both the initial and final exact Python fixtures pass on a pinned native ARM64
Linux image. Docker ran after Carrick, never concurrently. Carrick's unentitled
negative controls pass and every signed run reports zero remaining scoped
processes. The embedded carrier's default deadline bounds its wait path; the
UDP readiness check also has a five-second bound.

The runner does not publish a passing receipt for a failed run. Initial,
before-step control and final executables were therefore frozen immediately
and independently attested with SHA-256, CDHash, LC_UUID, entitlement and DOF.
See the three `destinations-*-artifact.json` files. Their binaries remain under
`target/lease-cost/syscall-code-writes/`; no one of them is a passing gate.

## Performance decision and next work

A material original-workload improvement remains plausible because native
residence can avoid recurring hardware transitions. The watch-churn feasibility
fixture approached 1.15x Linux; its translated computation, memory and other
watch cases did not establish parity. That research result is not an original
inotify09 prediction. The added write tracking is correctness groundwork and has
no demonstrated performance benefit by itself.

Keep the next delivery narrow: prove private RX admission and bind code/direct-link
revocation to active-native drain, connect recovered DSR emission and exact HVF
handoff, then run signed guest code and the unchanged dynamically linked original
inotify09 with both race participants. Remaining raw/internal writes and guest
hardware stores must be mediated or excluded by that admission proof. Do not
expand a general code-cache or instruction-set project before this vertical path.

The decision screen remains at least 20% lower original completion time in both
predeclared balanced blocks, with native residence, transitions and fallback
reasons measured separately from untraced timing. This screen is not the near-1x
goal. More passing helper contracts do not increase confidence in that wall-time
outcome. Full mixed-engine semantics, original timing and probe/smoke/full
promotion remain open. Earlier [code-content failures](../code-content/README.md)
remain recorded and are not closed by this step.

## Provenance

Worktree: `/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick`.
HEAD: `9bb2392396b8531e93f5262657bf3aa9c5767488`, with pre-existing campaign changes.
The 2,479-input manifest identifies the final signed source; its revision is
`sha256:475bc5fa32a0cbbaa1b818e4547f1cbb7ab690c5cbc7ee8c6f87c0eaa35c1a57`.
The initial manifest is retained separately. Contract metadata is archived
alongside the compiled-source manifest. `implementation.patch` contains only the
delta against this step's saved starting files plus its new files.

The previously measured release CLI and frozen baseline both remain SHA-256
`1142bb6dc6202ab3675dc6485b4f479e1d9425b2b75a293c948aef5e65db8918`.
They were neither rebuilt nor promoted by these signed test runs. No commit or
push was made. Raw checks and limitations are in `verification.json` and the
adjacent logs. `SHA256SUMS` covers this directory, excluding itself.
