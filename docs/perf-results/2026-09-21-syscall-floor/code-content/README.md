# Carrier instruction-content dependencies

2026-09-22. This implements the first content-revocation portion of the
[resident native-region design](../native-islands/design.md). It does not enable
native execution or complete that design's original-inotify09 milestone. No new
inotify09 performance result is claimed: the last accepted full comparison is
21.885 s Carrick versus 5.980 s Linux (3.66x), recorded in
[context-borrow](../context-borrow/README.md). Keep matched macOS I/O controls
separate. The 20% full-workload expansion screen and near-1x objective stand.

## Implemented

Physical backing now owns lazily allocated instruction-content dependencies,
indexed by 4 KiB physical page. Captures share a revocable page identity; writes
make it permanently stale. A later capture gets a new identity. Backing
retirement revokes surviving observations. COW creates independent backing, so
a write to the child does not revoke the source's unchanged bytes. Equal offsets
in different owners cannot authenticate each other.

The production foreign-copy commit invalidates affected dependencies before
copying bytes, including when its writing VA is non-executable. The existing
native data capability also admits a writer before returning a writable pointer.
That admission remains live through pointer use and ends on active-grant drop,
conversion from a mutation-scoped grant to a retained preparation, or span drop.
Preparing a window alone neither admits a writer nor revokes observations.
Reusing it establishes a new writer admission. The owned writer uses the existing
backing Arc; it does not allocate a second tracker for each access.

Authenticated instruction reads retain these dependencies through the HAL into
`InstructionRead`. Mapping validation and participating-write validation are
explicitly separate. The ordinary reader still handles execute-only deferred
recipes, but labels them `Untracked`; missing recipes still fail. Other backends
default to `Untracked`. **No content-status value is an executable publication
permit.** Guest hardware stores and several existing host-write paths are not
covered yet.

## Executed controls

Three behavioral red controls are retained:

- `red-foreign-write.log`: the real foreign COW/copy path changed bytes while
  both dependencies on that physical page remained valid.
- `red-native-write.log`: the real native data pointer changed bytes without
  revoking a content dependency.
- `red-native-scope.log`: temporarily omitting `ActiveNativeData` access release
  caused a subsequent real carrier instruction read to fail with `Retry` after
  all native work had stopped. The omission was restored before final checks.

The final tracker tests cover cold first-observer/writer races, overlapping
writers, concurrent final-observer cleanup, page crossings, out-of-range input,
backing retirement and unrelated-owner isolation. Carrier tests cover foreign
COW/copy, scoped native writes and reuse, execute-only resident reads and deferred
recipes. The foreign-copy test uses two dependencies on one physical page; it
is not a full two-MM executable-alias/publication test.

`kernel.mm.native-code-content` emits and evaluates real `ContractObservation`
records at scales 1/8/32/128. N one-page writes visit exactly N subscribed page
entries while 128 other page dependencies stay valid. The work count comes from
the actual invalidation traversal. The cold-write path allocates no registry.
The existing native-data activation contract still reports zero heap allocations
and zero repeated leaf checks during warmed reuse at all four scales. These
checks establish structural bounds, not wall-time improvements.

Source-stamped final checks and the signed guest regression results are recorded
in `verification.json` and the adjacent raw logs. The first dependency-inclusive
Clippy invocation failed on six existing `manual_is_multiple_of` diagnostics in
`carrick-aarch64` anonymous-discard code. The modified packages pass scoped
Clippy with `--no-deps -D warnings`; the full workspace lint gate is not green.
The contract registry passes, and inventory regeneration changes only the
`process_vm_writev` and `ptrace` entries.

## Signed results and open failures

The final signed warm-RX PTRACE_POKETEXT regression passes, along with the
unentitled negative control and run-scoped cleanup. Its exact executable is
frozen under `target/lease-cost/code-content/poketext-final`; the final signed
receipt identifies its SHA-256, CDHash, LC_UUID, entitlement and DOF. The initial
passing artifact was re-signed by the next runner, so promotion evidence here
uses the later frozen artifact and `signed-poketext-final-artifacts.jsonl`.

The separate signed foreign-copyout run is **not green**. Anonymous copyout
returned `(-1, EFAULT 14, child_status 1024)`; private-file copyout passed. The
runner does not publish failed-run receipts. The failed candidate was therefore
frozen immediately and independently attested in `deferred-candidate-artifact.json`.
Do not substitute the control or text-patching receipt for that failed run.

The exact before-step source was restored temporarily and a signed control was
built. That control passed. A fixed A/B/B/A diagnostic population on the frozen
control and candidate also passed all four runs. This leaves the original
failure intermittent and **unattributed**, not repaired or waived. The same
symptom was previously recorded in [private-publication](../private-publication/README.md),
which likewise did not establish baseline-versus-candidate causality. Every
source file was restored byte-identically after this diagnostic.

Fresh native ARM64 Linux controls pass both anonymous-copyout modes and the
text-patching probe. The exact private-file fixture fails its own assumption
that an unconstrained Linux mmap is 16 KiB aligned, before exercising the write;
it is not a qualified Linux differential. Scripts, image IDs, outputs and this
refusal are retained. Carrick and Docker phases were serialized. No image-tag
comparison is used to claim a same-image performance result.

The broader VM-free foreign-MM run is 75 pass, 1 fail, 1 existing ignore. The
failure is the pre-existing fresh-publication budget: one page-table invalidation
where the contract permits zero. It reproduces twice on the frozen before-step
unit binary with matching before-step contract metadata. The first two control
attempts loaded the new metric descriptor into the old enum and failed schema
parsing; those logs are retained but are not attribution evidence. Only
`baseline-maintenance-qualified-{0,1}.log` establishes the baseline structural
failure. Neither budget nor test was weakened.

## Required next integration

| Writer or lifecycle | Current evidence / remaining work |
| --- | --- |
| Foreign prepared copy | Invalidates before copy; COW source preserved |
| Native data pointer | Invalidates before access; scope release and reuse covered |
| Ordinary syscall copies | `write_guest_bytes` and `write_guest_bytes_checked` still need retained-owner write admission |
| Zero-copy syscall destinations | Existing `HostWriteGuard` callbacks need carrier participation; returning a raw pointer alone cannot bracket its later use |
| Zero/discard/remap/internal writes | Audit `zero_guest_backing` and publication/scrub paths; mediate writes that can reach observed live backing |
| Guest HVF stores / writable aliases | Require complete write-fault mediation or proven private RX admission; RX permission alone does not establish absence of writable aliases |
| Unmap/protection/COW/exec | Mapping revalidation rejects stale reads; translated entries and direct links still need atomic revocation and drain |
| External shared-file mutation | Exclude from initial native admission until mediated; do not treat a retained pointer as immutable code |

Continue toward one vertical milestone, not a general code-cache project:
complete writer participation for a proven private RX admission path, bind entry
and direct-link revocation to the existing exact-MM native execution/drain
protocol, and use that permit in recovered DSR emission and precise HVF handoff.
Run actual signed guest code before growing instruction coverage. Then run the
unchanged dynamically linked original inotify09, with both race participants,
and apply the predeclared balanced full-completion screen. No original native
execution, mixed-engine acceptance, full probe/smoke/full promotion, or new
performance acceptance is established here.

## Provenance

Worktree: `/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick`.
HEAD: `9bb2392396b8531e93f5262657bf3aa9c5767488`. The worktree already contained
substantial campaign changes; HEAD is not a clean-source identity.
`source-inputs-sha256.txt` identifies the compiled source inputs and
`source-revision.txt` is that manifest's SHA-256. `implementation.patch` is the
change from this step's saved starting files, plus the new implementation and
contract files. Earlier campaign work is preserved. No commit or push was made.

The previous signed release CLI and frozen baseline remain SHA-256
`1142bb6dc6202ab3675dc6485b4f479e1d9425b2b75a293c948aef5e65db8918`.
Signed regression test executables have their own immutable execution receipts;
they do not promote that older CLI or establish a new full-workload measurement.
