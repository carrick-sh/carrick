# Order 6 rebase onto reviewed order 5

This packet supersedes the pre-rebase worker verdict in
`2026-10-06-x86-order6-lifecycle-mapping.md` and its verification JSON.
Comparison base: `7b6d15813d328899c63a01bd1e506cc482425735`.
Original PR #71 head: `3fd7862be859e106cdfa27ec183fea9cf66ccf63`.
Host: `x86-w1`, Linux x86_64, real `/dev/kvm`; no Docker or HVF lane.

## Ownership resolution

The four original commits retain their authors. Seven initial source conflicts
and the subsequent host-authority inventory position conflict are resolved.
Order 5's core entry and ABI receipt implementation stays intact. The Linux
routing table still decodes typed `LifecycleCall`, and its `finish` authenticates
ordinary completion before installing the result and recording `orig_arg0`.
Its host-work refusal exempts only robust/mask/altstack setup, never gettid.
The ordinary and Born-in-zone transfer branches consume owned handoff receipts.

Order 6 removes the semantic lifecycle method from `PendingFamilies`: adapters
lend `LifecycleNative`, and Linux `invoke` returns data outcomes. The temporary
`pending_lifecycle` module is deleted rather than retained beside the moved
owner. Linux owns clone, signal mask, alternate stack, robust registration and
clear/wake policy. Core owns neutral incarnation, admission, publication and
rollback. Displaced ARM policy and ABI bodies remain deleted.

The ARM retirement hook and both x86 retirement/park hooks obtain receipts from
`carrick_core::entry::{retire_current,prepare_handoff,publish_handoff_park}`.
Receipt custody spans the native successor switch; raw scheduler transitions
cannot authenticate an entry transfer. Failed retirement restores the acquired
live membership and drops the exit admission rather than reporting completion.
The VM-free X5 fixture uses the same retirement authority.

`carrick-el1-abi/src/lib.rs`, including `CurrentTask`, has no diff against the
reviewed base. Its 128-byte stride, offsets and ABI hash assertions remain in
the retained ABI suite. No protocol/layout change or fallback owner is added.
The existing native FS/user-GS/XSAVE leaves remain shared with CPL0 progress.

## Every original order-6 red

All mutations were restored before the final green build. Each behavioral red
exited 101 with one failed test, rather than a compiler error. No red was dropped.

| Original red | Disposition and reason | Re-proved failure |
| --- | --- | --- |
| Shared lifecycle owner fence | Kept. The built source fence reads the actual `7b6d15813` dispatch source temporarily; reviewed order 5 still has the semantic lifecycle hook that order 6 must remove. | `order 6 must remove lifecycle from PendingFamilies` |
| ExitingPublished rollback to Born | Kept. The neutral core interleaving and 13-acquisition budget are unchanged. | `Some((1, Born))` instead of `Some((1, Published))` |
| Nonzero child-tid clear | Ported. X5's native retirement fixture now carries the core receipt and supplies Linux result-installation hooks; the clear-before-wake assertion is unchanged. | 1 instead of 0 at `clear before wake` |
| Unavailable native stack/TLS accepted | Kept. Force the shared production `child_context_supported` leaf to accept; the same Linux dispatch refusal must still precede output/pool changes. | Served instead of Forward |
| Wrong child FS selection | Kept assertion, ported native handoff adapter. Rebuild CPL0 with Linux-selected TLS + 8 (a mapped wrong word); an actual FS-relative child load must still detect it. | 0 instead of 62720 (`0xf500`) |
| Suppressed successor XSAVE restore | Kept assertion, ported native handoff adapter. Rebuild CPL0 without restoring the retained successor image; the real parent's XMM15 must still distinguish its saved state from the child's destructive live state. | Child inherited `0x5a`; resumed parent words are zero |

Commands and logs are retained in the sibling rebase verification JSON.
The fence binary is built green first, then executes while reading the reviewed
base file; this avoids treating a baseline compile incompatibility as a red.
The two hardware mutations each compile successfully before their KVM red.

## ARM production census against 7b6d15813

The unchanged standalone `order6-census` parser counts physical Rust source
lines excluding test item/module spans, test-only fields/initializers and
in-function test blocks. The base is a `git archive 7b6d15813` extraction of
these three `src/` directories. Commands:

```sh
cargo run --locked --offline --manifest-path docs/perf-results/order6-census/Cargo.toml -- /tmp/ord6-rebase-census-base
cargo run --locked --offline --manifest-path docs/perf-results/order6-census/Cargo.toml -- .
```

| Crate | Reviewed base production | Rebased production | Reduction |
| --- | ---: | ---: | ---: |
| carrick-el1 | 10,879 | 10,432 | 447 |
| carrick-el1-abi | 9,311 | 8,053 | 1,258 |
| carrick-aarch64 | 13,468 | 13,468 | 0 |
| **Total** | **33,658** | **31,953** | **1,705** |

All source lines including tests decrease from 58,829 to 56,634 (2,195).
The revised production delta is measured against the requested reviewed base;
it does not reuse the historical 1,813-line delta against `0f476ce7a`.

## Verification and limits

Final commands, artifact hash and gate outcomes are in the sibling verification
JSON. KVM X5 executes 16/64/256 births per MM in two live MMs, with
96/384/1536 semantic entries, matching completions and zero host forwards.
These witnesses retain their existing bounds and workloads.

No Docker, signed HVF, `just accept`, `remote-accept` or remote recapture was run.
The bounded two-context KVM fixture still does not qualify production executor
pool exhaustion, adopted-job retirement or the director's ARM signed comparison.

Shared tests, ARM/ABI/participant tests, image build, all three KVM targets,
touched-crate all-target Clippy, product `just clippy` and `just fmt-check`
all exited zero. The product check covers the runtime Linux feature closure.
The Linux Clippy configuration emits its existing unreachable
`libc::proc_listallpids` catalog warning; no source diagnostic failed Clippy.

## Clean reconciliation and full lint verdict

The clean-tree reconciler on `8f2707720` exits zero: all five position/fingerprint
inventories require zero changes, and all 661 authority rows are preserved.
It executes Linux CLI/runtime capture profiles and explicitly leaves the
macOS capture untouched. No inventory classification or capture was fabricated.

`just ci` passes formatting, product Clippy, probe coverage, product closure,
Semgrep, escape-hatch/carrier scans and the scanner self-tests before stopping
at the authority-artifact fixture suite: one failure and two errors (three
self-tests) report that the actual reviewed projection disagrees with the
macOS compiler capture. The director must recapture the rebased source.
Later CI stages were not executed by that stopped recipe.

**macOS projection is not the only remaining lint finding.** The separate
`check-personality-boundary` command reports nine `PendingSignals` violations
in `carrick-signal-core/src/policy.rs`. Running the same auditor against an
independent `git archive 7b6d15813` tree with that tree's own locked offline
metadata reports the exact same nine file/line/column/message tuples, with
zero additions/removals. The source blob is identical in both trees:
`bd084c723cc4058ef5e4f4c25a8f9cce4db5983e`. These unchanged findings were not
hidden, weakened or fixed outside the rebase fence. Full lint/CI remains red.

The final qualified CPL0 image SHA-256 is
`8f53a192ab861dddca6eec6c630a4b5c843a47d67090f0ce55c7cb9aa38a2206`.
No load generators or CPL0 test processes remain after scoped test completion.
