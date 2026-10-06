# N1 fork lane pause handoff

The director paused N1 while x86 settles on the shared core. This stack is
complete through source `6607b02817c24a93156e49f3abc149aa591f47d6`, based on
order 4 `56bf8c0caefe39fcc2260345d0a54772a74bffad`. There are no half-finished
edits, dropped guarantees or fixes in progress. Draft PR:
https://github.com/carrick-sh/carrick/pull/59.

Evidence root: `/Volumes/carrick-build/evidence/n1-cm/fork-ea0b4c26b/`.
`stack-audit-order4.tsv` records each fix; its `controls.tsv` qualifies 19
behavioral negative commands and 25 passing restored tests on the shared
path after the rebase. Signed results remain those of the earlier exact
`ea0b4c26b` artifact.

| Original fix | Status | Current fix commit / guarantee |
| --- | --- | --- |
| `c4b1836c4` | Kept | Private identity-only structural copy survives in the shared owner |
| `dc85ec647` | Kept | Live-leaf COW settlement survives |
| `f5121942c` | Kept | Later owner edits remain valid during settlement |
| `474d70f0e` | Kept | Live-leaf vvar refresh survives |
| `e6411c853` | Ported | `65bab0a1d`: vvar RO/NX sealing and native ceilings |
| `1ce444334` | Ported | `9aeaf6611`: readonly native leaf adoption |
| `be40000e3` | Ported | `29ccd7263`: canonical physical fork extents in core |
| `2414ef7dd` | Ported | `561712029`: bound physical table custody |
| `efc86a9fd` | Ported | `6607b0281`: closed identity words through the shared owner |
| `b26645d94` | Kept | `86a2dd1aa`: anonymous owner supply selection, both ISA witnesses |

Supporting red-first commits are `92156c89e` (actual fork owner-fault
witness), `48a6f1f05` (both ISA owner-fault witnesses), and `88d9e7c51`
(neutral physical-extent witnesses). `8990635b4` updates the earlier owner
fault inventories; `7228bb07f` records the initial integration audit. The
fixture-lock refresh is now upstream as `14649f563`; its duplicate was
omitted during rebase. The complete pre-rebase stack is retained on
`n1-cm-before-order4-ee105fb96`.

## Open signed failures

**None of the five signed fork tests passes at `ea0b4c26b`.** Every first
failure is the new integration regression
`HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage`.
The VMA, fixed-over-COW and ptrace cases again fail child vvar COW; spawn
fails before terminal settlement and fork-COW fails in warmup.
`results.tsv`, `s1.log` through `s5.log` and the three refusal traces retain
the per-case comparisons with `50d648e76`. All three traces report:

```text
OWNERFORKREFUSAL1|summary|closed_children=2|refusals=0|guest_results=1|witness_closed=1|errors=0|bounded=0
```

Admission controls fire; no refusal/check-ID/arena rows appear because the
failure occurs later. `vvar-coverage.core` and `vvar-coverage-lldb.log`
retain the actual carrier's 31-entry event ring and typed 518-row inventory
walk proving the fragmented vvar extent. Image provenance is retained in
`el1-image-freshness.json`; all eight signed scoped cleanups returned zero.

These ports repair the corresponding VM-free witnesses but have not run
signed. Later failures from `50d648e76` remain unqualified on the repaired
integration: child SIGSEGV in VMA/fixed-over-COW/fork-COW, ptrace options
errno 38, and spawn terminal-settlement SIGABRT. File-table lease and
clone-TID belong to n1g6 and were not edited here. No timeout, retry or
budget change is proposed as closure.

## Next step after the pause

Rebase once onto the director's settled shared core, repeat the ten-fix
audit, and reconcile clean authority captures. Obtain a new exact fixture
bundle for the resulting SHA. Under the host lease, restore that bundle,
force the EL1 image rebuild and record its embedded hash, then run the five
fork tests and three refusal traces with retained artifacts and scoped
cleanup. Compare first failures against `ea0b4c26b` and `50d648e76` before
making any signed improvement claim. No further signed cycle is authorized
during the pause.
