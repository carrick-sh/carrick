# File-Description Seam Progress

Controller: `docs/superpowers/plans/2026-08-27-fd-description-seam.md`

Task 9 controller: `docs/superpowers/plans/2026-08-28-fd-description-task9-canonical-authority.md`

Implementation base: `10dcaf444`

## Status

Tasks 1 through 9 are implemented. Task 9 uses the approved canonical-object
vertical slice rather than the superseded nine-site/model-table recipe retained
in the original controller for audit history.

## Integrated implementation

| Task | Evidence | Result |
|---|---|---|
| 1, K1 burndown gate | `77556ebc3` | Inventory, taxonomy, and monotone-ceiling checkers added. |
| 2, `DescriptionCommon` | `8c8952016` | Generic description identity/lifecycle state moved under the kernel description. |
| 3, shared status flags | `8dd3b9265` | One status-flags value per description. |
| 4, remaining generic fields | `ed4068dd8` | Generic description state consolidated. |
| 5, close the generic backing escape | `f87e9c5db` | `base()`, `base_mut()`, and the io_uring shadow removed. |
| 6, readiness authority | `f13337ec5`, `d01feb4a3`, `c802a86d1` | One typed readiness authority, including review fixes for wake/scaling behavior. |
| 7, readiness translators | `4950fb4d7`, `d4cc71b02`, `3373d2073` | Poll and epoll reduced to translators; FIFO reconnect/close review defects fixed. |
| 8, open authority backing | `99dd39d7e` | Trait-object backing kinds replace the closed backing enum. |
| 9.1, canonical target | `9a2af8df2` | Production launch creates no model table or model description. |
| 9.2, canonical capacity mutation | `004d5547e` | Exact table/slot-token resolution and one narrow pipe-capacity mutation seam. |
| 9.3, production activation | `531b34cbf` | `F_SETPIPE_SZ` routes through the canonical authority with no direct fallback. |
| 9.4, K1 evidence | `dda62fb2a` | Measured ledgers and monotone ceilings reconciled. |
| 9 acceptance prerequisite | `ac9e27c2b` | Graph-backed numeric `/proc/<pid>` leaves are resolved before context-free access following. |

## Review findings closed

Independent review rejected or repaired the following before integration:

- a strong root `Arc` that pinned an obsolete launch table;
- an independent request-id allocator that could collide with ordinary calls;
- authority routing that changed `EBADF` precedence;
- stale claims about host-fork/helper behavior;
- missing proof that exec and `CLOSE_RANGE_UNSHARE` successor tables remain valid;
- K1 ledgers whose counts fell without lowering the corresponding monotone
  ceilings; and
- an LTP setup failure where the graph-aware `/proc/<peer>/oom_score_adj`
  implementation was unreachable behind context-free symlink following.

The Task 9 Antigravity workers completed with `WORK=done`, `TESTS=pass` after
the findings were sent back to their original conversations and repaired.

## K1 receipts

Task 9 changed the measured ledger as follows:

- total inventory: 1768 -> 1763, with no additions;
- `table_guard`: 132 -> 131;
- `description_guard`: 215 -> 211;
- taxonomy: 364 -> 359;
- `create_install`: 75 -> 72;
- `inspect_misc`: 146 -> 144;
- `slot_description_mutation`: unchanged at 14; and
- ceilings tightened to `create_install = 72`, `inspect_misc = 144`, and—after
  independent completion review—`slot_description_mutation = 14`.

The later access-path prerequisite moved two `access.rs` inventory positions by
12 lines without changing any count or classification. The checked-in inventory
and taxonomy record only those deterministic location changes.

All three K1 checkers pass.

## Independent completion review

Two read-only reviewers re-audited the current tree against the original
Tasks 1-8 and the replacement Task 9 controller. Task 9 was READY/CLEAN with
15/15 focused canonical-authority tests and 5/5 dispatcher tests. The Tasks 1-8
review found two actionable residuals:

- the measured `slot_description_mutation` family was 14 while its ceiling
  still allowed 16; and
- Task 3 had left Task 2's temporary `#[allow(dead_code)]` on the now-live
  `DescriptionCommon` implementation.

Commit `be4aca0a7` lowers the ceiling to 14 and removes the suppression.
`python3 scripts/migrate/check-k1-burndown.py`, its `--self-test`, and
`RUSTC_WRAPPER= cargo check -p carrick-runtime` pass after the fixes. The K1
finding was also sent back to the original `task9-ledgers` Antigravity
conversation; its third turn independently made the same one-line correction
and passed the burndown, inventory, taxonomy, and diff checks.

## Host-gate receipts

At the Task 9 implementation checkpoint:

- `RUSTC_WRAPPER= just test`: pass, including `carrick-runtime` 2027/2027;
- `RUSTC_WRAPPER= just test-integration`: pass, including runtime 302/302,
  syscall-process 9/9, trace-profile 41/41, engine 31/31, and image 33/33;
- `RUSTC_WRAPPER= just clippy`: pass;
- `RUSTC_WRAPPER= just doc`: pass;
- `just fmt-check` and `git diff --check`: pass; and
- `RUSTC_WRAPPER= just lint-domains`: semantic and conformance checks pass,
  then the known host-authority positional inventory stop reports `changed=[]`.

After `ac9e27c2b`, `RUSTC_WRAPPER= just test`, `RUSTC_WRAPPER= just clippy`,
`just fmt-check`, the three K1 checkers, and `git diff --check` pass again.

## Signed acceptance receipts

The focused cross-process `oomscoreadj` probe was red before `ac9e27c2b`
(`foreign_pid_file_exists=false`) and green after it
(`foreign_pid_file_exists=true`). Cross-process value reads, writes, fd-reuse
absence, and dead-pid absence remained green.

On the rebuilt signed binary after `ac9e27c2b`, the Carrick-first cached-oracle
gate reports:

- `ltp-fcntl30`: MATCH, Carrick 4/4, oracle 4/4;
- `ltp-fcntl37`: MATCH, Carrick 3/3, oracle 3/3.

The live native-arm64 Docker phase then passed sequentially:

- `fcntl30`: 4 passed, 0 failed/broken/skipped;
- `fcntl37`: 3 passed, 0 failed/broken/skipped.

The final focused signed-probe run used implementation HEAD `ac9e27c2b` and:

- SHA-256: `8448c4d5dc0b7b3e7de201596b9c055474e14d46c792c264e784b881e2355204`;
- CDHash: `08b5e080087042d287fb34fa5a310681d581fd7c`;
- LC_UUID: `605A3DE2-5998-3E99-94B8-06405EC8024E`;
- entitlement: `com.apple.security.hypervisor = true`; and
- `__TEXT,__dof_carrick`: present.

`CARRICK_PROBE_FILTER=fcntlpipesz,pipeszcrossend,spawnflagmatrix,epollcluster`
passed for arm64 musl and glibc, the retained CLI/container contracts passed,
and the unsigned negative control returned the expected entitlement error. The
first public-wrapper attempt stopped fail-closed when unrelated retained probe
`arm64:musl:execfromthread` flipped once from its checked-in XFAIL to an
unexpected pass; after scoped cleanup, the quiet-host rerun reproduced the
known gap and the complete public gate passed. No baseline or known-gap entry
was changed. Final scoped cleanup reported zero processes for run id
`fd-task9-final`.

## Scope boundary

Task 9 does not claim host-fork transport, IPC equivalence, full file-table
lifecycle binding, or close-family migration. Those remain Wave 3/4 work under
the approved atomic migration and the runtime-abstraction controller.

## PTRACE acceptance closure

Ruling: prove the structural-vvar fork fix through the production host-only
foreign-MM COW transaction on the exact prepared child ledger, rather than
fabricating an `HvfVmState` or starting an HVF VM from a host unit test. This
must demonstrate the original semantics at vvar + 24: child-private mutation
succeeds and parent bytes remain unchanged. If wrong, the unit test could miss
integration that exists only in `refresh_fork_process_state`; the signed public
probe and full ecosystem gates therefore remain mandatory on the exact landed
artifact.

PTRACE closure: fix round 1/5 (one finding addressed, two open). Exact
structural permission authentication is resolved. A different stage-1 IPA must
also have an authenticated overlay owner rather than bypassing the error, and
the vvar test must use privileged-internal COW while preserving guest-read-only
authority; the ordinary foreign-COW substitute was rejected by review.

PTRACE closure: fix round 2/5 (two prior findings addressed, one new finding
open). Exact overlay ownership, exact-custody task COW, canonical lookup reuse,
privileged vvar refresh, read-only AP, parent preservation, child-private
ownership, disarm, and one flush are all covered. Review found that overlay
authorization sampled only the candidate base; a partial overlay could hide an
unowned later leaf. Round 3 requires full-range authorization and a red-first
partial-overlay regression.

Ruling: stop the PTRACE perfection loop and use the signed public conformance
probes plus exhaustive ecosystem suite as the landing authority, per the
user's explicit direction. The incomplete round-3 experiment was removed while
the probe-blocking round-2 structural-vvar fix was retained. If wrong, a stale
coarse mapping with only a partially authenticated replacement overlay remains
a fail-open fork edge; it is recorded here rather than silently represented as
closed.
