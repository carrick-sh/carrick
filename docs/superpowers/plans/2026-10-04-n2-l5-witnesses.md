# N2 L5 red-first handoff

Base: `b1167c6e19811c5b3a601d979cedca844656454f`, cloudmac, 2026-10-04.
Scope: tests only; **no row closed and no production path activated**.
Controller: PR #25's `2026-10-04-n2-readiness.md`, L5 / landing E.

## Witnesses and observed red

Auto-discovered target: `crates/carrick-mem/tests/n2_readiness_exec.rs`.
Each test invokes today's public `plan_elf_load_bytes_for`, first verifies
the valid control, then changes one header field. Each has the requested
`N2 red witness: row 11: ...` ignore reason. Each individual ignored run
exited 101 with **one failed, zero passed, two filtered out**.

| Witness | Row | Observed assertion output (relevant fields) | Production change that turns it green |
| --- | --- | --- | --- |
| `relocatable_elf_cannot_prepare_an_exec_image` | 11, invalid ELF | `ET_REL produced an exec load plan: Ok(LoadPlan { ... e_type: Other(1) })` | The one Linux load-plan parser rejects non-executable/non-shared-object ELF types before returning a prepared plan. |
| `oversized_load_file_cannot_prepare_an_exec_image` | 11, invalid PT_LOAD | `p_filesz > p_memsz produced a load plan: Ok(LoadPlan { ... file_size: 4, memory_size: 3, ... })` | Validate PT_LOAD file/memory size consistency in the parser before publishing its plan; do not rely on later host region materialization. |
| `unterminated_interp_cannot_select_a_different_interpreter` | 11, PT_INTERP | `unterminated PT_INTERP produced a load plan: Ok(LoadPlan { ... interpreter: Some("/ld.s"), ... })` | Validate the terminating NUL inside the declared interpreter extent before decoding/selecting its pathname. The fixture contains `/ld.so` with its NUL just outside that extent. |

Authority: [System V ABI Program Header](https://www.sco.com/developers/gabi/latest/ch5.pheader.html)
defines PT_LOAD size consistency and the terminated PT_INTERP pathname;
[execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) requires a
recognized executable format. These assertions demand rejection, not an
unqualified errno. No Linux oracle was run and no GPL source was consulted.

## Dependencies and deliberately unclaimed coverage

- The test lives in `carrick-mem/tests`, allowed by this phase's crate-test
  exception. `carrick-kernel-example` has no dependency on the ELF parser.
  Adding that dependency would edit a driver-reserved manifest; duplicating
  the parser would test a second implementation. No empty or fake-red
  `EX/tests/n2_readiness_exec.rs` was added.
- `kernel.el1.creation-native-path` is the plan's contract family (row 11
  semantics / row 13 work), but its descriptor is absent on this base.
  Contract registration and parser extraction/export belong to the driver.
  These parser assertions are preparation evidence, not registered contract
  acceptance or a zero-host-semantics census.
- **Two live same-VA MMs, exact old MM/fd/signal rollback, delayed owner
  completion, and staged OFD short-copy/cancel remain unbound.** N1 owner Exec
  prepare/commit/abort and the actual staged OFD cursor are unavailable here.
  No fake owner, cursor, zero counter, or missing-symbol test substitutes for
  those production APIs. The driver must retain two live owners throughout
  those future schedules, including vfork and stale successor publication.
- Today's public graph has existing controls in `n2_task_transactions`:
  `clone_during_exec_close_cannot_publish_and_rollback_reopens_birth_at_1_8_32`
  and `vfork_releases_only_on_exact_child_mm_release_at_1_8_32`.
  `kernel/exec.rs::every_exec_failpoint_preserves_published_generation` also
  covers graph failpoints. Copying these into newly ignored tests would not
  demonstrate a new failure or owner-MM integration.
- Non-UTF8 argv/env are already byte vectors in `dispatch/proc.rs::execve`
  and `runtime/exec.rs::load_execve_image`. Missing interpreter detection
  already returns `AddressSpaceError::Io(NotFound)` in `memory.rs`, while
  `load_execve_image` currently maps that loader error to ENOEXEC. That private
  runtime entry is not callable from an auto-discovered integration test;
  testing the public loader alone would not pin the runtime errno mismatch.
  Driver-owned preparation export is needed for that witness. No green-only
  argument/parser test is presented as a new red.
- No parser fixture proves venue, guest execution, deterministic work budgets,
  syscall errno, vfork wake cardinality, or rollback after owner admission.
  Signed/EL1, native-arm64 Docker, performance and composed acceptance remain
  driver obligations after N1. No Docker or guest was started in this phase.

## Reproduction and receipts

All commands run in the foreground after `source /Volumes/carrick/dev/env.sh`,
with `CARRICK_RUN_ID=n2-l5`. Receipts are under `target/n2-l5-receipts/` in
this worktree (not committed).

```sh
cargo test -p carrick-mem --test n2_readiness_exec relocatable_elf_cannot_prepare_an_exec_image -- --ignored --exact --nocapture
cargo test -p carrick-mem --test n2_readiness_exec oversized_load_file_cannot_prepare_an_exec_image -- --ignored --exact --nocapture
cargo test -p carrick-mem --test n2_readiness_exec unterminated_interp_cannot_select_a_different_interpreter -- --ignored --exact --nocapture
cargo test -p carrick-mem --test n2_readiness_exec
just clippy
just fmt-check
just lint-domains
```

The three red logs are `relocatable.log`, `oversized-load.log`, and
`unterminated-interp.log`; ordinary selection (`ordinary.log`) is green:
`0 passed; 0 failed; 3 ignored`. This is intentional exclusion of the reds,
not a conformance pass. Remaining check results are recorded below.

- `just clippy`: exit 0 (`clippy.log`).
- `just fmt-check`: exit 0 (`fmt-check.log`).
- `just lint-domains`: exit 0 (`lint-domains.log`). Its compiler census covers
  the three macOS profiles, 618 reviewed rows; Linux/FreeBSD/NetBSD profiles
  remain pending as explicitly reported by that gate.
- `scripts/sudo/kill.sh n2-l5`: exit 0, zero remaining scoped guest processes
  (`cleanup.log`). No guest was launched.
- Additional rulebook `just ci`: exit 101 (`ci.log`). Checks through workspace
  build passed; rustdoc failed on unchanged `carrick-mmu-core/src/aarch64.rs`
  at lines 299, 826, 889, 949, and 1831 (unresolved `[5:0]`,
  `publish_existing_invalid_private_pages`, and `AP[1]` links). Those same
  inherited errors are recorded in the readiness plan. CI's host-test and
  integration stages were not reached; no full-CI or acceptance claim.
- Parser witness source SHA-256:
  `0096522244756e8d82d1b1b1f8ba8e294bc036c2ca1ec15741aec3a6a5b61d55`.
