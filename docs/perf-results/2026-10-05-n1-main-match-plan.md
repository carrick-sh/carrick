# N1 main-result match implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline. Steps use
> checkbox syntax; the director owns integration and acceptance.

**Goal:** Make `work/n1-cm` pass every signed test that main `65098ea0e`
passes, retaining evidence for failures shared with main.

**Architecture:** Preserve the shared core's MM and frame authorities.
Integrate the file-mmap reservation seam into the existing runtime transport;
restore any missing capability forwarding with a red-first consumer witness.
Diagnose remaining signed fork failures from exact retained artifacts before
changing production code.

**Tech Stack:** Rust, VM-free Cargo tests, signed HVF embed, carrick trace and
LLDB, exact offline fixture bundles, exclusive cloudmac host lease.

**Spec:** Owner brief retained at
`/Volumes/carrick-build/evidence/n1-cm/main-match-20261005/owner-brief.md`.

## Global constraints

- Start from pushed handoff `7f6a2f757`, on integrated N1 `56bf8c0ca`.
- Merge file-mmap fix `3c5113bda` without rebasing the authorized base.
- Re-prove every combined-stack guarantee red, then restore and verify green.
- Signed runs require a director-published exact bundle and the gate lease.
- Force the EL1 image rebuild and retain its hash and artifact identity.
- No Docker, load generators, timeout or retry closure. The director
  subsequently authorized `just accept --phase signed` for exact `fa98b9f9c`.
- Stamp every run; clean only its scope with `scripts/sudo/kill.sh`.
- Commit and push each fix; post review-ready SHAs for bundle publication.
- File-table lease and clone-TID remain with n1g6; report causes there first.

## Review focus

- Runtime adapters must preserve backend-only reserved-content authority:
  exercise denied ordinary writes and successful exact reserved writes.
- Readonly imported vvar must retain native RO/NX ceilings and physical table
  custody: repeat the original image, adoption, refresh and inventory controls.
- Two live MMs sharing a VA must select their own physical owner and identity:
  repeat native and neutral core witnesses, including the x86 projection.
- File mapping over a retired EL1 reservation must load content and settle
  through its admitted venue: reverse the file-mmap selection and expect errno 12.
- Main-pass coverage must be complete by test identity: compare every baseline
  pass row with exact stack results, rather than closing on the five fork cases.

### Task 1: Integrate reserved file content and its runtime transport

**Files:** Merge the seven files in `3c5113bda`; inspect
`crates/carrick-runtime/src/runtime.rs` for `SplitView` transport.

**Interfaces:** Consumes `GuestMemory::write_owner_reserved_bytes` and
the borrowed reserved-write proof; produces one combined committed stack.

- [x] Merge the exact file-mmap commit, preserving identity transport.
- [x] Run `delegated_fixed_file_map_reuses_a_retired_el1_reservation`.
  Expected: pass; reversing reserved-write selection must fail with errno 12.
- [x] If the split adapter loses the new capability, write
  `split_loop_preserves_reserved_file_content_writes` before fixing it.
  Expected red: reserved content is refused; ordinary writes remain denied.
- [x] Forward only the reserved-content capability and rerun both witnesses.
  Expected green: exact bytes copied, ordinary writes still denied.
- [x] Commit integration and any correction separately, with verification.

### Task 2: Audit the combined stack

**Files:** Evidence under `main-match-20261005/`; audit tables and source
comparisons supplement the existing fork integration report.

**Interfaces:** Consumes committed Task 1 source; produces kept/ported/dropped
rows, negative-control receipts and restored positive results.

- [x] Re-run the ten-fix semantic audit, with unique new receipt paths.
- [x] Add the file-mmap reversal and any new transport reversal.
- [x] Inspect the combined commit inventory for further guarantees requiring
  controls; include preserved exit/wait fixes where they enter this scope.
- [x] Restore each edited file byte-for-byte; verify clean source and all
  positive witnesses. Expected: no dropped guarantee or unqualified red.
- [x] Run focused host suites, fmt-check, clippy and domain lint; reconcile
  reviewed inventories on a clean committed tree.
- [x] Push and post the exact SHA for a fixture bundle.

### Task 3: Qualify signed results against main

**Files:** Per-SHA evidence with `results.tsv`, bundle/image/artifact identities,
trace controls, cleanup receipts and the director's baseline pass list.

**Interfaces:** Consumes an exact bundle and main's per-test verdicts;
produces a test-identity comparison and a list of stack-only failures.

- [x] Restore the exact bundle under the gate lease; force and hash the EL1
  image rebuild. Expected: source and fixture identities match the SHA.
- [x] Run the five fork tests and three qualified refusal traces, then
  `el1_host_buffers_follow_reused_mapping_in_two_live_processes` and
  `case_inotify_watch_churn` with their applicable signed runners.
- [x] Run every additional main-pass binding: signed `el1_` embed,
  fresh-executable-page, generic probe shards and probe cases.
- [ ] Achieve parity after classification. Expected landing bar: zero tests
  passing on main fail on the stack; shared failures remain recorded.

### Task 4: Repair stack-only failures and hand off

**Files:** Only the owner/transport area named by retained trace or carrier
evidence, its cheapest capable witness and applicable contract binding.

**Interfaces:** Consumes a qualified failure; produces one independently
reviewable fix and a new exact signed result.

- [ ] Trace the actual failed boundary and inspect the carrier ring/core.
- [ ] Add a deterministic red witness and record the expected failure.
- [ ] Apply the smallest shared-owner correction; verify red-to-green and
  focused neighboring tests without changing budgets or concurrency.
- [ ] Commit, push and post each SHA; obtain a new exact bundle before the
  signed confirmation. Re-audit every guarantee after any authorized rebase.
- [ ] Perform a fresh whole-branch review, update draft PR #59 and post
  review-ready with the per-test comparison and all remaining shared failures.

## Current evidence

Exact `fa98b9f9c` signed execution is complete and red against main: see
`2026-10-05-n1-combined-fork-audit.md`. Native reserved-content consumer repair
is active; its VM-free controls do not confer signed acceptance. The 78
unexpected failure rows, early fork failures, incomplete generic subprobes and
fresh-executable missing result remain open. No budgets were weakened.

Native reserved-content repair and inventories are pushed as `506be1a74` and
`1e521ab1a`. The retained second-fork pool collision additionally has a native
exit/exec red-first repair; see `2026-10-05-n1-fork-control-retirement.md`.
Neither repair has a new signed verdict yet. Main's exact first failure lines
for its six excluded reds remain requested; ptrace errno 38 is not established
as a stack-only regression.
