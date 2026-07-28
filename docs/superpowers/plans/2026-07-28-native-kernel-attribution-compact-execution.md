# Darwin/AArch64 Kernel Attribution Compact Execution Plan

**Status:** authoritative execution controller
**Approved:** 2026-07-28 compact reset
**Supersedes for execution:** `2026-07-27-native-kernel-oncpu-attribution.md`

## Outcome

Turn the accepted but undifferentiated Darwin-kernel CPU bucket into two
receipt-bound whole-process-tree kernel-stack profiles, select one bounded
mechanism to spike, and then pursue a repeatable untraced wall-clock win.

This is not another plan-review campaign. Each code task follows strict
red/green TDD, one implementation commit, and one independent task review.
The detailed superseded plan remains a research reference only.

## Measured state and target

- Official baseline: `C0=19,375 ms`, `D0=1,007 ms`, `R0=19.2403x`.
- First milestone: `R <= 9.6202x`, equivalent to Carrick at or below about
  `9,688 ms` if Docker remains comparable.
- Destination: `R <= 2.0x`.
- Accepted whole-tree pair attributes 36.7%/37.0% of CPU to translated guest,
  34.5%/34.3% to Darwin kernel, 8.3%/8.0% to Darwin userspace, 5.1%/5.3% to
  process setup, and 0.0%/0.1% to the gateway.
- No source change has yet produced an accepted wall-clock win.
- H004 Variant 1 remains rejected: it exhausted the 64 MiB DSR cache before
  `BUILD_OK`, so it supplied no performance result.

## Global constraints

- The primary workload is the wrapper-free cold-`GOCACHE` Go build in
  `localhost:5005/carrick-go-conformance:1.24`, native arm64 image ID
  `sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
- Preserve, do not rewrite or re-bless:
  `scripts/perf/evidence/native-go-build-wall-baseline-v1.json` and
  `scripts/perf/evidence/native-go-build-wall-attribution-v1.json`.
- Track only the target and descendants admitted by `proc:::create`.
- Never run Carrick and the Docker oracle concurrently.
- Traced elapsed time is diagnostic only; it is never a performance result.
- `profile-499` is the only on-CPU sample clock. Every kernel sample increments
  the existing PC aggregate and exactly one kernel-stack aggregate in the same
  probe firing.
- Evidence rejects on any drop, interruption, timeout, bounded termination,
  non-natural exit, incomplete record, tracked process live at end, cleanup
  failure, receipt/provenance mismatch, arithmetic overflow, or kernel
  PC/stack mismatch.
- Historical profiles without kernel-stack rows continue to parse.
- No guest-execution behavior, cache size, sidecar policy, syscall semantics,
  or default-backend behavior changes are authorized by Tasks 1-4.
- Do not read Linux kernel or other GPL source.
- All file collision checks use directory-entry semantics: dangling symlinks
  count as existing and must never be followed, replaced, or mutated.

## Task 1: Emit and parse exact kernel on-CPU stacks

**Files**

- Modify `scripts/dtrace/native-wall.d`.
- Modify `crates/carrick-cli/src/trace_profile.rs`.

**Required behavior**

1. Add a kernel stack aggregation to the existing
   `profile-499 /track_pid[pid] && arg0 != 0/` clause. The same firing updates
   both `@cpu_kernel[arg0]` and the stack aggregate.
2. Emit aggregate rows as:
   `NWSTACK1|begin|state=kernel-oncpu|value=<samples>`, frames, `NWSTACK1|end`.
3. Preserve voluntary rows exactly:
   `state=voluntary|pid=<pid>|value_ns=<ns>`.
4. Parse stack headers as a state-dependent sum type:
   `kernel-oncpu` requires positive `value`, forbids `pid` and `value_ns`;
   `voluntary` requires positive `pid` and `value_ns`, forbids `value`.
   Unknown/duplicate/missing fields and empty frame lists reject.
5. Serialize kernel stacks as `phase=cpu-kernel-stack` with `count` and no
   `pid`/`value_ns`. Voluntary serialization remains unchanged.
6. If kernel stack rows are present, their count population must equal the
   `cpu-kernel-pc` population exactly. Historical absence remains valid.
7. Every decision-bearing PC and stack population uses checked `u64`
   accumulation. Overflow returns an explicit parse/evidence error; it never
   saturates, wraps, or panics.

**TDD gate**

Before production edits, add literal fixtures and prove RED for:

- valid `2 + 1` kernel stacks against three kernel PC samples;
- mismatch `2 != 3`;
- both/neither `value` and `value_ns`;
- forbidden `pid`, unknown field, zero value, empty frames;
- malformed voluntary rows and unchanged valid voluntary serialization;
- historical kernel PCs without stacks and zero-kernel historical input;
- `u64::MAX + 1` in the kernel PC population;
- `u64::MAX + 1` in the kernel stack population.

Name the production mutation caught by each test. Run the focused test before
and after implementation, then `just fmt`, re-run the focused test, and verify
that formatting changed only the two task files. Commit only those files.

## Task 2: Select a stable kernel family with exact arithmetic

**Files**

- Add `scripts/perf/native_kernel_attribution.py`.
- Add `scripts/perf/test_native_kernel_attribution.py`.

**Required behavior**

1. Read two completed native-wall JSONL profiles and reject malformed,
   incomplete, dropped, bounded, non-natural, or unreconciled evidence.
2. Independently reconcile kernel PC count and kernel-stack count for each run
   with checked non-negative 64-bit arithmetic.
3. Normalize a stack family from its first four symbolized kernel frames,
   removing only hexadecimal offsets. Preserve module and symbol names.
4. Use `fractions.Fraction` for every threshold and ordering decision.
5. Reject unless each run has at least 95% symbolized kernel leaves.
6. A family is selectable only when:
   - its mean kernel-sample share is at least 10%;
   - its per-run share differs by at most five percentage points;
   - it appears at at least 5% in each run; and
   - the shared top-ten family set covers at least 60% in each run.
7. Rank by exact mean share, then exact total count, then normalized family
   text. Emit one deterministic JSON document whose result is
   `selectable`, `diffuse`, or `rejected`, with exact counts, fractions,
   source hashes, and the selected family's representative stacks.
8. The tool records measurement selection only. It does not create H006 or
   mutate the hypothesis ledger.

**TDD gate**

Prove RED then GREEN using hand-derived fixtures for exact and just-over
five-point drift, exact and just-below 5% membership, independent 10% and 60%
failures, their conjunction, unresolved-leaf rejection, PC/stack mismatch,
`u64::MAX + 1`, and deterministic ordering under float-equivalent fractions.
Run the focused unittest from the repository root and `ruff` if available.

## Task 3: Capture a fail-closed, receipt-bound A/B pair

**Files**

- Add `scripts/perf/native_kernel_capture.py`.
- Add `scripts/perf/test_native_kernel_capture.py`.

**Required behavior**

1. The test module inserts the resolved `scripts/perf` directory into
   `sys.path` before importing `native_kernel_capture`.
2. Production defines `class EvidenceError(RuntimeError)`. Rejection tests
   assert its exact type and stable message fragment.
3. Preflight rejects every pre-existing A, B, receipt, analysis, or derived
   path using `os.path.lexists`/`lstat` semantics. Tests cover a dangling
   symlink at each of A, B, and a derived-output path and prove the entry was
   not read, followed, replaced, or mutated.
4. Reject a foreign Carrick/native-wall/Go-build workload or real Docker
   oracle. The runner's own launcher ancestry is excluded by resolved PID
   ancestry, not command-line substring matching.
5. Freeze clean HEAD, signed binary SHA-256, DOF presence, image identity,
   benchmark command/environment, timeout, and artifact paths before capture.
6. Run A then B serially with unique conservative run IDs and unchanged HEAD
   and binary. Never overlap the two runs or any Docker oracle.
7. Each receipt contains pre/post launcher ancestry, host/guest run IDs,
   command status, timeout state, exactly one `BUILD_OK`, descendant census,
   completion/drop state, cleanup command/status/log hashes, raw/profile
   hashes, and reconciliation totals.
8. Exact-run-ID cleanup is mandatory after every success or failure. Derived
   output is published atomically only after both receipts and the analyzer
   accept. Early rejection leaves absent outputs except for an explicit
   rejection receipt when enough provenance exists to make it trustworthy.
9. Receipt comparison rejects changed ancestry, HEAD, binary, image,
   invocation, environment, timeout policy, or producer/acceptance hashes.

**TDD gate**

Before production code, prove the import fails for the expected missing module.
Then prove RED/GREEN for `EvidenceError`, accepted summaries, every rejection
class, broken/different ancestry, self-exclusion versus foreign workloads,
all three dangling-symlink collisions, conditional receipts, cleanup on
failure, and atomic derived publication. Tests use fake subprocess boundaries
only for external signed/DTrace execution and assert real filesystem effects.

## Task 4: Collect the pair and select the next bounded spike

1. Start from a clean Task 3 commit. Verify the two preserved evidence hashes,
   HEAD, branch, no foreign workload/oracle, native-arm64 image identity, and
   registry-only Docker state.
2. Run `just build`; verify signature, entitlement expectations for the native
   path, `__DATA,__dof_carrick`, bundled-script marker, and binary hash.
3. Use the Task 3 runner once to capture A then B with the unchanged signed
   binary. Do not edit source, rebuild, or run Docker between captures.
4. Run Task 2 analysis. Publish receipts plus the small derived JSON; keep raw
   traces under `target/perf`.
5. Record exactly one result in the campaign ledger:
   `selectable family`, `diffuse kernel evidence`, or `measurement rejected`.
   Only a selectable family may proceed to a separately written causal H006
   spike. The other outcomes return to measurement repair/another evidence
   family without claiming a performance result.
6. Update `handoff.md` with measured evidence, source hashes, exact commands,
   and the immediate bounded next action.

## Spike and retention protocol after Task 4

A selected family still is not a hypothesis. Before changing runtime code:

1. Write one causal mechanism, a calculated upper bound against the
   `9,687.5 ms` Carrick milestone, a traced mechanism counter, and a stop
   condition. Obtain user approval.
2. Follow red/green TDD for the mechanism and prove the counter changes in a
   receipt-bound traced control/candidate pair. Traced elapsed time is not a
   wall result.
3. Run one correctness-only signed candidate feasibility demo.
4. Run untraced `C1/K1/C2/K2` in alternating contemporaneous order.
5. Promote a clear win to five untraced control plus five untraced candidate
   samples. Direct retention requires candidate/control median `<=0.97` and a
   bootstrap upper bound `<1.0`.
6. A smaller apparent win requires a second independent five-plus-five
   campaign; both campaign medians must favor the candidate and the pooled
   bootstrap upper bound must be `<1.0`.
7. Retain only a durable, maintainable change that also passes focused tests,
   signed cold-Go demo, native smoke, Node/CPython guardrails, `just fmt`,
   `just clippy`, and `just ci`.
8. After either retention branch, refresh receipt-bound `C`, `D`, and `R`.
   Reuse Docker only when its provenance and host state are comparable;
   otherwise rerun Carrick and Docker serially.

## Completion conditions

Tasks 1-4 complete the measurement-selection wave, not the performance goal.
The active goal remains incomplete until at least one retained change improves
untraced wall-clock seconds and the campaign has either reached `R <= 9.6202x`
or exhausted the approved step-function candidates with explicit evidence.
