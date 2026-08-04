### Task 7: Revert the losing implementation and close the stopped hypothesis

**Starting HEAD:** `9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d`

**Retention authority:** Task 6 ABBA artifact
`target/perf/native-optimistic-decode/abba-v1.json`, SHA-256
`5e88d50dc10308b56d76984146391fe77e1e8dda790303cd6ae37330ea2c1f05`,
plus the fresh independent Task 6 evidence-review approval recorded by the
controller before dispatching this task.

**Decision:** stop the optimistic decode-outside-writer implementation. It
regressed total child CPU by 13.740% and workload wall by 1.440%, losing 8/8
quads. Preserve the reviewed diagnostics and parser because they remain useful
for future concurrency experiments and accurately explain the losing work.

**Exact source boundary:**

- Revert `9e0b0817 fix(native): account failed optimistic decodes` first.
- Then revert `3733eeef perf(native): decode blocks outside process writer`.
- Preserve `d4c84088 perf(native): expose optimistic decode discard cost`.
- Preserve `9a2788d6 fix(perf): validate optimistic decode timing`.
- Preserve the design, plan, reports, and every target-only measurement receipt.
- Do not push, move local `main`, delete the detached control worktree, or rerun
  the ABBA campaign.

**Produces:**

- Two narrow revert commits restoring the retained monolithic writer behavior.
- Full focused, repository, signed-build, and native smoke evidence on the
  restored tree.
- `docs/perf-results/2026-08-04-native-optimistic-decode.md` as a stopped-
  hypothesis evidence record.
- Updated `handoff.md` that records the negative result, leaves the official
  10.1776x scoreboard unchanged, keeps eager whole-image translation deferred,
  and does not present the stopped lock line as the next candidate.
- Report `.superpowers/sdd/2026-08-04-native-optimistic-decode/task-7-report.md`.

- [ ] **Step 0: Verify the exact clean starting state**

Use `git -c core.fsmonitor=false` for status queries. Require exact HEAD
`9a2788d6...`, clean tracked state apart from this controller-created brief,
and the named Task 6 artifact hash above. Inspect both commits before reverting.
If any source drift or unexpected tracked edit exists, stop and report it; do
not overwrite it.

- [ ] **Step 1: Revert only the losing implementation**

Run the two reverts in dependency-reverse order:

```bash
git revert --no-edit 9e0b0817
git revert --no-edit 3733eeef
```

Resolve no semantic conflict by guesswork. If either revert conflicts, stop and
report the exact conflict. After both reverts, prove:

```bash
git diff --exit-code d4c84088 -- \
  crates/carrick-dsr-aarch64/src/artifact_spike.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-runtime/src/native_darwin/dsr/mod.rs
```

The three implementation files must be byte-equivalent to the reviewed
diagnostics-only tree at `d4c84088`. The parser/test difference introduced by
`9a2788d6` is intentionally retained.

Also require that production optimistic discard counters remain structurally
present and naturally zero on the restored serialized path; do not remove or
rename them.

- [ ] **Step 2: Run focused gates first**

Run:

```bash
cargo test -p carrick-dsr --lib profile -- --nocapture
cargo test -p carrick-dsr-aarch64 --lib translator::tests -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib native_darwin::dsr -- --nocapture
PYTHONPATH=scripts/perf python3 -m unittest \
  scripts/perf/test_native_compiler_budget.py \
  scripts/perf/test_direct_binding_mechanism.py -v
cargo clippy -p carrick-dsr-aarch64 -p carrick-runtime --all-targets -- -D warnings
cargo fmt --all -- --check
```

Record exact pass counts and intentional ignored tests. If a failure is caused
by the revert, diagnose and report it to the controller before any source fix;
do not silently reintroduce candidate behavior.

- [ ] **Step 3: Run full correctness and shipped-default smoke gates**

Run serially, with no other Carrick/Docker performance work active:

```bash
RUST_TEST_THREADS=1 just ci
just build
just conformance-native smoke
```

Record the restored HEAD, release binary SHA-256, strict codesign result,
hypervisor entitlement presence, and loadable `__dof_carrick` section. The
native smoke may use its ordinary cached Docker oracle behavior, but never run
Carrick and a live Docker oracle concurrently. Attribute any regression against
current HEAD before attempting a fix.

- [ ] **Step 4: Write durable stopped-hypothesis evidence**

Create `docs/perf-results/2026-08-04-native-optimistic-decode.md` and record:

- the design and exact candidate/control source and signed-binary identities;
- NATIVEPERF A/B hashes, counts, discard shares, and the duration-is-not-CPU
  qualification;
- accepted typed DTrace A2/B and paired-attribution hashes, zero-drop validity,
  the measured `psynch_cvwait` and strict adjacent writer-stack reductions, and
  the differing-workload mechanism-only caveat;
- Task 6 artifact hash, 34/34 sample and 32/32 measured validity, all CPU/user/
  sys/wall ratios and intervals, 0/8 candidate wins, and exact sign-test
  direction;
- the explicit conclusion that reducing the targeted wait mechanism did not
  reduce product CPU, while the precise additional-cost root cause remains
  inferred rather than proven;
- the exact two reverted commits and the diagnostics/parser commits retained;
- every focused/full/conformance gate actually run on the restored tree;
- the official serialized Carrick/Docker scoreboard remains 10.1776x because
  no qualifying retained candidate or fresh serialized refresh exists;
- eager whole-image translation remains a deferred future improvement because
  incremental JIT-on-JIT support is still required.

Do not cite target-only artifacts without also recording their SHA-256 and
producer/source/binary semantics. Do not describe the candidate as an official
baseline change.

- [ ] **Step 5: Update handoff and commit documentation**

Update `handoff.md` in place:

- replace the optimistic-decode next-step prediction with the measured stopped
  outcome;
- update confidence: 99% in the regression/no-retain verdict; high confidence
  in the preserved diagnostics; official 10.1776x unchanged;
- keep the user-approved policy of sequential at-least-10% non-regrettable
  wins, with smaller results retained only as measured enablers;
- state that the next candidate must come from a newly attributed current-
  retained-tree bucket rather than guessing from this losing candidate;
- keep eager translation explicitly deferred.

Commit only the evidence, handoff, Task 6/7 controller reports/ledger updates
that are already present and appropriate, and this brief with a narrow message:

```bash
git add docs/perf-results/2026-08-04-native-optimistic-decode.md \
  handoff.md \
  .superpowers/sdd/2026-08-04-native-optimistic-decode
git commit -m "docs(perf): record stopped optimistic decode experiment"
git -c core.fsmonitor=false status --short
```

Expected: clean tracked worktree. Do not remove target-only evidence. Report
all new commit IDs, gates, artifact hashes, unresolved concerns, and the best
evidence-backed next attribution question. Do not begin the next implementation
hypothesis in this task.
