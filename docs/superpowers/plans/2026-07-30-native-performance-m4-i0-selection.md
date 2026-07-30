# Native Performance M4: I0 and Next-Slice Selection Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the completed evidence control plane neutral against frozen
`H0`, publish one hash-bound `I0`, and select one bounded optimization
subproject from evidence-bounded removable translation and fault ceilings.

**Architecture:** A small Python verifier consumes only accepted M1/M2/M3
artifacts from one frozen post-M3 binary, rechecks their hashes and schemas,
derives inclusive component CPU estimates and narrower removable ceilings
without mixing event populations, and publishes `I0`. A typed JSONL hypothesis
ledger separates measured observations, conservative ceilings, state, and
bounded spike contracts. Two untraced ABBA campaigns provide H0 neutrality and
default/shared CPU authority; freshly recaptured traced pairs contribute shares
and ownership only.

**Tech Stack:** Python 3 standard library (`decimal`, `fractions`, `hashlib`,
`json`), M1 ABBA receipts/runner, M2 `native-wall`, M3 `native-faults`, Git
worktrees, Carrick's signed Darwin/AArch64 runner.

**Design authority:** `docs/superpowers/specs/2026-07-30-native-performance-evidence-control-plane-design.md`
sections 2, 8, 9, 11, 12, and 13.

## Global Constraints

- M1, M2, and M3 are complete with accepted immutable evidence.
- `H0` is exactly commit `0686248a`. It never moves or gets redefined.
- `I0` is the first accepted frozen post-M3 baseline with every optimization
  hypothesis in control state. Its neutrality, default/shared, two default and
  two shared wall profiles, and two fault profiles all name that exact receipt
  binary SHA/Mach-O UUID/source commit.
- Control-plane neutrality requires current-tip/H0 paired total-CPU estimate
  `<= 1.00` and one-sided 95% upper bound `<= 1.02`.
- H0 neutrality is not an optimization-retention claim; it need not establish
  a statistically significant improvement.
- Untraced ABBA supplies arm total CPU. Traced profiles supply sample shares
  and exact event populations. Traced elapsed time is ignored.
- The default/shared ABBA uses one current-tip receipt. `default` has sharing
  controls absent; `shared` sets only the approved sharing/direct-binding
  overlay with artifact spike absent.
- A component estimate is
  `untraced arm median total CPU × accepted native-wall sample share`.
- Translation share is exactly the sum of `private-translated`,
  `shared-translated`, `translation-build`, `translation-publication`,
  `gateway-prepare`, and `gateway-resolve`.
- Kernel share is exactly `kernel-non-syscall`.
- Exact fault event counts never get added to sampled CPU. They select an
  owner/mechanism inside the kernel ceiling.
- The translation removable ceiling is the positive shared-minus-default
  inclusive translation component excess, and exists only when typed ranges,
  units, and transitions support the locality premise.
- The fault removable ceiling is sampled CPU in live-qualified
  `kernel-non-syscall` stacks matching the versioned fault-path rule set. Exact
  fault counts choose the owner/repeat mechanism inside that sampled ceiling;
  event fractions never scale CPU.
- For two profiles, component dispersion is
  `abs(E1 - E2) / mean(E1, E2)`.
- Source artifacts are immutable by SHA-256. A changed source invalidates I0.
- The next subproject is the larger evidence-supported conservative removable
  CPU ceiling. Exact ties choose the narrower declared correctness surface;
  an exact ceiling-and-surface tie requires more evidence.
- M4 names one bounded first hypothesis; it does not implement it.
- Every ledger record is one of `PROPOSED`, `SPIKING`, `RETAIN`, `REJECT`, or
  `DEFER`.
- No Docker oracle runs concurrently with Carrick.
- No Linux kernel or other GPL implementation source is consulted.

---

## Task 1: Build the hash-bound I0 verifier and typed ledger

**Files:**

- Create: `scripts/perf/native_performance_i0.py`
- Create: `scripts/perf/test_native_performance_i0.py`
- Modify: `scripts/perf/native_wall_capture.py`
- Modify: `scripts/perf/test_native_wall_capture.py`
- Create: `scripts/perf/fixtures/native-performance-i0/accepted-abba.json`
- Create: `scripts/perf/fixtures/native-performance-i0/default-wall-a.json`
- Create: `scripts/perf/fixtures/native-performance-i0/default-wall-b.json`
- Create: `scripts/perf/fixtures/native-performance-i0/shared-wall-a.json`
- Create: `scripts/perf/fixtures/native-performance-i0/shared-wall-b.json`
- Create: `scripts/perf/fixtures/native-performance-i0/fault-attribution.json`
- Create: `scripts/perf/fixtures/native-performance-i0/kernel-stacks.json`
- Create: `scripts/perf/native_fault_stack_rules_v1.json`

**Schemas:**

- `carrick.native-performance-i0.v1`
- `carrick.native-performance-hypothesis.v1`

**Interfaces:**

```python
TRANSLATION_CATEGORIES = (
    "private-translated",
    "shared-translated",
    "translation-build",
    "translation-publication",
    "gateway-prepare",
    "gateway-resolve",
)

LEDGER_STATES = frozenset(
    {"PROPOSED", "SPIKING", "RETAIN", "REJECT", "DEFER"}
)


@dataclasses.dataclass(frozen=True)
class ComponentEstimate:
    first_cpu_s: Decimal
    second_cpu_s: Decimal
    mean_cpu_s: Decimal
    dispersion: Decimal


@dataclasses.dataclass(frozen=True)
class SliceCandidate:
    subproject: str
    first_hypothesis: str
    inclusive_component_cpu_s: Decimal
    removable_ceiling_cpu_s: Decimal | None
    correctness_surface_rank: int
    evidence_hashes: tuple[str, ...]
```

Required call signatures are
`sha256_file(path: pathlib.Path) -> str`,
`load_neutrality(path: pathlib.Path) -> dict[str, object]`,
`load_default_shared(path: pathlib.Path) -> dict[str, object]`,
`load_wall_pair(first_profile: pathlib.Path, second_profile: pathlib.Path,
analysis: pathlib.Path, *, expected_state: str) -> dict[str, object]`,
`load_fault_pair(provider: pathlib.Path, first_profile: pathlib.Path,
second_profile: pathlib.Path,
analysis: pathlib.Path) -> dict[str, object]`,
`create_frozen_session(repo: pathlib.Path, h0_commit: str,
output: pathlib.Path) -> dict[str, object]`,
`load_frozen_session(path: pathlib.Path) -> dict[str, object]`,
`seal_session_neutrality(session: pathlib.Path,
artifact: pathlib.Path) -> dict[str, object]`,
`publish_bundle(inputs: Sequence[tuple[str, pathlib.Path]],
destination: pathlib.Path, ledger_source: pathlib.Path) -> dict[str, object]`,
`materialize_ledger(bundle: pathlib.Path,
destination: pathlib.Path) -> dict[str, object]`,
`estimate_component(total_cpu_s: Decimal, first_share: Decimal,
second_share: Decimal) -> ComponentEstimate`, and
`select_next_slice(translation: SliceCandidate,
kernel: SliceCandidate) -> SliceCandidate`.

- [ ] **Step 1: Add red schema/hash/reconciliation tests**

Assert rejection of wrong schema, `accepted=false`, incomplete M1 artifact,
M2/M3 v1 compatibility evidence, changed source hash, missing category,
category sum mismatch, unstable traced pair, under-85% fault coverage, stale
provider receipt, non-default hypotheses, non-finite number, or duplicate
ledger ID. Typed loaders must also reject:

- a neutrality artifact that is not exactly H0 control versus frozen-tip
  candidate with identical complete default overlays;
- a default/shared artifact whose arms do not share one receipt or whose
  complete overlays are not exactly the checked-in semantic pair;
- a wall/fault profile whose commit, binary SHA, Mach-O UUID, image, host, run
  controls, or receipt differs from the frozen tip; and
- an analysis whose embedded source hash does not equal the explicit raw
  profile hash supplied to the loader. Embedded scratch paths remain recorded
  provenance but are not durable-path authority.

Mock `git` to test frozen-session creation: dirty input, wrong H0 resolution,
worktree collision, partial creation cleanup, detached H0/tip commits, and a
session file whose recorded paths/commits no longer match must all fail.
Test neutrality sealing with source drift, a different second artifact, and an
idempotent repeat of the same hash. Test bundle publication with duplicate
roles, source drift, destination collision, process-death simulation after
each staged copy/build/manifest sync, and a receipt/hash reconstruction over
every promoted file. No final bundle path may exist before the atomic rename.
Test ledger materialization as idempotent for the identical bundle and fatal
for a conflicting row.

Add a red `native_wall_capture.py capture-elf` test with the same receipt,
preflight, raw/summary/stdout/capture-receipt, guest-status, and cleanup
authority as M3's fault wrapper. It is used only to live-qualify the versioned
fault-stack rules against the known-page fixture.

Before the Task 1 commit, load both checked-in semantic overlays and assert
key-set equality with `PERFORMANCE_CONTROL_KEYS`, exactly two changed values
(`CARRICK_DSR_SHARED_TRANSLATION` and
`CARRICK_DSR_DIRECT_BINDINGS`), no unknown Carrick variable, and
`CARRICK_DSR_ARTIFACT_SPIKE is None` in both overlays. This test must already
be committed before the frozen session is created; no Task 2/3 capture may
edit the harness.

- [ ] **Step 2: Add red component arithmetic tests**

Use `Decimal(str(json_value))` for decisions. For total CPU `40` and shares
`0.30`, `0.32`, require estimates `12`, `12.8`, mean `12.4`, and dispersion
`0.8/12.4`. Assert translation is the exact six-category sum and kernel is
only `kernel-non-syscall`.

Add the design's material-improvement helper:

```python
def component_materially_improved(
    baseline: ComponentEstimate,
    final: ComponentEstimate,
) -> bool:
    ratio = final.mean_cpu_s / baseline.mean_cpu_s
    decrease = Decimal(1) - ratio
    noise = Decimal(2) * max(baseline.dispersion, final.dispersion)
    return ratio <= Decimal("0.90") and decrease > noise
```

Keep inclusive components separate from removable ceilings. Add tests requiring:

```python
translation_removable = max(
    Decimal(0),
    shared_translation.mean_cpu_s - default_translation.mean_cpu_s,
)
fault_removable = estimate_component(
    default_cpu_s,
    first_fault_path_share,
    second_fault_path_share,
)
```

The translation value is accepted only when the default/shared range and unit
evidence supports the declared scatter/locality comparison. The fault value
comes directly from sampled kernel-stack shares, not from fault event
fractions. A missing, unstable, or unqualified stack match yields
`removable_ceiling_cpu_s=None`.

- [ ] **Step 3: Add red deterministic-selection tests**

Translation wins when its non-null evidence-supported removable ceiling is
larger; kernel wins when its is larger. On exact equality, the lower
`correctness_surface_rank` wins. Reject a candidate without accepted
mechanism evidence instead of selecting by narrative plausibility. If both
ceilings are null or both ceiling and surface rank tie, reject selection and
require more evidence.

- [ ] **Step 4: Run and prove red**

```bash
python3 -m unittest \
  scripts/perf/test_native_performance_i0.py \
  scripts/perf/test_native_wall_capture.py -v
```

- [ ] **Step 5: Implement accepted-source loading**

Load each JSON/JSONL source once through its typed role loader, require its
exact expected schema, determinants, and acceptance fields, compute SHA-256
before and after parsing, and reject a change. Generic schema equality is not
arm authority. Store absolute source path, hash, schema, commit/binary/receipt
identity, exact complete overlay, host identity, and accepted
coverage/reconciliation fields in the manifest.

`create_frozen_session` requires an empty `git status --porcelain`, resolves
H0 exactly to `0686248a`, records current `HEAD` as `frozen_tip`, creates two
external detached worktrees under one `tempfile.mkdtemp` parent, and atomically
writes their canonical paths/commits plus the main harness path. It never
removes an existing path. `load_frozen_session` rechecks both worktree heads and
cleanliness. Cleanup is an explicit post-I0 operation, not implicit on failure.

`publish_bundle` requires unique closed role names and hashes every scratch
input. It creates one exclusive same-parent staging directory, copies and
`fsync`s each source there, builds the I0 plus the complete next-ledger image
from those staged paths, writes a closed `manifest.json`, `fsync`s every file
and the staging directory, then atomically renames the directory to the absent
final bundle and `fsync`s its parent. A crash can leave only an ignored staging
directory; it cannot expose a partial final set.

`ledger_source` has one explicit bootstrap rule: if the path is absent and no
bundle destination exists, its typed value is the empty ledger. If present it
must parse completely; if absent after any bundle exists, or if an empty file
is supplied, fail. Tests cover first-run absence, malformed/existing ledgers,
and a missing source on a non-bootstrap run.

The ledger inside the immutable bundle is authority.
`materialize_ledger` updates the conventional docs ledger as an idempotent
derived mirror under `flock`: an identical already-present row succeeds, a
conflict fails, and a temp-file rename plus directory `fsync` publishes the
mirror. Typed loaders receive and hash explicit bundle paths; they never follow
an embedded scratch path.

- [ ] **Step 6: Implement ceiling construction without population mixing**

For default and shared native-wall pairs:

```python
translation_share = sum(
    Decimal(str(category_shares[name]))
    for name in TRANSLATION_CATEGORIES
)
```

Multiply default shares by the default ABBA arm median CPU and shared shares
by the shared arm median CPU. Preserve both inclusive component means. The
translation candidate's removable ceiling is only the positive
shared-minus-default mean excess, treating the accepted default state as the
predeclared locality reference. It is supported only when the default/shared
ABBA, translation counts, distinct ranges/units, transitions, and profile
shares establish the locality question; a large inclusive bucket alone yields
`DEFER`.

The raw v2 native-wall rows already preserve canonicalized kernel stacks and
sample counts. Load the checked-in rule table:

```json
{
  "schema": "carrick.native-fault-stack-rules.v1",
  "kernel_image": "mach_kernel",
  "symbol_prefixes": ["vm_fault", "vm_page_fault", "pmap_fault"]
}
```

The live recapture must qualify at least one matching stack in the known-page
fixture, and both default profiles must report a stable matched share. Multiply
default total CPU by each matched `kernel-non-syscall` sample share to obtain
the fault-path component and use its mean as the removable ceiling. This is a
sampled fault-path upper bound; the fault attribution chooses the highest
supported owner/repetition mechanism inside it. Do not multiply CPU by a fault
event fraction. If such a proportional value is shown descriptively, label it
`uniform-cost upper-bound sensitivity`, never a component or selection
ceiling.

- [ ] **Step 7: Define the two bounded slice contracts**

The selector accepts only these measured templates:

```text
shared-translation-locality
  hypothesis: reduce process execution scatter across loaded shared unit
  mappings without changing translated instruction semantics
  opt-out: CARRICK_DISABLE_SHARED_TRANSLATION_LOCALITY=1
  maximum structural variants: 2
  mechanism gate: fewer dominant shared ranges/unit transitions and lower
  inclusive translation-side share
  stop: no mechanism movement or two variants fail two-quad ABBA

native-fault-owner
  hypothesis: remove repeated host-page faulting for the dominant qualified
  uniform/mixed/partial backing owner without changing guest VMA semantics
  opt-out: CARRICK_DISABLE_NATIVE_FAULT_OWNER=1
  maximum structural variants: 2
  mechanism gate: lower addressed event count, distinct-page repetition, and
  owning bucket population with catalog reconciliation unchanged
  stop: no mechanism movement or two variants fail two-quad ABBA
```

If the translation evidence does not prove its locality premise, record it
`DEFER` and do not give it a selectable ceiling. If fault evidence has no
qualified dominant owner/repeat mechanism or fault-path sampled ceiling, record
it `DEFER`. One or both candidates may be supported: when both are supported,
the selector proposes the larger ceiling and defers the other. M4 cannot
complete if neither candidate is supported or the declared tie-break remains
tied; collect more DTrace/LLDB evidence rather than guessing.

Each candidate declares a sorted unique `correctness_domains` set from the
actual bounded hypothesis (for example mapping lifetime, direct-binding
reachability, signal recovery, guest memory semantics, or fork/exec
coherence). `correctness_surface_rank` is the set cardinality, not a
preassigned preference. If ceilings and cardinalities both tie, narrow one
hypothesis or collect more evidence; do not use name order as a hidden
tie-break.

- [ ] **Step 8: Implement one atomic evidence/ledger bundle**

`native_performance_i0.py publish-bundle` takes explicit roles for both ABBA
artifacts, four native-wall raw/summary/stdout/capture sets plus two analyses,
the provider and qualification sources, two native-fault sets plus one
analysis, the frozen-tip arm receipt, and the current ledger. It hashes the
explicit staged inputs rather than trusting embedded paths, writes exactly one
selected `PROPOSED` row plus `DEFER` rows into the bundle's complete ledger
image, builds the I0, then publishes the whole bundle through the staging
directory transaction in Step 5. `verify-bundle` is read-only.

`materialize-ledger` is deliberately outside the evidence authority: it
reconciles the bundle's ledger image into
`docs/perf-results/native-performance-hypotheses.jsonl` idempotently so a crash
between bundle publication and the eventual Git commit is safely resumable.

- [ ] **Step 9: Run focused tests and commit**

```bash
python3 -m unittest \
  scripts/perf/test_native_performance_i0.py \
  scripts/perf/test_native_wall_capture.py -v
git diff --check
git add scripts/perf/native_performance_i0.py \
  scripts/perf/test_native_performance_i0.py \
  scripts/perf/native_wall_capture.py \
  scripts/perf/test_native_wall_capture.py \
  scripts/perf/native_fault_stack_rules_v1.json \
  scripts/perf/fixtures/native-performance-i0
git commit -m "diagnostics(perf): define the native I0 evidence manifest" -m \
"Verify accepted ABBA, native-wall, and native-fault artifacts by schema and
hash, derive non-overlapping component estimates, and make next-slice selection
deterministic and ledgered.

Verified with source-drift, arithmetic, reconciliation, tie-break, and atomic
publication tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 2: Prove the control plane neutral against frozen H0

**Files:** Scratch only under `target/perf`; no evidence is copied or committed
until every M4 source has been captured from the same frozen tip.

- [ ] **Step 1: Create two clean source worktrees**

From the clean current repository, after Task 1's verifier commit:

```bash
python3 scripts/perf/native_performance_i0.py freeze-session \
  --repo "$PWD" \
  --h0 0686248a \
  --output target/perf/native-m4-frozen-session.json
python3 scripts/perf/native_performance_i0.py verify-session \
  --session target/perf/native-m4-frozen-session.json
h0_repo=$(python3 scripts/perf/native_performance_i0.py session-path \
  --session target/perf/native-m4-frozen-session.json --key h0_repo)
tip_repo=$(python3 scripts/perf/native_performance_i0.py session-path \
  --session target/perf/native-m4-frozen-session.json --key tip_repo)
```

Both detached worktrees and the harness must be clean. Preserve both worktrees
until the final manifest, durable copies, and one evidence commit are complete.

- [ ] **Step 2: Prepare H0 and tip receipts**

```bash
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$h0_repo" \
  --destination target/perf/native-m4-h0 \
  --label h0-0686248a \
  --role control \
  --image localhost:5005/carrick-go-conformance:1.24
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$tip_repo" \
  --destination target/perf/native-m4-tip \
  --label frozen-post-m3-tip \
  --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
```

Require signed binaries, strict codesign, `__dof_carrick`, arm64 image
identity, clean commits, and immutable copied-file hashes.

- [ ] **Step 3: Run the two-binary eight-quad campaign**

Use one checked-in complete default overlay for both arms:

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt target/perf/native-m4-h0/arm.json \
  --candidate-receipt target/perf/native-m4-tip/arm.json \
  --control-overlay scripts/perf/overlays/native-default.json \
  --candidate-overlay scripts/perf/overlays/native-default.json \
  --quads 8 \
  --cooldown-seconds 2 \
  --output target/perf/native-h0-tip-neutrality-abba-v1.json
```

Require complete/accepted evidence, candidate/H0 total-CPU median quad ratio
at most `1.00`, and one-sided 95% upper bound at most `1.02`. A failure sends
the instrumentation back to M1/M2/M3 diagnosis; it does not redefine H0 or
weaken the bound.

- [ ] **Step 4: Verify and retain both frozen worktrees**

Run the typed neutrality verifier read-only after the campaign. It requires
H0 control, frozen-tip candidate, identical exact default overlays, and the
session/receipt/commit/binary determinants:

```bash
python3 scripts/perf/native_performance_i0.py verify-neutrality \
  --session target/perf/native-m4-frozen-session.json \
  --h0-arm target/perf/native-m4-h0/arm.json \
  --tip-arm target/perf/native-m4-tip/arm.json \
  --artifact target/perf/native-h0-tip-neutrality-abba-v1.json
```

- [ ] **Step 5: Freeze neutrality in scratch without advancing source**

Seal the accepted scratch artifact hash into the session through the exclusive,
atomic state transition implemented in Task 1:

```bash
python3 scripts/perf/native_performance_i0.py seal-neutrality \
  --session target/perf/native-m4-frozen-session.json \
  --artifact target/perf/native-h0-tip-neutrality-abba-v1.json
python3 scripts/perf/native_performance_i0.py verify-session \
  --session target/perf/native-m4-frozen-session.json
```

The first call verifies the artifact/session determinants, writes through a
same-directory fsynced temp plus atomic rename, and is idempotent only for the
same SHA-256. Do not copy it into Git, commit, rebuild, or prepare a new tip
receipt. Advancing source here would make later default/shared and traced
evidence describe a different baseline.

---

## Task 3: Capture the complete frozen-tip I0 evidence set

**Files:** Read the semantic overlays; write every campaign source to
`target/perf` only. No source commit advances during this task.

- [ ] **Step 1: Verify the complete semantic overlays**

`native-default.json` explicitly nulls every key in
`PERFORMANCE_CONTROL_KEYS`. `native-shared.json` is identical except:

```json
{
  "CARRICK_DSR_SHARED_TRANSLATION": "1",
  "CARRICK_DSR_DIRECT_BINDINGS": "1",
  "CARRICK_DSR_ARTIFACT_SPIKE": null
}
```

The complete M1 files, not this excerpt, are supplied to the runner. The
legacy `candidate` overlay is forbidden.

- [ ] **Step 2: Run the same-binary eight-quad campaign**

Use the exact frozen-tip receipt from Task 2 for both arms:

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt target/perf/native-m4-tip/arm.json \
  --candidate-receipt target/perf/native-m4-tip/arm.json \
  --control-overlay scripts/perf/overlays/native-default.json \
  --candidate-overlay scripts/perf/overlays/native-shared.json \
  --quads 8 \
  --cooldown-seconds 2 \
  --output target/perf/native-default-shared-abba-i0-v1.json
```

This campaign supplies default and shared arm total CPU for component
estimates. It is accepted evidence whether or not sharing wins; do not retain
or flip the default from this M4 observation alone.

- [ ] **Step 3: Recapture four native-wall profiles from the frozen binary**

```bash
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m4-tip/arm.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id native-m4-wall-default-a \
  --trace-out target/perf/native-m4-wall-default-a.raw \
  --summary-jsonl target/perf/native-m4-wall-default-a.jsonl \
  --stdout target/perf/native-m4-wall-default-a.stdout \
  --capture-receipt target/perf/native-m4-wall-default-a.capture.json
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m4-tip/arm.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id native-m4-wall-default-b \
  --trace-out target/perf/native-m4-wall-default-b.raw \
  --summary-jsonl target/perf/native-m4-wall-default-b.jsonl \
  --stdout target/perf/native-m4-wall-default-b.stdout \
  --capture-receipt target/perf/native-m4-wall-default-b.capture.json
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m4-tip/arm.json \
  --overlay scripts/perf/overlays/native-shared.json \
  --run-id native-m4-wall-shared-a \
  --trace-out target/perf/native-m4-wall-shared-a.raw \
  --summary-jsonl target/perf/native-m4-wall-shared-a.jsonl \
  --stdout target/perf/native-m4-wall-shared-a.stdout \
  --capture-receipt target/perf/native-m4-wall-shared-a.capture.json
python3 scripts/perf/native_wall_capture.py capture \
  --receipt target/perf/native-m4-tip/arm.json \
  --overlay scripts/perf/overlays/native-shared.json \
  --run-id native-m4-wall-shared-b \
  --trace-out target/perf/native-m4-wall-shared-b.raw \
  --summary-jsonl target/perf/native-m4-wall-shared-b.jsonl \
  --stdout target/perf/native-m4-wall-shared-b.stdout \
  --capture-receipt target/perf/native-m4-wall-shared-b.capture.json
python3 scripts/perf/native_wall_attribution.py \
  --capture-receipt target/perf/native-m4-wall-default-a.capture.json \
  --capture-receipt target/perf/native-m4-wall-default-b.capture.json \
  --rules scripts/perf/native_wall_symbol_rules_v2.json \
  --output target/perf/native-m4-wall-default-analysis.json
python3 scripts/perf/native_wall_attribution.py \
  --capture-receipt target/perf/native-m4-wall-shared-a.capture.json \
  --capture-receipt target/perf/native-m4-wall-shared-b.capture.json \
  --rules scripts/perf/native_wall_symbol_rules_v2.json \
  --output target/perf/native-m4-wall-shared-analysis.json
```

Each profile/capture receipt must name the same frozen binary/commit/image and
its exact semantic overlay. Both analyses must pass v2 lifecycle, category,
coverage, and stability gates.

- [ ] **Step 4: Requalify and recapture fault ownership from the same binary**

First build the known-page fixture, live-qualify fault-stack rules under
`native-wall`, then produce a current-boot provider receipt bound to the frozen
binary:

```bash
scripts/build-linux-fixtures.sh
python3 scripts/perf/native_wall_capture.py capture-elf \
  --receipt target/perf/native-m4-tip/arm.json \
  --elf fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-native-fault-pages \
  --run-id native-m4-wall-fault-stack \
  --trace-out target/perf/native-m4-wall-fault-stack.raw \
  --summary-jsonl target/perf/native-m4-wall-fault-stack.jsonl \
  --stdout target/perf/native-m4-wall-fault-stack.stdout \
  --capture-receipt target/perf/native-m4-wall-fault-stack.capture.json
python3 scripts/perf/native_performance_i0.py qualify-fault-stacks \
  --profile target/perf/native-m4-wall-fault-stack.jsonl \
  --stdout target/perf/native-m4-wall-fault-stack.stdout \
  --rules scripts/perf/native_fault_stack_rules_v1.json \
  --output target/perf/native-m4-fault-stack-qualification.json

target/perf/native-m4-tip/carrick __native-fault-abi-fixture \
  --control-loop-ms 15000 >target/perf/native-m4-fault-control.log 2>&1 &
control_pid=$!
trap 'kill "$control_pid" 2>/dev/null || true' EXIT
target/perf/native-m4-tip/carrick trace \
  --script scripts/dtrace/native-fault-qualify.d \
  --trace-out target/perf/native-m4-fault-qualify.raw \
  --capture-status-json target/perf/native-m4-fault-qualify.status.json -- \
  __native-fault-abi-fixture
wait "$control_pid"
trap - EXIT
python3 scripts/perf/native_fault_qualify.py \
  --raw target/perf/native-m4-fault-qualify.raw \
  --capture-status target/perf/native-m4-fault-qualify.status.json \
  --carrick target/perf/native-m4-tip/carrick \
  --output target/perf/native-m4-fault-qualification.json
python3 scripts/perf/native_fault_qualify.py seal-provider \
  --qualification target/perf/native-m4-fault-qualification.json \
  --carrick target/perf/native-m4-tip/carrick \
  --native-faults-d scripts/dtrace/native-faults.d \
  --analyzer scripts/perf/native_fault_attribution.py \
  --output target/perf/native-m4-fault-provider.json
```

Run the two primary profiles:

```bash
python3 scripts/perf/native_fault_capture.py capture-go \
  --receipt target/perf/native-m4-tip/arm.json \
  --qualification target/perf/native-m4-fault-provider.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id native-m4-fault-a \
  --trace-out target/perf/native-m4-fault-a.raw \
  --summary-jsonl target/perf/native-m4-fault-a.jsonl \
  --stdout target/perf/native-m4-fault-a.stdout \
  --capture-receipt target/perf/native-m4-fault-a.capture.json
python3 scripts/perf/native_fault_capture.py capture-go \
  --receipt target/perf/native-m4-tip/arm.json \
  --qualification target/perf/native-m4-fault-provider.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id native-m4-fault-b \
  --trace-out target/perf/native-m4-fault-b.raw \
  --summary-jsonl target/perf/native-m4-fault-b.jsonl \
  --stdout target/perf/native-m4-fault-b.stdout \
  --capture-receipt target/perf/native-m4-fault-b.capture.json
python3 scripts/perf/native_fault_attribution.py \
  --provider target/perf/native-m4-fault-provider.json \
  --capture-receipt target/perf/native-m4-fault-a.capture.json \
  --capture-receipt target/perf/native-m4-fault-b.capture.json \
  --output target/perf/native-m4-fault-analysis.json
```

Every source must name the frozen receipt identity. No M2/M3 milestone profile
is reused as I0 authority. All raw/stdout/capture inputs remain in scratch
until final gates pass.

---

## Task 4: Promote one immutable I0 and select the next subproject

**Files:**

- Create: `scripts/perf/evidence/native-performance-m4-v1/manifest.json`
- Create: `scripts/perf/evidence/native-performance-m4-v1/native-performance-i0-v1.json`
- Create: `scripts/perf/evidence/native-performance-m4-v1/native-performance-hypotheses.jsonl`
- Create: `docs/perf-results/native-performance-hypotheses.jsonl`
- Modify: `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`
- Modify: `handoff.md`

- [ ] **Step 1: Verify every source before assembly**

Run:

```bash
python3 scripts/perf/native_performance_i0.py verify \
  --session target/perf/native-m4-frozen-session.json \
  --h0-arm target/perf/native-m4-h0/arm.json \
  --tip-arm target/perf/native-m4-tip/arm.json \
  --neutrality target/perf/native-h0-tip-neutrality-abba-v1.json \
  --default-shared target/perf/native-default-shared-abba-i0-v1.json \
  --default-wall-raw-a target/perf/native-m4-wall-default-a.raw \
  --default-wall-profile-a target/perf/native-m4-wall-default-a.jsonl \
  --default-wall-stdout-a target/perf/native-m4-wall-default-a.stdout \
  --default-wall-capture-a target/perf/native-m4-wall-default-a.capture.json \
  --default-wall-raw-b target/perf/native-m4-wall-default-b.raw \
  --default-wall-profile-b target/perf/native-m4-wall-default-b.jsonl \
  --default-wall-stdout-b target/perf/native-m4-wall-default-b.stdout \
  --default-wall-capture-b target/perf/native-m4-wall-default-b.capture.json \
  --default-wall-analysis target/perf/native-m4-wall-default-analysis.json \
  --shared-wall-raw-a target/perf/native-m4-wall-shared-a.raw \
  --shared-wall-profile-a target/perf/native-m4-wall-shared-a.jsonl \
  --shared-wall-stdout-a target/perf/native-m4-wall-shared-a.stdout \
  --shared-wall-capture-a target/perf/native-m4-wall-shared-a.capture.json \
  --shared-wall-raw-b target/perf/native-m4-wall-shared-b.raw \
  --shared-wall-profile-b target/perf/native-m4-wall-shared-b.jsonl \
  --shared-wall-stdout-b target/perf/native-m4-wall-shared-b.stdout \
  --shared-wall-capture-b target/perf/native-m4-wall-shared-b.capture.json \
  --shared-wall-analysis target/perf/native-m4-wall-shared-analysis.json \
  --fault-stack-raw target/perf/native-m4-wall-fault-stack.raw \
  --fault-stack-profile target/perf/native-m4-wall-fault-stack.jsonl \
  --fault-stack-stdout target/perf/native-m4-wall-fault-stack.stdout \
  --fault-stack-capture target/perf/native-m4-wall-fault-stack.capture.json \
  --fault-stack-rules scripts/perf/native_fault_stack_rules_v1.json \
  --fault-stack-qualification target/perf/native-m4-fault-stack-qualification.json \
  --fault-qualification-raw target/perf/native-m4-fault-qualify.raw \
  --fault-qualification-status target/perf/native-m4-fault-qualify.status.json \
  --fault-qualification target/perf/native-m4-fault-qualification.json \
  --fault-provider target/perf/native-m4-fault-provider.json \
  --fault-raw-a target/perf/native-m4-fault-a.raw \
  --fault-profile-a target/perf/native-m4-fault-a.jsonl \
  --fault-stdout-a target/perf/native-m4-fault-a.stdout \
  --fault-capture-a target/perf/native-m4-fault-a.capture.json \
  --fault-raw-b target/perf/native-m4-fault-b.raw \
  --fault-profile-b target/perf/native-m4-fault-b.jsonl \
  --fault-stdout-b target/perf/native-m4-fault-b.stdout \
  --fault-capture-b target/perf/native-m4-fault-b.capture.json \
  --fault-analysis target/perf/native-m4-fault-analysis.json
```

Require every explicit raw/summary/stdout/capture hash to match, plus every
M1/M2/M3 acceptance, coverage, stability, lifecycle, control-state, and one
frozen-receipt identity field.

- [ ] **Step 2: Escalate ambiguity and reverify before promotion**

If a dominant shared PC/range or fault owner remains disputed, use LLDB on the
guest Carrick process and record the exact mapping/bytes/registers plus
transcript SHA-256. Re-run the relevant frozen-binary profile and the complete
Step 1 verifier after the finding. If neither candidate has a supported
removable ceiling or the deterministic tie remains unresolved, M4 stops here;
no evidence is promoted.

- [ ] **Step 3: Run final correctness and repository gates**

```bash
python3 -m unittest \
  scripts/perf/test_paired_stats.py \
  scripts/perf/test_native_go_build_abba.py \
  scripts/perf/test_native_wall_capture.py \
  scripts/perf/test_native_wall_attribution.py \
  scripts/perf/test_native_fault_qualify.py \
  scripts/perf/test_native_fault_capture.py \
  scripts/perf/test_native_fault_attribution.py \
  scripts/perf/test_native_performance_i0.py -v
just conformance-native smoke --workers 4
just conformance full --lane macos-native-dsr --workers 1 \
  --suite node-app-smoke --suite node-v8-smoke \
  --jsonl target/conformance/native-performance-m4-node.jsonl
just conformance full --lane macos-native-dsr --workers 1 \
  --suite cpython-subprocess --suite cpython-threading \
  --jsonl target/conformance/native-performance-m4-cpython.jsonl
just ci
```

All commands are serial. No Docker oracle overlaps a Carrick run. Re-run the
Step 1 verifier after the gates and require both frozen worktrees still clean.

- [ ] **Step 4: Publish the complete I0 bundle exactly once**

```bash
python3 scripts/perf/native_performance_i0.py publish-bundle \
  --destination scripts/perf/evidence/native-performance-m4-v1 \
  --ledger-source docs/perf-results/native-performance-hypotheses.jsonl \
  --input native-m4-session.json=target/perf/native-m4-frozen-session.json \
  --input native-m4-h0-arm.json=target/perf/native-m4-h0/arm.json \
  --input native-m4-tip-arm.json=target/perf/native-m4-tip/arm.json \
  --input native-m4-neutrality.json=target/perf/native-h0-tip-neutrality-abba-v1.json \
  --input native-m4-default-shared.json=target/perf/native-default-shared-abba-i0-v1.json \
  --input native-m4-wall-default-a.raw=target/perf/native-m4-wall-default-a.raw \
  --input native-m4-wall-default-a.jsonl=target/perf/native-m4-wall-default-a.jsonl \
  --input native-m4-wall-default-a.stdout=target/perf/native-m4-wall-default-a.stdout \
  --input native-m4-wall-default-a.capture.json=target/perf/native-m4-wall-default-a.capture.json \
  --input native-m4-wall-default-b.raw=target/perf/native-m4-wall-default-b.raw \
  --input native-m4-wall-default-b.jsonl=target/perf/native-m4-wall-default-b.jsonl \
  --input native-m4-wall-default-b.stdout=target/perf/native-m4-wall-default-b.stdout \
  --input native-m4-wall-default-b.capture.json=target/perf/native-m4-wall-default-b.capture.json \
  --input native-m4-wall-default-analysis.json=target/perf/native-m4-wall-default-analysis.json \
  --input native-m4-wall-shared-a.raw=target/perf/native-m4-wall-shared-a.raw \
  --input native-m4-wall-shared-a.jsonl=target/perf/native-m4-wall-shared-a.jsonl \
  --input native-m4-wall-shared-a.stdout=target/perf/native-m4-wall-shared-a.stdout \
  --input native-m4-wall-shared-a.capture.json=target/perf/native-m4-wall-shared-a.capture.json \
  --input native-m4-wall-shared-b.raw=target/perf/native-m4-wall-shared-b.raw \
  --input native-m4-wall-shared-b.jsonl=target/perf/native-m4-wall-shared-b.jsonl \
  --input native-m4-wall-shared-b.stdout=target/perf/native-m4-wall-shared-b.stdout \
  --input native-m4-wall-shared-b.capture.json=target/perf/native-m4-wall-shared-b.capture.json \
  --input native-m4-wall-shared-analysis.json=target/perf/native-m4-wall-shared-analysis.json \
  --input native-m4-wall-fault-stack.raw=target/perf/native-m4-wall-fault-stack.raw \
  --input native-m4-wall-fault-stack.jsonl=target/perf/native-m4-wall-fault-stack.jsonl \
  --input native-m4-wall-fault-stack.stdout=target/perf/native-m4-wall-fault-stack.stdout \
  --input native-m4-wall-fault-stack.capture.json=target/perf/native-m4-wall-fault-stack.capture.json \
  --input native-m4-fault-stack-qualification.json=target/perf/native-m4-fault-stack-qualification.json \
  --input native-m4-fault-stack-rules.json=scripts/perf/native_fault_stack_rules_v1.json \
  --input native-m4-fault-qualify.raw=target/perf/native-m4-fault-qualify.raw \
  --input native-m4-fault-qualify.status.json=target/perf/native-m4-fault-qualify.status.json \
  --input native-m4-fault-qualification.json=target/perf/native-m4-fault-qualification.json \
  --input native-m4-fault-provider.json=target/perf/native-m4-fault-provider.json \
  --input native-m4-fault-a.raw=target/perf/native-m4-fault-a.raw \
  --input native-m4-fault-a.jsonl=target/perf/native-m4-fault-a.jsonl \
  --input native-m4-fault-a.stdout=target/perf/native-m4-fault-a.stdout \
  --input native-m4-fault-a.capture.json=target/perf/native-m4-fault-a.capture.json \
  --input native-m4-fault-b.raw=target/perf/native-m4-fault-b.raw \
  --input native-m4-fault-b.jsonl=target/perf/native-m4-fault-b.jsonl \
  --input native-m4-fault-b.stdout=target/perf/native-m4-fault-b.stdout \
  --input native-m4-fault-b.capture.json=target/perf/native-m4-fault-b.capture.json \
  --input native-m4-fault-analysis.json=target/perf/native-m4-fault-analysis.json
```

The command reruns the same typed verification against its staged copies,
builds I0 plus the complete ledger image inside the staging directory, and
publishes only by atomic directory rename. `manifest.json` must reconstruct
every durable hash and the bundle destination must not have existed.

- [ ] **Step 5: Verify the bundle and materialize the derived ledger**

```bash
python3 scripts/perf/native_performance_i0.py verify-bundle \
  --bundle scripts/perf/evidence/native-performance-m4-v1
python3 scripts/perf/native_performance_i0.py materialize-ledger \
  --bundle scripts/perf/evidence/native-performance-m4-v1 \
  --destination docs/perf-results/native-performance-hypotheses.jsonl
```

The verifier enumerates the closed role table from `manifest.json`, rehashes
every explicit file in the bundle, reruns the typed source/selection checks,
and requires the bundled I0 and ledger image to reconstruct exactly. The
manifest stores:

- H0 and tip commit/binary/receipt identities;
- neutrality estimate and upper bound;
- default/shared untraced CPU arm medians and paired decision fields;
- two default and two shared native-wall source hashes, shares, distinct typed
  ranges/units, category estimates, and dispersions;
- provider receipt plus two native-fault source hashes, coverage, owner/page/
  repeat populations, and kernel estimates/dispersion;
- exact formulas and category sets;
- one selected candidate; and
- one SHA-256 for every input.

- [ ] **Step 6: Require one bounded `PROPOSED` row**

The selected ledger row includes observation, artifact hashes/current
validity, measured share or exact population, conservative CPU ceiling,
predicted counter/category movement, structural/correctness risk, opt-out
variable, at most two variants, stop condition, mechanism gate, and empty
future traced/ABBA result fields. The fixed template mapping is
`shared-translation-locality` ->
`CARRICK_DISABLE_SHARED_TRANSLATION_LOCALITY=1` and
`native-fault-owner` -> `CARRICK_DISABLE_NATIVE_FAULT_OWNER=1`. Record the
selected exact variable now; add only that selected key to
`PERFORMANCE_CONTROL_KEYS` when the separate optimization implementation
starts, not during M4 evidence assembly.

Every non-selected open question is explicitly `DEFER` with its measured
ceiling and reason. No row remains implicitly active.

- [ ] **Step 7: Update controller state honestly**

In the CPU evidence ledger and `handoff.md`, state:

- the control plane is complete and neutral;
- I0 is accepted with exact artifact hashes;
- which ceiling won and why;
- the selected bounded hypothesis and opt-out contract;
- all other hypotheses' explicit states; and
- the broader 0.70 total-CPU goal remains active.

The selected runtime change gets its own reviewed design and implementation
plan before code changes begin.

- [ ] **Step 8: Commit all promoted evidence, I0, and the selected next slice**

```bash
git add scripts/perf/evidence/native-performance-m4-v1 \
  docs/perf-results/native-performance-hypotheses.jsonl \
  docs/perf-results/2026-07-29-native-cpu-budget-evidence.md \
  handoff.md
git commit -m "diagnostics(perf): accept I0 and select the next native slice" -m \
"Bind untraced default/shared CPU, stable translation ownership, and qualified
fault ownership from one frozen post-M3 binary into one immutable baseline.
Select one bounded subproject from evidence-bounded removable ceilings while
keeping the 0.70 campaign open.

Verified with source-hash reconstruction, native smoke, Node/CPython
guardrails, and `just ci`.

Co-Authored-By: Codex <codex@openai.com>"
```

Run:

```bash
python3 scripts/perf/native_performance_i0.py verify-bundle \
  --bundle scripts/perf/evidence/native-performance-m4-v1
test -z "$(git status --short)"
```

Retain the two external source
worktrees and immutable H0/tip arm directories through the first optimization
wave so every receipt remains live-reverifiable; cleanup is a later explicit
controller action, not part of M4.

## Plan-Set Coverage Audit

| Design obligation | Executable owner |
|---|---|
| Section 5 receipts, explicit binary, ABBA, SplitMix64, sign/bootstrap/resolution, preflight, partial publication | M1 Tasks 1–6 |
| Section 6 typed private/shared ranges, process birth/image/runtime identity, fork frontiers, `DSRPROF2`, balanced kernel state, 14-category analysis | M2 Tasks 1–6 |
| Section 7 live provider qualification, mapping versions, qualified page capture, mixed/partial ownership, repetition, two-run acceptance | M3 Tasks 1–5 |
| Section 8 opt-out spike protocol and durable hypothesis states | M1 Task 5 and M4 Tasks 1/4 |
| Section 9 LLDB escalation and transcript provenance | M2 Task 6, M3 Task 5, M4 Task 4 |
| Section 10 red-first fixtures, signed live proof, smoke, Node, CPython, CI | Every milestone completion task |
| Section 11 M1–M4 delivery sequence | The four dated plan files in this set |
| Section 12 broader `0.70` campaign completion | Preserved as post-M4 controller state; explicitly not claimed by these plans |
| Section 13 stop/redesign conditions | Each milestone completion gate and fail-closed artifact path |

## M4 Completion Gate

M4 is complete only when:

- the frozen post-M3 tip is neutral against H0 under the `1.00`/`1.02` bounds;
- the default/shared same-binary campaign has eight complete quads;
- I0 contains accepted untraced, four native-wall, and two native-fault
  evidence paths from that same receipt with exact durable source hashes;
- inclusive components and removable translation/fault ceilings are separate,
  non-overlapping definitions;
- the ledger has exactly one evidence-supported `PROPOSED` next subproject and
  explicit states for every alternative;
- native smoke, Node, CPython, and `just ci` pass; and
- `handoff.md` says the control plane is complete while the broader performance
  goal remains active.

M4 completes the approved control-plane design, not the user's native
performance goal.
