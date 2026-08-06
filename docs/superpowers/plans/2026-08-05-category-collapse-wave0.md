# Category-Collapse Wave 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the two non-regrettable Wave-0 measurements of the
category-collapse strategy
([spec](../specs/2026-08-05-category-collapse-strategy-design.md)): the
Docker-side CPU denominators + category budgets, and the first Move-3
amplification-ledger entry (fs-walk) — plus one spec correction discovered
during planning.

**Architecture:** Pure measurement and documentation — zero runtime code
changes. A small Docker-only harness captures in-container user/sys CPU with
the POSIX `times` builtin using the exact `workload-spread.sh` fixtures
(asserted byte-identical, so results join the existing scoreboard). The
budget doc joins those denominators to the already-measured carrick-side v5
category shares. The ledger entry uses `carrick trace`'s bundled syscall
tracer on the fs-walk fixture.

**Tech Stack:** zsh (matching `scripts/perf/` house style), `docker run`,
python3 inline parsing, `carrick trace` (in-process libdtrace).

## Global Constraints

- **Never run carrick and Docker concurrently** (AGENTS.md two-phase rule).
  Task 2 is Docker-only; Task 4 is carrick-only; do not interleave them with
  each other or any other lane's runs.
- **Stamp `CARRICK_RUN_ID` on carrick runs; reap only with
  `scripts/sudo/kill.sh <run-id>`** — never `pkill -f carrick`.
- **Never truncate gate/measurement logs**: `tee` full output under
  `target/perf/`, grep binary-bearing logs with `-a`, check exit codes.
- **Quiet-host preflight before any timing**: `pmset -g batt`, `pmset -g
  therm`, and confirm no non-measurement process is holding ~a full core
  (`ps -Ao %cpu,comm | sort -rn | head`). The 2026-08-03 spread deferred for
  `mediaanalysisd` at 100%; follow that practice.
- **Do not touch `.superpowers/sdd/2026-08-05-native-live-translation-arena/`**
  — that controller owns Wave 1 (live arena); its sequencing is unchanged by
  this plan.
- **No runtime code changes and no new mechanisms in Wave 0** — measurement
  scripts and docs only. Measured figures are quoted with their source doc;
  anything derived is marked *derived*.
- **Commits:** Conventional Commits with a body (why/what/verified), trailer
  `Co-Authored-By:` crediting the executing agent. Never `--no-verify`.
- Carrick binary for Task 4 comes from `just build` (codesigned path), not
  bare cargo.

---

### Task 1: Correct the spec's fs-walk framing

Planning research resolved the spec's "fs-walk contradiction": it is a
**denominator difference, not a regression**. The evidence
([`container-lifecycle-split.jsonl`](../../perf-results/container-lifecycle-split.jsonl),
records `fs-walk-lifecycle-vs-in-guest` and `total-wall-drained-baseline`):
the 2026-08-02 trusted-dirfd campaign's **3.8x was TOTAL wall** (container
lifecycle included; lifecycle reached 2.7x), while the **in-guest** window was
**18.5x then (225 ms / 12 ms)** and is **18.9x now (265 ms / 14 ms)** —
consistent, and never fixed. The named redesign for the in-guest term is fs
endgame Lever B (serve reads from the shared cache tree as a read-only lower
layer, copy-up on write — roadmap Phase 4).

**Files:**
- Modify: `docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md`
  (Move 3 fs-walk bullet; Wave 0 item in §5)

**Interfaces:**
- Produces: the corrected Move-3 bullet text that Task 4's report links back to.

- [ ] **Step 1: Replace the Move-3 fs-walk bullet**

Replace the bullet beginning `**the fs-walk contradiction**:` with:

```markdown
- **the fs-walk in-guest amplification**: the current spread measures the
  in-guest fs-walk window at **18.9286x** (265 ms / 14 ms). The 2026-08-02
  trusted-dirfd result of ~3.8x was **total wall** (container lifecycle
  included; lifecycle reached 2.7x), while the in-guest window was 18.5x
  then and is 18.9x now
  ([`container-lifecycle-split.jsonl`](../../perf-results/container-lifecycle-split.jsonl),
  records `fs-walk-lifecycle-vs-in-guest`, `total-wall-drained-baseline`) —
  a denominator difference, not a regression. The in-guest fs term was never
  fixed; the named redesign is fs endgame Lever B (serve reads from the
  shared cache tree as a read-only lower layer, copy-up on write — roadmap
  Phase 4). First ledger entry: re-measure host-ops-per-guest-op on the
  `find /usr/local/go -type f` fixture at HEAD (AGENTS.md's 19.68
  hosts-opens-per-guest-open figure is flagged stale by AGENTS.md itself).
```

- [ ] **Step 2: Update the Wave-0 item in §5**

In §5 item 1, change `the fs-walk attribution` to
`the fs-walk in-guest amplification-ledger entry (Task 4 of the Wave-0 plan)`.

- [ ] **Step 3: Verify internal consistency**

Run: `grep -n "contradiction\|3.8x" docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md`
Expected: no remaining claim that the 3.8x-vs-18.9x pair is unexplained; the
§6 invalidation section and §8 do not reference the old framing (they don't
today — confirm nothing else needs the edit).

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md
git commit -m "docs: correct fs-walk framing in category-collapse spec

The spec called the 18.9x-vs-3.8x fs-walk pair an unexplained
contradiction. container-lifecycle-split.jsonl resolves it: 3.8x was
total wall (lifecycle, fixed to 2.7x by the trusted lanes); the in-guest
window was 18.5x then and 18.9x now - never fixed, not regressed. The
Move-3 entry becomes: ledger the in-guest amplification; the named
redesign is fs endgame Lever B."
```

---

### Task 2: Docker-side in-container CPU split harness + measurement

The category budgets need Docker's user/sys CPU for the spread fixtures. The
existing scoreboard deliberately does not capture it (the wall-refresh doc:
Docker's recorded `RUSAGE_CHILDREN` is the host `docker` wrapper only). The
instrument: append the POSIX `times` builtin inside the same in-container
`sh -c` window the spread harness already uses, Docker-only, with the fixture
strings asserted byte-identical against `workload-spread.sh` so the numbers
join the existing scoreboard.

**Files:**
- Create: `scripts/perf/docker-cpu-split.sh`
- Create: `docs/perf-results/2026-08-05-docker-cpu-split.md`

**Interfaces:**
- Consumes: fixture strings from `scripts/perf/workload-spread.sh:44-47`
  (compute, fs-walk, exec-20, build-cold).
- Produces: `target/perf/docker-cpu-split/docker-cpu-split.jsonl` with records
  `{"schema":"carrick.docker-cpu-split.v1","workload":<name>,"sample":<i>,"wall_ms":<int>,"user_s":<float>,"sys_s":<float>}`
  plus one `…meta.v1` header record; and the results doc with a
  medians table (columns: workload, wall_ms, user_s, sys_s, cpu_total_s).
  Task 3 consumes the medians table.

- [ ] **Step 1: Write the harness**

Create `scripts/perf/docker-cpu-split.sh` (mode 755):

```zsh
#!/bin/zsh
# Docker-side in-container CPU split for the workload-spread fixtures.
# Move 0 of docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md:
# the category budgets need Docker's user/sys denominators, which the spread
# harness deliberately does not capture (its Docker rusage is the host
# wrapper). DOCKER-ONLY BY DESIGN -- never run while any carrick workload is
# active (AGENTS.md two-phase rule).
set -eu
SCRIPT_DIR=${0:A:h}
REPO_ROOT=${SCRIPT_DIR:h:h}
cd "$REPO_ROOT"

IMAGE=${CARRICK_PERF_IMAGE:-localhost:5005/carrick-go-conformance:1.24}
N=${1:-5}
OUT_DIR=target/perf/docker-cpu-split
OUT_JSONL=$OUT_DIR/docker-cpu-split.jsonl
mkdir -p "$OUT_DIR"

# Fixtures MUST stay byte-identical to workload-spread.sh so this split can
# be joined to the spread scoreboard. Assert, don't trust.
typeset -A WL
WL[compute]="awk 'BEGIN{for(i=0;i<8000000;i++)s+=i;print s}' >/dev/null"
WL[fs-walk]='find /usr/local/go -type f | wc -l >/dev/null'
WL[exec-20]='i=0; while [ $i -lt 20 ]; do /usr/local/go/pkg/tool/linux_arm64/compile -V >/dev/null; i=$((i+1)); done'
WL[build-cold]='cd /tmp; rm -rf gcx bx; printf "package main\nfunc main(){println(\"ok\")}\n" > b.go; GOCACHE=/tmp/gcx /usr/local/go/bin/go build -o bx ./b.go'
ORDER=(compute fs-walk exec-20 build-cold)

for name in $ORDER; do
  grep -qF -- "${WL[$name]}" scripts/perf/workload-spread.sh || {
    print -u2 "error: fixture '$name' drifted from workload-spread.sh"
    exit 2
  }
done

print -r -- "$(python3 -c "
import json
print(json.dumps({
  'schema': 'carrick.docker-cpu-split.meta.v1',
  'git_commit': '$(git rev-parse HEAD)',
  'image': '$IMAGE',
  'image_id': '$(docker image inspect "$IMAGE" --format '{{.Id}}')',
  'samples_per_workload': $N,
  'method': 'in-container sh -c window: date +%s%N brackets + POSIX times builtin; shell-self and children lines summed',
}))")" >> "$OUT_JSONL"

run_one() { # workload-name sample -> one JSONL line on stdout
  local name=$1 i=$2 rid="cpusplit-docker-$name-$$-$i" out
  local script="set -eu; w0=\$(date +%s%N); ${WL[$name]}; w1=\$(date +%s%N); echo \"WORKLOAD_NS=\$((w1-w0))\"; times"
  out=$(docker run --rm --name "$rid" --platform linux/arm64 -w /tmp "$IMAGE" /bin/sh -c "$script")
  print -r -- "$out" > "$OUT_DIR/raw-$name-$i.txt"
  print -r -- "$out" | python3 -c "
import re, sys, json
raw = sys.stdin.read()
ns = int(re.search(r'WORKLOAD_NS=(\d+)', raw).group(1))
# times prints two lines after the marker: shell self, then children --
# each 'USERmUSERs SYSmSYSs'. Accept any fractional precision.
pairs = re.findall(r'(\d+)m([0-9.]+)s\s+(\d+)m([0-9.]+)s', raw)
assert len(pairs) >= 2, f'times output not recognized: {raw!r}'
sec = lambda m, s: int(m) * 60 + float(s)
user = sum(sec(p[0], p[1]) for p in pairs[-2:])
syst = sum(sec(p[2], p[3]) for p in pairs[-2:])
print(json.dumps({'schema': 'carrick.docker-cpu-split.v1',
                  'workload': '$name', 'sample': $i,
                  'wall_ms': ns // 1000000,
                  'user_s': round(user, 4), 'sys_s': round(syst, 4)}))
"
}

for name in $ORDER; do
  print -u2 "=== $name ==="
  for i in $(seq 1 $N); do
    line=$(run_one $name $i)
    print -r -- "$line" >> "$OUT_JSONL"
    print -u2 "  $line"
  done
done

print ""
printf "%-12s %10s %10s %10s %12s\n" workload wall_ms user_s sys_s cpu_total_s
python3 - "$OUT_JSONL" <<'PY'
import json, statistics, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if '"carrick.docker-cpu-split.v1"' in l]
for name in ['compute', 'fs-walk', 'exec-20', 'build-cold']:
    rs = [r for r in rows if r['workload'] == name]
    if not rs:
        continue
    med = lambda k: statistics.median(r[k] for r in rs)
    print(f"{name:<12} {med('wall_ms'):>10.0f} {med('user_s'):>10.3f} "
          f"{med('sys_s'):>10.3f} {med('user_s') + med('sys_s'):>12.3f}")
PY
```

- [ ] **Step 2: Probe-run one sample to verify the `times` format assumption**

Preflight the quiet host first (Global Constraints). Then:

Run: `scripts/perf/docker-cpu-split.sh 1 2>&1 | tee target/perf/docker-cpu-split/probe.log`
Expected: four JSONL lines with plausible values (compute user_s ≈ 0.1,
build-cold cpu_total_s roughly 1.5–2.5 s, sys_s nonzero for fs-walk), and a
summary table. If the parser assertion fires, inspect
`target/perf/docker-cpu-split/raw-*.txt` for the image's actual `times`
format and fix the regex — do not proceed on a guessed format.

- [ ] **Step 3: Reset output and run the real measurement**

Run:
```bash
rm -f target/perf/docker-cpu-split/docker-cpu-split.jsonl
scripts/perf/docker-cpu-split.sh 5 2>&1 | tee target/perf/docker-cpu-split/run-5x.log
```
Expected: 20 sample records + meta record; no docker failures; medians table
printed. Confirm no carrick process ran during the window
(`pgrep -fl 'carrick run' || true` → empty).

- [ ] **Step 4: Write the results doc**

Create `docs/perf-results/2026-08-05-docker-cpu-split.md` with: date, scope
(Docker-only denominators for Move 0), authority (git commit, image id,
docker version via `docker version --format '{{.Server.Version}}'`, host
preflight outcome, run window), the full per-sample table, the medians table,
and the explicit caveats: `times` granularity is centisecond-scale; the
in-container wall window matches the spread harness's bracket; carrick-side
CPU is deliberately NOT re-measured here (the wall-refresh's 20.167694 s
median and the v5 shares remain that side's authority).

- [ ] **Step 5: Verify doc figures against the JSONL**

Run: `python3 -c "import json;print(*[json.loads(l) for l in open('target/perf/docker-cpu-split/docker-cpu-split.jsonl') if 'v1\"' in l], sep='\n')"`
Expected: every number in the doc's tables appears verbatim in the JSONL
(medians recomputed by eye or the Step-1 summary block).

- [ ] **Step 6: Commit**

```bash
git add scripts/perf/docker-cpu-split.sh docs/perf-results/2026-08-05-docker-cpu-split.md
git commit -m "diagnostics(perf): measure docker-side in-container cpu split

Move 0 of the category-collapse strategy needs Docker's user/sys CPU as
the budget denominators; the spread harness only records the host docker
wrapper's rusage. New docker-only harness reuses the exact workload-spread
fixtures (byte-identity asserted at startup), brackets the same in-guest
window, and adds the POSIX times builtin inside the container. Medians in
docs/perf-results/2026-08-05-docker-cpu-split.md.

Verified: 5-sample run on a preflighted quiet host, raw receipts under
target/perf/docker-cpu-split/, parser assertion validated against the
image's real times output."
```

---

### Task 3: Category-budget table (the Move-0 policy artifact)

**Files:**
- Create: `docs/perf-results/2026-08-05-category-budgets.md`

**Interfaces:**
- Consumes: Task 2's medians table (build-cold `user_s`, `sys_s`,
  `cpu_total_s`); the v5 category shares
  ([`2026-08-04-current-default-broad-cpu-attribution.md`](../../perf-results/2026-08-04-current-default-broad-cpu-attribution.md)
  as restated in [`handoff.md`](../../../handoff.md)); carrick median total
  CPU 20.167694 s
  ([`2026-08-04-current-default-wall-refresh.md`](../../perf-results/2026-08-04-current-default-wall-refresh.md)).
- Produces: the budget table every subsequent perf work item is ranked
  against (spec Move 0), including named budget values per category.

- [ ] **Step 1: Compute the table**

Write `docs/perf-results/2026-08-05-category-budgets.md` containing, in
order:

1. **Inputs**, each with its source link: carrick total CPU 20.167694 s;
   the v5 shares (kernel 48.0232/48.7901, named-syscall 27.7520/28.8889,
   non-syscall 20.2712/19.9012, translated guest 25.8818/25.3278, Darwin
   userspace 10.0290/9.9863, other Carrick 8.3174/8.5377, translation
   6.0589/5.9643 — use the midpoint of each pair and say so); Docker
   build-cold `user_s`/`sys_s` medians from Task 2.
2. **Today's CPU-seconds per category**: midpoint share × 20.168 s, one row
   per category, summing to ~20.2 (show the sum; residual is unattributed
   sampling remainder and must be listed as its own row, not silently
   dropped).
3. **The 3x target**: target total carrick CPU = 3 × Docker
   `cpu_total_s` (state the equal-parallelism assumption ~2.5 cores from
   [`2026-08-03-build-serialization-attribution.md`](../../perf-results/2026-08-03-build-serialization-attribution.md)).
   Also state the 2x product-bar figure.
4. **Budgets per category**, spec Move-0 shape instantiated with real
   numbers: translation + translation-lock + translation-metadata ≈ 0
   (amortized); translated guest ≤ 1.3 × Docker `user_s`; Darwin kernel ≤
   2 × Docker `sys_s` — **if 2 × sys_s is implausibly small versus today's
   kernel CPU (likely: Docker sys will be a few hundred ms), say so
   plainly and set the kernel budget as (target total − other budgets)
   instead, showing the arithmetic** — the spec's §6 third invalidation
   condition is decided by exactly this comparison, so state its verdict;
   carrick host + Darwin userspace ≤ ~1 CPU-s combined. Budgets must sum
   to ≤ the 3x target with explicit slack shown.
5. **The ranking rule** (one paragraph): work items are ranked by
   category-budget movement; ABBA retention discipline unchanged; the ≥10%
   gate remains an attribution filter but a family addressable by one
   mechanism is judged as one candidate (link the spec).

- [ ] **Step 2: Verify arithmetic**

Run: `grep -n "s |" docs/perf-results/2026-08-05-category-budgets.md`
Then recompute two spot rows by hand (kernel and translated guest:
midpoint × 20.168) and the budget sum. Expected: rows match, categories sum
to total ± the stated residual, budgets sum ≤ target.

- [ ] **Step 3: Commit**

```bash
git add docs/perf-results/2026-08-05-category-budgets.md
git commit -m "docs(perf): derive category budgets from docker denominators

Instantiates Move 0 of the category-collapse strategy: joins the fresh
docker in-container cpu split to the v5 carrick category shares and the
official 20.168 s median, and states the per-category CPU budgets that
reach the 3x goal, with the ranking rule work items are judged by.
Also records the verdict on the spec's third invalidation condition
(whether the kernel budget can honestly be 2x docker sys)."
```

---

### Task 4: fs-walk in-guest amplification — first Move-3 ledger entry

Re-measure host-ops-per-guest-op on the fs-walk fixture at HEAD, replacing
the stale figures (AGENTS.md's "guest open → was 19.68 host opens …
Re-measure before quoting"; the 45k-host-call attribution in
`container-lifecycle-split.jsonl` predates the trusted lanes).

**Files:**
- Create: `docs/perf-results/2026-08-05-fswalk-amplification-ledger.md`
- Modify: `AGENTS.md` (the `guest open → was 19.68 host opens` bullet — fresh
  figure, same bullet shape)

**Interfaces:**
- Consumes: the corrected spec bullet from Task 1; `carrick trace` bundled
  syscall tracer (`--trace-out`); fixture string from
  `scripts/perf/workload-spread.sh:45`.
- Produces: the ledger table format Move 3 reuses for every subsequent
  entry: `guest op | guest count | host calls attributed | amplification |
  dominant host call`.

- [ ] **Step 0: Load the tracing skill**

Invoke the `carrick-trace` skill and follow it for invocation details,
progeny-following, and bounding — it supersedes any flag guess below.

- [ ] **Step 1: Build the signed binary and clear leftovers**

Run: `just build` then `pgrep -fl 'carrick run' || true`
Expected: clean build; no leftover carrick guests (reap any with
`scripts/sudo/kill.sh <run-id>`, never pkill).

- [ ] **Step 2: Capture the trace**

Run (shape — the skill governs exact flags; keep the fixture byte-identical
to the spread harness):

```bash
target/release/carrick trace -o target/perf/fswalk-ledger/trace.txt -- \
  run --exec-backend native -e CARRICK_RUN_ID=fswalk-ledger-1 -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'find /usr/local/go -type f | wc -l >/dev/null'
```

Expected: the run exits cleanly; the trace file contains the live stream and
the frequency-sorted aggregation. A zero-event capture is an error, not a
result (AGENTS.md) — diagnose, don't summarize emptiness. Docker must be
idle for the window.

- [ ] **Step 3: Build the ledger table**

From the aggregation, produce for the top guest fs ops (`openat`,
`newfstatat`/`statx`, `getdents64`, `close`, `read` at minimum): guest
count, host syscall count attributed to servicing them, amplification
ratio, and the dominant host call. Where the bundled tracer's aggregation
does not attribute host calls to guest ops directly, compute the
whole-fixture ratio (total host syscalls / total guest syscalls) and the
per-op guest counts, and say exactly which cells are whole-fixture rather
than per-op — no invented precision. Sanity-check totals against the old
`fswalk-amp6.raw` order of magnitude (45k host calls pre-trusted-lane).

- [ ] **Step 4: Write the ledger doc**

Create `docs/perf-results/2026-08-05-fswalk-amplification-ledger.md`: date,
scope (first Move-3 ledger entry), authority (binary sha256, git commit,
image, run id, trace file path + sha256), the ledger table, the in-guest
wall context (265 ms vs 14 ms = 18.9286x from the spread doc), and a
"next lever" line naming fs endgame Lever B with its expected effect on the
dominant rows.

- [ ] **Step 5: Refresh the stale AGENTS.md figure**

In `AGENTS.md`, update the `guest open → was 19.68 host opens` bullet with
the measured current figure and cite the new ledger doc, keeping the
"drive toward 1" framing. Keep the diff to that bullet.

- [ ] **Step 6: Verify and commit**

Run: `grep -n "19.68" AGENTS.md || true`
Expected: no stale uncited figure remains (the historical number may stay
only as explicit history, e.g. "was 19.68 … now X.XX").

```bash
git add docs/perf-results/2026-08-05-fswalk-amplification-ledger.md AGENTS.md
git commit -m "diagnostics(perf): ledger fs-walk host-per-guest-op amplification

First Move-3 amplification-ledger entry of the category-collapse
strategy: carrick-trace capture of the exact spread fs-walk fixture at
HEAD, host-ops-per-guest-op for the dominant fs syscalls, replacing the
stale pre-trusted-lane figures (AGENTS.md 19.68 opens/open, 45k-host-call
fswalk-amp6). In-guest fs-walk remains 18.9x; the named next lever is fs
endgame Lever B (read-only lower layer, copy-up on write).

Verified: non-empty bounded trace with receipts under
target/perf/fswalk-ledger/."
```

---

## Not in this plan (deliberately)

- **Wave 1 (live arena):** owned by
  `.superpowers/sdd/2026-08-05-native-live-translation-arena/` — Tasks 6C2 →
  6D/6E/6F → 7 continue exactly as sequenced in `handoff.md`.
- **Wave 2 (AOT-priced codegen):** gated on Wave 1's runtime-on ABBA; its
  plan is written after that gate with measured translation economics in
  hand.
- **Wave 3 beyond the first entry:** the ledger *instrument* (a `carrick
  debug`/`carrick trace` capability per the Rust-first rule) gets its own
  design once Task 4 shows which attribution the bundled tracer cannot
  already provide — building tooling before that would guess its
  requirements.
