# Go Conformance Gate (SP1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A differential harness that runs Go's own std-library test binaries under carrick and under Docker `linux/arm64`, diffs per-test PASS/FAIL, and reports carrick-only failures — producing the baseline T2 conformance tally and the regression net for later sub-projects.

**Architecture:** A shell harness (`scripts/go-conformance.sh`) that (1) cross-builds a curated set of Go std-test binaries with the carrick-compatible external-static-pie recipe inside a `golang` arm64 container, caching them; (2) runs each binary under carrick (`run-elf --raw --fs host`) and under a Docker arm64 container with identical args; (3) parses `--- PASS:`/`--- FAIL:` lines and reports tests that fail under carrick but pass under Docker (the correctness gap; environmental failures appear in both and cancel). A script is the MVP for fast iteration + an immediate baseline; a Rust `#[test]` wrapper that asserts "0 carrick-only failures against a baseline" is a follow-up (SP4).

**Tech Stack:** bash, Docker (`golang:1.24-bookworm` arm64 for builds, `debian:stable-slim` arm64 for the oracle), the signed `target/release/carrick`, Go test binaries.

---

## File structure

- Create: `scripts/go-conformance.sh` — the differential harness (build + run + diff + report).
- Create: `scripts/go-conformance-packages.txt` — the curated high-signal package list (one per line), so the set is data, not code.
- Output (gitignored, not committed): `/tmp/go-conformance/` build cache + per-run logs.

## Notes for the implementer

- carrick-compatible Go build recipe (from `scripts/build-go-fixtures.sh`):
  `CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=pie -ldflags "-linkmode external -extldflags -static-pie"`.
  For test binaries: `go test -c -buildmode=pie -ldflags "-linkmode external -extldflags -static-pie" -o <out> <pkg>`.
- Run a test binary skipping source-reading Examples and long tests:
  `<bin> -test.run 'Test' -test.short -test.v`.
- carrick run: `target/release/carrick run-elf --raw --fs host <bin> -- <args>`.
  Always `pkill -9 -f "carrick run-elf"` between runs and wrap each carrick run in `timeout -s KILL <N>` (a wedged guest ignores SIGTERM).
- Parse verdicts from `--- PASS: TestName` / `--- FAIL: TestName` lines.
- Differential logic: a test is a **carrick-only failure** iff it is FAIL (or absent) under carrick AND PASS under Docker. Those are the actionable gaps. A test FAIL under both is environmental → ignore.

---

### Task 1: Curated package list + build stage

**Files:**
- Create: `scripts/go-conformance-packages.txt`
- Create: `scripts/go-conformance.sh`

- [ ] **Step 1: Write the package list**

Create `scripts/go-conformance-packages.txt`:

```
sync
sync/atomic
context
time
os/signal
os/exec
runtime
net
```

- [ ] **Step 2: Write the build stage of the harness**

Create `scripts/go-conformance.sh`:

```bash
#!/usr/bin/env bash
# Differential Go std-test conformance: carrick vs Docker linux/arm64.
# Usage: scripts/go-conformance.sh [pkg ...]   (default: scripts/go-conformance-packages.txt)
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="/tmp/go-conformance"; mkdir -p "$cache/bin" "$cache/logs"
carrick="$repo/target/release/carrick"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"

pkgs=("$@")
if [ ${#pkgs[@]} -eq 0 ]; then
  mapfile -t pkgs < "$repo/scripts/go-conformance-packages.txt"
fi

build() {
  # Build all test binaries in one container invocation, cached by package name.
  local need=()
  for p in "${pkgs[@]}"; do
    local n; n=$(echo "$p" | tr / _)
    [ -x "$cache/bin/$n.test" ] || need+=("$p")
  done
  [ ${#need[@]} -eq 0 ] && return 0
  echo "building: ${need[*]}"
  docker run --rm --platform linux/arm64 -v "$cache/bin":/out golang:1.24-bookworm sh -c '
    for p in '"${need[*]}"'; do
      n=$(echo "$p" | tr / _)
      CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go test -c -buildmode=pie \
        -ldflags "-linkmode external -extldflags -static-pie" -o /out/$n.test "$p" \
        && echo "  built $n.test" || echo "  BUILD FAIL $p"
    done
    chmod -R a+rwx /out'
}
build
```

- [ ] **Step 3: Run the build stage and verify binaries appear**

Run: `bash scripts/go-conformance.sh sync time`
Expected: `building: sync time` then `built sync.test` / `built time.test`; `ls /tmp/go-conformance/bin/` shows `sync.test time.test`.

- [ ] **Step 4: Commit**

```bash
git add scripts/go-conformance.sh scripts/go-conformance-packages.txt
git commit -m "test(go-conformance): build stage for std-test differential harness"
```

---

### Task 2: Per-binary run-and-parse (carrick + Docker)

**Files:**
- Modify: `scripts/go-conformance.sh` (append run/parse functions + the diff)

- [ ] **Step 1: Append the run + parse + diff logic**

Append to `scripts/go-conformance.sh`:

```bash
# Extract "PASS <Test>" / "FAIL <Test>" verdict lines, sorted unique.
verdicts() { grep -oE '^--- (PASS|FAIL): [A-Za-z0-9_/]+' "$1" \
  | sed -E 's/^--- (PASS|FAIL): /\1 /' | sort -u; }

total_gap=0
for p in "${pkgs[@]}"; do
  n=$(echo "$p" | tr / _); bin="$cache/bin/$n.test"
  [ -x "$bin" ] || { echo "[$p] NO BINARY (build failed) — gap"; total_gap=$((total_gap+1)); continue; }

  # Docker oracle
  docker run --rm --platform linux/arm64 -v "$cache/bin":/b -w /b debian:stable-slim \
    "./$n.test" -test.run 'Test' -test.short -test.v > "$cache/logs/$n.docker" 2>&1

  # carrick
  pkill -9 -f "carrick run-elf" 2>/dev/null
  CARRICK_EXPOSED_CPUS=10 timeout -s KILL "$RUN_TIMEOUT" "$carrick" run-elf --raw --fs host \
    "$bin" -- -test.run 'Test' -test.short -test.v > "$cache/logs/$n.carrick" 2>&1
  pkill -9 -f "carrick run-elf" 2>/dev/null

  verdicts "$cache/logs/$n.docker"  > "$cache/logs/$n.docker.v"
  verdicts "$cache/logs/$n.carrick" > "$cache/logs/$n.carrick.v"

  # carrick-only failures: PASS in docker, not PASS in carrick.
  gap=$(comm -23 <(grep '^PASS ' "$cache/logs/$n.docker.v" | awk '{print $2}' | sort -u) \
                 <(grep '^PASS ' "$cache/logs/$n.carrick.v" | awk '{print $2}' | sort -u))
  dpass=$(grep -c '^PASS ' "$cache/logs/$n.docker.v")
  cpass=$(grep -c '^PASS ' "$cache/logs/$n.carrick.v")
  if [ -n "$gap" ]; then
    ngap=$(echo "$gap" | grep -c .)
    echo "[$p] docker=$dpass carrick=$cpass  CARRICK-ONLY FAILURES ($ngap):"
    echo "$gap" | sed 's/^/    /'
    total_gap=$((total_gap+ngap))
  else
    echo "[$p] docker=$dpass carrick=$cpass  OK (no carrick-only failures)"
  fi
done
echo "=== TOTAL carrick-only failures: $total_gap ==="
exit $([ "$total_gap" -eq 0 ] && echo 0 || echo 1)
```

- [ ] **Step 2: Run on the two fast packages and inspect**

Run: `bash scripts/go-conformance.sh sync sync/atomic`
Expected: lines like `[sync] docker=48 carrick=47  CARRICK-ONLY FAILURES (1): TestMutexMisuse` and `[sync/atomic] ... OK`. The `TestMutexMisuse` gap is the known pidfd/os-exec gap (SP2). A `TOTAL carrick-only failures` line prints.

- [ ] **Step 3: Commit**

```bash
git add scripts/go-conformance.sh
git commit -m "test(go-conformance): per-binary differential run + carrick-only-failure report"
```

---

### Task 3: Baseline tally over the full curated set

**Files:**
- Create: `docs/superpowers/go-conformance-baseline.md` (the recorded baseline)

- [ ] **Step 1: Build + run the full set, capture output**

Run: `bash scripts/go-conformance.sh 2>&1 | tee /tmp/go-conformance/baseline.txt`
Expected: a per-package report and a `TOTAL carrick-only failures: N` line. `runtime`/`net` may be slow or show load failures — that's data (record it).

- [ ] **Step 2: Record the baseline**

Create `docs/superpowers/go-conformance-baseline.md` with the captured per-package tally and the carrick-only failure list (paste from `/tmp/go-conformance/baseline.txt`), plus a one-line note classifying each gap (e.g., `TestMutexMisuse → pidfd/os-exec (SP2)`; any load failure → loader (SP3)).

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/go-conformance-baseline.md
git commit -m "docs(go-conformance): record baseline T2 tally vs Docker arm64"
```

---

## Self-review

- **Spec coverage (SP1):** build stage (Task 1), differential run + carrick-only-failure report (Task 2), baseline tally (Task 3) — all present. The Rust `#[test]` permanent-gate wrapper is intentionally deferred to SP4 (after capability fixes shrink the gap toward 0), noted in the plan header.
- **Placeholders:** none — script content is complete and runnable.
- **Consistency:** `verdicts()`, cache paths (`/tmp/go-conformance`), and the `-test.run 'Test' -test.short -test.v` invocation are identical across tasks.
- **Known-result anchor:** Task 2 Step 2 predicts the `sync`→`TestMutexMisuse` carrick-only failure already observed this session, so a correct harness reproduces it.
