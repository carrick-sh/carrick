### Task 6: Run the controlled eight-quad CPU gate

**Control source:** `a5bd4971`

**Candidate source HEAD:** `9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d`

**Candidate runtime implementation tip:** `9e0b08178b9335f03825001a56190a6e1b375837` (the only later commit is the reviewed Python-only validator repair).

**Candidate pre-ABBA binary SHA-256:** `1809ca3782184437b2e623b22a555ec5c5af08a40182697b6f8f6f78da148f06`.

**Exact image:** `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.

**Files:**
- Create/reuse only a clean detached control worktree at `/Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control` exactly at `a5bd4971`.
- Create target-only control/candidate arm receipts and ABBA artifact under `target/perf/native-optimistic-decode/`.
- Modify no tracked source. Do not revert a losing candidate; report the retention verdict to the controller.

**Produces:**
- Exact signed control and candidate arm receipts.
- Complete two-warmup plus eight A-B-B-A-quad campaign using identical `native-default.json` overlays.
- Report `.superpowers/sdd/2026-08-04-native-optimistic-decode/task-6-report.md`.

- [ ] **Step 0: Quiet-box and source preflight**

Confirm no other Carrick, DTrace, Docker, or performance harness workload is active. Confirm the candidate tracked tree is clean, HEAD exact, and existing binary hash exact. Check `git worktree list --porcelain` before creating the control. If the named control worktree already exists, require it to be a clean detached worktree at exact `a5bd4971`; otherwise stop and report rather than deleting or overwriting it.

- [ ] **Step 1: Prepare a clean exact control worktree**

```bash
git worktree add --detach \
  /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  a5bd4971
git -C /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control status --short
git -c core.fsmonitor=false status --short
```

Expected: both worktrees clean. Do not move local `main`.

- [ ] **Step 2: Build and freeze both signed arms**

```bash
just \
  -f /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control/justfile \
  -d /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  build
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  --destination target/perf/native-optimistic-decode/control-arm \
  --label retained-a5bd4971 \
  --role control \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$PWD" \
  --destination target/perf/native-optimistic-decode/candidate-arm \
  --label optimistic-decode-tip \
  --role candidate \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
```

Require clean source receipts, signed binaries, exact hashes, arm64 image identity, DOF sections, and identical image/semantic default overlay authority. Record both full source commits, binary hashes, receipt hashes, signature/DOF evidence, and candidate runtime/parser provenance. If a destination already exists, inspect it and fail closed; do not overwrite a prior receipt silently.

- [ ] **Step 3: Run the official comparison**

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt "$PWD/target/perf/native-optimistic-decode/control-arm/arm.json" \
  --candidate-receipt "$PWD/target/perf/native-optimistic-decode/candidate-arm/arm.json" \
  --control-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --candidate-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --quads 8 \
  --cooldown-seconds 2 \
  --timeout-seconds 30 \
  --allow-battery \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b \
  --output "$PWD/target/perf/native-optimistic-decode/abba-v1.json"
```

Battery is explicitly authorized by the user; thermal, load, cleanup, image, source, binary, and receipt gates remain mandatory. Run the campaign alone and let it finish. Do not run Docker concurrently or start another measurement. Report a checkpoint after arm preparation and at ABBA start; if the harness exposes safe progress, report at the halfway point without perturbing it.

- [ ] **Step 4: Apply the retention rule**

Require complete/accepted evidence, both excluded warmups, 32/32 measured `BUILD_OK`, and no cleanup, timeout, thermal, load, image, source, binary, overlay, or receipt failures. Independently recompute paired ratios/intervals/win counts/sign tests from the artifact using current repository analysis code or literal arithmetic; never rely on a single summary field.

Retain only when the two-sided paired total-child-CPU interval excludes 1.0 in the favorable direction and supported secondary metrics do not regress. At least 10% CPU is desired; a smaller result requires an explicit evidence-backed non-regrettable-enabler decision. Treat wall as resolved only if its ratio interval excludes 1.0. If CPU is flat/regressed, recommend reverting only the candidate implementation commits while preserving the design/plan/parser fix and target receipts; do not perform that revert in this task.

Write the report with exact commands; preflight; both arm and artifact identities/hashes; acceptance gate results; all 32 measurements plus excluded warmups summarized honestly; CPU/user/sys/wall ratios, two-sided intervals, wins, and sign-test result; retention recommendation; measured-vs-inferred confidence change; and concerns. Do not push or move local main.
