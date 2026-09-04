# Evidence Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicitly non-authoritative ABBA pilot and fail-closed, worktree-safe HVF cleanup.

**Architecture:** The Python harness carries an immutable evidence-class field from CLI selection through validation, decision, serialization, and exit status. The Rust conformance engine resolves one validated helper path, executes direct then non-interactive privileged cleanup, parses the helper's exact scoped census, and returns an error unless final residue is zero.

**Tech Stack:** Python 3 `unittest`, Rust 2024, `anyhow`, POSIX cleanup helper.

**Spec:** `docs/superpowers/specs/2026-09-04-evidence-tooling-design.md`

## Global Constraints

- Official ABBA evidence remains 8 through 127 quads and fail-closed.
- Directional pilots run 1 through 7 quads and can never be eligible or accepted.
- Cleanup remains scoped to one exact nonempty Carrick run id.
- No global process reap and no current-working-directory helper lookup.
- Implementation and tests land as one logical commit.

---

### Task 1: Directional ABBA pilot

**Files:**
- Modify: `scripts/tests/test_embed_go_build_abba.py`
- Modify: `scripts/perf/embed_go_build_abba.py`

**Interfaces:**
- Produces: `_validate_campaign_quads(quads: int, *, pilot: bool) -> str`
- Produces: `run_campaign(harness_repo, control, candidate, output, *, pilot: bool = False) -> dict[str, object]`
- Produces: top-level artifact `evidence_class` with `official` or `directional-pilot`

- [x] **Step 1: Write failing boundary and authority tests**

```python
self.assertEqual(_validate_campaign_quads(1, pilot=True), "directional-pilot")
with self.assertRaises(ValueError):
    _validate_campaign_quads(7, pilot=False)
artifact = {"complete": True, "evidence_class": "directional-pilot"}
_record_decision(artifact, {"status": "directional", "eligible": False})
self.assertFalse(artifact["accepted"])
self.assertEqual(_decision_exit_code(artifact), 0)
```

- [x] **Step 2: Run the focused Python test and verify RED**

Run: `python3 -m unittest scripts.tests.test_embed_go_build_abba -v`

Expected: failure because pilot validation and the `directional` decision do not exist.

- [x] **Step 3: Implement the minimum evidence-class flow**

```python
def _validate_campaign_quads(quads: int, *, pilot: bool) -> str:
    if pilot and type(quads) is int and 1 <= quads < MINIMUM_QUADS:
        return "directional-pilot"
    if not pilot and type(quads) is int and MINIMUM_QUADS <= quads <= 127:
        return "official"
    mode = "pilot" if pilot else "official"
    expected = "1 through 7" if pilot else "8 through 127"
    raise ValueError(f"{mode} campaigns require {expected} quads")
```

Pass the returned value into the artifact and decision. Keep computed ratios,
but force pilot `eligible = False`, `status = "directional"`, and
`accepted = False`. Add `--pilot`; a completed directional artifact exits 0.

- [x] **Step 4: Run the focused Python test and verify GREEN**

Run: `python3 -m unittest scripts.tests.test_embed_go_build_abba -v`

Expected: all tests pass.

### Task 2: Verified HVF cleanup

**Files:**
- Modify: `crates/carrick-conformance/src/engine.rs`

**Interfaces:**
- Produces: `scoped_cleanup_helper() -> anyhow::Result<PathBuf>`
- Produces: `parse_remaining_processes(output: &[u8]) -> anyhow::Result<usize>`
- Changes: `kill_scoped(pid, run_id, engine, cleanup) -> anyhow::Result<()>`

- [x] **Step 1: Write failing resolver and receipt-parser tests**

```rust
assert_eq!(parse_remaining_processes(b"remaining carrick procs (run-id x) = 0\n")?, 0);
assert!(parse_remaining_processes(b"permission denied\n").is_err());
assert!(validate_cleanup_helper(Path::new("relative/kill.sh")).is_err());
```

Use a temporary executable regular file to prove an absolute direct helper is
accepted, then replace it with a symlink and prove rejection.

- [x] **Step 2: Run the focused Rust test and verify RED**

Run: `cargo test -p carrick-conformance engine::tests::scoped_cleanup -- --nocapture`

Expected: compile failure because the cleanup resolver and parser do not exist.

- [x] **Step 3: Implement direct-first, verified cleanup**

```rust
fn parse_remaining_processes(output: &[u8]) -> anyhow::Result<usize> {
    let text = String::from_utf8_lossy(output);
    let receipts = text
        .lines()
        .filter(|line| line.trim().starts_with("remaining carrick procs ("))
        .collect::<Vec<_>>();
    if receipts.len() != 1 {
        anyhow::bail!("cleanup requires exactly one remaining-process receipt");
    }
    receipts[0]
        .rsplit_once('=')
        .ok_or_else(|| anyhow::anyhow!("cleanup receipt has no count"))?
        .1
        .trim()
        .parse()
        .map_err(Into::into)
}

fn run_hvf_cleanup(run_id: &str) -> anyhow::Result<()> {
    let helper = scoped_cleanup_helper()?;
    for privileged in [false, true] {
        let output = cleanup_command(&helper, run_id, privileged).output()?;
        if parse_remaining_processes(&output.stdout) == Ok(0) {
            return Ok(());
        }
    }
    anyhow::bail!("scoped carrick cleanup left residue for {run_id}")
}
```

The timeout path remains best-effort until the child is reaped; the final
post-wait cleanup propagates failure.

- [x] **Step 4: Run the focused Rust tests and verify GREEN**

Run: `cargo test -p carrick-conformance engine::tests::scoped_cleanup -- --nocapture`

Expected: all scoped cleanup tests pass without invoking real sudo or killing processes.

### Task 3: Integrated verification and commit

**Files:**
- Verify: all files above

**Interfaces:**
- Consumes: both completed tooling changes
- Produces: one reviewable commit on the feature worktree

- [x] **Step 1: Run formatting and focused gates**

Run: `cargo fmt --check`

Run: `python3 -m unittest scripts.tests.test_embed_go_build_abba -v`

Run: `cargo test -p carrick-conformance`

Expected: all commands succeed.

- [x] **Step 2: Run the repository gate**

Run: `RUST_TEST_THREADS=1 just ci`

Expected: the full non-guest gate succeeds.

- [x] **Step 3: Review the exact diff and commit**

```bash
git diff --check
git diff --stat
git add docs/superpowers/specs/2026-09-04-evidence-tooling-design.md \
  docs/superpowers/plans/2026-09-04-evidence-tooling.md \
  scripts/tests/test_embed_go_build_abba.py \
  scripts/perf/embed_go_build_abba.py \
  crates/carrick-conformance/src/engine.rs
git commit -m "tools: distinguish pilot evidence and verify cleanup"
```
