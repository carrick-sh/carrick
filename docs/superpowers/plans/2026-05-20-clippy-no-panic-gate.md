# No-Panic Clippy Gate — Implementation Plan (Goal #4, enforcement half)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Checkbox steps.
> **PRECONDITION:** Plan A merged (it deletes the `panic!` at dispatch.rs:1319, the only intentional panic; without that, the gate would need to allow it).

**Goal:** Make it impossible to silently reintroduce a supervisor-crashing `panic!`/`unwrap`/`expect`/`todo!`/`unimplemented!`. Add a crate-wide clippy deny gate; grandfather the small set of audited, defensible existing sites with documented `#[allow]`.

**Inventoried facts (read-only survey, 2026-05-20):** Only **17 production-code** occurrences exist (all of `tests/`-resident ones are already exempt as test code). After Plan A removes dispatch.rs:1319, **16** remain, all category-(a) "genuine invariant" or fatal-startup:
- `src/dispatch.rs`: 4007 (`unwrap`×2, `sigmask_bit` of SIGKILL/SIGSTOP — infallible constants), 6538 (`unwrap`, 8-byte slice from a guaranteed-len read), 12119–12122 (`unwrap`×4, fixed-offset slices of a 56-byte msghdr read).
- `src/dtrace_consumer.rs`: 209–210 (`unwrap`×2, `CString::new` of string literals).
- `src/main.rs`: 251–252 (`unwrap`×2, `CString::new` of literals), 910 (`expect`, tokio runtime build — fatal startup).
- `src/memory.rs`: 724, 730 (`expect`×2, min/max on a caller-guaranteed-non-empty iterator).
- `src/vfs/dev.rs`: 86 (`expect`, `strip_prefix("/dev/")` on `/dev/*`-by-construction entries).
- `src/vfs/rootfs.rs`: 220, 285 (`expect`×2, "rootfs metadata implies Some(rootfs)" type invariant).

No `[lints]` section in `Cargo.toml` today; no `clippy.toml`. Edition 2024 supports `[lints.clippy]`.

**Safety net:** `cargo clippy --all-targets -- -D warnings` must pass; `cargo test` stays green.

---

### Task 1: Add the deny gate and grandfather audited sites

**Files:** `Cargo.toml` (add `[lints.clippy]`), and the 6 source files above (add `#[allow]`).

- [ ] **Step 1:** Append to `Cargo.toml`:
```toml
[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
```
- [ ] **Step 2:** Run `cargo clippy --all-targets 2>&1 | grep -cE 'error:.*(unwrap|expect|panic)'` to see the full hit list (will include the 16 production sites; test code under `#[cfg(test)]` is auto-exempt by clippy's `allow-expect-in-tests`/`allow-unwrap-in-tests` — if not, add `[lints]` are not test-aware, so set `clippy.toml` with `allow-unwrap-in-tests = true` and `allow-expect-in-tests = true`).
- [ ] **Step 3:** Create `clippy.toml`:
```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests = true
```
- [ ] **Step 4:** For each of the 16 production sites, add an inline `#[allow(clippy::unwrap_used)]` (or `expect_used`) on the smallest enclosing statement/block, each with a `// INVARIANT:` comment stating why it cannot fail. Exact sites: dispatch.rs:4007, 6538, 12119–12122; dtrace_consumer.rs:209–210; main.rs:251–252, 910; memory.rs:724, 730; vfs/dev.rs:86; vfs/rootfs.rs:220, 285. Example for dispatch.rs:4007:
```rust
// INVARIANT: SIGKILL/SIGSTOP are valid signal numbers (< 64), so sigmask_bit is Some.
#[allow(clippy::unwrap_used)]
let kill = sigmask_bit(LINUX_SIGKILL).unwrap();
```
- [ ] **Step 5:** `cargo clippy --all-targets -- -D warnings 2>&1 | tail -5` → clean. `cargo test 2>&1 | tail -5` → green.
- [ ] **Step 6:** Commit: `git commit -am "Add no-panic clippy gate; grandfather audited infallible sites"`.

---

### Task 2: Wire the gate into CI / verification

- [ ] **Step 1:** If a CI workflow exists (`.github/workflows/*`), add `cargo clippy --all-targets -- -D warnings` as a required step. If none exists, add a note to `README.md` under a "Development" section documenting `cargo clippy --all-targets -- -D warnings` as a pre-commit gate. (Grep `.github/` first.)
- [ ] **Step 2:** Commit: `git commit -am "CI: enforce no-panic clippy gate on every build"`.

---

## Self-Review
- Spec coverage: goal #4 enforcement half fully — gate added, new panics/unwraps blocked crate-wide, existing sites audited+justified rather than blanket-allowed. Behavioral half (panic→ENOSYS) was Plan A.
- The gate is the structural guarantee the goal asks for: "so this can't regress back in."
