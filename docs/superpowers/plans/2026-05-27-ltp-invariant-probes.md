# LTP Invariant Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Carrick-owned deterministic probes and lib tests the authoritative ABI gate for LTP-surfaced syscall invariants.

**Architecture:** Each owned invariant is encoded as a deterministic `conformance-probes/src/bin/*.rs` static Linux/aarch64 probe or a focused Rust lib/integration test. Probe binaries are built by `scripts/build-probes.sh`, auto-discovered by `crates/carrick-cli/tests/conformance.rs::conformance_probes`, and mapped in `docs/conformance-coverage.md` to the LTP IDs or LTP behavior class they replace.

**Tech Stack:** Rust, `libc`, static `aarch64-unknown-linux-musl` probe binaries, Docker linux/arm64, `cargo test --release`.

---

### Task 1: Audit Current Signal Backfill

**Files:**
- Inspect: `conformance-probes/src/bin/sigchld.rs`
- Inspect: `conformance-probes/src/bin/maskfork.rs`
- Inspect: `conformance-probes/src/bin/pendingunblock.rs`
- Inspect: `crates/carrick-cli/tests/conformance.rs`
- Inspect: `docs/conformance-coverage.md`

- [ ] **Step 1: Confirm the three requested signal probes exist**

Run:

```bash
find conformance-probes/src/bin -maxdepth 1 -type f \( -name sigchld.rs -o -name maskfork.rs -o -name pendingunblock.rs \) -print | sort
```

Expected:

```text
conformance-probes/src/bin/maskfork.rs
conformance-probes/src/bin/pendingunblock.rs
conformance-probes/src/bin/sigchld.rs
```

- [ ] **Step 2: Confirm the probe gate auto-discovers compiled binaries**

Run:

```bash
rg -n "fn probe_binaries|fn conformance_probes|KNOWN_PROBE_GAPS" crates/carrick-cli/tests/conformance.rs
```

Expected: matches for `probe_binaries`, `conformance_probes`, and `KNOWN_PROBE_GAPS`; no per-probe manual allowlist is required.

- [ ] **Step 3: Confirm coverage-map ownership rows**

Run:

```bash
rg -n "SIGCHLD delivered|fork: child inherits blocked mask|Pending on unblock" docs/conformance-coverage.md
```

Expected: one row each mapping `sigchld`, `maskfork`, and `pendingunblock` to their invariants and LTP stand-ins.

### Task 2: Verify Signal Probe Batch

**Files:**
- Build output: `conformance-probes/target/aarch64-unknown-linux-musl/release/{sigchld,maskfork,pendingunblock}`
- Runtime binary: `target/release/carrick`

- [ ] **Step 1: Build Carrick release binary**

Run:

```bash
cargo build --release --bin carrick
```

Expected: exit 0 and `target/release/carrick` exists.

- [ ] **Step 2: Build static probe binaries**

Run:

```bash
scripts/build-probes.sh
```

Expected: exit 0 and the output list includes `sigchld`, `maskfork`, and `pendingunblock`.

- [ ] **Step 3: Verify the three signal probes match Linux through the gate path**

Run:

```bash
scripts/run-probe.sh sigchld
scripts/run-probe.sh maskfork
scripts/run-probe.sh pendingunblock
```

Expected:

```text
MATCH sigchld
MATCH maskfork
MATCH pendingunblock
```

- [ ] **Step 4: Run the cargo-owned probe gate**

Run:

```bash
cargo test --release -p carrick-cli --test conformance conformance_probes -- --nocapture
```

Expected: exit 0; the output includes `PASS sigchld`, `PASS maskfork`, and `PASS pendingunblock`.

### Task 3: Extend The Next Coverage Slice

**Files:**
- Modify or create: `conformance-probes/src/bin/<area>.rs`
- Modify: `docs/conformance-coverage.md`

- [ ] **Step 1: Pick the next LTP-only signal invariant from the coverage map**

Use the `Signals — backlog` section in `docs/conformance-coverage.md`. The highest-value next probe is the blocking signal-wait family: `sigwait01`, `sigwaitinfo01`, `sigtimedwait01`, and `rt_sigtimedwait01`.

- [ ] **Step 2: Write the failing deterministic probe first**

Create a probe that blocks a signal, sends it while blocked, waits for it through the specific syscall family under test, and prints booleans only. Verify RED through the faithful gate path:

```bash
scripts/build-probes.sh
scripts/run-probe.sh <new-probe-name>
```

Expected before the runtime fix: `DIFF <new-probe-name>` or timeout that demonstrates Carrick diverges from Linux for the intended invariant.

- [ ] **Step 3: Implement the minimal runtime fix**

Change only the runtime path necessary for the failing invariant. If the guest hangs or reports the wrong value in a way that is not immediately explained by the probe output, use `carrick trace --trace-out` with a focused D script and `progenyof($target)` before changing runtime code.

- [ ] **Step 4: Verify GREEN and update the map**

Run:

```bash
scripts/build-probes.sh
scripts/run-probe.sh <new-probe-name>
cargo test --release -p carrick-cli --test conformance conformance_probes -- --nocapture
```

Expected: `MATCH <new-probe-name>` from `scripts/run-probe.sh`, `PASS <new-probe-name>` from the cargo gate, and a new `docs/conformance-coverage.md` row mapping the probe to the exact invariant and LTP IDs.
