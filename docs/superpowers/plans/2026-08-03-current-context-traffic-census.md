# Current Context-Traffic Census Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Rust-owned, fail-closed census that joins the existing sampled
JIT PC trace to authenticated retirement snapshots and reports current-default
`DsrContext` traffic by exact slot, physical register, direction, and projected
share of total cold-build CPU.

**Architecture:** Keep DTrace as the sampling authority and the existing
retirement snapshot as the instruction-byte authority. Strengthen the snapshot
wire with a schema, byte length, and SHA-256, then add a portable `carrick
debug jit-shape-census` parser. The parser validates natural trace completion,
resolves each sampled PC against its process snapshot or one unique fork
ancestor, decodes exact AArch64 context accesses, and prints versioned JSON;
source audit, not an invented aggregate, determines which rows share one
production mechanism.

**Tech Stack:** Rust, `serde`/`serde_json`, `sha2`, existing Carrick DTrace and
native-Darwin code-snapshot export.

## Global Constraints

- The default runtime and emitted instruction stream must remain byte-identical;
  only the already opt-in snapshot export may do additional work.
- The existing `scripts/dtrace/native-shape-census.d` remains the durable
  sampled-PC instrument. Do not add a second D program or use `copyin`.
- A zero/missing/ambiguous sample join is an error, never an empty bucket.
- Fork ancestry fallback is legal only when the sampled child has its own
  authenticated snapshot and exactly one recorded ancestor snapshot resolves
  the PC.
- The total-CPU projection is an explicit input, `0 < share <= 1`, retained in
  the report. It is not measured by the shape trace.
- Do not combine context rows merely because they use x28 addressing. Host-bias
  loads, cache-pointer loads, architectural spill slots, and borrow-recovery
  channels are distinct mechanisms until the source audit proves otherwise.
- Compiler liveness does not make an architectural GPR unobservable: async
  signal recovery must retain an authoritative guest value at every emitted
  recovery point.
- Use red-first tests, keep commits narrow, run `RUST_TEST_THREADS=1 just ci`
  before accepting the diagnostic, and do not implement a production
  optimization unless one source-backed class clears 10% of total build CPU.

---

### Task 1: Authenticate the opt-in code-snapshot wire

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`

**Interfaces:**
- Consumes: `ProcessTranslator::code_snapshot() -> CodeSnapshot`.
- Produces: JSON schema `carrick.code-snapshot.v4` with `pid`, `cache_base`,
  `code_len`, `code_sha256`, and `blocks`; the adjacent `.bin` is the exact
  hashed payload.

- [x] **Step 1: Write the failing snapshot contract test**

Add a helper-level test which serializes a two-word snapshot and asserts the
metadata names schema `carrick.code-snapshot.v4`, length `8`, and the SHA-256 of
the exact little-endian bytes. Keep this below the snapshot helper rather than
forking a guest in a unit test.

- [x] **Step 2: Run the focused test and verify red**

Run:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_darwin::tests::code_snapshot_metadata_authenticates_exact_bytes -- --exact
```

Expected: FAIL because the existing JSON has no schema or digest.

- [x] **Step 3: Extract and use an authenticated metadata builder**

Add this private serialized shape in `native_darwin.rs`:

```rust
#[derive(serde::Serialize)]
struct CodeSnapshotMetadata<'a> {
    schema: &'static str,
    pid: u32,
    cache_base: u64,
    code_len: usize,
    code_sha256: String,
    blocks: &'a [(u64, u64)],
}
```

Build it from `CodeSnapshot`, with
`format!("{:x}", sha2::Sha256::digest(&snapshot.code))`, and preserve the
existing `.bin`-then-`.json` publication order. The export remains best-effort
and opt-in exactly as today.

- [x] **Step 4: Run focused runtime tests and commit**

Run:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime code_snapshot -- --nocapture
cargo clippy -p carrick-runtime --all-targets -- -D warnings
```

Commit:

```bash
git add crates/carrick-runtime/src/native_darwin.rs
git commit -m "fix(debug): authenticate JIT code snapshots"
```

---

### Task 2: Parse and validate the trace/snapshot join in Rust

**Files:**
- Create: `crates/carrick-cli/src/debug_jit_shape.rs`
- Modify: `crates/carrick-cli/src/main.rs`

**Interfaces:**
- Produces:
  `run_jit_shape_census(trace: &Path, snapshots: &Path,
  jit_share_of_total: f64) -> anyhow::Result<()>`.
- Internal typed inputs:

```rust
struct PcSample { pid: u32, pc: u64, count: u64 }
struct ForkLink { parent: u32, child: u32 }
struct Snapshot { pid: u32, base: u64, code: Vec<u8>, blocks: Vec<(u64, u64)> }
```

- [x] **Step 1: Write red parser-validity tests**

Construct in-memory `SHAPE1` fixtures and assert rejection of: no completion,
`bounded=1`, `target_completed=0`, nonzero `copyin-errors`, duplicate completion,
duplicate parent for one child, truncated PC rows, and the printed total not
equal to `jit + non-jit`. Add one green fixture with a fork row and two PC rows.

- [x] **Step 2: Run the module test target and verify red**

Run:

```bash
cargo test -p carrick-cli debug_jit_shape -- --nocapture
```

Expected: compile FAIL because `debug_jit_shape` is not implemented.

- [x] **Step 3: Implement the strict `SHAPE1` parser**

Accept only these records from the existing D program:

```text
SHAPE1|fork|parent=<u32>|child=<u32>
SHAPE1|samples=<u64>
SHAPE1|copyin-errors=<u64>
SHAPE1|region=jit|count=<u64>
SHAPE1|region=non-jit|count=<u64>
PC <u32> 0x<u64-hex> <u64>
SHAPE1|complete|bounded=0|target_completed=1|target_exit_reason=1
```

Ignore other non-protocol DTrace text, but require exactly one copyin, total,
each region, and complete record. Use checked addition for every aggregation.

- [x] **Step 4: Write red snapshot authentication and ancestry tests**

Use `tempfile::TempDir` to build v4 JSON/`.bin` pairs. Assert rejection of a
missing `.bin`, wrong schema, length mismatch, hash mismatch, duplicate
same-PID resolving ranges, sample with no process snapshot, sample outside all
own/ancestor ranges, and a child PC resolving in two ancestors. Assert success
when the child's own snapshot exists and exactly one recorded ancestor resolves
the inherited PC.

- [x] **Step 5: Implement snapshot loading and unique resolution**

Verify every JSON and byte payload before indexing it. Resolve against exactly
one own range first. Only if none matches, walk the acyclic fork parent chain;
require the child to have an authenticated snapshot and accept exactly one
ancestor candidate across the entire chain. Report own and inherited sample
counts separately.

- [x] **Step 6: Run focused tests and commit**

Run:

```bash
cargo test -p carrick-cli debug_jit_shape -- --nocapture
cargo clippy -p carrick-cli --all-targets -- -D warnings
```

Commit:

```bash
git add crates/carrick-cli/src/main.rs crates/carrick-cli/src/debug_jit_shape.rs
git commit -m "feat(debug): validate sampled JIT snapshots"
```

---

### Task 3: Decode exact context traffic and publish the census CLI

**Files:**
- Modify: `crates/carrick-cli/src/debug_jit_shape.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/debug.rs`
- Modify: `crates/carrick-cli/src/commands.rs`

**Interfaces:**
- Adds:

```text
carrick debug jit-shape-census TRACE --snapshots DIR --jit-share-of-total 0.46505
```

- Produces JSON schema `carrick.jit-shape-census.v1` with input/snapshot
  hashes, coverage, instruction families, exact context rows, and shares of
  matched-JIT and projected total CPU.

- [x] **Step 1: Write red AArch64 decode tests**

Pin these exact words and expected rows:

```rust
(0xf942_3791, "load", 1128, 17),
(0xf902_3791, "store", 1128, 17),
(0xf942_5793, "load", 1192, 19),
(0xf942_7f8f, "load", 1272, 15),
(0xf942_478f, "load", 1160, 15),
```

Also assert a guest load not based on x28 and an x28-based 32-bit access do not
enter the 64-bit context table. Decode `slot = imm12 * 8`, `register = Rt`, and
direction from the opcode; never infer a semantic name from the physical
register alone.

- [x] **Step 2: Implement family and semantic-row aggregation**

Classify at least the existing durable families (`ctx-load64`, `ctx-store64`,
`ctx-load32`, `ctx-store32`, `ctx-pair`, `guard-ldar`, `nzcv-mrs`, `nzcv-msr`,
`x17-materialize`, `x18-materialize`, `br-x17`, and `guest-other`). For every
64-bit x28 access emit the exact key `load|store:slot=<n>:x<rt>` plus a source
layout label from this closed table:

```text
936=nzcv-recovery
1072=entry
1080=exit-target
1120=rewrite-scratch
1128=rewrite-context-scratch-and-guest-x17
1144=generation
1160=indirect-x15-scratch
1168=indirect-x30-scratch
1192=host-bias
1200=guest-fault-address
1272=indirect-cache-pointer
144=guest-virtual-x18
152=guest-virtual-x19
224=guest-virtual-x28
other=unclassified
```

The report must print every row, not only a top-N list. Each row carries
`samples`, `share_of_matched_jit`, and
`projected_share_of_total_cpu = share_of_matched_jit * jit_share_of_total`.

- [x] **Step 3: Wire the portable debug subcommand**

Add `DebugCommand::JitShapeCensus { trace, snapshots,
jit_share_of_total }`, dispatch it on macOS and non-macOS builds like the two
existing text-only census commands, and declare the module unconditionally in
`main.rs`. Reject NaN, infinity, zero, and values above one.

- [x] **Step 4: Add a full-report fixture test**

Use two snapshots and one inherited sample. Assert exact input digest,
snapshot-manifest digest, own/inherited counts, zero missing counts, exact slot
rows, matched-JIT denominator, and the projected share multiplication. Mutate
one byte of one `.bin` and prove the command fails before printing JSON.

- [x] **Step 5: Run focused and CLI gates, then commit**

Run:

```bash
cargo test -p carrick-cli debug_jit_shape -- --nocapture
cargo test -p carrick-cli
cargo clippy -p carrick-cli --all-targets -- -D warnings
```

Commit:

```bash
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/debug.rs \
  crates/carrick-cli/src/commands.rs crates/carrick-cli/src/debug_jit_shape.rs
git commit -m "feat(debug): census exact JIT context traffic"
```

---

### Task 4: Qualify and capture the current-default mechanism twice

**Files:**
- Modify: `docs/perf-results/native-dsr-shape-census.jsonl`
- Modify: `handoff.md`
- Create: `docs/perf-results/2026-08-03-current-context-traffic.md`

**Interfaces:**
- Consumes: signed release binary, existing
  `scripts/dtrace/native-shape-census.d`, `CARRICK_DSR_CODE_SNAPSHOT_DIR`, two
  independent isolated warmed stores, and `jit_share_of_total=0.46505` from
  the accepted current-default module/route captures.
- Produces: two complete `carrick.jit-shape-census.v1` reports and a source map
  from each material row to its emitter/recovery contract.

- [x] **Step 1: Run full source validation and build/sign**

Run:

```bash
RUST_TEST_THREADS=1 just ci
just build
codesign --verify --verbose=2 target/release/carrick
otool -l target/release/carrick | rg '__dof_carrick'
```

Record clean source SHA, executable SHA-256, UUID, signature, DOF, D-program
SHA-256, image digest/architecture, store identity, power/thermal metadata, and
zero scoped survivors.

- [x] **Step 2: Run two naturally completed shape captures**

For A and B independently: create a new empty store, warm it once untraced,
then trace the canonical cold-`GOCACHE` build with the same store and a new
empty snapshot directory. Let `carrick trace` and the D consumer exit
naturally. Require exactly one `BUILD_OK`, one positive `WORKLOAD_NS`, status
zero, `copyin-errors=0`, `bounded=0`, `target_completed=1`, and zero scoped
survivors. Never cite the traced wall time.

- [x] **Step 3: Run the Rust census and source-audit every material row**

Run for each capture:

```bash
target/release/carrick debug jit-shape-census TRACE \
  --snapshots SNAPSHOTS --jit-share-of-total 0.46505
```

Bind each report and raw stream by SHA-256. Audit rows against `emit.rs`,
`gateway.rs`, and recovery actions. Keep these distinctions explicit:
`1192/x19` is host-bias loading, `1272/x15` is the indirect-cache pointer,
`1128/x17` mixes exit/entry and internal-edge guest-x17 authority, and
`1160/x15` is indirect-exit recovery.

- [x] **Step 4: Apply the opportunity gate**

Require the same source-backed, non-overlapping mechanism to project at least
10% of total CPU in both captures. A proposed physical-register residency
class must also explain how async signal/kick recovery reconstructs every guest
GPR at every word. If it does not clear the gate, record STOP and do not write a
production candidate. If it clears, write a separate production design before
editing emission.

- [x] **Step 5: Commit evidence and handoff**

Run `git diff --check`, update the official scoreboard only if an untraced
Carrick/Docker gate actually ran (it should not for an attribution-only stop),
and commit:

```bash
git add docs/perf-results/native-dsr-shape-census.jsonl \
  docs/perf-results/2026-08-03-current-context-traffic.md handoff.md
git commit -m "docs(perf): decide current context traffic"
```
