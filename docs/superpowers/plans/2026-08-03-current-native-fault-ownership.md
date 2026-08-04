# Current Native Fault Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Rust-owned, fail-closed native-fault profile that attributes
current-default Darwin zero-fill faults to Carrick-owned guest mappings versus
ordinary host allocations, then use two accepted cold-build captures to select
or stop the next production hypothesis at the 10% opportunity gate.

**Architecture:** Extend the existing native process-handoff seam with a typed
catalog of the exact stable host ranges already owned by NativeMappedMemory.
Replace the directional NFAULT1 stream with a birth-keyed NFAULT2 profile that
samples exact qualified 16 KiB fault pages and carries the active owned-range
catalog through fork and exec. A focused Rust module validates the raw stream,
joins every sampled page to one catalog, classifies it as guest-owned or
host-other, and emits an authenticated versioned report.

**Tech Stack:** Rust, serde/serde_json, sha2, Carrick USDT, DTrace vminfo,
existing native launch qualification, existing libdtrace trace runner.

## Global Constraints

- The shipped execution path must remain semantically and instruction-stream
  identical. Disabled USDT probes may add only their normal branch at the
  once-per-image publication seam.
- DTrace provider facts remain host/build-specific. Reuse the existing
  birth/terminal launch qualification and retain arg2 as the exact qualified
  16 KiB host-page base.
- The D program is bundled as TraceProfileKind::NativeFault; Rust owns parsing,
  validation, classification, provenance, and report generation.
- Track process incarnations by pid plus PROC_PIDTBSDINFO birth tuple. Fork
  children inherit the exact parent catalog; exec disarms the old catalog until
  the replacement publishes a complete one.
- Sampled page identity remains deterministic 1/64 because a lossless
  1.5-million-page aggregation perturbs libdtrace itself. Exact global outcome
  totals remain lossless.
- A missing birth, catalog, completion, BUILD_OK marker, workload marker, drop
  counter, or sampled-page join is an error. Zero events is an error.
- Classify one complete host page as guest-owned only when exactly one valid
  catalog owns it. Pages outside every declared range are host-other. Overlap,
  partial ownership, ambiguity, and overflow fail closed.
- Traced elapsed time is perturbation metadata only. It is never an end-to-end
  performance result.
- Use red-first tests and narrow commits. Do not implement a production memory
  change unless the same source-backed mechanism projects to at least 10% of
  total cold-build CPU in both accepted captures.

---

### Task 1: Publish the exact guest-owned host-range catalog

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`

**Interfaces:**
- Produces typed events
  `host_native_owned_range_reset(epoch)`,
  `host_native_owned_range_add(epoch, sequence, start, end)`, and
  `host_native_owned_range_ready(epoch, final_sequence)`.
- Consumes `NativeMappedMemory::owned_host_ranges`, which is immutable within
  one image and wholesale-replaced only by exec.

- [ ] **Step 1: Write red typed-catalog and handoff-order tests**

Add literal tests that reject zero epochs/sequences, empty/reversed/unaligned
ranges, duplicate sequence, and ready frontiers that do not equal the
published range count. Extend RecordingNativeImagePublisher so the successful
handoff expects this exact order:

    activate, host-base, host-catalog, guest, host-owned, host-jit, install, completion

The production mutation these tests catch is publishing a partial or stale
mapping catalog before the replacement image is fully active.

- [ ] **Step 2: Run the focused tests and prove red**

Run:

    RUST_TEST_THREADS=1 cargo test -p carrick-observability native_owned -- --nocapture
    RUST_TEST_THREADS=1 cargo test -p carrick-runtime process_handoff -- --nocapture

Expected: compile failure because the typed owned-range events and publisher
method do not exist.

- [ ] **Step 3: Implement the minimal typed event wire**

Add newtype-validated epoch and sequence values plus one validated range event.
Add matching real and stub probe signatures. The reset and ready events carry
one scalar each; add carries epoch, sequence, start, and end. Keep all raw
ordinals private to the wrappers.

- [ ] **Step 4: Publish one complete catalog per initial or replacement image**

Give NativeImagePublisher an
`owned(&[Range<HostVa>])` method and pass the current NativeMemoryHandle into
both initial and in-process exec handoffs. A process-local AtomicU64 assigns
monotonic nonzero epochs; fork inherits the current epoch and catalog through
copy-on-write. Fire reset, every exact range in sorted non-overlapping order,
then ready. Refuse publication on epoch overflow.

- [ ] **Step 5: Run focused gates and commit**

Run:

    RUST_TEST_THREADS=1 cargo test -p carrick-observability native_owned -- --nocapture
    RUST_TEST_THREADS=1 cargo test -p carrick-runtime process_handoff -- --nocapture
    cargo clippy -p carrick-observability -p carrick-runtime --all-targets -- -D warnings

Commit:

    git add crates/carrick-observability/src/probes.rs crates/carrick-runtime/src/native_darwin.rs crates/carrick-dsr-aarch64/src/mapped_memory.rs
    git commit -m "diagnostics(native): publish guest-owned host ranges"

---

### Task 2: Replace NFAULT1 with a qualified birth-keyed NFAULT2 stream

**Files:**
- Modify: `scripts/dtrace/native-fault-attribution.d`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/src/native_profile_qualification.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/trace_cli.rs`

**Interfaces:**
- Adds `TraceProfileKind::NativeFault` and CLI spelling `native-fault`.
- Produces NFAULT2 header, process birth/fork/exec/catalog records, sampled page
  rows, exact outcome totals, rejected-provider counts, and one natural
  completion record.

- [ ] **Step 1: Write red profile-selection and render tests**

Assert that `native-fault` parses, survives sudo argv reconstruction, selects
the bundled script, requires native launch qualification, does not request
kernel symbolization, and renders exactly one header plus the qualified
terminal map. The production mutation caught is silently running an
unauthenticated or user-supplied D program while labeling it native-fault.

- [ ] **Step 2: Run the CLI tests and prove red**

Run:

    cargo test -p carrick-cli native_fault_profile_selection -- --nocapture

Expected: compile failure because NativeFault and its bundled program do not
exist.

- [ ] **Step 3: Implement profile plumbing and authenticated rendering**

Bundle the existing script under BUNDLED_NATIVE_FAULT_D. Hash the immutable
template, not the receipt-substituted program, and render:

    NFAULT2|header|profile=native-fault|raw_schema=carrick.native-fault.raw.v2|os_build=...|program_sha256=...|birth_qualification_sha256=...|terminal_qualification_sha256=...|page_sample_modulus=64

Reuse the accepted birth and terminal qualification receipts. Do not request
the native-wall KDK symbol callback.

- [ ] **Step 4: Rewrite the existing D program as NFAULT2**

Track active process birth keys, fork inheritance, exec attempts/successes, and
the current complete owned-range catalog. Key sampled as_fault and zfod pages
by birth/image/catalog/outcome/page. Count COW without an address. Keep exact
all-tracked totals and explicit invalid-address, pre-birth, no-catalog,
lifecycle, catalog, and D action error counters. Print completion only when
the target exits naturally and every tracked process is retired.

- [ ] **Step 5: Run profile tests and D compilation, then commit**

Run:

    cargo test -p carrick-cli native_fault_profile_selection -- --nocapture
    cargo clippy -p carrick-cli -p carrick-runtime --all-targets -- -D warnings
    target/release/carrick trace --profile native-fault --trace-out target/perf/native-fault-smoke.raw -- run --exec-backend native localhost:5005/carrick-go-conformance:1.24 /bin/true

Require a natural NFAULT2 completion with nonzero fault totals and zero
violation counters.

Commit:

    git add scripts/dtrace/native-fault-attribution.d crates/carrick-runtime/src/dtrace_consumer.rs crates/carrick-cli/src/trace_profile.rs crates/carrick-cli/src/native_profile_qualification.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/trace_cli.rs
    git commit -m "diagnostics(trace): capture qualified native faults"

---

### Task 3: Validate and classify fault ownership in Rust

**Files:**
- Create: `crates/carrick-cli/src/native_fault_profile.rs`
- Modify: `crates/carrick-cli/src/main.rs`
- Modify: `crates/carrick-cli/src/commands.rs`

**Interfaces:**
- Produces `NativeFaultSummary::from_path(path, capture_status, authority)`.
- Emits schema `carrick.native-fault-attribution.v2` with authenticated inputs,
  capture completion, exact totals, sample coverage, ownership buckets,
  per-process counts, hot pages, and perturbation metadata.

- [ ] **Step 1: Write red parser and ownership tests**

Use hand-written NFAULT2 fixtures. Assert success for one parent catalog, one
fork-inherited child page, one guest-owned page, and one host-other page.
Assert rejection independently for duplicate headers/completion, missing
birth, invalid page alignment, zero totals, sample count above exact total,
fork cycles, duplicate parents, incomplete/overlapping catalogs, missing
catalog joins, catalog identity drift, nonzero violation/drop counters, and a
page only partially covered by a declared range.

The expected ownership counts are literal fixture values; no production helper
computes the expected side.

- [ ] **Step 2: Run the module test and prove red**

Run:

    cargo test -p carrick-cli native_fault_profile -- --nocapture

Expected: compile failure because NativeFaultSummary is absent.

- [ ] **Step 3: Implement strict parsing and catalog inheritance**

Parse only exact NFAULT2 record field sets. Use checked arithmetic throughout.
Build immutable catalogs keyed by process birth, image generation, and epoch.
Resolve a child catalog through exactly one acyclic parent chain. Intersect
`[page, page + 16384)` against sorted declared ranges and require either full
ownership by one range or no intersection.

- [ ] **Step 4: Implement the versioned report and trace-command handoff**

Report exact global totals separately from deterministic sampled ownership.
For each ownership bucket include sampled events, distinct process-pages,
repeat excess/factor, share of sampled addressed zfod, and the scaled event
estimate. Retain the template hash, qualification hashes, raw SHA-256, binary
provenance, command, capture report, and `gating_eligible=false` because the
instrument is perturbing. Write the report atomically through
`--summary-jsonl`.

- [ ] **Step 5: Run focused and CLI gates, then commit**

Run:

    cargo test -p carrick-cli native_fault_profile -- --nocapture
    RUST_TEST_THREADS=1 cargo test -p carrick-cli --bin carrick
    cargo clippy -p carrick-cli --all-targets -- -D warnings

Commit:

    git add crates/carrick-cli/src/native_fault_profile.rs crates/carrick-cli/src/main.rs crates/carrick-cli/src/commands.rs
    git commit -m "diagnostics(debug): classify native fault ownership"

---

### Task 4: Capture twice, bind the mechanism, and apply the gate

**Files:**
- Create: `docs/perf-results/2026-08-03-current-native-fault-ownership.md`
- Modify: `docs/perf-results/native-dsr-shape-census.jsonl`
- Modify: `handoff.md`

**Interfaces:**
- Consumes two naturally completed native-fault reports from the same current
  signed source and unchanged isolated warmed persistent stores.
- Produces one source-backed GO or STOP decision.

- [ ] **Step 1: Run full validation and build/sign**

Run `RUST_TEST_THREADS=1 just ci`, then `just build`. Record source SHA,
executable SHA-256, Mach-O UUID, signature, DOF presence, D-template SHA-256,
qualification receipt hashes, image digest/architecture, exact store content
manifest, host topology, power/thermal metadata, and zero scoped survivors.

- [ ] **Step 2: Run two naturally completed cold-build captures**

For A and B independently, reuse one previously warmed isolated store only
after recording its content manifest. Use a unique CARRICK_RUN_ID and a fresh
raw/summary/workload directory. Require exactly one BUILD_OK, one positive
WORKLOAD_NS, target status zero, natural NFAULT2 completion, all loss/error
counters zero, every sampled page joined, unchanged store manifest, and zero
survivors. Never cite traced wall time.

- [ ] **Step 3: Bind ownership to one source mechanism**

If guest-owned zfod dominates, split the owned range with source-authoritative
heap/mmap/image layout and compare the guest operation with Go's Darwin
allocator lowering. If host-other dominates, use the existing complete
allocation census or a new Rust allocator counter to name the retaining call
site; do not infer one from address shape. Keep exact event counts, sample
shares, and projected total-CPU opportunity separate.

- [ ] **Step 4: Apply the 10% gate**

Require the same correctness-preserving, non-overlapping source mechanism to
project at least 10% of total cold-build CPU in both captures. If it does not,
record STOP and select the next bucket. If it does, write a separate
single-variable production design and controlled ABBA plan before editing
runtime behavior.

- [ ] **Step 5: Commit evidence and update the controller**

Run `git diff --check`. Do not change the official 10.4446x ratio unless a
fresh serialized untraced Carrick-then-Docker comparison actually ran. Commit
the evidence, ledger row, completed plan, and handoff as one narrow
attribution-only change.
