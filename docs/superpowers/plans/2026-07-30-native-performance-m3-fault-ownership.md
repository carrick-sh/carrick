# Native Performance M3: Fault Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Qualify the live Darwin fault-provider ABI on the current boot, join
address-bearing `as_fault`/`zfod` events to versioned Carrick host-backing
catalogs, and accept two stable cold-Go-build ownership profiles.

**Architecture:** A hidden host fixture and standalone qualification D program
prove which private `vminfo` arguments are address-bearing before any campaign
can start. The native memory/translator authorities publish versioned
host-backing snapshots through the M2 process-image identity. A built-in
`native-faults` profile preserves exact 16 KiB page bases for qualified
outcomes and count-only data for everything else. Rust validates lifecycle and
population reconciliation; Python classifies each page as uniform, mixed,
partial, or host-other and measures repetition.

**Tech Stack:** Rust/clap/serde/usdt, libdtrace D language, Python 3 standard
library, Darwin `vminfo`/`proc` providers, Carrick's signed native AArch64
runner.

**Design authority:** `docs/superpowers/specs/2026-07-30-native-performance-evidence-control-plane-design.md`
sections 2, 7, 8, 9, and 10.

## Global Constraints

- M1 and M2 are landed. M3 reuses M2's `ProcessBirthKey`, image generation,
  runtime epoch, `ForkInherit`, and strict `DSRPROF2` parser.
- Probe presence or declared argument types are not qualification. The live
  fixture must prove the current host/boot contract.
- `fbt::vm_fault:entry` is disqualified on the current host because live
  censuses observed it inert. It is never a fallback address source.
- Only `vminfo:::as_fault` and `vminfo:::zfod` `arg2` may carry an address, and
  only after a matching accepted provider receipt.
- The address is an exact qualified 16 KiB host-page base. Never infer the
  original 4 KiB access offset.
- `vminfo:::cow_fault` and every other unqualified outcome are count-only.
- The mapping catalog describes Carrick host-backing ownership. It is not a
  live Linux VMA/permission model and is never used to classify sampled guest
  PCs.
- Guest `mmap`, `munmap`, and `mprotect` operations inside pre-owned
  reservoirs do not create catalog versions.
- Address attribution is disarmed before catalog ready and across exec
  transitions. Startup/transition events remain explicit count-only
  populations.
- An event is assigned to the exact mapping catalog version live when it
  fired. Later catalogs never relabel earlier events.
- Exact event counts and sampled kernel CPU remain separate tables.
- High cardinality is fail-closed: any aggregation, dynamic-variable, or
  principal-buffer drop invalidates the run.
- Traced time is never an official performance result.
- No Linux kernel or other GPL implementation source is consulted.

---

## Task 1: Live-qualify the private Darwin fault arguments

**Files:**

- Create: `crates/carrick-cli/src/native_fault_fixture.rs`
- Modify: `crates/carrick-cli/src/main.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/trace_cli.rs`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-cli/tests/cli.rs`
- Create: `scripts/dtrace/native-fault-qualify.d`
- Create: `scripts/perf/native_fault_qualify.py`
- Create: `scripts/perf/test_native_fault_qualify.py`
- Create: `scripts/perf/fixtures/native-fault-qualify/accepted.trace`
- Create: `scripts/perf/fixtures/native-fault-qualify/wrong-arg.trace`
- Create: `scripts/perf/fixtures/native-fault-qualify/dropped.trace`

**Rust domain:**

```rust
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFaultFixturePhase {
    OffsetTouches = 1,
    RepeatTouches = 2,
    ConsecutivePages = 3,
    CowWrite = 4,
}

pub(crate) struct NativeFaultFixtureOptions {
    pub hold_ms: u64,
    pub control_loop_ms: u64,
}

pub(crate) fn run_native_fault_abi_fixture(
    options: NativeFaultFixtureOptions,
) -> anyhow::Result<()>;
```

**Low-rate USDT probes:**

```rust
fn native__fault__fixture__mapping(_: u32, _: u64, _: u64, _: u64) {}
fn native__fault__fixture__phase(_: u32, _: u32, _: u64, _: u64, _: u64) {}
fn native__fault__fixture__complete(_: u32, _: i32) {}
```

- [ ] **Step 1: Add red hidden-command and fixture tests**

Assert `__native-fault-abi-fixture` is absent from ordinary help, rejects
unsupported hosts/page sizes, and exposes the four unique phase ordinals.
With an injected memory/probe recorder, require one aligned mapping
announcement, offset/repeat/consecutive/COW phases in order, a successful
completion, and cleanup on failure.

- [ ] **Step 2: Run and prove red**

```bash
cargo test -p carrick-cli --test cli native_fault_abi_fixture -- --nocapture
```

Expected: the hidden subcommand and dispatcher do not exist.

- [ ] **Step 3: Implement the fixture without a runtime map**

On macOS/arm64 with `hw.pagesize == 16384`, allocate an anonymous aligned span
with `libc::mmap`. Announce `[start,end)` and page size. Execute:

1. for offsets `0`, `4096`, `8192`, and `12288`, remap the owned whole 16 KiB
   host page anonymously at the same address, then make exactly one first write
   at that offset; all four qualified events must report the same page base;
2. repeated writes to the now-populated offsets;
3. first writes in four consecutive host pages; and
4. `fork`, one child write to a private page, `_exit`, and parent `waitpid`.

Use `libc`, not an ad-hoc extern block. Emit phase start/end bounds and declared
expected addressed population. The COW phase declares only a count and never
labels an argument as an address. The hidden `--control-loop-ms` option repeats
mapping announcement plus fresh-page touches until its deadline so a
simultaneous unrelated fixture started before DTrace remains observable
through the qualification window.

- [ ] **Step 4: Add red qualification-parser tests**

`native_fault_qualify.py` exposes
`host_identity() -> dict[str, object]` and
`qualify_trace(raw_path: pathlib.Path, carrick_binary: pathlib.Path,
capture_status_path: pathlib.Path,
output: pathlib.Path) -> dict[str, object]`.

Fixtures must reject wrong argument position, masked/unaligned values, wrong
stride, distinct pseudo-addresses for four offsets in one host page, missing
consecutive pages, addressed COW, admitted control-process events, phase
population mismatch, unnatural exit, completion mismatch, and every drop
class.

- [ ] **Step 5: Run and prove red**

```bash
python3 -m unittest scripts/perf/test_native_fault_qualify.py -v
```

- [ ] **Step 6: Implement the raw qualification D program**

Launch-scope from `$target`, admit only `proc:::create` children, and record
raw `arg0` through `arg4` for `as_fault`, `zfod`, and `cow_fault`. Do not
interpret or mask the values in D. Emit fixture mapping/phase/completion,
process lifecycle, live-at-end, and one completion record.
Also observe fixture mapping announcements globally: a simultaneous
`target/release/carrick __native-fault-abi-fixture --control-loop-ms 15000`
launched outside `$target` must remain in the raw control census but outside
every admitted fault aggregate.

- [ ] **Step 7: Publish consumer drop status and the qualification result**

Add `trace --capture-status-json FILE` for both bundled profiles and custom
scripts. After libdtrace stops, `commands.rs` atomically writes the complete
`DTraceRunReport` fields (natural/interrupted termination, principal,
aggregation, dynamic-variable, and other drops, exit reason, script hash, and
trace-output hash). A D program never claims to observe its own consumer drop
counters. Failure to write the sidecar is a failed trace.

`native_fault_qualify.py` requires the raw stream and this sidecar, hashes both,
and rejects any nonzero drop or mismatched raw hash. Only an accepted trace
writes schema `carrick.native-fault-qualification.v1` with the exact host,
provider argument findings, binary/qualification-D/qualification-validator
hashes, raw/status hashes, and `accepted=true`. Its closed `sha256` object is
exactly:

```json
{
  "binary": "64 lowercase hex digits",
  "qualification_d_program": "64 lowercase hex digits",
  "qualification_validator": "64 lowercase hex digits",
  "raw": "64 lowercase hex digits",
  "capture_status": "64 lowercase hex digits"
}
```

It does not yet claim a runnable `native-faults.d` provider receipt.

The later Task 4 `seal-provider` command consumes this accepted qualification
after the bundled profile and analyzer exist and writes:

```json
{
  "schema": "carrick.native-fault-provider.v1",
  "accepted": true,
  "host": {
    "product_version": "current sw_vers value",
    "os_build": "current sw_vers build",
    "kernel_version": "current uname value",
    "kernel_uuid": "current kern.uuid value",
    "architecture": "arm64",
    "boot_identity": "current kern.boottime value",
    "hw_pagesize": 16384
  },
  "provider": {
    "as_fault": {"provider": "vminfo", "probe": "as_fault", "address_arg": 2},
    "zfod": {"provider": "vminfo", "probe": "zfod", "address_arg": 2},
    "cow_fault": {"provider": "vminfo", "probe": "cow_fault", "address_arg": null}
  },
  "sha256": {
    "qualification_receipt": "64 lowercase hex digits",
    "binary": "64 lowercase hex digits",
    "qualification_d_program": "64 lowercase hex digits",
    "qualification_validator": "64 lowercase hex digits",
    "native_faults_d_program": "64 lowercase hex digits",
    "attribution_analyzer": "64 lowercase hex digits"
  }
}
```

Collect host fields from `sw_vers`, `uname -v`, `sysctl -n kern.uuid`,
`sysctl -n kern.boottime`, and `sysctl -n hw.pagesize`; a missing determinant
is fatal. Task 1 hashes the exact signed binary, qualification D program, and
qualification validator. `seal-provider` repeats those hashes against the
accepted qualification, then adds the qualification-receipt,
`native-faults.d`, and attribution-analyzer hashes from its explicit input
paths. The sealed provider is the attestation boundary for the historical
qualification sources: a later trace launch does not pretend it can re-open
unprovided paths.

Before `dtrace_go`, Rust verifies the closed accepted provider schema, current
host/boot/page size, current executable hash, provider/probe/address contract,
and its compiled-in `native-faults.d` hash. Before loading either capture, the
Python analyzer hashes its own `__file__` and requires the provider's
`attribution_analyzer` value; it then checks the provider receipt hash embedded
in each capture receipt. Thus every artifact is checked at the boundary where
its bytes are actually available. Task 1 cannot hash or publish authority for
`native-faults.d` before Task 3 creates and tests that source.

- [ ] **Step 8: Run focused tests and commit**

```bash
cargo test -p carrick-cli --test cli native_fault_abi_fixture -- --nocapture
python3 -m unittest scripts/perf/test_native_fault_qualify.py -v
just fmt
git diff --check
git add crates/carrick-cli/src/native_fault_fixture.rs \
  crates/carrick-cli/src/main.rs \
  crates/carrick-cli/src/args.rs \
  crates/carrick-cli/src/commands.rs \
  crates/carrick-cli/src/trace_cli.rs \
  crates/carrick-runtime/src/dtrace_consumer.rs \
  crates/carrick-observability/src/probes.rs \
  crates/carrick-cli/tests/cli.rs \
  scripts/dtrace/native-fault-qualify.d \
  scripts/perf/native_fault_qualify.py \
  scripts/perf/test_native_fault_qualify.py \
  scripts/perf/fixtures/native-fault-qualify
git commit -m "diagnostics(cli): qualify Darwin native fault arguments" -m \
"Prove the live vminfo argument contract with controlled 16 KiB page touches,
process-tree scoping, and count-only COW before publishing a boot-bound
provider receipt.

Verified with hidden-fixture and qualification corruption tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 2: Publish versioned host-backing ownership

**Files:**

- Create: `crates/carrick-dsr-aarch64/src/native_mapping_catalog.rs`
- Modify: `crates/carrick-dsr/src/probes.rs`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Domain:** Put the observation-facing enum/range/snapshot types in
`carrick-dsr::probes`, the existing USDT-free translator seam. The
`carrick-dsr-aarch64` builder consumes and re-exports those types; it never
calls `carrick-observability` directly.

```rust
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeMappingClass {
    GuestImage = 1,
    GuestHeap = 2,
    GuestMmapArena = 3,
    GuestStack = 4,
    SigreturnTrampoline = 5,
    SharedFileAperture = 6,
    PrivateOverlay = 7,
    PrivateTranslated = 8,
    SharedTranslated = 9,
    OtherOwned = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeMappingCatalogVersion(NonZeroU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAddressModeEvidence {
    Direct,
    Biased { host_bias: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMappingRange {
    pub class: NativeMappingClass,
    pub range: Range<HostVa>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMappingCatalogBase {
    pub address_mode: NativeAddressModeEvidence,
    pub owned_universe: Vec<Range<HostVa>>,
    pub ranges: Vec<NativeMappingRange>,
}
```

**Pure construction:**

```rust
pub fn build_native_mapping_catalog_base(
    image: &AddressSpace,
    layout: MemoryLayout,
    address_mode: NativeAddressMode,
    host_page_size: u64,
    owned_host_ranges: &[Range<HostVa>],
) -> Result<NativeMappingCatalogBase, NativeMappingCatalogError>;
```

- [ ] **Step 1: Add red mapping-domain tests**

Promote the current test-only `native_mapping_class_ranges` cases from
`native_darwin.rs` and add:

- stack region chosen by `initial_stack_pointer`;
- trampoline, heap, mmap arena, shared aperture, and private overlay;
- remaining loader extents as `GuestImage`;
- remaining owned bytes as `OtherOwned`;
- inverted/empty/overlapping ranges;
- impossible guest-to-host conversion;
- direct and biased address-mode preservation, including exact nonzero host
  bias and reversible host-to-guest candidates;
- uncovered or multiply covered owned bytes; and
- proof that no permission/RWX field exists.

- [ ] **Step 2: Run and prove red**

```bash
cargo test -p carrick-dsr-aarch64 native_mapping_catalog -- --nocapture
```

- [ ] **Step 3: Implement the pure base builder**

Normalize only adjacent ranges of the same class. Subtract stack, trampoline,
heap, mmap arena, shared aperture, and private overlay before classifying
remaining loader-owned extents as `GuestImage`. Subtract every declared class
from `owned_host_ranges` to form `OtherOwned`. Require the resulting
non-overlapping class union to cover the declared ownership universe exactly.

- [ ] **Step 4: Merge translated ownership in the M2 publisher**

Add:

```rust
impl ProcessTranslator {
    pub fn install_native_mapping_catalog_base(
        &self,
        base: NativeMappingCatalogBase,
    ) -> Result<NativeMappingCatalogVersion, DsrError>;

    pub fn native_mapping_catalog_version(
        &self,
    ) -> Option<NativeMappingCatalogVersion>;
}
```

Initial version 1 adds the private cache as `PrivateTranslated`. Each successful
M2 shared-range addition creates version N+1 with `SharedTranslated` before
the exclusive translator guard is released. A failed load publishes no
version. Fork inheritance records the exact version frontier and replays it;
exec begins at version 1 in the replacement runtime epoch.

Each full snapshot extends `owned_universe` with the private and loaded shared
translated extents before validating exact coverage. Translated mappings are
not silently treated as `HostOther` merely because they live outside the guest
memory reservoirs.

- [ ] **Step 5: Add the closure-gated catalog probe**

Declare:

```rust
fn host__native__map__catalog(
    _: u32,
    _: u64,
    _: u64,
    _: HostNativeMapCatalog,
) {}
```

The wrapper accepts typed runtime epoch/version and a borrowed catalog snapshot.
Its JSON payload contains address mode (`direct` or `biased` plus exact
`host_bias`), the ownership universe, and every class/range. Raw conversion
and JSON allocation occur only inside the enabled observability closure. Mirror
the no-op stub. Set the native profile's libdtrace `strsize` to 16 KiB rather
than the current hard-coded 512 bytes, reject a serialized payload above
12 KiB before firing, and test the maximum supported range count plus a
one-byte-over-limit rejection. The live known-page fixture must prove the
received payload hash equals the pre-publication hash with no truncation.
Ordinary native execution pays one disabled-probe branch per catalog version,
never a per-fault or per-memory-access event.

Extend `DsrProbeSink` with
`host_native_map_catalog(&self, event: &NativeMappingCatalogEvent<'_>)`, where
the event borrows the already retained typed snapshot plus epoch/version. The
sink is installed unconditionally, so sink presence is not an enabled-probe
test: neither the caller nor forwarder clones vectors or serializes JSON. The
exhaustive forwarder in `native_darwin.rs` maps every class variant inside the
observability probe closure after its enabled check. The translator fires only
through `carrick_dsr::probes::host_native_map_catalog`.

- [ ] **Step 6: Install at active image seams**

Build the static base after native memory layout is final, install it in the
dormant translator, and publish only at M2's active-image handoff. Republish
after fork and successful exec. Do not publish during pre-PONR replacement
construction or for guest operations inside existing reservoirs.

- [ ] **Step 7: Run focused tests and commit**

```bash
cargo test -p carrick-dsr-aarch64 native_mapping_catalog -- --nocapture
cargo test -p carrick-observability native_mapping -- --nocapture
just fmt
git diff --check
git add crates/carrick-dsr-aarch64/src/native_mapping_catalog.rs \
  crates/carrick-dsr/src/probes.rs \
  crates/carrick-dsr-aarch64/src/lib.rs \
  crates/carrick-dsr-aarch64/src/mapped_memory.rs \
  crates/carrick-dsr-aarch64/src/translator.rs \
  crates/carrick-observability/src/probes.rs \
  crates/carrick-runtime/src/native_darwin.rs
git commit -m "feat(runtime): publish native host backing catalogs" -m \
"Promote native backing ownership into a typed, exact-coverage catalog and
version it with private/shared translated ranges across active fork and exec
lifecycles. Publish no live VMA or permission claim.

Verified with coverage, overlap, translation-version, fork, and exec tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 3: Add the receipt-bound `native-faults` trace profile

**Files:**

- Create: `scripts/dtrace/native-faults.d`
- Modify: `scripts/dtrace/native-wall.d`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/trace_cli.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

**CLI:**

```rust
pub(crate) enum TraceProfileKind {
    Dsr,
    DsrIndirect,
    DsrFork,
    NativeWall,
    NativeFaults,
}

#[arg(long, value_name = "FILE", requires = "profile")]
fault_qualification: Option<PathBuf>,
```

**Bundled source:**

```rust
pub const BUNDLED_NATIVE_FAULTS_D: &str =
    include_str!("../../../scripts/dtrace/native-faults.d");
```

- [ ] **Step 1: Add red CLI/receipt tests**

Assert `--profile native-faults` requires `--fault-qualification`; every other
profile rejects it; sudo reconstruction retains the exact path; and trace
launch rejects stale host, boot, page size, provider/probe, address arg,
binary, provider schema, or bundled-D hash before `dtrace_go`. Separately,
`seal-provider` rejects stale qualification receipt/D/validator/analyzer
inputs, and the analyzer rejects a stale self-hash before reading captures.

- [ ] **Step 2: Add red strict-parser fixtures**

Under `DSRPROF2`, cover:

- valid addressed `as_fault`/`zfod`;
- valid count-only COW/pagein/major/protection/real-fault;
- addressed COW;
- misaligned page base;
- address before catalog ready;
- missing/gapped catalog version;
- fork frontier without the named parent version;
- exec-attempt disarm, failure restore, and success awaiting a new catalog;
- PID reuse or stale birth key;
- addressed total versus page aggregation mismatch;
- startup/transition total mismatch;
- COW record carrying address/catalog fields;
- overflow, unknown tag, mixed v1/v2, truncation, and every drop class.

- [ ] **Step 3: Run and prove red**

```bash
cargo test -p carrick-cli --test trace_profile native_faults -- --nocapture
cargo test -p carrick-cli trace_profile::tests::native_fault -- --nocapture
```

- [ ] **Step 4: Implement exact raw fault keys**

Reuse M2's admitted process tree and identity. Addressed keys are exactly:

```text
(birth_key, image_generation, runtime_epoch,
 mapping_catalog_version, outcome, host_page_base)
```

Count-only keys are:

```text
(birth_key, image_generation, runtime_epoch, outcome)
```

At `vminfo:::as_fault`/`zfod`, preserve `arg2` without masking or rounding.
When catalog attribution is not armed, increment an explicit
`pre_catalog_or_transition` total. At attempted exec, disarm; on failure,
restore the old ready version; on success, retire it until the new active image
publishes ready. COW and every other outcome never carry an address or version.

- [ ] **Step 5: Extend the closed `DSRPROF2` wire grammar**

M3 adds exactly these records to M2's grammar:

```text
DSRPROF2|map-catalog|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|version=V|address_mode=direct|host_bias=0|payload_sha256=H|payload=J
DSRPROF2|map-catalog|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|version=V|address_mode=biased|host_bias=B|payload_sha256=H|payload=J
DSRPROF2|fault-provider|name=N|probe=Q|address_arg=A
DSRPROF2|fault-page|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|version=V|outcome=O|host_page_base=A|count=N
DSRPROF2|fault-disabled|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|outcome=O|count=N
DSRPROF2|fault-count-only|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|outcome=O|count=N
DSRPROF2|fault-total|pid=P|start_sec=S|start_usec=U|image=I|epoch=E|outcome=O|count=N
```

`outcome` is closed to `as_fault`, `zfod`, `cow_fault`, `pagein`,
`major_fault`, `protection_fault`, and `real_fault`. `fault-page` is legal only
for `as_fault`/`zfod`; those outcomes require `fault-total` and partition into
page plus disabled populations. The other outcomes are legal only in
`fault-count-only`. Provider rows must exactly match the sealed receipt. JSON
payload parsing consumes the remainder after `payload=` and verifies its
declared SHA-256; no silent 16 KiB truncation is accepted.

M3 also activates `fork-inherit.mapping_frontier`: it is the parent's latest
ready mapping version and may be nonzero. The child must replay that exact
immutable prefix before attribution. M2-only parser fixtures may retain zero,
but an M3 gating profile rejects zero after a ready parent catalog. Update both
`native-wall.d` and `native-faults.d` plus the shared strict parser together;
every other unknown v2 tag or field remains fatal.

- [ ] **Step 6: Emit and reconcile all populations**

Emit lifecycle/catalog records, all-tracked outcome totals, addressed page
aggregates, attribution-disabled totals, count-only outcomes, live-at-end,
provider identity, consumer-reported drops, and exactly one completion. The
Rust parser adds
explicit v2 metric variants:

```rust
NativeMappingCatalog { identity, version, address_mode, catalog }
NativeFaultPage { identity, catalog_version, outcome, host_page_base, count }
NativeFaultCountOnly { identity, outcome, count }
NativeFaultAttributionDisabled { identity, outcome, count }
```

Use checked `u64` addition. Require every addressed value to be aligned to the
receipt page size, every catalog version contiguous/ready, and
`all_tracked = addressed + attribution_disabled` separately for `as_fault`
and `zfod`.

- [ ] **Step 7: Run focused tests and commit**

```bash
cargo test -p carrick-cli --test trace_profile native_faults -- --nocapture
cargo test -p carrick-cli trace_profile::tests::native_fault -- --nocapture
cargo test -p carrick-cli --test cli native_fault -- --nocapture
just fmt
git diff --check
git add scripts/dtrace/native-faults.d \
  scripts/dtrace/native-wall.d \
  crates/carrick-cli/src/trace_profile.rs \
  crates/carrick-cli/src/args.rs \
  crates/carrick-cli/src/trace_cli.rs \
  crates/carrick-cli/src/commands.rs \
  crates/carrick-runtime/src/dtrace_consumer.rs \
  crates/carrick-cli/tests/trace_profile.rs
git commit -m "diagnostics(cli): capture qualified native page faults" -m \
"Bind native fault capture to a live provider receipt, preserve qualified
16 KiB page bases under process-image/catalog identity, and keep COW and other
private outcomes count-only.

Verified with CLI, sudo-forwarding, receipt-drift, lifecycle, and corruption
fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 4: Analyze page ownership and repetition

**Files:**

- Create: `scripts/perf/native_fault_capture.py`
- Create: `scripts/perf/test_native_fault_capture.py`
- Modify: `scripts/perf/native_fault_qualify.py`
- Modify: `scripts/perf/test_native_fault_qualify.py`
- Create: `scripts/perf/native_fault_attribution.py`
- Create: `scripts/perf/test_native_fault_attribution.py`
- Create: `scripts/perf/fixtures/native-fault-attribution/uniform.jsonl`
- Create: `scripts/perf/fixtures/native-fault-attribution/mixed-partial.jsonl`
- Create: `scripts/perf/fixtures/native-fault-attribution/rejected.jsonl`

**Interfaces:**

```python
@dataclasses.dataclass(frozen=True)
class MappingRange:
    mapping_class: str
    start: int
    end: int


@dataclasses.dataclass(frozen=True)
class PageOwnership:
    kind: str
    classes: tuple[str, ...]
    fragments: tuple[tuple[str, int], ...]


@dataclasses.dataclass(frozen=True)
class VerifiedFaultInput:
    capture_receipt: pathlib.Path
    raw: pathlib.Path
    summary: pathlib.Path
    stdout: pathlib.Path
    receipt_sha256: str
    raw_sha256: str
    summary_sha256: str
    stdout_sha256: str
```

Required call signatures are
`classify_host_page(page_base: int, page_size: int,
ranges: tuple[MappingRange, ...]) -> PageOwnership`,
`load_verified_fault_input(capture_receipt: pathlib.Path,
provider: dict[str, object]) -> VerifiedFaultInput`,
`analyze_profile(capture_receipt: pathlib.Path,
provider: dict[str, object]) -> dict[str, object]`, and
`compare_profiles(first: dict[str, object],
second: dict[str, object]) -> dict[str, object]`,
`analyze_known_page_fixture(capture_receipt: pathlib.Path,
provider: dict[str, object]) -> dict[str, object]`, and
`seal_provider(qualification_path: pathlib.Path,
carrick_binary: pathlib.Path, native_faults_d: pathlib.Path,
analyzer_path: pathlib.Path, output: pathlib.Path) -> dict[str, object]`.

**Output schema:** `carrick.native-fault-attribution.v1`.

- [ ] **Step 1: Add red ownership fixtures**

For one 16 KiB page, cover:

- `Uniform(class)` when one class covers all bytes;
- `Mixed(class-set)` when two or more declared classes cover all bytes;
- `Partial(class-set)` when declared and undeclared bytes coexist; and
- `HostOther` when no declared Carrick mapping intersects.

Assert half-open boundary behavior, overlap rejection, fragment byte totals,
and that an event is never fractionally assigned to a favored class.

- [ ] **Step 2: Add red repetition/acceptance fixtures**

For each addressed outcome/process/ownership bucket, assert event count,
distinct pages, `repeat_excess = events - distinct_pages`,
`repeat_factor = events / distinct_pages`, highest-count pages, and reversible
guest-page candidates only when address mode permits. Separately assert
count-only outcomes and pre-catalog totals.

Reject under 85% combined addressed coverage, population mismatch, addressed
COW, non-ready/gapped catalog, misalignment, overflow/drop, rank change, or a
bucket above 10% moving more than five percentage points without an explicit
instability finding. Reject `git_dirty=true`, missing raw/stdout/capture hashes,
address-mode loss, biased reversal without the exact host bias, or a changed
qualification/provider determinant.

Load each profile only through its capture receipt. Rehash and verify the
explicit raw, summary, stdout, arm, overlay/ELF, qualification, and cleanup
fields before parsing; reject any embedded path or hash drift. Each analysis
records its capture-receipt hash and every verified source hash, and reloading
an analysis repeats the binding. Test changed raw, summary, stdout, missing
`BUILD_OK`/fixture marker, failed cleanup, wrong arm, and wrong provider
independently.

Compute combined coverage exactly as
`(addressed_as_fault + addressed_zfod) /
(all_tracked_as_fault + all_tracked_zfod)`. Attribution-disabled startup and
transition counts stay in the denominator.

For the known-page fixture, parse exactly one
`NATIVE_FAULT_PAGES_BEGIN guest_start=<hex> page_size=16384 pages=<n>` and one
`NATIVE_FAULT_PAGES_END` marker from captured stdout. Use the catalog's
`direct`/`biased(host_bias)` evidence to derive expected host pages; require
every expected page in the addressed profile and its declared ownership, and
require the count-only COW population. This command emits
`carrick.native-fault-known-pages.v1`.

- [ ] **Step 3: Run and prove red**

```bash
python3 -m unittest scripts/perf/test_native_fault_attribution.py -v
```

- [ ] **Step 4: Implement exact page intersection**

Intersect `[page_base, page_base + page_size)` against the exact ranges for the
event's process-image/runtime/catalog version. Sort fragments by address,
reject overlapping declarations, and classify from byte coverage. Report
mixed/partial composition descriptively while retaining one page/event bucket.

- [ ] **Step 5: Implement two-profile publication**

CLI:

```bash
python3 scripts/perf/native_fault_attribution.py \
  --provider PROVIDER.json \
  --capture-receipt RUN1.capture.json \
  --capture-receipt RUN2.capture.json \
  --output ATTRIBUTION.json
```

There is no gating CLI mode that accepts a bare `--profile` or `--stdout`.
Hash every closed source. Publish atomically only when both profiles
independently accept and the dominant ownership rank/stability rule passes.
Report no return result, VM tag, requested protection, wiring state, exact
4 KiB address, or COW address.

- [ ] **Step 6: Implement provider sealing and receipt-bound capture**

`native_fault_qualify.py seal-provider` revalidates the accepted current-boot
qualification, exact signed arm binary, bundled `native-faults.d`, and final
analyzer, then exclusively publishes `carrick.native-fault-provider.v1`. It
rejects a pre-existing output, unknown field, dirty source determinant, or
changed hash.

`native_fault_capture.py` has two typed subcommands:

```text
capture-go --receipt ARM --qualification PROVIDER --overlay OVERLAY
  --run-id ID --trace-out RAW --summary-jsonl JSONL --stdout STDOUT
  --capture-receipt RECEIPT
capture-elf --receipt ARM --qualification PROVIDER --elf ELF
  --run-id ID --trace-out RAW --summary-jsonl JSONL --stdout STDOUT
  --capture-receipt RECEIPT
```

Both reverify the arm, provider, clean source, complete overlay (for Go), M1
host preflight, and exact binary identity. `capture-go` shares M1's cold-Go
command builder and requires `BUILD_OK`; `capture-elf` invokes
`run-elf <ELF> --raw --exec-backend native` and requires guest exit status zero.
Both run the receipt binary's `trace --profile native-faults`, pass the sealed
provider, capture stdout/stderr, run scoped `kill.sh` in `finally`, and
atomically publish hashes for raw, summary, stdout, arm, provider, overlay/ELF,
marker, and cleanup evidence. Red tests inject every drift/failure.

`native_fault_capture.py promote-set` accepts exactly the M3 roles listed in
Task 5 Step 7. It revalidates qualification raw/status, the sealed provider,
the known-page analysis, both Go capture receipts, and their receipt-bound
analysis. It creates a same-parent exclusive staging directory, copies and
`fsync`s every source, writes and `fsync`s a closed `manifest.json`, then
atomically renames the complete directory to an absent destination and
`fsync`s the parent. Collision is fatal and no accepted destination is ever
overwritten. Failure-injection tests cover each copy, manifest, sync, rename,
and collision boundary; an interruption can leave only an ignored staging
directory.

- [ ] **Step 7: Run focused tests and commit**

```bash
python3 -m unittest \
  scripts/perf/test_native_fault_qualify.py \
  scripts/perf/test_native_fault_capture.py \
  scripts/perf/test_native_fault_attribution.py -v
git diff --check
git add scripts/perf/native_fault_capture.py \
  scripts/perf/test_native_fault_capture.py \
  scripts/perf/native_fault_qualify.py \
  scripts/perf/test_native_fault_qualify.py \
  scripts/perf/native_fault_attribution.py \
  scripts/perf/test_native_fault_attribution.py \
  scripts/perf/fixtures/native-fault-attribution
git commit -m "diagnostics(perf): attribute native fault ownership" -m \
"Join qualified as-fault and zero-fill page bases to their exact published
host-backing version and report uniform, mixed, partial, host-other, and repeat
populations without inventing 4 KiB or COW addresses. Seal provider authority
only after the profile/analyzer exist and preserve receipt-bound raw captures.

Verified with page-boundary, address-mode, provider/capture drift, repetition,
coverage, known-page, and two-run stability fixtures.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 5: Live-prove known pages and accept two workload captures

**Files:**

- Create: `fixtures/linux-aarch64-hello/src/native_fault_pages.rs`
- Modify: `fixtures/linux-aarch64-hello/Cargo.toml`
- Modify: `scripts/build-linux-fixtures.sh`
- Create: `scripts/perf/evidence/native-fault-m3-v1/manifest.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-qualify.raw`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-qualify.status.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-qualification-v1.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-provider-v1.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-pages.raw`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-pages.jsonl`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-pages.stdout`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-pages.capture.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-pages-analysis-v1.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-a-v1.raw`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-a-v1.jsonl`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-a-v1.stdout`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-a-v1.capture.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-b-v1.raw`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-b-v1.jsonl`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-b-v1.stdout`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-faults-go-b-v1.capture.json`
- Create: `scripts/perf/evidence/native-fault-m3-v1/native-fault-attribution-v1.json`
- Modify: `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`
- Modify: `handoff.md`

- [ ] **Step 1: Add and red-first the guest known-page fixture**

Add a dedicated Cargo binary `carrick-linux-aarch64-native-fault-pages`. It
maps consecutive anonymous pages, prints `NATIVE_FAULT_PAGES_BEGIN` with exact
range/page count, touches them, forks and writes once, waits, prints
`NATIVE_FAULT_PAGES_END`, and exits naturally. First prove the old binary lacks
the markers, then build through `scripts/build-linux-fixtures.sh`. Commit this
fixture before collecting performance evidence so every live workload sees a
clean source tree:

Add the explicit build entry used by this repository's fixture builder:

```bash
build_fixture "native_fault_pages.rs" \
  "carrick-linux-aarch64-native-fault-pages"
```

```bash
git add fixtures/linux-aarch64-hello/src/native_fault_pages.rs \
  fixtures/linux-aarch64-hello/Cargo.toml \
  scripts/build-linux-fixtures.sh
git commit -m "test(native): add known native fault pages" -m \
"Add a deterministic Linux/AArch64 mapping, first-touch, and fork-write
fixture for the qualified Darwin host-page ownership profile.

Verified by red-first marker absence and the Linux fixture build.

Co-Authored-By: Codex <codex@openai.com>"
```

- [ ] **Step 2: Build signed and run live provider qualification**

```bash
test -z "$(git status --porcelain)"
scripts/build-linux-fixtures.sh
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$PWD" \
  --destination target/perf/native-m3-tip \
  --label native-m3-tip \
  --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
target/perf/native-m3-tip/carrick __native-fault-abi-fixture \
  --control-loop-ms 15000 >target/perf/native-fault-control.log 2>&1 &
control_pid=$!
trap 'kill "$control_pid" 2>/dev/null || true' EXIT
target/perf/native-m3-tip/carrick trace \
  --script scripts/dtrace/native-fault-qualify.d \
  --trace-out target/perf/native-fault-qualify.raw \
  --capture-status-json target/perf/native-fault-qualify.status.json -- \
  __native-fault-abi-fixture
wait "$control_pid"
trap - EXIT
python3 scripts/perf/native_fault_qualify.py \
  --raw target/perf/native-fault-qualify.raw \
  --capture-status target/perf/native-fault-qualify.status.json \
  --carrick target/perf/native-m3-tip/carrick \
  --output target/perf/native-fault-qualification-v1.json
python3 scripts/perf/native_fault_qualify.py seal-provider \
  --qualification target/perf/native-fault-qualification-v1.json \
  --carrick target/perf/native-m3-tip/carrick \
  --native-faults-d scripts/dtrace/native-faults.d \
  --analyzer scripts/perf/native_fault_attribution.py \
  --output target/perf/native-fault-provider-v1.json
```

Require live `as_fault` and `zfod` `arg2`, 16 KiB alignment/stride, same-page
offset collapse, count-only COW, scoped control exclusion, natural completion,
and zero consumer-reported drops. The raw/status hashes must reconcile. Do not
accept `fbt::vm_fault`.

- [ ] **Step 3: Prove the known-page fixture**

```bash
python3 scripts/perf/native_fault_capture.py capture-elf \
  --receipt target/perf/native-m3-tip/arm.json \
  --qualification target/perf/native-fault-provider-v1.json \
  --elf fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-native-fault-pages \
  --run-id native-m3-known-pages \
  --trace-out target/perf/native-fault-pages.raw \
  --summary-jsonl target/perf/native-fault-pages.jsonl \
  --stdout target/perf/native-fault-pages.stdout \
  --capture-receipt target/perf/native-fault-pages.capture.json
python3 scripts/perf/native_fault_attribution.py known-page \
  --provider target/perf/native-fault-provider-v1.json \
  --capture-receipt target/perf/native-fault-pages.capture.json \
  --output target/perf/native-fault-pages-analysis-v1.json
```

Require only the supported claim: independently qualified 16 KiB
`as_fault`/`zfod` page bases and matching host-backing ownership, plus a
count-only COW population. The capture wrapper's concrete child command is
`run-elf <fixture> --raw --exec-backend native`; guest status zero and both
markers are mandatory.

- [ ] **Step 4: Capture two primary cold-Go-build profiles**

Use M1's exact default overlay, the immutable M3 arm, unique run IDs, and serial
receipt-bound captures. Keep raw, summaries, stdout, and capture receipts under
`target/perf/` until every capture and guardrail finishes:

```bash
python3 scripts/perf/native_fault_capture.py capture-go \
  --receipt target/perf/native-m3-tip/arm.json \
  --qualification target/perf/native-fault-provider-v1.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id native-m3-fault-go-a \
  --trace-out target/perf/native-faults-go-a-v1.raw \
  --summary-jsonl target/perf/native-faults-go-a-v1.jsonl \
  --stdout target/perf/native-faults-go-a-v1.stdout \
  --capture-receipt target/perf/native-faults-go-a-v1.capture.json
python3 scripts/perf/native_fault_capture.py capture-go \
  --receipt target/perf/native-m3-tip/arm.json \
  --qualification target/perf/native-fault-provider-v1.json \
  --overlay scripts/perf/overlays/native-default.json \
  --run-id native-m3-fault-go-b \
  --trace-out target/perf/native-faults-go-b-v1.raw \
  --summary-jsonl target/perf/native-faults-go-b-v1.jsonl \
  --stdout target/perf/native-faults-go-b-v1.stdout \
  --capture-receipt target/perf/native-faults-go-b-v1.capture.json
python3 scripts/perf/native_fault_attribution.py \
  --provider target/perf/native-fault-provider-v1.json \
  --capture-receipt target/perf/native-faults-go-a-v1.capture.json \
  --capture-receipt target/perf/native-faults-go-b-v1.capture.json \
  --output target/perf/native-fault-attribution-v1.json
```

Both runs require natural `BUILD_OK`, `git_dirty=false`, live set zero, zero drops, population
reconciliation, at least 85% addressed coverage, ready contiguous catalogs,
and stable dominant ownership.

- [ ] **Step 5: Escalate disputed owners to LLDB**

For a dominant `HostOther`, overlap, or disputed translated page, attach to the
guest Carrick process, use `scripts/carrick_lldb.py`, and record exact
`memory region`, relevant mappings/registers, binary hash, run ID, transcript
path, and SHA-256. A debugger finding may explain a bucket; it cannot weaken
the qualification/coverage gate.

- [ ] **Step 6: Run correctness and repository gates**

```bash
cargo test -p carrick-observability native_fault -- --nocapture
cargo test -p carrick-dsr-aarch64 native_mapping_catalog -- --nocapture
cargo test -p carrick-cli --test trace_profile native_faults -- --nocapture
python3 -m unittest \
  scripts/perf/test_native_fault_qualify.py \
  scripts/perf/test_native_fault_attribution.py -v
just conformance-native smoke --workers 4
just conformance full --lane macos-native-dsr --workers 1 \
  --suite node-app-smoke --suite node-v8-smoke \
  --jsonl target/conformance/native-performance-m3-node.jsonl
just conformance full --lane macos-native-dsr --workers 1 \
  --suite cpython-subprocess --suite cpython-threading \
  --jsonl target/conformance/native-performance-m3-cpython.jsonl
just ci
```

Run no Docker oracle concurrently.

- [ ] **Step 7: Record and commit accepted fault evidence**

Record the provider/raw/analyzer SHA-256 values, binary/commit, host/boot/page
size, coverage, event/page/repeat counts, ownership ranks, count-only outcomes,
stability, and any LLDB transcript. Keep exact events separate from sampled
kernel CPU and make no traced-time claim.

```bash
python3 scripts/perf/native_fault_capture.py promote-set \
  --destination scripts/perf/evidence/native-fault-m3-v1 \
  --input qualification.raw=target/perf/native-fault-qualify.raw \
  --input qualification.status=target/perf/native-fault-qualify.status.json \
  --input qualification.receipt=target/perf/native-fault-qualification-v1.json \
  --input provider.receipt=target/perf/native-fault-provider-v1.json \
  --input known-page.raw=target/perf/native-fault-pages.raw \
  --input known-page.jsonl=target/perf/native-fault-pages.jsonl \
  --input known-page.stdout=target/perf/native-fault-pages.stdout \
  --input known-page.capture=target/perf/native-fault-pages.capture.json \
  --input known-page.analysis=target/perf/native-fault-pages-analysis-v1.json \
  --input go-a.raw=target/perf/native-faults-go-a-v1.raw \
  --input go-a.jsonl=target/perf/native-faults-go-a-v1.jsonl \
  --input go-a.stdout=target/perf/native-faults-go-a-v1.stdout \
  --input go-a.capture=target/perf/native-faults-go-a-v1.capture.json \
  --input go-b.raw=target/perf/native-faults-go-b-v1.raw \
  --input go-b.jsonl=target/perf/native-faults-go-b-v1.jsonl \
  --input go-b.stdout=target/perf/native-faults-go-b-v1.stdout \
  --input go-b.capture=target/perf/native-faults-go-b-v1.capture.json \
  --input go.analysis=target/perf/native-fault-attribution-v1.json
git add scripts/perf/evidence/native-fault-m3-v1 \
  docs/perf-results/2026-07-29-native-cpu-budget-evidence.md \
  handoff.md
git commit -m "diagnostics(perf): accept native fault ownership" -m \
"Qualify the current Darwin vminfo address contract, prove known 16 KiB guest
touches against typed host backing, and accept two stable cold-Go-build fault
ownership captures.

Verified with native smoke, Node/CPython fork-exec guardrails, and `just ci`.

Co-Authored-By: Codex <codex@openai.com>"
```

## M3 Completion Gate

M3 is complete only when:

- the current boot has an accepted provider receipt;
- `as_fault`/`zfod` addresses are exact qualified 16 KiB page bases;
- COW and all unqualified outcomes remain count-only;
- every addressed event names a ready exact mapping-catalog version;
- startup/transition, addressed, and all-tracked populations reconcile;
- mixed/partial/host-other pages are preserved rather than guessed;
- two primary captures meet coverage, zero-drop, lifecycle, and stability
  gates; and
- the ledger/handoff link the immutable evidence without a traced-time
  performance claim.

M3 does not choose the optimization. M4 compares this fault-owner ceiling with
M2's translation ceiling.
