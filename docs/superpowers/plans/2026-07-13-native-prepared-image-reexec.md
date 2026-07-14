# Native Prepared-Image Self-Reexec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the duplicate guest executable load and anonymous byte copy from native fork-child host self-reexec while preserving PID, libdispatch safety, exact preflight bytes, fallback behavior, and Linux-visible process state.

**Architecture:** The fork child serializes the already-built `AddressSpace` into a bounded sparse anonymous regular file and places a typed, checksummed descriptor in the existing one-shot capsule. The fresh Carrick process validates that descriptor and maps the artifact `MAP_PRIVATE` into the existing native layout, then reuses the current relocation, vvar, DSR, protection, and run-loop paths. Ineligible artifacts fall back before host `execve` to the current digest-bound reload; failures after successful host `execve` are fatal and never reopen the guest path.

**Tech Stack:** Rust 2024, `serde`/`serde_json`, `sha2`, Darwin `mmap(2)`/`fcntl(2)`/`fstat(2)`, Carrick native DSR mapper, USDT/DTrace `dsr-fork`, signed release builds, static/dynamic PIE conformance probes, and seeded-bootstrap ABBA performance comparison.

## Global Constraints

- Work only in `/Volumes/CaseSensitive/carrick/.worktrees/codex-native-conformance` on `codex/native-conformance-quality`; preserve unrelated worktree state.
- Keep the real host `execve(2)` boundary. Do not replace it with `longjmp`, in-process reset, `posix_spawn`, or a helper process.
- Do not add a persistent DSR AOT cache in this slice. Remeasure cold translation only after prepared-image promotion, and require a separate design if it still contributes at least 10% of untraced fork-exec wall time.
- Do not read Linux kernel or other GPL implementation source. The checked-in design, man pages, Carrick source, probes, and Docker oracle are sufficient.
- The existing old-process `load_native_execve_image` result is the authority. A prepared image may optimize transport and mapping only after all current guest-visible validation succeeds.
- Never turn prepared-artifact ineligibility or construction failure into a new guest failure. Fall back to the current reload path before the point of no return.
- After successful host `execve`, never fall through from a corrupt prepared artifact to reopening the guest path; fail loudly with the exact adoption stage.
- Use typed guest addresses, lengths, artifact offsets, and relocation targets. Raw integers are allowed only at serialization, libc, and file-I/O boundaries through named constructors/accessors.
- Keep executable guest source mappings non-executable on the host. DSR executes translated cache code only.
- Do not call `sync_data`, `fsync`, or `F_FULLFSYNC`; the inherited anonymous regular files require coherent contents, not crash durability.
- Never run Carrick and Docker concurrently. Stamp every live Carrick run with a unique `CARRICK_RUN_ID` and reap it with `sudo -n scripts/sudo/kill.sh "$CARRICK_RUN_ID"`.
- After any `carrick-runtime` change, rebuild and re-sign the CLI with `just build`; a runtime-only build is not runnable evidence.
- Make the probe red against the parent/broken binary before relying on it as a regression test.
- Each behavior-changing commit needs a Conventional Commit subject, explanatory body, verification receipt, and `Co-Authored-By: Codex <codex@openai.com>` trailer.
- Promotion requires both correctness and the performance gate. A correct prepared path that misses the wall-time threshold stays experimental and is either revised or reverted.

---

## Task 1: Freeze the red baseline and implementation contracts

**Files:**

- Modify: `docs/superpowers/specs/2026-07-13-native-prepared-image-reexec-design.md`
- Modify: `docs/native-default-conformance-campaign.md`
- Create: `target/conformance/native-prepared-image/red/` (evidence only; do not commit)
- Verify: `scripts/dtrace/dsr-fork.d`
- Verify: `conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec`

- [ ] **Step 1: Mark the design review complete**

Change the design status to:

```markdown
**Status:** approved for implementation on 2026-07-13
```

Do not change the selected architecture or performance thresholds while changing the status.

- [ ] **Step 2: Record exact source and binary provenance**

Run:

```bash
git status --short
git rev-parse HEAD
shasum -a 256 target/release/carrick
codesign -dvvv target/release/carrick 2>&1 | rg 'CDHash|Identifier'
shasum -a 256 conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
mkdir -p target/conformance/native-prepared-image/red
```

Expected: the branch starts clean, the runtime source is `af1880d6` or its documented descendant, the Carrick binary is signed, and the canonical probe exists.

- [ ] **Step 3: Capture the current untraced red wall time**

Run one discarded warm-up and five recorded signed native repetitions serially. Use a new run id for every invocation and store stdout plus elapsed wall time under `target/conformance/native-prepared-image/red/`. Do not run Docker during this phase.

The guest command is:

```bash
probe=conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
for sample in warmup r1 r2 r3 r4 r5; do
  run_id="native-prepared-red-$sample-$$"
  CARRICK_RUN_ID="$run_id" /usr/bin/time -p \
    target/release/carrick run-elf --raw \
      --native-page-profile native16k "$probe" \
    >"target/conformance/native-prepared-image/red/$sample.log" 2>&1
  sudo -n scripts/sudo/kill.sh "$run_id"
done
```

Expected: every recorded run reports `iters=200`, no failed spawn, and a p50 near the current 12.1 ms median. Any materially different result must be explained before implementation.

- [ ] **Step 4: Capture the current lifecycle red profile**

Run:

```bash
CARRICK_RUN_ID=native-prepared-red-dtrace \
  timeout 180 target/release/carrick trace \
  --profile dsr-fork \
  --trace-out target/conformance/native-prepared-image/red/dsr-fork.raw \
  --summary-jsonl target/conformance/native-prepared-image/red/dsr-fork.jsonl -- \
  run-elf --native-page-profile native16k \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
sudo -n scripts/sudo/kill.sh native-prepared-red-dtrace
```

Expected red: 220 `host-self-reexec-image-load` pairs, no prepared-build/map phases yet, natural target completion, zero incomplete pairs, and zero drops.

- [ ] **Step 5: Add the measured red state to the campaign ledger**

Add one row to `docs/native-default-conformance-campaign.md` containing source SHA, signed binary SHA, canonical probe SHA, five-run p50 range/median, and lifecycle counts. Label it measured RED rather than projected.

- [ ] **Step 6: Commit the approved controller state**

Run:

```bash
git add docs/superpowers/specs/2026-07-13-native-prepared-image-reexec-design.md \
  docs/native-default-conformance-campaign.md
git commit -m "docs(native): start prepared-image implementation" -m "The approved native self-reexec optimization now has a frozen signed red baseline and lifecycle profile before code changes. Record exact source and artifact provenance so the later wall-time and phase comparison cannot drift onto stale binaries.

Verified: five canonical native perf_fork_exec runs completed 200 iterations and dsr-fork recorded the legacy fresh-image-load path with no incomplete pairs or drops.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 2: Add a metadata-only `AddressSpace` reconstruction API

**Files:**

- Modify: `crates/carrick-mem/src/memory.rs`
- Modify: `crates/carrick-mem/src/elf.rs`
- Test: inline `#[cfg(test)]` modules in both files

The prepared mapper needs the existing `/proc`, native-layout, read-only span, entry, and stack interfaces without manufacturing a full vector of ELF bytes. Keep this API transport-neutral in `carrick-mem`; the leaf crate must not know about capsule fds or Darwin.

- [ ] **Step 1: Write compile-red tests for transport-neutral metadata**

Add tests that try to build:

```rust
let metadata = AddressSpaceMetadata {
    entry: GuestVa(0x1000),
    initial_stack_pointer: GuestVa(0x8ff0),
    linux_auxv_image: vec![1, 2, 3, 4],
    regions: vec![MemoryRegionMetadata {
        start: GuestVa(0x1000),
        end: GuestVa(0x2000),
        perms: SegmentPerms { read: true, write: false, execute: true },
        shared: false,
    }, MemoryRegionMetadata {
        start: GuestVa(0x8000),
        end: GuestVa(0x9000),
        perms: SegmentPerms { read: true, write: true, execute: false },
        shared: false,
    }],
    ro_spans: vec![RoSpan { start: 0x1000, len: 0x1000, exec: true }],
};
let image = AddressSpace::from_metadata(metadata).expect("valid metadata");
```

Assert entry, stack pointer, auxv bytes, ordered region geometry/perms/shared bits, RO spans, and empty `MemoryRegion::bytes()` values. Add rejecting cases for overlap, inverted/empty regions, stack pointer outside all writable regions, RO spans outside declared regions, and RO span page misalignment.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo test -p carrick-mem memory::tests::address_space_metadata -- --nocapture
```

Expected: compile failure because `AddressSpaceMetadata`, `MemoryRegionMetadata`, and `AddressSpace::from_metadata` do not exist.

- [ ] **Step 3: Define transport-neutral metadata types**

Add public, non-serialized value types beside `AddressSpace`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegionMetadata {
    pub start: carrick_guest_mem::GuestVa,
    pub end: carrick_guest_mem::GuestVa,
    pub perms: SegmentPerms,
    pub shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpaceMetadata {
    pub entry: carrick_guest_mem::GuestVa,
    pub initial_stack_pointer: carrick_guest_mem::GuestVa,
    pub linux_auxv_image: Vec<u8>,
    pub regions: Vec<MemoryRegionMetadata>,
    pub ro_spans: Vec<crate::elf::RoSpan>,
}
```

Do not derive `Serialize` or `Deserialize`; capsule schema ownership stays in `carrick-runtime`.

- [ ] **Step 4: Implement checked reconstruction**

Implement `AddressSpace::from_metadata` by converting each metadata region into a `MemoryRegion` with empty bytes, calling `AddressSpace::from_regions` for canonical sorting/overlap validation, then setting the stack pointer, auxv image, and RO spans only after validating:

- `start < end` for every region;
- the stack pointer lies in exactly one writable region and is less than its end;
- every RO span is nonzero, 4 KiB aligned, checked-add safe, and contained in a readable declared region; and
- `linux_auxv_image` is accepted as an opaque already-serialized Linux ABI image.

Add precise `AddressSpaceError` variants rather than returning generic I/O errors.

- [ ] **Step 5: Run focused and leaf-crate gates**

Run:

```bash
cargo test -p carrick-mem address_space_metadata -- --nocapture
cargo test -p carrick-mem --lib
cargo clippy -p carrick-mem --all-targets -- -D warnings
```

Expected: all green, including pre-existing ELF/load tests.

- [ ] **Step 6: Commit the leaf API**

Run:

```bash
git add crates/carrick-mem/src/memory.rs crates/carrick-mem/src/elf.rs
git commit -m "feat(mem): rebuild address spaces from checked metadata" -m "Prepared native images need the existing entry, region, auxv, stack, and read-only-span interfaces without reloading ELF bytes. Add a transport-neutral checked constructor that creates metadata-only regions while preserving the same overlap and protection invariants.

Verified: carrick-mem metadata rejection tests, full carrick-mem library tests, and package clippy pass.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 3: Implement the bounded sparse prepared-image artifact

**Files:**

- Create: `crates/carrick-runtime/src/native_prepared_image.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: inline `#[cfg(test)]` module in `native_prepared_image.rs`

- [ ] **Step 1: Add compile-red round-trip and rejection tests**

Declare `#[cfg(target_os = "macos")] pub(crate) mod native_prepared_image;` in `lib.rs`, then write tests against these intended APIs:

```rust
pub(crate) fn prepare(
    image: &AddressSpace,
    relocations: &[NativeRelativeRelocation],
    host_page_size: u64,
) -> Result<PreparedImageDisposition, NativePreparedImageError>;

pub(crate) fn validate_for_resume(
    record: NativePreparedImageV1,
) -> Result<ValidatedPreparedImage, NativePreparedImageError>;
```

Use a synthetic image with executable bytes, BSS zeros, an 8 MiB stack with a nonzero suffix, auxv, RO spans, and two relative relocations. The round-trip must compare entry, stack pointer, region geometry/perms/bytes, auxv, RO spans, and relocations to the source image.

Add red rejection tests for:

- bad version and host-page geometry;
- socket/pipe fd instead of a regular file;
- fd device/inode/size/flags mismatch;
- truncated or extended artifact;
- unaligned, inverted, overlapping, or out-of-bounds region extents;
- more than 256 regions or 16,384 initialized spans;
- sparse extent over 1 GiB or written payload over 512 MiB;
- auxv over 64 KiB;
- initialized spans outside their region or artifact extent;
- stack pointer outside a writable stack region;
- RO spans outside regions or permission escalation;
- relocation target outside a writable declared region; and
- checksum mismatch after changing one initialized byte.

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```bash
cargo test -p carrick-runtime --lib native_prepared_image::tests -- --nocapture
```

Expected: compile failure for the absent artifact types and functions.

- [ ] **Step 3: Define typed wire-domain values and records**

In `native_prepared_image.rs`, define private or `pub(crate)` newtypes with checked constructors and explicit `.get()` accessors:

```rust
PreparedGuestVa(u64)
PreparedGuestLen(u64)
PreparedArtifactOffset(u64)
PreparedRegionIndex(u16)
```

Define `Serialize`/`Deserialize` records:

```rust
NativePreparedImageV1
NativePreparedRegionV1
NativePreparedSpanV1
NativePreparedRoSpanV1
NativeRelativeRelocation
```

`NativePreparedImageV1` contains fd identity/flags/size, format version, host-page size, entry, stack pointer, auxv bytes, ordered regions, initialized spans, RO spans, relocations, written-byte count, and SHA-256 digest. Do not serialize a Rust `AddressSpace`, `MemoryRegion`, pointer, `File`, or `SegmentPerms` directly; encode permissions as a validated three-bit ordinal/bitflag field. Define one fixed little-endian digest transcript containing magic, version, geometry, logical file size, written-byte count, entry, stack pointer, auxv, regions, spans, RO spans, relocations, and initialized payload bytes in table order. Exclude only the digest field itself and transit-specific fd number/flags/device/inode so the transcript is non-circular and content-authoritative.

Move the existing `NativeRelativeRelocation` definition from `native_darwin.rs` into this module and update imports without changing its loader behavior.

- [ ] **Step 4: Implement one canonical validator**

Implement `validate_record(&NativePreparedImageV1, &FileIdentity)`. Call it both before host exec and after resume. It must use checked arithmetic for every end calculation and enforce all v1 bounds from the design.

Return typed errors with stage and offending index/value. Distinguish:

```rust
PreparedImageDisposition::Prepared(PreparedImageArtifact)
PreparedImageDisposition::Ineligible(PreparedImageIneligibleReason)
```

Shared regions and representation limits are `Ineligible`; malformed internal tables, file I/O, and checksum failures are errors to log before selecting fallback.

- [ ] **Step 5: Implement sparse artifact construction**

Create the artifact with `tempfile::tempfile()`, allocate host-page-aligned extents, and `set_len` once. Scan the same copy window as the current mapper:

- for the stack region, start at `initial_stack_pointer` rounded down to the host page;
- for all other regions, inspect the complete region bytes;
- coalesce adjacent nonzero host pages into initialized spans;
- `write_at` only those spans; and
- hash canonical record fields plus each initialized span descriptor and bytes while writing.

Extract the current `native_region_copy_window` rule into a shared `pub(crate)` helper in the new module and make the legacy anonymous mapper call it. This prevents the artifact writer and fallback mapper from silently disagreeing about stack bytes.

Do not reread the payload or flush it before exec. Perform `fstat`, run the canonical validator, and retain the owned `File` in `PreparedImageArtifact` so its raw fd cannot close before `execve`.

- [ ] **Step 6: Implement fresh-process validation and metadata reconstruction**

`validate_for_resume` must:

1. duplicate the inherited fd with `F_DUPFD_CLOEXEC`;
2. verify regular-file identity, exact size, transit flags equal to `original_host_fd_flags & !FD_CLOEXEC`, and host-page geometry;
3. run the canonical bounds validator;
4. recompute SHA-256 from canonical metadata plus initialized payload bytes using `read_at`;
5. reconstruct `AddressSpace` through `AddressSpace::from_metadata`; and
6. close the raw inherited artifact fd after the duplicate is authoritative; and
7. return an owned `ValidatedPreparedImage` containing the duplicate file, metadata-only image, ordered file backings, and relocations.

The original inherited fd remains available only long enough for descriptor-flag restoration/adoption in the capsule layer.

- [ ] **Step 7: Prove sparse stack behavior**

In the synthetic 8 MiB stack test, assert:

- the artifact logical size includes the stack extent;
- initialized spans begin no earlier than the page containing `initial_stack_pointer`;
- written payload excludes the zero prefix;
- `st_blocks * 512` is materially below the logical stack extent when the filesystem reports allocation blocks; and
- mapping/reading the stack prefix returns zeros and the suffix matches the source.

- [ ] **Step 8: Run package gates**

Run:

```bash
cargo fmt --check
cargo test -p carrick-runtime --lib native_prepared_image::tests -- --nocapture
cargo test -p carrick-runtime --lib native_region_copy_window -- --nocapture
cargo clippy -p carrick-runtime --all-targets -- -D warnings
just lint-domains
```

Expected: all artifact and typed-domain cases green; no runtime behavior uses the artifact yet.

- [ ] **Step 9: Commit the artifact format**

Run:

```bash
git add crates/carrick-runtime/src/native_prepared_image.rs \
  crates/carrick-runtime/src/native_darwin.rs crates/carrick-runtime/src/lib.rs
git commit -m "feat(native): encode prepared exec images sparsely" -m "The fork child already owns the validated replacement AddressSpace, but self-reexec currently discards it and reloads the executable. Add a versioned, bounded sparse regular-file artifact with one canonical validator, typed offsets, exact fd identity, and checksummed initialized spans.

The artifact is not active yet. Shared or over-limit images are explicitly ineligible so the existing reload remains available without changing successful exec behavior.

Verified: prepared-image round-trip, corruption, bounds, sparse-stack, typed-domain, runtime clippy, and legacy copy-window tests pass.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 4: Carry the prepared artifact across the existing capsule safely

**Files:**

- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: inline tests in `native_exec_capsule.rs`
- Test: `crates/carrick-cli/tests/cli.rs`

- [ ] **Step 1: Add red capsule ownership and fallback tests**

Extend the sample `NativeGuestExecV1` with:

```rust
pub(crate) prepared_image: Option<NativePreparedImageV1>
```

Add tests proving:

- a prepared record round-trips in the capsule without embedding payload bytes;
- the artifact fd stays open until `execve` or explicit cleanup;
- forced artifact ineligibility emits a capsule with `prepared_image: None`;
- a forced construction/self-validation error also selects the legacy record before host exec;
- host `execve` failure restores the capsule fd, artifact fd, xsignal fd, and all guest survivor/close-on-exec fd flags; and
- the artifact is closed on every pre-exec return path.

Use a test-only injectable exec function/failpoint rather than actually replacing the unit-test process.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
cargo test -p carrick-runtime --lib native_exec_capsule::tests -- --nocapture
```

Expected: compile/test failure because the capsule has no prepared record or owned artifact.

- [ ] **Step 3: Extend `begin_guest_exec` at the authoritative seam**

Change the call from the fork-child `DispatchOutcome::Execve` branch to pass:

```rust
&image,
&relative_relocations,
```

to `native_exec_capsule::begin_guest_exec` after `validate_native_reexec_fd_state` and after all of `load_native_execve_image` succeeds.

Inside `begin_guest_exec`, call `native_prepared_image::prepare`. On `Prepared`, store the record in `NativeGuestExecV1` and retain the `PreparedImageArtifact` owner beside the capsule. On `Ineligible` or pre-exec preparation error, emit an exact diagnostic and store `None`; do not return a Linux error solely because the optimization was unavailable.

- [ ] **Step 4: Generalize descriptor preparation with ownership**

Change `exec_capsule` to accept `Option<PreparedImageArtifact>`. Include the artifact fd in the same `prepare_host_fd_flags` transaction as the capsule, xsignal fd, survivors, and close-on-exec fds. Clear `FD_CLOEXEC` only after the complete capsule and artifact have passed self-validation.

If any later flag change or host `execve` fails:

1. restore every flag in reverse order;
2. drop/close the artifact owner;
3. leave the old guest image runnable; and
4. return the existing guest-visible error path.

- [ ] **Step 5: Add deterministic failpoints**

Add `#[cfg(test)]` failpoints for artifact creation, pre-exec validation, artifact-fd flag preparation, and host exec return. Keep them module-local and self-resetting. Do not add production environment-variable branches.

- [ ] **Step 6: Run capsule and CLI transport gates**

Run:

```bash
cargo test -p carrick-runtime --lib native_exec_capsule::tests -- --nocapture
cargo test -p carrick-cli --test cli native_self_reexec -- --nocapture
cargo clippy -p carrick-runtime -p carrick-cli --all-targets -- -D warnings
```

Expected: capsule one-shot/nonce/corruption tests remain green, prepared ownership tests pass, and the transport-only PID probe still preserves its PID without a guest artifact.

- [ ] **Step 7: Commit capsule transport support**

Run:

```bash
git add crates/carrick-runtime/src/native_exec_capsule.rs \
  crates/carrick-runtime/src/native_darwin.rs crates/carrick-cli/tests/cli.rs
git commit -m "feat(native): carry prepared images through self-reexec" -m "Attach the bounded prepared-image record and its owned inherited fd to the existing one-shot native self-reexec capsule. Artifact ineligibility still selects the digest-bound reload, while descriptor preparation is transactional so a returned host exec restores every modified FD_CLOEXEC flag.

Verified: capsule ownership/fallback/failpoint tests, private PID-preserving CLI transport tests, and runtime/CLI clippy pass.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 5: Map prepared image extents through the existing native lifecycle

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_prepared_image.rs`
- Test: inline tests in `native_darwin.rs`

- [ ] **Step 1: Write red mapping parity tests**

Construct one ordinary byte-backed image and a validated prepared artifact from it. Map each in an isolated forked test process and compare:

- entry and initial SP;
- every declared region's bytes before relocations;
- relocated word values after mapping;
- vvar contents after stamping;
- `MemoryProtections` RO state;
- host VM protections for executable guest regions (must omit `PROT_EXEC`);
- native layout address mode and owned ranges; and
- `/proc` region/auxv snapshots published from the metadata-only image.

Add failpoint tests for the second region map, relocation, vvar stamp, and final protection. Each must retire already-mapped ranges and return the exact stage error.

- [ ] **Step 2: Run focused mapping tests and confirm RED**

Run:

```bash
cargo test -p carrick-runtime --lib native_prepared_mapping -- --nocapture
```

Expected: failure because `NativeMappedMemory` accepts only anonymous byte-backed regions.

- [ ] **Step 3: Introduce an internal image-backing enum**

Refactor `NativeMappedMemory::map_with_layout` to take:

```rust
enum NativeImageBacking<'a> {
    AnonymousBytes,
    Prepared(&'a ValidatedPreparedImage),
}
```

Keep `map_for_plan` passing `AnonymousBytes`. Add:

```rust
fn map_prepared_for_plan(
    prepared: &ValidatedPreparedImage,
    layout: MemoryLayout,
    plan: &ExecutionPlan,
) -> Result<Self, RuntimeError>
```

Both constructors must enter the same `NativeLayout`, region bookkeeping, sigreturn mapping, heap/mmap reservations, RO-span application, vvar stamping, relocation, DSR translator creation, and cleanup/commit path.

- [ ] **Step 4: Add the file-backed region mapper**

For each validated ordered region, `mmap` its host-page-aligned artifact extent with:

```rust
let flags = native_layout.fixed_mapping_flags(
    host_start,
    length,
    libc::MAP_PRIVATE,
)?;
let mapped = libc::mmap(
    host_start.raw() as *mut libc::c_void,
    length,
    libc::PROT_READ | libc::PROT_WRITE,
    flags,
    prepared.file_fd(),
    prepared.artifact_offset(region_index),
);
```

Require the returned address to equal the exact native-layout host address. Do not add `MAP_ANON`, do not copy region bytes, and do not use `MAP_SHARED`.

After mapping, reuse the existing icache clearing and final `mprotect` logic. Executable guest regions must become host read-only/non-executable exactly as in `map_region`. The artifact fd may close only after every image extent has mapped successfully; `MAP_PRIVATE` mappings remain valid after close.

- [ ] **Step 5: Factor common finalization without changing fallback**

Make the legacy and prepared branches share:

- vDSO/vvar load relocation;
- sigreturn trampoline mapping;
- heap and mmap arena mapping;
- RO-span bookkeeping;
- `stamp_vdso_vvar`;
- `apply_native_relative_relocations`;
- DSR generation/translator setup; and
- `NativeLayout::commit_if_ok` cleanup.

Do not duplicate those operations in the prepared branch. The only branch-specific operation should be image-region backing setup.

- [ ] **Step 6: Run mapping, runtime, and lint gates**

Run:

```bash
cargo test -p carrick-runtime --lib native_prepared_mapping -- --nocapture
cargo test -p carrick-runtime --lib native_exec -- --nocapture
cargo test -p carrick-runtime --lib
cargo clippy -p carrick-runtime --all-targets -- -D warnings
just lint-domains
```

Expected: byte-for-byte and protection parity, cleanup failpoints green, and all runtime library tests pass.

- [ ] **Step 7: Commit prepared mapping support**

Run:

```bash
git add crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-runtime/src/native_prepared_image.rs
git commit -m "feat(native): map prepared images after self-reexec" -m "The fresh native process can now map validated sparse image extents directly at the existing native layout instead of allocating anonymous regions and copying the rebuilt ELF image. Both backings share vvar, relocation, DSR, protection, and cleanup logic, preserving the non-executable source-page contract.

Verified: prepared-vs-legacy byte/protection parity, injected map/finalization cleanup failures, full runtime library tests, clippy, and typed-domain lint pass.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 6: Select prepared adoption in the fresh process and prove exact-byte behavior

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/native_prepared_image.rs`
- Verify: `crates/carrick-cli/tests/conformance.rs`
- Test: inline runtime/capsule tests

- [ ] **Step 1: Add red adoption and substitution tests**

Add tests for these resume outcomes:

1. `prepared_image: Some` validates/maps without invoking `load_native_execve_image`;
2. `prepared_image: None` invokes the unchanged loader and digest check;
3. changing the guest executable path bytes after artifact construction does not change prepared execution;
4. corrupting one initialized artifact byte after host exec terminates with `prepared-validate: checksum mismatch` and never calls the loader;
5. an injected second-region mapping failure after host exec terminates with `prepared-map: injected second-region mapping failure` and never calls the loader; and
6. a legacy fallback still detects a changed executable digest.

Use injected loader counters/test seams rather than timing to distinguish prepared from legacy.

- [ ] **Step 2: Run focused adoption tests and confirm RED**

Run:

```bash
cargo test -p carrick-runtime --lib native_prepared_resume -- --nocapture
```

Expected: the fresh process always calls `load_native_execve_image`, so the prepared cases fail.

- [ ] **Step 3: Split the fresh resume path at the capsule record**

In `resume_guest_from_capsule`, keep dispatcher/rootfs/process/fd restoration first. Then branch once:

```rust
let resumed = match guest.prepared_image {
    Some(record) => ResumedImage::Prepared(validate_for_resume(record)?),
    None => ResumedImage::Legacy(load_native_execve_image(
        &dispatcher,
        &guest.resolved_path,
        argv.clone(),
        env.clone(),
        &plan,
    )?),
};
```

Prepared validation must happen before `reset_memory_state_on_execve` and before any mapping side effect. Legacy keeps the current resolved-path reload and executable digest comparison unchanged.

- [ ] **Step 4: Factor common dispatcher reset and run-loop entry**

For both branches:

- reset memory and signal handlers once;
- publish the same executable identity/argv/env;
- obtain entry, initial SP, auxv, RO spans, and relocations from the selected image;
- enter one common `run_image_in_current_process` tail.

Add a `NativeImageSource` argument to the run function so it chooses `map_for_plan` or `map_prepared_for_plan` without duplicating namespace, signal, timer, `/proc`, reporter, or thread-runtime setup.

Close the prepared fd after mapping succeeds. Let `ValidatedPreparedImage` ownership close it on every error.

- [ ] **Step 5: Add a deterministic exact-byte substitution test**

In the runtime test module, create a temporary executable source containing marker A, load it through the ordinary preflight helper, and build a prepared artifact. Atomically replace the same path with valid marker-B bytes before calling the resume selector. Assert that the prepared branch maps marker A and the injected loader counter stays zero. Run the same setup with `prepared_image: None` as the red control and assert the legacy branch observes the replacement/digest failure.

This test must call the real prepared validator and mapper in a forked test process; the only injected seam is a loader invocation counter. Do not add a production environment-variable failpoint or a private CLI command.

- [ ] **Step 6: Build, sign, and run focused live correctness**

Run:

```bash
just build
strings target/release/carrick | rg 'prepared-validate|prepared-map'
otool -l target/release/carrick | rg dof_carrick
cargo test -p carrick-cli --test conformance \
  native_conformance_dsr_fork_exec_can_create_thread -- --exact --nocapture
cargo test -p carrick-runtime --lib \
  native_prepared_resume_ignores_changed_source_path -- --exact --nocapture
```

Expected: signed binary contains new stage strings and DOF; fork-exec-pthread and the forked exact-byte substitution test pass.

- [ ] **Step 7: Repeat the post-exec thread gate**

Run the signed `forkexecpthread` gate five times with unique run ids, cleaning each id afterward. Require all six success fields and zero leftover Carrick descendants every time.

- [ ] **Step 8: Commit activation**

Run:

```bash
git add crates/carrick-runtime/src/native_darwin.rs \
  crates/carrick-runtime/src/native_exec_capsule.rs \
  crates/carrick-runtime/src/native_prepared_image.rs
git commit -m "fix(native): resume the exact prepared exec image" -m "Select the prepared sparse image after PID-preserving host self-reexec and keep legacy digest-bound reload only for pre-exec artifact fallback. Prepared validation and mapping failures are fatal after the point of no return, so a changed guest path can never substitute different executable bytes.

Verified: red-first prepared/legacy path-substitution control, five signed forkexecpthread repetitions, adoption tests, and the native DOF/codesign checks pass.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 7: Add stable lifecycle observability and reconciliation

**Files:**

- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `scripts/dtrace/dsr-fork.d`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

- [ ] **Step 1: Write red ordinal and parser tests**

Append, never renumber, six lifecycle ordinals:

```text
39 HostSelfReexecPreparedBuildBegin
40 HostSelfReexecPreparedBuildEnd
41 HostSelfReexecPreparedValidateBegin
42 HostSelfReexecPreparedValidateEnd
43 HostSelfReexecPreparedMapBegin
44 HostSelfReexecPreparedMapEnd
```

Extend uniqueness tests and `trace_profile` fixtures to require sample names:

```text
host-self-reexec-prepared-build
host-self-reexec-prepared-validate
host-self-reexec-prepared-map
```

Add a parser fixture with one prepared lifecycle and zero image-load rows; another fallback fixture must contain image-load and zero prepared-map rows.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
cargo test -p carrick-observability dsr_cache_lifecycle -- --nocapture
cargo test -p carrick-cli --test trace_profile -- --nocapture
```

Expected: absent ordinals and sample parsers fail.

- [ ] **Step 3: Emit paired probes at exact boundaries**

Emit build begin/end around sparse artifact preparation, validate begin/end around fresh checksum/metadata validation, and map begin/end around file-backed image extent mapping. Ensure every error path either emits its matching end or is counted as incomplete by DTrace; do not emit success end before the operation succeeds.

Keep `HostSelfReexecImageLoadBegin/End` only around the legacy reload branch.

- [ ] **Step 4: Pair and reconcile in `dsr-fork.d`**

Track each new pair by pid/tid, emit nanosecond samples, incomplete rows, and aggregate counts. Reconcile prepared validate/map inside the existing host-self-reexec restore interval without double-counting outer time. Preserve the `DSRPROF1` format and all old sample names.

- [ ] **Step 5: Run parser and script gates**

Run:

```bash
cargo test -p carrick-observability dsr_cache_lifecycle -- --nocapture
cargo test -p carrick-cli --test trace_profile -- --nocapture
cargo test -p carrick-cli trace_profile -- --nocapture
rg -n 'prepared-(build|validate|map)' scripts/dtrace/dsr-fork.d \
  crates/carrick-cli/src/trace_profile.rs
```

Expected: ordinal uniqueness and both prepared/fallback fixtures pass.

- [ ] **Step 6: Build signed and capture the green lifecycle profile**

Run `just build`, then the exact Task 1 DTrace command into `target/conformance/native-prepared-image/green/` with a new run id.

Expected for the canonical 220-iteration prepared run:

- 220 prepared-build samples;
- 220 prepared-validate samples;
- 220 prepared-map samples;
- zero fresh image-load samples;
- zero incomplete pairs;
- zero DTrace drops; and
- natural target completion.

- [ ] **Step 7: Commit observability**

Run:

```bash
git add crates/carrick-observability/src/probes.rs \
  crates/carrick-runtime/src/native_exec_capsule.rs \
  crates/carrick-runtime/src/native_darwin.rs \
  scripts/dtrace/dsr-fork.d crates/carrick-cli/src/trace_profile.rs \
  crates/carrick-cli/tests/trace_profile.rs
git commit -m "diagnostics(native): trace prepared self-reexec phases" -m "Expose stable paired lifecycle phases for prepared artifact construction, fresh validation, and file-backed mapping while leaving image-load samples exclusive to fallback. The dsr-fork profile now proves which path ran and reconciles every prepared iteration without using traced magnitudes as the wall-time gate.

Verified: ordinal/parser fixtures pass and a signed 220-iteration trace records all prepared phases with zero fresh loads, incomplete pairs, or drops.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 8: Run the complete signed correctness ladder

**Files:**

- Modify only if a real regression is found: implementation and the narrowest existing/new test
- Evidence: `target/conformance/native-prepared-image/correctness/` (do not commit)
- Modify: `docs/native-default-conformance-campaign.md`

- [ ] **Step 1: Rebuild every runnable artifact from current sources**

Run:

```bash
scripts/build-probes.sh --native-pie
just build
just fmt-check
```

Record source SHA, Carrick SHA/CDHash, and static/dynamic probe hashes. Confirm the signed binary contains a new prepared-image stage marker.

- [ ] **Step 2: Run static and dynamic PIE exec reducers**

Run serially under native16k and linux4k where supported:

- direct exec;
- fork+exec;
- dynamic interpreter exec;
- shebang argv preservation;
- `forkexecpthread`;
- `vforkexecthread`;
- non-leader exec;
- exec-surviving descriptors;
- credentials/groups/umask/ignored signals/rlimits; and
- closed stdio.

Use the existing exact tests/probes discovered with:

```bash
rg -n 'forkexecpthread|vforkexecthread|shebang|non.leader.*exec|exec.*fd|closed.*stdio|rlimit|umask' \
  crates/carrick-cli/tests conformance-probes/src/bin
```

Do not invent a blanket test name. Run each exact discovered gate and store output.

- [ ] **Step 3: Run the complete native probe gate from repo root**

Run:

```bash
cargo test -p carrick-cli --test conformance conformance_probes -- --nocapture
```

Expected: the gate discovers real probe binaries and does not finish in the false-green ~0.04 s skip shape. Inspect binary logs with `rg -a`.

- [ ] **Step 4: Run focused ecosystem lanes serially**

Run these cached-oracle commands serially:

```bash
just conformance full --lane macos-native-dsr --workers 1 \
  --suite node-app-smoke --suite node-v8-smoke \
  --jsonl target/conformance/native-prepared-image/correctness/node.jsonl
just conformance full --lane macos-native-dsr --workers 1 \
  --suite go-build --suite go-runtime --suite go-sync \
  --jsonl target/conformance/native-prepared-image/correctness/go.jsonl
just conformance full --lane macos-native-dsr --workers 1 \
  --suite cpython-subprocess --suite cpython-threading \
  --jsonl target/conformance/native-prepared-image/correctness/cpython.jsonl
```

The harness completes Carrick work before any cache miss triggers Docker. Confirm no Carrick process remains before allowing an uncached oracle phase to start. Require no new content mismatch, crash, or timeout and no wall-time regression above the design's 2% rule after a variance-aware repeat.

- [ ] **Step 5: Run workers=4 smoke**

Run the established native smoke lane with workers=4 after the focused lanes are green:

```bash
just conformance smoke --lane macos-native-dsr --workers 4 --force \
  --jsonl target/conformance/native-prepared-image/correctness/smoke-workers4.jsonl
```

Classify every non-match against the existing campaign ledger; do not bless new failures as old debt.

- [ ] **Step 6: Fix any regression root-first**

For each regression:

1. reduce it to a fast reproducer;
2. check the Docker oracle in a separate phase;
3. test the signed parent binary;
4. add a deterministic red-first test;
5. fix the root cause without a shell/backend workaround; and
6. rerun the narrow reducer plus the affected ladder rung.

Commit each independent fix separately with exact verification receipts.

- [ ] **Step 7: Run the local code-quality gate**

Run:

```bash
just ci
```

Expected: format, clippy, typed-domain lint, deny, matrix drift, check, docs, unit, and integration tests all pass sequentially.

- [ ] **Step 8: Update measured campaign state**

Add ledger rows for every signed correctness rung and its exact result. Keep the two approved esoteric CPython fork-without-exec pthread gaps explicit; do not relabel them as prepared-image failures or successes.

---

## Task 9: Run the ABBA performance gate and make the promotion decision

**Files:**

- Create: `scripts/perf/analyze-native-prepared-image.py`
- Create: `docs/perf-results/2026-07-13-native-prepared-image.jsonl`
- Modify: `docs/native-default-conformance-campaign.md`
- Verify: `conformance-probes/src/bin/perf_fork.rs`
- Verify: `conformance-probes/src/bin/perf_fork_exec.rs`

- [ ] **Step 1: Add a red analyzer fixture**

Create a small Python `unittest` fixture inside `scripts/perf/analyze-native-prepared-image.py` or an adjacent test file. Feed known baseline/candidate samples and assert deterministic seeded-bootstrap outputs for:

- median ratio;
- 95% upper ratio;
- failed iteration count;
- promotion pass/fail; and
- the fork-only 1.02 upper-bound rule.

Run:

```bash
python3 scripts/perf/analyze-native-prepared-image.py --self-test
```

Expected RED before implementing the analyzer.

- [ ] **Step 2: Implement the dependency-free analyzer**

Use Python stdlib only (`json`, `random`, `statistics`). Seed the bootstrap explicitly and emit one JSON object containing raw sample arrays, medians, ratios, confidence bounds, sample count, seed, artifact hashes, source SHAs, and boolean gate results. Reject missing/failed iterations rather than silently filtering them.

- [ ] **Step 3: Prepare signed baseline and candidate binaries**

Use two isolated source states: the signed parent of Task 6 activation as baseline and current candidate. Build and sign each with `just build`, copy each binary into an untracked evidence directory, and record SHA/CDHash. Verify both embed the exact expected source marker; do not compare a stale shared `target/release/carrick`.

- [ ] **Step 4: Run fixed ABBA order**

For both `perf_fork` and `perf_fork_exec`:

- discard one warm-up per binary;
- record at least five repetitions per role;
- run in fixed `A B B A A B B A A B` order for five samples per role (extend by complete `A B B A` blocks when collecting more);
- use a unique run id per process;
- require the probe's complete iteration count and zero failures; and
- keep Docker stopped throughout the Carrick comparison.

Capture host model, macOS version, CPU count, AC/battery state, source and binary identity, command, stdout, and elapsed wall time.

- [ ] **Step 5: Analyze the candidate**

Run the seeded analyzer and require:

- `perf_fork_exec` candidate/baseline p50 ratio `<= 0.90`;
- fork-exec bootstrap 95% ratio upper bound `< 1.0`;
- `perf_fork` bootstrap 95% ratio upper bound `<= 1.02`;
- zero failed spawn iterations; and
- no focused ecosystem regression above 2% unless its confidence interval includes parity and a repeat clears it.

- [ ] **Step 6: Run Docker only for ratio context**

After all Carrick ABBA processes have stopped, run the exact-source probes under native arm64 Docker serially. This establishes the remaining native/Linux ratio; it is not mixed into the A/B confidence test.

- [ ] **Step 7: Choose one honest branch**

If every threshold passes, retain the prepared path and label it promoted. If correctness passes but the 10% wall gate fails, use the untraced and DTrace phase evidence to revise the representation; do not bless it. If revision cannot clear the gate without weakening invariants, revert the activation commits while retaining diagnostic/test improvements and record the negative result.

- [ ] **Step 8: Commit analyzer and measured result**

Run:

```bash
git add scripts/perf/analyze-native-prepared-image.py \
  docs/perf-results/2026-07-13-native-prepared-image.jsonl \
  docs/native-default-conformance-campaign.md
git commit -m "diagnostics(native): gate prepared-image spawn latency" -m "Record a reproducible signed ABBA comparison for native fork and fork-exec with seeded bootstrap confidence bounds, exact artifact provenance, and separate Docker ratio context. The campaign ledger promotes or rejects prepared-image adoption from measured wall time and workload stability rather than traced phase magnitudes.

Verified: analyzer self-tests pass; all recorded probe iterations complete; the checked-in result states each promotion threshold and its measured outcome.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Task 10: Resume full native laddering from the promoted state

**Files:**

- Modify: `docs/native-default-conformance-campaign.md`
- Modify only from real findings: relevant runtime/probe/baseline files
- Evidence: `target/conformance/native-full-bless/` (do not commit raw host-specific output unless the repo convention requires a curated result)

- [ ] **Step 1: Re-read the campaign ledger and select the next unblessed rung**

Do not restart already measured Node/Go/CPython work. Begin from workers=4 smoke and the outstanding Go load/time cases identified in the ledger, then move to full language/LTP lanes.

- [ ] **Step 2: Run Carrick-only full native phases**

Run:

```bash
just conformance full --lane macos-native-dsr --workers 4 --force \
  --jsonl target/conformance/native-full-bless/candidate.jsonl
```

The harness assigns and reaps unique per-suite run ids; do not override them with an inherited `CARRICK_RUN_ID`. Keep Carrick and Docker phases separate and capture source/binary/probe/cache provenance.

- [ ] **Step 3: Classify and fix every blocker**

Prioritize crashes, hangs, load sensitivity, pathological latency, and real ecosystem failures over esoteric parity. Keep every compromise explicit and bounded; never turn a current MATCH into an accepted gap.

- [ ] **Step 4: Refresh the Docker oracle only when required**

Use the committed cache for stable declarations. If the suite declaration changed or a canonical refresh is required, run Docker in its own phase and commit a legitimate cache rewrite only when images and platform are authoritative.

- [ ] **Step 5: Run exhaustive native bless**

Require the full planned lane matrix to complete without unclassified crash/hang/load failure. Separate exact MATCH, approved known gap, flaky-with-evidence, and unsupported-esoteric rows. Then run the unfiltered blessing pass:

```bash
just conformance full --lane macos-native-dsr --workers 4 --force --bless \
  --jsonl target/conformance/native-full-bless/blessed.jsonl
just matrix
```

- [ ] **Step 6: Run final gates and update controller state**

Run:

```bash
just ci
just check-matrix
git status --short
```

Update `docs/native-default-conformance-campaign.md` with final measured counts, artifacts, known gaps, and next near-parity work. Mark the overarching goal complete only after the exhaustive native run is genuinely blessed and no required work remains.
