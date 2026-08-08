# Tier D Node and Python Default Path — Wave 1 Implementation Plan

**Wave-1 status:** COMPLETE on signed `2fcf3906` (2026-08-07). The old
`0x38764d52` refusal and `BlockingRecordLock` leave are closed; full serialized
`just ci` passed. Task 6 is the measured Wave-2 continuation.

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two current, independently proven Tier-D blockers shared by
the Node/CPython campaign—the reserved AArch64 word refusal and CPython's
blocking record-lock leave—then produce a signed current-HEAD recensus that
authoritatively selects Wave 2.

**Architecture:** Keep `bad64` as the decoded-instruction and operand authority,
but admit decoder failures only when a small ARM-encoding-family validator
independently proves the word architecturally unallocated. Service record locks
on the calling Tier-D host pthread after dispatch releases subsystem locks,
using the same shared driver as the native DSR loop. Re-run the real Node and
CPython workloads after each change; do not pre-implement the next blocker.

**Tech Stack:** Rust 2024 workspace, `bad64`, Darwin/AArch64 native16k Tier D,
Carrick differential conformance harness, native-arm64 Docker oracle, signed
release Carrick binary.

## Global Constraints

- Governing design:
  `docs/superpowers/specs/2026-08-07-tier-d-node-python-default-design.md`.
- The active product goal remains Tier D default-on plus canonical Node and
  CPython no more than 2.0x Docker; this Wave-1 plan is not goal completion.
- Preserve the unrelated untracked `proposed-plan.md` exactly.
- No word-specific whitelist, code/data guess, silent mid-run Tier-T fallback,
  unconditional debug printing, or guest-visible semantic relaxation.
- Carrick and Docker never run concurrently. Stamp a unique `CARRICK_RUN_ID`
  and reap only that ID.
- `CARRICK_TIER_CENSUS` is a file path, not a boolean. Write it under
  `target/conformance/`; never set it to `1`.
- Build the runnable binary with `just build`, verify codesign, and record its
  SHA-256 before every live acceptance run.
- Red-first for every implementation. Retain only current-HEAD results; keep
  measurement distinct from projection.
- Each task ends in a narrow logical commit. Do not stage unrelated dirt.

---

### Task 1: Commit the current Wave-1 baseline

**Files:**

- Create: `docs/perf-results/2026-08-07-tier-d-node-python-baseline.md`
- Modify: `handoff.md`

**Interfaces:**

- Consumes: signed current-HEAD binary and the committed Docker oracle cache.
- Produces: the immutable pre-fix correctness/performance table and exact first
  blocker used by Tasks 2–4.

- [x] **Step 1: Verify the source and dirt boundary**

Run:

```bash
git status --short --branch
git rev-parse HEAD
shasum -a 256 target/release/carrick
codesign --verify --verbose=2 target/release/carrick
```

Expected: only `proposed-plan.md` is unrelated dirt; HEAD includes the design
commit; codesign succeeds.

- [x] **Step 2: Write the durable baseline**

Create the evidence document with these exact measured rows from the signed
`3e88dd8a` baseline (binary SHA-256
`287faa2572ce0671a982be8623e30c35f0ac0603527a4002a8b5b1dcf202be8a`):

```text
node-app-smoke       MATCH, Node scan-refused 0x38764d52, 19.68x
node-v8-smoke        MATCH, Node scan-refused 0x38764d52, 23.84x
cpython-fcntl        CARRICK_CRASH after 4/4, BlockingRecordLock, 11.59x
cpython-glob         MATCH 15/15, direct, 6.30x
cpython-json         MATCH 173/173, direct, 1.05x
cpython-math         MATCH 76/76, direct, 2.46x
cpython-subprocess   Empty, libcrypto window refusal 0x38764d52
cpython-threading    Empty, libcrypto window refusal 0x38764d52
```

Include the exact conformance commands, image tags, Node and libcrypto
disassembly/mapping-symbol evidence from design §2.1, and the prior controlled
CPython Tier-T 22.1x versus Tier-D 8.0x result as historical mechanism evidence.

- [x] **Step 3: Advance the controller without erasing history**

Add a new dated top section to `handoff.md` that names this campaign, links the
design and evidence, states the two Wave-1 blockers, and explicitly supersedes
the old instruction to return to broad Task 12 while leaving the older text as
history.

- [x] **Step 4: Validate the documents**

Run:

```bash
git diff --check
rg -n 'T[B]D|T[O]DO|F[I]XME|CARRICK_TIER_CENSUS=1' \
  docs/perf-results/2026-08-07-tier-d-node-python-baseline.md handoff.md
```

Expected: `git diff --check` succeeds; the search returns no incomplete marker
or incorrect census setting.

- [x] **Step 5: Commit**

```bash
git add handoff.md docs/perf-results/2026-08-07-tier-d-node-python-baseline.md
git commit -m "docs(native): record Tier D Node and Python baseline"
```

---

### Task 2: Admit independently proven unallocated load/store words

**Files:**

- Modify: `crates/carrick-native-darwin/src/direct.rs:1207-1218`
- Modify: `crates/carrick-native-darwin/src/direct.rs:1318-1365`
- Test: `crates/carrick-native-darwin/src/direct.rs:3424-3445`
- Test: `crates/carrick-native-darwin/src/direct.rs:4291-4309`

**Interfaces:**

- Consumes: raw AArch64 instruction word after `bad64::decode` fails.
- Produces: `word_is_proven_unallocated(word: u32) -> bool`, initially true
  only for unallocated encodings in the load/store register-offset family.

- [x] **Step 1: Add the red load-time and exec-window tests**

Add these tests beside the existing undecodable-word tests:

```rust
#[test]
fn scan_accepts_proven_unallocated_load_store_word_with_x18_bits() {
    let unallocated = 0x3876_4d52;
    let elf = elf_with_code(&[unallocated, movz(8, 93, 0), SVC_0]);
    assert!(
        matches!(scan_eligibility(&elf).expect("scan runs"), Ok(1)),
        "a source-proven unallocated encoding cannot access x18"
    );
}

#[test]
fn exec_window_accepts_proven_unallocated_load_store_word_with_x18_bits() {
    let file = elf_with_code(&[0x3876_4d52, movz(8, 93, 0), SVC_0]);
    let group = DirectLoadGroup::load(&fixture_elf(), record_only)
        .expect("load main")
        .expect("eligible");
    assert!(
        group
            .map_exec_file_window(&file, 0, 0x2000)
            .expect("scan runs")
            .is_ok(),
        "the same proof applies at the runtime executable-window boundary"
    );
}
```

- [x] **Step 2: Run the tests and verify red**

Run:

```bash
cargo test -p carrick-native-darwin \
  scan_accepts_proven_unallocated_load_store_word_with_x18_bits -- --nocapture
cargo test -p carrick-native-darwin \
  exec_window_accepts_proven_unallocated_load_store_word_with_x18_bits -- --nocapture
```

Expected: both fail because `scan_executable_words` returns
`DirectIneligible::UndecodableText` for `0x38764d52`.

- [x] **Step 3: Add family-mask and mutation tests**

Add a direct classifier test:

```rust
#[test]
fn unallocated_load_store_register_offset_proof_is_mask_exact() {
    assert!(word_is_proven_unallocated(0x3876_4d52));
    assert!(
        !word_is_proven_unallocated(0x3876_4952),
        "ldrb w18, [x10, w22, uxtw] is allocated and must take the veneer path"
    );
    assert!(
        !word_is_proven_unallocated(0xffff_fff2),
        "unrelated undecodable words remain fail-closed"
    );
}
```

Run it before implementation and confirm it fails to compile because the
classifier does not exist.

- [x] **Step 4: Implement the minimal source-bound classifier**

Place this beside `word_could_name_x18`:

```rust
/// A decoder failure is safe to leave untouched only when the encoding is
/// independently proven architecturally unallocated. This is the A64
/// load/store register-offset family: bits 29:27=111, bits 25:24=00 and
/// bit 21=1 select the family; bits 11:10 are fixed to 0b10. Any other value
/// in bits 11:10 is unallocated (Arm ARM DDI0487, "Load/store register
/// (register offset)").
fn word_is_proven_unallocated(word: u32) -> bool {
    const FAMILY_MASK: u32 = 0x3b20_0000;
    const FAMILY: u32 = 0x3820_0000;
    const FIXED_11_10_MASK: u32 = 0x0000_0c00;
    const FIXED_11_10: u32 = 0x0000_0800;

    (word & FAMILY_MASK) == FAMILY && (word & FIXED_11_10_MASK) != FIXED_11_10
}
```

In `scan_executable_words`, handle the independent proof before the existing
x18 refusal:

```rust
Err(_) if word_is_proven_unallocated(word) => {}
Err(_) if word_could_name_x18(word) => {
    return Err(DirectIneligible::UndecodableText { vaddr: site, word });
}
Err(_) => {}
```

Do not alter `patch_executable_words`: the unallocated word stays untouched,
which preserves SIGILL if execution ever reaches it.

- [x] **Step 5: Run focused and crate gates**

Run:

```bash
cargo test -p carrick-native-darwin proven_unallocated -- --nocapture
cargo test -p carrick-native-darwin unallocated_load_store_register_offset -- --nocapture
cargo test -p carrick-native-darwin --lib
just fmt-check
just clippy
```

Expected: new tests pass; existing suspicious `0xfffffff2` tests still refuse;
the full crate and lint gates pass.

- [x] **Step 6: Commit**

```bash
git add crates/carrick-native-darwin/src/direct.rs
git commit -m "fix(native): admit proven-unallocated Tier D words"
```

---

### Task 3: Rebuild, recensus, and bind the next blocker

**Files:**

- Modify: `docs/perf-results/2026-08-07-tier-d-node-python-baseline.md`
- Modify: `handoff.md`
- Runtime artifacts:
  `target/conformance/tierd-wave1-encoding-{fast,process}.jsonl`
- Runtime artifact: `target/conformance/tierd-wave1-encoding-census.log`

**Interfaces:**

- Consumes: Task 2 classifier and signed release binary.
- Produces: proof that Node main and CPython libcrypto pass the former scan, plus
  the exact next Tier-D leave/crash for each workload.

- [x] **Step 1: Build, sign, and bind the binary**

Run:

```bash
just build
codesign --verify --verbose=2 target/release/carrick
git rev-parse HEAD
shasum -a 256 target/release/carrick
strings -a target/release/carrick | rg 'CARRICK_NATIVE_DIRECT|native tier decision'
```

Expected: signed current-HEAD binary with the Tier-D marker present.

- [x] **Step 2: Run the fast Node/CPython phase serially**

Run from the repository root:

```bash
CARRICK_RUN_ID=tierd-wave1-encoding-fast \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-wave1-encoding-census.log \
just conformance-native smoke --workers 1 \
  --suite node-app-smoke \
  --suite node-v8-smoke \
  --suite cpython-fcntl \
  --suite cpython-glob \
  --suite cpython-json \
  --suite cpython-math \
  --jsonl target/conformance/tierd-wave1-encoding-fast.jsonl
```

Expected: there is no `scan-refused ... 0x38764d52`; Node now records
`direct-enter`. `cpython-fcntl` may remain red until Task 4.

- [x] **Step 3: Run the process/thread phase serially**

```bash
CARRICK_RUN_ID=tierd-wave1-encoding-process \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-wave1-encoding-census.log \
just conformance-native smoke --workers 1 \
  --suite cpython-subprocess \
  --suite cpython-threading \
  --jsonl target/conformance/tierd-wave1-encoding-process.jsonl
```

Expected: the former libcrypto `mmap(PROT_EXEC, fd)` refusal is absent. Any new
leave is named and becomes Wave 2 evidence; do not call an Empty verdict a
successful scan without the census.

- [x] **Step 4: Audit census closure**

Run:

```bash
rg -n 'scan-refused|scan-error|direct-enter|direct-leave|direct-exit' \
  target/conformance/tierd-wave1-encoding-census.log
jq -c '{name,verdict,carrick,perf}' \
  target/conformance/tierd-wave1-encoding-fast.jsonl \
  target/conformance/tierd-wave1-encoding-process.jsonl
```

Expected: every workload has tier events; zero-event output is a failed run.

- [x] **Step 5: Record and commit the result**

Append a dated Wave-1 encoding section to the evidence and handoff with source
commit, binary hash, commands, image identities, exact tier events, verdicts,
and the next named blocker. Do not report wrapper elapsed values as the
canonical product scoreboard.

```bash
git add handoff.md docs/perf-results/2026-08-07-tier-d-node-python-baseline.md
git commit -m "docs(native): record Tier D encoding recensus"
```

---

### Task 4: Service Tier-D blocking record locks

**Files:**

- Modify: `crates/carrick-runtime/src/direct_runner.rs:1372-1767`
- Test: `crates/carrick-runtime/src/direct_runner.rs:3102-3195`

**Interfaces:**

- Consumes: `DispatchOutcome::BlockingRecordLock` and
  `dispatch::drive_blocking_record_lock(&BlockingRecordLock)`.
- Produces: `DirectRunner::service_blocking_record_lock` mapping the driver's
  `Returned`/`Errno` outcome back to a Tier-D `ServiceVerdict`.

- [x] **Step 1: Reconfirm the red integration gate**

Run with a fresh census path:

```bash
CARRICK_RUN_ID=tierd-record-lock-red \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-record-lock-red.census.log \
just conformance-native smoke --workers 1 --suite cpython-fcntl \
  --jsonl target/conformance/tierd-record-lock-red.jsonl
```

Expected: `CARRICK_CRASH`/incomplete CPython count and a named
`direct-leave ... BlockingRecordLock`.

- [x] **Step 2: Add a red unit test for the direct-runner adapter**

Add this test in the direct-runner test module:

```rust
#[test]
fn blocking_record_lock_returns_through_the_tier_d_boundary() {
    use std::os::fd::AsRawFd as _;

    let file = tempfile::tempfile().expect("temp file");
    let lock = crate::dispatch::BlockingRecordLock::new(
        file.as_raw_fd(),
        libc::F_SETLKW,
        0,
        0,
        libc::F_WRLCK as i16,
        libc::SEEK_SET as i16,
    )
    .expect("pin lock fd");
    let runner = DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));

    assert!(matches!(
        runner.service_blocking_record_lock(25, &lock),
        ServiceVerdict::Resume(0)
    ));
}
```

- [x] **Step 3: Run the unit test and verify red**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime \
  blocking_record_lock_returns_through_the_tier_d_boundary -- --nocapture
```

Expected: compile failure because `service_blocking_record_lock` does not yet
exist.

- [x] **Step 4: Implement the adapter and dispatch arm**

Add the method:

```rust
fn service_blocking_record_lock(
    &self,
    syscall: u64,
    lock: &crate::dispatch::BlockingRecordLock,
) -> ServiceVerdict {
    match crate::dispatch::drive_blocking_record_lock(lock) {
        DispatchOutcome::Returned { value } => ServiceVerdict::Resume(value),
        DispatchOutcome::Errno { errno } => ServiceVerdict::Resume(errno.guest_retval()),
        other => {
            self.end_process(DirectRunOutcome::Unsupported {
                syscall,
                outcome: format!("blocking record-lock driver returned {other:?}"),
            });
            ServiceVerdict::Leave
        }
    }
}
```

Add this match arm before `Ok(other)` in `service_syscall`:

```rust
Ok(DispatchOutcome::BlockingRecordLock(lock)) => {
    return self.service_blocking_record_lock(number, &lock);
}
```

The helper runs only after `dispatch_threaded` returned the typed outcome and
released subsystem locks. Do not hold the Tier-D registry lock around the host
`fcntl`.

- [x] **Step 5: Run unit and integration green gates**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime \
  blocking_record_lock_returns_through_the_tier_d_boundary -- --nocapture
just build
CARRICK_RUN_ID=tierd-record-lock-green \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-record-lock-green.census.log \
just conformance-native smoke --workers 1 --suite cpython-fcntl \
  --jsonl target/conformance/tierd-record-lock-green.jsonl
just fmt-check
just clippy
```

Expected: unit test passes; `cpython-fcntl` matches its 8/8 Docker oracle with
no `BlockingRecordLock` leave; lint gates pass.

- [x] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/direct_runner.rs
git commit -m "fix(native): service Tier D blocking record locks"
```

---

### Task 5: Close Wave 1 and authorize Wave 2 from evidence

**Files:**

- Modify: `docs/perf-results/2026-08-07-tier-d-node-python-baseline.md`
- Modify: `handoff.md`
- Modify: `docs/superpowers/plans/2026-08-07-tier-d-node-python-default.md`

**Interfaces:**

- Consumes: Tasks 2–4 code and signed live results.
- Produces: a reviewed Wave-1 closeout and an exact Wave-2 task replacing any
  now-stale expected blocker.

- [x] **Step 1: Run the combined focused acceptance gate**

```bash
just build
CARRICK_RUN_ID=tierd-wave1-final \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-wave1-final.census.log \
just conformance-native smoke --workers 1 \
  --suite node-app-smoke \
  --suite node-v8-smoke \
  --suite cpython-fcntl \
  --suite cpython-glob \
  --suite cpython-json \
  --suite cpython-math \
  --suite cpython-subprocess \
  --suite cpython-threading \
  --jsonl target/conformance/tierd-wave1-final.jsonl
```

An overall non-zero exit is acceptable only for newly exposed, named blockers;
the two Wave-1 failure signatures must be absent.

- [x] **Step 2: Run host regression gates**

```bash
RUST_TEST_THREADS=1 just ci
```

Expected: pass. If it fails, attribute the failure against pre-change HEAD
before modifying runtime code.

- [x] **Step 3: Review the exact Wave-1 range**

```bash
git log --oneline --decorate a1c7fe19..HEAD
git diff --check a1c7fe19..HEAD
git status --short
```

Expected: only narrow Wave-1 commits; `proposed-plan.md` remains untouched.

- [x] **Step 4: Replace expectation with the measured Wave-2 blocker**

Use the final census and fatal/event-ring evidence to amend this plan with one
new task containing:

- the exact workload and image;
- the exact syscall/executable transition or fatal record;
- a deterministic red fixture;
- the Tier-T/HVF semantic reference;
- the proposed Darwin/Tier-D mechanism;
- focused and broad acceptance commands.

If Node reaches an anonymous executable transition, write the task against the
observed mmap/mprotect flags and V8 mapping shape. If CPython reaches
multithreaded fork, write it against the observed clone flags and live sibling
count. Do not retain both as guesses.

- [x] **Step 5: Commit Wave-1 closeout**

```bash
git add handoff.md \
  docs/perf-results/2026-08-07-tier-d-node-python-baseline.md \
  docs/superpowers/plans/2026-08-07-tier-d-node-python-default.md
git commit -m "docs(native): close Tier D Node and Python wave 1"
```

Wave 2 then continues under the governing design until the complete native
smoke, default flip, canonical workload harnesses, and no-more-than-2.0x
product gates are all proven.

---

### Task 6: Admit the measured reserved A64 major group

**Wave:** 2

**Files:**

- Modify: `crates/carrick-native-darwin/src/direct.rs`
- Test: `crates/carrick-native-darwin/src/direct.rs`
- Modify after live proof:
  `docs/perf-results/2026-08-07-tier-d-node-python-baseline.md`
- Modify after live proof: `handoff.md`

**Exact red workload and images:**

- `node-app-smoke` and `node-v8-smoke` in
  `localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`, manifest digest
  `sha256:50d22d4ee6776c57f6ad06ecc82e8219a9e5026e327aebab5847e17f61d46cbd`;
- `cpython-subprocess` and `cpython-threading` in
  `localhost:5050/cpython-test:3.12.13`, manifest digest
  `sha256:4af881c7d613f2b1e4b507a686387f8c804c1f259c3dfd06576ad534b193c286`.

The signed `2fcf3906` census records Node load-time refusal at virtual address
`0x1c4a76c` and CPython's syscall-222 `mmap(PROT_EXEC, fd)` window refusal at
file offset `0x2ce8b0`; both name raw word `0x61206272`.

**Semantic reference:** Tier T translates reached basic blocks, and HVF runs
the guest's control flow, so neither tries to decode inline data after a
`ret`. Tier D scans the whole executable section before direct entry and must
therefore distinguish architecturally unallocated words independently. The
Arm ARM DDI0487 "A64 instruction set encoding" main table reserves bit 31=`0`
with top-level `op0` bits 28:25=`0b0000`. `0x61206272` is in exactly that
group. Bit 31=`1` selects SME and must remain outside the proof. A one-bit
mutation, `0x69206272`, sets bit 27 and is allocated `stgp x18, x24,
[x19, #-1024]`; both bad64 0.12 and GNU AArch64 binutils 2.45 decode it. That
neighbor must stay outside the proof and on the existing x18 path.

- [x] **Step 1: Add deterministic red boundary and mask tests**

Add load-time and executable-window tests using `0x61206272`, parallel to the
Wave-1 corpus regressions. Add classifier assertions that:

```rust
assert!(word_is_proven_unallocated(0x6120_6272));
assert!(!word_is_proven_unallocated(0x6920_6272));
let allocated = bad64::decode(0x6920_6272, 0).expect("allocated STGP neighbor");
assert!(instruction_names_x18(&allocated));
assert!(!word_is_proven_unallocated(0x8080_0012));
bad64::decode(0x8080_0012, 0).expect("allocated SME control");
assert!(!word_is_proven_unallocated(0xffff_fff2));
```

- [x] **Step 2: Run the new tests and verify red**

```bash
cargo test -p carrick-native-darwin reserved_major -- --nocapture
```

Expected: the boundary tests refuse `0x61206272` and the classifier assertion
is false before implementation.

- [x] **Step 3: Extend the source-bound classifier minimally**

Add the current Arm top-level reserved group before the existing load/store
register-offset proof:

```rust
const RESERVED_MAJOR_OP0_MASK: u32 = 0x9e00_0000;
if word & RESERVED_MAJOR_OP0_MASK == 0 {
    return true;
}
```

Do not accept other decoder failures, inspect ASCII, consume mapping symbols,
or alter `patch_executable_words`.

- [x] **Step 4: Run focused and full scanner gates**

```bash
cargo test -p carrick-native-darwin reserved_major -- --nocapture
cargo test -p carrick-native-darwin proven_unallocated -- --nocapture
cargo test -p carrick-native-darwin \
  scan_refuses_undecodable_text_only_when_it_could_name_x18 -- --nocapture
cargo test -p carrick-native-darwin --lib
just fmt-check
just clippy
```

Expected: both real boundary fixtures pass; the allocated STGP neighbor is not
classified unallocated; the unrelated suspicious word still refuses.

- [x] **Step 5: Commit the code boundary**

```bash
git add crates/carrick-native-darwin/src/direct.rs
git commit -m "fix(native): admit reserved A64 major-group words"
```

- [x] **Step 6: Build signed and recensus all eight campaign suites**

```bash
just build
codesign --verify --verbose=2 target/release/carrick
shasum -a 256 target/release/carrick
CARRICK_RUN_ID=tierd-wave2-reserved-major \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=/Volumes/CaseSensitive/carrick/target/conformance/tierd-wave2-reserved-major.census.log \
just conformance-native smoke --workers 1 \
  --suite node-app-smoke \
  --suite node-v8-smoke \
  --suite cpython-fcntl \
  --suite cpython-glob \
  --suite cpython-json \
  --suite cpython-math \
  --suite cpython-subprocess \
  --suite cpython-threading \
  --jsonl target/conformance/tierd-wave2-reserved-major.jsonl
```

Acceptance: no `0x61206272`, `0x38764d52`, or `BlockingRecordLock` leave;
`cpython-fcntl` stays 8/8 MATCH. An overall nonzero exit is acceptable only for
a newly exposed named blocker with nonempty census evidence.

- [x] **Step 7: Record the exact next blocker and commit evidence**

Append source/binary/image provenance, verdicts, and the next named lifecycle
event to the evidence and handoff. Do not interpret an Empty row or a Node
Tier-T fallback as performance. Commit with:

```bash
git add handoff.md docs/perf-results/2026-08-07-tier-d-node-python-baseline.md \
  docs/superpowers/plans/2026-08-07-tier-d-node-python-default.md
git commit -m "docs(native): record Tier D reserved-major recensus"
```

---

### Task 7: Admit the measured unallocated Advanced SIMD shift opcode

**Wave:** 2

**Files:**

- Modify: `crates/carrick-native-darwin/src/direct.rs`
- Test: `crates/carrick-native-darwin/src/direct.rs`
- Modify after live proof:
  `docs/perf-results/2026-08-07-tier-d-node-python-baseline.md`
- Modify after live proof: `handoff.md`

**Exact red workload and images:** the same four workload/image pairs as Task
6. Signed source `01f60b29` advances Node to virtual address `0x1c4a798` and
CPython's libcrypto executable window to file offset `0x2ce8dc`; both refuse
raw word `0x6f406f72`. The word is the final raw-x18 decoder failure in the
shared OpenSSL banner.

**Semantic reference:** Arm ARM DDI0487's "Advanced SIMD shift by immediate"
encoding fixes bit 31=`0`, bits 28:23=`0b011110`, bit 10=`1`, and requires
`immh` bits 22:19 to be nonzero. Inside that class, the opcode subspace with
bit 15=`0` and bit 11=`1` is architecturally unallocated. The measured word is
in that exact subspace. Clearing bit 11 gives allocated `0x6f406772`,
`sqshlu v18.2d, v27.2d, #0`; clearing bit 10 gives allocated `0x6f406b72`, an
Advanced SIMD element multiply-long instruction. Both controls name vector
register 18, not guest GPR x18, and must remain outside the proof.

- [x] **Step 1: Add deterministic red boundary and mask tests**

Add load-time and executable-window tests using `0x6f406f72`. Add a classifier
test which proves the measured word accepted, both one-bit allocated controls
rejected, both controls decoded by `bad64`, and `0xfffffff2` still rejected.

- [x] **Step 2: Run the new tests and verify red**

```bash
cargo test -p carrick-native-darwin advanced_simd_shift -- --nocapture
```

Expected: both boundaries refuse the measured word and the classifier
assertion is false before implementation.

- [x] **Step 3: Extend the source-bound classifier minimally**

Add the Arm class after the top-level reserved-major proof and before the
existing load/store proof:

```rust
const SIMD_SHIFT_IMMEDIATE_MASK: u32 = 0x9f80_0400;
const SIMD_SHIFT_IMMEDIATE: u32 = 0x0f00_0400;
const SIMD_SHIFT_IMMH_MASK: u32 = 0x0078_0000;
const SIMD_SHIFT_UNALLOCATED_OPCODE_MASK: u32 = 0x0000_8800;
const SIMD_SHIFT_UNALLOCATED_OPCODE: u32 = 0x0000_0800;

if (word & SIMD_SHIFT_IMMEDIATE_MASK) == SIMD_SHIFT_IMMEDIATE
    && (word & SIMD_SHIFT_IMMH_MASK) != 0
    && (word & SIMD_SHIFT_UNALLOCATED_OPCODE_MASK)
        == SIMD_SHIFT_UNALLOCATED_OPCODE
{
    return true;
}
```

Do not accept a specific ASCII word, infer code/data, or alter the patcher.

- [x] **Step 4: Run focused and full scanner gates**

```bash
cargo test -p carrick-native-darwin advanced_simd_shift -- --nocapture
cargo test -p carrick-native-darwin proven_unallocated -- --nocapture
cargo test -p carrick-native-darwin reserved_major -- --nocapture
cargo test -p carrick-native-darwin \
  scan_refuses_undecodable_text_only_when_it_could_name_x18 -- --nocapture
cargo test -p carrick-native-darwin --lib
just fmt-check
just clippy
```

- [x] **Step 5: Commit, build signed, and recensus the eight suites**

Commit only `direct.rs`, build through `just build`, verify codesign and
SHA-256, then run the Task-6 eight-suite command with run ID and artifact stem
`tierd-wave2-simd-shift`. Acceptance requires all three prior scanner words
and `BlockingRecordLock` to remain absent. The new census selects Task 8.

The post-census source audit also added a red allocated-SME control and
narrowed the Task-6 mask from `0x1e00_0000` to `0x9e00_0000` in `7501cfa0`.
This correctness correction must be present in every Task-8 build.

---

### Task 8: Admit the measured unallocated SIMD unprivileged-load/store class

**Wave:** 2

**Files:**

- Modify: `crates/carrick-native-darwin/src/direct.rs`
- Test: `crates/carrick-native-darwin/src/direct.rs`
- Modify after live proof:
  `docs/perf-results/2026-08-07-tier-d-node-python-baseline.md`
- Modify after live proof: `handoff.md`

**Exact red workload and images:** the Task-7 signed census advances both Node
images to virtual address `0x1c53e64` and both CPython process/thread runs to
libcrypto file offset `0x2e4be4`; all refuse `0xbcc3cad1`. In the unstripped
Node executable this is byte `0x64` of the 272-byte local object
`_vpsm4_ex_consts` at `0x1c53e00`. The stripped libcrypto contains the same
272 bytes at `0x2e4b80`; both ranges have SHA-256
`ab0963561f345b19c2db922b349d5960763ef10175c5ab391061006b46424cb0`.

**Semantic reference:** Arm ARM DDI0487 "Load/store register (unprivileged)"
fixes bits 29:27=`0b111`, bits 25:24=`0b00`, and bits 11:10=`0b10`. Its `V`
bit 26 is fixed to zero because this class has only general-register forms;
`V=1` is architecturally unallocated for every `size`, `opc`, immediate, base,
and target field. The measured word has `V=1`; raw bits 14:10 resemble x18
only because they are immediate/addressing bits in this class. Clearing bit 29
gives allocated `0x9cc3cad1`, `ldr q17, <literal>`, which must remain outside
the proof.

- [ ] **Step 1: Add deterministic red boundary and mask tests**

Add load-time and executable-window tests using `0xbcc3cad1`. Add classifier
assertions that the measured word is proven, the one-bit allocated control is
not proven and decodes successfully, the SME control remains excluded, and
`0xfffffff2` still fails closed.

- [ ] **Step 2: Run the new tests and verify red**

```bash
cargo test -p carrick-native-darwin simd_unprivileged -- --nocapture
```

Expected: both boundaries refuse the measured word and the classifier
assertion is false before implementation.

- [ ] **Step 3: Extend the source-bound classifier minimally**

```rust
const SIMD_UNPRIVILEGED_MASK: u32 = 0x3f00_0c00;
const SIMD_UNPRIVILEGED_UNALLOCATED: u32 = 0x3c00_0800;

if (word & SIMD_UNPRIVILEGED_MASK) == SIMD_UNPRIVILEGED_UNALLOCATED {
    return true;
}
```

Do not admit other SIMD/FP load-store shapes, consume the Node object symbol,
or infer data from byte entropy.

- [ ] **Step 4: Run focused and full scanner gates**

```bash
cargo test -p carrick-native-darwin simd_unprivileged -- --nocapture
cargo test -p carrick-native-darwin reserved_major -- --nocapture
cargo test -p carrick-native-darwin advanced_simd_shift -- --nocapture
cargo test -p carrick-native-darwin proven_unallocated -- --nocapture
cargo test -p carrick-native-darwin --lib
just fmt-check
just clippy
```

- [ ] **Step 5: Commit, build signed, and recensus the eight suites**

Commit only `direct.rs`, build through `just build`, verify codesign and
SHA-256, then run the same serial eight-suite gate with run ID and artifact
stem `tierd-wave2-simd-unprivileged`. The signed census selects Task 9.
