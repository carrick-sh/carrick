# Arena Process Section + Pre-Fork Registration Implementation Plan (spec steps 3–4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate the three overlapping fork-shared process tables (PID-namespace member region, fork-shared child table, run-state table) into one arena process section, then flip fork registration to parent-pre-fills-child, structurally deleting the post-fork registration race class (the ptrace06 bug shape).

**Architecture:** A `ProcessSection` of 4096 generation-stamped `ProcessRecord`s joins the `ArenaLayout` from the arena-foundation plan. Each existing table migrates onto it one at a time behind its existing public API (run-state first — smallest; then the child table; then the PID-member table), keeping behavior identical. Only after all three read/write the same record does Task 6 change *when* records are written: the parent claims and fully populates the child's record before `libc::fork`; the child publishes only its own liveness.

**Tech Stack:** Rust, `libc`, `std::sync::atomic`; consumes `carrick-kernel` from the arena-foundation plan.

**PREREQUISITE:** `docs/superpowers/plans/2026-07-07-carrick-kernel-arena-foundation.md` fully landed (`KernelArena`, `ArenaLayout`, `domains`, `ArenaError`, `RobustLock` all exist and the permit table lives in the arena).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-06-carrick-kernel-authority-design.md` (rev 2), sections "Process identity and lifecycle" and "Fork" flow.
- Behavior-preserving until Task 6; every migration task must leave `just test` and the focused LTP rows green before the next starts.
- Exhaustion LOUD (typed error → errno + probe); capacity 4096 records (LTP drives 1000+ children; the old child table's 256 and member table's 1024 are the undersizing this fixes).
- Multi-word record init uses the claim-sentinel protocol (claim → fill → publish-last) already proven by `HOST_PID_REGISTERING` in `namespace/pid.rs:45-46`.
- Never `--no-verify`; `just build` for signed binaries; conformance rows named per task must be re-run.
- The three source tables to consolidate (field inventory, verified 2026-07-07):
  - `crates/carrick-runtime/src/run_state.rs` — 4096 × `AtomicU64` packing id (low 32) + `RunState` (bits 32..40) + `KIND_TID` bit 40; `publish`/`publish_guest_tid`; `MY_SLOT` process-local cache.
  - `crates/carrick-host/src/guest_cpu.rs:188-352` — `ChildSlot` ×256: `pid`, `parent_pid`, `subreaper_pid`, `adopted`, `guest_ns`, `exit_status`+`exit_ready`, `ptrace_stop_signal`; claim via CAS on `pid`.
  - `crates/carrick-runtime/src/namespace/pid.rs:38-110` — `NsSharedRegion` header (`next_pid` seeded 2, `init_host_pid/pgid/sid`, `init_sig_handlers`) + `MemberSlot` ×1024: `host_pid`, `ns_pid`, `parent_host_pid`, `execed: AtomicU8`, `flags` (ALIVE/ORPHANED/DEAD), `exit_status`; file-backed attach for `carrick exec` (`map_region` at `:216-263`).

---

### Task 1: Arena late attach by path

`namespace/pid.rs` supports an outside `carrick exec` process joining by mmapping a file. The arena must support the same before it can absorb that table. (The foundation plan unlinks the arena file immediately; this task keeps it linked in a run dir and adds attach.)

**Files:**
- Modify: `crates/carrick-kernel/src/arena.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs` (arena init call gains the run-scoped path + env handoff)

**Interfaces:**
- Produces:
  - `KernelArena::create_at(path: &std::path::Path) -> std::io::Result<KernelArena>` — like `create()` but keeps the file linked (0600, `O_EXCL`).
  - `KernelArena::attach(path: &std::path::Path) -> std::io::Result<KernelArena>` — opens + mmaps existing file, validates magic/version, FAILS CLOSED (`std::io::ErrorKind::InvalidData`) on mismatch.
  - `pub const ARENA_PATH_ENV: &str = "CARRICK_KERNEL_ARENA";` — set by the root runtime; read by `init_global()` (attach if set and file exists, else create).
- Consumes: foundation-plan `create()` internals (refactor shared mmap code into a private `map_file(fd, size)` helper).

- [ ] **Step 1: Write the failing tests** (arena.rs test mod)

```rust
#[test]
fn attach_joins_an_existing_arena() {
    let dir = std::env::temp_dir().join(format!("cka-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("arena");
    let a = KernelArena::create_at(&path).unwrap();
    a.layout().header.run_token.store(77, std::sync::atomic::Ordering::Release);
    let b = KernelArena::attach(&path).unwrap();
    assert_eq!(b.layout().header.run_token.load(std::sync::atomic::Ordering::Acquire), 77);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn attach_rejects_wrong_magic() {
    let dir = std::env::temp_dir().join(format!("cka-badmagic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("arena");
    std::fs::write(&path, vec![0u8; std::mem::size_of::<ArenaLayout>()]).unwrap();
    let e = KernelArena::attach(&path).err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    std::fs::remove_dir_all(&dir).ok();
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p carrick-kernel --lib arena` — compile error (`create_at`/`attach` missing).
- [ ] **Step 3: Implement** — factor the fd→mmap block of `create()` into `fn map_file(fd: libc::c_int, size: usize) -> std::io::Result<usize>`; `create_at` = open(O_RDWR|O_CREAT|O_EXCL) + ftruncate + map + publish header (NO unlink); `attach` = open(O_RDWR) + fstat size check (< size_of::<ArenaLayout>() → InvalidData) + map + verify `header.magic == ARENA_MAGIC && header.version == ARENA_VERSION` (Acquire load) else InvalidData. `init_global()` consults `std::env::var(ARENA_PATH_ENV)` first: attach if the file exists, `create_at` it otherwise; keep plain `create()` for tests.
- [ ] **Step 4: Runtime handoff** — in `crates/carrick-runtime/src/runtime.rs` root preinit (where `init_global` was added by the foundation plan), build the path under the run temp root (same directory scheme as the SysV `SHM_DIR`/run scope: `/tmp/carrick-kernel/{sysv_run_scope}` — reuse `sysv_run_scope()`-style scoping via `CARRICK_RUN_ID`), `std::env::set_var(ARENA_PATH_ENV, &path)` BEFORE `init_global()`, so fork children and `carrick exec` inherit it.
- [ ] **Step 5: Run** — `cargo test -p carrick-kernel --lib && just build && just test` — green.
- [ ] **Step 6: Commit**

```bash
git add crates/carrick-kernel crates/carrick-runtime
git commit -m "feat(kernel): arena create_at/attach by path with fail-closed validation"
```

---

### Task 2: ProcessSection layout + record protocol

**Files:**
- Create: `crates/carrick-kernel/src/process.rs`
- Modify: `crates/carrick-kernel/src/arena.rs` (`ArenaLayout` gains `pub processes: ProcessSection`; `ARENA_VERSION` 1 → 2; init in `create` path zero-fills + seeds `next_ns_pid = 2`)
- Modify: `crates/carrick-kernel/src/lib.rs` (`pub mod process;`)

**Interfaces:**
- Produces (consumed by Tasks 3–6 and later plans):

```rust
pub const PROCESS_RECORDS: usize = 4096;

/// Claim-sentinel: host_pid == REGISTERING while a record is being filled.
pub const REGISTERING: u32 = u32::MAX;

#[repr(C)]
pub struct ProcessSection {
    pub next_ns_pid: AtomicU32,       // seeded 2 (pid 1 = guest init)
    pub init_host_pid: AtomicU32,
    pub init_host_pgid: AtomicU32,
    pub init_host_sid: AtomicU32,
    pub init_sig_handlers: AtomicU64, // pid-1 protection mask (pid.rs parity)
    pub records: [ProcessRecord; PROCESS_RECORDS],
}

#[repr(C)]
pub struct ProcessRecord {
    pub host_pid: AtomicU32,          // 0 = free, REGISTERING = claiming
    pub generation: AtomicU32,        // ProcessGeneration, never 0 when live
    pub ns_pid: AtomicU32,
    pub parent_host_pid: AtomicU32,
    pub subreaper_pid: AtomicU32,
    pub flags: AtomicU32,             // FLAG_ALIVE|FLAG_ORPHANED|FLAG_DEAD|FLAG_ADOPTED
    pub exec_generation: AtomicU32,   // replaces pid.rs `execed: AtomicU8`; 0 = never execed
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    pub ctty: AtomicU32,
    pub run_state: AtomicU64,         // run_state.rs packing, verbatim
    pub ptrace_stop_signal: AtomicU64,
    pub exit_status: AtomicU64,
    pub exit_ready: AtomicU32,
    _pad: AtomicU32,
    pub guest_ns: AtomicU64,          // child guest-CPU rollup for wait4
}

pub const FLAG_ALIVE: u32 = 1 << 0;
pub const FLAG_ORPHANED: u32 = 1 << 1;
pub const FLAG_DEAD: u32 = 1 << 2;
pub const FLAG_ADOPTED: u32 = 1 << 3;

impl ProcessSection {
    /// Claim a free record, fill via the closure, publish host_pid last.
    /// `host_pid` may be REGISTERING-deferred: pass `None` to claim a record
    /// whose host pid is published later (the pre-fork parent path).
    pub fn claim(
        &self,
        host_pid: Option<HostPid>,
        generation: ProcessGeneration,
        fill: impl FnOnce(&ProcessRecord),
    ) -> Result<ProcessRecordRef, ArenaError>;

    pub fn find(&self, host_pid: HostPid) -> Option<ProcessRecordRef>;
    pub fn allocate_ns_pid(&self) -> u32;
    pub fn release(&self, r: ProcessRecordRef); // zero the record (slot reuse)
}

/// Index + generation pair so a stale ref cannot touch a reused slot.
#[derive(Clone, Copy)]
pub struct ProcessRecordRef { pub index: usize, pub generation: ProcessGeneration }
```

- `claim` protocol: CAS `host_pid` 0 → REGISTERING, store `generation`, run `fill`, then publish `host_pid` (Release) — real pid or keep REGISTERING for the deferred path (`publish_host_pid(r, pid)` completes it). `find` skips REGISTERING records.
- `ArenaLayout` (arena.rs) becomes `{ header, permits, processes }`, `ARENA_VERSION = 2`. `create`/`create_at` seed `processes.next_ns_pid = 2`.

- [ ] **Step 1: Write the failing tests** (bottom of process.rs; same `#[allow]` header as other test mods)

```rust
#[test]
fn claim_fill_publish_find_release_round_trip() {
    let arena = KernelArena::create().unwrap();
    let s = &arena.layout().processes;
    let generation = arena.allocate_generation();
    let r = s
        .claim(Some(HostPid::new(500)), generation, |rec| {
            rec.ns_pid.store(2, Ordering::Relaxed);
            rec.parent_host_pid.store(1, Ordering::Relaxed);
            rec.flags.store(FLAG_ALIVE, Ordering::Relaxed);
        })
        .unwrap();
    let found = s.find(HostPid::new(500)).unwrap();
    assert_eq!(found.index, r.index);
    assert_eq!(found.generation, generation);
    s.release(found);
    assert!(s.find(HostPid::new(500)).is_none());
}

#[test]
fn registering_records_are_invisible_to_find() {
    let arena = KernelArena::create().unwrap();
    let s = &arena.layout().processes;
    let generation = arena.allocate_generation();
    let r = s.claim(None, generation, |_| {}).unwrap(); // deferred host pid
    assert!(s.find(HostPid::new(REGISTERING)).is_none());
    s.publish_host_pid(r, HostPid::new(600));
    assert!(s.find(HostPid::new(600)).is_some());
}

#[test]
fn ns_pids_are_monotonic_from_2() {
    let arena = KernelArena::create().unwrap();
    let s = &arena.layout().processes;
    assert_eq!(s.allocate_ns_pid(), 2);
    assert_eq!(s.allocate_ns_pid(), 3);
}

#[test]
fn exhaustion_is_loud() {
    let arena = KernelArena::create().unwrap();
    let s = &arena.layout().processes;
    for i in 0..PROCESS_RECORDS {
        s.claim(Some(HostPid::new(1000 + i as u32)), arena.allocate_generation(), |_| {})
            .unwrap();
    }
    assert!(matches!(
        s.claim(Some(HostPid::new(1)), arena.allocate_generation(), |_| {}),
        Err(ArenaError::Exhausted { section: "processes", capacity: PROCESS_RECORDS })
    ));
}
```

- [ ] **Step 2: Run to verify failure** — compile error.
- [ ] **Step 3: Implement `process.rs`** exactly per the Interfaces block: linear scan claim (CAS 0→REGISTERING on `host_pid`), `generation` stored before `fill`, `publish_host_pid` does `host_pid.store(pid, Release)`; `find` = scan for pid with Acquire, re-check `generation != 0`; `release` = store 0 to every field, `host_pid` LAST (Release). Add `publish_host_pid(r: ProcessRecordRef, pid: HostPid)` to the impl (used by the deferred path and Task 6).
- [ ] **Step 4: Run** — `cargo test -p carrick-kernel --lib process` — 4 pass; also re-run `cargo test -p carrick-vmm-hvf permit_table_is_the_arena --lib` (layout grew; the version bump + offsets must still hold).
- [ ] **Step 5: Commit**

```bash
git add crates/carrick-kernel
git commit -m "feat(kernel): arena process section with claim-sentinel records"
```

---

### Task 3: Migrate the run-state table onto the process section

Smallest consumer first; proves the pattern with the least blast radius.

**Files:**
- Modify: `crates/carrick-runtime/src/run_state.rs`
- (dep already present from the foundation plan)

**Interfaces:**
- Consumes: `ProcessSection::{find, claim}`, `ProcessRecord::run_state`.
- Produces: UNCHANGED public API — `publish(state: RunState)`, `publish_guest_tid(tid, state)`, and the read path used by `vfs/proc.rs`. The `MY_SLOT` process-local cache stays (now caching a `ProcessRecordRef`).

- [ ] **Step 1: Identify the read path** — `grep -n "run_state::" crates/carrick-runtime/src/vfs/proc.rs crates/carrick-runtime/src/threaded_loop.rs crates/carrick-runtime/src/vcpu_loop/mod.rs`. List every caller in the task log before editing.
- [ ] **Step 2: Rewire storage** — `run_state.rs` keeps its packing helpers (`encode`/`decode`, `KIND_TID`) but the slot it writes becomes `record.run_state` for the calling process's arena record: `publish` = `find(HostPid::new(getpid()))` → cached ref → single `AtomicU64` store, claiming a record (`claim(Some(pid), generation, |_| {})`) only when none exists yet (pre-Task-6 processes may publish before any other registration — same lazy shape as today's slot claim). Guest-tid publication keeps the id+KIND_TID packing but goes to a SEPARATE per-tid claim keyed by tid — preserve today's semantics exactly: a tid entry is its own slot in the old table, so give tids their own records (`host_pid = tid | KIND bit` is NOT valid — instead claim with `Some(HostPid::new(tid))` and set the KIND_TID bit inside the packed `run_state` word as today; document that tid records never carry process fields).
- [ ] **Step 3: Delete the private mmap** — remove `init_table`/`table()`'s `MAP_ANON|MAP_SHARED` page and the leaked-Box fallback (fallback is now the arena's fail-closed panic — the silent-fallback deletion is the point); keep `init` as a thin call into `KernelArena::init_global()`.
- [ ] **Step 4: Tests** — existing run_state unit tests in the file must pass unchanged: `cargo test -p carrick-runtime run_state --lib`. Then the originating conformance rows: `target/release/carrick-conformance --suite ltp-kill12 --suite ltp-getpid01 --jsonl target/conformance/runstate-arena.jsonl` (kill12 exercises R/S disambiguation; run `just build` first). Expected: MATCH both.
- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime
git commit -m "refactor(runtime): run-state publishes into the arena process section"
```

---

### Task 4: Migrate the fork-shared child table onto the process section

**Files:**
- Modify: `crates/carrick-host/src/guest_cpu.rs:188-352`
- Modify: `crates/carrick-host/Cargo.toml` (add `carrick-kernel` dep)

**Interfaces:**
- Consumes: `ProcessSection::{claim, find, release}`, record fields `parent_host_pid`, `subreaper_pid`, `flags` (FLAG_ADOPTED), `guest_ns`, `exit_status`, `exit_ready`, `ptrace_stop_signal`.
- Produces: UNCHANGED public API of `guest_cpu.rs` — `init_child_table`, `register_child_with_parent`, `register_clone_parent_child`, `adopt_children_of`, `adopted_parent_for_self`/`_for`, `mark_self_ptrace_stop_pending`, exit-status set/get. Callers (`carrick-vmm-hvf`, runtime wait paths) must not change in this task.

- [ ] **Step 1: Write a parity test FIRST** (new `#[cfg(test)]` additions in guest_cpu.rs) capturing today's registration-order invariants — these are the ptrace06 lessons and they must survive the migration verbatim:

```rust
#[test]
fn late_parent_registration_preserves_ptrace_stop_and_ancestry() {
    // Simulates: child self-registers + publishes a ptrace stop marker,
    // THEN the parent registers fork ancestry over the same record.
    init_child_table();
    let child_pid = 44_001;
    // child half: self-register with no parent metadata, mark stop pending
    register_self_for_test(child_pid);
    mark_ptrace_stop_pending_for_test(child_pid, libc::SIGSTOP);
    // parent half: late ancestry registration
    register_child_with_parent(child_pid, 44_000);
    assert_eq!(ptrace_stop_signal_for_test(child_pid), Some(libc::SIGSTOP));
    assert_eq!(parent_pid_for_test(child_pid), Some(44_000));
}
```

(The existing code has these preservation rules from commit "preserve ptrace signal stops" — 584ce508; if test-visible accessors are missing, add narrow `#[cfg(test)]` helpers reading through the SAME code paths the wait logic uses. Run the test against the CURRENT table first: it must PASS pre-migration; that is the parity baseline.)

- [ ] **Step 2: Rewire storage** — replace `CHILD_TABLE: AtomicPtr<ChildSlot>` + the 256-slot mmap with lookups into `KernelArena::global().layout().processes`; each `ChildSlot` field maps 1:1 onto the `ProcessRecord` field named in Interfaces; slot claim (`compare_exchange` on `pid`, guest_cpu.rs:284-303) becomes `ProcessSection::claim`/`find`. Keep `init_child_table()` as an arena-init alias so init ordering call sites stay valid. Keep the field-preservation logic (marker/ancestry) EXACTLY — it is deleted only in Task 6.
- [ ] **Step 3: Run parity + host tests** — `cargo test -p carrick-host --lib` (all existing guest_cpu tests + Step 1's) — green.
- [ ] **Step 4: Signed build + focused rows** — `just build`, then `target/release/carrick-conformance --suite ltp-ptrace06 --suite ltp-clone08 --suite ltp-waitpid06 --jsonl target/conformance/childtable-arena.jsonl`. Expected: MATCH all three (ptrace06 48/48).
- [ ] **Step 5: Commit**

```bash
git add crates/carrick-host crates/carrick-kernel
git commit -m "refactor(host): fork-shared child table relocates into the arena process section"
```

---

### Task 5: Migrate the PID-namespace member table onto the process section

**Files:**
- Modify: `crates/carrick-runtime/src/namespace/pid.rs`

**Interfaces:**
- Consumes: `ProcessSection` header fields (`next_ns_pid`, `init_host_pid/pgid/sid`, `init_sig_handlers`), records (`ns_pid`, `parent_host_pid`, `flags`, `exec_generation`, `exit_status`), `KernelArena::attach` (Task 1).
- Produces: UNCHANGED public API of `namespace::pid` — registration, `mark_self_execed`/`mark_execed` (now `exec_generation.fetch_add(1)`; the boolean readers `is_execed_child_of_current`/`is_execed_child_of`/`execed_of` read `exec_generation > 0`), member iteration for the supervisor, `map_region` attach path.

- [ ] **Step 1: Enumerate invariants before editing** — read `pid.rs:216-309` and `:703-760` and record in the task log: the `HOST_PID_REGISTERING` sentinel discipline, slot-reuse reset (`:309`, `:759`), the setpgid EACCES-after-exec consumer (`crates/carrick-runtime/src/dispatch/...` — grep `is_execed_child_of`), and the supervisor's member iteration (`namespace/supervisor.rs` — grep `members`).
- [ ] **Step 2: Rewire** — `NsSharedRegion`'s member array is deleted; its header fields move to the `ProcessSection` header (they were seeded there in Task 2); every member operation resolves through `ProcessSection::find`/`claim`. `map_region`'s file-attach becomes `KernelArena::attach` + section pointer. `execed: AtomicU8` reads/writes become `exec_generation` per the Interfaces block. The `MEMBER_SLOTS = 1024` limit disappears (4096 records).
- [ ] **Step 3: Unit tests** — `cargo test -p carrick-runtime namespace::pid --lib` and `cargo test -p carrick-runtime setpgid_tests --lib` — green (these cover the exec-flag semantics landed in b703a605).
- [ ] **Step 4: Signed build + focused rows** — `just build`, then `target/release/carrick-conformance --suite ltp-setpgid03 --suite ltp-getpgid01 --suite ltp-kill10 --jsonl target/conformance/pidns-arena.jsonl`. Expected: MATCH all. Also verify `carrick exec` late-attach manually: `target/release/carrick run -d --name arena-exec-test ubuntu:24.04 sleep 30` then `target/release/carrick exec arena-exec-test /bin/true` — exit 0.
- [ ] **Step 5: Delete the now-empty private region code** (`NsSharedRegion` mmap, `REGION: AtomicPtr`), run `just test`, commit.

```bash
git add crates/carrick-runtime
git commit -m "refactor(runtime): PID-namespace member table relocates into the arena process section"
```

---

### Task 6: Pre-fork registration (spec step 4 — the behavior change)

Parent claims + fully populates the child's record BEFORE `libc::fork`; the child publishes only its own liveness. Deletes the post-fork race window and the preservation workarounds it required.

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs` and the fork dispatch path (grep `register_child_with_parent` callers — the parent-side call sites move pre-fork)
- Modify: `crates/carrick-host/src/guest_cpu.rs` (child-side: publish liveness; delete the marker/ancestry preservation paths from Task 4 Step 2)
- Test: `crates/carrick-kernel/tests/prefork_registration.rs`

**Interfaces:**
- Consumes: `ProcessSection::{claim, publish_host_pid}`, `ProcessRecordRef`.
- Produces:
  - `guest_cpu::prepare_child_record_pre_fork(parent: HostPid, ns_pid: u32, ptrace_traceme: bool, ...) -> ProcessRecordRef` — called by the parent at the fork quiesce point; claims with `claim(None, generation, fill)` (host pid deferred), fills ancestry/ns-pid/ptrace links, stashes the ref in a process-local static (`PENDING_CHILD_RECORD`).
  - `guest_cpu::complete_child_record_post_fork_child()` — child half: reads the inherited stash, `publish_host_pid(ref, getpid())`, sets FLAG_ALIVE. The PARENT also writes `host_pid` from fork's return value via `publish_host_pid` — same value, idempotent by design (document this).
  - Deletion: the "existing-slot registration preserves live ptrace_stop_signal and parent ancestry" repair logic (Task 4 kept it) is removed; the parity test from Task 4 Step 1 is REWRITTEN to assert the new invariant (marker set on an already-complete record).

- [ ] **Step 1: Write the failing cross-process test** (`tests/prefork_registration.rs`, real fork, same harness shape as `robust_lock_kill9.rs`)

```rust
//! The fork-registration race is structurally gone: between libc::fork and
//! the child's first instruction, the child's record is ALREADY complete
//! (ancestry + ns pid + ptrace links), so a sibling reading it observes no
//! REGISTERING window and no field ever transitions twice.
```
Test body: parent claims via `claim(None, ..)` + fills `parent_host_pid`/`ns_pid`/`ptrace_stop_signal`; forks; child asserts `find(getpid())` (after its own `publish_host_pid`) returns a record whose `parent_host_pid` and `ptrace_stop_signal` are ALREADY the parent's values with no write of its own; parent waits and asserts the same. A second fork-storm variant loops 200 children asserting zero `REGISTERING`-visible reads from a sibling scanner thread. Use exact assert style from Task 2's tests.

- [ ] **Step 2: Run to verify failure** — the helpers don't exist → compile error.
- [ ] **Step 3: Implement the two halves in guest_cpu.rs** and move the parent-side registration call from its post-fork location to the quiesce point (the fork path calls `fork_prepare_and_teardown` — the registration goes immediately before the `libc::fork` in the shared engine; grep `register_child_with_parent` and `register_clone_parent_child` for the exact call sites; `CLONE_PARENT` adoption keeps its adopted-table semantics, now pre-filled the same way).
- [ ] **Step 4: Delete the repair paths** — remove existing-slot preservation in registration (the 584ce508-era code), rewrite the Task 4 parity test to the new invariant, run `cargo test -p carrick-host --lib`.
- [ ] **Step 5: Full verification ladder**
  - `just build && just test`
  - Focused rows (the historical victims of this race class): `target/release/carrick-conformance --suite ltp-ptrace06 --suite ltp-ptrace11 --suite ltp-clone08 --suite ltp-kill10 --suite ltp-waitpid06 --jsonl target/conformance/prefork-reg.jsonl` — MATCH all; run ptrace06 THREE times (race-class fix: single green runs don't count).
  - `just conformance smoke` — exit 0.
- [ ] **Step 6: Commit**

```bash
git add crates/carrick-host crates/carrick-runtime crates/carrick-kernel
git commit -m "feat(runtime): pre-fork child registration eliminates the post-fork race window"
```

---

### Task 7: Gate + diary

- [ ] **Step 1:** `just ci`, then a full cached-oracle measurement: `target/release/carrick-conformance --tier full --force --jsonl target/conformance/after-process-section.jsonl`. Compare gating set against `target/conformance/full-after-xattr-084615.jsonl` — the gating set must be equal or smaller; any NEW gating row is a regression to fix before commit.
- [ ] **Step 2:** Diary entry (current conformance diary): tables consolidated, capacities unified at 4096, pre-fork registration landed, race-class deletions listed, measurement results.
- [ ] **Step 3:** Commit docs.

```bash
git add docs/ target/conformance/after-process-section.jsonl 2>/dev/null || git add docs/
git commit -m "docs(kernel): record process-section consolidation (migration steps 3-4)"
```

---

## Self-Review Notes

- Spec coverage: step 3 (consolidation ✓ Tasks 2–5, exec generation ✓ Tasks 2/5, capacities unified ✓, loud exhaustion ✓ Task 2) ; step 4 (pre-fork registration ✓ Task 6, repair-code deletion ✓ Task 6 Step 4, fork-storm race harness ✓ Task 6 Step 1). Run-state/pgid/sid/ctty fields exist in the record now; PTY/session ownership migration onto them is spec step 10, deliberately NOT in this plan.
- Ordering rationale: run-state (no ancestry semantics) → child table (ptrace parity test as a safety net) → PID members (exec semantics + attach) → only then the behavioral flip.
- Risk note for the implementer: Tasks 4–6 modify fork-adjacent code. Any hang reproduction goes through `carrick debug lldb-run` (see carrick-lldb skill), NOT eprintln, and every focused LTP row listed is the regression guard for its task — do not skip them even when unit tests are green.
