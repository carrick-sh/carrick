# File-Descriptor Description Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `kernel::FileDescriptionBacking` from an identity-only trait into
carrick's real open-file-description seam, so a new fd type is a new backing
type instead of ~17 edits to 25-arm matches — and so the approved FileAuthority
cutover has an open seam to land on instead of a second closed enum.

**Architecture:** Three sequenced phases inside one crate. Phase 1 hoists the
description state that is generic across every fd kind (`status_flags`,
`fd_refs`, `lease`, async-I/O owner, `F_SETSIG`, memfd seals, secretmem) out of
`OpenDescriptionBase` — where 25 enum variants each carry a copy — onto
`kernel::FileDescription`, which already owns description identity. Phase 2 adds
the first *operation* to `FileDescriptionBacking` (`readiness`) and collapses the
two divergent readiness state machines onto it. Phase 3 opens
`file_authority::AuthorityBacking` the same way and routes the first production
call-site family through `FileAuthorityCore::execute_call`, burning down the K1
ledger for the first time.

The migration is staged through one deliberately transient shared
`Arc<DescriptionCommon>` so that 100 construction sites and 57 install sites do
not all have to change in one commit. **That intermediate is deleted inside this
plan (Task 5).** It must not survive the plan; a merged dual-storage state would
be exactly the "two answers to reconcile" AGENTS.md forbids.

**Tech Stack:** Rust 2024 (pin in `rust-toolchain.toml`), `parking_lot`,
`carrick-abi` bitflags/typed domains, `scripts/migrate/rewrite.py` for
count-asserted mechanical passes, `just` recipes for every gate.

**Spec:** [`docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md`](2026-08-12-per-run-file-authority-atomic-migration.md)
(approved architecture; this plan implements the unscheduled part of its
**Wave 2 — direct core**: "Migrate production callers family-by-family without
enabling a second store"), under
[`docs/superpowers/specs/2026-08-09-hvpatch-k1-kernel-object-model.md`](../specs/2026-08-09-hvpatch-k1-kernel-object-model.md).

## Why this plan exists (measured at HEAD, 2026-08-27)

| Observation | Value |
|---|---|
| `OpenDescription` variants (`dispatch/fd_table.rs:890`) | 25 |
| `OpenDescriptionBase` fields shared by all 25 (`fd_table.rs:242`) | 21 |
| References to concrete `OpenDescription::` variants | 1,074 across 25 files |
| Functions that enumerate **all 25** variants | 17 |
| Functions that enumerate ≥6 variants | 34 |
| `FileDescriptionBacking` methods that are operations (`kernel/objects.rs:506`) | **0** of 6 |
| Types implementing `FileDescriptionBacking` | 2 (`RwLock<OpenDescription>`, `IoUringBacking`) |
| `FileAuthorityCore::execute_call` production callers | **0** |
| K1 legacy authority-escape call sites (`scripts/migrate/k1-file-authority-callsite-taxonomy.json`) | 361 in 9 families |
| Gates that run the K1 drift checkers | **0** |

Two of the 17 all-variant functions are `base()` and `base_mut()`
(`fd_table.rs:1741`, `:1774`) — 25 arms each whose only job is to reach fields
every variant already has. Both abort the process on `Closed`. So does
`FileDescription::open_description()` (`fd_table.rs:1518`), for any backing that
is not one of the two known ones — which is why `IoUringBacking` has to carry a
shadow `RwLock<OpenDescription>` (`ioring.rs:248`) purely to answer generic
questions. Phase 1 deletes all three aborts.

## Global Constraints

- **Rust first.** New capability lands in our own crates, not a new script.
  Mechanical repeated-shape passes go through `scripts/migrate/rewrite.py` with
  a committed, count-asserted spec (AGENTS.md, "Engineering standards").
- **No backward compatibility, no second path.** Every task that adds a
  forwarding shim names the later task that deletes it. Nothing in this plan may
  merge behind a feature flag or an `=1` opt-in.
- **Typed domains.** New number/flag surfaces derive from `bitflags!` or an
  ordinal enum. No hand-numbered constants, no bare `u32` crossing a semantic
  boundary. `just lint-domains` enforces the shipped bug shapes.
- **ABI constants live in `carrick-abi`.** No column-0 `const LINUX_*` in
  dispatch files. A new `LINUX_*` used as a match arm but not imported becomes a
  silent catch-all — check for `unreachable pattern` warnings.
- **Never `git stash`** in this checkout; the stash is repo-global and shared by
  every worktree. To set work aside, commit on your own branch.
- **Never `git commit --no-verify`.** If `fmt-check` fails, run `just fmt`.
- **`just test`, never a bare `cargo test --workspace --lib`.**
  `carrick-runtime`, `carrick-host` and `carrick-native-darwin` fork from the
  test harness and deadlock in parallel; the recipe serializes them.
- **Red-first.** Every behaviour-changing task writes its test first and
  **confirms it fails for the right reason** before the fix. A test that passes
  immediately proves nothing.
- **`just ci` before every push.** CI runs sequentially, so a red early step
  masks every later failure.
- Guest-running verification is out of scope for this plan; every task is
  gated by host-side tests plus `just ci`. Task 9 additionally requires
  `just conformance-probes` (signed, `just build` first) because it changes a
  guest-visible path.

---

## File Structure

| File | Responsibility after this plan |
|---|---|
| `crates/carrick-runtime/src/kernel/objects.rs` | Adds `DescriptionCommon` (generic per-description state) and `FileDescription`'s accessors for it. Grows `FileDescriptionBacking` by one operation, `readiness`. |
| `crates/carrick-runtime/src/dispatch/fd_table.rs` | Loses `OpenDescriptionBase`'s generic half, loses `base()`/`base_mut()`, loses the `open_description()` abort. Keeps the kind-specific state (socket options, pipe capacity, netlink queues). |
| `crates/carrick-runtime/src/dispatch/ioring.rs` | Loses the shadow `open_metadata` `OpenDescription`. Implements `readiness` directly. |
| `crates/carrick-runtime/src/dispatch/net.rs` | `epoll_ready_events` and `poll_ready_events` become thin translators over one backing call. |
| `crates/carrick-abi/src/lib.rs` | Gains `LinuxPollEvents ↔ LinuxEpollEvents` conversions so the two syscall surfaces share one readiness domain. |
| `crates/carrick-runtime/src/file_authority/backing.rs` | `AuthorityBacking` becomes an open trait with typed downcast instead of a closed 10-variant enum. |
| `scripts/migrate/check-k1-burndown.py` (new) | Gates the K1 ledger: authority-escape counts may fall, never rise. |
| `scripts/migrate/2026-08-27-description-common-*.json` (new) | The committed, count-asserted rewrite specs for Tasks 3, 4 and 5. |
| `justfile` | `lint-domains` runs the K1 inventory, taxonomy and burndown checkers. |

---

## Task 1: Gate the K1 burndown ledger

The campaign already has a checked inventory of every legacy authority escape
(`scripts/migrate/k1-file-authority-operation-inventory.json`, 361 entries) and a
family taxonomy with counts
(`scripts/migrate/k1-file-authority-callsite-taxonomy.json`). Neither checker is
wired into any gate, so the ledger can drift silently and the cutover has no
progress metric. Fix that first: every later task in this plan is measured by it.

**Files:**
- Create: `scripts/migrate/check-k1-burndown.py`
- Create: `scripts/migrate/k1-burndown-ceiling.json`
- Modify: `justfile` (the `lint-domains` recipe, currently at `justfile:129-132`)
- Test: `scripts/migrate/check-k1-burndown.py --self-test`

**Interfaces:**
- Consumes: `scripts/migrate/k1-file-authority-callsite-taxonomy.json`, whose
  top-level shape is `{"schema": 1, "counts": {<family>: <int>}, "entries": [...]}`
  with families `inspect_misc`, `lifecycle`, `create_install`, `read_attempt`,
  `write_attempt`, `slot_description_mutation`, `stream_transfer`,
  `mapping_ring`, `epoll_wait`.
- Produces: `scripts/migrate/k1-burndown-ceiling.json`, shape
  `{"schema": 1, "ceiling": {<family>: <int>}}`. Later tasks lower a family's
  ceiling in the same commit that removes the call sites.

- [ ] **Step 1: Write the failing self-test**

Create `scripts/migrate/check-k1-burndown.py` containing only the test entry
point and a stub, so the test can run and fail:

```python
#!/usr/bin/env python3
"""Fail when any K1 authority-escape family grows past its recorded ceiling.

The ceiling is a BURNDOWN target, not a description: it may only be lowered,
and it is lowered in the same commit that removes the call sites. A family that
grows is a new legacy escape being added while the cutover is in flight, which
is the failure mode this gate exists to catch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAXONOMY = ROOT / "scripts/migrate/k1-file-authority-callsite-taxonomy.json"
CEILING = ROOT / "scripts/migrate/k1-burndown-ceiling.json"


def violations(counts: dict[str, int], ceiling: dict[str, int]) -> list[str]:
    raise NotImplementedError


def self_test() -> int:
    assert violations({"epoll_wait": 3}, {"epoll_wait": 3}) == []
    assert violations({"epoll_wait": 2}, {"epoll_wait": 3}) == []
    assert violations({"epoll_wait": 4}, {"epoll_wait": 3}) == [
        "epoll_wait: 4 escapes exceeds ceiling 3"
    ]
    assert violations({"new_family": 1}, {}) == [
        "new_family: 1 escapes exceeds ceiling 0"
    ]
    print("check-k1-burndown self-test OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print(f"usage: {Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2
    counts = json.loads(TAXONOMY.read_text())["counts"]
    ceiling = json.loads(CEILING.read_text())["ceiling"]
    found = violations(counts, ceiling)
    if found:
        print("K1 authority-escape burndown regressed:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nA family may only shrink. If you deliberately removed call sites, "
            "lower the ceiling in scripts/migrate/k1-burndown-ceiling.json in the "
            "SAME commit.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 2: Run the self-test to verify it fails**

```bash
chmod +x scripts/migrate/check-k1-burndown.py
python3 scripts/migrate/check-k1-burndown.py --self-test
```

Expected: FAIL with `NotImplementedError`.

- [ ] **Step 3: Implement `violations`**

```python
def violations(counts: dict[str, int], ceiling: dict[str, int]) -> list[str]:
    found = []
    for family in sorted(set(counts) | set(ceiling)):
        actual = counts.get(family, 0)
        allowed = ceiling.get(family, 0)
        if actual > allowed:
            found.append(f"{family}: {actual} escapes exceeds ceiling {allowed}")
    return found
```

- [ ] **Step 4: Run the self-test to verify it passes**

```bash
python3 scripts/migrate/check-k1-burndown.py --self-test
```

Expected: `check-k1-burndown self-test OK`.

- [ ] **Step 5: Record today's ceiling from the live taxonomy**

```bash
python3 - <<'EOF'
import json, pathlib
tax = json.loads(pathlib.Path("scripts/migrate/k1-file-authority-callsite-taxonomy.json").read_text())
out = {"schema": 1, "ceiling": dict(sorted(tax["counts"].items()))}
pathlib.Path("scripts/migrate/k1-burndown-ceiling.json").write_text(json.dumps(out, indent=1) + "\n")
print(json.dumps(out, indent=1))
EOF
python3 scripts/migrate/check-k1-burndown.py
```

Expected: the printed ceiling matches the taxonomy counts
(`inspect_misc: 161`, `lifecycle: 62`, `create_install: 44`, `read_attempt: 13`,
`write_attempt: 19`, `slot_description_mutation: 9`, `stream_transfer: 12`,
`mapping_ring: 7`, `epoll_wait: 34`), and the second command exits 0.

- [ ] **Step 6: Wire all three K1 checkers into `just lint-domains`**

In `justfile`, replace the body of the `lint-domains` recipe with:

```just
lint-domains:
    python3 scripts/conformance/check-next-strategy.py
    ./scripts/lint-domains.sh
    python3 scripts/migrate/check-host-authority-transitions.py --check
    python3 scripts/migrate/check-k1-file-authority-inventory.py
    python3 scripts/migrate/check-k1-file-authority-taxonomy.py
    python3 scripts/migrate/check-k1-burndown.py
```

- [ ] **Step 7: Run the gate**

```bash
just lint-domains
```

Expected: PASS. If the inventory or taxonomy checker reports drift, the ledger
went stale since 2026-08-12 — regenerate it with the checker's own refresh path
and commit the regenerated JSON as part of this task, noting the drift in the
commit body. Do **not** lower the ceiling to accommodate drift.

- [ ] **Step 8: Commit**

```bash
git add scripts/migrate/check-k1-burndown.py scripts/migrate/k1-burndown-ceiling.json justfile
git add scripts/migrate/k1-file-authority-operation-inventory.json scripts/migrate/k1-file-authority-callsite-taxonomy.json
git commit -m "test(runtime): gate the K1 authority-escape burndown

The K1 cutover ledger (361 legacy authority escapes across nine families)
has been checked in since 2026-08-12 but no gate ran its drift checkers, so
it could go stale and the cutover had no progress metric. Wire
check-k1-file-authority-inventory.py and -taxonomy.py into just lint-domains
and add check-k1-burndown.py, which fails when a family grows past a recorded
ceiling. The ceiling may only be lowered, in the same commit that removes the
call sites.

Verified: just lint-domains passes; check-k1-burndown.py --self-test covers
equal, below, above and previously-unknown-family cases.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: `DescriptionCommon` on `kernel::FileDescription`

Introduce the type that will own the generic half of `OpenDescriptionBase`, and
hang it off `FileDescription` — which already owns description identity,
revision and epoll-owner edges. Nothing reads it yet; Task 3 moves the first
field's storage into it.

**Files:**
- Modify: `crates/carrick-runtime/src/kernel/objects.rs` (add the type; add the
  field to `FileDescription` at `:564-569`; extend the three constructors
  `concrete`, `concrete_restored`, `regular`, `epoll` at `:573-618`)
- Test: `crates/carrick-runtime/src/kernel/tests.rs`

**Interfaces:**
- Produces:
  - `pub(crate) struct DescriptionCommon` with
    `fn new(status_flags: u64) -> Self`,
    `fn status_flags(&self) -> u64`, `fn set_status_flags(&self, next: u64)`,
    `fn fd_refs(&self) -> usize`, `fn retain_fd_ref(&self)`,
    `fn release_fd_ref(&self) -> usize`,
    `fn lease(&self) -> i32`, `fn set_lease(&self, lease: i32)`,
    `fn owner(&self) -> AsyncIoOwner`, `fn set_owner(&self, owner: AsyncIoOwner)`,
    `fn async_sig(&self) -> i32`, `fn set_async_sig(&self, sig: i32)`,
    `fn seals(&self) -> Option<u32>`, `fn set_seals(&self, seals: Option<u32>)`,
    `fn secretmem(&self) -> bool`, `fn set_secretmem(&self, on: bool)`.
  - `pub(crate) struct AsyncIoOwner { pub(crate) owner_type: i32, pub(crate) owner_pid: i32 }`,
    `Clone + Copy + Debug + Default + Eq + PartialEq`; `Default` is `(0, 0)` = no owner.
  - `FileDescription::common(&self) -> &DescriptionCommon`.

- [ ] **Step 1: Write the failing test**

Append to `crates/carrick-runtime/src/kernel/tests.rs`:

```rust
#[test]
fn description_common_survives_the_closed_transition_and_counts_fd_refs() {
    let description = FileDescription::regular(FileDescriptionId::for_test(1));
    let common = description.common();

    assert_eq!(common.status_flags(), 0);
    assert_eq!(common.fd_refs(), 0);
    assert_eq!(common.owner(), AsyncIoOwner::default());
    assert_eq!(common.async_sig(), 0);
    assert_eq!(common.seals(), None);
    assert!(!common.secretmem());

    common.set_status_flags(carrick_abi::LINUX_O_NONBLOCK);
    common.set_owner(AsyncIoOwner {
        owner_type: 1,
        owner_pid: 42,
    });
    common.set_async_sig(carrick_abi::LINUX_SIGUSR1);
    common.set_seals(Some(0b0001));
    common.set_secretmem(true);

    common.retain_fd_ref();
    common.retain_fd_ref();
    assert_eq!(common.fd_refs(), 2);
    assert_eq!(common.release_fd_ref(), 1);
    assert_eq!(common.fd_refs(), 1);

    // The whole point of hoisting: this state is reachable through the
    // description identity, so it does not vanish when the backing drains to
    // its Closed shell — the case `OpenDescription::base()` aborts on today.
    assert_eq!(common.status_flags(), carrick_abi::LINUX_O_NONBLOCK);
    assert_eq!(
        common.owner(),
        AsyncIoOwner {
            owner_type: 1,
            owner_pid: 42,
        }
    );
    assert_eq!(common.async_sig(), carrick_abi::LINUX_SIGUSR1);
    assert_eq!(common.seals(), Some(0b0001));
    assert!(common.secretmem());
}
```

If `FileDescriptionId::for_test` does not exist, use the same id constructor the
neighbouring tests in that file already use; do not add a new one.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib description_common_survives -- --test-threads=1 --nocapture
```

Expected: FAIL to compile — `no method named 'common'`, `cannot find type
'AsyncIoOwner'`.

- [ ] **Step 3: Implement the type**

In `crates/carrick-runtime/src/kernel/objects.rs`, immediately above
`pub struct FileDescription`:

```rust
/// The async-I/O owner set by `F_SETOWN`/`F_SETOWN_EX`: the SIGIO/SIGURG
/// target. `(0, 0)` — the `Default` — means no owner. `owner_type` is
/// `F_OWNER_TID`/`F_OWNER_PID`/`F_OWNER_PGRP`; `owner_pid` is the positive id.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AsyncIoOwner {
    pub(crate) owner_type: i32,
    pub(crate) owner_pid: i32,
}

/// Open-file-description state that is generic across EVERY backing kind.
///
/// Linux keeps these on the description, so a `dup`, a `fork`, or a
/// `CLONE_FILES` sharer observes one value. Carrick used to keep a private copy
/// inside each of `OpenDescription`'s 25 variants (`OpenDescriptionBase`),
/// which cost two 25-arm matches to reach (`base`/`base_mut`), forced
/// `IoUringBacking` to carry a shadow `OpenDescription` purely to answer these
/// questions, and made the state unreachable — a process abort — once a
/// description drained to its `Closed` identity shell.
///
/// Reads take no description lock: every field is either an atomic or a short
/// `Mutex`, so the hot syscall prologue (`read(2)` asks seven of these
/// questions before a byte moves) does not serialize on the backing's `RwLock`.
#[derive(Debug)]
pub(crate) struct DescriptionCommon {
    status_flags: AtomicU64,
    /// Number of Linux fd-table entries naming this description across every
    /// process namespace. Deliberately excludes transient Rust `Arc` clones
    /// held by in-flight syscalls: Linux removes an epoll interest only after
    /// the last fd referring to the description closes, and `Arc::strong_count`
    /// cannot express that.
    fd_refs: AtomicUsize,
    /// `F_SETLEASE`/`F_GETLEASE`: `F_RDLCK`(0)/`F_WRLCK`(1)/`F_UNLCK`(2).
    lease: AtomicI32,
    /// `F_SETSIG`: the signal delivered on async I/O (0 = the default SIGIO).
    async_sig: AtomicI32,
    /// True for a `memfd_secret(2)` description.
    secretmem: AtomicBool,
    owner: Mutex<AsyncIoOwner>,
    /// `memfd_create(2)`/`F_ADD_SEALS` seal set. `None` = this description does
    /// not support sealing (`F_GET_SEALS`/`F_ADD_SEALS` → `EINVAL`).
    seals: Mutex<Option<u32>>,
}

impl DescriptionCommon {
    pub(crate) fn new(status_flags: u64) -> Self {
        Self {
            status_flags: AtomicU64::new(status_flags),
            fd_refs: AtomicUsize::new(0),
            lease: AtomicI32::new(crate::linux_abi::LINUX_F_UNLCK),
            async_sig: AtomicI32::new(0),
            secretmem: AtomicBool::new(false),
            owner: Mutex::new(AsyncIoOwner::default()),
            seals: Mutex::new(None),
        }
    }

    pub(crate) fn status_flags(&self) -> u64 {
        self.status_flags.load(Ordering::Relaxed)
    }

    pub(crate) fn set_status_flags(&self, next: u64) {
        self.status_flags.store(next, Ordering::Relaxed);
    }

    pub(crate) fn fd_refs(&self) -> usize {
        self.fd_refs.load(Ordering::Relaxed)
    }

    pub(crate) fn retain_fd_ref(&self) {
        self.fd_refs.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the count AFTER the release. Aborts on underflow: a negative
    /// logical fd-reference count means the close accounting has already lost
    /// track of an epoll interest's lifetime, and continuing would leak or
    /// double-free a registration.
    pub(crate) fn release_fd_ref(&self) -> usize {
        let previous = self.fd_refs.fetch_sub(1, Ordering::Relaxed);
        if previous == 0 {
            tracing::error!("logical fd reference count underflow");
            std::process::abort();
        }
        previous - 1
    }

    pub(crate) fn lease(&self) -> i32 {
        self.lease.load(Ordering::Relaxed)
    }

    pub(crate) fn set_lease(&self, lease: i32) {
        self.lease.store(lease, Ordering::Relaxed);
    }

    pub(crate) fn async_sig(&self) -> i32 {
        self.async_sig.load(Ordering::Relaxed)
    }

    pub(crate) fn set_async_sig(&self, sig: i32) {
        self.async_sig.store(sig, Ordering::Relaxed);
    }

    pub(crate) fn secretmem(&self) -> bool {
        self.secretmem.load(Ordering::Relaxed)
    }

    pub(crate) fn set_secretmem(&self, on: bool) {
        self.secretmem.store(on, Ordering::Relaxed);
    }

    pub(crate) fn owner(&self) -> AsyncIoOwner {
        *self.owner.lock()
    }

    pub(crate) fn set_owner(&self, owner: AsyncIoOwner) {
        *self.owner.lock() = owner;
    }

    pub(crate) fn seals(&self) -> Option<u32> {
        *self.seals.lock()
    }

    pub(crate) fn set_seals(&self, seals: Option<u32>) {
        *self.seals.lock() = seals;
    }
}
```

Add the atomics to the file's imports (`std::sync::atomic::{AtomicBool,
AtomicI32, AtomicU64, AtomicUsize, Ordering}`) alongside the existing
`AtomicBool` import.

- [ ] **Step 4: Hang it off `FileDescription`**

Add the field and initialize it in every constructor:

```rust
#[derive(Debug)]
pub struct FileDescription {
    id: FileDescriptionId,
    kind: FileDescriptionKind,
    common: DescriptionCommon,
    epoll_registrations: Mutex<BTreeMap<(FileDescriptionId, i32), Weak<FileDescription>>>,
    revision: ObjectRevision,
}
```

`concrete`, `concrete_restored`, `regular` and `epoll` each gain
`common: DescriptionCommon::new(0)`. `regular` and `epoll` are `const fn` /
plain `fn` today; `DescriptionCommon::new` is not `const`, so drop the `const`
from `regular`'s signature and fix the one or two call sites the compiler
points at. Add the accessor:

```rust
impl FileDescription {
    pub(crate) fn common(&self) -> &DescriptionCommon {
        &self.common
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib description_common_survives -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 6: Run the crate's host tests and the lint gate**

```bash
just test
just clippy
just lint-domains
```

Expected: all PASS. `clippy` may flag `DescriptionCommon`'s setters as unused —
that is expected at this task and is resolved by Task 3; silence it for this one
commit with `#[allow(dead_code)]` on the `impl` block **and delete the allow in
Task 3**.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/kernel/tests.rs
git commit -m "feat(runtime): add DescriptionCommon to FileDescription

Linux keeps status flags, the logical fd-reference count, the file lease, the
async-I/O owner, F_SETSIG, memfd seals and secretmem on the open file
description, so a dup or a CLONE_FILES sharer observes one value. Carrick keeps
a private copy inside each of OpenDescription's 25 variants, which costs two
25-arm matches to reach (base/base_mut), forces IoUringBacking to carry a
shadow OpenDescription to answer the same questions, and aborts the process
once a description drains to its Closed identity shell.

Introduce DescriptionCommon on kernel::FileDescription, which already owns
description identity. Reads take no backing lock, so the read(2) prologue stops
serializing on the description RwLock for seven separate questions. Nothing
reads it yet; the storage moves field-by-field in the following commits and
OpenDescriptionBase's generic half is deleted at the end of the series.

Verified: description_common_survives_the_closed_transition_and_counts_fd_refs
covers defaults, every setter, retain/release accounting, and readability after
the Closed transition. just test, just clippy, just lint-domains pass.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: Move `status_flags` storage into `DescriptionCommon`

`status_flags` is the field with the widest blast radius (35 read sites, 5 write
sites, and all 100 `OpenDescriptionBase::new(flags)` construction sites feed it).
Move it first, using the transient shared-`Arc` bridge so construction sites do
not change.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs:242-350` (the field
  and `OpenDescriptionBase::new`), `:1231-1247` (`kernel_file_description`,
  `FileSlot::from_open_description`), `:1832-1878` (the `OpenDescription`
  forwarders)
- Modify: `crates/carrick-runtime/src/kernel/objects.rs` (accept a prepared
  `Arc<DescriptionCommon>` in `FileDescription::concrete`)
- Test: `crates/carrick-runtime/src/dispatch/tests.rs`

**Interfaces:**
- Consumes: `DescriptionCommon`, `AsyncIoOwner`, `FileDescription::common` from Task 2.
- Produces:
  - `kernel::FileDescription::concrete_with_common<T>(backing: Arc<T>, common: Arc<DescriptionCommon>) -> Result<Self, ObjectIdError>`
  - `FileDescription::common(&self) -> &DescriptionCommon` now returns the
    backing-shared instance.
  - `OpenDescriptionBase::common(&self) -> &Arc<DescriptionCommon>` — the
    **transient** bridge, deleted in Task 5.

- [ ] **Step 1: Write the failing test**

Append to `crates/carrick-runtime/src/dispatch/tests.rs`, inside
`mod overlay_dispatch_tests`:

```rust
#[test]
fn status_flags_are_one_value_shared_by_the_description_and_its_backing() {
    let open_file = eventfd_open_file(0);

    // The description answers without taking the backing lock...
    assert_eq!(open_file.description.common().status_flags(), 0);

    // ...and it is the SAME storage the enum forwarder reads, not a copy.
    open_file
        .description
        .common()
        .set_status_flags(carrick_abi::LINUX_O_NONBLOCK);
    assert_eq!(
        open_file.description.read().status_flags(),
        carrick_abi::LINUX_O_NONBLOCK
    );

    open_file.description.write().set_status_flags(0);
    assert_eq!(open_file.description.common().status_flags(), 0);
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib status_flags_are_one_value -- --test-threads=1 --nocapture
```

Expected: FAIL — the two reads return independent values (the description's
`DescriptionCommon` is a fresh `new(0)`, the enum's is `OpenDescriptionBase`'s
own field), so the second assertion sees `0` instead of `LINUX_O_NONBLOCK`.

- [ ] **Step 3: Replace `OpenDescriptionBase`'s storage with the shared handle**

In `fd_table.rs`, change the field and constructor:

```rust
pub(super) struct OpenDescriptionBase {
    /// The description-level state this backing shares with its owning
    /// `kernel::FileDescription`. TRANSIENT: `OpenDescriptionBase` stops
    /// carrying it entirely once every reader goes through the description
    /// (see the deletion commit in this series).
    common: std::sync::Arc<crate::kernel::DescriptionCommon>,
    // ... every remaining kind-specific field unchanged ...
}
```

`new` becomes:

```rust
    pub(super) fn new(status_flags: u64) -> Self {
        Self {
            common: std::sync::Arc::new(crate::kernel::DescriptionCommon::new(status_flags)),
            // ... remaining fields unchanged ...
        }
    }

    pub(super) fn common(&self) -> &std::sync::Arc<crate::kernel::DescriptionCommon> {
        &self.common
    }
```

Delete the `status_flags: u64` and `fd_refs: Arc<AtomicUsize>` fields and their
initializers. Rewrite the accessors to delegate — note they no longer need
`&mut self`:

```rust
    pub(super) fn status_flags(&self) -> u64 {
        self.common.status_flags()
    }

    pub(super) fn set_status_flags(&self, next: u64) {
        self.common.set_status_flags(next);
    }
```

The derived predicates (`is_append`, `is_nonblocking`, `is_async`,
`access_mode`, `is_write_only`, `is_read_only`, `is_path`) keep their bodies —
they already read through `self.status_flags`, which is now the delegating
method.

- [ ] **Step 4: Thread the shared handle into `FileDescription`**

In `kernel/objects.rs`, add the constructor that accepts a prepared common
block, and make `concrete` delegate to it:

```rust
    pub(crate) fn concrete_with_common<T>(
        backing: Arc<T>,
        common: Arc<DescriptionCommon>,
    ) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Ok(Self {
            id: super::ids::allocate_file_description_id()?,
            kind: FileDescriptionKind::Concrete(OpaqueFileDescriptionBacking::new(backing)),
            common,
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        })
    }

    pub(crate) fn concrete<T>(backing: Arc<T>) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Self::concrete_with_common(backing, Arc::new(DescriptionCommon::new(0)))
    }
```

Change the `common` field's type from `DescriptionCommon` to
`Arc<DescriptionCommon>` and `common()` to `-> &DescriptionCommon` via `&self.common`.

In `fd_table.rs`, `kernel_file_description` reads the backing's handle and hands
it to the description, which is what joins the two:

```rust
pub(super) fn kernel_file_description(
    description: OpenDescriptionRef,
) -> Arc<crate::kernel::FileDescription> {
    let common = std::sync::Arc::clone(description.read().base().common());
    Arc::new(
        crate::kernel::FileDescription::concrete_with_common(description, common).unwrap_or_else(
            |error| {
                tracing::error!(%error, "file-description identity allocation failed");
                std::process::abort();
            },
        ),
    )
}
```

`IoUringBacking` construction (`ioring.rs`) does the same with its
`open_metadata`'s base, so a ring's description and its shadow agree; that
shadow is deleted in Task 5.

- [ ] **Step 5: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib status_flags_are_one_value -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 6: Move the read sites off the backing lock**

The 35 `status_flags` readers currently spell `…description.read().status_flags()`.
Rewrite them to `…description.common().status_flags()` with a committed,
count-asserted spec so the pass is auditable and drift-detecting:

```bash
scripts/migrate/rewrite.py --emit crates/carrick-runtime/src/dispatch/fs.rs \
  '.description.read().status_flags()' '.description.common().status_flags()' \
  > /tmp/entry.json
```

Build `scripts/migrate/2026-08-27-description-common-status-flags.json` as a
JSON array of such entries — one per file, with the exact occurrence count —
then:

```bash
scripts/migrate/rewrite.py --check scripts/migrate/2026-08-27-description-common-status-flags.json
scripts/migrate/rewrite.py scripts/migrate/2026-08-27-description-common-status-flags.json
```

Expected: `--check` reports the counts you wrote and no mismatch; the apply run
rewrites every file atomically. A count mismatch means the tree drifted — fix
the spec, never force the apply.

- [ ] **Step 7: Run the full host gate**

```bash
just fmt
just test
just clippy
just lint-domains
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src crates/carrick-abi/src scripts/migrate/2026-08-27-description-common-status-flags.json
git commit -m "refactor(runtime): share one status-flags value per description

O_NONBLOCK/O_APPEND/O_ASYNC and the access mode belong to the open file
description, so dup and CLONE_FILES sharers must observe one value. They lived
in OpenDescriptionBase, private to each of 25 enum variants, and every reader
took the backing RwLock to reach them — read(2) alone asks four such questions
before a byte moves.

Move the storage into the DescriptionCommon that kernel::FileDescription owns
and hand the same Arc to the backing, so the enum forwarders and the
description read one cell. Readers now go through the description and take no
backing lock. OpenDescriptionBase keeps a transient handle to the shared block;
it is deleted once the remaining fields follow.

Verified: status_flags_are_one_value_shared_by_the_description_and_its_backing
proves both directions of the join (write through the description, read through
the enum, and back). Mechanical reader migration applied through
scripts/migrate/rewrite.py with the count-asserted spec
scripts/migrate/2026-08-27-description-common-status-flags.json. just test,
just clippy, just lint-domains pass.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: Move the remaining generic fields

Repeat Task 3's pattern for `fd_refs`, `lease`, the async-I/O owner,
`async_sig`, `seals` and `secretmem`. These are smaller and independent of each
other, so they land as one commit.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs:242-582` (fields and
  accessors), `:1807-1895` (the `OpenDescription` forwarders)
- Modify: every site the compiler flags where a setter that used to need
  `&mut self` now takes `&self`
- Create: `scripts/migrate/2026-08-27-description-common-remaining.json`
- Test: `crates/carrick-runtime/src/dispatch/tests.rs`

**Interfaces:**
- Consumes: `DescriptionCommon`, `AsyncIoOwner`, `OpenDescriptionBase::common`
  from Task 3.
- Produces: no new API. `OpenDescriptionBase` afterwards holds **only**
  kind-specific state: `recv_timeout`, `send_timeout`, `pipe_capacity`,
  `pipe_capacity_shared`, `so_reuseaddr`, `so_reuseport`, `so_rcvbuf`,
  `so_sndbuf`, `so_passcred`, `ipv6_multicast_if`, `listening`,
  `connect_in_progress`, `pending_socket_error`, `socket_error_after_send`.

- [ ] **Step 1: Write the failing test**

Append to `crates/carrick-runtime/src/dispatch/tests.rs`:

```rust
#[test]
fn generic_description_state_outlives_the_backing_close() {
    let open_file = eventfd_open_file(0);
    let description = std::sync::Arc::clone(&open_file.description);

    description.common().retain_fd_ref();
    description.common().set_lease(crate::linux_abi::LINUX_F_WRLCK);
    description.common().set_owner(crate::kernel::AsyncIoOwner {
        owner_type: 2,
        owner_pid: 77,
    });
    description.common().set_async_sig(carrick_abi::LINUX_SIGUSR2);
    description.common().set_seals(Some(0b0010));
    description.common().set_secretmem(true);

    // Drain the backing to its Closed identity shell. Reaching this state used
    // to abort the process through OpenDescription::base().
    *description.write() = OpenDescription::Closed { was_epoll: false };

    assert_eq!(description.common().fd_refs(), 1);
    assert_eq!(description.common().lease(), crate::linux_abi::LINUX_F_WRLCK);
    assert_eq!(
        description.common().owner(),
        crate::kernel::AsyncIoOwner {
            owner_type: 2,
            owner_pid: 77,
        }
    );
    assert_eq!(description.common().async_sig(), carrick_abi::LINUX_SIGUSR2);
    assert_eq!(description.common().seals(), Some(0b0010));
    assert!(description.common().secretmem());
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib generic_description_state_outlives -- --test-threads=1 --nocapture
```

Expected: FAIL — either a compile error (`set_lease` still needs `&mut self` on
`OpenDescriptionBase`, not on `DescriptionCommon`) or, once it compiles, the
values read back as defaults because the enum still owns the storage.

- [ ] **Step 3: Delete the six fields from `OpenDescriptionBase` and delegate**

Remove `fd_refs`, `lease`, `owner_type`, `owner_pid`, `async_sig`, `seals`,
`secretmem` and their initializers. Replace the accessors with delegations:

```rust
    pub(super) fn lease(&self) -> i32 {
        self.common.lease()
    }

    pub(super) fn set_lease(&self, lease: i32) {
        self.common.set_lease(lease);
    }

    pub(super) fn owner(&self) -> (i32, i32) {
        let owner = self.common.owner();
        (owner.owner_type, owner.owner_pid)
    }

    pub(super) fn set_owner(&self, owner_type: i32, owner_pid: i32) {
        self.common.set_owner(crate::kernel::AsyncIoOwner {
            owner_type,
            owner_pid,
        });
    }

    pub(super) fn async_sig(&self) -> i32 {
        self.common.async_sig()
    }

    pub(super) fn set_async_sig(&self, sig: i32) {
        self.common.set_async_sig(sig);
    }

    pub(super) fn seals(&self) -> Option<u32> {
        self.common.seals()
    }

    pub(super) fn set_seals(&self, seals: Option<u32>) {
        self.common.set_seals(seals);
    }

    pub(super) fn secretmem(&self) -> bool {
        self.common.secretmem()
    }

    pub(super) fn set_secretmem(&self, secretmem: bool) {
        self.common.set_secretmem(secretmem);
    }
```

In the `OpenDescription` forwarders (`fd_table.rs:1807-1895`), `retain_fd_ref`,
`release_fd_ref` and `fd_ref_count` become `self.base().common().…`, and the
`set_*` forwarders lose their `&mut self`. Follow the compiler: every caller
that took `description.write()` only to call one of these setters now takes
`description.common()` instead. There should be no remaining `.base_mut()`
caller for these six fields.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib generic_description_state_outlives -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 5: Fix `FileDescriptionBacking::fd_ref_count`'s Closed special case**

`RwLock<OpenDescription>`'s impl (`fd_table.rs:1505-1512`) returns `0` for
`Closed` because the count used to live in the vanished base. That is now wrong —
the count is the description's, and a draining shell can legitimately still be
named. Replace the body with the unconditional read:

```rust
    fn fd_ref_count(&self) -> usize {
        self.read().fd_ref_count()
    }
```

and make `OpenDescription::fd_ref_count` read `self.base().common().fd_refs()`
for the functional variants, returning `0` only when the backing has no base at
all. Re-run the crate's kernel and dispatch tests; if a snapshot test pins the
old `Closed ⇒ 0` behaviour, update its expectation and say so in the commit
body — this is a deliberate semantic fix, not a test accommodation.

- [ ] **Step 6: Run the reader migration and the full host gate**

Build `scripts/migrate/2026-08-27-description-common-remaining.json` the same way
as Task 3 for the `.description.read().{lease,seals,owner,async_sig,is_secretmem}()`
shapes, then:

```bash
scripts/migrate/rewrite.py --check scripts/migrate/2026-08-27-description-common-remaining.json
scripts/migrate/rewrite.py scripts/migrate/2026-08-27-description-common-remaining.json
just fmt
just test
just clippy
just lint-domains
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-runtime/src scripts/migrate/2026-08-27-description-common-remaining.json
git commit -m "refactor(runtime): move the rest of the generic description state

The logical fd-reference count, the F_SETLEASE lease, the F_SETOWN async-I/O
owner, F_SETSIG, the memfd seal set and the memfd_secret marker are all
description-level state Linux shares across dup and CLONE_FILES. They were
copied into each of OpenDescription's 25 variants and became unreachable — an
abort in OpenDescription::base() — the moment a description drained to its
Closed identity shell, which is precisely when close accounting still needs the
fd-reference count.

Move all six into DescriptionCommon. OpenDescriptionBase now holds only
kind-specific state (socket options and timeouts, pipe capacity, the pending
socket errors, the netlink and multicast bookkeeping). Setters lose &mut self,
so a caller that took a description write lock to set an owner no longer does.

Behaviour change, deliberate: FileDescriptionBacking::fd_ref_count no longer
reports 0 for a Closed description. The count belongs to the description
identity, not to the drained backing, and a draining shell can still be named
by a live fd-table slot.

Verified: generic_description_state_outlives_the_backing_close sets all six
through the description, drains the backing to Closed, and reads them back.
just test, just clippy, just lint-domains pass.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: Delete `base()`, `base_mut()`, the io_uring shadow, and the abort

The payoff commit: with no generic state left in the enum, the two 25-arm
matches, the ring's shadow `OpenDescription`, and the
`open_description()` process abort all become deletable.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs:1741-1805` (delete
  `base`/`base_mut`), `:1518-1530` (delete the abort)
- Modify: `crates/carrick-runtime/src/dispatch/ioring.rs:236-260, 466-468`
  (delete `open_metadata`)
- Modify: `crates/carrick-runtime/src/kernel/objects.rs:506-521`
  (`FileDescriptionBacking` gains a default `fd_ref_count`)
- Create: `scripts/migrate/2026-08-27-description-common-delete-base.json`
- Test: `crates/carrick-runtime/src/dispatch/tests.rs`

**Interfaces:**
- Consumes: everything from Tasks 2–4.
- Produces:
  - `FileDescriptionBacking::retain_fd_ref`, `release_fd_ref` and
    `fd_ref_count` are **removed** from the trait — `FileDescription` answers
    them from `DescriptionCommon` for every backing, so no implementor
    reimplements them.
  - `FileDescription::open_description(&self) -> Option<&RwLock<OpenDescription>>`
    replaces the aborting `-> &RwLock<OpenDescription>`.

- [ ] **Step 1: Write the failing test**

Append to `crates/carrick-runtime/src/dispatch/tests.rs`:

```rust
#[test]
fn a_backing_with_no_open_description_answers_generic_questions_without_aborting() {
    // A backing that is NOT RwLock<OpenDescription> and carries no shadow copy
    // of one. Before this change, asking it a generic question reached
    // FileDescription::open_description(), which aborted the process.
    #[derive(Debug)]
    struct BareBacking;

    impl crate::kernel::FileDescriptionBacking for BareBacking {
        fn is_epoll(&self) -> bool {
            false
        }

        fn snapshot_until(
            &self,
            _deadline: std::time::Instant,
        ) -> Option<crate::kernel::FileDescriptionBackingSnapshot> {
            None
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    let description = crate::kernel::FileDescription::concrete_with_common(
        std::sync::Arc::new(BareBacking),
        std::sync::Arc::new(crate::kernel::DescriptionCommon::new(
            carrick_abi::LINUX_O_NONBLOCK,
        )),
    )
    .expect("file description identity");

    assert_eq!(
        description.common().status_flags(),
        carrick_abi::LINUX_O_NONBLOCK
    );
    description.common().retain_fd_ref();
    assert_eq!(description.common().fd_refs(), 1);
    assert!(!description.is_epoll());
    assert!(description.open_description().is_none());
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib a_backing_with_no_open_description -- --test-threads=1 --nocapture
```

Expected: FAIL to compile — `BareBacking` does not implement the trait's
`retain_fd_ref`/`release_fd_ref`/`fd_ref_count`, and `open_description` returns
`&RwLock<OpenDescription>`, not an `Option`.

- [ ] **Step 3: Shrink the trait**

In `kernel/objects.rs`, delete `retain_fd_ref`, `release_fd_ref` and
`fd_ref_count` from `FileDescriptionBacking`, leaving:

```rust
pub(crate) trait FileDescriptionBacking: Any + Send + Sync {
    fn is_epoll(&self) -> bool;

    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionBackingSnapshot>;

    fn as_any(&self) -> &dyn Any;
}
```

`FileDescription::retain_fd_ref`/`release_fd_ref`/`fd_ref_count` now delegate to
`self.common` unconditionally — including for `FileDescriptionKind::Regular` and
`::Epoll`, which previously returned early and silently dropped the accounting.

- [ ] **Step 4: Delete `base()`, `base_mut()` and the shadow**

In `fd_table.rs`, delete `OpenDescription::base` and `OpenDescription::base_mut`
entirely. Every remaining `.base()` caller wants a kind-specific field, so it
already knows the variant: rewrite each to destructure that variant directly.
Use a count-asserted spec for the repeated shapes and hand-edit the rest; the
compiler enumerates them all.

In `ioring.rs`, delete the `open_metadata: parking_lot::RwLock<OpenDescription>`
field, its initializer, and `open_metadata()`. `IoUringBacking` keeps its own
`is_epoll`/`snapshot_until`; everything generic now comes from
`FileDescription::common()`.

In `fd_table.rs`, replace the aborting resolver:

```rust
impl crate::kernel::FileDescription {
    /// The enum-shaped backing, when this description has one. `None` for a
    /// typed backing (io_uring today) — generic questions go through
    /// `common()`, which every backing answers.
    fn open_description(&self) -> Option<&RwLock<OpenDescription>> {
        self.concrete_backing::<RwLock<OpenDescription>>()
    }
}
```

`read()`/`try_read()`/`write()` become fallible in the same shape. Where a caller
genuinely requires the enum (a variant-specific match), have it return
`LINUX_EBADF`/`LINUX_EINVAL` for `None` rather than abort — the io_uring
pre-checks already scattered through those handlers become the `None` arm and
can be deleted.

- [ ] **Step 5: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib a_backing_with_no_open_description -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 6: Prove the 25-arm matches are gone**

```bash
grep -c 'OpenDescription::' crates/carrick-runtime/src/dispatch/fd_table.rs
grep -n 'fn base\b\|fn base_mut\b\|fn open_metadata\b' crates/carrick-runtime/src/dispatch/fd_table.rs crates/carrick-runtime/src/dispatch/ioring.rs
python3 - <<'EOF'
import re, os, collections
root = 'crates/carrick-runtime/src'
worst = collections.Counter()
for dp, _, fns in os.walk(root):
    for fn in fns:
        if not fn.endswith('.rs'):
            continue
        p = os.path.join(dp, fn)
        lines = open(p, encoding='utf8', errors='replace').read().split('\n')
        starts = [(i, m.group(6)) for i, l in enumerate(lines)
                  if (m := re.match(r'\s*(pub(\([^)]*\))?\s+)?(async\s+)?(const\s+)?(unsafe\s+)?fn\s+(\w+)', l))]
        starts.append((len(lines), None))
        for (s, name), (e, _) in zip(starts, starts[1:]):
            n = len(set(re.findall(r'OpenDescription::(\w+)', '\n'.join(lines[s:e]))))
            if n >= 20:
                worst[f"{p}::{name}"] = n
for k, v in worst.most_common():
    print(v, k)
print("functions matching >=20 variants:", len(worst))
EOF
```

Expected: the second command prints nothing (all three functions deleted), and
the census reports **15** functions at ≥20 variants, down from 17 — `base` and
`base_mut` gone. Record both numbers in the commit body.

- [ ] **Step 7: Run the full host gate**

```bash
just fmt
just test
just test-integration
just clippy
just doc
just lint-domains
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src scripts/migrate/2026-08-27-description-common-delete-base.json
git commit -m "refactor(runtime): delete base(), base_mut() and the io_uring shadow

With every generic field living on the description, OpenDescription::base and
base_mut — two 25-arm matches whose only job was to reach fields every variant
already had, both aborting the process on Closed — have nothing left to return.
Delete them.

IoUringBacking carried a whole shadow RwLock<OpenDescription> purely so the rest
of dispatch could ask it for status flags and a reference count; that is now
FileDescription::common(), so the shadow goes too. FileDescription::
open_description() stops aborting on an unrecognized backing and returns an
Option instead: a typed backing simply has no enum, and the io_uring pre-checks
scattered through the read/write/stat/mmap handlers collapse into its None arm.

FileDescriptionBacking loses retain_fd_ref/release_fd_ref/fd_ref_count — a
backing never reimplements them now. That also fixes silent accounting loss for
the Regular and Epoll description kinds, which used to return early.

Verified: a_backing_with_no_open_description_answers_generic_questions_without_
aborting builds a third backing type that implements only the three remaining
trait methods and answers every generic question — the extensibility this seam
was supposed to provide and did not. Functions matching >=20 OpenDescription
variants: 17 -> 15. just ci passes.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: One readiness authority

`epoll_ready_events` (`net.rs:1054`) and `poll_ready_events` (`net.rs:1958`) are
two readiness state machines over the same objects with asymmetric coverage:
poll names 14 variants epoll does not (`Netlink`, `Inotify`, `Fanotify`,
`SignalFd`, `Pidfd`, `PerfEvent`, `FsContext`, `File`, `InMemoryFile`,
`SyntheticFile`, `HostFile`, `Directory`, `Epoll`, `Closed`), and epoll names
one poll does not (`Mqueue`). Everything epoll does not name falls through to a
host `poll(2)` and returns `0` when the description has no host fd.

`Netlink` is exactly that case: it is synthetic, `host_fd_for_poll`
(`net.rs:~2130`) has no arm for it, and its readable bytes live in the
description's `recv_queue`. So `poll()` reports POLLIN on a netlink socket with
a queued dump while `epoll_pwait` reports nothing.

**Files:**
- Modify: `crates/carrick-abi/src/lib.rs` (add the typed conversions)
- Modify: `crates/carrick-runtime/src/kernel/objects.rs` (add `readiness` to the trait)
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs` (implement it for `RwLock<OpenDescription>`)
- Modify: `crates/carrick-runtime/src/dispatch/ioring.rs` (implement it for `IoUringBacking`)
- Test: `crates/carrick-runtime/src/dispatch/net.rs` (the crate's existing `mod tests` at the bottom of the file)

**Interfaces:**
- Consumes: `FileDescriptionBacking` (three methods after Task 5).
- Produces:
  - `carrick_abi::LinuxPollEvents::to_epoll(self) -> LinuxEpollEvents` and
    `LinuxEpollEvents::to_poll(self) -> LinuxPollEvents`.
  - `FileDescriptionBacking::readiness(&self, interest: LinuxEpollEvents) -> LinuxEpollEvents`,
    with **no default implementation** — a new backing must state its readiness.

- [ ] **Step 1: Write the failing test**

Append to `crates/carrick-runtime/src/dispatch/net.rs`'s test module:

```rust
#[test]
fn epoll_and_poll_agree_that_a_queued_netlink_dump_is_readable() {
    let dispatcher = SyscallDispatcher::new();
    let fd = dispatcher
        .install_fd_at_or_above(
            3,
            OpenFile::from_open_description(
                Arc::new(RwLock::new(OpenDescription::Netlink {
                    base: OpenDescriptionBase::new(0),
                    protocol: 0,
                    sock_type: LINUX_SOCK_DGRAM,
                    pid: 0,
                    groups: 0,
                    recv_queue: VecDeque::from(vec![0xAAu8; 32]),
                })),
                0,
            ),
        )
        .expect("install netlink fd");

    assert_eq!(
        dispatcher.poll_ready_events(fd, LINUX_POLLIN) & LINUX_POLLIN,
        LINUX_POLLIN,
        "poll(2) already reports a queued netlink dump as readable"
    );
    assert_eq!(
        dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
        LINUX_EPOLLIN,
        "epoll must report the same readiness as poll for the same description; \
         a synthetic netlink socket has no host fd, so the host-poll fallback \
         answers 0 and glibc's __check_pf/getaddrinfo never wakes"
    );
}
```

Use whichever socket-type constant the neighbouring netlink tests in that module
already import; do not add a new `const`.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib epoll_and_poll_agree_that_a_queued_netlink -- --test-threads=1 --nocapture
```

Expected: FAIL on the **second** assertion (`epoll_ready_events` returns 0)
while the first passes. If the first assertion fails instead, stop: the premise
is wrong and the divergence is elsewhere — re-derive it before continuing.

- [ ] **Step 3: Add the typed poll/epoll conversions**

In `crates/carrick-abi/src/lib.rs`, next to the two bitflags declarations
(`LinuxEpollEvents` at `:4859`, `LinuxPollEvents` at `:5135`):

```rust
impl LinuxPollEvents {
    /// The epoll spelling of the same readiness. Linux gives POLL* and EPOLL*
    /// the same numeric values for the bits both define, but they are different
    /// domains — poll is `i16`, epoll is `u32` and carries ET/ONESHOT bits poll
    /// has no encoding for — so the conversion is explicit and bit-by-bit.
    pub const fn to_epoll(self) -> LinuxEpollEvents {
        LinuxEpollEvents::from_bits_retain(self.bits() as u16 as u32)
    }
}

impl LinuxEpollEvents {
    /// The poll spelling of this readiness. Bits with no poll encoding
    /// (ET, ONESHOT, EXCLUSIVE, WAKEUP) are dropped.
    pub const fn to_poll(self) -> LinuxPollEvents {
        LinuxPollEvents::from_bits_truncate(self.bits() as i16)
    }
}
```

Add a unit test in the same file asserting `IN`, `OUT`, `PRI`, `ERR`, `HUP` and
`RDHUP` round-trip, and that `LinuxEpollEvents::ET.to_poll()` is empty.

- [ ] **Step 4: Add `readiness` to the trait and implement it for the enum**

In `kernel/objects.rs`:

```rust
pub(crate) trait FileDescriptionBacking: Any + Send + Sync {
    fn is_epoll(&self) -> bool;

    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionBackingSnapshot>;

    /// Level readiness for `interest`, in epoll's domain. This is the ONE
    /// readiness authority: `poll`/`ppoll` and `epoll_pwait` both translate to
    /// and from it rather than keeping separate state machines. A backing whose
    /// readiness lives in a real host object returns the host's answer; a
    /// synthetic backing answers from its own queues.
    fn readiness(&self, interest: LinuxEpollEvents) -> LinuxEpollEvents;

    fn as_any(&self) -> &dyn Any;
}
```

In `fd_table.rs`, implement it for `RwLock<OpenDescription>` by moving the
**union** of the two existing matches into one function. Every variant either
names an arm or falls through to the host-poll recompute. The synthetic
variants — `Netlink`, `Inotify`, `Fanotify`, `SignalFd`, `Pidfd`, `PerfEvent`,
`FsContext`, `Mqueue`, `InMemorySocket`, `PipeReader`, `PipeWriter`, `EventFd`,
`TimerFd`, `SyntheticDevice`, `File`, `InMemoryFile`, `SyntheticFile`,
`HostFile`, `Directory`, `Epoll`, `Closed` — take their arm from whichever of
the two current functions defines one, and `Netlink` takes poll's:

```rust
            OpenDescription::Netlink { recv_queue, .. } => {
                let mut ready = LinuxEpollEvents::empty();
                if !recv_queue.is_empty() {
                    ready |= LinuxEpollEvents::IN;
                }
                // A synthetic netlink socket has no send-side backpressure.
                ready |= LinuxEpollEvents::OUT;
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
```

Where the two functions disagree on an arm both define, **poll's arm wins** and
the commit body says which arms changed and why: poll's coverage is the strictly
larger and better-tested set, and every divergence found so far is epoll
missing a case rather than poll inventing one.

The `_ =>` fallback (the host `poll(2)` recompute with its SO_REUSEPORT,
MSG_ERRQUEUE and EPOLLPRI corrections) moves across unchanged — it is host-fd
behaviour, not per-variant behaviour.

- [ ] **Step 5: Implement it for `IoUringBacking`**

In `ioring.rs`, replace the ad-hoc `ready_events(&self, requested: u32) -> u32`
with the trait method, keeping the body (CQ head != tail ⇒ `IN`, always `OUT`)
and switching to `LinuxEpollEvents`. Delete `ready_events`.

- [ ] **Step 6: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib epoll_and_poll_agree_that_a_queued_netlink -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-abi/src/lib.rs crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/dispatch/fd_table.rs crates/carrick-runtime/src/dispatch/ioring.rs crates/carrick-runtime/src/dispatch/net.rs
git commit -m "fix(runtime): give every description one readiness authority

epoll_ready_events and poll_ready_events were two readiness state machines over
the same descriptions with asymmetric coverage: poll names fourteen variants
epoll does not, epoll names one poll does not, and everything epoll does not
name falls through to a host poll(2) that answers 0 when the description has no
host fd. A synthetic AF_NETLINK socket is exactly that case, so a queued
rtnetlink dump was readable to poll(2) and invisible to epoll_pwait — glibc's
__check_pf and getaddrinfo poll netlink, and an epoll-driven resolver never woke.

Add FileDescriptionBacking::readiness, the single level-readiness authority in
epoll's domain, and implement it once for the enum backing (the union of the two
old matches, poll's arm winning where they disagreed) and once for
IoUringBacking. Add typed LinuxPollEvents <-> LinuxEpollEvents conversions in
carrick-abi so the two syscall surfaces share one domain instead of two integer
widths.

Verified red-first: epoll_and_poll_agree_that_a_queued_netlink_dump_is_readable
fails on the epoll assertion and passes on the poll assertion against the
pre-fix binary, and passes on both after.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: Reduce `poll_ready_events` and `epoll_ready_events` to translators

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/net.rs:1054-1330` and `:1958-2260`
- Test: `crates/carrick-runtime/src/dispatch/net.rs` (test module)

**Interfaces:**
- Consumes: `FileDescriptionBacking::readiness`, `LinuxPollEvents::to_epoll`,
  `LinuxEpollEvents::to_poll` from Task 6.
- Produces: no new API; both functions keep their current signatures so no
  caller changes.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn poll_and_epoll_readiness_agree_for_every_installed_description_kind() {
    let dispatcher = SyscallDispatcher::new();
    for open_file in every_description_kind_fixture() {
        let fd = dispatcher
            .install_fd_at_or_above(3, open_file)
            .expect("install fixture fd");
        let epoll = dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN | LINUX_EPOLLOUT);
        let poll = dispatcher.poll_ready_events(fd, LINUX_POLLIN | LINUX_POLLOUT);
        assert_eq!(
            carrick_abi::LinuxEpollEvents::from_bits_retain(epoll).to_poll().bits()
                & (LINUX_POLLIN | LINUX_POLLOUT),
            poll & (LINUX_POLLIN | LINUX_POLLOUT),
            "poll and epoll must not disagree about fd {fd}"
        );
    }
}
```

Write `every_description_kind_fixture() -> Vec<OpenFile>` in the same test
module, returning one constructed `OpenFile` per `OpenDescription` variant that
can be built without a live guest — reuse `eventfd_open_file` from
`dispatch/tests.rs` as the shape. Variants needing a real host object (`HostFile`,
`HostSocket`, `HostPipe`) build one with `libc::pipe`/`libc::socketpair` and are
included; variants that cannot be constructed in-process are listed with a
one-line comment saying why, so the omission is deliberate and reviewable rather
than silent.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib poll_and_epoll_readiness_agree_for_every -- --test-threads=1 --nocapture
```

Expected: FAIL for at least the `Mqueue` fixture, which epoll answers from the
message queue and poll (pre-Task-7) does not name.

- [ ] **Step 3: Replace both bodies**

```rust
    fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        let interest = carrick_abi::LinuxEpollEvents::from_bits_retain(requested_events);
        open_file.description.readiness(interest).bits()
    }
```

```rust
    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_file(fd) else {
            return self.bare_stdio_poll_ready_events(fd, requested_events);
        };
        let interest = carrick_abi::LinuxPollEvents::from_bits_truncate(requested_events);
        open_file
            .description
            .readiness(interest.to_epoll())
            .to_poll()
            .bits()
    }
```

Move poll's bare-stdio special case (the `is_stdio_fd` branch that polls host fd
0 directly, `net.rs:1963-1990`) verbatim into a private
`bare_stdio_poll_ready_events(&self, fd: i32, requested_events: i16) -> i16`.
That branch is about fds with **no description at all**, so it stays outside the
readiness authority — say so in a comment.

Add `FileDescription::readiness(&self, interest: LinuxEpollEvents) -> LinuxEpollEvents`
in `kernel/objects.rs` forwarding to the backing, so both call sites read the
same way.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib poll_and_epoll_readiness_agree_for_every -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 5: Run the full gate**

```bash
just fmt
just test
just test-integration
just clippy
just doc
just lint-domains
just ci
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/net.rs crates/carrick-runtime/src/kernel/objects.rs
git commit -m "refactor(runtime): make poll and epoll translators over one readiness

epoll_ready_events and poll_ready_events each carried a per-variant readiness
match; the two could only agree by being edited together, and they had already
drifted. Both now resolve the fd, ask the backing for readiness once, and
translate: epoll returns the bits directly, poll converts through the typed
LinuxPollEvents <-> LinuxEpollEvents pair.

poll's bare-stdio branch moves to bare_stdio_poll_ready_events and stays outside
the authority on purpose: fds 0/1/2 with no description have no backing to ask.

Verified: poll_and_epoll_readiness_agree_for_every_installed_description_kind
installs one fixture per constructible OpenDescription variant and asserts the
two surfaces agree; it fails on Mqueue before this change. just ci passes.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: Open `AuthorityBacking`

`file_authority::AuthorityBacking` (`backing.rs:12`) is a closed 10-variant enum,
and its own doc says further kinds "are added here as their operation families
move". On that trajectory the cutover lands on a 25-variant closed enum — the
shape this plan just spent seven tasks dismantling — and it pulls io_uring, the
one fd type that escaped, back into an enum. Open it now, while it has ten
variants and one implementor family, not later.

**Files:**
- Modify: `crates/carrick-runtime/src/file_authority/backing.rs`
- Modify: `crates/carrick-runtime/src/file_authority/core.rs` (every
  `AuthorityBacking::` match)
- Test: `crates/carrick-runtime/src/file_authority/tests.rs`

**Interfaces:**
- Consumes: `DescriptionBackingSnapshot`, `VfsObjectId`, `EpollState`,
  `HostStreamKind`, `PipeId`, `PipeEnd` (unchanged).
- Produces:
  - `pub(super) trait AuthorityBackingKind: std::fmt::Debug + Send + Sync` with
    `fn snapshot(&self) -> DescriptionBackingSnapshot`,
    `fn host_fd(&self) -> Option<RawFd>`, and `fn as_any(&self) -> &dyn Any`.
  - `pub(super) struct AuthorityBacking(Box<dyn AuthorityBackingKind>)` with
    `fn new<T: AuthorityBackingKind + 'static>(kind: T) -> Self`,
    `fn snapshot(&self) -> DescriptionBackingSnapshot`,
    `fn host_fd(&self) -> Option<RawFd>`,
    `fn downcast_ref<T: AuthorityBackingKind + 'static>(&self) -> Option<&T>`,
    `fn downcast_mut<T: AuthorityBackingKind + 'static>(&mut self) -> Option<&mut T>`.
  - Ten types replacing the ten variants, same field names:
    `SyntheticBacking`, `VfsBacking`, `HostBacking`, `HostStreamBacking`,
    `IoUringBacking` (authority-local; do not confuse with
    `dispatch::ioring::IoUringBacking`), `EpollBacking`, `EventCounterBacking`,
    `SignalFdBacking`, `TimerBacking`, `PipeEndBacking`.

- [ ] **Step 1: Write the failing test**

Append to `crates/carrick-runtime/src/file_authority/tests.rs`:

```rust
#[test]
fn an_authority_backing_kind_can_be_added_without_editing_the_backing_module() {
    // The extensibility claim, stated as a test: a backing kind defined
    // OUTSIDE backing.rs participates fully. If this stops compiling, the
    // authority has re-closed and the cutover is heading back to a god enum.
    #[derive(Debug)]
    struct FictionalBacking {
        length: u64,
    }

    impl super::backing::AuthorityBackingKind for FictionalBacking {
        fn snapshot(&self) -> DescriptionBackingSnapshot {
            DescriptionBackingSnapshot::Synthetic {
                length: self.length,
            }
        }

        fn host_fd(&self) -> Option<std::os::fd::RawFd> {
            None
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    let backing = super::backing::AuthorityBacking::new(FictionalBacking { length: 9 });

    assert_eq!(
        backing.snapshot(),
        DescriptionBackingSnapshot::Synthetic { length: 9 }
    );
    assert_eq!(backing.host_fd(), None);
    assert_eq!(
        backing
            .downcast_ref::<FictionalBacking>()
            .expect("downcast to the concrete kind")
            .length,
        9
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib an_authority_backing_kind_can_be_added -- --test-threads=1 --nocapture
```

Expected: FAIL to compile — `AuthorityBackingKind` does not exist and
`AuthorityBacking` is an enum with no `new`.

- [ ] **Step 3: Convert the enum to a trait object**

Rewrite `backing.rs`:

```rust
use std::any::Any;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::epoll::EpollState;
use super::types::{DescriptionBackingSnapshot, VfsObjectId};

/// One authority-owned open-file-description payload.
///
/// Open by construction: a new backing kind is a new type implementing this
/// trait, not a new arm in every match over a closed enum. That is the whole
/// difference between this seam and the `dispatch::OpenDescription` enum it
/// replaces, where 17 functions had to enumerate all 25 variants.
pub(super) trait AuthorityBackingKind: std::fmt::Debug + Send + Sync {
    fn snapshot(&self) -> DescriptionBackingSnapshot;

    /// The host descriptor this backing's readiness and I/O ride on, if any.
    /// `None` for a purely synthetic backing.
    fn host_fd(&self) -> Option<RawFd>;

    fn as_any(&self) -> &dyn Any;
}

#[derive(Debug)]
pub(super) struct AuthorityBacking(Box<dyn AuthorityBackingKind>);

impl AuthorityBacking {
    pub(super) fn new<T>(kind: T) -> Self
    where
        T: AuthorityBackingKind + 'static,
    {
        Self(Box::new(kind))
    }

    pub(super) fn snapshot(&self) -> DescriptionBackingSnapshot {
        self.0.snapshot()
    }

    pub(super) fn host_fd(&self) -> Option<RawFd> {
        self.0.host_fd()
    }

    pub(super) fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: AuthorityBackingKind + 'static,
    {
        self.0.as_any().downcast_ref()
    }
}
```

Then define the ten concrete types, one per former variant, keeping the field
names identical so `core.rs`'s destructuring reads the same. A former
`AuthorityBacking::Host { fd, writable }` becomes:

```rust
#[derive(Debug)]
pub(super) struct HostBacking {
    pub(super) fd: OwnedFd,
    pub(super) writable: bool,
}

impl AuthorityBackingKind for HostBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::HostFile {
            writable: self.writable,
        }
    }

    fn host_fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

`downcast_mut` needs `as_any_mut`; add it to the trait alongside `as_any` and
implement it identically (`self`) in every kind. In `core.rs`, replace each
`match backing { AuthorityBacking::X { .. } => … }` with
`backing.downcast_ref::<XBacking>()`; the compiler enumerates every site.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib an_authority_backing_kind_can_be_added -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 5: Run the authority's own suite and the full gate**

```bash
cargo test -p carrick-runtime --lib file_authority:: -- --test-threads=1
just ci
```

Expected: all PASS. The authority suite is the only coverage this module has —
if any of it needed changing beyond mechanical `match` → `downcast_ref`
rewrites, stop and explain why in the commit body before proceeding.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/file_authority
git commit -m "refactor(runtime): open AuthorityBacking to new kinds

AuthorityBacking was a closed ten-variant enum whose own doc committed to
growing a variant per operation family. The legacy model it replaces is a
twenty-five-variant closed enum that seventeen functions must enumerate in full;
converging on the same shape one layer up would carry the cost forward, and it
would pull io_uring — the one fd type that escaped the legacy enum — back into
one.

Replace it with AuthorityBackingKind, a trait carrying snapshot and host_fd,
behind a boxed AuthorityBacking with typed downcast. The ten variants become
ten types with identical field names, so core.rs's destructuring is a
mechanical match-to-downcast rewrite.

Verified: an_authority_backing_kind_can_be_added_without_editing_the_backing_
module defines a backing kind in the test module and exercises it end to end;
if the authority ever re-closes, that test stops compiling. The full
file_authority suite passes unchanged. just ci passes.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 9: Route the first production family through the authority

> **Approved correction, 2026-08-28:** The live implementation invalidated the
> nine-site recipe below: the taxonomy has 14 heterogeneous entries, the actual
> `F_SETPIPE_SZ` guards are classified elsewhere, and activation creates an
> empty private authority table beside the canonical kernel `Arc<FileTable>`.
> The user approved replacing that dual-store recipe with the canonical-object
> cutover in
> [`2026-08-28-fd-description-task9-canonical-authority.md`](2026-08-28-fd-description-task9-canonical-authority.md).
> That replacement plan is authoritative for Task 9; the original text remains
> below only as an audit record of what was superseded.

`FileAuthorityCore::execute_call` has **zero** production callers. Route the
smallest K1 family — `slot_description_mutation`, 9 sites — through it, proving
Wave 2's mechanism end-to-end and lowering the burndown ceiling for the first
time. This is a guest-visible path, so it takes the signed probe gate too.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs` (the dispatcher's
  authority accessor at `:4984-4990`)
- Modify: the 9 sites the taxonomy marks `slot_description_mutation` — read
  them out of `scripts/migrate/k1-file-authority-callsite-taxonomy.json`
- Modify: `scripts/migrate/k1-burndown-ceiling.json`
- Test: `crates/carrick-runtime/src/file_authority/tests.rs`,
  `crates/carrick-runtime/src/dispatch/fs/tests.rs`

**Interfaces:**
- Consumes: `SyscallDispatcher::file_authority_binding`,
  `FileAuthorityRun`, `Command`, `Outcome`, `Request`, `Response` from the
  authority module; `AuthorityBacking::downcast_ref` from Task 8.
- Produces: `SyscallDispatcher::authority_call(&self, command: Command, expected: ObjectGeneration) -> Result<Outcome, AuthorityError>`
  — the single production entry point into the authority. Every later family
  migrates through this one function.

- [ ] **Step 1: List the exact sites**

```bash
python3 - <<'EOF'
import json, pathlib
tax = json.loads(pathlib.Path("scripts/migrate/k1-file-authority-callsite-taxonomy.json").read_text())
sites = [e for e in tax["entries"] if e["migration_family"] == "slot_description_mutation"]
for s in sites:
    print(f'{s["file"]}:{s["line"]}  {s["enclosing_function"]}  {s["text"]}')
print("total:", len(sites))
EOF
```

Expected: 9 lines. Paste them into the commit body — the plan's burndown is
only auditable if the commit names what it removed.

- [ ] **Step 2: Write the failing test**

Append to `crates/carrick-runtime/src/file_authority/tests.rs`:

```rust
#[test]
fn a_description_mutation_commits_once_and_publishes_one_revision() {
    let mut harness = Harness::new();
    let table = harness.create_table();
    let fd = harness.create_pipe_and_install(table);

    let before = harness.revision;
    let outcome = harness.send(
        Command::SetPipeCapacity {
            table,
            fd,
            capacity: PipeCapacity::from_guest(131_072).expect("pipe capacity"),
        },
        ObjectGeneration::INITIAL,
    );

    assert!(matches!(outcome, Outcome::DescriptionMutated { .. }));
    assert!(
        harness.revision > before,
        "one mutation publishes exactly one monotonic revision"
    );

    // A stale expected generation must be refused, not applied twice: the
    // client is the only place a retry can originate, and a silently
    // reapplied mutation is the partial-commit ambiguity the closed API
    // exists to prevent.
    let stale = harness.send_with_generation(
        Command::SetPipeCapacity {
            table,
            fd,
            capacity: PipeCapacity::from_guest(65_536).expect("pipe capacity"),
        },
        ObjectGeneration::INITIAL,
    );
    assert!(matches!(
        stale,
        Outcome::Error(AuthorityError::StaleGeneration { .. })
    ));
}
```

Use the `Harness` helpers already in that file
(`Harness::new`, `send`); add `create_table`, `create_pipe_and_install` and
`send_with_generation` there if they are not present, matching the existing
`send` shape.

- [ ] **Step 3: Run the test to verify it fails**

```bash
cargo test -p carrick-runtime --lib a_description_mutation_commits_once -- --test-threads=1 --nocapture
```

Expected: FAIL — either the helper does not exist, or the authority does not yet
refuse a stale generation for this command.

- [ ] **Step 4: Make the authority satisfy it**

Implement whatever `core.rs` is missing for `SetPipeCapacity`: generation
validation before mutation, one `revision.publish()` after all fields commit,
and `Outcome::DescriptionMutated` carrying the new revision. Follow the locking
order the approved plan fixes: authority lifecycle → tables by ascending
`FileTableId` → descriptions by ascending `FileDescriptionId`. Never hold an
authority lock across guest-memory access or a host wait.

- [ ] **Step 5: Run the test to verify it passes**

```bash
cargo test -p carrick-runtime --lib a_description_mutation_commits_once -- --test-threads=1 --nocapture
```

Expected: PASS.

- [ ] **Step 6: Add the single production entry point and route the 9 sites**

In `dispatch/mod.rs`:

```rust
    /// The one way production code reaches the file authority. Every K1
    /// family migrates through here; there is no second entry point and no
    /// fallback to the legacy table. A run whose authority is unbound has not
    /// completed activation, which is a lifecycle bug, not a condition to
    /// degrade around.
    pub(crate) fn authority_call(
        &self,
        command: crate::file_authority::Command,
        expected: crate::file_authority::ObjectGeneration,
    ) -> Result<crate::file_authority::Outcome, crate::file_authority::AuthorityError> {
        let authority = self
            .file_authority
            .read()
            .clone()
            .ok_or(crate::file_authority::AuthorityError::Unbound)?;
        authority.call(command, expected)
    }
```

Rewrite each of the 9 `slot_description_mutation` sites to call it instead of
taking a description write guard. Delete the legacy guard path at each site in
the same commit — do not leave a fallback.

- [ ] **Step 7: Lower the burndown ceiling**

```bash
python3 - <<'EOF'
import json, pathlib
p = pathlib.Path("scripts/migrate/k1-burndown-ceiling.json")
doc = json.loads(p.read_text())
doc["ceiling"]["slot_description_mutation"] = 0
p.write_text(json.dumps(doc, indent=1) + "\n")
EOF
python3 scripts/migrate/check-k1-file-authority-inventory.py
python3 scripts/migrate/check-k1-file-authority-taxonomy.py
python3 scripts/migrate/check-k1-burndown.py
```

Expected: the inventory and taxonomy checkers accept the regenerated ledger
(commit the regenerated JSON), and the burndown checker passes with
`slot_description_mutation: 0`.

- [ ] **Step 8: Run the full gate, including the signed probe gate**

```bash
just fmt
just ci
just build
just conformance-probes
```

Expected: `just ci` PASS. `just conformance-probes` PASS — this is the first
guest-visible authority routing, so the line-exact ABI probe gate is required,
not optional. Run it from the **repo root**: from any other cwd it finds no
probe binaries, SKIPs every lane and reports `ok` in 0.04s, which is a green
that gated nothing. Grep the gate's logs with `grep -a` — they carry binary
bytes and a plain `grep` silently matches nothing. Never run carrick and the
Docker oracle concurrently; stamp `CARRICK_RUN_ID` and reap with
`scripts/sudo/kill.sh <run-id>`, never `pkill -f carrick`.

- [ ] **Step 9: Commit**

```bash
git add crates/carrick-runtime/src scripts/migrate/k1-burndown-ceiling.json scripts/migrate/k1-file-authority-operation-inventory.json scripts/migrate/k1-file-authority-callsite-taxonomy.json
git commit -m "feat(runtime): route slot-description mutation through the authority

FileAuthorityCore has been built, tested and activated since 2026-08-12, and
execute_call had zero production callers: every syscall still mutated the legacy
per-description RwLock directly, so the authority was a second model of file
descriptors growing beside the shipping one. Wave 2 of the approved migration
says to move production callers family by family; this is the first family.

Add SyscallDispatcher::authority_call, the single production entry point, and
move the nine slot_description_mutation sites onto it, deleting the legacy guard
path at each. There is no fallback: an unbound authority is a lifecycle bug, not
a condition to degrade around.

Lower the slot_description_mutation burndown ceiling to 0 so the family cannot
regrow.

Sites removed:
<paste the nine file:line entries printed in Step 1>

Verified: a_description_mutation_commits_once_and_publishes_one_revision pins
one monotonic revision per mutation and a refused stale generation. just ci and
just conformance-probes pass on the signed binary.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Follow-on plans (deliberately not in this one)

Each of these is a separate subsystem that produces working software on its own,
and each deserves its own plan written against the state this one leaves behind:

1. **Port fd kinds out of `OpenDescription` one at a time**, io_uring-style, now
   that a backing needs only three trait methods plus `readiness`. Start with
   `SignalFd` (one field) to pin the mechanism, then `EventFd` (readiness +
   read/write + fork coherence). Each port deletes ~17 match arms; the census
   command in Task 5 Step 6 is the progress metric.
2. **Introduce the object/inode layer, pipes first.** Carrick models fd → description
   but not description → object, and fakes the third layer with `u64` ids in side
   registries. `pipe_buffered_bytes` (`fs.rs:4371`) linearly scans the entire fd
   table to find a pipe's peer by `pipe_id`; a real pipe object with two ends
   deletes the scan and the id.
3. **Collapse the authority's RPC layer.** `Command` (~50 variants), `Outcome`
   (~46), `Request`/`Response` and `MAX_TERMINAL_DEDUP_ENTRIES` exist to survive
   lost datagrams to a helper process deleted in `36d141d69`;
   `transport.rs:26` still describes "the datagram client". The approved plan's
   Transport section and its "Whole-syscall RPC" rejection predate both the
   helper's deletion and the retirement of the legacy host-process execution
   backends, so amend that plan before acting — do not silently contradict it.
4. **Give `read(2)` one fd resolution.** Its prologue (`fs.rs:10013`) makes seven
   independent fd-table round trips before a byte moves — `resources::files()`,
   `Arc` clone, `RwLock` on the map, slot clone, `RwLock` on the description,
   match — once per question. Tasks 3–5 remove the description lock from those
   questions; a resolve-once typed handle removes the rest. This is carrick's own
   host userspace, the bucket AGENTS.md names as unattacked.
5. **Give the VFS a notify hook** so inotify and fanotify stop depending on 16
   hand-placed emission calls in `fs.rs` for the in-memory backend while
   `EVFILT_VNODE` covers the host backend.

## Self-review notes

- **Spec coverage.** This plan implements the approved migration's Wave 2
  ("migrate production callers family-by-family without enabling a second
  store") for one family, plus the prerequisites that make the remaining
  families cheap. Waves 4 (lifecycle and backends) and 5 (deletion and
  enablement) stay with the approved plan and are not duplicated here.
- **Transient dual storage.** Tasks 3 and 4 deliberately share one
  `Arc<DescriptionCommon>` between the enum and the description. This is the one
  place the plan tolerates two spellings of one value, it exists only to keep
  the commits reviewable, and Task 5 deletes it. If the series stalls before
  Task 5, revert to before Task 3 rather than merging the bridge.
- **Behaviour changes are named, not smuggled.** Two: `fd_ref_count` stops
  reporting 0 for a `Closed` description (Task 4), and epoll gains the readiness
  arms poll already had, `Netlink` first (Task 6). Both have a test and a commit
  body explaining them.
- **Unverified premise to confirm at execution time.** Task 6's red-first test
  asserts that `epoll_ready_events` reports nothing for a queued netlink dump.
  That is read off the code — `host_fd_for_poll` has no `Netlink` arm, so the
  `_ =>` fallback returns 0 — but it has not been executed. If Step 2's first
  assertion fails, or the second one passes, the premise is wrong: stop and
  re-derive the divergence before writing any fix.
