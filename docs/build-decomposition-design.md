# Build Decomposition Design

Status: design / research. **Phase 1 partially LANDED 2026-05-26** (profile
tuning committed; lld REJECTED — see below). Date: 2026-05-26. Author:
build-systems investigation.

> **PHASE 1 OUTCOME (verified 2026-05-26).** The headline lever — committing
> `lld` (§3.B-1) — was tried and **rejected**: it breaks `carrick trace`. Root
> cause (proven): the `usdt` 0.6 crate hardcodes the macOS *Linker* backend
> (`usdt-impl` `build.rs`: `Some("macos") => Backend::Linker`), which depends on
> **Apple ld64's proprietary DTrace probe-processing pass** to synthesize the
> `__dof_carrick` Mach-O section. `ld64.lld` does not implement that pass, so the
> section is never emitted and `usdt::register_probes()` finds nothing
> (measured: **551 USDT probes under ld64 → 0 under lld** on the same trace).
> `ld64.lld` also rejects `-Wl,-no_dead_strip` outright. So **lld is off the
> table until `usdt` is moved to its linker-agnostic `no-linker` backend**
> (runtime-built DOF via the `dof_helper` ioctl) — a usdt fork/patch, tracked as
> a prerequisite for the big link-time win. `.cargo/config.toml` now carries a
> guard comment so nobody re-adds lld blindly.
>
> **CRATE SPLIT PROGRESS (2026-05-26).** Lower layer DONE + verified:
> `carrick-abi` (A1, linux_abi) → `carrick-guest-mem` (A2, the GuestMemory/
> MemoryError/Aarch64SyscallFrame hub types — BREAKS the memory↔dispatch cycle) →
> `carrick-mem` (A3-lower: memory+page_table+elf+vdso). A2.5 first broke the
> `memory→rootfs` edge (AddressSpace is now rootfs-agnostic via a read-closure).
> trap.rs was also fully decoupled from `dispatch` (its only edge was the hub
> types, now imported from carrick-guest-mem). All re-exported under original
> paths (zero call-site churn); each step verified (build + tests + signed +
> `carrick trace`).
>
> **Remaining A3/A4 (carrick-hvf, carrick-dispatch) — mapped, not yet done.**
> `carrick-hvf` is an ~8-module cluster, not a single lift: trap.rs (3,222 LOC) +
> host_mapping, vcpu_kick, fork_quiesce, ulock, guest_cpu, compat, probes. trap→
> dispatch is now gone; the one tricky external edge is `vcpu_kick → thread`
> (resolve by placing `thread` below hvf or splitting the kick interface).
> `carrick-dispatch` (A4) is the largest (dispatch/* ~15k LOC + fs_backend + vfs +
> rootfs + overlay) and must be checked for dispatch↔runtime/thread cycles before
> lifting. These are the next dedicated build session.
>
> **Landed instead (DOF-safe, no linker change):** `[profile.dev]`/`[profile.test]`
> `split-debuginfo = "unpacked"` (skip macOS dsymutil bundling per link) and a
> `[profile.dev-fast]` (`debug = "line-tables-only"`). Verified: release
> rebuild+sign OK, `carrick trace` intact (548 probes), leaf-edit incremental
> ~3.2s vs ~4.6s baseline. The crate-split work (§3.A / Phases 3–4) remains the
> real structural lever and is unaffected by the lld finding.
Toolchain measured: `cargo 1.95.0`, `rustc 1.95.0`, edition 2024, host `aarch64-apple-darwin`.

This document characterizes the current build, explains *why* it is slow,
and proposes a phased plan to make the dev/test loop faster and more robust.
Everything below is grounded in the actual tree; file paths and line counts
are real measurements taken on 2026-05-26.

---

## 1. Current state (measured)

### 1.1 Workspace shape

5 library/binary crates + 1 test-support crate (`crates/*`, workspace `Cargo.toml`,
`resolver = "2"`, `edition = "2024"`):

| crate | src .rs files | src LOC | role |
|---|---:|---:|---|
| `carrick-spec` | 1 | 176 | leaf: run-spec types, OCI ref types |
| `carrick-image` | 1 | 511 | OCI image pull/layout (dep: spec) |
| `carrick-engine` | 1 | 336 | orchestration (dep: spec, image, runtime) |
| `carrick-runtime` | **57** | **44,483** | **the monolith** (dep: spec, image) |
| `carrick-cli` | 7 | 1,426 | `carrick` binary (dep: all) |
| `carrick-test-support` | 1 | 60 | dev-only fixtures |

Workspace dependency edges (`cargo metadata --no-deps`):

```
carrick-spec     -> []
carrick-image    -> [spec]
carrick-runtime  -> [spec, image]            (+ test-support, image as dev-deps)
carrick-engine   -> [spec, image, runtime]
carrick-cli      -> [engine, image, runtime, spec, test-support]
```

`carrick-runtime` is **97% of the workspace's first-party source** (44.5k of ~46k LOC).
It is the bottleneck for every part of the loop.

### 1.2 The big modules inside `carrick-runtime`

Top modules by LOC (`wc -l` on `crates/carrick-runtime/src/**`):

| LOC | file | content |
|---:|---|---|
| 4,954 | `dispatch/fs.rs` | filesystem syscall handlers |
| 4,300 | `dispatch/mod.rs` | **dispatcher core + the hub types** (see §2) |
| 3,222 | `trap.rs` | HVF trap decode / page-fault / MMU |
| 2,591 | `runtime.rs` | run loop, `RunResult` |
| 2,438 | `dispatch/net.rs` | socket syscall handlers |
| 2,178 | `fs_backend.rs` | host/memory fs backends |
| 1,917 | `memory.rs` | `AddressSpace`, guest mem |
| 1,837 | `linux_abi.rs` | **pure constants/types, zero internal deps** |
| 1,115 | `vfs/rootfs.rs` | VFS rootfs |
| 1,072 | `dispatch/proc.rs` | process syscalls |
| 886 | `host_signal.rs` | host signal routing |
| 844 | `page_table.rs` | stage-1 page tables (dep: only `memory`) |

Module groups under `src/`: `dispatch/` (fs, net, mem, proc, signal, time, creds,
fd_table), `trap/`, `vfs/` (proc, dev, devpts, mount, rootfs).

### 1.3 `cargo build --timings` evidence (already on disk)

`target/cargo-timings/cargo-timing.html` (a real prior full build, total wall **57s**,
341 units). Parsed unit durations for first-party crates:

- **25** distinct `carrick-runtime` build units with `duration > 0`, summing to
  **305 CPU-seconds**. All first-party carrick units sum to **388 CPU-seconds**
  against 57s wall → ~6.8x parallelism (i.e. the machine's cores are saturated;
  the runtime rlib is rebuilt/linked many times over).
- Two clear **test-build waves**:
  - Wave at `start≈17.3s`: **9 units, ~14.9s each** — the post-API-change
    recompiles of test binaries that statically link the runtime rlib.
  - Wave at `start≈41.5s`: **10 units, ~10.9s each** — a second batch of test
    binaries linking the runtime.
- `carrick-engine` (336 LOC) shows **15s** and **9.5s** units — its wall time is
  dominated by *waiting on and linking* the runtime rlib, not its own code.

### 1.4 Incremental-edit floor (measured today)

- No-op / env-touched lib rebuild: **5.49s** (`cargo build -p carrick-runtime --lib`).
- One-line edit to a **leaf** module (`linux_abi.rs`) then lib build: **4.56s**.

Because the runtime is a single crate compiled as **one codegen target**, editing
*any* of its 57 files recompiles the entire 41k-line rlib. The leaf-vs-core edit
costs the same ~4.5–5.5s. There is no incrementality *across modules* — only
within rustc's own incremental cache for that one crate.

### 1.5 Build-variant fan-out

`ls target/debug/deps/libcarrick_runtime-*.rlib` → **9 distinct rlib hashes**.
Each distinct feature set / cfg / dev-vs-normal build of the runtime produces a
separately-compiled rlib. Every one of those is a full 41k-line compile.

### 1.6 Test-binary inventory (the recompile cascade)

`carrick-runtime/tests/`:
- **Consolidated integration binary** — `tests/integration/main.rs` is one binary
  with 18 `mod`s (`address_space`, `syscall_fs` [5,064 LOC], `syscall_net` [2,310],
  `syscall_creds`, `syscall_time`, `concurrency_contracts`, …). This consolidation
  is already done and is the single biggest win that was already captured: it
  collapses ~18 binaries into 1 link.
- **5 standalone test binaries** that *cannot* be consolidated because they touch
  process-global state (documented in `main.rs`): `trap_hvf.rs`, `runtime_loop.rs`
  (create the once-per-process HVF VM via `hv_vm_create`), `interactive_supervisor.rs`,
  `interactive_tty.rs` (real fork + PTY raw mode), `syscall_process.rs` (host
  `waitid`/`wait` observes all children), plus `thread_stress_harness.rs`,
  `mach_cow_probe.rs`.

`carrick-cli/tests/`: `cli.rs` (1,872 LOC), `conformance.rs` (683, bollard/Docker),
`linux_fixture.rs` (177), `nested_pipe.rs` (51).

**Each top-level `tests/*.rs` is its own test binary, and each statically links the
runtime rlib + relinks on any runtime API change.** With ~7 runtime test binaries +
4 cli test binaries + the integration binary, a single touch of a runtime public
item triggers ~12 separate rustc+link invocations of code that all embeds the
44k-line rlib. That is exactly the §1.3 "waves."

### 1.7 Linker / profile config (the surprising part)

- **There is no `.cargo/config.toml` anywhere in the repo, and no `[profile.*]`
  in any `Cargo.toml`.** Confirmed by `find` + `grep`. The build runs on stock
  `dev`/`test` profiles (`opt-level=0`, `debug=2` full debuginfo, `incremental=true`,
  default `codegen-units=256` for dev).
- `lld` *is installed* (`/opt/homebrew/bin/lld`) and project memory says it was
  "adopted (~2.16x incrementals)" — but **it is not wired into any committed config
  or any script.** Either it is configured only in an uncommitted local env, or that
  win has silently regressed. This is a robustness gap (the speedup is not
  reproducible from a clean checkout).
- `sccache`, `mold` are **not installed**.
- Release path: `scripts/build-signed.sh` does `cargo build --release` then
  `codesign --force --sign - --entitlements scripts/entitlements.plist
  target/release/carrick`. Required because `cargo build --release` strips the
  signature → guest runs fail `HV_DENIED (0xfae94007)`.
- A `build.rs` in `carrick-runtime` compiles a tiny C shim (`csrc/carrick_shim.c`,
  the SIMD/FP-reg ABI workaround) via the `cc` crate, gated to macOS/aarch64.
  Cheap; not a bottleneck.

---

## 2. Why `carrick-runtime` is monolithic — the dependency hub

The root cause is **where the foundational shared types live.** Grepping for the
type definitions:

```
dispatch/mod.rs:459  pub struct Aarch64SyscallFrame
dispatch/mod.rs:666  pub trait  GuestMemory
dispatch/mod.rs:768  pub enum   MemoryError
memory.rs:179        pub struct AddressSpace
elf.rs:114           pub struct SegmentPerms
```

The hub types (`GuestMemory`, `MemoryError`, `Aarch64SyscallFrame`) are defined
**inside the 4,300-line `dispatch/mod.rs`** — the single biggest behavioral module.
Fan-in (files that `use crate::...`):

- `use crate::linux_abi` → **15 files** (it is the natural leaf; `linux_abi.rs`
  itself has **zero** `use crate::` — pure constants/types).
- `use crate::dispatch` → **10 files**
- `use crate::memory` → **6 files**

So nearly everything depends on `dispatch` *only because the core traits/types are
buried there.* And there is a **cycle**:

```
memory.rs      uses dispatch::{GuestMemory, MemoryError}   (memory.rs:8)
dispatch/mod.rs uses memory::{LINUX_HEAP_BASE, ... }        (dispatch/mod.rs:346)
trap.rs        uses dispatch::{Aarch64SyscallFrame, GuestMemory, MemoryError},
               memory::AddressSpace, page_table, linux_abi  (trap.rs:4-6)
page_table.rs  uses only memory  (page_table.rs:581)
```

`memory ↔ dispatch` is a genuine cycle that blocks a clean split until the hub
types are extracted. `page_table → memory` and `linux_abi → (nothing)` are clean
one-way edges, ready to lift immediately.

### Natural seams (in dependency order)

1. **`carrick-abi`** (pure leaf): `linux_abi.rs` (1,837 LOC) — constants, errno
   tables, prot/flag bitflags. Zero internal deps today. **Liftable as-is.**
2. **`carrick-guest-mem`** (leaf after a small extraction): the `GuestMemory`
   trait + `MemoryError` enum + `Aarch64SyscallFrame` moved *out* of
   `dispatch/mod.rs` into this crate; then `memory.rs`, `page_table.rs`,
   `elf.rs::SegmentPerms`, `AddressSpace` live here. Depends only on `carrick-abi`.
   **This is the keystone move that breaks the `memory ↔ dispatch` cycle.**
3. **`carrick-hvf`** (the trap/MMU engine): `trap.rs`, `page_table` glue,
   `shared_aperture`, `host_mapping`, `vcpu_kick`, the `applevisor` deps and the
   `cc` shim/`build.rs`. Depends on `carrick-abi` + `carrick-guest-mem`. This is
   the only crate that needs the HVF deps and the macOS/aarch64 cfg — isolating it
   means pure-logic crates stop carrying applevisor in their build graph.
4. **`carrick-dispatch`** (the syscall surface): `dispatch/*` (fs/net/mem/proc/
   signal/time/creds/fd_table), `compat`, `fs_backend`, `vfs/*`, `rootfs`,
   `overlay`, `syscall`. The largest behavioral crate; depends on abi + guest-mem
   (+ spec, image as today).
5. **`carrick-runtime`** (thin top): `execute.rs`, `runtime.rs`, `thread.rs`,
   `host_signal`, `io_wait`, `pty_relay`, `interactive_supervisor`, `dtrace_consumer`,
   `probes` — the run loop and process lifecycle. Depends on dispatch + hvf.

This is exactly the layering project memory already gestures at
("linux_abi/memory/page_table as a leaf crate; dispatch as its own crate;
trap/HVF engine separate from syscall dispatch").

---

## 3. Concrete proposals

Each proposal lists **effort / risk / expected payoff**.

### 3.A Crate-splitting plan

Split in the dependency order above. Do the cheap, cycle-free lifts first.

| step | new crate | modules moved | breaks cycle? | effort | risk | payoff |
|---|---|---|---|---|---|---|
| A1 | `carrick-abi` | `linux_abi.rs` | no | **low** (1–2h; 15 import sites → `carrick_abi::`) | low | small alone, but unblocks A2 |
| A2 | `carrick-guest-mem` | extract `GuestMemory`/`MemoryError`/`Aarch64SyscallFrame` from `dispatch/mod.rs`; move `memory.rs`, `page_table.rs`, `SegmentPerms` | **yes** | **med** (the keystone; touches the hub) | med | makes memory/MMU edits not rebuild dispatch |
| A3 | `carrick-hvf` | `trap.rs`, `shared_aperture`, `host_mapping`, `vcpu_kick`, `build.rs`+shim, applevisor deps | no | med | med (cfg-gating, the `cc` shim) | applevisor/HVF rebuilds isolated from logic crates |
| A4 | `carrick-dispatch` | `dispatch/*`, `compat`, `fs_backend`, `vfs/*`, `rootfs`, `overlay`, `syscall` | no | high (largest) | med | edits to fs/net handlers stop rebuilding hvf/runtime |
| A5 | `carrick-runtime` (slim) | run loop, thread, signal, io_wait, pty, probes | no | med | low | top layer is small + fast to relink |

**Why this reduces rebuild scope.** Today every edit recompiles 44k lines as one
unit and relinks ~12 test binaries. After the split, editing e.g. `dispatch/fs.rs`
recompiles only `carrick-dispatch` and the crates *above* it (`carrick-runtime`,
`carrick-engine`, `carrick-cli`) — but **not** `carrick-abi`, `carrick-guest-mem`,
or `carrick-hvf`, which are cached rlibs. rustc compiles separate crates in
parallel and only re-links downstream. The §1.6 test cascade shrinks because most
pure tests can target the leaf crates (`carrick-guest-mem`, `carrick-dispatch`)
whose rlibs are smaller and rebuild far less often.

**Sequencing rule:** A1 → A2 are mandatory and ordered (A2 needs A1; A2 breaks the
cycle). A3/A4/A5 can follow independently. Stop after A2 if time-boxed — it already
delivers the cycle break and lets `memory`/`page_table` edits skip `dispatch`.

### 3.B Compile-time levers (no crate split required — Phase 1)

Add a root `[profile.*]` block to the workspace `Cargo.toml` and a committed
`.cargo/config.toml`. These are cheap, reversible, and independent of §3.A.

1. **Commit the linker.** Create `.cargo/config.toml`:
   ```toml
   [target.aarch64-apple-darwin]
   rustflags = ["-C", "link-arg=-fuse-ld=lld"]
   ```
   This makes the (already-installed) `lld` win reproducible from a clean checkout
   instead of relying on an uncommitted local env. **Payoff: the claimed ~2.16x
   link speedup, made durable.** Link time dominates the §1.3 test waves (each test
   binary statically links the 44k-line rlib), so this hits the actual long pole.
   *Risk:* low; verify guest runs still work (linker choice does not affect the
   codesign step). Effort: 15 min.

2. **`split-debuginfo = "unpacked"`** (macOS default is `packed`/dSYM-ish bundling
   which is slow). In `[profile.dev]` and `[profile.test]`:
   ```toml
   [profile.dev]
   split-debuginfo = "unpacked"
   [profile.test]
   split-debuginfo = "unpacked"
   ```
   Avoids the `dsymutil` packaging step on every link. **Payoff: meaningful link-time
   cut on macOS**, compounds with lld. Risk: low (lldb still works with unpacked).

3. **`debug = "line-tables-only"`** for the dev/test profiles. The runtime carries
   `debug=2` full debuginfo today; line-tables-only keeps backtraces and
   `carrick trace`/lldb line info while dropping the heavy type/variable DWARF.
   ```toml
   [profile.dev]
   debug = "line-tables-only"
   ```
   *Caveat:* the `macos-vm-lldb-debug` workflows want variable inspection. Make this
   a **named profile** (e.g. `[profile.dev-fast]`) the everyday loop uses, and keep a
   `dev` (full debuginfo) profile for deep lldb sessions. Payoff: less debuginfo to
   emit + link → faster builds and smaller rlibs (which also speeds the §1.5 nine
   rlib variants). Risk: low if gated to a profile.

4. **`opt-level` asymmetry for deps vs workspace.** First-party code stays at
   `opt-level=0` (fast compile); leave heavy third-party crates at their defaults.
   Do **not** globally raise opt-level — it would slow compile. (Listed for
   completeness; the win here is small relative to 1–3.)

5. **`codegen-units`** — dev already defaults to 256 (max parallelism within a
   crate), so there is nothing to gain on dev. After §3.A, leaf crates compile in
   parallel as separate units anyway. No change recommended for dev.

6. **`sccache`** — feasibility: workable as a wrapper (`RUSTC_WRAPPER=sccache`).
   Payoff is real for *clean*/CI builds and for the §1.5 multiple rlib variants
   (cache hits across feature sets), but **limited for the inner edit loop** (a
   changed crate is always a cache miss). The `build.rs`/`cc` shim and `usdt`
   proc-macro/DOF generation can interact poorly with caching — validate before
   committing. Recommend **CI-only** initially. Effort: low; risk: med (correctness
   of cached HVF/usdt artifacts).

7. **dylib / `prefer-dynamic`** — not recommended. It would complicate the codesign
   + hypervisor-entitlement step (the entitlement is on the final Mach-O; dynamic
   libs add signing surface) and HVF needs a clean signed image. Skip.

### 3.C Test architecture

**Why `nextest` hangs the HVF tests (and the real fix).** `cargo test` runs all
tests *inside one process* (threads); the consolidated integration binary
explicitly relies on that (`main.rs`: "Only tests safe to run as parallel threads
in one process live here"). `nextest` runs **each test in its own process**. The
HVF-touching tests (`trap_hvf`, `runtime_loop`) call `hv_vm_create`, which is
**once-per-process and process-global**, and the interactive ones do real fork +
PTY raw-mode and host `waitid` that observes all children. Under nextest's
process-per-test model these collide / wedge the vCPU — that is the documented
"nextest hangs HVF tests" and why it was rejected wholesale.

**The partition that recovers nextest for the bulk of tests:**

- Tag the **pure/logic** tests (the 18 `mod`s in `tests/integration/` — dispatcher,
  ELF load, rootfs, io, address_space, syscall_* that touch no process-global state)
  as a group that **can** run under a fast parallel runner. After §3.A these become
  unit/integration tests of `carrick-dispatch` / `carrick-guest-mem` with **no
  applevisor in the dependency graph at all**, so they build and run fast and
  safely in parallel.
- Keep the **HVF / process-global** group (`trap_hvf`, `runtime_loop`,
  `interactive_*`, `syscall_process`, `thread_stress_harness`, `mach_cow_probe`,
  cli `conformance.rs`) as a **serially-run** group: `cargo test` with
  `--test-threads=1`, or nextest with a profile that forces these into a serial
  test-group (`[[profile.default.overrides]] ... test-group = "serial"`,
  `[test-groups] serial = { max-threads = 1 }`). nextest *does* support serial
  groups — the prior rejection was using it undifferentiated.
- Net effect: the large, fast-moving logic test set gets parallel nextest; only the
  handful of genuinely process-global tests run serially. Effort: med; risk: low
  (the partition is already documented in `main.rs`, we are just formalizing it).

**Reduce test-binary fan-out (independent of nextest).** The §1.6 standalone
binaries each re-embed the 44k-line rlib. After §3.A they embed only the smaller
crate they test (e.g. `trap_hvf` → `carrick-hvf`, not the whole runtime), shrinking
each link in the §1.3 waves. Also prefer `--lib` unit tests (inline `#[cfg(test)]`
modules already exist, e.g. `memory.rs`, `page_table.rs`, `dispatch/mod.rs`) for
pure logic — `cargo test --lib` skips the integration-binary link entirely and is
the fastest inner loop for non-HVF changes.

### 3.D Robustness / loop flakiness

- **Make the linker reproducible** (§3.B-1): the current "lld is faster" win exists
  only in uncommitted env. Commit it so a clean checkout is fast and consistent.
- **Codesign friction.** `cargo build --release` strips the signature → `HV_DENIED`.
  `scripts/build-signed.sh` re-signs, but anyone running a bare `cargo build
  --release` (or an IDE) gets a silently broken binary. Recommend: a `cargo` alias
  or a thin `target/release/carrick` post-build wrapper, and document that
  `build-signed.sh` is the only supported release path. Lower-risk: a `Justfile`/`make`
  target so the resign is never forgotten. (Design note only — not changing it here.)
- **The `cc` shim + `usdt` DOF** are build-script/proc-macro steps that must survive
  any crate move (they go with `carrick-hvf` in §3.A-A3). Note for the migration:
  keep `build.rs` and `csrc/` co-located with the crate that owns the applevisor
  deps, and re-confirm `__dof_carrick` is not stripped by lld (project memory:
  "the real break was the lld linker stripping `__dof_carrick`, since reverted").
  **This is the one place where committing lld globally could regress USDT probes —
  must be verified in Phase 1.**
- **`sccache` only after** confirming it does not poison the usdt/DOF or HVF shim
  artifacts.

---

## 4. Phased rollout

Each phase is independently shippable and has a concrete measurement.

### Phase 0 — Baseline (1 commit, no behavior change)
Capture a reproducible baseline so later phases have an oracle.
- Record: `cargo build --workspace --timings` (full), and three inner-loop numbers:
  touch a leaf module (`linux_abi.rs`) → `cargo build -p carrick-runtime --lib`;
  touch a hub item; full `cargo test --no-run` link time.
- Today's reference: lib incremental **~4.6s**, full build **57s wall / 388 CPU-s**,
  test waves of **9×14.9s** and **10×10.9s**.
- **Verify:** numbers are stable across 3 runs.

### Phase 1 — Profile + linker tuning (cheap wins; no crate split)
Apply §3.B-1,2,3: commit `.cargo/config.toml` with `lld`, add `[profile.dev]`/
`[profile.test]` with `split-debuginfo="unpacked"` + a `dev-fast` profile with
`debug="line-tables-only"`.
- **Effort:** ~1 hour. **Risk:** low. Must re-verify USDT `carrick trace` still
  works (the `__dof_carrick`/lld interaction) and that a signed guest run still
  succeeds.
- **Verify:** re-run the Phase-0 numbers. Expect the link-dominated test waves to
  drop most (lld + unpacked debuginfo + line-tables-only all cut link/debuginfo
  time). Target: full-build wall and per-test-link time down measurably; confirm
  `carrick trace -s …` still emits probes and `carrick run <signed>` works.

### Phase 2 — Test partition + nextest for logic tests (§3.C)
Formalize the HVF/serial vs pure/parallel split. Add nextest config with a `serial`
test-group for HVF/process-global tests; run the logic set in parallel.
- **Effort:** med. **Risk:** low (partition already documented in `main.rs`).
- **Verify:** the logic test set passes under parallel nextest with no hangs; the
  serial group still passes; total `cargo/nextest test` wall time vs Phase-1.

### Phase 3 — Lift the leaf crates (§3.A A1 + A2)
`carrick-abi`, then extract the hub types into `carrick-guest-mem` (breaks the
`memory ↔ dispatch` cycle).
- **Effort:** A1 low, A2 med. **Risk:** A2 med (touches the hub in `dispatch/mod.rs`).
- **Verify:** `cargo metadata` shows the new edges and **no cycle**; editing
  `memory.rs`/`page_table.rs` rebuilds only `carrick-guest-mem` + downstream, *not*
  `carrick-dispatch`; re-measure the leaf-edit inner loop (should drop from ~4.6s of
  whole-runtime recompile to a small-crate recompile).

### Phase 4 — Split HVF + dispatch (§3.A A3 + A4 + A5)
Extract `carrick-hvf` (applevisor + shim isolated), then `carrick-dispatch`, leaving
a slim `carrick-runtime`.
- **Effort:** high (A4 is the largest). **Risk:** med.
- **Verify:** pure-logic test crates have **no applevisor in their dep graph**
  (`cargo tree -p carrick-dispatch | grep applevisor` → empty); editing
  `dispatch/fs.rs` rebuilds dispatch + above but not hvf/abi/guest-mem; re-run the
  full `--timings` and compare CPU-seconds and wall to Phase 0.

### Phase 5 (optional) — CI `sccache` + robustness polish (§3.B-6, §3.D)
CI-only `RUSTC_WRAPPER=sccache` after validating usdt/HVF artifact correctness; add
a `make`/`just` target so the codesign re-sign is never skipped.
- **Verify:** CI clean-build cache hit-rate; a bare `cargo build --release` either
  re-signs or fails loudly instead of silently producing an `HV_DENIED` binary.

---

## 5. Top recommendations (summary)

1. **Phase 1 profile/linker tuning** — commit `lld` in `.cargo/config.toml` +
   `split-debuginfo="unpacked"` + line-tables-only dev profile. ~1h, low risk,
   directly attacks the link-dominated test waves (9×14.9s, 10×10.9s in the real
   timing data). Makes the already-claimed lld win reproducible from a clean
   checkout. Must re-verify USDT probes survive lld.
2. **Extract the hub types into `carrick-abi` + `carrick-guest-mem`** (Phase 3) —
   the keystone. The foundational `GuestMemory`/`MemoryError`/`Aarch64SyscallFrame`
   are buried in the 4,300-line `dispatch/mod.rs`, creating a `memory ↔ dispatch`
   cycle that forces the whole 44k-line crate to recompile on any edit. Breaking
   this is what turns the monolith into parallel, independently-cached crates.
3. **Formalize the HVF-serial / logic-parallel test partition** (Phase 2) — nextest
   was rejected wholesale, but it hangs *only* the `hv_vm_create`/fork/PTY
   process-global tests. Put those 6–7 binaries in a nextest serial test-group and
   let the large pure-logic set run parallel; after the crate split they don't even
   link applevisor.
