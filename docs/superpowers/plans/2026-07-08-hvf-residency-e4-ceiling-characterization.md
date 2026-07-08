# HVF Residency Ceiling E4 Characterization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Characterize what the measured ~126 system-wide HVF residency ceiling actually scales with (vCPUs per VM, mapped guest memory), price lease-reacquire cost against mapping fragmentation, land the red-first over-ceiling workload probe, and record the E4 evidence doc that gates the `WakeFromBlockingSyscall` lease implementation.

**Architecture:** Pure evidence campaign in the E1→E3 series style — extend existing probes (`hvf_fork_probe`, `clonebasic`), add one new conformance probe (`procladder`), run bounded measurement matrices, record verdicts in `docs/2026-07-08-hvf-residency-e4-evidence.md`, and promote Track 3 in the strategy memo. **No runtime/engine behavior changes in this plan.** The lease implementation gets its own plan after E4's verdicts are in, because its eviction threshold, churn bound, and replay budget are exactly what E4 measures.

**Tech Stack:** Rust (probe binaries), Hypervisor.framework FFI (`applevisor`-style raw bindings already in `hvf_fork_probe.rs`), DTrace USDT (`fork-phases.d`, already committed), the conformance probe gate (`scripts/run-probe.sh`, `cargo test -p carrick-cli --test conformance`).

## Global Constraints

- NEVER `git commit --no-verify`; `cargo fmt` must pass (hooks enforce it).
- Never run a carrick guest and a Docker oracle concurrently (`scripts/run-probe.sh` already sequences its two phases; keep manual runs sequential too).
- **WindowServer guardrail:** mass *concurrent* HVF create/destroy loops have crashed WindowServer/Finder on this host. E4 runs are single bursts or single-process sequential loops, one at a time, with no other carrick runs, conformance grinds, or Docker builds active. Never script a retry loop around the ceiling runs.
- The one-Linux-process-to-one-host-process invariant is untouched; nothing in this plan adds a daemon, broker, or hot-path RPC.
- macOS DTrace USDT probes in this provider path support at most **5 arguments** (6th reads as zero) — do not add USDT probes with 6 args.
- `hvf_fork_probe` needs the hypervisor entitlement after every rebuild: `codesign --force --sign - --entitlements scripts/entitlements.plist target/release/hvf_fork_probe`.
- Conformance probes must produce deterministic output (booleans only, no counts/times/pids) and must stay byte-identical to the Docker oracle at default knob values — env/argv knobs follow the `FORK_MEM_MB` precedent from E2.2.
- Evidence logs go under `target/conformance/logs/hvf-residency-e4/` (uncommitted; referenced by path from the evidence doc, as in E2/E3).
- Guest binaries are Linux aarch64 musl, built by `scripts/build-probes.sh`; the guest page size is 4 KiB, the host page size is 16 KiB.

## Background for the implementer (read once)

- `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` is a **host** macOS binary poking HVF directly. Its `concurrent-ceiling` mode forks children that each `hv_vm_create` + `hv_vcpu_create` (one vCPU) and park until SIGKILL; the measured ceiling on this host is ~126 (see `crates/carrick-vmm-hvf/src/trap.rs:761`). The soft budget `GLOBAL_VCPU_CEILING` is 120 (`trap.rs:775`).
- The **soft-budget** wait (`acquire_global_vcpu_permit`, `trap.rs:867`) retries **forever** with 1→50 ms backoff. The **hard-limit** wait (`create_with_no_resources_backpressure`, `trap.rs:1589`) gives up after 10 s. So a guest fork past 120 live guest processes stalls indefinitely — that is the red behavior Task 5 pins.
- `CARRICK_HVF_ADMISSION_TRACE=1` (host env) turns on gated admission logging (`trap.rs:1559`).
- `scripts/dtrace/fork-phases.d` consumes the committed `fork__rebuild`/`fork__lifecycle`/`fork__footprint` USDT probes and prints per-side `desc_count`, `map_count`, and elapsed µs. Invoke against the **run-elf** path to avoid nested `dtrace -c` quoting (E2 note).
- `conformance-probes/src/bin/clonebasic.rs` already takes `argv[1]`/`FORK_MEM_MB` as a resident-memory knob (E2.2). The probe gate (`cargo test -p carrick-cli --test conformance`) runs every built probe with **no env knobs set**, so knob defaults must keep probes green.

---

### Task 1: Parameterize `concurrent-ceiling` by vCPUs-per-VM and mapped memory

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs:228-232` (arg parsing), `:254` (usage), `:913-1016` (`concurrent_ceiling`)

**Interfaces:**
- Produces: `hvf_fork_probe concurrent-ceiling [max] [hold_secs] [vcpus_per_vm] [map_mib]` — Task 2 runs this matrix.

- [ ] **Step 1: Extend the arg parsing and usage text**

In `main()`, replace the `"concurrent-ceiling"` arm:

```rust
"concurrent-ceiling" => {
    let max = parse_u64_arg(&args, 1, 100);
    let hold_secs = parse_u64_arg(&args, 2, 60);
    let vcpus_per_vm = parse_u64_arg(&args, 3, 1).max(1);
    let map_mib = parse_u64_arg(&args, 4, 0);
    concurrent_ceiling(max, hold_secs, vcpus_per_vm, map_mib);
}
```

and the usage line:

```rust
println!("  hvf_fork_probe concurrent-ceiling [max] [hold_secs] [vcpus_per_vm] [map_mib]");
```

- [ ] **Step 2: Add the per-child extras helper**

Add above `fn concurrent_ceiling`. HVF binds a vCPU to its creating thread, so each extra vCPU needs a live parked thread; children are SIGKILLed at teardown, so the threads never need clean shutdown. The mapped memory is touched **before** `hv_vm_map` so it is resident, mirroring what a real guest's mapped-and-used memory looks like to the kernel resource accountant.

```rust
/// Create this child's VM + first vCPU, then the requested extras:
/// `map_mib` MiB of resident anonymous memory mapped into the guest, and
/// `vcpus_per_vm - 1` additional vCPUs, each on its own parked thread
/// (HVF binds a vCPU to its creating thread).
fn create_vm_with_extras(vcpus_per_vm: u64, map_mib: u64) -> Result<Duration, hv_return_t> {
    const EXTRA_GUEST_ADDR: u64 = 0x2000_0000;
    let start = Instant::now();
    let (_vm, _first) = Vm::create()?;
    if map_mib > 0 {
        let bytes = (map_mib as usize) * 1024 * 1024;
        let host = unsafe {
            libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(HV_ERROR);
        }
        let mut off = 0usize;
        while off < bytes {
            unsafe { *host.cast::<u8>().add(off) = 1 };
            off += 16384;
        }
        let perms: hv_memory_flags_t = HV_MEMORY_READ | HV_MEMORY_WRITE;
        let rc = unsafe { hv_vm_map(host.cast_const(), EXTRA_GUEST_ADDR, bytes, perms) };
        if rc != HV_SUCCESS {
            return Err(rc);
        }
    }
    let (tx, rx) = std::sync::mpsc::channel::<hv_return_t>();
    for _ in 1..vcpus_per_vm {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut vcpu = 0;
            let mut exit: *const hv_vcpu_exit_t = ptr::null();
            let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null_mut()) };
            let _ = tx.send(rc);
            loop {
                std::thread::park();
            }
        });
    }
    drop(tx);
    for _ in 1..vcpus_per_vm {
        match rx.recv() {
            Ok(rc) if rc == HV_SUCCESS => {}
            Ok(rc) => return Err(rc),
            Err(_) => return Err(HV_ERROR),
        }
    }
    Ok(start.elapsed())
}
```

- [ ] **Step 3: Thread the knobs through `concurrent_ceiling`**

Change the signature and header print:

```rust
fn concurrent_ceiling(max: u64, hold_secs: u64, vcpus_per_vm: u64, map_mib: u64) {
    println!(
        "case=concurrent-ceiling max={max} hold_secs={hold_secs} vcpus_per_vm={vcpus_per_vm} map_mib={map_mib}"
    );
```

In the child branch (`pid == 0`), replace

```rust
let (rc, create_us): (hv_return_t, u64) = match Vm::create() {
    Ok((_vm, elapsed)) => (HV_SUCCESS, elapsed.as_micros() as u64),
    Err(rc) => (rc, 0),
};
```

with

```rust
let (rc, create_us): (hv_return_t, u64) = match create_vm_with_extras(vcpus_per_vm, map_mib) {
    Ok(elapsed) => (HV_SUCCESS, elapsed.as_micros() as u64),
    Err(rc) => (rc, 0),
};
```

Also update the final summary line so the knobs are recorded in the machine-readable footer:

```rust
println!(
    "=== CEILING max_concurrent_vms={live} vcpus_per_vm={vcpus_per_vm} map_mib={map_mib} total_vcpus={} failure={} first_create_us={} last_create_us={} ===",
    live * vcpus_per_vm,
    failure
        .map(rc_label)
        .unwrap_or_else(|| "none(reached max, no hard limit hit)".to_owned()),
    first_create_us.unwrap_or(0),
    last_create_us,
);
```

- [ ] **Step 4: Build, sign, smoke-run at tiny scale**

```bash
just build -p carrick-vmm-hvf --bin hvf_fork_probe
codesign --force --sign - --entitlements scripts/entitlements.plist target/release/hvf_fork_probe
target/release/hvf_fork_probe concurrent-ceiling 4 30 2 8
```

Expected: `case=concurrent-ceiling max=4 hold_secs=30 vcpus_per_vm=2 map_mib=8`, four `live=` lines, footer `=== CEILING max_concurrent_vms=4 vcpus_per_vm=2 map_mib=8 total_vcpus=8 failure=none(reached max, no hard limit hit) ... ===`, `torn_down=4 children`, exit 0. Also confirm backward compat: `target/release/hvf_fork_probe concurrent-ceiling 4 30` behaves identically to before (vcpus_per_vm=1, map_mib=0).

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt -p carrick-vmm-hvf
git add crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs
git commit -m "diagnostics(hvf): parameterize concurrent-ceiling by vcpus and mapped memory"
```

---

### Task 2: Run the E4.1 ceiling-characterization matrix

**Files:**
- Create (logs, uncommitted): `target/conformance/logs/hvf-residency-e4/ceiling-*.log`

**Interfaces:**
- Consumes: Task 1's extended probe.
- Produces: the ceiling scaling law (per-VM vs per-vCPU vs memory-coupled) that Task 6 records and the lease plan consumes.

- [ ] **Step 1: Quiet-host preflight**

No conformance grind, no other carrick runs, no Docker builds running. Verify: `pgrep -lf 'carrick|docker build' || true` shows nothing carrick-related (Docker Desktop's idle daemon is fine).

- [ ] **Step 2: Run the matrix, one run at a time, sequentially**

```bash
mkdir -p target/conformance/logs/hvf-residency-e4
cd /Volumes/CaseSensitive/carrick
STAMP=$(date +%Y%m%d-%H%M%S)
{ sw_vers; sysctl -n hw.model hw.memsize hw.ncpu; } > target/conformance/logs/hvf-residency-e4/host-info-$STAMP.log

for spec in "1 0" "2 0" "4 0" "1 16" "1 64"; do
  set -- $spec
  v=$1; m=$2
  target/release/hvf_fork_probe concurrent-ceiling 150 120 "$v" "$m" \
    | tee "target/conformance/logs/hvf-residency-e4/ceiling-v${v}-m${m}-$STAMP.log"
  sleep 10   # let HVF settle between bursts (churn guardrail)
done
```

Each run forks up to 150 children in a single burst, records `max_concurrent_vms`, then SIGKILLs them all. The `hold_secs=120` alarm is a self-destruct backstop; normal teardown happens in seconds.

- [ ] **Step 3: Read the decision table off the footers**

| Observation | Verdict |
|---|---|
| `v2/v4` ceilings ≈ 126/N (total_vcpus ≈ constant) | resource is **per-vCPU** — multithreaded hot processes eat the budget; lease policy must reclaim per-vCPU |
| `v2/v4` ceilings ≈ 126 (total_vcpus scales up) | resource is **per-VM** — only process count matters; lease policy can think in whole-VM units |
| `m16/m64` ceilings drop vs `m0` | resource is **memory-coupled** — big guests eat the budget; eviction must weight by mapped size |
| `m16/m64` ceilings ≈ `m0` | mapped memory is free w.r.t. the ceiling |

Record the raw footers; Task 6 writes the verdict. If any run fails in an unexpected way (e.g. `HV_DENIED`, fork errno), stop and record — do not retry in a loop.

---

### Task 3: E4.2 sequential churn timing (existing probe mode, no code)

**Files:**
- Create (logs, uncommitted): `target/conformance/logs/hvf-residency-e4/recreate-loop-*.log`

**Interfaces:**
- Produces: sustained sequential VM create/destroy latency — the lease plan's re-materialization cost ceiling and churn-rate reference.

- [ ] **Step 1: Run the existing `recreate-loop` mode, single process, sequential**

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
target/release/hvf_fork_probe recreate-loop 200 0 \
  | tee target/conformance/logs/hvf-residency-e4/recreate-loop-200-$STAMP.log
```

This is one process doing 200 sequential create/destroy cycles — the same shape every fork already performs, NOT the concurrent mass-run loop that crashed WindowServer. Do not parallelize it and do not wrap it in a retry loop.

- [ ] **Step 2: Record min/median/max cycle latency from the log**

Expected ballpark from E2.1: create ≈ 44–80 µs, destroy ≈ 110 µs. If sustained cycles degrade over the loop (creeping latency), that is a finding — record it; it bounds how aggressively the lease layer may cycle residency.

---

### Task 4: Price stage-2 replay against guest VA fragmentation (`FORK_MAPS`)

**Files:**
- Modify: `conformance-probes/src/bin/clonebasic.rs`
- Create (logs, uncommitted): `target/conformance/logs/hvf-residency-e4/fork-phases-maps*-*.log`

**Interfaces:**
- Consumes: committed `fork__rebuild` USDT + `scripts/dtrace/fork-phases.d` (prints per-side `desc_count`, `map_count`, replay elapsed µs).
- Produces: replay-cost-vs-fragmentation curve, and the answer to "what drives `HvfVmState::mappings` count" — the lease-reacquire pricing input.

The open question this answers: E2/E3 saw 14 stage-2 descriptors and ~100 µs replay for a trivial guest. Does *guest-side* VA fragmentation (many disjoint mmaps, mixed protections) multiply carrick's host mapping descriptors — making lease reacquire expensive for mapping-heavy processes — or is the descriptor count bounded by carrick's own region layout regardless of guest behavior? Either answer is a verdict.

- [ ] **Step 1: Add the `FORK_MAPS` knob to clonebasic**

Add below `mem_mb_arg_or_env()` (keeping the E2.2 argv/env precedent — `argv[1]` = mem MiB, `argv[2]` = map count, because this host's DTrace refuses `/usr/bin/env` as a `-c` target):

```rust
fn maps_arg_or_env() -> usize {
    std::env::args()
        .nth(2)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or_else(|| env_usize("FORK_MAPS"))
}

/// Fragment the guest VA space before the fork: `count` disjoint 64 KiB
/// anonymous mappings, each followed by a 64 KiB munmap hole so neighbors
/// can never coalesce, with every other region dropped to PROT_READ so the
/// host also sees protection boundaries. Touches one byte per 4 KiB page so
/// the kept pages are resident. Returns how many regions were made.
fn fragmented_mappings(count: usize) -> usize {
    const KEEP: usize = 64 * 1024;
    const SPAN: usize = 128 * 1024;
    let mut made = 0usize;
    for i in 0..count {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SPAN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            break;
        }
        let mut off = 0usize;
        while off < KEEP {
            unsafe { *p.cast::<u8>().add(off) = 1 };
            off += 4096;
        }
        unsafe {
            libc::munmap(p.cast::<u8>().add(KEEP).cast(), SPAN - KEEP);
            if i % 2 == 1 {
                libc::mprotect(p, KEEP, libc::PROT_READ);
            }
        }
        made += 1;
    }
    made
}
```

In `main()`, after `let mem = resident_memory(mem_mb);` add:

```rust
let maps_made = fragmented_mappings(maps_arg_or_env());
```

and at the end, next to the existing `mem` black_box:

```rust
hint::black_box(maps_made);
```

**Output must not change** — no new `report!` lines; the oracle diff stays byte-identical at any knob value.

- [ ] **Step 2: Rebuild probes and verify the gate stays green**

```bash
scripts/build-probes.sh
scripts/run-probe.sh clonebasic
```

Expected: `MATCH clonebasic` (defaults: 0 MiB, 0 maps — behavior unchanged).

- [ ] **Step 3: Run the DTrace fragmentation matrix**

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
for maps in 0 256 1024; do
  timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d \
    -c "target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic -- 0 $maps" \
    | tee "target/conformance/logs/hvf-residency-e4/fork-phases-maps${maps}-$STAMP.log"
done
```

Sequential, one at a time. Record per side: `desc_count`, `map_count`, local replay elapsed µs, and host `fork(2)` µs (role 2/3 phase 3).

- [ ] **Step 4: Read the verdict**

- `desc_count` flat at ~14 across 0→1024 guest maps ⇒ guest fragmentation does NOT drive host descriptors; lease-reacquire replay is bounded ~100 µs for any workload — record as **replay-bounded** (best case for the lease design).
- `desc_count` scaling with maps ⇒ record the µs-per-descriptor slope; the lease plan needs an eviction bias against fragmented processes and possibly descriptor coalescing.

- [ ] **Step 5: fmt + commit**

```bash
rustfmt conformance-probes/src/bin/clonebasic.rs
git add conformance-probes/src/bin/clonebasic.rs
git commit -m "probe(conformance): clonebasic FORK_MAPS guest-fragmentation knob"
```

---

### Task 5: `procladder` — the red-first over-ceiling workload probe

**Files:**
- Create: `conformance-probes/src/bin/procladder.rs`
- Create (logs, uncommitted): `target/conformance/logs/hvf-residency-e4/procladder-*.log`

**Interfaces:**
- Produces: the standing many-process invariant probe. Default `N=8` keeps the probe gate green today; `PROC_LADDER_N=160` is the red configuration that the future `WakeFromBlockingSyscall` lease work must turn green (its acceptance test).

- [ ] **Step 1: Write the probe**

`conformance-probes/src/bin/procladder.rs`:

```rust
//! Many-process residency invariant: a parent can hold N simultaneously-alive,
//! *blocked* children (each parked in `pause(2)`) and then reap them all.
//!
//! On Linux this is trivially true for any reasonable N. Under carrick/HVF the
//! host materializes one VM+vCPU per guest process, and the measured
//! system-wide residency ceiling is ~126 (soft budget 120, trap.rs
//! GLOBAL_VCPU_CEILING) — so at N past the budget, fork stalls indefinitely in
//! the unbounded permit wait while every child sleeps holding a permit. This
//! probe is the red-first gate for the WakeFromBlockingSyscall residency-lease
//! track: blocked processes should not hold materialized VMM residency.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_reaped_all — every forked child was SIGKILLed and reaped
//!
//! N defaults to 8 (safely under the ceiling) so the probe gate stays green;
//! the over-ceiling evidence/acceptance run sets PROC_LADDER_N=160.
//!
//! Deterministic output only — booleans, never counts/times/pids.

use conformance_probes::report;
use std::env;

fn ladder_n() -> usize {
    env::var("PROC_LADDER_N")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 1024)
}

fn main() {
    let n = ladder_n();
    let mut pids: Vec<i32> = Vec::with_capacity(n);
    unsafe {
        for _ in 0..n {
            let pid = libc::fork();
            if pid == 0 {
                loop {
                    libc::pause();
                }
            }
            if pid < 0 {
                break;
            }
            pids.push(pid);
        }
        let forked = pids.len();
        for &pid in &pids {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut reaped = 0usize;
        for &pid in &pids {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid {
                reaped += 1;
            }
        }
        report!(
            ladder_forked_all = forked == n,
            ladder_reaped_all = reaped == forked,
        );
    }
}
```

- [ ] **Step 2: Build and verify green at default N (the gate configuration)**

```bash
scripts/build-probes.sh
scripts/run-probe.sh procladder
```

Expected: `MATCH procladder` with `ladder_forked_all=true` / `ladder_reaped_all=true`. This is what the probe gate (`cargo test -p carrick-cli --test conformance`) will run — green.

- [ ] **Step 3: Record the red run at N=160 (carrick side only, right-reason check)**

The red manifestation is a **stall**, not an errno: `acquire_global_vcpu_permit` retries forever, so fork #~121 never returns while 120 paused children hold permits. Bound it with `timeout`, observe the live-guest plateau, and clean up by run id:

```bash
mkdir -p target/conformance/logs/hvf-residency-e4
STAMP=$(date +%Y%m%d-%H%M%S)
PROBE=conformance-probes/target/aarch64-unknown-linux-musl/release/procladder
RUN_ID="cr-e4-ladder-$$"

( sleep 45; echo "live_guests_at_45s=$(pgrep -f "carrick:$RUN_ID:" | wc -l | tr -d ' ')" ) &
base64 -i "$PROBE" | CARRICK_RUN_ID=$RUN_ID CARRICK_HVF_ADMISSION_TRACE=1 \
  timeout 90 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p' 2>&1 \
  | tee "target/conformance/logs/hvf-residency-e4/procladder-160-$STAMP.log"
echo "rc=$?" | tee -a "target/conformance/logs/hvf-residency-e4/procladder-160-$STAMP.log"
wait
sudo -n scripts/sudo/kill.sh "$RUN_ID" 2>/dev/null || pkill -9 -f "carrick:$RUN_ID:"
```

Expected red-for-the-right-reason evidence, all recorded in the log:
- no probe output before the 90 s timeout (fork stalled, so `report!` never ran) → `rc=124`;
- `live_guests_at_45s` ≈ the soft budget (~120), i.e. the plateau is at `GLOBAL_VCPU_CEILING`, not some other failure;
- no `HV_NO_RESOURCES` hard-limit propagation lines (the soft budget parks first).

If instead the probe *completes* with `ladder_forked_all=false`, that is a different (bounded-failure) behavior than the current code reads — record exactly what happened; the evidence doc must describe the real failure mode.

Docker sanity (sequential, after the carrick run):

```bash
base64 -i "$PROBE" | docker run --rm -i --platform linux/arm64 ubuntu:24.04 \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p'
```

Expected: `ladder_forked_all=true`, `ladder_reaped_all=true` in under a second.

- [ ] **Step 4: fmt + commit**

```bash
rustfmt conformance-probes/src/bin/procladder.rs
git add conformance-probes/src/bin/procladder.rs
git commit -m "probe(conformance): procladder many-process residency invariant"
```

---

### Task 6: E4 evidence doc, strategy-memo addendum, memory index

**Files:**
- Create: `docs/2026-07-08-hvf-residency-e4-evidence.md`
- Modify: `docs/superpowers/specs/2026-07-08-carrick-architecture-strategy-memo.md` (append an addendum section at the end)
- Modify (user memory, not repo): `/Users/tjfontaine/.claude/projects/-Volumes-CaseSensitive-carrick/memory/` — new `project_hvf_residency_e4.md` + `MEMORY.md` index line

**Interfaces:**
- Consumes: every log from Tasks 2–5.
- Produces: the E4 verdict that the `WakeFromBlockingSyscall` lease implementation plan (separate, next) takes as input.

- [ ] **Step 1: Write the evidence doc**

`docs/2026-07-08-hvf-residency-e4-evidence.md`, following the E2/E3 template exactly (Verdict → Instrumentation Added → Measurements → Verification Commands → Next Track). Fill every number from the Task 2–5 logs — no estimates. The Verdict section must answer, explicitly:

1. Is the ~126 ceiling per-VM, per-vCPU, or memory-coupled? (Task 2 decision table.)
2. What is the sustained sequential create/destroy cycle cost, and does it degrade over 200 cycles? (Task 3.)
3. Does guest VA fragmentation multiply stage-2 descriptors/replay cost, or is replay bounded? (Task 4.)
4. What exactly happens today when a workload exceeds the soft budget with blocked (non-exiting) children — stall shape, plateau count, timeout behavior? (Task 5.)
5. Therefore: the residency-lease design constraints — eviction unit (VM vs vCPU), reacquire budget (µs), churn bound, and the acceptance test (`PROC_LADDER_N=160 procladder` MATCH).

Also record host info (macOS version, hw.model, memsize) so future cross-host runs are comparable — the ceiling is machine/OS-specific and undocumented by Apple; note that re-running Task 2's matrix after macOS updates is cheap insurance.

- [ ] **Step 2: Append the strategy-memo addendum**

At the end of `docs/superpowers/specs/2026-07-08-carrick-architecture-strategy-memo.md` append:

```markdown
## Addendum 2026-07-08: residency ceiling promotes Track 3

E4 (`docs/2026-07-08-hvf-residency-e4-evidence.md`) characterized the
system-wide HVF residency ceiling (~126 measured; soft budget 120). Because
blocked guest processes currently hold their VM/vCPU residency, the ceiling
binds on *alive* processes, not *running* ones, and a workload holding more
than the soft budget of blocked processes stalls in the unbounded permit
wait. That is a functional ceiling on whole-system workloads, not a latency
number.

Priority change: Track 3's `WakeFromBlockingSyscall` lease class moves ahead
of Track 4 (shared waiters and IPC objects). The lease design parameters
(eviction unit, reacquire budget, churn bound) come from E4's measurements.
The acceptance test is `PROC_LADDER_N=160` `procladder` matching the oracle.
```

If E4's verdicts contradict any sentence above (e.g. the ceiling turns out memory-coupled), edit the addendum to say what was actually measured — the doc records evidence, not the plan's predictions.

- [ ] **Step 3: Write the user-memory file and index line**

`project_hvf_residency_e4.md` in the memory directory, `type: project`, summarizing: ceiling scaling verdict, replay-bounded-or-not, procladder red status, and that the lease plan is next. Add the one-line pointer to `MEMORY.md`.

- [ ] **Step 4: Commit**

```bash
git add docs/2026-07-08-hvf-residency-e4-evidence.md docs/superpowers/specs/2026-07-08-carrick-architecture-strategy-memo.md
git commit -m "docs(arch): record E4 residency-ceiling evidence and promote Track 3"
```

---

## Explicitly out of scope (next plans, gated on E4)

- **`WakeFromBlockingSyscall` lease implementation** — its own plan, written against E4's measured eviction unit, reacquire budget, and churn bound; acceptance = `PROC_LADDER_N=160 procladder` MATCH plus no regression on `perf_fork`/`perf_fork_exec`.
- **Signal-pump stop sleep-tick fix** (`vcpu_kick.rs:158`, ~1.2 ms/fork) — separate small change with its own red-first measurement via the existing `fork-phases.d` harness.
- I/O-burst and park/wake overhead evidence campaigns (5–10x and ~2x vs Docker) — separate E-series.
