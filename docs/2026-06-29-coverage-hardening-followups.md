# Coverage-hardening campaign — fleet-pending follow-ups (2026-06-29)

Companion to [`2026-06-29-coverage-regression-audit.md`](2026-06-29-coverage-regression-audit.md).
The audit's R1–R7 + Phase-1 landed on branch `feat/coverage-regression-hardening`
(seccomp live-bug fix, the futex errno-ABI guard + cross-backend observability,
the x86 syscall-completeness gate, sigframe guards, the CI cross-checks +
dormant kvm-smoke lane, the carrick-portable hoists, and the carrick-runtime
Phase-1 guards). What remains is the tail that **cannot meet the project's
"Definition of Done = live-verified end-to-end" bar from an Apple-Silicon dev
host** — it needs the FreeBSD/NetBSD/Linux fleet (and, for the reclaim path,
M:N thread-stress under a running guest). Each item below is specified to be
turnkey on the right box.

> **Tooling note that gates these:** `carrick-thread` now depends on
> `carrick-observability` (so the shared futex seam can fire the neutral
> `futex-unexpected-errno` probe on every backend). `carrick-observability`'s
> real `usdt` provider emits inline asm keyed to the **host** arch, so
> `cargo check --target x86_64-unknown-{freebsd,netbsd} -p carrick-vmm-bhyve`
> no longer compiles from an aarch64 Mac (it pulls `usdt` → aarch64 asm for an
> x86 target). This is pre-existing for the full freebsd closure (carrick-runtime
> already pulls observability) and harmless in CI (x86_64 runners, host==target);
> it only means **bhyve/nvmm engine changes must be compiled on an x86_64 host**
> (the FreeBSD/NetBSD fleet or an x86 Linux box), which is where they are tested
> anyway. `just check-netbsd` still works because NetBSD takes the observability
> `stub` path.

---

## R4-x86 — the carrick-x86 / reclaim consolidation (fleet)

### 1. bhyve reclaim: fail loud instead of silent FP/FS-GS corruption (correctness; do first)

`crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs::save_guest_state` (the M:N
reclaim-on-block path) silently swallows every read error:
`get_register_set(&SNAPSHOT_REGS).unwrap_or_default()` (→ empty vals → a too-short
buffer that makes `rebind_to_slot` panic on `copy_from_slice`),
`get_desc(...).unwrap_or((0,0,0))` (→ FS/GS base restored as 0 → broken TLS), and
`get_xsave().ok().flatten()` (→ flag 0, **conflated with the legit "thread has no
FP yet" case** → SSE/AVX silently dropped). The restore side
(`rebind_to_slot`, the `let _ = …set_xsave(&xs)` at ~line 1861) also ignores a
failed FP restore.

**Fix (local to bhyve_x86_engine.rs — no trait change):** add a leading
valid-header byte to the snapshot buffer.
- `save_guest_state`: build the body inside a `|| -> Result<Vec<u8>, TrapError>`
  closure that `?`-propagates `get_register_set` / `get_desc` /
  `get_xsave` (matching `Ok(Some)` → flag 1 + data, `Ok(None)` → flag 0 = legit
  no-FP, so the conflation is resolved). On `Ok(buf)` prepend `1`; on `Err`,
  return `vec![0]`.
- `rebind_to_slot`: if `state.first() != Some(&1)` → return
  `Err(TrapError::Hypervisor("bhyve reclaim: incomplete guest-state snapshot; refusing to restore zeroed state"))`;
  otherwise parse the body at `&state[1..]` (shift every offset by 1) with a
  length pre-check (return `Err` instead of panicking on a short buffer), and
  propagate the FP-restore `set_xsave` error instead of `let _`.

**Verify on x86_64:** `cargo check --target x86_64-unknown-freebsd
--all-targets -p carrick-vmm-bhyve` on an x86 host; run the bhyve thread-stress
gate (`scripts/run-thread-stress.sh` / the bhyve grind harness) so the reclaim
path actually executes. The error path itself is rare — the win is converting
silent corruption into a clean, attributable thread failure.

### 2. Shared x86 reclaim/snapshot serializer — VERIFY THE DATA FIRST, don't force-unify

The audit suggested one `carrick-x86` serializer over `X86VcpuSnapshot` for both
KVM (`kvm_x86_engine.rs` `serialize_x86_snapshot`) and bhyve
(`save_guest_state`). **Caution:** KVM's `serialize_x86_snapshot` is the *fork*
snapshot (full sregs/regs/xsave/MSRs); bhyve's `save_guest_state` is the
*reclaim* per-thread snapshot (`SNAPSHOT_REGS` + FS/GS + xsave). These capture
**different register sets for different purposes** — they are not obviously the
same wire format. Before unifying, confirm on-box that the captured state is
genuinely identical; if not, the high-value move is narrower: a shared
`carrick-x86` **XSAVE round-trip helper** (`fxsave_to_xsave`/`xsave_to_fxsave`
already live there) with a **red-first unit test that round-trips a non-zero YMM
region** (this part IS macOS-verifiable in `carrick-x86`'s own tests — it does
not need a backend), guarding the FP serialization both backends already share.

### 3. clone3 init-blob Stage-4 — has a TRAP, do carefully

`carrick-x86/src/bringup.rs::msr_init_blob` is the shared init blob; bhyve keeps
a duplicate in `guest_setup_x86.rs`. The audit wants them unified, BUT the shared
copy is **missing the 6837b3bd RDX/RCX restore fix** — re-pointing bhyve at it
today re-introduces the Go `#PF` at `RIP=0`. Port the `entry_rdx`/`entry_rcx`
params into the shared blob FIRST, move the
`msr_init_blob_restores_entry_rdx_rcx_before_iretq` assertion into `carrick-x86`
(macOS-runnable), prove it green, THEN delete the bhyve duplicate.

### 4. demand-paging RamInner ↔ WindowRegion (test visibility)

bhyve `RamInner` (reservation/writability/window-prune) and nvmm `WindowRegion`
are two diverged demand-paging models whose guard tests
(`reservation_writability_is_preserved_through_commit`,
`remove_windows_lets_reused_va_recommit_fresh`) compile to nothing on macOS CI.
Hoist the **pure** logic (no backend mapping syscalls) into a `carrick-x86`
module and move the tests there so `cargo test --workspace` runs them on macOS.
Keep the backend-specific mapping calls in the backends.

---

## R6 — conformance gating: fleet population

The harness mechanisms (lane-derived overlays, `--bless --lane`, the per-probe
gating allowlist, oracle golden-key guard, excused-probe fingerprint) land via
the carrick-conformance work on this branch. What needs the **fleet + Docker
oracle**:
- Populate the per-probe **gating allowlist** with the x86 probes that actually
  pass on the KVM/bhyve/NVMM fleet (run the gate, promote the green ones).
- Author + red-first-validate the new differential probes against the oracle
  (`seccompdefaultprofile` — guards the R2 fix end-to-end — plus
  `afunixbackpressure`, `semctlsetmode`, `sockopterrno`, `connectunspec`,
  `clockcoherence`, `reclaimfpregs`, `sigexitignmap`, `fasynciodeliver`, and a
  macOS Rosetta suite). Per the project's TDD rule, each probe must be proven RED
  against the broken binary before it is blessed — which requires the oracle, so
  it cannot be authored blind from a dev host.
- Seed/commit `baseline.bhyve.jsonl` + `baseline.nvmm.jsonl` with the real
  blessed verdicts from a canonical fleet run.

---

## Phase-4 long tail (mixed; verifiability noted)

- **Threaded futex `{0,0}`** (`dispatch_threaded_futex` in dispatch/mod.rs) — the
  519dd40f fix missed the live multithreaded path. (Host-neutral, macOS-runnable;
  in progress on this branch.)
- **`shmctl(IPC_SET)` mode store** — currently a universal no-op. (macOS-runnable;
  in progress.)
- **`Reg`/`SysReg`/`X86Reg` T1 refactor** + fix the false "compile error" doc — the
  three-way split forces `reg_to_x86()` + `unreachable!()` arms. High-risk (hot
  syscall path); macOS-compilable but wants the full conformance gate after.
- **OFD → process-lock downgrade** on BSD: add a `baseline.bsd.jsonl` excuse +
  a `compat-report` entry so the deliberate divergence is tracked, not buried.
- **inotify capability-driven source ownership** — on Linux the dispatch synthesis
  double-emits alongside the native inotify fd; let the native source own and
  suppress synthesis. (Linux-behavior; KVM-lane-verified.)
- **NVMM `vcpu_budget` override** — NVMM uses `NoopScheduler`, so >max_vcpus
  lifetime threads fail vCPU-create. Override `vcpu_budget()` to the queried
  `max_vcpus` + recycle the cpuid slot. (Compile-verifiable via `check-netbsd`;
  behavior is NetBSD-fleet.)
- **fuzz crate CI build** — `fuzz/` is an excluded sub-workspace that never
  compiles in CI; add `cargo build --manifest-path fuzz/Cargo.toml`, then
  sockaddr/msghdr/cmsg/clone_args decode targets.
- **`kvm_xsig` dead-forwarder cleanup** — cosmetic; `check-linux`-verifiable.
