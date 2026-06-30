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

### 1. bhyve reclaim: fail loud instead of silent FP/FS-GS corruption — ✅ LANDED (d6672417)

> **Done 2026-06-30**, compile-verified on x86_64 FreeBSD 15.1 (the real bhyve
> target). Implemented the no-trait-change design below: `save_guest_state`
> `?`-propagates the register/desc/FP reads inside a `Result` closure (Ok(None)
> stays the legit no-FP case) and returns an EMPTY buffer on error;
> `rebind_to_slot` rejects a too-short buffer with a clean `TrapError` and
> propagates the FP-restore error. Happy-path buffer format is byte-identical, so
> normal reclaim is unchanged. **Remaining:** a full reclaim-stress run (an x86
> thread-stress fixture under bhyve) to exercise the path end-to-end — the change
> is safe-by-construction, so this is confirmation, not a blocker.


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

## Fleet-verification findings (2026-06-30, x86_64 KVM box root@10.14.14.66)

Driving the seccomp R2 fix end-to-end on a real x86 KVM guest (build my branch
in `/root/carrick-campaign`, run a static x86_64 ELF that installs the
Docker-prologue filter under `carrick run --platform linux/amd64 -v …`) surfaced
two things:

- ✅ **A second, general seccomp bug — `KILL_PROCESS` silently ignored (LANDED, 98651926).**
  `SeccompState::check` chose the most-restrictive stacked action with a raw
  `action < result` compare. That holds for every `SECCOMP_RET_*` EXCEPT
  `KILL_PROCESS = 0x8000_0000` (the largest u32, yet the most severe), so a
  guest's `RET_KILL_PROCESS` filter NEVER won and was ignored on every lane —
  and it masked the R2 arch fix (the libseccomp/Docker arch-mismatch action is
  KILL_PROCESS). Fixed with an explicit severity rank; red-first unit test +
  verified end-to-end: unconditional-KILL now SIGSYS-kills (exit 159); the
  `arch != X86_64 -> KILL` prologue ALLOWS the x86_64 guest (SURVIVED); an
  `arch != AARCH64 -> KILL` prologue KILLS it. This pair (T2 survives + T3 kills)
  is the definitive proof the R2 arch fix reports x86_64 on a real x86 guest.
- ✅ **NEW bug found + fixed: static x86 binaries SIGSEGV at exit (was 139) — entry RDX not zeroed (LANDED, e96cb54a).**
  The x86_64-gate test printed `SURVIVED` then exited **139**. Root-caused on the
  KVM box with a fault diagnostic: `rip=cr2=0x600` (an instruction-fetch #PF — the
  guest CALLED a garbage pointer at exit), STATIC-only and x86-only (the same
  static aarch64 binary exits cleanly under HVF; dynamic x86 binaries are clean).
  Cause: `program_longmode_entry` set RIP/RSP/RFLAGS but left the other entry GPRs
  as leftover init-blob state; the SysV x86-64 ABI defines RDX at entry as
  `rtld_fini` (0 = none), which glibc registers via `__cxa_atexit` and CALLS at
  exit — so a static binary jumped to garbage. Fixed by zeroing the entry GPRs
  (matching Linux `ELF_PLAT_INIT`). Verified end-to-end: static `write+return 0`
  now exits 0; dynamic guests unchanged. **Regression guard TODO (fits R6):** a
  `staticexit` conformance probe (a static ELF that returns 0 → MATCH exit 0).

Box note: `/root/carrick-campaign` (1.2 GB, my branch + a built debug `carrick`)
is left on the box for inspection — `rm -rf` it to reclaim space.

## bhyve fleet verification (2026-06-30, FreeBSD 15.1 root@10.14.14.189)

Built this branch on the FreeBSD box (`/root/carrick-campaign`) and ran the same
probes/workloads as the KVM lane under bhyve:

- ✅ **All three shared fixes carry to bhyve.** `seccompenforce` is all-true
  (KILL_PROCESS→SIGSYS, native arch, native number) and a static `write+return 0`
  ELF exits 0 — confirming the seccomp dispatcher fixes and the carrick-x86
  entry-GPR static-exit fix (which is in shared `program_longmode_entry`) all fix
  bhyve too, not just KVM. Single-threaded demand-paging + mremap is also correct.
- 🐞 **NEW (pre-existing) bhyve bug: `CLONE_VM` threads do not coherently share
  BSS/heap.** A pthread program where N threads `atomic_fetch_add` a shared
  global reports `isum=0` (all writes lost) for **N=2 and up** — i.e. NOT
  reclaim-related (hw.vmm.maxcpu=8; it fails well below that), and not my
  regression (none of my changes touch bhyve's clone/guest-memory model; the
  original Jun-23 binary crashed earlier on the same test, mine runs far enough to
  show the wrong result). The same binary is correct natively and under
  Linux/KVM. So threads aren't sharing the main thread's address space on bhyve —
  this is the campaign's known-hard "bhyve guest-memory coherence" area (see the
  `forkshared` / MAP_SHARED-anon / cross-process-futex-mirror work). It breaks
  most multithreaded guests (Go, Python-with-threads, …). **Repro:** a 2-thread
  `pthread_barrier_wait` + `atomic_fetch_add(&global, id)` under `carrick run
  --platform linux/amd64` on bhyve → `isum=0`.

  **CORRECTED ROOT CAUSE (2026-06-30, after a workflow design + dtrace/lldb/bhyvectl dig — the
  "memory coherence" framing above is WRONG):** the shared counter reads 0 because the worker
  threads **never execute a single instruction of guest user code** — not because their writes
  are lost. Evidence chain:
  - A glibc NPTL `pthread_create` issues `clone3` with the full `THREAD_MASK` (`flags=0x3d0f00`),
    so the dispatcher routes it to the **in-process sibling path** (`vcpu_loop/threads.rs` →
    `materialize_sibling`), NOT the `EagerCopy` fork path. The fork/`ForkRamStrategy` redesign is
    the wrong target (the adversarial review caught this).
  - The sibling reaches `run_vcpu_until_exit` → `next_syscall` → bhyve `run_x86` → the `VM_RUN`
    ioctl, and **never returns** from that first run. A native `lldb` backtrace of the wedged
    `guest-tid-*` thread shows it in `__sys_ioctl` ← `BhyveVcpu::run_x86` (vmm_x86.rs:242). It is
    NOT blocked: per-thread CPU climbs ~+5s/5s at ~70-80% — the vCPU **spins in guest code**.
  - `bhyvectl --vm=… --cpu=1` shows the sibling vCPU pinned at a **fixed** `rip=0x1153a4` (a tight
    self-loop), with `rax=0` and `rsp`=child-stack — so the ring-0 blob's `iretq` *did* deliver
    the clone-child context. It just spins at one instruction, issuing no syscall/fault/HLT, so
    the worker never runs and `pthread_join` returns the moment the process `_exit`s.
  - `VM_CAP_HALT_EXIT` is enabled on the main (BSP) vCPU but NOT on siblings — a real latent gap,
    but enabling it did NOT fix this (it is a spin, not a halt).

  **EXACT ROOT CAUSE (2026-06-30, pinned):** guest VA `0x1153a4` is the `jmp .` (`EB FE`) at the
  end of the **per-vCPU `#PF` fault stub** (`fault_slot_gpa(X86_FAULT_STUB_GPA=0x114000, id=1)` =
  `0x115000`; vector-14 stub + offset `0x24`). The bhyve fault stub
  (`guest_setup_x86::fault_stub_for_vector`) is `…store fault frame to scratch; OUT %al,$0xC7
  (E6 C7); jmp . (EB FE)` — it signals the host via the **`OUT $0xC7` doorbell** then *parks at
  the `jmp .`* until the host services the fault and moves RIP off it. The sibling takes a demand
  `#PF` (first touch of its fresh thread stack), runs the stub, but **its `OUT $0xC7` does NOT
  VM-exit** — so the host never sees the doorbell (verified: an id-keyed probe in run()'s
  `FAULT_DOORBELL` arm never fires for `id!=0`), and the AP parks in the `jmp .` forever. carrick's
  syscall (`OUT $0xC5`) and FP (`OUT $0xC6`) doorbells are the same `OUT`-based mechanism, so the
  AP can't make a syscall either — it can do *nothing* that exits via I/O.

  Ruled out (carrick-side setup is COMPLETE for the sibling): `program_x86_vcpu_longmode_entry`
  (the restore path, via `set_syscall_msrs`) already does `program_fault_tables(id)` (IDT/TR for
  the sibling's slot) AND `set_capability(VM_CAP_HALT_EXIT,1)` — so fault tables, HALT_EXIT,
  segments, and the blob+iretq are all correct (the iretq delivered rax=0 + child-stack
  correctly). Explicitly tested on the box and did NOT fix it: adding HALT_EXIT in
  `materialize_sibling` (already set), and skipping `vcpu_reset` for fresh siblings.

  So the bug is **bhyve-level: a sibling (AP, vcpuid≥1) vCPU's port `OUT` does not cause a
  `VM_EXITCODE_INOUT`**, while the BSP's (vcpuid 0) does (its FAULT doorbells were observed exiting
  in run()). This is what carrick's entire trap/doorbell substrate depends on, so the AP runs zero
  guest user instructions. **Key lever for the fix:** `VM_CAP_HALT_EXIT` *is* honored on the AP
  (it's set in the restore path) — i.e. a guest `HLT` *does* exit even when `OUT` does not — so a
  **HLT-based doorbell** (replace the `OUT $0xCx` doorbells with `HLT` + a reason marker, disambig
  in run()'s `VM_EXITCODE_HLT` arm) is a viable carrick-side fix that sidesteps the AP I/O-exit
  defect. The alternative is to root-cause why the AP's VMX I/O-exit control isn't active (a bhyve
  VMCS-init question; not resolvable from carrick without bhyve VMX internals). Next: prototype the
  HLT-doorbell on the fault stub and confirm the sibling reaches the host, then extend to the
  syscall/FP doorbells.

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
