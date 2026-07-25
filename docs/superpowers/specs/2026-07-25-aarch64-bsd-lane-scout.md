# aarch64-BSD native lane — grounding + design scout

**Date:** 2026-07-25
**Repo state:** `main` @ `2d567fb7` (the campaign brief cited `f5c15ccd`; nothing in this
document depends on the delta).
**Scope:** bringing carrick's native (no-VMM) backend up on **FreeBSD/aarch64** and
**NetBSD/aarch64** — the "aarch64-BSD lanes".
**Method:** read-only repo synthesis of five independently-scouted and then adversarially
verified dimensions (run-path shareability, host-crate anatomy, page geometry, gate path,
seam reuse). **No VM was booted.** Every claim is tagged VERIFIED (read in-repo),
INFERRED (reasoning over verified facts), or NEEDS-ON-BOX (only a guest probe settles it).
Where a verifier refuted or corrected a scout claim, the verifier's version is what appears
here; refuted claims are called out explicitly so they are not re-litigated.

**Precedent:** the NetBSD/x86_64 native lane campaign (31 commits, merged). Read
`docs/netbsd-native-lane-evidence.md`,
`docs/superpowers/specs/2026-07-25-netbsd-runpath-sharing-scout.md`, and
`docs/superpowers/specs/2026-07-24-fsbase-swap-seam-design.md` for the shape this
document is trying to be the aarch64 analogue of.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Does the aarch64 run path serve BSD aarch64 as bounded host-glue? | **YES, with one caveat**: bounded host-glue **plus** two net-new artifacts (an assembly port and a per-host trap/kick shim) **plus** one genuine design decision inside `carrick-dsr-aarch64` (ESR-free fault lowering) **plus** a 4-crate arch-gating pre-step x86 never needed. |
| How much smaller is the aarch64 run path than the x86 one? | **2.3x.** 5,880 production lines vs 13,669. Five non-test `cfg(target_os)` sites in the whole production half. Zero Darwin-only `libc` symbols. |
| Biggest new-code item | The trap/kick shim (2× ~300 LoC C, or 2× ~150 LoC Rust after gateway surgery). Not behind a seam today — consumed as 7 raw `unsafe extern "C"` declarations. |
| Biggest surprise (the FSGSBASE-analogue) | **ESR_EL1 does not exist in either BSD's aarch64 signal frame**, and it is load-bearing in **three** production paths — including one (`resolve_native16k_write_exec_fault`'s WnR bit) that is **MORE reachable at 4K pages, not less**. Runner-up: physical **x18**, where Darwin has a kernel opt-in the BSDs lack. |
| Second-biggest surprise | The gateway saves host `x19-x30` + `q8-q15` but **not host `x18`** — while translated code writes physical `x18`. Safe on Darwin only because the non-custom ABI treats x18 as kernel-reserved. |
| Hard blocker count (VERIFIED, code) | 6 |
| NEEDS-ON-BOX unknowns | 12 probe groups / 38 individual probes |
| Tasks | 16 (7 shared, 5 per-OS ×2 = the bulk of the labour, 4 gate/infra) |

---

## 1. Verdict on the thesis

### 1.1 The verdict

**The thesis HOLDS.** A BSD-aarch64 lane reuses the SAME aarch64 run loop the way
`native_freebsd.rs` was reused for NetBSD/x86: a cfg-widened module gate plus a
cfg-selected host-ops alias block. It is not a rewrite, and the run *loop* is measurably
cleaner than `native_freebsd.rs` was before its NetBSD re-gate.

**But the shape differs from the x86 precedent in one decisive way, and the campaign
must be sized for it:** the aarch64 lane's host glue is *not yet behind seams*. Where
NetBSD/x86 only had to swap a `use … as fault/futex` module alias against an
ALREADY-EXTRACTED `carrick_native_freebsd::fault` API, the aarch64 lane consumes its host
shim as **7 raw `unsafe extern "C"` declarations** bound to a 675-line Darwin C file, and
its gateway assembly is **Mach-O-symbol-welded**. So the campaign needs a
**seam-CREATION** step larger than x86's Task 3a — and it also needs one real decision
*inside* `carrick-dsr-aarch64`, the crate the thesis wanted to reuse verbatim.

### 1.2 Quantitative basis (all VERIFIED)

| Measure | aarch64 / Darwin | x86 / BSD | Note |
|---|---|---|---|
| Run-module production lines | **5,880** (`native_darwin.rs:1..5880`; `#[cfg(test)] mod tests` opens at 5881, EOF 12985 → 55% tests) | 13,669 (`native_freebsd.rs`; tests open at 13670 of 15837 → 14%) | 2.3x smaller because translate/emit/decode/block/memory-model were already extracted to `carrick-dsr-aarch64` (19,984 lines) while x86's stayed inline |
| Inner run loop | **854 lines** (`native_darwin.rs:2017`–`2870`) | 1,781 | fetch→translate→enter is **two calls** into an already-hollowed arch crate (`native_darwin.rs:2092`, `:2104`) vs x86's 543 inline lines |
| Non-test `cfg(target_os)` sites in the production half | **5** (`native_darwin.rs:545`, `582`, `619`, `1439`/`1447`, `2185`/`2199`) | 15 inventory items incl. 16 `exclusive_fixed_map_flag()` call sites | the whole module is gated once at `lib.rs:154`, so re-gating is a one-line change plus these five |
| Darwin-only `libc` symbols in the production half | **0** | n/a | complete inventory of 48 distinct `libc::` symbols is POSIX: fork/waitpid/waitid/pipe/poll/dup2/fcntl/pthread_kill/pthread_self/_exit/read/write/…; no `mach_*`, no `MAP_JIT`, no `__ulock`, no `dispatch_*`, no CoreFoundation |
| `target_os` hits in the ISA engine | **21** in `carrick-dsr-aarch64/src` — 15 in `counter.rs`, 4 in `gateway.rs`, plus `translator.rs`'s `mach_port` field. Every one is `all(macos, aarch64)` or `macos`; **no bare `target_arch` gate exists** | 4 in `carrick-dsr-x86/src`, all `cfg(freebsd)` test code | `mapped_memory.rs` (4,868 lines), `emit.rs`, `decode.rs`, `block.rs`, `emulate.rs`, `types.rs`, `artifact_spike.rs` have **zero** `target_os` hits |

### 1.3 The three-bucket tally

**11 SHARED-ALREADY** (zero campaign work):

- The signal-delivery decision core and fault-injection core are generic over
  `carrick_hal::SyscallTrap` and already serve both `NativeSignalTrap` (aarch64) and
  `NativeX86Trap` (x86): `crate::vcpu_loop::{deliver_pending_signal, inject_fault_signal,
  upgrade_protection_si_code, lower_el0_fault}`.
- `crate::fork_quiesce` (from `carrick-thread`, `fork_quiesce.rs` has only a `#[cfg(test)]`
  at :394) provides the fork/exec barriers used at 14 sites in the aarch64 loop.
- `NativeTimerDelivery` on portable `crate::itimer` + `carrick_timer_core`.
- `carrick_portable::si_pid` handles the siginfo width difference.
- Guest threads spawn via `std::thread::Builder` (`native_darwin.rs:3389`, `410`, `489`,
  `514`) — no raw clone/pthread_create/_lwp_create anywhere.
- Child-exit watching goes through `carrick_host_bsd::kqueue`
  (`native_darwin.rs:396-458`, `5715-5743`); that crate is `#![cfg(carrick_bsd_family)]`
  (`carrick-host-bsd/src/lib.rs:11`) whose `build.rs:15-24` emits the cfg from
  `CARGO_CFG_TARGET_OS` for macos|ios|freebsd|netbsd|openbsd|dragonfly with **no arch
  input at all** — so kqueue/errno/signum are already available on aarch64 BSD.
- `carrick-dsr/src/{lane,host,fault,cache,identity_memory}.rs` carry **zero** arch gates in
  production code (verified exhaustively: `lane.rs`'s only cfg is `#[cfg(test)]` at :93;
  `host.rs`'s at :155; `fault.rs` has no cfg at all; `cache.rs`'s two arch gates at :753 and
  :816 are both inside the `#[cfg(test)] mod test_host` opened at :738; `identity_memory.rs`'s
  five freebsd gates are inside the `#[cfg(test)]` module opened at :2630).
- `carrick_dsr::host::{JitRegion, ForkChildJit, NativeHostJit}` was written with aarch64 in
  mind — its doc at `host.rs:9-26` names "flush_icache is mandatory (AArch64 non-coherent
  I-cache)" and both W^X shapes.
- The prepared-image SCHEMA (`carrick_dsr::prepared_image`) and the exec-capsule transport
  are un-gated plain POSIX.
- `carrick-portable`'s `minherit` (FreeBSD `SYS_minherit`=250, NetBSD=273, at
  `carrick-portable/src/lib.rs:1184-1205`) — BSD syscall numbers are per-OS not per-arch;
  the whole file has zero `target_arch` and zero `asm!`.

**16 LANE-DISPATCHABLE** (a cfg arm, an alias, a trait method, or a table row — see the
reuse table in §2).

**7 DARWIN-WELDED** — and **5 of the 7 are capabilities the BSDs DO NOT NEED**:

| # | Weld | Verdict |
|---|---|---|
| 1 | custom-x18 ABI (`dlsym` of `os_set_custom_x18_abi_enabled` / `os_custom_x18_abi_enabled` / `update_tpidr`; TPIDR_EL0 bit 48 `0x0001_0000_0000_0000` toggled every crossing) — `csrc/native_darwin.c:210-292`, `222-224`, `235-253`, `271-293`, `295-341` | **Not needed on BSD if x18 is free** → ~20 LoC no-op. See §4 for the risk if it isn't. |
| 2 | ESR/FAR from `uc->uc_mcontext->__es` (`csrc/native_darwin.c:371-378`) | **Needs substitution.** The one genuine design decision. See §4.2. |
| 3 | execve self-reexec transport (`native_exec_capsule.rs`, 1,889 lines; produce/consume arms hard-gated `cfg(all(macos, aarch64))`) | **Not needed.** `grep -c native_exec_capsule crates/carrick-runtime/src/native_freebsd.rs` = 0 — the x86 BSD lane emulates execve in-process (`native_freebsd.rs:6968` `load_execve_image`, `Step::Execve` at :9910). Darwin needs it only because "after a real host `fork(2)`, Darwin permits only a narrow child-side API surface". |
| 4 | USDT probes (`carrick-observability/src/probes.rs:36-51` compiles the real provider only for `target_os="macos"` OR `all(any(linux,freebsd), target_arch="x86_64")`) | **Permanent stub / red-list.** Both aarch64 BSDs fall to the stub. The ~350-line `NativeDsrProbeForwarder` (`native_darwin.rs:1061-1409`) compiles but fires nothing → no `carrick trace`, no DSR profiling probes, no lifecycle markers on the new lanes. Matches the recorded bsdvm red list. |
| 5 | `_dyld_get_image_header(0)` in the shim's fatal-signal diagnostic printer (`csrc/native_darwin.c:446`) | **Not needed.** Diagnostics only. |
| 6 | libdispatch post-fork restriction forcing `native_clone_thread_rejection` (`native_darwin.rs:4686-4700`) | **Not needed — its removal is a BSD capability GAIN.** |
| 7 | `MAP_JIT` | **Already fully absorbed** by `NativeHostJit`. |

### 1.4 What makes it MORE welded than x86's re-gate — three items

1. **The host shim is not behind a seam.** `native_darwin.rs:545-568` is a raw
   `unsafe extern "C"` block for 7 entry points (`install_dsr_signal_handlers`,
   `kick_state_{create,destroy,request,acknowledge,bind_current,unbind_current}`)
   implemented by `crates/carrick-native-darwin/csrc/native_darwin.c` (675 lines). A
   `native_shim_fail_closed` module mirrors the names for off-lane builds
   (`native_darwin.rs:570-621`, `use` at :619) — but there is **no** `fault`-module
   trait/alias seam of the kind `carrick_native_{freebsd,netbsd}::fault` provides for x86
   (543 lines, 5-symbol module API).

2. **The gateway assembly is Mach-O-welded and calls the shim by name.**
   `crates/carrick-dsr-aarch64/src/gateway_aarch64.S` is 212 lines of pure AArch64 (no
   syscalls, no Mach, no OS dependency in the instruction stream), but every symbol carries
   the Mach-O leading underscore (`.globl _carrick_dsr_enter_raw` at :19-20;
   `_carrick_dsr_exit_{syscall,direct,indirect,sensitive,unsupported,signal}` at :113-119;
   `_carrick_dsr_exit_common_{start,end}` at :140/:195) while the Rust externs at
   `gateway.rs:236-244` declare them **un-prefixed** — consistent on Mach-O, broken on ELF.
   It also `bl`s two Darwin-private ABI-switch helpers by name at :39
   (`_carrick_native_dsr_enter_guest_abi`) and :131/:194
   (`_carrick_native_dsr_enter_host_abi`). `build.rs:7-17` assembles it only for
   `os == "macos" && arch == "aarch64"`, and `gateway.rs`'s ENTIRE `native_gateway`
   module (including `syscall_exit_address()`) sits behind `cfg(all(macos, aarch64))`
   (:232) with a fail-closed `DsrError::Gateway` complement (:465-539). The x86 gateway
   already models the portable form — un-prefixed globals (`gateway_x86_64.S:41`) plus a
   `#if defined(__ELF__) .section .note.GNU-stack` tail (~:348-350) and
   `#if defined(__NetBSD__)` arms.

3. **A structural asymmetry in the signal exit determines the shim's size.**
   VERIFIED by direct read: `_carrick_dsr_exit_signal`
   (`gateway_aarch64.S:119-133`) does **not** save the guest register file — it does
   `clrex`, recovers the context pointer from a 16-byte recovery slot below the saved host
   SP, sets phase 2, calls `enter_host_abi`, and branches straight to
   `carrick_dsr_restore_host`. By contrast `carrick_dsr_exit_common` (:142-184) DOES save
   (`stp x0, x1, [x28, #0]` …). Consequence: on aarch64 the **signal handler** must
   snapshot the entire mcontext into the 1216-byte `carrick_native_dsr_signal_context` —
   hence 8 `_Static_assert`s pinning offsets 832/1080/1088/1096/1104/1112/1152/1160/1168/
   1176/1184/1192/1200 and size 1216 (`csrc/native_darwin.c:63-90`). On x86, the shim only
   needs a signal-stub address + the byte offset of a lane-neutral 24-byte
   `carrick_dsr::fault::FaultRecord`, because the x86 gateway's shared exit TAIL saves the
   guest registers.

### 1.5 The alternative shape, if the controller judges it too welded

There is no "write a second run loop" fallback worth taking — the loop is 854 lines and
2 of its 5 host-specific sites are `snapshot.esr` diagnostic reads. The real fork is
**how deep to extract before porting**:

- **Route (a) — mirror the C shim per host.** ~300 LoC C each, needs full knowledge of
  the 1216-byte `DsrContext`/snapshot layout and its `_Static_assert`s. Faster, and
  **zero risk to the proven Darwin gateway**.
- **Route (b) — extract first.** Change `_carrick_dsr_exit_signal` in
  `gateway_aarch64.S` to save the guest register file the way `carrick_dsr_exit_common`
  already does, so the shim only needs a lane-neutral record + an offset — yielding a
  small pure-Rust shim exactly like `carrick-native-netbsd/src/fault.rs`. Better end
  state, honest "deeper extraction first" answer, but it touches the Darwin gateway's
  signal path.

**Recommendation: (a) for the first landing, with (b) logged as the follow-on.** The x86
campaign's own precedent is to land the lane and defer the cosmetic/structural cleanups
(`native_freebsd.rs` → `native_x86.rs` was explicitly deferred "for git-blame continuity",
`lib.rs:159-162`). Route (b) done *after* two working BSD shims exist is a refactor with
three consumers to validate against; done *before*, it is speculative surgery on the only
working lane.

---

## 2. The required host-crate surface — REUSE TABLE

**Housing decision (recommended, VERIFIED-grounded): do NOT create new crates.** Both
`carrick-native-freebsd` (`src/lib.rs:20`) and `carrick-native-netbsd` (`src/lib.rs:19`)
are gated `#![cfg(target_os = …)]` **only** — `grep -rc target_arch` over all 11 source
files of both crates returns **0 for every file**. `NativeHost::NAME` is the OS not the
ISA (`carrick-dsr/src/lane.rs:37`, comment `"darwin" | "freebsd"`), and `::NAME` has no
consumer in `carrick-runtime/src` or `carrick-dsr/src`, so nothing infers ISA from it.
`carrick-runtime/Cargo.toml:133-139` target-gates both deps by `target_os` only, so an
aarch64 arm inside the same crate is already dependency-reachable. → **arch-gated modules
inside the existing crates, on the SAME `FreebsdHost`/`NetbsdHost` types.** The price is a
mandatory arch-gating cleanup of the just-landed x86 modules (Task 1).

Legend: **AS-IS** = reusable verbatim from the x86 BSD crate · **VARIANT** = same shape,
aarch64 body · **NEW** = net-new · **DROP** = not needed on BSD.

| Piece | FreeBSD/aarch64 | NetBSD/aarch64 | Reason / evidence | Size |
|---|---|---|---|---|
| **JIT mapping (W^X)** | **AS-IS** | **AS-IS** | shm dual-map is arch-agnostic and already on-box unit-tested. FreeBSD `shm_open(SHM_ANON)`+ftruncate+2 `MAP_SHARED` maps (`carrick-native-freebsd/src/jit.rs:47-62`, `115-150`); NetBSD has no `SHM_ANON` so it creates `/carrick-jit-<pid>-<n>` `O_CREAT\|O_EXCL` with **allocation-free formatting** (fork-child safe) then `shm_unlink`s immediately (`carrick-native-netbsd/src/jit.rs:61-92`, `103-148`) | 0 |
| **`ForkChildJit`** | **AS-IS** (`Fresh`) | **AS-IS** (`Fresh`) | A `MAP_SHARED` dual map is inherited-*shared* across fork, so the child MUST take a fresh object — proven with a real fork test (`carrick-native-netbsd/src/jit.rs:389-455`). Darwin returns `Inherited` because `MAP_JIT` is `MAP_PRIVATE`/CoW | 0 |
| **`begin/end_thread_write`** | **AS-IS** (no-op) | **AS-IS** (no-op) | dual-map needs no per-thread toggle; Darwin's `pthread_jit_write_protect_np` is the Apple-Silicon-only hardware toggle | 0 |
| **`flush_icache`** | **VARIANT** | **VARIANT** | **MANDATORY on aarch64, currently a documented x86 NO-OP in both crates** (`carrick-native-freebsd/src/jit.rs:167-170`, `carrick-native-netbsd/src/jit.rs:253-256`). **This is the one item that fails SILENTLY** — because the crate gate is `target_os`-only, `fn flush_icache(&self, _exec_ptr, _len) {}` compiles and runs unchanged on aarch64 and produces stale-I-cache execution of freshly-published code. Body = `__clear_cache(exec_ptr, exec_ptr+len)`. **Must land in the SAME commit that first makes either crate compile on aarch64.** | ~20 LoC ea. |
| **Fault shim (mcontext read + PC/SP rewrite)** | **NEW** | **NEW** | Structure of `carrick-native-{freebsd,netbsd}/src/fault.rs` is the right template (process-global atomics `CODE_BASE`/`CODE_LEN`/`SIGNAL_STUB`/`KICK_STUB`/`FAULT_RECORD_OFFSET`/`OLD_ACTIONS`; a 5-symbol API; out-of-region faults restore the prior disposition so host bugs stay fatal), **but "just swap the accessors" does NOT carry**: see §2.1 | 300 LoC ea. (C) or 150 (Rust, route (b)) |
| **ESR substitute** | **NEW (shared design)** | **NEW (shared design)** | Neither BSD exposes ESR. Load-bearing in **three** production paths — see §4.2 | ~M, shared |
| **Kick transport** | **VARIANT** | **VARIANT** | Signal NUMBER is an arch-independent OS fact and is already chosen: FreeBSD 65/66 (`native_freebsd.rs:7518-7528`), NetBSD 33/34 (`carrick-native-netbsd/src/fault.rs:184` + `lib.rs:30-36` const-assert). Delivery is POSIX `pthread_kill`. What changes vs x86: rewrite **PC not RIP**, and there is no spilled-RCX to repair. Darwin uses SIGPIPE only because macOS has no RT signals | S ea. |
| **Kick-state object** | **NEW** | **NEW** | Darwin's C `kick_state_{create,destroy,request,acknowledge,bind_current,unbind_current}` (`csrc/native_darwin.c:92-194`) is 7 of the 7 raw externs; the deferred-kick-in-TLS + typed-exit-status-5/8 machinery (`:451-473`, `:499-533`) rides with it | folded into the fault shim |
| **Cross-process futex** | **AS-IS (module) / NEW (adapter)** | **AS-IS (module) / NEW (adapter)** | `carrick-native-freebsd/src/futex.rs` (`_umtx_op`=454 + 1024-slot `MAP_SHARED` waiter table + logical requeue) and `carrick-native-netbsd/src/futex.rs` (`SYS___futex`=166, Linux-shaped, no table) have **zero** `target_arch`, use only `libc::syscall` + POSIX mmap, and expose the identical 4-fn API. Lower primitives `carrick-host/src/{umtx.rs:4, netbsd_futex.rs:22}` are OS-gated only. **BUT** the aarch64 loop consumes `Arc<dyn carrick_hal::PlatformFutex>` (`native_darwin.rs:3171`, `:3196`, `:8738`) and **no type implementing `PlatformFutex` over the BSD primitives exists anywhere** — `grep -rn 'impl .*PlatformFutex for' crates/` = **0 hits**; `BsdFutex` appears only in comments | ~80 LoC: lift the 2 `SharedFutexSyscall` adapters out of the VMM crates + 2 `threaded_impl` arms |
| **Waiter key** | **AS-IS** | n/a (default `None`) | `carrick-native-freebsd/src/waiter_key.rs:18-90` is pure `sysctl(CTL_KERN/KERN_PROC/KERN_PROC_VMMAP)` + `kve_vn_fsid`/`kve_vn_fileid`/`kve_offset` arithmetic. libc cross-check: `kinfo_vmentry`, `MAP_EXCL`, `PROC_REAP_ACQUIRE` all live in libc's **MI** freebsd module, not in `aarch64.rs`/`x86_64.rs` | 0 |
| **`exclusive_fixed_map_flag`** | **AS-IS** (`MAP_EXCL`) | **AS-IS** (default 0) | mmap flag, arch-independent (`carrick-native-freebsd/src/lib.rs:54-56`; NetBSD documents keeping the default at `lib.rs:48-53`). **Note: the aarch64 lane has ZERO call sites** — it uses biased `mapped_memory`, not `identity_memory`, so the 16 x86 call sites don't exist here | 0 |
| **`become_guest_reaper`** | **AS-IS** (`procctl(PROC_REAP_ACQUIRE)`) | **AS-IS** (no-op = existing red-listed gap) | arch-independent. **Open:** the aarch64 production code never calls `become_guest_reaper()` at all (0 hits in `native_darwin.rs:1..5880`) — so either Darwin has an equivalent elsewhere, or the aarch64 lane already has this orphan-reaping gap on macOS today. Worth a targeted look before it is silently inherited on two more hosts | 0 |
| **`vdso_tsc_calibration`** | **DROP** (default `None`) | **DROP** (already `None`) | x86 by name AND body: `carrick-native-freebsd/src/tsc.rs:87,89` `std::arch::x86_64::_rdtsc`, `:43-59` `machdep.tsc_freq`. Exactly one consumer, `native_freebsd.rs:6484`. Wired **unconditionally** at `carrick-native-freebsd/src/lib.rs:76-78` → **must gain an arch gate or FreeBSD/aarch64 does not compile** | XS (gate) |
| **`fsbase.rs`** | n/a | **DROP** | Exists solely because NetBSD denies ring-3 FSGSBASE (`carrick-native-netbsd/src/fsbase.rs:33-35`, `61-107` naked x86 asm). **No aarch64 analogue** — see §4.1. Needs an arch gate | XS (gate) |
| **Host counter plan** | **NEW** | **NEW** | Duty with **no seam at all** today. `carrick-dsr-aarch64/src/counter.rs`'s `host_counter_plan()`/`host_counter_scale()` return `Unsupported`/`None` on every non-macOS target (:~193-198, :~209-215). `plan_for_mode(Some(1), …)` already returns `Inline{Cntvct, 1:1}` (:120-128) — the correct BSD answer, architecturally SIMPLER than Darwin's commpage-mode read. **But `fallback_counter_ticks()` is `#[cfg(target_os="macos")]`** (:~224) so the BSD lane needs its own tick source, not just a re-gate; and `CNTFRQ_EL0` is a **direct virtualized host read** (`decode.rs:1107-1111`), so guest and host must agree on frequency with no translation layer | ~60 LoC |
| **vvar clock sources** | **VARIANT** | **VARIANT** | `install_native_probe_sink` installs `native_vvar_clock_sources` into `mapped_memory`; that fn calls `crate::trap::host_counter_frequency()` + `host_clock_uptime_ns()`. On macOS `crate::trap` IS carrick-vmm-hvf's; on the non-macOS arm `crate::trap` re-exports `carrick_host::clock::host_clock_uptime_ns` but **not** `host_counter_frequency` (that symbol lives only in `carrick-vmm-hvf/src/trap/sysreg.rs:95` and, deliberately duplicated, `carrick-dsr-aarch64/src/counter.rs:20`). The BSD arm returns `(0,0)`, which the vvar stamper's zero-frequency guard skips | ~20 LoC |
| **Exec transport** | **DROP** | **DROP** | See weld #3 in §1.3 | 0 |
| **The 2 new `NativeHost` methods from the x86 campaign** | inherited | inherited | `become_guest_reaper` + `vdso_tsc_calibration`. Both defaulted (`carrick-dsr/src/lane.rs:66-84`); aarch64 needs neither actively | 0 |
| **New `NativeHost` methods the aarch64 lane wants** | **NEW** | **NEW** | counter plan, vvar clock sources, guest-ABI switch (enter/exit hooks), kick signal number. **Design question in §7** | 3–6 methods |
| **`minherit`** | **AS-IS** | **AS-IS** | `carrick-portable/src/lib.rs:1184-1205`, zero `target_arch`, zero `asm!` | 0 |
| **kqueue / errno / signum** | **AS-IS** | **AS-IS** | `carrick-host-bsd` is `#![cfg(carrick_bsd_family)]`, arch-neutral by construction | 0 |
| **USDT probes** | **DROP (stub)** | **DROP (stub)** | Weld #4. Capability loss, red-list | 0 to accept |

**Headline counts: 12 AS-IS · 7 VARIANT · 6 NEW · 5 DROP.**

### 2.1 Why the fault shim cannot be a mechanical accessor swap (REFUTES a scout claim)

The x86 shims read the mcontext through `libc` (`mc_rip`/`mc_r15`/`mc_rcx` on FreeBSD;
`__gregs[_REG_RIP=21 / _REG_R15=11 / _REG_RCX=3]` with a const-assert on NetBSD,
`carrick-native-netbsd/src/fault.rs:51-59`). That does **not** carry to aarch64, because
libc-0.2.186's aarch64 BSD bindings are unusable for this purpose:

- **NetBSD/aarch64 is self-inconsistent.**
  `libc/src/unix/bsd/netbsdlike/netbsd/aarch64.rs:14-18` declares
  `mcontext_t { __gregs: [greg_t; 32], __fregs, __spare[8] }` while its OWN constants at
  :122-132 are `_REG_ELR = 32`, `_REG_SPSR = 33`, `_REG_TIPDR = 34` — indices **past the
  end of the array** (real NetBSD aarch64 `_NGREG` is 35: X0-X30, SP=X31, ELR=32, SPSR=33,
  TPIDR=34). `__gregs[_REG_ELR as usize]` is a constant out-of-bounds index, so the shim
  **cannot read or rewrite the PC** through libc's `mcontext_t` at all. Contrast the amd64
  precedent where the binding IS self-consistent (`netbsd/x86_64.rs:12` 26-element array,
  `:55` `_REG_RIP = 21`).
- **A live landmine in the same file:** `netbsd/aarch64.rs` DOES define `_REG_R11 = 11`
  and `_REG_R15 = 15` (AArch32 aliases). A careless copy of the amd64
  `fault.rs:55-59` index assert will **compile against the wrong register file**.
- **FreeBSD/aarch64 mis-sizes `mcontext_t`.**
  `libc/src/unix/bsd/freebsdlike/freebsd/aarch64.rs:19-25` declares
  `fpregs { fp_q: u128, … }` — a **single** 128-bit lane — while the aarch64 snapshot needs
  all 32 vector registers (`carrick-dsr-aarch64/src/snapshot.rs:19` `v: [[u8;16];32]`, Darwin
  `memcpy` at `csrc/native_darwin.c:374`) plus fpsr/fpcr. The single-lane `fp_q` also makes
  `mc_flags`/`mc_spare` offsets wrong.
- **The real siginfo extras are invisible.** NetBSD carries `si_trap`/`si_trap2`/`si_trap3`
  and FreeBSD carries `si_trapno`, but libc exposes neither (`netbsdlike/netbsd/mod.rs:225-236`
  is padded to `__pad2:[u64;13]`).

**Conclusion:** write the aarch64-BSD fault shim in **C against real system headers** (like
`csrc/native_darwin.c`), or ship a **locally-asserted `#[repr(C)]` redefinition** — the
in-tree precedent for the latter is `carrick-native-netbsd/src/fsbase.rs:20-30`, which
transcribes a raw on-box ABI rather than trusting libc. **Do not read the aarch64 BSD
mcontext through libc bindings.** This finding is independent of the ESR question and
applies even if an ESR-equivalent is found.

### 2.2 Two claims from earlier scouting that were REFUTED — do not re-plan around them

**(a) The `flush_icache` "seam gap" is NOT a seam gap.** The scout argued that because
`fn flush_icache(&self, exec_ptr: *const u8, len: usize)` (`carrick-dsr/src/host.rs:141`)
receives only the EXEC alias while the bytes were stored through the RW alias, the
**shared** `carrick-dsr` trait would have to change. REFUTED on three grounds:

1. On ARMv8-A data/unified caches are required to behave as PIPT and both aliases map the
   same physical frame, so `dc cvau`/`ic ivau` (i.e. `__clear_cache`) issued on the EXEC VA
   cleans/invalidates exactly the lines the write-alias stores dirtied; `DC CVAU` is
   permission-checked as a *read*, and the exec alias is `PROT_READ|PROT_EXEC`. [INFERRED
   from the architecture; NEEDS-ON-BOX only for `SCTLR_EL1.UCI` EL0 access, which both BSDs
   need for their own `__clear_cache`.]
2. Even if (1) were false, the fix is **host-local**. "Stateless" is a doc note, not an
   invariant the crates honor — `carrick-native-netbsd/src/jit.rs:53` already keeps a
   `static JIT_SHM_COUNTER: AtomicU64` and both fault shims keep process-global atomics. A
   host crate can register `(exec_base, write_base, capacity)` in `map_code_cache` and
   derive the write alias with **zero** shared-seam change.
3. A write-alias signature would not even serve one existing call site:
   `carrick-dsr-aarch64/src/mapped_memory.rs:157-161` flushes GUEST exec pages that are not
   inside any `JitRegion`.

For the record, if the signature ever DID change the blast radius is **5** production call
sites (`cache.rs:604`, `:636`, `:719`, `carrick-dsr-aarch64/src/mapped_memory.rs:159`,
`carrick-dsr-x86/src/translator.rs:134`) + 5 non-host impls (`carrick-dsr/src/lane.rs:115`,
`cache.rs:797`, `cache.rs:853`, `carrick-dsr-x86/src/translator.rs:605`,
`carrick-runtime/src/native_darwin/darwin_jit.rs:47`) + ~25 test sites — not 4.
**Drop the seam-gap workstream.**

Reassurance the earlier scouting missed: the **guest**-side maintenance ops are not part of
this risk at all. Guest `dc cvau`/`ic ivau` are decoded as sensitive exits
(`decode.rs:1133-1137`) and serviced as pure NO-OPs (`native_darwin.rs:2230`
`DcCvau | IcIvau => {}`), because coherence for guest code goes through the page-generation
guards. Only carrick's OWN JIT publication needs host icache maintenance — and using the
compiler builtin `__clear_cache` sidesteps the `SCTLR_EL1.UCI` question entirely.

**(b) The 2026-07-17 seams design did NOT exclude this campaign.** Its line 167-168 reads
in full: "No attempt to run x86_64 guests on macOS or aarch64 guests on FreeBSD via DSR
(native is same-ISA by definition; cross-ISA stays VMM/Rosetta)." The parenthetical makes
it a **cross-ISA** exclusion — on that doc's rig "FreeBSD" means the amd64 box, so
"aarch64 guests on FreeBSD" = aarch64 guest on an amd64 host. aarch64-Linux on
aarch64-FreeBSD is same-ISA and not excluded; `page_profile.rs:110-119` echoes the same
invariant as live code. **Keep the consequence, discard the reasoning:** the real reason to
distrust that doc's portability claims for the aarch64 direction is its own
verification-constraint section at :77-90 — the rig could never cross-check an aarch64
target (`ring`'s C build lacks an Apple SDK; usdt 0.6.0 picks probe-asm registers by
proc-macro HOST arch). The aarch64 arms of the factoring are **uncompiled-by-construction**,
not out-of-scope-by-intent.

---

## 3. Page geometry

### 3.1 What `native16k` and `linux4k` mean

They are the two Darwin-only answers to ONE problem: Darwin/aarch64 has a **16 KiB** host
page while Linux/aarch64 guests assume 4 KiB.

- **`Native16k`** = *uniform*, host == linux == 16384. The guest is simply TOLD pages are
  16K, via `AT_PAGESZ` (`carrick-mem/src/memory.rs:1221-1231`) and every syscall-layer
  rounding through `SyscallDispatcher::linux_page_size()`
  (`dispatch/mod.rs:2558-2560`; 28 call sites across `carrick-runtime/src`, ~20 in
  `dispatch/mem.rs`).
- **`Linux4kOn16k`** = 4096-over-16384, the only case that turns on the guarded/composed
  sub-page apparatus, which exists because one 16K host page can contain 4 Linux pages
  with different permissions that a host `mprotect` cannot express. Policy =
  `classify_host_page_state` + `decide_linux4k_on_16k_mapping`
  (`carrick-dsr/src/page_geometry.rs:113-194`): Uniform16k → direct mprotect;
  Composed16k → private-backing compose; MixedGuarded → `PROT_NONE` + decode-and-emulate;
  ExecutableMixedPage → refused. The emulators are a bounded catalog in
  `carrick-dsr-aarch64/src/emulate.rs` (**7** entry points: :325, :401, :583, :710, :807,
  :1034, :1165 — scalar/SIMD/pair/atomic/exclusive + the fault dispatcher).

There are exactly two variants (`carrick-guest-mem/src/lib.rs:181-184`, duplicated in
`carrick-spec/src/lib.rs:307` with a comment explaining why: carrick-dsr must stay off
carrick-spec's dependency graph). **No uniform-4K variant exists.**

### 3.2 What the BSD aarch64 hosts likely are — and this is NOT verified

`docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md:27-30` asserts "**4K
pages.** FreeBSD/NetBSD arm64 are 4K-page hosts vs Darwin's 16K … run the aarch64 DSR
translator in a 4K world for the first time." **That is an unsourced assertion in a design
doc.** A repo-wide search finds no captured page-size probe of those VMs (`scripts/bsdvm.py`
has zero occurrences of `pagesize`/`page_size`/`PAGE_SIZE`; the only `_SC_PAGESIZE` hits
under `docs/` are Darwin/x86 plan snippets). Nothing in code asserts "aarch64 ⇒ 16K": the
constant is named `DARWIN_NATIVE_PAGE_SIZE` (`page_geometry.rs:13`) and
`carrick-dsr/src/lane.rs:15-22` deliberately refuses a per-ISA page constant. Host
detection is runtime `sysconf(_SC_PAGESIZE)` (`page_profile.rs:225-234`), so the *code*
does not care — but every "4K" estimate in this document is **conditional until one
`getconf PAGESIZE` is run on each guest.**

### 3.3 Consequences for the new `page_profile` arms, per scenario

The capability table is a 3-arm match on `(HostOs, host_isa)` at `page_profile.rs:123-140`:
`(Macos, Aarch64) → native_plan`, `(FreeBsd, Amd64)` and `(NetBsd, Amd64) →
x86_native_plan`, then a catch-all `Unsupported`. `native_plan` (:144-189) returns
`Unsupported` in **all three** request arms unless `host_page_size ==
DARWIN_NATIVE_PAGE_SIZE` (:148-152, :157-161, :165-169).

**Scenario A — 4 KiB (expected).** The needed arm's *values* are exactly
`x86_native_plan`'s (`page_profile.rs:196-223`): refuse any non-Auto request, require
`host_page_size == DEFAULT_LINUX_PAGE_SIZE`, emit `native_profile: None`. Nothing in that
body is x86-specific; only its name and 2 strings say FreeBSD/x86_64, and the two tests
that touch it assert only the substring `"no page-profile knob"` (:405, :447) so a rename
is test-safe. **BUT the x86 arm's *reasoning* does NOT carry — see §3.4.**

*Genuine simplification at 4K:* the linux4k guarded-page machinery becomes unreachable.
`uses_linux4k_subpages()` is `host == 16K && linux == 4K`
(`mapped_memory.rs:1626-1628`, mirrored at :298-300) and is FALSE at 4K/4K;
`classify_host_page_state` short-circuits to `Uniform` whenever host == linux
(`page_geometry.rs:117-118`); `linux4k_address_is_guarded` returns false unless
`uses_linux4k_subpages()` (:2532-2534, verified by direct read); and every guarded
emulator's permission check routes through `linux4k_range_allows` which returns false
off-predicate (:1896). The `native_darwin.rs:3031-3043` guarded arm is dead at 4K, and the
emulators re-check the predicate themselves (`emulate.rs:1165-1186`) so a mis-wired fault
shim yields a typed `NativeMemoryError::Unsupported`, not silent corruption.

**Scenario B — 16 KiB.** The natural arm is the *uniform-16K* shape (`Auto → Native16k`,
host == linux == 16384) — and because `page_geometry.rs:117-118` short-circuits on
host == linux, **zero guarded machinery is reached**. The guarded apparatus becomes
load-bearing only if that lane *additionally* needs 4 KiB guest semantics (the `linux4k`
knob), which is a separate requirement. Note an x86-shaped arm on a 16K host fails
**closed**, not wrong (`page_profile.rs:208-212`), so the arm choice carries no
silent-wrong-answer risk.

**Scenario C — 64 KiB.** Needs a genuinely new profile: `page_profile.rs:151/159/167` hard-refuse
`!= 16384`, `dispatch/proc.rs:4132` derives `16*1024` from `Native16k`, and
`carrick-guest-mem/src/lib.rs:181-184` has no 64K variant.

**Constraint on any arm (VERIFIED test):** `native_linux4k_plan_reports_4k_linux_on_16k_host`
(`page_profile.rs:464-490`) expects `resolve_execution_plan(Native, Linux4k)` to be `Err` on
any host that is not Darwin/aarch64-with-16K-pages. An arm that ACCEPTS `linux4k` turns it
red on the box; refusing the knob (x86 style) keeps it green. Separately, the conformance
runner splices `--native-page-profile native16k` unconditionally into its native-DSR lane
argv (`carrick-conformance/src/lane.rs:240-251`, `446-449`), so a BSD-aarch64 conformance
lane must not clone that lane variant.

### 3.4 The real trap: at 4K the write-exec machinery gets MORE reachable, not less

**This REFUTES the intuitive reading and is the single most important geometry finding.**
VERIFIED by direct read of `mapped_memory.rs`:

- `native16k_write_exec_page()` (:1631-1646) gates on `uses_linux4k_subpages()` being
  **FALSE** plus `region.host_protects`. At 4K/4K the predicate is false → **the gate is
  OPEN**, returning `Some(page_start)` for any `host_protects` region page whose prot has
  `PROT_WRITE|PROT_EXEC`.
- `prepare_native16k_write_exec_host_write()` (:1727-1734) likewise gates on
  `len == 0 || uses_linux4k_subpages()` → active at 4K.
- `native_host_prot_for_page()` (:2540-2550) takes the `!uses_linux4k_subpages()` branch at
  4K and returns `native16k_host_prot(prot)`.
- `native16k_host_prot()` (:3879-3889) **unconditionally** strips `PROT_WRITE` from any
  `W|X` page and **always** strips `PROT_EXEC`, at **every** geometry. So a guest RWX page
  is host-mapped read-only and the guest's first write MUST take this fault.
- `supports_concurrent_exec_protection()` returns `true` unconditionally (:3731-3733), so
  `dispatch/mem.rs:1104-1128`'s `native16k_write_exec_rejection` early-returns `None` at
  :1117 — no dispatch-level guard keeps a 4K lane out.
- `prepare_dsr_execution` also calls `native16k_write_exec_page(snapshot.pc)`
  (`native_darwin.rs:1955`) — active at 4K.

**Concrete failure mode with a synthesized `esr = 0`:** `mapped_memory.rs:1761`
`!matches!(0, 0x0c..=0x0f)` → `Ok(false)` → `native_darwin.rs:3044-3050`
`lower_el0_fault(0, …)` → `el0_fault_signal(0)` with `ec == 0` → `None` →
`native_die_by_signal(SIGSEGV)`. **A guest holding any `PROT_WRITE|PROT_EXEC` mapping is
killed on its first write.**

Meanwhile `has_native16k_write_exec_pages()` (:1648-1651) **does** hard-check
`host_page_size != 16*1024 || linux_page_size != host_page_size → false`, so at 4K the
vfork safety refusal (`native16k_vfork_rejection`, :1668-1672) **silently disarms** while
the fault path stays armed. Scoping honesty: this is a **DORMANT TRAP**, not a live defect
— the sole production consumer is `native_darwin.rs:2520-2524`, inside a module gated
`cfg(all(macos, aarch64))` where the host page is always 16K (the other cited "consumer",
`native_darwin.rs:9427`, is inside `#[cfg(test)] fn
native16k_write_exec_rejects_later_vfork`).

**The deeper defect the campaign should fix:** both functions use **page size as a proxy
for a HOST W^X POLICY question** (Darwin forbids RWX without `MAP_JIT`). The correct fix is
a host-policy predicate, not "also accept 4096 in the 16K clause". Whether a BSD/aarch64
host needs the W→X flip at all is NEEDS-ON-BOX; NetBSD is the specific risk (its x86 host
crate already needed shm dual-map W^X for JIT, and PaX mprotect exists).

**INFERRED mitigation worth costing (recommended):** under DSR the host never maps guest
pages executable (`native16k_host_prot` always strips `PROT_EXEC`), so every abort on a
guest page is a **data** abort, and a fault on a page whose current host prot is read-only
is necessarily a **write**. The WnR bit is therefore derivable from carrick's own
protection metadata with **no kernel help** — which is the ESR-free answer for this path.

### 3.5 `native_profile: None` is overloaded — a semantics decision, not a match arm

VERIFIED consumers of `native_profile.is_some()` / `native_geometry().is_some()`:

| Site | Effect of `Some` vs `None` |
|---|---|
| `dispatch/proc.rs:401-407` `select_ptrace_transport` | returns `PtraceTransport::VirtualNative` iff `native_profile.is_some()` |
| `exec_helpers.rs:514-520`, `:552-556` | drives the whole `PtraceSignalRoute` decision and `stop_after_traced_exec` |
| `dispatch/mod.rs:5609` + `dispatch/fs.rs:2425` | sets `native_guest_va` (→ `vfs/proc.rs:2390-2406` measured VmRSS) |
| `dispatch/mem.rs:1111`, `:1138`, `:3577` | **W\|X SAFETY POLICY** — `native16k_write_exec_rejection`, `native16k_exec_transition_rejection`, and mprotect partial-syscall ENOMEM reporting |
| `native_exec_capsule.rs:301-309`, `:1129` | the guest-execve re-exec capsule **bails** with "native guest exec has no native page profile" on `None` |
| `native_darwin.rs:640-644`, `707-711`, `848-851` | the three aarch64 run entries **hard-require** `native_geometry()` to be `Some` |

Two corrections to earlier framing: (i) `dispatch/proc.rs:4128-4136`, cited as "the
profile→page-size derivation a new variant must handle", is a `#[cfg(test)] mod
native_virtual_ptrace_tests` helper — the production derivation is `page_profile.rs:176-179`
(verified). (ii) The **VmRSS** consequence is a **no-op-with-fallback**: choosing `Some` on a
BSD host would not enable measured VmRSS because `carrick-host/src/host_proc.rs:1827-1831`
is a `None` stub off Darwin ("the native exec backend is macOS-only") and `vfs/proc.rs`
falls back to clamped whole-process RSS. So the substantive halves are **ptrace transport,
the W|X policy set, and the exec capsule.**

Critically: `dispatch/mem.rs:1114-1116` refuses **shared** W|X *before* the
`supports_concurrent_exec_protection()` escape at :1117 (verified by direct read) — so
"native16k shared write-exec mappings are not yet coherent across fork" is the one refusal
that is **LIVE on Darwin today and silently disappears with `None`.**

**The decision:** either (i) keep `native_profile: None` and explicitly re-gate the aarch64
native16k W|X *mechanism* and *policy* on a **host W^X predicate** (not page size, not the
profile enum), or (ii) add a **uniform-4K `NativePageProfile` variant** so the
profile-keyed policy set stays coherent — which then touches `carrick-spec/src/lib.rs:307`,
`carrick-guest-mem/src/lib.rs:181-184`, `page_profile.rs`, `dispatch/mem.rs:1111/1138/3577`,
`native_exec_capsule.rs:301-309`, and the serde wire name (`carrick-spec/src/lib.rs:1022-1031`
pins `linux4k_on16k`). **This is not a copy-paste. It is the campaign's second real design
ruling.**

### 3.6 Every place that hard-codes 16K on the aarch64 path (file:line)

| Location | What |
|---|---|
| `carrick-dsr/src/page_geometry.rs:13` | `DARWIN_NATIVE_PAGE_SIZE = 16_384` |
| `carrick-runtime/src/page_profile.rs:151`, `:159`, `:167` | `native_plan` refuses `host_page_size != DARWIN_NATIVE_PAGE_SIZE` in all three request arms |
| `carrick-runtime/src/page_profile.rs:176-179` | `Native16k → linux_page_size = host_page_size` |
| `carrick-dsr-aarch64/src/mapped_memory.rs:299` | `uses_linux4k_subpages` on the trait impl |
| `carrick-dsr-aarch64/src/mapped_memory.rs:1627` | the inherent `uses_linux4k_subpages` |
| `carrick-dsr-aarch64/src/mapped_memory.rs:1649` | `has_native16k_write_exec_pages`'s `host_page_size != 16*1024` — **the asymmetric guard of §3.4** |
| `carrick-dsr-aarch64/src/mapped_memory.rs:4782` | 16K test constant (`HOST_PAGE`) |
| `carrick-runtime/src/dispatch/proc.rs:4132` | `Native16k => 16*1024` (in a `#[cfg(test)]` helper) |
| `carrick-dsr/src/page_geometry.rs:180-188` | `UnsupportedGeometry` diagnostic text hardcodes "requires 16K host pages and 4K Linux pages" |
| `carrick-dsr/src/page_geometry.rs:33-38`, `:117-118` | `HostPageState::Uniform16k` is returned for ANY host == linux — a 4096/4096 lane will report "Uniform16k" |

Those are the **only** 16K literals in the 4,868-line `mapped_memory.rs` (`grep -c
target_os` = 0; `NativeMappingRollback::new` validates only
`host_page_size.is_power_of_two()`, :492-497), so a 4K/4K `NativeMappedMemory` is
constructible.

### 3.7 4K is not a never-run code path — but it IS a never-run end-to-end geometry

**REFUTES** the "third, never-run geometry" framing. Four in-crate unit tests already
construct 4096/4096 and drive the exclusive-monitor emulation: the shared fixture at
`mapped_memory.rs:4530-4562` sets `host_page_size: page_size, linux_page_size: page_size`
and `PageGenerationTable::new(page_size)`, called with `const PAGE: usize = 4096` by :4566,
:4628, :4693, :4742. So the exclusive monitor and `PageGenerationTable` construction ARE
covered at 4096.

**What is genuinely un-exercised at 4096:** the host-mprotect/protection surface
(`native_host_prot_for_page`, `mprotect_host_page`, `protect_range`, the
temporary-access-lift paths) and `NativeMappingRollback`'s tracking loop — and note these
unit tests run on a **16K macOS host**, so they exercise the LOGIC at 4096 but never a real
4K host mapping.

### 3.8 Two adjacent geometry facts, flagged so they are not lost

- **The shared x86 run loop hardcodes its own `const PAGE: u64 = 4096`**
  (`native_freebsd.rs:6464`) and **never reads `plan.page_geometry` at all** (grep for
  `page_geometry` and `linux_page_size` in that file returns nothing). PAGE drives
  `AT_PAGESZ` (:7090), ELF load-plan alignment (:6571-6572, :6611), vDSO rounding (:6737),
  the sigreturn-trampoline scratch page (:6817, :6828, :6833, :6858), the resident-fault
  mprotect (:9645) and DSR block boundaries (:5226, :8823). `carrick-dsr/src/identity_memory.rs:225`
  has a second `pub const PAGE: u64 = 4096`. Correct only while the host is 4K — right for
  the expected BSD aarch64 case, but the assumption rides along invisibly. A fail-closed
  `assert sysconf(_SC_PAGESIZE) == PAGE` at lane entry is the cheap answer.
- **Guest-memory model choice.** The two existing native lanes use **disjoint** models:
  aarch64/Darwin uses biased `NativeMappedMemory`/`SharedNativeMemory`
  (`carrick-dsr-aarch64::mapped_memory`; 105 refs in `native_darwin.rs`, 0 in
  `native_freebsd.rs`), x86/BSD uses `IdentityGuestMemory` (42 refs in
  `native_freebsd.rs`, 0 in `native_darwin.rs`). **Recommendation: reuse `mapped_memory`
  verbatim.** Generalizing `identity_memory` to aarch64 is explicitly discouraged by its
  own module doc (`identity_memory.rs:1-42`, `X86_64_USER_END_EXCLUSIVE = 1<<47`,
  deliberately not generic over `GuestIsa`/`NativeHost`), and page geometry is neutral
  between the models at 4K.
  **But note (REFUTES "Darwin appears only in error strings"):** `mapped_memory` carries
  Darwin **VA-hole policy**, not just portable code — `NATIVE_DARWIN_{VVAR,VDSO}_BASE`
  (:49-52), `NATIVE_DARWIN_HEAP_BASE = 0x8_0000_0000` / `_HEAP_SIZE` (:112-113),
  `NATIVE_DARWIN_MMAP_BASE = 0xa0_0000_0000` / `_MMAP_SIZE` (:114-115), consumed by the
  default layout at :119-122, plus the imported
  `NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE` (:14). And its `MAP_FIXED` policy comes from
  `carrick_dsr::address` (`address.rs:653`), whose production code encodes a macOS
  exact-mmap-hint assumption documented at `address.rs:756-761` ("require the host to honor
  an EXACT non-`MAP_FIXED` mmap hint … the FreeBSD native lane will need
  `MAP_FIXED|MAP_EXCL` probing"). It also declares its own `minherit` extern with
  Mach-named constants `VM_INHERIT_SHARE=0`/`VM_INHERIT_COPY=1` (:171-172, :4467-4480) —
  value-compatible with BSD `INHERIT_SHARE`/`COPY` but unverified on box.
  The wider address model likewise bakes Darwin VA facts as **constants, not seams**:
  `carrick-dsr/src/address.rs:22-44` `DARWIN_USER_VA_END = 0x8000_0000_0000`,
  `NATIVE_DARWIN_HARD_PAGEZERO_END = 0x1_0000_0000` (Darwin's mandatory 4 GiB
  `__PAGEZERO`), `NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE = 0x7_0000_0000`,
  `BIAS_CANDIDATES`, `BIASED_GUEST_APERTURE_END = 0x200_0000_0000`, a
  `NativeAddressError::OutsideDarwinUserRange` variant, and its own `1<<47` constant where
  `GuestIsa::USER_VA_END_EXCLUSIVE` (`1<<48` for `Aarch64Isa`) already exists as the
  intended seam. Neither BSD has a 4 GiB pagezero, so a BSD lane could map lower.

---

## 4. The FSGSBASE-analogue analysis

The NetBSD/x86 campaign's defining surprise was that NetBSD does not enable ring-3
`CR4.FSGSBASE`, so the shared x86 gateway's `rdfsbase`/`wrfsbase` SIGILLed before any guest
instruction. What is the aarch64 equivalent?

### 4.1 Guest TLS: the good news — there is NO fsbase-swap analogue

**VERIFIED, and it is the single largest simplification vs the x86 lane.** The aarch64 lane
never swaps a hardware TLS register to a guest value:

- Guest `mrs x, tpidr_el0` → `SensitiveKind::ReadTpidr` (`decode.rs:1091-1094`); guest
  `msr tpidr_el0, x` → `WriteTpidr` (:1119-1122). **Both directions trap out.**
- The run loop services them from a plain software `guest_tpidr_el0: u64`
  (`native_darwin.rs:2026-2030` declaration, :2167-2173 read, :2175-2183 write), carried
  into clone children (:2492, :3376-3421, `parent_guest_tpidr_el0` threaded through
  `native_clone_child_context` :1804-1821) and zeroed on execve (:2765).
- `CLONE_SETTLS` → TPIDR_EL0 is likewise software (`dispatch/mod.rs:1472`).
- There is **no** hardware fast path a kernel could deny: a case-insensitive grep for
  `tpidr` across `gateway_aarch64.S`, `emit.rs`, `translator.rs`, `gateway.rs`,
  `snapshot.rs` returns **ZERO** hits.

So there is nothing analogous to the fsbase-swap seam to port, no
`carrick-native-netbsd/src/fsbase.rs` twin needed, and a `_Thread_local` active-context
pointer is legitimate in the aarch64 signal handler (exactly what the Darwin shim does,
`csrc/native_darwin.c:198-204`). Contrast the x86 lane's explicit "guest fs base is live,
host TLS is poison" (`carrick-native-freebsd/src/fault.rs:14-22`).

**Two caveats, both important:**

1. **Darwin DOES read-modify-write the HOST's TPIDR_EL0 on the hottest path** — just not
   for guest TLS. `csrc/native_darwin.c:271-279` (`carrick_native_set_custom_x18`: read
   `TPIDR_EL0`, mask with `0xfffffffffff00000`, set/clear bit 48, write back **through the
   dlsym'd private `update_tpidr`**) runs inside `carrick_native_dsr_enter_guest_abi`
   (:295-325) and `..._enter_host_abi` (:331-338), which the gateway `bl`s at
   `gateway_aarch64.S:39`, `:131`, `:194`. That is a **private-symbol availability**
   dependency in the same hot path — different in kind from x86's permission-denial risk,
   but a host-ABI dependency nonetheless. On BSD it should simply not exist.
2. **`TPIDRRO_EL0` is not decoded at all** (`decode.rs:1117` `_ => InstAction::Unsupported`),
   so any aarch64 guest touching the read-only thread pointer fails on **all** hosts
   including Darwin today. Pre-existing gap; flagged so the campaign is not blamed for it.

### 4.2 The actual FSGSBASE-class risk #1: **ESR_EL1 does not exist on either BSD**

**VERIFIED from source, with the mitigation and the residual risk both sharpened.**

`NativeUcontextSnapshot` carries `esr` and `far` (`carrick-dsr-aarch64/src/snapshot.rs:26-27`),
populated by the Darwin shim from `uc->uc_mcontext->__es.__esr` / `__far`
(`csrc/native_darwin.c:371-378`, `534-541`) — an **Apple extension**. Neither BSD's aarch64
mcontext exposes it:

- FreeBSD: `gpregs { gp_x[30], gp_lr, gp_sp, gp_elr, gp_spsr: u32, gp_pad }` +
  `mcontext_t { mc_gpregs, mc_fpregs, mc_flags, mc_pad, mc_spare[8] }` — no ESR, no FAR
  (`libc-0.2.186/src/unix/bsd/freebsdlike/freebsd/aarch64.rs:10-33`).
- NetBSD: `mcontext_t { __gregs: [greg_t; 32], __fregs, __spare[8] }` with
  `_REG_X0..X31`, `_REG_ELR = 32`, `_REG_SPSR = 33`, `_REG_TIPDR = 34` and **no `_REG_ESR`**
  (`netbsdlike/netbsd/aarch64.rs:14-18`, `96-132`). Contrast NetBSD/x86_64, which DOES have
  `_REG_TRAPNO`/`_REG_ERR`.

**ESR is load-bearing in THREE production paths, not one** (this REFUTES the
"debug-only helper" reading):

| Path | Site | Without ESR |
|---|---|---|
| Fault lowering (the whole Linux triple) | `native_darwin.rs:3044-3050` → `vcpu_loop/signal.rs:157-163` `lower_el0_fault(esr, pc, addr)` → `el0_fault_signal(esr)` (`signal.rs:86-110`, `ec = (esr>>26)&0x3f`, `_ => None`) | `esr = 0` ⇒ `ec = 0` ⇒ `None` ⇒ **`native_die_by_signal(SIGSEGV)`**. `lower_el0_fault` also CHOOSES `elr`-vs-`far` as `si_addr` on the ESR class (pinned by `vcpu_loop/mod.rs:2782-2819`: EC 0x3c → SIGTRAP/TRAP_BRKPT/elr; EC 0x24 → SIGSEGV/SEGV_MAPERR/far; EC 0x24 + DFSC 0x21 → SIGBUS/BUS_ADRALN) |
| Debug traps | `carrick-dsr-aarch64/src/translator.rs:2389` `el0_debug_signal(snapshot.esr)` → `esr.rs:13-27` | The ONLY producer of the ESR-free `ThreadFault::Guest` on the real signal path — so **the BRK / single-step / HW-watchpoint SIGTRAP path (ptrace, Go `TestDebugCall`) dies too** |
| Self-modifying code / JIT guests | `native_darwin.rs:3020-3030` → `mapped_memory.rs:1751-1800` `resolve_native16k_write_exec_fault(addr, pc, esr)` decodes EC (0x20/0x21 instruction abort vs 0x24/0x25 data abort), DFSC (`0x0c..=0x0f` permission fault) **and ESR bit 6 = WnR** (:1781) | POSIX siginfo carries **no write-vs-read bit**. And per §3.4 this path is **MORE reachable at 4K, not less** |

**The mitigation is better-supported than first argued, in two ways:**

1. **The neutral pair is ALREADY plumbed.** The aarch64 exit type already carries the host
   siginfo pair: `NativeDsrExit::Fault { signal, code, .. }` → `ThreadFault::Host { signal,
   code }` (`translator.rs:2341`, `:2404`, `:2412`), and the snapshot already carries
   neutral `signal`/`signal_code` fields (`snapshot.rs:22-27`, mirrored with
   `_Static_assert`s in `csrc/native_darwin.c:23-40`). `native_darwin.rs:3044-3050`
   **DISCARDS** that payload in favour of `lower_el0_fault(snapshot.esr, …)`, while
   :3044-3045's `ThreadFault::Guest { signum, code }` arm already consumes an ESR-free
   pair. **So the ESR-free lowering is a decision change at exactly two sites**
   (`translator.rs:2388-2416` and `native_darwin.rs:3044-3053`) — **no ABI change**. Note
   ESR cannot be smuggled through the shared `carrick_dsr::fault::FaultRecord` (no `esr`
   field, `size == 24` asserted, `fault.rs:20-53`) — it must ride the aarch64 snapshot.
2. **WnR is derivable from carrick's own metadata.** See §3.4: the host never maps guest
   pages executable, so every guest-page abort is a data abort, and a fault on a page whose
   current host prot is read-only is necessarily a write.

**Residual wrinkles (be honest about these):**

- `el0_debug_signal` is consumed **INSIDE** the supposedly-verbatim arch crate on the raw
  ESR (`translator.rs:2389`), so the BSD shim must either **synthesize a plausible ESR
  word** (ec = 0x3c etc.) or `carrick-dsr-aarch64` needs a new input. Cheap, but it is a
  change inside the crate the thesis wanted untouched.
- Whether FreeBSD/NetBSD actually deliver `TRAP_BRKPT` for `BRK #0`, `BUS_ADRALN` for
  misalignment, and a distinguishable instruction-fetch abort is **NEEDS-ON-BOX**.
- The real BSD siginfo extras (`si_trapno` on FreeBSD, `si_trap`/`si_trap2`/`si_trap3` on
  NetBSD) are not exposed by libc — reinforcing §2.1's "write the shim in C against real
  headers" conclusion. **A discoverable ESR-equivalent in a spare mcontext slot, siginfo
  extra, or ptrace is the ONE probe that could collapse this whole workstream back to
  size-S.**

### 4.3 The actual FSGSBASE-class risk #2: physical **x18**

**Corrected picture (an earlier scout claim was REFUTED here — read carefully).**

**What is true (VERIFIED):**
- Physical **x28** is a permanently reserved context pointer
  (`gateway_aarch64.S:21-22` "Physical x28 is the translated-thread context pointer.
  Guest x18 and guest x28 stay virtualized in snapshot.x[] throughout translation.").
- Guest x18 AND x28 are virtualized into spill slots
  (`carrick-dsr-aarch64/src/block.rs:512-518` says it verbatim: "native16k keeps the guest's
  x18/x28 in a spill slot (physical x18/x28 are carrick's own reserved registers)";
  :499-503 rejects `MemoryBase::VirtualX18|VirtualX28`; :74-80 defines
  `InstAction::VirtualizedX18/VirtualizedX28`; helper at `decode.rs:780-786`).
- Physical **x18** IS emitted, but in a **narrow, recovery-covered scratch window**:
  `emit.rs:805-816` (`ldr x18,[x28,#off]` / `str x18,[x28,#1080]`) — reached **only** when
  the guest's indirect-branch target register is x18 or x28 (`virtual_snapshot_offset`,
  `emit.rs:385-391` returns `Some` only for 18/28). It is also used in the biased-memory
  hot path (`emit.rs:2035`, `:2226` `lsr x18, effective, #BIASED_FAST_ADDRESS_BITS`) and at
  `:3706`, each carrying a `RecoveryAction` (`emit.rs:2020-2075`
  `emit_with_biased_recovery`; `translator.rs:2380-2388` `recover_rewrite_state`).
  Every other site deliberately keeps x18 empty (`emit.rs:818-826`, `:914-921`, `:939-946`).
- Darwin needs a **kernel opt-in** to make x18 usable at all: `dlsym` of three
  Apple-private symbols (`csrc/native_darwin.c:236-238`) and a `TPIDR_EL0` bit-48 toggle at
  every crossing. **Only ONE of the three is ever invoked** — `update_tpidr` (:271-278);
  the other two are presence checks (:239-242).

**REFUTED: "if a BSD kernel clobbers x18 across sigreturn, the lanes need a translator
register reassignment."** carrick **already** runs on a host that does not reliably
preserve physical x18 across asynchronous signals, and is structured to tolerate exactly
that: `emit.rs:818-821` ("Darwin does not reliably restore custom x18 across asynchronous
signals") and `csrc/native_darwin.c:464` ("Darwin's signal return does not reliably preserve
custom x18") are the **design premise**, not a bug. The guest's x18/x28 live in snapshot
spill slots; the signal snapshotter **refuses** to read mcontext x18/x28
(`csrc/native_darwin.c:361-364`, `if (!preserve_virtual_registers || (i != 18 && i != 28))`);
every physical-x18 window carries a `RecoveryAction`. A BSD kernel that clobbers x18 across
sigreturn lands carrick in an **already-supported configuration**.

**Also REFUTED: the direction of the fallback.** "Stop reserving physical x18" means letting
GUEST x18 live in the physical register — strictly **MORE** exposure to a clobbering
kernel. The correct fix in that branch is the **opposite and much smaller**: delete the
`emit.rs:805-816` scratch window and always take the `emit.rs:818-826` `else` shape (store
the guest register straight into the context), plus drop the `exit_link` recovery. A
localized emitter change, **not** a translator redesign. Conversely, if the BSDs do NOT
claim x18, un-virtualizing guest x18 is an **optional optimization**, not required work.

**What the residual risk actually is (CANNOT-CONFIRM from the repo — NEEDS-ON-BOX):**
whether **host userland** (FreeBSD `rtld`/`libthr`, NetBSD `ld.elf_so`/`libpthread`) keeps
live state in x18 across a call. And the risk is **asymmetric in the direction that is
uncomfortable**: Darwin has a kernel opt-in that makes x18 usable; **neither BSD has any
such opt-in**, so if x18 IS claimed on a BSD there is no host-glue remedy — it goes
straight to the emitter change above. "Strictly simpler than Darwin" is the unhedged best
case, not the expected value.

**Scope note on the collapse:** "~20 LoC no-op" covers the x18 part alone. The two ABI-switch
functions also carry active-context set/clear, deferred-kick drain with a synthetic
`exit_status = 8`, a phase-zero test hook, and the kick-signal unblock/block
(`csrc/native_darwin.c:295-338`, `583-607`, ~45 lines) — all of which must be reimplemented
per host **regardless** of the x18 answer.

### 4.4 The NEW risk nobody had on a list: the gateway does not save/restore **host** x18

**VERIFIED by direct read.** `_carrick_dsr_enter_raw` saves host `sp`, `x19-x30` and
`q8-q15` (`gateway_aarch64.S:22-35`) and `carrick_dsr_restore_host` restores the same set
(:142-184). **x18 is absent from both sets** — `grep -n 'x18\|w18' gateway_aarch64.S`
yields exactly two hits (lines 21 and 84), **both comments**. Meanwhile translated code
writes physical x18 (`emit.rs:2035`, `:2226`).

**Consequence for the campaign inventory:** a BSD-aarch64 lane must either **prove host
userland treats x18 as caller-clobbered scratch**, or **ADD x18 to the gateway's host
save/restore set**. That is gateway-assembly work **additive** to the already-planned
Mach-O→ELF port, and it appears on neither the 7-weld nor the 16-lane-dispatchable list. On
Darwin the omission is safe only because the non-custom ABI treats x18 as kernel-reserved.

### 4.5 EL0 system-register accessibility — the third candidate

`CNTVCT_EL0`/`CNTFRQ_EL0` are architecturally EL0-readable but gated by
`CNTKCTL_EL1.EL0VCTEN`/`EL0PCTEN`, and `dc cvau`/`ic ivau` by `SCTLR_EL1.UCI` — both
**kernel policy**. The aarch64 lane emits a **direct** `mrs CNTVCT_EL0` for guest counter
reads (`decode.rs:1103-1106` → `CounterRead`) and passes `mrs CNTFRQ_EL0` straight through
(:1107-1111). The run loop's `SensitiveKind::ReadCounter` arm is `#[cfg(target_os="macos")]`
with a non-macOS arm returning `Unsupported("native DSR counter fallback requires macOS")`
(`native_darwin.rs:2184-2202`). If either BSD traps these at EL0, that is an FSGSBASE-shaped
SIGILL before any guest instruction — hence probe group **P4** in §6.

---

## 5. Gate path

### 5.1 Where the ladder stands (VERIFIED)

`scripts/bsdvm.py:83-105`:

| Stage | Command | report_only | available |
|---|---|---|---|
| stage0 | `cargo test -p carrick-portable -p carrick-hal -p carrick-host -p carrick-mem` | False | **True** |
| stage1 | `cargo build --workspace` | True ("red list IS the bring-up worklist") | **True** |
| stage2 | `cmds=[]` | True | **False** — note "requires NativeLane aarch64 host lanes (seam extraction)" |
| stage3 | `cmds=[]` | True | **False** — note "requires stage2 + LTP gate tooling (native-x86-ltp-gate lineage)" |

`run_gate` raises `SystemExit` for any unavailable stage at :1026-1027 — **before** the
golden-image check (:1028) and the `out_dir` creation (:1033-1034).

**Correction to the brief's framing:** the stage2 note is **still accurate**, not stale.
Its stated requirement is "NativeLane aarch64 host lanes", and those still do not exist —
`crates/carrick-runtime/src/native/mod.rs:87-135` wires only `DarwinAarch64Lane`,
`FreebsdX8664Lane`, `NetbsdX8664Lane`, and the no-lane error at :143-147 enumerates exactly
those three (verified by direct read). Only the note's **parenthetical mechanism** ("seam
extraction") has been delivered.

**Flipping stage2 on requires editing exactly three assertions** in
`scripts/test_bsdvm.py`: `test_stage_table_matches_spec_ladder` asserts
`assertFalse(STAGES["stage2"].available)` (:1214) and `assertIn("NativeLane",
STAGES["stage2"].note)` (:1215); `test_unavailable_stage_is_a_clear_error` (:1218-1222)
builds a stage2 mock, asserts `SystemExit`, and asserts `"NativeLane" in
str(ctx.exception)`. Re-pointing the second at stage3 also forces changing its assertion
string — stage3's note contains no "NativeLane" (it reads "requires stage2 + LTP gate
tooling (native-x86-ltp-gate lineage)").

### 5.2 What stage2 should run

**Test shape (the NetBSD/x86 precedent), VERIFIED:**
`crates/carrick-runtime/tests/native_netbsd_x86.rs` is **155 lines**:
`#![cfg(all(target_os = "netbsd", target_arch = "x86_64"))]` at :39, a `fixture()` helper
joining `env!("CARGO_MANIFEST_DIR")` with `"../carrick-dsr-x86/tests/fixtures"` at :41-45,
and **four** escalating `#[test]`s at :51, :72, :92, :129 asserting the same `RunResult`
contract (exit_code / stdout / `traps == 1`). Documented invocation at :36-38. (The
incumbent `native_freebsd_x86.rs` is 1,058 lines with its own gate at :14 — that split is
historical, not principled.)

**Recommended stage2 command:**

```
cd /root/carrick && cargo test -p carrick-runtime \
  --no-default-features --features platform-<freebsd|netbsd>-arm64 \
  --test native_bsd_arm64 -- --test-threads=1
```

with **ONE shared test file** `crates/carrick-runtime/tests/native_bsd_arm64.rs` gated
`#![cfg(all(any(target_os = "freebsd", target_os = "netbsd"), target_arch = "aarch64"))]`
— the two lanes arrive simultaneously, so a single file is the better first landing.

**Three hard constraints on that command:**

1. **It must `test`/`build`, never `check`.** `carrick-vmm-nvmm` compiles clean on aarch64
   and only the `-lnvmm` **link** fails, so `cargo check --features platform-netbsd` would
   PASS and hide the break.
2. **The feature name is probably new.** See §5.4 — neither existing platform feature works
   on aarch64. Whether `dep:carrick-vmm-nvmm` may sit in a `[features]` entry when the dep
   is declared only under an arch-scoped `[target.'cfg(…)'.dependencies]` table is an
   **open cargo question**; if it does not work, new arch-scoped feature names are required
   and every consumer (`carrick-cli/Cargo.toml:23-26`, `justfile:11-15`, the cross-check
   recipes) must learn them.
3. **Spell the command literally in `bsdvm.py`'s STAGES.** `justfile:11-16`'s
   `_platform_features` selects by `os()` **only**, with no `arch()` dimension — on an
   aarch64 BSD guest every consumer (`justfile:30-31` `_platform_crates`, `:124-125`
   `test`, `:140-141` `doc`) selects a feature set that cannot compile. `bsdvm.py`'s STAGES
   already hold literal cargo strings (:86-93).

**Also required before any ELF can run:** the `page_profile` capability-table arm.
`run_static_native` → `native_darwin::run_static_elf` needs a resolved `ExecutionPlan` with
native page geometry and errors out at `native_darwin.rs:642` and `:709` without one. **The
acceptance task depends on §3.5's decision, not just on the seam.**

**Correction to an earlier claim about entry points:** `runtime::run_static_elf` does not
exist — `run_static_elf` is `pub(crate)` in `native_darwin.rs:626`. The public platform-macos
entry is `runtime::run_static_elf_with_backend_args_and_dispatcher_debug`
(`runtime.rs:268`) which resolves a plan then calls `crate::native::run_static_native`
(:296-299). And `crate::native::run_static_native` / `run_oci_native` are **NOT
feature-gated** — only `#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]`
(`native/mod.rs:154`, :216) — and both already end in an `#[allow(unreachable_code)]` arm
returning `no_native_lane_wired()` (:136-149, :250-265). **So on a VMM-less BSD/aarch64
build those dispatch fns already compile and fail at runtime with a typed message; the lane
work is one new cfg arm in each of three dispatch fns plus a
`Freebsd/NetbsdAarch64Lane` type and a `HostNativeLane` alias arm — not inventing an entry
point.**

### 5.3 Fixtures — an aarch64 acceptance ELF ALREADY EXISTS (REFUTES the earlier claim)

`git ls-files | xargs file | grep 'ELF.*aarch64'` returns **8 git-tracked, statically-linked
aarch64 Linux ELFs** (verified by direct run):

```
crates/carrick-vmm-kvm/fixtures/hello-aarch64/hello-aarch64
crates/carrick-vmm-kvm/fixtures/hello-stack-aarch64/hello-stack-aarch64
crates/carrick-vmm-kvm/fixtures/exec-target-exit0/exec-target-exit0
crates/carrick-vmm-kvm/fixtures/exec-target-exit1/exec-target-exit1
crates/carrick-vmm-kvm/fixtures/fork-wait4/fork-wait4
crates/carrick-vmm-kvm/fixtures/fork-execve-true/fork-execve-true
crates/carrick-vmm-kvm/fixtures/fork-execve-false/fork-execve-false
crates/carrick-vmm-kvm/fixtures/pipe-fork/pipe-fork
```

They are genuine Linux-ABI guests (`hello-aarch64/hello.S:1-18` = `mov x8,#64; svc #0`
(`__NR_write`) then `mov x8,#94; svc #0` (`__NR_exit_group`)), each with `build.sh` +
`README.md` + `oracle.expected` — i.e. **the "commit prebuilt, keep the recipe" discipline
already exists for aarch64**, and they travel over the existing `git push HEAD` transport
(`bsdvm.py:880-955`; no scp/rsync anywhere in the file).

**What IS missing (2–3 of 4 rungs):** the x86 ladder is tinyguest (no_std static-PIE,
write+exit_group=21) → identity-loop (1000 getpid + 1000 gettid, `traps == 1`) →
computeloop (50M-iteration pure loop, `traps == 1`, exit 192) → hello-std (real std Rust,
exit 129), all tracked with SHA-256 digest discipline
(`carrick-dsr-x86/tests/fixtures/README.md:3-33`, :97/131/144/172/214/282). On the aarch64
side there is **no chaining/`traps == 1` fixture and no std-Rust fixture**:
`scripts/build-linux-fixtures.sh:84-144` lists ~55 aarch64 fixtures and every one is
freestanding (`build_fixture` :27-51 links `--entry=_start -C panic=abort --gc-sections`,
no CRT, no std). `crates/carrick-dsr-aarch64/` has **no `tests/` directory at all**.

**Two residual risks:**
- All 8 tracked aarch64 ELFs are **ET_EXEC fixed-load** (`file` says "executable", not "pie
  executable") whereas the x86 rung-1 fixture is **static-PIE**. Whether the aarch64 DSR
  native loader accepts ET_EXEC at its fixed vaddr on a BSD host is an **unraised
  NEEDS-ON-BOX question** (probe P12).
- Building fixtures on the guests is **impossible**: `scripts/build-linux-fixtures.sh:11-14`
  exits 2 without the rustup `aarch64-unknown-linux-musl` target and :17-20 exits 2 without
  `$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld`; both guests run non-rustup
  pkg/pkgsrc rust ("(built from a source tarball)" in both gate reports). Cross-build on the
  Mac and commit.

### 5.4 The four blockers between here and a stage2 command

**These are NOT seam work.** All VERIFIED from source.

**B1 — `carrick-runtime` cannot compile on either aarch64 BSD, with ANY feature set.**
Both host crates are `#![cfg(target_os = …)]`-only and are **unconditional** target-deps of
`carrick-runtime` (`Cargo.toml:133-134` freebsd, `:138-139` netbsd — `target_os` only, no
arch predicate; contrast `:149` which DOES use `all(macos, aarch64)`). The x86-welded
surface spans **4 modules across 2 crates**, not 2 files:

| Crate | File | Break |
|---|---|---|
| carrick-native-freebsd | `tsc.rs:87`, `:89` | `std::arch::x86_64::_rdtsc`, wired **unconditionally** at `lib.rs:76-78` |
| carrick-native-freebsd | `fault.rs:167,177,180-182,188,209,216,225` | `mc_rip`/`mc_r15`/`mc_rcx` — libc defines these only in `freebsdlike/freebsd/x86_64/mod.rs:108`; FreeBSD/aarch64's `mcontext_t` is `mc_gpregs: gpregs` |
| carrick-native-netbsd | `fsbase.rs:61-107` | `core::arch::naked_asm!` + `asm!` with x86 registers |
| carrick-native-netbsd | `fault.rs:55-59`, `:197`, `:237`, `:317-319` | `libc::_REG_RIP/_REG_RSP/_REG_R15/_REG_RCX` — defined only in `netbsdlike/netbsd/x86_64.rs:55` |

Plus: `carrick-runtime`'s `default = ["platform-macos"]` (`Cargo.toml:30`) means stage1's
`cargo build --workspace` additionally drags `carrick-vmm-hvf` (which has **no
crate-level `#![cfg]` at all**) on an aarch64 BSD — which is why `justfile:122-125` never
uses `--workspace` off-macOS. The in-tree fix pattern exists:
`carrick-native-darwin/src/lib.rs:21` is `#![cfg(target_os = "macos")]` **plus** an inner
`#[cfg(target_arch = "aarch64")]` real/stub split at :25.

**B2 — `--features platform-freebsd` is a COMPILE break on FreeBSD/aarch64.**
`Cargo.toml:69` = `["dep:carrick-vmm-bhyve", "dep:carrick-host-bsd"]`, and `lib.rs:398-399`
does `#[cfg(feature = "platform-freebsd")] pub use carrick_vmm_bhyve::make_bhyve_futex as
hvf_futex;` — but `make_bhyve_futex` is `#[cfg(target_arch = "x86_64")]`
(`carrick-vmm-bhyve/src/lib.rs:35-38`) ⇒ E0432. **And it is worse than one symbol:** at
least **seven more** feature-only-gated (no arch predicate) references to x86_64-only bhyve
items compile in under the same feature — `lib.rs:771` `make_bhyve_futex` inside
`BhyveHostBackend`, `:775` `BhyveForkCoordinator`, `:779` `BhyveKicker`, `:787`
`BhyveTimerDelivery`, `:867-868` `BhyveKickHandle`, `:900` `run_elf::run_elf_bhyve`, `:911`
`build_x86_engine_shared`, `:2080` `ActiveGlue = carrick_vmm_bhyve::BhyveGlue`. (`lib.rs:1624`
`run_oci` IS arch-gated — proof the predicate was applied unevenly.) **It is also a link
edge:** `carrick-vmm-bhyve/src/lib.rs:21` `pub mod vmm;` is NOT arch-gated and
`src/vmm.rs:114` carries `#[link(name = "vmmapi")]`.

**B3 — `--features platform-netbsd` is a LINK break on NetBSD/aarch64.**
`Cargo.toml:70` = `["dep:carrick-vmm-nvmm", "dep:carrick-host-bsd"]`;
`carrick-vmm-nvmm/src/lib.rs:22` is `#![cfg(target_os = "netbsd")]` with **no arch gating of
any module** (`grep target_arch` over the crate hits only `src/main.rs:8`, `:32`) and
`src/nvmm.rs:330` carries `#[link(name = "nvmm")]`. NVMM is an x86-only NetBSD subsystem.
Its dep `carrick-x86` is fully portable, so nothing fails to *compile* — the failure is
purely the `-lnvmm` edge (physical absence of `/usr/lib/libnvmm.so` on arm64 =
NEEDS-ON-BOX).

⇒ **A VMM-less BSD feature pair is required**, plus the futex re-homing. That re-homing is
**cheap** because the real syscall shims already live in the portable host crate:
`carrick-host/src/lib.rs:62-72` lists `netbsd_futex`, `umtx`, `ulock`;
`carrick-vmm-nvmm/src/nvmm_futex.rs` is **52 lines** whose bodies are just
`carrick_host::netbsd_futex::wait/wake` wrapped in
`carrick_thread::platform_futex::classify_observed_wait_slice` (and that module has no
`target_arch` at all). **The arch-gating pass therefore spans FOUR crates:**
carrick-native-freebsd, carrick-native-netbsd, carrick-vmm-bhyve, carrick-vmm-nvmm.

**B4 — the two observed stage1 red-list items.** Recovered from the real gate reports under
`~/.carrick/bsdvm/results` (both at head `4405a25b`/`59ba720b`, **not** current main — real
evidence, not re-measured at HEAD):

| Box | Failure | On the critical path to an acceptance ELF? |
|---|---|---|
| freebsd-arm64 stage1 (rc=101, 91.8s, rustc 1.96.1) | `usdt-impl 0.6.0` **E0308**: `no-linker.rs:166 modname[i] = byte as i8;` infers `[i8; 64]` while `fn ioctl_section(buf: &[u8], modname: [std::os::raw::c_char; 64])` at :171 expects `[u8; 64]` — **`c_char` is unsigned on aarch64**. Blocks `usdt-impl` → `carrick-observability` (`Cargo.toml:27-36`) → `carrick-runtime` (`:125`) + `carrick-vmm-hvf` (`:44`) | **YES.** `cargo test -p carrick-runtime` cannot build. **Not avoidable by features** — carrick-observability's own comment says target-gating `usdt` would break `probes::stub::register_dtrace_probes`, whose signature returns `usdt::Error`. Fix = `[patch.crates-io]` a fixed usdt-impl, bump if upstream fixed >0.6.0 (**unchecked — worth 5 minutes on crates.io**), or own the error type + target-gate the dep. NetBSD is unaffected (usdt compiles to a pure-Rust no-op there) |
| netbsd-arm64 stage1 (rc=101, 126.5s, rustc 1.91.1) | `bad64-sys`'s C lib `libarm64decode` **built fine** (every `exit status: 0`, `cargo:rustc-link-lib=static=arm64decode` emitted), then **bindgen-0.72.1 panicked**: "Unable to find libclang: couldn't find any valid shared libraries matching `['libclang.so','libclang.so.*']`". Chain: `bad64` → `bad64-sys` → bindgen (build-dep). `bad64` is an **unconditional** dep of `carrick-dsr-aarch64` (`Cargo.toml:29-34`, comment "bad64/dynasmrt are UNCONDITIONAL"), which is an **unconditional** dep of `carrick-runtime` (`:84-88`) | **YES — this blocks THE AARCH64 TRANSLATE ENGINE ITSELF.** Fix is **PROVISIONING, NOT CODE**: pkgsrc `clang` (libclang.so) or `LIBCLANG_PATH`, added to `bsdvm.py:603`'s `pkg_add` step + a refresh-golden. There is **no escape hatch in the crate**: the vendored `bad64-sys-0.10.0/build.rs` calls `bindgen::Builder::default()…generate().expect(…)` unconditionally, with no pregenerated-bindings feature and no cfg guard |

**Predicted B4c (NEEDS-ON-BOX):** the freebsd-arm64 build died at `usdt-impl` having
compiled only ~76 crates — `carrick-native-freebsd`, `carrick-dsr-aarch64` and `bad64-sys`
**never appear in the log**. So expect a **second** bindgen/libclang failure on
freebsd-arm64 immediately after the usdt fix (FreeBSD base ships clang binaries but the
shared libclang generally comes from the llvm port; the x86 FreeBSD box needed
`pkg install llvm19` for lldb). `bsdvm.py:544` is verbatim
`("env ASSUME_ALWAYS_YES=yes pkg install -y git just rust python3", 3600)` — no llvm.
**Add llvm pre-emptively; it is low-cost insurance.** The same caveat applies to B1: those
blockers are read from source and have **never been observed failing**, because stage1
stops earlier.

**stage0 is green on both and stays green:** `cargo test -p carrick-portable -p carrick-hal
-p carrick-host -p carrick-mem` avoids both blockers (none of those four crates depends on
`usdt` or `bad64`). freebsd-arm64 PASS with rustc 1.96.1; netbsd-arm64 PASS with rustc
1.91.1. (Minor: the two PASSes are at *different* heads — `59ba720b` and `4405a25b` — so
"both green at the same commit" was never actually measured.)

### 5.5 Gate mechanics that constrain what stage2 may be (VERIFIED)

- Per-step ssh timeout is **7200 s** (`bsdvm.py:1066`); a timed-out step marks all
  remaining steps `<skipped: prior step timed out>` (:1078-1081).
- The captured tail is truncated to the **last 4000 chars** (:1073, :1083) and `report.txt`
  renders only the **last 10 lines** per step (:978). **A long stage2 failure list WILL be
  clipped** — prefer a stage2 command that writes a JSON artifact and `cat`s it (the stage3
  lineage already does this).
- Guests are `-smp 4 -m 6144` (:150-151). stage1's partial builds reached their failures in
  **92–127 s**, so a cold full `cargo test -p carrick-runtime` build+link is **genuinely
  unmeasured** against the 7200 s budget.
- `just bsdvm-acceptance` (`justfile:379-380`) runs **only** stage0+stage1 for both VMs;
  stage2 must be appended. `cmd_ladder` separates `steps_ok` (the report's own `pass`) from
  `exit_ok` (`rc`, which folds in report-only) at :1226-1227 and prints
  `"PASS" if exit_ok` at :1240/:1245-1249 — **so a red report-only stage2 prints PASS.**
  If report-only is chosen, the acceptance summary must quote `steps_ok` explicitly.
- **Toolchain skew is real but not a blocker.** `rust-toolchain.toml:9-11` pins 1.96.0 and
  :20 declares no `aarch64-unknown-{freebsd,netbsd}` triple (Tier 3, no rustup host build).
  Guests: freebsd-arm64 **1.96.1**, netbsd-arm64 **1.91.1** — five minor versions behind,
  so **netbsd-arm64 is the tightest MSRV in the fleet**; any post-1.91 language/std feature
  fails there ONLY. Corollary: **gates must not run `fmt`/`fmt-check` on the guests**
  (rustfmt 1.91 vs pinned 1.96 = exactly the skew `rust-toolchain.toml` exists to prevent).

### 5.6 stage3 is further away than stage2, for two independent reasons

1. The runner it drives, `crates/carrick-runtime/examples/native_run.rs`, is
   `#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]` at :5 and prints
   "native_run is FreeBSD/amd64 only" otherwise (:55-56) — **it was never even re-gated for
   the NetBSD x86 lane**, so every new lane inherits that work.
2. The gate is welded to an x86 fixture: `scripts/native-x86-ltp-gate.py:27`
   `FIXTURE = "ltp-20260529-x86_64-musl-static-pie"`; :211-216 `--runner` defaults to
   `target/debug/examples/native_run`; :217-218 `--ltp-bin-root` and `--rootfs` are both
   `required=True`; :251-262 the rootfs must contain `bin/sh` **and** `bin/zcat` or the
   script returns 2. **No aarch64-musl static LTP fixture exists in-tree**, and the
   conformance oracle is keyed per-arch.

---

## 6. THE ON-BOX PROBE PLAN

Ordered by **value × unblocking power**. Run on **both** `freebsd-arm64` (127.0.0.1:2201)
and `netbsd-arm64` (127.0.0.1:2202) unless a probe is marked per-OS. Every probe names the
exact command/header and the decision it settles. **P0 first — it unblocks everything
else.**

### P0 — Provisioning / build unblock (run FIRST; ~30 min)

| # | Command | Settles |
|---|---|---|
| P0.1 | **netbsd**: `pkg_add -U clang; ls -l /usr/pkg/lib/libclang.so*` then `LIBCLANG_PATH=/usr/pkg/lib cargo build -p carrick-dsr-aarch64` | **The single highest-value probe.** Does the aarch64 translate engine build at all? (`bad64-sys` bindgen needs libclang; there is no pregenerated-bindings escape hatch.) |
| P0.2 | **freebsd**: `ls -l /usr/lib/libclang.so* /usr/local/llvm*/lib/libclang.so* 2>/dev/null; pkg install -y llvm19; ls -l /usr/local/llvm19/lib/libclang.so*` then `cargo build -p carrick-dsr-aarch64` | Does FreeBSD/aarch64 have the same bindgen blocker hiding behind the usdt failure? (Predicted B4c.) |
| P0.3 | Both: `cargo --version; rustc --version; rustc -vV` | Re-confirm the 1.96.1 / 1.91.1 skew before choosing any post-1.91 language feature |
| P0.4 | Both: `cargo build -p carrick-portable -p carrick-hal -p carrick-host -p carrick-mem -p carrick-dsr -p carrick-dsr-aarch64` then `cargo test -p carrick-dsr-aarch64` | The direct analogue of the NetBSD/x86 scout's "shared crates build clean together" probe — settles whether `carrick-dsr-aarch64` **minus its gateway** really is host-agnostic. Report every failure. |
| P0.5 | Both: `cargo build --workspace` (expect red), then `cargo build -p carrick-runtime --no-default-features --features platform-<freebsd\|netbsd>` | The FULL red list = the arch-gating worklist. Confirm the two predicted breaks: (a) `threaded_impl::hvf_futex` unresolved on FreeBSD/aarch64 (`make_bhyve_futex` is `cfg(target_arch="x86_64")`); (b) carrick-vmm-nvmm's entire x86 surface + `-lnvmm` on NetBSD/aarch64 |
| P0.6 | **netbsd**: `ls -l /usr/lib/libnvmm.so* /usr/lib/libnvmm.a 2>/dev/null; echo rc=$?` · **freebsd**: `ls -l /usr/lib/libvmmapi.so*` | Is `platform-<os>` merely undesirable on arm64, or hard-impossible? (expected: both absent) |
| P0.7 | Both: `time cargo build -p carrick-runtime --no-default-features --features <new-feature> --tests` on a **cold** target dir | Sizes real stage2 wall time against `bsdvm.py`'s 7200 s per-step budget (genuinely unmeasured — stage1 only reached its failure in 92–127 s) |
| P0.8 | **netbsd**: `ls $(rustc --print sysroot)/lib/rustlib/` and `ls $(rustc --print sysroot)/lib/rustlib/*/bin/` | Closes off "build the guest fixtures on the box" for good (expect: no `aarch64-unknown-linux-musl` std, no `rust-lld`) |

### P1 — PAGE GEOMETRY (one command; gates §3 entirely)

| # | Command | Settles |
|---|---|---|
| P1.1 | Both: `getconf PAGESIZE`; `sysctl hw.pagesize`; `sysctl hw.pagesizes` (FreeBSD superpage list); `sysctl -n hw.machine hw.machine_arch` | **Every "4K" estimate in this document is conditional on this.** 4096 ⇒ Scenario A; 16384 ⇒ Scenario B (Darwin's own geometry, already exercised end-to-end); 65536 ⇒ Scenario C (new profile) |
| P1.2 | Both: a 5-line program printing `sysconf(_SC_PAGESIZE)` | This is literally what `page_profile.rs:225-234` reads and what `prepared_image.rs:769-779` fail-closed compares against. Must agree with P1.1 |
| P1.3 | Both: map 3 pages, `mprotect` the middle one, dump the map (`procstat -v $$` FreeBSD, `pmap -x $$` NetBSD) | Confirms 4096 is the real VM **granule**, not just the reported constant — three distinct 4096-byte regions, not one coalesced 16K region |

### P2 — MCONTEXT GROUND TRUTH (gates the fault-shim route; §2.1)

| # | Command | Settles |
|---|---|---|
| P2.1 | **freebsd**: dump `/usr/include/machine/{ucontext.h,mcontext.h,frame.h,reg.h}`. Record: `sizeof(mcontext_t)`, `sizeof(ucontext_t)`, `offsetof(ucontext_t, uc_mcontext)`, `offsetof(mcontext_t, mc_gpregs.gp_elr / .gp_sp / .gp_lr / .gp_x / .gp_spsr)`, `sizeof(struct fpregs)`, and the full `mc_flags`/`mc_spare` layout | Can the shim be Rust-via-libc, or must it be C / a locally-asserted `repr(C)`? Cross-check libc's `fpregs.fp_q: u128` (a **single** lane where the real header has 32) |
| P2.2 | **netbsd**: dump `/usr/include/aarch64/mcontext.h` + `sys/ucontext.h`. Record `_NGREG` and the numeric values of `_REG_{X0,X18,X28,X30,X31,SP,PC,ELR,SPSR,TPIDR}` | Cross-check libc's `__gregs: [greg_t; 32]` vs `_REG_ELR = 32` (**suspected binding bug** — a constant OOB index). Also record `_REG_R11`/`_REG_R15` (AArch32 aliases) so the index-assert landmine is documented |
| P2.3 | **Both, decisive**: does **ANY** field carry `ESR_EL1` or `FAR_EL1` — a spare mcontext slot, `si_trapno` (FreeBSD), `si_trap`/`si_trap2`/`si_trap3` (NetBSD), or a ptrace request? | **The ONE probe that could collapse the whole §4.2 workstream from M back to S.** |

### P3 — SIGNAL-HANDLER PC-REWRITE ROUND TRIP (the NetBSD/amd64 Task-2 probe, ported)

| # | Command | Settles |
|---|---|---|
| P3.1 | Both: install a SIGSEGV handler on an altstack (`SA_SIGINFO\|SA_ONSTACK`, deliberately **no** `SA_RESTART`), fault a `PROT_NONE` page, rewrite the mcontext PC (FreeBSD `mc_gpregs.gp_elr`; NetBSD `__gregs[_REG_PC]`) **and** SP to a recovery stub, `sigreturn`, confirm execution resumes at the stub with the other guest registers intact | The entire redirect-into-the-signal-exit-stub mechanism. Without this there is no fault shim |
| P3.2 | Both: confirm a **16-byte-aligned recovery-slot write below the saved SP** survives sigreturn | The Darwin shim's exact mechanism (`csrc/native_darwin.c:556-559`) and the one `_carrick_dsr_exit_signal` reads (`gateway_aarch64.S:124-126`) |
| P3.3 | Both: in the handler, read **and WRITE** the mcontext's saved x18 and x28, sigreturn, confirm honored | Whether the `physical_x18` field (`gateway.rs:420`) is satisfiable, and whether x28 (the context pointer) can be recovered without the recovery slot |

### P4 — EL0 SYSTEM-REGISTER ACCESSIBILITY (the aarch64 FSGSBASE-analogue; §4.5)

| # | Command | Settles |
|---|---|---|
| P4.1 | Both: one C probe, in a child with a SIGILL handler, executing each of: `mrs x0, cntvct_el0` · `mrs x0, cntfrq_el0` · `mrs x0, ctr_el0` · `mrs x0, dczid_el0` · `dc cvau, x0` + `ic ivau, x0` + `dsb ish` + `isb` on a mapped page · `clrex`. Report SIGILL vs success for each | `CNTKCTL_EL1.EL0VCTEN`/`EL0PCTEN` and `SCTLR_EL1.UCI` are **load-bearing**. A SIGILL here is an FSGSBASE-shaped blocker before any guest instruction |
| P4.2 | Both: report the `CNTFRQ_EL0` value, and whether `CNTVCT_EL0` advances monotonically across a host suspend | Decides whether `HostCounterPlan::Inline{Cntvct, 1:1}` (`counter.rs:120-128`) is correct or a syscall fallback is needed. Note `CNTFRQ_EL0` is a **direct** virtualized host read (`decode.rs:1107-1111`) — guest and host must agree with no translation layer |

### P5 — X18 CLOBBER PROBE (§4.3 / §4.4; the campaign's biggest register unknown)

| # | Command | Settles |
|---|---|---|
| P5.1 | Both: write a sentinel to x18 via inline asm, then (a) make a plain syscall (`getpid`) and re-read; (b) call `printf`/`malloc`/`pthread_mutex_lock`/`pthread_create`+join and re-read; (c) raise SIGUSR1 with an `SA_SIGINFO` handler and re-read after return; (d) same via a redirected SIGSEGV whose handler rewrites PC (the gateway's actual pattern) | **(b) is the one that matters.** Does host *userland* keep live state in x18 across a call? A clobbering **kernel** is already tolerated by design (`emit.rs:818-821`, `native_darwin.c:464`); a clobbering **userland** is not, and neither BSD has Darwin's opt-in |
| P5.2 | **freebsd**: `objdump -d /libexec/ld-elf.so.1 \| grep -w x18`; also `/lib/libc.so.7`, `/lib/libthr.so.3`. **netbsd**: same against `/usr/libexec/ld.elf_so`, `/usr/lib/libc.so`, `/usr/lib/libpthread.so`. Also grep the base build flags for `-ffixed-x18` | Direct evidence for P5.1's verdict, and whether the toolchain itself reserves x18 |
| P5.3 | Both: confirm host x18 is treated as **caller-clobbered scratch** across a normal function call boundary | **Decides §4.4**: whether the gateway must ADD x18 to its host save/restore set (it currently saves only sp, x19-x30, q8-q15) |

### P6 — si_code FIDELITY MATRIX (the ESR substitute; §4.2)

| # | Command | Settles |
|---|---|---|
| P6.1 | Both: record `(si_signo, si_code, si_addr)` for — (a) read of an unmapped page [expect SIGSEGV/SEGV_MAPERR]; (b) write to a `PROT_READ` page [SIGSEGV/SEGV_ACCERR]; (c) **execute** of a `PROT_NONE` page [instruction abort]; (d) misaligned LDXR/exclusive access [SIGBUS/BUS_ADRALN]; (e) `BRK #0` [SIGTRAP/TRAP_BRKPT]; (f) hardware single-step via ptrace [TRAP_TRACE]; (g) HW breakpoint and HW watchpoint [TRAP_HWBKPT] | Builds the ESR-free classifier that replaces `el0_fault_signal`/`el0_debug_signal`. (e)–(g) gate the ptrace/Go-`TestDebugCall` path |
| P6.2 | Both: for (a) vs (c), confirm whether an **instruction-fetch abort inside the code cache** is distinguishable from a data abort — e.g. by comparing `si_addr` to the interrupted PC | Darwin gets this from ESR's EC field. Without it, the shim needs a heuristic |
| P6.3 | Both: for (b), confirm the write-vs-read discrimination is **not** available anywhere in siginfo | Validates §3.4's INFERRED mitigation (derive WnR from carrick's own protection metadata) as the only route |

### P7 — W^X JIT + DUAL-MAP ICACHE (§2.2)

| # | Command | Settles |
|---|---|---|
| P7.1 | Both: `shm_open(unique)` (FreeBSD `SHM_ANON`; NetBSD named-then-`shm_unlink`) + `ftruncate` + `mmap(PROT_READ\|PROT_EXEC)` + `mmap(PROT_READ\|PROT_WRITE)` on the same object. Write `mov w0,#42; ret` (`0x52800540`, `0xd65f03c0`) through the RW view, execute through RX | The existing shm dual-map recipe on aarch64. Confirm `PROT_EXEC` on a `MAP_SHARED` shm mapping is permitted (FreeBSD any W^X sysctl; NetBSD PaX `mprotect` via `paxctl` / `sysctl security.pax`) |
| P7.2 | Both: extend P7.1 — write code through the RW alias, run `dc cvau`/`ic ivau`/`dsb ish`/`isb` **ONLY on the EXEC alias VA**, execute; then overwrite with a second function and repeat. Also try maintenance on the WRITE VA only, and no maintenance at all | A stale second result would prove exec-VA-only cleaning insufficient. **Expected: exec-VA suffices (PIPT).** Prefer testing `__clear_cache` directly — it sidesteps the `SCTLR_EL1.UCI` question |
| P7.3 | Both: does either host permit `PROT_WRITE\|PROT_EXEC` directly? | Would simplify — and is the **host W^X policy predicate** §3.4 says should replace the page-size proxy |
| P7.4 | Both: does a fork child's inherited `MAP_SHARED` dual map stay coherent? | `ForkChildJit::Inherited` vs `Fresh` (NetBSD/x86 needed `Fresh`) |
| P7.5 | Both: guest maps `PROT_WRITE\|PROT_EXEC` then `vfork` | Whether `mapped_memory.rs:1648-1651` lets it through at 4K, as the code reading predicts (§3.4) |

### P8 — FUTEX / KICK / SIGNAL ABI

| # | Command | Settles |
|---|---|---|
| P8.1 | **netbsd**: `grep __futex /usr/include/sys/syscall.h`; `cat /usr/include/sys/futex.h` | `carrick-host/src/netbsd_futex.rs:24` **hardcodes** `SYS___FUTEX = 166` and `carrick-native-netbsd/src/futex.rs:44-48` hardcodes `FUTEX_{WAIT,WAKE,REQUEUE,CMP_REQUEUE} = {0,1,3,4}` from the amd64 headers. NetBSD has one arch-common `syscalls.master` so these are very likely right — **but the entire cross-process futex silently misroutes if wrong** |
| P8.2 | **freebsd**: confirm `_umtx_op` wait/wake semantics and that `MAP_SHARED\|MAP_ANON` cross-fork wake works on arm64; confirm `kern.proc.vmmap`/`kinfo_vmentry` and `procctl(PROC_REAP_ACQUIRE)` behave identically to amd64 | The waiter-count table and the reaper. libc's bindings are MI so they compile; the **kernel behaviour** is unproven on arm64 |
| P8.3 | Both: print `SIGRTMIN`/`SIGRTMAX`/`NSIG`; confirm libthr/libpthread reserves no leading RT signal | Expect FreeBSD 65/126, NetBSD 33/63 (their x86 twins) so a kick PAIR `(N, N+1)` is free — the const-assert pattern at `carrick-native-netbsd/src/lib.rs:29-36` |
| P8.4 | Both: confirm a non-`SA_RESTART` RT signal delivered with `pthread_kill` interrupts a blocking syscall with EINTR | The kick's whole premise |

### P9 — ELF ASSEMBLY ACCEPTANCE (§1.4 item 2)

| # | Command | Settles |
|---|---|---|
| P9.1 | Both: copy `crates/carrick-dsr-aarch64/src/gateway_aarch64.S`, strip the leading underscore from every symbol, `cc -c` with the system compiler | Does the assembler accept `.equ`, `.p2align 2`, `stp q8, q9, [x10, #0]`, `msr nzcv/fpsr/fpcr`, `mrs`, `clrex`? Does it need `.type f,%function` / `.size` / `.hidden` / the `#if defined(__ELF__) .section .note.GNU-stack` tail? Record the clang/gcc version on each box |
| P9.2 | Both: confirm the `cc` crate + a `.S` containing `#if defined(__ELF__)` and a symbol-prefix macro links a static lib into rustc output | The amd64 lanes prove yes; confirm arm64 |

### P10 — IDENTITY-VS-BIASED / VA LAYOUT FEASIBILITY

| # | Command | Settles |
|---|---|---|
| P10.1 | Both: dump the process's own VA occupancy (`procstat -v` FreeBSD, `pmap` / `/proc/curproc/map` NetBSD) | Is there any mandatory low-VA guard comparable to Darwin's 4 GiB `__PAGEZERO`? |
| P10.2 | Both: `mmap(MAP_FIXED)` at the addresses a static aarch64 Linux ELF actually wants — `0x400000`, `0x10000`, and a PIE base like `0xaaaa_aaaa_0000` | Could the BSD-aarch64 lane use the **identity** model, or must it keep biased `mapped_memory`? |
| P10.3 | Both: `MAP_FIXED` probe at the aarch64 native layout addresses — heap `0x8_0000_0000`, mmap arena `0xa0_0000_0000` with a 32 GiB `PROT_NONE` reservation; confirm `MAP_NORESERVE` semantics and the user-VA ceiling (`Aarch64Isa` asserts `1<<48`) | Whether the Darwin arena bases in `mapped_memory.rs:112-115` are usable as-is |
| P10.4 | Both: does the host honor an **EXACT non-`MAP_FIXED` mmap hint**? | `carrick-dsr/src/address.rs:756-761` documents this as a macOS assumption and flags that the BSD lane "will need `MAP_FIXED\|MAP_EXCL` probing" |

### P11 — USDT / DTRACE VIABILITY (decides whether the campaign has any tracing)

| # | Command | Settles |
|---|---|---|
| P11.1 | **freebsd**: is `dtrace` present, and is DTrace enabled in the arm64 kernel? Does the `usdt` crate build with its **real** backend for `aarch64-unknown-freebsd`? | Whether `carrick-observability/src/probes.rs:36-51`'s aarch64-BSD stub is **permanent** |
| P11.2 | **freebsd**, after a usdt fix: `cargo build -p carrick-observability && cargo build -p carrick-runtime --no-default-features --features <new-bsd-arm64-feature>` | Proves the usdt strategy actually selected is buildable and nothing else in the observability chain is `c_char`-sensitive |

### P12 — FIXTURE / LOADER ACCEPTANCE (host-side prep, then on-box)

| # | Command | Settles |
|---|---|---|
| P12.1 | **On the Mac (no VM):** `readelf -lW` the tracked aarch64 ELFs under `crates/carrick-vmm-kvm/fixtures/` — record `p_align` (aarch64 GNU ld commonly uses 64 KiB max-page-size) and `e_type` | Does the load-plan page-alignment path tolerate `p_align > host page size`? And confirm all 8 are ET_EXEC, not ET_DYN |
| P12.2 | Both, once a lane exists: run `crates/carrick-vmm-kvm/fixtures/hello-aarch64/hello-aarch64` through the new lane | **The acceptance moment.** Also settles whether the aarch64 native loader accepts **ET_EXEC at a fixed vaddr** on a BSD host (the x86 rung-1 fixture is static-PIE, so this is untested territory) |
| P12.3 | Both, once a lane exists: from inside a real static aarch64 Linux ELF print `getauxval(AT_PAGESZ)`, `getpagesize()`, `sysconf(_SC_PAGESIZE)`; assert all three == the host value. Then LTP `getpagesize01` + mmap/mprotect alignment cases | End-to-end geometry correctness (§3.7's never-run-end-to-end gap) |
| P12.4 | Both: run stage0 and **diff the executed-test list against the Darwin run** | Sizes the prepared-image/exec-capsule coverage hole from `prepared_image.rs:1284-1296` and `native_exec_capsule.rs:1096-1107`. **Note:** those suites are in `carrick-dsr`/`carrick-runtime`, which stage0 never compiles — so this diff belongs to whatever future stage runs those suites, not stage0 |

**Total: 12 probe groups, 38 individual probes.**

---

## 7. Proposed task breakdown

Mirroring the NetBSD/x86 staging (prereqs → host crates → seam/re-gate → wiring →
acceptance → gate ladder). **(×2)** = per-OS, done twice.

| # | Task | Kind | Size | Depends on |
|---|---|---|---|---|
| **T0** | **On-box probe phase.** Execute §6 P0–P11 on both guests; write the evidence doc. Deferred by the controller; everything below is contingent on it | shared | **M** (1–2 days) | — |
| **T1** | **Arch-gate the four crates.** `carrick-native-freebsd`: `#[cfg(target_arch="x86_64")]` on `tsc.rs` + `fault.rs` + the `vdso_tsc_calibration` wiring at `lib.rs:76-78`. `carrick-native-netbsd`: same on `fsbase.rs` + `fault.rs`. `carrick-vmm-bhyve`: arch-gate the 8 feature-only-gated x86 references in `carrick-runtime/src/lib.rs` (`:398-399`, `:771`, `:775`, `:779`, `:787`, `:867-868`, `:900`, `:911`, `:2080`) **and** `pub mod vmm` / `#[link(name="vmmapi")]`. `carrick-vmm-nvmm`: add an arch gate (`src/lib.rs:22` is OS-only over an unconditional x86 engine + `-lnvmm`). **Include the aarch64 `flush_icache` fail-closed/`__clear_cache` body in the same commit** — it is the one item that fails SILENTLY | shared | **M** | T0 P0.5 |
| **T2** | **A VMM-less BSD/aarch64 feature pair** + **futex re-homing**: lift the two ~40-line `SharedFutexSyscall` adapters out of `carrick-vmm-{bhyve,nvmm}` into a non-VMM home, add 2 `threaded_impl` arms, and **write the missing `PlatformFutex` adapter over `carrick-host::{umtx,netbsd_futex}`** (`grep -rn 'impl .*PlatformFutex for' crates/` = 0 hits today). Resolve the open cargo question about `dep:` in `[features]` vs arch-scoped `[target.'cfg(…)'.dependencies]` | shared | **M** | T1 |
| **T3** | **Fix the freebsd-arm64 usdt-impl `c_char` blocker.** First check crates.io for a release >0.6.0 that fixes `no-linker.rs:166` (a one-line workspace bump); otherwise `[patch.crates-io]` a fork, or own the `usdt::Error` return type in `probes::stub` and target-gate the dep | shared | **S–M** | T0 P0.2 |
| **T4** | **bsdvm provisioning**: add pkgsrc `clang`/`LIBCLANG_PATH` to the netbsd `provision_commands` (`bsdvm.py:603`) and `llvm19` to the freebsd one (`:544`); refresh-golden both | shared | **S** | T0 P0.1/P0.2 |
| **T5** | **The page-geometry decision + arm.** Generalize `x86_native_plan` → `uniform4k_native_plan` (rename + 3 strings; test-safe), add the two `(FreeBsd\|NetBsd, Aarch64)` arms. **Then make the §3.5 ruling**: `native_profile: None` + re-gate the aarch64 native16k W\|X mechanism *and* policy on a **host W^X predicate** (recommended), vs a new uniform-4K `NativePageProfile` variant (touches `carrick-spec:307`, `carrick-guest-mem:181-184`, `dispatch/mem.rs:1111/1138/3577`, `native_exec_capsule.rs:301-309`, serde). Also fix the `mapped_memory.rs:1648-1651` vs `:1631` asymmetry. Cosmetics: `HostPageState::Uniform16k` → `Uniform`, the 16K diagnostic strings | shared | **M** | T0 P1, P7.3 |
| **T6** | **The ESR-free fault-lowering design + implementation.** Two decision sites (`translator.rs:2388-2416`, `native_darwin.rs:3044-3053`) consume the already-plumbed neutral `(signal, code)` instead of `lower_el0_fault(esr,…)`; derive WnR from carrick's own protection metadata for `resolve_native16k_write_exec_fault`; either synthesize a plausible ESR word for `el0_debug_signal` or give `carrick-dsr-aarch64` a new input. **Controller ruling needed before T7** | shared | **M–L** | T0 P2.3, P6 |
| **T7** | **Gateway ELF port.** `SYM()`/`#ifdef __APPLE__` macro + `.type`/`.size` + the `__ELF__ .note.GNU-stack` tail in `gateway_aarch64.S`; widen `build.rs:7-17`; widen `gateway.rs`'s whole `native_gateway` module cfg (:232, :455, :465, :538). **Plus** (pending P5.3) add host **x18** to the enter/restore save sets (§4.4) | shared | **M** (~1 day + the x18 delta) | T0 P9, P5.3 |
| **T8** | **The enter/exit ABI hook seam.** Decide: same-named C symbols per host crate (current Darwin `bl`-by-name shape) **vs** a host-injected function pointer in the context (the x86 `CTX_SET_FSBASE_FN` / `X86DsrContext::set_fsbase_fn` precedent — cleaner, lets the `.S` stay OS-agnostic, but changing `DsrContext` offsets touches the `.equ` table and the C shim's `_Static_assert`s) | shared | **M** | T7 |
| **T9** | **The trap/kick shim** — the campaign's biggest deliverable. Per host: `install_dsr_signal_handlers`, `kick_state_{create,destroy,request,acknowledge,bind_current,unbind_current}`, `dsr_enter_guest_abi`, `dsr_enter_host_abi`, the mcontext↔snapshot mapping (against **real headers**, not libc — §2.1), sigaltstack/sigmask policy, the RT kick pair, and the ~45 lines of active-context/deferred-kick/phase bookkeeping that survive regardless of the x18 answer | **(×2)** | **L** each | T6, T8 |
| **T10** | **Host counter plan + vvar clock sources.** A BSD arm returning `Inline{Cntvct, 1:1}`; un-gate/replace `fallback_counter_ticks` (currently `cfg(macos)`); widen `host_counter_frequency`'s cfg; point the vvar arm at `carrick_dsr_aarch64::counter::host_counter_frequency` + `carrick_host::clock::host_clock_uptime_ns`; re-gate the `ReadCounter` arm (`native_darwin.rs:2184-2202`) | shared | **S–M** | T0 P4 |
| **T11** | **Re-gate the run module + the LaneHost alias block.** Widen `lib.rs:154` to `cfg(all(any(macos,freebsd,netbsd), aarch64))`; add a cfg-selected `use … as LaneHost/LaneHostJit/fault/kick` block mirroring `native_freebsd.rs:60-83`; fix the 5 non-test cfg sites; **add the missing netbsd arm to `native_darwin/darwin_jit.rs`** (or delete that shim in favour of the alias — today `cfg(not(any(macos,freebsd)))` sends NetBSD to `UnsupportedHostJit` while FreeBSD/aarch64 silently resolves to the x86 no-op-`flush_icache` JIT) | shared | **M** | T9, T10 |
| **T12** | **Lane wiring.** `Freebsd/NetbsdAarch64Lane` structs + `NativeLane` impls + `HostNativeLane` alias arms in `native/mod.rs:87-135`; one new cfg arm in each of the three `crate::native` dispatch fns; target-gated Cargo dep blocks | **(×2)**, XS each | **XS** | T11 |
| **T13** | **The inline-test surface.** `native_darwin.rs`'s test half is 7,104 lines (55%) with ≥16 explicitly Darwin-gated blocks (8712, 8724, 8935, 8953, 9001, 9043, 9089, 9164, 11195, 11249, 11282, 11396, 11446, 11807, 11849, 12148) **plus** the ~8.5k-line Darwin-JIT-entangled `native_darwin/dsr/` tree (`emit.rs` 1,913 — "tests stay HERE because nearly every test publishes into a live TranslationCache through the Darwin host JIT"; `oracle.rs` 3,481 live-execution oracle; `mod.rs` 2,299; `gateway.rs` 343; `block.rs` 293; `artifact_spike.rs` 209). The x86 campaign's adversarial review found `mod identity_raw_range_tests` broke `cargo test` on NetBSD after the cfg flip. **Do a `#[cfg(all(test, target_os="macos"))]` sweep UP FRONT** rather than accumulating a second instance of that debt | shared | **M** | T11 |
| **T14** | **Acceptance test + the missing fixture rungs.** One shared `crates/carrick-runtime/tests/native_bsd_arm64.rs` gated `cfg(all(any(freebsd,netbsd), aarch64))`, modelled on the 155-line `native_netbsd_x86.rs`. Rung 1 exists (`hello-aarch64`). Cross-build on the Mac and commit: a chaining/`traps == 1` fixture and a real-std-Rust fixture, with README + SHA-256 digests + `build.sh` matching the existing discipline | shared | **M** | T12 |
| **T15** | **stage2 in the gate ladder.** Populate `bsdvm.py` STAGES stage2 with the literal cargo string (never `cargo check`); set `available=True`; re-point the 3 pinning assertions in `test_bsdvm.py:1203-1222`; append stage2 to `just bsdvm-acceptance` (`justfile:379-380`); if report-only, quote `steps_ok` not `exit_ok`; make the command write a JSON artifact and `cat` it (the 4000-char/10-line truncation will clip a long failure list) | shared | **S** | T14 |
| **T16** | **stage3 groundwork** (explicitly out of scope for the first landing; log it). Re-gate `examples/native_run.rs` (`cfg(all(freebsd, x86_64))` — never even widened for the NetBSD x86 lane), and build an aarch64-musl static LTP fixture + per-arch oracle to replace `native-x86-ltp-gate.py`'s `FIXTURE = "ltp-20260529-x86_64-musl-static-pie"` | shared | **L** | T15 |

**Totals: 16 tasks. 14 shared, 2 per-OS (×2) — but T9 (the shim) is the single largest and
is one of the two doubled ones.** Rough sizing: **1 M probe phase + 6 M + 1 M–L + 1 L(×2) +
2 S–M + 2 S + 1 XS(×2) + 1 L deferred.** Order-of-magnitude: comparable to the NetBSD/x86
campaign's 31 commits **plus** the arch-gating pre-step (T1–T4) and the two genuine design
rulings (T5 §3.5, T6 §4.2) that x86 never faced.

**Which lane first?** **FreeBSD/aarch64.** More of its host crate is already written and
reusable as-is (waiter_key, `MAP_EXCL`, the `procctl` reaper), and it is a Rust tier-2
target with the newer guest rustc (1.96.1 vs 1.91.1). Against it: FreeBSD carries the usdt
blocker (T3) while NetBSD does not. NetBSD/aarch64 has the simpler futex (no waiter table)
but is tier-3, has the tightest MSRV, and already carries the reaper gap.

---

## 8. Risks + unknowns

### 8.1 VERIFIED blockers (code, must be fixed; no probe needed)

| # | Blocker | Evidence |
|---|---|---|
| **V1** | `carrick-runtime` cannot compile on either aarch64 BSD with any feature set: 4 x86-welded modules in 2 `target_os`-only-gated crates that are unconditional target-deps | `carrick-native-freebsd/src/{tsc.rs:87,89; fault.rs:167,177,180-182,188,209,216,225}` + `lib.rs:76-78`; `carrick-native-netbsd/src/{fsbase.rs:61-107; fault.rs:55-59,197,237,317-319}`; `carrick-runtime/Cargo.toml:133-134,138-139` |
| **V2** | `flush_icache` is a **silent** wrong-code hazard: the x86 no-op compiles and runs on aarch64 because the crate gate is `target_os`-only | `carrick-native-freebsd/src/jit.rs:167-170`; `carrick-native-netbsd/src/jit.rs:253-256`; contract at `carrick-dsr/src/host.rs:140-141`. Aggravated by `native_darwin/darwin_jit.rs:17-18` resolving FreeBSD/aarch64 to exactly that impl, with **no netbsd arm at all** (:24) |
| **V3** | Neither BSD platform feature works on aarch64: `platform-freebsd` = compile break (8+ x86-only bhyve refs) + `-lvmmapi`; `platform-netbsd` = `-lnvmm` link break on an un-arch-gated crate | `carrick-runtime/Cargo.toml:69-70`; `carrick-runtime/src/lib.rs:398-399,771,775,779,787,867-868,900,911,2080`; `carrick-vmm-bhyve/src/lib.rs:21,35-38` + `src/vmm.rs:114`; `carrick-vmm-nvmm/src/lib.rs:22,42` + `src/nvmm.rs:330` |
| **V4** | No `PlatformFutex` impl over the BSD host primitives exists anywhere in the tree — so "reuse the Darwin loop's futex wiring" is an **unwritten adapter**, not a wiring choice | `grep -rn 'impl .*PlatformFutex for' crates/` = 0 hits; `BsdFutex` only in comments (`carrick-host/src/umtx.rs:2`, `carrick-host-bsd/build.rs:4`); consumer at `native_darwin.rs:3171,3196,8738` |
| **V5** | ESR_EL1 is absent from both BSDs' aarch64 mcontext, and it is load-bearing in **three** production paths, one of which (WnR) is **more** reachable at 4K | libc `freebsdlike/freebsd/aarch64.rs:10-33`, `netbsdlike/netbsd/aarch64.rs:14-18,96-132`; consumers `native_darwin.rs:3044-3050` → `vcpu_loop/signal.rs:86-110,157-163`; `translator.rs:2389` → `esr.rs:13-27`; `native_darwin.rs:3020-3030` → `mapped_memory.rs:1751-1800` (WnR at :1781) |
| **V6** | libc's aarch64 BSD mcontext bindings are unusable for the shim: NetBSD `[greg_t; 32]` vs `_REG_ELR = 32` (constant OOB); FreeBSD `fpregs.fp_q: u128` (single lane, mis-sizes `mcontext_t`); `_REG_R11`/`_REG_R15` AArch32 aliases are an index-assert landmine | `netbsdlike/netbsd/aarch64.rs:14-18` vs `:110,122-132`; `freebsdlike/freebsd/aarch64.rs:19-25` |
| **V7** | The gateway does not save/restore **host x18** while translated code writes physical x18 | `gateway_aarch64.S:22-35` (saves sp, x19-x30, q8-q15) and `:142-184` (restores the same set); `grep 'x18\|w18'` = 2 hits, both comments; writes at `emit.rs:2035`, `:2226` |
| **V8** | The `mapped_memory.rs:1648-1651` vs `:1631` guard asymmetry: at 4K the W\|X **mechanism** stays armed while the vfork **refusal** disarms. DORMANT (only consumer is in a `cfg(macos, aarch64)` module) but the new lane would activate it | verified by direct read; the profile-keyed policy twins at `dispatch/mem.rs:1111,1138,3577` also go OFF with `native_profile: None`, including the shared-W\|X refusal at `:1114-1116` that is LIVE on Darwin today |
| **V9** | usdt-impl 0.6.0 E0308 on FreeBSD/aarch64 (`c_char` unsigned), on the critical path; **not avoidable by features** | `~/.carrick/bsdvm/results/20260723-150512-freebsd-arm64-stage1/report.json`; `carrick-observability/Cargo.toml:27-36`, `carrick-runtime/Cargo.toml:125`, root `Cargo.toml:121` |
| **V10** | bindgen/libclang absent on netbsd-arm64, blocking `bad64-sys` → `carrick-dsr-aarch64` → the aarch64 translate engine. **Provisioning, not code** — and there is no pregenerated-bindings escape hatch in the crate | `~/.carrick/bsdvm/results/20260723-150644-netbsd-arm64-stage1/report.json`; `Cargo.lock:150-158`; `carrick-dsr-aarch64/Cargo.toml:29-34`; vendored `bad64-sys-0.10.0/build.rs` |
| **V11** | Two of the four acceptance-ladder rungs have no aarch64 fixture (chaining/`traps==1`, real-std Rust), and the fixture builder cannot run on the guests (needs rustup musl std + `rust-lld`) | `scripts/build-linux-fixtures.sh:11-14,17-20,27-51,84-144`; `crates/carrick-dsr-aarch64/tests` does not exist |
| **V12** | `carrick-vmm-hvf` has **no crate-level `#![cfg]`** and `carrick-runtime`'s `default = ["platform-macos"]`, so stage1's `cargo build --workspace` drags HVF onto both BSD guests | `carrick-vmm-hvf/src/lib.rs:1-30`; `carrick-runtime/Cargo.toml:30`; `justfile:122-125` never uses `--workspace` off-macOS |
| **V13** | **Capability losses, accepted (red-list):** USDT probes are a permanent stub on aarch64 BSD (no `carrick trace`, no DSR profiling probes, no lifecycle markers, and `NativeDsrProbeForwarder`'s ~350 lines compile but fire nothing). NetBSD has no `procctl` reaper equivalent (orphans reparent to host init; guest `wait4(-1)` sees ECHILD). NetBSD/aarch64 gets **no guest CPU accounting at all** — `guest_cpu::native_self_cpu_ns()` has a FreeBSD `getrusage` arm but no NetBSD arm (falls to `None` at `guest_cpu.rs:126-129`; a NetBSD arm is ~15 LoC), and `current_thread_port()` stubs to 0 / `thread_cpu_us_for_port` to `None` off macOS — affecting `times`/`getrusage`/proc-stat/RLIMIT_CPU/CPU-itimers | `probes.rs:36-51`; `carrick-dsr/src/lane.rs:66-72`; `carrick-host/src/{guest_cpu.rs:105-129, host_proc.rs:478-481,1657-1666,1827-1831}` |

### 8.2 NEEDS-ON-BOX unknowns, ranked by how much they could change the plan

| # | Unknown | If it goes badly | Probe |
|---|---|---|---|
| **U1** | **Host page size.** No file in the repo states it; the only authority is a design-doc assertion | Every "4K" estimate in §3 changes shape. 16K collapses §3.7's "third geometry" framing (it becomes Darwin's own, already exercised); 64K needs a new profile touching 4 crates | P1.1 |
| **U2** | **Is x18 claimed by host userland?** Darwin has a kernel opt-in the BSDs lack | Straight to the emitter change (delete the `emit.rs:805-816` scratch window). Bounded, but inside the ISA crate | P5.1, P5.2 |
| **U3** | **Is host x18 caller-clobbered scratch across a call?** | The gateway must ADD x18 to its host save/restore set — assembly work additive to T7 | P5.3 |
| **U4** | **Is there ANY ESR-equivalent** in a spare mcontext slot / `si_trapno` / `si_trap*` / ptrace? | **Upside risk**: a YES collapses T6 from M–L to S | P2.3 |
| **U5** | **si_code fidelity**: does either BSD deliver TRAP_BRKPT for `BRK #0`, BUS_ADRALN for misalignment, and a distinguishable instruction-fetch abort? | The ESR-free classifier loses fidelity; ptrace/single-step/HW-watchpoint may be unimplementable | P6 |
| **U6** | **EL0 access to CNTVCT/CNTFRQ and `dc cvau`/`ic ivau`** (`CNTKCTL_EL1.EL0*EN`, `SCTLR_EL1.UCI`) | A SIGILL here is a true FSGSBASE-shaped blocker before any guest instruction | P4.1 |
| **U7** | **Exec-VA-only icache cleaning across a dual map** | Falls back to registering `(exec_base, write_base)` in the host crate — **host-local, no shared-seam change** (§2.2) | P7.2 |
| **U8** | **`PROT_EXEC` on a `MAP_SHARED` shm mapping** (FreeBSD W^X sysctls; NetBSD PaX mprotect) | The whole dual-map JIT strategy needs a different shape on that host | P7.1, P7.3 |
| **U9** | **NetBSD `SYS___futex` = 166 and `FUTEX_*` = {0,1,3,4} on aarch64** — hardcoded, transcribed from amd64 headers | The entire cross-process futex **silently misroutes** | P8.1 |
| **U10** | **Does the aarch64 native loader accept ET_EXEC at a fixed vaddr?** All 8 tracked aarch64 fixtures are ET_EXEC; the x86 rung-1 fixture is static-PIE | The acceptance ELF needs rebuilding as static-PIE before it can run | P12.1, P12.2 |
| **U11** | **Cold stage2 wall time** on a 4-vCPU/6 GiB QEMU-HVF arm64 guest vs the 7200 s per-step budget | The gate needs splitting into multiple steps | P0.7 |
| **U12** | **Does cargo accept `dep:X` in `[features]` when X is declared only under an arch-scoped `[target.'cfg(…)'.dependencies]`?** | New arch-scoped feature names, and every consumer (`carrick-cli/Cargo.toml:23-26`, `justfile:11-15`, the cross-check recipes) must learn them | P0.5 + a local cargo experiment |
| **U13** | **libc-crate coverage on the real box toolchains**: does `libc::procctl`/`PROC_REAP_ACQUIRE`, `kinfo_vmentry`/`KERN_PROC_VMMAP`, `MAP_EXCL`, `shm_open`/`SHM_ANON` compile for `aarch64-unknown-{freebsd,netbsd}`? | A missing binding turns a REUSABLE-AS-IS row into a clean-room raw-syscall row | P0.4, P8.2 |
| **U14** | **Fixed-address arena mappability** at Darwin's `0x8_0000_0000` heap / `0xa0_0000_0000` mmap arena, `MAP_NORESERVE` semantics, and whether the host honors an exact non-`MAP_FIXED` hint | The BSD lane must re-derive its VA layout (and might get to use identity instead of biased) | P10 |
| **U15** | **DTrace/usdt on FreeBSD/aarch64** | The USDT stub is permanent on both lanes — the campaign ships with no tracing | P11.1 |

### 8.3 Open design questions the controller should rule on BEFORE Task 1

1. **Fault-shim shape (§1.5).** Route (a) mirror the C shim per host, vs route (b) first
   change `_carrick_dsr_exit_signal` to save the guest register file so a small pure-Rust
   shim suffices. **Recommendation: (a) now, (b) as a logged follow-on.**
2. **The `native_profile` ruling (§3.5).** `None` + a host-W^X-predicate re-gate of the
   aarch64 native16k W|X mechanism *and* policy, vs a new uniform-4K `NativePageProfile`
   variant. Decides whether virtual-ptrace and the exec capsule are available on the new
   lanes. **Recommendation: `None` + host-W^X predicate; the exec capsule is not needed
   (weld #3) and virtual-ptrace can be a follow-on.**
3. **The ESR ruling (§4.2/T6).** Synthesize an ESR word in the shim (keeps the shared loop
   untouched but fabricates architectural state) vs teach the aarch64 loop the neutral
   `(signal, si_code, addr)` lowering (more honest, two decision sites, plus one change
   inside `carrick-dsr-aarch64` for `el0_debug_signal`). **Recommendation: the neutral
   lowering** — the payload is already plumbed and the arch-crate change is small.
4. **The ABI-hook shape (T8).** Same-named C symbols per host crate vs a host-injected
   function pointer in `DsrContext` (the x86 `CTX_SET_FSBASE_FN` precedent).
5. **`NativeHost` growth.** Its current extra methods (`shared_futex_waiter_key`,
   `exclusive_fixed_map_flag`, `vdso_tsc_calibration`) are all x86/identity-model concerns;
   the aarch64 lane wants **different** ones (counter plan, vvar clock sources, guest-ABI
   switch, kick signal). Does the trait grow an aarch64 sub-seam, or get split? Note also
   that the trap/kick/altstack contracts were **deliberately kept out** of the trait
   (`carrick-dsr/src/host.rs:4-7`) and the x86 lane reaches them through a **module alias**
   (`native_freebsd.rs:60-83`), not trait methods — so the aarch64 campaign's primary seam
   work is a second module-alias seam, with the trait a secondary widening.
6. **Rename `native_darwin.rs` → `native_aarch64.rs`?** The x86 campaign explicitly
   deferred `native_freebsd.rs` → `native_x86.rs` "for git-blame continuity"
   (`lib.rs:159-162`). Consistency argues for deferring here too, but the file name would
   then be actively misleading for three hosts.
7. **Fix or red-list the NetBSD guest-CPU-accounting gap?** A NetBSD `getrusage` arm in
   `guest_cpu.rs` is ~15 LoC and buys `times`/`getrusage`/proc-stat/RLIMIT_CPU/CPU-itimers.
8. **Does the aarch64 lane need a subreaper equivalent at all?** The aarch64 production
   code never calls `become_guest_reaper()` (0 hits in `native_darwin.rs:1..5880`) — so
   either Darwin has an equivalent elsewhere, or the aarch64 lane already has the
   orphan-reaping gap on macOS today. **Worth a targeted look before the campaign silently
   inherits it on two more hosts.**
9. **stage2 gating or report-only?** stage0's convention is gating, stage1's is report-only
   ("the red list IS the bring-up worklist"). If report-only, the acceptance summary must
   quote `steps_ok` — `cmd_ladder` prints PASS on `exit_ok`, which is 0 for a report-only
   stage regardless of failures.
