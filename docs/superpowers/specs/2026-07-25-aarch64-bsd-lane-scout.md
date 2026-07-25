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

**T0 UPDATE (2026-07-25, post-probe).** The on-box probe phase ran on both guests. Every
NEEDS-ON-BOX item below is now marked **SETTLED-MEASURED** (probe ran, output attached),
**SETTLED-READ** (header/man-page/source citation only), **DOWNGRADED** (a probe claim an
adversarial verifier weakened or refuted — the verifier's version is what appears here), or
**STILL-OPEN**. §6 has been rewritten as an executed probe log. Where the original text and
the probe data disagree the probe data wins, and the original prediction is kept inline so
the estimate error stays visible.

---

## 0a. PLAN OF RECORD AFTER T0

**Verdict: GO — WITH CAVEATS.**

**The single biggest reason to go:** the campaign's central thesis was measured, not argued.
`cargo test -p carrick-dsr-aarch64` is **87 passed / 0 failed on BOTH guests** (P0.4 ×2) —
the aarch64 ISA engine, memory model and shared host crates need **zero** arch/OS work.
Independently corroborated by both verifiers: the crate has 91 `#[test]`s of which exactly 4
are `cfg(all(macos, aarch64))` in `counter.rs`; 91 − 4 = 87, on both boxes.
**Scope it honestly:** `carrick-dsr-aarch64/build.rs:7-17` assembles the gateway only on
macos+aarch64 and `gateway.rs:465+` stubs every exit address to 0 off-Darwin, so those 87
tests **cannot execute one translated instruction** on a BSD. They prove the crate compiles
and its pure-Rust + real-`mmap` logic passes. They do not prove translation works.

**The caveats, in order of how much they change the plan:**

1. **Host page size is 4096 on BOTH guests** (P1.1/P1.2/P1.3 ×2, three independent sources
   each, including a real `mprotect` granule) ⇒ **Scenario A, unconditionally.** Every "4K"
   estimate in §3 now stands. But see (2).
2. **The §3.4 write-exec mechanism is REACHABLE at 4K and must NOT be disarmed.** A
   post-probe read of `mapped_memory.rs:1694-1724` + `:3879-3889` (done during this
   write-up; see §3.4) shows `native16k_host_prot` **never** grants `PROT_EXEC` to a guest
   page at any geometry — the "executable" state is read-only + icache-clean. So the W↔X
   flip is a **self-modifying-code detection** mechanism, not a host-W^X-policy workaround,
   and it is required on any host regardless of whether that host permits RWX.
   **This REFUTES the freebsd-arm64 probe agent's headline recommendation to "disarm the
   whole mechanism on a permits-RWX host."**
3. **The ESR answer differs between the two guests, and one of them needs synthesis work.**
   NetBSD delivers the **raw ESR_EL1 word** in `siginfo_t.si_trap` (P2.3; 9 exception
   classes, every EC/ISS/WnR/IL bit independently re-decoded by the verifier, including
   three full MSR-trap ISS operand decodes). FreeBSD delivers only the **EC field** in
   `si_trapno` (P2.3; 12 provoked faults) — no ISS, so no DFSC and **no WnR bit**. The
   FreeBSD synthesis is therefore `esr = (si_trapno << 26) | dfsc_from(si_signo, si_code)`,
   **not** the bare `<< 26` the probe report headlined (§4.2 shows why the bare form is
   wrong in the majority of measured cases).
4. **Two new blockers joined §5.4's four**, both one-liners, both on the critical path:
   **B5** `carrick-dsr/src/identity_memory.rs:1365` `vec![0i8; pages]` passed to
   `libc::mincore(_,_,*mut c_char)` — E0308 on every non-Apple aarch64 (measured on BOTH
   guests, source-verified by BOTH verifiers); **B6** the un-gated `run_oci` caller at
   `carrick-runtime/src/lib.rs:589`.
5. **NetBSD PaX MPROTECT pins each mapping's maxprot at `mmap` time**, so carrick's "reserve
   32 GiB `PROT_NONE`, promote later" arena pattern fails EACCES. Measured fix, needing no
   privilege, sysctl or `paxctl`: reserve `PROT_READ|PROT_WRITE (+MAP_NORESERVE)` then
   immediately demote the whole reservation to `PROT_NONE`. Portable (works on Darwin too).
6. **`carrick_dsr::address::map_exact` rests on a Darwin-only guarantee and is broken on
   FreeBSD.** FreeBSD ignores exact non-`MAP_FIXED` hints (P10.4; three hints, all ASLR'd
   away), and `map_exact` (`address.rs:52-92`) maps *without* `MAP_FIXED` then compares — so
   it returns `HostCollision` **always**. Implementer gotcha: the `MAP_EXCL` collision errno
   is **ENOMEM, not EEXIST**. NetBSD honored both hints tested but has **no `MAP_EXCL` at
   all** and its `MAP_FIXED` silently clobbers, so hint-plus-verify is the only safe shape
   there — and the NetBSD "no rewrite needed" conclusion was **DOWNGRADED to INDICATIVE** by
   verification (two samples, both in vacant regions).

**Build FreeBSD/aarch64 first.** Unchanged from the pre-probe recommendation, and the data
strengthened it: FreeBSD's whole host-capability surface came back green with no policy
surprises (RWX permitted; `_umtx_op` cross-fork wake works on arm64; `procctl` reaper works;
`kern.proc.vmmap`/`kinfo_vmentry` works; `MAP_EXCL` exists; all three Darwin arena bases map
exactly; user VA ceiling is exactly `1<<48`), its cold acceptance-path build is **13 s**, and
its rustc is 1.96.1. NetBSD brings two design constraints nobody had on a list (PaX maxprot
pinning; no `MAP_EXCL`), the fleet's tightest MSRV (1.91.1), and no HW-debug registers. The
one point against FreeBSD — the usdt blocker — is a **single line** and is now fully
characterized (§5.4 B4a). **Order: T1 → T4 → T3 → T2 → T17 → T5 → T6 → T7 → T8 →
T9(freebsd) → T10 → T11 → T12 → T14 → T15, then T9(netbsd) + the netbsd half of T12**
(T13 in parallel with T11; T16 deferred). Full per-task rationale in §7.

**What the maintainer must rule on before work starts (§8.3):** exactly **one** ruling gates a
task — **Q2, the `native_profile` decision**, which gates **T5** (not T1, as the pre-probe text
assumed). Q1 (fault-shim route) and Q3 (the ESR ruling) are now **DECIDED by data**. Q4, Q5,
Q7 and Q9 have recommendations with stated trade-offs but no data behind them; Q6 is pure
taste; **Q8 is not a ruling at all — it is a 30-minute repo question nobody answered** (does
anything on the aarch64 path ever call `become_guest_reaper()`? still 0 call sites).

**Two capability facts to write into the plan now rather than discover later:**

- **USDT can NEVER fire on freebsd-arm64.** `fasttrap.ko` does not exist in `/boot/kernel`,
  `kldload fasttrap` = ENOENT, and dtrace itself reports "pid provider is not installed on
  this system" (P11.1). The pid/fasttrap provider is the only route by which USDT sites fire
  on FreeBSD, so fixing usdt-impl buys **compilation only**. Substitute: kernel DTrace is
  rich and works (52,622 fbt + 2,376 syscall + sdt/sched/vm/proc/io/ip/tcp probes) — the same
  shape as the existing `carrick-bhyve-debug` workflow. NetBSD ships `/usr/sbin/dtrace` +
  `dtrace_sdt` modules but DTrace is not enabled in GENERIC64, and `usdt` 0.6 has no NetBSD
  backend. So weld #4 stands on both lanes, for **different reasons** (FreeBSD: kernel;
  NetBSD: crate).
- **`flush_icache` is a LIVE silent-corruption trap the moment either host crate compiles on
  aarch64.** Measured on freebsd-arm64 (P7.2 case iv): publishing code through the RW alias
  with **no** cache maintenance executed the **stale** previous function. The empty
  `fn flush_icache(&self, _exec_ptr, _len) {}` is `target_os`-gated only, so it compiles and
  runs unchanged. The `__clear_cache` body **must** land in the same commit that first makes
  either crate build on aarch64, with a regression test shaped like that case.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Does the aarch64 run path serve BSD aarch64 as bounded host-glue? | **YES, with one caveat**: bounded host-glue **plus** two net-new artifacts (an assembly port and a per-host trap/kick shim) **plus** one genuine design decision inside `carrick-dsr-aarch64` (ESR-free fault lowering) **plus** a 4-crate arch-gating pre-step x86 never needed. |
| How much smaller is the aarch64 run path than the x86 one? | **2.3x.** 5,880 production lines vs 13,669. Five non-test `cfg(target_os)` sites in the whole production half. Zero Darwin-only `libc` symbols. |
| Biggest new-code item | The trap/kick shim (2× ~300 LoC C, or 2× ~150 LoC Rust after gateway surgery). Not behind a seam today — consumed as 7 raw `unsafe extern "C"` declarations. |
| Biggest surprise (the FSGSBASE-analogue) | **ESR_EL1 is not in either BSD's aarch64 *mcontext*** — but **T0 found it in *siginfo* on both**: NetBSD `si_trap` = the raw 32-bit ESR word; FreeBSD `si_trapno` = the EC field only. Load-bearing in three production paths; the WnR bit is available free on NetBSD and must be derived from carrick's own metadata on FreeBSD. Runner-up: physical **x18** — **T0 settled it as FREE on both hosts.** |
| Second-biggest surprise | The gateway saves host `x19-x30` + `q8-q15` but **not host `x18`** — while translated code writes physical `x18`. **T0 CLOSED this at zero cost**: host x18 is ordinary caller-clobbered scratch on both BSDs (measured by poisoning it across heavy libc/pthread workloads), so no additive gateway save/restore is needed. |
| Hard blocker count (VERIFIED, code) | **8** (6 pre-probe + B5 `mincore` c_char + B6 un-gated `run_oci` caller) |
| NEEDS-ON-BOX unknowns | 12 probe groups / **46** probes (the "38" was a miscount) = 82 applicable probe×host pairs — **EXECUTED**, see §6. **71 MEASURED, 4 DOWNGRADED by verification, 1 NOT-RUN, 6 BLOCKED** (P12.2/3/4 on both hosts, behind T1+T2+T5+T9 — **zero blocked by a host capability**). Of §8.2's 15 ranked unknowns: 13 resolved, 1 partial, 1 still open (U12, settleable locally) |
| Tasks | **17** (15 shared, 2 per-OS ×2; T9 the shim is the largest and is one of the doubled ones). **Post-T0 sizing: net roughly flat, risk redistributed — T3 S–M→S, T6 M–L→S–M, T7 M→S, T10 S–M→S; T5 M→M–L; NEW T17 (S–M); T9 unchanged L but materially de-risked.** |
| Design rulings (§8.3) | **2 DECIDED by data** (fault-shim route → (a); ESR → feed the real carrier), **5 LEANS**, 1 pure taste call, 1 unanswered repo question. **Two of the three "blocks Task 1" rulings are settled; the third (`native_profile`) blocks T5, not T1** |

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

#### T0 UPDATE — CONFIRMED and sharpened on both hosts (P2.1, P2.2), with exact numbers

**SETTLED-MEASURED. Both predictions were right, and the real headers are worse than libc in
one new way each.** Use these numbers as the `_Static_assert` / `repr(C)` contract.

**freebsd-arm64 (P2.1).** Real header confirms
`struct fpregs { __uint128_t fp_q[32]; fp_sr; fp_cr; fp_flags; fp_pad; }` — **32 lanes,
sizeof 528** — where libc declares a single `u128`, so **libc mis-sizes `mcontext_t` by 496
bytes** and every downstream offset is wrong. **NEW correction to this document:** the header
tail is `mc_flags; mc_pad; __uint64_t mc_ptr /* Address of extra_regs struct */;
__uint64_t mc_spare[7];` — i.e. `mc_spare[**7**]` plus an `mc_ptr`, not `mc_spare[8]`.
`mc_ptr` is the architected SVE extension slot (`ARM64_CTX_SVE = 0x00657673`,
`ARM64_CTX_END = 0xa5a5a5a5`), so a future SVE-aware snapshot has a home.

Measured: `sizeof(mcontext_t)=880`, `sizeof(ucontext_t)=960`, `sizeof(gpregs)=272`,
`sizeof(siginfo_t)=80`, `offsetof(ucontext_t, uc_mcontext)=16`. Within `mcontext_t`:
`gp_x=0`, `gp_lr=240`, `gp_sp=248`, `gp_elr=256`, `gp_spsr=264`, `mc_fpregs=272`,
`fp_sr=784`, `fp_cr=788`, `mc_flags=800`, `mc_ptr=808`, `mc_spare=816`. From `&ucontext_t`:
`gp_elr=272`, `gp_sp=264`, `mc_spare=832`. `siginfo_t`: `si_signo=0`, `si_errno=4`,
`si_code=8`, `si_pid=12`, `si_status=20`, `si_addr=24`, **`si_trapno=40`**. `char` is
**UNSIGNED** — which is also the root cause of blocker B5.

**netbsd-arm64 (P2.2).** The suspected libc bug is **real**: real `_NGREG` is **35**
(X0–X30, SP=31, ELR/PC=32, SPSR=33, TPIDR=34) against libc's `[greg_t; 32]`, so libc's own
`_REG_ELR = 32` **is a constant out-of-bounds index** — the shim cannot read or rewrite the PC
through libc's `mcontext_t` at all. **The AArch32-alias landmine is also real and was measured
live:** in P0.5's build, `libc::_REG_R15` **did NOT error** (it resolves as the AArch32 alias
= 15) while `_REG_RIP`/`_REG_RSP`/`_REG_RCX` did — so only 3 of the 4 index constants fail
loudly. The existing const-assert (`REG_R15 == 11`) happens to catch it, but a shim that
renames the constants without re-asserting would **silently index the wrong register file**.

Measured: `sizeof(mcontext_t)=880`, `sizeof(ucontext_t)=944`,
`offsetof(uc_mcontext)=64`, `__gregs@0` (280 B), `__fregs@288` (528 B = 32×16 + fpcr + fpsr),
`__spare@816` (8 × u64), `sizeof(siginfo_t)=128` with `si_signo@0`, `si_code@4`, `si_addr@16`,
`si_trap@24`, `si_trap2@28`, `si_trap3@32`. `_REG_SP=31`, `_REG_PC=_REG_ELR=32`,
`_REG_SPSR=33`, `_REG_TPIDR=34`, `_REG_LR=30`, `_REG_FP=29`; AArch32 aliases `_REG_R11=11`,
`_REG_R15=15`, `_REG_CPSR=16`. `char_is_signed=0`.

⇒ **Conclusion UNCHANGED and now empirically grounded: write the shim in C against real
headers, or ship a locally-asserted `#[repr(C)]` pinned to exactly these numbers.**

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
this risk at all.

**T0 UPDATE — (a) is CONFIRMED-MEASURED on freebsd-arm64 and SUPPORTED on netbsd-arm64. Keep
the seam-gap workstream dropped.** freebsd P7.2 ran a controlled differential: five sequential
publications through the RW alias at the same offset with alternating expected values —
(i) clean on EXEC VA → correct; (ii) second publish, clean on EXEC VA → correct 134, **not** the
stale 42; (iii) clean on the WRITE VA only → also correct (PIPT, both aliases work);
(iv) **NO maintenance → returned the STALE value**; (v) `__builtin___clear_cache` on the EXEC
alias → correct. `DC CVAU` succeeded on a `PROT_READ|PROT_EXEC` alias with no write permission,
exactly as the architecture says (permission-checked as a read). netbsd P7.2 reproduced (i),
(iii) and (v) but — honestly self-reported — case (iv) **also** passed there, so that box could
not demonstrate *necessity*; `CTR_EL0` L1Ip=3 (PIPT) corroborates the architectural argument.
**Two consequences:** the shared `carrick-dsr` trait signature (exec pointer only) needs no
change, AND the ~20-LoC `__clear_cache` VARIANT is **mandatory and urgent** because case (iv)
is a measured silent-staleness bug. Scope note: tested only on a single ≤1-line region — range
flushing across a multi-page code cache is architecturally safe but extrapolated. Also
FreeBSD-and-Apple-Silicon-specific: do not generalize the PIPT observation to other aarch64
hosts.

Guest `dc cvau`/`ic ivau` are decoded as sensitive exits
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

### 3.2 What the BSD aarch64 hosts ARE — **SETTLED-MEASURED (P1.1/P1.2/P1.3, both guests)**

**Both guests are 4096-byte-page hosts. Scenario A is the live one, unconditionally.**
Three independent sources agree on each box, and the third is a real VM granule, not a
reported constant:

| | freebsd-arm64 | netbsd-arm64 |
|---|---|---|
| `getconf PAGESIZE` | 4096 | 4096 |
| `sysctl hw.pagesize` | 4096 | 4096 |
| `sysconf(_SC_PAGESIZE)` / `getpagesize()` | 4096 / 4096 | 4096 / 4096 |
| real granule (P1.3) | `procstat -v` shows the `mprotect`'d middle page as its own **exactly 4096-byte** `r--` entry (`0x…844000-0x…845000`), neighbours uncoalesced | `/proc/curproc/map` shows a distinct 4096-byte entry `curprot=---`, `maxprot=rw-` |
| `hw.machine` / `hw.machine_arch` | `arm64` / `aarch64` | `evbarm` / `aarch64` |

**Do not misread FreeBSD's `hw.pagesizes = { 4096, 65536, 2097152, 1073741824 }` as
Scenario C** — that is the *superpage* list; the base page is 4096.

Consequences, now unconditional:
- The new `page_profile` arm takes `x86_native_plan`'s **values** (§3.3 Scenario A).
- The linux4k guarded/composed apparatus is **unreachable** (`uses_linux4k_subpages()` is
  `host == 16K && linux == 4K`, false at 4096/4096).
- §3.4's dormant trap is **live design surface**, not theory — see §3.4's T0 UPDATE.
- A 4096/4096 `NativeMappedMemory` is both constructible **and enforceable**: unlike the
  16K macOS host where the existing 4096 unit tests run, these hosts genuinely enforce a
  4096-byte protection granule, so §3.7's never-run-end-to-end surface can be exercised for
  real.
- Bonus corroboration the freebsd probe agent did not claim: its own probe base
  `0x40e6cb843000` is 4K- but **not** 16K-aligned, which alone falsifies a 16K granule.

The pre-probe reasoning that follows is kept for provenance.

### 3.2 (pre-probe) What the BSD aarch64 hosts likely are — and this is NOT verified

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

#### T0 UPDATE — the trap is REACHABLE, and the "host W^X policy" framing was WRONG

**SETTLED-MEASURED that the geometry predicate is open (P1.1 ×2 ⇒ 4096/4096), and
SETTLED-READ, during this write-up, that the mechanism is NOT a host-W^X-policy workaround.**

The two probe agents reached opposite recommendations here, and **both** rested on the same
mistaken premise — that the W↔X flip exists because the *host* forbids RWX. Direct read
refutes it:

- `native16k_host_prot()` (`mapped_memory.rs:3879-3889`) strips `PROT_EXEC` from a guest page
  **unconditionally, at every geometry, on every host**. A guest page is never host-executable
  under DSR — guest code is translated, not run in place.
- `make_native16k_write_exec_page_executable()` (`:1694-1724`) therefore does **not** grant
  `PROT_EXEC`. It calls `native_clear_icache` and re-applies `native16k_host_prot(prot)`,
  i.e. it returns the page to **read-only + icache-clean**.

So the mechanism is **self-modifying-code / translation-cache coherence detection**: a guest
`PROT_WRITE|PROT_EXEC` page is host-mapped read-only *specifically so the guest's first write
traps*, letting carrick invalidate translations before the guest executes the new bytes. That
requirement is host-policy-independent. It follows that:

- **The freebsd-arm64 probe agent's headline recommendation — "the host permits RWX (P7.3),
  therefore disarm the whole native16k write-exec mechanism rather than port it" — is
  REFUTED. Do not plan on it.** Disarming it would silently break SMC detection for any guest
  holding an RWX mapping. FreeBSD permitting RWX (measured: `mmap(RWX)` and
  `mprotect(RW→RWX)` both succeed and execute) is real and useful — it means the *host JIT*
  has no policy obstacle — but it says nothing about guest pages.
- **The mechanism must stay armed at 4K, so the WnR bit must be supplied.** On netbsd-arm64
  that is free: `si_trap` bit 6 is present and correct (P6.3, measured — WnR=1 for a store to
  a `PROT_READ` page, 0 for a load from `PROT_NONE`, with identical `si_code` in both cases).
  On freebsd-arm64 it is genuinely absent (P6.3, measured: the write-to-RO and read-of-NONE
  cases produce **identical** payloads in every field, `si_trapno=36` both) ⇒ FreeBSD **must**
  use the metadata-derived WnR above. That mitigation is therefore **required, not optional**,
  and it is FreeBSD-only.
- **The `:1648-1651` vs `:1631` asymmetry is still a real bug to fix in T5**: at 4096 the
  fault path is armed while `has_native16k_write_exec_pages()` → `native16k_vfork_rejection`
  silently disarms. P7.5 measured that the host permits the sequence (a FreeBSD vfork child
  executed the parent's W|X page, exit 0), so nothing at the OS level stops a guest from
  reaching the disagreement. Re-gate both on the **same** predicate.
- The "deeper defect" framing stands, but the correct predicate is **"does this geometry need
  SMC write-trapping?"** (answer: always, under DSR) — *not* a host W^X policy predicate.
  §3.5's decision (i) should be re-read with that substitution.

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

#### T0 UPDATE — the ruling still stands open, but its content changed

**The data LEANS decision (i) (`native_profile: None` + an explicit re-gate), but not for the
reason §3.4 originally gave.** Per §3.4's T0 UPDATE, the W↔X flip is **SMC-detection**, not a
host-W^X-policy workaround — so the predicate to re-gate it on is *"does this geometry need SMC
write-trapping?"* (always, under DSR), **not** a host W^X predicate. Under decision (i) the
mechanism therefore stays **armed** at 4096/4096, exactly as `native16k_write_exec_page()`
already does, and the T5 work reduces to:
1. fix the `:1648-1651` vs `:1631` asymmetry so the **vfork refusal** and the **fault path**
   agree at 4096 (measured host-reachable: freebsd P7.5);
2. supply the WnR bit — free on NetBSD (`si_trap` bit 6), metadata-derived on FreeBSD;
3. rename the geometry-proxy predicates so nothing reads "16K" as "needs SMC trapping".

What decision (i) still costs, unchanged: `native_profile: None` turns OFF the profile-keyed
policy set at `dispatch/mem.rs:1111/1138/3577`, including the shared-W|X refusal at `:1114-1116`
that is LIVE on Darwin today. That is the trade-off the maintainer must weigh (§8.3 Q2) and the
probes did not touch it. Two facts that make (i) cheaper than it looked: the exec capsule is
not needed on BSD (weld #3, and freebsd P0.5b confirmed the x86 BSD lane emulates execve
in-process), and virtual-ptrace is a legitimate follow-on given **both** hosts have HW-debug
limitations anyway (FreeBSD: no `TRAP_HWBKPT` in `signal.h`; NetBSD: no `PT_GETDBREGS` at all).

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

### 4.2 The actual FSGSBASE-class risk #1: ESR_EL1 — **SETTLED-MEASURED, and it is IN SIGINFO on both hosts (but differently)**

#### T0 UPDATE — read this before the pre-probe analysis below

**The pre-probe claim "ESR_EL1 does not exist on either BSD" was correct about the
*mcontext* and WRONG about the *signal frame as a whole*.** P2.3 found an ESR carrier in
`siginfo` on both hosts. **The two hosts are NOT equivalent and must be planned separately.**

**netbsd-arm64 — `siginfo_t.si_trap` is the RAW 32-bit ESR_EL1 word. SETTLED-MEASURED.**
Nine exception classes provoked; every syndrome independently re-decoded by the verifier
against the ARM ARM and found architecturally exact:

| Provoked fault | `si_trap` | decode |
|---|---|---|
| store to `PROT_READ` page | `0x9200004F` | EC 0x24 data abort, DFSC 0x0F permission-L3, **WnR=1** |
| load from `PROT_NONE` page | `0x92000007` | EC 0x24, DFSC 0x07 translation-L3, WnR=0 |
| execute `PROT_NONE` | `0x82000007` | EC 0x20 instruction abort, IFSC 0x07 |
| execute RW-no-X | `0x8200000F` | EC 0x20, IFSC 0x0F |
| `BRK #0` | `0xF2000000` | EC 0x3C |
| `UDF` | `0x02000000` | EC 0x00 + IL |
| `mrs cntpct_el0` | `0x6232f841` | EC 0x18; ISS operands decode to **exactly CNTPCT_EL0** (Op0=3/Op1=3/CRn=14/CRm=0/Op2=1, direction=read) |
| misaligned SP then push | `0x9A000000` | EC 0x26 SP alignment |
| `PT_STEP` | `0xCB000022` | EC 0x32 software step, ISV=1, ISS.IFSC=0b100010 |

`si_addr` carries FAR. `si_trap` is at byte offset 24, `si_trap2` at 28, `si_trap3` at 32.
`mcontext.__spare[8]` is all-zero in every case — the ESR is in siginfo, not the mcontext.
Verifier note: **no amount of header-reading produces correctly-encoded MSR-trap ISS operand
fields for three different system registers. This is a genuine measurement.**
⇒ On NetBSD the shim feeds `si_trap as u32 as u64` straight into
`lower_el0_fault(esr, pc, addr)` and `el0_debug_signal(snapshot.esr)` with **no synthesis and
no decision change**.

**freebsd-arm64 — `siginfo_t.si_trapno` is the ESR **EC field only**. SETTLED-MEASURED.**
Twelve provoked faults plus ptrace single-step: data abort (all four variants) → 36 = `0x24`;
instruction abort (all three variants) → 32 = `0x20`; `BRK #0` and `BRK #1` → 60 = `0x3c`;
`mrs cntpct_el0` → 24 = `0x18`; `UDF` and `raise()` → 0; `PT_STEP` → 50 = `0x32`.
Cross-checked against `/usr/include/machine/armreg.h:660-662` (`ESR_ELx_EC_SHIFT 26`).
Reachable from a tracer too: `PT_LWPINFO` embeds a full `struct __siginfo`
(`sys/ptrace.h:147`). **What is NOT available: the entire ISS.** No DFSC, **no WnR bit**, no
FAR (`si_addr` substitutes). `mc_spare[0..6]` / `mc_ptr` / `mc_flags` carry nothing
fault-related (measured across every fault: spare all-zero, `mc_flags` always
`0x1 = _MC_FP_VALID`, `mc_ptr` a constant per-process pointer). `machine/frame.h:51-52` DOES
have `tf_esr`/`tf_far` in the kernel trapframe, but `machine/reg.h:40-46 struct reg`
(`PT_GETREGS`) has only `x[30]/lr/sp/elr/spsr` — the kernel deliberately drops ESR/FAR at
**both** the signal and ptrace register boundaries. `mrs esr_el1` / `far_el1` SIGILL at EL0.

**⚠️ CORRECTION the plan must carry — the FreeBSD synthesis formula.** The probe report
headlined `esr = si_trapno << 26`. **That is insufficient, and the report's own P6.1 data
refutes it.** `el0_fault_signal` (`vcpu_loop/signal.rs:86-109`, re-read during this
write-up) reads **both** fields:

```rust
let ec   = (esr >> 26) & 0x3f;
let dfsc =  esr        & 0x3f;
let segv_code = if (0x0c..=0x0f).contains(&dfsc) { SEGV_ACCERR } else { SEGV_MAPERR };
match ec { 0x24 | 0x25 => if dfsc == 0x21 { SIGBUS/BUS_ADRALN } else { SIGSEGV/segv_code }, … }
```

With `dfsc = 0` the function returns `SEGV_MAPERR` **unconditionally** and can **never**
return `SIGBUS/BUS_ADRALN`. But P6.1 measured FreeBSD delivering `SEGV_ACCERR` in 4 of 7
fault cases and `SIGBUS/BUS_ADRALN` for a misaligned `LDXR`. **The contract is therefore:**

```
esr = (si_trapno as u64) << 26 | dfsc_from(si_signo, si_code)
      // 0x0c  when si_code == SEGV_ACCERR   (permission fault)
      // 0x21  when (si_signo, si_code) == (SIGBUS, BUS_ADRALN)
      // 0x00  otherwise (translation fault)
```

Partial self-healing, worth knowing but not relying on: `upgrade_protection_si_code`
(`signal.rs:126-146`) already recovers MAPERR→ACCERR from carrick's own protection metadata
on the guest-page path, so the ACCERR half is semi-redundant. The BUS_ADRALN half is not.

**Also scoped: the "§4.2 collapses from M-L to S" claim is FreeBSD-*and*-NetBSD-true but for
different work.** The freebsd probe report stated the collapse unscoped; §4.2 covers both
BSDs and `si_trapno` is a FreeBSD field with no NetBSD analogue (NetBSD's is `si_trap`, a
different mechanism). Post-probe sizing: **T6 goes M–L → S–M**, where the residual work is
(a) the FreeBSD DFSC synthesis above, (b) a shim-side fail-closed default for unrecognized
EC values, and (c) the `el0_debug_signal` input, which now needs **no** change on either host.

**Residual gaps in the ESR story, honestly:**

- **FreeBSD si_trapno was measured for 6 EC values only** (0x00, 0x18, 0x20, 0x24, 0x32,
  0x3c). **NOT measured: 0x30 (HW breakpoint), 0x34 (watchpoint), 0x2c (SIGFPE/FP exception),
  0x07 (SIMD/FP access trap), 0x2f (SError).** The probe report presented 0x30/0x34 as though
  measured; the verifier **DOWNGRADED them to INFERRED from the ARM EC table** — no hardware
  breakpoint or watchpoint was ever armed. Since `esr.rs:19-25` maps `0x30|0x31` and
  `0x34|0x35` → `TRAP_HWBKPT`, this is directly load-bearing for the ptrace / Go
  `TestDebugCall` path. **A shim that assumes "si_trapno is always the EC" must fail closed on
  an unrecognized value.** Cheap follow-up probe.
- **SIGFPE (EC 0x2c) was probed on neither host**, yet
  `carrick-native-netbsd/src/fault.rs:47-48` lists
  `GUEST_FAULT_SIGNALS = [SIGSEGV, SIGBUS, SIGFPE, SIGILL]`. Small residual on both lanes.
- **EC 0x26 (SP alignment) is not in `el0_fault_signal`'s match** (it handles only
  0x20/0x21/0x24/0x25), so the NetBSD-measured SP-alignment ESR falls to `_ => None` → fatal.
  Pre-existing on Darwin too, but "feed `si_trap` in unchanged" glosses over it.
- **NetBSD's `si_trap` is a 32-bit `int`**, so ESR's ISS2 (bits 55:32 on ARMv8.7+) is
  truncated. Carrick reads nothing there today.
- **libc exposes neither field**, so §2.1's "write the shim in C / a locally-asserted
  `repr(C)`" conclusion **survives independently of the ESR result**.

**Instruction-vs-data abort discrimination: SETTLED-MEASURED on both, two ways.** (1) EC:
0x20 vs 0x24, no overlap on either host. (2) Even ESR-free: `si_addr == elr` for every
instruction abort and for no data abort. **But use the EC as primary** — freebsd measured a
misaligned `LDXR` (a *data* abort) that ALSO had `si_addr == elr`, so the address test alone
is unsound.

**si_code fidelity vs Linux — the two hosts differ, and NetBSD is the divergent one:**

| Case | freebsd-arm64 | netbsd-arm64 | Linux |
|---|---|---|---|
| read unmapped | SEGV_MAPERR | SEGV_MAPERR | SEGV_MAPERR |
| permission fault | **SEGV_ACCERR** | **SEGV_MAPERR** (divergent) | SEGV_ACCERR |
| `BRK #0` | SIGTRAP/TRAP_BRKPT | SIGTRAP/TRAP_BRKPT | same |
| `PT_STEP` | SIGTRAP/TRAP_TRACE | SIGTRAP/TRAP_TRACE | same |
| `UDF` | SIGILL/ILL_ILLTRP | SIGILL/**ILL_ILLTRP** (Linux: ILL_ILLOPC) | ILL_ILLOPC |
| misaligned exclusive | SIGBUS/BUS_ADRALN | **no fault at all** — ⛔ DOWNGRADED, see below | SIGBUS/BUS_ADRALN *(architectural; not measured on Linux here)* |
| plain misaligned load | **no fault** | no fault | no fault to normal memory *(architectural)* — so this is **not** the LTP-fidelity difference the freebsd report called it |
| HW breakpoint/watchpoint | `TRAP_HWBKPT` **not defined in signal.h** (though `PT_GETDBREGS`=37 exists); EC 0x30/0x34 **INFERRED, not measured** | `PT_GETDBREGS`/`PT_SETDBREGS` **do not exist** ⇒ HW debug unreachable via ptrace | TRAP_HWBKPT |

⇒ **Decode the ESR carrier, do not trust `si_code`.** On NetBSD `si_code` is wrong for
permission faults where `si_trap`'s DFSC 0x0F is right. This is the strongest argument for
plumbing the ESR carrier rather than a `(signal, si_code)` pair.

**⛔ DOWNGRADED BY VERIFICATION — do not plan on this:** netbsd P6.1(d) reported
"misaligned `LDXR`/`LDAXR`/`STXR`/`LDAR`/`CASAL`/`LDP` → **no fault at all**". The verifier
flagged this as **contradicting the ARM ARM**, which mandates an alignment check on exclusives
and acquire/release regardless of `SCTLR_EL1.A`, and the guests run **hvf-accelerated on Apple
Silicon** (`bsdvm.py:148 -accel hvf`) where it should fault. freebsd-arm64 measured the
opposite (`SIGBUS/BUS_ADRALN` for misaligned `LDXR`) on the same silicon, which all but
confirms a netbsd probe-construction error. **Treat as a probe bug; re-probe if any
guest-SIGBUS conformance depends on it.** Note the netbsd agent's inference — that the
`EC 0x24 + DFSC 0x21 → SIGBUS/BUS_ADRALN` lowering "can essentially never fire on Apple
silicon, and Darwin/HVF shares it" — rests on that bad datum and must not be carried.

The pre-probe analysis below is kept for provenance; its `mcontext` inventory is still
correct and still the reason the shim cannot go through libc.

---

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

#### T0 UPDATE — x18 is FREE on both hosts. §4.3's uncomfortable branch does NOT materialize.

**SETTLED-MEASURED (P5.1, P5.2, P5.3 on both guests). The unhedged best case is what
happened.** The load-bearing probe is the **poison test**, and it is the one to cite: x18 was
poisoned before heavy libc/libthr/libpthread workloads (200 malloc/free cycles, stdio,
`pthread_mutex`, `mmap`, 4 concurrent `pthread_create`+join, signal round trips) and **every
path completed correctly** ⇒ host userland reads **no incoming x18**, on either host.

| | freebsd-arm64 | netbsd-arm64 |
|---|---|---|
| x18 refs in the threading lib | `libthr.so.3`: **0** | `libpthread.so`: **0** |
| x18 refs in libc | `libc.so.7`: 847, all plain scratch-temp shapes | `libc.so`: 2016, plain compiler temporaries (`ldr/ldp/eor/ror/bic`) |
| rtld | `ld-elf.so.1`: 177, incl. `ldr x18,[x0,#0xa0]` in `__tls_get_addr` (scratch) + one conservative `stp x17,x18` / `ldp x17,x18` caller-preserve pair in the lazy-binding trampoline | `ld.elf_so`: 11, incl. the same `stp x17,x18,[sp,#112]` / `ldp` trampoline pair |
| `-ffixed-x18` in base build flags | none in `/usr/share/mk` | none in `/usr/share/mk` |
| poison test | all paths correct; workload left x18 = `0x400` | all paths correct; workload left x18 = `0xa` / `0xffffffff` |
| mcontext x18/x28 read+write across sigreturn (P3.3) | **both honored** | **both honored** |

**⚠️ FRAMING CORRECTION the verifier insisted on, and it matters for planning.** The
freebsd report headlined "x18 is preserved across every syscall/libc/libthr/pthread_create/
signal boundary". That over-generalizes and is contradicted by its own P5.3: a heavier
workload including 4× `pthread_create`+join left x18 = `0x400`. netbsd measured the same
shape (`pthread_create` alone clobbers → `0xa`). **The correct statement is: x18 is ordinary
caller-clobbered scratch — incidentally preserved on some libc paths, clobbered on others.**
Nobody may conclude carrick can park data in physical x18 across a libc call. Both *decisions*
below are unaffected — in fact the clobber datum strengthens them.

**Decisions now settled for both lanes:**
- **Weld #1 (custom-x18 ABI) collapses to a genuine ~20-LoC no-op.** No `dlsym`, no
  TPIDR_EL0 bit-48 toggle, no host-glue remedy needed. Neither OS has (or needs) an opt-in.
- **No emitter change.** The `emit.rs:805-816` physical-x18 scratch window stays; the
  `emit.rs:2035`/`:2226` biased-memory uses stay; no translator register reassignment.
- **Better than Darwin in one respect:** both BSD kernels round-trip mcontext x18 **and** x28
  through the signal frame (measured both readable and writable), where
  `csrc/native_darwin.c:361-364` deliberately refuses to read them and `:464` documents
  Darwin's unreliability. So a BSD shim may recover the x28 context pointer from the mcontext
  **directly**, making the 16-byte recovery slot a redundancy rather than the only channel —
  and it may drop Darwin's `preserve_virtual_registers` exclusion of indices 18/28 and
  snapshot the full register file. Strictly simpler than the Darwin path.
- Caveat on the `physical_x18` link: `gateway.rs:420 physical_x18: context.exit_link` is fed
  from the gateway's own context, **not** from the mcontext, so "P3.3 proves `physical_x18` is
  satisfiable" is a loose inference (inherited from this document's own P3.3 framing). The
  mcontext round-trip result stands on its own.

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

#### T0 UPDATE — **CLOSED at zero cost on BOTH hosts. Remove this item from the inventory.**

**SETTLED-MEASURED (P5.3 ×2).** The first disjunct is proven: host userland treats x18 as
caller-clobbered scratch on both BSDs. The decisive evidence is not "x18 was preserved" (it
sometimes was, sometimes was not) but the pair of facts that (a) a **poisoned** x18 never
disturbed any libc/libthr/libpthread path, and (b) libc/gcc **allocate x18 as an ordinary
temporary** (847 refs FreeBSD, 2016 NetBSD) — which by definition makes it call-clobbered, so
a callee (carrick's gateway) destroying it is safe. `grep -n 'x18\|w18' gateway_aarch64.S`
yielding only two **comment** hits (lines 21, 84) is therefore SAFE on both hosts.

⇒ **T7 loses its "+ the x18 delta". The Mach-O→ELF port stays a pure symbol rename with no
additive host save/restore work.** The rtld `stp x17, x18` trampoline pair on both hosts is a
transparent-interposition caller-preserve courtesy, not a live-state claim — and it is
actually protective for carrick.

### 4.5 EL0 system-register accessibility — the third candidate

`CNTVCT_EL0`/`CNTFRQ_EL0` are architecturally EL0-readable but gated by
`CNTKCTL_EL1.EL0VCTEN`/`EL0PCTEN`, and `dc cvau`/`ic ivau` by `SCTLR_EL1.UCI` — both
**kernel policy**. The aarch64 lane emits a **direct** `mrs CNTVCT_EL0` for guest counter
reads (`decode.rs:1103-1106` → `CounterRead`) and passes `mrs CNTFRQ_EL0` straight through
(:1107-1111). The run loop's `SensitiveKind::ReadCounter` arm is `#[cfg(target_os="macos")]`
with a non-macOS arm returning `Unsupported("native DSR counter fallback requires macOS")`
(`native_darwin.rs:2184-2202`). If either BSD traps these at EL0, that is an FSGSBASE-shaped
SIGILL before any guest instruction — hence probe group **P4** in §6.

#### T0 UPDATE — **NO FSGSBASE-shaped blocker on either host. SETTLED-MEASURED (P4.1 ×2).**

Every load-bearing op is permitted at EL0 on both guests:

| Op | freebsd-arm64 | netbsd-arm64 |
|---|---|---|
| `mrs cntvct_el0` | **OK** | **OK** |
| `mrs cntfrq_el0` | OK = 24 000 000 | OK = 24 000 000 |
| `mrs ctr_el0` | OK `0x9444c004` | OK `0x9444c004` (IminLine/DminLine 64 B, **L1Ip=3 = PIPT**) |
| `mrs dczid_el0` | OK = 4 | OK = 4 |
| `dc cvau` + `dsb ish` + `ic ivau` + `isb`, `dc civac`, `dc zva`, `__clear_cache` | **all OK**, incl. `dc cvau`/`ic ivau` on a `PROT_READ\|PROT_EXEC` page | **all OK**, incl. on an `r-x` page |
| `clrex`, `mrs/msr nzcv`, `fpsr`, `fpcr`, `tpidr_el0` (r+w), `tpidrro_el0` | all OK | all OK |
| `mrs cntpct_el0` | **SIGILL** (`si_code=5 ILL_PRVREG`, EC 0x18 trapped-MSR) | **SIGILL** (EC 0x18) |
| `mrs midr_el1`, `id_aa64isar0_el1`, `id_aa64pfr0_el1` | **OK** (kernel-emulated) | **SIGILL** (EC 0x18) |
| `mrs cntkctl_el1 / esr_el1 / far_el1 / sctlr_el1` | SIGILL (expected) | SIGILL (expected) |

⇒ **`SCTLR_EL1.UCI = 1` and `CNTKCTL_EL1.EL0VCTEN = 1` on both**, which closes §2.2(a)'s last
open caveat *empirically* (not just architecturally) and makes `decode.rs:1103-1111`'s direct
`mrs CNTVCT_EL0` / `CNTFRQ_EL0` pass-through correct on both hosts.

**Two NEW risks this probe surfaced, both to be recorded rather than fixed now:**
1. **`CNTPCT_EL0` is DENIED at EL0 on both hosts** (`CNTKCTL_EL1.EL0PCTEN = 0`,
   `EL0VCTEN = 1`). Any guest or host path reading the **physical** counter SIGILLs. The
   counter plan must be strictly **virtual-counter-only**. Note this is a **Linux-fidelity
   gap**: `CNTPCT_EL0` *is* EL0-readable on Linux/aarch64, and `decode.rs:250/1103/1107`
   handles only CNTVCT/CNTFRQ — so a guest `mrs CNTPCT_EL0` will SIGILL where Linux succeeds.
2. **NetBSD SIGILLs on `MIDR_EL1` and the `ID_AA64*` registers where FreeBSD emulates them.**
   A Linux guest reading `MIDR_EL1` cannot be served by host pass-through on NetBSD. This is a
   pre-existing shape shared with Darwin, not campaign-caused, but it is a per-host asymmetry.

**Host counter plan: `HostCounterPlan::Inline{Cntvct, 1:1}` is CORRECT on both.
SETTLED-MEASURED (P4.2 ×2).** `CNTFRQ_EL0 = 24 MHz`; FreeBSD measured 23 999 760 Hz over a
300 ms nanosleep (ratio 0.999990) with **0 regressions across 200 000 samples**; NetBSD
measured monotonic over 100 000 reads with a correct rate. `plan_for_mode(Some(1), ..)` needs
no scale and no fallback tick source for correctness — architecturally **simpler** than
Darwin's commpage-mode read. `counter.rs` still needs a non-macOS `fallback_counter_ticks()`
body, but it is just `mrs cntvct_el0`.
**Two caveats:** (i) **do not hardcode 24 MHz** — that is the QEMU/HVF virt value (identical
to Apple Silicon, which is why it looks right); bare-metal arm64 will differ, so the 1:1 claim
must be re-measured if the lane ever runs off these VMs. (ii) **STILL-OPEN:** §6's P4.2 asked
whether `CNTVCT_EL0` stays monotonic **across a host suspend**. Neither guest tested that —
200k tight samples and a 300 ms sleep are not a suspend. On a QEMU/HVF guest on a Mac that can
sleep, this is a real open question. **Report as OPEN, not settled.**

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

#### T0 UPDATE — both residual risks measured

- **ET_EXEC: SETTLED on the host side, STILL-OPEN on the loader side.** P12.1 (run on the Mac,
  independently re-run byte-for-byte by **both** verifiers) confirms all 8 fixtures are
  **ET_EXEC**, machine 183, load base `0x200000`, entries `0x210120` (×4, 4 phdrs) /
  `0x210158` (×4, 5 phdrs), `GNU_STACK` RW, and — the fact that matters most —
  **`p_align = 0x10000` on EVERY LOAD segment, i.e. 16× the 4096-byte host page.** P10.2
  measured that **both** hosts grant those exact addresses via `MAP_FIXED`
  (`0x200000`/`0x210000`, and a 3-page span), and P10.1b measured that a real **Rust (PIE)**
  host process leaves the whole window free (zero mappings below 16 MiB across three ASLR'd
  runs). ⚠️ Two things this does **not** settle: whether the aarch64 **load-plan rounding
  tolerates `p_align` > host page size** (untestable without a lane — **read that code before
  T14**), and the fact that a **non-PIE** carrick host would land at `0x200000` itself and
  collide exactly (P10.1b measured a plain `cc` FreeBSD binary doing precisely that) — so the
  free window is a property of Rust's PIE default, not of the OS.
- **Building fixtures on the guests: CONFIRMED IMPOSSIBLE on both** (P0.8 ×2) — neither
  sysroot carries an `aarch64-unknown-linux-musl` std and neither box has rustup. Cross-build
  on the Mac and commit, as written. Minor correction: **`rust-lld` IS present** in the
  freebsd guest's sysroot (absent on netbsd), so on FreeBSD the script trips its *target*
  guard at `:11-14`, not its *linker* guard at `:17-20`.

### 5.4 The blockers between here and a stage2 command — **now EIGHT, all MEASURED**

#### T0 UPDATE — status of every blocker, plus two new ones

| Blocker | Pre-probe status | T0 status |
|---|---|---|
| **B1** carrick-native-{freebsd,netbsd} x86 welds | read from source, never observed | **CONFIRMED-MEASURED on both, line-exact.** freebsd: **9 errors** — `tsc.rs:87,89` (E0433 `std::arch::x86_64`) + `fault.rs:167,177,180,188,209,216,225` (E0609 `mc_rip`/`mc_r15`/`mc_rcx`). A 3-line arch-gate in `lib.rs` (`pub mod fault`, `pub mod tsc`, `fn vdso_tsc_calibration`) clears it with no other fallout. netbsd: **9 errors** — `fault.rs:55,56,58` (`_REG_RIP`/`_REG_RSP`/`_REG_RCX`) + 6 `invalid register` operands in `fsbase.rs:98-103`. **Caveat from the netbsd verifier: 9 is a FLOOR, not the worklist size** — `fsbase.rs:65-77`'s `#[unsafe(naked)] naked_asm!` body is pure x86 mnemonics with only `const` operands, so it fails at *codegen*, which never runs because type-check aborted. Expect a 10th break after the first pass. |
| **B2** `platform-freebsd` compile break | "at least seven more" refs | **CONFIRMED-MEASURED and LARGER: 10 distinct errors** in `carrick-runtime/src/lib.rs` — `:399` (E0432 `make_bhyve_futex`), `:771`, `:775`, `:779`, `:787`, `:868`, `:900`, `:911`, `:2079`, **plus `:589` (E0425 `run_oci`) = the new B6.** **The link-edge half is REFUTED for FreeBSD:** `/usr/lib/libvmmapi.so.7` + `libvmmapi.a` **EXIST** on FreeBSD 15.1/aarch64 (bhyve/arm64 is a thing), `cc -lvmmapi` links rc=0, and `cargo build -p carrick-vmm-bhyve` compiles clean. So B2 is purely arch-gated-Rust-items — same decision (VMM-less feature pair), **different justification** from NetBSD. |
| **B3** `platform-netbsd` link break | expected physical absence | **CONFIRMED-MEASURED as HARD-IMPOSSIBLE:** no `/usr/lib/libnvmm*`, no `/usr/include/nvmm.h`, no `/dev/nvmm` on NetBSD/aarch64. Also: `--features platform-netbsd` dies at B1's 9 errors and **never reaches** the `-lnvmm` edge — confirming §5.2's constraint that stage2 must `test`/`build`, never `check`. |
| **B4a** usdt-impl 0.6.0 E0308 (freebsd) | observed in a gate report | **REPRODUCED verbatim at HEAD** (`usdt-impl-0.6.0/src/no-linker.rs:166 modname[i] = byte as i8` vs `:171 [c_char; 64]`). **The open "worth 5 minutes on crates.io" question is SETTLED: crates.io's LATEST usdt/usdt-impl IS 0.6.0** (`max_version = 0.6.0`, 2025-09-05; verified independently by the verifier via the crates.io API) ⇒ **there is NO upstream release to bump to.** Fix is **one line**; `s/byte as i8/byte as std::os::raw::c_char/` makes **`carrick-observability` AND `carrick-thread`** both build clean, and nothing else in the chain is `c_char`-sensitive. Recommend `[patch.crates-io]` on a vendored usdt-impl (there is no `[patch.crates-io]` in the workspace `Cargo.toml` today). **NetBSD is unaffected — confirmed by build:** `carrick-observability` compiles there in 5.88 s (usdt 0.6.0 builds as the pure-Rust no-op). **Reverse-dep tree measured:** usdt reaches carrick-observability/runtime/vmm-hvf → aarch64, thread, vmm-{kvm,bhyve,nvmm}, engine, cli; it does **NOT** reach carrick-dsr-aarch64/dsr/mem/host/hal/portable — proven independently by P0.4's green build, so `-p carrick-dsr-aarch64` avoids it entirely. |
| **B4b** bindgen/libclang (netbsd) | observed in a gate report | **CONFIRMED and CLOSED BY PROVISIONING.** `pkg_add -U clang` (pkgsrc 10.0_2026Q1 aarch64) installs clang-19.1.7nb2 + llvm-19.1.7nb1 → `/usr/pkg/lib/libclang.so.19.1.7`; with `LIBCLANG_PATH=/usr/pkg/lib`, bad64-sys's bindgen succeeds. |
| **B4c** predicted second bindgen failure (freebsd) | PREDICTED | **CONFIRMED.** Base FreeBSD/aarch64 ships clang 19.1.7 **binaries** but **no shared libclang** (`ls /usr/lib/libclang.so*` and `/usr/local/llvm*/lib/libclang.so*` both empty). `pkg install -y llvm19` (261 MiB download / 2 GiB installed, pulls libedit+lua53) provides `/usr/local/llvm19/lib/libclang.so.19.1.7`; with `LIBCLANG_PATH` set, bad64-sys builds and carrick-dsr-aarch64 produces a 31 MB rlib. **100% provisioning, no code change.** |
| **B5 — NEW** | not on any list | **`crates/carrick-dsr/src/identity_memory.rs:1365` `let mut residency = vec![0i8; pages];` passed to `libc::mincore(_, _, *mut c_char)` at `:1373`.** `c_char` is **UNSIGNED** on aarch64 everywhere except Apple ⇒ unconditional E0308. **Measured on BOTH guests; source-verified independently by BOTH verifiers**, including that the file's only `target_os` gates are at `:2634+` inside the `#[cfg(test)]` module opened at `:2630` — so this is unconditional **production** code in a crate §1.3 lists as SHARED-ALREADY with "zero arch gates in production code". **It blocks `carrick-dsr-aarch64`, i.e. the aarch64 translate engine, exactly as bindgen does.** One-line fix: `vec![0 as libc::c_char; pages]`; the sibling site at `:674` already uses the correct portable `.cast::<libc::c_char>()` form, and grep shows `:1365` is the only hardcoded-`i8` site in `crates/*/src`. **Must land before or with the libclang provisioning or nothing downstream builds.** By the same mechanism it must also break aarch64-linux (INFERRED — correct by AAPCS64, unmeasured there). Cheap audit item: never hardcode `i8`/`u8` where libc says `c_char`. |
| **B6 — NEW** | not on any list | **`carrick-runtime/src/lib.rs:589 crate::runtime::run_oci(spec)` is an UN-GATED caller** inside an `impl Runtime` gated only on `any(feature = …)`, while all four `pub fn run_oci` **definitions** (`:1601`, `:1612`, `:1621`, `:1633`) are gated `all(feature = "platform-X", target_arch = "x86_64"\|"aarch64")`. This document previously read `run_oci` as "arch-gated — proof the predicate was applied unevenly"; **it is arch-gated at the definition and unresolved at the caller, so the unevenness cuts the other way.** ⚠️ **MAGNITUDE CORRECTION:** the freebsd probe report called this "5 unresolved call sites"; the verifier established it is **ONE** E0425 whose diagnostic *notes* the four cfg'd-out candidates. **Worklist item = 1 line, not 5.** The generalized lesson stands: **the arch-gating pass must gate callers, not just definitions.** |

**Two evidence-hygiene notes carried forward from verification** (the findings are real either
way, but the provenance was misstated): freebsd P0.5b's 10 runtime errors were observed **with a
scratch arch-gate patch applied** to `carrick-native-freebsd` — they cannot come from the bare
command line shown, because B1 aborts first. And freebsd P0.2's "libclang unblocked the rlib"
line omits that **B5 also had to be fixed**; the rlib post-dates both.

**STILL-OPEN on the red list:** the *full* `cargo build --workspace` list. freebsd used targeted
`-p`/`--features` invocations, so `carrick-vmm-hvf` (which has **no crate-level `#![cfg]`**) was
never enumerated there. netbsd DID capture it: with libclang + B5 fixed, `--workspace
--keep-going` yields exactly three failing units — `carrick-vmm-hvf` (16 errors, 4 classes:
E0433 `carrick_host_bsd` unresolved at `host_signal.rs:129,789,1109,1129,1139,1147`; E0433
`darwin_kqueue` at `host_signal.rs:432,434,456,458` + `timer_delivery.rs:57,59,79,81`; E0425
`wake_signal_pump_all` at `timer_delivery.rs:67`; E0615 `si_pid` at `host_signal.rs:498`),
`carrick-native-netbsd` (B1's 9), and `carrick-cli`'s `build.rs:36` which fails **closed** with a
clear diagnostic. `carrick-vmm-hvf` is **not** on the acceptance path — it appears only via
`carrick-runtime`'s `default = ["platform-macos"]`, so a VMM-less feature pair sidesteps it and
the hvf noise is a **stage1-only artifact**.

---

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

#### T0 UPDATE — timing and toolchain

- **Toolchain skew: SETTLED-MEASURED (P0.3 ×2).** freebsd-arm64 = rustc/cargo **1.96.1**
  (host `aarch64-unknown-freebsd`, LLVM 22.1.2); netbsd-arm64 = **1.91.1** (LLVM 19.1.7). Both
  are non-rustup source-tarball builds, so **`rust-toolchain.toml`'s 1.96.0 pin is inert on
  both guests** — it blocks nothing. The `fmt` corollary is confirmed and sharpened: guest
  rustfmt is **1.8.0** on netbsd vs the pinned 1.9.0. Nothing in the FreeBSD lane is
  MSRV-constrained; the constraint is entirely netbsd-arm64's 1.91.1.
- **Wall time: SETTLED for FreeBSD, NOT settled for the real stage2 command.** freebsd P0.7 is
  a genuinely cold build (`rm -rf`'d `CARGO_TARGET_DIR`) of the entire 6-crate acceptance path
  including bad64-sys's C library and bindgen: **13 s wall / 433 MB**, plus 2 s for the test
  link, against the 7200 s budget. Guest clock verified accurate first (a 10 s sleep measured
  10 s guest-side). ⚠️ **netbsd P0.7 was DOWNGRADED by verification:** its "47.64 s cold
  286-crate workspace build ⇒ budget settled" ran `--workspace --keep-going` with **rc=101**,
  meaning `carrick-runtime` — 154 673 lines in `src`, the workspace's dominant unit — **never
  compiled**. That number is a **lower bound excluding the most expensive compile**, and the
  spec's P0.7 asked for `cargo build -p carrick-runtime … --tests`. The budget is *probably*
  still fine (single-digit minutes), but **re-measure with the real command at T1**.
- The **real** stage2 risk is therefore confirmed to be the **4000-char tail truncation**, not
  the timeout. stage2 must write a JSON artifact and `cat` it.

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

## 6. THE ON-BOX PROBE PLAN — **EXECUTED (T0, 2026-07-25)**

The plan below ran on **both** guests (`freebsd-arm64` 127.0.0.1:2201, `netbsd-arm64`
127.0.0.1:2202), one agent per guest, each result then adversarially verified against the
repo by a second reviewer. **Where a verifier downgraded or refuted a probe claim, the
verifier's version is what appears in this document.**

**Status vocabulary**

| Tag | Meaning |
|---|---|
| **MEASURED** | the probe ran; command + verbatim output attached in the T0 phase record |
| **READ** | header / man-page / source citation only — no execution |
| **DOWNGRADED** | a probe claim a verifier weakened or refuted; the weakened version is what stands |
| **BLOCKED** | could not execute; the blocking error and what would unblock it are named |
| **NOT-RUN** | applicable but not executed (with the reason and the impact) |
| **N/A** | per-OS probe, not applicable to that host |

**Tally.** 12 groups / **46** individual probes (the pre-probe text said "38" — that was a
miscount; the group tables always listed 46). Of the **82 applicable probe×host pairs**:
**71 MEASURED**, 4 DOWNGRADED, 1 NOT-RUN, 6 BLOCKED (P12.2/P12.3/P12.4 on both hosts, all
behind T1+T2+T5+T9 — not behind any host limitation). **Zero probes were blocked by a host
capability.** Every raw command and its verbatim output lives in the T0 phase record; the
numbers that changed the plan are reproduced inline in §2.1, §3.2, §3.4, §4.2–§4.5, §5.4 and
§5.5 rather than only here.

### P0 — Provisioning / build unblock

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P0.1 | netbsd | **MEASURED** | **YES — the engine builds.** `pkg_add -U clang` (pkgsrc 10.0_2026Q1) → clang-19.1.7nb2 + llvm-19.1.7nb1 → `/usr/pkg/lib/libclang.so.19.1.7`; with `LIBCLANG_PATH=/usr/pkg/lib` bad64-sys's bindgen succeeds. Then blocked again by **B5** (new); one-line fix ⇒ 31 MB rlib | §5.4 B4b, B5 |
| P0.2 | freebsd | **MEASURED** | **Predicted B4c CONFIRMED.** Base ships clang 19.1.7 **binaries**, no shared libclang. `pkg install -y llvm19` (261 MiB dl / 2 GiB installed) → `/usr/local/llvm19/lib/libclang.so.19.1.7`. ⚠️ hygiene: the result line omitted that **B5 also had to be fixed** before the rlib appeared | §5.4 B4c |
| P0.3 | both | **MEASURED** | freebsd rustc/cargo **1.96.1** (LLVM 22.1.2); netbsd **1.91.1** (LLVM 19.1.7). Both non-rustup source-tarball ⇒ `rust-toolchain.toml`'s 1.96.0 pin is **inert on both**. netbsd rustfmt 1.8.0 vs pinned 1.9.0 | §5.5 T0 UPDATE |
| P0.4 | both | **MEASURED** | **The campaign's central result.** 6-crate acceptance path builds green and `cargo test -p carrick-dsr-aarch64` = **87 passed / 0 failed on BOTH**. Independently corroborated by both verifiers (91 `#[test]`s − 4 `cfg(macos,aarch64)` in `counter.rs` = 87, exact). **Scope honestly:** `build.rs:7-17` assembles the gateway only on macos+aarch64 and `gateway.rs:465+` stubs exit addresses to 0 off-Darwin ⇒ these tests **execute zero translated instructions** on a BSD | §0a, §1.3 |
| P0.5 | both | **MEASURED** | Full red list = the arch-gating worklist. freebsd: B1 = 9 errors, B2 = 10 errors incl. new **B6**. netbsd: exactly three failing units (`carrick-vmm-hvf` 16, `carrick-native-netbsd` 9, `carrick-cli` build.rs failing **closed**). ⚠️ two caveats carried: netbsd's 9 is a **floor** (`fsbase.rs:65-77` naked x86 asm fails at *codegen*, never reached); freebsd's B2 list was observed **with a scratch arch-gate applied**, not from the bare command shown | §5.4 |
| P0.6 | both | **MEASURED** | netbsd: **hard-impossible** — no `libnvmm*`, no `nvmm.h`, no `/dev/nvmm`. freebsd: **REFUTES the prediction** — `/usr/lib/libvmmapi.so.7` + `.a` EXIST, `cc -lvmmapi` links rc=0, `carrick-vmm-bhyve` compiles clean. Same decision (VMM-less feature pair), **different justification per OS** | §5.4 B2/B3 |
| P0.7 | freebsd | **MEASURED** | Genuinely cold (`rm -rf`'d target dir) 6-crate acceptance path incl. bad64-sys's C lib + bindgen: **13 s wall / 433 MB**; +2 s for the test link. Guest clock sanity-checked first | §5.5 T0 UPDATE |
| P0.7 | netbsd | **DOWNGRADED** | Reported "47.64 s cold 286-crate workspace ⇒ budget settled". Verifier: the run was `--workspace --keep-going` with **rc=101** — `carrick-runtime` (154,673 lines in `src`) **never compiled**. Lower bound excluding the dominant unit. **Budget is probably fine; re-measure with the real stage2 command at T1** | §5.5 T0 UPDATE |
| P0.8 | both | **MEASURED** | No `aarch64-unknown-linux-musl` std, no rustup, on either. ⇒ cross-build fixtures on the Mac and commit (§5.3). **Correction to this doc:** `rust-lld` **IS** present in the freebsd sysroot (absent on netbsd), so `build-linux-fixtures.sh` trips its target guard, not necessarily its linker guard | §5.3 |

### P1 — Page geometry

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P1.1 | both | **MEASURED** | **4096 on BOTH ⇒ SCENARIO A, unconditionally.** freebsd `hw.pagesize=4096`, `hw.pagesizes={4096,65536,2097152,1073741824}` (65536 is a **superpage** size — do not misread as Scenario C), `hw.machine_arch=aarch64`. netbsd `hw.pagesize=4096`, `hw.machine=evbarm` | §3.2 |
| P1.2 | both | **MEASURED** | `sysconf(_SC_PAGESIZE)` = 4096 on both — agrees with P1.1, so `page_profile.rs:225-234` and `prepared_image.rs:769-779`'s fail-closed compare both pass at lane entry | §3.2 |
| P1.3 | both | **MEASURED** | 4096 is the **real VM granule**, not a reported constant. freebsd `procstat -v`: the `mprotect`'d middle page appears as its own exactly-4096-byte `r--` entry between two `rw-` regions. netbsd `/proc/curproc/map`: same, and the map exposes **curprot AND maxprot** per entry — which independently corroborates P7.3's PaX model. Verifier bonus: freebsd's probe base `0x40e6cb843000` is 4K- but **not** 16K-aligned, which alone falsifies a 16K granule | §3.2 |

### P2 — mcontext ground truth (gates the fault-shim route)

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P2.1 | freebsd | **READ + MEASURED** | Header read (`machine/ucontext.h`) **plus** measured `sizeof`/`offsetof`. libc's single-lane `fp_q: u128` vs the real `__uint128_t fp_q[32]` mis-sizes `mcontext_t` by **496 bytes**. **NEW:** the tail is `mc_ptr` (SVE `extra_regs` slot) + `mc_spare[**7**]`, not `mc_spare[8]` | §2.1 T0 UPDATE (full offset table) |
| P2.2 | netbsd | **READ + MEASURED** | Suspected libc bug is **real**: `_NGREG` = **35** vs libc's `[greg_t; 32]`, so libc's own `_REG_ELR = 32` is a **constant OOB index**. AArch32-alias landmine measured live: `libc::_REG_R15` **resolves** (=15) while `_REG_RIP/RSP/RCX` do not | §2.1 T0 UPDATE |
| P2.3 | **both — DECISIVE** | **MEASURED** | **An ESR carrier exists in `siginfo` on BOTH hosts, but they are NOT equivalent.** netbsd `si_trap` = the **raw 32-bit ESR_EL1 word** (9 exception classes; every EC/ISS/WnR/IL bit independently re-decoded by the verifier, incl. three full MSR-trap ISS operand decodes that no header read could produce). freebsd `si_trapno` = the **EC field only** (12 provoked faults + `PT_STEP`); **no ISS ⇒ no DFSC, no WnR**. ⚠️ the freebsd report's headline formula `esr = si_trapno << 26` is **refuted by its own P6.1 data** — see the corrected contract | §4.2 T0 UPDATE |

### P3 — Signal-handler PC-rewrite round trip

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P3.1 | both | **MEASURED** | **FULLY GREEN on both.** `SA_SIGINFO\|SA_ONSTACK`, no `SA_RESTART`; handler rewrote PC (`gp_elr` / `__gregs[_REG_PC]`) **and** SP to a stub; execution resumed at the stub, SP preserved, x0 write-back honored, callee-saved sentinels intact | §1.5, §8.3 Q1 |
| P3.2 | both | **MEASURED** | The 16-byte-aligned recovery slot below the saved SP **survives sigreturn** on both. freebsd's variant is **stricter than the Darwin mechanism it models** — it left SP unchanged and read *below* it (red-zone survival), so the verdict holds a fortiori | §1.5 |
| P3.3 | both | **MEASURED** | mcontext **x18 and x28 are both READABLE and WRITABLE** across sigreturn on both hosts — **better than Darwin** (`native_darwin.c:361-364` refuses to read them). ⚠️ two caveats: `gateway.rs:420 physical_x18` is fed from the gateway's own context, not the mcontext, so "physical_x18 is satisfiable" is a loose inference; and the production slot anchors to `context->host_sp − 16` (`native_darwin.c:556-558`), not the interrupted mcontext SP the probes used | §4.3 T0 UPDATE |

### P4 — EL0 system-register accessibility

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P4.1 | both | **MEASURED** | **NO FSGSBASE-shaped blocker on either host.** `SCTLR_EL1.UCI = 1` and `CNTKCTL_EL1.EL0VCTEN = 1` on both. SIGILL only on `CNTPCT_EL0` (both) and `MIDR_EL1`/`ID_AA64*` (netbsd only — freebsd emulates them) | §4.5 T0 UPDATE (full matrix) |
| P4.2 | both | **MEASURED (steady state)** | `HostCounterPlan::Inline{Cntvct, 1:1}` is **CORRECT on both**. `CNTFRQ_EL0` = 24 MHz; freebsd ratio 0.999990 with 0 regressions/200k samples; netbsd monotonic over 100k. **Do not hardcode 24 MHz** (QEMU/HVF virt value) | §4.5 T0 UPDATE |
| P4.2 (suspend clause) | both | **STILL-OPEN** | §6 asked whether `CNTVCT_EL0` stays monotonic **across a host suspend**. Neither guest tested it — 200k tight samples and a 300 ms sleep are not a suspend. On a QEMU/HVF guest on a Mac that sleeps, this is a genuine open question | §4.5 T0 UPDATE |

### P5 — x18 clobber

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P5.1 | both | **MEASURED** | **x18 is FREE on both.** The load-bearing evidence is the **poison test**: x18 poisoned before heavy libc/libthr/libpthread workloads (malloc/stdio/mutex/mmap/4× `pthread_create`+join/signal round trips) and **every path completed correctly** ⇒ host userland reads **no incoming x18** | §4.3 T0 UPDATE |
| P5.1 (framing) | freebsd | **DOWNGRADED** | The report headlined "preserved across every boundary". Contradicted by its own P5.3 (a heavier workload left x18 = `0x400`); netbsd measured the same shape (`pthread_create` alone → `0xa`). **Correct statement: x18 is ordinary caller-clobbered scratch.** Carrick may **not** park data in physical x18 across a libc call. Both decisions below are unaffected — the clobber datum strengthens them | §4.3 T0 UPDATE |
| P5.2 | both | **MEASURED** | No toolchain reservation anywhere. Threading lib x18 refs: **0** on both. libc: 847 (freebsd) / 2016 (netbsd), all plain compiler temporaries. No `-ffixed-x18` in `/usr/share/mk` on either | §4.3 T0 UPDATE |
| P5.3 | both | **MEASURED — closes §4.4** | Host x18 is caller-clobbered scratch ⇒ **the gateway does NOT need to add host x18 to its save/restore set** on either host. `grep 'x18\|w18' gateway_aarch64.S` yielding only two **comment** hits is SAFE | §4.4 T0 UPDATE |

### P6 — si_code fidelity matrix (the ESR substitute)

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P6.1 (a)–(f) | both | **MEASURED** | Full matrix recorded. Both deliver `TRAP_BRKPT` for `BRK #0` and `TRAP_TRACE` for `PT_STEP`. **NetBSD is the divergent one**: `SEGV_MAPERR` for a *permission* fault where Linux (and freebsd) say `SEGV_ACCERR` — while NetBSD's own `si_trap` DFSC `0x0F` is right. ⇒ **decode the ESR carrier, do not trust `si_code`** | §4.2 T0 UPDATE (table) |
| P6.1 (a) | netbsd | **NOT-RUN (self-reported)** | Read-of-unmapped was **inconclusive by construction** — an intervening `printf`'s malloc re-mapped the just-`munmap`'d VA. Honestly self-flagged; case (b2) (read of `PROT_NONE`) substitutes. Impact: nil | — |
| P6.1 (d) | netbsd | **DOWNGRADED — do not plan on this** | Reported "misaligned `LDXR`/`LDAXR`/`STXR`/`LDAR`/`CASAL`/`LDP` → no fault at all". Verifier: **contradicts the ARM ARM** (alignment check on exclusives/acquire-release is mandatory regardless of `SCTLR_EL1.A`), the guests run **hvf-accelerated on Apple Silicon** (`bsdvm.py:148`), and **freebsd measured the opposite on the same silicon** (`SIGBUS/BUS_ADRALN`). Treat as a probe-construction bug. **The derived inference — "the `EC 0x24 + DFSC 0x21 → BUS_ADRALN` lowering can never fire on Apple silicon, and Darwin/HVF shares it" — rests on the bad datum and must NOT be carried** | §4.2 T0 UPDATE |
| P6.1 (g) | freebsd | **DOWNGRADED to INFERRED** | `TRAP_HWBKPT` is **not defined** in FreeBSD's `signal.h` (though `PT_GETDBREGS` = 37 exists) — that part is MEASURED. But **no hardware breakpoint or watchpoint was ever armed**; the claimed `si_trapno` values for EC 0x30/0x34 are extrapolation from the ARM EC table. `esr.rs:19-25` maps `0x30\|0x31`/`0x34\|0x35` → `TRAP_HWBKPT`, so this is load-bearing for the ptrace / Go `TestDebugCall` path. **Cheap follow-up probe** | §4.2 T0 UPDATE |
| P6.1 (g) | netbsd | **MEASURED (negative)** | `PT_GETDBREGS`/`PT_SETDBREGS` **do not exist** on NetBSD/aarch64 ⇒ HW breakpoints/watchpoints are unreachable via ptrace. BRK + software single-step both work and both carry a correct ESR | §4.2 T0 UPDATE |
| P6.2 | both | **MEASURED** | Instruction-vs-data abort distinguishable **two ways** on both: EC (0x20 vs 0x24, no overlap) and `si_addr == elr`. **Use EC as primary** — freebsd measured a misaligned `LDXR` (a *data* abort) that ALSO had `si_addr == elr`, so the address test alone is unsound | §4.2 T0 UPDATE |
| P6.3 | both | **MEASURED** | **The hosts split.** netbsd: WnR is **free** — `si_trap` bit 6 = 1 for a store to `PROT_READ`, 0 for a load from `PROT_NONE`, with identical `si_code` in both cases. freebsd: **genuinely absent** — the two cases produce **identical payloads in every field** (`si_trapno=36` both, `mc_spare` all-zero, `mc_flags` always `0x1`) ⇒ the metadata-derived WnR mitigation is **required, not optional, and FreeBSD-only** | §3.4, §4.2 T0 UPDATEs |

### P7 — W^X JIT + dual-map icache

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P7.1 | both | **MEASURED** | The shm dual-map recipe works **verbatim** on aarch64 on both — freebsd `SHM_ANON`, netbsd named-`shm_open`+`shm_unlink`. `PROT_EXEC` on a `MAP_SHARED` shm mapping is permitted on both; code written through the RW alias executed through the RX alias. **0 LoC for the mapping duty** | §2.2 |
| P7.2 | freebsd | **MEASURED (controlled differential)** | Five sequential publications with alternating expected/stale values: exec-VA cleaning sufficient (i, ii); write-VA cleaning also works (iii, PIPT); `__clear_cache` works (v); **and (iv) NO maintenance returned the STALE function.** `DC CVAU` succeeded on a `PROT_READ\|PROT_EXEC` alias | §2.2 T0 UPDATE |
| P7.2 | netbsd | **MEASURED, necessity NOT shown (self-flagged)** | Reproduced (i)/(iii)/(v), but case (iv) **also passed** there — so that box could not demonstrate *necessity*. `CTR_EL0` L1Ip=3 (PIPT) corroborates the architectural argument. **Do not read the (iv) pass as licence to drop `__clear_cache`** | §2.2 T0 UPDATE |
| P7.3 | both | **MEASURED — and the conclusion drawn from it was REFUTED** | freebsd **permits RWX outright** (`mmap(RWX)`, `mprotect(RW→RX)`, `RW→RWX` all succeed). netbsd **PaX MPROTECT is on by default and pins each mapping's maxprot at mmap time** (full A/B/C/D shape matrix + a `paxctl +m` control experiment that lifts every restriction). ⛔ **Both agents' derived recommendations rested on the same mistaken premise** — that the W↔X flip exists because the *host* forbids RWX. Direct read refutes it: `native16k_host_prot` never grants `PROT_EXEC` to a guest page at any geometry, so the flip is **SMC detection**, host-policy-independent | §3.4 T0 UPDATE |
| P7.4 | both | **MEASURED** | The inherited `MAP_SHARED` dual map stays **shared** on both (child's publish visible to the **parent** — a real bidirectional coherence test) ⇒ **`ForkChildJit::Fresh` is REQUIRED**. Already what both host crates return (`jit.rs:172-179`) ⇒ **0 LoC** | §2 reuse table |
| P7.5 | freebsd | **MEASURED** | The host permits the sequence — a vfork child executed the parent's W\|X page, exit 0. So nothing at the OS level stops a guest from reaching the `:1648-1651` vs `:1631` disagreement at 4K | §3.4 T0 UPDATE |
| P7.5 | netbsd | **NOT-RUN** | Skipped without flag (verifier caught it). **Impact LOW and the answer is entailed**: P7.3 measured that NetBSD denies RWX outright, so the probe's own premise (map W\|X, then vfork) cannot be set up there. The repo half is readable anyway — `mapped_memory.rs:1648-1651` hard-checks `host_page_size != 16*1024`, confirmed by both verifiers | §3.4 T0 UPDATE |

### P8 — Futex / kick / signal ABI

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P8.1 | netbsd | **MEASURED** | `SYS___futex` = **166** and `FUTEX_{WAIT,WAKE,REQUEUE,CMP_REQUEUE}` = **{0,1,3,4}** confirmed on aarch64 — **and not merely from headers**: a real cross-process `MAP_SHARED\|MAP_ANON` wake ran (wake count 1, child `FUTEX_WAIT` rc=0), and a value mismatch returned EAGAIN exactly as Linux does. **The silent-misroute risk is CLOSED** | §2 reuse table |
| P8.2 | freebsd | **MEASURED (all three)** | `_umtx_op` cross-fork wake on `MAP_SHARED\|MAP_ANON` **works on arm64** (parent woke rc=0 after 155 ms from a separate process's `UMTX_OP_WAKE`); `UMTX_OP_WAIT_UINT_PRIVATE` timeout → ETIMEDOUT; `kern.proc.vmmap`/`kinfo_vmentry` works (`kve_structsize` = 160 vs `sizeof` 1160 — the classic variable-structsize layout); `procctl(PROC_REAP_ACQUIRE)` + `PROC_REAP_STATUS` work. Latent fragility noted: `waiter_key.rs:33` guards on `size_of::<kinfo_vmentry>()` (1160) while a real entry is 160 B — a heuristic on entry *count*, not a bound; the walk at `:62` correctly uses `kve_structsize` | §2 reuse table |
| P8.3 | both | **MEASURED** | freebsd SIGRTMIN/SIGRTMAX = **65/126**, netbsd **33/63** — exactly their x86 twins, so both const-asserts hold. The already-chosen kick **pairs** (65,66) and (33,34) are `SIG_DFL`/unclaimed in a threaded process on both. freebsd `SIGSTKSZ` = 36864 (> Darwin's) — relevant if a shim sizes an altstack statically | §2 reuse table |
| P8.4 | both | **MEASURED** | A non-`SA_RESTART` RT signal via `pthread_kill` interrupts a blocking `read(2)` with **EINTR** on both. **The kick's premise holds; combined with P3.1 the whole kick machinery has no remaining unknowns** | §2 reuse table |

### P9 — ELF assembly acceptance

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P9.1 | both | **MEASURED** | **The Mach-O→ELF port is a pure `s/_carrick/carrick/`.** Assembles rc=0 first try on both — clang 19.1.7 (freebsd) and base gcc 10.5.0 / GNU as (netbsd). Every directive/instruction accepted (`.equ`, `.p2align 2`, `stp/ldp` q-pairs, `msr nzcv/fpsr/fpcr`, `mrs`, `clrex`, `dsb`, `isb`); **no** `.type`/`.size`/`.hidden` needed. freebsd control: the **original underscored** file also assembles ⇒ the underscores are a link-time naming issue only. `.note.GNU-stack` accepted on netbsd, not required on freebsd (binaries came out `GNU_STACK=RW`) — add it for x86-gateway parity. **Count correction:** 21 changed lines, not the reported 20 (`grep -c '_carrick'` = 21: 9 `.globl`, 9 label defs, 3 `bl`) | §1.4 item 2 |
| P9.2 | both | **MEASURED** | `.S` → `ar` static lib → linked into **both** a C binary and a **rustc** output, symbols resolved, ran. Measured `exit_common_end − exit_common_start` = **188 bytes** on both hosts in two independent address spaces — matching the 212-line source, which is a strong internal consistency check | §1.4 item 2 |

### P10 — Identity-vs-biased / VA layout

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P10.1 | both | **MEASURED** | **No `__PAGEZERO` analogue on either.** Only page 0 itself is refused (EINVAL); `0x1000` maps fine. ⇒ `address.rs:22-44`'s `NATIVE_DARWIN_HARD_PAGEZERO_END = 0x1_0000_0000` is a **Darwin fact, not a portable one** | §3.8 |
| P10.1b | freebsd | **MEASURED (extra)** | A plain `cc` FreeBSD binary is **ET_EXEC at a FIXED `0x200000` with `p_align=0x10000`** — the *same* base and alignment as the aarch64 Linux fixtures, so a **non-PIE** host would collide exactly. Rust binaries are ET_DYN/PIE and ASLR'd high (three runs: `0x37f3…`, `0x1232…`, `0x2540…`), **zero mappings below 16 MiB**. ⇒ the low-VA window is free, **but that margin is a property of Rust's PIE default, not of the OS** | §3.8 |
| P10.2 | both | **MEASURED** | Every address a static aarch64 Linux ELF wants is placeable via `MAP_FIXED` on both: `0x10000`, `0x200000`/`0x210000` (the tracked fixtures' real load addresses), `0x400000`, `0xaaaa_aaaa_0000`. Only `0x0` fails. **The identity model is feasible on both hosts** (still not recommended — see §8.3) | §3.8 |
| P10.3 | both | **MEASURED** | All three Darwin arena bases (heap `0x8_0000_0000`, mmap `0xa0_0000_0000`, sigreturn trampoline `0x7_0000_0000`) map **exactly** on both, and the 32 GiB reservation succeeds. User-VA ceiling: freebsd exactly `1<<48` (matching `Aarch64Isa::USER_VA_END_EXCLUSIVE`, **larger** than Darwin's `1<<47`); netbsd ≥ `0xffff_0000_0000`, `1<<48 − 16K` = EFBIG. `MAP_NORESERVE` is a checked non-issue (already `#[allow(deprecated)]` at `mapped_memory.rs:178-179`). ⚠️ **NEW netbsd blocker:** under default PaX a mapping created `PROT_NONE` can **never** be promoted (EACCES) ⇒ the reserve-`PROT_NONE`-then-promote pattern fails. **Measured mitigation needing no privilege/sysctl/`paxctl`: reserve `PROT_READ\|PROT_WRITE (+MAP_NORESERVE)` then immediately demote the whole reservation to `PROT_NONE`** (portable — works on Darwin too) | §0a caveat 5 |
| P10.4 | freebsd | **MEASURED** | **Exact non-`MAP_FIXED` hints are NOT honored** — three hints, all ASLR'd first-fit away. `MAP_FIXED\|MAP_EXCL` collision detection **does** work, but the errno is **ENOMEM (12), not EEXIST**. Verifier-corroborated at source: `address.rs:52-92 map_exact` maps *without* `MAP_FIXED` then compares, so on this host it returns `HostCollision` **always** | §0a caveat 6 |
| P10.4 | netbsd | **DOWNGRADED to INDICATIVE** | Reported "exact hints honored ⇒ no rewrite needed". Verifier: only **two samples**, both at addresses far from NetBSD's topdown allocator region — vacancy explains the result as well as hint-honoring does. And the agent's own evidence shows **`MAP_EXCL` does not exist** and `MAP_FIXED` **silently replaces** an existing mapping, i.e. the atomic-exclusive property the seam wants is *absent*. "Hint-plus-verify" is right; "no rewrite needed" is **not established** | §0a caveat 6 |

### P11 — USDT / DTrace viability

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P11.1 | freebsd | **MEASURED** | **USDT can NEVER fire on freebsd-arm64 — for a KERNEL reason, not a crate reason.** `fasttrap.ko` does not exist in `/boot/kernel`, `kldload fasttrap` = ENOENT, and dtrace itself says "pid provider is not installed on this system". The pid/fasttrap provider is the only route by which USDT sites fire on FreeBSD. **Kernel DTrace is rich and works** (27 providers / ~56k probes: 52,622 fbt + 2,376 syscall + sdt/sched/vm/proc/io/ip/tcp) | §0a, §8.1 V13 |
| P11.1 | netbsd | **MEASURED (variant)** | `usdt` 0.6.0 compiles as the **pure-Rust no-op**, so `carrick-observability` builds clean in 5.88 s — the freebsd `c_char` blocker does **not** affect this lane. NetBSD ships `/usr/sbin/dtrace` + `dtrace_sdt`/`dtrace_fbt` modules but DTrace is **not enabled in GENERIC64**. ⇒ weld #4 stands on both lanes for **different reasons** (freebsd: kernel; netbsd: crate). Also confirmed: **`just` is absent on netbsd**, so gates must spell literal cargo commands | §0a |
| P11.2 | freebsd | **MEASURED** | **A ONE-LINE fix unblocks the whole chain**: `s/byte as i8/byte as std::os::raw::c_char/` in `usdt-impl-0.6.0/src/no-linker.rs:166` makes **`carrick-observability` AND `carrick-thread`** both build clean; nothing else in the chain is `c_char`-sensitive. crates.io's **latest IS 0.6.0** (verified independently via the crates.io API) ⇒ **no upstream release to bump to**. Reverse-dep tree measured: usdt does **not** reach carrick-dsr-aarch64/dsr/mem/host/hal/portable | §5.4 B4a |

### P12 — Fixture / loader acceptance

| # | Host | Status | Result | Detail |
|---|---|---|---|---|
| P12.1 | Mac | **MEASURED — independently re-run by BOTH verifiers, byte-for-byte** | All 8 tracked aarch64 fixtures are **ET_EXEC** (machine 183), load base `0x200000`, entries `0x210120` (×4, 4 phdrs) / `0x210158` (×4, 5 phdrs), **every LOAD segment `p_align = 0x10000` = 16× the host page**, `GNU_STACK` RW. ⇒ two acceptance prerequisites: the load-plan alignment path must **tolerate `p_align` > host page size**, and the aarch64 native loader must accept **ET_EXEC at a fixed vaddr** (the x86 rung-1 fixture is static-PIE, so this is new territory). P10.2 proves the addresses are obtainable on both hosts | §5.3, T14 |
| P12.2 | both | **BLOCKED** | **Blocking error:** no aarch64-BSD `NativeLane` exists (`native/mod.rs:87-135` wires only `DarwinAarch64Lane` / `FreebsdX8664Lane` / `NetbsdX8664Lane`), `carrick-runtime` does not compile under **any** feature set on either guest (P0.5), and there is no `page_profile` arm for `(FreeBsd\|NetBsd, Aarch64)` so `run_static_elf` would error at `native_darwin.rs:642/:709` even if it linked. **Unblocked by:** T1 + T2 + T5 + T9 + T11 + T12, in that order. **Every host capability it needs measured green** (P3, P4, P7, P9, P10) — this is pure code-side sequencing, not a host limitation | §5.4, §7 |
| P12.3 | both | **BLOCKED** | Same gate as P12.2. Host-side prerequisite is settled: the value the guest must agree with is unambiguously **4096** from three independent sources on each host (P1.1/P1.2/P1.3). When the lane exists this becomes a cheap assertion and closes §3.7's never-run-end-to-end geometry gap **at a geometry the host genuinely enforces** | §3.7 |
| P12.4 | both | **BLOCKED** | Same gate, **plus** the spec's own note: the prepared-image and exec-capsule suites live in `carrick-dsr`/`carrick-runtime`, which stage0 never compiles, so the diff belongs to a later stage. Nearest available substitute measured: `cargo test -p carrick-dsr-aarch64` = 87/87 on both — a suite Darwin also runs and stage0's crate set excludes. **Recommend a stage1.5 rung running exactly that** (13–15 s cold, green today modulo B5) — it converts the campaign's most load-bearing thesis claim from an argument into a gate | §7 T15 |

**Probes deliberately not re-run, and what would settle them cheaply:** P4.2's host-suspend
clause (suspend/resume the VM, re-read `CNTVCT`); freebsd P6.1(g) (arm a HW breakpoint and a
watchpoint via `PT_SETDBREGS`, read `si_trapno` — expect EC 0x30/0x34); SIGFPE / EC `0x2c` on
both (`carrick-native-netbsd/src/fault.rs:47-48` lists SIGFPE in `GUEST_FAULT_SIGNALS` and it
was probed on neither host); netbsd P6.1(d) (re-probe misaligned exclusives correctly);
netbsd P0.7 with the real stage2 command. **None of these blocks T1.**

---

## 7. Task breakdown — **REVISED POST-T0**

Mirroring the NetBSD/x86 staging (prereqs → host crates → seam/re-gate → wiring →
acceptance → gate ladder). **(×2)** = per-OS, done twice.

**Net sizing effect of T0: roughly flat, with the risk redistributed.** Four tasks SHRANK
(T3, T6, T7, T10), one GREW (T5), one is NEW (T17), and the single largest deliverable (T9,
the shim) is **unchanged in size but materially de-risked** — every mechanism it depends on
is now measured working, and its mcontext contract is a table of numbers rather than a
research question.

| # | Task | Kind | Pre-T0 | **Post-T0** | Δ | Depends on |
|---|---|---|---|---|---|---|
| **T0** | On-box probe phase | shared | M | **DONE** | ✅ | — |
| **T1** | Arch-gating pass | shared | M | **M** | contents grew | — |
| **T2** | VMM-less BSD/aarch64 feature pair + futex re-homing | shared | M | **M** | — | T1 |
| **T3** | usdt-impl `c_char` fix (freebsd) | shared | S–M | **S** | ↓ | — |
| **T4** | bsdvm provisioning | shared | S | **S** | contents grew | — |
| **T5** | Page-geometry arm + the §3.5 ruling + the SMC re-gate | shared | M | **M–L** | ↑ | T1, **§8.3 Q2 ruling** |
| **T6** | ESR fault lowering | shared | M–L | **S–M** | ↓↓ | T1 |
| **T7** | Gateway ELF port | shared | M | **S** | ↓↓ | T1 |
| **T8** | Enter/exit ABI hook seam | shared | M | **M** | — | T7 |
| **T9** | The trap/kick shim | **(×2)** | L | **L** each | de-risked | T6, T8 |
| **T10** | Host counter plan + vvar clock sources | shared | S–M | **S** | ↓ | — |
| **T11** | Re-gate the run module + LaneHost alias block | shared | M | **M** | — | T9, T10 |
| **T12** | Lane wiring | **(×2)** | XS | **XS** each | — | T11 |
| **T13** | `cfg(all(test, macos))` sweep | shared | M | **M** | — | T11 |
| **T14** | Acceptance test + missing fixture rungs | shared | M | **M** | — | T12 |
| **T15** | stage2 in the gate ladder (+ a new stage1.5 rung) | shared | S | **S** | contents grew | T14 |
| **T16** | stage3 groundwork (out of scope for the first landing) | shared | L | **L** | — | T15 |
| **T17 — NEW** | **Host-exact-placement seam** (`map_exact`) **+ PaX-safe reservation shape** | shared | — | **S–M** | NEW | T1 |

### What each task actually is now

- **T1 — Arch-gating.** `carrick-native-freebsd`: a **3-line** arch-gate in `lib.rs`
  (`pub mod fault`, `pub mod tsc`, `fn vdso_tsc_calibration`) clears all 9 errors with no
  other fallout (P0.5a, measured). `carrick-native-netbsd`: same shape on `fsbase.rs` +
  `fault.rs`, **but budget a 10th break** — `fsbase.rs:65-77`'s naked x86 `asm!` fails at
  *codegen*, which type-check abort hid. `carrick-vmm-bhyve` / `carrick-vmm-nvmm`: item
  gates. **Plus, in the SAME commit** (this is the item that fails *silently*): the aarch64
  `flush_icache` `__clear_cache` body **with a regression test shaped like P7.2 case (iv)**,
  which measured stale-code execution with no maintenance. **Plus B5** (one line,
  `identity_memory.rs:1365`) and **B6** (one line, the un-gated `run_oci` caller at
  `lib.rs:589` — **1 site, not the 5 the probe report claimed**). Grew by 2 one-liners and
  the 10th break; shrank on the FreeBSD half; net **M**.
- **T2 — feature pair + futex.** Unchanged. The futex *primitives* are now measured working
  on aarch64 (netbsd `SYS___futex`=166 + a real cross-process wake, P8.1; freebsd `_umtx_op`
  cross-fork wake + `kinfo_vmentry` + `procctl` reaper, P8.2), so the residual is exactly
  what §8.1 V4 said: the **unwritten `PlatformFutex` adapter** (~80 LoC). **U12 (cargo
  `dep:` in `[features]` under an arch-scoped target table) is STILL-OPEN** — no probe
  touched it, and it needs manifest edits to test.
- **T3 — usdt. SHRANK to S.** One line; crates.io's latest **is** 0.6.0 so there is nothing
  to bump to; `[patch.crates-io]` a vendored `usdt-impl`. **And it buys compilation only** —
  P11.1 proved the probes can never fire on freebsd-arm64, so do **not** budget follow-on
  work toward making USDT work there.
- **T4 — provisioning. Contents grew.** Two packages, not one: `llvm19` on the freebsd
  `pkg install` line (`bsdvm.py:544`) and `clang` on the netbsd `pkg_add` line (`:602-606`)
  — **plus `LIBCLANG_PATH` exported in the gate env on both** (`/usr/local/llvm19/lib`,
  `/usr/pkg/lib`); bindgen does not find them on its own. Then refresh-golden both.
- **T5 — geometry + the §3.5 ruling. GREW to M–L.** The *arm itself* is now trivial
  (Scenario A settled by P1.1/1.2/1.3 on both, so it takes `x86_native_plan`'s values), but
  §3.4's T0 UPDATE moved work **into** this task: (a) the W↔X flip is **SMC detection**, not
  a host-W^X workaround, so it must stay **armed** at 4K on both hosts — the freebsd probe
  agent's "disarm it" recommendation is REFUTED; (b) the `:1648-1651` vs `:1631` asymmetry
  must be fixed so the vfork refusal and the fault path agree (P7.5 measured the sequence is
  host-reachable); (c) the **WnR bit must be supplied** — free on NetBSD (`si_trap` bit 6),
  **metadata-derived on FreeBSD, where it is required not optional** (P6.3); (d) rename the
  geometry-proxy predicates so nothing reads "16K" as "needs SMC trapping". **Still gated on
  the §8.3 Q2 maintainer ruling.**
- **T6 — ESR lowering. SHRANK M–L → S–M**, and its *shape* changed: an ESR carrier exists in
  `siginfo` on **both** hosts (P2.3), so the plan is **feed the real ESR**, not "teach the
  loop a neutral `(signal, si_code)` lowering". NetBSD: `si_trap as u32 as u64` verbatim,
  **zero** decision change at `translator.rs:2388-2416` / `native_darwin.rs:3044-3053`, and
  `el0_debug_signal` needs no new input. FreeBSD: synthesize
  `esr = (si_trapno << 26) | dfsc_from(si_signo, si_code)` — the bare `<< 26` the probe
  report headlined is **wrong in the majority of measured cases** (§4.2). Residual: a
  fail-closed default for unrecognized EC values (freebsd EC 0x30/0x34 are INFERRED, not
  measured), and SIGFPE/EC 0x2c is unprobed on both.
- **T7 — Gateway ELF port. SHRANK M → S.** Measured on both hosts: a pure
  `s/_carrick/carrick/` (21 lines) assembles rc=0 first try, archives, and links into a
  **rustc** output with all symbols resolved (P9.1/P9.2). No directive additions needed;
  add the `#if defined(__ELF__) .note.GNU-stack` tail for parity with the x86 gateway.
  **T7 loses its "+ the x18 delta" entirely** — §4.4 is closed at zero cost by P5.3 on both
  hosts. Remaining: widen `build.rs:7-17` and the four `gateway.rs` module cfgs, and supply
  the two `carrick_native_dsr_enter_{guest,host}_abi` helpers.
- **T8 — ABI hook seam.** Unchanged in size; **the trade-off shifted** — P9.1 measured the
  `.S` porting as-is, which removes most of the value of the function-pointer shape's main
  selling point (keeping the `.S` OS-agnostic). See §8.3 Q4.
- **T9 — the trap/kick shim. Still L each, but materially de-risked.** Everything it stands
  on is measured: PC+SP rewrite and the 16-byte recovery slot round-trip (P3.1/P3.2);
  mcontext x18/x28 readable **and writable**, which is **better than Darwin** and lets the
  BSD shim drop `preserve_virtual_registers`' 18/28 exclusion and recover x28 from the
  mcontext directly (P3.3); the kick signal pairs and the EINTR premise (P8.3/P8.4); and the
  mcontext contract is now a table of exact numbers to `_Static_assert` (§2.1 T0 UPDATE).
  **Write it in C against real headers** — that conclusion survives the ESR result
  independently, because libc exposes neither `si_trap` nor `si_trapno` and mis-binds both
  mcontexts. The irreducible content is the ~45 lines of active-context / deferred-kick
  (synthetic `exit_status = 8`) / phase-hook / kick-mask bookkeeping, which must be
  reimplemented per host **regardless** of the x18 answer.
- **T10 — counter plan. SHRANK to S.** `Inline{Cntvct, 1:1}` measured correct on both
  (P4.1/P4.2); the missing non-macOS `fallback_counter_ticks()` body is one `mrs cntvct_el0`.
  Two things to record rather than fix: **do not hardcode 24 MHz** (QEMU/HVF virt value), and
  **`CNTPCT_EL0` is denied at EL0 on both hosts** — a real Linux-fidelity gap, since
  `CNTPCT_EL0` *is* EL0-readable on Linux/aarch64 and `decode.rs:250/1103/1107` handles only
  CNTVCT/CNTFRQ.
- **T11–T14.** Unchanged. T14 gains a concrete constraint from P12.1: all 8 fixtures are
  **ET_EXEC at `0x200000` with `p_align = 0x10000` on every LOAD segment (16× the host
  page)**, so **read the aarch64 load-plan rounding before the acceptance task** rather than
  discovering it there — and fixtures must be cross-built on the Mac (P0.8 ×2).
- **T15 — gate ladder. Contents grew: add a stage1.5 rung.** `cargo build`/`test -p
  carrick-dsr-aarch64` (plus the other 5 acceptance-path crates) with `LIBCLANG_PATH` set is
  **13–15 s cold and green today** modulo B5, and it converts the campaign's central thesis
  from an argument into a gate. stage2 itself must write a **JSON artifact and `cat` it** —
  P0.7 confirms the 7200 s budget is not the risk; the **4000-char tail truncation** is.
  ⚠️ netbsd's cold-build number was DOWNGRADED (it never compiled `carrick-runtime`), so
  **re-measure the real stage2 command at T1**.
- **T17 — NEW: host-exact-placement seam + PaX-safe reservation shape. S–M.** Two
  independent host facts that neither the pre-probe plan nor the reuse table had:
  (a) `carrick_dsr::address::map_exact` (`address.rs:52-92`) maps **without** `MAP_FIXED`
  then compares the returned address — it rests on a **Darwin-only** exact-hint guarantee
  (documented at `address.rs:756-761`). FreeBSD ignores exact hints (P10.4, three samples,
  all ASLR'd away) ⇒ `map_exact` returns `HostCollision` **always** there. It must be
  replaced by `MAP_FIXED|MAP_EXCL` probing behind the `NativeHost` seam. **Implementer
  gotcha: the collision errno is ENOMEM, not EEXIST.** NetBSD has **no `MAP_EXCL` at all**
  and its `MAP_FIXED` silently clobbers, so hint-plus-verify is the only safe shape there —
  and the NetBSD "hints honored, no rewrite needed" result was **DOWNGRADED to INDICATIVE**
  (two samples, both in vacant regions). All 14 `map_exact` call sites are in
  `native_darwin*` — i.e. **exactly the file T11 re-gates for BSD**, which is why this is a
  real workstream rather than a note.
  (b) NetBSD **PaX MPROTECT pins maxprot at `mmap` time**, so the reserve-`PROT_NONE`-then-
  promote arena pattern fails EACCES. Measured fix, no privilege/sysctl/`paxctl` needed:
  reserve `PROT_READ|PROT_WRITE (+MAP_NORESERVE)`, then immediately demote the whole
  reservation to `PROT_NONE` (P10.3). Portable — it works on Darwin too, so it can land as a
  single shape change rather than a cfg fork.

**Totals: 17 tasks. 15 shared, 2 per-OS (×2) — T9 (the shim) remains the single largest and
is one of the two doubled ones.** Order-of-magnitude: still comparable to the NetBSD/x86
campaign's 31 commits **plus** the arch-gating pre-step (T1–T4, T17) and the two genuine
design rulings x86 never faced — **of which T0 settled one (the ESR ruling, §8.3 Q3) and
left one open (the `native_profile` ruling, §8.3 Q2).**

**Recommended order:** **T1 → T4 → T3 → T2 → T17 → T5 → T6 → T7 → T8 → T9(freebsd) → T10 →
T11 → T12 → T14 → T15**, then **T9(netbsd) + the netbsd half of T12**; T13 in parallel with
T11; T16 deferred.

**Which lane first? FreeBSD/aarch64** — unchanged from the pre-probe recommendation, and the
data strengthened it. FreeBSD's whole host-capability surface came back green with **no
policy surprises**: RWX permitted, `_umtx_op` cross-fork wake works on arm64, the `procctl`
reaper works, `kern.proc.vmmap`/`kinfo_vmentry` works, `MAP_EXCL` exists, all three Darwin
arena bases map exactly, the user-VA ceiling is exactly `1<<48`, `MIDR_EL1`/`ID_AA64*` are
kernel-emulated, and the cold acceptance-path build is **13 s** on rustc 1.96.1. NetBSD
brings **two design constraints nobody had on a list** (PaX maxprot pinning; no `MAP_EXCL`),
the fleet's tightest MSRV (1.91.1), no HW-debug registers at all, an `si_code` that is
**wrong** for permission faults, and no `just`. The one point against FreeBSD — the usdt
blocker — is a **single line**. The one point *for* NetBSD is real and worth banking: its
`si_trap` is the **raw ESR word**, so the NetBSD shim needs no synthesis at all.

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

#### T0 UPDATE — every V-row's status after the probe phase

| Row | T0 status |
|---|---|
| **V1** | **CONFIRMED-MEASURED on both**, line-exact (P0.5). See §5.4 B1 — including the netbsd caveat that 9 errors is a *floor*, not the worklist size |
| **V2** | **CONFIRMED-MEASURED as a live silent-corruption trap**, not a theoretical one: freebsd P7.2 case (iv) executed the **stale** function after publishing with no cache maintenance. The `__clear_cache` body must land in the same commit that first makes either crate build on aarch64 |
| **V3** | **CONFIRMED, with one half REFUTED per-OS.** netbsd: hard-impossible (NVMM physically absent). freebsd: **`libvmmapi` EXISTS on aarch64 and links** — so the FreeBSD break is purely arch-gated Rust items, not a link edge. Same decision, different justification |
| **V4** | **UNCHANGED — still 0 impls.** But the *primitives* are now measured working on aarch64 (P8.1, P8.2), so the residual is exactly the ~80-LoC adapter |
| **V5** | **PARTIALLY REFUTED — the biggest single change from T0.** ESR is absent from both *mcontexts* (correct) but **present in *siginfo* on both** (P2.3): netbsd `si_trap` = the raw ESR word; freebsd `si_trapno` = the EC field only. WnR is free on NetBSD and must be metadata-derived on FreeBSD. **T6 shrinks M–L → S–M** |
| **V6** | **CONFIRMED-MEASURED and sharpened on both** — see §2.1's T0 UPDATE for the exact `_Static_assert` numbers. The NetBSD `_REG_R15` AArch32-alias landmine was observed **live** in P0.5's build |
| **V7** | **CLOSED at zero cost on both hosts** (P5.3). Host x18 is ordinary caller-clobbered scratch; no additive gateway save/restore. **Remove from the inventory** |
| **V8** | **STILL A REAL BUG, and now measured host-reachable** (freebsd P7.5: a vfork child executed the parent's W\|X page, exit 0). Fix in T5 — and per §3.4's T0 UPDATE the correct predicate is *"does this geometry need SMC write-trapping?"* (always, under DSR), **not** a host-W^X-policy predicate |
| **V9** | **REPRODUCED verbatim at HEAD**, and the open crates.io question is SETTLED: **0.6.0 is the latest**, there is nothing to bump to. Fix is one line |
| **V10** | **CONFIRMED and CLOSED BY PROVISIONING** on netbsd (`pkg_add -U clang`), and the **predicted twin CONFIRMED** on freebsd (`pkg install llvm19`). Both need `LIBCLANG_PATH` in the gate env |
| **V11** | **CONFIRMED on both** — no `aarch64-unknown-linux-musl` std on either guest. Minor correction: `rust-lld` **is** present in the freebsd sysroot |
| **V12** | **CONFIRMED-MEASURED on netbsd** (16 errors, 4 classes — see §5.4). It is a **stage1-only artifact**: `carrick-vmm-hvf` is not on the acceptance path and a VMM-less feature pair sidesteps it |
| **V13** | **CONFIRMED and made WORSE in one dimension, better in another.** Worse: USDT on freebsd-arm64 is dead for a **kernel** reason (`fasttrap.ko` absent) — fixing the crate buys compilation only. Better: **kernel DTrace is rich and works on freebsd** (52,622 fbt + 2,376 syscall + sdt/sched/vm/proc/io/ip/tcp), which is a genuine substitute of the same shape as the `carrick-bhyve-debug` workflow. NetBSD ships dtrace but it is not enabled in GENERIC64. **NEW capability losses to add to the red list:** freebsd has no `TRAP_HWBKPT` in `signal.h`, netbsd has **no `PT_GETDBREGS`/`PT_SETDBREGS` at all** (HW breakpoints/watchpoints unreachable via ptrace), and `CNTPCT_EL0` is **denied at EL0 on both** where Linux permits it |

**Two blockers joined the list post-T0:** **B5** (`carrick-dsr/src/identity_memory.rs:1365`,
`vec![0i8]` → `libc::mincore`'s `*mut c_char` — unconditional E0308 on every non-Apple
aarch64, blocking the translate engine itself) and **B6** (the un-gated `run_oci` caller at
`carrick-runtime/src/lib.rs:589`). Both are one-liners; both are on the critical path. Full
detail in §5.4.

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

#### T0 UPDATE — every NEEDS-ON-BOX unknown, resolved

| # | T0 resolution | Probe |
|---|---|---|
| **U1** | **RESOLVED: 4096 on BOTH ⇒ Scenario A, unconditionally.** Three independent sources per host including a real `mprotect` granule. Every "4K" estimate in §3 now stands | P1.1/1.2/1.3 ×2 |
| **U2** | **RESOLVED — best case.** Host userland keeps **no live state** in x18 on either host (poison test). No emitter change; the `emit.rs:805-816` scratch window stays. ⚠️ but x18 **is** caller-clobbered — carrick may not park data there across a libc call | P5.1, P5.2 ×2 |
| **U3** | **RESOLVED — no gateway work.** §4.4 closed at zero cost on both | P5.3 ×2 |
| **U4** | **RESOLVED — the upside risk landed.** An ESR carrier exists in `siginfo` on both hosts, though **not the same one**: netbsd `si_trap` (raw ESR), freebsd `si_trapno` (EC only). **T6: M–L → S–M** | P2.3 ×2 |
| **U5** | **RESOLVED, with per-host fidelity gaps.** Both give `TRAP_BRKPT` for `BRK #0` and `TRAP_TRACE` for `PT_STEP`. **NetBSD's `si_code` is WRONG for permission faults** (MAPERR where Linux says ACCERR) — the strongest argument for decoding the ESR carrier rather than `si_code`. HW-debug: freebsd has no `TRAP_HWBKPT` define, netbsd has no `PT_GETDBREGS` at all | P6.1/6.2/6.3 ×2 |
| **U6** | **RESOLVED — no blocker.** `SCTLR_EL1.UCI = 1` and `CNTKCTL_EL1.EL0VCTEN = 1` on both. New: **`CNTPCT_EL0` denied on both** | P4.1 ×2 |
| **U7** | **RESOLVED — exec-VA-only cleaning suffices** (measured on freebsd with a controlled negative; supported on netbsd). Keep the seam-gap workstream dropped, and treat the `__clear_cache` body as **mandatory and urgent** | P7.2 ×2 |
| **U8** | **RESOLVED — the dual-map JIT works verbatim on both**, `PROT_EXEC` on `MAP_SHARED` shm permitted on both, `ForkChildJit::Fresh` required on both (already what the crates return ⇒ 0 LoC) | P7.1/7.4 ×2 |
| **U9** | **RESOLVED — the hardcodes are correct on aarch64**, and not merely from headers: a real cross-process wake ran. Silent-misroute risk CLOSED | P8.1 |
| **U10** | **RESOLVED on the host side, STILL-OPEN on the loader side.** All 8 fixtures are ET_EXEC at `0x200000` with `p_align = 0x10000`; both hosts grant those exact addresses via `MAP_FIXED`. **Whether the aarch64 load-plan tolerates `p_align` (65536) > host page (4096) is UNTESTED** — no lane exists to exercise it. Read the rounding before T14 | P12.1, P10.2 |
| **U11** | **RESOLVED for FreeBSD (13 s cold), NOT for the real stage2 command.** netbsd's number was DOWNGRADED — its build never compiled `carrick-runtime`. The real risk is the **4000-char tail truncation**, not the timeout | P0.7 ×2 |
| **U12** | **STILL-OPEN.** No probe touched it (it needs manifest edits, and both agents were read-only on carrick source). If cargo refuses `dep:X` in `[features]` when X is arch-scoped, new arch-scoped feature names are required and `justfile:11-16`'s `_platform_features` (which selects by `os()` with **no `arch()` dimension**) plus every consumer must learn them. **Settle it with a 10-minute local cargo experiment before T2** | — |
| **U13** | **RESOLVED — every REUSABLE-AS-IS row survived.** `procctl`/`PROC_REAP_ACQUIRE`, `kinfo_vmentry`/`KERN_PROC_VMMAP`, `MAP_EXCL`, `SHM_ANON` all present and working on freebsd/aarch64; netbsd's `SYS___futex`/`FUTEX_*` correct. **One exception, and it is new: `MAP_EXCL` does not exist on NetBSD at all** | P8.2, P8.1, P10.3/10.4 |
| **U14** | **RESOLVED, and it produced the new T17.** All three Darwin arena bases + the 32 GiB reservation work on both. But **FreeBSD does not honor exact non-`MAP_FIXED` hints** (⇒ `map_exact` is broken there; collision errno is **ENOMEM**, not EEXIST) and **NetBSD PaX forbids promoting a `PROT_NONE` reservation** (⇒ reserve RW then demote). Identity model is *feasible* on both but still not recommended | P10.1–10.4 ×2 |
| **U15** | **RESOLVED — the answer is worse than "maybe".** USDT can **never** fire on freebsd-arm64 (`fasttrap.ko` absent; kernel reason, not crate reason), and netbsd's DTrace is not enabled in GENERIC64 while `usdt` 0.6 has no NetBSD backend. **The campaign ships with no USDT tracing on either lane.** Substitute: freebsd kernel DTrace (52k fbt + 2.4k syscall probes) | P11.1 ×2 |

**Net: 13 of 15 RESOLVED, 1 partially (U10's loader half), 1 STILL-OPEN (U12 — settle it
locally, not on a box).**

### 8.3 The nine open design questions — **RULED ON WITH T0 DATA**

Each question is tagged **DECIDED** (the probe data settles it), **LEANS** (the data points
one way; the recommendation and its reason are stated, but a maintainer should sign off), or
**NEEDS A MAINTAINER RULING** (the data does not bear on it — the trade-off is stated in the
form a busy expert can act on). **Do not read a LEANS as a decision.**

**Tally: 2 DECIDED · 5 LEANS · 1 pure ruling · 1 unanswered repo question.**
Three of the nine were flagged as blocking Task 1 — the fault-shim route, the
`native_profile` ruling, and the ESR ruling. **Two of those three are now DECIDED by data
(Q1, Q3); the third (Q2) still needs the maintainer — and it blocks T5, not T1.**

---

**Q1 — Fault-shim shape (§1.5): route (a) mirror the C shim per host, vs route (b) change
`_carrick_dsr_exit_signal` first. → DECIDED: route (a).**

Every element of the Darwin mechanism was measured working on **both** hosts: PC rewrite via
`gp_elr` / `__gregs[_REG_PC]`, SP rewrite, SP preservation, x0 write-back, callee-saved
registers intact, and the 16-byte-aligned recovery slot below the saved SP surviving
`sigreturn` (P3.1, P3.2). Route (a) therefore needs **no surgery on the proven Darwin gateway
signal path** — which was the entire reason to prefer it. Two findings make (a) *cheaper on
BSD than on Darwin*: mcontext x18 **and** x28 are both readable and writable across sigreturn
(P3.3), where `native_darwin.c:361-364` deliberately refuses to read them — so the BSD shim
may drop `preserve_virtual_registers`' 18/28 exclusion and recover the x28 context pointer
from the mcontext directly, making the recovery slot a redundancy rather than the only
channel. **Route (b) stays a logged follow-on, and is now clearly optional.**
*One caveat to carry into T9:* the probes anchored the slot to the **interrupted mcontext
SP**, while production anchors to `context->host_sp − 16` (`native_darwin.c:556-558`). The
primitive is proven; the exact production anchor is not (low risk — the gateway reads it via
`ldr x9,[sp]` after the handler sets SP, which is anchor-agnostic).

**Q2 — The `native_profile` ruling (§3.5). → LEANS (i), but NEEDS A MAINTAINER RULING. This
is the one remaining ruling that blocks a task (T5).**

**Recommendation: (i) keep `native_profile: None` and explicitly re-gate the aarch64
native16k W|X mechanism and policy** — but on a **corrected predicate**. §3.4's T0 UPDATE
establishes (by direct source read, during this write-up) that `native16k_host_prot`
**never** grants `PROT_EXEC` to a guest page at any geometry, so the W↔X flip is
**self-modifying-code detection**, not a host-W^X-policy workaround. The predicate to re-gate
on is therefore *"does this geometry need SMC write-trapping?"* — answer: **always, under
DSR** — **not** a host W^X predicate. This **REFUTES the freebsd probe agent's headline
recommendation to disarm the mechanism because the host permits RWX.**

**The trade-off the maintainer must weigh, in one sentence:** choosing `None` turns **off**
the profile-keyed policy set at `dispatch/mem.rs:1111/1138/3577` — including the **shared-W|X
refusal at `:1114-1116` that is LIVE on Darwin today** and sits *before* the
`supports_concurrent_exec_protection()` escape — and disables virtual-ptrace transport on the
new lanes, in exchange for not touching six files plus a serde wire name
(`carrick-spec:307`, `carrick-guest-mem:181-184`, `page_profile.rs`, `dispatch/mem.rs` ×3,
`native_exec_capsule.rs:301-309`, `carrick-spec:1022-1031`).
**Two facts make (i) cheaper than it looked pre-probe:** the exec capsule is not needed on
BSD (weld #3; the x86 BSD lane emulates execve in-process), and virtual-ptrace is a
legitimate follow-on given **both** hosts have HW-debug limitations anyway (FreeBSD: no
`TRAP_HWBKPT`; NetBSD: no `PT_GETDBREGS` at all). **No probe touched the shared-W|X-refusal
trade-off — that is genuinely a judgement call, not a measurement.**

**Q3 — The ESR ruling (§4.2 / T6). → DECIDED, and the data chose a THIRD option neither
branch anticipated: feed the REAL ESR carrier.**

Both pre-probe branches — "synthesize an ESR word" vs "teach the loop the neutral
`(signal, si_code)` lowering" — assumed no ESR existed. **P2.3 found one in `siginfo` on both
hosts**, so:

- **NetBSD: no synthesis at all.** `si_trap` is the raw 32-bit ESR_EL1 word (9 exception
  classes, every EC/ISS/WnR/IL bit independently re-decoded by the verifier). Feed
  `si_trap as u32 as u64` into `lower_el0_fault(esr, pc, addr)` and
  `el0_debug_signal(snapshot.esr)` — **zero** decision change at `translator.rs:2388-2416` or
  `native_darwin.rs:3044-3053`, **no** ABI change, **no** new `carrick-dsr-aarch64` input.
- **FreeBSD: EC-only, so partial synthesis.** The contract is
  `esr = (si_trapno << 26) | dfsc_from(si_signo, si_code)` with `0x0c` for `SEGV_ACCERR` and
  `0x21` for `(SIGBUS, BUS_ADRALN)`. **The bare `<< 26` form the probe report headlined is
  wrong** — with `dfsc = 0` the function returns `SEGV_MAPERR` unconditionally and can never
  return `SIGBUS/BUS_ADRALN`, yet FreeBSD measured `SEGV_ACCERR` in 4 of 7 fault cases and
  `BUS_ADRALN` for a misaligned `LDXR`.

**The "neutral `(signal, si_code)` lowering" recommendation is now actively REFUTED for
NetBSD**: NetBSD's `si_code` is **wrong** for permission faults (`SEGV_MAPERR` where Linux
says `SEGV_ACCERR`) while its `si_trap` DFSC `0x0F` is right. Decode the carrier; do not
trust `si_code`. **Required residual in T6: fail closed on an unrecognized EC** — FreeBSD's
`si_trapno` was measured for 6 EC values only, and EC 0x30/0x34 (HW breakpoint/watchpoint)
were **DOWNGRADED to INFERRED** by verification.

**Q4 — The ABI-hook shape (T8): same-named C symbols per host crate vs a host-injected
function pointer in `DsrContext`. → LEANS same-named C symbols for the first landing; NEEDS A
MAINTAINER RULING as a long-term seam preference.**

No probe bears on it directly, but **P9.1 shifted the trade-off**: the function-pointer
shape's main selling point was keeping the `.S` OS-agnostic, and P9.1 measured that the `.S`
ports to ELF as a **pure symbol rename that assembles first try on both hosts** — so that
benefit is now worth much less. **The trade-off:** same-named C symbols means zero `.S`
change and matches the existing Darwin `bl`-by-name shape, at the cost of N copies of the
switch (one per host crate); the function-pointer shape (the x86 `CTX_SET_FSBASE_FN` /
`X86DsrContext::set_fsbase_fn` precedent) is the cleaner long-term seam but **changes
`DsrContext` offsets, which touches the `.equ` table and every `_Static_assert` in the C
shim** — i.e. it perturbs the one artifact the campaign most wants to leave alone.

**Q5 — `NativeHost` growth: sub-seam, split, or module alias? → LEANS "module alias primary,
grow the trait only for placement/mmap concerns"; NEEDS A MAINTAINER RULING.**

T0 gave the trait a **concrete new customer**: `exclusive_fixed_map_flag` is already a
`NativeHost` method, and T17 must wire `MAP_FIXED|MAP_EXCL` probing into `map_exact` for
FreeBSD (and hint-plus-verify for NetBSD, which has no `MAP_EXCL`) — so the trait grows for
**placement** regardless of how the aarch64 concerns are seamed. Meanwhile the aarch64-shaped
concerns (counter plan, vvar clock sources, guest-ABI switch, kick signal) are reached today
through a **module alias** (`native_freebsd.rs:60-83`), not trait methods, and the trap/kick/
altstack contracts were **deliberately** kept out of the trait (`carrick-dsr/src/host.rs:4-7`).
**The trade-off:** a second module-alias seam is the low-friction path that matches the x86
precedent and keeps the trait small, but it means two parallel seam mechanisms coexist
indefinitely; folding everything into the trait is more uniform but re-opens a boundary the
existing design closed on purpose.

**Q6 — Rename `native_darwin.rs` → `native_aarch64.rs`? → NEEDS A MAINTAINER RULING (pure
taste; no data bears on it). Recommendation: defer, consistent with x86.**

One datum T0 adds: the file's `darwin_jit.rs` submodule already **mis-resolves FreeBSD/aarch64
to the x86 no-op `flush_icache`** and has **no netbsd arm at all** (V2) — so the name is not
merely stale, it is adjacent to a live bug that T1 must fix anyway. **The trade-off:** renaming
now costs git-blame continuity on a 12,985-line file (the exact reason `lib.rs:159-162`
deferred `native_freebsd.rs` → `native_x86.rs`); not renaming leaves a file named for one of
the three OSes it serves.

**Q7 — Fix or red-list the NetBSD guest-CPU-accounting gap? → LEANS "fix, but not on the
critical path"; NEEDS A MAINTAINER RULING on scope.**

No probe touched it. A NetBSD `getrusage` arm in `guest_cpu.rs:126-129` is ~15 LoC and buys
`times`/`getrusage`/proc-stat/RLIMIT_CPU/CPU-itimers. Since NetBSD is the **second** lane
(Q-order aside, §7 builds FreeBSD first), this can land with the netbsd half of T9/T12 rather
than blocking anything. **The trade-off is purely scope discipline:** 15 LoC now vs one more
line on a red list that already carries no-USDT, no-HW-debug and no-reaper for that host.

**Q8 — Does the aarch64 lane need a subreaper equivalent at all? → STILL UNANSWERED — and it
is a REPO question, not a probe question. It was not done.**

T0 measured the **primitive**: `procctl(P_PID, PROC_REAP_ACQUIRE)` + `PROC_REAP_STATUS` both
work on FreeBSD/aarch64 (P8.2c). It did **not** answer the actual question, which is whether
anything on the aarch64 path ever calls `become_guest_reaper()` — `grep` still shows **0 call
sites in `native_darwin.rs:1..5880`**. So either Darwin reaps elsewhere, or **the aarch64 lane
already carries an orphan-reaping gap on macOS today**. **Recommendation: a 30-minute targeted
read before T9**, so the campaign does not silently inherit the gap on two more hosts (and so
NetBSD's known lack of a `procctl` equivalent is costed against the right baseline).

**Q9 — stage2 gating or report-only? → LEANS report-only for the first landing; NEEDS A
MAINTAINER RULING.**

Data bears on it only indirectly, but usefully: P0.7 shows **wall time is not the risk**
(13 s cold for the acceptance path on FreeBSD, against a 7200 s per-step budget), while the
**4000-char tail truncation is** — so whichever way this goes, **stage2 must write a JSON
artifact and `cat` it.** **The trade-off:** report-only matches stage1's convention ("the red
list IS the bring-up worklist") and lets the lane land incrementally, but `cmd_ladder` prints
`PASS` on `exit_ok` — which is 0 for a report-only stage **regardless of failures** — so the
acceptance summary **must** quote `steps_ok` explicitly or the ladder will lie.
**Independent of this ruling, add the stage1.5 rung** (`cargo test -p carrick-dsr-aarch64` +
the 5 other acceptance-path crates, with `LIBCLANG_PATH` set): it is 13–15 s cold, **green
today** modulo B5, and it converts the campaign's central thesis from an argument into a gate.