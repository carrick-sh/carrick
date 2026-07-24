# NetBSD/x86_64 Native Lane Bring-Up — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bring up a NetBSD/x86_64 host lane for the native backend — a static x86_64 ELF running under `--exec-backend native` on NetBSD — proving the seam floor makes a new lane host-glue. Reuse `carrick-dsr-x86` + `identity_memory` verbatim; build only the NetBSD host-OS seam.

**Architecture:** New `carrick-native-netbsd` crate (NativeHost impl: JIT, fault shim, futex, waiter-key, lwp threads) + wiring (`native/mod.rs` third `HostNativeLane` arm, `page_profile` capability entry). Scout-first: characterize NetBSD primitives on VM 201 before committing crate shapes.

**Design:** `docs/superpowers/specs/2026-07-24-netbsd-native-lane-design.md` (approved).

**Host:** willow VM 201 (`root@10.14.14.136`, NetBSD 10.1 amd64, rust 1.96, libclang). Wake: `ssh root@willow 'qm start 201'` (~40s). bindgen needs `LIBCLANG_PATH=/usr/pkg/lib`. Sync: `git archive HEAD | ssh root@10.14.14.136 'rm -rf /root/carrick && mkdir /root/carrick && tar -C /root/carrick -xf -'`.

## Global Constraints

- Same-ISA: `carrick-dsr-x86` + `identity_memory` reused VERBATIM. If either needs a NetBSD change → shared-seam defect, STOP + escalate (don't patch locally).
- Scout-first per subsystem; STOP-with-gap if a primitive can't support what the lane needs.
- Clean-room: NetBSD ABIs from man-pages/box-headers/oracle only; the mremap-oracle pattern for any ABI question.
- No scattered `#[cfg(target_os)]` in shared code; NetBSD joins `HostNativeLane` as one new cfg arm.
- Build/verify on VM 201 (the NetBSD lane compiles only there — like native_freebsd on the fbsd box): `LIBCLANG_PATH=/usr/pkg/lib . ~/.cargo/env && cargo build/test ...`. macOS + the fbsd box must stay green (NetBSD crate is `#![cfg(target_os="netbsd")]`, empty elsewhere; the wiring cfg must not break existing lanes). Restore VM 201 to a clean state after; STOP/BLOCKED if unexpected.
- Logical commit per task, standard trailers (`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + session `Claude-Session:`), NEVER `--no-verify`.
- Branch: `feat/netbsd-native-lane` off main ≥ c8fe6192.

## Task 0: Grounding scout (on-box characterization → committed grounding doc)

**Files:** Create `docs/superpowers/specs/2026-07-25-netbsd-primitives-grounding.md`. No carrick code.

Wake VM 201; sync current main. For EACH host primitive, characterize on the box (compile tiny C probes with `cc`, read `/usr/include` headers, run man pages) and decide a mechanism or a BLOCKED-with-gap:

- [ ] **JIT/W^X:** Does NetBSD have `SHM_ANON`? (grep `/usr/include/sys/mman.h`.) If no (expected), which fork-repair mechanism: named `shm_open`+`shm_unlink`+dual-map, `MAP_PRIVATE` CoW (Darwin `Inherited`-style), or `mprotect` RW↔RX (only if NetBSD's threading makes it safe — FreeBSD rejected it as process-wide). Prove the chosen mechanism with a C probe (map RX+RW aliases, write via RW, execute via RX, fork, confirm child's writes don't hit parent's exec pages). Decide `remap_for_fork_child`'s `Fresh`/`Inherited` answer.
- [ ] **Fault shim:** NetBSD `mcontext_t`/`__mcontext`/`__gregs` layout for amd64 (`/usr/include/machine/mcontext.h`, `/usr/include/sys/ucontext.h`) — the RIP/RSP/GPR/error-code register indices a signal handler reads. C probe: install a SIGSEGV handler, fault, read the trap RIP from mcontext, confirm.
- [ ] **Futex:** `SYS___futex` signature + semantics (`/usr/include/sys/futex.h`, `man 2 __futex`, syscall number in `/usr/include/sys/syscall.h`). Does it support cross-process (shared-memory futex word), FUTEX_REQUEUE/CMP_REQUEUE, and a woken-count return? (FreeBSD `_umtx_op` lacked count+atomic-requeue → the waiter-table workaround; determine if NetBSD needs the same or is closer to Linux `SYS_futex`.) STUDY `crates/carrick-vmm-nvmm/src/nvmm_futex.rs` (in-repo NetBSD SYS___futex art) + `carrick_host` NetBSD futex helpers. C probe: cross-process wait/wake via a MAP_SHARED word.
- [ ] **Threads:** lwp creation (`_lwp_create`, `/usr/include/lwp.h`) for guest `clone(CLONE_VM|CLONE_THREAD)` — the NetBSD analog of the FreeBSD pthread-based `spawn_clone_thread`.
- [ ] **Verbatim-reuse probe:** on the box, `cargo build -p carrick-dsr-x86 -p carrick-mem` (identity_memory lives in carrick-dsr per Phase 2) with `LIBCLANG_PATH` — do they compile clean on NetBSD, or surface cfg gaps? Catalog any gap (that's a shared-seam item, not NetBSD-local).
- [ ] Commit the grounding doc: `docs(netbsd): host-primitive grounding for the native lane`. If any primitive is BLOCKED (e.g. SYS___futex can't do cross-process), STOP → escalate before Task 1.

## Task 1: `carrick-native-netbsd` crate + NativeHost JIT

**Files:** new `crates/carrick-native-netbsd/{Cargo.toml,src/lib.rs,src/jit.rs}` (+ `build.rs`/csrc if the fault shim needs C — likely Task 2), workspace membership (check the `crates/*` glob).

- [ ] Create the crate (`#![cfg(target_os="netbsd")]`, mirror `carrick-native-freebsd`'s shape). Implement `NetbsdHostJit: carrick_dsr::host::NativeHostJit` using Task-0's chosen W^X mechanism; `remap_for_fork_child` per Task-0's decision; `NetbsdHost: carrick_dsr::lane::NativeHost` (NAME="netbsd", active_jit). Unit test the JIT (map/write/exec/fork-repair) on the box. Verify: box `cargo test -p carrick-native-netbsd`; macOS + fbsd box unaffected (empty crate elsewhere). Commit `feat(netbsd): host crate + W^X JIT`.

## Task 2: Fault shim + kick

**Files:** `carrick-native-netbsd/src/fault.rs` (+ csrc if a C trap shim is cleaner, mirroring native_darwin.c's role). Redirect SIGSEGV/SIGBUS/SIGFPE to the guest via NetBSD mcontext (Task-0 layout); kick transport for thread wake.

- [ ] Implement + box unit test (fault → guest handler delivery). Commit `feat(netbsd): fault shim + kick transport`.

## Run-path scout verdict (2026-07-25, `e321f1ba`) + review corrections (`acae446e` review)

The run-path sharing scout (`docs/superpowers/specs/2026-07-25-netbsd-runpath-sharing-scout.md`)
inventoried native_freebsd.rs (15,784 ln, `#![cfg(all(freebsd,x86_64))]`). **Verdict:
THESIS HOLDS — bounded host-glue, no run-loop LOGIC welded.** 4 shared-already / 9
lane-dispatchable / **2 FreeBSD-welded** (both graceful: `procctl(PROC_REAP_ACQUIRE)`
subreaper → red-list capability gap on NetBSD; TSC vDSO sysctl-names → `None` fallback).
**No thread-spawn gap** — the guest-clone thread uses `std::thread::Builder` +
`libc::pthread_kill` (native_freebsd.rs:7855/7696), portable; no `_lwp_create` needed.

An adversarial review (verified against source) CONFIRMED the thesis but corrected three
over-optimistic framings — folded into the tasks below:

1. **[F1, highest] The inline TEST surface is FreeBSD-welded and un-inventoried.**
   native_freebsd.rs has 119 `#[test]` fns; `mod identity_raw_range_tests`
   (native_freebsd.rs:218, gated only `#[cfg(test)]`) imports
   `carrick_native_freebsd::futex::{SYS_UMTX_OP, UMTX_OP_WAKE, waiter_parked_count}`
   (225-227) and issues raw `SYS_UMTX_OP`/`UMTX_OP_WAKE` (517-524); another test uses
   `libc::__error()` (11662, NetBSD is `__errno`). Flipping the file `#![cfg]` to
   `any(freebsd,netbsd)` breaks `cargo test`/`--all-targets` on NetBSD. **Fix (Task 3a):**
   gate the FreeBSD-welded inline test surface `#[cfg(all(test, target_os="freebsd"))]`.
   The run loop's 119 unit tests stay FreeBSD-lane; NetBSD unit-test coverage of the shared
   loop is a RED-LIST follow-on, not this campaign.
2. **[F2] `carrick-native-netbsd` has NO `futex.rs` yet** (only fault/jit/lib). The
   "futex module exists on both crates" claim was false; NetBSD futex is net-new (Task 3b),
   mirroring the 4-fn symmetric API below.
3. **[F3] `procctl` degradation is behavioral, not a pure no-op** — without it, guest
   double-forked orphans reparent to host init (not guest-init), so guest `wait4` returns
   ECHILD and the run loop's own subreaper bookkeeping (native_freebsd.rs:12093-12103,
   getppid-reports-guest-init) goes stale. Red-list this behavior precisely. The kick is a
   signal **pair** (`FREEBSD_NATIVE_EXIT_KICK_SIGNAL=65` and `+1`, at 6156-6157/15703-15704);
   NetBSD's `NATIVE_EXIT_KICK_SIGNAL=33` needs `+1`=34 reserved too (both first-two-RT).

**Box constraint:** Task 3a edits native_freebsd.rs while it is still freebsd-gated → it
compiles only on FreeBSD in isolation. Because the FreeBSD box is contended (regression
DEFERRED per maintainer), 3a+3b are authored as two logical commits but **verified as a
stack on the NetBSD box** (VM 201) after 3b's cfg flip makes the file compile there; the
FreeBSD-lane build+test+LTP regression gates **merge**, not authoring.

## Task 3a: Host-ops seam + FreeBSD behind it + test-gating (behavior-preserving)

**Files:** `crates/carrick-runtime/src/native_freebsd.rs`; `crates/carrick-dsr/src/lane.rs`
(the `NativeHost` trait — add the 2 methods); `crates/carrick-native-freebsd/src/lib.rs`
(FreeBSD impls of the 2 methods).

- [ ] **Seam the host-primitive sites.** Introduce `type LaneHost = <HostNativeLane as
  NativeLane>::Host` (or equivalent) and route the ~16 `MAP_EXCL`
  (`FreebsdHost::exclusive_fixed_map_flag`), JIT (`active_host_jit`/`FreebsdHostJit` at
  7175/8175/8275/8966/8995/9781), and waiter-key sites through it. Most are ALREADY behind
  `NativeHost`/`NativeHostJit` trait methods — verify each is a mechanical alias swap; flag
  any that isn't.
- [ ] **Add 2 `NativeHost` methods** for the 2 welded services, FreeBSD impl only this task:
  `become_guest_reaper()` (wraps `procctl(PROC_REAP_ACQUIRE)` at 8388) and
  `vdso_tsc_calibration() -> Option<...>` (wraps the TSC sysctl block 6378-6462). Route the
  two call sites through the trait. Default trait bodies: reaper = best-effort no-op returning
  a "not-subreaper" indicator; tsc = `None`.
- [ ] **Gate the FreeBSD-welded inline test surface** `#[cfg(all(test, target_os="freebsd"))]`
  (F1): at minimum `mod identity_raw_range_tests` (218) and any `#[cfg(test)]` module
  referencing `carrick_native_freebsd::futex::` internals or `libc::__error()`. On FreeBSD
  this is a no-op (tests still compile+run); it prevents the NetBSD compile break in 3b.
- [ ] Behavior-preserving on FreeBSD. Commit `refactor(native): host-ops seam behind
  native_freebsd run loop`. FreeBSD-box build+test verification is DEFERRED (gates merge).

## Task 3b: Re-gate to any(freebsd,netbsd) + NetBSD futex + dispatch

**Files:** `crates/carrick-runtime/src/native_freebsd.rs` (the `#![cfg]` flip + module-alias
`use` block + call-site path edits); new `crates/carrick-native-netbsd/src/futex.rs`;
`carrick-native-netbsd/src/lib.rs` (export futex; impl the 2 `NativeHost` methods).

- [ ] **NetBSD futex.rs** — mirror the FreeBSD symmetric production API via `SYS___futex`
  (166): `pub fn init_shared_waiter_table()` → **no-op** (SYS___futex is Linux-shaped: native
  woken-count + `FUTEX_CMP_REQUEUE`, so NO waiter-table workaround — per grounding doc);
  `pub fn shared_wait(word: usize, waiter_key: usize, value: u32, timeout:
  Option<Duration>, interrupted: &dyn Fn() -> bool) -> i64`;
  `pub fn shared_wake(word: usize, waiter_key: usize, count: u32) -> i64`;
  `pub fn shared_requeue(from_word: usize, from_key: usize, to_key: usize, wake_count: u32,
  requeue_count: u32) -> (u32, u32)`. Clean-room: `SYS___futex` ABI from the box's
  `/usr/include/sys/futex.h` + man page + `crates/carrick-vmm-nvmm/src/nvmm_futex.rs`
  (in-repo art); the mremap-oracle pattern for any ABI question. Cross-process via the
  MAP_SHARED word (grounding-doc-verified).
- [ ] **Impl the 2 `NativeHost` methods on `NetbsdHost`**: `become_guest_reaper()` → the
  graceful degradation (no procctl; document the ECHILD/getppid divergence, F3);
  `vdso_tsc_calibration()` → `None` (NetBSD lacks the FreeBSD TSC sysctl names). Reserve
  `NATIVE_EXIT_KICK_SIGNAL+1`=34 alongside 33 (F3 kick-pair).
- [ ] **Re-gate + dispatch (atomic with the above):** flip native_freebsd.rs:26 `#![cfg]` to
  `#![cfg(all(any(target_os="freebsd", target_os="netbsd"), target_arch="x86_64"))]`; replace
  the 5 `carrick_native_freebsd::futex::` call sites (8379/10797/10838/10873/10903) with a
  cfg-selected module alias (`use carrick_native_freebsd::futex;` on freebsd /
  `use carrick_native_netbsd::futex;` on netbsd) + `futex::fn(...)`; same alias pattern for
  the `fault` module + kick const. (Filename stays `native_freebsd.rs` this campaign for
  git-blame continuity — rename to a neutral name is a logged follow-on.)
- [ ] **Verify the 3a+3b stack on the NetBSD box** (VM 201): `LIBCLANG_PATH=/usr/pkg/lib
  cargo build -p carrick-runtime` compiles; `carrick-native-netbsd` futex unit test
  (cross-process wait/wake via MAP_SHARED word) passes. FreeBSD-lane regression DEFERRED
  (gates merge). Commit `feat(netbsd): cross-process futex + re-gate run loop to any(freebsd,netbsd)`.

## Task 4: Wiring

**Files:** `native/mod.rs` (`NetbsdX8664Lane` + third `HostNativeLane` arm), `page_profile.rs` (`(NetBsd, Amd64)` entry), `carrick-portable` (complete NetBSD arms if the build surfaces gaps), Cargo.toml deps (netbsd-target-gated).

- [ ] Wire; verify the one-cfg-pair discipline holds (drift-guard test extends to NetBSD). macOS + fbsd box + NetBSD box all build. Commit `feat(netbsd): wire NetbsdX8664Lane into the native facade`.

## Task 5: ACCEPTANCE — static ELF runs + gate ladder

- [ ] **Step 1:** a static x86_64 hello ELF runs under the native dispatch path on NetBSD (reuse the `run_elf_native_dispatch` entry, the hello-x86_64 fixture). RED→GREEN on the box. This is the campaign's acceptance moment.
- [ ] **Step 2:** adapt `scripts/native-x86-ltp-gate.py` to the NetBSD host (a bsdvm-style or direct-ssh gate; the LTP static-musl fixtures need to reach VM 201). Run the curated set; record the pass-set. Parity-minus-known-gaps = success; the red list IS the NetBSD worklist (kqueue EVFILT, lwp edge cases, etc.).
- [ ] **Step 3:** commit series (acceptance fixture wiring + gate script + a `docs/netbsd-native-lane-evidence.md` with the pass-set + red-list worklist). If Step 1 can't reach a running ELF due to a shared-seam gap, STOP → that gap is the finding (escalate; it may reshape the plan).

## Task 6: Evidence + gate

- [ ] macOS `just ci` + fbsd box regression (the FreeBSD lane untouched) + NetBSD box acceptance. Evidence doc: what host-glue NetBSD needed (the ~N-line crate — measure vs the "~15 lines" thesis), which shared-seam changes NetBSD forced (futex dispatch), the red-list worklist, honest "what NetBSD does NOT yet do." Commit `docs(netbsd): native lane evidence` → finishing-a-development-branch.

## Follow-on pointer

The NetBSD red list becomes its own campaign (like the FreeBSD LTP ladders): kqueue EVFILT wiring, lwp/clone edge cases, signal/fork coherence, the futex-correctness items (futex_cmp_requeue) inherited from the shared lane. NetBSD reaching FreeBSD-parity is the follow-on goal. **Named red-list carry-ins from the run-path review:** (F1) NetBSD lacks unit-test coverage of the shared run loop — the 119 native_freebsd.rs inline tests stay FreeBSD-gated; porting the OS-agnostic ones to run on NetBSD is a follow-on. (F3) `procctl` subreaper capability gap — guest double-forked orphans reparent to host init on NetBSD, so guest `wait4` of grandchildren returns ECHILD and getppid/subreaper bookkeeping (native_freebsd.rs:12093-12103) is stale; a NetBSD reap mechanism (or an accepted-limitation doc) is the follow-on. Rename `native_freebsd.rs` to a lane-neutral name (it now serves both BSDs) — deferred this campaign for git-blame continuity.
