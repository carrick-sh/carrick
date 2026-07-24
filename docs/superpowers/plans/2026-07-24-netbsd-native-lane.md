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

## Task 3: Futex (mirror + lane dispatch)

**Files:** `carrick-native-netbsd/src/{futex.rs,waiter_key.rs}`, `crates/carrick-runtime/src/native_freebsd.rs`... — NO. NetBSD's run loop reuses the SAME native run path as FreeBSD (native_freebsd.rs is x86-lane, but the futex call sites reference `carrick_native_freebsd::futex` directly). The seam gap (Phase-3 Task-4 review): the four `SharedFutexWait/Wake/Requeue` call sites need LANE DISPATCH. Design the minimal dispatch (a small host-futex indirection selected by the same cfg as `HostNativeLane`, OR — better — factor the shared cross-lane futex indirection the Phase-3 Task-4 SharedFutexSyscall-precedent finding pointed at, if it fits sized-to-consumption). This is the one place NetBSD forces a shared-layer change (correctly — it's the seam completing). Scout the dispatch shape in Step 1; STOP if it needs speculative surface.

- [ ] Step 1: decide the futex lane-dispatch shape (mirror-module + cfg dispatch, or the SharedFutexSyscall-style shared trait). Step 2: implement `NetbsdSharedFutex` via SYS___futex (+ waiter-table only if Task-0 says SYS___futex needs it) + waiter_key (MAP_TRYFIXED). Step 3: wire the 4 call sites to dispatch by lane. Box test + fbsd box regression (the FreeBSD lane's futex must still pass — its own futex tests + the deflaked cross-fork test 12/12). Commit `feat(netbsd): cross-process futex + lane dispatch`.

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

The NetBSD red list becomes its own campaign (like the FreeBSD LTP ladders): kqueue EVFILT wiring, lwp/clone edge cases, signal/fork coherence, the futex-correctness items (futex_cmp_requeue) inherited from the shared lane. NetBSD reaching FreeBSD-parity is the follow-on goal.
