# Platform-Agnostic Linux Emulation Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the attached platform-agnostic Linux emulation audit into a complete, evidence-backed remediation program.

**Architecture:** Treat the report as a set of candidate findings, not as authoritative implementation guidance. Each track starts with a minimal proof artifact or target-host compile gate, then fixes the smallest durable seam, then records the remaining platform limitation honestly.

**Tech Stack:** Rust 2024, Carrick Cargo workspace, existing conformance probes, host unit tests, Docker oracle where guest behavior must be compared, real FreeBSD/NetBSD/Linux target-host gates for backend claims.

## Global Constraints

- Do not read Linux kernel or GPL implementation source.
- Use existing Carrick seams before adding new abstractions.
- Rank work by correctness, robustness, durability, then leverage.
- Keep host/VMM and guest-ISA differences explicit when they are real mechanism boundaries.
- Build/run guest binaries through `just build` or `just run` on macOS when runtime execution is required.
- Do not run Carrick and Docker oracle phases concurrently.
- Keep commits narrow and do not stage unrelated files.
- Every task that changes behavior must add or update a focused proof: unit test, host integration test, conformance probe, or target-host compile/runtime gate.

---

## Scope Check

The report spans HAL contracts, x86 bring-up, VMM backends, BSD host primitives, runtime fork-coherence, VFS metadata, AF_UNIX metadata, signal semantics, and sigframe state. That is too broad for one implementation task or one commit series.

This plan is therefore a master remediation ledger. Each task below is an independently reviewable track. A track is complete only when its proof artifact is present and its current limitation is either fixed or documented with a targeted follow-up.

## Vetted Finding Status

### Confirmed High-Priority Defects

- FreeBSD shared-futex mirror assumes `host_addr + 4` is a mirror waiter field in `crates/carrick-host/src/umtx.rs`; the safety contract is not enforced at that layer.
- BSD signal translation has guest/host number collisions for Linux-only signals that identity-map through `SIGNUM_XLATE`.
- `PtyTable`, FIFO beacon state, and epoll in-memory wake registries are process-local maps/fd lists whose fork behavior needs explicit cleanup or durable ownership checks.
- `ptsname_r` is declared directly in `crates/carrick-runtime/src/vfs/devpts.rs`; NetBSD portability needs a `libc`/portable wrapper or cfg split.
- NetBSD has no `copy_user_xattrs` implementation in `crates/carrick-runtime/src/layer_cache.rs`.
- Rootfs overlay directory enumeration does not visibly share the bind-VFS sidecar filtering rule for `.carrick-lnkown.*`.
- `RegAccess` and `InjectParams` still expose ISA-specific FP/signal details through generic-looking contracts.

### Partially Stale Or Already Mitigated Claims

- The generic `carrick-x86::msr_init_blob` is present but explicitly marked unconsumed. It still lacks the bhyve copy's MXCSR/XCR0 setup, so the right fix is parity plus adoption, not treating bhyve's duplicate as the only implementation.
- Bhyve `MAP_SHARED` file aliases are still copy-backed, but current code now registers writable aliases and flushes around fork/wait barriers. The remaining work is to prove coverage, close holes, and document non-coherent cases.
- Bhyve partial uncommitted range handling has an existing `commit_range` split. The plan should regression-test it rather than blindly reimplement it.
- KVM/bhyve/NVMM timer delivery is duplicated in shape, but timer-core already owns the fallback loop. This is a cleanup task after correctness gates, not a blocker.
- `GuestArch` is intentionally a monomorphized guest-ISA seam. It may need smaller associated traits, but a broad split should wait until the concrete call sites prove benefit.

### Needs Target-Host Validation

- NVMM writable `MAP_SHARED` behavior and the report's zero-filled regular-file path need a NetBSD runtime gate.
- FreeBSD/NetBSD `/proc` host introspection gaps need target-host compile and behavior checks.
- `EPOLLPRI`/OOB behavior on FreeBSD/NetBSD kqueue should be captured as a capability difference with a target-host test.
- OFD lock fallback semantics should be tested on FreeBSD/NetBSD and either fixed with a userspace lock table or documented as a precise limitation.

## File Structure

- Modify `crates/carrick-host/src/umtx.rs`: make the FreeBSD shared futex API accept an explicit mirror-slot handle or typed waiter address instead of deriving `host_addr + 4`.
- Modify `crates/carrick-x86/src/vmm.rs`: strengthen `shared_futex_host_addr`/`shared_futex_uses_mirror` into a typed result that distinguishes direct shared words from mirror slots.
- Modify `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`: return typed mirror futex locations and add regression tests around mirrored vs non-mirrored shared futex pages.
- Modify `crates/carrick-host-bsd/src/signum.rs`: replace identity fallback for ambiguous BSD-host numbers with a complete, collision-aware translation policy.
- Modify `crates/carrick-runtime/src/dispatch/signal.rs`: add a siglongjmp/altstack reconciliation strategy or a documented probe-backed limitation if exact detection is impossible.
- Modify `crates/carrick-runtime/src/vfs/devpts.rs`: move `ptsname_r` behind `carrick-portable` or cfg-specific implementations and harden fork ownership semantics.
- Modify `crates/carrick-runtime/src/dispatch/fifo_beacon.rs`: add fork-child cleanup or owner-pid filtering for inherited beacon write fds.
- Modify `crates/carrick-runtime/src/dispatch/epoll_shim.rs`: make the wake registry fork-aware and prevent stale fd-number writes after fork.
- Modify `crates/carrick-runtime/src/dispatch/net/support.rs`: make AF_UNIX xattr persistence failure explicit and non-leaky.
- Modify `crates/carrick-runtime/src/fs_backend.rs` and `crates/carrick-runtime/src/vfs/bind.rs`: share one sidecar-filtering predicate for all directory enumeration paths.
- Modify `crates/carrick-runtime/src/layer_cache.rs`: add NetBSD user-xattr copy support or a target-host skip that preserves permission correctness by another mechanism.
- Modify `crates/carrick-portable/src/lib.rs`: replace BSD OFD command aliases with a capability-backed path or precise `ENOTSUP` behavior if emulation is not implemented in this track.
- Modify `crates/carrick-host/src/host_proc.rs`: add NetBSD `pid_info`/`parent_pid` and BSD `self_thread_cpu_us` where host APIs exist.
- Modify `crates/carrick-x86/src/bringup.rs` and `crates/carrick-vmm-bhyve/src/guest_setup_x86.rs`: make the shared x86 bring-up blob byte-complete and retire stale backend-local copies after parity tests pass.
- Modify `crates/carrick-hal/src/error.rs`, `crates/carrick-hal/src/threaded.rs`, `crates/carrick-hal/src/sigframe.rs`, `crates/carrick-hal/src/guest_arch.rs`, and `crates/carrick-hal/src/trap.rs`: narrow generic-looking HAL contracts after behavior fixes are covered.
- Add conformance probes under `conformance-probes/src/bin/` for guest-visible regressions.
- Add or update target-host docs under `docs/` for validated limitations that remain intentionally unfixed.

---

## Task 1: Prove And Fix FreeBSD Shared-Futex Mirror Safety

**Files:**
- Modify: `crates/carrick-x86/src/vmm.rs`
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`
- Modify: `crates/carrick-host/src/umtx.rs`
- Test: backend unit tests near `bhyve_x86_engine` mirror allocation
- Probe: add a shared-futex probe if no existing probe covers non-mirrored shared futex misuse

**Interfaces:**
- Produces: a typed shared-futex location enum such as `SharedFutexLocation::Direct { host_addr }` and `SharedFutexLocation::Mirror { value_addr, waiter_addr }`.
- Consumes: existing `PlatformFutex::shared_wait/shared_wake` and x86 VMM shared-futex resolution.

- [x] Add a failing unit test that routes a non-mirror shared futex through the FreeBSD wait path and proves the current API cannot distinguish it from a mirror slot.
- [x] Replace `shared_futex_host_addr` plus `shared_futex_uses_mirror` with one typed result so the waiter counter address is provided by the backend, not inferred.
- [x] Change FreeBSD `_umtx_op` wait/wake helpers to receive the explicit waiter counter address only for mirror slots.
- [x] Keep direct shared futex words on hosts that have true shared backing from touching adjacent guest memory.
- [x] Verify with `cargo test -p carrick-x86` and the bhyve backend unit tests.
- [ ] On FreeBSD, run the targeted shared-futex/LTP checkpoint gate that originally justified the mirror.
- [x] Commit as `fix(bhyve): type shared futex mirror waiters`.

**Local evidence:** `cargo test -p carrick-thread --lib -- --test-threads=1`, `cargo test -p carrick-host --lib umtx`, `cargo test -p carrick-x86 --lib`, `cargo test -p carrick-runtime --lib shared_futex`, `cargo test -p carrick-vmm-kvm --lib kvm_futex`, `cargo test -p carrick-vmm-bhyve --lib futex`, and `cargo test -p carrick-vmm-nvmm --lib futex` pass on macOS. The FreeBSD target-host LTP checkpoint gate remains open.

## Task 2: Make BSD Signal Translation Collision-Aware

**Files:**
- Modify: `crates/carrick-host-bsd/src/signum.rs`
- Modify if needed: `crates/carrick-runtime/src/exec_helpers.rs`
- Modify if needed: `crates/carrick-runtime/src/dispatch/proc.rs`
- Probe: add `conformance-probes/src/bin/bsd_signal_xlate.rs`

**Interfaces:**
- Produces: total guest-to-host and host-to-guest signal handling for ambiguous Linux/BSD numbers.
- Consumes: existing `SIGNUM_XLATE`, `linux_to_host_signum`, and `host_to_linux_signum`.

- [x] Add table tests for `SIGPWR`, `SIGSTKFLT`, `SIGURG`, `SIGUSR1`, `SIGIO`, and host `SIGINFO`.
- [x] Decide the Linux-visible policy for signals that have no safe BSD host signal carrier: emulate in carrick's explicit-signal ring, reject sends with Linux `EINVAL`, or map to an internal carrier plus metadata.
- [x] Implement the policy without identity-fallback collisions.
- [x] Ensure Ctrl+T/host `SIGINFO` is ignored or handled as a host-control signal, not delivered to the guest as Linux `SIGIO`.
- [x] Verify host unit tests on macOS and target BSD build/tests where available.
- [ ] Run a guest probe that sends and observes the affected signals under the BSD host lane.
- [x] Commit as `fix(bsd): avoid signal number collisions`.

**Local evidence:** `cargo test -p carrick-host-bsd signum --lib`, `cargo test -p carrick-runtime cross_process_xsig_policy_routes_unhostable_signals --lib`, `cargo test -p carrick-runtime wait_status_tests --lib`, `cargo test -p carrick-runtime sigdeath_marker --lib`, `cargo test -p carrick-vmm-hvf host_signal --lib`, `cargo test -p carrick-vmm-bhyve --lib signal`, `cargo test -p carrick-vmm-nvmm --lib signal`, and `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin bsd_signal_xlate` pass. The new `bsd_signal_xlate` probe still needs a BSD host-lane runtime run.

## Task 3: Harden Fork-Coherent Runtime Registries

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fifo_beacon.rs`
- Modify: `crates/carrick-runtime/src/dispatch/epoll_shim.rs`
- Modify: `crates/carrick-runtime/src/vfs/devpts.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Test: focused unit tests around close-after-fork ownership
- Probe: FIFO EOF, epoll eventfd wake, and PTY stale slave fork probes

**Interfaces:**
- Produces: fork-aware cleanup hooks for process-local registries.
- Consumes: existing dispatcher fork lifecycle, fd close paths, and `PtyTable::free_if_owner`.

- [x] Add explicit `after_fork_child` functions for FIFO beacon and epoll wake fd registry, plus PTY table owner-state coverage.
- [x] Register those hooks at the existing post-fork child reset point.
- [x] For FIFO beacons, close inherited beacon write fds in children that do not own the guest writer fd, or key beacon writer entries by owner pid and ignore stale child copies.
- [x] For epoll wake fds, clear inherited wake registries in fork children before any child fd close/reallocation can make stale fd numbers dangerous.
- [x] For PTYs, keep `owner_pid` as the authority and add tests proving child close/open cannot resurrect or expose a freed parent PTY.
- [x] Verify with `cargo test -p carrick-runtime fifo_beacon epoll pty`.
- [ ] Add guest probes for the three user-visible fork cases and run `just conformance-probes` after codesigned build.
- [x] Commit as `fix(runtime): reset fork-local fd registries`.

**Local evidence:** `cargo test -p carrick-runtime fifo_beacon --lib`, `cargo test -p carrick-runtime epoll --lib`, and `cargo test -p carrick-runtime pty --lib` pass. Guest fork probes and `just conformance-probes` remain open.

## Task 4: Close Metadata And Sidecar Leaks

**Files:**
- Modify: `crates/carrick-runtime/src/vfs/bind.rs`
- Modify: `crates/carrick-runtime/src/fs_backend.rs`
- Modify: `crates/carrick-runtime/src/layer_cache.rs`
- Modify: `crates/carrick-runtime/src/dispatch/net/support.rs`
- Test: rootfs readdir, scratch-cache xattr copy, AF_UNIX xattr fallback

**Interfaces:**
- Produces: shared internal-metadata predicates and explicit AF_UNIX persistence failure behavior.
- Consumes: bind-VFS symlink owner sidecars, rootfs overlay directory enumeration, xattr-backed AF_UNIX path stamps.

- [x] Move `is_link_owner_sidecar` or an equivalent predicate to a module usable by both bind and rootfs overlay enumeration.
- [x] Add a regression test where a rootfs directory contains `.carrick-lnkown.<name>` and assert guest readdir hides it.
- [x] Add NetBSD `copy_user_xattrs` using the host extattr/xattr API available on NetBSD, or make cache seeding preserve virtual uid/gid by avoiding metadata-dropping fast paths on NetBSD.
- [x] Change AF_UNIX bind persistence so xattr failure records an explicit non-persistent state; do not later leak a private host `<hash>.sock` path as if it were guest-visible truth.
- [x] Add a test for xattr-unavailable AF_UNIX nodes that expects either the original guest path from durable fallback metadata or a Linux-compatible failure, never host path leakage.
- [x] Verify with `cargo test -p carrick-runtime sidecar xattr unix`.
- [x] Commit as `fix(runtime): hide internal metadata across backends`.

**Local evidence:** `cargo test -p carrick-runtime readdir_hides_internal_sidecar_entries --lib`, `cargo test -p carrick-runtime layered_directory_entries_hide_internal_sidecar_names --lib`, `cargo test -p carrick-runtime sidecar --lib`, `cargo test -p carrick-runtime unix --lib`, `cargo test -p carrick-runtime host_to_linux_sockaddr_unix_falls_back_to_xattr_across_processes --lib`, and `cargo check -p carrick-portable --target x86_64-unknown-netbsd` pass. NetBSD layer-cache fast seeding remains conservative: the current runtime does not enable the Linux/FreeBSD `replicate_tree` cache path on NetBSD, so no metadata-dropping seed path was added in this task; real NetBSD scratch-cache behavior remains a target-host gate.

## Task 5: Make NetBSD And BSD Host Introspection Buildable

**Files:**
- Modify: `crates/carrick-runtime/src/vfs/devpts.rs`
- Modify: `crates/carrick-portable/src/lib.rs`
- Modify: `crates/carrick-host/src/host_proc.rs`
- Test: target-host `cargo check` for NetBSD and FreeBSD feature sets

**Interfaces:**
- Produces: cfg-correct pty naming, process ancestry, and thread CPU accounting.
- Consumes: existing `carrick-portable` OS shim and `/proc` emulation call sites.

- [ ] Move pty slave-name resolution behind `carrick-portable`; use `libc` functions where available and cfg out unsupported host calls cleanly.
- [ ] Add a NetBSD build gate that proves `ptsname_r` no longer hard-links from runtime code when absent.
- [ ] Implement NetBSD `pid_info` and `parent_pid` from a clean host API source, or return a documented Linux-compatible absence only for inaccessible non-guest processes.
- [ ] Add FreeBSD and NetBSD `self_thread_cpu_us` support if host APIs provide per-thread accounting; otherwise document why `RUSAGE_THREAD` parity cannot be claimed on that host.
- [ ] Verify with target-host `cargo build -p carrick-cli --no-default-features --features platform-netbsd` and `platform-freebsd`.
- [ ] Commit as `fix(portable): gate bsd host introspection`.

## Task 6: Validate And Improve MAP_SHARED Semantics

**Files:**
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`
- Modify: `crates/carrick-vmm-nvmm/src/nvmm_x86_engine.rs`
- Modify if needed: `crates/carrick-x86/src/vmm.rs`
- Probe: file-backed `MAP_SHARED` fork/writeback probe and SysV shm probe

**Interfaces:**
- Produces: explicit backend capability results for file-backed shared aliases.
- Consumes: existing bhyve alias flush/refresh hooks and NVMM alias registration.

- [ ] Add a differential probe that maps a file `MAP_SHARED`, writes before and after fork, waits, and checks parent, child, and host file visibility against Docker.
- [ ] Run the probe on HVF/KVM first to establish the known-good model.
- [ ] Run or queue the same probe on bhyve and NVMM target hosts.
- [ ] For bhyve, verify existing `flush_shm_aliases` and `refresh_shared_after_wait` cover the probe; close any missing exit/wait/vfork path.
- [ ] For NVMM, decide whether writable aliases can use true registered HVA or need the same file-mediated flush/refresh path.
- [ ] Convert remaining unsupported cases into capability checks that fail loudly with a Linux errno or documented baseline gap, not silent incoherence.
- [ ] Commit as `fix(x86): prove shared file alias coherence`.

## Task 7: Adopt Shared x86 Bring-Up Blobs Safely

**Files:**
- Modify: `crates/carrick-x86/src/bringup.rs`
- Modify: `crates/carrick-vmm-bhyve/src/guest_setup_x86.rs`
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`
- Test: blob-byte parity tests and AVX/floating-point smoke fixtures

**Interfaces:**
- Produces: one byte-complete `msr_init_blob`/FP-stub implementation in `carrick-x86`.
- Consumes: bhyve `NeedsRing0Blob` and `run_fp_stub` paths.

- [ ] Add parity tests comparing the shared `carrick-x86` blob to the currently working bhyve blob, including MXCSR mask setup and `XCR0 = 0x7`.
- [ ] Make `carrick-x86::msr_init_blob` include the missing MXCSR/XCR0 sequence and any entry-register preservation needed by bhyve.
- [ ] Repoint bhyve to the shared blob and shared `run_fp_stub`.
- [ ] Delete stale backend-local duplicates only after parity and runtime smoke pass.
- [ ] Verify with `cargo test -p carrick-x86`, `cargo test -p carrick-vmm-bhyve`, and the bhyve AVX/FP signal fixtures on FreeBSD.
- [ ] Commit as `refactor(x86): share complete bringup blobs`.

## Task 8: Rationalize Timer Delivery Duplication

**Files:**
- Modify: `crates/carrick-hal/src/timer_delivery.rs` if a helper belongs in HAL
- Modify: `crates/carrick-vmm-kvm/src/timer_delivery.rs`
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_threaded_glue.rs`
- Modify: `crates/carrick-vmm-nvmm/src/nvmm_threaded_glue.rs`
- Test: timer-core/unit tests plus one POSIX timer guest probe

**Interfaces:**
- Produces: one shared fallback POSIX timer arm helper parameterized by kicker and thread id.
- Consumes: `carrick_timer_core::posix::run_fallback` and process-signal publication.

- [ ] Confirm current duplication is byte-equivalent after comments and host-specific names are ignored.
- [ ] Extract only the shared arm/disarm helper; keep backend-specific kqueue/no-kqueue decisions local.
- [ ] Preserve existing semantics: process-directed signal publication plus `kick_all`.
- [ ] Verify timer unit tests and a guest POSIX timer smoke under HVF/KVM plus target BSD lane if available.
- [ ] Commit as `refactor(timer): share fallback posix delivery`.

## Task 9: Fix Or Fence BSD Epoll/OFD Semantics

**Files:**
- Modify: `crates/carrick-host-bsd/src/kqueue.rs`
- Modify: `crates/carrick-host-bsd/src/multiplexer.rs`
- Modify: `crates/carrick-portable/src/lib.rs`
- Modify if needed: runtime fcntl/OFD lock handling
- Probe: OOB/`EPOLLPRI` probe and OFD double-open lock probe

**Interfaces:**
- Produces: capability-backed BSD event and lock behavior.
- Consumes: current kqueue event filters and portable OFD constants.

- [ ] Add a probe for TCP OOB readiness mapped through `EPOLLPRI`.
- [ ] On FreeBSD/NetBSD, prove whether the current sentinel behavior returns a controlled Linux errno or silently drops readiness.
- [ ] If OOB cannot be supported, document it as a capability gap and ensure registration fails predictably.
- [ ] Add a probe where one process opens the same file twice and exercises Linux OFD lock independence.
- [ ] Either implement a Carrick OFD lock table keyed by open description for BSD hosts, or reject OFD locks with a clear Linux errno instead of pretending process locks are equivalent.
- [ ] Verify on target BSD hosts.
- [ ] Commit as `fix(bsd): fence unsupported epoll and ofd semantics`.

## Task 10: Repair Signal Altstack State After Non-`rt_sigreturn` Handler Exit

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/signal.rs`
- Modify if needed: per-ISA sigframe restoration hooks
- Probe: `siglongjmp` from `SA_ONSTACK` signal handler

**Interfaces:**
- Produces: a correct or explicitly bounded model for active signal-frame tracking.
- Consumes: `handler_frames`, `sigaltstack`, `rt_sigreturn`, and signal delivery bookkeeping.

- [ ] Add a Linux/Docker oracle probe where a signal handler on altstack exits via `siglongjmp`, then later signals and `sigaltstack(NULL, &old)` are observed.
- [ ] Run the probe under Carrick to prove the reported stuck-on-altstack behavior.
- [ ] Evaluate durable detection options: guest SP range reconciliation before `sigaltstack` queries, frame-token validation on delivery, or clearing stale frames when PC/SP prove the handler is no longer active.
- [ ] Implement the smallest option that matches Docker for the probe without breaking nested signal handlers that return normally through `rt_sigreturn`.
- [ ] Verify with the new probe plus existing signal unit tests.
- [ ] Commit as `fix(runtime): reconcile altstack after siglongjmp`.

## Task 11: Narrow HAL Contracts After Correctness Fixes

**Files:**
- Modify: `crates/carrick-hal/src/error.rs`
- Modify: `crates/carrick-hal/src/threaded.rs`
- Modify: `crates/carrick-hal/src/sigframe.rs`
- Modify: `crates/carrick-hal/src/guest_arch.rs`
- Modify: `crates/carrick-hal/src/trap.rs`
- Modify: backend implementations in `crates/carrick-vmm-hvf`, `crates/carrick-vmm-kvm`, `crates/carrick-vmm-bhyve`, and `crates/carrick-vmm-nvmm` as required
- Test: compile-shape tests in `carrick-hal` plus backend compile gates

**Interfaces:**
- Produces: clearer ISA-specific register/sigframe/trap contracts without hiding real backend differences.
- Consumes: existing `Reg`, `SysReg`, `RegAccess`, `InjectParams`, `TrapError`, `GuestArch`, and `SyscallTrap`.

- [ ] Split register identifiers into guest-ISA typed surfaces or associated register enums so AArch64 engines do not carry x86 register variants as generic obligations.
- [ ] Move x86 FP/SIMD save/restore shape out of generic `RegAccess`; expose it through an x86 sigframe trait or associated helper.
- [ ] Split `InjectParams` into ISA-neutral signal delivery inputs plus AArch64-specific frame extras.
- [ ] Keep `set_memory_model` explicit but rename or move it to a memory-model capability so it is not presented as a generic syscall-trap operation.
- [ ] Lower AArch64 raw `EL0Fault`/`GuestAtEl1` into ISA-neutral `GuestFault` before generic runtime boundaries where feasible; keep raw details in backend diagnostics.
- [ ] Do not split `GuestArch` just for aesthetics. Split only where a call site can depend on one focused associated trait without dragging page-table, vDSO, trampoline, and signal-frame responsibilities together.
- [ ] Verify with `cargo test -p carrick-hal` and backend `cargo check` gates.
- [ ] Commit as `refactor(hal): narrow isa-specific contracts`.

## Task 12: Decide HVF Adoption Of `HvVm`/`HvVcpu`

**Files:**
- Modify if adopted: `crates/carrick-hal/src/hypervisor.rs`
- Modify if adopted: `crates/carrick-vmm-hvf/src/*`
- Docs: update `docs/hal.md`

**Interfaces:**
- Produces: either HVF implementations of raw hypervisor traits or a documented decision that `SyscallTrap`/engine-level traits are the real shared seam.
- Consumes: existing `HvVm`/`HvVcpu`, KVM implementations, and HVF applevisor direct driver.

- [ ] Audit actual consumers of `HvVm`/`HvVcpu`; do not widen the abstraction if KVM is the only user.
- [ ] Compare the value of HVF adoption against keeping applevisor-specific lifecycle explicit.
- [ ] If adoption reduces duplicated backend lifecycle code, implement a small HVF adapter and compile-shape tests.
- [ ] If adoption adds indirection without shared consumers, document the boundary and remove claims that this is a portability blocker.
- [ ] Verify with `just check -p carrick-vmm-hvf` or the closest available workspace check.
- [ ] Commit as `docs(hal): classify raw hypervisor seam` or `refactor(hvf): implement raw hv traits`.

## Final Gate

- [ ] Run `just fmt-check`.
- [ ] Run `just clippy`.
- [ ] Run `just test`.
- [ ] Run `just test-integration`.
- [ ] Run `just conformance-probes` after `just build` on macOS.
- [ ] Run target-host build gates for Linux/KVM, FreeBSD/bhyve, and NetBSD/NVMM for all tasks that touched those lanes.
- [ ] Re-render docs/support artifacts only when the relevant command is part of the task.
- [ ] Update this plan with completed task links and any intentionally deferred limitations.

## Recommended Execution Order

1. Task 1: FreeBSD futex mirror safety.
2. Task 2: BSD signal collision handling.
3. Task 3: fork-coherent runtime registries.
4. Task 4: metadata and sidecar leaks.
5. Task 5: NetBSD/BSD portability build blockers.
6. Task 6: `MAP_SHARED` behavior proof and fixes.
7. Task 10: siglongjmp/altstack behavior.
8. Task 7: shared x86 bring-up adoption.
9. Task 9: BSD epoll/OFD semantics.
10. Task 8: timer delivery cleanup.
11. Task 11: HAL contract narrowing.
12. Task 12: HVF raw hypervisor seam decision.

This ordering intentionally puts correctness and fork-coherence before abstraction work. HAL cleanup should consume the facts produced by the earlier tracks, not preempt them.
