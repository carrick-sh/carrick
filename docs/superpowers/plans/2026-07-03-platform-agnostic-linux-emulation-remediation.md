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
- [x] On FreeBSD, run the targeted shared-futex/LTP checkpoint gate that originally justified the mirror.
- [x] Commit as `fix(bhyve): type shared futex mirror waiters`.

**Evidence:** `cargo test -p carrick-thread --lib -- --test-threads=1`, `cargo test -p carrick-host --lib umtx`, `cargo test -p carrick-x86 --lib`, `cargo test -p carrick-runtime --lib shared_futex`, `cargo test -p carrick-vmm-kvm --lib kvm_futex`, `cargo test -p carrick-vmm-bhyve --lib futex`, and `cargo test -p carrick-vmm-nvmm --lib futex` pass on macOS. FreeBSD VM 200 (`10.14.14.189`) now passes the targeted shared-futex probes under bhyve: `futexshare` reports `futex_shared_cross_process=true`, and `futexsharedalias` matches its refreshed amd64-musl oracle.

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
- [x] Run a guest probe that sends and observes the affected signals under the BSD host lane.
- [x] Commit as `fix(bsd): avoid signal number collisions`.

**Evidence:** `cargo test -p carrick-host-bsd signum --lib`, `cargo test -p carrick-runtime cross_process_xsig_policy_routes_unhostable_signals --lib`, `cargo test -p carrick-runtime wait_status_tests --lib`, `cargo test -p carrick-runtime sigdeath_marker --lib`, `cargo test -p carrick-vmm-hvf host_signal --lib`, `cargo test -p carrick-vmm-bhyve --lib signal`, `cargo test -p carrick-vmm-nvmm --lib signal`, and `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin bsd_signal_xlate` pass. FreeBSD VM 200 (`10.14.14.189`) passes the `bsd_signal_xlate` runtime probe under bhyve: `child_handlers_installed`, `kill_sigstkflt_ok`, `kill_sigpwr_ok`, `kill_sigio_ok`, `child_waited`, and `child_exited_zero` all report `true`.

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
- [x] Add guest probes for the three user-visible fork cases and run `just conformance-probes` after codesigned build.
- [x] Commit as `fix(runtime): reset fork-local fd registries`.

**Evidence:** `cargo test -p carrick-runtime fifo_beacon --lib`, `cargo test -p carrick-runtime epoll --lib`, and `cargo test -p carrick-runtime pty --lib` pass. Guest probes now cover the user-visible fork cases: `fifoforkeof`, `epollforkeventfd`, and `ptyforkreopen` all pass in the local `just conformance-probes` arm64-musl gate. Target smoke coverage also passed with the same probes under Linux KVM VM 210 (`10.14.14.66`) and FreeBSD VM 200 (`10.14.14.189`) after replacing `/root/carrick` with commit `7e5fa359`.

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

- [x] Move pty slave-name resolution behind `carrick-portable`; use `libc` functions where available and cfg out unsupported host calls cleanly.
- [x] Add a NetBSD build gate that proves `ptsname_r` no longer hard-links from runtime code when absent.
- [x] Implement NetBSD `pid_info` and `parent_pid` from a clean host API source, or return a documented Linux-compatible absence only for inaccessible non-guest processes.
- [x] Add FreeBSD and NetBSD `self_thread_cpu_us` support if host APIs provide per-thread accounting; otherwise document why `RUSAGE_THREAD` parity cannot be claimed on that host.
- [x] Verify with target-host `cargo build -p carrick-cli --no-default-features --features platform-freebsd`; defer `platform-netbsd` per user direction.
- [x] Commit as `fix(portable): gate bsd host introspection`.

**Evidence:** `cargo check -p carrick-portable`, `cargo check -p carrick-portable --target x86_64-unknown-freebsd`, `cargo check -p carrick-portable --target x86_64-unknown-netbsd`, `cargo check -p carrick-host`, `cargo check -p carrick-host --target x86_64-unknown-freebsd`, `cargo check -p carrick-host --target x86_64-unknown-netbsd`, `cargo check -p carrick-runtime --lib`, and `cargo test -p carrick-host --lib` pass. Full FreeBSD verification now also passes natively on VM 200 (`10.14.14.189`): `cargo check -p carrick-host-bsd --lib`, `cargo check -p carrick-portable --lib`, `cargo check -p carrick-runtime --lib --no-default-features --features platform-freebsd`, and `cargo build -p carrick-cli --no-default-features --features platform-freebsd --release` via the local `just build` recipe. NetBSD/NVMM is intentionally skipped in this execution pass per user direction.

## Task 6: Validate And Improve MAP_SHARED Semantics

**Files:**
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`
- Modify: `crates/carrick-vmm-nvmm/src/nvmm_x86_engine.rs`
- Modify if needed: `crates/carrick-x86/src/vmm.rs`
- Probe: file-backed `MAP_SHARED` fork/writeback probe and SysV shm probe

**Interfaces:**
- Produces: explicit backend capability results for file-backed shared aliases.
- Consumes: existing bhyve alias flush/refresh hooks and NVMM alias registration.

- [x] Add a differential probe that maps a file `MAP_SHARED`, writes before and after fork, waits, and checks parent, child, and host file visibility against Docker.
- [x] Run the probe on HVF/KVM first to establish the known-good model.
- [x] Run or queue the same probe on bhyve and NVMM target hosts.
- [x] For bhyve, verify existing `flush_shm_aliases` and `refresh_shared_after_wait` cover the probe; close any missing exit/wait/vfork path.
- [x] For NVMM, decide whether writable aliases can use true registered HVA or need the same file-mediated flush/refresh path.
- [x] Convert remaining unsupported cases into capability checks that fail loudly with a Linux errno or documented baseline gap, not silent incoherence.
- [x] Commit as `test(conformance): probe shared file writeback`.

**Evidence:** added `mmapfileforkwriteback`, which checks parent pre-fork writes, child post-fork writes, parent post-wait mapping visibility, and backing-file visibility for child and parent writes. `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin mmapfileforkwriteback` and `cargo check --manifest-path conformance-probes/Cargo.toml --target x86_64-unknown-linux-musl --bin mmapfileforkwriteback` pass. Local HVF `scripts/run-probe.sh mmapfileforkwriteback` matches Docker, and the full `just conformance-probes` arm64-musl gate now passes with `mmapfileforkwriteback` in the serial timing-sensitive lane. Linux KVM VM 210 (`10.14.14.66`) reports all seven booleans true. FreeBSD VM 200 initially exposed a real bhyve gap (`file_saw_parent_post=false`); `fix(bhyve): sync copied shared aliases` adds a copied-alias syscall-boundary flush, preserves `wait4`/`waitid` child-refresh ordering, restricts the per-syscall hook to backends that opt into copied-alias synchronization, and the FreeBSD probe now reports all seven booleans true. Static review still finds NVMM uses registered host `MAP_SHARED` HVA; runtime NVMM target testing is intentionally skipped with NetBSD.

## Task 7: Adopt Shared x86 Bring-Up Blobs Safely

**Files:**
- Modify: `crates/carrick-x86/src/bringup.rs`
- Modify: `crates/carrick-vmm-bhyve/src/guest_setup_x86.rs`
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`
- Test: blob-byte parity tests and AVX/floating-point smoke fixtures

**Interfaces:**
- Produces: one byte-complete `msr_init_blob`/FP-stub implementation in `carrick-x86`.
- Consumes: bhyve `NeedsRing0Blob` and `run_fp_stub` paths.

- [x] Add parity tests comparing the shared `carrick-x86` blob to the currently working bhyve blob, including MXCSR mask setup and `XCR0 = 0x7`.
- [x] Make `carrick-x86::msr_init_blob` include the missing MXCSR/XCR0 sequence and any entry-register preservation needed by bhyve.
- [x] Repoint bhyve to the shared blob and shared `run_fp_stub`.
- [x] Remove the stale backend-local implementation duplicate; keep the compatibility wrapper until FreeBSD runtime smoke permits API cleanup.
- [x] Verify with `cargo test -p carrick-x86`, `cargo test -p carrick-vmm-bhyve`, and the bhyve AVX/FP signal fixtures on FreeBSD.
- [x] Commit as `refactor(x86): share complete bringup blobs`.

**Evidence:** `carrick_x86::msr_init_blob` now emits the MXCSR mask sequence, `XSETBV(XCR0=7)`, and final RDX/RCX restore before `iretq`; new shared tests assert those byte sequences. The bhyve-local `msr_init_blob` body now delegates to `carrick_x86::msr_init_blob`, and bhyve already used `carrick_x86::fp_stub_bytes` and `carrick_x86::run_fp_stub`. `cargo test -p carrick-x86 --lib` passes locally. FreeBSD VM 200 (`10.14.14.189`) passes `cargo test -p carrick-vmm-bhyve --lib` with 32 tests and the bhyve runtime smoke `forkfpreclaim` (`workers_ok=180 forks_reaped=30`, `FORKFPRECLAIM_DONE`).

## Task 8: Rationalize Timer Delivery Duplication

**Files:**
- Modify: `crates/carrick-hal/src/timer_delivery.rs` if a helper belongs in HAL
- Modify: `crates/carrick-vmm-kvm/src/timer_delivery.rs`
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_threaded_glue.rs`
- Modify: `crates/carrick-vmm-nvmm/src/nvmm_threaded_glue.rs`
- Test: timer-core/unit tests plus one POSIX timer guest probe

**Interfaces:**
- Produces: one shared fallback POSIX timer arm helper parameterized by kicker; backend `main_tid` fields remain construction metadata because delivery is process-directed.
- Consumes: `carrick_timer_core::posix::run_fallback` and process-signal publication.

- [x] Confirm current duplication is byte-equivalent after comments and host-specific names are ignored.
- [x] Extract only the shared arm/disarm helper; keep backend-specific kqueue/no-kqueue decisions local.
- [x] Preserve existing semantics: process-directed signal publication plus `kick_all`.
- [x] Verify timer unit tests and a guest POSIX timer smoke under HVF/KVM plus target BSD lane if available.
- [x] Commit as `refactor(timer): share fallback posix delivery`.

**Evidence:** KVM, bhyve, and NVMM all now call `carrick_hal::timer_delivery::arm_fallback_posix_timer` / `disarm_fallback_posix_timer`; interval-timer `arm_itimer` policy remains backend-local. The helper keeps the prior POSIX sequence: `carrick_timer_core::posix::arm`, spawn `carrick-ptimer-{id}`, `publish_process_signal(signum)`, and `kick_all()`. New HAL test `fallback_posix_timer_publishes_process_signal_and_kicks_all` proves the shared helper publishes the process pending signal and kicks the registry. Verification passed: `cargo test -p carrick-hal fallback_posix_timer_publishes_process_signal_and_kicks_all --lib -- --test-threads=1`, `cargo test -p carrick-hal --lib -- --test-threads=1`, `cargo test -p carrick-timer-core --lib -- --test-threads=1`, `cargo check -p carrick-vmm-kvm --lib`, `cargo check -p carrick-vmm-bhyve --lib`, `cargo check -p carrick-vmm-nvmm --lib`, `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin posixtimers`, and the same `posixtimers` check for `x86_64-unknown-linux-musl`. Guest `posixtimers` smoke now passes under local HVF, Linux KVM VM 210, and FreeBSD VM 200.

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

- [x] Add a probe for TCP OOB readiness mapped through `EPOLLPRI`.
- [x] On FreeBSD/NetBSD, prove whether the current sentinel behavior returns a controlled Linux errno or silently drops readiness.
- [x] If OOB cannot be supported, document it as a capability gap and ensure registration fails predictably.
- [x] Add a probe where one process opens the same file twice and exercises Linux OFD lock independence.
- [x] Either implement a Carrick OFD lock table keyed by open description for BSD hosts, or reject OFD locks with a clear Linux errno instead of pretending process locks are equivalent.
- [x] Verify on target BSD hosts.
- [x] Commit as `fix(bsd): fence unsupported epoll and ofd semantics`.

**Local evidence:** Existing probes cover the required Linux invariants: `conformance-probes/src/bin/epollpri.rs` exercises TCP urgent data -> `EPOLLPRI`, and `conformance-probes/src/bin/fcntlofdlock.rs` exercises same-process double-open OFD conflicts plus `l_pid = -1`. FreeBSD/NetBSD `KqueueMultiplexer::register_io` now returns host `EOPNOTSUPP` immediately for OOB interest instead of attempting the impossible `EVFILT_EXCEPT` sentinel; runtime `epoll_ctl(ADD/MOD)` now propagates multiplexer registration errors through `host_to_linux_errno` before recording interest. `carrick_portable::host_ofd_locks_supported()` exposes the host capability, and runtime guest `F_OFD_*` commands on unsupported BSD hosts validate the `flock` pointer then return Linux `ENOTSUP` rather than mapping to process locks. Local verification passed: `cargo check -p carrick-host-bsd --lib`, `cargo check -p carrick-portable --lib`, `cargo check -p carrick-runtime --lib`, `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin epollpri --bin fcntlofdlock`, same probe check for `x86_64-unknown-linux-musl`, `cargo check -p carrick-portable --target x86_64-unknown-freebsd`, `cargo check -p carrick-portable --target x86_64-unknown-netbsd`, `cargo check -p carrick-host-bsd --lib --target x86_64-unknown-freebsd`, `cargo check -p carrick-host-bsd --lib --target x86_64-unknown-netbsd`, `cargo test -p carrick-runtime epoll --lib -- --test-threads=1`, and `cargo test -p carrick-host-bsd --lib -- --test-threads=1`. Native target verification passed after replacing `/root/carrick` with this branch on FreeBSD VM 200 (`10.14.14.189`): `cargo check -p carrick-host-bsd --lib`, `cargo check -p carrick-portable --lib`, and `cargo check -p carrick-runtime --lib --no-default-features --features platform-freebsd`. Linux x86 replacement checks also passed on VM 210 (`10.14.14.66`) and LXC 104 (`10.14.14.39`): `cargo check -p carrick-vmm-kvm --lib` and `cargo check -p carrick-runtime --lib --no-default-features --features platform-linux`. NetBSD target verification is intentionally skipped for this task per user direction.

## Task 10: Repair Signal Altstack State After Non-`rt_sigreturn` Handler Exit

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/signal.rs`
- Modify if needed: per-ISA sigframe restoration hooks
- Probe: `siglongjmp` from `SA_ONSTACK` signal handler

**Interfaces:**
- Produces: a correct or explicitly bounded model for active signal-frame tracking.
- Consumes: `handler_frames`, `sigaltstack`, `rt_sigreturn`, and signal delivery bookkeeping.

- [x] Add a Linux/Docker oracle probe where a signal handler on altstack exits via `siglongjmp`, then later signals and `sigaltstack(NULL, &old)` are observed.
- [x] Run the probe under Carrick to prove the reported stuck-on-altstack behavior.
- [x] Evaluate durable detection options: guest SP range reconciliation before `sigaltstack` queries, frame-token validation on delivery, or clearing stale frames when PC/SP prove the handler is no longer active.
- [x] Implement the smallest option that matches Docker for the probe without breaking nested signal handlers that return normally through `rt_sigreturn`.
- [x] Verify with the new probe plus existing signal unit tests.
- [x] Commit as `fix(runtime): reconcile altstack after siglongjmp`.

**Local evidence:** added `siglongjmpaltstack`, which installs an `SA_ONSTACK` handler, exits the first handler via `siglongjmp`, confirms `sigaltstack(NULL, &old)` no longer reports `SS_ONSTACK`, replaces the altstack, and confirms the next signal uses the replacement stack. Native Linux VM 210 (`10.14.14.66`) reports all probe booleans true. Red-first Carrick check at pre-fix commit `5340692d` failed as expected: `after_longjmp_not_onstack=false`, `replace_altstack_ok=false`, `replace_altstack_errno=1`, and the second handler did not use the replacement altstack. The fix passes `cargo fmt --check`, `cargo check -p carrick-runtime --lib`, `cargo test -p carrick-runtime dispatch::signal::tests --lib`, `cargo check --manifest-path conformance-probes/Cargo.toml --target aarch64-unknown-linux-musl --bin siglongjmpaltstack`, `cargo check --manifest-path conformance-probes/Cargo.toml --target x86_64-unknown-linux-musl --bin siglongjmpaltstack`, `just build`, and `scripts/run-probe.sh siglongjmpaltstack` with `MATCH`.

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

- [x] Audit register identifiers and document that narrower native engine surfaces translate into the shared `Reg`/`SysReg` adapter only at sigframe/raw-hypervisor boundaries.
- [x] Audit x86 FP/SIMD save/restore in `RegAccess`; document it as boundary-local debt and defer a split until a concrete sigframe caller can consume a smaller bound.
- [x] Audit `InjectParams`; document it as the sigframe input bundle and defer a split until an associated sigframe trait can be introduced without a shotgun rewrite.
- [x] Classify `set_memory_model` as the guest Linux memory-model hook with non-HVF no-op defaults, not a raw hypervisor capability.
- [x] Confirm AArch64 raw `EL0Fault` is already lowered into ISA-neutral `GuestFault` at the threaded runtime boundary while x86 emits `GuestFault` directly.
- [x] Document that `GuestArch` should only split where a focused call site can consume a smaller capability without dragging page-table, vDSO, trampoline, and signal-frame responsibilities together.
- [x] Verify with `cargo test -p carrick-hal` and backend `cargo check` gates.
- [x] Commit as `docs(hal): classify platform contract seams`.

**Outcome:** this task is closed as a contract classification, not a broad trait-splitting refactor. Current source already has narrower native engine surfaces (`Aarch64Vcpu`, `X86Vcpu`, x86 backend register helpers), page-table and syscall-table associated traits under `GuestArch`, and the threaded runtime lowers AArch64 raw `EL0Fault` into ISA-neutral `GuestFault` while x86 emits `GuestFault` directly. `RegAccess` remains the shared sigframe/trap-loop adapter, and `InjectParams` remains the sigframe input bundle; both are documented as boundary-local and should only be split by a future caller that can consume a smaller capability without a shotgun rewrite. `set_memory_model` is documented as the guest Linux memory-model hook with a non-HVF no-op default, not as a raw hypervisor API. Verification for the docs/code-comment classification passed with `cargo test -p carrick-hal --lib` and `cargo check -p carrick-vmm-hvf --lib`.

## Task 12: Decide HVF Adoption Of `HvVm`/`HvVcpu`

**Files:**
- Modify if adopted: `crates/carrick-hal/src/hypervisor.rs`
- Modify if adopted: `crates/carrick-vmm-hvf/src/*`
- Docs: update `docs/hal.md`

**Interfaces:**
- Produces: either HVF implementations of raw hypervisor traits or a documented decision that `SyscallTrap`/engine-level traits are the real shared seam.
- Consumes: existing `HvVm`/`HvVcpu`, KVM implementations, and HVF applevisor direct driver.

- [x] Audit actual consumers of `HvVm`/`HvVcpu`; do not widen the abstraction if KVM is the only user.
- [x] Compare the value of HVF adoption against keeping applevisor-specific lifecycle explicit.
- [x] If adoption reduces duplicated backend lifecycle code, implement a small HVF adapter and compile-shape tests.
- [x] If adoption adds indirection without shared consumers, document the boundary and remove claims that this is a portability blocker.
- [x] Verify with `just check -p carrick-vmm-hvf` or the closest available workspace check.
- [x] Commit as `docs(hal): classify raw hypervisor seam` or `refactor(hvf): implement raw hv traits`.

**Outcome:** HVF adoption is intentionally deferred. `HvVm`/`HvVcpu` are documented as raw adapter traits used where they remove real duplication, while the portability boundary for HVF remains the engine-level `SyscallTrap` / `ThreadedEngine` surface over `applevisor`. This avoids adding an HVF adapter that would only add indirection around codesign-bound lifecycle and vCPU coordination. Verification used `cargo check -p carrick-vmm-hvf --lib`.

## Final Gate

- [x] Run `just fmt-check`.
- [x] Run `just clippy`.
- [x] Run `just test`.
- [x] Run `just test-integration`.
- [x] Run `just conformance-probes` after `just build` on macOS.
- [x] Run target-host build gates for Linux/KVM and FreeBSD/bhyve for all tasks that touched those lanes.
- [x] Re-render docs/support artifacts only when the relevant command is part of the task.
- [x] Update this plan with completed task links and any intentionally deferred limitations.

**Final evidence:** the code-bearing branch state through
`7e5fa3593` passes `just fmt-check`, `just clippy`, `just test`,
`just test-integration`, and `just conformance-probes`. The final probe gate
rebuilt and signed `target/release/carrick`; the gating `arm64:musl` lane passed
including `futexshare`, `futexsharedalias`, `mmapfileforkwriteback`,
`fifoforkeof`, `epollforkeventfd`, `ptyforkreopen`, `posixtimers`,
`siglongjmpaltstack`, and `preemptsigstorm`. The non-gating report-only lanes
remained non-blocking: `arm64:gnu` reported 5 diffs, `amd64:musl` reported 99
diffs, and `amd64:gnu` skipped because the gnu x86_64 probes were not built.

**Target-host evidence:** `/root/carrick` was replaced on the x86 targets and
checked at commit `7e5fa3593`. FreeBSD VM 200 (`10.14.14.189`) passes
`just build`, `cargo test -p carrick-vmm-bhyve --lib`, and injected amd64-musl
runtime probes `futexshare`, `futexsharedalias`, `mmapfileforkwriteback`, and
`forkfpreclaim`. Linux KVM VM 210 (`10.14.14.66`) passes
`cargo build -p carrick-cli --no-default-features --features platform-linux
--release` and the same injected amd64-musl runtime probes. Linux LXC 104
(`10.14.14.39`) passes compile-only gates `cargo check -p carrick-vmm-kvm --lib`
and `cargo check -p carrick-runtime --lib --no-default-features --features
platform-linux`.

NetBSD/NVMM target-host verification is intentionally deferred per user
direction for this execution pass.

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
