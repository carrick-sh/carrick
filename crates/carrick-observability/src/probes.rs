//! USDT (DTrace) probe provider — SHARED across the DTrace-capable backends.
//!
//! This module hosts the carrick USDT provider so EVERY backend whose host OS
//! supports `usdt` (macOS, FreeBSD, and Linux) fires REAL probes, while the
//! others (e.g. NetBSD) link a no-op stub with identical signatures. It was
//! formerly private to carrick-vmm-hvf (macOS-only); hoisting it here lets the
//! FreeBSD bhyve build get the genuine provider too, and lets the dispatcher
//! call one `crate::probes::…` surface on all platforms.
//!
//! Linux gets REAL probes via usdt's SystemTap SDT backend (`.note.stapsdt`
//! anchors), read by `bpftrace -l 'usdt:<carrick-bin>:carrick:*'` — e.g.
//! `carrick:futex-route`, `carrick:fork-quiesce`. usdt ≥0.6 emits these on
//! stable Rust (the old `asm` feature is now a no-op); `register_dtrace_probes`
//! (called from carrick-cli `main`) registers them at startup. (An earlier
//! comment gated Linux out as "no-op"; that predated usdt's Linux support.)
//!
//! Layout:
//!   * `real` — the genuine `#[usdt::provider]` plus its safe wrappers, compiled
//!     where usdt can emit probe anchors: `macos` (both arches — the HVF aarch64
//!     path) and `x86_64` `linux`/`freebsd`. usdt 0.6's SDT backend emits x86
//!     asm and keys the decision off the BUILD HOST, so an `aarch64`
//!     `linux`/`freebsd` target cross-built from an x86_64 host would otherwise
//!     emit `rdi`/`rsi`/… and fail with "invalid register" — those targets take
//!     the stub instead.
//!   * `stub` — a byte-for-byte signature mirror with empty bodies, compiled on
//!     every OTHER target (NetBSD, and aarch64 linux/freebsd). The non-probe
//!     helpers (`guest_mem_probe_points`,
//!     `guest_mem_copy`, `guest_mem_point`) carry their REAL bodies in BOTH arms
//!     so behaviour is identical regardless of platform.
//!
//! `usdt` is a non-target-gated dependency of this crate: on stub targets it
//! compiles as a pure-Rust no-op, but `usdt::Error` is still needed by the
//! stub's `register_dtrace_probes` return type (the dispatcher calls it on every
//! platform). See the crate manifest comment for why this is the correct choice.

#[cfg(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
))]
pub use real::*;
#[cfg(not(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
)))]
pub use stub::*;

#[derive(Clone, Copy, Debug)]
pub struct EpollMaskedProbe {
    pub origin: i32,
    pub fd: i32,
    pub host_fd: i32,
    pub requested: u32,
    pub raw_ready: u32,
    pub last_ready: u32,
    pub read_avail: u64,
    pub last_read_avail: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UlockRequeueProbe {
    pub phase: u32,
    pub from_key: u64,
    pub to_key: u64,
    pub wake_req: u32,
    pub requeue_req: u32,
    pub wake_ret: u32,
    pub requeue_ret: u32,
    pub from_count: u32,
    pub from_requeue_wake: u32,
    pub from_requeue_count: u32,
    pub from_logical_requeued: u32,
    pub from_logical_wake: u32,
    pub to_count: u32,
    pub to_requeue_wake: u32,
    pub to_requeue_count: u32,
    pub to_logical_requeued: u32,
    pub to_logical_wake: u32,
}

macro_rules! dsr_ordinal_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident = $value:expr),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum $name {
            $($variant = $value),+
        }

        impl $name {
            pub const ALL: [Self; dsr_ordinal_enum!(@count $($variant),+)] = [
                $(Self::$variant),+
            ];

            #[inline(always)]
            pub const fn raw(self) -> u32 {
                self as u32
            }
        }
    };
    (@count $($variant:ident),+) => {
        <[()]>::len(&[$(dsr_ordinal_enum!(@unit $variant)),+])
    };
    (@unit $variant:ident) => { () };
}

dsr_ordinal_enum! {
    /// Typed reason a translated DSR run slice returned to Rust.
    pub enum DsrExitKind {
        Syscall = 1,
        DirectResolver = 2,
        IndirectResolver = 3,
        Fault = 4,
        Kick = 5,
        Sensitive = 6,
        Unsupported = 7,
    }
}

dsr_ordinal_enum! {
    /// Result of preparing a guest PC for translated execution.
    pub enum DsrPrepareOutcome {
        ResumeEntryHit = 1,
        BlockIndexHit = 2,
        Translated = 3,
        Failed = 4,
    }
}

dsr_ordinal_enum! {
    /// Stable diagnostic category for a DSR operation result.
    pub enum DsrOperationOutcome {
        Success = 0,
        PcOverflow = 1,
        Decode = 2,
        Malformed = 3,
        BlockPolicy = 4,
        MemoryRead = 5,
        UnsupportedBlockAction = 6,
        Assembler = 7,
        Gateway = 8,
        CachePolicy = 9,
        GenerationChanged = 10,
        Host = 11,
        CacheCapacity = 12,
        InvalidTarget = 13,
    }
}

dsr_ordinal_enum! {
    /// Resolver family used for a translated control-flow exit.
    pub enum DsrResolveKind {
        Direct = 1,
        Indirect = 2,
    }
}

dsr_ordinal_enum! {
    /// Low-cardinality DSR translation-cache event.
    pub enum DsrCacheEventKind {
        BlockHit = 1,
        BlockMiss = 2,
        TargetPublish = 3,
        Invalidate = 4,
        BlockPublish = 5,
        CapacityFailure = 6,
    }
}

dsr_ordinal_enum! {
    /// Process role for a DSR cache lifecycle boundary.
    pub enum DsrCacheRole {
        Common = 0,
        Parent = 1,
        Child = 2,
    }
}

dsr_ordinal_enum! {
    /// Stable DSR cache lifecycle boundary.
    pub enum DsrCacheLifecyclePhase {
        ForkChildRepairBegin = 1,
        ForkChildRepairEnd = 2,
        ExecResetBegin = 3,
        ExecResetEnd = 4,
    }
}

#[cfg(test)]
mod dsr_probe_abi {
    use super::{
        DsrCacheEventKind, DsrCacheLifecyclePhase, DsrCacheRole, DsrExitKind, DsrOperationOutcome,
        DsrPrepareOutcome, DsrResolveKind,
    };

    fn assert_unique(values: &[u32]) {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len());
    }

    #[test]
    fn exit_kind_values_match_gateway_status() {
        assert_eq!(DsrExitKind::Syscall.raw(), 1);
        assert_eq!(DsrExitKind::DirectResolver.raw(), 2);
        assert_eq!(DsrExitKind::IndirectResolver.raw(), 3);
        assert_eq!(DsrExitKind::Fault.raw(), 4);
        assert_eq!(DsrExitKind::Kick.raw(), 5);
        assert_eq!(DsrExitKind::Sensitive.raw(), 6);
        assert_eq!(DsrExitKind::Unsupported.raw(), 7);
    }

    #[test]
    fn prepare_outcome_values_are_stable_and_unique() {
        assert_eq!(DsrPrepareOutcome::ResumeEntryHit.raw(), 1);
        assert_eq!(DsrPrepareOutcome::BlockIndexHit.raw(), 2);
        assert_eq!(DsrPrepareOutcome::Translated.raw(), 3);
        assert_eq!(DsrPrepareOutcome::Failed.raw(), 4);
        assert_unique(&DsrPrepareOutcome::ALL.map(DsrPrepareOutcome::raw));
    }

    #[test]
    fn operation_outcome_values_match_dsr_error_categories() {
        assert_eq!(DsrOperationOutcome::Success.raw(), 0);
        assert_eq!(DsrOperationOutcome::PcOverflow.raw(), 1);
        assert_eq!(DsrOperationOutcome::Decode.raw(), 2);
        assert_eq!(DsrOperationOutcome::Malformed.raw(), 3);
        assert_eq!(DsrOperationOutcome::BlockPolicy.raw(), 4);
        assert_eq!(DsrOperationOutcome::MemoryRead.raw(), 5);
        assert_eq!(DsrOperationOutcome::UnsupportedBlockAction.raw(), 6);
        assert_eq!(DsrOperationOutcome::Assembler.raw(), 7);
        assert_eq!(DsrOperationOutcome::Gateway.raw(), 8);
        assert_eq!(DsrOperationOutcome::CachePolicy.raw(), 9);
        assert_eq!(DsrOperationOutcome::GenerationChanged.raw(), 10);
        assert_eq!(DsrOperationOutcome::Host.raw(), 11);
        assert_eq!(DsrOperationOutcome::CacheCapacity.raw(), 12);
        assert_eq!(DsrOperationOutcome::InvalidTarget.raw(), 13);
        assert_unique(&DsrOperationOutcome::ALL.map(DsrOperationOutcome::raw));
    }

    #[test]
    fn resolver_cache_and_lifecycle_values_are_stable_and_unique() {
        assert_eq!(DsrResolveKind::Direct.raw(), 1);
        assert_eq!(DsrResolveKind::Indirect.raw(), 2);
        assert_unique(&DsrResolveKind::ALL.map(DsrResolveKind::raw));

        assert_eq!(DsrCacheEventKind::BlockHit.raw(), 1);
        assert_eq!(DsrCacheEventKind::BlockMiss.raw(), 2);
        assert_eq!(DsrCacheEventKind::TargetPublish.raw(), 3);
        assert_eq!(DsrCacheEventKind::Invalidate.raw(), 4);
        assert_eq!(DsrCacheEventKind::BlockPublish.raw(), 5);
        assert_eq!(DsrCacheEventKind::CapacityFailure.raw(), 6);
        assert_unique(&DsrCacheEventKind::ALL.map(DsrCacheEventKind::raw));

        assert_eq!(DsrCacheRole::Common.raw(), 0);
        assert_eq!(DsrCacheRole::Parent.raw(), 1);
        assert_eq!(DsrCacheRole::Child.raw(), 2);
        assert_unique(&DsrCacheRole::ALL.map(DsrCacheRole::raw));

        assert_eq!(DsrCacheLifecyclePhase::ForkChildRepairBegin.raw(), 1);
        assert_eq!(DsrCacheLifecyclePhase::ForkChildRepairEnd.raw(), 2);
        assert_eq!(DsrCacheLifecyclePhase::ExecResetBegin.raw(), 3);
        assert_eq!(DsrCacheLifecyclePhase::ExecResetEnd.raw(), 4);
        assert_unique(&DsrCacheLifecyclePhase::ALL.map(DsrCacheLifecyclePhase::raw));
    }

    #[test]
    fn probe_wrappers_expose_typed_scalar_only_signatures() {
        let _: fn(i32, u64) = super::dsr_prepare_begin;
        let _: fn(i32, u64, u64, u64, DsrPrepareOutcome) = super::dsr_prepare_end;
        let _: fn(i32, u64, u64, u64) = super::dsr_run_begin;
        let _: fn(i32, DsrExitKind, u64, u64, i32) = super::dsr_run_end;
        let _: fn(i32, u64, u64) = super::dsr_translate_begin;
        let _: fn(i32, u64, u64, u64, DsrOperationOutcome) = super::dsr_translate_end;
        let _: fn(i32, DsrResolveKind, u64, u64) = super::dsr_resolve_begin;
        let _: fn(i32, DsrResolveKind, u64, u64, DsrOperationOutcome) = super::dsr_resolve_end;
        let _: fn(i32, DsrCacheEventKind, u64, u64, u64) = super::dsr_cache_event;
        let _: fn(DsrCacheRole, u64) = super::dsr_cache_capacity;
        let _: fn(DsrCacheRole, DsrCacheLifecyclePhase, u64, u64, u64) = super::dsr_cache_lifecycle;
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
))]
mod real {
    //! THEORY OF OPERATION
    //!
    //! These are the static DTrace USDT probes the `carrick trace` tracer (and any
    //! ad-hoc D script) hangs off. The guiding principle is ZERO PERTURBATION when
    //! no consumer is attached: every wrapper here calls a `usdt`-generated probe
    //! that is gated on `is_enabled` at the call site, so a probe with no listening
    //! D script costs a single predicted-not-taken branch. That is why debugging
    //! carrick is supposed to go through these probes rather than `eprintln!`, which
    //! both perturbs timing (and so hides Heisenbugs) and pays its cost
    //! unconditionally.
    //!
    //! Two encoding conventions, chosen per-probe by how hot it is:
    //!
    //!   * RAW POINTER (hot path). A probe that fires on EVERY syscall or trap —
    //!     `syscall__entry`, `vcpu__trap`, `unhandled__syscall` — passes the ADDRESS
    //!     of a `#[repr(C)]` struct ([`crate::compat::SyscallArgs`] /
    //!     [`crate::compat::GuestRegs`]) as a `u64`. The D script does
    //!     `copyin(addr, sizeof)` and reads fields by offset as native `u64`s. This
    //!     avoids building a string on every fire (what made an earlier JSON-encoding
    //!     `carrick trace` slow — the cost was ours, not DTrace's) and, unlike
    //!     `json()`+`strtoll` in D, round-trips a full unsigned 64-bit value exactly.
    //!     The matching struct layouts in the `.d` scripts mirror these `repr(C)`
    //!     definitions field-for-field, so field ORDER is load-bearing.
    //!
    //!   * SCALARS (cold path). A probe that fires only on a rare event —
    //!     `vcpu__fault`, `fork__quiesce`, `lifecycle`, the page-table probes —
    //!     passes its diagnostics as plain scalar args captured at fire time. This is
    //!     more robust when the event is fatal (a fault that kills the process
    //!     immediately would outrun a `copyin`-a-pointer action) and the per-fire
    //!     cost is irrelevant because the probe is off the happy path.
    //!
    //! The `usdt` provider caps a probe at 6 args, which is why composite payloads
    //! ride as a pointer-to-struct rather than expanding into argument lists.

    use crate::compat::{CompatEvent, SyscallArgs};

    /// USDT probes for the carrick provider. The `usdt` crate's hard cap is
    /// 6 args per probe, so syscall args ride as a `&SyscallArgs` reference
    /// — usdt JSON-encodes it through serde and passes the resulting
    /// C-string pointer to DTrace. Consumers use `copyinstr(argN)` to read
    /// the JSON (looks like `[v0,v1,v2,v3,v4,v5]`).
    #[usdt::provider(provider = "carrick")]
    mod carrick_usdt {
        use crate::compat::SyscallArgs;

        // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6], contiguous); DTrace
        // does `copyin(arg2, 48)` and reads the six args by offset. This probe
        // fires on EVERY guest syscall, so we must NOT JSON-encode here — that
        // string-builds on every fire even for a script that only wants one
        // syscall, which is what made `carrick trace` slow (DTrace itself is
        // production-safe; the cost was ours). Same raw-pointer trick as
        // `vcpu__trap`.
        fn syscall__entry(_: u64, _: &str, _: u64) {}
        fn syscall__return(_: u64, _: &str, _: i64, _: i32) {}
        // The Rust provider accepts six arguments, but macOS has returned a
        // constant zero for arg5 at real DSR probe sites. Keep this scalar ABI
        // at five arguments or fewer and use a low-frequency companion probe
        // when another value is required.
        /// DSR guest-entry preparation boundaries. All arguments are copied
        /// scalars so disabled probes do not materialize diagnostic state.
        fn dsr__prepare__begin(_: i32, _: u64) {}
        fn dsr__prepare__end(_: i32, _: u64, _: u64, _: u64, _: u32) {}
        /// One translated execution slice, from gateway entry to typed exit.
        fn dsr__run__begin(_: i32, _: u64, _: u64, _: u64) {}
        fn dsr__run__end(_: i32, _: u32, _: u64, _: u64, _: i32) {}
        /// Block decode, planning, emission, and publication boundaries.
        fn dsr__translate__begin(_: i32, _: u64, _: u64) {}
        fn dsr__translate__end(_: i32, _: u64, _: u64, _: u64, _: u32) {}
        /// Direct and indirect translated-control-flow resolution boundaries.
        fn dsr__resolve__begin(_: i32, _: u32, _: u64, _: u64) {}
        fn dsr__resolve__end(_: i32, _: u32, _: u64, _: u64, _: u32) {}
        /// Translation-cache activity and fork/exec lifecycle boundaries.
        fn dsr__cache__event(_: i32, _: u32, _: u64, _: u64, _: u64) {}
        fn dsr__cache__capacity(_: u32, _: u64) {}
        fn dsr__cache__lifecycle(_: u32, _: u32, _: u64, _: u64, _: u64) {}
        // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6]); DTrace copyin's 48
        // bytes — same raw-pointer convention as `syscall__entry`, no JSON.
        fn unhandled__syscall(_: u64, _: &str, _: u64) {}
        fn partial__syscall(_: u64, _: &str, _: u64, _: &str) {}
        fn unhandled__ioctl(_: i32, _: u64, _: u64) {}
        fn proc__read__unimplemented(_: &str) {}
        fn sys__read__unimplemented(_: &str) {}
        fn signal__unsupported(_: i32, _: &str) {}
        // pid, signum, generation — fires when an interval-timer thread publishes.
        fn itimer__fire(_: u32, _: i32, _: u64) {}
        /// Fires on every guest syscall that passes flag bits we don't
        /// recognise. Catches Linux ABI drift loudly instead of letting
        /// the dispatcher silently drop behaviour the guest expected.
        fn unknown__syscall__flags(_: u64, _: &str, _: u32, _: u64) {}
        /// Fires before `libc::fork` from the trap engine's clone path.
        /// Args are the captured pre-fork vCPU PC, ELR_EL1, and CPSR.
        fn fork__pre(_: u64, _: u64, _: u64) {}
        /// Fires after the parent/child have rebuilt their HVF context and
        /// restored the snapshot. `pid` is the libc::fork return value
        /// (0 in the child, child pid in the parent).
        fn fork__post(_: i32, _: u64, _: u64) {}
        /// Fork stop-the-world quiesce trace. `phase`: 0=begin (a=others to wait
        /// for, b=kicker live count), 1=quiesce TIMEOUT (a=others, b=paused),
        /// 2=hv_vm_destroy result (a=rc — NONZERO means a vCPU was still live, the
        /// HV_BUSY root cause), 3=vcpu_create result in a sibling rebuild / spawn
        /// (a=rc, b=site: 0=rebuild 1=spawn). `tid` is the acting thread.
        fn fork__quiesce(_: i32, _: i64, _: i64, _: i32) {}
        /// Fork rebuild detail. `role`: 0=parent, 1=child. `phase`: 0=begin,
        /// 1=local-map-end, 2=sibling-map-end, 3=restore-end. `desc_count` is the
        /// local descriptor set for phases 0/1/3 and the sibling candidate set for
        /// phase 2. `map_count` is the number of `hv_vm_map` calls completed in
        /// that phase. `elapsed_us` is measured from the phase start, except phase
        /// 3 which is total rebuild elapsed.
        fn fork__rebuild(_: i32, _: i32, _: u64, _: u64, _: u64) {}
        /// Fork lifecycle phase timing. `role`: 0=runtime-parent/common,
        /// 1=runtime-child, 2=aarch64-parent/common, 3=aarch64-child,
        /// 4=hvf-parent/common, 5=hvf-child. `phase` is domain-local and
        /// documented in the E2.1 evidence artifact; `elapsed_us` is the
        /// just-finished phase duration. `a` and `b` are phase-specific counts or
        /// return codes.
        fn fork__lifecycle(_: i32, _: i32, _: u64, _: i64, _: i64) {}
        /// Fork address-space footprint sample. `phase` is sample-local; current
        /// E2.2 diagnostics use 0=immediately-before-host-fork. The remaining
        /// fields are host VM region count, guest mmap-arena high-water, current
        /// resident bytes, and current virtual bytes.
        fn fork__footprint(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Fork footprint attribution by HVF guest mapping class. Args are:
        /// class id, region count, scanned bytes, resident bytes, and flags.
        fn fork__footprint__class(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Per-run lifecycle marker, one probe fired at each phase boundary so a
        /// DTrace consumer can time each phase as a delta. `phase`:
        /// 0=run-entry, 1=image-ready, 2=vm-created, 3=guest-loaded (ready to run),
        /// 4=first-vcpu-run, 5=vm-destroy-begin, 6=vm-destroy-end. (guest-exit has
        /// its own probe between 4 and 5.) Cheap: fires a handful of times per run.
        fn lifecycle(_: u32) {}
        /// Fires every syscall trap. `arg0` is the ADDRESS of a
        /// `compat::GuestRegs` (`#[repr(C)]`); DTrace does
        /// `copyin(arg0, sizeof(gregs_t))` and reads fields by offset. A
        /// raw pointer (not JSON) keeps this hot probe cheap and lets D
        /// read full u64 register values exactly.
        fn vcpu__trap(_: u64) {}
        /// Fires when a guest EL0 sync exception other than `svc #0` reaches the
        /// trap loop (the fatal `EL0Fault` path) — an instruction/data abort or
        /// undefined instruction that crashes the guest. Args: `esr`, `elr`, `far`,
        /// `x30`(LR), `sp`(SP_EL0), `tid`. Fires only on the fault, so a
        /// `carrick trace` script can `--stack`-walk the faulting guest thread with
        /// near-zero hot-path overhead (it never fires on the happy path). The key
        /// diagnostic for the c>=20 sibling-vCPU corruption faults.
        fn vcpu__fault(_: u64, _: u64, _: u64, _: u64, _: u64, _: i32) {}
        /// Companion to `vcpu__fault` carrying the decoded fault diagnostics as
        /// SCALARS (captured at probe-fire time — robust even when the fault kills
        /// the process immediately, unlike a copyin-a-pointer probe whose action
        /// runs too late). `insn` is the faulting instruction word (read host-side
        /// at `elr` — DTrace can't copyin a guest VA); `rn` is the base register a
        /// load/store dereferenced (`(insn>>5)&0x1f`); `xrn` is that register's
        /// value, BEST-EFFORT (read after the EL1 trap trampoline, which may have
        /// clobbered it). The AUTHORITATIVE faulting pointer is `far` (HW-latched):
        /// for a data abort `far == base + imm`, so a `ldr xN,[xN,#8]` with far=0x19
        /// means the base held 0x11=17. Lets a trace see the faulting access
        /// WITHOUT an eprintln rebuild. Fires only at the fault.
        fn vcpu__fault__regs(_: u64, _: u64, _: u64, _: u64, _: u32, _: u64) {}
        /// Fires from `map_host_alias` (the post-boot high-VA hv_vm_map path) with
        /// the MANAGER's L0..L3 stage-1 descriptors for the alias VA + whether this
        /// is a forked child and whether the page-table build succeeded (rc: 0 ok,
        /// else nonzero). Diagnoses why a forked child's alias mapping diverges from
        /// the parent's. Fires only on this path (no hot-path cost).
        fn pt__alias__walk(_: u64, _: u64, _: u64, _: u64, _: u64, _: i32) {}
        /// Fires from `map_host_alias` right after the stage-2 `hv_vm_map` with the
        /// alias VA/IPA/size and the raw `hv_return_t` (`rc`: 0 ok). Diagnoses an
        /// hv_vm_map failure in a forked child (the stage-2 coherence wall) before
        /// the page-table build is even attempted. `forked` bit: this is a forked child.
        fn hv__vm__map__alias(_: u64, _: u64, _: u64, _: i32, _: i32) {}
        /// Fires when a signal is published for later delivery. `target_tid` is the
        /// guest tid for a thread-directed signal (tkill/tgkill route) or 0 for a
        /// process-directed one; `signum` the Linux signum; `kind` 1=thread-directed
        /// 0=process-directed. Lets `carrick trace` see WHERE a signal was routed
        /// (vs which tid actually drains it via `signal-deliver`) — the missing
        /// visibility for the cross-thread / blocked-thread delivery bugs.
        fn signal__publish(_: i32, _: i32, _: i32) {}
        /// Fires every time the dispatcher routes a `futex(2)` syscall. `pid`,
        /// `addr` (guest VA of the futex word), `op` (FUTEX_WAIT=0 / WAKE=1 / ...),
        /// `shared` (1 = routed through `__ulock` because the address lives in a
        /// host-MAP_SHARED region; 0 = routed through the per-process parking lot).
        /// A WAKE that returns 0 on a `shared=1` address but the waiter exists in
        /// another process — that's the cross-process rendezvous failing.
        fn futex__route(_: u32, _: u64, _: i32, _: i32, _: u64) {}
        /// Fires at each `ulock::wait` entry and exit. `pid`, `host_addr`,
        /// `value`, `timeout_us`, `phase` (0=entry, 1=exit), `rc` (exit only).
        fn ulock__wait(_: u32, _: u64, _: u32, _: u32, _: i32, _: i64) {}
        /// Fires for each iteration of the dispatcher's FUTEX_WAKE loop:
        /// `pid`, `host_addr`, `iter`, `rc` (0 on wake-one success, <0 on ENOENT).
        fn ulock__wake(_: u32, _: u64, _: i32, _: i64) {}
        /// Raw-pointer payload for shared-futex requeue side-table accounting.
        /// See `UlockRequeueProbe`; phase 0=before host requeue, 1=after.
        fn ulock__requeue(_: u64) {}
        /// A cross-process futex wait slice returned a host errno OUTSIDE the
        /// Linux FUTEX_WAIT set (not ETIMEDOUT/EINTR), which the shared ABI guard
        /// folds to a spurious wake instead of leaking it (glibc nptl would abort
        /// on it). `pid`, `host_addr`, `errno` (the raw host errno swallowed).
        /// Fires on EVERY backend (HVF/KVM/bhyve/NVMM) from the one shared seam,
        /// so a host whose futex primitive returns a surprising errno is visible
        /// on the bring-up lanes, not just macOS. Frequent fires = a real
        /// host-futex mismatch worth a spec, not just noise.
        fn futex__unexpected__errno(_: u32, _: u64, _: i32) {}
        /// Fires at each `deliver_pending_signal` cycle. `tid` is the delivering
        /// thread; `pending` the signum it drained (0 = nothing deliverable to it).
        /// Pair with `signal-publish` to see a signal published for tid X but never
        /// drained by X (the routing/tid-mismatch and blocked-thread cases).
        fn signal__deliver(_: i32, _: i32) {}
        /// Fires when `execve_into` has finished swapping the engine to
        /// the new image. `path`, `entry`, `initial_sp`, `mapping_count`
        /// let dtrace operators verify the new process layout.
        fn execve__loaded(_: &str, _: u64, _: u64, _: u64) {}
        /// Fires at the tail of `execve_into` with the actual SCTLR/TTBR0/
        /// MAIR values read back from HVF. Use this to verify the new
        /// process's stage-1 MMU state matches what the fresh-from-cli
        /// case sets up.
        fn execve__sysregs(_: u64, _: u64, _: u64) {}
        /// Fires every time the dispatcher's `open_at_path` resolves a
        /// guest path. `pid` is the carrick-host pid (so the parent vs
        /// forked-children streams are demultiplexable). `result_size`
        /// is the bytes returned (for File) or `0` (for Directory /
        /// errno). `errno` is `0` on success.
        fn path__open(_: u32, _: &str, _: u64, _: i32) {}
        /// Fires when a guest process exits via exit_group. `pid` is the
        /// carrick-host pid; correlate with `execve__loaded` (same pid) to
        /// see which binary exited with which code.
        fn guest__exit(_: u32, _: i32) {}
        /// M:N scheduler — a guest thread was ADMITTED to a vCPU slot (a new
        /// `clone` sibling, or the main reservation). `tid` guest thread, `slot`
        /// the granted vCPU id, `budget` the pool size N (`usize::MAX`-clamped to
        /// u32 on unbounded HVF/KVM). Pair with `mn__reclaim` to trace the M:N
        /// lifecycle of a guest thread over the bounded vCPU pool.
        fn mn__admit(_: i32, _: u32, _: u32) {}
        /// M:N scheduler — a BLOCKING guest thread's reclaim decision (the heart of
        /// the M:N: how a thread time-shares the bounded vCPU pool). `tid` guest
        /// thread, `old_slot` the slot it held entering the block, `new_slot` the
        /// slot it holds on wake, `kind`: 0=PARKED (uncontended — kept its vCPU, no
        /// reclaim, the fast path), 1=RECLAIMED and got its OWN slot back (no
        /// re-bind), 2=RECLAIMED onto a DIFFERENT slot (full state re-bind — another
        /// thread ran on its vCPU while it blocked). A trace can compute the
        /// reclaim/park ratio and spot re-bind storms.
        fn mn__reclaim(_: i32, _: u32, _: u32, _: i32) {}
        /// Fires on execve with the joined argv (space-separated), so
        /// dtrace operators can see exactly how the guest invokes a
        /// child (e.g. apt's sqv method calling /usr/bin/sqv).
        fn execve__argv(_: u32, _: &str, _: &str) {}
        /// Host-pipe I/O: `dir` is 0 for read, 1 for write; `n` is the
        /// byte count (negative on error). Used to trace whether a forked
        /// child's stdout actually reaches the parent's pipe read.
        fn host__pipe__io(_: u32, _: i32, _: i32, _: i64) {}
        /// epoll_ctl decision: decoded guest event values without forcing DTrace
        /// scripts to copyin guest memory. `errno` is zero on success.
        fn epoll__ctl(_: i32, _: u64, _: i32, _: u32, _: u64, _: i32) {}
        /// Per-interest epoll_pwait readiness decision. `requested`, `raw_ready`,
        /// `last_ready`, and `ready` are Linux epoll event bitmasks.
        fn epoll__interest(_: i32, _: i32, _: u32, _: u32, _: u32, _: u32) {}
        /// Masked epoll readiness sample. Arg0 is the ADDRESS of an
        /// `EpollMaskedProbe` payload.
        fn epoll__masked(_: u64) {}
        /// Epoll host-registration rebind decision. Arg0 is the ADDRESS of an
        /// `EpollRebindProbe` payload.
        fn epoll__rebind(_: u64) {}
        /// Host-backed fd that epoll_pwait hands to the runtime's kqueue waiter.
        /// `poll_events` is the libc POLL* mask used to build EVFILT registrations.
        fn epoll__wait__fd(_: i32, _: i32, _: i32, _: i32, _: i32) {}
        /// epoll_pwait result decision. `kind` is 0 for immediate guest return and
        /// 1 for WaitOnFds handoff.
        fn epoll__result(_: i32, _: i32, _: i32, _: i32, _: i32) {}
        /// A drained multiplexer edge whose `(guest_fd, generation)` udata handle no
        /// longer matches any live interest — a stale edge for a recycled fd (the
        /// ABA hazard). Dropped, not mis-delivered; fires here so the recycle race is
        /// observable rather than silent.
        fn epoll__stale__edge(_: u64, _: i32, _: u32) {}
        /// Runtime blocking-I/O wait begin. `tid` is the guest thread id,
        /// `timeout_ms` is -1 for infinite, and fd0/events0 + fd1/events1 are the
        /// first two host fd wait targets.
        fn io__wait__begin(_: i32, _: i32, _: i64, _: i32, _: i32, _: i32) {}
        /// Runtime blocking-I/O wait end. `result` is 0=Ready, 1=TimedOut,
        /// 2=Interrupted; fd0/fd1/fd2 are the first host fds from the wait set.
        fn io__wait__end(_: i32, _: i32, _: i32, _: i32, _: i32, _: i32) {}
        /// Fires on a filesystem-backend decision/outcome. `op` names the
        /// operation + result (e.g. "set_times:ok", "set_times:open_none",
        /// "set_times:futimens_err", "unlink", "rename"), `path` is the
        /// resolved guest path, `errno` is the Linux errno carrick returns
        /// (0 on success). Lets `carrick trace` see WHY a host-backed fs
        /// syscall returned an errno — the internal reason invisible to the guest.
        fn fs__op(_: u32, _: &str, _: &str, _: i32) {}
        /// Fires when a guest signal handler frame is injected. `signum` is the
        /// Linux signal, `saved_pc` the pre-signal PC stored in the sigframe (the
        /// PC the eventual rt_sigreturn must restore), `new_sp` the SP_EL0 the
        /// frame was written at, `handler` the guest handler entry. Lets a trace
        /// see exactly what state is captured for later restore.
        fn signal__inject(_: i32, _: u64, _: u64, _: u64) {}
        /// Fires inside rt_sigreturn/restore. `saved_pc` is the PC about to be
        /// restored into ELR_EL1, `sp` the SP_EL0 the frame was read from,
        /// `magic` the frame magic read back. A corrupted `saved_pc` or `magic`
        /// here pinpoints sigframe corruption (the "PROT_REA" wild-PC crash).
        fn signal__restore(_: u64, _: u64, _: u64) {}
        /// Fires when a cross-thread kick (`hv_vcpus_exit`) lands while the vCPU is
        /// still executing carrick's EL1 trap trampoline (not at guest EL0). `pc` is
        /// the EL1 PC, `el` the current exception level (1+). carrick resumes
        /// instead of injecting a signal at this non-guest PC; a nonzero rate here
        /// is the signal-vs-trampoline race being correctly absorbed.
        fn kick__in_kernel(_: u64, _: u32) {}
        /// Cumulative kick/inject counters fired once at process exit (cheap, one
        /// fire per process) so a trace can read the totals without paying the
        /// per-event `kick-in-kernel` cost: `el1_resumed` (kicks absorbed in the
        /// EL1 trampoline), `kick_inject` (EL0 kick-path signal injections),
        /// `inject_at_el1` (carrick-vs-guest invariant violations — must be 0).
        fn kick__stats(_: u64, _: u64, _: u64) {}
        /// Reusable guest-memory watchpoint (compiled in only under the `watchpoint`
        /// feature). When that build has `CARRICK_WATCH_ADDR=<hex>` set, fires before
        /// EVERY syscall with (`syscall_nr`, `addr`, the current little-endian u64 at
        /// `addr`). Lets a trace bracket exactly which syscall a guest address changes
        /// across — e.g. which operation corrupts a GOT slot. Absent from a stock
        /// build; zero-cost (and not even read) when the env var is unset.
        fn mem__watch(_: u64, _: u64, _: u64) {}
        /// Fires in rt_sigaction with the first four u64 words the guest passed in
        /// its `struct sigaction` (offsets 0/8/16/24). Lets a trace see the exact
        /// on-the-wire layout — sa_handler, sa_flags, and whether offset 16 is
        /// sa_restorer (glibc-style) or sa_mask (aarch64 kernel ABI, no restorer).
        fn sigaction__read(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Fires when the interactive session supervisor forks the Carrick runtime
        /// child. Distinct from guest fork-post; this is the host-side `run -t`
        /// process boundary.
        fn supervisor__fork(_: i32) {}
        /// Fires when the runtime child has moved into its own process group and
        /// is waiting for the supervisor to make that pgrp foreground.
        fn supervisor__child__ready(_: i32) {}
        /// Fires after the supervisor attempts to make the runtime child pgrp the
        /// pty foreground group. `errno` is 0 on success.
        fn supervisor__foreground__pgrp(_: i32, _: i32) {}
        /// Fires when the supervisor reaps the runtime child.
        fn supervisor__child__exit(_: i32, _: i32) {}
        /// Page-table-edit Pause-Modify-Resume tracing. carrick (the VMM) edits the
        /// guest's shared stage-1 descriptors from the host while sibling vCPUs run;
        /// these probes let a `carrick trace` PROVE the stop-the-world engages and
        /// converges (rather than guessing).
        ///  * `pt__pause__begin`: an editing vCPU became the sole coordinator.
        ///    `tid` editor, `others_in_guest` siblings still walking tables at entry,
        ///    `count` live vCPUs.
        ///  * `pt__pause__ready`: all siblings left guest; the edit may proceed.
        ///    `spins` wait iterations, `wait_us` microseconds waited.
        ///  * `pt__pause__timeout`: the convergence deadline was hit. MUST never
        ///    fire — a nonzero rate means a sibling stayed in guest (exactly the
        ///    corruption PMR prevents). `wait_us` is the deadline budget.
        ///  * `pt__pause__end`: the pause was released and siblings resumed. `tid`.
        fn pt__pause__begin(_: i32, _: i32, _: i32) {}
        fn pt__pause__ready(_: i32, _: i32, _: i64) {}
        fn pt__pause__timeout(_: i32, _: i64) {}
        fn pt__pause__end(_: i32) {}
        /// Stage-1 spare sub-table pool occupancy, fired after each table edit.
        /// `in_use` live split tables, `free_list` reclaimable pages, `capacity`
        /// total spare pages. A rising `in_use` toward `capacity` is the
        /// coalesce-disabled pool leak; flat `in_use` proves coalescing keeps it
        /// bounded. `changed` is 1 if this edit mutated descriptors (0 = no-op skip).
        fn pt__pool(_: u32, _: u32, _: u32, _: i32) {}
        /// Fault-site host page-table walk. On a guest EL0 translation/permission
        /// fault, the live stage-1 descriptors read from the host backing at the
        /// faulting VA: `far` and `l0`/`l1`/`l2`/`l3`. An invalid (`& 1 == 0`) leaf
        /// proves the PTE is wrong IN MEMORY (logic bug); a valid RW leaf proves the
        /// memory is fine and the faulting vCPU's TLB was stale (coherence bug).
        fn pt__fault__walk(_: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Guest-memory copy mapping decision. `dir`: 0=guest->host read,
        /// 1=host->guest internal write, 2=host->guest syscall checked write.
        /// `addr`/`len` are the guest VA range. `stage1_ipa` is the live stage-1
        /// output for `addr`, or `u64::MAX` if unmapped/non-high-VA. `mapping_start`
        /// is the host mapping Carrick actually selected.
        fn guest__mem__copy(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-copy`: `mapping_start`, `mapping_end`, and
        /// `mapping_ipa` for the selected region. Kept below five args because
        /// macOS DTrace silently reports the sixth USDT argument as zero here.
        fn guest__mem__region(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Guest-memory copy content fingerprint. Same `dir`/`addr`/`len` as
        /// `guest-mem-copy`; then a wrapping byte-sum plus little-endian first
        /// eight bytes of the copied payload. This avoids DTrace reading guest VAs.
        fn guest__mem__bytes(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-bytes`: little-endian last eight bytes.
        fn guest__mem__tail(_: u32, _: u64, _: u64, _: u64) {}
        /// Stage-1 sample point inside a guest-memory copy range. Args are:
        /// `dir`, sample guest VA, `sample_va - mapping_start`,
        /// `stage1_ipa - mapping_ipa` or `u64::MAX`, and live stage-1 IPA.
        fn guest__mem__point(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Opt-in content fingerprint for a configured subrange inside a
        /// guest-memory copy. Args are `dir`, base guest VA, subrange offset,
        /// subrange length, and wrapping byte sum.
        fn guest__mem__subrange(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-subrange`: little-endian first and last eight
        /// bytes of the configured subrange.
        fn guest__mem__subedge(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-subrange`: nonzero byte count for the
        /// configured subrange. Kept separate because macOS DTrace drops a sixth
        /// USDT argument at some probe sites.
        fn guest__mem__subcount(_: u32, _: u64, _: u64, _: u64) {}
    }

    #[inline(always)]
    pub fn dsr_prepare_begin(tid: i32, guest_pc: u64) {
        carrick_usdt::dsr__prepare__begin!(|| (tid, guest_pc));
    }

    #[inline(always)]
    pub fn dsr_prepare_end(
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        generation: u64,
        outcome: super::DsrPrepareOutcome,
    ) {
        carrick_usdt::dsr__prepare__end!(|| {
            (tid, guest_pc, cache_pc, generation, outcome.raw())
        });
    }

    #[inline(always)]
    pub fn dsr_run_begin(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64) {
        carrick_usdt::dsr__run__begin!(|| (tid, guest_pc, cache_pc, generation));
    }

    #[inline(always)]
    pub fn dsr_run_end(
        tid: i32,
        kind: super::DsrExitKind,
        guest_pc: u64,
        target_pc: u64,
        status: i32,
    ) {
        carrick_usdt::dsr__run__end!(|| (tid, kind.raw(), guest_pc, target_pc, status));
    }

    #[inline(always)]
    pub fn dsr_translate_begin(tid: i32, guest_pc: u64, generation: u64) {
        carrick_usdt::dsr__translate__begin!(|| (tid, guest_pc, generation));
    }

    #[inline(always)]
    pub fn dsr_translate_end(
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        emitted_bytes: u64,
        outcome: super::DsrOperationOutcome,
    ) {
        carrick_usdt::dsr__translate__end!(|| {
            (tid, guest_pc, cache_pc, emitted_bytes, outcome.raw())
        });
    }

    #[inline(always)]
    pub fn dsr_resolve_begin(
        tid: i32,
        kind: super::DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
    ) {
        carrick_usdt::dsr__resolve__begin!(|| (tid, kind.raw(), source_pc, target_pc));
    }

    #[inline(always)]
    pub fn dsr_resolve_end(
        tid: i32,
        kind: super::DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
        outcome: super::DsrOperationOutcome,
    ) {
        carrick_usdt::dsr__resolve__end!(|| {
            (tid, kind.raw(), source_pc, target_pc, outcome.raw())
        });
    }

    #[inline(always)]
    pub fn dsr_cache_event(
        tid: i32,
        kind: super::DsrCacheEventKind,
        guest_pc: u64,
        generation: u64,
        used_bytes: u64,
    ) {
        carrick_usdt::dsr__cache__event!(|| {
            (tid, kind.raw(), guest_pc, generation, used_bytes)
        });
    }

    #[inline(always)]
    pub fn dsr_cache_capacity(role: super::DsrCacheRole, capacity_bytes: u64) {
        carrick_usdt::dsr__cache__capacity!(|| (role.raw(), capacity_bytes));
    }

    #[inline(always)]
    pub fn dsr_cache_lifecycle(
        role: super::DsrCacheRole,
        phase: super::DsrCacheLifecyclePhase,
        used_bytes: u64,
        block_count: u64,
        generation_count: u64,
    ) {
        carrick_usdt::dsr__cache__lifecycle!(|| {
            (
                role.raw(),
                phase.raw(),
                used_bytes,
                block_count,
                generation_count,
            )
        });
    }

    pub fn fork_pre(pc: u64, elr: u64, cpsr: u64) {
        carrick_usdt::fork__pre!(|| (pc, elr, cpsr));
    }

    // For these helpers the PID read happens INSIDE the closure. usdt's
    // `probe!` macro only invokes the closure when the probe is enabled
    // (it gates on `is_enabled()` in asm before calling), so `getpid()`
    // is genuinely zero-cost when no DTrace consumer is attached.
    pub fn path_open(path: &str, result_size: u64, errno: i32) {
        carrick_usdt::path__open!(|| (std::process::id(), path, result_size, errno));
    }

    pub fn itimer_fire(signum: i32, generation: u64) {
        carrick_usdt::itimer__fire!(|| (std::process::id(), signum, generation));
    }

    pub fn futex_route(addr: u64, op: i32, shared: i32, host_addr: u64) {
        carrick_usdt::futex__route!(|| (std::process::id(), addr, op, shared, host_addr));
    }

    pub fn ulock_wait(host_addr: u64, value: u32, timeout_us: u32, phase: i32, rc: i64) {
        carrick_usdt::ulock__wait!(|| (
            std::process::id(),
            host_addr,
            value,
            timeout_us,
            phase,
            rc
        ));
    }

    pub fn ulock_wake(host_addr: u64, iter: i32, rc: i64) {
        carrick_usdt::ulock__wake!(|| (std::process::id(), host_addr, iter, rc));
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct UlockRequeueWireProbe {
        pid: u64,
        phase: u64,
        from_key: u64,
        to_key: u64,
        wake_req: u64,
        requeue_req: u64,
        wake_ret: u64,
        requeue_ret: u64,
        from_count: u64,
        from_requeue_wake: u64,
        from_requeue_count: u64,
        from_logical_requeued: u64,
        from_logical_wake: u64,
        to_count: u64,
        to_requeue_wake: u64,
        to_requeue_count: u64,
        to_logical_requeued: u64,
        to_logical_wake: u64,
    }

    thread_local! {
        static ULOCK_REQUEUE_PROBE: std::cell::Cell<UlockRequeueWireProbe> =
            const { std::cell::Cell::new(UlockRequeueWireProbe {
                pid: 0,
                phase: 0,
                from_key: 0,
                to_key: 0,
                wake_req: 0,
                requeue_req: 0,
                wake_ret: 0,
                requeue_ret: 0,
                from_count: 0,
                from_requeue_wake: 0,
                from_requeue_count: 0,
                from_logical_requeued: 0,
                from_logical_wake: 0,
                to_count: 0,
                to_requeue_wake: 0,
                to_requeue_count: 0,
                to_logical_requeued: 0,
                to_logical_wake: 0,
            }) };
    }

    #[inline(never)]
    pub fn ulock_requeue(sample: super::UlockRequeueProbe) {
        let payload = UlockRequeueWireProbe {
            pid: std::process::id() as u64,
            phase: sample.phase as u64,
            from_key: sample.from_key,
            to_key: sample.to_key,
            wake_req: sample.wake_req as u64,
            requeue_req: sample.requeue_req as u64,
            wake_ret: sample.wake_ret as u64,
            requeue_ret: sample.requeue_ret as u64,
            from_count: sample.from_count as u64,
            from_requeue_wake: sample.from_requeue_wake as u64,
            from_requeue_count: sample.from_requeue_count as u64,
            from_logical_requeued: sample.from_logical_requeued as u64,
            from_logical_wake: sample.from_logical_wake as u64,
            to_count: sample.to_count as u64,
            to_requeue_wake: sample.to_requeue_wake as u64,
            to_requeue_count: sample.to_requeue_count as u64,
            to_logical_requeued: sample.to_logical_requeued as u64,
            to_logical_wake: sample.to_logical_wake as u64,
        };
        ULOCK_REQUEUE_PROBE.with(|slot| {
            slot.set(payload);
            let ptr = slot.as_ptr() as u64;
            carrick_usdt::ulock__requeue!(|| ptr);
        });
    }

    pub fn futex_unexpected_errno(host_addr: u64, errno: i32) {
        carrick_usdt::futex__unexpected__errno!(|| (std::process::id(), host_addr, errno));
    }

    pub fn guest_exit(code: i32) {
        carrick_usdt::guest__exit!(|| (std::process::id(), code));
    }

    pub fn mn_admit(tid: i32, slot: u32, budget: u32) {
        carrick_usdt::mn__admit!(|| (tid, slot, budget));
    }

    pub fn mn_reclaim(tid: i32, old_slot: u32, new_slot: u32, kind: i32) {
        carrick_usdt::mn__reclaim!(|| (tid, old_slot, new_slot, kind));
    }

    /// Per-run lifecycle phase markers (see the `lifecycle` provider doc). Fire one
    /// at each boundary so `carrick trace` can attribute the per-run wall-clock to
    /// startup / VM-create / guest-load / run / teardown phases.
    pub mod phase {
        pub const RUN_ENTRY: u32 = 0;
        pub const IMAGE_READY: u32 = 1;
        pub const VM_CREATED: u32 = 2;
        pub const GUEST_LOADED: u32 = 3;
        pub const FIRST_VCPU_RUN: u32 = 4;
        pub const VM_DESTROY_BEGIN: u32 = 5;
        pub const VM_DESTROY_END: u32 = 6;
    }

    pub fn lifecycle(phase: u32) {
        carrick_usdt::lifecycle!(|| phase);
    }

    pub fn execve_argv(path: &str, argv: &[Vec<u8>]) {
        // argv items are opaque bytes (Linux ABI); lossily decode + join for the
        // trace (display only). `argv.join` allocates, so it can't move inside the
        // closure (the returned `&str` would dangle once the closure's local String
        // drops, before usdt serialises it). execve is rare, so the unconditional
        // join is acceptable; the hot paths above are zero-cost-when-disabled.
        let joined = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a))
            .collect::<Vec<_>>()
            .join(" ");
        carrick_usdt::execve__argv!(|| (std::process::id(), path, joined.as_str()));
    }

    pub fn fs_op(op: &str, path: &str, errno: i32) {
        carrick_usdt::fs__op!(|| (std::process::id(), op, path, errno));
    }

    pub fn host_pipe_io(host_fd: i32, dir: i32, n: i64) {
        carrick_usdt::host__pipe__io!(|| (std::process::id(), host_fd, dir, n));
    }

    pub fn epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32) {
        carrick_usdt::epoll__ctl!(|| (epfd, op, fd, events, data, errno));
    }

    pub fn epoll_interest(
        epfd: i32,
        fd: i32,
        requested: u32,
        raw_ready: u32,
        last_ready: u32,
        ready: u32,
    ) {
        carrick_usdt::epoll__interest!(|| (epfd, fd, requested, raw_ready, last_ready, ready));
    }

    /// Raw-pointer payload for `epoll-masked`. Keep field order in sync with
    /// `scripts/dtrace/epoll-wait-debug.d`.
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EpollMaskedWireProbe {
        origin: u64,
        fd: u64,
        host_fd: u64,
        requested: u64,
        raw_ready: u64,
        last_ready: u64,
        read_avail: u64,
        last_read_avail: u64,
    }

    thread_local! {
        static EPOLL_MASKED_PROBE: std::cell::Cell<EpollMaskedWireProbe> =
            const { std::cell::Cell::new(EpollMaskedWireProbe {
                origin: 0,
                fd: 0,
                host_fd: 0,
                requested: 0,
                raw_ready: 0,
                last_ready: 0,
                read_avail: 0,
                last_read_avail: 0,
            }) };
    }

    #[inline(never)]
    pub fn epoll_masked(sample: super::EpollMaskedProbe) {
        let payload = EpollMaskedWireProbe {
            origin: sample.origin as u64,
            fd: sample.fd as i64 as u64,
            host_fd: sample.host_fd as i64 as u64,
            requested: sample.requested as u64,
            raw_ready: sample.raw_ready as u64,
            last_ready: sample.last_ready as u64,
            read_avail: sample.read_avail,
            last_read_avail: sample.last_read_avail,
        };
        EPOLL_MASKED_PROBE.with(|slot| {
            slot.set(payload);
            let ptr = slot.as_ptr() as u64;
            carrick_usdt::epoll__masked!(|| ptr);
        });
    }

    /// Raw-pointer payload for `epoll-rebind`. Keep field order in sync with
    /// `scripts/dtrace/epoll-wait-debug.d`.
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EpollRebindProbe {
        reason: u64,
        host_fd: u64,
        survivor_fd: u64,
        survivor_gen: u64,
        union_events: u64,
        effective: u64,
    }

    thread_local! {
        static EPOLL_REBIND_PROBE: std::cell::Cell<EpollRebindProbe> =
            const { std::cell::Cell::new(EpollRebindProbe {
                reason: 0,
                host_fd: 0,
                survivor_fd: 0,
                survivor_gen: 0,
                union_events: 0,
                effective: 0,
            }) };
    }

    #[inline(never)]
    pub fn epoll_rebind(
        reason: u32,
        host_fd: i32,
        survivor_fd: i32,
        survivor_gen: u32,
        union_events: u32,
        effective: u32,
    ) {
        let payload = EpollRebindProbe {
            reason: reason as u64,
            host_fd: host_fd as i64 as u64,
            survivor_fd: survivor_fd as i64 as u64,
            survivor_gen: survivor_gen as u64,
            union_events: union_events as u64,
            effective: effective as u64,
        };
        EPOLL_REBIND_PROBE.with(|slot| {
            slot.set(payload);
            let ptr = slot.as_ptr() as u64;
            carrick_usdt::epoll__rebind!(|| ptr);
        });
    }

    pub fn epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32) {
        carrick_usdt::epoll__wait__fd!(|| (epfd, fd, host_fd, poll_events, timeout_ms));
    }

    pub fn epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32) {
        carrick_usdt::epoll__result!(|| (epfd, ready_count, wait_count, timeout_ms, kind));
    }

    pub fn epoll_stale_edge(udata: u64, guest_fd: i32, generation: u32) {
        carrick_usdt::epoll__stale__edge!(|| (udata, guest_fd, generation));
    }

    pub fn io_wait_begin(
        tid: i32,
        fd_count: i32,
        timeout_ms: i64,
        fd0: i32,
        events0: i32,
        fd1: i32,
    ) {
        carrick_usdt::io__wait__begin!(|| (tid, fd_count, timeout_ms, fd0, events0, fd1));
    }

    pub fn io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32) {
        carrick_usdt::io__wait__end!(|| (tid, result, fd_count, fd0, fd1, fd2));
    }

    pub fn fork_quiesce(phase: i32, a: i64, b: i64, tid: i32) {
        carrick_usdt::fork__quiesce!(|| (phase, a, b, tid));
    }

    pub fn fork_rebuild(role: i32, phase: i32, desc_count: u64, map_count: u64, elapsed_us: u64) {
        carrick_usdt::fork__rebuild!(|| (role, phase, desc_count, map_count, elapsed_us));
    }

    pub fn fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64) {
        carrick_usdt::fork__lifecycle!(|| (role, phase, elapsed_us, a, b));
    }

    pub fn fork_footprint(
        phase: i32,
        vm_region_count: u64,
        arena_high_water: u64,
        resident_bytes: u64,
        virtual_bytes: u64,
    ) {
        carrick_usdt::fork__footprint!(|| {
            (
                phase,
                vm_region_count,
                arena_high_water,
                resident_bytes,
                virtual_bytes,
            )
        });
    }

    pub fn fork_footprint_class(
        class_id: i32,
        region_count: u64,
        scan_bytes: u64,
        resident_bytes: u64,
        flags: u64,
    ) {
        carrick_usdt::fork__footprint__class!(|| {
            (class_id, region_count, scan_bytes, resident_bytes, flags)
        });
    }

    pub fn with_fork_footprint_class_probe<F>(emit: F)
    where
        F: FnOnce(),
    {
        let mut emit = Some(emit);
        carrick_usdt::fork__footprint__class!(|| {
            if let Some(emit) = emit.take() {
                emit();
            }
            (0, 0, 0, 0, 0)
        });
    }

    pub fn fork_post(pid: i32, pc: u64, elr: u64) {
        carrick_usdt::fork__post!(|| (pid, pc, elr));
    }

    pub fn signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64) {
        carrick_usdt::signal__inject!(|| (signum, saved_pc, new_sp, handler));
    }

    pub fn signal_restore(saved_pc: u64, sp: u64, magic: u64) {
        carrick_usdt::signal__restore!(|| (saved_pc, sp, magic));
    }

    pub fn kick_in_kernel(pc: u64, el: u32) {
        carrick_usdt::kick__in_kernel!(|| (pc, el));
    }

    pub fn kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64) {
        carrick_usdt::kick__stats!(|| (el1_resumed, kick_inject, inject_at_el1));
    }

    pub fn mem_watch(syscall_nr: u64, addr: u64, value: u64) {
        carrick_usdt::mem__watch!(|| (syscall_nr, addr, value));
    }

    pub fn sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64) {
        carrick_usdt::sigaction__read!(|| (signum, w0, w1, w2, w3));
    }

    pub fn supervisor_fork(child_pid: i32) {
        carrick_usdt::supervisor__fork!(|| child_pid);
    }

    pub fn supervisor_child_ready(runtime_pid: i32) {
        carrick_usdt::supervisor__child__ready!(|| runtime_pid);
    }

    pub fn supervisor_foreground_pgrp(pgid: i32, errno: i32) {
        carrick_usdt::supervisor__foreground__pgrp!(|| (pgid, errno));
    }

    pub fn supervisor_child_exit(pid: i32, status: i32) {
        carrick_usdt::supervisor__child__exit!(|| (pid, status));
    }

    pub fn pt_pause_begin(tid: i32, others_in_guest: i32, count: i32) {
        carrick_usdt::pt__pause__begin!(|| (tid, others_in_guest, count));
    }

    pub fn pt_pause_ready(tid: i32, spins: i32, wait_us: i64) {
        carrick_usdt::pt__pause__ready!(|| (tid, spins, wait_us));
    }

    pub fn pt_pause_timeout(tid: i32, wait_us: i64) {
        carrick_usdt::pt__pause__timeout!(|| (tid, wait_us));
    }

    pub fn pt_pause_end(tid: i32) {
        carrick_usdt::pt__pause__end!(|| tid);
    }

    pub fn pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32) {
        carrick_usdt::pt__pool!(|| (in_use, free_list, capacity, changed));
    }

    pub fn pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64) {
        carrick_usdt::pt__fault__walk!(|| (far, l0, l1, l2, l3));
    }

    pub mod guest_mem_dir {
        pub const READ_GUEST: u32 = 0;
        pub const WRITE_GUEST: u32 = 1;
        pub const WRITE_GUEST_CHECKED: u32 = 2;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct GuestMemProbeDigest {
        checksum: u64,
        nonzero: u64,
        head: u64,
        tail: u64,
    }

    fn guest_mem_probe_digest(bytes: &[u8]) -> GuestMemProbeDigest {
        let checksum = bytes
            .iter()
            .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)));
        GuestMemProbeDigest {
            checksum,
            nonzero: bytes.iter().filter(|byte| **byte != 0).count() as u64,
            head: guest_mem_probe_edge(bytes.iter().copied()),
            tail: if bytes.len() <= 8 {
                guest_mem_probe_edge(bytes.iter().copied())
            } else {
                guest_mem_probe_edge(bytes[bytes.len() - 8..].iter().copied())
            },
        }
    }

    fn guest_mem_probe_edge(bytes: impl IntoIterator<Item = u8>) -> u64 {
        bytes
            .into_iter()
            .take(8)
            .enumerate()
            .fold(0u64, |word, (idx, byte)| {
                word | (u64::from(byte) << (idx * 8))
            })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct GuestMemSubrangeConfig {
        offset: usize,
        length: usize,
    }

    fn guest_mem_subrange_config() -> Option<GuestMemSubrangeConfig> {
        static CONFIG: std::sync::OnceLock<Option<GuestMemSubrangeConfig>> =
            std::sync::OnceLock::new();

        *CONFIG.get_or_init(|| {
            let offset = parse_guest_mem_probe_usize_env("CARRICK_GUEST_MEM_SUB_OFFSET")?;
            let length = parse_guest_mem_probe_usize_env("CARRICK_GUEST_MEM_SUB_LEN")?;
            (length != 0).then_some(GuestMemSubrangeConfig { offset, length })
        })
    }

    fn parse_guest_mem_probe_usize_env(name: &str) -> Option<usize> {
        let value = std::env::var(name).ok()?;
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        if let Some(hex) = value.strip_prefix("0x") {
            usize::from_str_radix(hex, 16).ok()
        } else {
            value.parse::<usize>().ok()
        }
    }

    fn guest_mem_probe_subrange(
        bytes: &[u8],
        config: GuestMemSubrangeConfig,
    ) -> Option<(u64, GuestMemProbeDigest)> {
        let end = config.offset.checked_add(config.length)?;
        let subrange = bytes.get(config.offset..end)?;
        Some((config.offset as u64, guest_mem_probe_digest(subrange)))
    }

    pub fn guest_mem_probe_points(address: u64, length: usize) -> [Option<u64>; 5] {
        if length == 0 {
            return [None, None, None, None, None];
        }

        let length = length as u64;
        let three_quarter_offset = (length / 4) * 3 + ((length % 4) * 3) / 4;
        let candidates = [
            Some(address),
            address.checked_add(length / 4),
            address.checked_add(length / 2),
            address.checked_add(three_quarter_offset),
            address.checked_add(length - 1),
        ];
        let mut points = [None, None, None, None, None];
        let mut next = 0usize;
        for candidate in candidates.into_iter().flatten() {
            if points[..next].contains(&Some(candidate)) {
                continue;
            }
            points[next] = Some(candidate);
            next += 1;
        }
        points
    }

    pub fn guest_mem_copy(
        direction: u32,
        address: u64,
        length: usize,
        stage1_ipa: Option<u64>,
        mapping_start: u64,
        mapping_end: u64,
        mapping_ipa: u64,
    ) {
        let stage1_ipa = stage1_ipa.unwrap_or(u64::MAX);
        carrick_usdt::guest__mem__copy!(|| (
            direction,
            address,
            length as u64,
            stage1_ipa,
            mapping_start
        ));
        carrick_usdt::guest__mem__region!(|| (
            direction,
            address,
            mapping_start,
            mapping_end,
            mapping_ipa
        ));
    }

    pub fn guest_mem_bytes(direction: u32, address: u64, bytes: &[u8]) {
        carrick_usdt::guest__mem__bytes!(|| {
            let digest = guest_mem_probe_digest(bytes);
            (
                direction,
                address,
                bytes.len() as u64,
                digest.checksum,
                digest.head,
            )
        });
        carrick_usdt::guest__mem__tail!(|| (
            direction,
            address,
            bytes.len() as u64,
            guest_mem_probe_digest(bytes).tail
        ));
        if let Some(config) = guest_mem_subrange_config()
            && let Some((offset, digest)) = guest_mem_probe_subrange(bytes, config)
        {
            carrick_usdt::guest__mem__subrange!(|| (
                direction,
                address,
                offset,
                config.length as u64,
                digest.checksum,
            ));
            carrick_usdt::guest__mem__subedge!(|| (
                direction,
                address,
                offset,
                digest.head,
                digest.tail,
            ));
            carrick_usdt::guest__mem__subcount!(|| (direction, address, offset, digest.nonzero));
        }
    }

    pub fn guest_mem_point(
        direction: u32,
        address: u64,
        stage1_ipa: Option<u64>,
        mapping_start: u64,
        mapping_ipa: u64,
    ) {
        let va_offset = address.wrapping_sub(mapping_start);
        let ipa_offset = stage1_ipa
            .map(|ipa| ipa.wrapping_sub(mapping_ipa))
            .unwrap_or(u64::MAX);
        carrick_usdt::guest__mem__point!(|| (
            direction,
            address,
            va_offset,
            ipa_offset,
            stage1_ipa.unwrap_or(u64::MAX)
        ));
    }

    // `#[inline(never)]`: usdt embeds the probe site (an asm! anchor) in
    // the function body. If this gets inlined into multiple callers, each
    // copy becomes a SEPARATE DTrace probe site that fires independently
    // — so a single logical trap would fire `vcpu-trap` twice. Pinning the
    // function to one body keeps it a single, stable probe site.
    #[inline(never)]
    pub fn vcpu_trap(regs: &crate::compat::GuestRegs) {
        // Pass the struct's address; DTrace copyin's it. The reference is
        // live for the duration of this (inline(never)) function, which is
        // where usdt's synchronous probe fire happens, so the pointer is
        // valid when DTrace reads it.
        let ptr = regs as *const crate::compat::GuestRegs as u64;
        carrick_usdt::vcpu__trap!(|| ptr);
    }

    pub fn execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64) {
        carrick_usdt::execve__loaded!(|| (path, entry, initial_sp, mapping_count));
    }

    pub fn execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64) {
        carrick_usdt::execve__sysregs!(|| (sctlr, ttbr0, mair));
    }

    /// Fires on a fatal guest EL0 fault (instruction/data abort, undef). See the
    /// `vcpu__fault` provider doc. Cheap: only fires at the fault.
    pub fn vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32) {
        carrick_usdt::vcpu__fault!(|| (esr, elr, far, x30, sp, tid));
    }

    /// Emit the decoded fault diagnostics as scalars. See the `vcpu__fault__regs`
    /// provider doc. Scalars are captured at fire time, so this survives a fault
    /// that kills the process before DTrace's action runs. Fires only at the fault.
    pub fn vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64) {
        carrick_usdt::vcpu__fault__regs!(|| (esr, elr, far, insn, rn, xrn));
    }

    /// Emit a high-VA alias page-table walk. See `pt__alias__walk`. `flag` bit0 =
    /// forked child, bit1 = the page-table build failed.
    pub fn pt_alias_walk(va: u64, descs: [u64; 4], flag: i32) {
        carrick_usdt::pt__alias__walk!(|| (va, descs[0], descs[1], descs[2], descs[3], flag));
    }

    /// Emit the stage-2 `hv_vm_map` result for an alias mapping. See
    /// `hv__vm__map__alias`. Fires right after the call, success or failure.
    pub fn hv_vm_map_alias(va: u64, ipa: u64, size: u64, rc: i32, forked: i32) {
        carrick_usdt::hv__vm__map__alias!(|| (va, ipa, size, rc, forked));
    }

    /// A signal was published for delivery. See `signal__publish`.
    pub fn signal_publish(target_tid: i32, signum: i32, kind: i32) {
        carrick_usdt::signal__publish!(|| (target_tid, signum, kind));
    }

    /// A `deliver_pending_signal` cycle ran. See `signal__deliver`.
    pub fn signal_deliver(tid: i32, pending: i32) {
        carrick_usdt::signal__deliver!(|| (tid, pending));
    }

    pub fn register_dtrace_probes() -> Result<(), usdt::Error> {
        // Install the compat reporter's per-event probe hook so every recorded
        // CompatEvent fires its DTrace probe. compat lives in the neutral
        // carrick-observability crate (no usdt dep) and only fires probes through
        // this hook; Linux/bhyve never install it. Idempotent (OnceLock).
        crate::compat::set_probe_hook(fire);
        usdt::register_probes()
    }

    pub fn fire(event: &CompatEvent) {
        fire_usdt(event);
    }

    fn fire_usdt(event: &CompatEvent) {
        match event {
            CompatEvent::SyscallEntry { number, name, args } => {
                // `args` lives in `event` for the duration of this synchronous
                // probe fire, so its address is valid when DTrace copyin's it.
                let args_ptr = args as *const SyscallArgs as u64;
                carrick_usdt::syscall__entry!(|| (*number, name.as_ref(), args_ptr));
            }
            CompatEvent::SyscallReturn {
                number,
                name,
                retval,
                errno,
            } => {
                carrick_usdt::syscall__return!(|| {
                    (*number, name.as_ref(), *retval, errno.unwrap_or(0))
                });
            }
            CompatEvent::UnhandledSyscall { number, name, args } => {
                let args_ptr = args as *const SyscallArgs as u64;
                carrick_usdt::unhandled__syscall!(|| (*number, name.as_str(), args_ptr));
            }
            CompatEvent::PartialSyscall {
                number,
                name,
                args,
                reason,
            } => {
                let args_ptr = args as *const SyscallArgs as u64;
                carrick_usdt::partial__syscall!(|| (
                    *number,
                    name.as_str(),
                    args_ptr,
                    reason.as_str()
                ));
            }
            CompatEvent::UnhandledIoctl { fd, request, arg } => {
                carrick_usdt::unhandled__ioctl!(|| (*fd, *request, *arg));
            }
            CompatEvent::ProcReadUnimplemented { path } => {
                carrick_usdt::proc__read__unimplemented!(|| path.as_str());
            }
            CompatEvent::SysReadUnimplemented { path } => {
                carrick_usdt::sys__read__unimplemented!(|| path.as_str());
            }
            CompatEvent::SignalUnsupported { signum, reason } => {
                carrick_usdt::signal__unsupported!(|| (*signum, reason.as_str()));
            }
            CompatEvent::UnknownSyscallFlags {
                number,
                name,
                argument,
                unknown_bits,
            } => {
                carrick_usdt::unknown__syscall__flags!(|| (
                    *number,
                    name.as_str(),
                    *argument,
                    *unknown_bits
                ));
            }
        }
    }

    #[allow(dead_code)]
    fn _assert_args_are_serializable(args: &SyscallArgs) -> &SyscallArgs {
        args
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn guest_mem_probe_digest_reports_wrapping_sum_and_edges() {
            let bytes = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0,
                0x90, 0x80,
            ];

            let digest = super::guest_mem_probe_digest(&bytes);

            assert_eq!(digest.checksum, 0x5e4);
            assert_eq!(digest.nonzero, 16);
            assert_eq!(digest.head, 0x0807_0605_0403_0201);
            assert_eq!(digest.tail, 0x8090_a0b0_c0d0_e0f0);
        }

        #[test]
        fn guest_mem_probe_digest_zero_pads_short_edges() {
            let digest = super::guest_mem_probe_digest(&[0xaa, 0xbb, 0xcc]);

            assert_eq!(digest.checksum, 0x231);
            assert_eq!(digest.nonzero, 3);
            assert_eq!(digest.head, 0x00cc_bbaa);
            assert_eq!(digest.tail, 0x00cc_bbaa);
        }

        #[test]
        fn guest_mem_probe_subrange_reports_exact_window_digest() {
            let bytes = [0xaa, 0x00, 0xbb, 0xcc, 0x00, 0xdd];

            let (_, digest) = super::guest_mem_probe_subrange(
                &bytes,
                super::GuestMemSubrangeConfig {
                    offset: 1,
                    length: 4,
                },
            )
            .unwrap();

            assert_eq!(digest.checksum, 0x187);
            assert_eq!(digest.nonzero, 2);
            assert_eq!(digest.head, 0x00cc_bb00);
            assert_eq!(digest.tail, 0x00cc_bb00);
        }

        #[test]
        fn guest_mem_probe_points_cover_quarters_and_last_byte_without_duplicates() {
            assert_eq!(
                super::guest_mem_probe_points(0x1000, 0),
                [None, None, None, None, None]
            );
            assert_eq!(
                super::guest_mem_probe_points(0x1000, 1),
                [Some(0x1000), None, None, None, None]
            );
            assert_eq!(
                super::guest_mem_probe_points(0x1000, 2),
                [Some(0x1000), Some(0x1001), None, None, None]
            );
            assert_eq!(
                super::guest_mem_probe_points(0x4590, 8192),
                [
                    Some(0x4590),
                    Some(0x4d90),
                    Some(0x5590),
                    Some(0x5d90),
                    Some(0x658f)
                ]
            );
        }

        #[test]
        fn guest_mem_probe_points_sample_inside_large_range_quarters() {
            let points = super::guest_mem_probe_points(0x4590, 8192);

            assert!(
                points.contains(&Some(0x5d90)),
                "expected 75% sample point in {points:?}"
            );
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
)))]
mod stub {
    //! No-op probe surface for backends whose host OS does not support `usdt`
    //! (Linux, NetBSD). Every public item the `real` module exports is mirrored
    //! here with an IDENTICAL signature and an empty body, so the dispatcher's
    //! `crate::probes::…` call sites compile unchanged. The three non-probe
    //! helpers (`guest_mem_probe_points`/`guest_mem_copy`/`guest_mem_point`) are
    //! plain logic, not probe fires, so they keep their REAL bodies — behaviour
    //! is identical to the real arm.

    macro_rules! stub {
        ($name:ident($($param:ident: $ty:ty),* $(,)?)) => {
            #[allow(dead_code, unused_variables)]
            #[inline(always)]
            pub fn $name($($param: $ty),*) {}
        };
    }

    stub!(dsr_prepare_begin(tid: i32, guest_pc: u64));
    stub!(dsr_prepare_end(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64, outcome: super::DsrPrepareOutcome));
    stub!(dsr_run_begin(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64));
    stub!(dsr_run_end(tid: i32, kind: super::DsrExitKind, guest_pc: u64, target_pc: u64, status: i32));
    stub!(dsr_translate_begin(tid: i32, guest_pc: u64, generation: u64));
    stub!(dsr_translate_end(tid: i32, guest_pc: u64, cache_pc: u64, emitted_bytes: u64, outcome: super::DsrOperationOutcome));
    stub!(dsr_resolve_begin(tid: i32, kind: super::DsrResolveKind, source_pc: u64, target_pc: u64));
    stub!(dsr_resolve_end(tid: i32, kind: super::DsrResolveKind, source_pc: u64, target_pc: u64, outcome: super::DsrOperationOutcome));
    stub!(dsr_cache_event(tid: i32, kind: super::DsrCacheEventKind, guest_pc: u64, generation: u64, used_bytes: u64));
    stub!(dsr_cache_capacity(role: super::DsrCacheRole, capacity_bytes: u64));
    stub!(dsr_cache_lifecycle(role: super::DsrCacheRole, phase: super::DsrCacheLifecyclePhase, used_bytes: u64, block_count: u64, generation_count: u64));
    stub!(fork_pre(pc: u64, elr: u64, cpsr: u64));
    stub!(path_open(path: &str, result_size: u64, errno: i32));
    stub!(itimer_fire(signum: i32, generation: u64));
    stub!(futex_route(addr: u64, op: i32, shared: i32, host_addr: u64));
    stub!(ulock_wait(host_addr: u64, value: u32, timeout_us: u32, phase: i32, rc: i64));
    stub!(ulock_wake(host_addr: u64, iter: i32, rc: i64));
    stub!(ulock_requeue(sample: super::UlockRequeueProbe));
    stub!(futex_unexpected_errno(host_addr: u64, errno: i32));
    stub!(guest_exit(code: i32));
    stub!(mn_admit(tid: i32, slot: u32, budget: u32));
    stub!(mn_reclaim(tid: i32, old_slot: u32, new_slot: u32, kind: i32));
    stub!(lifecycle(phase: u32));
    stub!(execve_argv(path: &str, argv: &[Vec<u8>]));
    stub!(fs_op(op: &str, path: &str, errno: i32));
    stub!(host_pipe_io(host_fd: i32, dir: i32, n: i64));
    stub!(epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32));
    stub!(epoll_interest(epfd: i32, fd: i32, requested: u32, raw_ready: u32, last_ready: u32, ready: u32));
    stub!(epoll_masked(sample: super::EpollMaskedProbe));
    stub!(epoll_rebind(reason: u32, host_fd: i32, survivor_fd: i32, survivor_gen: u32, union_events: u32, effective: u32));
    stub!(epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32));
    stub!(epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32));
    stub!(epoll_stale_edge(udata: u64, guest_fd: i32, generation: u32));
    stub!(io_wait_begin(tid: i32, fd_count: i32, timeout_ms: i64, fd0: i32, events0: i32, fd1: i32));
    stub!(io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32));
    stub!(fork_quiesce(phase: i32, a: i64, b: i64, tid: i32));
    stub!(fork_rebuild(role: i32, phase: i32, desc_count: u64, map_count: u64, elapsed_us: u64));
    stub!(fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64));
    stub!(fork_footprint(phase: i32, vm_region_count: u64, arena_high_water: u64, resident_bytes: u64, virtual_bytes: u64));
    stub!(fork_footprint_class(class_id: i32, region_count: u64, scan_bytes: u64, resident_bytes: u64, flags: u64));
    stub!(fork_post(pid: i32, pc: u64, elr: u64));
    stub!(signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64));
    stub!(signal_restore(saved_pc: u64, sp: u64, magic: u64));
    stub!(kick_in_kernel(pc: u64, el: u32));
    stub!(kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64));
    stub!(mem_watch(syscall_nr: u64, addr: u64, value: u64));
    stub!(sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64));
    stub!(supervisor_fork(child_pid: i32));
    stub!(supervisor_child_ready(runtime_pid: i32));
    stub!(supervisor_foreground_pgrp(pgid: i32, errno: i32));
    stub!(supervisor_child_exit(pid: i32, status: i32));
    stub!(pt_pause_begin(tid: i32, others_in_guest: i32, count: i32));
    stub!(pt_pause_ready(tid: i32, spins: i32, wait_us: i64));
    stub!(pt_pause_timeout(tid: i32, wait_us: i64));
    stub!(pt_pause_end(tid: i32));
    stub!(pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32));
    stub!(pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64));
    stub!(guest_mem_bytes(direction: u32, address: u64, bytes: &[u8]));
    stub!(vcpu_trap(regs: &crate::compat::GuestRegs));
    stub!(execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64));
    stub!(execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64));
    stub!(vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32));
    stub!(vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64));
    stub!(pt_alias_walk(va: u64, descs: [u64; 4], flag: i32));
    stub!(hv_vm_map_alias(va: u64, ipa: u64, size: u64, rc: i32, forked: i32));
    stub!(signal_publish(target_tid: i32, signum: i32, kind: i32));
    stub!(signal_deliver(tid: i32, pending: i32));
    stub!(fire(event: &crate::compat::CompatEvent));

    pub fn with_fork_footprint_class_probe<F>(_emit: F)
    where
        F: FnOnce(),
    {
    }

    /// Per-run lifecycle phase markers (mirrors `real::phase`).
    pub mod phase {
        pub const RUN_ENTRY: u32 = 0;
        pub const IMAGE_READY: u32 = 1;
        pub const VM_CREATED: u32 = 2;
        pub const GUEST_LOADED: u32 = 3;
        pub const FIRST_VCPU_RUN: u32 = 4;
        pub const VM_DESTROY_BEGIN: u32 = 5;
        pub const VM_DESTROY_END: u32 = 6;
    }

    /// Guest-memory copy direction tags (mirrors `real::guest_mem_dir`).
    pub mod guest_mem_dir {
        pub const READ_GUEST: u32 = 0;
        pub const WRITE_GUEST: u32 = 1;
        pub const WRITE_GUEST_CHECKED: u32 = 2;
    }

    // The three non-probe helpers carry their REAL bodies (plain logic), so the
    // Linux/NetBSD arm computes identical results to the macOS/FreeBSD arm.

    pub fn guest_mem_probe_points(address: u64, length: usize) -> [Option<u64>; 5] {
        if length == 0 {
            return [None, None, None, None, None];
        }

        let length = length as u64;
        let three_quarter_offset = (length / 4) * 3 + ((length % 4) * 3) / 4;
        let candidates = [
            Some(address),
            address.checked_add(length / 4),
            address.checked_add(length / 2),
            address.checked_add(three_quarter_offset),
            address.checked_add(length - 1),
        ];
        let mut points = [None, None, None, None, None];
        let mut next = 0usize;
        for candidate in candidates.into_iter().flatten() {
            if points[..next].contains(&Some(candidate)) {
                continue;
            }
            points[next] = Some(candidate);
            next += 1;
        }
        points
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guest_mem_copy(
        _direction: u32,
        _address: u64,
        _length: usize,
        _stage1_ipa: Option<u64>,
        _mapping_start: u64,
        _mapping_end: u64,
        _mapping_ipa: u64,
    ) {
    }

    pub fn guest_mem_point(
        _direction: u32,
        _address: u64,
        _stage1_ipa: Option<u64>,
        _mapping_start: u64,
        _mapping_ipa: u64,
    ) {
    }

    pub fn register_dtrace_probes() -> Result<(), usdt::Error> {
        Ok(())
    }
}
