//! USDT-free probe seam for the DSR memory/cache machinery.
//!
//! `carrick-dsr` must stay free of `usdt` (the proc macro selects probe-asm
//! registers by the HOST arch, which breaks `--target aarch64-apple-darwin`
//! cross-checks from a non-Darwin rig — see the portability-seams design
//! doc). The moved memory-model code therefore fires its lifecycle/exec-map
//! probes through this indirection: the runtime installs a forwarder that
//! maps these mirrored enums 1:1 onto `carrick-observability`'s and calls the
//! real USDT probes; until a sink is installed every call helper is a no-op.
//!
//! The enums mirror `carrick-observability/src/probes.rs` variant-for-variant
//! and value-for-value; the DTrace consumer decodes raw ordinals, so the
//! mirrored discriminants are ABI and must never drift from the originals
//! (the runtime forwarder's exhaustive `match` breaks the build if a variant
//! is added on either side alone).

use std::sync::OnceLock;

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
    /// Stable DSR cache lifecycle boundary. Mirrors
    /// `carrick_observability::probes::DsrCacheLifecyclePhase` exactly.
    pub enum DsrCacheLifecyclePhase {
        ForkChildRepairBegin = 1,
        ForkChildRepairEnd = 2,
        ExecResetBegin = 3,
        ExecResetEnd = 4,
        ExecImageUnmapBegin = 5,
        ExecImageUnmapEnd = 6,
        ExecImageMapBegin = 7,
        ExecImageMapEnd = 8,
        ExecCacheResetBegin = 9,
        ExecCacheResetEnd = 10,
        ExecRelocationBegin = 11,
        ExecRelocationEnd = 12,
        ExecTranslatorHandoffBegin = 13,
        ExecTranslatorHandoffEnd = 14,
        ExecMapMmapBegin = 15,
        ExecMapMmapEnd = 16,
        ExecMapCopyBegin = 17,
        ExecMapCopyEnd = 18,
        ExecMapIcacheBegin = 19,
        ExecMapIcacheEnd = 20,
        ExecMapProtectBegin = 21,
        ExecMapProtectEnd = 22,
        ExecMapVvarBegin = 23,
        ExecMapVvarEnd = 24,
        HostSelfReexecBegin = 25,
        HostSelfReexecEnd = 26,
        HostSelfReexecProbesReady = 27,
        HostSelfReexecCapsuleBegin = 28,
        HostSelfReexecCapsuleEnd = 29,
        HostSelfReexecRestoreBegin = 30,
        HostSelfReexecDispatcherReady = 31,
        HostSelfReexecImageLoadBegin = 32,
        HostSelfReexecImageLoadEnd = 33,
        HostSelfReexecResetBegin = 34,
        HostSelfReexecResetEnd = 35,
        HostSelfReexecGuestEntry = 36,
        HostSelfReexecPreflightBegin = 37,
        HostSelfReexecCapsulePrepareBegin = 38,
        HostSelfReexecPreparedBuildBegin = 39,
        HostSelfReexecPreparedBuildEnd = 40,
        HostSelfReexecPreparedValidateBegin = 41,
        HostSelfReexecPreparedValidateEnd = 42,
        HostSelfReexecPreparedMapBegin = 43,
        HostSelfReexecPreparedMapEnd = 44,
    }
}

dsr_ordinal_enum! {
    /// Aggregate component of one native DSR exec image mapping. Mirrors
    /// `carrick_observability::probes::DsrExecMapDetailKind` exactly.
    pub enum DsrExecMapDetailKind {
        Mmap = 1,
        Copy = 2,
        Icache = 3,
        Protect = 4,
        Vvar = 5,
    }
}

/// Receiver for the two probe families the DSR memory model fires. Argument
/// lists are exactly the observability functions' (`dsr_cache_lifecycle` /
/// `dsr_exec_map_detail`) with the mirrored enums substituted.
pub trait DsrProbeSink: Send + Sync {
    fn dsr_cache_lifecycle(
        &self,
        tid: i32,
        phase: DsrCacheLifecyclePhase,
        used_bytes: u64,
        block_count: u64,
        generation_count: u64,
    );

    fn dsr_exec_map_detail(
        &self,
        tid: i32,
        kind: DsrExecMapDetailKind,
        duration_ns: u64,
        bytes: u64,
        operations: u64,
    );
}

static SINK: OnceLock<&'static dyn DsrProbeSink> = OnceLock::new();

/// Install the process-wide probe sink. Idempotent, first-install-wins: a
/// second call (any thread) leaves the first sink in place and returns
/// without error, so racing initializers cannot flip a live sink mid-run.
pub fn install_probe_sink(sink: &'static dyn DsrProbeSink) {
    let _ = SINK.set(sink);
}

/// Fire the `dsr__cache__lifecycle` probe through the installed sink; no-op
/// when no sink is installed (probes simply vanish, matching a build with no
/// DTrace consumer attached).
#[inline(always)]
pub fn dsr_cache_lifecycle(
    tid: i32,
    phase: DsrCacheLifecyclePhase,
    used_bytes: u64,
    block_count: u64,
    generation_count: u64,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_cache_lifecycle(tid, phase, used_bytes, block_count, generation_count);
    }
}

/// Fire the `dsr__exec__map__detail` probe through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn dsr_exec_map_detail(
    tid: i32,
    kind: DsrExecMapDetailKind,
    duration_ns: u64,
    bytes: u64,
    operations: u64,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_exec_map_detail(tid, kind, duration_ns, bytes, operations);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct CountingSink {
        lifecycle: AtomicU64,
        detail: AtomicU64,
    }

    impl DsrProbeSink for CountingSink {
        fn dsr_cache_lifecycle(
            &self,
            _tid: i32,
            _phase: DsrCacheLifecyclePhase,
            _used_bytes: u64,
            _block_count: u64,
            _generation_count: u64,
        ) {
            self.lifecycle.fetch_add(1, Ordering::Relaxed);
        }

        fn dsr_exec_map_detail(
            &self,
            _tid: i32,
            _kind: DsrExecMapDetailKind,
            _duration_ns: u64,
            _bytes: u64,
            _operations: u64,
        ) {
            self.detail.fetch_add(1, Ordering::Relaxed);
        }
    }

    // One test on purpose: the sink is a process-global OnceLock, so the
    // uninstalled no-op, the first install, and the ignored second install
    // must be exercised in a fixed order within a single test.
    #[test]
    fn uninstalled_is_noop_then_first_install_wins() {
        static FIRST: CountingSink = CountingSink {
            lifecycle: AtomicU64::new(0),
            detail: AtomicU64::new(0),
        };
        static SECOND: CountingSink = CountingSink {
            lifecycle: AtomicU64::new(0),
            detail: AtomicU64::new(0),
        };

        // No sink installed: helpers must be a silent no-op.
        dsr_cache_lifecycle(1, DsrCacheLifecyclePhase::ExecImageMapBegin, 0, 0, 0);
        dsr_exec_map_detail(1, DsrExecMapDetailKind::Mmap, 0, 0, 0);
        assert_eq!(FIRST.lifecycle.load(Ordering::Relaxed), 0);
        assert_eq!(FIRST.detail.load(Ordering::Relaxed), 0);

        install_probe_sink(&FIRST);
        dsr_cache_lifecycle(1, DsrCacheLifecyclePhase::ExecImageMapEnd, 1, 2, 3);
        dsr_exec_map_detail(1, DsrExecMapDetailKind::Copy, 4, 5, 6);
        assert_eq!(FIRST.lifecycle.load(Ordering::Relaxed), 1);
        assert_eq!(FIRST.detail.load(Ordering::Relaxed), 1);

        // Second install is ignored (first-install-wins) and does not error.
        install_probe_sink(&SECOND);
        dsr_cache_lifecycle(1, DsrCacheLifecyclePhase::ExecCacheResetBegin, 0, 0, 0);
        assert_eq!(FIRST.lifecycle.load(Ordering::Relaxed), 2);
        assert_eq!(SECOND.lifecycle.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND.detail.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mirrored_ordinals_are_dense_and_start_at_one() {
        // The DTrace consumer decodes raw ordinals; catch accidental edits.
        for (index, phase) in DsrCacheLifecyclePhase::ALL.iter().enumerate() {
            assert_eq!(phase.raw() as usize, index + 1);
        }
        for (index, kind) in DsrExecMapDetailKind::ALL.iter().enumerate() {
            assert_eq!(kind.raw() as usize, index + 1);
        }
    }
}
