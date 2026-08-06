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

use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::OnceLock;

use carrick_guest_mem::{GuestVa, HostVa};

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
    /// Executable translated-code ownership carried by a typed range event.
    /// Mirrors `carrick_observability::probes::TranslatedRangeKind` exactly.
    pub enum TranslatedRangeKind {
        PrivateProcessCache = 1,
        SharedUnit = 2,
    }
}

/// Rejected translated-range identity or executable extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TranslatedRangeError {
    #[error("translated-range epoch must be nonzero")]
    ZeroEpoch,
    #[error("translated-range sequence must be nonzero")]
    ZeroSequence,
    #[error("translated shared-unit identity must be nonzero")]
    ZeroUnitId,
    #[error("translated executable range is empty at 0x{address:x}")]
    EmptyRange { address: usize },
    #[error("translated executable range is reversed: 0x{start:x}..0x{end:x}")]
    ReversedRange { start: usize, end: usize },
    #[error("translated executable range is not four-byte aligned: 0x{start:x}..0x{end:x}")]
    UnalignedRange { start: usize, end: usize },
}

/// Nonzero identity for one process-image translated-range catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedRangeEpoch(NonZeroU64);

impl TranslatedRangeEpoch {
    pub fn new(value: u64) -> Result<Self, TranslatedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TranslatedRangeError::ZeroEpoch)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Nonzero monotonically increasing identity for one catalog addition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedRangeSequence(NonZeroU64);

impl TranslatedRangeSequence {
    pub fn new(value: u64) -> Result<Self, TranslatedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TranslatedRangeError::ZeroSequence)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable nonzero identity for one loaded shared translation unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedUnitId(NonZeroU64);

impl TranslatedUnitId {
    pub fn new(value: u64) -> Result<Self, TranslatedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TranslatedRangeError::ZeroUnitId)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Reset the translated-range catalog for one process-image epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedRangeReset {
    epoch: TranslatedRangeEpoch,
}

impl TranslatedRangeReset {
    pub const fn reset(epoch: TranslatedRangeEpoch) -> Self {
        Self { epoch }
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }
}

/// Add one typed executable range to the active translated-range catalog.
///
/// The enum variants keep private and shared payloads distinct:
///
/// ```compile_fail
/// use carrick_dsr::probes::{
///     TranslatedRangeAdd, TranslatedRangeEpoch, TranslatedRangeSequence,
///     TranslatedSharedRange, TranslatedUnitId,
/// };
/// use carrick_guest_mem::HostVa;
///
/// let epoch = TranslatedRangeEpoch::new(1).unwrap();
/// let sequence = TranslatedRangeSequence::new(1).unwrap();
/// let unit_id = TranslatedUnitId::new(1).unwrap();
/// let shared = TranslatedSharedRange::shared(
///     epoch,
///     sequence,
///     unit_id,
///     HostVa(0x1000)..HostVa(0x2000),
/// ).unwrap();
/// let _ = TranslatedRangeAdd::Private(shared);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslatedRangeAdd {
    Private(TranslatedPrivateRange),
    Shared(TranslatedSharedRange),
}

impl TranslatedRangeAdd {
    pub const fn kind(&self) -> TranslatedRangeKind {
        match self {
            Self::Private(_) => TranslatedRangeKind::PrivateProcessCache,
            Self::Shared(_) => TranslatedRangeKind::SharedUnit,
        }
    }
}

/// Exact half-open executable extent of the process-private translation cache.
///
/// Its fields are private and there is no unit-ID parameter, so a caller
/// cannot construct a private event with shared-unit identity.
///
/// ```compile_fail
/// use carrick_dsr::probes::{
///     TranslatedPrivateRange, TranslatedRangeEpoch, TranslatedRangeSequence,
/// };
/// use carrick_guest_mem::HostVa;
///
/// let epoch = TranslatedRangeEpoch::new(1).unwrap();
/// let sequence = TranslatedRangeSequence::new(1).unwrap();
/// let _ = TranslatedPrivateRange {
///     epoch,
///     sequence,
///     range: HostVa(0x1000)..HostVa(0x2000),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedPrivateRange {
    epoch: TranslatedRangeEpoch,
    sequence: TranslatedRangeSequence,
    range: Range<HostVa>,
}

impl TranslatedPrivateRange {
    pub fn private(
        epoch: TranslatedRangeEpoch,
        sequence: TranslatedRangeSequence,
        range: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&range)?;
        Ok(Self {
            epoch,
            sequence,
            range,
        })
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }

    pub const fn sequence(&self) -> TranslatedRangeSequence {
        self.sequence
    }

    pub const fn range(&self) -> &Range<HostVa> {
        &self.range
    }
}

/// Exact half-open executable extent of one shared translation unit.
///
/// Its fields are private and construction requires a typed unit ID, so a
/// caller cannot publish a shared event without unit identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedSharedRange {
    epoch: TranslatedRangeEpoch,
    sequence: TranslatedRangeSequence,
    unit_id: TranslatedUnitId,
    range: Range<HostVa>,
}

impl TranslatedSharedRange {
    pub fn shared(
        epoch: TranslatedRangeEpoch,
        sequence: TranslatedRangeSequence,
        unit_id: TranslatedUnitId,
        range: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&range)?;
        Ok(Self {
            epoch,
            sequence,
            unit_id,
            range,
        })
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }

    pub const fn sequence(&self) -> TranslatedRangeSequence {
        self.sequence
    }

    pub const fn unit_id(&self) -> TranslatedUnitId {
        self.unit_id
    }

    pub const fn range(&self) -> &Range<HostVa> {
        &self.range
    }

    /// Re-key a previously validated shared range for a process-local replay.
    ///
    /// Fork replay preserves the unit, sequence, and executable extent while
    /// advancing only the child catalog epoch. Construction is infallible
    /// because the retained event already passed all typed validation.
    pub fn replayed_in(&self, epoch: TranslatedRangeEpoch) -> Self {
        Self {
            epoch,
            sequence: self.sequence,
            unit_id: self.unit_id,
            range: self.range.clone(),
        }
    }
}

/// Close the initial translated-range replay for one process-image epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedRangeReady {
    epoch: TranslatedRangeEpoch,
    final_sequence: u64,
}

impl TranslatedRangeReady {
    pub const fn ready(epoch: TranslatedRangeEpoch, final_sequence: u64) -> Self {
        Self {
            epoch,
            final_sequence,
        }
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }

    pub const fn final_sequence(&self) -> u64 {
        self.final_sequence
    }
}

fn validate_translated_range(range: &Range<HostVa>) -> Result<(), TranslatedRangeError> {
    let start = range.start.raw();
    let end = range.end.raw();
    if start == end {
        return Err(TranslatedRangeError::EmptyRange { address: start });
    }
    if start > end {
        return Err(TranslatedRangeError::ReversedRange { start, end });
    }
    if !start.is_multiple_of(4) || !end.is_multiple_of(4) {
        return Err(TranslatedRangeError::UnalignedRange { start, end });
    }
    Ok(())
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

dsr_ordinal_enum! {
    /// Typed reason a translated DSR run slice returned to Rust. Mirrors
    /// `carrick_observability::probes::DsrExitKind` exactly.
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
    /// Result of preparing a guest PC for translated execution. Mirrors
    /// `carrick_observability::probes::DsrPrepareOutcome` exactly.
    pub enum DsrPrepareOutcome {
        ResumeEntryHit = 1,
        BlockIndexHit = 2,
        Translated = 3,
        Failed = 4,
    }
}

dsr_ordinal_enum! {
    /// Stable diagnostic category for a DSR operation result. Mirrors
    /// `carrick_observability::probes::DsrOperationOutcome` exactly.
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
    /// Resolver family used for a translated control-flow exit. Mirrors
    /// `carrick_observability::probes::DsrResolveKind` exactly.
    pub enum DsrResolveKind {
        Direct = 1,
        Indirect = 2,
    }
}

dsr_ordinal_enum! {
    /// Low-cardinality DSR translation-cache event. Mirrors
    /// `carrick_observability::probes::DsrCacheEventKind` exactly.
    ///
    /// `LiveReadyHit` / `LiveWinnerPublish` name the container-lifetime LIVE
    /// arena's own serves and publications; `BlockHit` / `BlockPublish` mean
    /// the PRIVATE bump cache.
    ///
    /// `LiveCasLoss` is a lost block claim; `LiveValidationRefusal` is a
    /// record this process found and REFUSED (torn, unresolvable, or an
    /// unknown state); `LivePrivateFallback` is every other named reason the
    /// lane declined; `LiveStaleAbortRecovered` is an instruction abort in a
    /// revoked chunk that the exact classifier recovered privately. There is
    /// deliberately NO kind for the policy-off `Unconfigured` fallback: that
    /// is every authoritative miss on the shipped default, so a probe there
    /// would put a new call on the default translate path.
    pub enum DsrCacheEventKind {
        BlockHit = 1,
        BlockMiss = 2,
        TargetPublish = 3,
        Invalidate = 4,
        BlockPublish = 5,
        CapacityFailure = 6,
        DirectBindingEligible = 7,
        DirectBindingPublish = 8,
        DirectBindingCasLoss = 9,
        DirectBindingClear = 10,
        DirectBindingValidationFailure = 11,
        DirectBindingUnitLoaded = 12,
        LiveReadyHit = 13,
        LiveWinnerPublish = 14,
        LiveCasLoss = 15,
        LivePrivateFallback = 16,
        LiveValidationRefusal = 17,
        LiveStaleAbortRecovered = 18,
    }
}

/// One exact 64 KiB live-arena RX chunk this task protected `PROT_NONE`
/// because a guest write, `mprotect`, `munmap`, or remap changed its source
/// page (Task 7's revocation seam).
///
/// It deliberately carries NO thread identity: revocation runs on the memory
/// mutation seam, which has no guest thread in scope, and a fabricated `tid`
/// would put a sentinel into a real domain. The fields are private and
/// construction validates the extent, so a caller cannot publish an empty or
/// inverted revocation.
///
/// ```compile_fail
/// use carrick_dsr::probes::DsrLiveChunkRevocation;
/// use carrick_guest_mem::{GuestVa, HostVa};
///
/// let _ = DsrLiveChunkRevocation {
///     source_page: GuestVa(0x1000),
///     chunk_index: 0,
///     rx: HostVa(0x2000)..HostVa(0x3000),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsrLiveChunkRevocation {
    source_page: GuestVa,
    chunk_index: u32,
    rx: Range<HostVa>,
}

impl DsrLiveChunkRevocation {
    pub fn revoked(
        source_page: GuestVa,
        chunk_index: u32,
        rx: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&rx)?;
        Ok(Self {
            source_page,
            chunk_index,
            rx,
        })
    }

    pub const fn source_page(&self) -> GuestVa {
        self.source_page
    }

    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    pub const fn rx(&self) -> &Range<HostVa> {
        &self.rx
    }
}

dsr_ordinal_enum! {
    /// Process role for a DSR cache lifecycle boundary. Mirrors
    /// `carrick_observability::probes::DsrCacheRole` exactly.
    pub enum DsrCacheRole {
        Common = 0,
        Parent = 1,
        Child = 2,
    }
}

dsr_ordinal_enum! {
    /// Non-overlapping component of a DSR block translation. Mirrors
    /// `carrick_observability::probes::DsrTranslationSubphase` exactly.
    pub enum DsrTranslationSubphase {
        Decode = 1,
        Plan = 2,
        Emit = 3,
        PublicationIndex = 4,
        DuplicateWait = 5,
    }
}

dsr_ordinal_enum! {
    /// Host synchronization boundary whose kernel waits need a stable reason.
    /// Mirrors `carrick_observability::probes::DsrSynchronizationKind`
    /// exactly.
    pub enum DsrSynchronizationKind {
        GenerationTableWrite = 1,
        ProcessStateRead = 2,
        ProcessStateWrite = 3,
    }
}

/// Receiver for the probe families the DSR memory model and translator
/// orchestration fire. Argument lists are exactly the observability
/// functions' (`dsr_cache_lifecycle` / `dsr_exec_map_detail` /
/// `dsr_prepare_*` / `dsr_run_*` / `dsr_translate_*` / `dsr_resolve_*` /
/// `dsr_cache_event` / `dsr_cache_capacity`) with the mirrored enums
/// substituted.
pub trait DsrProbeSink: Send + Sync {
    fn translated_range_reset(&self, event: TranslatedRangeReset);

    fn translated_range_add(&self, event: TranslatedRangeAdd);

    fn translated_range_ready(&self, event: TranslatedRangeReady);

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

    fn dsr_prepare_begin(&self, tid: i32, guest_pc: u64);

    fn dsr_prepare_end(
        &self,
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        generation: u64,
        outcome: DsrPrepareOutcome,
    );

    fn dsr_run_begin(&self, tid: i32, guest_pc: u64, cache_pc: u64, generation: u64);

    fn dsr_run_end(&self, tid: i32, kind: DsrExitKind, guest_pc: u64, target_pc: u64, status: i32);

    fn dsr_translate_begin(&self, tid: i32, guest_pc: u64, generation: u64);

    fn dsr_translate_end(
        &self,
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        emitted_bytes: u64,
        outcome: DsrOperationOutcome,
    );

    fn dsr_translate_subphase_begin(
        &self,
        tid: i32,
        subphase: DsrTranslationSubphase,
        guest_pc: u64,
        generation: u64,
    );

    fn dsr_translate_subphase_end(
        &self,
        tid: i32,
        subphase: DsrTranslationSubphase,
        guest_pc: u64,
        generation: u64,
    );

    fn dsr_synchronization_begin(&self, kind: DsrSynchronizationKind);

    fn dsr_synchronization_end(&self, kind: DsrSynchronizationKind);

    fn dsr_resolve_begin(&self, tid: i32, kind: DsrResolveKind, source_pc: u64, target_pc: u64);

    fn dsr_resolve_end(
        &self,
        tid: i32,
        kind: DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
        outcome: DsrOperationOutcome,
    );

    fn dsr_cache_event(
        &self,
        tid: i32,
        kind: DsrCacheEventKind,
        guest_pc: u64,
        generation: u64,
        used_bytes: u64,
    );

    fn dsr_cache_capacity(&self, role: DsrCacheRole, capacity_bytes: u64);

    /// One live-arena RX chunk revoked `PROT_NONE` by this task.
    fn dsr_live_chunk_revoked(&self, event: DsrLiveChunkRevocation);

    /// Host-VA bounds of this process's JIT code cache, fired once at
    /// creation. This exists so a `dtrace` script can tell a JIT program
    /// counter from a host one WITHOUT unwinding: `ustack()` cannot walk
    /// translated frames (they use x29 as a guest register), and it fails by
    /// FABRICATING plausible stacks rather than erroring, so a profiler has to
    /// classify the PC before deciding to unwind at all.
    fn dsr_cache_bounds(&self, base: u64, end: u64);
}

static SINK: OnceLock<&'static dyn DsrProbeSink> = OnceLock::new();

/// Install the process-wide probe sink. Idempotent, first-install-wins: a
/// second call (any thread) leaves the first sink in place and returns
/// without error, so racing initializers cannot flip a live sink mid-run.
pub fn install_probe_sink(sink: &'static dyn DsrProbeSink) {
    let _ = SINK.set(sink);
}

/// Fire a translated-range catalog reset through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn translated_range_reset(event: TranslatedRangeReset) {
    if let Some(sink) = SINK.get() {
        sink.translated_range_reset(event);
    }
}

/// Fire one typed translated-range catalog addition through the installed
/// sink; no-op when no sink is installed.
#[inline(always)]
pub fn translated_range_add(event: TranslatedRangeAdd) {
    if let Some(sink) = SINK.get() {
        sink.translated_range_add(event);
    }
}

/// Fire the initial translated-range replay frontier through the installed
/// sink; no-op when no sink is installed.
#[inline(always)]
pub fn translated_range_ready(event: TranslatedRangeReady) {
    if let Some(sink) = SINK.get() {
        sink.translated_range_ready(event);
    }
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

/// Fire the `dsr__prepare__begin` probe through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn dsr_prepare_begin(tid: i32, guest_pc: u64) {
    if let Some(sink) = SINK.get() {
        sink.dsr_prepare_begin(tid, guest_pc);
    }
}

/// Fire the `dsr__prepare__end` probe through the installed sink; no-op when
/// no sink is installed.
#[inline(always)]
pub fn dsr_prepare_end(
    tid: i32,
    guest_pc: u64,
    cache_pc: u64,
    generation: u64,
    outcome: DsrPrepareOutcome,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_prepare_end(tid, guest_pc, cache_pc, generation, outcome);
    }
}

/// Fire the `dsr__run__begin` probe through the installed sink; no-op when
/// no sink is installed.
#[inline(always)]
pub fn dsr_run_begin(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64) {
    if let Some(sink) = SINK.get() {
        sink.dsr_run_begin(tid, guest_pc, cache_pc, generation);
    }
}

/// Fire the `dsr__run__end` probe through the installed sink; no-op when no
/// sink is installed.
#[inline(always)]
pub fn dsr_run_end(tid: i32, kind: DsrExitKind, guest_pc: u64, target_pc: u64, status: i32) {
    if let Some(sink) = SINK.get() {
        sink.dsr_run_end(tid, kind, guest_pc, target_pc, status);
    }
}

/// Fire the `dsr__translate__begin` probe through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn dsr_translate_begin(tid: i32, guest_pc: u64, generation: u64) {
    if let Some(sink) = SINK.get() {
        sink.dsr_translate_begin(tid, guest_pc, generation);
    }
}

/// Fire the `dsr__translate__end` probe through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn dsr_translate_end(
    tid: i32,
    guest_pc: u64,
    cache_pc: u64,
    emitted_bytes: u64,
    outcome: DsrOperationOutcome,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_translate_end(tid, guest_pc, cache_pc, emitted_bytes, outcome);
    }
}

/// Fire the `dsr__translate__subphase__begin` probe through the installed
/// sink; no-op when no sink is installed.
#[inline(always)]
pub fn dsr_translate_subphase_begin(
    tid: i32,
    subphase: DsrTranslationSubphase,
    guest_pc: u64,
    generation: u64,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_translate_subphase_begin(tid, subphase, guest_pc, generation);
    }
}

/// Fire the `dsr__translate__subphase__end` probe through the installed
/// sink; no-op when no sink is installed.
#[inline(always)]
pub fn dsr_translate_subphase_end(
    tid: i32,
    subphase: DsrTranslationSubphase,
    guest_pc: u64,
    generation: u64,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_translate_subphase_end(tid, subphase, guest_pc, generation);
    }
}

/// Fire the `dsr__synchronization__begin` probe through the installed sink;
/// no-op when no sink is installed.
#[inline(always)]
pub fn dsr_synchronization_begin(kind: DsrSynchronizationKind) {
    if let Some(sink) = SINK.get() {
        sink.dsr_synchronization_begin(kind);
    }
}

/// Fire the `dsr__synchronization__end` probe through the installed sink;
/// no-op when no sink is installed.
#[inline(always)]
pub fn dsr_synchronization_end(kind: DsrSynchronizationKind) {
    if let Some(sink) = SINK.get() {
        sink.dsr_synchronization_end(kind);
    }
}

/// Acquire one host synchronization primitive while bracketing only the
/// acquisition itself. Work performed under the returned guard is outside
/// the probe span, so a joined DTrace syscall is evidence of blocking during
/// acquisition rather than merely holding the lock.
#[inline(always)]
pub fn acquire_with_synchronization_reason<T>(
    kind: DsrSynchronizationKind,
    acquire: impl FnOnce() -> T,
) -> T {
    dsr_synchronization_begin(kind);
    let acquired = acquire();
    dsr_synchronization_end(kind);
    acquired
}

/// Fire the `dsr__resolve__begin` probe through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn dsr_resolve_begin(tid: i32, kind: DsrResolveKind, source_pc: u64, target_pc: u64) {
    if let Some(sink) = SINK.get() {
        sink.dsr_resolve_begin(tid, kind, source_pc, target_pc);
    }
}

/// Fire the `dsr__resolve__end` probe through the installed sink; no-op when
/// no sink is installed.
#[inline(always)]
pub fn dsr_resolve_end(
    tid: i32,
    kind: DsrResolveKind,
    source_pc: u64,
    target_pc: u64,
    outcome: DsrOperationOutcome,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_resolve_end(tid, kind, source_pc, target_pc, outcome);
    }
}

/// Fire the `dsr__cache__event` probe through the installed sink; no-op when
/// no sink is installed.
#[inline(always)]
pub fn dsr_cache_event(
    tid: i32,
    kind: DsrCacheEventKind,
    guest_pc: u64,
    generation: u64,
    used_bytes: u64,
) {
    if let Some(sink) = SINK.get() {
        sink.dsr_cache_event(tid, kind, guest_pc, generation, used_bytes);
    }
}

/// Fire the `dsr__cache__capacity` probe through the installed sink; no-op
/// when no sink is installed.
#[inline(always)]
pub fn dsr_cache_capacity(role: DsrCacheRole, capacity_bytes: u64) {
    if let Some(sink) = SINK.get() {
        sink.dsr_cache_capacity(role, capacity_bytes);
    }
}

/// Fire the `dsr__cache__bounds` probe through the installed sink; no-op when
/// no sink is installed.
#[inline(always)]
pub fn dsr_cache_bounds(base: u64, end: u64) {
    if let Some(sink) = SINK.get() {
        sink.dsr_cache_bounds(base, end);
    }
}

/// Fire the `dsr__live__chunk__revoked` probe through the installed sink;
/// no-op when no sink is installed.
#[inline(always)]
pub fn dsr_live_chunk_revoked(event: DsrLiveChunkRevocation) {
    if let Some(sink) = SINK.get() {
        sink.dsr_live_chunk_revoked(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_mem::HostVa;
    use std::ops::Range;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct CountingSink {
        translated_reset: AtomicU64,
        translated_add: AtomicU64,
        translated_ready: AtomicU64,
        lifecycle: AtomicU64,
        detail: AtomicU64,
        synchronization: AtomicU64,
        live_chunk_revoked: AtomicU64,
    }

    impl DsrProbeSink for CountingSink {
        fn translated_range_reset(&self, _event: TranslatedRangeReset) {
            self.translated_reset.fetch_add(1, Ordering::Relaxed);
        }

        fn translated_range_add(&self, _event: TranslatedRangeAdd) {
            self.translated_add.fetch_add(1, Ordering::Relaxed);
        }

        fn translated_range_ready(&self, _event: TranslatedRangeReady) {
            self.translated_ready.fetch_add(1, Ordering::Relaxed);
        }

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

        fn dsr_prepare_begin(&self, _tid: i32, _guest_pc: u64) {}

        fn dsr_prepare_end(
            &self,
            _tid: i32,
            _guest_pc: u64,
            _cache_pc: u64,
            _generation: u64,
            _outcome: DsrPrepareOutcome,
        ) {
        }

        fn dsr_run_begin(&self, _tid: i32, _guest_pc: u64, _cache_pc: u64, _generation: u64) {}

        fn dsr_run_end(
            &self,
            _tid: i32,
            _kind: DsrExitKind,
            _guest_pc: u64,
            _target_pc: u64,
            _status: i32,
        ) {
        }

        fn dsr_translate_begin(&self, _tid: i32, _guest_pc: u64, _generation: u64) {}

        fn dsr_translate_end(
            &self,
            _tid: i32,
            _guest_pc: u64,
            _cache_pc: u64,
            _emitted_bytes: u64,
            _outcome: DsrOperationOutcome,
        ) {
        }

        fn dsr_translate_subphase_begin(
            &self,
            _tid: i32,
            _subphase: DsrTranslationSubphase,
            _guest_pc: u64,
            _generation: u64,
        ) {
        }

        fn dsr_translate_subphase_end(
            &self,
            _tid: i32,
            _subphase: DsrTranslationSubphase,
            _guest_pc: u64,
            _generation: u64,
        ) {
        }

        fn dsr_resolve_begin(
            &self,
            _tid: i32,
            _kind: DsrResolveKind,
            _source_pc: u64,
            _target_pc: u64,
        ) {
        }

        fn dsr_resolve_end(
            &self,
            _tid: i32,
            _kind: DsrResolveKind,
            _source_pc: u64,
            _target_pc: u64,
            _outcome: DsrOperationOutcome,
        ) {
        }

        fn dsr_cache_event(
            &self,
            _tid: i32,
            _kind: DsrCacheEventKind,
            _guest_pc: u64,
            _generation: u64,
            _used_bytes: u64,
        ) {
        }

        fn dsr_cache_capacity(&self, _role: DsrCacheRole, _capacity_bytes: u64) {}

        fn dsr_cache_bounds(&self, _base: u64, _end: u64) {}

        fn dsr_live_chunk_revoked(&self, _event: DsrLiveChunkRevocation) {
            self.live_chunk_revoked.fetch_add(1, Ordering::Relaxed);
        }

        fn dsr_synchronization_begin(&self, _kind: DsrSynchronizationKind) {
            self.synchronization.fetch_add(1, Ordering::Relaxed);
        }

        fn dsr_synchronization_end(&self, _kind: DsrSynchronizationKind) {
            self.synchronization.fetch_add(1, Ordering::Relaxed);
        }
    }

    // One test on purpose: the sink is a process-global OnceLock, so the
    // uninstalled no-op, the first install, and the ignored second install
    // must be exercised in a fixed order within a single test.
    #[test]
    fn uninstalled_is_noop_then_first_install_wins() {
        static FIRST: CountingSink = CountingSink {
            translated_reset: AtomicU64::new(0),
            translated_add: AtomicU64::new(0),
            translated_ready: AtomicU64::new(0),
            lifecycle: AtomicU64::new(0),
            detail: AtomicU64::new(0),
            synchronization: AtomicU64::new(0),
            live_chunk_revoked: AtomicU64::new(0),
        };
        static SECOND: CountingSink = CountingSink {
            translated_reset: AtomicU64::new(0),
            translated_add: AtomicU64::new(0),
            translated_ready: AtomicU64::new(0),
            lifecycle: AtomicU64::new(0),
            detail: AtomicU64::new(0),
            synchronization: AtomicU64::new(0),
            live_chunk_revoked: AtomicU64::new(0),
        };

        // No sink installed: helpers must be a silent no-op.
        let translated_epoch = TranslatedRangeEpoch::new(1)
            .unwrap_or_else(|error| unreachable!("valid translated epoch: {error}"));
        let translated_sequence = TranslatedRangeSequence::new(1)
            .unwrap_or_else(|error| unreachable!("valid translated sequence: {error}"));
        let translated_private = TranslatedPrivateRange::private(
            translated_epoch,
            translated_sequence,
            HostVa(0x1000)..HostVa(0x2000),
        )
        .unwrap_or_else(|error| unreachable!("valid translated private range: {error}"));
        translated_range_reset(TranslatedRangeReset::reset(translated_epoch));
        translated_range_add(TranslatedRangeAdd::Private(translated_private.clone()));
        translated_range_ready(TranslatedRangeReady::ready(translated_epoch, 1));
        dsr_cache_lifecycle(1, DsrCacheLifecyclePhase::ExecImageMapBegin, 0, 0, 0);
        dsr_exec_map_detail(1, DsrExecMapDetailKind::Mmap, 0, 0, 0);
        assert_eq!(FIRST.translated_reset.load(Ordering::Relaxed), 0);
        assert_eq!(FIRST.translated_add.load(Ordering::Relaxed), 0);
        assert_eq!(FIRST.translated_ready.load(Ordering::Relaxed), 0);
        assert_eq!(FIRST.lifecycle.load(Ordering::Relaxed), 0);
        assert_eq!(FIRST.detail.load(Ordering::Relaxed), 0);

        install_probe_sink(&FIRST);
        translated_range_reset(TranslatedRangeReset::reset(translated_epoch));
        translated_range_add(TranslatedRangeAdd::Private(translated_private));
        translated_range_ready(TranslatedRangeReady::ready(translated_epoch, 1));
        dsr_cache_lifecycle(1, DsrCacheLifecyclePhase::ExecImageMapEnd, 1, 2, 3);
        dsr_exec_map_detail(1, DsrExecMapDetailKind::Copy, 4, 5, 6);
        let generations =
            crate::cache::PageGenerationTable::new(16 * 1024).expect("valid generation table");
        generations
            .observe(carrick_guest_mem::GuestVa(0x1_0000))
            .expect("generation observation");
        assert_eq!(FIRST.translated_reset.load(Ordering::Relaxed), 1);
        assert_eq!(FIRST.translated_add.load(Ordering::Relaxed), 1);
        assert_eq!(FIRST.translated_ready.load(Ordering::Relaxed), 1);
        assert_eq!(FIRST.lifecycle.load(Ordering::Relaxed), 1);
        assert_eq!(FIRST.detail.load(Ordering::Relaxed), 1);
        assert_eq!(FIRST.synchronization.load(Ordering::Relaxed), 2);

        // Second install is ignored (first-install-wins) and does not error.
        install_probe_sink(&SECOND);
        dsr_cache_lifecycle(1, DsrCacheLifecyclePhase::ExecCacheResetBegin, 0, 0, 0);
        assert_eq!(FIRST.lifecycle.load(Ordering::Relaxed), 2);
        assert_eq!(SECOND.translated_reset.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND.translated_add.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND.translated_ready.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND.lifecycle.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND.detail.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND.synchronization.load(Ordering::Relaxed), 0);
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
        for (index, kind) in DsrExitKind::ALL.iter().enumerate() {
            assert_eq!(kind.raw() as usize, index + 1);
        }
        for (index, outcome) in DsrPrepareOutcome::ALL.iter().enumerate() {
            assert_eq!(outcome.raw() as usize, index + 1);
        }
        for (index, kind) in DsrResolveKind::ALL.iter().enumerate() {
            assert_eq!(kind.raw() as usize, index + 1);
        }
        for (index, kind) in DsrCacheEventKind::ALL.iter().enumerate() {
            assert_eq!(kind.raw() as usize, index + 1);
        }
        assert_eq!(DsrCacheEventKind::DirectBindingEligible.raw(), 7);
        assert_eq!(DsrCacheEventKind::DirectBindingPublish.raw(), 8);
        assert_eq!(DsrCacheEventKind::DirectBindingCasLoss.raw(), 9);
        assert_eq!(DsrCacheEventKind::DirectBindingClear.raw(), 10);
        assert_eq!(DsrCacheEventKind::DirectBindingValidationFailure.raw(), 11);
        assert_eq!(DsrCacheEventKind::DirectBindingUnitLoaded.raw(), 12);
        assert_eq!(DsrCacheEventKind::LiveReadyHit.raw(), 13);
        assert_eq!(DsrCacheEventKind::LiveWinnerPublish.raw(), 14);
        assert_eq!(DsrCacheEventKind::LiveCasLoss.raw(), 15);
        assert_eq!(DsrCacheEventKind::LivePrivateFallback.raw(), 16);
        assert_eq!(DsrCacheEventKind::LiveValidationRefusal.raw(), 17);
        assert_eq!(DsrCacheEventKind::LiveStaleAbortRecovered.raw(), 18);
        for (index, subphase) in DsrTranslationSubphase::ALL.iter().enumerate() {
            assert_eq!(subphase.raw() as usize, index + 1);
        }
        for (index, kind) in DsrSynchronizationKind::ALL.iter().enumerate() {
            assert_eq!(kind.raw() as usize, index + 1);
        }
        // These two families start at zero (`Success` / `Common` are ordinal
        // 0 in the observability originals).
        for (index, outcome) in DsrOperationOutcome::ALL.iter().enumerate() {
            assert_eq!(outcome.raw() as usize, index);
        }
        for (index, role) in DsrCacheRole::ALL.iter().enumerate() {
            assert_eq!(role.raw() as usize, index);
        }
    }

    fn translated_epoch(value: u64) -> TranslatedRangeEpoch {
        TranslatedRangeEpoch::new(value).unwrap_or_else(|error| {
            unreachable!("nonzero test epoch must be valid: {error}");
        })
    }

    fn translated_sequence(value: u64) -> TranslatedRangeSequence {
        TranslatedRangeSequence::new(value).unwrap_or_else(|error| {
            unreachable!("nonzero test sequence must be valid: {error}");
        })
    }

    fn translated_unit_id(value: u64) -> TranslatedUnitId {
        TranslatedUnitId::new(value).unwrap_or_else(|error| {
            unreachable!("nonzero test unit identity must be valid: {error}");
        })
    }

    #[test]
    fn translated_range_domain_rejects_zero_identity_and_malformed_extents() {
        assert!(matches!(
            TranslatedRangeEpoch::new(0),
            Err(TranslatedRangeError::ZeroEpoch)
        ));
        assert!(matches!(
            TranslatedRangeSequence::new(0),
            Err(TranslatedRangeError::ZeroSequence)
        ));
        assert!(matches!(
            TranslatedUnitId::new(0),
            Err(TranslatedRangeError::ZeroUnitId)
        ));

        for range in [
            HostVa(0x1000)..HostVa(0x1000),
            HostVa(0x2000)..HostVa(0x1000),
            HostVa(0x1001)..HostVa(0x2000),
            HostVa(0x1000)..HostVa(0x2002),
        ] {
            assert!(
                TranslatedPrivateRange::private(
                    translated_epoch(1),
                    translated_sequence(1),
                    range.clone()
                )
                .is_err(),
                "malformed private executable extent must be rejected"
            );
            assert!(
                TranslatedSharedRange::shared(
                    translated_epoch(1),
                    translated_sequence(1),
                    translated_unit_id(1),
                    range
                )
                .is_err(),
                "malformed shared executable extent must be rejected"
            );
        }
    }

    #[test]
    fn translated_range_domain_has_typed_constructor_and_fire_shapes() {
        let _: fn(
            TranslatedRangeEpoch,
            TranslatedRangeSequence,
            Range<HostVa>,
        ) -> Result<TranslatedPrivateRange, TranslatedRangeError> = TranslatedPrivateRange::private;
        let _: fn(
            TranslatedRangeEpoch,
            TranslatedRangeSequence,
            TranslatedUnitId,
            Range<HostVa>,
        ) -> Result<TranslatedSharedRange, TranslatedRangeError> = TranslatedSharedRange::shared;
        let _: fn(TranslatedRangeReset) = translated_range_reset;
        let _: fn(TranslatedRangeAdd) = translated_range_add;
        let _: fn(TranslatedRangeReady) = translated_range_ready;

        let private = TranslatedPrivateRange::private(
            translated_epoch(2),
            translated_sequence(3),
            HostVa(0x1000)..HostVa(0x2000),
        )
        .unwrap_or_else(|error| unreachable!("valid private range: {error}"));
        let shared = TranslatedSharedRange::shared(
            translated_epoch(2),
            translated_sequence(4),
            translated_unit_id(5),
            HostVa(0x3000)..HostVa(0x4000),
        )
        .unwrap_or_else(|error| unreachable!("valid shared range: {error}"));

        assert_eq!(
            TranslatedRangeAdd::Private(private.clone()).kind(),
            TranslatedRangeKind::PrivateProcessCache
        );
        assert_eq!(
            TranslatedRangeAdd::Shared(shared.clone()).kind(),
            TranslatedRangeKind::SharedUnit
        );
        assert_eq!(translated_epoch(7).get(), 7);
        assert_eq!(translated_sequence(11).get(), 11);
        assert_eq!(translated_unit_id(13).get(), 13);
        assert_eq!(private.range(), &(HostVa(0x1000)..HostVa(0x2000)));
        assert_eq!(shared.unit_id(), translated_unit_id(5));
    }

    #[test]
    fn translated_range_kind_ordinals_are_stable_and_unique() {
        assert_eq!(TranslatedRangeKind::PrivateProcessCache.raw(), 1);
        assert_eq!(TranslatedRangeKind::SharedUnit.raw(), 2);
        let mut ordinals = TranslatedRangeKind::ALL
            .map(TranslatedRangeKind::raw)
            .to_vec();
        ordinals.sort_unstable();
        ordinals.dedup();
        assert_eq!(ordinals.len(), TranslatedRangeKind::ALL.len());
    }
}
