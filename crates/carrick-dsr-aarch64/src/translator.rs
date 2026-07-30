//! AArch64 DSR translator orchestration: `ProcessTranslator` /
//! `ThreadTranslator`, block publication + direct-link resolution
//! (`encode_aarch64_direct_branch`), the resolver-stat census, the
//! sibling-profile exactly-once registry, and the typed exit dispatch
//! (`ThreadExit` / `finish_exit_profiled`).
//!
//! Moved verbatim from `carrick-runtime/src/native_darwin/dsr/mod.rs` as the
//! extraction-completing slice of
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md.
//! Deliberate seam changes (everything else is a pure move):
//! * probes fire through `carrick_dsr::probes` (the usdt-free sink seam)
//!   instead of `carrick-observability`; the `probe_fields`/`probe_outcome`
//!   projections moved here with their only consumers, retargeted onto the
//!   mirrored enums.
//! * the host JIT arrives through the installed-global `install_host_jit`
//!   seam (the process-global shape `darwin_jit::active_host_jit()` already
//!   had); the runtime installs its Darwin impl at every backend entry.
//! * the sibling registry records the portable
//!   `carrick_host::host_proc::ThreadPort` (the mach port on Darwin).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};

use carrick_dsr::probes;
use parking_lot::{Mutex, RwLock};

use crate::emit::{recover_rewrite_state, recovery_resume_pc};
use crate::mapped_memory::NativeMappedMemory;
use crate::snapshot::NativeUcontextSnapshot;
use crate::{artifact_spike, block, emit, gateway, types};
use carrick_dsr::host::NativeHostJit;

/// Projection of a [`types::NativeDsrExit`] onto the probe tuple, retargeted
/// onto `carrick_dsr::probes`' mirrored `DsrExitKind` when the translator
/// orchestration (its only consumer) moved into this crate. Verbatim mapping
/// of the pre-extraction `NativeDsrExit::probe_fields`.
pub trait NativeDsrExitProbeExt {
    fn probe_fields(self) -> (probes::DsrExitKind, u64, u64, i32);
}

impl NativeDsrExitProbeExt for types::NativeDsrExit {
    fn probe_fields(self) -> (probes::DsrExitKind, u64, u64, i32) {
        use probes::DsrExitKind;

        match self {
            Self::Syscall { resume } => (DsrExitKind::Syscall, resume.raw(), 0, 1),
            Self::ResolveDirect {
                source,
                target,
                binding: _,
            } => (DsrExitKind::DirectResolver, source.raw(), target.raw(), 2),
            Self::ResolveIndirect { source, target, .. } => {
                (DsrExitKind::IndirectResolver, source.raw(), target.raw(), 3)
            }
            Self::Fault {
                guest_pc, address, ..
            } => (DsrExitKind::Fault, guest_pc.raw(), address.raw() as u64, 4),
            Self::Kick { resume, .. } => (DsrExitKind::Kick, resume.raw(), 0, 5),
            Self::Sensitive {
                guest_pc, resume, ..
            } => (DsrExitKind::Sensitive, guest_pc.raw(), resume.raw(), 6),
            Self::Unsupported { guest_pc, .. } => (DsrExitKind::Unsupported, guest_pc.raw(), 0, 7),
            Self::KickAtEntry { resume } => (DsrExitKind::Kick, resume.raw(), 0, 8),
            Self::StaleGeneration { guest_pc, .. } => (
                DsrExitKind::DirectResolver,
                guest_pc.raw(),
                guest_pc.raw(),
                2,
            ),
        }
    }
}

/// Projection of a [`types::DsrError`] onto the probe operation-outcome
/// ordinal, retargeted onto `carrick_dsr::probes`' mirrored
/// `DsrOperationOutcome` (see [`NativeDsrExitProbeExt`]). Verbatim mapping of
/// the pre-extraction `DsrError::probe_outcome`.
pub trait DsrErrorProbeExt {
    fn probe_outcome(&self) -> probes::DsrOperationOutcome;
}

impl DsrErrorProbeExt for types::DsrError {
    fn probe_outcome(&self) -> probes::DsrOperationOutcome {
        use probes::DsrOperationOutcome;

        match self {
            Self::Profile(_) => DsrOperationOutcome::CachePolicy,
            Self::PcOverflow { .. } => DsrOperationOutcome::PcOverflow,
            Self::Decode { .. } => DsrOperationOutcome::Decode,
            Self::Malformed { .. } => DsrOperationOutcome::Malformed,
            Self::BlockPolicy(_) => DsrOperationOutcome::BlockPolicy,
            Self::MemoryRead { .. } => DsrOperationOutcome::MemoryRead,
            Self::UnsupportedBlockAction { .. } => DsrOperationOutcome::UnsupportedBlockAction,
            Self::Assembler(_) => DsrOperationOutcome::Assembler,
            Self::Gateway(_) => DsrOperationOutcome::Gateway,
            Self::CachePolicy(_) => DsrOperationOutcome::CachePolicy,
            Self::CacheCapacity { .. } => DsrOperationOutcome::CacheCapacity,
            Self::GenerationChanged { .. } => DsrOperationOutcome::GenerationChanged,
            Self::Host { .. } => DsrOperationOutcome::Host,
        }
    }
}
use carrick_dsr::{cache, profile};

/// Process-global host W^X JIT seam. The translator machinery (and
/// `NativeMappedMemory`'s internal `ProcessTranslator` construction) reaches
/// the host JIT through this registry exactly the way the pre-extraction
/// code reached `darwin_jit::active_host_jit()` -- a process-global lookup --
/// so `ProcessTranslator::new(capacity)` keeps its signature. The runtime
/// installs its Darwin impl at every native-backend entry point (alongside
/// the probe sink); tests install a plain-mmap test JIT. First-install-wins,
/// idempotent, mirroring `carrick_dsr::probes::install_probe_sink`.
static HOST_JIT: OnceLock<&'static dyn NativeHostJit> = OnceLock::new();

/// Install the process-wide host JIT. Idempotent, first-install-wins.
pub fn install_host_jit(jit: &'static dyn NativeHostJit) {
    let _ = HOST_JIT.set(jit);
}

/// The installed host JIT if any -- the memory model's icache helper
/// treats "none installed" as a no-op (pure-mapping test configuration).
pub(crate) fn installed_host_jit() -> Option<&'static dyn NativeHostJit> {
    HOST_JIT.get().copied()
}

/// The installed host JIT, or a typed `DsrError::Host` if the runtime (or a
/// test harness) has not installed one -- translation fails closed rather
/// than picking a platform default this ISA crate cannot know.
fn active_host_jit() -> Result<&'static dyn NativeHostJit, types::DsrError> {
    HOST_JIT
        .get()
        .copied()
        .ok_or_else(|| types::DsrError::Host {
            operation: "native host JIT seam",
            error: std::io::Error::other(
                "no host JIT installed (install_host_jit was never called)",
            ),
        })
}
const ARTIFACT_KEY_PREFIX_INSTRUCTIONS: usize = 16;

pub fn shared_translation_runtime_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DSR_SHARED_TRANSLATION").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    })
}

/// Encode the AArch64 `B` instruction that links `site` to `target`.
///
/// The guest-ISA half of the pre-extraction `patch_direct_branch`: the
/// extracted cache (`carrick_dsr::cache`) is ISA-neutral and only patches
/// fully encoded words via `TranslationCache::patch_code_word`, so the
/// displacement computation, `B`-range check, and opcode encoding stay here
/// with the rest of the AArch64 layer.
pub fn encode_aarch64_direct_branch(
    site: cache::LinkSite,
    target: types::CacheVa,
) -> Result<u32, types::DsrError> {
    let source = site
        .source
        .host()
        .raw()
        .checked_add(site.slot.get() as usize)
        .ok_or_else(|| types::DsrError::CachePolicy("direct-link source overflow".to_string()))?;
    if !source.is_multiple_of(4) {
        return Err(types::DsrError::CachePolicy(format!(
            "direct-link source is not instruction aligned: 0x{source:x}"
        )));
    }
    let displacement = (target.host().raw() as i128) - (source as i128);
    if displacement % 4 != 0 {
        return Err(types::DsrError::CachePolicy(format!(
            "direct-link displacement is not instruction aligned: {displacement}"
        )));
    }
    let words = displacement / 4;
    if !(-(1_i128 << 25)..(1_i128 << 25)).contains(&words) {
        return Err(types::DsrError::CachePolicy(format!(
            "direct-link target is outside AArch64 B range: {displacement} bytes"
        )));
    }
    Ok(0x1400_0000 | ((words as i64 as u32) & 0x03ff_ffff))
}

#[derive(Debug)]
pub enum ThreadExit {
    Syscall {
        resume: carrick_guest_mem::GuestVa,
    },
    Continue,
    Sensitive(types::SensitiveExit),
    Fault {
        kind: ThreadFault,
        address: ThreadFaultAddress,
    },
    Kick,
    Unsupported(String),
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectBindingResetEvent {
    CellsCleared,
    ThreadCachesCleared,
    IndexesCleared,
    DescriptorsDropped,
    ExecutableRangeHeadReset,
    UnitsDropped,
    ExecutableRangeNodesDropped,
    PrivateCursorReset,
}

#[derive(Debug)]
struct DirectBindingExecProcessIdentity;

#[derive(Debug)]
struct DirectBindingExecThreadIdentity;

/// Single-use authority to clear one retiring process translator for exec.
///
/// The fields are deliberately private: only the surviving thread's
/// [`ThreadTranslator::prepare_direct_binding_exec_reset`] can mint this
/// capability after clearing its local translated-resume state.
#[doc(hidden)]
pub struct DirectBindingExecResetToken {
    process_identity: Arc<DirectBindingExecProcessIdentity>,
    thread_identity: Arc<DirectBindingExecThreadIdentity>,
    thread_epoch: u64,
    consumed: bool,
}

impl DirectBindingExecResetToken {
    pub(crate) fn validate_for(
        &self,
        process: &ProcessTranslator,
        thread: &ThreadTranslator,
    ) -> Result<(), types::DsrError> {
        if self.consumed {
            return Err(types::DsrError::CachePolicy(
                "direct-binding exec reset token was already consumed".to_string(),
            ));
        }
        if !Arc::ptr_eq(&self.process_identity, &process.exec_reset_identity)
            || !Arc::ptr_eq(
                &thread.process.exec_reset_identity,
                &process.exec_reset_identity,
            )
        {
            return Err(types::DsrError::CachePolicy(
                "direct-binding exec reset token belongs to another process".to_string(),
            ));
        }
        if !Arc::ptr_eq(&self.thread_identity, &thread.exec_reset_identity) {
            return Err(types::DsrError::CachePolicy(
                "direct-binding exec reset token belongs to another thread".to_string(),
            ));
        }
        if self.thread_epoch != thread.exec_reset_epoch {
            return Err(types::DsrError::CachePolicy(
                "direct-binding exec reset token is stale".to_string(),
            ));
        }
        Ok(())
    }

    fn consume_for(
        &mut self,
        process: &ProcessTranslator,
        thread: &ThreadTranslator,
    ) -> Result<(), types::DsrError> {
        self.validate_for(process, thread)?;
        self.consumed = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ThreadFault {
    Host { signal: i32, code: i32 },
    Guest { signum: i32, code: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadFaultAddress {
    Host(carrick_guest_mem::HostVa),
    Guest(carrick_guest_mem::GuestVa),
}

impl ThreadFaultAddress {
    pub fn raw(self) -> u64 {
        match self {
            Self::Host(address) => address.raw() as u64,
            Self::Guest(address) => address.raw(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct PreparedEntry {
    // `pub` for the runtime's still-resident test suites and oracle.
    pub entry: types::CacheVa,
    pub generation: types::CodeGeneration,
    cache_start: usize,
    cache_end: usize,
    address_mode: carrick_dsr::address::NativeAddressMode,
    generation_bindings: usize,
    generation_binding_count: usize,
    executable_range_catalog: *const gateway::ExecutableRangeCatalogHeader,
}

pub struct PreparedExit {
    // `pub` for the runtime's still-resident oracle.
    pub exit: types::NativeDsrExit,
}

impl PreparedExit {
    pub const fn profile_class(&self) -> profile::ExitClass {
        self.exit.profile_class()
    }
}

/// Per-thread block cache: the read-side fast path in front of the process-wide
/// block index.
///
/// This generalizes a ONE-entry `resume_entry`. A single slot hit often enough on
/// straight-line resumption to be worth keeping, but any control flow alternating
/// between more than one hot block thrashed it, and EVERY miss then took
/// `ProcessState`'s `RwLock`. Profiling measured
/// `parking_lot::RawRwLock::lock_shared_slow` as the single largest leaf at 8.2%
/// of all on-CPU time -- reached from `translate_read_mostly`, which every
/// gateway exit calls (`docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`,
/// run 8).
///
/// **Invalidation contract, unchanged from the single slot it replaces.** Both
/// paths that remove blocks stay covered:
///
/// * PER-PAGE invalidation (`ProcessState::translate`'s `blocks.remove(&stale)`)
///   ADVANCES that page's generation. Entries are keyed `(guest, generation)` and
///   the generation is re-observed on every lookup, so a stale entry simply stops
///   matching. Nothing to do.
/// * WHOLE-INDEX resets (`blocks.clear()` plus `cache.reset_after_fork_for_exec()`
///   on fork-child adoption and exec) move no generation, so they must clear this
///   cache explicitly. They do, at exactly the three points that cleared
///   `resume_entry`.
///
/// Direct-mapped rather than associative: the lookup has to be cheaper than the
/// lock it avoids, and a single indexed slot compare is. A colliding pair of hot
/// blocks degrades to the old one-entry behaviour, never to anything worse.
struct ThreadBlockCache {
    slots: Box<
        [Option<(
            carrick_guest_mem::GuestVa,
            types::CodeGeneration,
            types::CacheVa,
        )>],
    >,
}

impl ThreadBlockCache {
    /// 1024 slots is ~24 KiB per thread, and the whole array is cleared only on
    /// fork/exec.
    const SLOTS: usize = 1024;
    const SHIFT: u32 = 64 - Self::SLOTS.trailing_zeros();

    fn new() -> Self {
        Self {
            slots: vec![None; Self::SLOTS].into_boxed_slice(),
        }
    }

    /// Fibonacci hash of the word-aligned guest VA. Block entries are 4-byte
    /// aligned, so the low two bits carry no information.
    #[inline]
    fn index(guest: carrick_guest_mem::GuestVa) -> usize {
        let mixed = (guest.raw() >> 2).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (mixed >> Self::SHIFT) as usize
    }

    #[inline]
    fn get(
        &self,
        guest: carrick_guest_mem::GuestVa,
    ) -> Option<(types::CodeGeneration, types::CacheVa)> {
        match self.slots[Self::index(guest)] {
            Some((cached, generation, entry)) if cached == guest => Some((generation, entry)),
            _ => None,
        }
    }

    #[inline]
    fn insert(
        &mut self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
        entry: types::CacheVa,
    ) {
        self.slots[Self::index(guest)] = Some((guest, generation, entry));
    }

    fn clear(&mut self) {
        self.slots.fill(None);
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

pub struct ThreadTranslator {
    // Fields are `pub` + doc(hidden)-by-convention: the runtime's
    // still-resident, JIT-entangled test suites (and the oracle) reach into
    // them until the host-seam slice moves those tests too.
    pub process: Arc<ProcessTranslator>,
    pub tid: i32,
    block_cache: ThreadBlockCache,
    /// Distinct `(source, target)` private -> shared edges this thread has
    /// resolved, under profiling only. 135.7M such exits is meaningless until it
    /// is divided by the number of edges producing them: a small set traversed
    /// many times each is a binding problem with a bounded fix, whereas a set as
    /// large as the exit count would mean the edges are genuinely one-shot.
    profiled_private_to_shared_edges: std::collections::HashSet<(u64, u64)>,
    /// The same for private -> private edges. This is the CONTROL: if those are
    /// also traversed many times each yet resolve rarely, a binding mechanism
    /// already exists and the fix is to extend it to shared targets. If instead
    /// they are one-shot (distinct ~= exits), no such mechanism exists and the
    /// asymmetry is simply that shared units concentrate the HOT code.
    profiled_private_to_private_edges: std::collections::HashSet<(u64, u64)>,
    /// Last `cache.used_bytes()` seen under the lock. The per-thread fast path
    /// reports this rather than taking the lock for a diagnostic gauge.
    last_cache_used_bytes: u64,
    pub stats: ResolverStats,
    pub budget: profile::ThreadBudget,
    profile_finalized: bool,
    pub nested_translation_ns: u64,
    last_kick: Option<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>)>,
    indirect_cache: gateway::IndirectTargetCache,
    exec_reset_identity: Arc<DirectBindingExecThreadIdentity>,
    exec_reset_epoch: u64,
}

/// One process's published JIT code plus its guest-to-cache block index,
/// copied out for offline diagnostics (see `ProcessTranslator::code_snapshot`).
pub struct CodeSnapshot {
    pub cache_base: u64,
    pub code: Vec<u8>,
    /// `(guest_va, cache_entry_host_va)` for every published private block.
    pub blocks: Vec<(u64, u64)>,
}

pub struct ProcessTranslator {
    // `pub` for the runtime's still-resident test suites (see ThreadTranslator).
    pub state: RwLock<ProcessState>,
    private_target_authority: Box<gateway::TargetCacheAuthority>,
    private_jit_epoch: Arc<crate::direct_binding::PrivateJitEpoch>,
    exec_reset_identity: Arc<DirectBindingExecProcessIdentity>,
}

impl Drop for ProcessTranslator {
    fn drop(&mut self) {
        if std::env::var_os("CARRICK_DSR_ARTIFACT_REPORT").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        if let Some(store) = &self.state.get_mut().artifact_store {
            let snapshot = store.snapshot();
            eprintln!(
                "CARRICK_ARTIFACT pid={} lookups={} cross_process_hits={} inserts={} replay_ns={} sealed={}",
                unsafe { libc::getpid() },
                snapshot.lookups,
                snapshot.hits,
                snapshot.inserts,
                snapshot.replay_ns,
                snapshot.sealed,
            );
        }
    }
}

pub struct ProcessState {
    pub cache: cache::TranslationCache,
    pub artifact_store: Option<artifact_spike::ArtifactStore>,
    pub blocks: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::CacheVa>,
    pub pending:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), Vec<cache::LinkSite>>,
    pub stats: ResolverStats,
    pub reported_stats: ResolverStats,
    pub sensitive: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), SensitiveMetadata>,
    pub exclusive_fusion_sites: [BTreeSet<(u64, u32)>; profile::ExclusiveFusionClass::COUNT],
    pub unsupported:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), (u32, bad64::Op)>,
    pub published: Vec<PublishedBlock>,
    /// `published` indices for blocks emitted into the private bump-allocated
    /// code cache, ascending by cache entry address.
    private_published_index: Vec<PublishedIndexEntry>,
    /// `published` indices for blocks mapped from shared translation units,
    /// ascending by cache entry address. Kept apart from the private index
    /// because a unit's own mapping can sit anywhere relative to the private
    /// cursor -- see [`ProcessState::push_published`].
    shared_published_index: Vec<PublishedIndexEntry>,
    pub dependencies: cache::PageBlockDependencies,
    pub profiling: bool,
    artifact_image_digest: Option<[u8; 32]>,
    shared_translation: Option<SharedTranslationConfiguration>,
    shared_blocks:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), SharedBlockAuthority>,
    /// Guest `[start, end)` of every block mapped from a loaded shared unit,
    /// sorted and non-overlapping, for classifying a guest PC as shared or
    /// private.
    ///
    /// `shared_blocks` is keyed by block START, which answers "is this PC a
    /// shared block's ENTRY" -- not "is this PC inside shared code". Those differ
    /// for every PC that is not an entry, and `PlannedExit::Direct` carries the
    /// BRANCHING instruction's PC, which is an entry only for a one-instruction
    /// block. Classifying exits with the start-keyed map is exactly what produced
    /// the retracted `shared_source=178` reading in
    /// `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md` run 6.
    shared_guest_ranges: Vec<(carrick_guest_mem::GuestVa, carrick_guest_mem::GuestVa)>,
    loaded_shared_units: Vec<LoadedSharedUnit>,
    shared_unit_segments_consulted: BTreeSet<carrick_guest_mem::GuestVa>,
    shared_recording_segments: BTreeSet<carrick_guest_mem::GuestVa>,
    shared_candidates:
        BTreeMap<carrick_guest_mem::GuestVa, Vec<crate::shared_cache::PortableBlockCandidate>>,
    shared_publish_attempted: bool,
    direct_bindings: crate::direct_binding::DirectBindingRegistry,
    executable_ranges: gateway::ExecutableRangeCatalog,
    /// Guest blocks one emitted block may fuse (1 = no superblock formation).
    /// Resolved once from `block::superblock_segment_limit()`; the only site
    /// that reads the switch, so planner and emitter tests stay deterministic.
    superblock_segments: usize,
}

struct SharedTranslationConfiguration {
    image: crate::shared_cache::SharedImageConfig,
    store: Arc<dyn crate::shared_cache::TranslationUnitStore>,
}

#[derive(Clone, Copy)]
struct SharedBlockAuthority {
    generation_bindings: usize,
    generation_binding_count: usize,
    cache_start: usize,
    cache_end: usize,
    target_authority: usize,
    loaded_unit_index: usize,
}

impl SharedBlockAuthority {
    fn owns(self, entry: types::CacheVa) -> bool {
        let address = entry.host().raw();
        (self.cache_start..self.cache_end).contains(&address)
    }
}

struct LoadedSharedUnit {
    _unit: crate::shared_cache::SharedLoadedTranslationUnit,
    _generation_bindings: Box<[gateway::GenerationBinding]>,
    _target_authority: Box<gateway::TargetCacheAuthority>,
    _direct_binding_unit_index: Option<usize>,
}

const fn translation_source_words_required(
    artifact_store_present: bool,
    shared_translation_configured: bool,
) -> bool {
    artifact_store_present || shared_translation_configured
}

#[derive(Clone, Copy)]
pub struct SensitiveMetadata {
    pub exit: types::SensitiveExit,
    pub fusion: Option<types::ExclusiveFusionSite>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationOutcome {
    BlockIndexHit,
    SharedUnit,
    ArtifactReplay,
    Translated,
}

#[derive(Clone, Copy, Debug)]
pub struct TranslationResult {
    pub entry: types::CacheVa,
    pub generation: types::CodeGeneration,
    pub outcome: TranslationOutcome,
    pub emitted_bytes: u64,
    pub cache_used_bytes: u64,
}

pub struct PublishedBlock {
    pub entry: types::CacheVa,
    pub len: usize,
    pub map: Vec<emit::PcMapEntry>,
    pub recovery: Vec<emit::RecoveryEntry>,
    pub _generation: cache::PageGenerationObservation,
}

/// One entry of an address-ordered index over [`ProcessState::published`]:
/// where a block's emitted code starts, and where the block itself sits in
/// publication order.
#[derive(Clone, Copy)]
struct PublishedIndexEntry {
    start: carrick_guest_mem::HostVa,
    block: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverStats {
    pub resolver_exits: u64,
    pub one_entry_hits: u64,
    pub translations: u64,
    pub duplicate_publications: u64,
    pub gateway_entries: u64,
    pub syscall_exits: u64,
    pub direct_resolver_exits: u64,
    pub cache_lookups: u64,
    pub cache_lookup_hits: u64,
    pub invalidated_blocks: u64,
    pub translation_ns: u64,
    pub translation_decode_ns: u64,
    pub translation_plan_ns: u64,
    pub translation_emit_ns: u64,
    pub translation_publication_ns: u64,
    pub shared_unit_lookups: u64,
    pub shared_unit_hits: u64,
    pub shared_unit_loads: u64,
    pub shared_blocks_mapped: u64,
    pub shared_translations_avoided: u64,
    /// `ResolveDirect` exits classified by whether the SOURCE (the branching
    /// instruction's guest PC) and the TARGET fall inside shared-unit code.
    /// Thread-scoped, like `direct_resolver_exits`.
    pub resolve_src_shared_tgt_shared: u64,
    pub resolve_src_shared_tgt_private: u64,
    pub resolve_src_private_tgt_shared: u64,
    pub resolve_src_private_tgt_private: u64,
    invalid: Option<profile::ProfileError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverStat {
    ResolverExits,
    OneEntryHits,
    Translations,
    DuplicatePublications,
    GatewayEntries,
    SyscallExits,
    DirectResolverExits,
    CacheLookups,
    CacheLookupHits,
    InvalidatedBlocks,
    TranslationNs,
    TranslationDecodeNs,
    TranslationPlanNs,
    TranslationEmitNs,
    TranslationPublicationNs,
    // Process-scoped like Translations and CacheLookups: incremented on
    // `ProcessState::stats`, so they MUST flow through `checked_delta` /
    // `reported_stats` or summing the per-thread records over-counts them once
    // per reporting thread.
    SharedUnitLookups,
    SharedUnitHits,
    SharedUnitLoads,
    SharedBlocksMapped,
    SharedTranslationsAvoided,
    ResolveSrcSharedTgtShared,
    ResolveSrcSharedTgtPrivate,
    ResolveSrcPrivateTgtShared,
    ResolveSrcPrivateTgtPrivate,
}

impl ResolverStat {
    const ALL: [Self; 24] = [
        Self::ResolverExits,
        Self::OneEntryHits,
        Self::Translations,
        Self::DuplicatePublications,
        Self::GatewayEntries,
        Self::SyscallExits,
        Self::DirectResolverExits,
        Self::CacheLookups,
        Self::CacheLookupHits,
        Self::InvalidatedBlocks,
        Self::TranslationNs,
        Self::TranslationDecodeNs,
        Self::TranslationPlanNs,
        Self::TranslationEmitNs,
        Self::TranslationPublicationNs,
        Self::SharedUnitLookups,
        Self::SharedUnitHits,
        Self::SharedUnitLoads,
        Self::SharedBlocksMapped,
        Self::SharedTranslationsAvoided,
        Self::ResolveSrcSharedTgtShared,
        Self::ResolveSrcSharedTgtPrivate,
        Self::ResolveSrcPrivateTgtShared,
        Self::ResolveSrcPrivateTgtPrivate,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::ResolverExits => "resolver_exits",
            Self::OneEntryHits => "one_entry_hits",
            Self::Translations => "translations",
            Self::DuplicatePublications => "duplicate_publications",
            Self::GatewayEntries => "gateway_entries",
            Self::SyscallExits => "syscall_exits",
            Self::DirectResolverExits => "direct_resolver_exits",
            Self::CacheLookups => "cache_lookups",
            Self::CacheLookupHits => "cache_lookup_hits",
            Self::InvalidatedBlocks => "invalidated_blocks",
            Self::TranslationNs => "translation_ns",
            Self::TranslationDecodeNs => "translation_decode_ns",
            Self::TranslationPlanNs => "translation_plan_ns",
            Self::TranslationEmitNs => "translation_emit_ns",
            Self::TranslationPublicationNs => "translation_publication_ns",
            Self::SharedUnitLookups => "shared_unit_lookups",
            Self::SharedUnitHits => "shared_unit_hits",
            Self::SharedUnitLoads => "shared_unit_loads",
            Self::SharedBlocksMapped => "shared_blocks_mapped",
            Self::SharedTranslationsAvoided => "shared_translations_avoided",
            Self::ResolveSrcSharedTgtShared => "resolve_src_shared_tgt_shared",
            Self::ResolveSrcSharedTgtPrivate => "resolve_src_shared_tgt_private",
            Self::ResolveSrcPrivateTgtShared => "resolve_src_private_tgt_shared",
            Self::ResolveSrcPrivateTgtPrivate => "resolve_src_private_tgt_private",
        }
    }
}

impl ResolverStats {
    fn get(self, stat: ResolverStat) -> u64 {
        match stat {
            ResolverStat::ResolverExits => self.resolver_exits,
            ResolverStat::OneEntryHits => self.one_entry_hits,
            ResolverStat::Translations => self.translations,
            ResolverStat::DuplicatePublications => self.duplicate_publications,
            ResolverStat::GatewayEntries => self.gateway_entries,
            ResolverStat::SyscallExits => self.syscall_exits,
            ResolverStat::DirectResolverExits => self.direct_resolver_exits,
            ResolverStat::CacheLookups => self.cache_lookups,
            ResolverStat::CacheLookupHits => self.cache_lookup_hits,
            ResolverStat::InvalidatedBlocks => self.invalidated_blocks,
            ResolverStat::TranslationNs => self.translation_ns,
            ResolverStat::TranslationDecodeNs => self.translation_decode_ns,
            ResolverStat::TranslationPlanNs => self.translation_plan_ns,
            ResolverStat::TranslationEmitNs => self.translation_emit_ns,
            ResolverStat::TranslationPublicationNs => self.translation_publication_ns,
            ResolverStat::SharedUnitLookups => self.shared_unit_lookups,
            ResolverStat::SharedUnitHits => self.shared_unit_hits,
            ResolverStat::SharedUnitLoads => self.shared_unit_loads,
            ResolverStat::SharedBlocksMapped => self.shared_blocks_mapped,
            ResolverStat::SharedTranslationsAvoided => self.shared_translations_avoided,
            ResolverStat::ResolveSrcSharedTgtShared => self.resolve_src_shared_tgt_shared,
            ResolverStat::ResolveSrcSharedTgtPrivate => self.resolve_src_shared_tgt_private,
            ResolverStat::ResolveSrcPrivateTgtShared => self.resolve_src_private_tgt_shared,
            ResolverStat::ResolveSrcPrivateTgtPrivate => self.resolve_src_private_tgt_private,
        }
    }

    fn set(&mut self, stat: ResolverStat, value: u64) {
        match stat {
            ResolverStat::ResolverExits => self.resolver_exits = value,
            ResolverStat::OneEntryHits => self.one_entry_hits = value,
            ResolverStat::Translations => self.translations = value,
            ResolverStat::DuplicatePublications => self.duplicate_publications = value,
            ResolverStat::GatewayEntries => self.gateway_entries = value,
            ResolverStat::SyscallExits => self.syscall_exits = value,
            ResolverStat::DirectResolverExits => self.direct_resolver_exits = value,
            ResolverStat::CacheLookups => self.cache_lookups = value,
            ResolverStat::CacheLookupHits => self.cache_lookup_hits = value,
            ResolverStat::InvalidatedBlocks => self.invalidated_blocks = value,
            ResolverStat::TranslationNs => self.translation_ns = value,
            ResolverStat::TranslationDecodeNs => self.translation_decode_ns = value,
            ResolverStat::TranslationPlanNs => self.translation_plan_ns = value,
            ResolverStat::TranslationEmitNs => self.translation_emit_ns = value,
            ResolverStat::TranslationPublicationNs => self.translation_publication_ns = value,
            ResolverStat::SharedUnitLookups => self.shared_unit_lookups = value,
            ResolverStat::SharedUnitHits => self.shared_unit_hits = value,
            ResolverStat::SharedUnitLoads => self.shared_unit_loads = value,
            ResolverStat::SharedBlocksMapped => self.shared_blocks_mapped = value,
            ResolverStat::SharedTranslationsAvoided => self.shared_translations_avoided = value,
            ResolverStat::ResolveSrcSharedTgtShared => self.resolve_src_shared_tgt_shared = value,
            ResolverStat::ResolveSrcSharedTgtPrivate => self.resolve_src_shared_tgt_private = value,
            ResolverStat::ResolveSrcPrivateTgtShared => self.resolve_src_private_tgt_shared = value,
            ResolverStat::ResolveSrcPrivateTgtPrivate => {
                self.resolve_src_private_tgt_private = value
            }
        }
    }

    pub fn add(&mut self, stat: ResolverStat, value: u64) {
        if self.invalid.is_some() {
            return;
        }
        match self.get(stat).checked_add(value) {
            Some(total) => self.set(stat, total),
            None => {
                self.invalid = Some(profile::ProfileError::CounterOverflow(stat.name()));
            }
        }
    }

    fn add_elapsed(&mut self, stat: ResolverStat, elapsed: std::time::Duration) {
        match u64::try_from(elapsed.as_nanos()) {
            Ok(ns) => self.add(stat, ns),
            Err(_) => {
                self.invalid = Some(profile::ProfileError::CounterOverflow(stat.name()));
            }
        }
    }

    fn add_usize(&mut self, stat: ResolverStat, value: usize) {
        match u64::try_from(value) {
            Ok(value) => self.add(stat, value),
            Err(_) => {
                self.invalid = Some(profile::ProfileError::CounterOverflow(stat.name()));
            }
        }
    }

    fn checked_delta(self, prior: Self) -> Result<Self, profile::ProfileError> {
        if let Some(error) = self.invalid.or(prior.invalid) {
            return Err(error);
        }
        let mut delta = Self::default();
        for stat in ResolverStat::ALL {
            let value = self
                .get(stat)
                .checked_sub(prior.get(stat))
                .ok_or(profile::ProfileError::CounterUnderflow(stat.name()))?;
            delta.set(stat, value);
        }
        Ok(delta)
    }
}

// Moved into `carrick_dsr::profile` (all fields `pub`) with the census; the
// re-export keeps the bare `ProfileSnapshot` name and every field access in
// this module unchanged.
pub use profile::ProfileSnapshot;

/// One live guest OS thread's most-recently republished profiling state,
/// visible to every OTHER guest thread of this same process.
///
/// WHY THIS EXISTS: Linux `exit_group` (guest syscall 94) kills every thread
/// of a process at once, unconditionally -- that is correct Linux semantics,
/// and this runtime's `DispatchOutcome::Exit` handler matches it with an
/// unconditional `libc::_exit()`. But `libc::_exit()` gives every OTHER live
/// host OS thread backing a sibling guest thread ZERO chance to run any code
/// of its own, `Drop` included, so a sibling's `ThreadTranslator` (a plain
/// stack local, normally flushed by its own `Drop`) is simply never flushed:
/// its already-consumed DSR execution CPU still lands in the host kernel's
/// PER-PROCESS `getrusage` gauge (a live, passive counter, not something a
/// thread has to report), but no per-thread `core.thread_cpu_ns` NATIVEPERF
/// record for it is ever written. The Python analyzer's derived helper
/// residual (`process_cpu - Σ flushed thread_cpu`) then silently absorbs that
/// real guest execution as if it were profiler/runtime overhead.
///
/// The fix: every guest thread republishes a cheap, self-consistent COPY of
/// its own counters here on every DSR loop iteration (`Copy`, no allocation,
/// no correctness dependency on freshness beyond "at most one iteration
/// old"). When `exit_group` fires, the thread that observed it -- after
/// flushing and deregistering ITSELF exactly as before -- drains whatever
/// other entries remain and emits a complete record for each, using the
/// entry's last-published counters for identity/reconciliation and a LIVE
/// cross-thread `thread_info` read (via the mach port each thread captures
/// on itself at registration) for the one field that must never be stale:
/// `thread_cpu_ns`.
///
/// The self-flush and the drain race each other for real; see [`SiblingSlot`]
/// for how the map arbitrates that race so each record is emitted EXACTLY
/// once.
///
/// Scope and lifetime: this `static` is exactly as process-scoped as
/// `profile::PROCESS_STARTUP` -- Carrick runs each guest PROCESS as a real,
/// separate forked host OS process, so a plain `static` here already means
/// "this guest process's registry" with no extra plumbing. A fork child
/// inherits a COW snapshot describing OS threads (and mach ports) that do
/// not exist in the new process; `ThreadTranslator::after_fork_child` clears
/// it and re-seeds the one surviving thread. A real execve resets it for
/// free (a fresh process image reinitializes every `static`). Entirely
/// unused (no lock ever taken, no port ever queried) when profiling is off.
#[derive(Clone, Copy)]
struct SiblingSnapshot {
    budget: profile::ThreadBudget,
    stats: ResolverStats,
    nested_translation_ns: u64,
    mach_port: carrick_host::host_proc::ThreadPort,
}

/// EXACTLY-ONCE ARBITRATION. Exactly two parties can ever emit a given
/// thread's record: the thread ITSELF (its own retirement flush — individual
/// `exit(2)`, `Execve` self-reexec, `native_die_by_signal`, `RetireForExec`)
/// and a FOREIGN thread's `exit_group` drain. Those two genuinely run at the
/// same instant on two cores, because `exit_group` fires while its siblings
/// are still executing. If both emit, the wire carries a duplicate
/// `(pid, tid, era)` group — which `parse_nativeperf` HARD-REJECTS, i.e. an
/// intermittent hard failure of a real profiled campaign run, not a
/// degradation.
///
/// So the map operation itself is the single arbiter: whoever's `remove` /
/// take-under-lock observes a `Live` slot has *claimed* the exclusive right
/// to emit that record, and the loser emits nothing.
///
/// The drain leaves a `Drained` TOMBSTONE rather than removing the slot
/// outright. Without it the claim would not be total: `libc::_exit()` is not
/// instantaneous, so between a drain (which already emitted a sibling's
/// record) and the actual `_exit()`, that sibling can complete another DSR
/// loop iteration, REPUBLISH a fresh `Live` slot, then reach its own
/// retirement flush — win the claim on the slot it just re-created — and emit
/// the very same `(pid, tid, era)` a second time. The tombstone makes
/// "already emitted by a drain" a durable, observable fact: `publish` refuses
/// to overwrite it, and a self-flush that finds it stands down.
/// * `Some(snapshot)` — LIVE: registered and unclaimed. Whoever takes it (the
///   owning thread's self-flush, or a foreign drain) has claimed the exclusive
///   right to emit that record.
/// * `None` — DRAINED tombstone: a foreign `exit_group` drain has already
///   emitted this thread's record. Neither party may emit it again.
///
/// `Option::take()` under the registry lock IS the claim: it flips LIVE to
/// DRAINED and hands the snapshot to exactly one caller.
type SiblingSlot = Option<SiblingSnapshot>;

static SIBLING_PROFILES: OnceLock<Mutex<HashMap<i32, SiblingSlot>>> = OnceLock::new();

fn sibling_profiles() -> &'static Mutex<HashMap<i32, SiblingSlot>> {
    SIBLING_PROFILES.get_or_init(|| Mutex::new(HashMap::new()))
}

impl ThreadTranslator {
    /// Test-only convenience constructor (kept always-compiled:
    /// `cfg(test)` does not cross crates, and the runtime's still-resident
    /// JIT-entangled test suites construct translators through this).
    #[doc(hidden)]
    pub fn new(capacity: usize) -> Result<Self, types::DsrError> {
        Ok(Self::for_process(
            Arc::new(ProcessTranslator::new(capacity)?),
            0,
        ))
    }

    pub fn for_process(process: Arc<ProcessTranslator>, tid: i32) -> Self {
        Self {
            process,
            tid,
            block_cache: ThreadBlockCache::new(),
            profiled_private_to_shared_edges: std::collections::HashSet::new(),
            profiled_private_to_private_edges: std::collections::HashSet::new(),
            last_cache_used_bytes: 0,
            stats: ResolverStats::default(),
            budget: profile::ThreadBudget::from_environment(tid),
            profile_finalized: false,
            nested_translation_ns: 0,
            last_kick: None,
            indirect_cache: gateway::IndirectTargetCache::new(),
            exec_reset_identity: Arc::new(DirectBindingExecThreadIdentity),
            exec_reset_epoch: 0,
        }
    }

    pub fn after_fork_child(&mut self, tid: i32) {
        self.tid = tid;
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ForkChildRepairBegin,
            used_bytes,
            block_count,
            generation_count,
        );
        self.process.after_fork_child();
        self.block_cache.clear();
        self.exec_reset_epoch = self.exec_reset_epoch.wrapping_add(1);
        self.stats = ResolverStats::default();
        self.budget.reset_after_fork_child(tid);
        if self.budget.enabled() {
            // The child's rusage clock restarted at fork: restart the process
            // startup window here so its first gateway entry claims the
            // child's own bring-up cost (profile-off runs read no clocks).
            profile::reset_process_startup_after_fork_child();
            profile::reset_profile_exec_epoch_after_fork_child();
            // `fork()` only duplicates the calling thread: every OTHER entry
            // in the inherited (COW) sibling registry names an OS thread --
            // and a mach port -- that does not exist in this new process.
            // Clear it (`Drained` tombstones included: they describe the
            // PARENT's emissions, and the child re-registers from scratch)
            // before re-seeding this, the one surviving thread; else a later
            // `exit_group` drain in the child would `thread_info` a
            // stale/dangling port name from the parent's port namespace.
            //
            // Safe to take this lock here for exactly the reason the
            // pre-existing `self.process.state` lock above is: the fork is
            // serialized by the quiesce barrier. The forking thread calls
            // `fork_quiesce::set_quiescing()` and then blocks in
            // `wait_quiesced(others, timeout)` until all `others` guest
            // threads have PARKED in `park_if_quiescing()` (via
            // `NativeThreadRuntime::park_for_fork_quiesce`), and only then
            // calls `libc::fork()`. `publish_sibling_snapshot` takes this
            // lock at the DSR loop top and releases it before that park
            // point, and it is never held across the park -- so no thread can
            // be holding it at the instant the child's address space is
            // snapshotted, and the child can never inherit it locked.
            sibling_profiles().lock().clear();
        }
        self.profile_finalized = false;
        self.nested_translation_ns = 0;
        self.last_kick = None;
        self.indirect_cache.clear();
        // Re-register the surviving thread under its (possibly renumbered)
        // child tid with the just-reset budget/stats, querying its mach port
        // fresh -- the child's task port namespace is its own, so the old
        // port value is not to be trusted even for this same thread.
        self.publish_sibling_snapshot();
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ForkChildRepairEnd,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    pub fn begin_exec_reset(&self) {
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecResetBegin,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    pub fn begin_exec_handoff(&self) {
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecTranslatorHandoffBegin,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    /// Clears the surviving thread's direct-target state under exec quiesce.
    ///
    /// The runtime calls this after sibling retirement and before mapped
    /// memory starts retiring the old image. No translated execution may
    /// resume until `reset_for_exec` installs the replacement process.
    pub fn prepare_direct_binding_exec_reset(&mut self) -> DirectBindingExecResetToken {
        self.block_cache.clear();
        self.indirect_cache.clear();
        self.exec_reset_epoch = self.exec_reset_epoch.wrapping_add(1);
        DirectBindingExecResetToken {
            process_identity: Arc::clone(&self.process.exec_reset_identity),
            thread_identity: Arc::clone(&self.exec_reset_identity),
            thread_epoch: self.exec_reset_epoch,
            consumed: false,
        }
    }

    pub fn reset_for_exec(&mut self, next: Arc<ProcessTranslator>) {
        self.reset_for_exec_with_sink(next, |frames| {
            let _ = profile::write_protocol_frames_to_fd(libc::STDERR_FILENO, frames);
        });
    }

    #[doc(hidden)]
    pub fn reset_for_exec_with_sink(
        &mut self,
        next: Arc<ProcessTranslator>,
        mut sink: impl FnMut(&[String]),
    ) {
        if let Some(frames) = self.take_profile_frames() {
            sink(&frames);
        }
        self.process = next;
        self.block_cache.clear();
        self.exec_reset_epoch = self.exec_reset_epoch.wrapping_add(1);
        self.start_next_profile_epoch();
        self.last_kick = None;
        self.indirect_cache.clear();
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecTranslatorHandoffEnd,
            used_bytes,
            block_count,
            generation_count,
        );
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecResetEnd,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    pub fn start_next_profile_epoch(&mut self) {
        self.reset_profile_accumulators();
        self.budget.reset_after_exec();
    }

    pub fn start_next_profile_era_same_image(&mut self) {
        self.reset_profile_accumulators();
        self.budget.reset_same_image_profile_era();
    }

    fn reset_profile_accumulators(&mut self) {
        self.stats = ResolverStats::default();
        self.profile_finalized = false;
        self.nested_translation_ns = 0;
    }

    #[doc(hidden)]
    pub fn profile_snapshot(&self) -> ProfileSnapshot {
        let process = self.process.state.read();
        ProfileSnapshot {
            resolver_exits: self.stats.resolver_exits,
            one_entry_hits: self.stats.one_entry_hits,
            translations: process.stats.translations,
            duplicate_publications: process.stats.duplicate_publications,
            gateway_entries: self.stats.gateway_entries,
            syscall_exits: self.stats.syscall_exits,
            direct_resolver_exits: self.stats.direct_resolver_exits,
            cache_lookups: process.stats.cache_lookups,
            cache_lookup_hits: process.stats.cache_lookup_hits,
            invalidated_blocks: process.stats.invalidated_blocks,
            translation_ns: process.stats.translation_ns,
            translation_decode_ns: process.stats.translation_decode_ns,
            translation_plan_ns: process.stats.translation_plan_ns,
            translation_emit_ns: process.stats.translation_emit_ns,
            translation_publication_ns: process.stats.translation_publication_ns,
            nested_translation_ns: self.nested_translation_ns,
            cache_used_bytes: process.cache.used_bytes(),
            cache_capacity_bytes: process.cache.capacity_bytes(),
            direct_binding_owner_validation_failures: process
                .direct_bindings
                .counters()
                .owner_validation_failures,
            direct_binding_authority_validation_failures: process
                .direct_bindings
                .counters()
                .authority_validation_failures,
            direct_binding_cas_wins: process.direct_bindings.counters().cas_wins,
            direct_binding_cas_losses: process.direct_bindings.counters().cas_losses,
            direct_binding_stale_winner_clears: process
                .direct_bindings
                .counters()
                .stale_winner_clears,
            direct_binding_publication_retries: process
                .direct_bindings
                .counters()
                .publication_retries,
            resolve_private_to_shared_distinct_edges: self.profiled_private_to_shared_edges.len()
                as u64,
            resolve_private_to_private_distinct_edges: self.profiled_private_to_private_edges.len()
                as u64,
            resolve_src_shared_tgt_shared: self.stats.resolve_src_shared_tgt_shared,
            resolve_src_shared_tgt_private: self.stats.resolve_src_shared_tgt_private,
            resolve_src_private_tgt_shared: self.stats.resolve_src_private_tgt_shared,
            resolve_src_private_tgt_private: self.stats.resolve_src_private_tgt_private,
            shared_unit_lookups: process.stats.shared_unit_lookups,
            shared_unit_hits: process.stats.shared_unit_hits,
            shared_unit_loads: process.stats.shared_unit_loads,
            shared_blocks_mapped: process.stats.shared_blocks_mapped,
            shared_translations_avoided: process.stats.shared_translations_avoided,
            exclusive_fusion_sites: process.exclusive_fusion_site_counts(),
        }
    }

    /// Claim this process epoch's OUTSTANDING process-wide resolver delta for
    /// the calling thread's record. The process-wide counters (translations,
    /// cache lookups/hits, invalidated blocks, translation_*_ns, duplicate
    /// publications) are SHARED by every thread of the process, so they are
    /// published as a delta against a single `reported_stats` checkpoint that
    /// this call advances: whatever accrued since the last claim is assigned
    /// to exactly ONE record, and the next claimer starts from the new
    /// checkpoint. That is what makes summing the per-thread records recover
    /// the process totals exactly once (see
    /// `process_resolver_deltas_are_counted_exactly_once_across_threads`).
    fn claim_profile_snapshot(&mut self) -> Result<ProfileSnapshot, profile::ProfileError> {
        if let Some(error) = self.stats.invalid {
            return Err(error);
        }
        let mut process = self.process.state.write();
        let delta = process.stats.checked_delta(process.reported_stats)?;
        process.reported_stats = process.stats;
        Ok(ProfileSnapshot {
            resolver_exits: self.stats.resolver_exits,
            one_entry_hits: self.stats.one_entry_hits,
            translations: delta.translations,
            duplicate_publications: delta.duplicate_publications,
            gateway_entries: self.stats.gateway_entries,
            syscall_exits: self.stats.syscall_exits,
            direct_resolver_exits: self.stats.direct_resolver_exits,
            cache_lookups: delta.cache_lookups,
            cache_lookup_hits: delta.cache_lookup_hits,
            invalidated_blocks: delta.invalidated_blocks,
            translation_ns: delta.translation_ns,
            translation_decode_ns: delta.translation_decode_ns,
            translation_plan_ns: delta.translation_plan_ns,
            translation_emit_ns: delta.translation_emit_ns,
            translation_publication_ns: delta.translation_publication_ns,
            nested_translation_ns: self.nested_translation_ns,
            cache_used_bytes: process.cache.used_bytes(),
            cache_capacity_bytes: process.cache.capacity_bytes(),
            direct_binding_owner_validation_failures: process
                .direct_bindings
                .counters()
                .owner_validation_failures,
            direct_binding_authority_validation_failures: process
                .direct_bindings
                .counters()
                .authority_validation_failures,
            direct_binding_cas_wins: process.direct_bindings.counters().cas_wins,
            direct_binding_cas_losses: process.direct_bindings.counters().cas_losses,
            direct_binding_stale_winner_clears: process
                .direct_bindings
                .counters()
                .stale_winner_clears,
            direct_binding_publication_retries: process
                .direct_bindings
                .counters()
                .publication_retries,
            resolve_private_to_shared_distinct_edges: self.profiled_private_to_shared_edges.len()
                as u64,
            resolve_private_to_private_distinct_edges: self.profiled_private_to_private_edges.len()
                as u64,
            resolve_src_shared_tgt_shared: self.stats.resolve_src_shared_tgt_shared,
            resolve_src_shared_tgt_private: self.stats.resolve_src_shared_tgt_private,
            resolve_src_private_tgt_shared: self.stats.resolve_src_private_tgt_shared,
            resolve_src_private_tgt_private: self.stats.resolve_src_private_tgt_private,
            shared_unit_lookups: delta.shared_unit_lookups,
            shared_unit_hits: delta.shared_unit_hits,
            shared_unit_loads: delta.shared_unit_loads,
            shared_blocks_mapped: delta.shared_blocks_mapped,
            shared_translations_avoided: delta.shared_translations_avoided,
            exclusive_fusion_sites: process.exclusive_fusion_site_counts(),
        })
    }

    /// The resolver snapshot for a DRAINED SIBLING's record.
    ///
    /// Deliberately does NOT claim the process-wide delta: every field that is
    /// a delta against the shared `reported_stats` checkpoint
    /// (`translations`, `duplicate_publications`, `cache_lookups`,
    /// `cache_lookup_hits`, `invalidated_blocks`, `translation_*_ns`) is
    /// reported as ZERO here, BY CONSTRUCTION, and the checkpoint is left
    /// untouched.
    ///
    /// WHY: the process-wide delta must be assigned exactly once per process
    /// epoch, and the DRAINING thread's own flush -- which always runs
    /// immediately before the drain, at every one of the `libc::_exit()` seams
    /// (`translator.finalize_profile_epoch()` then
    /// `translator.drain_sibling_profiles_before_process_exit()`) -- has
    /// already claimed it via `claim_profile_snapshot`. If the drain claimed
    /// again per sibling, only the FIRST sibling in the loop would receive the
    /// (near-zero) residue and every later one would silently get ~0 anyway,
    /// with the split depending on nothing but loop order: the same zeros,
    /// arbitrarily and nondeterministically distributed. Reporting a
    /// structural zero is the same information, stated honestly, and keeps the
    /// "assigned exactly once, never double-counted" invariant trivially true.
    ///
    /// The PER-THREAD fields (`resolver_exits`, `one_entry_hits`,
    /// `gateway_entries`, `syscall_exits`, `direct_resolver_exits`,
    /// `nested_translation_ns`) are the sibling's OWN real counters, and the
    /// cache POINT-IN-TIME gauges (`cache_used_bytes`/`cache_capacity_bytes`)
    /// are real live reads -- neither is a delta, so neither is affected.
    fn drained_sibling_profile_snapshot(
        process: &ProcessTranslator,
        stats: ResolverStats,
        nested_translation_ns: u64,
    ) -> Result<ProfileSnapshot, profile::ProfileError> {
        if let Some(error) = stats.invalid {
            return Err(error);
        }
        let process_state = process.state.read();
        Ok(ProfileSnapshot {
            resolver_exits: stats.resolver_exits,
            one_entry_hits: stats.one_entry_hits,
            gateway_entries: stats.gateway_entries,
            syscall_exits: stats.syscall_exits,
            direct_resolver_exits: stats.direct_resolver_exits,
            nested_translation_ns,
            // Point-in-time gauges, never deltas: real live reads.
            cache_used_bytes: process_state.cache.used_bytes(),
            cache_capacity_bytes: process_state.cache.capacity_bytes(),
            direct_binding_owner_validation_failures: process_state
                .direct_bindings
                .counters()
                .owner_validation_failures,
            direct_binding_authority_validation_failures: process_state
                .direct_bindings
                .counters()
                .authority_validation_failures,
            direct_binding_cas_wins: process_state.direct_bindings.counters().cas_wins,
            direct_binding_cas_losses: process_state.direct_bindings.counters().cas_losses,
            direct_binding_stale_winner_clears: process_state
                .direct_bindings
                .counters()
                .stale_winner_clears,
            direct_binding_publication_retries: process_state
                .direct_bindings
                .counters()
                .publication_retries,
            // Process-wide deltas: owned by the draining thread's own record
            // (see the doc comment above); structurally zero here.
            translations: 0,
            duplicate_publications: 0,
            cache_lookups: 0,
            cache_lookup_hits: 0,
            invalidated_blocks: 0,
            translation_ns: 0,
            translation_decode_ns: 0,
            translation_plan_ns: 0,
            translation_emit_ns: 0,
            translation_publication_ns: 0,
            // Process-wide deltas, like the block above: owned by the draining
            // thread's own record, so structurally zero here.
            resolve_private_to_shared_distinct_edges: 0,
            resolve_private_to_private_distinct_edges: 0,
            resolve_src_shared_tgt_shared: stats.resolve_src_shared_tgt_shared,
            resolve_src_shared_tgt_private: stats.resolve_src_shared_tgt_private,
            resolve_src_private_tgt_shared: stats.resolve_src_private_tgt_shared,
            resolve_src_private_tgt_private: stats.resolve_src_private_tgt_private,
            shared_unit_lookups: 0,
            shared_unit_hits: 0,
            shared_unit_loads: 0,
            shared_blocks_mapped: 0,
            shared_translations_avoided: 0,
            exclusive_fusion_sites: process_state.exclusive_fusion_site_counts(),
        })
    }

    #[doc(hidden)]
    pub fn take_profile_frames(&mut self) -> Option<Vec<String>> {
        if !self.budget.enabled() || self.profile_finalized {
            return None;
        }
        self.profile_finalized = true;
        // EXACTLY-ONCE. A foreign `exit_group` drain races this flush for the
        // right to emit this thread's record. The map operation is the single
        // arbiter: emit ONLY if this thread won the claim. If the drain got
        // there first it has already emitted this record, and emitting it
        // again would put a duplicate `(pid, tid, era)` group on the wire --
        // a hard parse failure, not a degradation.
        if !self.claim_own_profile_emission() {
            return None;
        }
        let frames = self
            .budget
            .complete_record()
            .and_then(|record| {
                let snapshot = self.claim_profile_snapshot()?;
                let gauges = profile::flush_gauges(self.budget.thread_cpu_baseline_ns())?;
                record.to_protocol_frames_with_resolver(snapshot, gauges)
            })
            .unwrap_or_else(|error| vec![self.budget.invalid_protocol_line(error)]);
        Some(frames)
    }

    pub fn finalize_profile_epoch(&mut self) {
        if let Some(frames) = self.take_profile_frames() {
            let _ = profile::write_protocol_frames_to_fd(libc::STDERR_FILENO, &frames);
        }
    }

    /// Register (first call) or republish (every later call) this thread's
    /// profiling state so a FOREIGN thread can emit a complete record on its
    /// behalf if `exit_group` kills it before it gets to flush itself. Safe
    /// to call unconditionally at any DSR loop-iteration boundary: at that
    /// point the prior iteration's `record_exit`/phase counters are always
    /// fully reconciled with `self.stats` (both are only ever advanced
    /// together, earlier in the same iteration, before control returns here),
    /// so a snapshot taken here can always be turned into a valid, reconciled
    /// `CompleteThreadRecord` later. A no-op (no lock, no port lookup) when
    /// profiling is disabled.
    ///
    /// Never resurrects a `Drained` tombstone: once a foreign drain has
    /// emitted this thread's record, re-registering would let a later
    /// self-flush win a claim on the freshly re-created slot and emit the same
    /// `(pid, tid, era)` a second time (see `SiblingSlot`).
    pub fn publish_sibling_snapshot(&self) {
        if !self.budget.enabled() {
            return;
        }
        let snapshot = SiblingSnapshot {
            budget: self.budget,
            stats: self.stats,
            nested_translation_ns: self.nested_translation_ns,
            mach_port: carrick_host::host_proc::current_thread_port(),
        };
        let mut slots = sibling_profiles().lock();
        match slots.get(&self.tid) {
            // A DRAINED tombstone: a foreign drain already emitted this
            // thread's record. Never resurrect the slot.
            Some(None) => {}
            _ => {
                slots.insert(self.tid, Some(snapshot));
            }
        }
    }

    /// Claim the exclusive right to emit THIS thread's record, arbitrated by a
    /// single map operation under the registry lock. Returns true iff the
    /// caller may emit.
    ///
    /// - LIVE slot (`Some(_)`): this thread took it, so the drain cannot --
    ///   emit.
    /// - DRAINED tombstone (`Some(None)`): a foreign `exit_group` drain
    ///   already emitted this record -- do NOT emit (and the tombstone goes
    ///   straight back, so a later republish + self-flush cannot resurrect
    ///   the duplicate either).
    /// - no slot at all (`None`): this thread never registered (a
    ///   profiling-off translator, or one that never reached a DSR
    ///   loop-iteration boundary), so no drain can possibly know about it --
    ///   emit.
    ///
    /// Profiling off: there is no registry and no claim to make, and
    /// `take_profile_frames` has already returned `None` before reaching here,
    /// so the profile-off path still emits nothing at all.
    fn claim_own_profile_emission(&self) -> bool {
        if !self.budget.enabled() {
            return true;
        }
        let mut slots = sibling_profiles().lock();
        match slots.remove(&self.tid) {
            Some(Some(_)) => true,
            Some(None) => {
                slots.insert(self.tid, None);
                false
            }
            None => true,
        }
    }

    /// About to trigger a process-wide `libc::_exit()` because Linux
    /// `exit_group` semantics (or this being the last live thread) say every
    /// OTHER guest OS thread of this process dies right now, unconditionally,
    /// with zero chance to run any code of its own -- `Drop` included. Emit a
    /// complete NATIVEPERF record for every still-`Live` sibling using its
    /// last-published counters (reconciled -- see `publish_sibling_snapshot`)
    /// and a LIVE cross-thread `thread_info` read of its actual CPU via the
    /// mach port it captured at registration (CPU is never stale here,
    /// regardless of how long ago the rest of the snapshot was published).
    ///
    /// Taking a `Live` slot CLAIMS it, exactly as a self-flush would, and
    /// leaves a `Drained` tombstone so the owning thread -- which may be
    /// concurrently racing its own retirement flush on another core, and may
    /// even complete another DSR iteration before the `_exit()` lands --
    /// stands down instead of emitting a duplicate `(pid, tid, era)` group
    /// (see [`SiblingSlot`]).
    ///
    /// The siblings drained here report structurally zero process-wide
    /// resolver deltas (see `drained_sibling_profile_snapshot`); the caller,
    /// [`Self::finalize_profile_epoch_at_process_exit`], flushes its own
    /// record AFTER this drain and thereby claims the epoch's entire
    /// outstanding process-wide delta exactly once.
    ///
    /// A no-op when profiling is disabled. Never emits a wire `invalid`
    /// record: a sibling whose record cannot be reconstructed is reported
    /// through `tracing::warn!` and skipped, because the profile parser
    /// rejects any `invalid` record for the WHOLE profile -- so emitting one
    /// would be a strictly worse failure than losing this one thread's
    /// attribution.
    #[doc(hidden)]
    pub fn drain_sibling_profiles_before_process_exit(&self) {
        if !self.budget.enabled() {
            return;
        }
        let siblings: Vec<SiblingSnapshot> = {
            let mut slots = sibling_profiles().lock();
            // `take()` IS the claim: it flips each LIVE slot to a DRAINED
            // tombstone and hands this thread the snapshot, so the owning
            // thread -- which may be racing its own retirement flush on
            // another core right now -- stands down instead of emitting a
            // duplicate.
            slots.values_mut().filter_map(Option::take).collect()
        };
        for snapshot in siblings {
            match Self::drained_sibling_frames(&self.process, &snapshot) {
                Ok(frames) => {
                    let _ = profile::write_protocol_frames_to_fd(libc::STDERR_FILENO, &frames);
                }
                Err(error) => tracing::warn!(
                    %error,
                    tid = snapshot.budget.tid(),
                    "native DSR could not reconstruct the profile record of a guest thread \
                     killed by exit_group; its CPU stays in the derived helper residual"
                ),
            }
        }
    }

    fn drained_sibling_frames(
        process: &ProcessTranslator,
        snapshot: &SiblingSnapshot,
    ) -> Result<Vec<String>, profile::ProfileError> {
        let record = snapshot.budget.complete_record()?;
        let resolver = Self::drained_sibling_profile_snapshot(
            process,
            snapshot.stats,
            snapshot.nested_translation_ns,
        )?;
        let gauges = profile::flush_gauges_for_port(
            snapshot.mach_port,
            snapshot.budget.thread_cpu_baseline_ns(),
        )?;
        record.to_protocol_frames_with_resolver(resolver, gauges)
    }

    /// The COMPLETE profile flush for a thread that is about to terminate the
    /// WHOLE process: Linux `exit_group`, or an `exit(2)`/retirement that
    /// turned out to be the last live thread. The imminent `libc::_exit()`
    /// kills every other guest OS thread of this process instantly, with zero
    /// chance for any of them to run a line of its own code, `Drop` included.
    ///
    /// The three steps are ORDERED, and the order is load-bearing:
    ///
    /// 1. Claim THIS thread's own registry slot, so the drain in step 2 cannot
    ///    emit this thread's record from the (up to one iteration stale)
    ///    snapshot it published at the loop top -- this thread is alive and
    ///    running, and owns its own, current record.
    /// 2. Drain the siblings. Each one's record is emitted with structurally
    ///    zero process-wide resolver deltas (`drained_sibling_profile_snapshot`).
    /// 3. Flush THIS thread's own record LAST. Its `claim_profile_snapshot`
    ///    therefore assigns it the process epoch's ENTIRE outstanding
    ///    process-wide resolver delta -- including everything the siblings
    ///    accumulated right up to this instant. Nothing is dropped (as it
    ///    would be if this thread claimed BEFORE the drain and the siblings'
    ///    last microseconds of shared work went to nobody) and nothing is
    ///    double-counted: the delta is assigned exactly once, to this record.
    ///
    /// If ANOTHER thread's `exit_group` drain has already emitted this
    /// thread's record (two threads can call `exit_group` at once), step 1
    /// observes the `Drained` tombstone and step 3 correctly emits nothing.
    pub fn finalize_profile_epoch_at_process_exit(&mut self) {
        if !self.budget.enabled() {
            return;
        }
        let _ = self.claim_own_profile_emission();
        self.drain_sibling_profiles_before_process_exit();
        self.finalize_profile_epoch();
    }
}

impl Drop for ThreadTranslator {
    fn drop(&mut self) {
        self.finalize_profile_epoch();
    }
}

impl ProcessTranslator {
    pub fn new(capacity: usize) -> Result<Self, types::DsrError> {
        Self::new_with_host(capacity, active_host_jit()?)
    }

    fn new_with_host(
        capacity: usize,
        host: &'static dyn NativeHostJit,
    ) -> Result<Self, types::DsrError> {
        artifact_spike::ensure_authority_if_enabled()?;
        let cache = cache::TranslationCache::new(capacity, host)?;
        let cache_range = cache.host_range();
        let translator = Self {
            private_target_authority: Box::new(gateway::TargetCacheAuthority::new(
                cache_range.start,
                cache_range.end,
                std::ptr::null(),
            )),
            private_jit_epoch: crate::direct_binding::PrivateJitEpoch::process_owner(),
            exec_reset_identity: Arc::new(DirectBindingExecProcessIdentity),
            state: RwLock::new(ProcessState {
                cache,
                artifact_store: artifact_spike::store_if_enabled()?,
                blocks: BTreeMap::new(),
                pending: BTreeMap::new(),
                stats: ResolverStats::default(),
                reported_stats: ResolverStats::default(),
                sensitive: BTreeMap::new(),
                exclusive_fusion_sites: std::array::from_fn(|_| BTreeSet::new()),
                unsupported: BTreeMap::new(),
                published: Vec::new(),
                private_published_index: Vec::new(),
                shared_published_index: Vec::new(),
                dependencies: cache::PageBlockDependencies::default(),
                profiling: std::env::var_os("CARRICK_DSR_PROFILE").is_some(),
                artifact_image_digest: None,
                shared_translation: None,
                shared_blocks: BTreeMap::new(),
                shared_guest_ranges: Vec::new(),
                loaded_shared_units: Vec::new(),
                shared_unit_segments_consulted: BTreeSet::new(),
                shared_recording_segments: BTreeSet::new(),
                shared_candidates: BTreeMap::new(),
                shared_publish_attempted: false,
                direct_bindings: crate::direct_binding::DirectBindingRegistry::new(
                    crate::shared_cache::direct_binding_runtime_enabled(),
                ),
                executable_ranges: gateway::ExecutableRangeCatalog::new(
                    cache_range.start,
                    cache_range.end,
                )?,
                superblock_segments: block::superblock_segment_limit(),
            }),
        };
        probes::dsr_cache_capacity(
            probes::DsrCacheRole::Common,
            u64::try_from(capacity).unwrap_or(u64::MAX),
        );
        // Publish the cache's host-VA bounds so a profiler can classify a sampled
        // PC as JIT or host without unwinding it.
        probes::dsr_cache_bounds(cache_range.start as u64, cache_range.end as u64);
        Ok(translator)
    }

    pub fn cache_host_range(&self) -> std::ops::Range<u64> {
        let range = self.state.read().cache.host_range();
        range.start as u64..range.end as u64
    }

    /// Copy the published JIT code and the guest-to-cache block index for
    /// offline diagnostics (the sampled-PC shape census). Callers must hold
    /// no writer expectations: the read guard excludes emitters, and at the
    /// process-exit seam where this runs no sibling thread is left to patch
    /// direct links.
    pub fn code_snapshot(&self) -> CodeSnapshot {
        let state = self.state.read();
        let range = state.cache.host_range();
        let used = state.cache.used_bytes().min(range.end - range.start);
        // SAFETY: `[range.start, range.start + used)` is this process's own
        // live JIT mapping (readable for the process lifetime), and the state
        // read guard held above excludes every cache writer.
        let code = unsafe { std::slice::from_raw_parts(range.start as *const u8, used) }.to_vec();
        let blocks = state
            .blocks
            .iter()
            .map(|((guest, _generation), entry)| (guest.raw(), entry.host().0 as u64))
            .collect();
        CodeSnapshot {
            cache_base: range.start as u64,
            code,
            blocks,
        }
    }

    pub fn configure_shared_image(
        &self,
        image: crate::shared_cache::SharedImageConfig,
        store: Arc<dyn crate::shared_cache::TranslationUnitStore>,
    ) -> Result<(), types::DsrError> {
        if image.segments.is_empty() {
            return Err(types::DsrError::CachePolicy(
                "shared translation image has no executable segments".to_string(),
            ));
        }
        let mut state = self.state.write();
        if state.shared_translation.is_some() {
            return Err(types::DsrError::CachePolicy(
                "shared translation image was already configured".to_string(),
            ));
        }
        state.shared_translation = Some(SharedTranslationConfiguration { image, store });
        Ok(())
    }

    pub fn configure_artifact_image_digest(
        &self,
        executable_digest: [u8; 32],
    ) -> Result<(), types::DsrError> {
        let mut state = self.state.write();
        if state
            .artifact_image_digest
            .replace(executable_digest)
            .is_some()
        {
            return Err(types::DsrError::CachePolicy(
                "artifact executable identity was already configured".to_string(),
            ));
        }
        Ok(())
    }

    pub fn publish_shared_candidates(
        &self,
        memory: &NativeMappedMemory,
    ) -> Result<Vec<crate::shared_cache::PublishOutcome>, types::DsrError> {
        let (configuration, mut batches) = {
            let mut state = self.state.write();
            if state.shared_publish_attempted {
                return Ok(Vec::new());
            }
            state.shared_publish_attempted = true;
            let Some(configuration) = state.shared_translation.as_ref() else {
                return Ok(Vec::new());
            };
            let configuration = (
                configuration.image.clone(),
                Arc::clone(&configuration.store),
            );
            let batches = std::mem::take(&mut state.shared_candidates);
            (configuration, batches)
        };
        let (image, store) = configuration;
        let mut outcomes = Vec::new();
        let binding_layout = if crate::shared_cache::direct_binding_runtime_enabled() {
            crate::shared_cache::DirectBindingLayout::SidecarV1
        } else {
            crate::shared_cache::DirectBindingLayout::Disabled
        };
        for segment in &image.segments {
            let Some(candidates) = batches.remove(&segment.guest_start) else {
                continue;
            };
            if candidates.is_empty()
                || candidates.iter().any(|candidate| {
                    match memory.dsr_generation_observation(candidate.guest_start) {
                        Ok(observation) => observation.expected() != types::CodeGeneration::INITIAL,
                        Err(_) => true,
                    }
                })
            {
                continue;
            }
            let pending = crate::shared_cache::PendingTranslationUnit::pack(
                image.key_for_segment(segment),
                candidates,
                binding_layout,
            )?;
            let outcome = store.publish(&pending).map_err(|reason| {
                types::DsrError::CachePolicy(format!(
                    "shared translation publication failed: {reason:?}"
                ))
            })?;
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    #[doc(hidden)]
    pub fn configured_shared_segment_count(&self) -> usize {
        self.state
            .read()
            .shared_translation
            .as_ref()
            .map_or(0, |configuration| configuration.image.segments.len())
    }

    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn enable_direct_bindings_for_test(&self) {
        self.state.write().direct_bindings =
            crate::direct_binding::DirectBindingRegistry::new(true);
    }

    #[doc(hidden)]
    pub fn lifecycle_snapshot(&self) -> (u64, u64, u64) {
        let state = self.state.read();
        (
            u64::try_from(state.cache.used_bytes()).unwrap_or(u64::MAX),
            u64::try_from(state.blocks.len()).unwrap_or(u64::MAX),
            u64::try_from(state.dependencies.page_count()).unwrap_or(u64::MAX),
        )
    }

    pub fn after_fork_child(&self) -> crate::direct_binding::ForkBindingClearStats {
        let mut state = self.state.write();
        let direct_binding_stats = state
            .direct_bindings
            .clear_inherited_after_fork_with_recorder(|cell| {
                probes::dsr_cache_event(
                    0,
                    probes::DsrCacheEventKind::DirectBindingClear,
                    cell.get() as u64,
                    crate::direct_binding::DirectBindingClearReason::ForkReset.raw(),
                    0,
                );
            });
        state.cache.after_fork_child();
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        let capacity = u64::try_from(state.cache.capacity_bytes()).unwrap_or(u64::MAX);
        drop(state);
        probes::dsr_cache_capacity(probes::DsrCacheRole::Child, capacity);
        direct_binding_stats
    }

    pub fn reset_after_fork_for_exec(
        &self,
        thread: &ThreadTranslator,
        token: &mut DirectBindingExecResetToken,
    ) -> Result<crate::direct_binding::ExecBindingClearStats, types::DsrError> {
        self.reset_after_fork_for_exec_inner(thread, token, |_| {})
    }

    #[cfg(test)]
    pub(crate) fn reset_after_fork_for_exec_with_recorder(
        &self,
        thread: &ThreadTranslator,
        token: &mut DirectBindingExecResetToken,
        recorder: impl FnMut(DirectBindingResetEvent),
    ) -> Result<crate::direct_binding::ExecBindingClearStats, types::DsrError> {
        self.reset_after_fork_for_exec_inner(thread, token, recorder)
    }

    fn reset_after_fork_for_exec_inner(
        &self,
        thread: &ThreadTranslator,
        token: &mut DirectBindingExecResetToken,
        mut recorder: impl FnMut(DirectBindingResetEvent),
    ) -> Result<crate::direct_binding::ExecBindingClearStats, types::DsrError> {
        token.consume_for(self, thread)?;
        let mut state = self.state.write();
        let clear_stats = state.direct_bindings.clear_all_before_exec_with_evidence(
            |phase| match phase {
                crate::direct_binding::DirectBindingExecClearPhase::Cells => {
                    recorder(DirectBindingResetEvent::CellsCleared);
                    recorder(DirectBindingResetEvent::ThreadCachesCleared);
                }
                crate::direct_binding::DirectBindingExecClearPhase::Indexes => {
                    recorder(DirectBindingResetEvent::IndexesCleared);
                }
                crate::direct_binding::DirectBindingExecClearPhase::Descriptors => {
                    recorder(DirectBindingResetEvent::DescriptorsDropped);
                    assert_eq!(
                        Arc::strong_count(&self.private_jit_epoch),
                        1,
                        "private JIT cursor cannot reset while a descriptor epoch lease survives"
                    );
                }
            },
            |cell| {
                probes::dsr_cache_event(
                    thread.tid,
                    probes::DsrCacheEventKind::DirectBindingClear,
                    cell.get() as u64,
                    crate::direct_binding::DirectBindingClearReason::ExecReset.raw(),
                    0,
                );
            },
        );
        state.executable_ranges.reset_head_to_private();
        recorder(DirectBindingResetEvent::ExecutableRangeHeadReset);
        state.shared_blocks.clear();
        state.shared_guest_ranges.clear();
        state.loaded_shared_units.clear();
        recorder(DirectBindingResetEvent::UnitsDropped);
        state.executable_ranges.drop_shared_nodes();
        recorder(DirectBindingResetEvent::ExecutableRangeNodesDropped);
        state.clear_published();
        state.blocks.clear();
        state.pending.clear();
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        state.sensitive.clear();
        state.unsupported.clear();
        state.dependencies = cache::PageBlockDependencies::default();
        state.shared_translation = None;
        state.shared_unit_segments_consulted.clear();
        state.shared_recording_segments.clear();
        state.shared_candidates.clear();
        state.shared_publish_attempted = false;
        state.cache.reset_after_fork_for_exec();
        recorder(DirectBindingResetEvent::PrivateCursorReset);
        Ok(clear_stats)
    }

    #[cfg(test)]
    pub fn private_epoch_leases_for_test(&self) -> usize {
        crate::direct_binding::PrivateJitEpoch::live_descriptor_leases(&self.private_jit_epoch)
    }
}

impl ProcessState {
    fn try_load_shared_unit(
        &mut self,
        tid: i32,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
    ) -> Result<Option<types::CacheVa>, types::DsrError> {
        if generation != types::CodeGeneration::INITIAL {
            return Ok(None);
        }
        let Some(configuration) = &self.shared_translation else {
            return Ok(None);
        };
        let Some(segment) = configuration.image.segments.iter().find(|segment| {
            segment
                .guest_start
                .raw()
                .checked_add(segment.guest_len.get())
                .is_some_and(|end| (segment.guest_start.raw()..end).contains(&guest.raw()))
        }) else {
            return Ok(None);
        };
        let segment_start = segment.guest_start;
        if !self.shared_unit_segments_consulted.insert(segment_start) {
            return Ok(None);
        }
        let key = configuration.image.key_for_segment(segment);
        let source_words = Arc::clone(&segment.source_words);
        let store = Arc::clone(&configuration.store);
        self.stats.shared_unit_lookups = self.stats.shared_unit_lookups.saturating_add(1);
        let mut unit = match store.load(&key, &source_words) {
            Ok(Some(unit)) => unit,
            Ok(None) => {
                if store.claim_recording(&key) {
                    self.shared_recording_segments.insert(segment_start);
                }
                return Ok(None);
            }
            Err(_) => return Ok(None),
        };
        self.stats.shared_unit_loads = self.stats.shared_unit_loads.saturating_add(1);
        let binding_count = unit
            .manifest
            .blocks
            .iter()
            .map(|block| block.generation_binding as usize)
            .max()
            .map_or(0, |index| index.saturating_add(1));
        if binding_count == 0 || binding_count > unit.manifest.blocks.len() {
            return Err(types::DsrError::CachePolicy(
                "shared translation unit has invalid generation bindings".to_string(),
            ));
        }
        let mut bindings = std::iter::repeat_with(|| None)
            .take(binding_count)
            .collect::<Vec<_>>();
        let mut observations = Vec::with_capacity(unit.manifest.blocks.len());
        for block in &unit.manifest.blocks {
            let observation = memory.dsr_generation_observation(block.guest_start)?;
            if observation.expected() != types::CodeGeneration::INITIAL {
                return Ok(None);
            }
            let slot = bindings
                .get_mut(block.generation_binding as usize)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "shared generation binding index is out of range".to_string(),
                    )
                })?;
            if slot.is_some() {
                return Err(types::DsrError::CachePolicy(
                    "shared generation binding index is duplicated".to_string(),
                ));
            }
            *slot = Some(gateway::GenerationBinding::new(
                observation.current_atomic(),
                types::CodeGeneration::INITIAL,
            ));
            observations.push(observation);
        }
        let generation_bindings = bindings
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                types::DsrError::CachePolicy(
                    "shared generation binding table has a hole".to_string(),
                )
            })?
            .into_boxed_slice();
        let bindings_pointer = generation_bindings.as_ptr() as usize;
        let cache_start = unit.base;
        let cache_end = cache_start
            .checked_add(unit.manifest.code_len as usize)
            .ok_or_else(|| {
                types::DsrError::CachePolicy("shared translation range overflow".to_string())
            })?;
        let target_authority = Box::new(gateway::TargetCacheAuthority::new(
            cache_start,
            cache_end,
            generation_bindings.as_ptr(),
        ));
        let target_authority_pointer = target_authority.as_ref() as *const _;
        let loaded_unit_index = self.loaded_shared_units.len();
        let direct_binding_unit_index = self.direct_bindings.register_loaded_unit(&unit)?;
        let direct_binding_unit_digest =
            crate::direct_binding::direct_binding_unit_digest(&unit.manifest.key)?;
        let direct_binding_record_count =
            u64::try_from(unit.manifest.bindings.len()).unwrap_or(u64::MAX);
        let direct_binding_data_bytes = unit.manifest.binding_data_len;
        let host_bias = unit.manifest.key.host_bias();
        for (block, observation) in unit.manifest.blocks.iter_mut().zip(observations) {
            let address = cache_start
                .checked_add(block.entry_offset as usize)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy("shared block address overflow".to_string())
                })?;
            let entry = types::CacheVa::published(carrick_guest_mem::HostVa(address));
            let (map, recovery, _direct_links) = block.template.take_runtime_metadata(host_bias)?;
            let block_key = (block.guest_start, types::CodeGeneration::INITIAL);
            if block.requires_sensitive_metadata {
                let planned = block::plan_block(
                    memory,
                    block.guest_start,
                    types::CodeGeneration::INITIAL,
                    256,
                )?;
                let block::PlannedExit::Sensitive { exit, fusion, .. } = planned.exit else {
                    return Err(types::DsrError::CachePolicy(format!(
                        "shared block 0x{:x} lost sensitive metadata identity",
                        block.guest_start.raw(),
                    )));
                };
                self.sensitive
                    .insert(block_key, SensitiveMetadata { exit, fusion });
            }
            self.push_published(PublishedBlock {
                entry,
                len: block.code_len as usize,
                map,
                recovery,
                _generation: observation.clone(),
            });
            self.blocks.insert(block_key, entry);
            self.dependencies.record(
                observation.page(),
                block.guest_start,
                observation.expected(),
            );
            if let Some(end) = block
                .guest_start
                .raw()
                .checked_add((block.template.source_words().len() as u64) * 4)
            {
                // Guest extent comes from the SOURCE words; `code_len` is the
                // emitted cache length and bears no fixed relation to the span of
                // guest instructions the block covers.
                self.shared_guest_ranges
                    .push((block.guest_start, carrick_guest_mem::GuestVa(end)));
            }
            self.shared_blocks.insert(
                block_key,
                SharedBlockAuthority {
                    generation_bindings: bindings_pointer,
                    generation_binding_count: generation_bindings.len(),
                    cache_start,
                    cache_end,
                    target_authority: target_authority_pointer as usize,
                    loaded_unit_index,
                },
            );
        }
        self.shared_guest_ranges.sort_unstable();
        self.stats.shared_blocks_mapped = self
            .stats
            .shared_blocks_mapped
            .saturating_add(unit.manifest.blocks.len() as u64);
        self.loaded_shared_units.push(LoadedSharedUnit {
            _unit: unit,
            _generation_bindings: generation_bindings,
            _target_authority: target_authority,
            _direct_binding_unit_index: direct_binding_unit_index,
        });
        self.executable_ranges.prepend(cache_start, cache_end)?;
        probes::dsr_cache_event(
            tid,
            probes::DsrCacheEventKind::DirectBindingUnitLoaded,
            direct_binding_unit_digest,
            direct_binding_record_count,
            direct_binding_data_bytes,
        );
        let result = self.blocks.get(&(guest, generation)).copied();
        if result.is_some() {
            self.stats.shared_unit_hits = self.stats.shared_unit_hits.saturating_add(1);
            self.stats.shared_translations_avoided =
                self.stats.shared_translations_avoided.saturating_add(1);
        }
        Ok(result)
    }

    pub fn record_exclusive_fusion_site(&mut self, site: types::ExclusiveFusionSite) {
        if !self.profiling {
            return;
        }
        let class = profile::ExclusiveFusionClass::from(site.disposition);
        self.exclusive_fusion_sites[class.index()].insert((site.guest.raw(), site.word));
    }

    pub fn exclusive_fusion_site_counts(&self) -> [u64; profile::ExclusiveFusionClass::COUNT] {
        std::array::from_fn(|index| {
            u64::try_from(self.exclusive_fusion_sites[index].len()).unwrap_or(u64::MAX)
        })
    }

    /// Read-only warm-cache-hit lookup: the fast path for
    /// `ThreadTranslator::translate` under `ProcessTranslator::state.read()`.
    /// Never mutates -- callable concurrently from any number of readers.
    ///
    /// `blocks` is keyed by `(guest, generation)`, and `generation` here MUST
    /// be the CALLER'S freshly observed current generation (the same value
    /// `translate` derives from `memory.dsr_generation_observation(guest)`).
    /// That is what makes this safe without replicating `translate`'s
    /// `invalidate_page` step: a stale (pre-mutation) block is stored under
    /// its OLD generation key, so once the guest page is modified, the
    /// current generation changes and `blocks.get(&(guest, generation))` for
    /// the NEW generation can never observe the old entry -- it simply isn't
    /// there yet. The stale entry is only actually removed from `blocks` by
    /// `translate`'s `invalidate_page` on the write path, but a caller keyed
    /// on the current generation never matches it regardless, so skipping
    /// that cleanup here is safe, not just fast.
    pub fn cached_block(
        &self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
    ) -> Option<types::CacheVa> {
        self.blocks.get(&(guest, generation)).copied()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "publication consumes the complete translation result and profiling context"
    )]
    fn publish_emitted(
        &mut self,
        memory: &NativeMappedMemory,
        key: (carrick_guest_mem::GuestVa, types::CodeGeneration),
        source_page: carrick_guest_mem::GuestVa,
        observation: cache::PageGenerationObservation,
        emitted: emit::EmittedBlock,
        emitted_bytes: u64,
        outcome: TranslationOutcome,
    ) -> Result<TranslationResult, types::DsrError> {
        let entry = emitted.entry();
        // `ProcessState::translate` owns `&mut self` from the process
        // translator's write guard. It re-checks `blocks` after acquiring
        // that guard, then retains exclusive access through this publication.
        // A second mutex-protected publication index cannot arbitrate a race
        // here: Rust already makes a concurrent `&mut ProcessState`
        // impossible. The former index performed two mutex acquisitions and
        // two BTreeMap mutations for every newly translated block while
        // recording zero duplicate publications in production profiles.
        let emitted_len = emitted.len();
        let (map, links, recovery) = emitted.into_runtime_metadata();
        self.push_published(PublishedBlock {
            entry,
            len: emitted_len,
            map,
            recovery,
            _generation: observation,
        });
        self.blocks.insert(key, entry);
        self.dependencies.record(source_page, key.0, key.1);
        for link in links {
            let target_generation = memory.dsr_generation_observation(link.target)?.expected();
            let target_key = (link.target, target_generation);
            let site = cache::LinkSite {
                source: entry,
                slot: link.slot,
            };
            if let Some(target) = self.blocks.get(&target_key)
                && !self.shared_blocks.contains_key(&target_key)
            {
                let word = encode_aarch64_direct_branch(site, *target)?;
                self.cache.patch_code_word(site, word)?;
            } else {
                self.pending.entry(target_key).or_default().push(site);
            }
        }
        if let Some(sites) = self.pending.remove(&key) {
            for site in sites {
                let word = encode_aarch64_direct_branch(site, entry)?;
                self.cache.patch_code_word(site, word)?;
            }
        }
        Ok(TranslationResult {
            entry,
            generation: key.1,
            outcome,
            emitted_bytes,
            cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
        })
    }

    #[doc(hidden)]
    pub fn translate(
        &mut self,
        tid: i32,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<TranslationResult, types::DsrError> {
        let observation = memory.dsr_generation_observation(guest)?;
        let source_page = observation.page();
        let generation = observation.expected();
        let stale_blocks = self.dependencies.invalidate_page(source_page, generation);
        if self.profiling {
            self.stats
                .add_usize(ResolverStat::InvalidatedBlocks, stale_blocks.len());
        }
        for stale in stale_blocks {
            self.direct_bindings
                .invalidate_target_with_recorder(stale.0, stale.1, |cell| {
                    probes::dsr_cache_event(
                        tid,
                        probes::DsrCacheEventKind::DirectBindingClear,
                        cell.get() as u64,
                        crate::direct_binding::DirectBindingClearReason::TargetInvalidation.raw(),
                        stale.1.get(),
                    );
                });
            self.blocks.remove(&stale);
            self.shared_blocks.remove(&stale);
            probes::dsr_cache_event(
                tid,
                probes::DsrCacheEventKind::Invalidate,
                stale.0.raw(),
                stale.1.get(),
                u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            );
        }
        let key = (guest, generation);
        if self.profiling {
            self.stats.add(ResolverStat::CacheLookups, 1);
        }
        if let Some(entry) = self.blocks.get(&key) {
            if self.profiling {
                self.stats.add(ResolverStat::CacheLookupHits, 1);
            }
            probes::dsr_cache_event(
                tid,
                probes::DsrCacheEventKind::BlockHit,
                guest.raw(),
                generation.get(),
                u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            );
            return Ok(TranslationResult {
                entry: *entry,
                generation,
                outcome: TranslationOutcome::BlockIndexHit,
                emitted_bytes: 0,
                cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            });
        }
        if let Some(entry) = self.try_load_shared_unit(tid, memory, guest, generation)? {
            return Ok(TranslationResult {
                entry,
                generation,
                outcome: TranslationOutcome::SharedUnit,
                emitted_bytes: 0,
                cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            });
        }
        probes::dsr_cache_event(
            tid,
            probes::DsrCacheEventKind::BlockMiss,
            guest.raw(),
            generation.get(),
            u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
        );
        probes::dsr_translate_begin(tid, guest.raw(), generation.get());
        let translation_started = self.profiling.then(std::time::Instant::now);
        let artifact_address_mode: emit::EmitAddressMode = memory.address_mode().into();
        let artifact_store_present = self.artifact_store.is_some();
        let artifact_lookup_allowed = self
            .artifact_store
            .as_ref()
            .is_some_and(|store| store.may_contain_guest(guest, artifact_address_mode));
        let artifact_image_key = artifact_store_present
            .then(|| {
                (generation == types::CodeGeneration::INITIAL)
                    .then_some(self.artifact_image_digest)
                    .flatten()
                    .map(|digest| {
                        artifact_spike::ArtifactKey::from_image_digest(
                            guest,
                            digest,
                            artifact_address_mode,
                        )
                    })
            })
            .flatten();
        let artifact_key_words = (artifact_store_present && artifact_image_key.is_none())
            .then(|| {
                memory
                    .instruction_fingerprint_words(guest, ARTIFACT_KEY_PREFIX_INSTRUCTIONS)
                    .ok()
            })
            .flatten();
        let artifact_key = artifact_image_key.or_else(|| {
            artifact_key_words.as_ref().map(|words| {
                artifact_spike::ArtifactKey::from_source(guest, words, artifact_address_mode)
            })
        });
        let result = (|| -> Result<TranslationResult, types::DsrError> {
            let mut artifact_template = if artifact_lookup_allowed {
                artifact_key.and_then(|artifact_key| {
                    self.artifact_store
                        .as_ref()
                        .and_then(|store| store.lookup(artifact_key).ok().flatten())
                })
            } else {
                None
            };
            let artifact_matches = artifact_template.as_ref().is_some_and(|template| {
                artifact_image_key.is_some()
                    || memory
                        .instruction_fingerprint_words(guest, template.source_words().len())
                        .is_ok_and(|words| template.matches_source(&words))
            });
            if !artifact_spike::validate_fresh_enabled()
                && artifact_matches
                && let Some(template) = artifact_template.take()
            {
                let bindings = artifact_spike::ArtifactBindings::for_replay(
                    observation.current_atomic() as *const std::sync::atomic::AtomicU64 as u64,
                    generation.get(),
                    artifact_address_mode,
                )?;
                let replay_started = std::time::Instant::now();
                if let Ok(emitted) =
                    artifact_spike::replay_artifact_owned(&mut self.cache, template, &bindings)
                {
                    if let Some(store) = &self.artifact_store {
                        store.record_replay_ns(
                            u64::try_from(replay_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                        );
                    }
                    if observation.current() != generation {
                        return Err(types::DsrError::GenerationChanged {
                            page: guest.raw(),
                            expected: generation.get(),
                            observed: observation.current().get(),
                        });
                    }
                    let emitted_bytes = u64::try_from(emitted.len()).unwrap_or(u64::MAX);
                    probes::dsr_cache_event(
                        tid,
                        probes::DsrCacheEventKind::BlockPublish,
                        guest.raw(),
                        generation.get(),
                        u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
                    );
                    return self.publish_emitted(
                        memory,
                        key,
                        source_page,
                        observation,
                        emitted,
                        emitted_bytes,
                        TranslationOutcome::ArtifactReplay,
                    );
                }
            }
            probes::dsr_translate_subphase_begin(
                tid,
                probes::DsrTranslationSubphase::Decode,
                guest.raw(),
                generation.get(),
            );
            let decode_started = self.profiling.then(std::time::Instant::now);
            let block_result = block::plan_block_with_segments(
                memory,
                guest,
                generation,
                256,
                self.superblock_segments,
            );
            if let Some(started) = decode_started {
                self.stats
                    .add_elapsed(ResolverStat::TranslationDecodeNs, started.elapsed());
            }
            probes::dsr_translate_subphase_end(
                tid,
                probes::DsrTranslationSubphase::Decode,
                guest.raw(),
                generation.get(),
            );
            let block = block_result?;
            let block_word_count = usize::try_from(
                block
                    .end
                    .raw()
                    .saturating_sub(block.start.raw())
                    .checked_div(4)
                    .unwrap_or(0),
            )
            .unwrap_or(0);
            let block_source_words = translation_source_words_required(
                self.artifact_store.is_some(),
                self.shared_translation.is_some(),
            )
            .then(|| {
                memory
                    .instruction_fingerprint_words(guest, block_word_count)
                    .ok()
                    .filter(|words| words.len() == block_word_count)
            })
            .flatten();
            let artifact_source_words = if self.artifact_store.is_some() {
                block_source_words.clone()
            } else {
                None
            };

            probes::dsr_translate_subphase_begin(
                tid,
                probes::DsrTranslationSubphase::Plan,
                guest.raw(),
                generation.get(),
            );
            let plan_started = self.profiling.then(std::time::Instant::now);
            let plan_result = (|| -> Result<(), types::DsrError> {
                if observation.current() != generation {
                    return Err(types::DsrError::GenerationChanged {
                        page: guest.raw(),
                        expected: generation.get(),
                        observed: observation.current().get(),
                    });
                }
                // The TERMINAL exit, not `block.exit`: superblock formation
                // makes `block.exit` the first segment's exit, which for a
                // fused plan is an internal conditional edge. Only the last
                // segment can carry sensitive/unsupported metadata, because
                // extension stops at anything that is not a conditional
                // branch.
                match block.terminal_exit() {
                    block::PlannedExit::Sensitive {
                        guest: sensitive_guest,
                        exit,
                        fusion,
                        ..
                    } => {
                        if let Some(site) = fusion {
                            self.record_exclusive_fusion_site(site);
                        }
                        self.sensitive.insert(
                            (sensitive_guest, generation),
                            SensitiveMetadata { exit, fusion },
                        );
                    }
                    block::PlannedExit::ExclusiveRegion {
                        guest: sensitive_guest,
                        exit,
                        fusion,
                        ..
                    } => {
                        self.record_exclusive_fusion_site(fusion);
                        self.sensitive.insert(
                            (sensitive_guest, generation),
                            SensitiveMetadata {
                                exit: exit.fallback,
                                fusion: Some(fusion),
                            },
                        );
                    }
                    _ => {}
                }
                if let block::PlannedExit::Unsupported {
                    guest: unsupported_guest,
                    word,
                    op,
                } = block.terminal_exit()
                {
                    self.unsupported
                        .insert((unsupported_guest, generation), (word, op));
                }
                Ok(())
            })();
            if let Some(started) = plan_started {
                self.stats
                    .add_elapsed(ResolverStat::TranslationPlanNs, started.elapsed());
            }
            probes::dsr_translate_subphase_end(
                tid,
                probes::DsrTranslationSubphase::Plan,
                guest.raw(),
                generation.get(),
            );
            plan_result?;

            probes::dsr_translate_subphase_begin(
                tid,
                probes::DsrTranslationSubphase::Emit,
                guest.raw(),
                generation.get(),
            );
            let emit_started = self.profiling.then(std::time::Instant::now);
            let emitted_result = (|| {
                let portable_segment = self
                    .shared_translation
                    .as_ref()
                    .and_then(|configuration| {
                        configuration.image.segments.iter().find(|segment| {
                            let segment_end = segment
                                .guest_start
                                .raw()
                                .checked_add(segment.guest_len.get());
                            segment_end.is_some_and(|end| {
                                block.start.raw() >= segment.guest_start.raw()
                                    && block.end.raw() <= end
                            })
                        })
                    })
                    .map(|segment| segment.guest_start);
                let portable_candidate = if generation == types::CodeGeneration::INITIAL
                    && let Some(segment) = portable_segment
                    && self.shared_recording_segments.contains(&segment)
                    && let Some(source_words) = block_source_words.clone()
                    // Superblocks are deliberately out of scope for the shared
                    // and artifact caches in this slice: both key a template on
                    // one block's source words and replay it byte-for-byte, and
                    // neither has been proven against a plan whose emitted unit
                    // spans several guest blocks. A fused block simply takes the
                    // plain emit path -- a lost cache hit, never wrong code.
                    && block.extensions.is_empty()
                    && matches!(
                        block.terminal_exit(),
                        block::PlannedExit::Syscall { .. }
                            | block::PlannedExit::Direct { .. }
                            | block::PlannedExit::Indirect { .. }
                            | block::PlannedExit::Sensitive { .. }
                            | block::PlannedExit::Continue { .. }
                    ) {
                    let binding = self.shared_candidates.get(&segment).map_or(0, Vec::len);
                    u32::try_from(binding).ok().and_then(|generation_binding| {
                        emit::record_portable_block_artifact(
                            &block,
                            generation_binding,
                            memory.address_mode().into(),
                            source_words,
                        )
                        .ok()
                        .map(|artifact| {
                            (
                                segment,
                                crate::shared_cache::PortableBlockCandidate {
                                    guest_start: block.start,
                                    generation_binding,
                                    requires_sensitive_metadata: matches!(
                                        block.terminal_exit(),
                                        block::PlannedExit::Sensitive { .. }
                                    ),
                                    template: artifact.template,
                                },
                            )
                        })
                    })
                } else {
                    None
                };
                let artifact_eligible = self
                    .artifact_store
                    .as_ref()
                    .is_some_and(artifact_spike::ArtifactStore::accepting_inserts)
                    && artifact_key.is_some()
                    && artifact_source_words.is_some()
                    && block_word_count >= artifact_spike::minimum_source_words()
                    && block.extensions.is_empty()
                    && matches!(
                        block.terminal_exit(),
                        block::PlannedExit::Syscall { .. }
                            | block::PlannedExit::Direct { .. }
                            | block::PlannedExit::Indirect { .. }
                            | block::PlannedExit::Continue { .. }
                    );
                let (emitted, artifact) = if artifact_eligible {
                    emit::emit_block_recording_artifact_optional(
                        &mut self.cache,
                        &block,
                        emit::GenerationGuard::new(observation.current_atomic(), generation),
                        memory.address_mode().into(),
                        artifact_source_words.clone().unwrap_or_default(),
                    )?
                } else {
                    (
                        emit::emit_block_with_generation(
                            &mut self.cache,
                            &block,
                            emit::GenerationGuard::new(observation.current_atomic(), generation),
                            memory.address_mode().into(),
                        )?,
                        None,
                    )
                };
                if let (Some(store), Some(artifact_key), Some(artifact)) = (
                    self.artifact_store.as_ref(),
                    artifact_key,
                    artifact.as_ref(),
                ) {
                    if artifact_spike::validate_fresh_enabled()
                        && let Some(stored) = artifact_template.as_ref()
                        && let Some(mismatch) = stored.mismatch_summary(&artifact.template)
                    {
                        return Err(types::DsrError::CachePolicy(format!(
                            "artifact fresh-validation mismatch at guest 0x{:x} in \
                             {artifact_address_mode:?}: {mismatch}",
                            guest.raw()
                        )));
                    }
                    if artifact_spike::validate_fresh_enabled() && artifact_template.is_some() {
                        let replay_bindings = artifact_spike::ArtifactBindings::for_replay(
                            observation.current_atomic() as *const std::sync::atomic::AtomicU64
                                as u64,
                            generation.get(),
                            artifact_address_mode,
                        )?;
                        if let Some(mismatch) = artifact.bindings.mismatch_summary(&replay_bindings)
                        {
                            return Err(types::DsrError::CachePolicy(format!(
                                "artifact fresh-validation binding mismatch at guest 0x{:x} in \
                                 {artifact_address_mode:?}: {mismatch}",
                                guest.raw()
                            )));
                        }
                    }
                    let _ = store.insert(artifact_key, &artifact.template);
                } else if artifact_spike::validate_fresh_enabled() && artifact_template.is_some() {
                    return Err(types::DsrError::CachePolicy(format!(
                        "artifact fresh-validation could not record guest 0x{:x} in \
                         {artifact_address_mode:?}",
                        guest.raw()
                    )));
                }
                let emitted_bytes = u64::try_from(emitted.len()).unwrap_or(u64::MAX);
                probes::dsr_cache_event(
                    tid,
                    probes::DsrCacheEventKind::BlockPublish,
                    guest.raw(),
                    generation.get(),
                    u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
                );
                if observation.current() != generation {
                    return Err(types::DsrError::GenerationChanged {
                        page: guest.raw(),
                        expected: generation.get(),
                        observed: observation.current().get(),
                    });
                }
                if let Some((segment, candidate)) = portable_candidate {
                    self.shared_candidates
                        .entry(segment)
                        .or_default()
                        .push(candidate);
                }
                if let Some(started) = translation_started {
                    self.stats
                        .add_elapsed(ResolverStat::TranslationNs, started.elapsed());
                }
                self.stats.add(ResolverStat::Translations, 1);
                Ok::<_, types::DsrError>((emitted, emitted_bytes))
            })();
            if let Some(started) = emit_started {
                self.stats
                    .add_elapsed(ResolverStat::TranslationEmitNs, started.elapsed());
            }
            probes::dsr_translate_subphase_end(
                tid,
                probes::DsrTranslationSubphase::Emit,
                guest.raw(),
                generation.get(),
            );
            let (emitted, emitted_bytes) = emitted_result?;

            probes::dsr_translate_subphase_begin(
                tid,
                probes::DsrTranslationSubphase::PublicationIndex,
                guest.raw(),
                generation.get(),
            );
            let publication_started = self.profiling.then(std::time::Instant::now);
            let publication_result = self.publish_emitted(
                memory,
                key,
                source_page,
                observation,
                emitted,
                emitted_bytes,
                TranslationOutcome::Translated,
            );
            if let Some(started) = publication_started {
                self.stats
                    .add_elapsed(ResolverStat::TranslationPublicationNs, started.elapsed());
            }
            probes::dsr_translate_subphase_end(
                tid,
                probes::DsrTranslationSubphase::PublicationIndex,
                guest.raw(),
                generation.get(),
            );
            publication_result
        })();

        let (cache_pc, emitted_bytes, outcome) = match &result {
            Ok(translated) => (
                translated.entry.host().raw() as u64,
                translated.emitted_bytes,
                probes::DsrOperationOutcome::Success,
            ),
            Err(error) => (0, 0, error.probe_outcome()),
        };
        probes::dsr_translate_end(tid, guest.raw(), cache_pc, emitted_bytes, outcome);
        if matches!(&result, Err(types::DsrError::CacheCapacity { .. })) {
            probes::dsr_cache_event(
                tid,
                probes::DsrCacheEventKind::CapacityFailure,
                guest.raw(),
                generation.get(),
                u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            );
        }
        result
    }

    /// Record one published block. THE publication point: both the private
    /// translation path and the shared-unit load path go through here so the
    /// block list and every index over it are updated together.
    ///
    /// `published` itself stays in publication order -- the fault diagnostic
    /// reports its bounds, and the block-index consumers walk it -- so the
    /// address ordering `guest_pc_for_cache` needs lives in the two side
    /// indexes instead.
    fn push_published(&mut self, block: PublishedBlock) {
        let entry = PublishedIndexEntry {
            start: block.entry.host(),
            block: self.published.len(),
        };
        // The private cache is a bump allocator: `begin_write` hands out
        // strictly increasing extents, and the one cursor rewind
        // (`reset_after_fork_for_exec`) clears `published` with it, so a
        // private block appends. A shared translation unit is dlopen'd into
        // its OWN mapping at a base unrelated to that cursor, so its blocks
        // can land below everything published so far -- they get their own
        // list rather than breaking the append the private list relies on.
        let index = if self.cache.host_range().contains(&entry.start.raw()) {
            &mut self.private_published_index
        } else {
            &mut self.shared_published_index
        };
        let at = match index.last() {
            Some(last) if last.start > entry.start => {
                index.partition_point(|indexed| indexed.start <= entry.start)
            }
            _ => index.len(),
        };
        index.insert(at, entry);
        self.published.push(block);
    }

    /// Drop every published block together with the indexes over them.
    /// Is `pc` inside a block mapped from a loaded shared unit?
    ///
    /// Binary search over the sorted ranges: this runs on every `ResolveDirect`
    /// under profiling, so it must not be a scan.
    fn shared_block_contains(&self, pc: carrick_guest_mem::GuestVa) -> bool {
        let ranges = &self.shared_guest_ranges;
        match ranges.binary_search_by(|(start, _)| start.raw().cmp(&pc.raw())) {
            // Exact hit on a block start.
            Ok(_) => true,
            // Otherwise the candidate is the range starting just below `pc`.
            Err(0) => false,
            Err(index) => {
                let (_, end) = ranges[index - 1];
                pc.raw() < end.raw()
            }
        }
    }

    fn clear_published(&mut self) {
        self.published.clear();
        self.private_published_index.clear();
        self.shared_published_index.clear();
    }

    /// The published block whose emitted extent contains `cache_pc`, if any.
    ///
    /// Each index is sorted by cache entry address and published extents are
    /// disjoint -- the private cache bump-allocates, and a shared unit owns
    /// its own mapping -- so the only candidate in an index is the last block
    /// starting at or below `cache_pc`. That makes this two binary searches
    /// rather than a scan of every block the process has ever translated
    /// (~132k after a cold `go build`), on a path every guest fault and every
    /// asynchronous kick runs.
    ///
    /// Resolves through `get` rather than indexing: an index that ever fell
    /// out of step with `published` must degrade into this function's existing
    /// "outside published DSR blocks" diagnostic, not panic a guest fault.
    fn published_block_containing(&self, cache_pc: usize) -> Option<&PublishedBlock> {
        [&self.private_published_index, &self.shared_published_index]
            .into_iter()
            .find_map(|index| {
                let at = index.partition_point(|indexed| indexed.start.raw() <= cache_pc);
                let block = self.published.get(index.get(at.checked_sub(1)?)?.block)?;
                let start = block.entry.host().raw();
                let end = start.checked_add(block.len)?;
                (start..end).contains(&cache_pc).then_some(block)
            })
    }

    fn guest_pc_for_cache(
        &self,
        cache_pc: carrick_guest_mem::GuestVa,
    ) -> Result<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>), types::DsrError> {
        let cache_pc = usize::try_from(cache_pc.raw()).map_err(|_| {
            types::DsrError::CachePolicy(format!(
                "cache PC does not fit host pointer: 0x{:x}",
                cache_pc.raw()
            ))
        })?;
        if let Some(block) = self.published_block_containing(cache_pc) {
            let start = block.entry.host().raw();
            let offset = u32::try_from(cache_pc - start).map_err(|_| {
                types::DsrError::CachePolicy("cache PC offset exceeds u32".to_string())
            })?;
            let guest = block
                .map
                .iter()
                .find(|entry| entry.cache == types::CacheOffset::published(offset))
                .map(|entry| entry.guest)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "cache PC 0x{cache_pc:x} is not an emitted instruction boundary"
                    ))
                })?;
            let recovery = block
                .recovery
                .iter()
                .find(|entry| entry.cache == types::CacheOffset::published(offset))
                .map(|entry| entry.action);
            return Ok((guest, recovery));
        }
        let first = self
            .published
            .first()
            .map(|block| (block.entry.host().raw(), block.len));
        let last = self
            .published
            .last()
            .map(|block| (block.entry.host().raw(), block.len));
        let in_cache = self
            .cache
            .contains_host_pc(carrick_guest_mem::HostVa(cache_pc));
        Err(types::DsrError::CachePolicy(format!(
            "cache PC 0x{cache_pc:x} is outside published DSR blocks \
             (in_cache={in_cache}, published={}, first={first:?}, last={last:?}, \
             signal_gateway=0x{:x}, common_gateway=0x{:x})",
            self.published.len(),
            gateway::signal_exit_address(),
            gateway::direct_exit_address(),
        )))
    }
}

impl ThreadTranslator {
    /// Two-phase translate: a fully concurrent READ fast path for a warm
    /// cache hit, falling back to the exclusive WRITE path (the existing,
    /// unchanged `ProcessState::translate`: invalidate + lookup + translate
    /// + insert) on a miss.
    ///
    /// The generation is derived the SAME way `ProcessState::translate`
    /// derives it (`memory.dsr_generation_observation(guest).expected()`) --
    /// this call is `&self` on `NativeMappedMemory` and touches only the
    /// per-page generation table (a different, cheap lock), never
    /// `ProcessState`. Recomputing it again inside the write-path `translate`
    /// on a miss is redundant but harmless (idempotent, no side effects on
    /// `ProcessState`).
    ///
    /// See `ProcessState::cached_block` for why a hit found here can never be
    /// a stale (pre-mutation) block, and
    /// `docs/superpowers/specs/2026-07-15-dsr-translation-cache-read-mostly-design.md`
    /// for the full design.
    fn translate_read_mostly(
        &mut self,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<TranslationResult, types::DsrError> {
        let generation = memory.dsr_generation_observation(guest)?.expected();
        // Per-thread fast path, taken BEFORE any lock. Every gateway exit reaches
        // this function, and the shared read guard below was measured as the
        // largest single leaf in the profile (`lock_shared_slow`, 8.2% of all
        // on-CPU time). The generation was just re-observed above, so a hit here
        // is exactly as fresh as one taken under the lock; see
        // `ThreadBlockCache`'s invalidation contract.
        if let Some((cached_generation, entry)) = self.block_cache.get(guest)
            && cached_generation == generation
        {
            self.stats.add(ResolverStat::OneEntryHits, 1);
            probes::dsr_cache_event(
                self.tid,
                probes::DsrCacheEventKind::BlockHit,
                guest.raw(),
                generation.get(),
                // Deliberately the LAST OBSERVED value, not a fresh read: fetching
                // it is what the lock is for, and this gauge is diagnostic only.
                self.last_cache_used_bytes,
            );
            return Ok(TranslationResult {
                entry,
                generation,
                outcome: TranslationOutcome::BlockIndexHit,
                emitted_bytes: 0,
                cache_used_bytes: self.last_cache_used_bytes,
            });
        }
        {
            // Scoped so the read guard is dropped before any write-path
            // fallback tries to acquire the write lock (RwLock is not
            // reentrant: read-then-write on the same thread would deadlock).
            let state = probes::acquire_with_synchronization_reason(
                probes::DsrSynchronizationKind::ProcessStateRead,
                || self.process.state.read(),
            );
            if let Some(entry) = state.cached_block(guest, generation) {
                let cache_used_bytes = u64::try_from(state.cache.used_bytes()).unwrap_or(u64::MAX);
                drop(state);
                self.last_cache_used_bytes = cache_used_bytes;
                self.block_cache.insert(guest, generation, entry);
                probes::dsr_cache_event(
                    self.tid,
                    probes::DsrCacheEventKind::BlockHit,
                    guest.raw(),
                    generation.get(),
                    cache_used_bytes,
                );
                return Ok(TranslationResult {
                    entry,
                    generation,
                    outcome: TranslationOutcome::BlockIndexHit,
                    emitted_bytes: 0,
                    cache_used_bytes,
                });
            }
        }
        // Miss under the read guard: fall through to the exclusive write
        // path. `ProcessState::translate` re-checks `blocks.get` itself as
        // its very first lookup (after a no-op `invalidate_page` when the
        // page hasn't changed), so a block another thread inserted in the
        // read-drop-to-write-acquire gap is found there -- no duplicate
        // translation -- and a genuine miss is translated exactly as before.
        let mut state = probes::acquire_with_synchronization_reason(
            probes::DsrSynchronizationKind::ProcessStateWrite,
            || self.process.state.write(),
        );
        let translated = state.translate(self.tid, memory, guest)?;
        drop(state);
        self.last_cache_used_bytes = translated.cache_used_bytes;
        self.block_cache
            .insert(guest, translated.generation, translated.entry);
        Ok(translated)
    }

    fn translate<const PROFILE: bool>(
        &mut self,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<TranslationResult, types::DsrError> {
        let timer = if PROFILE {
            Some(profile::PhaseTimer::start_if::<true>())
        } else {
            None
        };
        let translated = self.translate_read_mostly(memory, guest);
        if let Some(timer) = timer {
            let elapsed_ns = match timer.elapsed_ns() {
                Ok(elapsed_ns) => elapsed_ns,
                Err(error) => return Err(self.budget.invalidate(error).into()),
            };
            self.budget
                .add_phase(profile::Phase::Translate, elapsed_ns)?;
            self.nested_translation_ns = match self.nested_translation_ns.checked_add(elapsed_ns) {
                Some(total) => total,
                None => {
                    return Err(self
                        .budget
                        .invalidate(profile::ProfileError::CounterOverflow(
                            "nested_translation_ns",
                        ))
                        .into());
                }
            };
        }
        translated
    }

    fn guest_pc_for_cache(
        &self,
        cache_pc: carrick_guest_mem::GuestVa,
    ) -> Result<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>), types::DsrError> {
        self.process.state.read().guest_pc_for_cache(cache_pc)
    }

    fn target_cache_authority(
        &self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
        entry: types::CacheVa,
    ) -> Result<*const gateway::TargetCacheAuthority, types::DsrError> {
        let state = self.process.state.read();
        if let Some(authority) = state
            .shared_blocks
            .get(&(guest, generation))
            .copied()
            .filter(|authority| authority.owns(entry))
        {
            return Ok(authority.target_authority as *const gateway::TargetCacheAuthority);
        }
        drop(state);
        if self.process.private_target_authority.owns(entry) {
            return Ok(self.process.private_target_authority.as_ref() as *const _);
        }
        Err(types::DsrError::CachePolicy(format!(
            "translated target 0x{:x} has no executable authority",
            entry.host().raw()
        )))
    }

    fn direct_binding_target(
        &self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
        entry: types::CacheVa,
    ) -> Result<crate::direct_binding::DirectBindingTarget, types::DsrError> {
        let state = self.process.state.read();
        if let Some(authority) = state
            .shared_blocks
            .get(&(guest, generation))
            .copied()
            .filter(|authority| authority.owns(entry))
        {
            let loaded = state
                .loaded_shared_units
                .get(authority.loaded_unit_index)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "shared direct-binding authority lost its loaded unit".to_string(),
                    )
                })?;
            return Ok(crate::direct_binding::DirectBindingTarget::shared_in_unit(
                crate::direct_binding::DirectBindingTargetPrefix {
                    target_cache_pc: entry.host().raw() as u64,
                    cache_start: authority.cache_start as u64,
                    cache_end: authority.cache_end as u64,
                    generation_bindings: authority.generation_bindings as u64,
                },
                guest,
                generation,
                loaded._unit.clone(),
                authority.loaded_unit_index,
            ));
        }
        let cache_range = state.cache.host_range();
        if self.process.private_target_authority.owns(entry) {
            return Ok(crate::direct_binding::DirectBindingTarget::private(
                crate::direct_binding::DirectBindingTargetPrefix {
                    target_cache_pc: entry.host().raw() as u64,
                    cache_start: cache_range.start as u64,
                    cache_end: cache_range.end as u64,
                    generation_bindings: 0,
                },
                guest,
                generation,
                &self.process.private_jit_epoch,
            ));
        }
        Err(types::DsrError::CachePolicy(format!(
            "translated target 0x{:x} has no retained direct-binding authority",
            entry.host().raw()
        )))
    }

    fn resolve_indirect<const PROFILE: bool>(
        &mut self,
        memory: &NativeMappedMemory,
        _source: carrick_guest_mem::GuestVa,
        target: carrick_guest_mem::GuestVa,
    ) -> Result<(types::CacheVa, types::CodeGeneration), types::DsrError> {
        self.stats.add(ResolverStat::ResolverExits, 1);
        let translated = self.translate::<PROFILE>(memory, target)?;
        let authority =
            self.target_cache_authority(target, translated.generation, translated.entry)?;
        self.indirect_cache
            .publish(target, translated.generation, translated.entry, authority);
        probes::dsr_cache_event(
            self.tid,
            probes::DsrCacheEventKind::TargetPublish,
            target.raw(),
            translated.generation.get(),
            translated.cache_used_bytes,
        );
        Ok((translated.entry, translated.generation))
    }

    #[doc(hidden)]
    pub fn resolver_stats(&self) -> ResolverStats {
        let process = self.process.state.read().stats;
        ResolverStats {
            resolver_exits: self.stats.resolver_exits,
            one_entry_hits: self.stats.one_entry_hits,
            translations: process.translations,
            duplicate_publications: process.duplicate_publications,
            gateway_entries: self.stats.gateway_entries,
            syscall_exits: self.stats.syscall_exits,
            direct_resolver_exits: self.stats.direct_resolver_exits,
            cache_lookups: process.cache_lookups,
            cache_lookup_hits: process.cache_lookup_hits,
            invalidated_blocks: process.invalidated_blocks,
            translation_ns: process.translation_ns,
            translation_decode_ns: process.translation_decode_ns,
            translation_plan_ns: process.translation_plan_ns,
            translation_emit_ns: process.translation_emit_ns,
            translation_publication_ns: process.translation_publication_ns,
            shared_unit_lookups: process.shared_unit_lookups,
            shared_unit_hits: process.shared_unit_hits,
            shared_unit_loads: process.shared_unit_loads,
            shared_blocks_mapped: process.shared_blocks_mapped,
            shared_translations_avoided: process.shared_translations_avoided,
            invalid: self.stats.invalid.or(process.invalid),
            resolve_src_shared_tgt_shared: self.stats.resolve_src_shared_tgt_shared,
            resolve_src_shared_tgt_private: self.stats.resolve_src_shared_tgt_private,
            resolve_src_private_tgt_shared: self.stats.resolve_src_private_tgt_shared,
            resolve_src_private_tgt_private: self.stats.resolve_src_private_tgt_private,
        }
    }

    #[doc(hidden)]
    pub fn patch_first_completed_recovery_for_test(
        &mut self,
        guest: carrick_guest_mem::GuestVa,
        word: u32,
    ) -> Result<carrick_guest_mem::HostVa, types::DsrError> {
        let cache_pc = self
            .recovery_points_for_test(guest)
            .into_iter()
            .find_map(|(cache_pc, action)| {
                matches!(
                    action,
                    emit::RecoveryAction::RecoverBiasedMemory(recovery)
                        if recovery.instruction_complete
                )
                .then_some(cache_pc)
            })
            .ok_or_else(|| {
                types::DsrError::CachePolicy(format!(
                    "no completed biased recovery instruction for guest PC 0x{:x}",
                    guest.raw()
                ))
            })?;
        self.patch_recovery_word_for_test(cache_pc, word)?;
        Ok(cache_pc.host())
    }

    /// Force superblock formation on for this translator, whatever
    /// `CARRICK_DSR_SUPERBLOCK` says.
    ///
    /// The switch resolves once per process, so a test binary cannot flip it by
    /// setting the variable. Without this hook the fused path would be
    /// unreachable from the production translator in tests -- which is how a
    /// feature behind an opt-in switch ends up shipping unexercised.
    #[doc(hidden)]
    pub fn set_superblock_segments_for_test(&self, segments: usize) {
        self.process.state.write().superblock_segments = segments.max(1);
    }

    #[doc(hidden)]
    pub fn recovery_points_for_test(
        &self,
        guest: carrick_guest_mem::GuestVa,
    ) -> Vec<(types::CacheVa, emit::RecoveryAction)> {
        let state = self.process.state.read();
        state
            .published
            .iter()
            .flat_map(|block| {
                block.recovery.iter().filter_map(|recovery| {
                    if !matches!(
                        recovery.action,
                        emit::RecoveryAction::RestoreScratch { .. }
                            | emit::RecoveryAction::RestoreScratchCompleted { .. }
                            | emit::RecoveryAction::CommitVirtualizedAndRestoreScratch { .. }
                            | emit::RecoveryAction::RestoreScratchAndContext { .. }
                            | emit::RecoveryAction::RestoreScratchAndContextCompleted { .. }
                            | emit::RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                                ..
                            }
                            | emit::RecoveryAction::RestoreDualVirtualReadOnly { .. }
                            | emit::RecoveryAction::RestoreDualVirtualReadOnlyCompleted { .. }
                            | emit::RecoveryAction::CommitDualVirtualAndRestore { .. }
                            | emit::RecoveryAction::RecoverCounterRead(_)
                            | emit::RecoveryAction::RecoverBiasedMemory(_)
                    ) {
                        return None;
                    }
                    let mapped_guest = block
                        .map
                        .iter()
                        .find(|mapping| mapping.cache == recovery.cache)
                        .map(|mapping| mapping.guest);
                    if mapped_guest != Some(guest) {
                        return None;
                    }
                    block
                        .entry
                        .host()
                        .raw()
                        .checked_add(recovery.cache.get() as usize)
                        .map(carrick_guest_mem::HostVa)
                        .map(types::CacheVa::published)
                        .map(|cache_pc| (cache_pc, recovery.action))
                })
            })
            .collect()
    }

    #[doc(hidden)]
    pub fn patch_recovery_word_for_test(
        &mut self,
        cache_pc: types::CacheVa,
        word: u32,
    ) -> Result<(), types::DsrError> {
        let mut state = self.process.state.write();
        let is_recovery = state.published.iter().any(|block| {
            let start = block.entry.host().raw();
            block.recovery.iter().any(|recovery| {
                start
                    .checked_add(recovery.cache.get() as usize)
                    .is_some_and(|address| address == cache_pc.host().raw())
            })
        });
        if !is_recovery {
            return Err(types::DsrError::CachePolicy(format!(
                "test patch target is not a recovery instruction: 0x{:x}",
                cache_pc.host().raw()
            )));
        }
        Ok(state.cache.patch_word_for_test(cache_pc, word)?)
    }

    pub fn profiling_enabled(&self) -> bool {
        self.budget.enabled()
    }

    pub fn begin_profile_phase(&mut self) {
        self.nested_translation_ns = 0;
    }

    pub fn add_profile_phase(
        &mut self,
        phase: profile::Phase,
        timer: profile::PhaseTimer,
    ) -> Result<(), profile::ProfileError> {
        let elapsed_ns = match timer.elapsed_ns() {
            Ok(elapsed_ns) => elapsed_ns,
            Err(error) => return Err(self.budget.invalidate(error)),
        };
        let exclusive_ns = if matches!(
            phase,
            profile::Phase::PrepareIndex | profile::Phase::FinishExit
        ) {
            match elapsed_ns.checked_sub(self.nested_translation_ns) {
                Some(exclusive_ns) => exclusive_ns,
                None => return Err(self.budget.invalidate(profile::ProfileError::TimeOverlap)),
            }
        } else {
            elapsed_ns
        };
        self.nested_translation_ns = 0;
        self.budget.add_phase(phase, exclusive_ns)
    }

    pub fn add_profile_phase_ns(
        &mut self,
        phase: profile::Phase,
        elapsed_ns: u64,
    ) -> Result<(), profile::ProfileError> {
        self.budget.add_phase(phase, elapsed_ns)
    }

    pub fn add_profile_blocked_cpu_ns(
        &mut self,
        elapsed_ns: u64,
    ) -> Result<(), profile::ProfileError> {
        self.budget.add_blocked_cpu_ns(elapsed_ns)
    }

    pub fn record_profile_exit(
        &mut self,
        class: profile::ExitClass,
    ) -> Result<(), profile::ProfileError> {
        self.budget.record_exit(class)
    }

    pub fn record_profile_sensitive(
        &mut self,
        class: profile::SensitiveClass,
    ) -> Result<(), profile::ProfileError> {
        self.budget.record_sensitive(class)
    }

    pub fn invalidate_profile(&mut self, error: profile::ProfileError) -> profile::ProfileError {
        self.budget.invalidate(error)
    }

    pub fn prepare_entry<const PROFILE: bool>(
        &mut self,
        memory: &NativeMappedMemory,
        snapshot: &NativeUcontextSnapshot,
    ) -> Result<PreparedEntry, types::DsrError> {
        let guest = carrick_guest_mem::GuestVa(snapshot.pc);
        if PROFILE {
            self.begin_profile_phase();
        }
        if PROFILE {
            probes::dsr_prepare_begin(self.tid, guest.raw());
        }
        let selection = (|| -> Result<_, types::DsrError> {
            if let Some((generation, entry)) = self.block_cache.get(guest)
                && memory.dsr_generation_observation(guest)?.expected() == generation
            {
                self.stats.add(ResolverStat::OneEntryHits, 1);
                return Ok((entry, generation, probes::DsrPrepareOutcome::ResumeEntryHit));
            }
            // No explicit eviction on a generation mismatch: the slot is keyed by
            // guest VA and `translate` overwrites it below with the fresh
            // generation.
            let translated = self.translate::<PROFILE>(memory, guest)?;
            let outcome = match translated.outcome {
                TranslationOutcome::BlockIndexHit => probes::DsrPrepareOutcome::BlockIndexHit,
                TranslationOutcome::SharedUnit => probes::DsrPrepareOutcome::BlockIndexHit,
                TranslationOutcome::ArtifactReplay | TranslationOutcome::Translated => {
                    probes::DsrPrepareOutcome::Translated
                }
            };
            Ok((translated.entry, translated.generation, outcome))
        })();
        let (entry, generation, outcome) = match selection {
            Ok(selection) => selection,
            Err(error) => {
                if PROFILE {
                    probes::dsr_prepare_end(
                        self.tid,
                        guest.raw(),
                        0,
                        0,
                        probes::DsrPrepareOutcome::Failed,
                    );
                }
                return Err(error);
            }
        };
        let state = self.process.state.read();
        let shared = state
            .shared_blocks
            .get(&(guest, generation))
            .copied()
            .filter(|authority| authority.owns(entry));
        let cache_range = state.cache.host_range();
        let executable_range_catalog = state.executable_ranges.header_ptr();
        drop(state);
        let prepared = PreparedEntry {
            entry,
            generation,
            cache_start: shared.map_or(cache_range.start, |authority| authority.cache_start),
            cache_end: shared.map_or(cache_range.end, |authority| authority.cache_end),
            address_mode: memory.address_mode(),
            generation_bindings: shared.map_or(0, |authority| authority.generation_bindings),
            generation_binding_count: shared
                .map_or(0, |authority| authority.generation_binding_count),
            executable_range_catalog,
        };
        if PROFILE {
            probes::dsr_prepare_end(
                self.tid,
                guest.raw(),
                entry.host().raw() as u64,
                generation.get(),
                outcome,
            );
        }
        Ok(prepared)
    }

    pub fn enter_prepared<const PROFILE: bool>(
        &mut self,
        prepared: PreparedEntry,
        snapshot: &mut NativeUcontextSnapshot,
    ) -> Result<PreparedExit, types::DsrError> {
        let guest_pc = snapshot.pc;
        let mut exit = types::NativeDsrExit::Syscall {
            resume: carrick_guest_mem::GuestVa(snapshot.pc),
        };
        if PROFILE {
            // First gateway entry of any guest thread ends the process
            // startup window (atomic claim; a single load once claimed).
            if let Err(error) = profile::claim_process_startup() {
                return Err(self.budget.invalidate(error).into());
            }
        }
        if self.budget.enabled() {
            self.stats.add(ResolverStat::GatewayEntries, 1);
        }
        if PROFILE {
            probes::dsr_run_begin(
                self.tid,
                guest_pc,
                prepared.entry.host().raw() as u64,
                prepared.generation.get(),
            );
        }
        let gateway_result =
            if prepared.generation_binding_count == 0 && !shared_translation_runtime_enabled() {
                gateway::enter_translated_with_trusted_private_cache(
                    prepared.entry,
                    snapshot,
                    &mut exit,
                    &self.indirect_cache,
                    prepared.address_mode,
                )
            } else if prepared.generation_binding_count == 0 {
                gateway::enter_translated_with_cache_range_and_catalog(
                    prepared.entry,
                    snapshot,
                    &mut exit,
                    &self.indirect_cache,
                    prepared.cache_start,
                    prepared.cache_end,
                    prepared.address_mode,
                    prepared.executable_range_catalog,
                )
            } else {
                // SAFETY: `ProcessState::loaded_shared_units` owns the boxed table
                // for the entire configured image lifetime. Exec reset cannot run
                // concurrently with an active prepared entry.
                let bindings = unsafe {
                    std::slice::from_raw_parts(
                        prepared.generation_bindings as *const gateway::GenerationBinding,
                        prepared.generation_binding_count,
                    )
                };
                gateway::enter_translated_with_cache_range_and_generation_bindings_and_catalog(
                    prepared.entry,
                    snapshot,
                    &mut exit,
                    &self.indirect_cache,
                    prepared.cache_start,
                    prepared.cache_end,
                    prepared.address_mode,
                    bindings,
                    prepared.executable_range_catalog,
                )
            };
        if let Err(error) = gateway_result {
            if PROFILE {
                probes::dsr_run_end(
                    self.tid,
                    probes::DsrExitKind::Unsupported,
                    guest_pc,
                    0,
                    i32::try_from(error.probe_outcome().raw()).unwrap_or(i32::MAX),
                );
            }
            return Err(error);
        }
        if PROFILE {
            let (kind, exit_guest_pc, target_pc, status) = exit.probe_fields();
            probes::dsr_run_end(self.tid, kind, exit_guest_pc, target_pc, status);
        }
        Ok(PreparedExit { exit })
    }

    #[doc(hidden)]
    pub fn finish_exit(
        &mut self,
        memory: &NativeMappedMemory,
        snapshot: &mut NativeUcontextSnapshot,
        prepared: PreparedEntry,
        exit: PreparedExit,
    ) -> Result<ThreadExit, types::DsrError> {
        self.finish_exit_profiled::<false>(memory, snapshot, prepared, exit)
    }

    pub fn finish_exit_profiled<const PROFILE: bool>(
        &mut self,
        memory: &NativeMappedMemory,
        snapshot: &mut NativeUcontextSnapshot,
        prepared: PreparedEntry,
        exit: PreparedExit,
    ) -> Result<ThreadExit, types::DsrError> {
        if PROFILE {
            self.begin_profile_phase();
        }
        if self.budget.enabled() {
            match exit.exit {
                types::NativeDsrExit::Syscall { .. } => {
                    self.stats.add(ResolverStat::SyscallExits, 1);
                }
                types::NativeDsrExit::ResolveDirect { source, target, .. } => {
                    self.stats.add(ResolverStat::DirectResolverExits, 1);
                    // A0's exit criterion: classify by RANGE containment, and
                    // report source and target together. One shared `read()` for
                    // both, under the profiling guard only.
                    let (source_shared, target_shared) = {
                        let state = self.process.state.read();
                        (
                            state.shared_block_contains(source),
                            state.shared_block_contains(target),
                        )
                    };
                    self.stats.add(
                        match (source_shared, target_shared) {
                            (true, true) => ResolverStat::ResolveSrcSharedTgtShared,
                            (true, false) => ResolverStat::ResolveSrcSharedTgtPrivate,
                            (false, true) => {
                                self.profiled_private_to_shared_edges
                                    .insert((source.raw(), target.raw()));
                                ResolverStat::ResolveSrcPrivateTgtShared
                            }
                            (false, false) => {
                                self.profiled_private_to_private_edges
                                    .insert((source.raw(), target.raw()));
                                ResolverStat::ResolveSrcPrivateTgtPrivate
                            }
                        },
                        1,
                    );
                }
                types::NativeDsrExit::ResolveIndirect { .. } => {}
                _ => {}
            }
        }
        Ok(match exit.exit {
            types::NativeDsrExit::Syscall { resume } => ThreadExit::Syscall { resume },
            types::NativeDsrExit::ResolveDirect {
                source,
                target,
                binding,
            } => {
                let binding_cell = binding.raw_cell();
                probes::dsr_resolve_begin(
                    self.tid,
                    probes::DsrResolveKind::Direct,
                    source.raw(),
                    target.raw(),
                );
                let binding_eligibility = self
                    .process
                    .state
                    .write()
                    .direct_bindings
                    .classify_cold_exit(source, target, binding);
                match &binding_eligibility {
                    Ok(eligibility) => {
                        probes::dsr_cache_event(
                            self.tid,
                            probes::DsrCacheEventKind::DirectBindingEligible,
                            source.raw(),
                            u64::from(eligibility.ordinal.get()),
                            eligibility.cell.map_or(0, |cell| cell.get() as u64),
                        );
                    }
                    Err(reason) => {
                        probes::dsr_cache_event(
                            self.tid,
                            probes::DsrCacheEventKind::DirectBindingValidationFailure,
                            source.raw(),
                            reason.raw(),
                            binding_cell,
                        );
                    }
                }
                let translated = match self.translate::<PROFILE>(memory, target) {
                    Ok(translated) => translated,
                    Err(error) => {
                        probes::dsr_resolve_end(
                            self.tid,
                            probes::DsrResolveKind::Direct,
                            source.raw(),
                            target.raw(),
                            error.probe_outcome(),
                        );
                        return Err(error);
                    }
                };
                let authority =
                    self.target_cache_authority(target, translated.generation, translated.entry)?;
                self.indirect_cache.publish(
                    target,
                    translated.generation,
                    translated.entry,
                    authority,
                );
                if let Ok(eligibility) = binding_eligibility
                    && let Some(cell) = eligibility.cell
                {
                    let binding = crate::direct_binding::DirectBindingMiss {
                        cell,
                        ordinal: eligibility.ordinal,
                    };
                    match self.direct_binding_target(
                        target,
                        translated.generation,
                        translated.entry,
                    ) {
                        Ok(descriptor) => {
                            let evidence = self
                                .process
                                .state
                                .write()
                                .direct_bindings
                                .publish_with_evidence(binding, source, target, descriptor);
                            for _ in 0..evidence.cas_losses {
                                probes::dsr_cache_event(
                                    self.tid,
                                    probes::DsrCacheEventKind::DirectBindingCasLoss,
                                    source.raw(),
                                    u64::from(eligibility.ordinal.get()),
                                    cell.get() as u64,
                                );
                            }
                            if let Some(generation) = evidence.stale_clear_generation {
                                probes::dsr_cache_event(
                                    self.tid,
                                    probes::DsrCacheEventKind::DirectBindingClear,
                                    cell.get() as u64,
                                    crate::direct_binding::DirectBindingClearReason::StaleWinnerRemoval
                                        .raw(),
                                    generation.get(),
                                );
                            }
                            if matches!(
                                evidence.outcome,
                                crate::direct_binding::DirectBindingPublishOutcome::Published
                                    | crate::direct_binding::DirectBindingPublishOutcome::PublishedAfterStale
                            ) {
                                probes::dsr_cache_event(
                                    self.tid,
                                    probes::DsrCacheEventKind::DirectBindingPublish,
                                    source.raw(),
                                    u64::from(eligibility.ordinal.get()),
                                    cell.get() as u64,
                                );
                            }
                            if let Some(reason) = evidence.validation_failure {
                                probes::dsr_cache_event(
                                    self.tid,
                                    probes::DsrCacheEventKind::DirectBindingValidationFailure,
                                    source.raw(),
                                    reason.raw(),
                                    cell.get() as u64,
                                );
                            }
                        }
                        Err(_) => {
                            probes::dsr_cache_event(
                                self.tid,
                                probes::DsrCacheEventKind::DirectBindingValidationFailure,
                                source.raw(),
                                crate::direct_binding::DirectBindingValidationReason::AuthorityMismatch
                                    .raw(),
                                cell.get() as u64,
                            );
                        }
                    }
                }
                probes::dsr_cache_event(
                    self.tid,
                    probes::DsrCacheEventKind::TargetPublish,
                    target.raw(),
                    translated.generation.get(),
                    translated.cache_used_bytes,
                );
                probes::dsr_resolve_end(
                    self.tid,
                    probes::DsrResolveKind::Direct,
                    source.raw(),
                    target.raw(),
                    probes::DsrOperationOutcome::Success,
                );
                snapshot.pc = target.raw();
                ThreadExit::Continue
            }
            types::NativeDsrExit::ResolveIndirect { source, target, .. } => {
                probes::dsr_resolve_begin(
                    self.tid,
                    probes::DsrResolveKind::Indirect,
                    source.raw(),
                    target.raw(),
                );
                if !target.raw().is_multiple_of(4) {
                    probes::dsr_resolve_end(
                        self.tid,
                        probes::DsrResolveKind::Indirect,
                        source.raw(),
                        target.raw(),
                        probes::DsrOperationOutcome::InvalidTarget,
                    );
                    snapshot.pc = source.raw();
                    return Ok(ThreadExit::Fault {
                        kind: ThreadFault::Guest {
                            signum: carrick_abi::LINUX_SIGBUS,
                            code: carrick_abi::LINUX_BUS_ADRALN,
                        },
                        address: ThreadFaultAddress::Guest(target),
                    });
                }
                if !memory.guest_address_is_executable(target.raw()) {
                    probes::dsr_resolve_end(
                        self.tid,
                        probes::DsrResolveKind::Indirect,
                        source.raw(),
                        target.raw(),
                        probes::DsrOperationOutcome::InvalidTarget,
                    );
                    snapshot.pc = source.raw();
                    return Ok(ThreadExit::Fault {
                        kind: ThreadFault::Guest {
                            signum: carrick_abi::LINUX_SIGSEGV,
                            code: if memory.region_contains(target.raw(), 1) {
                                carrick_abi::LINUX_SEGV_ACCERR
                            } else {
                                carrick_abi::LINUX_SEGV_MAPERR
                            },
                        },
                        address: ThreadFaultAddress::Guest(target),
                    });
                }
                let (entry, target_generation) =
                    match self.resolve_indirect::<PROFILE>(memory, source, target) {
                        Ok(resolved) => resolved,
                        Err(error) => {
                            probes::dsr_resolve_end(
                                self.tid,
                                probes::DsrResolveKind::Indirect,
                                source.raw(),
                                target.raw(),
                                error.probe_outcome(),
                            );
                            return Err(error);
                        }
                    };
                probes::dsr_resolve_end(
                    self.tid,
                    probes::DsrResolveKind::Indirect,
                    source.raw(),
                    target.raw(),
                    probes::DsrOperationOutcome::Success,
                );
                self.block_cache.insert(target, target_generation, entry);
                snapshot.pc = target.raw();
                ThreadExit::Continue
            }
            types::NativeDsrExit::Sensitive {
                guest_pc,
                generation,
                ..
            } => {
                let metadata = self
                    .process
                    .state
                    .read()
                    .sensitive
                    .get(&(guest_pc, generation))
                    .copied()
                    .ok_or_else(|| {
                        types::DsrError::BlockPolicy(format!(
                            "missing sensitive-exit metadata for guest PC 0x{:x}",
                            guest_pc.raw()
                        ))
                    })?;
                if PROFILE && let Some(site) = metadata.fusion {
                    self.budget
                        .record_exclusive_fusion(profile::ExclusiveFusionClass::from(
                            site.disposition,
                        ))
                        .map_err(|error| types::DsrError::BlockPolicy(error.to_string()))?;
                }
                ThreadExit::Sensitive(metadata.exit)
            }
            types::NativeDsrExit::Unsupported { guest_pc, .. } => {
                let (word, op) = self
                    .process
                    .state
                    .read()
                    .unsupported
                    .get(&(guest_pc, prepared.generation))
                    .copied()
                    .ok_or_else(|| {
                        types::DsrError::BlockPolicy(format!(
                            "missing unsupported-exit metadata for guest PC 0x{:x}",
                            guest_pc.raw()
                        ))
                    })?;
                ThreadExit::Unsupported(format!(
                    "{op:?} 0x{word:08x} at guest PC 0x{:x}",
                    guest_pc.raw()
                ))
            }
            types::NativeDsrExit::Fault {
                guest_pc,
                signal,
                code,
                address,
                rewrite_scratch,
                rewrite_context_scratch,
                generation_pstate_scratch,
                indirect_x15_scratch,
                indirect_x30_scratch,
                physical_x18,
                gateway_phase,
                biased_guest_fault_address,
            } => {
                let (guest_pc, recovery) = self.guest_pc_for_cache(guest_pc).map_err(|error| {
                    types::DsrError::CachePolicy(format!(
                        "{error}; trapped signal={signal} code={code} address=0x{:x} \
                         sp=0x{:x} lr=0x{:x} x0=0x{:x} x16=0x{:x} x17=0x{:x} \
                         guest_x18=0x{:x} physical_x18=0x{physical_x18:x} \
                         gateway_phase={gateway_phase} x28=0x{:x} \
                         esr=0x{:x} far=0x{:x} \
                         last_kick={:?}",
                        address.raw(),
                        snapshot.sp,
                        snapshot.x[30],
                        snapshot.x[0],
                        snapshot.x[16],
                        snapshot.x[17],
                        snapshot.x[18],
                        snapshot.x[28],
                        snapshot.esr,
                        snapshot.far,
                        self.last_kick,
                    ))
                })?;
                if let Some(recovery) = recovery {
                    recover_rewrite_state(
                        snapshot,
                        recovery,
                        rewrite_scratch,
                        rewrite_context_scratch,
                        generation_pstate_scratch,
                        indirect_x15_scratch,
                        indirect_x30_scratch,
                    )?;
                }
                snapshot.pc = recovery_resume_pc(guest_pc, recovery)?;
                let (kind, address) =
                    if let Some((signum, code)) = crate::esr::el0_debug_signal(snapshot.esr) {
                        (
                            ThreadFault::Guest { signum, code },
                            ThreadFaultAddress::Guest(guest_pc),
                        )
                    } else if recovery.is_some_and(|action| {
                        matches!(
                            action,
                            emit::RecoveryAction::RecoverBiasedMemory(_)
                                | emit::RecoveryAction::RestoreScratchInvalidBiasedLiteral { .. }
                        )
                    }) && biased_guest_fault_address
                        >= carrick_dsr::address::BIASED_GUEST_APERTURE_END
                    {
                        snapshot.far = biased_guest_fault_address;
                        snapshot.fault_address = biased_guest_fault_address;
                        (
                            ThreadFault::Host { signal, code },
                            ThreadFaultAddress::Guest(carrick_guest_mem::GuestVa(
                                biased_guest_fault_address,
                            )),
                        )
                    } else {
                        (
                            ThreadFault::Host { signal, code },
                            ThreadFaultAddress::Host(address),
                        )
                    };
                ThreadExit::Fault { kind, address }
            }
            types::NativeDsrExit::Kick {
                resume,
                rewrite_scratch,
                rewrite_context_scratch,
                generation_pstate_scratch,
                indirect_x15_scratch,
                indirect_x30_scratch,
            } => {
                let (guest_pc, recovery) = self.guest_pc_for_cache(resume)?;
                if let Some(recovery) = recovery {
                    recover_rewrite_state(
                        snapshot,
                        recovery,
                        rewrite_scratch,
                        rewrite_context_scratch,
                        generation_pstate_scratch,
                        indirect_x15_scratch,
                        indirect_x30_scratch,
                    )?;
                }
                self.last_kick = Some((guest_pc, recovery));
                snapshot.pc = recovery_resume_pc(guest_pc, recovery)?;
                ThreadExit::Kick
            }
            types::NativeDsrExit::KickAtEntry { resume } => {
                snapshot.pc = resume.raw();
                ThreadExit::Kick
            }
            other => ThreadExit::Unsupported(format!("{other:?}")),
        })
    }
}

#[cfg(test)]
mod tests {
    // Moved from the runtime dsr/mod.rs test module with the probe
    // projections they exercise; the expected values are now the
    // carrick_dsr::probes mirrors (ordinal-identical to the USDT enums
    // by the mirrored-ordinal tests in carrick-dsr).
    use super::{
        DsrErrorProbeExt as _, NativeDsrExitProbeExt as _, ProcessTranslator, SharedBlockAuthority,
        translation_source_words_required,
    };
    use crate::types;
    use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};
    use carrick_guest_mem::GuestVa;
    use std::ptr::NonNull;

    const PC: GuestVa = GuestVa(0x1000);

    struct TestHostJit;

    static TEST_HOST_JIT: TestHostJit = TestHostJit;

    impl NativeHostJit for TestHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            Ok(())
        }

        fn map_code_cache(&self, capacity: usize) -> std::io::Result<JitRegion> {
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            let base = NonNull::new(mapped.cast::<u8>())
                .ok_or_else(|| std::io::Error::other("mmap returned null"))?;
            Ok(JitRegion {
                exec_base: base,
                write_base: base,
                capacity,
            })
        }

        unsafe fn unmap(&self, region: &JitRegion) {
            let _ = unsafe { libc::munmap(region.exec_base.as_ptr().cast(), region.capacity) };
        }

        fn begin_thread_write(&self) {}

        fn end_thread_write(&self) {}

        fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {}

        fn remap_for_fork_child(&self, _prior: &JitRegion) -> std::io::Result<ForkChildJit> {
            Ok(ForkChildJit::Inherited)
        }
    }

    #[test]
    fn source_words_are_captured_only_for_enabled_reuse_consumers() {
        assert!(!translation_source_words_required(false, false));
        assert!(translation_source_words_required(true, false));
        assert!(translation_source_words_required(false, true));
        assert!(translation_source_words_required(true, true));
    }

    #[test]
    fn cache_host_range_matches_configured_executable_capacity() {
        let translator =
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
        let range = translator.cache_host_range();

        assert!(range.start < range.end);
        assert_eq!(range.end - range.start, 64 * 1024);
    }

    #[test]
    fn code_snapshot_captures_published_words_and_block_index() {
        let translator =
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
        let entry = {
            let mut state = translator.state.write();
            let published = state
                .cache
                .publish_words(&[0xd503_201f, 0xd65f_03c0])
                .expect("publish");
            state.blocks.insert(
                (
                    carrick_guest_mem::GuestVa(0x40_0000),
                    types::CodeGeneration::INITIAL,
                ),
                published.entry(),
            );
            published.entry()
        };

        let snapshot = translator.code_snapshot();

        let base = translator.cache_host_range().start;
        assert_eq!(snapshot.cache_base, base);
        let offset = (entry.host().0 as u64 - base) as usize;
        assert!(snapshot.code.len() >= offset + 8);
        assert_eq!(
            &snapshot.code[offset..offset + 4],
            &0xd503_201f_u32.to_le_bytes()
        );
        assert_eq!(
            &snapshot.code[offset + 4..offset + 8],
            &0xd65f_03c0_u32.to_le_bytes()
        );
        assert_eq!(snapshot.blocks, vec![(0x40_0000, entry.host().0 as u64)]);
    }

    #[test]
    fn shared_authority_only_owns_entries_inside_its_unit() {
        let authority = SharedBlockAuthority {
            generation_bindings: 0x7000,
            generation_binding_count: 3,
            cache_start: 0x1000,
            cache_end: 0x2000,
            target_authority: 0,
            loaded_unit_index: 0,
        };
        assert!(authority.owns(types::CacheVa::published(carrick_guest_mem::HostVa(0x1800))));
        assert!(!authority.owns(types::CacheVa::published(carrick_guest_mem::HostVa(0x2800))));
    }

    /// `ProcessState::guest_pc_for_cache` lowers a cache PC back to the guest
    /// PC that produced it, and every guest fault and asynchronous kick runs
    /// it. These pin the answers it must keep giving as its cost model
    /// changes: the same `(guest, recovery)` tuple for a PC in the first,
    /// middle and last published block, the same tuple for a block whose code
    /// lives OUTSIDE the private bump cache (the shape a shared translation
    /// unit publishes), and the same diagnostic payload -- reported in
    /// publication order -- for a PC in no block at all.
    mod guest_pc_lowering {
        use super::TEST_HOST_JIT;
        use crate::translator::{ProcessState, ProcessTranslator, PublishedBlock};
        use crate::{emit, gateway, types};
        use carrick_dsr::cache::PageGenerationTable;
        use carrick_guest_mem::{GuestVa, HostVa};

        const NOP: u32 = 0xd503_201f;
        const WORDS: u32 = 4;
        const BLOCK_LEN: usize = WORDS as usize * 4;

        /// A block whose PC map covers one guest word per emitted word and
        /// whose single recovery point sits on the SECOND word, so a lookup
        /// that lands on the wrong block cannot accidentally agree.
        fn published_block(
            generations: &PageGenerationTable,
            entry: types::CacheVa,
            guest: GuestVa,
            words: u32,
        ) -> PublishedBlock {
            PublishedBlock {
                entry,
                len: words as usize * 4,
                map: (0..words)
                    .map(|word| emit::PcMapEntry {
                        guest: GuestVa(guest.raw() + u64::from(word) * 4),
                        cache: types::CacheOffset::published(word * 4),
                    })
                    .collect(),
                recovery: vec![emit::RecoveryEntry {
                    cache: types::CacheOffset::published(4),
                    action: emit::RecoveryAction::RestoreGuestX17,
                }],
                _generation: generations.observe(guest).expect("generation observation"),
            }
        }

        /// Publish real code through the bump-allocated private cache, then
        /// index the extent it handed back.
        fn publish_private_sized(
            state: &mut ProcessState,
            generations: &PageGenerationTable,
            guest: GuestVa,
            words: u32,
        ) -> types::CacheVa {
            let entry = state
                .cache
                .publish_words(&vec![NOP; words as usize])
                .expect("publish words")
                .entry();
            state.push_published(published_block(generations, entry, guest, words));
            entry
        }

        fn publish_private(
            state: &mut ProcessState,
            generations: &PageGenerationTable,
            guest: GuestVa,
        ) -> types::CacheVa {
            publish_private_sized(state, generations, guest, WORDS)
        }

        /// Index a block whose code is NOT in the private cache. A shared
        /// translation unit is dlopen'd into its own mapping, so
        /// `try_load_shared_unit` publishes entries at a base that bears no
        /// relation to the bump cursor -- including below every private block
        /// published so far.
        fn publish_foreign(
            state: &mut ProcessState,
            generations: &PageGenerationTable,
            entry: types::CacheVa,
            guest: GuestVa,
        ) {
            state.push_published(published_block(generations, entry, guest, WORDS));
        }

        /// The second word of `entry` -- the word the recovery point is on.
        fn recovery_pc(entry: types::CacheVa) -> GuestVa {
            GuestVa((entry.host().raw() + 4) as u64)
        }

        #[test]
        fn lowers_a_pc_in_the_first_middle_and_last_published_block() {
            let translator =
                ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
            let generations = PageGenerationTable::new(4096).expect("generation table");
            let mut state = translator.state.write();

            const BLOCKS: u32 = 512;
            let entries = (0..BLOCKS)
                .map(|block| {
                    publish_private(
                        &mut state,
                        &generations,
                        GuestVa(0x40_0000 + u64::from(block) * 0x100),
                    )
                })
                .collect::<Vec<_>>();

            for block in [0, BLOCKS / 2, BLOCKS - 1] {
                let (guest, recovery) = state
                    .guest_pc_for_cache(recovery_pc(entries[block as usize]))
                    .unwrap_or_else(|error| panic!("block {block} lowering: {error}"));

                assert_eq!(guest, GuestVa(0x40_0000 + u64::from(block) * 0x100 + 4));
                assert_eq!(recovery, Some(emit::RecoveryAction::RestoreGuestX17));
            }
        }

        #[test]
        fn lowers_a_pc_in_a_block_published_below_the_private_cache() {
            let translator =
                ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
            let generations = PageGenerationTable::new(4096).expect("generation table");
            let mut state = translator.state.write();
            let below_cache = state.cache.host_range().start - 0x10_0000;

            let first = publish_private(&mut state, &generations, GuestVa(0x40_0000));
            let foreign = types::CacheVa::published(HostVa(below_cache));
            publish_foreign(&mut state, &generations, foreign, GuestVa(0x50_0000));
            let last = publish_private(&mut state, &generations, GuestVa(0x60_0000));

            for (entry, guest_base) in [(first, 0x40_0000), (foreign, 0x50_0000), (last, 0x60_0000)]
            {
                let (guest, recovery) = state
                    .guest_pc_for_cache(recovery_pc(entry))
                    .unwrap_or_else(|error| {
                        panic!("entry 0x{:x} lowering: {error}", entry.host().raw())
                    });

                assert_eq!(guest, GuestVa(guest_base + 4));
                assert_eq!(recovery, Some(emit::RecoveryAction::RestoreGuestX17));
            }
        }

        #[test]
        fn lowers_a_recycled_cache_address_through_the_block_republished_there() {
            // `reset_after_fork_for_exec` drops the published blocks and
            // rewinds the bump cursor together, so the exec'd image
            // republishes over the exact addresses the pre-exec image used --
            // with its own block layout. A lookup that still knew the retired
            // blocks would lower a fault through the PREVIOUS image.
            let translator =
                ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
            let generations = PageGenerationTable::new(4096).expect("generation table");
            let mut state = translator.state.write();

            let retired = (0..4u32)
                .map(|block| {
                    publish_private(
                        &mut state,
                        &generations,
                        GuestVa(0x40_0000 + u64::from(block) * 0x100),
                    )
                })
                .collect::<Vec<_>>();

            state.clear_published();
            state.cache.reset_after_fork_for_exec();

            // One 16-word block over the span the four retired 4-word blocks
            // covered, so a PC that fell in the middle of a retired block now
            // falls in the MIDDLE of the block that replaced them.
            let republished =
                publish_private_sized(&mut state, &generations, GuestVa(0x70_0000), 4 * WORDS);
            assert_eq!(
                republished, retired[0],
                "the exec'd image must recycle the cache base"
            );

            let cache_pc = GuestVa((retired[1].host().raw() + 4) as u64);
            let (guest, _) = state
                .guest_pc_for_cache(cache_pc)
                .expect("a recycled address lowers through the live block");

            assert_eq!(guest, GuestVa(0x70_0000 + BLOCK_LEN as u64 + 4));
        }

        #[test]
        fn reports_publication_order_bounds_for_a_pc_in_no_published_block() {
            let translator =
                ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
            let generations = PageGenerationTable::new(4096).expect("generation table");
            let mut state = translator.state.write();
            let below_cache = state.cache.host_range().start - 0x10_0000;

            let first = publish_private(&mut state, &generations, GuestVa(0x40_0000));
            publish_foreign(
                &mut state,
                &generations,
                types::CacheVa::published(HostVa(below_cache)),
                GuestVa(0x50_0000),
            );
            let last = publish_private(&mut state, &generations, GuestVa(0x60_0000));

            let stray = GuestVa((below_cache - 0x10_0000) as u64);
            let error = state
                .guest_pc_for_cache(stray)
                .expect_err("a PC in no block cannot lower");

            let types::DsrError::CachePolicy(message) = error else {
                panic!("lowering a stray PC must stay a cache-policy error");
            };
            // Byte-identical to the shipped diagnostic. `first`/`last` are the
            // bounds in PUBLICATION order -- the foreign block sits between
            // them. The gateway addresses are the crate-test placeholders (see
            // the `exit_address!` note in `gateway`), read from the same
            // getters the diagnostic reads.
            assert_eq!(
                message,
                format!(
                    "cache PC 0x{:x} is outside published DSR blocks \
                     (in_cache=false, published=3, first={:?}, last={:?}, \
                     signal_gateway=0x{:x}, common_gateway=0x{:x})",
                    stray.raw(),
                    Some((first.host().raw(), BLOCK_LEN)),
                    Some((last.host().raw(), BLOCK_LEN)),
                    gateway::signal_exit_address(),
                    gateway::direct_exit_address(),
                )
            );
        }
    }

    mod direct_binding_owner_and_publication {
        use super::{ProcessTranslator, TEST_HOST_JIT};
        use crate::direct_binding::{
            DirectBindingCellRef, DirectBindingCellVa, DirectBindingEligibility,
            DirectBindingExitMetadata, DirectBindingMiss, DirectBindingOrdinal,
            DirectBindingPublishOutcome, DirectBindingRegistry, DirectBindingTarget,
            DirectBindingTargetPrefix, DirectBindingValidationReason, PrivateJitEpoch,
        };
        use crate::emit::DirectLinkKind;
        use crate::shared_cache::{
            AddressModeIdentity, DIRECT_BINDING_CELL_SIZE, DirectBindingLayout, ExecutableIdentity,
            GuestCodeLen, ImageFileLen, ImageFileOffset, NativePageProfileIdentity,
            SharedLoadedTranslationUnit, SourceFingerprint, TRANSLATION_UNIT_SCHEMA_V2,
            TranslationUnitKey, TranslationUnitManifest, UnresolvedDirectBindingRecord,
        };
        use crate::types::CodeGeneration;
        use carrick_guest_mem::GuestVa;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicPtr, Ordering};

        pub(super) struct UnitFixture {
            pub(super) storage: Box<[AtomicPtr<DirectBindingTarget>]>,
            pub(super) unit: SharedLoadedTranslationUnit,
        }

        pub(super) fn key(seed: u8) -> TranslationUnitKey {
            TranslationUnitKey::for_segment(
                ExecutableIdentity::Digest([seed; 32]),
                ImageFileOffset::new(u64::from(seed) * 0x1000),
                ImageFileLen::new(0x4000).expect("nonzero file length"),
                GuestVa(0x40_0000),
                GuestCodeLen::new(0x4000).expect("nonzero guest length"),
                SourceFingerprint([seed.wrapping_add(1); 32]),
                NativePageProfileIdentity::Native16k,
                AddressModeIdentity::Direct,
            )
        }

        pub(super) fn record(
            source: GuestVa,
            target: GuestVa,
            ordinal: u32,
        ) -> UnresolvedDirectBindingRecord {
            UnresolvedDirectBindingRecord {
                source,
                target,
                kind: DirectLinkKind::Branch,
                ordinal: DirectBindingOrdinal::claimed(ordinal),
                stub_start: ordinal * 128,
                stub_end: ordinal * 128 + 128,
            }
        }

        pub(super) fn sidecar_unit(
            unit_key: TranslationUnitKey,
            records: Vec<UnresolvedDirectBindingRecord>,
        ) -> UnitFixture {
            let storage = std::iter::repeat_with(|| AtomicPtr::new(std::ptr::null_mut()))
                .take(records.len())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let binding_base =
                DirectBindingCellVa::mapped(storage.as_ptr() as usize).expect("aligned cells");
            let binding_data_len = u64::try_from(
                records
                    .len()
                    .checked_mul(DIRECT_BINDING_CELL_SIZE as usize)
                    .expect("binding data length"),
            )
            .expect("binding data length fits u64");
            let unit = SharedLoadedTranslationUnit::new_with_binding_base(
                TranslationUnitManifest {
                    schema: TRANSLATION_UNIT_SCHEMA_V2,
                    key: unit_key,
                    dylib_sha256: [0x55; 32],
                    base_export: "test_code".to_string(),
                    code_len: 0x1000,
                    blocks: Vec::new(),
                    binding_layout: DirectBindingLayout::SidecarV1,
                    binding_export: "test_bindings".to_string(),
                    binding_data_len,
                    cell_size: DIRECT_BINDING_CELL_SIZE,
                    bindings: records,
                    binding_relocations: Vec::new(),
                },
                0x10_0000,
                Some(binding_base),
                Arc::new(()),
            );
            UnitFixture { storage, unit }
        }

        fn disabled_unit(
            unit_key: TranslationUnitKey,
            records: Vec<UnresolvedDirectBindingRecord>,
        ) -> SharedLoadedTranslationUnit {
            SharedLoadedTranslationUnit::new_with_binding_base(
                TranslationUnitManifest {
                    schema: TRANSLATION_UNIT_SCHEMA_V2,
                    key: unit_key,
                    dylib_sha256: [0x66; 32],
                    base_export: "test_code".to_string(),
                    code_len: 0x1000,
                    blocks: Vec::new(),
                    binding_layout: DirectBindingLayout::Disabled,
                    binding_export: String::new(),
                    binding_data_len: 0,
                    cell_size: 0,
                    bindings: records,
                    binding_relocations: Vec::new(),
                },
                0x20_0000,
                None,
                Arc::new(()),
            )
        }

        pub(super) fn process_with_direct_bindings() -> ProcessTranslator {
            let process =
                ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");
            process.state.write().direct_bindings = DirectBindingRegistry::new(true);
            process
        }

        pub(super) fn private_target(
            target: GuestVa,
            generation: CodeGeneration,
            cache_pc: u64,
            epoch: &Arc<PrivateJitEpoch>,
        ) -> DirectBindingTarget {
            DirectBindingTarget::private(
                DirectBindingTargetPrefix {
                    target_cache_pc: cache_pc,
                    cache_start: 0x80_0000,
                    cache_end: 0x81_0000,
                    generation_bindings: 0,
                },
                target,
                generation,
                epoch,
            )
        }

        #[test]
        fn miss_must_match_one_exact_loaded_owner_cell_and_ordinal() {
            let source = GuestVa(0x40_0100);
            let target = GuestVa(0x50_0100);
            let fixture = sidecar_unit(key(1), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            let cell = fixture.unit.binding_base.expect("binding base");

            let owner = state
                .direct_bindings
                .owner_key(
                    DirectBindingMiss {
                        cell,
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                    source,
                    target,
                )
                .expect("exact owner");
            assert_eq!(owner.unit, fixture.unit.manifest.key);
            assert_eq!(owner.ordinal, DirectBindingOrdinal::claimed(0));
            assert_eq!(
                state.direct_bindings.owner_key(
                    DirectBindingMiss {
                        cell,
                        ordinal: DirectBindingOrdinal::claimed(1),
                    },
                    source,
                    target,
                ),
                None,
            );
            assert_eq!(
                state.direct_bindings.owner_key(
                    DirectBindingMiss {
                        cell: DirectBindingCellVa::mapped(
                            fixture.storage.as_ptr() as usize + DIRECT_BINDING_CELL_SIZE as usize,
                        )
                        .expect("aligned adjacent address"),
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                    source,
                    target,
                ),
                None,
            );
        }

        #[test]
        fn guest_source_target_pair_cannot_select_another_unit_instance() {
            let source = GuestVa(0x40_0200);
            let target = GuestVa(0x50_0200);
            let first = sidecar_unit(key(2), vec![record(source, target, 0)]);
            let second = sidecar_unit(key(3), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&first.unit)
                .expect("register first")
                .expect("first owner");
            state
                .direct_bindings
                .register_loaded_unit(&second.unit)
                .expect("register second")
                .expect("second owner");

            let owner = state
                .direct_bindings
                .owner_key(
                    DirectBindingMiss {
                        cell: first.unit.binding_base.expect("first binding base"),
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                    source,
                    target,
                )
                .expect("first exact owner");

            assert_eq!(owner.unit, first.unit.manifest.key);
            assert_ne!(owner.unit, second.unit.manifest.key);
        }

        #[test]
        fn active_source_after_cross_unit_hit_selects_exit_time_authority() {
            let a_source = GuestVa(0x40_1000);
            let b_source = GuestVa(0x40_2000);
            let target = GuestVa(0x50_1000);
            let first = sidecar_unit(key(20), vec![record(a_source, b_source, 0)]);
            let second = sidecar_unit(key(21), vec![record(b_source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&first.unit)
                .expect("register A");
            state
                .direct_bindings
                .register_loaded_unit(&second.unit)
                .expect("register B");

            let selected = state
                .direct_bindings
                .classify_cold_exit(
                    b_source,
                    target,
                    DirectBindingExitMetadata::Mapped(DirectBindingMiss {
                        cell: second.unit.binding_base.expect("B cell"),
                        ordinal: DirectBindingOrdinal::claimed(0),
                    }),
                )
                .expect("B is the exact exit-time source");

            assert_eq!(
                selected,
                DirectBindingEligibility {
                    unit: second.unit.manifest.key.clone(),
                    ordinal: DirectBindingOrdinal::claimed(0),
                    cell: second.unit.binding_base,
                }
            );
        }

        #[test]
        fn duplicate_source_target_never_guesses_active_source() {
            let source = GuestVa(0x40_3000);
            let target = GuestVa(0x50_3000);
            let first = disabled_unit(key(22), vec![record(source, target, 0)]);
            let second = disabled_unit(key(23), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&first)
                .expect("register first disabled manifest");
            state
                .direct_bindings
                .register_loaded_unit(&second)
                .expect("register second disabled manifest");

            assert_eq!(
                state.direct_bindings.classify_cold_exit(
                    source,
                    target,
                    DirectBindingExitMetadata::Absent
                ),
                Err(DirectBindingValidationReason::AmbiguousEligibleRecord),
            );
        }

        #[test]
        fn disabled_unit_retains_manifest_ordinal_with_zero_cell() {
            let source = GuestVa(0x40_4000);
            let target = GuestVa(0x50_4000);
            let unit = disabled_unit(key(24), vec![record(source, target, 7)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            assert_eq!(
                state
                    .direct_bindings
                    .register_loaded_unit(&unit)
                    .expect("retain disabled manifest"),
                None,
            );

            let selected = state
                .direct_bindings
                .classify_cold_exit(source, target, DirectBindingExitMetadata::Absent)
                .expect("disabled eligibility remains authoritative");
            assert_eq!(selected.ordinal, DirectBindingOrdinal::claimed(7));
            assert_eq!(selected.cell, None);
        }

        #[test]
        fn missing_or_mismatched_cold_authority_fails_before_publication() {
            let source = GuestVa(0x40_5000);
            let target = GuestVa(0x50_5000);
            let fixture = sidecar_unit(key(25), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register sidecar");

            assert_eq!(
                state.direct_bindings.classify_cold_exit(
                    GuestVa(0x40_5004),
                    target,
                    DirectBindingExitMetadata::Absent,
                ),
                Err(DirectBindingValidationReason::MissingEligibleRecord),
            );
            assert_eq!(
                state.direct_bindings.classify_cold_exit(
                    source,
                    target,
                    DirectBindingExitMetadata::Absent
                ),
                Err(DirectBindingValidationReason::MissMetadataMismatch),
            );
            assert!(fixture.storage[0].load(Ordering::Acquire).is_null());
        }

        #[test]
        fn malformed_present_cell_is_a_mapped_cell_failure() {
            let source = GuestVa(0x40_6000);
            let target = GuestVa(0x50_6000);
            let fixture = sidecar_unit(key(26), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register sidecar");

            assert_eq!(
                state.direct_bindings.classify_cold_exit(
                    source,
                    target,
                    DirectBindingExitMetadata::MappedCellFailure {
                        raw_cell: 0x20_001,
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                ),
                Err(DirectBindingValidationReason::MappedCellFailure),
            );
            assert!(fixture.storage[0].load(Ordering::Acquire).is_null());
        }

        #[test]
        fn first_publisher_sets_the_bitmap_and_incoming_record() {
            let source = GuestVa(0x40_0300);
            let target = GuestVa(0x50_0300);
            let fixture = sidecar_unit(key(4), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let mut state = process.state.write();
            let unit_index = state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");

            let outcome = state.direct_bindings.publish(
                miss,
                source,
                target,
                private_target(target, CodeGeneration::INITIAL, 0x80_0100, &epoch),
            );

            assert_eq!(outcome, DirectBindingPublishOutcome::Published);
            assert!(state.direct_bindings.is_published(unit_index, miss.ordinal));
            assert_eq!(
                state
                    .direct_bindings
                    .incoming_count(target, CodeGeneration::INITIAL),
                1,
            );
            assert!(!fixture.storage[0].load(Ordering::Acquire).is_null());
        }

        #[test]
        fn a_valid_losing_publisher_accepts_the_complete_winner() {
            let source = GuestVa(0x40_0400);
            let target = GuestVa(0x50_0400);
            let fixture = sidecar_unit(key(5), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    miss,
                    source,
                    target,
                    private_target(target, CodeGeneration::INITIAL, 0x80_0200, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            let winner = fixture.storage[0].load(Ordering::Acquire);

            let outcome = state.direct_bindings.publish(
                miss,
                source,
                target,
                private_target(target, CodeGeneration::INITIAL, 0x80_0200, &epoch),
            );

            assert_eq!(outcome, DirectBindingPublishOutcome::ExistingWinner);
            assert_eq!(fixture.storage[0].load(Ordering::Acquire), winner);
            assert_eq!(
                state
                    .direct_bindings
                    .incoming_count(target, CodeGeneration::INITIAL),
                1,
            );
            assert_eq!(state.direct_bindings.counters().cas_losses, 1);
        }

        #[test]
        fn a_stale_winner_is_exactly_cleared_and_retried_once() {
            let source = GuestVa(0x40_0500);
            let target = GuestVa(0x50_0500);
            let fixture = sidecar_unit(key(6), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    miss,
                    source,
                    target,
                    private_target(target, CodeGeneration::claimed(1), 0x80_0300, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            let stale = fixture.storage[0].load(Ordering::Acquire);

            let outcome = state.direct_bindings.publish(
                miss,
                source,
                target,
                private_target(target, CodeGeneration::claimed(2), 0x80_0400, &epoch),
            );

            assert_eq!(outcome, DirectBindingPublishOutcome::PublishedAfterStale);
            assert_ne!(fixture.storage[0].load(Ordering::Acquire), stale);
            assert_eq!(state.direct_bindings.counters().stale_winner_clears, 1);
            assert_eq!(state.direct_bindings.counters().publication_retries, 1);
            assert_eq!(
                state
                    .direct_bindings
                    .incoming_count(target, CodeGeneration::claimed(2)),
                1,
            );
        }

        #[test]
        fn a_replacement_winner_survives_a_lost_exact_stale_clear() {
            let source = GuestVa(0x40_0580);
            let target = GuestVa(0x50_0580);
            let fixture = sidecar_unit(key(8), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let mut state = process.state.write();
            let unit_index = state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    miss,
                    source,
                    target,
                    private_target(target, CodeGeneration::claimed(1), 0x80_0600, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            let stale = fixture.storage[0].load(Ordering::Acquire);
            let mut replacement = std::ptr::null_mut();

            let outcome = state.direct_bindings.publish_with_stale_observer_for_test(
                miss,
                source,
                target,
                private_target(target, CodeGeneration::claimed(2), 0x80_0700, &epoch),
                |registry, observed_stale| {
                    assert_eq!(observed_stale, stale);
                    // SAFETY: the fixture owns this live `AtomicPtr` cell
                    // until the state guard and registry are dropped.
                    let cell = unsafe {
                        DirectBindingCellRef::from_mapped_address(miss.cell).expect("fixture cell")
                    };
                    assert!(cell.clear_if(observed_stale));
                    assert_eq!(
                        registry.publish(
                            miss,
                            source,
                            target,
                            private_target(target, CodeGeneration::claimed(3), 0x80_0800, &epoch,),
                        ),
                        DirectBindingPublishOutcome::Published,
                    );
                    replacement = cell.load_acquire();
                    assert!(!replacement.is_null());
                },
            );

            assert_eq!(outcome, DirectBindingPublishOutcome::Rejected);
            assert_eq!(fixture.storage[0].load(Ordering::Acquire), replacement);
            assert!(state.direct_bindings.is_published(unit_index, miss.ordinal));
            assert_eq!(
                state
                    .direct_bindings
                    .incoming_count(target, CodeGeneration::claimed(3)),
                1,
            );
        }

        #[test]
        fn failed_owner_or_authority_validation_leaves_the_cell_null() {
            let source = GuestVa(0x40_0600);
            let target = GuestVa(0x50_0600);
            let fixture = sidecar_unit(key(7), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let cell = fixture.unit.binding_base.expect("binding base");
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");

            assert_eq!(
                state.direct_bindings.publish(
                    DirectBindingMiss {
                        cell,
                        ordinal: DirectBindingOrdinal::claimed(1),
                    },
                    source,
                    target,
                    private_target(target, CodeGeneration::INITIAL, 0x80_0500, &epoch),
                ),
                DirectBindingPublishOutcome::Rejected,
            );
            assert!(fixture.storage[0].load(Ordering::Acquire).is_null());

            assert_eq!(
                state.direct_bindings.publish(
                    DirectBindingMiss {
                        cell,
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                    source,
                    target,
                    private_target(target, CodeGeneration::INITIAL, 0x90_0000, &epoch),
                ),
                DirectBindingPublishOutcome::Rejected,
            );
            assert!(fixture.storage[0].load(Ordering::Acquire).is_null());
        }
    }

    mod direct_binding_fork_reset {
        use super::direct_binding_owner_and_publication::{
            UnitFixture, key, private_target, process_with_direct_bindings, record, sidecar_unit,
        };
        use crate::direct_binding::{
            DirectBindingCellRef, DirectBindingCellVa, DirectBindingMiss, DirectBindingOrdinal,
            DirectBindingPublishOutcome, DirectBindingTarget,
        };
        use crate::types::CodeGeneration;
        use carrick_guest_mem::GuestVa;
        use std::sync::atomic::Ordering;

        pub(super) fn one_published_binding(
            seed: u8,
        ) -> (UnitFixture, super::ProcessTranslator, GuestVa, GuestVa) {
            let source = GuestVa(0x41_0000 + u64::from(seed) * 0x100);
            let target = GuestVa(0x51_0000 + u64::from(seed) * 0x100);
            let fixture = sidecar_unit(key(seed), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    DirectBindingMiss {
                        cell: fixture.unit.binding_base.expect("binding base"),
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                    source,
                    target,
                    private_target(
                        target,
                        CodeGeneration::INITIAL,
                        0x80_0100,
                        &process.private_jit_epoch,
                    ),
                ),
                DirectBindingPublishOutcome::Published,
            );
            drop(state);
            (fixture, process, source, target)
        }

        fn child_exit_status(pid: libc::pid_t) -> i32 {
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
            libc::WEXITSTATUS(status)
        }

        #[test]
        fn fork_child_clears_only_published_ordinals_without_allocation() {
            let records = (0..70_u32)
                .map(|ordinal| {
                    record(
                        GuestVa(0x42_0000 + u64::from(ordinal) * 4),
                        GuestVa(0x52_0000 + u64::from(ordinal) * 4),
                        ordinal,
                    )
                })
                .collect::<Vec<_>>();
            let fixture = sidecar_unit(key(20), records);
            let process = process_with_direct_bindings();
            let unit_index;
            {
                let mut state = process.state.write();
                unit_index = state
                    .direct_bindings
                    .register_loaded_unit(&fixture.unit)
                    .expect("register owner")
                    .expect("SidecarV1 owner");
                for ordinal in [1_u32, 65] {
                    let source = GuestVa(0x42_0000 + u64::from(ordinal) * 4);
                    let target = GuestVa(0x52_0000 + u64::from(ordinal) * 4);
                    assert_eq!(
                        state.direct_bindings.publish(
                            DirectBindingMiss {
                                cell: DirectBindingCellVa::mapped(
                                    fixture.storage.as_ptr() as usize
                                        + ordinal as usize
                                            * crate::shared_cache::DIRECT_BINDING_CELL_SIZE
                                                as usize,
                                )
                                .expect("published cell"),
                                ordinal: DirectBindingOrdinal::claimed(ordinal),
                            },
                            source,
                            target,
                            private_target(
                                target,
                                CodeGeneration::INITIAL,
                                0x80_1000 + u64::from(ordinal) * 4,
                                &process.private_jit_epoch,
                            ),
                        ),
                        DirectBindingPublishOutcome::Published,
                    );
                }
            }
            let unpublished_target = Box::new(private_target(
                GuestVa(0x52_0008),
                CodeGeneration::INITIAL,
                0x80_2000,
                &process.private_jit_epoch,
            ));
            let unpublished_pointer =
                std::ptr::from_ref::<DirectBindingTarget>(unpublished_target.as_ref()).cast_mut();
            let unpublished_cell =
                DirectBindingCellVa::mapped(fixture.storage.as_ptr() as usize + 2 * 8)
                    .expect("unpublished cell");
            // SAFETY: the fixture owns this live cell and `unpublished_target`
            // outlives every load below.
            unsafe {
                DirectBindingCellRef::from_mapped_address(unpublished_cell)
                    .expect("fixture cell")
                    .publish_null(unpublished_pointer)
                    .expect("install untracked sentinel");
            }
            let before = process
                .state
                .read()
                .direct_bindings
                .arena_snapshot_for_test(unit_index);

            let stats = process.after_fork_child();

            let after = process
                .state
                .read()
                .direct_bindings
                .arena_snapshot_for_test(unit_index);
            assert_eq!(after, before, "fork repair must not grow or reclaim arenas");
            assert_eq!(stats.cells_cleared, 2);
            assert!(stats.pages_touched >= 1);
            assert!(fixture.storage[1].load(Ordering::Acquire).is_null());
            assert!(fixture.storage[65].load(Ordering::Acquire).is_null());
            assert_eq!(
                fixture.storage[2].load(Ordering::Acquire),
                unpublished_pointer,
                "a cell without a published bitmap bit must not be touched"
            );
        }

        #[test]
        fn fork_child_clear_is_cow_private_from_the_parent() {
            let (fixture, process, _, _) = one_published_binding(21);
            let parent_pointer = fixture.storage[0].load(Ordering::Acquire);
            assert!(!parent_pointer.is_null());

            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if pid == 0 {
                process.after_fork_child();
                let cleared = fixture.storage[0].load(Ordering::Acquire).is_null();
                unsafe { libc::_exit(i32::from(!cleared)) };
            }

            assert_eq!(
                child_exit_status(pid),
                0,
                "child did not clear its COW cell"
            );
            assert_eq!(
                fixture.storage[0].load(Ordering::Acquire),
                parent_pointer,
                "child repair must not mutate the parent's COW sidecar"
            );
        }

        #[test]
        fn child_rebind_does_not_mutate_parent_cells() {
            let (fixture, process, source, target) = one_published_binding(22);
            let parent_pointer = fixture.storage[0].load(Ordering::Acquire);
            assert!(!parent_pointer.is_null());

            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if pid == 0 {
                process.after_fork_child();
                let outcome = process.state.write().direct_bindings.publish(
                    DirectBindingMiss {
                        cell: fixture.unit.binding_base.expect("binding base"),
                        ordinal: DirectBindingOrdinal::claimed(0),
                    },
                    source,
                    target,
                    private_target(
                        target,
                        CodeGeneration::INITIAL,
                        0x80_0200,
                        &process.private_jit_epoch,
                    ),
                );
                let rebound = fixture.storage[0].load(Ordering::Acquire);
                let private_rebind =
                    outcome == DirectBindingPublishOutcome::Published && rebound != parent_pointer;
                unsafe { libc::_exit(i32::from(!private_rebind)) };
            }

            assert_eq!(child_exit_status(pid), 0, "child did not rebind from null");
            assert_eq!(
                fixture.storage[0].load(Ordering::Acquire),
                parent_pointer,
                "the child's new descriptor must stay private to its COW image"
            );
        }

        #[test]
        fn fork_child_retains_inherited_catalog_and_publishes_through_cow() {
            let process = process_with_direct_bindings();
            let inherited = 0x90_0000..0x91_0000;
            process
                .state
                .write()
                .executable_ranges
                .prepend(inherited.start, inherited.end)
                .expect("publish inherited executable range");
            let parent_head = process.state.read().executable_ranges.head_ptr();

            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if pid == 0 {
                process.after_fork_child();
                let child_only = 0xa0_0000..0xa1_0000;
                let mut state = process.state.write();
                let inherited_visible = state.executable_ranges.contains(inherited.start + 0x100);
                state
                    .executable_ranges
                    .prepend(child_only.start, child_only.end)
                    .expect("publish child-only executable range");
                let child_visible = state.executable_ranges.contains(child_only.start + 0x100);
                let child_head_changed = state.executable_ranges.head_ptr() != parent_head;
                unsafe {
                    libc::_exit(i32::from(
                        !(inherited_visible && child_visible && child_head_changed),
                    ))
                };
            }

            assert_eq!(
                child_exit_status(pid),
                0,
                "child did not retain and extend its inherited catalog"
            );
            let state = process.state.read();
            assert_eq!(
                state.executable_ranges.head_ptr(),
                parent_head,
                "child catalog publication must not mutate the parent COW header"
            );
            assert!(state.executable_ranges.contains(inherited.start + 0x100));
            assert!(
                !state.executable_ranges.contains(0xa0_0100),
                "child-only executable range leaked into the parent catalog"
            );
        }
    }

    mod direct_binding_exec_reset {
        use super::super::{DirectBindingResetEvent, ThreadTranslator};
        use super::direct_binding_fork_reset::one_published_binding;
        use crate::types::{CacheVa, CodeGeneration};
        use carrick_guest_mem::{GuestVa, HostVa};
        use std::sync::Arc;

        const EXPECTED_ORDER: [DirectBindingResetEvent; 8] = [
            DirectBindingResetEvent::CellsCleared,
            DirectBindingResetEvent::ThreadCachesCleared,
            DirectBindingResetEvent::IndexesCleared,
            DirectBindingResetEvent::DescriptorsDropped,
            DirectBindingResetEvent::ExecutableRangeHeadReset,
            DirectBindingResetEvent::UnitsDropped,
            DirectBindingResetEvent::ExecutableRangeNodesDropped,
            DirectBindingResetEvent::PrivateCursorReset,
        ];

        fn publish_catalog_range(
            process: &super::super::ProcessTranslator,
            seed: usize,
        ) -> std::ops::Range<usize> {
            let start = 0xb0_0000 + seed * 0x20_000;
            let range = start..start + 0x10_000;
            process
                .state
                .write()
                .executable_ranges
                .prepend(range.start, range.end)
                .expect("publish test executable range");
            range
        }

        fn catalog_head(process: &super::super::ProcessTranslator) -> usize {
            process.state.read().executable_ranges.head_ptr() as usize
        }

        fn prepare_thread(
            process: &Arc<super::super::ProcessTranslator>,
        ) -> (ThreadTranslator, super::super::DirectBindingExecResetToken) {
            let guest = GuestVa(0x60_0000);
            let entry = CacheVa::published(HostVa(process.cache_host_range().start as usize));
            let mut thread = ThreadTranslator::for_process(Arc::clone(process), 42);
            thread
                .block_cache
                .insert(guest, CodeGeneration::INITIAL, entry);
            thread.indirect_cache.publish(
                guest,
                CodeGeneration::INITIAL,
                entry,
                process.private_target_authority.as_ref(),
            );
            // SAFETY: the thread exclusively owns this fixed-layout cache,
            // and the slice covers exactly its two 32-byte ways per set.
            let words_before = unsafe {
                std::slice::from_raw_parts(
                    thread.indirect_cache.as_ptr().cast::<u64>(),
                    crate::gateway::INDIRECT_CACHE_ENTRIES * 8,
                )
            };
            assert!(words_before.iter().any(|word| *word != 0));

            let token = thread.prepare_direct_binding_exec_reset();

            assert!(thread.block_cache.is_empty());
            // SAFETY: as above; preparation completed synchronously while
            // this test retains exclusive access to the thread translator.
            let words_after = unsafe {
                std::slice::from_raw_parts(
                    thread.indirect_cache.as_ptr().cast::<u64>(),
                    crate::gateway::INDIRECT_CACHE_ENTRIES * 8,
                )
            };
            assert!(words_after.iter().all(|word| *word == 0));
            (thread, token)
        }

        #[test]
        fn valid_exec_reset_token_yields_exact_catalog_lifecycle_order() {
            let (fixture, process, _, _) = one_published_binding(23);
            let process = Arc::new(process);
            let shared_range = publish_catalog_range(&process, 23);
            let (thread, mut token) = prepare_thread(&process);
            let mut events = Vec::new();

            process
                .reset_after_fork_for_exec_with_recorder(&thread, &mut token, |event| {
                    events.push(event);
                })
                .expect("valid exec reset authority");

            assert_eq!(events, EXPECTED_ORDER);
            let state = process.state.read();
            assert_eq!(state.executable_ranges.shared_node_count(), 0);
            assert!(
                !state.executable_ranges.contains(shared_range.start + 0x100),
                "authorized exec reset retained a shared executable range"
            );
            drop(state);
            assert!(
                fixture.storage[0]
                    .load(std::sync::atomic::Ordering::Acquire)
                    .is_null(),
                "exec must clear every published cell before retiring its descriptor"
            );
        }

        #[test]
        fn private_cursor_reuse_requires_the_last_descriptor_epoch_lease_to_drop() {
            let (_fixture, process, _, _) = one_published_binding(24);
            let process = Arc::new(process);
            let (mut thread, mut token) = prepare_thread(&process);
            assert_eq!(process.private_epoch_leases_for_test(), 1);
            let mut first = Vec::new();

            process
                .reset_after_fork_for_exec_with_recorder(&thread, &mut token, |event| {
                    first.push(event);
                })
                .expect("first authorized reset");

            assert_eq!(process.private_epoch_leases_for_test(), 0);
            assert_eq!(first, EXPECTED_ORDER);
            let mut second_token = thread.prepare_direct_binding_exec_reset();
            let mut second = Vec::new();
            process
                .reset_after_fork_for_exec_with_recorder(&thread, &mut second_token, |event| {
                    second.push(event)
                })
                .expect("fresh authority keeps successful reset idempotent");
            assert_eq!(second, EXPECTED_ORDER, "exec reset must be idempotent");
            assert_eq!(process.private_epoch_leases_for_test(), 0);
            thread.reset_for_exec(Arc::clone(&process));
            assert!(thread.block_cache.is_empty());
        }

        #[test]
        fn foreign_process_exec_reset_authority_is_rejected() {
            let (_authority_fixture, authority_process, _, _) = one_published_binding(25);
            let authority_process = Arc::new(authority_process);
            let (_authority_thread, mut token) = prepare_thread(&authority_process);
            let (victim_fixture, victim_process, _, _) = one_published_binding(26);
            let victim_process = Arc::new(victim_process);
            let _shared_range = publish_catalog_range(&victim_process, 26);
            let catalog_before = catalog_head(&victim_process);
            let victim_thread = ThreadTranslator::for_process(Arc::clone(&victim_process), 43);

            let outcome = victim_process.reset_after_fork_for_exec(&victim_thread, &mut token);

            assert!(outcome.is_err(), "foreign process token must fail");
            assert_eq!(
                catalog_head(&victim_process),
                catalog_before,
                "foreign exec-reset authority mutated the executable catalog"
            );
            assert!(
                !victim_fixture.storage[0]
                    .load(std::sync::atomic::Ordering::Acquire)
                    .is_null(),
                "failed validation must precede every published-cell mutation"
            );
        }

        #[test]
        fn exec_reset_authority_from_another_thread_is_rejected() {
            let (fixture, process, _, _) = one_published_binding(27);
            let process = Arc::new(process);
            let _shared_range = publish_catalog_range(&process, 27);
            let catalog_before = catalog_head(&process);
            let (_other_thread, mut token) = prepare_thread(&process);
            let surviving_thread = ThreadTranslator::for_process(Arc::clone(&process), 43);
            assert!(surviving_thread.block_cache.is_empty());

            let outcome = process.reset_after_fork_for_exec(&surviving_thread, &mut token);

            assert!(
                outcome.is_err(),
                "a different surviving thread must not inherit reset authority"
            );
            assert_eq!(
                catalog_head(&process),
                catalog_before,
                "foreign-thread exec-reset authority mutated the executable catalog"
            );
            assert!(
                !fixture.storage[0]
                    .load(std::sync::atomic::Ordering::Acquire)
                    .is_null(),
                "foreign-thread rejection must leave published cells intact"
            );
        }

        #[test]
        fn reused_exec_reset_authority_is_rejected() {
            let (_fixture, process, _, _) = one_published_binding(28);
            let process = Arc::new(process);
            let _shared_range = publish_catalog_range(&process, 28);
            let (thread, mut token) = prepare_thread(&process);

            process
                .reset_after_fork_for_exec(&thread, &mut token)
                .expect("first token consumption");
            let catalog_before_reuse = catalog_head(&process);
            let second = process.reset_after_fork_for_exec(&thread, &mut token);

            assert!(second.is_err(), "exec reset authority must be single-use");
            assert_eq!(
                catalog_head(&process),
                catalog_before_reuse,
                "reused exec-reset authority mutated the executable catalog"
            );
        }

        #[test]
        fn failed_exec_reset_validation_leaves_published_cell_intact() {
            let (fixture, process, _, _) = one_published_binding(29);
            let process = Arc::new(process);
            let _shared_range = publish_catalog_range(&process, 29);
            let catalog_before = catalog_head(&process);
            let mut thread = ThreadTranslator::for_process(Arc::clone(&process), 42);
            let mut stale = thread.prepare_direct_binding_exec_reset();
            let _current = thread.prepare_direct_binding_exec_reset();

            let outcome = process.reset_after_fork_for_exec(&thread, &mut stale);

            assert!(outcome.is_err(), "stale reset authority must fail");
            assert_eq!(
                catalog_head(&process),
                catalog_before,
                "stale exec-reset authority mutated the executable catalog"
            );
            assert!(
                !fixture.storage[0]
                    .load(std::sync::atomic::Ordering::Acquire)
                    .is_null(),
                "validation must complete before the first cell clear"
            );
        }
    }

    mod direct_binding_target_generation_invalidation {
        use super::direct_binding_owner_and_publication::{
            key, private_target, process_with_direct_bindings, record, sidecar_unit,
        };
        use crate::direct_binding::{
            DirectBindingCellRef, DirectBindingMiss, DirectBindingOrdinal,
            DirectBindingPublishOutcome, DirectBindingTarget, PrivateJitEpoch,
        };
        use crate::types::CodeGeneration;
        use carrick_dsr::cache::PageGenerationTable;
        use carrick_guest_mem::GuestVa;
        use std::sync::atomic::Ordering;

        fn traversal_or_resolve(
            cell: DirectBindingCellRef,
            resolver: impl FnOnce(),
        ) -> *mut DirectBindingTarget {
            let acquired = cell.load_acquire();
            if !acquired.is_null() {
                return acquired;
            }
            resolver();
            let rebound = cell.load_acquire();
            assert!(
                !rebound.is_null(),
                "resolver must publish the rebound target"
            );
            rebound
        }

        #[test]
        fn target_generation_invalidation_clears_only_the_expected_descriptor() {
            let first_source = GuestVa(0x41_0100);
            let second_source = GuestVa(0x41_0200);
            let target = GuestVa(0x51_0100);
            let old_generation = CodeGeneration::claimed(1);
            let new_generation = CodeGeneration::claimed(2);
            let fixture = sidecar_unit(
                key(9),
                vec![
                    record(first_source, target, 0),
                    record(second_source, target, 1),
                ],
            );
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let first_miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let second_miss = DirectBindingMiss {
                cell: crate::direct_binding::DirectBindingCellVa::mapped(
                    fixture.storage.as_ptr() as usize
                        + crate::shared_cache::DIRECT_BINDING_CELL_SIZE as usize,
                )
                .expect("second cell"),
                ordinal: DirectBindingOrdinal::claimed(1),
            };
            let mut state = process.state.write();
            let unit_index = state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    first_miss,
                    first_source,
                    target,
                    private_target(target, old_generation, 0x80_1100, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            assert_eq!(
                state.direct_bindings.publish(
                    second_miss,
                    second_source,
                    target,
                    private_target(target, old_generation, 0x80_1200, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            assert_eq!(
                state.direct_bindings.publish(
                    second_miss,
                    second_source,
                    target,
                    private_target(target, new_generation, 0x80_1300, &epoch),
                ),
                DirectBindingPublishOutcome::PublishedAfterStale,
            );
            let newer = fixture.storage[1].load(Ordering::Acquire);

            let stats = state
                .direct_bindings
                .invalidate_target(target, old_generation);

            assert!(
                fixture.storage[0].load(Ordering::Acquire).is_null(),
                "the exact old descriptor must be cleared"
            );
            assert_eq!(fixture.storage[1].load(Ordering::Acquire), newer);
            assert!(
                !state
                    .direct_bindings
                    .is_published(unit_index, DirectBindingOrdinal::claimed(0))
            );
            assert!(
                state
                    .direct_bindings
                    .is_published(unit_index, DirectBindingOrdinal::claimed(1))
            );
            assert_eq!(stats.visited, 2);
            assert_eq!(stats.exact_clears, 1);
            assert_eq!(stats.newer_publication_misses, 1);
            assert_eq!(stats.bitmap_bits_cleared, 1);
            assert_eq!(
                state.direct_bindings.incoming_count(target, old_generation),
                0,
            );
            assert_eq!(
                state.direct_bindings.incoming_count(target, new_generation),
                1,
            );
        }

        #[test]
        fn a_reader_of_the_old_descriptor_remains_safe_until_generation_guard() {
            let source = GuestVa(0x42_0100);
            let target = GuestVa(0x52_0100);
            let generations = PageGenerationTable::new(16 * 1024).expect("generation table");
            let old_generation = generations
                .observe(target)
                .expect("old target observation")
                .expected();
            let fixture = sidecar_unit(key(10), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    miss,
                    source,
                    target,
                    private_target(target, old_generation, 0x80_2100, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            let acquired = fixture.storage[0].load(Ordering::Acquire);
            assert!(!acquired.is_null());
            let current_generation = generations
                .note_guest_code_write(target..GuestVa(target.raw() + 4))
                .expect("target generation mutation");

            let stats = state
                .direct_bindings
                .invalidate_target(target, old_generation);

            assert!(fixture.storage[0].load(Ordering::Acquire).is_null());
            assert_eq!(stats.exact_clears, 1);
            assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 1);
            // SAFETY: invalidation unpublishes but never reclaims descriptors;
            // the process-owned registry still pins this acquired pointer.
            let old_reader = unsafe { &*acquired };
            assert_eq!(old_reader.target_page(), target);
            assert_eq!(old_reader.target_generation(), old_generation);
            assert_eq!(
                generations
                    .generation_for_pc(target)
                    .expect("current target generation"),
                current_generation
            );
            assert_ne!(
                old_reader.target_generation(),
                current_generation,
                "the target entry generation guard must reject the old reader"
            );
            assert!(
                !generations
                    .is_current(target, old_reader.target_generation())
                    .expect("generation guard check")
            );
        }

        #[test]
        fn the_next_traversal_rebinds_and_then_stays_out_of_the_resolver() {
            let source = GuestVa(0x43_0100);
            let target = GuestVa(0x53_0100);
            let old_generation = CodeGeneration::claimed(7);
            let new_generation = CodeGeneration::claimed(8);
            let fixture = sidecar_unit(key(11), vec![record(source, target, 0)]);
            let process = process_with_direct_bindings();
            let epoch = PrivateJitEpoch::process_owner();
            let miss = DirectBindingMiss {
                cell: fixture.unit.binding_base.expect("binding base"),
                ordinal: DirectBindingOrdinal::claimed(0),
            };
            let mut state = process.state.write();
            state
                .direct_bindings
                .register_loaded_unit(&fixture.unit)
                .expect("register owner")
                .expect("SidecarV1 owner");
            assert_eq!(
                state.direct_bindings.publish(
                    miss,
                    source,
                    target,
                    private_target(target, old_generation, 0x80_3100, &epoch),
                ),
                DirectBindingPublishOutcome::Published,
            );
            let _ = state
                .direct_bindings
                .invalidate_target(target, old_generation);
            let cell = unsafe {
                DirectBindingCellRef::from_mapped_address(miss.cell).expect("fixture cell")
            };
            let mut resolver_exits = 0_u64;

            let rebound = traversal_or_resolve(cell, || {
                resolver_exits += 1;
                assert_eq!(
                    state.direct_bindings.publish(
                        miss,
                        source,
                        target,
                        private_target(target, new_generation, 0x80_3200, &epoch),
                    ),
                    DirectBindingPublishOutcome::Published,
                );
            });
            let repeated = traversal_or_resolve(cell, || {
                resolver_exits += 1;
            });

            assert_eq!(resolver_exits, 1);
            assert_eq!(repeated, rebound);
            // SAFETY: the registry pins the rebound descriptor.
            assert_eq!(unsafe { &*rebound }.target_generation(), new_generation);
        }
    }

    #[test]
    fn dsr_error_probe_outcomes_cover_every_error_category() {
        use carrick_dsr::probes::DsrOperationOutcome;

        let op = bad64::decode(0xd400_0001, PC.raw())
            .expect("decode svc")
            .op();
        let cases = [
            (
                types::DsrError::PcOverflow { pc: PC.raw() },
                DsrOperationOutcome::PcOverflow,
            ),
            (
                types::DsrError::Decode {
                    pc: PC.raw(),
                    word: 0,
                    detail: "decode".to_string(),
                },
                DsrOperationOutcome::Decode,
            ),
            (
                types::DsrError::Malformed {
                    pc: PC.raw(),
                    word: 0xd400_0001,
                    op,
                },
                DsrOperationOutcome::Malformed,
            ),
            (
                types::DsrError::BlockPolicy("block".to_string()),
                DsrOperationOutcome::BlockPolicy,
            ),
            (
                types::DsrError::MemoryRead {
                    pc: PC.raw(),
                    detail: "read".to_string(),
                },
                DsrOperationOutcome::MemoryRead,
            ),
            (
                types::DsrError::UnsupportedBlockAction {
                    block_start: PC.raw(),
                    generation: 1,
                    guest_pc: PC.raw(),
                    word: 0xd400_0001,
                    op,
                    class: "test",
                },
                DsrOperationOutcome::UnsupportedBlockAction,
            ),
            (
                types::DsrError::Assembler("assembler".to_string()),
                DsrOperationOutcome::Assembler,
            ),
            (
                types::DsrError::Gateway("gateway".to_string()),
                DsrOperationOutcome::Gateway,
            ),
            (
                types::DsrError::CachePolicy("cache".to_string()),
                DsrOperationOutcome::CachePolicy,
            ),
            (
                types::DsrError::GenerationChanged {
                    page: PC.raw(),
                    expected: 1,
                    observed: 2,
                },
                DsrOperationOutcome::GenerationChanged,
            ),
            (
                types::DsrError::Host {
                    operation: "test",
                    error: std::io::Error::from_raw_os_error(libc::EINVAL),
                },
                DsrOperationOutcome::Host,
            ),
            (
                types::DsrError::CacheCapacity {
                    requested: 8,
                    used: 12,
                    capacity: 16,
                },
                DsrOperationOutcome::CacheCapacity,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.probe_outcome(), expected, "error={error}");
        }
    }

    #[test]
    fn native_dsr_exit_probe_fields_classify_every_variant() {
        use carrick_dsr::probes::DsrExitKind;
        use types::{CodeGeneration, NativeDsrExit};

        let op = bad64::decode(0xd400_0001, PC.raw())
            .expect("decode svc")
            .op();
        let target = GuestVa(0x2000);
        let cases = [
            (
                NativeDsrExit::Syscall { resume: target },
                (DsrExitKind::Syscall, target.raw(), 0, 1),
            ),
            (
                NativeDsrExit::ResolveDirect {
                    source: PC,
                    target,
                    binding: crate::direct_binding::DirectBindingExitMetadata::Absent,
                },
                (DsrExitKind::DirectResolver, PC.raw(), target.raw(), 2),
            ),
            (
                NativeDsrExit::ResolveIndirect {
                    source: PC,
                    target,
                    link: None,
                },
                (DsrExitKind::IndirectResolver, PC.raw(), target.raw(), 3),
            ),
            (
                NativeDsrExit::Fault {
                    guest_pc: PC,
                    signal: libc::SIGSEGV,
                    code: 0,
                    address: carrick_guest_mem::HostVa(target.raw() as usize),
                    rewrite_scratch: 0,
                    rewrite_context_scratch: 0,
                    generation_pstate_scratch: 0,
                    indirect_x15_scratch: 0,
                    indirect_x30_scratch: 0,
                    physical_x18: 0,
                    gateway_phase: 0,
                    biased_guest_fault_address: 0,
                },
                (DsrExitKind::Fault, PC.raw(), target.raw(), 4),
            ),
            (
                NativeDsrExit::Kick {
                    resume: target,
                    rewrite_scratch: 0,
                    rewrite_context_scratch: 0,
                    generation_pstate_scratch: 0,
                    indirect_x15_scratch: 0,
                    indirect_x30_scratch: 0,
                },
                (DsrExitKind::Kick, target.raw(), 0, 5),
            ),
            (
                NativeDsrExit::Sensitive {
                    guest_pc: PC,
                    resume: target,
                    generation: CodeGeneration::INITIAL,
                },
                (DsrExitKind::Sensitive, PC.raw(), target.raw(), 6),
            ),
            (
                NativeDsrExit::Unsupported {
                    guest_pc: PC,
                    word: 0xd400_0001,
                    op,
                },
                (DsrExitKind::Unsupported, PC.raw(), 0, 7),
            ),
            (
                NativeDsrExit::KickAtEntry { resume: target },
                (DsrExitKind::Kick, target.raw(), 0, 8),
            ),
            (
                NativeDsrExit::StaleGeneration {
                    guest_pc: PC,
                    observed: CodeGeneration::INITIAL,
                },
                (DsrExitKind::DirectResolver, PC.raw(), PC.raw(), 2),
            ),
        ];

        for (exit, expected) in cases {
            assert_eq!(exit.probe_fields(), expected, "exit={exit:?}");
        }
    }
}
