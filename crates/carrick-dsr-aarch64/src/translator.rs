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
            Self::ResolveDirect { source, target } => {
                (DsrExitKind::DirectResolver, source.raw(), target.raw(), 2)
            }
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

pub struct ThreadTranslator {
    // Fields are `pub` + doc(hidden)-by-convention: the runtime's
    // still-resident, JIT-entangled test suites (and the oracle) reach into
    // them until the host-seam slice moves those tests too.
    pub process: Arc<ProcessTranslator>,
    pub tid: i32,
    resume_entry: Option<(
        carrick_guest_mem::GuestVa,
        types::CodeGeneration,
        types::CacheVa,
    )>,
    indirect_cache: gateway::IndirectTargetCache,
    pub stats: ResolverStats,
    pub budget: profile::ThreadBudget,
    profile_finalized: bool,
    pub nested_translation_ns: u64,
    last_kick: Option<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>)>,
}

pub struct ProcessTranslator {
    // `pub` for the runtime's still-resident test suites (see ThreadTranslator).
    pub state: RwLock<ProcessState>,
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
    pub dependencies: cache::PageBlockDependencies,
    pub publications: cache::ConcurrentPublicationIndex,
    pub profiling: bool,
    shared_translation: Option<SharedTranslationConfiguration>,
}

struct SharedTranslationConfiguration {
    image: crate::shared_cache::SharedImageConfig,
    _store: Arc<dyn crate::shared_cache::TranslationUnitStore>,
}

#[derive(Clone, Copy)]
pub struct SensitiveMetadata {
    pub exit: types::SensitiveExit,
    pub fusion: Option<types::ExclusiveFusionSite>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationOutcome {
    BlockIndexHit,
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
}

impl ResolverStat {
    const ALL: [Self; 15] = [
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
            resume_entry: None,
            indirect_cache: gateway::IndirectTargetCache::new(),
            stats: ResolverStats::default(),
            budget: profile::ThreadBudget::from_environment(tid),
            profile_finalized: false,
            nested_translation_ns: 0,
            last_kick: None,
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
        self.resume_entry = None;
        self.indirect_cache.clear();
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
        self.resume_entry = None;
        self.indirect_cache.clear();
        self.start_next_profile_epoch();
        self.last_kick = None;
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
        artifact_spike::ensure_authority_if_enabled()?;
        let translator = Self {
            state: RwLock::new(ProcessState {
                cache: cache::TranslationCache::new(capacity, active_host_jit()?)?,
                artifact_store: artifact_spike::store_if_enabled()?,
                blocks: BTreeMap::new(),
                pending: BTreeMap::new(),
                stats: ResolverStats::default(),
                reported_stats: ResolverStats::default(),
                sensitive: BTreeMap::new(),
                exclusive_fusion_sites: std::array::from_fn(|_| BTreeSet::new()),
                unsupported: BTreeMap::new(),
                published: Vec::new(),
                dependencies: cache::PageBlockDependencies::default(),
                publications: cache::ConcurrentPublicationIndex::default(),
                profiling: std::env::var_os("CARRICK_DSR_PROFILE").is_some(),
                shared_translation: None,
            }),
        };
        probes::dsr_cache_capacity(
            probes::DsrCacheRole::Common,
            u64::try_from(capacity).unwrap_or(u64::MAX),
        );
        Ok(translator)
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
        state.shared_translation = Some(SharedTranslationConfiguration {
            image,
            _store: store,
        });
        Ok(())
    }

    #[doc(hidden)]
    pub fn configured_shared_segment_count(&self) -> usize {
        self.state
            .read()
            .shared_translation
            .as_ref()
            .map_or(0, |configuration| configuration.image.segments.len())
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

    pub fn after_fork_child(&self) {
        let mut state = self.state.write();
        state.cache.after_fork_child();
        state.publications.after_fork_child();
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        let capacity = u64::try_from(state.cache.capacity_bytes()).unwrap_or(u64::MAX);
        drop(state);
        probes::dsr_cache_capacity(probes::DsrCacheRole::Child, capacity);
    }

    pub fn reset_after_fork_for_exec(&self) {
        let mut state = self.state.write();
        state.published.clear();
        state.cache.reset_after_fork_for_exec();
        state.blocks.clear();
        state.pending.clear();
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        state.sensitive.clear();
        state.unsupported.clear();
        state.dependencies = cache::PageBlockDependencies::default();
        state.publications.reset_for_exec();
        state.shared_translation = None;
    }
}

impl ProcessState {
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
        tid: i32,
        memory: &NativeMappedMemory,
        key: (carrick_guest_mem::GuestVa, types::CodeGeneration),
        source_page: carrick_guest_mem::GuestVa,
        observation: cache::PageGenerationObservation,
        emitted: emit::EmittedBlock,
        emitted_bytes: u64,
        outcome: TranslationOutcome,
    ) -> Result<TranslationResult, types::DsrError> {
        let entry = emitted.entry();
        // The extracted publication index is probe-free; fire the exact
        // pre-extraction DuplicateWait subphase probes from its observer.
        let published_entry = self
            .publications
            .get_or_publish_observed(key, || entry, &|event| match event {
                cache::PublicationWaitEvent::WaitBegin => probes::dsr_translate_subphase_begin(
                    tid,
                    probes::DsrTranslationSubphase::DuplicateWait,
                    key.0.raw(),
                    key.1.get(),
                ),
                cache::PublicationWaitEvent::WaitEnd => probes::dsr_translate_subphase_end(
                    tid,
                    probes::DsrTranslationSubphase::DuplicateWait,
                    key.0.raw(),
                    key.1.get(),
                ),
            });
        if published_entry != entry {
            self.stats.add(ResolverStat::DuplicatePublications, 1);
            return Ok(TranslationResult {
                entry: published_entry,
                generation: key.1,
                outcome,
                emitted_bytes,
                cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            });
        }
        self.published.push(PublishedBlock {
            entry,
            len: emitted.len(),
            map: emitted.map().entries().to_vec(),
            recovery: emitted.recovery().to_vec(),
            _generation: observation,
        });
        let links = emitted.direct_links().to_vec();
        self.blocks.insert(key, entry);
        self.dependencies.record(source_page, key.0, key.1);
        for link in links {
            let target_generation = memory.dsr_generation_observation(link.target)?.expected();
            let target_key = (link.target, target_generation);
            let site = cache::LinkSite {
                source: entry,
                slot: link.slot,
            };
            if let Some(target) = self.blocks.get(&target_key) {
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
            self.blocks.remove(&stale);
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
        let artifact_key_words = self.artifact_store.as_ref().and_then(|store| {
            if !store.accepting_inserts() && !store.may_contain_guest(guest, artifact_address_mode)
            {
                return None;
            }
            memory
                .instruction_fingerprint_words(guest, ARTIFACT_KEY_PREFIX_INSTRUCTIONS)
                .ok()
        });
        let artifact_key = artifact_key_words.as_ref().map(|words| {
            artifact_spike::ArtifactKey::from_source(guest, words, artifact_address_mode)
        });
        let result = (|| -> Result<TranslationResult, types::DsrError> {
            let artifact_template = artifact_key.and_then(|artifact_key| {
                self.artifact_store
                    .as_ref()
                    .and_then(|store| store.lookup(artifact_key).ok().flatten())
            });
            if !artifact_spike::validate_fresh_enabled()
                && let Some(template) = artifact_template.as_ref()
                && memory
                    .instruction_fingerprint_words(guest, template.source_words().len())
                    .is_ok_and(|words| template.matches_source(&words))
            {
                let bindings = artifact_spike::ArtifactBindings::for_replay(
                    observation.current_atomic() as *const std::sync::atomic::AtomicU64 as u64,
                    generation.get(),
                    artifact_address_mode,
                )?;
                let replay_started = std::time::Instant::now();
                if let Ok(emitted) =
                    artifact_spike::replay_artifact(&mut self.cache, template, &bindings)
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
                        tid,
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
            let block_result = block::plan_block(memory, guest, generation, 256);
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
            let artifact_source_words = self.artifact_store.as_ref().and_then(|_| {
                let word_count = usize::try_from(
                    block
                        .end
                        .raw()
                        .saturating_sub(block.start.raw())
                        .checked_div(4)?,
                )
                .ok()?;
                memory
                    .instruction_fingerprint_words(guest, word_count)
                    .ok()
                    .filter(|words| words.len() == word_count)
            });

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
                match block.exit {
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
                } = block.exit
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
                let artifact_eligible = self
                    .artifact_store
                    .as_ref()
                    .is_some_and(artifact_spike::ArtifactStore::accepting_inserts)
                    && artifact_key.is_some()
                    && artifact_source_words.is_some()
                    && matches!(
                        block.exit,
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
                tid,
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
        for block in &self.published {
            let start = block.entry.host().raw();
            let Some(end) = start.checked_add(block.len) else {
                continue;
            };
            if !(start..end).contains(&cache_pc) {
                continue;
            }
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
        {
            // Scoped so the read guard is dropped before any write-path
            // fallback tries to acquire the write lock (RwLock is not
            // reentrant: read-then-write on the same thread would deadlock).
            let state = self.process.state.read();
            if let Some(entry) = state.cached_block(guest, generation) {
                let cache_used_bytes = u64::try_from(state.cache.used_bytes()).unwrap_or(u64::MAX);
                drop(state);
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
        self.process
            .state
            .write()
            .translate(self.tid, memory, guest)
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

    fn resolve_indirect<const PROFILE: bool>(
        &mut self,
        memory: &NativeMappedMemory,
        _source: carrick_guest_mem::GuestVa,
        target: carrick_guest_mem::GuestVa,
    ) -> Result<(types::CacheVa, types::CodeGeneration), types::DsrError> {
        self.stats.add(ResolverStat::ResolverExits, 1);
        let translated = self.translate::<PROFILE>(memory, target)?;
        self.indirect_cache
            .publish(target, translated.generation, translated.entry);
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
            invalid: self.stats.invalid.or(process.invalid),
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
            if let Some((cached_guest, generation, entry)) = self.resume_entry {
                if cached_guest == guest
                    && memory.dsr_generation_observation(guest)?.expected() == generation
                {
                    self.stats.add(ResolverStat::OneEntryHits, 1);
                    return Ok((entry, generation, probes::DsrPrepareOutcome::ResumeEntryHit));
                }
                self.resume_entry = None;
            }
            let translated = self.translate::<PROFILE>(memory, guest)?;
            self.resume_entry = Some((guest, translated.generation, translated.entry));
            let outcome = match translated.outcome {
                TranslationOutcome::BlockIndexHit => probes::DsrPrepareOutcome::BlockIndexHit,
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
        let cache_range = self.process.state.read().cache.host_range();
        let prepared = PreparedEntry {
            entry,
            generation,
            cache_start: cache_range.start,
            cache_end: cache_range.end,
            address_mode: memory.address_mode(),
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
        let gateway_result = gateway::enter_translated_with_cache_range(
            prepared.entry,
            snapshot,
            &mut exit,
            &self.indirect_cache,
            prepared.cache_start,
            prepared.cache_end,
            prepared.address_mode,
        );
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
                types::NativeDsrExit::ResolveDirect { .. } => {
                    self.stats.add(ResolverStat::DirectResolverExits, 1);
                }
                types::NativeDsrExit::ResolveIndirect { .. } => {}
                _ => {}
            }
        }
        Ok(match exit.exit {
            types::NativeDsrExit::Syscall { resume } => ThreadExit::Syscall { resume },
            types::NativeDsrExit::ResolveDirect { source, target } => {
                probes::dsr_resolve_begin(
                    self.tid,
                    probes::DsrResolveKind::Direct,
                    source.raw(),
                    target.raw(),
                );
                if let Err(error) = self.translate::<PROFILE>(memory, target) {
                    probes::dsr_resolve_end(
                        self.tid,
                        probes::DsrResolveKind::Direct,
                        source.raw(),
                        target.raw(),
                        error.probe_outcome(),
                    );
                    return Err(error);
                }
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
                self.resume_entry = Some((target, target_generation, entry));
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
    use super::{DsrErrorProbeExt as _, NativeDsrExitProbeExt as _};
    use crate::types;
    use carrick_guest_mem::GuestVa;

    const PC: GuestVa = GuestVa(0x1000);

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
                NativeDsrExit::ResolveDirect { source: PC, target },
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
