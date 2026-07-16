use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};

use carrick_observability::probes;
use parking_lot::{Mutex, RwLock};

pub(super) mod block;
pub(super) mod cache;
pub(super) mod decode;
pub(super) mod emit;
pub(super) mod gateway;
#[cfg(test)]
mod oracle;
pub(super) mod profile;
pub(super) mod types;

#[derive(Debug)]
pub(super) enum ThreadExit {
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
pub(super) enum ThreadFault {
    Host { signal: i32, code: i32 },
    Guest { signum: i32, code: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ThreadFaultAddress {
    Host(carrick_guest_mem::HostVa),
    Guest(carrick_guest_mem::GuestVa),
}

impl ThreadFaultAddress {
    pub(super) fn raw(self) -> u64 {
        match self {
            Self::Host(address) => address.raw() as u64,
            Self::Guest(address) => address.raw(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct PreparedEntry {
    entry: types::CacheVa,
    generation: types::CodeGeneration,
    cache_start: usize,
    cache_end: usize,
    address_mode: super::address::NativeAddressMode,
}

pub(super) struct PreparedExit {
    exit: types::NativeDsrExit,
}

impl PreparedExit {
    pub(super) const fn profile_class(&self) -> profile::ExitClass {
        self.exit.profile_class()
    }
}

pub(super) struct ThreadTranslator {
    process: Arc<ProcessTranslator>,
    tid: i32,
    resume_entry: Option<(
        carrick_guest_mem::GuestVa,
        types::CodeGeneration,
        types::CacheVa,
    )>,
    indirect_cache: gateway::IndirectTargetCache,
    stats: ResolverStats,
    budget: profile::ThreadBudget,
    profile_finalized: bool,
    nested_translation_ns: u64,
    last_kick: Option<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>)>,
}

pub(super) struct ProcessTranslator {
    state: RwLock<ProcessState>,
}

struct ProcessState {
    cache: cache::TranslationCache,
    blocks: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::CacheVa>,
    pending: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), Vec<cache::LinkSite>>,
    stats: ResolverStats,
    reported_stats: ResolverStats,
    sensitive: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), SensitiveMetadata>,
    exclusive_fusion_sites: [BTreeSet<(u64, u32)>; profile::ExclusiveFusionClass::COUNT],
    unsupported: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), (u32, bad64::Op)>,
    published: Vec<PublishedBlock>,
    dependencies: cache::PageBlockDependencies,
    publications: cache::ConcurrentPublicationIndex,
    profiling: bool,
}

#[derive(Clone, Copy)]
struct SensitiveMetadata {
    exit: types::SensitiveExit,
    fusion: Option<types::ExclusiveFusionSite>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TranslationOutcome {
    BlockIndexHit,
    Translated,
}

#[derive(Clone, Copy, Debug)]
struct TranslationResult {
    entry: types::CacheVa,
    generation: types::CodeGeneration,
    outcome: TranslationOutcome,
    emitted_bytes: u64,
    cache_used_bytes: u64,
}

struct PublishedBlock {
    entry: types::CacheVa,
    len: usize,
    map: Vec<emit::PcMapEntry>,
    recovery: Vec<emit::RecoveryEntry>,
    _generation: cache::PageGenerationObservation,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ResolverStats {
    pub(super) resolver_exits: u64,
    pub(super) one_entry_hits: u64,
    pub(super) translations: u64,
    pub(super) duplicate_publications: u64,
    pub(super) gateway_entries: u64,
    pub(super) syscall_exits: u64,
    pub(super) direct_resolver_exits: u64,
    pub(super) cache_lookups: u64,
    pub(super) cache_lookup_hits: u64,
    pub(super) invalidated_blocks: u64,
    pub(super) translation_ns: u64,
    pub(super) translation_decode_ns: u64,
    pub(super) translation_plan_ns: u64,
    pub(super) translation_emit_ns: u64,
    pub(super) translation_publication_ns: u64,
    invalid: Option<profile::ProfileError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolverStat {
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

    fn add(&mut self, stat: ResolverStat, value: u64) {
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ProfileSnapshot {
    pub(super) resolver_exits: u64,
    pub(super) one_entry_hits: u64,
    pub(super) translations: u64,
    pub(super) duplicate_publications: u64,
    pub(super) gateway_entries: u64,
    pub(super) syscall_exits: u64,
    pub(super) direct_resolver_exits: u64,
    pub(super) cache_lookups: u64,
    pub(super) cache_lookup_hits: u64,
    pub(super) invalidated_blocks: u64,
    pub(super) translation_ns: u64,
    pub(super) translation_decode_ns: u64,
    pub(super) translation_plan_ns: u64,
    pub(super) translation_emit_ns: u64,
    pub(super) translation_publication_ns: u64,
    pub(super) nested_translation_ns: u64,
    pub(super) cache_used_bytes: usize,
    pub(super) cache_capacity_bytes: usize,
    pub(super) exclusive_fusion_sites: [u64; profile::ExclusiveFusionClass::COUNT],
}

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
    mach_port: libc::mach_port_t,
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
    #[cfg(test)]
    pub(super) fn new(capacity: usize) -> Result<Self, types::DsrError> {
        Ok(Self::for_process(
            Arc::new(ProcessTranslator::new(capacity)?),
            0,
        ))
    }

    pub(super) fn for_process(process: Arc<ProcessTranslator>, tid: i32) -> Self {
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

    pub(super) fn after_fork_child(&mut self, tid: i32) {
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

    pub(super) fn begin_exec_reset(&self) {
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecResetBegin,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    pub(super) fn begin_exec_handoff(&self) {
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecTranslatorHandoffBegin,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    pub(super) fn reset_for_exec(&mut self, next: Arc<ProcessTranslator>) {
        self.reset_for_exec_with_sink(next, |frames| {
            let _ = profile::write_protocol_frames_to_fd(libc::STDERR_FILENO, frames);
        });
    }

    fn reset_for_exec_with_sink(
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

    pub(super) fn start_next_profile_epoch(&mut self) {
        self.stats = ResolverStats::default();
        self.budget.reset_after_exec();
        self.profile_finalized = false;
        self.nested_translation_ns = 0;
    }

    #[cfg(test)]
    pub(super) fn profile_snapshot(&self) -> ProfileSnapshot {
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

    fn take_profile_frames(&mut self) -> Option<Vec<String>> {
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

    pub(super) fn finalize_profile_epoch(&mut self) {
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
    /// `(pid, tid, era)` a second time (see [`SiblingSlot`]).
    pub(super) fn publish_sibling_snapshot(&self) {
        if !self.budget.enabled() {
            return;
        }
        let snapshot = SiblingSnapshot {
            budget: self.budget,
            stats: self.stats,
            nested_translation_ns: self.nested_translation_ns,
            mach_port: crate::host_proc::current_thread_port(),
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
    fn drain_sibling_profiles_before_process_exit(&self) {
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
    pub(super) fn finalize_profile_epoch_at_process_exit(&mut self) {
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
    pub(super) fn new(capacity: usize) -> Result<Self, types::DsrError> {
        let translator = Self {
            state: RwLock::new(ProcessState {
                cache: cache::TranslationCache::new(capacity)?,
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
            }),
        };
        probes::dsr_cache_capacity(
            probes::DsrCacheRole::Common,
            u64::try_from(capacity).unwrap_or(u64::MAX),
        );
        Ok(translator)
    }

    fn lifecycle_snapshot(&self) -> (u64, u64, u64) {
        let state = self.state.read();
        (
            u64::try_from(state.cache.used_bytes()).unwrap_or(u64::MAX),
            u64::try_from(state.blocks.len()).unwrap_or(u64::MAX),
            u64::try_from(state.dependencies.page_count()).unwrap_or(u64::MAX),
        )
    }

    fn after_fork_child(&self) {
        let mut state = self.state.write();
        state.cache.after_fork_child();
        state.publications.after_fork_child();
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        let capacity = u64::try_from(state.cache.capacity_bytes()).unwrap_or(u64::MAX);
        drop(state);
        probes::dsr_cache_capacity(probes::DsrCacheRole::Child, capacity);
    }

    pub(super) fn reset_after_fork_for_exec(&self) {
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
    }
}

impl ProcessState {
    fn record_exclusive_fusion_site(&mut self, site: types::ExclusiveFusionSite) {
        if !self.profiling {
            return;
        }
        let class = profile::ExclusiveFusionClass::from(site.disposition);
        self.exclusive_fusion_sites[class.index()].insert((site.guest.raw(), site.word));
    }

    fn exclusive_fusion_site_counts(&self) -> [u64; profile::ExclusiveFusionClass::COUNT] {
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
    fn cached_block(
        &self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
    ) -> Option<types::CacheVa> {
        self.blocks.get(&(guest, generation)).copied()
    }

    fn translate(
        &mut self,
        tid: i32,
        memory: &super::NativeMappedMemory,
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
        let result = (|| -> Result<TranslationResult, types::DsrError> {
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
                let emitted = emit::emit_block_with_generation(
                    &mut self.cache,
                    &block,
                    emit::GenerationGuard::new(observation.current_atomic(), generation),
                    memory.address_mode().into(),
                )?;
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
            let entry = emitted.entry();
            let publication_result = (|| -> Result<TranslationResult, types::DsrError> {
                let published_entry = self
                    .publications
                    .get_or_publish_profiled(tid, key, || entry);
                if published_entry != entry {
                    self.stats.add(ResolverStat::DuplicatePublications, 1);
                    return Ok(TranslationResult {
                        entry: published_entry,
                        generation,
                        outcome: TranslationOutcome::Translated,
                        emitted_bytes,
                        cache_used_bytes: u64::try_from(self.cache.used_bytes())
                            .unwrap_or(u64::MAX),
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
                self.dependencies.record(source_page, guest, generation);

                for link in links {
                    let target_generation =
                        memory.dsr_generation_observation(link.target)?.expected();
                    let target_key = (link.target, target_generation);
                    let site = cache::LinkSite {
                        source: entry,
                        slot: link.slot,
                    };
                    if let Some(target) = self.blocks.get(&target_key) {
                        self.cache.patch_direct_branch(site, *target)?;
                    } else {
                        self.pending.entry(target_key).or_default().push(site);
                    }
                }
                if let Some(sites) = self.pending.remove(&key) {
                    for site in sites {
                        self.cache.patch_direct_branch(site, entry)?;
                    }
                }
                Ok(TranslationResult {
                    entry,
                    generation,
                    outcome: TranslationOutcome::Translated,
                    emitted_bytes,
                    cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
                })
            })();
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
        memory: &super::NativeMappedMemory,
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
        memory: &super::NativeMappedMemory,
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
        memory: &super::NativeMappedMemory,
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

    #[cfg(test)]
    pub(super) fn resolver_stats(&self) -> ResolverStats {
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

    #[cfg(test)]
    fn patch_first_completed_recovery_for_test(
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

    #[cfg(test)]
    fn recovery_points_for_test(
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

    #[cfg(test)]
    fn patch_recovery_word_for_test(
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
        state.cache.patch_word_for_test(cache_pc, word)
    }

    pub(super) fn profiling_enabled(&self) -> bool {
        self.budget.enabled()
    }

    pub(super) fn begin_profile_phase(&mut self) {
        self.nested_translation_ns = 0;
    }

    pub(super) fn add_profile_phase(
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

    pub(super) fn add_profile_phase_ns(
        &mut self,
        phase: profile::Phase,
        elapsed_ns: u64,
    ) -> Result<(), profile::ProfileError> {
        self.budget.add_phase(phase, elapsed_ns)
    }

    pub(super) fn add_profile_blocked_cpu_ns(
        &mut self,
        elapsed_ns: u64,
    ) -> Result<(), profile::ProfileError> {
        self.budget.add_blocked_cpu_ns(elapsed_ns)
    }

    pub(super) fn record_profile_exit(
        &mut self,
        class: profile::ExitClass,
    ) -> Result<(), profile::ProfileError> {
        self.budget.record_exit(class)
    }

    pub(super) fn record_profile_sensitive(
        &mut self,
        class: profile::SensitiveClass,
    ) -> Result<(), profile::ProfileError> {
        self.budget.record_sensitive(class)
    }

    pub(super) fn invalidate_profile(
        &mut self,
        error: profile::ProfileError,
    ) -> profile::ProfileError {
        self.budget.invalidate(error)
    }

    pub(super) fn prepare_entry<const PROFILE: bool>(
        &mut self,
        memory: &super::NativeMappedMemory,
        snapshot: &super::NativeUcontextSnapshot,
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
                TranslationOutcome::Translated => probes::DsrPrepareOutcome::Translated,
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

    pub(super) fn enter_prepared<const PROFILE: bool>(
        &mut self,
        prepared: PreparedEntry,
        snapshot: &mut super::NativeUcontextSnapshot,
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

    #[cfg(test)]
    pub(super) fn finish_exit(
        &mut self,
        memory: &super::NativeMappedMemory,
        snapshot: &mut super::NativeUcontextSnapshot,
        prepared: PreparedEntry,
        exit: PreparedExit,
    ) -> Result<ThreadExit, types::DsrError> {
        self.finish_exit_profiled::<false>(memory, snapshot, prepared, exit)
    }

    pub(super) fn finish_exit_profiled<const PROFILE: bool>(
        &mut self,
        memory: &super::NativeMappedMemory,
        snapshot: &mut super::NativeUcontextSnapshot,
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
                if PROFILE {
                    if let Some(site) = metadata.fusion {
                        self.budget
                            .record_exclusive_fusion(profile::ExclusiveFusionClass::from(
                                site.disposition,
                            ))
                            .map_err(|error| types::DsrError::BlockPolicy(error.to_string()))?;
                    }
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
                let (kind, address) = if let Some((signum, code)) =
                    crate::vcpu_loop::el0_debug_signal(snapshot.esr)
                {
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
                    >= super::address::BIASED_GUEST_APERTURE_END
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

fn recovery_resume_pc(
    guest_pc: carrick_guest_mem::GuestVa,
    recovery: Option<emit::RecoveryAction>,
) -> Result<u64, types::DsrError> {
    if recovery.is_some_and(emit::RecoveryAction::instruction_complete) {
        guest_pc.raw().checked_add(4).ok_or_else(|| {
            types::DsrError::CachePolicy("DSR completed-instruction resume PC overflow".to_string())
        })
    } else {
        Ok(guest_pc.raw())
    }
}

fn recover_rewrite_state(
    snapshot: &mut super::NativeUcontextSnapshot,
    action: emit::RecoveryAction,
    saved_scratch: u64,
    saved_context_scratch: u64,
    saved_generation_pstate: u64,
    saved_indirect_x15: u64,
    saved_indirect_x30: u64,
) -> Result<(), types::DsrError> {
    if let emit::RecoveryAction::RecoverBiasedMemory(recovery) = action {
        let saved_values = [
            saved_scratch,
            saved_context_scratch,
            saved_indirect_x15,
            saved_indirect_x30,
        ];
        let base_value = if recovery.commit_base {
            let index = usize::try_from(recovery.base_scratch).map_err(|_| {
                types::DsrError::CachePolicy("biased base scratch index overflow".to_string())
            })?;
            let current = snapshot.x.get(index).copied().ok_or_else(|| {
                types::DsrError::CachePolicy(format!(
                    "biased base scratch x{} is outside snapshot",
                    recovery.base_scratch
                ))
            })?;
            Some(match recovery.base_coordinate {
                // AArch64 pre/post-index writeback is modulo 2^64. The memory
                // access used a valid translated address before the update;
                // only the architectural result may wrap below the bias.
                emit::BiasedBaseCoordinate::Host => current.wrapping_sub(recovery.host_bias.get()),
                emit::BiasedBaseCoordinate::Guest => current,
            })
        } else {
            None
        };
        let virtual_x18 = recovery
            .virtual_x18_scratch
            .map(|register| {
                usize::try_from(register)
                    .ok()
                    .and_then(|index| snapshot.x.get(index).copied())
                    .ok_or_else(|| {
                        types::DsrError::CachePolicy(format!(
                            "biased virtual x18 scratch x{register} is outside snapshot"
                        ))
                    })
            })
            .transpose()?;
        let virtual_x28 = recovery
            .virtual_x28_scratch
            .map(|register| {
                usize::try_from(register)
                    .ok()
                    .and_then(|index| snapshot.x.get(index).copied())
                    .ok_or_else(|| {
                        types::DsrError::CachePolicy(format!(
                            "biased virtual x28 scratch x{register} is outside snapshot"
                        ))
                    })
            })
            .transpose()?;
        let scratch_count = usize::from(recovery.scratch_count);
        if scratch_count > recovery.scratch_registers.len() {
            return Err(types::DsrError::CachePolicy(format!(
                "biased recovery scratch count {scratch_count} exceeds capacity"
            )));
        }
        for (register, value) in recovery.scratch_registers[..scratch_count]
            .iter()
            .copied()
            .zip(saved_values)
        {
            let index = usize::try_from(register).map_err(|_| {
                types::DsrError::CachePolicy("biased scratch index overflow".to_string())
            })?;
            let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                types::DsrError::CachePolicy(format!(
                    "biased scratch x{register} is outside snapshot"
                ))
            })?;
            *slot = value;
        }
        if let Some(value) = virtual_x18 {
            snapshot.x[18] = value;
        }
        if let Some(value) = virtual_x28 {
            snapshot.x[28] = value;
        }
        if let Some(value) = base_value {
            match recovery.base {
                emit::BiasedBase::Register(register) => {
                    let index = usize::try_from(register).map_err(|_| {
                        types::DsrError::CachePolicy("biased guest base index overflow".to_string())
                    })?;
                    let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                        types::DsrError::CachePolicy(format!(
                            "biased guest base x{register} is outside snapshot"
                        ))
                    })?;
                    *slot = value;
                }
                emit::BiasedBase::StackPointer => snapshot.sp = value,
                emit::BiasedBase::VirtualX18 => snapshot.x[18] = value,
                emit::BiasedBase::VirtualX28 => snapshot.x[28] = value,
                emit::BiasedBase::None => {
                    return Err(types::DsrError::CachePolicy(
                        "biased recovery attempted to commit a missing base".to_string(),
                    ));
                }
            }
        }
        return Ok(());
    }
    let (register, context_register) = match action {
        emit::RecoveryAction::Noop => return Ok(()),
        emit::RecoveryAction::RestoreGuestX17 => {
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        emit::RecoveryAction::RestoreGenerationGuardRegisters => {
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        emit::RecoveryAction::RestoreGenerationGuard => {
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            snapshot.pstate = saved_generation_pstate;
            return Ok(());
        }
        emit::RecoveryAction::RestoreIndirectRegisters => {
            snapshot.x[15] = saved_indirect_x15;
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        emit::RecoveryAction::RestoreIndirectResolver => {
            snapshot.x[15] = saved_indirect_x15;
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            snapshot.x[30] = saved_indirect_x30;
            snapshot.pstate = saved_generation_pstate;
            return Ok(());
        }
        emit::RecoveryAction::RestoreDualVirtualReadOnly {
            x18_scratch,
            x28_scratch,
            context_scratch,
        }
        | emit::RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
            x18_scratch,
            x28_scratch,
            context_scratch,
        } => {
            for (register, value) in [
                (x18_scratch, saved_indirect_x15),
                (x28_scratch, saved_scratch),
                (context_scratch, saved_context_scratch),
            ] {
                let index = usize::try_from(register).map_err(|_| {
                    types::DsrError::CachePolicy("dual virtual scratch index overflow".to_string())
                })?;
                let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "dual virtual scratch x{register} is outside snapshot"
                    ))
                })?;
                *slot = value;
            }
            return Ok(());
        }
        emit::RecoveryAction::CommitDualVirtualAndRestore {
            x18_scratch,
            x28_scratch,
            context_scratch,
            virtual_register,
            virtual_scratch,
        } => {
            let virtual_scratch_index = usize::try_from(virtual_scratch).map_err(|_| {
                types::DsrError::CachePolicy("dual virtual result index overflow".to_string())
            })?;
            let value = snapshot
                .x
                .get(virtual_scratch_index)
                .copied()
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "dual virtual result x{virtual_scratch} is outside snapshot"
                    ))
                })?;
            let virtual_index = usize::try_from(virtual_register).map_err(|_| {
                types::DsrError::CachePolicy("dual virtual destination overflow".to_string())
            })?;
            let virtual_slot = snapshot.x.get_mut(virtual_index).ok_or_else(|| {
                types::DsrError::CachePolicy(format!(
                    "dual virtual destination x{virtual_register} is outside snapshot"
                ))
            })?;
            *virtual_slot = value;
            for (register, value) in [
                (x18_scratch, saved_indirect_x15),
                (x28_scratch, saved_scratch),
                (context_scratch, saved_context_scratch),
            ] {
                let index = usize::try_from(register).map_err(|_| {
                    types::DsrError::CachePolicy("dual virtual scratch index overflow".to_string())
                })?;
                let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "dual virtual scratch x{register} is outside snapshot"
                    ))
                })?;
                *slot = value;
            }
            return Ok(());
        }
        emit::RecoveryAction::RestoreScratch { register }
        | emit::RecoveryAction::RestoreScratchInvalidBiasedLiteral { register }
        | emit::RecoveryAction::RestoreScratchCompleted { register }
        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratch { register, .. } => {
            (register, None)
        }
        emit::RecoveryAction::RestoreScratchAndContext {
            register,
            context_register,
        }
        | emit::RecoveryAction::RestoreScratchAndContextCompleted {
            register,
            context_register,
        }
        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
            register,
            context_register,
            ..
        } => (register, Some(context_register)),
        emit::RecoveryAction::RecoverBiasedMemory(_) => {
            return Err(types::DsrError::CachePolicy(
                "biased recovery escaped its typed handler".to_string(),
            ));
        }
    };
    let index = usize::try_from(register)
        .map_err(|_| types::DsrError::CachePolicy("rewrite scratch index overflow".to_string()))?;
    let current = snapshot.x.get(index).copied().ok_or_else(|| {
        types::DsrError::CachePolicy(format!("rewrite scratch x{register} is outside snapshot"))
    })?;
    let virtual_register = match action {
        emit::RecoveryAction::CommitVirtualizedAndRestoreScratch {
            virtual_register, ..
        }
        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
            virtual_register,
            ..
        } => Some(virtual_register),
        _ => None,
    };
    if let Some(virtual_register) = virtual_register {
        let virtual_index = usize::try_from(virtual_register).map_err(|_| {
            types::DsrError::CachePolicy("virtual register index overflow".to_string())
        })?;
        let slot = snapshot.x.get_mut(virtual_index).ok_or_else(|| {
            types::DsrError::CachePolicy(format!(
                "virtual register x{virtual_register} is outside snapshot"
            ))
        })?;
        *slot = current;
    }
    snapshot.x[index] = saved_scratch;
    if let Some(context_register) = context_register {
        let context_index = usize::try_from(context_register).map_err(|_| {
            types::DsrError::CachePolicy("rewrite context scratch index overflow".to_string())
        })?;
        let slot = snapshot.x.get_mut(context_index).ok_or_else(|| {
            types::DsrError::CachePolicy(format!(
                "rewrite context scratch x{context_register} is outside snapshot"
            ))
        })?;
        *slot = saved_context_scratch;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode::classify;
    use super::types::{
        DirectKind, IndirectKind, InstAction, MemoryBase, MemoryClass, MemoryVirtualization,
        PcRelativeKind, SensitiveKind,
    };
    use carrick_guest_mem::{GuestMemory, GuestVa};
    use proptest::prelude::*;

    const PC: GuestVa = GuestVa(0x1000);

    fn fork_test(test: impl FnOnce() + std::panic::UnwindSafe) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let passed = std::panic::catch_unwind(test).is_ok();
            unsafe { libc::_exit(i32::from(!passed)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn biased_recovery_fixture(
        base: super::emit::BiasedBase,
        coordinate: super::emit::BiasedBaseCoordinate,
        complete: bool,
    ) -> super::emit::RecoveryAction {
        super::emit::RecoveryAction::RecoverBiasedMemory(super::emit::BiasedMemoryRecovery {
            scratch_registers: [9, 10, 0, 0],
            scratch_count: 2,
            base_scratch: 9,
            base,
            base_coordinate: coordinate,
            commit_base: true,
            virtual_x18_scratch: None,
            virtual_x28_scratch: None,
            host_bias: super::super::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias"),
            instruction_complete: complete,
        })
    }

    #[test]
    fn biased_recovery_resume_and_wrapping_writeback_are_architectural() {
        let retry = biased_recovery_fixture(
            super::emit::BiasedBase::Register(0),
            super::emit::BiasedBaseCoordinate::Host,
            false,
        );
        let completed = biased_recovery_fixture(
            super::emit::BiasedBase::Register(0),
            super::emit::BiasedBaseCoordinate::Host,
            true,
        );
        assert_eq!(
            super::recovery_resume_pc(PC, Some(retry)).unwrap(),
            PC.raw()
        );
        assert_eq!(
            super::recovery_resume_pc(PC, Some(completed)).unwrap(),
            PC.raw() + 4
        );

        let mut snapshot = super::super::NativeUcontextSnapshot::default();
        snapshot.x[9] = 3;
        super::recover_rewrite_state(&mut snapshot, completed, 0xaa, 0xbb, 0, 0, 0)
            .expect("recover wrapped writeback");
        assert_eq!(snapshot.x[0], 3_u64.wrapping_sub(0x80_0000_0000));
        assert_eq!(snapshot.x[9], 0xaa);
        assert_eq!(snapshot.x[10], 0xbb);
    }

    #[test]
    fn biased_recovery_commits_register_sp_and_virtual_bases_last() {
        let bias = 0x80_0000_0000;
        let guest = 0x1234_5000;
        for base in [
            super::emit::BiasedBase::Register(16),
            super::emit::BiasedBase::StackPointer,
            super::emit::BiasedBase::VirtualX18,
            super::emit::BiasedBase::VirtualX28,
        ] {
            let action =
                biased_recovery_fixture(base, super::emit::BiasedBaseCoordinate::Host, true);
            let mut snapshot = super::super::NativeUcontextSnapshot::default();
            snapshot.x[9] = bias + guest;
            super::recover_rewrite_state(&mut snapshot, action, 0xaa, 0xbb, 0, 0, 0)
                .expect("recover biased base");
            match base {
                super::emit::BiasedBase::Register(16) => assert_eq!(snapshot.x[16], guest),
                super::emit::BiasedBase::StackPointer => assert_eq!(snapshot.sp, guest),
                super::emit::BiasedBase::VirtualX18 => assert_eq!(snapshot.x[18], guest),
                super::emit::BiasedBase::VirtualX28 => assert_eq!(snapshot.x[28], guest),
                super::emit::BiasedBase::Register(_) | super::emit::BiasedBase::None => {
                    panic!("unexpected recovery base")
                }
            }
            assert_eq!(snapshot.x[9], 0xaa);
            assert_eq!(snapshot.x[10], 0xbb);
        }
    }

    fn mapped_dsr_test_memory(
        words: &[u32],
    ) -> Result<(super::super::NativeMappedMemory, GuestVa), String> {
        let page_size = 16 * 1024_u64;
        let layout = super::super::MemoryLayout {
            heap_base: super::super::NATIVE_DARWIN_HEAP_BASE,
            heap_size: page_size,
            mmap_base: super::super::NATIVE_DARWIN_MMAP_BASE,
            mmap_size: page_size,
        };
        let image = super::super::AddressSpace::from_regions(0, Vec::new())
            .map_err(|error| error.to_string())?;
        let mut memory = super::super::NativeMappedMemory::map_with_translator(
            &image, layout, page_size, page_size, None, None,
        )
        .map_err(|error| error.to_string())?;
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        memory
            .write_bytes_raw(layout.mmap_base, &code)
            .map_err(|error| error.to_string())?;
        memory
            .protect_range(
                layout.mmap_base,
                page_size as usize,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            )
            .map_err(|error| error.to_string())?;
        Ok((memory, GuestVa(layout.mmap_base)))
    }

    #[test]
    fn dsr_translation_result_distinguishes_publish_and_index_hit() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let result = (|| -> Result<(), String> {
                let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001])?;
                let process =
                    super::ProcessTranslator::new(16 * 1024).map_err(|error| error.to_string())?;
                let mut state = process.state.write();
                let first = state
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;
                let second = state
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;
                if first.outcome != super::TranslationOutcome::Translated
                    || second.outcome != super::TranslationOutcome::BlockIndexHit
                    || first.entry != second.entry
                {
                    return Err(format!(
                        "unexpected outcomes: first={first:?} second={second:?}"
                    ));
                }
                drop(state);
                let (used_bytes, block_count, generation_count) = process.lifecycle_snapshot();
                if used_bytes == 0 || block_count != 1 || generation_count != 1 {
                    return Err(format!(
                        "unexpected lifecycle snapshot: used={used_bytes} blocks={block_count} generations={generation_count}"
                    ));
                }
                if first.cache_used_bytes != used_bytes {
                    return Err(format!(
                        "unexpected cache used bytes: result={} snapshot={used_bytes}",
                        first.cache_used_bytes,
                    ));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                super::super::child_write_stderr(format!("{error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    /// Read-mostly RwLock fast path: a warm cache hit must resolve through a
    /// SHARED `&ProcessState` (`state.read()`), never `&mut`, so concurrent
    /// translations can proceed fully in parallel. `cached_block` is the
    /// read-only accessor the fast path uses.
    #[test]
    fn read_fast_path_hits_warm_cache_without_mut_access() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let result = (|| -> Result<(), String> {
                let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001])?;
                let process =
                    super::ProcessTranslator::new(16 * 1024).map_err(|error| error.to_string())?;
                // Populate the block via the write path, exactly as the real
                // miss path does.
                let translated = process
                    .state
                    .write()
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;

                let observation = memory
                    .dsr_generation_observation(guest)
                    .map_err(|error| error.to_string())?;
                // Read-only lookup: only `&ProcessState` (`.read()`) is held
                // here -- this would not compile against a `&mut self`
                // accessor, and it must be able to run concurrently with any
                // other reader.
                let hit = process
                    .state
                    .read()
                    .cached_block(guest, observation.expected());
                if hit != Some(translated.entry) {
                    return Err(format!(
                        "expected read fast path to hit the inserted block {:?}, got {hit:?}",
                        translated.entry
                    ));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                super::super::child_write_stderr(format!("{error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    /// The cache key embeds the generation, so a stale (pre-mutation) block
    /// must never be returned by the read fast path once the guest page has
    /// been modified: `cached_block` is queried with the CURRENT generation,
    /// which the old block's key does not match.
    #[test]
    fn read_fast_path_never_returns_a_stale_generation_block() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let result = (|| -> Result<(), String> {
                let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001])?;
                let process =
                    super::ProcessTranslator::new(16 * 1024).map_err(|error| error.to_string())?;
                let first = process
                    .state
                    .write()
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;

                // Mutate the guest code: bumps the page's generation, so
                // `first`'s block is now keyed by a STALE generation.
                let new_generation = memory
                    .note_dsr_code_mutation(guest.raw(), 4)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "expected a DSR generation".to_string())?;
                if new_generation == first.generation {
                    return Err("code mutation did not change the generation".to_string());
                }

                // The read fast path, queried with the CURRENT generation,
                // must miss -- the old block's key is (guest, OLD
                // generation), which can never match. It must fall through
                // to the write path, which performs the actual invalidation.
                let hit = process.state.read().cached_block(guest, new_generation);
                if hit.is_some() {
                    return Err(format!(
                        "read fast path returned a stale-generation hit: {hit:?}"
                    ));
                }

                // The write path re-translates cleanly at the new generation.
                let second = process
                    .state
                    .write()
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;
                if second.generation != new_generation {
                    return Err(format!(
                        "expected re-translation at the new generation {new_generation:?}, got {:?}",
                        second.generation
                    ));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                super::super::child_write_stderr(format!("{error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn repeated_prepare_keeps_valid_last_entry_hot() {
        fork_test(|| {
            let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]).expect("map test memory");
            let snapshot = super::super::NativeUcontextSnapshot {
                pc: guest.raw(),
                ..Default::default()
            };
            let mut translator =
                super::ThreadTranslator::new(16 * 1024).expect("create translator");
            let first = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare first entry");
            let before = translator.profile_snapshot();
            let second = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare repeated entry");
            let after = translator.profile_snapshot();
            assert_eq!(first.entry, second.entry);
            assert_eq!(after.one_entry_hits - before.one_entry_hits, 1);
        });
    }

    #[test]
    fn generation_change_discards_last_prepared_entry() {
        fork_test(|| {
            let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]).expect("map test memory");
            let snapshot = super::super::NativeUcontextSnapshot {
                pc: guest.raw(),
                ..Default::default()
            };
            let mut translator =
                super::ThreadTranslator::new(16 * 1024).expect("create translator");
            let first = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare first entry");
            let changed = memory
                .note_dsr_code_mutation(guest.raw(), 4)
                .expect("record code mutation")
                .expect("DSR generation");
            let before = translator.profile_snapshot();
            let second = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare after mutation");
            let after = translator.profile_snapshot();
            assert_eq!(second.generation, changed);
            assert_ne!(first.generation, second.generation);
            assert_eq!(after.one_entry_hits, before.one_entry_hits);
            assert_ne!(first.entry, second.entry);
        });
    }

    #[test]
    fn dsr_error_probe_outcomes_cover_every_error_category() {
        use carrick_observability::probes::DsrOperationOutcome;

        let op = bad64::decode(0xd400_0001, PC.raw())
            .expect("decode svc")
            .op();
        let cases = [
            (
                super::types::DsrError::PcOverflow { pc: PC.raw() },
                DsrOperationOutcome::PcOverflow,
            ),
            (
                super::types::DsrError::Decode {
                    pc: PC.raw(),
                    word: 0,
                    detail: "decode".to_string(),
                },
                DsrOperationOutcome::Decode,
            ),
            (
                super::types::DsrError::Malformed {
                    pc: PC.raw(),
                    word: 0xd400_0001,
                    op,
                },
                DsrOperationOutcome::Malformed,
            ),
            (
                super::types::DsrError::BlockPolicy("block".to_string()),
                DsrOperationOutcome::BlockPolicy,
            ),
            (
                super::types::DsrError::MemoryRead {
                    pc: PC.raw(),
                    detail: "read".to_string(),
                },
                DsrOperationOutcome::MemoryRead,
            ),
            (
                super::types::DsrError::UnsupportedBlockAction {
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
                super::types::DsrError::Assembler("assembler".to_string()),
                DsrOperationOutcome::Assembler,
            ),
            (
                super::types::DsrError::Gateway("gateway".to_string()),
                DsrOperationOutcome::Gateway,
            ),
            (
                super::types::DsrError::CachePolicy("cache".to_string()),
                DsrOperationOutcome::CachePolicy,
            ),
            (
                super::types::DsrError::GenerationChanged {
                    page: PC.raw(),
                    expected: 1,
                    observed: 2,
                },
                DsrOperationOutcome::GenerationChanged,
            ),
            (
                super::types::DsrError::Host {
                    operation: "test",
                    error: std::io::Error::from_raw_os_error(libc::EINVAL),
                },
                DsrOperationOutcome::Host,
            ),
            (
                super::types::DsrError::CacheCapacity {
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
        use super::types::{CodeGeneration, NativeDsrExit};
        use carrick_observability::probes::DsrExitKind;

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

    #[test]
    fn thread_translator_stores_the_guest_tid() {
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        let mut translator = super::ThreadTranslator::for_process(process, 37);
        assert_eq!(translator.tid, 37);
        translator.after_fork_child(73);
        assert_eq!(translator.tid, 73);
    }

    #[test]
    fn fork_child_reset_does_not_mix_parent_profile_identity() {
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        process.state.write().stats.translations = 9;
        let mut translator = super::ThreadTranslator::for_process(process, 42);
        translator.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        translator
            .budget
            .record_exit(super::profile::ExitClass::Syscall)
            .expect("record parent exit");

        translator.after_fork_child(73);

        let record = translator
            .budget
            .complete_record()
            .expect("fresh child profile");
        assert_eq!(record.pid, unsafe { libc::getpid() });
        assert_eq!(record.tid, 73);
        assert_eq!(record.gateway_entries, 0);
        assert_eq!(translator.profile_snapshot().translations, 0);
        translator.budget = super::profile::ThreadBudget::disabled_for_test(0, 0);
    }

    #[test]
    fn dsr_indirect_resolver_stats_start_at_zero() {
        let translator = super::ThreadTranslator::new(16 * 1024).expect("create translator");
        assert_eq!(translator.resolver_stats(), super::ResolverStats::default());
        let profile = translator.profile_snapshot();
        assert_eq!(profile.gateway_entries, 0);
        assert_eq!(profile.syscall_exits, 0);
        assert_eq!(profile.cache_lookups, 0);
        assert_eq!(profile.cache_used_bytes, 0);
        assert_eq!(profile.cache_capacity_bytes, 16 * 1024);
        assert_eq!(profile.translation_decode_ns, 0);
        assert_eq!(profile.translation_plan_ns, 0);
        assert_eq!(profile.translation_emit_ns, 0);
        assert_eq!(profile.translation_publication_ns, 0);
    }

    #[test]
    fn exclusive_fusion_sites_deduplicate_across_generations() {
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        let site = super::types::ExclusiveFusionSite {
            guest: PC,
            word: 0x885f_7c20,
            disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
            biased_scratch: None,
        };
        {
            let mut state = process.state.write();
            state.profiling = true;
            for generation in [
                super::types::CodeGeneration::INITIAL,
                super::types::CodeGeneration::claimed(1),
            ] {
                state.record_exclusive_fusion_site(site);
                state.sensitive.insert(
                    (site.guest, generation),
                    super::SensitiveMetadata {
                        exit: super::types::SensitiveExit {
                            kind: super::types::SensitiveKind::Exclusive(site.word),
                            register: None,
                            resume: GuestVa(site.guest.raw() + 4),
                        },
                        fusion: Some(site),
                    },
                );
            }
        }
        let mut translator = super::ThreadTranslator::for_process(process, 0);
        translator.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        let snapshot = translator.profile_snapshot();
        assert_eq!(
            snapshot.exclusive_fusion_sites
                [super::profile::ExclusiveFusionClass::EligibleBackendDisabled.index()],
            1
        );
        translator.budget = super::profile::ThreadBudget::disabled_for_test(0, 0);
    }

    #[test]
    fn exec_handoff_starts_a_new_fusion_site_epoch() {
        let old = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create old translator"),
        );
        let next = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create next translator"),
        );
        let site = |guest, word| super::types::ExclusiveFusionSite {
            guest: GuestVa(guest),
            word,
            disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
            biased_scratch: None,
        };
        {
            let mut state = old.state.write();
            state.profiling = true;
            state.record_exclusive_fusion_site(site(0x1000, 0x885f_7c20));
        }
        next.state.write().profiling = true;
        let mut thread = super::ThreadTranslator::for_process(old, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);

        thread.reset_for_exec_with_sink(next, |_| {});
        thread
            .process
            .state
            .write()
            .record_exclusive_fusion_site(site(0x2000, 0x885f_7c41));
        let frames = thread.take_profile_frames().expect("post-exec frames");

        assert!(
            frames.iter().any(|frame| {
                frame.contains("|frame=core|") && frame.ends_with("|exec_epoch=1")
            })
        );
        assert!(frames.iter().any(|frame| {
            frame.contains("|frame=fusion-sites-a|")
                && frame.contains("|fusion_eligible_backend_disabled=1|")
        }));
    }

    #[test]
    fn large_pre_exec_catalog_is_not_carried_into_replacement_translator() {
        let old = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create old translator"),
        );
        let next = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create next translator"),
        );
        {
            let mut state = old.state.write();
            state.profiling = true;
            for index in 0..4096_u64 {
                state.record_exclusive_fusion_site(super::types::ExclusiveFusionSite {
                    guest: GuestVa(0x1000 + index * 4),
                    word: 0x885f_7c20,
                    disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
                    biased_scratch: None,
                });
            }
        }
        next.state.write().profiling = true;
        let mut thread = super::ThreadTranslator::for_process(old, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);

        thread.reset_for_exec_with_sink(std::sync::Arc::clone(&next), |_| {});

        assert_eq!(
            next.state.read().exclusive_fusion_site_counts()
                [super::profile::ExclusiveFusionClass::EligibleBackendDisabled.index()],
            0
        );
        thread.budget = super::profile::ThreadBudget::disabled_for_test(0, 0);
    }

    #[test]
    fn dsr_exec_switch_keeps_retiring_translator_metadata_alive() {
        let old = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create old translator"),
        );
        let key = (PC, super::types::CodeGeneration::INITIAL);
        let entry = super::types::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        old.state.read().publications.get_or_publish(key, || entry);
        let mut thread = super::ThreadTranslator::for_process(std::sync::Arc::clone(&old), 0);
        let next = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create next translator"),
        );

        thread.reset_for_exec(next);

        assert_eq!(
            old.state.read().publications.published_count(),
            1,
            "pre-exec threads must retain old PC metadata until their Arc retires"
        );
    }

    fn protocol_value(frames: &[String], key: &str) -> u64 {
        frames
            .iter()
            .flat_map(|frame| frame.split('|'))
            .find_map(|field| field.strip_prefix(&format!("{key}=")))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing protocol field {key}"))
    }

    #[test]
    fn exec_finalizes_coherent_pre_and_post_eras() {
        let old = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create old translator"),
        );
        old.state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 3);
        old.state
            .write()
            .stats
            .add(super::ResolverStat::TranslationNs, 11);
        let mut thread = super::ThreadTranslator::for_process(old, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        thread
            .budget
            .record_exit(super::profile::ExitClass::Syscall)
            .expect("record pre-exec exit");
        thread.nested_translation_ns = 17;
        let next = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create next translator"),
        );
        next.state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 5);
        let mut pre_exec = Vec::new();

        thread.reset_for_exec_with_sink(next, |frames| pre_exec.extend_from_slice(frames));

        assert_eq!(protocol_value(&pre_exec, "era"), 0);
        assert_eq!(protocol_value(&pre_exec, "gateway_entries"), 1);
        assert_eq!(protocol_value(&pre_exec, "translations"), 3);
        assert_eq!(protocol_value(&pre_exec, "nested_translation_ns"), 11);
        assert_eq!(protocol_value(&pre_exec, "translate_phase_nested_ns"), 17);
        let post_exec = thread.take_profile_frames().expect("post-exec era");
        assert!(protocol_value(&post_exec, "era") > 0);
        assert_eq!(protocol_value(&post_exec, "gateway_entries"), 0);
        assert_eq!(protocol_value(&post_exec, "translations"), 5);
        assert_eq!(protocol_value(&post_exec, "nested_translation_ns"), 0);
        assert_eq!(protocol_value(&post_exec, "translate_phase_nested_ns"), 0);
    }

    #[test]
    fn post_exec_seeded_era_thread_cpu_excludes_the_installed_baseline() {
        // Models runtime re-entry after a PID-preserving host self-reexec
        // (`resume_guest_from_capsule`): the surviving thread's kernel CPU
        // counter is cumulative across the exec, so its post-exec
        // `ThreadBudget` carries an installed baseline. Install one
        // comfortably above anything this era could plausibly consume before
        // the flush below, so the era's own `thread_cpu_ns` must saturate at
        // zero — proving the pre-exec CPU that era already flushed is
        // excluded here rather than double-counted.
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        let mut thread = super::ThreadTranslator::for_process(process, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        thread
            .budget
            .install_thread_cpu_baseline_ns_for_test(1_000_000_000_000);

        let frames = thread.take_profile_frames().expect("post-exec-seeded era");

        assert_eq!(protocol_value(&frames, "thread_cpu_ns"), 0);
    }

    #[test]
    fn process_resolver_deltas_are_counted_exactly_once_across_threads() {
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        let mut first = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 42);
        let mut second = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 43);
        first.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        second.budget = super::profile::ThreadBudget::enabled_for_test(41, 43);
        process
            .state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 7);
        let first_frames = first.take_profile_frames().expect("first record");
        process
            .state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 5);
        let second_frames = second.take_profile_frames().expect("second record");

        assert_eq!(protocol_value(&first_frames, "translations"), 7);
        assert_eq!(protocol_value(&second_frames, "translations"), 5);
        assert_eq!(
            protocol_value(&first_frames, "translations")
                + protocol_value(&second_frames, "translations"),
            12
        );
    }

    #[test]
    fn take_profile_frames_emits_typed_attribution_frames() {
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        let mut thread = super::ThreadTranslator::for_process(process, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);

        let frames = thread.take_profile_frames().expect("attribution frames");

        assert_eq!(frames.len(), 14);
        assert!(frames.iter().any(|frame| frame.contains("|frame=process|")));
        assert!(
            frames
                .iter()
                .any(|frame| frame.contains("|phase_blocked_cpu_ns="))
        );
        // Gauge fields must parse; the flush-time process CPU of the test
        // harness is always positive.
        let _ = protocol_value(&frames, "thread_cpu_ns");
        let _ = protocol_value(&frames, "startup_wall_ns");
        let _ = protocol_value(&frames, "startup_cpu_ns");
        assert!(protocol_value(&frames, "process_cpu_ns") > 0);
    }

    #[test]
    fn resolver_overflow_invalidates_and_finalization_is_idempotent() {
        let process = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create translator"),
        );
        let mut thread = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        process.state.write().stats.translations = u64::MAX;
        process
            .state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 1);

        let frames = thread.take_profile_frames().expect("invalid record");
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("|complete=0|"));
        assert!(frames[0].contains("|reason=counter-overflow"));
        assert!(thread.take_profile_frames().is_none());
    }

    /// The seam that owns the flush: `native_darwin::finalize_native_thread_exit`
    /// is the function the real `DispatchOutcome::ThreadExit` dispatch arm
    /// calls before a guest thread retires. Driving the actual dispatch loop
    /// end-to-end (a real forked guest binary hitting a real `exit(2)`) is
    /// outside what a pure unit test can reach here, so this test calls the
    /// exact production function directly with a synthetic sibling thread and
    /// proves the two properties the attribution defect depended on: (1) a
    /// thread that retires via this path emits its complete NATIVEPERF
    /// `core`/`thread_cpu_ns` record — not silently absorbed into another
    /// pid's helper residual — and (2) that flush is exactly-once, so the
    /// translator's later `Drop` cannot duplicate the `(pid, tid, era)`
    /// group the wire protocol (and the Python analyzer) rejects on replay.
    #[test]
    fn thread_exit_flushes_the_exiting_threads_profile_record() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            // Redirect the real fd 2 to a pipe for the duration of the call:
            // `finalize_profile_epoch` writes NATIVEPERF frames directly to
            // `libc::STDERR_FILENO`, exactly as the production dispatch loop
            // does, so this observes the identical wire the campaign harness
            // parses instead of a stand-in.
            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let (memory, _guest) = mapped_dsr_test_memory(&[]).expect("map test memory");
            let memory: super::super::SharedNativeMemory =
                std::sync::Arc::new(super::super::NativeMemoryHandle::new(memory));

            let runtime = super::super::NativeThreadRuntime::new_current();
            // clear_child_tid=0 so `finish_thread` never dereferences guest
            // memory: this test only exercises the profile-flush contract.
            let sib_tid = runtime.registry.register_child(0);
            let mut sibling = runtime.sibling(sib_tid);
            let dispatcher = super::super::SyscallDispatcher::new();

            let process = std::sync::Arc::new(
                super::ProcessTranslator::new(16 * 1024).expect("create process translator"),
            );
            let mut translator = super::ThreadTranslator::for_process(process, sib_tid.raw());
            translator.budget = super::profile::ThreadBudget::enabled_for_test(
                unsafe { libc::getpid() },
                sib_tid.raw(),
            );
            translator
                .budget
                .record_exit(super::profile::ExitClass::Syscall)
                .expect("record a balanced gateway entry/exit pair");

            let outcome = super::super::finalize_native_thread_exit(
                &mut translator,
                &mut sibling,
                &dispatcher,
                &memory,
                0,
            );

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }
            runtime.registry.exit(sib_tid);

            assert!(
                matches!(outcome, super::super::NativeThreadLoopOutcome::ThreadDone),
                "a sibling with a live process leader must retire as ThreadDone"
            );
            assert!(
                captured.contains("NATIVEPERF1|thread|"),
                "ThreadExit must flush a NATIVEPERF record before the thread retires; \
                 captured stderr: {captured:?}"
            );
            assert!(captured.contains(&format!("|tid={}|", sib_tid.raw())));
            assert!(captured.contains("|frame=core|"));
            assert!(
                translator.take_profile_frames().is_none(),
                "the flush must be exactly-once: a later drop/finalize must not re-emit \
                 the same (pid, tid, era) group"
            );
        });
    }

    /// Extracts every complete `NATIVEPERF1|thread|...` line naming `tid` from
    /// captured stderr text.
    fn frames_for_tid(captured: &str, tid: i32) -> Vec<String> {
        let needle = format!("|tid={tid}|");
        captured
            .lines()
            .filter(|line| line.starts_with("NATIVEPERF1|thread|") && line.contains(&needle))
            .map(str::to_owned)
            .collect()
    }

    /// How many complete `core` frames (i.e. how many EMITTED RECORDS -- one
    /// `core` frame per record) name `tid` in the captured wire.
    fn core_frames_for_tid(captured: &str, tid: i32) -> usize {
        frames_for_tid(captured, tid)
            .iter()
            .filter(|line| line.contains("|frame=core|"))
            .count()
    }

    /// EXACTLY-ONCE UNDER CONCURRENCY. The registry hands one thread's record
    /// to exactly one of two possible emitters -- the thread's own self-flush
    /// (individual `exit(2)` via `finalize_native_thread_exit`, an `Execve`
    /// self-reexec, `native_die_by_signal`, or a `RetireForExec` retirement)
    /// or a FOREIGN thread's `exit_group` drain -- and those two can genuinely
    /// run at the same instant on two cores, since `exit_group` fires while
    /// siblings are still executing. If both emit, the wire carries a
    /// duplicate `(pid, tid, era)` group, which `parse_nativeperf` hard-rejects
    /// ("duplicate frame ... for duplicate thread identity") -- an intermittent
    /// HARD FAILURE of a real profiled campaign run, not a degradation.
    ///
    /// Two REAL OS threads, synchronized only through the shared registry plus
    /// a per-iteration barrier that lines their two claims up as tightly as
    /// the scheduler allows: one repeatedly registers-then-self-flushes, the
    /// other repeatedly drains. Across every iteration each identity must
    /// appear EXACTLY once on the wire -- never twice (duplicate) and never
    /// zero times (lost).
    #[test]
    fn sibling_flush_is_exactly_once_when_a_drain_races_a_self_flush() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;
            use std::sync::{Arc, Barrier};

            const ITERATIONS: i32 = 256;
            const FIRST_TID: i32 = 20_000;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            // Drain the pipe CONCURRENTLY: 256 iterations x 10 frames x up to
            // two emitters is far past the 64 KiB pipe buffer, so a reader that
            // only ran after the join would wedge the writers.
            let read_fd = stderr_pipe[0];
            let reader = std::thread::spawn(move || {
                let mut text = String::new();
                let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
                file.read_to_string(&mut text)
                    .expect("read captured stderr");
                text
            });

            let pid = unsafe { libc::getpid() };
            let process = std::sync::Arc::new(
                super::ProcessTranslator::new(16 * 1024).expect("create process translator"),
            );
            let barrier = Arc::new(Barrier::new(2));

            let self_flusher = {
                let process = std::sync::Arc::clone(&process);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    for index in 0..ITERATIONS {
                        let tid = FIRST_TID + index;
                        let mut translator = super::ThreadTranslator::for_process(
                            std::sync::Arc::clone(&process),
                            tid,
                        );
                        translator.budget =
                            super::profile::ThreadBudget::enabled_for_test(pid, tid);
                        // "At DSR loop entry" -- register the slot a foreign
                        // drain could take.
                        translator.publish_sibling_snapshot();
                        barrier.wait();
                        // Alternate which side is favoured so BOTH orderings
                        // are exercised: on even iterations yield so the drain
                        // most likely wins the claim, on odd ones go straight
                        // for it so this thread most likely wins. Either way
                        // the identity must land on the wire exactly once.
                        if index % 2 == 0 {
                            std::thread::yield_now();
                        }
                        // ...and race a drain with this thread's OWN
                        // retirement flush.
                        translator.finalize_profile_epoch();
                    }
                })
            };
            let drainer = {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut leader = super::ThreadTranslator::for_process(process, 42);
                    leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
                    for index in 0..ITERATIONS {
                        barrier.wait();
                        if index % 2 == 1 {
                            std::thread::yield_now();
                        }
                        leader.drain_sibling_profiles_before_process_exit();
                    }
                    leader.finalize_profile_epoch();
                })
            };
            self_flusher.join().expect("join self-flushing thread");
            drainer.join().expect("join draining thread");

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let captured = reader.join().expect("join stderr reader");

            assert!(
                !captured.contains("NATIVEPERF1|invalid|"),
                "the race must never produce an invalid record"
            );
            let mut duplicated = Vec::new();
            let mut lost = Vec::new();
            for index in 0..ITERATIONS {
                let tid = FIRST_TID + index;
                match core_frames_for_tid(&captured, tid) {
                    1 => {}
                    0 => lost.push(tid),
                    n => duplicated.push((tid, n)),
                }
            }
            assert!(
                duplicated.is_empty(),
                "a drain racing a self-flush DOUBLE-emitted {} of {ITERATIONS} identities \
                 (duplicate (pid, tid, era) groups the wire protocol rejects): {duplicated:?}",
                duplicated.len()
            );
            assert!(
                lost.is_empty(),
                "a drain racing a self-flush LOST {} of {ITERATIONS} identities entirely: {lost:?}",
                lost.len()
            );
        });
    }

    /// The process-wide resolver counters (translations, cache lookups/hits,
    /// invalidated blocks, translation_*_ns, duplicate publications) are
    /// SHARED by every thread of the process and are published as a delta
    /// against ONE `reported_stats` checkpoint. So the delta must be assigned
    /// to exactly one record per process epoch -- never split arbitrarily, and
    /// never double-counted.
    ///
    /// At an `exit_group` seam the owner is the DRAINING thread's own record:
    /// its `finalize_profile_epoch()` always runs immediately before the
    /// drain, and claims the outstanding delta. The siblings drained after it
    /// therefore report structurally ZERO process-wide deltas -- not "whatever
    /// happened to still be unclaimed when the loop reached them", which
    /// would hand the first sibling the residue and every later one ~0 purely
    /// as a function of loop order.
    ///
    /// This pins that ownership. It also pins what must NOT be zeroed: the
    /// siblings' own PER-THREAD resolver counters, and the cache
    /// point-in-time gauges (neither is a delta).
    #[test]
    fn a_drain_leaves_the_process_wide_resolver_delta_to_the_draining_threads_record() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const LEADER_TID: i32 = 42;
            const SIBLING_TIDS: [i32; 2] = [9051, 9052];
            let process = std::sync::Arc::new(
                super::ProcessTranslator::new(16 * 1024).expect("create process translator"),
            );
            // The whole process epoch's shared, process-wide resolver work.
            process
                .state
                .write()
                .stats
                .add(super::ResolverStat::Translations, 11);
            process
                .state
                .write()
                .stats
                .add(super::ResolverStat::CacheLookups, 23);

            // Two siblings register, then die without ever running their own
            // flush (exit_group's hard kill) -- each with its OWN per-thread
            // resolver counters, which must survive the drain intact.
            let mut siblings = Vec::new();
            for (index, tid) in SIBLING_TIDS.into_iter().enumerate() {
                let mut sibling =
                    super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), tid);
                sibling.budget = super::profile::ThreadBudget::enabled_for_test(pid, tid);
                sibling
                    .stats
                    .add(super::ResolverStat::OneEntryHits, (index as u64) + 1);
                sibling.publish_sibling_snapshot();
                siblings.push(sibling);
            }

            let mut leader =
                super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), LEADER_TID);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, LEADER_TID);
            // The real `exit_group` seam: claim own slot, drain the siblings,
            // then flush this thread's own record LAST so it claims the whole
            // outstanding process-wide delta.
            leader.finalize_profile_epoch_at_process_exit();

            // The siblings were killed by the `_exit()`: they never run again.
            for sibling in siblings {
                std::mem::forget(sibling);
            }

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            // The draining thread's own record owns the whole process delta.
            let leader_frames = frames_for_tid(&captured, LEADER_TID);
            assert_eq!(core_frames_for_tid(&captured, LEADER_TID), 1);
            assert_eq!(protocol_value(&leader_frames, "translations"), 11);
            assert_eq!(protocol_value(&leader_frames, "cache_lookups"), 23);

            for (index, tid) in SIBLING_TIDS.into_iter().enumerate() {
                let frames = frames_for_tid(&captured, tid);
                assert_eq!(
                    core_frames_for_tid(&captured, tid),
                    1,
                    "each drained sibling must be emitted exactly once"
                );
                // Process-wide deltas: structurally zero on EVERY drained
                // sibling -- not just the 2nd..Nth. Before this rule, the
                // first sibling in the drain loop swallowed the (arbitrary)
                // residue and the rest silently got 0.
                for field in [
                    "translations",
                    "duplicate_publications",
                    "cache_lookups",
                    "cache_lookup_hits",
                    "invalidated_blocks",
                    "nested_translation_ns",
                    "nested_translation_decode_ns",
                    "nested_translation_plan_ns",
                    "nested_translation_emit_ns",
                    "nested_translation_publication_ns",
                ] {
                    assert_eq!(
                        protocol_value(&frames, field),
                        0,
                        "drained sibling tid={tid} must report a structurally zero \
                         process-wide delta for {field} (the draining thread's record owns it)"
                    );
                }
                // ...but its OWN per-thread counters are real, and the cache
                // point-in-time gauges are real live reads. Neither is a delta.
                assert_eq!(
                    protocol_value(&frames, "one_entry_hits"),
                    (index as u64) + 1,
                    "a drained sibling's per-thread resolver counters must survive intact"
                );
                assert_eq!(protocol_value(&frames, "cache_capacity_bytes"), 16 * 1024);
            }
        });
    }

    /// The root cause this task fixes: Linux `exit_group` kills every OTHER
    /// live guest OS thread of a process unconditionally, at the runtime's own
    /// `libc::_exit()`, with zero chance for any of them to run their own
    /// flush -- Drop included. A thread that registered a sibling slot (every
    /// DSR loop iteration republishes one, see `publish_sibling_snapshot`) but
    /// never got to self-flush must still have its complete NATIVEPERF record
    /// emitted by whichever thread drains the registry before calling
    /// `libc::_exit()`, carrying its own identity and a plausible
    /// `thread_cpu_ns` read LIVE, cross-thread, via the mach port it captured
    /// on itself at registration.
    #[test]
    fn exit_group_drain_emits_a_registered_but_unflushed_siblings_record() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const SIBLING_TID: i32 = 9042;
            let process = std::sync::Arc::new(
                super::ProcessTranslator::new(16 * 1024).expect("create process translator"),
            );

            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(0);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
            let sibling_process = std::sync::Arc::clone(&process);
            let sibling_thread = std::thread::spawn(move || {
                let mut translator =
                    super::ThreadTranslator::for_process(sibling_process, SIBLING_TID);
                translator.budget =
                    super::profile::ThreadBudget::enabled_for_test(pid, SIBLING_TID);
                translator
                    .budget
                    .record_exit(super::profile::ExitClass::Syscall)
                    .expect("record a balanced gateway entry/exit pair");
                // "At DSR loop entry" -- the real call site is the top of
                // `run_native_dsr_thread_loop_profiled`; this registers the
                // same way.
                translator.publish_sibling_snapshot();
                // Burn real CPU (sleeping would advance wall time, not the
                // thread's own `thread_info` CPU counters this test proves a
                // FOREIGN thread can read).
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(20);
                let mut spin: u64 = 0;
                while std::time::Instant::now() < deadline {
                    spin = spin.wrapping_add(1);
                }
                std::hint::black_box(spin);
                ready_tx.send(()).expect("signal registered and warmed up");
                // Simulate `exit_group`'s kernel-level, unconditional kill:
                // this thread runs no more of its own code after the leader's
                // drain runs, Drop included, so it must never reach
                // `take_profile_frames` -- `mem::forget` instead of letting
                // the value drop naturally.
                release_rx.recv().expect("wait for the leader's drain");
                std::mem::forget(translator);
            });

            ready_rx.recv().expect("sibling registered its slot");

            let mut leader = super::ThreadTranslator::for_process(process, 42);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
            leader.drain_sibling_profiles_before_process_exit();
            // Flush the leader's OWN (uninteresting, all-zero) record here,
            // still inside the redirected-stderr window, so its `Drop` does
            // not write directly to the real fd 2 after the restore below.
            leader.finalize_profile_epoch();

            release_tx.send(()).expect("release the sibling thread");
            sibling_thread.join().expect("join sibling thread");

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            let sibling_frames = frames_for_tid(&captured, SIBLING_TID);
            assert_eq!(
                sibling_frames.len(),
                14,
                "the drain must emit the sibling's complete 14-frame record exactly once; \
                 captured stderr: {captured:?}"
            );
            for frame in [
                "core",
                "exits",
                "sensitive",
                "fusion-exec-a",
                "fusion-exec-b",
                "fusion-sites-a",
                "fusion-sites-b",
                "phases-a",
                "phases-b",
                "resolver-thread",
                "resolver-process",
                "resolver-times",
                "cache-gauge",
                "process",
            ] {
                let marker = format!("|frame={frame}|");
                assert_eq!(
                    sibling_frames
                        .iter()
                        .filter(|line| line.contains(&marker))
                        .count(),
                    1,
                    "frame {frame} must appear exactly once for the drained sibling"
                );
            }
            let thread_cpu_ns = protocol_value(&sibling_frames, "thread_cpu_ns");
            assert!(
                thread_cpu_ns > 0,
                "a sibling thread that spun for 20ms must report a plausibly nonzero \
                 thread_cpu_ns read live via its mach port, got {thread_cpu_ns}"
            );
        });
    }

    /// Exactly-once: a thread that runs its OWN flush (and so deregisters
    /// itself) must never ALSO be re-emitted by a later foreign
    /// `exit_group` drain -- a double emission is a duplicate `(pid, tid,
    /// era)` group, which the Python analyzer hard-rejects on replay.
    #[test]
    fn exit_group_drain_never_reemits_a_thread_that_already_self_flushed() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const SELF_FLUSHED_TID: i32 = 9043;
            let process = std::sync::Arc::new(
                super::ProcessTranslator::new(16 * 1024).expect("create process translator"),
            );

            let mut already_flushed = super::ThreadTranslator::for_process(
                std::sync::Arc::clone(&process),
                SELF_FLUSHED_TID,
            );
            already_flushed.budget =
                super::profile::ThreadBudget::enabled_for_test(pid, SELF_FLUSHED_TID);
            already_flushed
                .budget
                .record_exit(super::profile::ExitClass::Syscall)
                .expect("record a balanced gateway entry/exit pair");
            // Register, exactly like a real DSR loop iteration would...
            already_flushed.publish_sibling_snapshot();
            // ...then flush and deregister itself, exactly like the normal
            // (non-`exit_group`) retirement paths do.
            already_flushed.finalize_profile_epoch();

            let mut leader = super::ThreadTranslator::for_process(process, 42);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
            // The `exit_group` seam: the leader's own flush already ran
            // (mirrored here by `already_flushed.finalize_profile_epoch()`
            // above standing in for a DIFFERENT thread's self-flush); now
            // drain whatever siblings remain -- which must be none.
            leader.drain_sibling_profiles_before_process_exit();
            // Flush the leader's OWN (uninteresting, all-zero) record here,
            // still inside the redirected-stderr window, so its `Drop` does
            // not write directly to the real fd 2 after the restore below.
            leader.finalize_profile_epoch();

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            let frames = frames_for_tid(&captured, SELF_FLUSHED_TID);
            assert_eq!(
                frames.len(),
                14,
                "a self-flushed thread's record must appear exactly once (its own \
                 self-flush), never a second time from the leader's drain; captured: {captured:?}"
            );
        });
    }

    /// Zero cost / zero effect when profiling is off: a thread whose budget
    /// was never enabled must never register a sibling slot at all, so a
    /// foreign drain finds (and emits) nothing for it.
    #[test]
    fn disabled_profiling_thread_never_registers_a_sibling_slot() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const DISABLED_TID: i32 = 9044;
            let process = std::sync::Arc::new(
                super::ProcessTranslator::new(16 * 1024).expect("create process translator"),
            );

            let mut disabled =
                super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), DISABLED_TID);
            disabled.budget = super::profile::ThreadBudget::disabled_for_test(pid, DISABLED_TID);
            disabled.publish_sibling_snapshot();

            let mut leader = super::ThreadTranslator::for_process(process, 42);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
            leader.drain_sibling_profiles_before_process_exit();
            // Flush the leader's OWN (uninteresting, all-zero) record here,
            // still inside the redirected-stderr window, so its `Drop` does
            // not write directly to the real fd 2 after the restore below.
            leader.finalize_profile_epoch();

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            assert!(
                frames_for_tid(&captured, DISABLED_TID).is_empty(),
                "a profile-disabled thread must never publish a sibling slot; captured: {captured:?}"
            );
        });
    }

    #[test]
    fn dsr_fork_child_exec_reuses_and_clears_inherited_translator() {
        let process =
            super::ProcessTranslator::new(16 * 1024).expect("create inherited translator");
        let key = (PC, super::types::CodeGeneration::INITIAL);
        let entry = super::types::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        process
            .state
            .read()
            .publications
            .get_or_publish(key, || entry);

        process.reset_after_fork_for_exec();

        let state = process.state.read();
        assert_eq!(state.publications.published_count(), 0);
        assert!(state.blocks.is_empty());
        assert!(state.published.is_empty());
    }

    #[test]
    fn classifies_copy_syscall_and_control_flow() {
        assert!(matches!(
            classify(0x9100_0400, PC),
            Ok(InstAction::Copy(0x9100_0400))
        ));
        assert!(matches!(
            classify(0xd503_251f, PC),
            Ok(InstAction::Copy(0xd503_251f))
        ));
        for word in [0xd53b_4416, 0xd51b_4416, 0xd53b_4436, 0xd51b_4436] {
            assert!(
                matches!(classify(word, PC), Ok(InstAction::Copy(observed)) if observed == word)
            );
        }
        assert!(matches!(
            classify(0xa900_4b82, PC),
            Ok(InstAction::Memory(memory))
                if memory.word == 0xa900_4b82
                    && memory.virtualization == MemoryVirtualization::X18X28ReadOnly
        ));
        assert!(matches!(
            classify(0xf900_0e5c, PC),
            Ok(InstAction::Memory(memory))
                if memory.word == 0xf900_0e5c
                    && memory.virtualization == MemoryVirtualization::X18X28ReadOnly
        ));
        assert!(matches!(
            classify(0x910a_6392, PC),
            Ok(InstAction::VirtualizedX18WriteX28Read {
                word: 0x910a_6392,
                ..
            })
        ));
        assert!(matches!(
            classify(0xcb16_0392, PC),
            Ok(InstAction::VirtualizedX18WriteX28Read {
                word: 0xcb16_0392,
                ..
            })
        ));
        assert!(matches!(
            classify(0xa94d_cb8f, PC),
            Ok(InstAction::Memory(memory))
                if memory.word == 0xa94d_cb8f
                    && memory.virtualization == MemoryVirtualization::X18WriteX28Read
        ));
        assert!(matches!(
            classify(0xd400_0001, PC),
            Ok(InstAction::Syscall { resume }) if resume == GuestVa(0x1004)
        ));
        assert!(matches!(
            classify(0x1400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Branch && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0x9400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Call && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd61f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Branch
        ));
        assert!(matches!(
            classify(0xd65f_03c0, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Return
        ));
    }

    #[test]
    fn copy_subset_rejects_virtualized_register_operands() {
        let word = 0xd280_0032;
        assert!(super::decode::decoded_operands_mention_x18(word, PC));
        assert!(matches!(
            classify(word, PC),
            Ok(InstAction::VirtualizedX18 { word: observed, .. }) if observed == word
        ));
        let word = 0xd280_003c;
        assert!(super::decode::decoded_operands_mention_x28(word, PC));
        assert!(matches!(
            classify(word, PC),
            Ok(InstAction::VirtualizedX28 { word: observed, .. }) if observed == word
        ));
        assert!(matches!(
            classify(0xf940_0240, PC),
            Ok(InstAction::Memory(memory)) if memory.base == MemoryBase::VirtualX18
        ));
        assert!(matches!(
            classify(0xf940_0380, PC),
            Ok(InstAction::Memory(memory)) if memory.base == MemoryBase::VirtualX28
        ));
    }

    proptest! {
        #[test]
        fn copy_subset_never_contains_virtualized_registers(word in any::<u32>()) {
            if matches!(classify(word, PC), Ok(InstAction::Copy(_))) {
                prop_assert!(!super::decode::decoded_operands_mention_x18(word, PC));
                prop_assert!(!super::decode::decoded_operands_mention_x28(word, PC));
            }
        }
    }

    #[test]
    #[ignore = "set CARRICK_DSR_SCAN_ELF to audit a built AArch64 ELF"]
    fn dsr_static_elf_reserved_register_decode_audit() {
        let path = std::env::var("CARRICK_DSR_SCAN_ELF").expect("CARRICK_DSR_SCAN_ELF");
        let bytes = std::fs::read(&path).expect("read scan ELF");
        let elf = goblin::elf::Elf::parse(&bytes).expect("parse scan ELF");
        let mut blind_spots = Vec::new();
        for header in elf.program_headers.iter().filter(|header| {
            header.p_type == goblin::elf::program_header::PT_LOAD
                && header.p_flags & goblin::elf::program_header::PF_X != 0
        }) {
            let start = usize::try_from(header.p_offset).expect("segment offset");
            let length = usize::try_from(header.p_filesz).expect("segment length");
            for (index, chunk) in bytes[start..start + length].chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes(chunk.try_into().expect("instruction word"));
                let pc =
                    GuestVa(header.p_vaddr + u64::try_from(index * 4).expect("instruction PC"));
                let Ok(instruction) = bad64::decode(word, pc.raw()) else {
                    continue;
                };
                let text_mentions_reserved = instruction
                    .to_string()
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| matches!(token, "x18" | "w18" | "x28" | "w28"));
                let decoder_mentions_reserved =
                    super::decode::decoded_operands_mention_x18(word, pc)
                        || super::decode::decoded_operands_mention_x28(word, pc);
                if text_mentions_reserved && !decoder_mentions_reserved {
                    blind_spots.push(format!("0x{:x}: 0x{word:08x} {instruction}", pc.raw()));
                }
            }
        }
        assert!(
            blind_spots.is_empty(),
            "bad64 operand audit missed x18/x28 references:\n{}",
            blind_spots.join("\n")
        );
    }

    #[test]
    fn dsr_vdso_reserved_register_decode_audit() {
        let bytes = carrick_mem::vdso::vdso_image_bytes();
        let elf = goblin::elf::Elf::parse(&bytes).expect("parse vDSO ELF");
        let mut blind_spots = Vec::new();
        for header in elf.program_headers.iter().filter(|header| {
            header.p_type == goblin::elf::program_header::PT_LOAD
                && header.p_flags & goblin::elf::program_header::PF_X != 0
        }) {
            let start = usize::try_from(header.p_offset).expect("segment offset");
            let length = usize::try_from(header.p_filesz).expect("segment length");
            for (index, chunk) in bytes[start..start + length].chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes(chunk.try_into().expect("instruction word"));
                let pc =
                    GuestVa(header.p_vaddr + u64::try_from(index * 4).expect("instruction PC"));
                let Ok(instruction) = bad64::decode(word, pc.raw()) else {
                    continue;
                };
                let text_mentions_reserved = instruction
                    .to_string()
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| matches!(token, "x18" | "w18" | "x28" | "w28"));
                let decoder_mentions_reserved =
                    super::decode::decoded_operands_mention_x18(word, pc)
                        || super::decode::decoded_operands_mention_x28(word, pc);
                if text_mentions_reserved && !decoder_mentions_reserved {
                    blind_spots.push(format!("0x{:x}: 0x{word:08x} {instruction}", pc.raw()));
                }
            }
        }
        assert!(
            blind_spots.is_empty(),
            "vDSO operand audit missed x18/x28 references:\n{}",
            blind_spots.join("\n")
        );
    }

    #[test]
    fn classifies_pc_relative_and_sensitive_operations() {
        assert!(matches!(
            classify(0x1000_0040, PC),
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::Adr && inst.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd53b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadTpidr
        ));
        assert!(matches!(
            classify(0xd51b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::WriteTpidr
        ));
        assert!(matches!(
            classify(0xd50b_7420, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcZva
        ));
        assert!(matches!(
            classify(0x9000_0000, PC),
            Ok(InstAction::PcRelative(inst)) if inst.kind == PcRelativeKind::Adrp
        ));
        assert!(matches!(
            classify(0x5800_0040, PC),
            Ok(InstAction::Memory(memory))
                if memory.class == MemoryClass::Literal
                    && memory.base == MemoryBase::Literal(GuestVa(0x1008))
        ));
        assert!(matches!(
            classify(0xd53b_0020, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadCtr
        ));
        assert!(matches!(
            classify(0xd53b_00e0, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadDczid
        ));
        assert!(matches!(
            classify(0xd50b_7b20, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcCvau
        ));
        assert!(matches!(
            classify(0xd50b_7520, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::IcIvau
        ));
    }

    #[test]
    fn dsr_counter_register_reads_execute_directly() {
        assert!(matches!(
            classify(0xd53b_e042, PC),
            Ok(InstAction::Copy(0xd53b_e042))
        ));
        assert!(matches!(
            classify(0xd53b_e002, PC),
            Ok(InstAction::Copy(0xd53b_e002))
        ));
        assert!(matches!(
            classify(0xd53b_e052, PC),
            Ok(InstAction::VirtualizedX18 {
                word: 0xd53b_e052,
                ..
            })
        ));
        assert!(matches!(
            classify(0xd53b_e05c, PC),
            Ok(InstAction::VirtualizedX28 {
                word: 0xd53b_e05c,
                ..
            })
        ));
    }

    #[test]
    fn classifies_conditional_compare_test_and_indirect_calls() {
        assert!(matches!(
            classify(0x5400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Conditional && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: false }
                    && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb500_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: true }
        ));
        assert!(matches!(
            classify(0x3600_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: false }
        ));
        assert!(matches!(
            classify(0x3700_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: true }
        ));
        assert!(matches!(
            classify(0xd63f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Call
        ));
    }

    proptest! {
        #[test]
        fn direct_branch_targets_follow_signed_imm26(word_offset in -0x1ff_ffff_i32..=0x1ff_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (word_offset as u32) & 0x03ff_ffff;
            let word = 0x1400_0000 | immediate;
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(word_offset) * 4));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::Direct(exit))
                    if exit.kind == DirectKind::Branch && exit.target == expected
            ));
        }

        #[test]
        fn adr_targets_follow_signed_imm21(byte_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (byte_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x1000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(byte_offset)));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adr && inst.target == expected
            ));
        }

        #[test]
        fn adrp_targets_follow_signed_page_imm21(page_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0abc);
            let immediate = (page_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x9000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa((pc.raw() & !0xfff).wrapping_add_signed(i64::from(page_offset) * 4096));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adrp && inst.target == expected
            ));
        }
    }

    #[test]
    fn dsr_cache_publishes_executable_aarch64_code() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let result = super::cache::TranslationCache::new(16 * 1024).and_then(|mut cache| {
                let mut writer = cache.begin_write(8)?;
                writer.write_words(&[0xd280_0540, 0xd65f_03c0])?; // mov x0,#42; ret
                let published = writer.publish()?;
                if published.len() != 8
                    || !cache.contains_host_pc(published.entry().host())
                    || cache.contains_host_pc(carrick_guest_mem::HostVa(1))
                {
                    return Err(super::types::DsrError::CachePolicy(
                        "published code metadata was inconsistent".to_string(),
                    ));
                }
                let function: extern "C" fn() -> u64 =
                    unsafe { std::mem::transmute(published.entry().host().raw()) };
                if function() != 42 {
                    return Err(super::types::DsrError::CachePolicy(
                        "published code returned the wrong value".to_string(),
                    ));
                }
                Ok(())
            });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_cache_second_publication_executes_new_instructions() {
        let mut cache =
            super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let mut first_writer = cache.begin_write(8).expect("begin first cache write");
        first_writer
            .write_words(&[0xd280_0540, 0xd65f_03c0])
            .expect("write first code");
        let first = first_writer.publish().expect("publish first code");
        let first_function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(first.entry().host().raw()) };
        assert_eq!(first_function(), 42);

        let mut second_writer = cache.begin_write(8).expect("begin second cache write");
        second_writer
            .write_words(&[0xd280_00e0, 0xd65f_03c0])
            .expect("write second code"); // mov x0,#7; ret
        let second = second_writer.publish().expect("publish second code");
        let second_function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(second.entry().host().raw()) };
        assert_eq!(second_function(), 7);
        assert_ne!(first.entry(), second.entry());
    }

    fn assert_child_faults(action: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            action();
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let fatal_handler_exit = libc::WIFEXITED(status)
            && matches!(
                libc::WEXITSTATUS(status),
                value if value == 128 + libc::SIGBUS || value == 128 + libc::SIGSEGV
            );
        assert!(
            fatal_handler_exit
                || (libc::WIFSIGNALED(status)
                    && matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV)),
            "child unexpectedly survived W/X violation: status=0x{status:x}"
        );
    }

    #[test]
    fn dsr_cache_write_and_execute_phases_are_disjoint() {
        assert_child_faults(|| {
            let mut cache =
                super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
            let mut writer = cache.begin_write(8).expect("begin cache write");
            writer
                .write_words(&[0xd280_0540, 0xd65f_03c0])
                .expect("write code");
            let function: extern "C" fn() -> u64 =
                unsafe { std::mem::transmute(writer.entry_for_test().host().raw()) };
            let _ = function();
        });

        assert_child_faults(|| {
            let mut cache =
                super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
            let mut writer = cache.begin_write(8).expect("begin cache write");
            writer
                .write_words(&[0xd280_0540, 0xd65f_03c0])
                .expect("write code");
            let published = writer.publish().expect("publish code");
            let ptr = published.entry().host().raw() as *mut u32;
            unsafe { std::ptr::write_volatile(ptr, 0xd280_00e0) };
        });
    }

    #[test]
    fn dsr_cache_published_code_is_fork_inherited() {
        let mut cache =
            super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let mut writer = cache.begin_write(8).expect("begin cache write");
        writer
            .write_words(&[0xd280_0540, 0xd65f_03c0])
            .expect("write code");
        let published = writer.publish().expect("publish code");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let function: extern "C" fn() -> u64 =
                unsafe { std::mem::transmute(published.entry().host().raw()) };
            unsafe { libc::_exit(i32::from(function() != 42)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_cache_child_discards_inherited_unpublished_write() {
        let mut cache =
            super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let writer = cache.begin_write(8).expect("begin inherited cache write");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            drop(writer);
            let result = cache.begin_write(8).and_then(|mut clean_writer| {
                clean_writer.write_words(&[0xd280_00e0, 0xd65f_03c0])?;
                let published = clean_writer.publish()?;
                let function: extern "C" fn() -> u64 =
                    unsafe { std::mem::transmute(published.entry().host().raw()) };
                if function() != 7 {
                    return Err(super::types::DsrError::CachePolicy(
                        "child clean transaction returned the wrong value".to_string(),
                    ));
                }
                Ok(())
            });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);

        drop(writer);
    }

    #[test]
    fn dsr_cache_exhaustion_is_a_typed_error() {
        let mut cache =
            super::cache::TranslationCache::new(1).expect("allocate one-page translation cache");
        let error = match cache.begin_write(16 * 1024 + 4) {
            Ok(_) => panic!("oversized write should exhaust cache"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::types::DsrError::CacheCapacity {
                requested: 16_388,
                used: 0,
                capacity: 16_384,
            }
        ));
    }
}
