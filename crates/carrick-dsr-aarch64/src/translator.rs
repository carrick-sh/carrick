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
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};

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

/// The persistent per-image translation store is DEFAULT ON; exact
/// `CARRICK_DSR_PERSISTENT_STORE=0` restores the per-run translation path for
/// rollback and controlled comparisons.
///
/// The parity blocker that forced opt-in (`707fd9c5`) is FIXED
/// architecturally: attached units used to run compute-bound shapes +65-78%
/// slower (awk-8M 358 → ~594 ms) because
/// `record_portable_block_artifact`'s authority-mode second emission gave
/// unit blocks a `BindingIndex` guard with no trusted entry, so every
/// patched edge re-ran an 11-instruction guard ending in an `ldar`
/// (`docs/perf-results/2026-08-03-store-template-parity-mechanism.md`).
/// Units now carry the NATIVE recording tap — the ONE emission's
/// `ArtifactTemplate` with Absolute-guard relocations, the trusted entry,
/// and private-gateway exits — and the install replays each block through
/// `publish_emitted`, so an installed block is INDISTINGUISHABLE from a
/// natively-translated one (word identity + trusted-entry registration +
/// patched links past the guard pinned by
/// `translator::tests::native_tap_unit_install` and
/// `emit::tests::recorded_emission_is_word_identical_to_native_emission`).
/// The `BindingIndex` guard, `PortableUnitAuthority` emission, edge
/// trampolines, and the direct-binding cell sidecar are DELETED; the current
/// hot/cold wire is `TRANSLATOR_ABI_CURRENT = 8` + `{stem}.metadata-v5`, so
/// older stores refuse cleanly to a miss and re-record.
///
/// Default-on authority is the receipt-bound 16-quad cold-Go-build ABBA at
/// `6821d2ba`: store-on won 16/16 quads, reducing total CPU 8.33%, elapsed
/// 8.43%, and workload wall 8.84%, with zero failed samples. Mechanism and
/// correctness qualification are recorded in
/// `docs/perf-results/2026-08-03-persistent-store-default-confirmation.md`.
/// The election/persistence mechanics remain fail-soft (fork-claim clearing,
/// first-miss election, per-host persistence, crash-safe rename+digest).
pub fn persistent_store_runtime_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        persistent_store_enabled_from(std::env::var_os("CARRICK_DSR_PERSISTENT_STORE").as_deref())
    })
}

fn persistent_store_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
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

    fn prepare_consumption<'token>(
        &'token mut self,
        process: &ProcessTranslator,
        thread: &ThreadTranslator,
    ) -> Result<ValidatedDirectBindingExecResetToken<'token>, types::DsrError> {
        self.validate_for(process, thread)?;
        Ok(ValidatedDirectBindingExecResetToken { token: self })
    }
}

struct ValidatedDirectBindingExecResetToken<'token> {
    token: &'token mut DirectBindingExecResetToken,
}

impl ValidatedDirectBindingExecResetToken<'_> {
    fn consume(self) {
        self.token.consumed = true;
    }
}

/// Fully validated authority for one retiring translator's infallible exec
/// reset commit.
#[must_use = "a prepared exec reset must be committed only after mapped-memory PONR"]
pub struct PreparedDirectBindingExecReset<'process, 'thread, 'token> {
    state: RwLockWriteGuard<'process, ProcessState>,
    thread: &'thread ThreadTranslator,
    token: ValidatedDirectBindingExecResetToken<'token>,
    catalog: Option<PreparedCatalogExecReset>,
}

impl PreparedDirectBindingExecReset<'_, '_, '_> {
    /// Consumes the validated token and retires process-owned translator state
    /// without any recoverable operation.
    pub fn commit(self) -> crate::direct_binding::ExecBindingClearStats {
        self.commit_inner(|_| {})
    }
    fn commit_inner(
        self,
        mut recorder: impl FnMut(DirectBindingResetEvent),
    ) -> crate::direct_binding::ExecBindingClearStats {
        let PreparedDirectBindingExecReset {
            mut state,
            thread,
            token,
            catalog,
        } = self;
        let _ = thread.tid;
        token.consume();
        if let Some(catalog) = catalog {
            state.translated_ranges.commit_dormant_for_exec(catalog);
        }
        // No direct-binding cells exist any more (installed unit blocks are
        // patched like native blocks), so the exec reset's clear phases are
        // recorded for sequencing evidence but clear nothing.
        let clear_started = std::time::Instant::now();
        recorder(DirectBindingResetEvent::CellsCleared);
        recorder(DirectBindingResetEvent::ThreadCachesCleared);
        recorder(DirectBindingResetEvent::IndexesCleared);
        recorder(DirectBindingResetEvent::DescriptorsDropped);
        let clear_stats = crate::direct_binding::ExecBindingClearStats {
            duration: clear_started.elapsed(),
            ..Default::default()
        };
        state.executable_ranges.reset_head_to_private();
        recorder(DirectBindingResetEvent::ExecutableRangeHeadReset);
        recorder(DirectBindingResetEvent::UnitsDropped);
        state.attached_units.clear();
        state.attached_unit_blocks.clear();
        state.executable_ranges.drop_shared_nodes();
        recorder(DirectBindingResetEvent::ExecutableRangeNodesDropped);
        state.clear_published();
        state.blocks.clear();
        state.pending.clear();
        state.direct_link_incoming.clear();
        state.trusted_entries.clear();
        state.trusted_route_entries.clear();
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
        clear_stats
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

/// Fully constructed initial thread translator awaiting process publication.
/// Committing it is a move and has no recoverable failure path.
#[must_use = "a prepared thread install must be committed or discarded"]
pub struct PreparedThreadInstall {
    thread: ThreadTranslator,
}

impl PreparedThreadInstall {
    pub fn commit(self) -> ThreadTranslator {
        self.thread
    }
}

/// Checked replacement-thread handoff that exclusively borrows its survivor
/// until the process swap is committed.
#[must_use = "a prepared exec handoff must be committed or discarded"]
pub struct PreparedThreadExecHandoff<'a> {
    thread: &'a mut ThreadTranslator,
    next: Arc<ProcessTranslator>,
    next_exec_reset_epoch: u64,
}

impl PreparedThreadExecHandoff<'_> {
    /// Commit the already checked replacement. This API is deliberately
    /// Result-free: all recoverable validation happened in preparation.
    pub fn commit(self) {
        self.commit_with_sink(|frames| {
            let _ = profile::write_protocol_frames_to_fd(libc::STDERR_FILENO, frames);
        });
    }

    #[doc(hidden)]
    pub fn commit_with_sink(self, mut sink: impl FnMut(&[String])) {
        let Self {
            thread,
            next,
            next_exec_reset_epoch,
        } = self;
        if let Some(frames) = thread.take_profile_frames() {
            sink(&frames);
        }
        thread.process = next;
        thread.block_cache.clear();
        thread.exec_reset_epoch = next_exec_reset_epoch;
        thread.start_next_profile_epoch();
        thread.last_kick = None;
        thread.indirect_cache.clear();
        let (used_bytes, block_count, generation_count) = thread.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            thread.tid,
            probes::DsrCacheLifecyclePhase::ExecTranslatorHandoffEnd,
            used_bytes,
            block_count,
            generation_count,
        );
        probes::dsr_cache_lifecycle(
            thread.tid,
            probes::DsrCacheLifecyclePhase::ExecResetEnd,
            used_bytes,
            block_count,
            generation_count,
        );
    }
}

/// One process's published JIT code plus its guest-to-cache block index,
/// copied out for offline diagnostics (see `ProcessTranslator::code_snapshot`).
#[derive(Debug)]
pub struct CodeSnapshot {
    pub cache_base: u64,
    pub code: Vec<u8>,
    /// `(guest_va, cache_entry_host_va)` for every published private block.
    pub blocks: Vec<(u64, u64)>,
    pub trusted_routes: Vec<TrustedRouteSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TrustedRouteSnapshot {
    pub guest_start: u64,
    pub generation: u64,
    pub origin: TrustedRouteOrigin,
    pub fallthrough: std::ops::Range<u64>,
    pub direct: std::ops::Range<u64>,
    pub indirect: std::ops::Range<u64>,
    pub fallthrough_branch: u64,
    pub direct_branch: u64,
    pub indirect_branch: u64,
    pub common_body: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustedRouteOrigin {
    Owned,
    UnitReplay,
}

pub struct ProcessTranslator {
    // `pub` for the runtime's still-resident test suites (see ThreadTranslator).
    pub state: RwLock<ProcessState>,
    private_target_authority: Box<gateway::TargetCacheAuthority>,
    private_jit_epoch: Arc<crate::direct_binding::PrivateJitEpoch>,
    exec_reset_identity: Arc<DirectBindingExecProcessIdentity>,
}

trait TranslatedRangeRecorder {
    fn reset(&mut self, event: probes::TranslatedRangeReset);
    fn add(&mut self, event: probes::TranslatedRangeAdd);
    fn ready(&mut self, event: probes::TranslatedRangeReady);
}

trait ForkChildRepairRecorder: TranslatedRangeRecorder {
    fn process_repaired(&mut self);
}

struct DsrTranslatedRangeRecorder;

impl TranslatedRangeRecorder for DsrTranslatedRangeRecorder {
    fn reset(&mut self, event: probes::TranslatedRangeReset) {
        probes::translated_range_reset(event);
    }

    fn add(&mut self, event: probes::TranslatedRangeAdd) {
        probes::translated_range_add(event);
    }

    fn ready(&mut self, event: probes::TranslatedRangeReady) {
        probes::translated_range_ready(event);
    }
}

impl ForkChildRepairRecorder for DsrTranslatedRangeRecorder {
    fn process_repaired(&mut self) {}
}

#[derive(Debug)]
struct TranslatedRangeCatalog {
    epoch: probes::TranslatedRangeEpoch,
    next_sequence: u64,
    ready_sequence: Option<u64>,
    private: std::ops::Range<carrick_guest_mem::HostVa>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedCatalogExecReset {
    next_epoch: probes::TranslatedRangeEpoch,
}

impl TranslatedRangeCatalog {
    fn dormant(
        private: std::ops::Range<carrick_guest_mem::HostVa>,
    ) -> Result<Self, types::DsrError> {
        let mut recorder = DsrTranslatedRangeRecorder;
        Self::dormant_with_recorder(private, &mut recorder)
    }

    fn dormant_with_recorder(
        private: std::ops::Range<carrick_guest_mem::HostVa>,
        _recorder: &mut impl TranslatedRangeRecorder,
    ) -> Result<Self, types::DsrError> {
        if private.start.raw() == 0 || private.end.raw() == 0 {
            return Err(types::DsrError::CachePolicy(format!(
                "translated private range has a zero endpoint: 0x{:x}..0x{:x}",
                private.start.raw(),
                private.end.raw(),
            )));
        }
        let epoch = probes::TranslatedRangeEpoch::new(1)
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        let sequence = probes::TranslatedRangeSequence::new(1)
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        probes::TranslatedPrivateRange::private(epoch, sequence, private.clone())
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        Ok(Self {
            epoch,
            next_sequence: sequence.get(),
            ready_sequence: None,
            private,
        })
    }

    fn activate_if_dormant(&mut self) -> Result<(), types::DsrError> {
        let mut recorder = DsrTranslatedRangeRecorder;
        self.activate_if_dormant_with_recorder(&mut recorder)
    }

    fn activate_if_dormant_with_recorder(
        &mut self,
        recorder: &mut impl TranslatedRangeRecorder,
    ) -> Result<(), types::DsrError> {
        if self.ready_sequence.is_some() {
            return Ok(());
        }
        let sequence = probes::TranslatedRangeSequence::new(self.next_sequence)
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        let private =
            probes::TranslatedPrivateRange::private(self.epoch, sequence, self.private.clone())
                .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        let final_sequence = sequence.get();
        let next_sequence = final_sequence.checked_add(1).ok_or_else(|| {
            types::DsrError::CachePolicy(
                "translated-range sequence overflow during initial activation".to_string(),
            )
        })?;
        let reset = probes::TranslatedRangeReset::reset(self.epoch);
        let ready = probes::TranslatedRangeReady::ready(self.epoch, final_sequence);

        recorder.reset(reset);
        recorder.add(probes::TranslatedRangeAdd::Private(private));
        recorder.ready(ready);
        self.next_sequence = next_sequence;
        self.ready_sequence = Some(final_sequence);
        Ok(())
    }

    fn replay_after_fork(
        &mut self,
        recorder: &mut impl TranslatedRangeRecorder,
    ) -> Result<(), types::DsrError> {
        let inherited_ready = self.ready_sequence.ok_or_else(|| {
            types::DsrError::CachePolicy(
                "cannot replay a dormant translated-range catalog after fork".to_string(),
            )
        })?;
        let epoch_value = self.epoch.get().checked_add(1).ok_or_else(|| {
            types::DsrError::CachePolicy(
                "translated-range epoch overflow during fork replay".to_string(),
            )
        })?;
        let epoch = probes::TranslatedRangeEpoch::new(epoch_value)
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        let private_sequence = probes::TranslatedRangeSequence::new(1)
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        let private =
            probes::TranslatedPrivateRange::private(epoch, private_sequence, self.private.clone())
                .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;

        let expected_sequence = 2_u64;
        if expected_sequence != self.next_sequence {
            return Err(types::DsrError::CachePolicy(
                "translated-range sequence frontier is inconsistent during fork replay".to_string(),
            ));
        }
        let frontier = self.next_sequence.checked_sub(1).ok_or_else(|| {
            types::DsrError::CachePolicy(
                "translated-range sequence frontier underflow during fork replay".to_string(),
            )
        })?;
        if inherited_ready == 0 || inherited_ready > frontier {
            return Err(types::DsrError::CachePolicy(format!(
                "translated-range ready sequence {inherited_ready} is outside inherited \
                 frontier 1..={frontier} during fork replay"
            )));
        }
        let reset = probes::TranslatedRangeReset::reset(epoch);
        let ready = probes::TranslatedRangeReady::ready(epoch, frontier);

        recorder.reset(reset);
        recorder.add(probes::TranslatedRangeAdd::Private(private));
        recorder.ready(ready);
        self.epoch = epoch;
        self.ready_sequence = Some(frontier);
        Ok(())
    }

    fn prepare_dormant_for_exec(&self) -> Result<PreparedCatalogExecReset, types::DsrError> {
        if self.ready_sequence.is_none() {
            return Err(types::DsrError::CachePolicy(
                "cannot reset a dormant translated-range catalog for exec".to_string(),
            ));
        }
        let next_epoch = self.epoch.get().checked_add(1).ok_or_else(|| {
            types::DsrError::CachePolicy(
                "translated-range epoch overflow during exec reset".to_string(),
            )
        })?;
        Ok(PreparedCatalogExecReset {
            next_epoch: probes::TranslatedRangeEpoch::new(next_epoch)
                .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?,
        })
    }

    fn commit_dormant_for_exec(&mut self, prepared: PreparedCatalogExecReset) {
        self.epoch = prepared.next_epoch;
        self.next_sequence = 1;
        self.ready_sequence = None;
    }
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
    translated_ranges: TranslatedRangeCatalog,
    pub artifact_store: Option<artifact_spike::ArtifactStore>,
    pub blocks: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::CacheVa>,
    pub pending:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), Vec<cache::LinkSite>>,
    /// Reverse of every PRIVATE direct link `patch_direct_link_if_reachable`
    /// installs: target guest 4 KiB page -> patched slots. Severed eagerly
    /// when a guest code write bumps a page generation, restoring the
    /// unpatched `b +1` fall-into-stub word so the next traversal resolves
    /// through the gateway. Net-new state: link metadata was previously
    /// dropped at publication (Phase 2 audit,
    /// docs/superpowers/specs/2026-08-01-steady-state-block-boundary-tax-design.md).
    pub direct_link_incoming: BTreeMap<u64, Vec<cache::LinkSite>>,
    /// Trusted second entry points of PRIVATE blocks, keyed like `blocks`.
    /// Patched direct links target `entry + offset`, skipping the generation
    /// guard the link's existence (plus Phase 2a severing) makes redundant.
    pub trusted_entries:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::CacheOffset>,
    pub trusted_route_entries:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), TrustedRouteEntries>,
    pub stats: ResolverStats,
    pub reported_stats: ResolverStats,
    pub sensitive: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), SensitiveMetadata>,
    pub exclusive_fusion_sites: [BTreeSet<(u64, u32)>; profile::ExclusiveFusionClass::COUNT],
    pub unsupported:
        BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), (u32, bad64::Op)>,
    pub published: Vec<PublishedBlock>,
    /// `published` indices ascending by cache entry address. Installed unit
    /// blocks replay into the same bump-allocated cache as native
    /// translations, so one index covers every published block.
    private_published_index: Vec<PublishedIndexEntry>,
    pub dependencies: cache::PageBlockDependencies,
    pub profiling: bool,
    artifact_image_digest: Option<[u8; 32]>,
    shared_translation: Option<SharedTranslationConfiguration>,
    shared_unit_segments_consulted: BTreeSet<carrick_guest_mem::GuestVa>,
    shared_recording_segments: BTreeSet<carrick_guest_mem::GuestVa>,
    /// Units this process attached from the store, blocks NOT yet replayed.
    /// A block is replayed into the private cache on its FIRST lookup
    /// (`replay_attached_unit_block`), so an exec that touches a fraction of
    /// a unit never pays for the rest. Each unit pins its `.code` mapping
    /// (and, for the store path, its metadata mapping) for the process
    /// lifetime; fork children inherit both by COW and keep replaying.
    attached_units: Vec<crate::shared_cache::SharedLoadedTranslationUnit>,
    /// Guest block start -> (unit, block) for every not-yet-replayed block of
    /// every attached unit. An entry is removed when its block replays (the
    /// block index in `blocks` then owns the lookup), when its page
    /// regenerates, or when its unit is detached after a replay refusal.
    attached_unit_blocks: BTreeMap<carrick_guest_mem::GuestVa, AttachedUnitBlock>,
    shared_candidates:
        BTreeMap<carrick_guest_mem::GuestVa, Vec<crate::shared_cache::PortableBlockCandidate>>,
    shared_publish_attempted: bool,
    executable_ranges: gateway::ExecutableRangeCatalog,
    /// Guest blocks one emitted block may fuse (1 = no superblock formation).
    /// Resolved once from `block::superblock_segment_limit()`; the only site
    /// that reads the switch, so planner and emitter tests stay deterministic.
    superblock_segments: usize,
    trusted_route_split: emit::TrustedRouteSplit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedRouteEntries {
    pub fallthrough: types::CacheVa,
    pub direct: types::CacheVa,
    pub indirect: types::CacheVa,
    pub sequence_bytes: u32,
    pub common_body: types::CacheVa,
}

struct SharedTranslationConfiguration {
    image: crate::shared_cache::SharedImageConfig,
    store: Arc<dyn crate::shared_cache::TranslationUnitStore>,
}

/// One not-yet-replayed block of an attached unit: indices into
/// `ProcessState::attached_units` and that unit's manifest block table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AttachedUnitBlock {
    unit: u32,
    block: u32,
}

/// What one `replay_attached_unit_block` call did, so the LOOKUP path can
/// census each lookup exactly once (a fresh consult is already counted as
/// `consulted`/`loaded`; only a store-bypassing repeat records its outcome).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttachedReplayOutcome {
    /// The block replayed and published; the lookup is served.
    Replayed(types::CacheVa),
    /// No attached unit covers this guest VA (never recorded by a unit, or
    /// its entry was dropped by an earlier per-block failure).
    NotCovered,
    /// The page regenerated; no INITIAL-keyed entry can serve it again.
    Regenerated,
    /// The private cache is out of room; translate privately instead.
    Capacity,
    /// Replay validation refused the unit's bytes; the unit is detached.
    Refused,
}

const fn translation_source_words_required(
    artifact_store_present: bool,
    shared_translation_configured: bool,
) -> bool {
    artifact_store_present || shared_translation_configured
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensitiveMetadata {
    pub exit: types::SensitiveExit,
    pub fusion: Option<types::ExclusiveFusionSite>,
}

fn merge_sensitive_metadata(
    key: (carrick_guest_mem::GuestVa, types::CodeGeneration),
    current: SensitiveMetadata,
    incoming: SensitiveMetadata,
) -> Result<SensitiveMetadata, types::DsrError> {
    if current.exit != incoming.exit {
        return Err(types::DsrError::CachePolicy(format!(
            "shared sensitive exit conflicts at guest 0x{:x}",
            key.0.raw()
        )));
    }
    Ok(SensitiveMetadata {
        exit: current.exit,
        fusion: if current.fusion == incoming.fusion {
            current.fusion
        } else {
            None
        },
    })
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
    metadata: PublishedBlockMetadata,
    pub _generation: cache::PageGenerationObservation,
}

/// Where a published block's fault-reconstruction metadata (pc map and
/// recovery) lives. Faults are rare; replay is not — so a unit-replayed
/// block leaves this metadata UNDECODED in the unit's mapped cold stream
/// instead of materializing ~98% of the unit's records per exec.
pub enum PublishedBlockMetadata {
    /// Built by this process (native translation or private artifact
    /// replay): owned outright.
    Owned {
        map: Vec<emit::PcMapEntry>,
        recovery: Vec<emit::RecoveryEntry>,
    },
    /// Replayed from an attached unit: decode the block's cold blob on
    /// demand. `bindings` are the replay-time bindings, so a fault-time
    /// recovery rebind produces exactly what an eager replay would have.
    Unit {
        manifest: Arc<crate::shared_cache::TranslationUnitManifest>,
        block: u32,
        bindings: artifact_spike::ArtifactBindings,
    },
}

impl PublishedBlockMetadata {
    /// Materialize the block's pc map and rebound recovery entries — owned
    /// directly, or decoded from the unit's cold stream. Test-support
    /// sweeps use this; the fault path (`guest_pc_for_cache`) searches the
    /// decoded stream directly instead so it rebinds only the entry it
    /// found.
    fn materialize(
        &self,
    ) -> Result<(Vec<emit::PcMapEntry>, Vec<emit::RecoveryEntry>), types::DsrError> {
        match self {
            Self::Owned { map, recovery } => Ok((map.clone(), recovery.clone())),
            Self::Unit {
                manifest,
                block,
                bindings,
            } => {
                let cold = manifest.block_cold(*block as usize).map_err(|reason| {
                    types::DsrError::CachePolicy(format!(
                        "unit cold metadata refused at materialize: {reason:?}"
                    ))
                })?;
                let recovery = cold
                    .recovery
                    .into_entries()?
                    .into_iter()
                    .map(|entry| {
                        Ok(emit::RecoveryEntry {
                            cache: entry.cache(),
                            action: entry.action().rebind(bindings)?,
                        })
                    })
                    .collect::<Result<Vec<_>, types::DsrError>>()?;
                Ok((cold.map, recovery))
            }
        }
    }
}
/// One entry of an address-ordered index over [`ProcessState::published`]:
/// where a block's emitted code starts, and where the block itself sits in
/// publication order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    /// Blocks REPLAYED from attached units (on first lookup), not blocks
    /// made available — that is `shared_blocks_attached`. The gap between
    /// the two is exactly the replay work lazy install avoided.
    pub shared_blocks_mapped: u64,
    pub shared_translations_avoided: u64,
    /// Blocks indexed at unit attach, available for lazy replay.
    pub shared_blocks_attached: u64,
    pub shared_metadata_bytes_read: u64,
    pub shared_metadata_bytes_mapped: u64,
    pub shared_metadata_validation_ns: u64,
    pub shared_mapped_immutable_records: u64,
    pub shared_owned_immutable_records: u64,
    pub shared_guest_range_derivations: u64,
    pub shared_direct_edge_group_builds: u64,
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
    SharedBlocksAttached,
    SharedMetadataBytesRead,
    SharedMetadataBytesMapped,
    SharedMetadataValidationNs,
    SharedMappedImmutableRecords,
    SharedOwnedImmutableRecords,
    SharedGuestRangeDerivations,
    SharedDirectEdgeGroupBuilds,
    ResolveSrcSharedTgtShared,
    ResolveSrcSharedTgtPrivate,
    ResolveSrcPrivateTgtShared,
    ResolveSrcPrivateTgtPrivate,
}

impl ResolverStat {
    const ALL: [Self; 32] = [
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
        Self::SharedBlocksAttached,
        Self::SharedMetadataBytesRead,
        Self::SharedMetadataBytesMapped,
        Self::SharedMetadataValidationNs,
        Self::SharedMappedImmutableRecords,
        Self::SharedOwnedImmutableRecords,
        Self::SharedGuestRangeDerivations,
        Self::SharedDirectEdgeGroupBuilds,
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
            Self::SharedBlocksAttached => "shared_blocks_attached",
            Self::SharedMetadataBytesRead => "shared_metadata_bytes_read",
            Self::SharedMetadataBytesMapped => "shared_metadata_bytes_mapped",
            Self::SharedMetadataValidationNs => "shared_metadata_validation_ns",
            Self::SharedMappedImmutableRecords => "shared_mapped_immutable_records",
            Self::SharedOwnedImmutableRecords => "shared_owned_immutable_records",
            Self::SharedGuestRangeDerivations => "shared_guest_range_derivations",
            Self::SharedDirectEdgeGroupBuilds => "shared_direct_edge_group_builds",
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
            ResolverStat::SharedBlocksAttached => self.shared_blocks_attached,
            ResolverStat::SharedMetadataBytesRead => self.shared_metadata_bytes_read,
            ResolverStat::SharedMetadataBytesMapped => self.shared_metadata_bytes_mapped,
            ResolverStat::SharedMetadataValidationNs => self.shared_metadata_validation_ns,
            ResolverStat::SharedMappedImmutableRecords => self.shared_mapped_immutable_records,
            ResolverStat::SharedOwnedImmutableRecords => self.shared_owned_immutable_records,
            ResolverStat::SharedGuestRangeDerivations => self.shared_guest_range_derivations,
            ResolverStat::SharedDirectEdgeGroupBuilds => self.shared_direct_edge_group_builds,
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
            ResolverStat::SharedBlocksAttached => self.shared_blocks_attached = value,
            ResolverStat::SharedMetadataBytesRead => self.shared_metadata_bytes_read = value,
            ResolverStat::SharedMetadataBytesMapped => self.shared_metadata_bytes_mapped = value,
            ResolverStat::SharedMetadataValidationNs => self.shared_metadata_validation_ns = value,
            ResolverStat::SharedMappedImmutableRecords => {
                self.shared_mapped_immutable_records = value
            }
            ResolverStat::SharedOwnedImmutableRecords => {
                self.shared_owned_immutable_records = value
            }
            ResolverStat::SharedGuestRangeDerivations => {
                self.shared_guest_range_derivations = value
            }
            ResolverStat::SharedDirectEdgeGroupBuilds => {
                self.shared_direct_edge_group_builds = value
            }
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

    fn saturating_add(&mut self, stat: ResolverStat, value: u64) {
        self.set(stat, self.get(stat).saturating_add(value));
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
    /// Preserve the typed read failure while naming both the control-flow
    /// boundary that supplied its would-be guest PC and whether that value is
    /// actually a host JIT-cache address. Translation failures are cold, so
    /// the range lookup and formatting happen only after a read has failed;
    /// the production translation fast path pays no extra work.
    fn with_memory_read_origin(
        &self,
        error: types::DsrError,
        origin: impl FnOnce() -> String,
    ) -> types::DsrError {
        match error {
            types::DsrError::MemoryRead { pc, detail } => {
                let cache_range = self.process.cache_host_range();
                let cache_contains = cache_range.contains(&pc);
                let cache_reverse = if cache_contains {
                    match self.guest_pc_for_cache(carrick_guest_mem::GuestVa(pc)) {
                        Ok((guest, recovery)) => {
                            format!("guest=0x{:x} recovery={recovery:?}", guest.raw())
                        }
                        Err(error) => format!("error={error}"),
                    }
                } else {
                    "not-attempted".to_string()
                };
                types::DsrError::MemoryRead {
                    pc,
                    detail: format!(
                        "{detail}; translation-origin={}; cache-range=0x{:x}..0x{:x}; \
                         cache-contains={cache_contains}; cache-reverse={cache_reverse}",
                        origin(),
                        cache_range.start,
                        cache_range.end,
                    ),
                }
            }
            other => other,
        }
    }

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

    /// Construct every initial thread-owned object before the selected
    /// process publishes its translated-range identity.
    pub fn prepare_for_process(process: Arc<ProcessTranslator>, tid: i32) -> PreparedThreadInstall {
        PreparedThreadInstall {
            thread: Self::for_process(process, tid),
        }
    }

    pub fn after_fork_child(&mut self, tid: i32) -> Result<(), types::DsrError> {
        let mut recorder = DsrTranslatedRangeRecorder;
        self.after_fork_child_inner(tid, &mut recorder, &mut |_| {})
    }

    #[cfg(test)]
    fn after_fork_child_with_recorders(
        &mut self,
        tid: i32,
        recorder: &mut impl ForkChildRepairRecorder,
        lifecycle: &mut impl FnMut(probes::DsrCacheLifecyclePhase),
    ) -> Result<(), types::DsrError> {
        self.after_fork_child_inner(tid, recorder, lifecycle)
    }

    fn after_fork_child_inner(
        &mut self,
        tid: i32,
        recorder: &mut impl ForkChildRepairRecorder,
        lifecycle: &mut impl FnMut(probes::DsrCacheLifecyclePhase),
    ) -> Result<(), types::DsrError> {
        let next_exec_reset_epoch = self.next_exec_reset_epoch()?;
        self.tid = tid;
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        lifecycle(probes::DsrCacheLifecyclePhase::ForkChildRepairBegin);
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ForkChildRepairBegin,
            used_bytes,
            block_count,
            generation_count,
        );
        self.process.after_fork_child_inner(recorder)?;
        self.block_cache.clear();
        self.exec_reset_epoch = next_exec_reset_epoch;
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
        lifecycle(probes::DsrCacheLifecyclePhase::ForkChildRepairEnd);
        Ok(())
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
    pub fn prepare_direct_binding_exec_reset(
        &mut self,
    ) -> Result<DirectBindingExecResetToken, types::DsrError> {
        let next_exec_reset_epoch = self.next_exec_reset_epoch_for_prepared_exec()?;
        self.block_cache.clear();
        self.indirect_cache.clear();
        self.exec_reset_epoch = next_exec_reset_epoch;
        Ok(DirectBindingExecResetToken {
            process_identity: Arc::clone(&self.process.exec_reset_identity),
            thread_identity: Arc::clone(&self.exec_reset_identity),
            thread_epoch: self.exec_reset_epoch,
            consumed: false,
        })
    }

    pub fn prepare_reset_for_exec(
        &mut self,
        next: Arc<ProcessTranslator>,
    ) -> Result<PreparedThreadExecHandoff<'_>, types::DsrError> {
        let next_exec_reset_epoch = self.next_exec_reset_epoch()?;
        Ok(PreparedThreadExecHandoff {
            thread: self,
            next,
            next_exec_reset_epoch,
        })
    }

    pub fn reset_for_exec(&mut self, next: Arc<ProcessTranslator>) -> Result<(), types::DsrError> {
        self.prepare_reset_for_exec(next)?.commit();
        Ok(())
    }

    #[doc(hidden)]
    pub fn reset_for_exec_with_sink(
        &mut self,
        next: Arc<ProcessTranslator>,
        sink: impl FnMut(&[String]),
    ) -> Result<(), types::DsrError> {
        self.prepare_reset_for_exec(next)?.commit_with_sink(sink);
        Ok(())
    }

    fn next_exec_reset_epoch(&self) -> Result<u64, types::DsrError> {
        self.exec_reset_epoch.checked_add(1).ok_or_else(|| {
            types::DsrError::CachePolicy(
                "thread exec-reset authority generation overflow".to_string(),
            )
        })
    }

    fn next_exec_reset_epoch_for_prepared_exec(&self) -> Result<u64, types::DsrError> {
        let prepared_epoch = self.next_exec_reset_epoch()?;
        prepared_epoch.checked_add(1).ok_or_else(|| {
            types::DsrError::CachePolicy(
                "thread exec-reset authority cannot reserve replacement handoff generation"
                    .to_string(),
            )
        })?;
        Ok(prepared_epoch)
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
            direct_binding_owner_validation_failures: 0,
            direct_binding_authority_validation_failures: 0,
            direct_binding_cas_wins: 0,
            direct_binding_cas_losses: 0,
            direct_binding_stale_winner_clears: 0,
            direct_binding_publication_retries: 0,
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
            shared_blocks_attached: process.stats.shared_blocks_attached,
            shared_metadata_bytes_read: process.stats.shared_metadata_bytes_read,
            shared_metadata_bytes_mapped: process.stats.shared_metadata_bytes_mapped,
            shared_metadata_validation_ns: process.stats.shared_metadata_validation_ns,
            shared_mapped_immutable_records: process.stats.shared_mapped_immutable_records,
            shared_owned_immutable_records: process.stats.shared_owned_immutable_records,
            shared_guest_range_derivations: process.stats.shared_guest_range_derivations,
            shared_direct_edge_group_builds: process.stats.shared_direct_edge_group_builds,
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
            direct_binding_owner_validation_failures: 0,
            direct_binding_authority_validation_failures: 0,
            direct_binding_cas_wins: 0,
            direct_binding_cas_losses: 0,
            direct_binding_stale_winner_clears: 0,
            direct_binding_publication_retries: 0,
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
            shared_blocks_attached: delta.shared_blocks_attached,
            shared_metadata_bytes_read: delta.shared_metadata_bytes_read,
            shared_metadata_bytes_mapped: delta.shared_metadata_bytes_mapped,
            shared_metadata_validation_ns: delta.shared_metadata_validation_ns,
            shared_mapped_immutable_records: delta.shared_mapped_immutable_records,
            shared_owned_immutable_records: delta.shared_owned_immutable_records,
            shared_guest_range_derivations: delta.shared_guest_range_derivations,
            shared_direct_edge_group_builds: delta.shared_direct_edge_group_builds,
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
            direct_binding_owner_validation_failures: 0,
            direct_binding_authority_validation_failures: 0,
            direct_binding_cas_wins: 0,
            direct_binding_cas_losses: 0,
            direct_binding_stale_winner_clears: 0,
            direct_binding_publication_retries: 0,
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
            shared_blocks_attached: 0,
            shared_metadata_bytes_read: 0,
            shared_metadata_bytes_mapped: 0,
            shared_metadata_validation_ns: 0,
            shared_mapped_immutable_records: 0,
            shared_owned_immutable_records: 0,
            shared_guest_range_derivations: 0,
            shared_direct_edge_group_builds: 0,
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
        Self::new_with_host_and_route_split(capacity, host, emit::trusted_route_split_enabled())
    }

    fn new_with_host_and_route_split(
        capacity: usize,
        host: &'static dyn NativeHostJit,
        trusted_route_split: emit::TrustedRouteSplit,
    ) -> Result<Self, types::DsrError> {
        artifact_spike::ensure_authority_if_enabled()?;
        let cache = cache::TranslationCache::new(capacity, host)?;
        let cache_range = cache.host_range();
        let translated_ranges = TranslatedRangeCatalog::dormant(
            carrick_guest_mem::HostVa(cache_range.start)
                ..carrick_guest_mem::HostVa(cache_range.end),
        )?;
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
                translated_ranges,
                artifact_store: artifact_spike::store_if_enabled()?,
                blocks: BTreeMap::new(),
                pending: BTreeMap::new(),
                direct_link_incoming: BTreeMap::new(),
                trusted_entries: BTreeMap::new(),
                trusted_route_entries: BTreeMap::new(),
                stats: ResolverStats::default(),
                reported_stats: ResolverStats::default(),
                sensitive: BTreeMap::new(),
                exclusive_fusion_sites: std::array::from_fn(|_| BTreeSet::new()),
                unsupported: BTreeMap::new(),
                published: Vec::new(),
                private_published_index: Vec::new(),
                dependencies: cache::PageBlockDependencies::default(),
                profiling: std::env::var_os("CARRICK_DSR_PROFILE").is_some(),
                artifact_image_digest: None,
                shared_translation: None,
                shared_unit_segments_consulted: BTreeSet::new(),
                shared_recording_segments: BTreeSet::new(),
                attached_units: Vec::new(),
                attached_unit_blocks: BTreeMap::new(),
                shared_candidates: BTreeMap::new(),
                shared_publish_attempted: false,
                executable_ranges: gateway::ExecutableRangeCatalog::new(
                    cache_range.start,
                    cache_range.end,
                )?,
                superblock_segments: block::superblock_segment_limit(),
                trusted_route_split,
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

    pub fn activate_translated_range_catalog(&self) -> Result<(), types::DsrError> {
        self.state.write().translated_ranges.activate_if_dormant()
    }

    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn set_translated_range_epoch_for_test(&self, epoch: u64) -> Result<(), types::DsrError> {
        self.state.write().translated_ranges.epoch = probes::TranslatedRangeEpoch::new(epoch)
            .map_err(|error| types::DsrError::CachePolicy(error.to_string()))?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn translated_range_catalog_state_for_test(&self) -> (u64, u64, Option<u64>) {
        let state = self.state.read();
        let catalog = &state.translated_ranges;
        (
            catalog.epoch.get(),
            catalog.next_sequence.saturating_sub(1),
            catalog.ready_sequence,
        )
    }

    #[cfg(test)]
    fn activate_translated_range_catalog_with_recorder(
        &self,
        recorder: &mut impl TranslatedRangeRecorder,
    ) -> Result<(), types::DsrError> {
        self.state
            .write()
            .translated_ranges
            .activate_if_dormant_with_recorder(recorder)
    }

    /// Sever recorded private direct links into `range`; see
    /// `ProcessState::sever_direct_links_in` (private).
    pub fn sever_direct_links_in(
        &self,
        range: std::ops::Range<carrick_guest_mem::GuestVa>,
    ) -> Result<usize, types::DsrError> {
        self.state.write().sever_direct_links_in(range)
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
    pub fn code_snapshot(&self) -> Result<CodeSnapshot, types::DsrError> {
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
        if !code.len().is_multiple_of(4) {
            return Err(types::DsrError::CachePolicy(format!(
                "code snapshot length {} is not instruction aligned",
                code.len()
            )));
        }
        let words = code
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect::<Vec<_>>();
        let cache_base = range.start as u64;
        let mut trusted_routes = Vec::with_capacity(state.trusted_route_entries.len());
        for (&(guest, generation), routes) in &state.trusted_route_entries {
            let entry = state.blocks.get(&(guest, generation)).ok_or_else(|| {
                types::DsrError::CachePolicy(format!(
                    "trusted route for guest 0x{:x} generation {} has no block",
                    guest.raw(),
                    generation.get()
                ))
            })?;
            let published = state
                .published_block_containing(entry.host().raw())
                .filter(|published| published.entry == *entry)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "trusted route for guest 0x{:x} generation {} has no published metadata",
                        guest.raw(),
                        generation.get()
                    ))
                })?;
            let origin = match &published.metadata {
                PublishedBlockMetadata::Owned { .. } => TrustedRouteOrigin::Owned,
                PublishedBlockMetadata::Unit { .. } => TrustedRouteOrigin::UnitReplay,
            };
            let relative = |address: types::CacheVa, name: &str| {
                let address = address.host().raw() as u64;
                let offset = address.checked_sub(cache_base).ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "trusted {name} route address 0x{address:x} precedes cache"
                    ))
                })?;
                u32::try_from(offset).map_err(|_| {
                    types::DsrError::CachePolicy(format!(
                        "trusted {name} route offset {offset} exceeds u32"
                    ))
                })
            };
            let fallthrough = relative(routes.fallthrough, "fallthrough")?;
            let derived = emit::derive_trusted_route_offsets(
                &words,
                fallthrough,
                generation,
                emit::TrustedRouteSplit::Enabled,
            )?
            .ok_or_else(|| {
                types::DsrError::CachePolicy("trusted route derivation was disabled".to_string())
            })?;
            let expected = TrustedRouteEntries {
                fallthrough: types::CacheVa::published(carrick_guest_mem::HostVa(
                    range.start + derived.fallthrough.get() as usize,
                )),
                direct: types::CacheVa::published(carrick_guest_mem::HostVa(
                    range.start + derived.direct.get() as usize,
                )),
                indirect: types::CacheVa::published(carrick_guest_mem::HostVa(
                    range.start + derived.indirect.get() as usize,
                )),
                sequence_bytes: derived.sequence_bytes,
                common_body: types::CacheVa::published(carrick_guest_mem::HostVa(
                    range.start + derived.common_body.get() as usize,
                )),
            };
            if *routes != expected {
                return Err(types::DsrError::CachePolicy(format!(
                    "trusted route geometry mismatch for guest 0x{:x} generation {}",
                    guest.raw(),
                    generation.get()
                )));
            }
            let sequence_bytes = u64::from(routes.sequence_bytes);
            let span = |start: types::CacheVa| -> Result<std::ops::Range<u64>, types::DsrError> {
                let start = start.host().raw() as u64;
                let end = start.checked_add(sequence_bytes).ok_or_else(|| {
                    types::DsrError::CachePolicy("trusted route span overflow".to_string())
                })?;
                Ok(start..end)
            };
            let fallthrough = span(routes.fallthrough)?;
            let direct = span(routes.direct)?;
            let indirect = span(routes.indirect)?;
            trusted_routes.push(TrustedRouteSnapshot {
                guest_start: guest.raw(),
                generation: generation.get(),
                origin,
                fallthrough_branch: fallthrough.end,
                direct_branch: direct.end,
                indirect_branch: indirect.end,
                fallthrough,
                direct,
                indirect,
                common_body: routes.common_body.host().raw() as u64,
            });
        }
        trusted_routes.sort_by_key(|route| route.fallthrough.start);
        for pair in trusted_routes.windows(2) {
            if pair[0].indirect_branch >= pair[1].fallthrough.start {
                return Err(types::DsrError::CachePolicy(format!(
                    "trusted route spans overlap between guest 0x{:x} and 0x{:x}",
                    pair[0].guest_start, pair[1].guest_start
                )));
            }
        }
        Ok(CodeSnapshot {
            cache_base: range.start as u64,
            code,
            blocks,
            trusted_routes,
        })
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
            )?;
            let publish_started = std::time::Instant::now();
            let publish_result = store.publish(&pending);
            xlat_census::record_publish_ns(publish_started.elapsed().as_nanos() as u64);
            let outcome = publish_result.map_err(|reason| {
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

    #[doc(hidden)]
    pub fn lifecycle_snapshot(&self) -> (u64, u64, u64) {
        let state = self.state.read();
        (
            u64::try_from(state.cache.used_bytes()).unwrap_or(u64::MAX),
            u64::try_from(state.blocks.len()).unwrap_or(u64::MAX),
            u64::try_from(state.dependencies.page_count()).unwrap_or(u64::MAX),
        )
    }

    pub fn after_fork_child(
        &self,
    ) -> Result<crate::direct_binding::ForkBindingClearStats, types::DsrError> {
        let mut recorder = DsrTranslatedRangeRecorder;
        self.after_fork_child_inner(&mut recorder)
    }
    fn after_fork_child_inner(
        &self,
        recorder: &mut impl ForkChildRepairRecorder,
    ) -> Result<crate::direct_binding::ForkBindingClearStats, types::DsrError> {
        let mut state = self.state.write();
        let direct_binding_stats = crate::direct_binding::ForkBindingClearStats::default();
        state.cache.after_fork_child();
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        // The recording claim is the PARENT's: the store's builder election
        // names the parent pid, and the parent publishes its own candidate
        // batch at its exit or exec. A child that keeps the COW-inherited
        // claim and batch republishes the same unit at its own exec — the
        // "concurrent publishers" term the 2026-08-03 scoreboard correction
        // measured at +6.4 ms per exec across a parallel go build.
        state.shared_recording_segments.clear();
        state.shared_candidates.clear();
        // The child inherited the parent's census by COW along with the warm
        // block index, but it performed none of those translations. Leaving
        // them would re-attribute the parent's whole set to every child once
        // fork children started flushing (they die at `libc::_exit`, so they
        // never used to write a file at all).
        xlat_census::reset_after_fork();
        recorder.process_repaired();
        state.translated_ranges.replay_after_fork(recorder)?;
        let capacity = u64::try_from(state.cache.capacity_bytes()).unwrap_or(u64::MAX);
        drop(state);
        probes::dsr_cache_capacity(probes::DsrCacheRole::Child, capacity);
        Ok(direct_binding_stats)
    }

    pub fn reset_after_fork_for_exec(
        &self,
        thread: &ThreadTranslator,
        token: &mut DirectBindingExecResetToken,
    ) -> Result<crate::direct_binding::ExecBindingClearStats, types::DsrError> {
        Ok(self
            .prepare_reset_after_fork_for_exec(thread, token, false)?
            .commit())
    }
    /// Preflights the complete retiring-translator reset while the old image
    /// remains authoritative. No logical process state or token is mutated.
    pub fn prepare_reset_after_fork_for_exec<'process, 'thread, 'token>(
        &'process self,
        thread: &'thread ThreadTranslator,
        token: &'token mut DirectBindingExecResetToken,
        reset_translated_catalog: bool,
    ) -> Result<PreparedDirectBindingExecReset<'process, 'thread, 'token>, types::DsrError> {
        let state = self.state.write();
        let token = token.prepare_consumption(self, thread)?;
        let live_private_leases =
            crate::direct_binding::PrivateJitEpoch::live_descriptor_leases(&self.private_jit_epoch);
        if live_private_leases != 0 {
            return Err(types::DsrError::CachePolicy(format!(
                "private JIT descriptor lease ownership mismatch: {live_private_leases} live, \
                 but no holder can retain an epoch lease"
            )));
        }
        let catalog = reset_translated_catalog
            .then(|| state.translated_ranges.prepare_dormant_for_exec())
            .transpose()?;
        Ok(PreparedDirectBindingExecReset {
            state,
            thread,
            token,
            catalog,
        })
    }

    #[cfg(test)]
    pub fn private_epoch_leases_for_test(&self) -> usize {
        crate::direct_binding::PrivateJitEpoch::live_descriptor_leases(&self.private_jit_epoch)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn private_jit_epoch_lease_for_test(&self) -> Arc<crate::direct_binding::PrivateJitEpoch> {
        let _state = self.state.read();
        Arc::clone(&self.private_jit_epoch)
    }
}

impl ProcessState {
    fn try_load_shared_unit(
        &mut self,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
    ) -> Result<Option<types::CacheVa>, types::DsrError> {
        // Every early return below is counted, because "the store was never
        // consulted" and "the store was consulted and missed" imply opposite
        // fixes and were previously indistinguishable. See `xlat_census`.
        if generation != types::CodeGeneration::INITIAL {
            xlat_census::record_lookup_skipped(xlat_census::LookupSkip::Regenerated);
            return Ok(None);
        }
        let Some(configuration) = &self.shared_translation else {
            xlat_census::record_lookup_skipped(xlat_census::LookupSkip::LaneUnconfigured);
            return Ok(None);
        };
        let Some(segment) = configuration.image.segments.iter().find(|segment| {
            segment
                .guest_start
                .raw()
                .checked_add(segment.guest_len.get())
                .is_some_and(|end| (segment.guest_start.raw()..end).contains(&guest.raw()))
        }) else {
            xlat_census::record_lookup_skipped(xlat_census::LookupSkip::OutsideSegment);
            return Ok(None);
        };
        let segment_start = segment.guest_start;
        if !self.shared_unit_segments_consulted.insert(segment_start) {
            // The segment's store consult already happened; the only thing a
            // repeat lookup can be served from is an ATTACHED unit's
            // not-yet-replayed block. This lookup never touches the store, so
            // it records its own census outcome — exactly one record per
            // lookup, `replayed` or a skip.
            return match self.replay_attached_unit_block(memory, guest)? {
                AttachedReplayOutcome::Replayed(entry) => {
                    xlat_census::record_lookup_replayed();
                    Ok(Some(entry))
                }
                AttachedReplayOutcome::Regenerated => {
                    xlat_census::record_lookup_skipped(xlat_census::LookupSkip::Regenerated);
                    Ok(None)
                }
                AttachedReplayOutcome::NotCovered
                | AttachedReplayOutcome::Capacity
                | AttachedReplayOutcome::Refused => {
                    xlat_census::record_lookup_skipped(xlat_census::LookupSkip::SegmentRepeat);
                    Ok(None)
                }
            };
        }
        let key = configuration.image.key_for_segment(segment);
        let source_words = Arc::clone(&segment.source_words);
        let store = Arc::clone(&configuration.store);
        self.stats.shared_unit_lookups = self.stats.shared_unit_lookups.saturating_add(1);
        let load_started = std::time::Instant::now();
        let load_result = store.load(&key, &source_words);
        xlat_census::record_load_ns(load_started.elapsed().as_nanos() as u64);
        let unit = match load_result {
            Ok(Some(unit)) => {
                xlat_census::record_lookup_loaded();
                unit
            }
            Ok(None) => {
                let claimed = store.claim_recording(&key);
                xlat_census::record_lookup_file_miss(claimed);
                if claimed {
                    self.shared_recording_segments.insert(segment_start);
                }
                return Ok(None);
            }
            Err(reason) => {
                xlat_census::record_lookup_miss(reason);
                return Ok(None);
            }
        };
        self.stats.shared_unit_loads = self.stats.shared_unit_loads.saturating_add(1);
        match self.attach_shared_unit(unit) {
            Ok(()) => {}
            // A unit the attach validators refuse (a stale store shape, bad
            // geometry) must fail closed to private translation, never kill
            // the guest that consulted the store. The warn — not silence —
            // is what keeps a store that never attaches from reading as a
            // plain miss.
            Err(types::DsrError::CachePolicy(reason)) => {
                tracing::warn!(
                    reason,
                    guest = guest.raw(),
                    "shared unit refused at attach; translating privately"
                );
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        // This lookup is already censused as a store consult (`loaded`); its
        // replay outcome must not add a second record to the per-lookup
        // census identity.
        match self.replay_attached_unit_block(memory, guest)? {
            AttachedReplayOutcome::Replayed(entry) => Ok(Some(entry)),
            AttachedReplayOutcome::NotCovered
            | AttachedReplayOutcome::Regenerated
            | AttachedReplayOutcome::Capacity
            | AttachedReplayOutcome::Refused => Ok(None),
        }
    }

    /// Attach a loaded unit for LAZY per-block replay: validate its manifest
    /// fail-closed, index every block by guest start, and pin the unit (its
    /// lease keeps the `.code` bytes mapped). No block is replayed here —
    /// `replay_attached_unit_block` replays each on its first lookup, so an
    /// exec pays replay cost only for the blocks it actually reaches.
    fn attach_shared_unit(
        &mut self,
        unit: crate::shared_cache::SharedLoadedTranslationUnit,
    ) -> Result<(), types::DsrError> {
        let metadata_load_evidence = unit.load_evidence;
        unit.manifest.validate_ranges().map_err(|reason| {
            types::DsrError::CachePolicy(format!(
                "loaded shared translation manifest is invalid: {reason:?}"
            ))
        })?;
        if usize::try_from(unit.manifest.code_len).is_err() {
            return Err(types::DsrError::CachePolicy(
                "shared translation range length does not fit usize".to_string(),
            ));
        }
        let source_base = unit.source_base;
        if source_base == 0 || !source_base.is_multiple_of(4) {
            return Err(types::DsrError::CachePolicy(format!(
                "shared translation source address is unusable: 0x{source_base:x}"
            )));
        }
        let unit_index = u32::try_from(self.attached_units.len()).map_err(|_| {
            types::DsrError::CachePolicy("attached unit count exceeds u32".to_string())
        })?;
        let mut indexed = 0_u64;
        for (block_index, block) in unit.manifest.blocks().iter().enumerate() {
            let block_index = u32::try_from(block_index).map_err(|_| {
                types::DsrError::CachePolicy("attached unit block index exceeds u32".to_string())
            })?;
            // First-attached wins: configured segments are disjoint, so a
            // collision would mean two units claim one guest VA — serving
            // the first-attached one is deterministic either way.
            self.attached_unit_blocks
                .entry(block.guest_start)
                .or_insert(AttachedUnitBlock {
                    unit: unit_index,
                    block: block_index,
                });
            indexed = indexed.saturating_add(1);
        }
        self.stats.shared_blocks_attached =
            self.stats.shared_blocks_attached.saturating_add(indexed);
        self.attached_units.push(unit);
        self.apply_shared_metadata_evidence(metadata_load_evidence);
        Ok(())
    }

    /// Replay ONE attached-unit block — the one `guest` names — through
    /// `publish_emitted`, THE publication point, so a replayed block is
    /// INDISTINGUISHABLE from a natively-translated one: Absolute guard,
    /// trusted entry registered, pending links patched, incoming links
    /// severable, page dependencies recorded.
    ///
    /// Fail-closed per block: a regenerated page or a full cache drops the
    /// block's index entry and falls back to private translation; a replay
    /// VALIDATION refusal (corrupt words, an opcode mismatch) detaches the
    /// whole unit — blocks already replayed passed validation and stay, and
    /// every remaining lookup translates privately.
    ///
    /// Census-free by design: the caller records exactly one census outcome
    /// per LOOKUP, and a fresh consult is already counted before it replays.
    fn replay_attached_unit_block(
        &mut self,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<AttachedReplayOutcome, types::DsrError> {
        let Some(&AttachedUnitBlock { unit, block }) = self.attached_unit_blocks.get(&guest) else {
            return Ok(AttachedReplayOutcome::NotCovered);
        };
        let Some(attached) = self.attached_units.get(unit as usize) else {
            return Err(types::DsrError::CachePolicy(format!(
                "attached unit index {unit} is out of bounds"
            )));
        };
        // Clone the Arc'd manifest handle and copy the scalars so the borrow
        // of `self.attached_units` ends before the `&mut self` replay calls.
        let manifest = Arc::clone(&attached.manifest);
        let source_base = attached.source_base;
        let Some(&record) = manifest.blocks().get(block as usize) else {
            return Err(types::DsrError::CachePolicy(format!(
                "attached unit block index {block} is out of bounds"
            )));
        };
        debug_assert_eq!(record.guest_start, guest);
        let code_len = usize::try_from(manifest.code_len).map_err(|_| {
            types::DsrError::CachePolicy(
                "shared translation range length does not fit usize".to_string(),
            )
        })?;
        let key = (guest, types::CodeGeneration::INITIAL);
        let observation = memory.dsr_generation_observation(guest)?;
        if observation.expected() != types::CodeGeneration::INITIAL {
            // The page regenerated after attach: no INITIAL-keyed block can
            // ever be looked up again, so the entry is dead.
            self.attached_unit_blocks.remove(&guest);
            return Ok(AttachedReplayOutcome::Regenerated);
        }
        let start = usize::try_from(record.entry_offset).map_err(|_| {
            types::DsrError::CachePolicy("shared block entry offset does not fit usize".to_string())
        })?;
        let end = start
            .checked_add(record.code_len as usize)
            .filter(|end| *end <= code_len)
            .ok_or_else(|| {
                types::DsrError::CachePolicy("shared block extent exceeds its unit".to_string())
            })?;
        // SAFETY: `TranslationUnitStore::load` contract — `source_base`
        // addresses `code_len` readable bytes pinned by the attached unit's
        // lease, held in `self.attached_units` for the process lifetime, and
        // `start..end` was bounds-checked against `code_len` just above. The
        // block's words are COPIED into the private cache by replay.
        let source = unsafe { std::slice::from_raw_parts(source_base as *const u8, code_len) };
        let words = source[start..end]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect::<Vec<_>>();
        let mode: emit::EmitAddressMode = memory.address_mode().into();
        let bindings = artifact_spike::ArtifactBindings::for_replay(
            observation.current_atomic() as *const std::sync::atomic::AtomicU64 as u64,
            types::CodeGeneration::INITIAL.get(),
            mode,
        )?;
        // Sensitive-exit metadata is not part of the template (it is
        // plan-derived), so re-plan the block to harvest it BEFORE the
        // block becomes reachable.
        if record.requires_sensitive_metadata {
            self.harvest_unit_block_sensitive_metadata(memory, guest)?;
        }
        // Decode ONLY the block's hot blob (relocations, trusted entry,
        // direct links). The cold blob (pc map + recovery, ~98% of the
        // unit's records) stays undecoded in the unit's mapped metadata;
        // publication retains a handle to it for fault-time decode.
        let replayed = manifest
            .block_hot(block as usize)
            .map_err(|reason| {
                types::DsrError::CachePolicy(format!("shared unit hot blob refused: {reason:?}"))
            })
            .and_then(|hot| {
                artifact_spike::replay_unit_block(
                    &mut self.cache,
                    words,
                    hot,
                    &bindings,
                    self.trusted_route_split,
                )
            });
        let emitted = match replayed {
            Ok(emitted) => emitted,
            // Replay validation refused the recorded bytes. The unit is
            // suspect as a whole: detach it fail-closed so no other block
            // of it can publish, and translate privately from here on.
            Err(types::DsrError::CachePolicy(reason)) => {
                tracing::warn!(
                    reason,
                    guest = guest.raw(),
                    "shared unit block refused at replay; detaching unit and \
                     translating privately"
                );
                self.attached_unit_blocks
                    .retain(|_, entry| entry.unit != unit);
                return Ok(AttachedReplayOutcome::Refused);
            }
            // A full cache means "translate privately" (which will fail the
            // same way if truly out of room), never a hard guest error.
            Err(types::DsrError::CacheCapacity { .. }) => {
                self.attached_unit_blocks.remove(&guest);
                return Ok(AttachedReplayOutcome::Capacity);
            }
            Err(error) => return Err(error),
        };
        if observation.current() != types::CodeGeneration::INITIAL {
            // The page regenerated between observation and replay: a block
            // published under the INITIAL key could never be looked up. The
            // replayed extent is unreachable; the entry is dead.
            self.attached_unit_blocks.remove(&guest);
            return Ok(AttachedReplayOutcome::Regenerated);
        }
        let emitted_bytes = u64::try_from(emitted.len()).unwrap_or(u64::MAX);
        match self.publish_emitted_with_metadata(
            memory,
            key,
            observation.page(),
            observation,
            emitted,
            emitted_bytes,
            TranslationOutcome::SharedUnit,
            Some(PublishedBlockMetadata::Unit {
                manifest: Arc::clone(&manifest),
                block,
                bindings,
            }),
        ) {
            Ok(_) => {}
            Err(types::DsrError::GenerationChanged { .. }) => {
                self.attached_unit_blocks.remove(&guest);
                return Ok(AttachedReplayOutcome::Regenerated);
            }
            Err(types::DsrError::CacheCapacity { .. }) => {
                self.attached_unit_blocks.remove(&guest);
                return Ok(AttachedReplayOutcome::Capacity);
            }
            Err(error) => return Err(error),
        }
        self.attached_unit_blocks.remove(&guest);
        self.stats.shared_blocks_mapped = self.stats.shared_blocks_mapped.saturating_add(1);
        self.stats.shared_translations_avoided =
            self.stats.shared_translations_avoided.saturating_add(1);
        self.stats.shared_unit_hits = self.stats.shared_unit_hits.saturating_add(1);
        let Some(&entry) = self.blocks.get(&key) else {
            return Err(types::DsrError::CachePolicy(format!(
                "replayed block 0x{:x} did not publish into the private cache",
                guest.raw()
            )));
        };
        Ok(AttachedReplayOutcome::Replayed(entry))
    }

    /// Re-plan a unit block whose terminal exit carries sensitive metadata
    /// and merge that metadata into the process table, exactly as a fresh
    /// translation's plan phase would.
    fn harvest_unit_block_sensitive_metadata(
        &mut self,
        memory: &NativeMappedMemory,
        block_start: carrick_guest_mem::GuestVa,
    ) -> Result<(), types::DsrError> {
        let planned = block::plan_block_with_segments(
            memory,
            block_start,
            types::CodeGeneration::INITIAL,
            256,
            self.superblock_segments,
        )?;
        let block::PlannedExit::Sensitive {
            guest: sensitive_guest,
            exit,
            fusion,
            ..
        } = planned.terminal_exit()
        else {
            return Err(types::DsrError::CachePolicy(format!(
                "shared block 0x{:x} lost sensitive metadata identity",
                block_start.raw(),
            )));
        };
        if let Some(site) = fusion {
            self.record_exclusive_fusion_site(site);
        }
        let sensitive_key = (sensitive_guest, types::CodeGeneration::INITIAL);
        let metadata = SensitiveMetadata { exit, fusion };
        let merged = match self.sensitive.get(&sensitive_key).copied() {
            Some(current) => merge_sensitive_metadata(sensitive_key, current, metadata)?,
            None => metadata,
        };
        self.sensitive.insert(sensitive_key, merged);
        Ok(())
    }

    fn apply_shared_metadata_evidence(
        &mut self,
        evidence: crate::shared_cache::TranslationMetadataLoadEvidence,
    ) {
        for (stat, value) in [
            (ResolverStat::SharedMetadataBytesRead, evidence.bytes_read),
            (
                ResolverStat::SharedMetadataBytesMapped,
                evidence.bytes_mapped,
            ),
            (
                ResolverStat::SharedMetadataValidationNs,
                evidence.validation_ns,
            ),
            (
                ResolverStat::SharedOwnedImmutableRecords,
                evidence.owned_records,
            ),
        ] {
            self.stats.saturating_add(stat, value);
        }
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
        self.publish_emitted_with_metadata(
            memory,
            key,
            source_page,
            observation,
            emitted,
            emitted_bytes,
            outcome,
            None,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "publication consumes the complete emission decomposition"
    )]
    fn publish_emitted_with_metadata(
        &mut self,
        memory: &NativeMappedMemory,
        key: (carrick_guest_mem::GuestVa, types::CodeGeneration),
        source_page: carrick_guest_mem::GuestVa,
        observation: cache::PageGenerationObservation,
        emitted: emit::EmittedBlock,
        emitted_bytes: u64,
        outcome: TranslationOutcome,
        metadata: Option<PublishedBlockMetadata>,
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
        let trusted_entry = emitted.trusted_entry();
        let trusted_routes = emitted
            .trusted_routes()
            .map(|routes| {
                let absolute = |offset: types::CacheOffset| {
                    entry
                        .host()
                        .raw()
                        .checked_add(offset.get() as usize)
                        .map(carrick_guest_mem::HostVa)
                        .map(types::CacheVa::published)
                        .ok_or_else(|| {
                            types::DsrError::CachePolicy(
                                "trusted route absolute address overflow".to_string(),
                            )
                        })
                };
                Ok::<TrustedRouteEntries, types::DsrError>(TrustedRouteEntries {
                    fallthrough: absolute(routes.fallthrough)?,
                    direct: absolute(routes.direct)?,
                    indirect: absolute(routes.indirect)?,
                    sequence_bytes: routes.sequence_bytes,
                    common_body: absolute(routes.common_body)?,
                })
            })
            .transpose()?;
        let (map, links, recovery) = emitted.into_runtime_metadata();
        // A unit-replayed block's emission carries EMPTY map/recovery (its
        // fault metadata lives undecoded in the unit); the caller supplies
        // the handle instead.
        let metadata = metadata.unwrap_or(PublishedBlockMetadata::Owned { map, recovery });
        self.push_published(PublishedBlock {
            entry,
            len: emitted_len,
            metadata,
            _generation: observation,
        });
        self.blocks.insert(key, entry);
        if let Some(offset) = trusted_entry {
            self.trusted_entries.insert(key, offset);
        }
        if let Some(routes) = trusted_routes {
            self.trusted_route_entries.insert(key, routes);
        }
        self.dependencies.record(source_page, key.0, key.1);
        for link in links {
            let target_observation = memory.dsr_generation_observation(link.target)?;
            let target_generation = target_observation.expected();
            let target_key = (link.target, target_generation);
            let site = cache::LinkSite {
                source: entry,
                slot: link.slot,
            };
            // Installed unit blocks come through `publish_emitted` exactly
            // like native translations, so every target is patched directly
            // at its trusted entry — no binding-table trampolines.
            match self.blocks.get(&target_key).copied() {
                Some(target) => {
                    let target = self.trusted_target(target_key, target);
                    self.patch_direct_link_if_reachable(site, target, link.target)?
                }
                None => {
                    self.pending.entry(target_key).or_default().push(site);
                }
            }
        }
        if let Some(sites) = self.pending.remove(&key) {
            let entry = self.trusted_target(key, entry);
            for site in sites {
                self.patch_direct_link_if_reachable(site, entry, key.0)?;
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
        if let Some(entry) = self.try_load_shared_unit(memory, guest, generation)? {
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
                // Fused (superblock) plans ARE in scope for the unit lane.
                // Superblock formation extends only along the FALL-THROUGH
                // edge and stops at `page_end`, so a fused plan is contiguous
                // and single-page and `block.end` covers every segment.
                // Excluding them cost 2.2x of shared coverage: 14.4% fused vs
                // 32.1% unfused (run 26).
                //
                // `ExclusiveRegion` stays out via the terminal-exit list
                // below: that lowering owns its whole block and is not a
                // segment.
                let unit_candidate_segment = if generation == types::CodeGeneration::INITIAL
                    && let Some(segment) = portable_segment
                    && self.shared_recording_segments.contains(&segment)
                    && matches!(
                        block.terminal_exit(),
                        block::PlannedExit::Syscall { .. }
                            | block::PlannedExit::Direct { .. }
                            | block::PlannedExit::Indirect { .. }
                            | block::PlannedExit::Sensitive { .. }
                            | block::PlannedExit::Continue { .. }
                    ) {
                    Some(segment)
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
                // ONE native emission serves execution, the per-image
                // artifact store, AND the unit lane: recording is a pure tap
                // (byte-identical words, trusted entry included), so a unit
                // candidate IS the native emission — not a second
                // authority-mode assembly.
                let (emitted, artifact) = if artifact_eligible || unit_candidate_segment.is_some() {
                    emit::emit_block_recording_artifact_optional_with_route_split(
                        &mut self.cache,
                        &block,
                        emit::GenerationGuard::new(observation.current_atomic(), generation),
                        memory.address_mode().into(),
                        artifact_source_words.clone().unwrap_or_default(),
                        self.trusted_route_split,
                    )?
                } else {
                    (
                        emit::emit_block_with_generation_and_route_split(
                            &mut self.cache,
                            &block,
                            emit::GenerationGuard::new(observation.current_atomic(), generation),
                            memory.address_mode().into(),
                            self.trusted_route_split,
                        )?,
                        None,
                    )
                };
                let portable_candidate = match (unit_candidate_segment, artifact.as_ref()) {
                    (Some(segment), Some(artifact)) => Some((
                        segment,
                        crate::shared_cache::PortableBlockCandidate {
                            guest_start: block.start,
                            requires_sensitive_metadata: matches!(
                                block.terminal_exit(),
                                block::PlannedExit::Sensitive { .. }
                            ),
                            template: artifact.template.clone(),
                        },
                    )),
                    _ => None,
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
            xlat_census::record(guest, block.start, block.end);
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
    /// Patch one direct-link site to branch straight at `target`, or leave the
    /// site alone when the target is out of `B` range.
    ///
    /// Out-of-range is NOT an error: the unpatched site still holds the
    /// `b`-to-next-instruction that falls into the gateway exit stub, which is
    /// correct, merely slower. Propagating an error here would turn a placement
    /// accident into a failed translation. Measured placement on this host puts
    /// every loaded unit within 2.0 MiB of the private cache (53/53), so the
    /// fallback is a safety net rather than the common path.
    ///
    /// Safe without an un-patching path on invalidation for the same reason the
    /// pre-existing private->private patching is: the target block opens with its
    /// own generation guard, so a branch that lands in a stale target is detected
    /// there and exits. That is the same net `DirectBindingTable::invalidate_target`
    /// relies on when it pins descriptors so "a reader that acquired `expected`
    /// can safely reach the target's generation guard".
    /// The address a patched direct link should target: the block's trusted
    /// entry (past the guard) when it has one, its guarded entry otherwise
    /// (shared-unit blocks and recorded blocks never expose one).
    fn trusted_target(
        &self,
        key: (carrick_guest_mem::GuestVa, types::CodeGeneration),
        entry: types::CacheVa,
    ) -> types::CacheVa {
        if let Some(routes) = self.trusted_route_entries.get(&key) {
            return routes.direct;
        }
        match self.trusted_entries.get(&key) {
            Some(offset) => types::CacheVa::published(carrick_guest_mem::HostVa(
                entry.host().raw() + offset.get() as usize,
            )),
            None => entry,
        }
    }

    fn patch_direct_link_if_reachable(
        &mut self,
        site: cache::LinkSite,
        target: types::CacheVa,
        target_guest: carrick_guest_mem::GuestVa,
    ) -> Result<(), types::DsrError> {
        match encode_aarch64_direct_branch(site, target) {
            Ok(word) => {
                self.cache.patch_code_word(site, word)?;
                self.direct_link_incoming
                    .entry(target_guest.raw() & !0xfff)
                    .or_default()
                    .push(site);
                Ok(())
            }
            Err(types::DsrError::CachePolicy(reason))
                if reason.contains("outside AArch64 B range") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Sever every recorded private direct link whose TARGET lies in a guest
    /// page overlapping `range`, restoring the unpatched `b +1` word so the
    /// next traversal falls into the stub and resolves through the gateway.
    /// Runs from the mapped-memory code-write path AFTER the generation
    /// bump; a racing entry through a not-yet-severed link is bounded by one
    /// block body -- the same window the entry guard tolerates today.
    pub(crate) fn sever_direct_links_in(
        &mut self,
        range: std::ops::Range<carrick_guest_mem::GuestVa>,
    ) -> Result<usize, types::DsrError> {
        const UNPATCHED_FALL_INTO_STUB: u32 = 0x1400_0001;
        let first = range.start.raw() & !0xfff;
        let last = range.end.raw().saturating_add(0xfff) & !0xfff;
        let pages: Vec<u64> = self
            .direct_link_incoming
            .range(first..last)
            .map(|(page, _)| *page)
            .collect();
        let mut severed = 0;
        for page in pages {
            if let Some(sites) = self.direct_link_incoming.remove(&page) {
                for site in sites {
                    self.cache.patch_code_word(site, UNPATCHED_FALL_INTO_STUB)?;
                    severed += 1;
                }
            }
        }
        Ok(severed)
    }

    fn push_published(&mut self, block: PublishedBlock) {
        let entry = PublishedIndexEntry {
            start: block.entry.host(),
            block: self.published.len(),
        };
        // The private cache is a bump allocator: `begin_write` hands out
        // strictly increasing extents, and the one cursor rewind
        // (`reset_after_fork_for_exec`) clears `published` with it, so a
        // block appends. Installed unit blocks replay into this same cache
        // and come through here like every native translation.
        let index = &mut self.private_published_index;
        let at = match index.last() {
            Some(last) if last.start > entry.start => {
                index.partition_point(|indexed| indexed.start <= entry.start)
            }
            _ => index.len(),
        };
        index.insert(at, entry);
        self.published.push(block);
    }

    fn clear_published(&mut self) {
        self.published.clear();
        self.private_published_index.clear();
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
        [&self.private_published_index]
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
            let offset = types::CacheOffset::published(offset);
            let (guest, recovery) = match &block.metadata {
                PublishedBlockMetadata::Owned { map, recovery } => (
                    map.iter()
                        .find(|entry| entry.cache == offset)
                        .map(|entry| entry.guest),
                    recovery
                        .iter()
                        .find(|entry| entry.cache == offset)
                        .map(|entry| entry.action),
                ),
                // A unit-replayed block: its pc map and recovery live
                // undecoded in the unit's mapped cold stream. Decode them
                // NOW — faults are rare, replays are not — and rebind the
                // found recovery action with the replay-time bindings, so
                // the outcome is bit-identical to an eager replay's.
                PublishedBlockMetadata::Unit {
                    manifest,
                    block: unit_block,
                    bindings,
                } => {
                    let cold = manifest
                        .block_cold(*unit_block as usize)
                        .map_err(|reason| {
                            types::DsrError::CachePolicy(format!(
                                "unit cold metadata refused at fault for cache PC \
                             0x{cache_pc:x}: {reason:?}"
                            ))
                        })?;
                    let guest = cold
                        .map
                        .iter()
                        .find(|entry| entry.cache == offset)
                        .map(|entry| entry.guest);
                    let action = cold
                        .recovery
                        .into_entries()?
                        .into_iter()
                        .find(|entry| entry.cache() == offset)
                        .map(|entry| entry.action().rebind(bindings))
                        .transpose()?;
                    (guest, action)
                }
            };
            let guest = guest.ok_or_else(|| {
                types::DsrError::CachePolicy(format!(
                    "cache PC 0x{cache_pc:x} is not an emitted instruction boundary"
                ))
            })?;
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
        let _ = (guest, generation);
        if self.process.private_target_authority.owns(entry) {
            return Ok(self.process.private_target_authority.as_ref() as *const _);
        }
        Err(types::DsrError::CachePolicy(format!(
            "translated target 0x{:x} has no executable authority",
            entry.host().raw()
        )))
    }

    /// Publish `target` into the per-thread indirect target cache, choosing
    /// the entry FLAVOR (see `gateway::IndirectTargetCacheEntry`):
    ///
    /// - a PRIVATE-cache target with a trusted entry publishes flavor 1 —
    ///   the trusted-entry code address plus the target page's generation
    ///   atomic, so the emitted hot path validates staleness inline and
    ///   lands past the guard;
    /// - everything else (shared-unit targets, blocks without a trusted
    ///   entry) keeps flavor 0: the guarded entry plus a
    ///   `TargetCacheAuthority` the emitted slow path installs.
    ///
    /// Callable only after `translate()` returned — that call takes and
    /// RELEASES the process-state write lock internally, so the short read
    /// lock here cannot deadlock.
    fn publish_indirect_target(
        &mut self,
        memory: &NativeMappedMemory,
        target: carrick_guest_mem::GuestVa,
        translated: &TranslationResult,
    ) -> Result<(), types::DsrError> {
        if self.process.private_target_authority.owns(translated.entry) {
            let trusted_code = {
                let state = self.process.state.read();
                state
                    .trusted_route_entries
                    .get(&(target, translated.generation))
                    .map(|routes| routes.indirect.host().raw() as u64)
                    .or_else(|| {
                        state
                            .trusted_entries
                            .get(&(target, translated.generation))
                            .map(|offset| {
                                translated.entry.host().raw() as u64 + u64::from(offset.get())
                            })
                    })
            };
            if let Some(trusted_code) = trusted_code {
                // The same atomic the target's emitted guard materializes:
                // the page-generation cell `memory.dsr_generation_observation`
                // hands the translate/guard wiring. Its address is stable for
                // the life of the generation table (entries are never
                // removed), and fork/exec clear the indirect cache before a
                // new table exists.
                let observation = memory.dsr_generation_observation(target)?;
                let generation_atomic = std::ptr::from_ref(observation.current_atomic()) as u64;
                self.indirect_cache.publish_private_trusted(
                    target,
                    trusted_code,
                    generation_atomic,
                    translated.generation,
                );
                return Ok(());
            }
        }
        let authority =
            self.target_cache_authority(target, translated.generation, translated.entry)?;
        self.indirect_cache
            .publish(target, translated.generation, translated.entry, authority);
        Ok(())
    }

    fn resolve_indirect<const PROFILE: bool>(
        &mut self,
        memory: &NativeMappedMemory,
        source: carrick_guest_mem::GuestVa,
        target: carrick_guest_mem::GuestVa,
    ) -> Result<(types::CacheVa, types::CodeGeneration), types::DsrError> {
        self.stats.add(ResolverStat::ResolverExits, 1);
        let translated = self.translate::<PROFILE>(memory, target).map_err(|error| {
            self.with_memory_read_origin(error, || {
                format!(
                    "indirect-resolver source=0x{:x} target=0x{:x}",
                    source.raw(),
                    target.raw()
                )
            })
        })?;
        self.publish_indirect_target(memory, target, &translated)?;
        probes::dsr_cache_event(
            self.tid,
            probes::DsrCacheEventKind::TargetPublish,
            target.raw(),
            translated.generation.get(),
            translated.cache_used_bytes,
        );
        Ok((translated.entry, translated.generation))
    }

    /// Test/diagnostic view of the indirect-cache way published for `guest`:
    /// `(cache, authority, reserved)`.
    #[doc(hidden)]
    pub fn indirect_cache_entry_for_test(
        &self,
        guest: carrick_guest_mem::GuestVa,
    ) -> Option<(u64, u64, u64)> {
        self.indirect_cache.entry_snapshot(guest)
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
            shared_blocks_attached: process.shared_blocks_attached,
            shared_metadata_bytes_read: process.shared_metadata_bytes_read,
            shared_metadata_bytes_mapped: process.shared_metadata_bytes_mapped,
            shared_metadata_validation_ns: process.shared_metadata_validation_ns,
            shared_mapped_immutable_records: process.shared_mapped_immutable_records,
            shared_owned_immutable_records: process.shared_owned_immutable_records,
            shared_guest_range_derivations: process.shared_guest_range_derivations,
            shared_direct_edge_group_builds: process.shared_direct_edge_group_builds,
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
        let mut points = Vec::new();
        for block in &state.published {
            let Ok((map, recovery)) = block.metadata.materialize() else {
                // Test-support sweep: a block whose unit metadata cannot
                // materialize has no recovery points to offer here; the
                // production fault path reports the decode failure itself.
                continue;
            };
            for recovery in &recovery {
                if !matches!(
                    recovery.action,
                    emit::RecoveryAction::RestoreScratch { .. }
                        | emit::RecoveryAction::RestoreScratchCompleted { .. }
                        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratch { .. }
                        | emit::RecoveryAction::RestoreScratchAndContext { .. }
                        | emit::RecoveryAction::RestoreScratchAndContextCompleted { .. }
                        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext { .. }
                        | emit::RecoveryAction::RestoreDualVirtualReadOnly { .. }
                        | emit::RecoveryAction::RestoreDualVirtualReadOnlyCompleted { .. }
                        | emit::RecoveryAction::CommitDualVirtualAndRestore { .. }
                        | emit::RecoveryAction::RecoverCounterRead(_)
                        | emit::RecoveryAction::RecoverBiasedMemory(_)
                ) {
                    continue;
                }
                let mapped_guest = map
                    .iter()
                    .find(|mapping| mapping.cache == recovery.cache)
                    .map(|mapping| mapping.guest);
                if mapped_guest != Some(guest) {
                    continue;
                }
                if let Some(point) = block
                    .entry
                    .host()
                    .raw()
                    .checked_add(recovery.cache.get() as usize)
                    .map(carrick_guest_mem::HostVa)
                    .map(types::CacheVa::published)
                    .map(|cache_pc| (cache_pc, recovery.action))
                {
                    points.push(point);
                }
            }
        }
        points
    }

    #[doc(hidden)]
    pub fn direct_binding_recovery_points_for_test(
        &self,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<Vec<(types::CacheVa, emit::RecoveryAction)>, types::DsrError> {
        let state = self.process.state.read();
        let mut points = Vec::new();
        for block in &state.published {
            let (map, _recovery) = block.metadata.materialize()?;
            let cache_offsets = map
                .iter()
                .filter(|mapping| mapping.guest == guest)
                .map(|mapping| mapping.cache)
                .collect::<Vec<_>>();
            for cache in cache_offsets {
                let address = block
                    .entry
                    .host()
                    .raw()
                    .checked_add(cache.get() as usize)
                    .ok_or_else(|| {
                        types::DsrError::CachePolicy(
                            "direct-binding recovery test address overflow".to_string(),
                        )
                    })?;
                let cache_pc =
                    carrick_guest_mem::GuestVa(u64::try_from(address).map_err(|_| {
                        types::DsrError::CachePolicy(
                            "direct-binding recovery test address exceeds u64".to_string(),
                        )
                    })?);
                let (mapped_guest, recovery) = state.guest_pc_for_cache(cache_pc)?;
                if mapped_guest == guest
                    && let Some(action @ emit::RecoveryAction::RestoreDirectBinding { .. }) =
                        recovery
                {
                    points.push((
                        types::CacheVa::published(carrick_guest_mem::HostVa(address)),
                        action,
                    ));
                }
            }
        }
        Ok(points)
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
            let Ok((_map, recovery)) = block.metadata.materialize() else {
                return false;
            };
            recovery.iter().any(|recovery| {
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
            let translated = self.translate::<PROFILE>(memory, guest).map_err(|error| {
                self.with_memory_read_origin(error, || {
                    format!("prepare-entry guest=0x{:x}", guest.raw())
                })
            })?;
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
        let prepared = PreparedEntry {
            entry,
            generation,
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
        // Installed unit blocks replay into the private cache with trusted
        // entries, so every prepared entry takes the trusted private-cache
        // arm — the shared cache-range/binding-table gateway arms are gone.
        let gateway_result = gateway::enter_translated_with_trusted_private_cache(
            prepared.entry,
            snapshot,
            &mut exit,
            &self.indirect_cache,
            self.process.private_target_authority.as_ref(),
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
                types::NativeDsrExit::ResolveDirect { source, target, .. } => {
                    self.stats.add(ResolverStat::DirectResolverExits, 1);
                    // Installed unit blocks are indistinguishable from native
                    // translations, so every resolve edge is private->private.
                    let (source_shared, target_shared) = (false, false);
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
            types::NativeDsrExit::ResolveDirect { source, target } => {
                probes::dsr_resolve_begin(
                    self.tid,
                    probes::DsrResolveKind::Direct,
                    source.raw(),
                    target.raw(),
                );
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
                        return Err(self.with_memory_read_origin(error, || {
                            format!(
                                "direct-resolver source=0x{:x} target=0x{:x}",
                                source.raw(),
                                target.raw()
                            )
                        }));
                    }
                };
                self.publish_indirect_target(memory, target, &translated)?;
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
                physical_reserved,
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
                        physical_reserved,
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
                physical_reserved,
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
                        physical_reserved,
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
        DsrErrorProbeExt as _, ForkChildRepairRecorder, NativeDsrExitProbeExt as _,
        ProcessTranslator, SensitiveMetadata, ThreadTranslator, TranslatedRangeCatalog,
        TranslatedRangeRecorder, merge_sensitive_metadata, translation_source_words_required,
    };
    use crate::types;
    use carrick_dsr::cache::PageGenerationTable;
    use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};
    use carrick_dsr::probes::{
        DsrCacheLifecyclePhase, TranslatedPrivateRange, TranslatedRangeAdd, TranslatedRangeEpoch,
        TranslatedRangeReady, TranslatedRangeReset, TranslatedRangeSequence,
    };
    use carrick_guest_mem::{GuestVa, HostVa};
    use std::ptr::NonNull;
    use std::sync::{Arc, Barrier};

    const PC: GuestVa = GuestVa(0x1000);

    /// The persistent store is default-ON with an exact `=0` rollback hatch.
    /// Pinned on the pure parser because the runtime gate caches the
    /// environment in a `OnceLock`.
    #[test]
    fn persistent_store_default_and_hatch_parse() {
        assert!(
            super::persistent_store_enabled_from(None),
            "persistent translation is the shipped default"
        );
        assert!(!super::persistent_store_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
        assert!(
            super::persistent_store_enabled_from(Some(std::ffi::OsStr::new("1"))),
            "=1 remains an explicit enable for controlled campaigns"
        );
        assert!(
            super::persistent_store_enabled_from(Some(std::ffi::OsStr::new("false"))),
            "only exact =0 is the rollback hatch"
        );
    }

    #[test]
    fn prepare_memory_read_names_the_loop_entry_origin() {
        let process = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator"),
        );
        let mut translator = ThreadTranslator::for_process(process, 41);
        let memory = crate::mapped_memory::NativeMappedMemory::shared_install_test_fixture(4096);
        let snapshot = super::NativeUcontextSnapshot {
            pc: 0x1073_36538,
            ..Default::default()
        };

        let error = match translator.prepare_entry::<false>(&memory, &snapshot) {
            Err(error) => error,
            Ok(_) => panic!("an unmapped loop-entry PC must fail translation"),
        };

        assert!(
            error
                .to_string()
                .contains("translation-origin=prepare-entry guest=0x107336538"),
            "{error}"
        );
    }

    #[test]
    fn prepare_memory_read_reports_when_the_would_be_guest_pc_is_in_the_jit_cache() {
        let process = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator"),
        );
        let cache_pc = process.cache_host_range().start;
        let mut translator = ThreadTranslator::for_process(process, 42);
        let memory = crate::mapped_memory::NativeMappedMemory::shared_install_test_fixture(4096);
        let snapshot = super::NativeUcontextSnapshot {
            pc: cache_pc,
            ..Default::default()
        };

        let error = match translator.prepare_entry::<false>(&memory, &snapshot) {
            Err(error) => error,
            Ok(_) => panic!("a JIT host PC must not be translated as a guest PC"),
        };

        assert!(error.to_string().contains("cache-contains=true"), "{error}");
    }

    #[test]
    fn direct_resolver_memory_read_names_source_and_target_origin() {
        let process = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator"),
        );
        let cache_entry = process.cache_host_range().start;
        let mut translator = ThreadTranslator::for_process(process, 42);
        let memory = crate::mapped_memory::NativeMappedMemory::shared_install_test_fixture(4096);
        let source = GuestVa(0x40_0100);
        let target = GuestVa(0x1073_36538);
        let prepared = super::PreparedEntry {
            entry: types::CacheVa::published(HostVa(
                usize::try_from(cache_entry).expect("cache address fits usize"),
            )),
            generation: types::CodeGeneration::INITIAL,
            address_mode: memory.address_mode(),
        };
        let exit = super::PreparedExit {
            exit: types::NativeDsrExit::ResolveDirect { source, target },
        };
        let mut snapshot = super::NativeUcontextSnapshot::default();

        let error = translator
            .finish_exit(&memory, &mut snapshot, prepared, exit)
            .expect_err("an unmapped direct target must fail translation");

        assert!(
            error
                .to_string()
                .contains("translation-origin=direct-resolver source=0x400100 target=0x107336538"),
            "{error}"
        );
    }

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

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RecordedTranslatedRange {
        Reset(TranslatedRangeReset),
        Add(TranslatedRangeAdd),
        Ready(TranslatedRangeReady),
    }

    #[derive(Default)]
    struct TranslatedRangeRecorderFixture {
        events: Vec<RecordedTranslatedRange>,
    }

    impl TranslatedRangeRecorder for TranslatedRangeRecorderFixture {
        fn reset(&mut self, event: TranslatedRangeReset) {
            self.events.push(RecordedTranslatedRange::Reset(event));
        }

        fn add(&mut self, event: TranslatedRangeAdd) {
            self.events.push(RecordedTranslatedRange::Add(event));
        }

        fn ready(&mut self, event: TranslatedRangeReady) {
            self.events.push(RecordedTranslatedRange::Ready(event));
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RecordedForkChildRepair {
        ProcessRepaired,
        Range(RecordedTranslatedRange),
    }

    struct ForkChildRepairRecorderFixture<'a> {
        state: &'a parking_lot::RwLock<super::ProcessState>,
        events: Vec<RecordedForkChildRepair>,
    }

    impl ForkChildRepairRecorderFixture<'_> {
        fn assert_writer_held(&self) {
            assert!(
                self.state.try_read().is_none(),
                "fork replay escaped the process-state writer"
            );
        }
    }

    impl TranslatedRangeRecorder for ForkChildRepairRecorderFixture<'_> {
        fn reset(&mut self, event: TranslatedRangeReset) {
            self.assert_writer_held();
            self.events.push(RecordedForkChildRepair::Range(
                RecordedTranslatedRange::Reset(event),
            ));
        }

        fn add(&mut self, event: TranslatedRangeAdd) {
            self.assert_writer_held();
            self.events.push(RecordedForkChildRepair::Range(
                RecordedTranslatedRange::Add(event),
            ));
        }

        fn ready(&mut self, event: TranslatedRangeReady) {
            self.assert_writer_held();
            self.events.push(RecordedForkChildRepair::Range(
                RecordedTranslatedRange::Ready(event),
            ));
        }
    }

    impl ForkChildRepairRecorder for ForkChildRepairRecorderFixture<'_> {
        fn process_repaired(&mut self) {
            self.assert_writer_held();
            self.events.push(RecordedForkChildRepair::ProcessRepaired);
        }
    }

    #[test]
    fn translated_range_catalog_stays_dormant_until_one_process_activation() {
        let mut recorder = TranslatedRangeRecorderFixture::default();
        let private = HostVa(0x1000)..HostVa(0x2000);
        let _catalog = TranslatedRangeCatalog::dormant_with_recorder(private, &mut recorder)
            .expect("valid dormant catalog");

        assert_eq!(recorder.events, Vec::<RecordedTranslatedRange>::new());
    }

    #[test]
    fn translated_range_catalog_emits_initial_private_replay_once_across_siblings() {
        let process = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator"),
        );
        let cache_range = process.state.read().cache.host_range();
        let expected_range = HostVa(cache_range.start)..HostVa(cache_range.end);
        let epoch = TranslatedRangeEpoch::new(1).expect("nonzero epoch");
        let sequence = TranslatedRangeSequence::new(1).expect("nonzero sequence");
        let private = TranslatedPrivateRange::private(epoch, sequence, expected_range)
            .expect("valid private cache range");
        let expected = vec![
            RecordedTranslatedRange::Reset(TranslatedRangeReset::reset(epoch)),
            RecordedTranslatedRange::Add(TranslatedRangeAdd::Private(private)),
            RecordedTranslatedRange::Ready(TranslatedRangeReady::ready(epoch, 1)),
        ];
        let sibling_count = 8;
        let barrier = Arc::new(Barrier::new(sibling_count));
        let siblings = (0..sibling_count)
            .map(|_| {
                let process = Arc::clone(&process);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut recorder = TranslatedRangeRecorderFixture::default();
                    barrier.wait();
                    process
                        .activate_translated_range_catalog_with_recorder(&mut recorder)
                        .expect("sibling activation");
                    recorder.events
                })
            })
            .collect::<Vec<_>>();
        let events = siblings
            .into_iter()
            .flat_map(|sibling| sibling.join().expect("sibling join"))
            .collect::<Vec<_>>();

        assert_eq!(events, expected);
    }

    #[test]
    fn translated_range_catalog_rejects_invalid_private_state_before_publication() {
        for private in [
            HostVa(0)..HostVa(4),
            HostVa(0x1000)..HostVa(0x1000),
            HostVa(0x2000)..HostVa(0x1000),
            HostVa(0x1001)..HostVa(0x2000),
            HostVa(0x1000)..HostVa(0x2002),
        ] {
            let mut recorder = TranslatedRangeRecorderFixture::default();

            let result = TranslatedRangeCatalog::dormant_with_recorder(private, &mut recorder);

            assert!(result.is_err());
            assert_eq!(recorder.events, Vec::<RecordedTranslatedRange>::new());
        }
    }

    fn active_catalog() -> (TranslatedRangeCatalog, TranslatedRangeRecorderFixture) {
        let mut recorder = TranslatedRangeRecorderFixture::default();
        // Wide enough that the shared fixture subranges (0x2000-0x6000) are
        // CONTAINED: the copy transport installs shared units inside the
        // private cache, so containment is the catalog's validity rule.
        let mut catalog = TranslatedRangeCatalog::dormant_with_recorder(
            HostVa(0x1000)..HostVa(0x8000),
            &mut recorder,
        )
        .expect("dormant catalog");
        catalog
            .activate_if_dormant_with_recorder(&mut recorder)
            .expect("activate catalog");
        recorder.events.clear();
        (catalog, recorder)
    }

    #[test]
    fn translated_range_catalog_replays_private_range_under_checked_fork_epoch() {
        let (mut catalog, mut recorder) = active_catalog();
        let private = catalog.private.clone();
        let epoch = TranslatedRangeEpoch::new(2).expect("nonzero epoch");
        let sequence = TranslatedRangeSequence::new(1).expect("nonzero sequence");

        catalog
            .replay_after_fork(&mut recorder)
            .expect("fork replay");

        assert_eq!(
            recorder.events,
            vec![
                RecordedTranslatedRange::Reset(TranslatedRangeReset::reset(epoch)),
                RecordedTranslatedRange::Add(TranslatedRangeAdd::Private(
                    TranslatedPrivateRange::private(epoch, sequence, private.clone())
                        .expect("valid private range"),
                )),
                RecordedTranslatedRange::Ready(TranslatedRangeReady::ready(epoch, 1)),
            ]
        );
        assert_eq!(catalog.epoch, epoch);
        assert_eq!(catalog.next_sequence, 2);
        assert_eq!(catalog.ready_sequence, Some(1));
        assert_eq!(catalog.private, private);
    }

    #[test]
    fn translated_range_catalog_rejects_replay_while_dormant() {
        let mut recorder = TranslatedRangeRecorderFixture::default();
        let mut catalog = TranslatedRangeCatalog::dormant_with_recorder(
            HostVa(0x1000)..HostVa(0x2000),
            &mut recorder,
        )
        .expect("dormant catalog");
        let before = (
            catalog.epoch,
            catalog.next_sequence,
            catalog.ready_sequence,
            catalog.private.clone(),
        );

        let result = catalog.replay_after_fork(&mut recorder);

        assert!(matches!(result, Err(types::DsrError::CachePolicy(_))));
        assert!(recorder.events.is_empty());
        assert_eq!(
            (
                catalog.epoch,
                catalog.next_sequence,
                catalog.ready_sequence,
                catalog.private,
            ),
            before
        );
    }

    #[test]
    fn translated_range_catalog_rejects_invalid_inherited_ready_frontier() {
        for invalid_ready in [0, 2] {
            let (mut catalog, mut recorder) = active_catalog();
            recorder.events.clear();
            catalog.ready_sequence = Some(invalid_ready);
            let before = (
                catalog.epoch,
                catalog.next_sequence,
                catalog.ready_sequence,
                catalog.private.clone(),
            );

            let result = catalog.replay_after_fork(&mut recorder);

            assert!(matches!(result, Err(types::DsrError::CachePolicy(_))));
            assert!(
                recorder.events.is_empty(),
                "invalid ready {invalid_ready} emitted replay events"
            );
            assert_eq!(
                (
                    catalog.epoch,
                    catalog.next_sequence,
                    catalog.ready_sequence,
                    catalog.private.clone(),
                ),
                before,
                "invalid ready {invalid_ready} mutated the catalog"
            );
        }
    }

    #[test]
    fn translated_range_catalog_fork_epoch_overflow_is_failure_atomic() {
        let (mut catalog, mut recorder) = active_catalog();
        recorder.events.clear();
        catalog.epoch = TranslatedRangeEpoch::new(u64::MAX).expect("maximum epoch is nonzero");
        let before = (
            catalog.epoch,
            catalog.next_sequence,
            catalog.ready_sequence,
            catalog.private.clone(),
        );

        let result = catalog.replay_after_fork(&mut recorder);

        assert!(matches!(result, Err(types::DsrError::CachePolicy(_))));
        assert!(recorder.events.is_empty());
        assert_eq!(
            (
                catalog.epoch,
                catalog.next_sequence,
                catalog.ready_sequence,
                catalog.private,
            ),
            before
        );
    }

    #[test]
    fn translated_range_catalog_exec_reset_prepares_then_commits_dormant() {
        let (mut catalog, recorder) = active_catalog();
        let private = catalog.private.clone();

        let prepared = catalog
            .prepare_dormant_for_exec()
            .expect("prepare active catalog retirement");

        assert_eq!(catalog.epoch.get(), 1, "preparation changed the live epoch");
        assert_eq!(catalog.next_sequence, 2);
        assert_eq!(catalog.ready_sequence, Some(1));
        assert!(recorder.events.is_empty());

        catalog.commit_dormant_for_exec(prepared);

        assert_eq!(catalog.epoch.get(), 2);
        assert_eq!(catalog.next_sequence, 1);
        assert_eq!(catalog.ready_sequence, None);
        assert_eq!(catalog.private, private);
        assert!(
            recorder.events.is_empty(),
            "exec reset emitted range events"
        );
    }

    #[test]
    fn translated_range_catalog_exec_epoch_overflow_is_eventless_and_atomic() {
        let (mut catalog, recorder) = active_catalog();
        catalog.epoch = TranslatedRangeEpoch::new(u64::MAX).expect("maximum epoch");
        let before = (
            catalog.epoch,
            catalog.next_sequence,
            catalog.ready_sequence,
            catalog.private.clone(),
        );

        let result = catalog.prepare_dormant_for_exec();

        assert!(matches!(result, Err(types::DsrError::CachePolicy(_))));
        assert!(recorder.events.is_empty());
        assert_eq!(
            (
                catalog.epoch,
                catalog.next_sequence,
                catalog.ready_sequence,
                catalog.private.clone(),
            ),
            before,
        );
    }

    #[test]
    fn translated_range_catalog_second_exec_reset_rejects_dormant_unchanged() {
        let (mut catalog, recorder) = active_catalog();
        let prepared = catalog
            .prepare_dormant_for_exec()
            .expect("prepare first reset");
        catalog.commit_dormant_for_exec(prepared);
        let before = (
            catalog.epoch,
            catalog.next_sequence,
            catalog.ready_sequence,
            catalog.private.clone(),
        );

        let result = catalog.prepare_dormant_for_exec();

        assert!(matches!(result, Err(types::DsrError::CachePolicy(_))));
        assert!(recorder.events.is_empty());
        assert_eq!(
            (
                catalog.epoch,
                catalog.next_sequence,
                catalog.ready_sequence,
                catalog.private.clone(),
            ),
            before,
        );
    }

    #[test]
    fn translated_range_catalog_post_exec_activation_replays_private_once() {
        let (mut catalog, mut recorder) = active_catalog();
        let prepared = catalog
            .prepare_dormant_for_exec()
            .expect("prepare exec reset");
        catalog.commit_dormant_for_exec(prepared);
        let private = catalog.private.clone();
        let epoch = TranslatedRangeEpoch::new(2).expect("exec epoch");

        catalog
            .activate_if_dormant_with_recorder(&mut recorder)
            .expect("activate replacement");
        catalog
            .activate_if_dormant_with_recorder(&mut recorder)
            .expect("idempotent activation");

        assert_eq!(
            recorder.events,
            vec![
                RecordedTranslatedRange::Reset(TranslatedRangeReset::reset(epoch)),
                RecordedTranslatedRange::Add(TranslatedRangeAdd::Private(
                    TranslatedPrivateRange::private(
                        epoch,
                        TranslatedRangeSequence::new(1).expect("private sequence"),
                        private,
                    )
                    .expect("private replay"),
                )),
                RecordedTranslatedRange::Ready(TranslatedRangeReady::ready(epoch, 1)),
            ],
        );
        assert_eq!(catalog.next_sequence, 2);
        assert_eq!(catalog.ready_sequence, Some(1));
    }

    #[test]
    fn translated_range_catalog_abandoned_exec_preparation_leaves_active_state() {
        let (catalog, recorder) = active_catalog();
        let before = (
            catalog.epoch,
            catalog.next_sequence,
            catalog.ready_sequence,
            catalog.private.clone(),
        );

        let _prepared = catalog
            .prepare_dormant_for_exec()
            .expect("prepare reset without committing");

        assert!(recorder.events.is_empty());
        assert_eq!(
            (
                catalog.epoch,
                catalog.next_sequence,
                catalog.ready_sequence,
                catalog.private.clone(),
            ),
            before,
        );
    }

    #[test]
    fn fork_child_replay_failure_preserves_thread_cache_and_suppresses_end_event() {
        let process = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator"),
        );
        process
            .activate_translated_range_catalog()
            .expect("activate catalog");
        process.state.write().translated_ranges.epoch =
            TranslatedRangeEpoch::new(u64::MAX).expect("maximum epoch is nonzero");
        let mut thread = ThreadTranslator::for_process(Arc::clone(&process), 41);
        thread.block_cache.insert(
            GuestVa(0x4000),
            types::CodeGeneration::INITIAL,
            types::CacheVa::published(HostVa(
                usize::try_from(process.cache_host_range().start).expect("host cache address"),
            )),
        );
        let mut repair_recorder = ForkChildRepairRecorderFixture {
            state: &process.state,
            events: Vec::new(),
        };
        let mut lifecycle = Vec::new();
        let mut record_lifecycle = |phase| lifecycle.push(phase);

        let result =
            thread.after_fork_child_with_recorders(42, &mut repair_recorder, &mut record_lifecycle);

        assert!(matches!(result, Err(types::DsrError::CachePolicy(_))));
        assert!(
            !thread.block_cache.is_empty(),
            "thread cache must remain intact until process replay succeeds"
        );
        assert_eq!(
            repair_recorder.events,
            vec![RecordedForkChildRepair::ProcessRepaired]
        );
        assert_eq!(
            lifecycle,
            vec![DsrCacheLifecyclePhase::ForkChildRepairBegin],
            "failed replay must not announce fork repair completion"
        );
    }
    fn shared_sensitive_metadata(
        resume: GuestVa,
        fusion: Option<types::ExclusiveFusionSite>,
    ) -> SensitiveMetadata {
        SensitiveMetadata {
            exit: types::SensitiveExit {
                kind: types::SensitiveKind::ReadCounter,
                register: None,
                resume,
            },
            fusion,
        }
    }

    fn shared_sensitive_fusion(guest: GuestVa, word: u32) -> types::ExclusiveFusionSite {
        types::ExclusiveFusionSite {
            guest,
            word,
            disposition: types::ExclusiveFusionDisposition::EligibleBackendDisabled,
            biased_scratch: None,
        }
    }

    #[test]
    fn shared_sensitive_merge_preserves_matching_fusion() {
        let key = (GuestVa(0x4008), types::CodeGeneration::INITIAL);
        let fusion = shared_sensitive_fusion(key.0, 0x885f_fc20);
        let metadata = shared_sensitive_metadata(GuestVa(0x400c), Some(fusion));

        assert_eq!(
            merge_sensitive_metadata(key, metadata, metadata).expect("identical metadata"),
            metadata
        );
    }

    #[test]
    fn shared_sensitive_merge_drops_missing_or_conflicting_fusion() {
        let key = (GuestVa(0x4008), types::CodeGeneration::INITIAL);
        let first_fusion = shared_sensitive_fusion(key.0, 0x885f_fc20);
        let second_fusion = shared_sensitive_fusion(key.0, 0x885f_7c20);
        let exit = GuestVa(0x400c);

        for (case, left, right) in [
            (
                "present versus absent",
                shared_sensitive_metadata(exit, Some(first_fusion)),
                shared_sensitive_metadata(exit, None),
            ),
            (
                "different present sites",
                shared_sensitive_metadata(exit, Some(first_fusion)),
                shared_sensitive_metadata(exit, Some(second_fusion)),
            ),
        ] {
            assert_eq!(
                merge_sensitive_metadata(key, left, right)
                    .unwrap_or_else(|error| panic!("{case}: {error}")),
                shared_sensitive_metadata(exit, None),
                "{case}"
            );
        }
    }

    #[test]
    fn shared_sensitive_merge_rejects_conflicting_exit() {
        let key = (GuestVa(0x4008), types::CodeGeneration::INITIAL);
        let before = shared_sensitive_metadata(GuestVa(0x400c), None);
        let conflict = shared_sensitive_metadata(GuestVa(0x4010), None);

        assert!(matches!(
            merge_sensitive_metadata(key, before, conflict),
            Err(types::DsrError::CachePolicy(message))
                if message.contains("sensitive exit")
                    && message.contains("0x4008")
        ));
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

        let snapshot = translator.code_snapshot().expect("valid code snapshot");

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
        assert!(snapshot.trusted_routes.is_empty());
    }

    fn diagnostic_snapshot_fixture(words: &[u32]) -> ProcessTranslator {
        let translator = ProcessTranslator::new_with_host_and_route_split(
            64 * 1024,
            &TEST_HOST_JIT,
            crate::emit::TrustedRouteSplit::Enabled,
        )
        .expect("translator");
        let mut state = translator.state.write();
        let published = state.cache.publish_words(words).expect("publish");
        let entry = published.entry();
        let key = (GuestVa(0x40_0000), types::CodeGeneration::claimed(7));
        let generations = PageGenerationTable::new(4096).expect("generation table");
        state.push_published(super::PublishedBlock {
            entry,
            len: words.len() * 4,
            metadata: super::PublishedBlockMetadata::Owned {
                map: Vec::new(),
                recovery: Vec::new(),
            },
            _generation: generations.observe(key.0).expect("generation observation"),
        });
        state.blocks.insert(key, entry);
        let at = |offset: usize| types::CacheVa::published(HostVa(entry.host().raw() + offset));
        state.trusted_route_entries.insert(
            key,
            super::TrustedRouteEntries {
                fallthrough: at(0),
                direct: at(16),
                indirect: at(32),
                sequence_bytes: 12,
                common_body: at(48),
            },
        );
        drop(state);
        translator
    }

    #[test]
    fn code_snapshot_exports_validated_trusted_route_spans() {
        let translator = diagnostic_snapshot_fixture(&[
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0009,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0005,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0001,
            0xd503_201f,
        ]);

        let snapshot = translator
            .code_snapshot()
            .expect("valid diagnostic snapshot");
        let route = snapshot.trusted_routes.first().expect("one route row");
        let base = snapshot.cache_base;
        assert_eq!(route.guest_start, 0x40_0000);
        assert_eq!(route.generation, 7);
        assert_eq!(route.fallthrough, base..base + 12);
        assert_eq!(route.direct, base + 16..base + 28);
        assert_eq!(route.indirect, base + 32..base + 44);
        assert_eq!(route.fallthrough_branch, base + 12);
        assert_eq!(route.direct_branch, base + 28);
        assert_eq!(route.indirect_branch, base + 44);
        assert_eq!(route.common_body, base + 48);
        assert_eq!(route.origin, super::TrustedRouteOrigin::Owned);
    }

    #[test]
    fn code_snapshot_rejects_mismatched_trusted_route_sequences() {
        let translator = diagnostic_snapshot_fixture(&[
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0009,
            0xd503_201f,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0005,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0001,
            0xd503_201f,
        ]);

        let error = translator
            .code_snapshot()
            .expect_err("unequal trusted sequences must fail closed");
        assert!(
            error.to_string().contains("trusted route sequences differ"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn code_snapshot_rejects_trusted_route_without_block() {
        let translator = diagnostic_snapshot_fixture(&[
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0009,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0005,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0001,
            0xd503_201f,
        ]);
        translator.state.write().blocks.clear();

        let error = translator
            .code_snapshot()
            .expect_err("orphan trusted route must fail closed");
        assert!(
            error.to_string().contains("has no block"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn code_snapshot_rejects_stale_trusted_route_geometry() {
        let translator = diagnostic_snapshot_fixture(&[
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0009,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0005,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0001,
            0xd503_201f,
        ]);
        {
            let mut state = translator.state.write();
            let routes = state
                .trusted_route_entries
                .values_mut()
                .next()
                .expect("one trusted route");
            routes.direct = routes.fallthrough;
        }

        let error = translator
            .code_snapshot()
            .expect_err("stale route geometry must fail closed");
        assert!(
            error
                .to_string()
                .contains("trusted route geometry mismatch"),
            "unexpected error: {error}"
        );
    }

    /// The native-tap unit contract, end to end at the translator level:
    /// record candidates through the ONE native emission, pack them into a
    /// unit, round-trip the manifest through the serialized wire, install by
    /// per-block replay, and prove the installed blocks are
    /// INDISTINGUISHABLE from native translations — word-identical code,
    /// trusted entries registered, and cross-block direct links patched to
    /// land PAST the generation guard. This is the store side of the
    /// 2026-08-03 parity mechanism
    /// (`docs/perf-results/2026-08-03-store-template-parity-mechanism.md`):
    /// the emission side pinned word identity of the RECORDING
    /// (`emit::tests::recorded_emission_is_word_identical_to_native_emission`);
    /// these pin word identity of the INSTALL.
    mod native_tap_unit_install {
        use super::TEST_HOST_JIT;
        use crate::block::{BlockPlan, PlannedExit};
        use crate::mapped_memory::NativeMappedMemory;
        use crate::shared_cache::{
            AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
            NativePageProfileIdentity, PendingTranslationUnit, PortableBlockCandidate,
            SharedLoadedTranslationUnit, SourceFingerprint, TranslationUnitKey,
            decode_translation_unit_metadata, encode_translation_unit_metadata,
        };
        use crate::translator::{
            AttachedReplayOutcome, ProcessTranslator, encode_aarch64_direct_branch,
        };
        use crate::types::{CodeGeneration, DirectExit, DirectKind};
        use crate::{emit, types};
        use carrick_dsr::cache;
        use carrick_guest_mem::GuestVa;
        use std::sync::Arc;

        const BLOCK_A: GuestVa = GuestVa(0x40_0000);
        const BLOCK_B: GuestVa = GuestVa(0x40_0100);

        fn unit_key() -> TranslationUnitKey {
            TranslationUnitKey::for_segment(
                ExecutableIdentity::Digest([0x7a; 32]),
                ImageFileOffset::new(0),
                ImageFileLen::new(0x4000).expect("file length"),
                BLOCK_A,
                GuestCodeLen::new(0x4000).expect("guest length"),
                SourceFingerprint::from_words(&[0x1400_0001, 0xd400_0001]),
                NativePageProfileIdentity::Native16k,
                AddressModeIdentity::Direct,
            )
        }

        fn syscall_plan(start: GuestVa) -> BlockPlan {
            BlockPlan {
                start,
                end: GuestVa(start.raw() + 4),
                generation: CodeGeneration::INITIAL,
                instructions: Vec::new(),
                exit: PlannedExit::Syscall {
                    guest: start,
                    resume: GuestVa(start.raw() + 4),
                },
                extensions: Vec::new(),
            }
        }

        fn branch_plan(start: GuestVa, target: GuestVa) -> BlockPlan {
            BlockPlan {
                start,
                end: GuestVa(start.raw() + 4),
                generation: CodeGeneration::INITIAL,
                instructions: Vec::new(),
                exit: PlannedExit::Direct {
                    guest: start,
                    word: 0x1400_0001,
                    exit: DirectExit {
                        kind: DirectKind::Branch,
                        target,
                        resume: GuestVa(start.raw() + 4),
                        condition: None,
                        register: None,
                        bit: None,
                    },
                },
                extensions: Vec::new(),
            }
        }

        /// Record a candidate through the native tap against the SAME
        /// generation cell the install will observe, returning the candidate
        /// and the native reference emission for word comparison.
        fn record_candidate(
            memory: &NativeMappedMemory,
            plan: &BlockPlan,
        ) -> (PortableBlockCandidate, emit::EmittedBlock, Vec<u32>) {
            record_candidate_with_route_split(memory, plan, emit::TrustedRouteSplit::Disabled)
        }

        fn record_candidate_with_route_split(
            memory: &NativeMappedMemory,
            plan: &BlockPlan,
            route_split: emit::TrustedRouteSplit,
        ) -> (PortableBlockCandidate, emit::EmittedBlock, Vec<u32>) {
            let observation = memory
                .dsr_generation_observation(plan.start)
                .expect("record-time observation");
            let mut scratch = crate::test_jit::test_cache(256 * 1024);
            let (emitted, artifact) = emit::emit_block_recording_artifact_with_route_split(
                &mut scratch,
                plan,
                emit::GenerationGuard::new(observation.current_atomic(), CodeGeneration::INITIAL),
                emit::EmitAddressMode::Direct,
                vec![0xd503_201f],
                route_split,
            )
            .expect("record native-tap candidate");
            // Capture the reference words BEFORE any patching can occur.
            let words = read_words(emitted.entry(), emitted.len());
            (
                PortableBlockCandidate {
                    guest_start: plan.start,
                    requires_sensitive_metadata: false,
                    template: artifact.template,
                },
                emitted,
                words,
            )
        }

        fn read_words(entry: types::CacheVa, len: usize) -> Vec<u32> {
            // SAFETY: the test JIT is plain RW anonymous memory owned by the
            // cache for the duration of the test.
            let bytes = unsafe { std::slice::from_raw_parts(entry.host().raw() as *const u8, len) };
            bytes
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
                .collect()
        }

        /// Serves exactly one pre-built unit; counts store consults so tests
        /// can pin "attached once, replayed per lookup".
        struct LookupFixtureStore {
            unit: std::sync::Mutex<Option<SharedLoadedTranslationUnit>>,
            loads: std::sync::atomic::AtomicU64,
        }

        impl crate::shared_cache::TranslationUnitStore for LookupFixtureStore {
            fn load(
                &self,
                _key: &TranslationUnitKey,
                _source_words: &[u32],
            ) -> Result<Option<SharedLoadedTranslationUnit>, crate::shared_cache::UnitMissReason>
            {
                self.loads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(self.unit.lock().expect("fixture unit lock").clone())
            }

            fn publish(
                &self,
                _pending: &PendingTranslationUnit,
            ) -> Result<crate::shared_cache::PublishOutcome, crate::shared_cache::UnitMissReason>
            {
                Ok(crate::shared_cache::PublishOutcome::Existing)
            }
        }

        struct LookupFixture {
            translator: ProcessTranslator,
            store: Arc<LookupFixtureStore>,
            _code: Arc<Vec<u8>>,
        }

        /// The segment's source words: `unit_key()` fingerprints exactly this
        /// pair, so `key_for_segment` derives the same key the unit carries.
        const SEGMENT_SOURCE_WORDS: [u32; 2] = [0x1400_0001, 0xd400_0001];

        /// Configure a translator whose shared lane serves `unit` through the
        /// REAL lookup path (`try_load_shared_unit`), not a direct install
        /// call.
        fn fixture_for_unit(
            unit: SharedLoadedTranslationUnit,
            code: Arc<Vec<u8>>,
        ) -> LookupFixture {
            fixture_for_unit_with_route_split(unit, code, emit::TrustedRouteSplit::Disabled)
        }

        fn fixture_for_unit_with_route_split(
            unit: SharedLoadedTranslationUnit,
            code: Arc<Vec<u8>>,
            route_split: emit::TrustedRouteSplit,
        ) -> LookupFixture {
            let store = Arc::new(LookupFixtureStore {
                unit: std::sync::Mutex::new(Some(unit)),
                loads: std::sync::atomic::AtomicU64::new(0),
            });
            let translator = ProcessTranslator::new_with_host_and_route_split(
                256 * 1024,
                &TEST_HOST_JIT,
                route_split,
            )
            .expect("translator");
            translator
                .configure_shared_image(
                    crate::shared_cache::SharedImageConfig {
                        executable: ExecutableIdentity::Digest([0x7a; 32]),
                        page_profile: NativePageProfileIdentity::Native16k,
                        address_mode: AddressModeIdentity::Direct,
                        segments: vec![crate::shared_cache::SharedExecutableSegment::new(
                            ImageFileOffset::new(0),
                            ImageFileLen::new(0x4000).expect("file length"),
                            BLOCK_A,
                            GuestCodeLen::new(0x4000).expect("guest length"),
                            SEGMENT_SOURCE_WORDS.to_vec().into(),
                        )],
                    },
                    Arc::clone(&store) as Arc<dyn crate::shared_cache::TranslationUnitStore>,
                )
                .expect("configure shared lookup fixture");
            LookupFixture {
                translator,
                store,
                _code: code,
            }
        }

        /// Build a unit from `candidates`, round-trip it through the wire, and
        /// serve it through a `fixture_for_unit` translator.
        fn lookup_fixture(candidates: Vec<PortableBlockCandidate>) -> LookupFixture {
            lookup_fixture_with_route_split(candidates, emit::TrustedRouteSplit::Disabled)
        }

        fn lookup_fixture_with_route_split(
            candidates: Vec<PortableBlockCandidate>,
            route_split: emit::TrustedRouteSplit,
        ) -> LookupFixture {
            let pending = PendingTranslationUnit::pack(unit_key(), candidates).expect("pack unit");
            // Round-trip the manifest through the exact wire the store
            // persists, so serde of relocations, trusted entries, direct
            // links, and run-encoded recovery is part of what this proves.
            let bytes = encode_translation_unit_metadata(
                &pending.key,
                [0; 32],
                pending.code.len() as u64,
                &pending.blocks,
            )
            .expect("encode manifest");
            let manifest =
                decode_translation_unit_metadata(Arc::new(bytes)).expect("decode manifest");
            let code = Arc::new(pending.code.clone());
            let unit = SharedLoadedTranslationUnit::new(
                manifest,
                code.as_ptr() as usize,
                Arc::clone(&code) as Arc<dyn Send + Sync>,
            );
            fixture_for_unit_with_route_split(unit, code, route_split)
        }

        /// Look one guest block up through the shared lane, as `translate`'s
        /// miss path would.
        fn lookup(
            fixture: &LookupFixture,
            memory: &NativeMappedMemory,
            guest: GuestVa,
        ) -> Result<Option<types::CacheVa>, types::DsrError> {
            fixture.translator.state.write().try_load_shared_unit(
                memory,
                guest,
                CodeGeneration::INITIAL,
            )
        }

        #[test]
        fn a_lookup_replays_only_the_looked_up_block() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (a, _native_a, words_a) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            let (b, _native_b, words_b) = record_candidate(&memory, &syscall_plan(BLOCK_B));
            let fixture = lookup_fixture(vec![a, b]);

            let entry_a = fixture
                .translator
                .state
                .write()
                .try_load_shared_unit(&memory, BLOCK_A, CodeGeneration::INITIAL)
                .expect("lookup A")
                .expect("A must be served from the unit");
            {
                let state = fixture.translator.state.read();
                assert_eq!(
                    state.blocks.get(&(BLOCK_A, CodeGeneration::INITIAL)),
                    Some(&entry_a)
                );
                assert!(
                    !state
                        .blocks
                        .contains_key(&(BLOCK_B, CodeGeneration::INITIAL)),
                    "attach must NOT eagerly replay a block that was never looked up"
                );
                assert_eq!(
                    state.stats.shared_blocks_mapped, 1,
                    "shared_blocks_mapped counts blocks REPLAYED, not blocks attached"
                );
                assert_eq!(read_words(entry_a, words_a.len() * 4), words_a);
            }

            let entry_b = fixture
                .translator
                .state
                .write()
                .try_load_shared_unit(&memory, BLOCK_B, CodeGeneration::INITIAL)
                .expect("lookup B")
                .expect("B must replay from the ATTACHED unit on its first lookup");
            let state = fixture.translator.state.read();
            assert_eq!(read_words(entry_b, words_b.len() * 4), words_b);
            assert_eq!(
                fixture
                    .store
                    .loads
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "the store is consulted once per segment; later lookups replay \
                 from the attached unit"
            );
            assert_eq!(state.stats.shared_blocks_mapped, 2);
            assert_eq!(
                state.stats.shared_translations_avoided, 2,
                "every replayed block avoided one fresh translation"
            );
        }

        /// The census contract rides on `AttachedReplayOutcome`: the lookup
        /// path records exactly one census outcome per lookup from this
        /// value, so its semantics are pinned here — served, not-covered,
        /// consumed-entry, and regenerated — hermetically, without arming
        /// the process-global census.
        #[test]
        fn replay_outcomes_distinguish_served_uncovered_and_regenerated() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (a, _native_a, _words_a) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            let (b, _native_b, _words_b) = record_candidate(&memory, &syscall_plan(BLOCK_B));
            // Recorded while the page is still INITIAL; attached only after
            // the regeneration below.
            let (a2, _native_a2, _words_a2) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            let (b2, _native_b2, _words_b2) = record_candidate(&memory, &syscall_plan(BLOCK_B));
            let fixture = lookup_fixture(vec![a, b]);

            // Consult once so the unit attaches (the consult path's census
            // record is `loaded`, not `replayed`).
            fixture
                .translator
                .state
                .write()
                .try_load_shared_unit(&memory, BLOCK_A, CodeGeneration::INITIAL)
                .expect("lookup A")
                .expect("A must be served from the unit");

            let mut state = fixture.translator.state.write();
            // A VA inside the segment that no recorded block starts at.
            let uncovered = GuestVa(BLOCK_A.raw() + 0x40);
            assert_eq!(
                state
                    .replay_attached_unit_block(&memory, uncovered)
                    .expect("uncovered lookup"),
                AttachedReplayOutcome::NotCovered,
                "a VA no unit block starts at must not be served"
            );
            let served = state
                .replay_attached_unit_block(&memory, BLOCK_B)
                .expect("replay B");
            let entry_b = *state
                .blocks
                .get(&(BLOCK_B, CodeGeneration::INITIAL))
                .expect("B published");
            assert_eq!(
                served,
                AttachedReplayOutcome::Replayed(entry_b),
                "a first lookup of an attached block replays and serves it"
            );
            assert_eq!(
                state
                    .replay_attached_unit_block(&memory, BLOCK_B)
                    .expect("replay B again"),
                AttachedReplayOutcome::NotCovered,
                "a replayed block's index entry is consumed; the private \
                 cache owns later lookups"
            );

            // Regenerate BLOCK_A's page AFTER attach: its still-indexed
            // entry is dead and must report so (and be dropped).
            let observation = memory
                .dsr_generation_observation(BLOCK_A)
                .expect("observe page");
            observation.current_atomic().store(
                CodeGeneration::INITIAL.get() + 1,
                std::sync::atomic::Ordering::Release,
            );
            // BLOCK_A itself already replayed via the consult; attach the
            // pre-regeneration recording in a fresh process instead. (BLOCK_A
            // and BLOCK_B share the fixture page, so the consult below also
            // reports the regeneration rather than serving B.)
            drop(state);
            let second = lookup_fixture(vec![a2, b2]);
            assert_eq!(
                second
                    .translator
                    .state
                    .write()
                    .try_load_shared_unit(&memory, BLOCK_B, CodeGeneration::INITIAL)
                    .expect("consult via B"),
                None,
                "a regenerated page must not serve an INITIAL-keyed block"
            );
            assert_eq!(
                second
                    .translator
                    .state
                    .write()
                    .replay_attached_unit_block(&memory, BLOCK_A)
                    .expect("replay A on a regenerated page"),
                AttachedReplayOutcome::Regenerated,
                "a regenerated page's attached entry reports Regenerated"
            );
            assert_eq!(
                second
                    .translator
                    .state
                    .write()
                    .replay_attached_unit_block(&memory, BLOCK_A)
                    .expect("replay A after the drop"),
                AttachedReplayOutcome::NotCovered,
                "a regenerated entry is dropped, not retried"
            );
        }

        /// A replayed block's pc map and recovery stay UNDECODED in the
        /// unit (the whole point of the hot/cold wire split); a fault that
        /// interrogates the block must decode them on demand and answer
        /// EXACTLY as a natively-translated block would.
        #[test]
        fn a_fault_on_a_replayed_block_decodes_unit_cold_metadata() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (a, _native_a, _words_a) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            let reference = a.template.clone();
            let fixture = lookup_fixture(vec![a]);
            let entry_a = fixture
                .translator
                .state
                .write()
                .try_load_shared_unit(&memory, BLOCK_A, CodeGeneration::INITIAL)
                .expect("lookup A")
                .expect("A must be served from the unit");

            let state = fixture.translator.state.read();
            let block = state
                .published
                .iter()
                .find(|block| block.entry == entry_a)
                .expect("replayed block is published");
            assert!(
                matches!(
                    block.metadata,
                    crate::translator::PublishedBlockMetadata::Unit { .. }
                ),
                "a replayed block must retain a UNIT metadata handle, not \
                 materialized maps"
            );
            let map = reference.pc_map_entries();
            assert!(!map.is_empty(), "the recording carries a pc map");
            for entry in map {
                let cache_pc = GuestVa(
                    u64::try_from(entry_a.host().raw()).expect("host pointer fits u64")
                        + u64::from(entry.cache.get()),
                );
                let (guest, _recovery) = state
                    .guest_pc_for_cache(cache_pc)
                    .expect("fault lowering decodes the unit's cold metadata");
                assert_eq!(
                    guest, entry.guest,
                    "cold-decoded pc map must answer like the recording"
                );
            }
            // A PC BETWEEN instruction boundaries still refuses, exactly as
            // an owned map would.
            let unmapped = GuestVa(
                u64::try_from(entry_a.host().raw()).expect("host pointer fits u64")
                    + u64::from(map[0].cache.get())
                    + 2,
            );
            assert!(
                state.guest_pc_for_cache(unmapped).is_err(),
                "a non-boundary PC must refuse from cold metadata too"
            );
        }

        /// Attach a packed unit and replay EVERY candidate block by looking
        /// each one up — the lazy equivalent of the old eager whole-unit
        /// install, for tests that assert on the fully-replayed state.
        fn attach_and_replay_all(
            memory: &NativeMappedMemory,
            candidates: Vec<PortableBlockCandidate>,
        ) -> Result<LookupFixture, types::DsrError> {
            attach_and_replay_all_with_route_split(
                memory,
                candidates,
                emit::TrustedRouteSplit::Disabled,
            )
        }

        fn attach_and_replay_all_with_route_split(
            memory: &NativeMappedMemory,
            candidates: Vec<PortableBlockCandidate>,
            route_split: emit::TrustedRouteSplit,
        ) -> Result<LookupFixture, types::DsrError> {
            let guests: Vec<GuestVa> = candidates
                .iter()
                .map(|candidate| candidate.guest_start)
                .collect();
            let fixture = lookup_fixture_with_route_split(candidates, route_split);
            for guest in guests {
                lookup(&fixture, memory, guest)?;
            }
            Ok(fixture)
        }

        #[test]
        fn installed_blocks_are_word_identical_with_registered_trusted_entries() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (candidate, _native, native_words) =
                record_candidate(&memory, &syscall_plan(BLOCK_A));
            let trusted = candidate
                .template
                .trusted_entry()
                .expect("native tap records the trusted entry");

            let installed =
                attach_and_replay_all(&memory, vec![candidate]).expect("replay native-tap unit");
            let state = installed.translator.state.read();
            let key = (BLOCK_A, CodeGeneration::INITIAL);
            let entry = *state.blocks.get(&key).expect("installed block");
            assert_eq!(
                state.trusted_entries.get(&key).map(|offset| offset.get()),
                Some(trusted.offset),
                "the installed block registers the SAME trusted entry native \
                 emission exposes — patched links will land past the guard"
            );
            let installed_words = read_words(entry, native_words.len() * 4);
            assert_eq!(
                installed_words, native_words,
                "replayed unit block must be word-identical to the native \
                 emission against the same generation cell"
            );
        }

        #[test]
        fn cross_block_direct_links_patch_to_the_target_trusted_entry() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (branch, native_branch, branch_words) =
                record_candidate(&memory, &branch_plan(BLOCK_A, BLOCK_B));
            let (target, _native_target, target_words) =
                record_candidate(&memory, &syscall_plan(BLOCK_B));
            let link = native_branch.direct_links()[0];

            let installed = attach_and_replay_all(&memory, vec![branch, target])
                .expect("replay two-block unit");
            let state = installed.translator.state.read();
            let entry_a = *state
                .blocks
                .get(&(BLOCK_A, CodeGeneration::INITIAL))
                .expect("installed branch block");
            let entry_b = *state
                .blocks
                .get(&(BLOCK_B, CodeGeneration::INITIAL))
                .expect("installed target block");
            let trusted_b = *state
                .trusted_entries
                .get(&(BLOCK_B, CodeGeneration::INITIAL))
                .expect("target trusted entry");

            let installed_a = read_words(entry_a, branch_words.len() * 4);
            let slot_index = (link.slot.get() / 4) as usize;
            let expected_branch = encode_aarch64_direct_branch(
                cache::LinkSite {
                    source: entry_a,
                    slot: link.slot,
                },
                types::CacheVa::published(carrick_guest_mem::HostVa(
                    entry_b.host().raw() + trusted_b.get() as usize,
                )),
            )
            .expect("encode expected patched link");
            assert_eq!(
                installed_a[slot_index], expected_branch,
                "the A->B edge must be a patched direct branch landing at \
                 B's trusted entry, past the generation guard"
            );
            // Every word except the patched slot is the native emission.
            for (index, (installed, native)) in installed_a.iter().zip(&branch_words).enumerate() {
                if index != slot_index {
                    assert_eq!(installed, native, "word {index} diverges");
                }
            }
            let installed_b = read_words(entry_b, target_words.len() * 4);
            assert_eq!(installed_b, target_words);
        }

        #[test]
        fn diagnostic_replay_routes_direct_links_to_only_the_direct_copy() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (branch, native_branch, branch_words) = record_candidate_with_route_split(
                &memory,
                &branch_plan(BLOCK_A, BLOCK_B),
                emit::TrustedRouteSplit::Enabled,
            );
            let (target, _native_target, _target_words) = record_candidate_with_route_split(
                &memory,
                &syscall_plan(BLOCK_B),
                emit::TrustedRouteSplit::Enabled,
            );
            let link = native_branch.direct_links()[0];

            let installed = attach_and_replay_all_with_route_split(
                &memory,
                vec![branch, target],
                emit::TrustedRouteSplit::Enabled,
            )
            .expect("replay diagnostic two-block unit");
            let state = installed.translator.state.read();
            let entry_a = *state
                .blocks
                .get(&(BLOCK_A, CodeGeneration::INITIAL))
                .expect("installed branch block");
            let routes_b = *state
                .trusted_route_entries
                .get(&(BLOCK_B, CodeGeneration::INITIAL))
                .expect("target diagnostic routes");

            assert_ne!(routes_b.fallthrough, routes_b.direct);
            assert_ne!(routes_b.direct, routes_b.indirect);
            let installed_a = read_words(entry_a, branch_words.len() * 4);
            let slot_index = (link.slot.get() / 4) as usize;
            let expected_branch = encode_aarch64_direct_branch(
                cache::LinkSite {
                    source: entry_a,
                    slot: link.slot,
                },
                routes_b.direct,
            )
            .expect("encode diagnostic direct route");
            assert_eq!(
                installed_a[slot_index], expected_branch,
                "patched direct link must land only at the direct route copy"
            );
            let snapshot = installed
                .translator
                .code_snapshot()
                .expect("replayed route snapshot");
            assert!(
                snapshot.trusted_routes.iter().all(|route| {
                    route.origin == crate::translator::TrustedRouteOrigin::UnitReplay
                }),
                "every installed route must retain its unit-replay origin"
            );
        }

        #[test]
        fn diagnostic_flavor_one_publication_uses_only_the_indirect_copy() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (target, _native_target, _target_words) = record_candidate_with_route_split(
                &memory,
                &syscall_plan(BLOCK_B),
                emit::TrustedRouteSplit::Enabled,
            );
            let installed = attach_and_replay_all_with_route_split(
                &memory,
                vec![target],
                emit::TrustedRouteSplit::Enabled,
            )
            .expect("replay diagnostic target");
            let process = Arc::new(installed.translator);
            let (entry, routes) = {
                let state = process.state.read();
                (
                    *state
                        .blocks
                        .get(&(BLOCK_B, CodeGeneration::INITIAL))
                        .expect("installed target block"),
                    *state
                        .trusted_route_entries
                        .get(&(BLOCK_B, CodeGeneration::INITIAL))
                        .expect("target diagnostic routes"),
                )
            };
            let translated = crate::translator::TranslationResult {
                entry,
                generation: CodeGeneration::INITIAL,
                outcome: crate::translator::TranslationOutcome::SharedUnit,
                emitted_bytes: 0,
                cache_used_bytes: 0,
            };
            let mut thread = crate::translator::ThreadTranslator::for_process(process, 17);
            thread
                .publish_indirect_target(&memory, BLOCK_B, &translated)
                .expect("publish flavor-1 target");
            let (_tagged_generation, _generation_atomic, trusted_code) = thread
                .indirect_cache
                .entry_snapshot(BLOCK_B)
                .expect("published indirect cache entry");
            assert_eq!(
                trusted_code,
                routes.indirect.host().raw() as u64,
                "flavor-1 cache must publish only the indirect route copy"
            );
        }

        #[test]
        fn a_corrupt_code_image_fails_closed_to_translation() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (candidate, _native, _words) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            let pending =
                PendingTranslationUnit::pack(unit_key(), vec![candidate]).expect("pack unit");
            let manifest = crate::shared_cache::TranslationUnitManifest::from_blocks(
                &pending.key,
                [0; 32],
                pending.code.len() as u64,
                &pending.blocks,
            )
            .expect("round-trip corrupt-image manifest");
            // Corrupt the first relocation site (the guard's
            // generation-address materialization): replay's opcode
            // validation must refuse rather than publish wrong code.
            let mut code = pending.code.clone();
            let first_relocation_word = pending
                .blocks
                .iter()
                .find_map(|block| {
                    block
                        .template
                        .first_relocation_word_for_test()
                        .map(|offset| (block.entry_offset / 4 + offset) as usize)
                })
                .expect("native tap records process relocations");
            code[first_relocation_word * 4..first_relocation_word * 4 + 4]
                .copy_from_slice(&0xd503_201f_u32.to_le_bytes());
            let code = Arc::new(code);
            let unit = SharedLoadedTranslationUnit::new(
                manifest,
                code.as_ptr() as usize,
                Arc::clone(&code) as Arc<dyn Send + Sync>,
            );
            let fixture = fixture_for_unit(unit, code);
            // Replay validation refuses the corrupt words: the lookup FALLS
            // BACK to private translation (no guest-visible error) and the
            // unit is detached so no other block of it can publish.
            let first = lookup(&fixture, &memory, BLOCK_A).expect("lookup survives refusal");
            assert_eq!(first, None, "a refused block must fall back, not serve");
            assert!(
                fixture.translator.state.read().blocks.is_empty(),
                "no block may publish from a refused unit"
            );
            let second = lookup(&fixture, &memory, BLOCK_A).expect("second lookup");
            assert_eq!(second, None, "a detached unit must not retry replay");
            assert_eq!(
                fixture
                    .store
                    .loads
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "the refusal must not re-consult the store"
            );
        }

        #[test]
        fn a_regenerated_page_skips_installation_without_error() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (candidate, _native, _words) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            // Regenerate the page between record and install.
            let observation = memory
                .dsr_generation_observation(BLOCK_A)
                .expect("observe page");
            observation.current_atomic().store(
                CodeGeneration::INITIAL.get() + 1,
                std::sync::atomic::Ordering::Release,
            );

            let installed = attach_and_replay_all(&memory, vec![candidate])
                .expect("lookup skips the stale block");
            let state = installed.translator.state.read();
            assert!(
                state.blocks.is_empty(),
                "a block recorded at INITIAL must not publish on a regenerated page"
            );
            assert!(state.trusted_entries.is_empty());
        }

        #[test]
        fn install_registers_page_dependencies_for_invalidation() {
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let (candidate, _native, _words) = record_candidate(&memory, &syscall_plan(BLOCK_A));
            let installed =
                attach_and_replay_all(&memory, vec![candidate]).expect("replay native-tap unit");
            let mut state = installed.translator.state.write();
            let key = (BLOCK_A, CodeGeneration::INITIAL);
            assert!(state.blocks.contains_key(&key));
            // Guest code-page replacement: the dependency recorded through
            // `publish_emitted` must invalidate the installed block exactly
            // like a natively-translated one.
            let observation = memory
                .dsr_generation_observation(BLOCK_A)
                .expect("observe page");
            let page = observation.page();
            let stale = state
                .dependencies
                .invalidate_page(page, CodeGeneration::claimed(2));
            assert!(
                stale.contains(&key),
                "installed block must be registered for page invalidation: {stale:?}"
            );
        }
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
        use crate::translator::{
            ProcessState, ProcessTranslator, PublishedBlock, PublishedBlockMetadata,
        };
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
                metadata: PublishedBlockMetadata::Owned {
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
                },
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

        /// Index a block whose code is NOT in the private cache. Real
        /// shared units are copied INTO the cache now, but the shared index
        /// must stay correct for entries at arbitrary addresses -- this
        /// fixture pins the ordering behavior for the non-cache case.
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
                    physical_reserved: 0,
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
                    physical_reserved: 0,
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

/// Translation redundancy census: how much of a cold build's ~433k translations
/// is the SAME guest code re-translated in a different process, and how much of
/// it could a shared translation unit ever have served?
///
/// This is the number that decides whether translation amortization is a
/// 2x-of-Docker-class lever or a dead end, and no existing instrument answers
/// it: `CARRICK_DSR_PROFILE` counts translations per process but says nothing
/// about distinctness ACROSS processes, and the shared-translation lane's own
/// 14% reduction (1,196,909 -> 1,031,914) reflects its coverage ceiling rather
/// than the underlying redundancy.
///
/// Env-gated on `CARRICK_XLAT_CENSUS_DIR` so it costs one relaxed load and a
/// branch when unset. Every record carries, besides the block's entry guest VA:
///
/// * the **translation unit identity** the block belongs to -- the `file_stem()`
///   of the `TranslationUnitKey` the shared lane would mint for the containing
///   segment. That is what turns a distinct-VA count into a distinct-unit-key
///   count, which is the quantity the AOT-cache workstream is sized against.
/// * the block's **coverage** relative to that segment
///   ([`xlat_census::SegmentCoverage`]).
///   The runtime uses two different containment predicates -- a unit LOOKUP
///   keys on the entry VA alone (`try_load_shared_unit`) while today's
///   PRODUCER only records a block whose whole range fits inside one segment
///   (`record_portable_block_artifact`) -- so a single fraction would either
///   overstate the ceiling or understate what is publishable. Both are
///   derivable from these records.
///
/// ## Store attribution
///
/// A cache directory holding exactly ONE unit key is the finding this census
/// exists to explain, and the coverage records above cannot explain it on their
/// own: they say where the blocks were, not what the store did about them.
/// [`xlat_census::CensusStore`] closes that gap by counting, per process, the
/// outcome of every shared-unit lookup `try_load_shared_unit` attempts --
/// including the ones that return before the store is touched at all.
///
/// The distinction that matters is between **never consulted** and
/// **consulted and missed**, because they imply opposite fixes. A lookup is
/// skipped for one of four reasons ([`xlat_census::LookupSkip`]) -- the code
/// generation moved, the lane installed no configuration in this process, the
/// block is outside every configured segment, or this process already consulted
/// that segment once. Only a lookup that survives all four reaches
/// `TranslationUnitStore::load`, and its result is then counted as loaded, a
/// file miss (with the `claim_recording` election's verdict), or a typed
/// [`crate::shared_cache::UnitMissReason`]. `no-authority` is a first-class
/// reason rather than an alias of `missing-pair` precisely so a descendant that
/// never adopted the container cache stops reading as a process whose lookups
/// merely missed.
///
/// Two identities hold by construction and are re-checked at parse time, so a
/// future return path added without a counter is caught rather than silently
/// under-counting: `consulted == loaded + file_miss + sum(misses)` and
/// `recording_claimed + recording_declined == file_miss`.
///
/// The image identity is installed from `configure_shared_translation`
/// **whether or not the shared lane is enabled**, so the census describes the
/// DEFAULT path rather than the lane-on arm. Enumerating segments costs one
/// SHA-256 over the executable spans per process image, and is paid only when
/// the census is armed.
///
/// ## Flush coverage
///
/// The dump used to be a bare `libc::atexit` hook, which on this lane fires for
/// exactly ONE terminal path (the post-`execve` resume incarnation's
/// `std::process::exit`). Every other guest process -- the container's pid 1,
/// every fork child that exits without exec'ing, and the pre-exec incarnation
/// of every fork+exec child -- dies at `libc::_exit` or `libc::execve` and lost
/// its census entirely. Measured on a three-process shell fixture, that was
/// 60.9% of translations recorded and pid 1 (37.7% of the total) invisible.
///
/// Flushing is now explicit at the two seams that own it: every process exit
/// funnels through `finalize_native_process_exit`, and both `execve` shapes
/// (the host self-re-exec and the in-process image replacement) flush before
/// the old image is gone. [`xlat_census::flush`] DRAINS, so a later flush of an
/// already-drained process writes nothing and the `atexit` hook survives only
/// as a backstop.
///
/// **Still not covered, by construction:** a process killed by a fatal signal
/// (guest SIGSEGV, `scripts/sudo/kill.sh`, the trap-limit kill) never runs any
/// flush. A census taken over a run with kills is a lower bound and must say so.
///
/// Caveat the consumer must apply: the native lane loads PIE guests at a FIXED
/// base, so two DIFFERENT guest binaries can translate the same VA. A union
/// over VAs therefore UNDER-counts distinct code and OVER-states redundancy --
/// which is exactly why the unit stem is recorded beside it: stems are
/// content-addressed and do not alias.
pub mod xlat_census {
    use crate::shared_cache::SharedImageConfig;
    /// Part of the census file model: a `MISS` line's reason. Re-exported here
    /// so an out-of-crate aggregator parses the census with the SAME typed
    /// vocabulary the runtime wrote it with, instead of matching on strings.
    pub use crate::shared_cache::UnitMissReason;
    use carrick_guest_mem::GuestVa;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    /// Schema tag on line 1 of every census file. Bump it when a field's
    /// meaning changes; [`CensusFile::parse`] fails closed on anything else.
    /// V4: the STORE line gained `replayed=` (lookups served by lazily
    /// replaying a block from an already-attached unit), and `segment-repeat`
    /// narrowed to "consulted segment, block NOT covered by its unit".
    pub const CENSUS_SCHEMA: &str = "XLATCENSUS4";

    /// Where a translated block sits relative to this process's configured
    /// shared-translation segments.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub enum SegmentCoverage {
        /// The entry VA is outside every configured segment. No translation
        /// unit of any design could serve this block: it is the population that
        /// bounds the whole workstream from above.
        Outside,
        /// The entry VA is inside a segment but the block runs past that
        /// segment's end. A unit lookup would hit; today's producer refuses to
        /// record it.
        EntryOnly,
        /// The whole block lies inside one segment. This is the geometric
        /// NECESSARY condition for `record_portable_block_artifact` to accept
        /// the block; it is NOT sufficient, and must not be read as "today's
        /// producer publishes this". Recording is additionally gated on an
        /// `INITIAL` generation, a WON recorder election for the segment,
        /// available source words, and a terminal exit outside the
        /// `Unsupported`/`ExclusiveRegion` set -- so on the default (lane-off)
        /// path the truly-published share of `Contained` is exactly zero.
        Contained,
    }

    impl SegmentCoverage {
        /// Wire token used in the census file.
        pub const fn token(self) -> &'static str {
            match self {
                Self::Outside => "outside",
                Self::EntryOnly => "entry",
                Self::Contained => "contained",
            }
        }

        fn from_token(token: &str) -> Option<Self> {
            match token {
                "outside" => Some(Self::Outside),
                "entry" => Some(Self::EntryOnly),
                "contained" => Some(Self::Contained),
                _ => None,
            }
        }
    }

    /// Why a fresh translation never reached the shared-unit store.
    ///
    /// `ProcessState::try_load_shared_unit` runs on every block-index miss and
    /// returns early for one of these four reasons. Counting them is what
    /// separates "the store was consulted and missed" from "the store was never
    /// consulted", which is the difference between a persistence problem and a
    /// coverage problem.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub enum LookupSkip {
        /// The block's code generation is not `INITIAL`: guest code at this VA
        /// was mutated, so no published unit can describe it.
        Regenerated,
        /// This process installed no shared-translation configuration: the
        /// hatch (`CARRICK_DSR_PERSISTENT_STORE=0`) is set, or the image
        /// yielded no executable segment.
        LaneUnconfigured,
        /// The block's entry VA lies outside every configured segment -- the
        /// population no unit of any design can serve.
        OutsideSegment,
        /// This process already consulted the containing segment once, and
        /// the block is NOT served by an attached unit (outside the unit's
        /// recorded set, dropped after a per-block refusal, or no unit
        /// loaded). Lookups an attached unit DOES serve are counted as
        /// `replayed` on the STORE line, not here.
        SegmentRepeat,
    }

    impl LookupSkip {
        /// Every skip reason, in wire order; the census counter index is a
        /// position in this table.
        pub const ALL: [Self; 4] = [
            Self::Regenerated,
            Self::LaneUnconfigured,
            Self::OutsideSegment,
            Self::SegmentRepeat,
        ];

        /// Wire token used in the census file.
        pub const fn token(self) -> &'static str {
            match self {
                Self::Regenerated => "regenerated",
                Self::LaneUnconfigured => "lane-unconfigured",
                Self::OutsideSegment => "outside-segment",
                Self::SegmentRepeat => "segment-repeat",
            }
        }

        fn from_token(token: &str) -> Option<Self> {
            Self::ALL.into_iter().find(|skip| skip.token() == token)
        }

        /// Position in [`Self::ALL`].
        const fn index(self) -> usize {
            match self {
                Self::Regenerated => 0,
                Self::LaneUnconfigured => 1,
                Self::OutsideSegment => 2,
                Self::SegmentRepeat => 3,
            }
        }
    }

    /// What this process's shared-unit lookups did.
    ///
    /// Empty (every field zero, both maps empty) for a process that performed
    /// no translation at all. A process that translated always populates at
    /// least one `skipped` bucket, because every block-index miss passes
    /// through `try_load_shared_unit`.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct CensusStore {
        /// Lookups that reached `TranslationUnitStore::load`.
        pub consulted: u64,
        /// Lookups that returned a unit.
        pub loaded: u64,
        /// Lookups served WITHOUT touching the store, by replaying a block
        /// from an already-attached unit on its first lookup. Not part of
        /// the `consulted` identity — the store was not consulted.
        pub replayed: u64,
        /// Lookups whose unit files were absent from the store.
        pub file_miss: u64,
        /// File misses where `claim_recording` elected this process as the
        /// recorder. Today's election declines the FIRST sighting of a key, so
        /// a run with `claimed == 0` and `declined > 0` says the election, not
        /// the store, is where publication stops.
        pub recording_claimed: u64,
        /// File misses where `claim_recording` declined.
        pub recording_declined: u64,
        /// Lookups that never reached the store, by reason.
        pub skipped: BTreeMap<LookupSkip, u64>,
        /// Lookups the store refused, by typed reason.
        pub misses: BTreeMap<UnitMissReason, u64>,
        /// Wall nanoseconds this process spent inside
        /// `TranslationUnitStore::load` (open, map, validate). Paid by every
        /// process that consults, whether or not it gets a unit.
        pub load_ns: u64,
        /// Wall nanoseconds this process spent inside
        /// `TranslationUnitStore::publish` (encode, write, link, sign). Paid
        /// only by the elected recorder.
        pub publish_ns: u64,
    }

    impl CensusStore {
        /// True when this process recorded no lookup activity at all.
        pub fn is_empty(&self) -> bool {
            self.consulted == 0
                && self.loaded == 0
                && self.replayed == 0
                && self.file_miss == 0
                && self.recording_claimed == 0
                && self.recording_declined == 0
                && self.skipped.is_empty()
                && self.misses.is_empty()
        }

        /// Lookups that never reached the store.
        pub fn skipped_total(&self) -> u64 {
            self.skipped
                .values()
                .fold(0u64, |sum, count| sum.saturating_add(*count))
        }

        /// Store refusals, summed over reasons.
        pub fn miss_total(&self) -> u64 {
            self.misses
                .values()
                .fold(0u64, |sum, count| sum.saturating_add(*count))
        }
    }

    /// Which seam drained the census. Recorded so an aggregator can tell a
    /// complete process record from a partial one without guessing.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum CensusFlush {
        /// `finalize_native_process_exit`: the last live thread of a guest
        /// process retired. Covers the container's pid 1, `exit_group`, and
        /// every fork child that exits without exec'ing.
        ProcessExit,
        /// A fork child is about to become another image through carrick's host
        /// self-re-exec. `libc::execve` runs no `atexit` handler and the
        /// successor keeps this pid.
        HostSelfReexec,
        /// A single-threaded `execve` replacing the image in place. carrick's
        /// own statics survive it, so without this flush two guest images'
        /// records would merge into one file under a fixed PIE base.
        InProcessExec,
        /// The `libc::atexit` backstop. Writes nothing when an explicit flush
        /// already drained this process.
        AtexitBackstop,
    }

    impl CensusFlush {
        /// Wire token used in the census file header.
        pub const fn token(self) -> &'static str {
            match self {
                Self::ProcessExit => "process-exit",
                Self::HostSelfReexec => "host-self-reexec",
                Self::InProcessExec => "in-process-exec",
                Self::AtexitBackstop => "atexit-backstop",
            }
        }

        fn from_token(token: &str) -> Option<Self> {
            match token {
                "process-exit" => Some(Self::ProcessExit),
                "host-self-reexec" => Some(Self::HostSelfReexec),
                "in-process-exec" => Some(Self::InProcessExec),
                "atexit-backstop" => Some(Self::AtexitBackstop),
                _ => None,
            }
        }
    }

    /// One configured executable segment and the translation-unit identity the
    /// shared lane would key it on.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CensusSegment {
        pub guest_start: GuestVa,
        pub guest_len: u64,
        /// Hex `TranslationUnitKey::file_stem()`; `-` when the key could not be
        /// serialized (which would also mean the lane could not publish it).
        pub unit_stem: String,
    }

    /// The process image the records below belong to.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CensusImage {
        /// Hex `ExecutableIdentity::Digest`, or `-` for a `HostFile` identity.
        pub identity: String,
        pub segments: Vec<CensusSegment>,
    }

    /// One distinct (entry VA, segment, coverage) triple and how many fresh
    /// translations this process spent on it.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CensusRecord {
        pub guest_va: GuestVa,
        /// Index into [`CensusImage::segments`]; `None` when
        /// [`SegmentCoverage::Outside`].
        pub segment: Option<u32>,
        pub coverage: SegmentCoverage,
        pub translations: u64,
    }

    /// A single drained census, as written to `xlat-<pid>-<stamp>-<seq>.txt`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CensusFile {
        pub pid: i32,
        /// This process's flush ordinal, from 0.
        pub sequence: u64,
        pub reason: CensusFlush,
        /// Fresh translations this process performed since the previous flush.
        pub total: u64,
        pub image: Option<CensusImage>,
        pub records: Vec<CensusRecord>,
        /// What this process's shared-unit lookups did. Drained by the same
        /// flush, so a file is one process incarnation's complete story.
        pub store: CensusStore,
    }

    /// A census file that does not parse. Fails closed: an aggregator must
    /// report the bad file rather than silently averaging over fewer processes.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CensusParseError {
        /// 1-based line number.
        pub line: usize,
        pub reason: String,
    }

    impl std::fmt::Display for CensusParseError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "line {}: {}", self.line, self.reason)
        }
    }

    impl std::error::Error for CensusParseError {}

    impl CensusFile {
        /// Render the census file's exact on-disk text.
        pub fn render(&self) -> String {
            use std::fmt::Write as _;
            let (identity, segment_count) = self.image.as_ref().map_or(("-", 0usize), |image| {
                (image.identity.as_str(), image.segments.len())
            });
            let mut out = format!(
                "{CENSUS_SCHEMA}|pid={}|seq={}|reason={}|total={}|distinct={}|image={identity}|segments={segment_count}\n",
                self.pid,
                self.sequence,
                self.reason.token(),
                self.total,
                self.records.len(),
            );
            let _ = writeln!(
                out,
                "STORE|consulted={}|loaded={}|replayed={}|file_miss={}|recording_claimed={}|recording_declined={}|load_ns={}|publish_ns={}",
                self.store.consulted,
                self.store.loaded,
                self.store.replayed,
                self.store.file_miss,
                self.store.recording_claimed,
                self.store.recording_declined,
                self.store.load_ns,
                self.store.publish_ns,
            );
            for (skip, count) in &self.store.skipped {
                let _ = writeln!(out, "SKIP|{}|{count}", skip.token());
            }
            for (reason, count) in &self.store.misses {
                let _ = writeln!(out, "MISS|{}|{count}", reason.token());
            }
            if let Some(image) = &self.image {
                for (index, segment) in image.segments.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "SEG|{index}|{:#x}|{:#x}|{}",
                        segment.guest_start.raw(),
                        segment.guest_len,
                        segment.unit_stem
                    );
                }
            }
            for record in &self.records {
                let segment = record
                    .segment
                    .map_or_else(|| "-".to_string(), |index| index.to_string());
                let _ = writeln!(
                    out,
                    "VA|{:#x}|{segment}|{}|{}",
                    record.guest_va.raw(),
                    record.coverage.token(),
                    record.translations
                );
            }
            out
        }

        /// Parse the text [`CensusFile::render`] produces. One definition of the
        /// format, shared by the writer and by whatever aggregates it.
        pub fn parse(text: &str) -> Result<Self, CensusParseError> {
            let mut lines = text.lines().enumerate();
            let (header_index, header) = lines.next().ok_or_else(|| CensusParseError {
                line: 1,
                reason: "census file is empty".to_string(),
            })?;
            let header_line = header_index.saturating_add(1);
            let fields = parse_header(header, header_line)?;
            let identity = field(&fields, "image", header_line)?.to_string();
            let segment_count = parse_u64(field(&fields, "segments", header_line)?, header_line)?;
            let mut file = Self {
                pid: parse_i32(field(&fields, "pid", header_line)?, header_line)?,
                sequence: parse_u64(field(&fields, "seq", header_line)?, header_line)?,
                reason: CensusFlush::from_token(field(&fields, "reason", header_line)?)
                    .ok_or_else(|| CensusParseError {
                        line: header_line,
                        reason: "unknown flush reason".to_string(),
                    })?,
                total: parse_u64(field(&fields, "total", header_line)?, header_line)?,
                // `image=-` with `segments=0` is the "no image was configured"
                // encoding; `configure_image` never installs an empty one.
                image: (identity != "-" || segment_count != 0).then(|| CensusImage {
                    identity,
                    segments: Vec::new(),
                }),
                records: Vec::new(),
                store: CensusStore::default(),
            };
            let distinct = parse_u64(field(&fields, "distinct", header_line)?, header_line)?;
            let mut saw_store = false;
            for (index, line) in lines {
                let line_number = index.saturating_add(1);
                let mut columns = line.split('|');
                match columns.next() {
                    Some("STORE") => {
                        if saw_store {
                            return Err(CensusParseError {
                                line: line_number,
                                reason: "census file has a second STORE line".to_string(),
                            });
                        }
                        let mut parsed = parse_store(line, line_number)?;
                        // Carry over any `SKIP`/`MISS` lines that preceded this
                        // one. `parse_store` reads the scalar fields and returns
                        // empty maps, so a wholesale `file.store = parsed` would
                        // discard those counts silently -- and neither
                        // construction identity below covers the maps, so the
                        // loss would parse clean and report zero.
                        parsed.skipped = std::mem::take(&mut file.store.skipped);
                        parsed.misses = std::mem::take(&mut file.store.misses);
                        file.store = parsed;
                        saw_store = true;
                    }
                    Some("SKIP") => {
                        let (skip, count) = parse_skip(&mut columns, line_number)?;
                        let entry = file.store.skipped.entry(skip).or_insert(0);
                        *entry = entry.saturating_add(count);
                    }
                    Some("MISS") => {
                        let (reason, count) = parse_miss(&mut columns, line_number)?;
                        let entry = file.store.misses.entry(reason).or_insert(0);
                        *entry = entry.saturating_add(count);
                    }
                    Some("SEG") => {
                        let segment = parse_segment(&mut columns, line_number)?;
                        let image = file.image.as_mut().ok_or_else(|| CensusParseError {
                            line: line_number,
                            reason: "segment line without a configured image".to_string(),
                        })?;
                        image.segments.push(segment);
                    }
                    Some("VA") => file.records.push(parse_record(&mut columns, line_number)?),
                    _ => {
                        return Err(CensusParseError {
                            line: line_number,
                            reason: "expected a STORE, SKIP, MISS, SEG or VA line".to_string(),
                        });
                    }
                }
            }
            if !saw_store {
                return Err(CensusParseError {
                    line: header_line,
                    reason: "census file has no STORE line".to_string(),
                });
            }
            // Identities that hold by construction at the recording site. A
            // future early return added to `try_load_shared_unit` without a
            // counter breaks one of them, so the parser is the backstop rather
            // than the aggregate silently under-counting.
            let accounted = file
                .store
                .loaded
                .saturating_add(file.store.file_miss)
                .saturating_add(file.store.miss_total());
            if accounted != file.store.consulted {
                return Err(CensusParseError {
                    line: header_line,
                    reason: format!(
                        "store consulted={} but outcomes account for {accounted}",
                        file.store.consulted
                    ),
                });
            }
            let elections = file
                .store
                .recording_claimed
                .saturating_add(file.store.recording_declined);
            if elections != file.store.file_miss {
                return Err(CensusParseError {
                    line: header_line,
                    reason: format!(
                        "store file_miss={} but {elections} recording elections were counted",
                        file.store.file_miss
                    ),
                });
            }
            let declared_segments = usize::try_from(segment_count).unwrap_or(usize::MAX);
            let actual_segments = file.image.as_ref().map_or(0, |image| image.segments.len());
            if declared_segments != actual_segments {
                return Err(CensusParseError {
                    line: header_line,
                    reason: format!(
                        "header declares {declared_segments} segments, file has {actual_segments}"
                    ),
                });
            }
            if usize::try_from(distinct).unwrap_or(usize::MAX) != file.records.len() {
                return Err(CensusParseError {
                    line: header_line,
                    reason: format!(
                        "header declares {distinct} distinct entries, file has {}",
                        file.records.len()
                    ),
                });
            }
            Ok(file)
        }
    }

    fn parse_header(header: &str, line: usize) -> Result<Vec<(&str, &str)>, CensusParseError> {
        let mut parts = header.split('|');
        if parts.next() != Some(CENSUS_SCHEMA) {
            return Err(CensusParseError {
                line,
                reason: format!("expected schema {CENSUS_SCHEMA}"),
            });
        }
        parts
            .map(|part| {
                part.split_once('=').ok_or_else(|| CensusParseError {
                    line,
                    reason: format!("header field {part:?} is not key=value"),
                })
            })
            .collect()
    }

    fn field<'a>(
        fields: &[(&'a str, &'a str)],
        name: &str,
        line: usize,
    ) -> Result<&'a str, CensusParseError> {
        fields
            .iter()
            .find_map(|(key, value)| (*key == name).then_some(*value))
            .ok_or_else(|| CensusParseError {
                line,
                reason: format!("header is missing {name}="),
            })
    }

    fn parse_u64(value: &str, line: usize) -> Result<u64, CensusParseError> {
        value.parse().map_err(|_| CensusParseError {
            line,
            reason: format!("{value:?} is not an unsigned integer"),
        })
    }

    fn parse_i32(value: &str, line: usize) -> Result<i32, CensusParseError> {
        value.parse().map_err(|_| CensusParseError {
            line,
            reason: format!("{value:?} is not a pid"),
        })
    }

    fn parse_hex(value: &str, line: usize) -> Result<u64, CensusParseError> {
        let digits = value.strip_prefix("0x").ok_or_else(|| CensusParseError {
            line,
            reason: format!("{value:?} is not 0x-prefixed hex"),
        })?;
        u64::from_str_radix(digits, 16).map_err(|_| CensusParseError {
            line,
            reason: format!("{value:?} is not hex"),
        })
    }

    fn column<'a>(
        columns: &mut impl Iterator<Item = &'a str>,
        name: &str,
        line: usize,
    ) -> Result<&'a str, CensusParseError> {
        columns.next().ok_or_else(|| CensusParseError {
            line,
            reason: format!("missing {name} column"),
        })
    }

    fn parse_store(line_text: &str, line: usize) -> Result<CensusStore, CensusParseError> {
        let mut parts = line_text.split('|');
        if parts.next() != Some("STORE") {
            return Err(CensusParseError {
                line,
                reason: "expected a STORE line".to_string(),
            });
        }
        let fields = parts
            .map(|part| {
                part.split_once('=').ok_or_else(|| CensusParseError {
                    line,
                    reason: format!("store field {part:?} is not key=value"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CensusStore {
            consulted: parse_u64(field(&fields, "consulted", line)?, line)?,
            loaded: parse_u64(field(&fields, "loaded", line)?, line)?,
            replayed: parse_u64(field(&fields, "replayed", line)?, line)?,
            file_miss: parse_u64(field(&fields, "file_miss", line)?, line)?,
            recording_claimed: parse_u64(field(&fields, "recording_claimed", line)?, line)?,
            recording_declined: parse_u64(field(&fields, "recording_declined", line)?, line)?,
            skipped: BTreeMap::new(),
            misses: BTreeMap::new(),
            load_ns: parse_u64(field(&fields, "load_ns", line)?, line)?,
            publish_ns: parse_u64(field(&fields, "publish_ns", line)?, line)?,
        })
    }

    fn parse_skip<'a>(
        columns: &mut impl Iterator<Item = &'a str>,
        line: usize,
    ) -> Result<(LookupSkip, u64), CensusParseError> {
        let token = column(columns, "skip reason", line)?;
        let skip = LookupSkip::from_token(token).ok_or_else(|| CensusParseError {
            line,
            reason: format!("unknown lookup-skip reason {token:?}"),
        })?;
        let count = parse_u64(column(columns, "count", line)?, line)?;
        Ok((skip, count))
    }

    fn parse_miss<'a>(
        columns: &mut impl Iterator<Item = &'a str>,
        line: usize,
    ) -> Result<(UnitMissReason, u64), CensusParseError> {
        let token = column(columns, "miss reason", line)?;
        let reason = UnitMissReason::from_token(token).ok_or_else(|| CensusParseError {
            line,
            reason: format!("unknown unit-miss reason {token:?}"),
        })?;
        let count = parse_u64(column(columns, "count", line)?, line)?;
        Ok((reason, count))
    }

    fn parse_segment<'a>(
        columns: &mut impl Iterator<Item = &'a str>,
        line: usize,
    ) -> Result<CensusSegment, CensusParseError> {
        let _index = column(columns, "index", line)?;
        let guest_start = GuestVa(parse_hex(column(columns, "guest_start", line)?, line)?);
        let guest_len = parse_hex(column(columns, "guest_len", line)?, line)?;
        let unit_stem = column(columns, "unit_stem", line)?.to_string();
        Ok(CensusSegment {
            guest_start,
            guest_len,
            unit_stem,
        })
    }

    fn parse_record<'a>(
        columns: &mut impl Iterator<Item = &'a str>,
        line: usize,
    ) -> Result<CensusRecord, CensusParseError> {
        let guest_va = GuestVa(parse_hex(column(columns, "guest_va", line)?, line)?);
        let segment = match column(columns, "segment", line)? {
            "-" => None,
            raw => Some(raw.parse::<u32>().map_err(|_| CensusParseError {
                line,
                reason: format!("{raw:?} is not a segment index"),
            })?),
        };
        let coverage =
            SegmentCoverage::from_token(column(columns, "coverage", line)?).ok_or_else(|| {
                CensusParseError {
                    line,
                    reason: "unknown coverage token".to_string(),
                }
            })?;
        let translations = parse_u64(column(columns, "translations", line)?, line)?;
        Ok(CensusRecord {
            guest_va,
            segment,
            coverage,
            translations,
        })
    }

    #[derive(Default)]
    struct CensusState {
        total: u64,
        records: BTreeMap<(GuestVa, Option<u32>, SegmentCoverage), u64>,
        image: Option<CensusImage>,
    }

    /// Shared-unit lookup outcomes, as lock-free counters.
    ///
    /// Deliberately NOT inside [`CensusState`]'s mutex: `try_load_shared_unit`
    /// runs on every block-index miss, so folding it into the same lock would
    /// double the census's per-translation lock traffic. A relaxed add is
    /// enough -- these are process-scoped totals read only at a flush seam,
    /// never compared against each other mid-run.
    struct StoreCounters {
        consulted: AtomicU64,
        loaded: AtomicU64,
        replayed: AtomicU64,
        file_miss: AtomicU64,
        recording_claimed: AtomicU64,
        recording_declined: AtomicU64,
        skipped: [AtomicU64; LookupSkip::ALL.len()],
        misses: [AtomicU64; UnitMissReason::ALL.len()],
        load_ns: AtomicU64,
        publish_ns: AtomicU64,
    }

    static STORE_COUNTERS: StoreCounters = StoreCounters {
        consulted: AtomicU64::new(0),
        loaded: AtomicU64::new(0),
        replayed: AtomicU64::new(0),
        file_miss: AtomicU64::new(0),
        recording_claimed: AtomicU64::new(0),
        recording_declined: AtomicU64::new(0),
        skipped: [const { AtomicU64::new(0) }; LookupSkip::ALL.len()],
        misses: [const { AtomicU64::new(0) }; UnitMissReason::ALL.len()],
        load_ns: AtomicU64::new(0),
        publish_ns: AtomicU64::new(0),
    };

    static STATE: OnceLock<Mutex<CensusState>> = OnceLock::new();
    static FLUSH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    static ARMED: OnceLock<bool> = OnceLock::new();

    fn state() -> &'static Mutex<CensusState> {
        STATE.get_or_init(|| Mutex::new(CensusState::default()))
    }

    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Take the counters and leave them at zero, so a second flush of the same
    /// process writes nothing and cannot double-count.
    fn drain_store_counters() -> CensusStore {
        let read = |counter: &AtomicU64| counter.swap(0, Ordering::Relaxed);
        let mut store = CensusStore {
            consulted: read(&STORE_COUNTERS.consulted),
            loaded: read(&STORE_COUNTERS.loaded),
            replayed: read(&STORE_COUNTERS.replayed),
            file_miss: read(&STORE_COUNTERS.file_miss),
            recording_claimed: read(&STORE_COUNTERS.recording_claimed),
            recording_declined: read(&STORE_COUNTERS.recording_declined),
            skipped: BTreeMap::new(),
            misses: BTreeMap::new(),
            load_ns: read(&STORE_COUNTERS.load_ns),
            publish_ns: read(&STORE_COUNTERS.publish_ns),
        };
        for skip in LookupSkip::ALL {
            if let Some(counter) = STORE_COUNTERS.skipped.get(skip.index()) {
                let count = read(counter);
                if count != 0 {
                    store.skipped.insert(skip, count);
                }
            }
        }
        for reason in UnitMissReason::ALL {
            if let Some(counter) = STORE_COUNTERS.misses.get(reason.index()) {
                let count = read(counter);
                if count != 0 {
                    store.misses.insert(reason, count);
                }
            }
        }
        store
    }

    // The `bump_*` halves are separate from the `record_*` wrappers so the
    // accumulation the census actually depends on is directly testable: the
    // wrappers' `armed()` gate reads a process-wide `OnceLock`, and a test that
    // set the environment to flip it would race every other test in the binary.
    fn bump_skip(skip: LookupSkip) {
        if let Some(counter) = STORE_COUNTERS.skipped.get(skip.index()) {
            bump(counter);
        }
    }

    fn bump_loaded() {
        bump(&STORE_COUNTERS.consulted);
        bump(&STORE_COUNTERS.loaded);
    }

    fn bump_replayed() {
        bump(&STORE_COUNTERS.replayed);
    }

    fn bump_file_miss(claimed: bool) {
        bump(&STORE_COUNTERS.consulted);
        bump(&STORE_COUNTERS.file_miss);
        bump(if claimed {
            &STORE_COUNTERS.recording_claimed
        } else {
            &STORE_COUNTERS.recording_declined
        });
    }

    fn bump_miss(reason: UnitMissReason) {
        bump(&STORE_COUNTERS.consulted);
        if let Some(counter) = STORE_COUNTERS.misses.get(reason.index()) {
            bump(counter);
        }
    }

    /// A shared-unit lookup returned before touching the store.
    ///
    /// Called from `ProcessState::try_load_shared_unit`, once per fresh
    /// translation that does not reach `TranslationUnitStore::load`.
    pub fn record_lookup_skipped(skip: LookupSkip) {
        if !armed() {
            return;
        }
        arm_backstop();
        bump_skip(skip);
    }

    /// The store served a unit.
    /// Accumulate wall time spent inside `TranslationUnitStore::load`.
    ///
    /// Timed at the CALL, not inside the store, so it covers open, map and
    /// validate for hits and misses alike - the term a consulting process pays
    /// whether or not it gets a unit back.
    pub fn record_load_ns(elapsed: u64) {
        if !armed() {
            return;
        }
        arm_backstop();
        STORE_COUNTERS.load_ns.fetch_add(elapsed, Ordering::Relaxed);
    }

    /// Accumulate wall time spent inside `TranslationUnitStore::publish`.
    pub fn record_publish_ns(elapsed: u64) {
        if !armed() {
            return;
        }
        arm_backstop();
        STORE_COUNTERS
            .publish_ns
            .fetch_add(elapsed, Ordering::Relaxed);
    }

    pub fn record_lookup_loaded() {
        if !armed() {
            return;
        }
        arm_backstop();
        bump_loaded();
    }

    /// A lookup was served by replaying a block from an already-attached
    /// unit — the store itself was not consulted, so this is counted beside
    /// (never inside) the `consulted` identity.
    pub fn record_lookup_replayed() {
        if !armed() {
            return;
        }
        arm_backstop();
        bump_replayed();
    }

    /// The store had no files for this key, and `claim_recording` returned
    /// `claimed`. The election's verdict rides along because "the store missed"
    /// and "the store missed AND declined to let us record" are different
    /// answers to why nothing was ever published.
    pub fn record_lookup_file_miss(claimed: bool) {
        if !armed() {
            return;
        }
        arm_backstop();
        bump_file_miss(claimed);
    }

    /// The store refused the key for a typed reason.
    pub fn record_lookup_miss(reason: UnitMissReason) {
        if !armed() {
            return;
        }
        arm_backstop();
        bump_miss(reason);
    }

    fn census_dir() -> Option<&'static String> {
        static DIR: OnceLock<Option<String>> = OnceLock::new();
        DIR.get_or_init(|| std::env::var("CARRICK_XLAT_CENSUS_DIR").ok())
            .as_ref()
    }

    /// True when `CARRICK_XLAT_CENSUS_DIR` is set. Everything else in this
    /// module is a no-op when it is not, so the default path pays one relaxed
    /// load and a branch.
    pub fn armed() -> bool {
        census_dir().is_some()
    }

    fn hex_digest(digest: [u8; 32]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(digest.len().saturating_mul(2));
        for byte in digest {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Install the image whose blocks subsequent [`record`] calls belong to.
    ///
    /// Called from `NativeMappedMemory::configure_shared_translation` for every
    /// process image, including each `execve` replacement, and independently of
    /// the `CARRICK_DSR_PERSISTENT_STORE` hatch -- the census's job is to
    /// describe whichever arm is running. The stems are derived once per
    /// (image, segment) here rather than per translation.
    /// Forget the configured image, so a successor with no configurable segment
    /// cannot inherit its predecessor's.
    ///
    /// carrick's in-process `execve` keeps this process's statics. Under the
    /// fixed PIE base the successor's blocks land on the SAME guest VAs, so a
    /// stale image would attribute them to another binary's unit stem — the one
    /// thing the stem exists to prevent, and it would be silently wrong rather
    /// than absent.
    pub fn clear_image() {
        if !armed() {
            return;
        }
        if let Ok(mut state) = state().lock() {
            state.image = None;
        }
    }

    pub fn configure_image(image: &SharedImageConfig) {
        if !armed() {
            return;
        }
        if image.segments.is_empty() {
            clear_image();
            return;
        }
        let identity = image
            .executable_digest()
            .map_or_else(|| "-".to_string(), hex_digest);
        let segments = image
            .segments
            .iter()
            .map(|segment| CensusSegment {
                guest_start: segment.guest_start,
                guest_len: segment.guest_len.get(),
                unit_stem: image
                    .key_for_segment(segment)
                    .file_stem()
                    .unwrap_or_else(|_| "-".to_string()),
            })
            .collect();
        if let Ok(mut state) = state().lock() {
            state.image = Some(CensusImage { identity, segments });
        }
    }

    /// Classify a translated block against the configured segments.
    ///
    /// Pure and separately tested because the runtime holds two different
    /// containment predicates: a unit LOOKUP keys on the entry VA
    /// (`try_load_shared_unit`), while the PRODUCER requires the whole block to
    /// fit (`record_portable_block_artifact`). Reporting only one of them would
    /// either overstate the ceiling or understate what is publishable today.
    fn classify(
        segments: &[CensusSegment],
        entry: GuestVa,
        block_start: GuestVa,
        block_end: GuestVa,
    ) -> (Option<u32>, SegmentCoverage) {
        for (index, segment) in segments.iter().enumerate() {
            let Some(segment_end) = segment.guest_start.raw().checked_add(segment.guest_len) else {
                continue;
            };
            if entry.raw() < segment.guest_start.raw() || entry.raw() >= segment_end {
                continue;
            }
            let coverage = if block_start.raw() >= segment.guest_start.raw()
                && block_end.raw() <= segment_end
            {
                SegmentCoverage::Contained
            } else {
                SegmentCoverage::EntryOnly
            };
            return (u32::try_from(index).ok(), coverage);
        }
        (None, SegmentCoverage::Outside)
    }

    /// Called on every FRESH translation (never on a cache hit).
    pub fn record(entry: GuestVa, block_start: GuestVa, block_end: GuestVa) {
        if !armed() {
            return;
        }
        arm_backstop();
        let Ok(mut state) = state().lock() else {
            return;
        };
        state.total = state.total.saturating_add(1);
        let key = {
            let (segment, coverage) = state
                .image
                .as_ref()
                .map_or((None, SegmentCoverage::Outside), |image| {
                    classify(&image.segments, entry, block_start, block_end)
                });
            (entry, segment, coverage)
        };
        let count = state.records.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// A `fork` child inherits `total`/`records` by COW but performs none of the
    /// parent's translations. Without this reset the parent's whole set would be
    /// re-attributed to every child and `sum(per-file total)` would stop being
    /// the real translation count. The image survives: the child runs it.
    pub fn reset_after_fork() {
        if !armed() {
            return;
        }
        // Same reasoning for the lookup counters: the child performed none of
        // the parent's lookups, and `shared_unit_segments_consulted` is itself
        // inherited, so leaving them would attribute the parent's consultations
        // to a process that will never make one.
        let _ = drain_store_counters();
        // And for the flush ordinal. A child forked AFTER an in-process
        // `execve` inherits its parent's non-zero sequence and writes its first
        // file at `seq=1`, so it contributes no `seq=0` start -- which is the
        // one thing the aggregator's whole lineage model keys on
        // (`incarnations`, `flush_balance`, `reexec_successors_missing` in
        // `carrick-cli/src/debug_census.rs`). Leaving it inherited made the
        // instrument silently under-report coverage on any fixture where a
        // process execs in place before forking (`sh -c '<one command>'`), and
        // report it correctly on fixtures where it does not, which is the worst
        // possible failure shape for a number that gates a KILL criterion.
        FLUSH_SEQUENCE.store(0, Ordering::Relaxed);
        if let Ok(mut state) = state().lock() {
            state.total = 0;
            state.records.clear();
        }
    }

    /// Drain this process's records to `<dir>/xlat-<pid>-<stamp>-<seq>.txt`.
    ///
    /// Draining is what makes the seams composable: a second flush of an
    /// already-drained process writes nothing, so the `atexit` backstop and the
    /// explicit exit flush cannot double-count each other.
    ///
    /// The filename needs the timestamp because carrick's guest `execve` is a
    /// host SELF-re-exec: the successor keeps this pid AND restarts the flush
    /// sequence at 0, so `xlat-<pid>.txt` (or even `xlat-<pid>-<seq>.txt`) had
    /// the pre-exec flush truncated by its own successor.
    pub fn flush(reason: CensusFlush) {
        let Some(dir) = census_dir() else {
            return;
        };
        let Ok(mut guard) = state().lock() else {
            return;
        };
        // Drained under the same guard the records are, so the two halves of a
        // process's story cannot be split across two files.
        let store = drain_store_counters();
        if guard.total == 0 && store.is_empty() {
            return;
        }
        let total = std::mem::take(&mut guard.total);
        let records = std::mem::take(&mut guard.records);
        let image = guard.image.clone();
        drop(guard);
        let pid = unsafe { libc::getpid() };
        let sequence = FLUSH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let file = CensusFile {
            pid,
            sequence,
            reason,
            total,
            image,
            records: records
                .into_iter()
                .map(
                    |((guest_va, segment, coverage), translations)| CensusRecord {
                        guest_va,
                        segment,
                        coverage,
                        translations,
                    },
                )
                .collect(),
            store,
        };
        let _ = std::fs::write(
            format!("{dir}/xlat-{pid}-{stamp}-{sequence}.txt"),
            file.render(),
        );
    }

    extern "C" fn dump() {
        flush(CensusFlush::AtexitBackstop);
    }

    fn arm_backstop() {
        ARMED.get_or_init(|| {
            // Backstop only. Every native termination path that carries
            // translations flushes explicitly (see `CensusFlush`); `atexit`
            // covers the residual `std::process::exit` shapes and is free once
            // an explicit flush has drained the state.
            unsafe { libc::atexit(dump) };
            true
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn segments() -> Vec<CensusSegment> {
            vec![
                CensusSegment {
                    guest_start: GuestVa(0x40_0000),
                    guest_len: 0x1000,
                    unit_stem: "aa".repeat(32),
                },
                CensusSegment {
                    guest_start: GuestVa(0x50_0000),
                    guest_len: 0x40,
                    unit_stem: "bb".repeat(32),
                },
            ]
        }

        #[test]
        fn classify_separates_lookup_containment_from_producer_containment() {
            let segments = segments();
            // Wholly inside segment 0: publishable today.
            assert_eq!(
                classify(
                    &segments,
                    GuestVa(0x40_0010),
                    GuestVa(0x40_0010),
                    GuestVa(0x40_0020)
                ),
                (Some(0), SegmentCoverage::Contained)
            );
            // Entry inside segment 1, block runs past its end: a unit lookup
            // would hit, today's producer refuses to record it.
            assert_eq!(
                classify(
                    &segments,
                    GuestVa(0x50_0030),
                    GuestVa(0x50_0030),
                    GuestVa(0x50_0080)
                ),
                (Some(1), SegmentCoverage::EntryOnly)
            );
            // Exactly abutting the segment end is still contained.
            assert_eq!(
                classify(
                    &segments,
                    GuestVa(0x50_0000),
                    GuestVa(0x50_0000),
                    GuestVa(0x50_0040)
                ),
                (Some(1), SegmentCoverage::Contained)
            );
            // Outside every segment: no unit could ever serve it.
            assert_eq!(
                classify(
                    &segments,
                    GuestVa(0x7f_0000),
                    GuestVa(0x7f_0000),
                    GuestVa(0x7f_0010)
                ),
                (None, SegmentCoverage::Outside)
            );
            // No configured image at all reads as Outside.
            assert_eq!(
                classify(
                    &[],
                    GuestVa(0x40_0010),
                    GuestVa(0x40_0010),
                    GuestVa(0x40_0020)
                ),
                (None, SegmentCoverage::Outside)
            );
        }

        fn store() -> CensusStore {
            CensusStore {
                consulted: 4,
                loaded: 1,
                replayed: 7,
                file_miss: 1,
                recording_claimed: 0,
                recording_declined: 1,
                skipped: BTreeMap::from([
                    (LookupSkip::LaneUnconfigured, 9),
                    (LookupSkip::SegmentRepeat, 40),
                ]),
                misses: BTreeMap::from([(UnitMissReason::NoAuthority, 2)]),
                load_ns: 1_500_000,
                publish_ns: 2_500_000,
            }
        }

        #[test]
        fn renders_the_record_shape() {
            let file = CensusFile {
                pid: 4242,
                sequence: 1,
                reason: CensusFlush::HostSelfReexec,
                total: 5,
                image: Some(CensusImage {
                    identity: "cd".repeat(32),
                    segments: vec![CensusSegment {
                        guest_start: GuestVa(0x40_0000),
                        guest_len: 0x1000,
                        unit_stem: "aa".repeat(32),
                    }],
                }),
                records: vec![
                    CensusRecord {
                        guest_va: GuestVa(0x40_0010),
                        segment: Some(0),
                        coverage: SegmentCoverage::Contained,
                        translations: 3,
                    },
                    CensusRecord {
                        guest_va: GuestVa(0x7f_0000),
                        segment: None,
                        coverage: SegmentCoverage::Outside,
                        translations: 2,
                    },
                ],
                store: store(),
            };
            let identity = "cd".repeat(32);
            let stem = "aa".repeat(32);
            let expected = format!(
                "XLATCENSUS4|pid=4242|seq=1|reason=host-self-reexec|total=5|distinct=2|image={identity}|segments=1\n\
                 STORE|consulted=4|loaded=1|replayed=7|file_miss=1|recording_claimed=0|recording_declined=1|load_ns=1500000|publish_ns=2500000\n\
                 SKIP|lane-unconfigured|9\n\
                 SKIP|segment-repeat|40\n\
                 MISS|no-authority|2\n\
                 SEG|0|0x400000|0x1000|{stem}\n\
                 VA|0x400010|0|contained|3\n\
                 VA|0x7f0000|-|outside|2\n"
            );
            assert_eq!(file.render(), expected);
            assert_eq!(CensusFile::parse(&expected), Ok(file));
        }

        #[test]
        fn renders_a_process_that_never_configured_an_image() {
            let file = CensusFile {
                pid: 7,
                sequence: 0,
                reason: CensusFlush::ProcessExit,
                total: 1,
                image: None,
                records: vec![CensusRecord {
                    guest_va: GuestVa(0x1000),
                    segment: None,
                    coverage: SegmentCoverage::Outside,
                    translations: 1,
                }],
                store: CensusStore {
                    skipped: BTreeMap::from([(LookupSkip::LaneUnconfigured, 1)]),
                    ..CensusStore::default()
                },
            };
            let expected = "XLATCENSUS4|pid=7|seq=0|reason=process-exit|total=1|distinct=1|image=-|segments=0\n\
                            STORE|consulted=0|loaded=0|replayed=0|file_miss=0|recording_claimed=0|recording_declined=0|load_ns=0|publish_ns=0\n\
                            SKIP|lane-unconfigured|1\n\
                            VA|0x1000|-|outside|1\n";
            assert_eq!(file.render(), expected);
            assert_eq!(CensusFile::parse(expected), Ok(file));
        }

        #[test]
        fn parse_fails_closed_on_a_truncated_or_mislabelled_file() {
            const HEADER: &str = "XLATCENSUS4|pid=1|seq=0|reason=process-exit|total=0|distinct=0|image=-|segments=0\n";
            const STORE: &str = "STORE|consulted=0|loaded=0|replayed=0|file_miss=0|recording_claimed=0|recording_declined=0|load_ns=0|publish_ns=0\n";
            let cases = [
                (String::new(), "empty"),
                (
                    "XLATCENSUS2|pid=1|seq=0|reason=process-exit|total=0|distinct=0|image=-|segments=0\n"
                        .to_string(),
                    "superseded schema",
                ),
                (
                    // V3 files lack `replayed=`; a V4 parser must refuse them
                    // rather than default the field.
                    "XLATCENSUS3|pid=1|seq=0|reason=process-exit|total=0|distinct=0|image=-|segments=0\n"
                        .to_string(),
                    "superseded schema v3",
                ),
                (
                    format!("{HEADER}{STORE}").replace("distinct=0", "distinct=1"),
                    "distinct mismatch",
                ),
                (
                    format!("{HEADER}{STORE}").replace("process-exit", "fell-over"),
                    "reason",
                ),
                (
                    format!("{HEADER}{STORE}VA|400010|-|outside|1\n").replace("total=0", "total=1")
                        .replace("distinct=0", "distinct=1"),
                    "unprefixed hex",
                ),
                (
                    format!("{HEADER}{STORE}SEG|0|0x1000|0x10|aa\n"),
                    "segment without image",
                ),
                (HEADER.to_string(), "no STORE line"),
                (
                    format!("{HEADER}{STORE}SKIP|not-a-skip|1\n"),
                    "unknown skip reason",
                ),
                (
                    format!("{HEADER}{STORE}MISS|not-a-reason|1\n"),
                    "unknown miss reason",
                ),
                (
                    // consulted must equal loaded + file_miss + misses.
                    format!("{HEADER}{STORE}").replace("consulted=0", "consulted=3"),
                    "store outcomes do not account for consulted",
                ),
                (
                    // A file miss always carries exactly one election verdict.
                    format!("{HEADER}{STORE}").replace(
                        "consulted=0|loaded=0|replayed=0|file_miss=0",
                        "consulted=1|loaded=0|replayed=0|file_miss=1",
                    ),
                    "file miss without an election verdict",
                ),
                (
                    // Two STORE lines: the second used to overwrite the first
                    // wholesale, so "last one wins" parsed clean.
                    format!("{HEADER}{STORE}{STORE}"),
                    "second STORE line",
                ),
            ];
            for (text, what) in cases {
                assert!(
                    CensusFile::parse(&text).is_err(),
                    "expected {what} to be rejected"
                );
            }
        }

        /// `SKIP`/`MISS` counts that precede the `STORE` line must survive it.
        ///
        /// The parser used to assign `file.store = parse_store(..)` wholesale,
        /// and `parse_store` returns empty maps — so a reordered or
        /// concatenated file silently lost every earlier `SKIP`/`MISS` count
        /// AND still satisfied both construction identities, which do not cover
        /// the maps. It parsed clean and reported zero.
        #[test]
        fn skip_counts_before_the_store_line_are_not_discarded_by_it() {
            const HEADER: &str = "XLATCENSUS4|pid=1|seq=0|reason=process-exit|total=0|distinct=0|image=-|segments=0\n";
            const STORE: &str = "STORE|consulted=0|loaded=0|replayed=0|file_miss=0|recording_claimed=0|recording_declined=0|load_ns=0|publish_ns=0\n";
            let reordered = format!("{HEADER}SKIP|segment-repeat|7\nMISS|no-authority|0\n{STORE}");
            let file = CensusFile::parse(&reordered).expect("reordered file parses");
            assert_eq!(
                file.store.skipped.get(&LookupSkip::SegmentRepeat).copied(),
                Some(7)
            );
        }

        /// A process that only ever LOADED shared units performs no fresh
        /// translation, so its header `total` is 0. It must still be written,
        /// or the one outcome that proves the lane worked would be the one the
        /// census throws away.
        #[test]
        fn a_process_with_no_translations_but_store_activity_is_not_empty() {
            assert!(CensusStore::default().is_empty());
            let loaded_only = CensusStore {
                consulted: 1,
                loaded: 1,
                ..CensusStore::default()
            };
            assert!(!loaded_only.is_empty());
            let skipped_only = CensusStore {
                skipped: BTreeMap::from([(LookupSkip::SegmentRepeat, 1)]),
                ..CensusStore::default()
            };
            assert!(!skipped_only.is_empty());
        }

        /// The counters, the drain, and the wire format end to end -- through
        /// the same `bump_*` helpers the recording wrappers call, so a drift
        /// between "what the runtime counts" and "what the file says" fails
        /// here rather than in a report nobody can reproduce.
        #[test]
        fn lookup_counters_accumulate_drain_and_survive_the_wire() {
            // Any residue from an earlier assertion in this test binary would
            // make the expected values wrong; the counters are process-global.
            let _ = drain_store_counters();
            bump_skip(LookupSkip::Regenerated);
            bump_skip(LookupSkip::SegmentRepeat);
            bump_skip(LookupSkip::SegmentRepeat);
            bump_loaded();
            bump_file_miss(true);
            bump_file_miss(false);
            bump_miss(UnitMissReason::NoAuthority);
            bump_miss(UnitMissReason::Schema);

            let drained = drain_store_counters();
            assert_eq!(drained.consulted, 5, "loaded + file misses + refusals");
            assert_eq!(drained.loaded, 1);
            assert_eq!(drained.file_miss, 2);
            assert_eq!(drained.recording_claimed, 1);
            assert_eq!(drained.recording_declined, 1);
            assert_eq!(
                drained.skipped,
                BTreeMap::from([(LookupSkip::Regenerated, 1), (LookupSkip::SegmentRepeat, 2),])
            );
            assert_eq!(
                drained.misses,
                BTreeMap::from([
                    (UnitMissReason::NoAuthority, 1),
                    (UnitMissReason::Schema, 1),
                ])
            );
            assert_eq!(drained.skipped_total(), 3);
            assert_eq!(drained.miss_total(), 2);
            // Both identities the parser re-checks.
            assert_eq!(
                drained.loaded + drained.file_miss + drained.miss_total(),
                drained.consulted
            );
            assert_eq!(
                drained.recording_claimed + drained.recording_declined,
                drained.file_miss
            );

            // Draining is what keeps a second flush from double-counting.
            assert!(drain_store_counters().is_empty());

            let file = CensusFile {
                pid: 11,
                sequence: 0,
                reason: CensusFlush::ProcessExit,
                total: 0,
                image: None,
                records: Vec::new(),
                store: drained,
            };
            assert_eq!(CensusFile::parse(&file.render()), Ok(file));
        }

        #[test]
        fn coverage_and_flush_tokens_round_trip() {
            for coverage in [
                SegmentCoverage::Outside,
                SegmentCoverage::EntryOnly,
                SegmentCoverage::Contained,
            ] {
                assert_eq!(
                    SegmentCoverage::from_token(coverage.token()),
                    Some(coverage)
                );
            }
            for reason in [
                CensusFlush::ProcessExit,
                CensusFlush::HostSelfReexec,
                CensusFlush::InProcessExec,
                CensusFlush::AtexitBackstop,
            ] {
                assert_eq!(CensusFlush::from_token(reason.token()), Some(reason));
            }
            for skip in LookupSkip::ALL {
                assert_eq!(LookupSkip::from_token(skip.token()), Some(skip));
                assert_eq!(LookupSkip::ALL.get(skip.index()), Some(&skip));
            }
            assert_eq!(LookupSkip::from_token("segment_repeat"), None);
        }
    }
}
