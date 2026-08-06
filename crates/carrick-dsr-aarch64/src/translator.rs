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
        state.stats = ResolverStats::default();
        state.reported_stats = ResolverStats::default();
        state.sensitive.clear();
        state.unsupported.clear();
        state.dependencies = cache::PageBlockDependencies::default();
        state.shared_translation = None;
        // The replacement image is a different executable with different
        // segments, so the outgoing image's live unit key and this process's
        // authority over the arena for it are both retired here. Without the
        // reset, `configure_live_image` would trip its already-configured
        // guard AFTER old-image retirement (fatal) and the replacement image
        // could never install a view. `clear_published` above already emptied
        // the live indexes, and `executable_ranges` dropped the RX payload's
        // catalog node; `install_live_authority` re-registers both for the
        // replacement image over the SAME inherited arena.
        state.live_translation = None;
        state.live_authority = None;
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
    /// The executable region that owns `entry`, resolved when the entry was
    /// prepared. The gateway installs THIS region's cache range, so a live
    /// block is entered under the live-arena authority and a private block
    /// under the private one — never one under the other's range.
    authority: PublicationAuthority,
}

impl PreparedEntry {
    /// Test/diagnostic view of the executable region this entry was prepared
    /// against.
    #[doc(hidden)]
    pub const fn executable_authority(&self) -> PublicationAuthority {
        self.authority
    }
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

type PublishedBlockKey = (carrick_guest_mem::GuestVa, types::CodeGeneration);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublishedBlockLookup {
    entry: types::CacheVa,
    trusted_entry: Option<types::CacheOffset>,
}

/// Independently synchronized mirror of the published block index.
///
/// `ProcessState`'s write lock deliberately spans decode, emit, publication,
/// dependency updates, and direct-link patching. Warm cross-thread lookups used
/// to take that same lock for one `BTreeMap::get`, so a translator doing useful
/// write-side work forced every reader into Darwin's `psynch_cvwait`. The mirror
/// is published only after a block is executable and its invalidation dependency
/// is registered. Its lock therefore covers just a lookup or one index update,
/// never translation.
///
/// Sharding keeps unrelated publications from stopping unrelated readers. The
/// per-thread cache remains the first-level path; this is the process-wide
/// second level for a thread's first encounter with an already-published block.
struct PublishedBlockIndex {
    shards: Box<[RwLock<BTreeMap<PublishedBlockKey, PublishedBlockLookup>>]>,
}

impl PublishedBlockIndex {
    const SHARDS: usize = 64;
    const SHIFT: u32 = 64 - Self::SHARDS.trailing_zeros();

    fn new() -> Self {
        Self {
            shards: (0..Self::SHARDS)
                .map(|_| RwLock::new(BTreeMap::new()))
                .collect(),
        }
    }

    #[inline]
    fn shard(key: PublishedBlockKey) -> usize {
        let guest = key.0.raw() >> 2;
        let generation = key.1.get().rotate_left(29);
        let mixed = (guest ^ generation).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (mixed >> Self::SHIFT) as usize
    }

    #[inline]
    fn get(
        &self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
    ) -> Option<PublishedBlockLookup> {
        let key = (guest, generation);
        self.shards[Self::shard(key)].read().get(&key).copied()
    }

    fn insert(&self, key: PublishedBlockKey, lookup: PublishedBlockLookup) {
        self.shards[Self::shard(key)].write().insert(key, lookup);
    }

    fn remove(&self, key: PublishedBlockKey) {
        self.shards[Self::shard(key)].write().remove(&key);
    }

    fn clear(&self) {
        for shard in &self.shards {
            shard.write().clear();
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| shard.read().is_empty())
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
        #[cfg(feature = "alloc-owner-census")]
        let allocation_transition = {
            let next_exec_epoch = thread.budget.next_exec_epoch_after_reset();
            match crate::alloc_owner_census::begin_in_process_exec(next_exec_epoch) {
                Ok(transition) => Some(transition),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "failed to begin in-process allocation-owner transition"
                    );
                    None
                }
            }
        };
        if let Some(frames) = thread.take_profile_frames() {
            sink(&frames);
        }
        thread.process = next;
        thread.block_cache.clear();
        thread.exec_reset_epoch = next_exec_reset_epoch;
        thread.start_next_profile_epoch();
        #[cfg(feature = "alloc-owner-census")]
        if let Some(transition) = allocation_transition
            && let Err(error) = transition.rearm_successor()
        {
            tracing::warn!(
                error = %error,
                "failed to rearm in-process allocation-owner successor"
            );
        }
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
pub struct CodeSnapshot {
    pub cache_base: u64,
    pub code: Vec<u8>,
    /// `(guest_va, cache_entry_host_va)` for every published private block.
    pub blocks: Vec<(u64, u64)>,
}

/// Which of this process's executable regions owns a translated entry.
///
/// ENUMERATED, never inferred by a wildcard: every consumer (`target cache
/// authority`, gateway entry, direct-link resolution) matches exhaustively, so
/// a third executable region cannot be added without a compile error at each
/// decision point that would otherwise silently treat it as private.
///
/// A replayed shared UNIT block is `Private`: it replays into the private bump
/// cache and executes from it, exactly like a native translation. Only the
/// live arena's RX payload is a second executable region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationAuthority {
    /// The process's private bump-allocated JIT cache.
    Private,
    /// This process view's live-arena RX payload.
    Live,
}

pub struct ProcessTranslator {
    // `pub` for the runtime's still-resident test suites (see ThreadTranslator).
    pub state: RwLock<ProcessState>,
    published_blocks: Arc<PublishedBlockIndex>,
    private_target_authority: Box<gateway::TargetCacheAuthority>,
    /// The ONE stable target authority over this process view's live-arena RX
    /// payload, minted by `install_live_authority`.
    ///
    /// Boxed and install-once so emitted code may hold its address: a
    /// flavor-0 indirect-cache entry stores the record's pointer, and the
    /// emitted slow path dereferences it to validate and install the target's
    /// cache range. A `OnceLock` rather than a lock-protected slot because
    /// every read is on the resolver/gateway path and the record never
    /// changes: an in-process exec re-installs the SAME arena mapping, and
    /// `install_live_authority` refuses a payload that disagrees.
    live_target_authority: std::sync::OnceLock<Box<gateway::TargetCacheAuthority>>,
    /// The process's executable-range catalog header, copied out of
    /// `ProcessState` once at construction. Stable for the translator's life
    /// (see `gateway::ExecutableRangeCatalogAuthority`), which keeps the
    /// gateway entry off the process-state lock.
    executable_range_catalog: gateway::ExecutableRangeCatalogAuthority,
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
    published_blocks: Arc<PublishedBlockIndex>,
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
    live_translation: Option<LiveTranslationConfiguration>,
    /// This process's authority over the container-lifetime live arena.
    /// `None` (the default) is what makes every live path below inert: the
    /// compiler policy is what installs one.
    live_authority: Option<Arc<dyn crate::live_arena::LiveTranslationAuthority>>,
    /// Live blocks installed by THIS process, keyed exactly like `blocks`.
    ///
    /// Deliberately a SEPARATE index: `blocks` is the private publication
    /// authority that `publish_emitted_with_metadata` patches direct links
    /// against, and a live block is never a private link target until Task 6E
    /// carries publication kind into that decision.
    live_blocks: BTreeMap<PublishedBlockKey, types::CacheVa>,
    /// `published` indices ascending by LIVE RX entry address — the live half
    /// of the address index `published_block_containing` searches. Live code
    /// lives in the arena mapping, not the private bump cache, so it needs its
    /// own ordered index; the two are disjoint by construction.
    live_published_index: Vec<PublishedIndexEntry>,
    /// Descriptor-authoritative ownership hint per 16 KiB source page. Task 7
    /// revocation enumerates chunks per source page; recording the hint at
    /// install keeps that enumeration off the translate path once a page's
    /// chunks are known.
    live_source_pages: BTreeMap<carrick_guest_mem::GuestVa, LiveSourcePageHint>,
    /// Exact 64 KiB local RX chunks this process revoked `PROT_NONE`
    /// (Task 7), ascending by `rx_start` so the stale-abort classifier is a
    /// binary search. Entries are TASK-LOCAL bookkeeping over this view's own
    /// alias; they carry no shared-arena state. Cleared by the in-process
    /// exec reset (retired live ranges are dropped with the rest of the
    /// image's live bookkeeping) and rebuilt from the retained records by the
    /// fork-child repair before guest entry.
    revoked_live_chunks: Vec<crate::live_arena::LiveRevokedChunk>,
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
}

struct SharedTranslationConfiguration {
    image: crate::shared_cache::SharedImageConfig,
    store: Arc<dyn crate::shared_cache::TranslationUnitStore>,
}

struct LiveTranslationConfiguration {
    image: crate::shared_cache::SharedImageConfig,
    unit_digests: BTreeMap<carrick_guest_mem::GuestVa, [u8; 32]>,
    host_page_size: u64,
    /// The ONE exact live unit key, resolved once at configuration.
    ///
    /// `key_for_segment` re-derives the segment source fingerprint, so
    /// rebuilding it per translation miss would put a whole-segment hash on
    /// the miss path. The configured image holds exactly one segment.
    key: Arc<crate::shared_cache::TranslationUnitKey>,
    /// The image's host bias, the only process binding a shared INITIAL
    /// recovery action may carry. Copied here so fault-time COLD rebinding
    /// never has to reach back into the configuration.
    host_bias: Option<u64>,
}

/// One source page's descriptor-authoritative live ownership.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LiveSourcePageHint {
    /// ACTIVE groups observed owning chunks for this page.
    groups: BTreeSet<u32>,
    /// ACTIVE chunk indices observed for this page.
    chunks: BTreeSet<u32>,
}

/// Why one live-arena consultation fell back to the private translator.
///
/// Every ineligibility is NAMED: a live publication is never best-effort, and
/// "the arena was never consulted" and "the arena refused" imply opposite
/// fixes. Task 6F turns these into typed resolver counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveFallback {
    /// No live authority, or no configured live image (the default).
    Unconfigured,
    /// The page is not at its INITIAL generation.
    Regenerated,
    /// No configured live segment contains the block.
    OutsideSegment,
    /// The decoded interval leaves its 16 KiB source page.
    CrossPage,
    /// The terminal exit is sensitive, exclusive, or unsupported.
    UnsupportedShape,
    /// The block's exact source words are unavailable.
    SourceWordsUnavailable,
    /// The unique winner's own preparation refused.
    PrepareRefused,
    /// The installed block resolved no usable process-local entry.
    UnresolvedEntry,
    /// The arena's own named refusal (BUILDING, FAILED, CAS loss, corruption,
    /// capacity, exhausted probes, key encoding, unknown state).
    Arena(crate::live_arena::LivePrivateReason),
}

/// Exact recovery for one classified stale live instruction abort (Task 7).
///
/// Everything recovery needs, resolved from the LAZY live metadata while the
/// classifier still holds the state read guard: the exact guest PC (and any
/// mid-lowering rewrite action) for the faulting cache PC, plus the block's
/// published key so the stale block can be removed from the lookup indexes.
#[derive(Clone, Copy, Debug)]
struct LiveStaleRecovery {
    guest_pc: carrick_guest_mem::GuestVa,
    recovery: Option<emit::RecoveryAction>,
    block_key: PublishedBlockKey,
}

/// One revoked chunk found by the classifier's binary search, still borrowing
/// the state so `recover` resolves through the SAME retained address index.
struct RevokedChunkView<'state> {
    state: &'state ProcessState,
}

impl RevokedChunkView<'_> {
    fn recover(&self, pc: u64) -> Option<LiveStaleRecovery> {
        self.state.recover_stale_live(pc)
    }
}

/// The live lane's configured identity, resolved once per consultation so the
/// borrow of `ProcessState` ends before installation mutates it.
struct LiveLaneContext {
    authority: Arc<dyn crate::live_arena::LiveTranslationAuthority>,
    key: Arc<crate::shared_cache::TranslationUnitKey>,
    host_bias: Option<u64>,
}

/// The 16 KiB source page a live source group is keyed on.
const LIVE_SOURCE_PAGE_BYTES: u64 = crate::live_arena::LIVE_SOURCE_PAGE_BYTES;

/// One AArch64 instruction: the shortest interval a block can occupy, used to
/// screen a READY lookup against the configured live segment before consulting
/// the arena (the exact decoded interval is not known until the plan exists).
const LIVE_MINIMUM_BLOCK_BYTES: u64 = 4;

/// What one direct-link patch attempt did.
///
/// `OutOfReach` is a SUCCESS: the site keeps its unpatched fall-into-stub and
/// resolves through the gateway, which is correct and merely slower. It is a
/// named outcome rather than a bare `Ok(())` because "patched" and "too far to
/// patch" are the two answers a link-reach counter has to tell apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectLinkPatch {
    Patched,
    OutOfReach,
}

/// What one live-arena consultation produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveConsultation {
    /// A validated live block this process may execute now.
    Installed(types::CacheVa),
    /// No shared record exists for this exact key yet; the caller may plan and
    /// attempt the unique-winner path.
    Miss,
    /// An IMMEDIATE private fallback with its named reason.
    Private(LiveFallback),
}

fn live_sizing_configuration_with(
    configuration: Option<&LiveTranslationConfiguration>,
    sizing_armed: impl FnOnce() -> bool,
) -> Option<&LiveTranslationConfiguration> {
    configuration.filter(|_| sizing_armed())
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

/// Temporary evidence policy for the compiler-unit live-arena experiment.
///
/// Task 6C1 configures exact identity and exports sizing evidence without
/// constructing or transporting an arena. Runtime `compiler` activation is
/// guarded by carrick-runtime until packed-slab ownership lands in Task 6C2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveArenaRuntimePolicy {
    Disabled,
    Compiler,
}

/// Current-tip Task 6C compiler unit. This supersedes the pre-Task-6
/// `7ead8102...b4c` census stem: Task 6 moved the exact key to translator ABI
/// 8, while the executable digest and `0x10000 + 0x8d5000` segment stayed
/// invariant. Current-tip sizing must reproduce this complete
/// `TranslationUnitKey::file_stem()` before any live-runtime experiment.
const LIVE_ARENA_COMPILER_UNIT_STEM: &str =
    "a5948df76537f6a44e99e30b712e46ceae1871f91f3fe11e954b421dab7752b5";

pub fn live_arena_runtime_policy_from(
    value: Option<&std::ffi::OsStr>,
) -> Result<LiveArenaRuntimePolicy, types::DsrError> {
    match value {
        None => Ok(LiveArenaRuntimePolicy::Disabled),
        Some(value) if value == "0" => Ok(LiveArenaRuntimePolicy::Disabled),
        Some(value) if value == "compiler" => Ok(LiveArenaRuntimePolicy::Compiler),
        Some(value) => Err(types::DsrError::CachePolicy(format!(
            "CARRICK_DSR_LIVE_ARENA must be exactly 0 or compiler, got {:?}",
            value
        ))),
    }
}

pub fn live_arena_runtime_policy() -> Result<LiveArenaRuntimePolicy, types::DsrError> {
    live_arena_runtime_policy_from(std::env::var_os("CARRICK_DSR_LIVE_ARENA").as_deref())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LiveArenaSizingTotals {
    prepared_blocks: u64,
    aligned_code_bytes: u64,
    hot_bytes: u64,
    cold_bytes: u64,
    aligned_hot_bytes: u64,
    aligned_cold_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveArenaPreparedSize {
    lengths: emit::SharedInitialLengths,
    aligned_code: u64,
    aligned_hot: u64,
    aligned_cold: u64,
}

/// Exact, unique prepared-output sizing for one process incarnation.
///
/// The key is the complete live-domain unit digest plus guest block start.
/// Repeated translations therefore do not inflate the arena record or byte
/// requirements. Cross-process unioning remains an offline evidence step.
struct LiveArenaSizingCensus {
    host_page_size: u64,
    totals: LiveArenaSizingTotals,
    blocks: BTreeMap<([u8; 32], carrick_guest_mem::GuestVa), LiveArenaPreparedSize>,
}

impl LiveArenaSizingCensus {
    fn new(host_page_size: u64) -> Result<Self, types::DsrError> {
        if host_page_size != crate::live_arena::LIVE_SOURCE_PAGE_BYTES {
            return Err(types::DsrError::CachePolicy(format!(
                "live sizing host page size must match the 16 KiB arena protocol, got {host_page_size}"
            )));
        }
        Ok(Self {
            host_page_size,
            totals: LiveArenaSizingTotals::default(),
            blocks: BTreeMap::new(),
        })
    }

    #[cfg(test)]
    fn with_totals_for_test(host_page_size: u64, totals: LiveArenaSizingTotals) -> Self {
        Self {
            host_page_size,
            totals,
            blocks: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    const fn totals(&self) -> LiveArenaSizingTotals {
        self.totals
    }

    fn record(
        &mut self,
        unit_digest: [u8; 32],
        guest_start: carrick_guest_mem::GuestVa,
        lengths: emit::SharedInitialLengths,
    ) -> Result<(), types::DsrError> {
        let key = (unit_digest, guest_start);
        if let Some(existing) = self.blocks.get(&key) {
            if existing.lengths == lengths {
                return Ok(());
            }
            return Err(types::DsrError::CachePolicy(format!(
                "live sizing exact block changed shape at guest 0x{:x}",
                guest_start.raw()
            )));
        }
        let checked_align = |value: u64, alignment: u64, section: &str| {
            let mask = alignment - 1;
            value
                .checked_add(mask)
                .map(|rounded| rounded & !mask)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(format!(
                        "live sizing {section} alignment overflowed for {value} bytes"
                    ))
                })
        };
        let aligned_code = checked_align(lengths.code, self.host_page_size, "code")?;
        let aligned_hot = checked_align(lengths.hot, 8, "HOT")?;
        let aligned_cold = checked_align(lengths.cold, 8, "COLD")?;
        let next = LiveArenaSizingTotals {
            prepared_blocks: self.totals.prepared_blocks.checked_add(1).ok_or_else(|| {
                types::DsrError::CachePolicy(
                    "live sizing prepared block count overflowed".to_string(),
                )
            })?,
            aligned_code_bytes: self
                .totals
                .aligned_code_bytes
                .checked_add(aligned_code)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "live sizing aligned code byte sum overflowed".to_string(),
                    )
                })?,
            hot_bytes: self
                .totals
                .hot_bytes
                .checked_add(lengths.hot)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy("live sizing HOT byte sum overflowed".to_string())
                })?,
            cold_bytes: self
                .totals
                .cold_bytes
                .checked_add(lengths.cold)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy("live sizing COLD byte sum overflowed".to_string())
                })?,
            aligned_hot_bytes: self
                .totals
                .aligned_hot_bytes
                .checked_add(aligned_hot)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "live sizing aligned HOT byte sum overflowed".to_string(),
                    )
                })?,
            aligned_cold_bytes: self
                .totals
                .aligned_cold_bytes
                .checked_add(aligned_cold)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "live sizing aligned COLD byte sum overflowed".to_string(),
                    )
                })?,
        };
        self.blocks.insert(
            key,
            LiveArenaPreparedSize {
                lengths,
                aligned_code,
                aligned_hot,
                aligned_cold,
            },
        );
        self.totals = next;
        Ok(())
    }

    fn record_prepared(
        &mut self,
        unit_digest: [u8; 32],
        guest_start: carrick_guest_mem::GuestVa,
        prepared: &emit::PreparedSharedInitial,
    ) -> Result<(), types::DsrError> {
        self.record(unit_digest, guest_start, prepared.lengths())
    }

    fn render(&self, reason: &str) -> String {
        use std::fmt::Write as _;

        fn digest_hex(digest: [u8; 32]) -> String {
            use std::fmt::Write as _;
            let mut rendered = String::with_capacity(64);
            for byte in digest {
                let _ = write!(rendered, "{byte:02x}");
            }
            rendered
        }

        let mut rendered = format!(
            "LIVEARENASIZE1 reason={reason} host_page={}\n",
            self.host_page_size
        );
        for ((unit_digest, guest_start), size) in &self.blocks {
            let _ = writeln!(
                rendered,
                "BLOCK unit={} guest=0x{:x} code={} code_cursor={} hot={} hot_cursor={} cold={} cold_cursor={}",
                digest_hex(*unit_digest),
                guest_start.raw(),
                size.lengths.code,
                size.aligned_code,
                size.lengths.hot,
                size.aligned_hot,
                size.lengths.cold,
                size.aligned_cold,
            );
        }
        let _ = writeln!(
            rendered,
            "TOTAL prepared={} code_cursor={} hot={} hot_cursor={} cold={} cold_cursor={}",
            self.totals.prepared_blocks,
            self.totals.aligned_code_bytes,
            self.totals.hot_bytes,
            self.totals.aligned_hot_bytes,
            self.totals.cold_bytes,
            self.totals.aligned_cold_bytes,
        );
        rendered
    }

    #[cfg(test)]
    fn render_for_test(&self, reason: &str) -> String {
        self.render(reason)
    }
}

/// Arena-free, opt-in exporter for sizing the exact compiler live unit. It
/// prepares Task 5 shared INITIAL outputs but never constructs, looks up, or
/// publishes a Darwin arena.
pub mod live_sizing_census {
    use super::{LiveArenaSizingCensus, types};
    use crate::emit::{PreparedSharedInitial, SharedInitialLengths};
    use carrick_guest_mem::GuestVa;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    const ENV: &str = "CARRICK_DSR_LIVE_ARENA_SIZING_DIR";
    static CENSUS_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    static STATE: OnceLock<Mutex<Option<LiveArenaSizingCensus>>> = OnceLock::new();
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    static BACKSTOP_ARMED: OnceLock<()> = OnceLock::new();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum SizingFlush {
        ProcessExit,
        HostSelfReexec,
        InProcessExec,
        AtexitBackstop,
    }

    impl SizingFlush {
        const fn token(self) -> &'static str {
            match self {
                Self::ProcessExit => "process-exit",
                Self::HostSelfReexec => "host-self-reexec",
                Self::InProcessExec => "in-process-exec",
                Self::AtexitBackstop => "atexit-backstop",
            }
        }
    }

    fn state() -> &'static Mutex<Option<LiveArenaSizingCensus>> {
        STATE.get_or_init(|| Mutex::new(None))
    }

    fn census_dir() -> Option<&'static PathBuf> {
        CENSUS_DIR
            .get_or_init(|| {
                std::env::var_os(ENV)
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
            })
            .as_ref()
    }

    pub fn armed() -> bool {
        census_dir().is_some()
    }

    fn update(
        host_page_size: u64,
        update: impl FnOnce(&mut LiveArenaSizingCensus) -> Result<(), types::DsrError>,
    ) -> Result<(), types::DsrError> {
        if !armed() {
            return Ok(());
        }
        arm_backstop();
        let mut guard = state().lock().map_err(|_| {
            types::DsrError::CachePolicy("live sizing census lock is poisoned".to_string())
        })?;
        let census = match guard.as_mut() {
            Some(census) if census.host_page_size == host_page_size => census,
            Some(_) => {
                return Err(types::DsrError::CachePolicy(
                    "live sizing census host page size changed within an incarnation".to_string(),
                ));
            }
            None => guard.insert(LiveArenaSizingCensus::new(host_page_size)?),
        };
        update(census)
    }

    pub fn record(
        host_page_size: u64,
        unit_digest: [u8; 32],
        guest_start: GuestVa,
        lengths: SharedInitialLengths,
    ) -> Result<(), types::DsrError> {
        update(host_page_size, |census| {
            census.record(unit_digest, guest_start, lengths)
        })
    }

    pub fn record_prepared(
        host_page_size: u64,
        unit_digest: [u8; 32],
        guest_start: GuestVa,
        prepared: &PreparedSharedInitial,
    ) -> Result<(), types::DsrError> {
        update(host_page_size, |census| {
            census.record_prepared(unit_digest, guest_start, prepared)
        })
    }

    pub fn reset_after_fork() {
        if !armed() {
            return;
        }
        if let Ok(mut guard) = state().lock() {
            *guard = None;
        }
        SEQUENCE.store(0, Ordering::Relaxed);
    }

    pub fn flush(reason: SizingFlush) {
        let Some(dir) = census_dir() else {
            return;
        };
        let census = match state().lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => None,
        };
        let Some(census) = census else {
            return;
        };
        let pid = unsafe { libc::getpid() };
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let file = dir.join(format!("live-size-{pid}-{stamp}-{sequence}.txt"));
        if let Err(error) = std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::write(&file, census.render(reason.token())))
        {
            tracing::warn!(%error, path = %file.display(), "live arena sizing census export failed");
        }
    }

    extern "C" fn dump() {
        flush(SizingFlush::AtexitBackstop);
    }

    fn arm_backstop() {
        BACKSTOP_ARMED.get_or_init(|| {
            // Explicit exit/exec flushes drain the state first. This covers
            // only residual `std::process::exit` paths and writes nothing
            // after an earlier drain.
            unsafe { libc::atexit(dump) };
        });
    }
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
    /// Served from the container-lifetime live arena: either another
    /// process's READY record or this process's own winning publication.
    LiveArena,
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
    /// Installed from the live arena: the pc map and recovery metadata stay
    /// UNDECODED in the arena's mapped COLD pool until a guest fault
    /// interrogates them, exactly as a unit-replayed block leaves them in its
    /// unit. A shared INITIAL emission carries no process relocation, so
    /// `host_bias` is the only binding its recovery actions can require.
    Live {
        authority: Arc<dyn crate::live_arena::LiveBlockAuthority>,
        host_bias: Option<u64>,
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
            Self::Live {
                authority,
                host_bias,
            } => {
                let cold = artifact_spike::decode_shared_initial_cold(
                    authority.cold_metadata().map_err(|reason| {
                        types::DsrError::CachePolicy(format!(
                            "live COLD metadata refused at materialize: {reason:?}"
                        ))
                    })?,
                )?;
                let recovery = cold
                    .recovery
                    .into_entries()?
                    .into_iter()
                    .map(|entry| {
                        Ok(emit::RecoveryEntry {
                            cache: entry.cache(),
                            action: entry.rebind_with_host_bias(*host_bias)?,
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

/// Keep one address-ordered published index ordered as blocks append.
///
/// Shared by the private and live indexes: both are append-mostly (a bump
/// cache, an append-only arena chunk), so the common case is a push and only a
/// rollover pays for the binary search.
fn insert_published_index(index: &mut Vec<PublishedIndexEntry>, entry: PublishedIndexEntry) {
    let at = match index.last() {
        Some(last) if last.start > entry.start => {
            index.partition_point(|indexed| indexed.start <= entry.start)
        }
        _ => index.len(),
    };
    index.insert(at, entry);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverStats {
    pub resolver_exits: u64,
    pub one_entry_hits: u64,
    pub translations: u64,
    pub optimistic_decode_discards: u64,
    pub optimistic_decode_discard_ns: u64,
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
    pub live_index_hits: u64,
    pub live_ready_hits: u64,
    pub live_ready_misses: u64,
    pub live_publish_wins: u64,
    pub live_publish_adoptions: u64,
    pub live_blocks_installed: u64,
    pub live_code_bytes: u64,
    pub live_hot_bytes: u64,
    pub live_cold_bytes: u64,
    pub live_links_patched: u64,
    pub live_links_out_of_reach: u64,
    /// One counter per named live-lane fallback, indexed by
    /// [`profile::LiveLaneFallbackClass`]. An array rather than seventeen
    /// scalars for the same reason `exclusive_fusion_sites` is one: the
    /// producer's mapping is a single exhaustive match, so a new fallback
    /// reason cannot quietly land in a neighbouring counter.
    live_fallbacks: [u64; profile::LiveLaneFallbackClass::COUNT],
    invalid: Option<profile::ProfileError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverStat {
    ResolverExits,
    OneEntryHits,
    Translations,
    OptimisticDecodeDiscards,
    OptimisticDecodeDiscardNs,
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
    // Container-lifetime LIVE arena lane. Process-scoped like the Shared*
    // family above: incremented on `ProcessState::stats`, so they MUST flow
    // through `checked_delta` / `reported_stats`.
    LiveIndexHits,
    LiveReadyHits,
    LiveReadyMisses,
    LivePublishWins,
    LivePublishAdoptions,
    LiveBlocksInstalled,
    LiveCodeBytes,
    LiveHotBytes,
    LiveColdBytes,
    LiveLinksPatched,
    LiveLinksOutOfReach,
}

impl ResolverStat {
    const ALL: [Self; 44] = [
        Self::ResolverExits,
        Self::OneEntryHits,
        Self::Translations,
        Self::OptimisticDecodeDiscards,
        Self::OptimisticDecodeDiscardNs,
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
        Self::LiveIndexHits,
        Self::LiveReadyHits,
        Self::LiveReadyMisses,
        Self::LivePublishWins,
        Self::LivePublishAdoptions,
        Self::LiveBlocksInstalled,
        Self::LiveCodeBytes,
        Self::LiveHotBytes,
        Self::LiveColdBytes,
        Self::LiveLinksPatched,
        Self::LiveLinksOutOfReach,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::ResolverExits => "resolver_exits",
            Self::OneEntryHits => "one_entry_hits",
            Self::Translations => "translations",
            Self::OptimisticDecodeDiscards => "optimistic_decode_discards",
            Self::OptimisticDecodeDiscardNs => "optimistic_decode_discard_ns",
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
            Self::LiveIndexHits => "live_index_hits",
            Self::LiveReadyHits => "live_ready_hits",
            Self::LiveReadyMisses => "live_ready_misses",
            Self::LivePublishWins => "live_publish_wins",
            Self::LivePublishAdoptions => "live_publish_adoptions",
            Self::LiveBlocksInstalled => "live_blocks_installed",
            Self::LiveCodeBytes => "live_code_bytes",
            Self::LiveHotBytes => "live_hot_bytes",
            Self::LiveColdBytes => "live_cold_bytes",
            Self::LiveLinksPatched => "live_links_patched",
            Self::LiveLinksOutOfReach => "live_links_out_of_reach",
        }
    }
}

impl ResolverStats {
    fn get(self, stat: ResolverStat) -> u64 {
        match stat {
            ResolverStat::ResolverExits => self.resolver_exits,
            ResolverStat::OneEntryHits => self.one_entry_hits,
            ResolverStat::Translations => self.translations,
            ResolverStat::OptimisticDecodeDiscards => self.optimistic_decode_discards,
            ResolverStat::OptimisticDecodeDiscardNs => self.optimistic_decode_discard_ns,
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
            ResolverStat::LiveIndexHits => self.live_index_hits,
            ResolverStat::LiveReadyHits => self.live_ready_hits,
            ResolverStat::LiveReadyMisses => self.live_ready_misses,
            ResolverStat::LivePublishWins => self.live_publish_wins,
            ResolverStat::LivePublishAdoptions => self.live_publish_adoptions,
            ResolverStat::LiveBlocksInstalled => self.live_blocks_installed,
            ResolverStat::LiveCodeBytes => self.live_code_bytes,
            ResolverStat::LiveHotBytes => self.live_hot_bytes,
            ResolverStat::LiveColdBytes => self.live_cold_bytes,
            ResolverStat::LiveLinksPatched => self.live_links_patched,
            ResolverStat::LiveLinksOutOfReach => self.live_links_out_of_reach,
        }
    }

    fn set(&mut self, stat: ResolverStat, value: u64) {
        match stat {
            ResolverStat::ResolverExits => self.resolver_exits = value,
            ResolverStat::OneEntryHits => self.one_entry_hits = value,
            ResolverStat::Translations => self.translations = value,
            ResolverStat::OptimisticDecodeDiscards => self.optimistic_decode_discards = value,
            ResolverStat::OptimisticDecodeDiscardNs => self.optimistic_decode_discard_ns = value,
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
            ResolverStat::LiveIndexHits => self.live_index_hits = value,
            ResolverStat::LiveReadyHits => self.live_ready_hits = value,
            ResolverStat::LiveReadyMisses => self.live_ready_misses = value,
            ResolverStat::LivePublishWins => self.live_publish_wins = value,
            ResolverStat::LivePublishAdoptions => self.live_publish_adoptions = value,
            ResolverStat::LiveBlocksInstalled => self.live_blocks_installed = value,
            ResolverStat::LiveCodeBytes => self.live_code_bytes = value,
            ResolverStat::LiveHotBytes => self.live_hot_bytes = value,
            ResolverStat::LiveColdBytes => self.live_cold_bytes = value,
            ResolverStat::LiveLinksPatched => self.live_links_patched = value,
            ResolverStat::LiveLinksOutOfReach => self.live_links_out_of_reach = value,
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

    /// Count one named live-lane fallback. The class is derived by an
    /// exhaustive match on the producer's own reason, so this is the only
    /// place a fallback can be attributed and no reason can go uncounted.
    fn add_live_fallback(&mut self, fallback: LiveFallback) {
        if self.invalid.is_some() {
            return;
        }
        let class = profile::LiveLaneFallbackClass::from(fallback);
        let slot = &mut self.live_fallbacks[class.index()];
        match slot.checked_add(1) {
            Some(total) => *slot = total,
            None => {
                self.invalid = Some(profile::ProfileError::CounterOverflow(
                    "live_lane_fallbacks",
                ));
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
        for class in profile::LiveLaneFallbackClass::ALL {
            delta.live_fallbacks[class.index()] = self.live_fallbacks[class.index()]
                .checked_sub(prior.live_fallbacks[class.index()])
                .ok_or(profile::ProfileError::CounterUnderflow(
                    "live_lane_fallbacks",
                ))?;
        }
        Ok(delta)
    }
}

impl From<LiveFallback> for profile::LiveLaneFallbackClass {
    /// The one mapping from a produced fallback reason to its counter, with
    /// no wildcard on either enum: a new `LiveFallback` variant or a new
    /// `LivePrivateReason` is a compile error here, not a silent merge into
    /// whichever class happens to sit next to it.
    fn from(fallback: LiveFallback) -> Self {
        match fallback {
            LiveFallback::Unconfigured => Self::Unconfigured,
            LiveFallback::Regenerated => Self::Regenerated,
            LiveFallback::OutsideSegment => Self::OutsideSegment,
            LiveFallback::CrossPage => Self::CrossPage,
            LiveFallback::UnsupportedShape => Self::UnsupportedShape,
            LiveFallback::SourceWordsUnavailable => Self::SourceWordsUnavailable,
            LiveFallback::PrepareRefused => Self::PrepareRefused,
            LiveFallback::UnresolvedEntry => Self::UnresolvedEntry,
            LiveFallback::Arena(reason) => match reason {
                crate::live_arena::LivePrivateReason::Building => Self::ArenaBuilding,
                crate::live_arena::LivePrivateReason::Failed => Self::ArenaFailed,
                crate::live_arena::LivePrivateReason::CasLost => Self::ArenaCasLost,
                crate::live_arena::LivePrivateReason::InvalidRecord => Self::ArenaInvalidRecord,
                crate::live_arena::LivePrivateReason::Capacity => Self::ArenaCapacity,
                crate::live_arena::LivePrivateReason::ExhaustedProbes => Self::ArenaExhaustedProbes,
                crate::live_arena::LivePrivateReason::KeyEncoding => Self::ArenaKeyEncoding,
                crate::live_arena::LivePrivateReason::WriteAttempted => Self::ArenaWriteAttempted,
                crate::live_arena::LivePrivateReason::UnknownState => Self::ArenaUnknownState,
            },
        }
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
            optimistic_decode_discards: process.stats.optimistic_decode_discards,
            optimistic_decode_discard_ns: process.stats.optimistic_decode_discard_ns,
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
            live_index_hits: process.stats.live_index_hits,
            live_ready_hits: process.stats.live_ready_hits,
            live_ready_misses: process.stats.live_ready_misses,
            live_publish_wins: process.stats.live_publish_wins,
            live_publish_adoptions: process.stats.live_publish_adoptions,
            live_blocks_installed: process.stats.live_blocks_installed,
            live_code_bytes: process.stats.live_code_bytes,
            live_hot_bytes: process.stats.live_hot_bytes,
            live_cold_bytes: process.stats.live_cold_bytes,
            live_links_patched: process.stats.live_links_patched,
            live_links_out_of_reach: process.stats.live_links_out_of_reach,
            live_fallbacks: process.stats.live_fallbacks,
        }
    }

    /// Claim this process epoch's OUTSTANDING process-wide resolver delta for
    /// the calling thread's record. The process-wide counters (translations,
    /// cache lookups/hits, invalidated blocks, translation_*_ns, optimistic
    /// decode discard counters) are SHARED by every thread of the process, so
    /// they are
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
            optimistic_decode_discards: delta.optimistic_decode_discards,
            optimistic_decode_discard_ns: delta.optimistic_decode_discard_ns,
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
            live_index_hits: delta.live_index_hits,
            live_ready_hits: delta.live_ready_hits,
            live_ready_misses: delta.live_ready_misses,
            live_publish_wins: delta.live_publish_wins,
            live_publish_adoptions: delta.live_publish_adoptions,
            live_blocks_installed: delta.live_blocks_installed,
            live_code_bytes: delta.live_code_bytes,
            live_hot_bytes: delta.live_hot_bytes,
            live_cold_bytes: delta.live_cold_bytes,
            live_links_patched: delta.live_links_patched,
            live_links_out_of_reach: delta.live_links_out_of_reach,
            live_fallbacks: delta.live_fallbacks,
        })
    }

    /// The resolver snapshot for a DRAINED SIBLING's record.
    ///
    /// Deliberately does NOT claim the process-wide delta: every field that is
    /// a delta against the shared `reported_stats` checkpoint
    /// (`translations`, `optimistic_decode_discards`,
    /// `optimistic_decode_discard_ns`, `cache_lookups`, `cache_lookup_hits`,
    /// `invalidated_blocks`, `translation_*_ns`) is
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
            optimistic_decode_discards: 0,
            optimistic_decode_discard_ns: 0,
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
            // Process-wide deltas, like the blocks above: owned by the
            // draining thread's own record, so structurally zero here.
            live_index_hits: 0,
            live_ready_hits: 0,
            live_ready_misses: 0,
            live_publish_wins: 0,
            live_publish_adoptions: 0,
            live_blocks_installed: 0,
            live_code_bytes: 0,
            live_hot_bytes: 0,
            live_cold_bytes: 0,
            live_links_patched: 0,
            live_links_out_of_reach: 0,
            live_fallbacks: [0; profile::LiveLaneFallbackClass::COUNT],
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
        let translated_ranges = TranslatedRangeCatalog::dormant(
            carrick_guest_mem::HostVa(cache_range.start)
                ..carrick_guest_mem::HostVa(cache_range.end),
        )?;
        let published_blocks = Arc::new(PublishedBlockIndex::new());
        let executable_ranges =
            gateway::ExecutableRangeCatalog::new(cache_range.start, cache_range.end)?;
        // The header is a heap `Box` the catalog owns; moving the catalog into
        // `ProcessState` below does not move it, so this authority stays valid
        // for the translator's whole life.
        let executable_range_catalog = executable_ranges.authority();
        let translator = Self {
            private_target_authority: Box::new(gateway::TargetCacheAuthority::new(
                cache_range.start,
                cache_range.end,
                std::ptr::null(),
            )),
            live_target_authority: std::sync::OnceLock::new(),
            executable_range_catalog,
            private_jit_epoch: crate::direct_binding::PrivateJitEpoch::process_owner(),
            exec_reset_identity: Arc::new(DirectBindingExecProcessIdentity),
            published_blocks: Arc::clone(&published_blocks),
            state: RwLock::new(ProcessState {
                cache,
                published_blocks,
                translated_ranges,
                artifact_store: artifact_spike::store_if_enabled()?,
                blocks: BTreeMap::new(),
                pending: BTreeMap::new(),
                direct_link_incoming: BTreeMap::new(),
                trusted_entries: BTreeMap::new(),
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
                live_translation: None,
                live_authority: None,
                live_blocks: BTreeMap::new(),
                live_published_index: Vec::new(),
                live_source_pages: BTreeMap::new(),
                revoked_live_chunks: Vec::new(),
                shared_unit_segments_consulted: BTreeSet::new(),
                shared_recording_segments: BTreeSet::new(),
                attached_units: Vec::new(),
                attached_unit_blocks: BTreeMap::new(),
                shared_candidates: BTreeMap::new(),
                shared_publish_attempted: false,
                executable_ranges,
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

    /// Task 7 revocation seam; see `ProcessState::revoke_live_source_range`
    /// (private). Called from `note_dsr_code_mutation` after the generation
    /// bump, before the caller's source mutation proceeds.
    pub fn revoke_live_source_range(
        &self,
        range: std::ops::Range<carrick_guest_mem::GuestVa>,
    ) -> Result<usize, types::DsrError> {
        self.state.write().revoke_live_source_range(range)
    }

    /// This process's revoked-chunk catalog, for lifecycle assertions.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn revoked_live_chunks_for_test(&self) -> Vec<crate::live_arena::LiveRevokedChunk> {
        self.state.read().revoked_live_chunks.clone()
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

    /// Install the exact shared-image identity for the live-arena experiment
    /// without implying that a persistent unit store exists.
    pub(crate) fn configure_live_image(
        &self,
        image: crate::shared_cache::SharedImageConfig,
        host_page_size: u64,
    ) -> Result<bool, types::DsrError> {
        self.configure_live_image_matching(image, host_page_size, LIVE_ARENA_COMPILER_UNIT_STEM)
    }

    fn configure_live_image_matching(
        &self,
        mut image: crate::shared_cache::SharedImageConfig,
        host_page_size: u64,
        exact_unit_stem: &str,
    ) -> Result<bool, types::DsrError> {
        if image.segments.is_empty() {
            return Err(types::DsrError::CachePolicy(
                "live translation image has no executable segments".to_string(),
            ));
        }
        if !host_page_size.is_power_of_two() {
            return Err(types::DsrError::CachePolicy(format!(
                "live translation host page size must be a nonzero power of two, got {host_page_size}"
            )));
        }
        let selected = image
            .segments
            .iter()
            .enumerate()
            .map(|(index, segment)| {
                let key = image.key_for_segment(segment);
                key.file_stem()
                    .map(|stem| (index, key, stem))
                    .map_err(|error| {
                        types::DsrError::CachePolicy(format!(
                            "live translation unit key cannot be encoded: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|(_, _, stem)| stem == exact_unit_stem);
        let Some((selected_index, key, _)) = selected else {
            return Ok(false);
        };
        let selected_segment = image.segments.swap_remove(selected_index);
        let live_digest = key.live_digest().map_err(|error| {
            types::DsrError::CachePolicy(format!(
                "live translation unit key cannot be digested: {error}"
            ))
        })?;
        image.segments = vec![selected_segment];
        let unit_digests = BTreeMap::from([(image.segments[0].guest_start, live_digest)]);
        let host_bias = key.host_bias();
        let mut state = self.state.write();
        if state.live_translation.is_some() {
            return Err(types::DsrError::CachePolicy(
                "live translation image was already configured".to_string(),
            ));
        }
        state.live_translation = Some(LiveTranslationConfiguration {
            image,
            unit_digests,
            host_page_size,
            key: Arc::new(key),
            host_bias,
        });
        Ok(true)
    }

    /// Install this process's live-arena authority, its ONE stable target
    /// authority over the view's RX payload, and that payload's
    /// executable-range catalog node.
    ///
    /// The runtime calls it once per process image, after the arena owner
    /// exists and the live image is configured; without it every live path is
    /// inert, which is what keeps the default (policy-off) translator
    /// byte-identical. An in-process `execve` clears the authority and its
    /// catalog node in the exec reset and calls this again for the replacement
    /// image — over the SAME inherited arena, which is why a second install
    /// must present the same RX payload and is refused by name if it does not.
    ///
    /// Ordering is fail-closed: every refusal happens before any mutation, and
    /// the catalog node is prepared (allocated, reserved) before the head that
    /// publishes it to the signal handler moves.
    pub fn install_live_authority(
        &self,
        authority: Arc<dyn crate::live_arena::LiveTranslationAuthority>,
    ) -> Result<(), types::DsrError> {
        let payload = authority.rx_payload().ok_or_else(|| {
            types::DsrError::CachePolicy(
                "live translation authority exposes no RX payload range".to_string(),
            )
        })?;
        let start = payload.start().raw();
        let end = payload.end().raw();
        let mut state = self.state.write();
        if state.live_authority.is_some() {
            return Err(types::DsrError::CachePolicy(
                "live translation authority was already installed".to_string(),
            ));
        }
        // A semantic comparison between two typed host intervals, not between
        // raw casts: "does the installed record describe the same executable
        // region this view exposes".
        match self.live_target_authority.get() {
            Some(existing) if existing.host_range() == payload.host_range() => {}
            Some(existing) => {
                let installed = existing.host_range();
                return Err(types::DsrError::CachePolicy(format!(
                    "live translation RX payload 0x{start:x}..0x{end:x} disagrees with this \
                     process's installed target authority 0x{:x}..0x{:x}",
                    installed.start.raw(),
                    installed.end.raw(),
                )));
            }
            None => {}
        }
        let prepared = state.executable_ranges.prepare_prepend(start, end)?;
        // Infallible from here: the record is install-once and the catalog
        // node is already allocated.
        let _ = self
            .live_target_authority
            .set(Box::new(gateway::TargetCacheAuthority::new(
                start,
                end,
                // A shared INITIAL block carries no generation guard, so there
                // is no per-page binding table for emitted code to consult.
                std::ptr::null(),
            )));
        state.executable_ranges.commit_prepend(prepared);
        state.live_authority = Some(authority);
        Ok(())
    }

    /// The stable target-authority record for one executable region, or the
    /// named refusal that this process has no such region.
    ///
    /// The match is exhaustive on purpose (see [`PublicationAuthority`]).
    fn executable_authority(
        &self,
        authority: PublicationAuthority,
    ) -> Result<&gateway::TargetCacheAuthority, types::DsrError> {
        match authority {
            PublicationAuthority::Private => Ok(self.private_target_authority.as_ref()),
            PublicationAuthority::Live => self
                .live_target_authority
                .get()
                .map(Box::as_ref)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "live executable authority was requested before it was installed"
                            .to_string(),
                    )
                }),
        }
    }

    /// Which executable region owns `entry`, or the named refusal that none
    /// does.
    ///
    /// Two range compares against the private cache and, when a live authority
    /// is installed, two more against the RX payload — no lock, because both
    /// records are stable for the translator's life. An entry belonging to
    /// neither region can never reach emitted code: this is the fail-closed
    /// point every publication and every gateway entry passes through.
    pub(crate) fn publication_authority(
        &self,
        entry: types::CacheVa,
    ) -> Result<PublicationAuthority, types::DsrError> {
        if self.private_target_authority.owns(entry) {
            return Ok(PublicationAuthority::Private);
        }
        if self
            .live_target_authority
            .get()
            .is_some_and(|live| live.owns(entry))
        {
            return Ok(PublicationAuthority::Live);
        }
        Err(types::DsrError::CachePolicy(format!(
            "translated target 0x{:x} has no executable authority",
            entry.host().raw()
        )))
    }

    /// This process's executable-range catalog, as the gateway entry and the
    /// signal handler consume it.
    pub(crate) fn executable_range_catalog(&self) -> gateway::ExecutableRangeCatalogAuthority {
        self.executable_range_catalog
    }

    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn configure_live_image_matching_for_test(
        &self,
        image: crate::shared_cache::SharedImageConfig,
        host_page_size: u64,
        exact_unit_stem: &str,
    ) -> Result<bool, types::DsrError> {
        self.configure_live_image_matching(image, host_page_size, exact_unit_stem)
    }

    #[cfg(test)]
    fn live_unit_digests_for_test(&self) -> Vec<[u8; 32]> {
        self.state
            .read()
            .live_translation
            .as_ref()
            .map(|configuration| configuration.unit_digests.values().copied().collect())
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn shared_store_configured_for_test(&self) -> bool {
        self.state.read().shared_translation.is_some()
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
        #[cfg(feature = "alloc-owner-census")]
        let _owner = crate::alloc_owner_census::scope(
            crate::alloc_owner_wire::AllocationOwner::SharedTranslationSupport,
        );
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
        // Task 7: the revoked-chunk catalog is rebuilt (and PROT_NONE
        // re-asserted in this task) BEFORE any guest entry can fault into an
        // inherited stale chunk.
        state.rebuild_revoked_live_catalog_after_fork()?;
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
        live_sizing_census::reset_after_fork();
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
                AttachedReplayOutcome::Replayed(entry) => Ok(Some(entry)),
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
        #[cfg(feature = "alloc-owner-census")]
        let _owner = crate::alloc_owner_census::scope(
            crate::alloc_owner_wire::AllocationOwner::SharedTranslationSupport,
        );
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
                artifact_spike::replay_unit_block(&mut self.cache, words, hot, &bindings)
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
            xlat_census::PublicationCensus::UnitReplay,
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
    /// `ThreadTranslator::translate` under the original process-state read
    /// lock. Retained as the authoritative write-path recheck; warm readers
    /// now use `ProcessTranslator::published_blocks` instead.
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
        census: xlat_census::PublicationCensus,
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
            census,
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
        census: xlat_census::PublicationCensus,
    ) -> Result<TranslationResult, types::DsrError> {
        #[cfg(feature = "alloc-owner-census")]
        let _owner = crate::alloc_owner_census::scope(
            crate::alloc_owner_wire::AllocationOwner::PublicationIndexes,
        );
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
        let (map, links, recovery) = emitted.into_runtime_metadata();
        let owns_metadata = metadata.is_none();
        xlat_census::record_publication(census, || {
            let capacity_bytes = |capacity: usize, element_size: usize| {
                u64::try_from(capacity)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::try_from(element_size).unwrap_or(u64::MAX))
            };
            xlat_census::CensusMemory {
                private_blocks: u64::from(owns_metadata),
                unit_blocks: u64::from(!owns_metadata),
                jit_bytes_written: u64::try_from(emitted_len).unwrap_or(u64::MAX),
                owned_map_entries: if owns_metadata {
                    u64::try_from(map.len()).unwrap_or(u64::MAX)
                } else {
                    0
                },
                owned_map_len_bytes: if owns_metadata {
                    capacity_bytes(map.len(), std::mem::size_of::<emit::PcMapEntry>())
                } else {
                    0
                },
                owned_map_capacity_bytes: if owns_metadata {
                    capacity_bytes(map.capacity(), std::mem::size_of::<emit::PcMapEntry>())
                } else {
                    0
                },
                owned_recovery_entries: if owns_metadata {
                    u64::try_from(recovery.len()).unwrap_or(u64::MAX)
                } else {
                    0
                },
                owned_recovery_len_bytes: if owns_metadata {
                    capacity_bytes(recovery.len(), std::mem::size_of::<emit::RecoveryEntry>())
                } else {
                    0
                },
                owned_recovery_capacity_bytes: if owns_metadata {
                    capacity_bytes(
                        recovery.capacity(),
                        std::mem::size_of::<emit::RecoveryEntry>(),
                    )
                } else {
                    0
                },
                direct_link_capacity_bytes: capacity_bytes(
                    links.capacity(),
                    std::mem::size_of::<emit::DirectLink>(),
                ),
            }
        });
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
            // at its trusted entry — no binding-table trampolines. A LIVE
            // target resolves here too (`direct_link_target`), which is what
            // lets a private source patch into the arena instead of waiting
            // in `pending` for a private translation that will never come.
            match self.direct_link_target(target_key) {
                Some((authority, target)) => {
                    let patch = self.patch_direct_link_if_reachable(site, target, link.target)?;
                    // Only a LIVE target is the live lane's business; a
                    // private-to-private patch is the ordinary case the
                    // private counters already describe.
                    match authority {
                        PublicationAuthority::Live => {
                            let stat = match patch {
                                DirectLinkPatch::Patched => ResolverStat::LiveLinksPatched,
                                DirectLinkPatch::OutOfReach => ResolverStat::LiveLinksOutOfReach,
                            };
                            self.stats.add(stat, 1);
                        }
                        PublicationAuthority::Private => {}
                    }
                }
                None => {
                    self.pending.entry(target_key).or_default().push(site);
                }
            }
        }
        if let Some(sites) = self.pending.remove(&key) {
            let entry = self.trusted_target(key, entry);
            for site in sites {
                // A PRIVATE publication draining its own pending sites; the
                // live link counters deliberately do not move here.
                let _ = self.patch_direct_link_if_reachable(site, entry, key.0)?;
            }
        }
        // Publish to the independently synchronized read index only after all
        // fallible process-state bookkeeping succeeds. A partial publication
        // that returns an error remains discoverable by the authoritative
        // `blocks` recheck below, which repairs this mirror before serving it.
        self.published_blocks.insert(
            key,
            PublishedBlockLookup {
                entry,
                trusted_entry,
            },
        );
        Ok(TranslationResult {
            entry,
            generation: key.1,
            outcome,
            emitted_bytes,
            cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
        })
    }

    /// The live lane's configured identity, or the named reason there is none.
    fn live_lane(&self) -> Result<LiveLaneContext, LiveFallback> {
        let authority = self
            .live_authority
            .as_ref()
            .ok_or(LiveFallback::Unconfigured)?;
        let configuration = self
            .live_translation
            .as_ref()
            .ok_or(LiveFallback::Unconfigured)?;
        Ok(LiveLaneContext {
            authority: Arc::clone(authority),
            key: Arc::clone(&configuration.key),
            host_bias: configuration.host_bias,
        })
    }

    /// Name one live-lane fallback AND count it, in one place.
    ///
    /// Every `LiveConsultation::Private` in this module is produced here, so
    /// the counter cannot drift from the reason the translator actually
    /// returned: there is no second way to build the value.
    fn live_fallback(&mut self, fallback: LiveFallback) -> LiveConsultation {
        self.stats.add_live_fallback(fallback);
        LiveConsultation::Private(fallback)
    }

    /// The read-only exact READY lookup performed at the top of an
    /// authoritative INITIAL miss.
    ///
    /// A hit validates actual mapped code/HOT/current generation inside the
    /// consumer and installs WITHOUT touching the private cache. Every other
    /// outcome is either a `Miss` (the caller may plan and race for the block)
    /// or a named immediate private fallback.
    fn live_ready_consultation(
        &mut self,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
        observation: &cache::PageGenerationObservation,
    ) -> LiveConsultation {
        if generation != types::CodeGeneration::INITIAL {
            return self.live_fallback(LiveFallback::Regenerated);
        }
        let key = (guest, generation);
        // An already-installed live block is served from this process's own
        // live index rather than re-validating the shared record (which would
        // re-hash the mapped code on every entry). Counted apart from a fresh
        // READY acquisition: the two say different things about sharing.
        if let Some(entry) = self.live_blocks.get(&key).copied() {
            self.stats.add(ResolverStat::LiveIndexHits, 1);
            return LiveConsultation::Installed(entry);
        }
        let lane = match self.live_lane() {
            Ok(lane) => lane,
            Err(reason) => return self.live_fallback(reason),
        };
        let Some(block_end) = guest
            .raw()
            .checked_add(LIVE_MINIMUM_BLOCK_BYTES)
            .map(carrick_guest_mem::GuestVa)
        else {
            return self.live_fallback(LiveFallback::OutsideSegment);
        };
        if !lane.key.contains_guest_interval(guest, block_end) {
            return self.live_fallback(LiveFallback::OutsideSegment);
        }
        match lane.authority.acquire_ready(&lane.key, guest, observation) {
            crate::live_arena::LiveReadyOutcome::Installed(authority) => {
                match self.install_live_block(key, observation, lane.host_bias, authority) {
                    Ok(entry) => {
                        self.stats.add(ResolverStat::LiveReadyHits, 1);
                        LiveConsultation::Installed(entry)
                    }
                    Err(reason) => self.live_fallback(reason),
                }
            }
            crate::live_arena::LiveReadyOutcome::Miss => {
                self.stats.add(ResolverStat::LiveReadyMisses, 1);
                LiveConsultation::Miss
            }
            crate::live_arena::LiveReadyOutcome::Private(reason) => {
                self.live_fallback(LiveFallback::Arena(reason))
            }
        }
    }

    /// The unique-winner path, entered ONLY after the plan exists and only for
    /// a shape B3 accepts.
    ///
    /// The plan is rejected here — named — before any arena state is touched;
    /// `claim_eligible` then owns the two-phase generation/group/CAS protocol,
    /// and only the block winner's `prepare` runs.
    fn live_winner_publication(
        &mut self,
        block: &block::BlockPlan,
        guest: carrick_guest_mem::GuestVa,
        generation: types::CodeGeneration,
        observation: &cache::PageGenerationObservation,
        address_mode: emit::EmitAddressMode,
        source_words: Option<&Vec<u32>>,
    ) -> LiveConsultation {
        if generation != types::CodeGeneration::INITIAL || observation.current() != generation {
            return self.live_fallback(LiveFallback::Regenerated);
        }
        // Only a supported, non-sensitive, non-exclusive INITIAL plan may
        // enter `claim_eligible`. `ExclusiveRegion` and `Unsupported` own their
        // whole block; `Sensitive` carries plan-derived metadata a shared block
        // cannot republish.
        if !matches!(
            block.terminal_exit(),
            block::PlannedExit::Syscall { .. }
                | block::PlannedExit::Direct { .. }
                | block::PlannedExit::Indirect { .. }
                | block::PlannedExit::Continue { .. }
        ) {
            return self.live_fallback(LiveFallback::UnsupportedShape);
        }
        // The record is keyed by the block's own start, and the translation is
        // installed under `guest`; a plan that starts elsewhere would publish
        // one identity and install another.
        if block.start != guest {
            return self.live_fallback(LiveFallback::UnsupportedShape);
        }
        let source_page = guest.raw() / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES;
        let Some(source_page_end) = source_page.checked_add(LIVE_SOURCE_PAGE_BYTES) else {
            return self.live_fallback(LiveFallback::CrossPage);
        };
        if block.end.raw() <= block.start.raw() || block.end.raw() > source_page_end {
            return self.live_fallback(LiveFallback::CrossPage);
        }
        let Some(source_words) = source_words else {
            return self.live_fallback(LiveFallback::SourceWordsUnavailable);
        };
        let lane = match self.live_lane() {
            Ok(lane) => lane,
            Err(reason) => return self.live_fallback(reason),
        };
        if !lane.key.contains_guest_interval(block.start, block.end) {
            return self.live_fallback(LiveFallback::OutsideSegment);
        }
        // A WIN is a block this process prepared; an ADOPTION is a race it
        // lost and was still served from the winner's READY record without
        // preparing. The protocol cannot report which happened -- both are
        // `Installed` -- but the caller owns the closure, so observing whether
        // it ran is exact and costs nothing on either path.
        let mut prepared_here = false;
        let outcome = {
            let mut prepare = || {
                prepared_here = true;
                emit::prepare_shared_initial(&lane.key, block, address_mode, source_words.clone())
            };
            lane.authority.publish_winner(
                &lane.key,
                block.start,
                block.end,
                observation,
                std::process::id() as i32,
                &mut prepare,
            )
        };
        match outcome {
            crate::live_arena::LivePublishOutcome::Installed(authority) => {
                match self.install_live_block(
                    (guest, generation),
                    observation,
                    lane.host_bias,
                    authority,
                ) {
                    Ok(entry) => {
                        self.stats.add(
                            if prepared_here {
                                ResolverStat::LivePublishWins
                            } else {
                                ResolverStat::LivePublishAdoptions
                            },
                            1,
                        );
                        LiveConsultation::Installed(entry)
                    }
                    Err(reason) => self.live_fallback(reason),
                }
            }
            crate::live_arena::LivePublishOutcome::Private(reason) => {
                self.live_fallback(LiveFallback::Arena(reason))
            }
            crate::live_arena::LivePublishOutcome::PrepareRefused(_) => {
                self.live_fallback(LiveFallback::PrepareRefused)
            }
        }
    }

    /// Install one acquired live block into this process's bookkeeping.
    ///
    /// It deliberately shares only what is common with a private publication —
    /// the published list, an ordered address index, the page dependency, and
    /// the read-side lookup mirror. It never inserts into `blocks`,
    /// `trusted_entries`, `pending`, or `direct_link_incoming`, and it never
    /// touches the private cache: a live block is not a private link target
    /// and is never a mutable-index source (Task 6E owns both decisions).
    fn install_live_block(
        &mut self,
        key: PublishedBlockKey,
        observation: &cache::PageGenerationObservation,
        host_bias: Option<u64>,
        authority: Box<dyn crate::live_arena::LiveBlockAuthority>,
    ) -> Result<types::CacheVa, LiveFallback> {
        let host_entry = authority.entry();
        let extents = authority.extents();
        let len = authority.code_len();
        if host_entry.raw() == 0 || len == 0 || authority.guest_start().raw() != key.0.raw() {
            return Err(LiveFallback::UnresolvedEntry);
        }
        // The block's exact published extents, counted where the block is
        // installed so both consultation paths are covered by one site. These
        // are NEVER added to `cache.used_bytes()`: live code executes from the
        // arena mapping, and folding it into the private gauge would make the
        // private cache look like it grew when it did not.
        self.stats.add(ResolverStat::LiveBlocksInstalled, 1);
        self.stats
            .add(ResolverStat::LiveCodeBytes, extents.code.len);
        self.stats.add(ResolverStat::LiveHotBytes, extents.hot.len);
        self.stats
            .add(ResolverStat::LiveColdBytes, extents.cold.len);
        let source_page = authority.source_page();
        self.note_live_source_page(source_page, authority.group_slot(), authority.chunk_index());
        let entry = types::CacheVa::published(host_entry);
        let authority: Arc<dyn crate::live_arena::LiveBlockAuthority> = Arc::from(authority);
        self.push_published_live(PublishedBlock {
            entry,
            len,
            metadata: PublishedBlockMetadata::Live {
                authority,
                host_bias,
            },
            _generation: observation.clone(),
        });
        self.live_blocks.insert(key, entry);
        self.dependencies.record(observation.page(), key.0, key.1);
        self.published_blocks.insert(
            key,
            PublishedBlockLookup {
                entry,
                trusted_entry: None,
            },
        );
        Ok(entry)
    }

    /// Refresh the descriptor-authoritative source-page/group hint.
    ///
    /// The block's own chunk is recorded unconditionally; the full ACTIVE
    /// descriptor enumeration runs only when this page reveals a chunk the
    /// hint did not already carry, which keeps a per-descriptor scan off the
    /// steady-state install path.
    fn note_live_source_page(
        &mut self,
        source_page: carrick_guest_mem::GuestVa,
        group_slot: u32,
        chunk_index: u32,
    ) {
        let known = self
            .live_source_pages
            .get(&source_page)
            .is_some_and(|hint| hint.chunks.contains(&chunk_index));
        if known {
            return;
        }
        let enumerated = self
            .live_authority
            .as_ref()
            .map(|authority| authority.active_chunks_for_source_page(source_page))
            .unwrap_or_default();
        let hint = self.live_source_pages.entry(source_page).or_default();
        hint.groups.insert(group_slot);
        hint.chunks.insert(chunk_index);
        for owned in enumerated {
            hint.groups.insert(owned.group_slot);
            hint.chunks.insert(owned.chunk_index);
        }
    }

    /// Task 7 revocation seam: called from every `note_guest_code_write`
    /// owner (via `note_dsr_code_mutation`) AFTER the generation bump and
    /// BEFORE the caller's source mutation proceeds.
    ///
    /// Enumerates every ACTIVE descriptor for the mutated 16 KiB source
    /// pages through the live authority (the descriptor table is authority;
    /// `live_source_pages` is only a validated hint that may ADD chunks),
    /// protects each deduplicated exact 64 KiB local RX chunk `PROT_NONE`
    /// once, records the revoked catalog for the stale-abort classifier, and
    /// removes the pages' stale live blocks from the process lookup indexes.
    /// Errors are fail-closed for the caller's mutation.
    fn revoke_live_source_range(
        &mut self,
        range: std::ops::Range<carrick_guest_mem::GuestVa>,
    ) -> Result<usize, types::DsrError> {
        if range.start.raw() >= range.end.raw() {
            return Ok(0);
        }
        let Some(authority) = self.live_authority.as_ref() else {
            // No live authority (the shipped default): no shared chunk can be
            // executable in this process, so there is nothing to revoke.
            return Ok(0);
        };
        let page_mask = LIVE_SOURCE_PAGE_BYTES - 1;
        let first = range.start.raw() & !page_mask;
        let last = range.end.raw().saturating_sub(1) & !page_mask;
        // The process-local hints for the covered pages. They may only ADD
        // chunks: the authority re-enumerates ACTIVE descriptors itself.
        let mut hints = Vec::new();
        let mut page = first;
        loop {
            if let Some(hint) = self
                .live_source_pages
                .get(&carrick_guest_mem::GuestVa(page))
            {
                for chunk in &hint.chunks {
                    hints.push(crate::live_arena::LiveSourceChunkHint {
                        source_page: carrick_guest_mem::GuestVa(page),
                        chunk_index: *chunk,
                    });
                }
            }
            if page == last {
                break;
            }
            page = page.checked_add(LIVE_SOURCE_PAGE_BYTES).ok_or_else(|| {
                types::DsrError::CachePolicy(
                    "live revocation range overflowed a source page step".to_string(),
                )
            })?;
        }
        let revoked = authority.revoke_source_range(range, &hints)?;
        let count = revoked.len();
        for chunk in revoked {
            match self
                .revoked_live_chunks
                .binary_search_by(|seen| seen.rx_start.raw().cmp(&chunk.rx_start.raw()))
            {
                // A re-revocation of an already-revoked chunk is idempotent.
                Ok(at) => self.revoked_live_chunks[at] = chunk,
                Err(at) => self.revoked_live_chunks.insert(at, chunk),
            }
        }
        // The revoked pages' live blocks leave the LOOKUP indexes now, so no
        // pre-bump racing observation can be served a block whose chunk is
        // PROT_NONE. Removal is keyed by block START, which COVERS every
        // affected live block: B3's CrossPage refusal means a live block
        // never leaves its own 16 KiB source page, so a block whose start
        // lies outside the mutated pages has no bytes inside them. (And even
        // a hypothetical miss would be safe, not stale: its chunk is
        // PROT_NONE, so any entry faults into the exact classifier and
        // recovery evicts the block on first fault.) The ADDRESS index
        // (`live_published_index`/`published`) deliberately survives: it is
        // the fault-recovery index the stale classifier maps a revoked cache
        // PC back to a guest PC with.
        let end_exclusive = last.saturating_add(LIVE_SOURCE_PAGE_BYTES);
        let stale: Vec<PublishedBlockKey> = self
            .live_blocks
            .range(
                (
                    carrick_guest_mem::GuestVa(first),
                    types::CodeGeneration::INITIAL,
                )..,
            )
            .map(|(key, _)| *key)
            .take_while(|key| key.0.raw() < end_exclusive)
            .collect();
        for key in stale {
            self.live_blocks.remove(&key);
            self.published_blocks.remove(key);
        }
        Ok(count)
    }

    /// Task 7, the fork leg: rebuild the revoked-chunk catalog in a fork
    /// child BEFORE guest entry.
    ///
    /// The child inherited the parent's catalog and PROT_NONE protections by
    /// copy, but the catalog is bookkeeping over a task-local protection —
    /// so the child re-derives it through the SAME revocation seam, which
    /// also re-asserts `PROT_NONE` in the child's own task (idempotent) so
    /// the guarantee never rests on fork protection-inheritance subtleties.
    fn rebuild_revoked_live_catalog_after_fork(&mut self) -> Result<(), types::DsrError> {
        if self.revoked_live_chunks.is_empty() {
            return Ok(());
        }
        let Some(authority) = self.live_authority.as_ref() else {
            // A catalog can only have been filled through an authority; if
            // the authority is gone the retained records cannot serve
            // recovery either way. Keep them: classification against them is
            // read-only and still exact.
            return Ok(());
        };
        let mut pages: BTreeMap<
            carrick_guest_mem::GuestVa,
            Vec<crate::live_arena::LiveSourceChunkHint>,
        > = BTreeMap::new();
        for chunk in &self.revoked_live_chunks {
            pages.entry(chunk.source_page).or_default().push(
                crate::live_arena::LiveSourceChunkHint {
                    source_page: chunk.source_page,
                    chunk_index: chunk.chunk_index,
                },
            );
        }
        let mut rebuilt: Vec<crate::live_arena::LiveRevokedChunk> = Vec::new();
        for (page, hints) in pages {
            let end = page
                .raw()
                .checked_add(LIVE_SOURCE_PAGE_BYTES)
                .ok_or_else(|| {
                    types::DsrError::CachePolicy(
                        "revoked source page overflowed its page end".to_string(),
                    )
                })?;
            for chunk in
                authority.revoke_source_range(page..carrick_guest_mem::GuestVa(end), &hints)?
            {
                match rebuilt
                    .binary_search_by(|seen| seen.rx_start.raw().cmp(&chunk.rx_start.raw()))
                {
                    Ok(at) => rebuilt[at] = chunk,
                    Err(at) => rebuilt.insert(at, chunk),
                }
            }
        }
        self.revoked_live_chunks = rebuilt;
        Ok(())
    }

    /// Task 7 classifier: consume ONLY the measured stale shape — an
    /// instruction abort (`EC 0x20|0x21`, measured `0x20` with IFSC 0x06 on
    /// this host's fd backing, arriving as SIGBUS) whose `pc == far` lies in
    /// a chunk THIS process revoked — and map it to exact recovery. Every
    /// other shape returns `None` and falls through to the existing fault
    /// path unchanged.
    ///
    /// Read-only against the descriptor-derived local catalog and the
    /// retained published address index; it takes no lock the faulted thread
    /// could already hold (it runs in the thread's ordinary run-loop context,
    /// after the C handler has already returned through the gateway exit).
    fn stale_live_instruction_abort(
        &self,
        esr: u64,
        pc: u64,
        far: u64,
    ) -> Option<LiveStaleRecovery> {
        let ec = (esr >> 26) & 0x3f;
        if !matches!(ec, 0x20 | 0x21) || pc != far {
            return None;
        }
        self.revoked_chunk_containing(pc)?.recover(pc)
    }

    /// The revoked chunk containing `pc`, as a view that can attempt exact
    /// recovery. One binary search over the ascending-by-`rx_start` catalog.
    fn revoked_chunk_containing(&self, pc: u64) -> Option<RevokedChunkView<'_>> {
        let pc = usize::try_from(pc).ok()?;
        let at = self
            .revoked_live_chunks
            .partition_point(|chunk| chunk.rx_start.raw() <= pc);
        let chunk = self.revoked_live_chunks.get(at.checked_sub(1)?)?;
        (pc < chunk.rx_start.raw().checked_add(chunk.rx_len)?)
            .then_some(RevokedChunkView { state: self })
    }

    /// Exact recovery for a PC inside a revoked chunk, or `None` (fail-closed
    /// to the normal fault path) when the PC cannot be recovered EXACTLY.
    fn recover_stale_live(&self, pc: u64) -> Option<LiveStaleRecovery> {
        let cache_pc = usize::try_from(pc).ok()?;
        let block = self.published_block_containing(cache_pc)?;
        // Only a LIVE block may recover through this path: a private block in
        // a revoked address range cannot exist (the catalogs cover disjoint
        // mappings), so anything else is fail-closed.
        let PublishedBlockMetadata::Live { authority, .. } = &block.metadata else {
            return None;
        };
        let block_key = (authority.guest_start(), block._generation.expected());
        let entry = block.entry.host().raw() as u64;
        let (guest_pc, recovery) = match self.guest_pc_for_cache(carrick_guest_mem::GuestVa(pc)) {
            Ok(found) => found,
            // The block ENTRY is always an exact boundary — no guest
            // instruction has partially executed there — even when the
            // emitted map's first entry is not at offset zero.
            Err(_) if pc == entry => (authority.guest_start(), None),
            Err(_) => return None,
        };
        Some(LiveStaleRecovery {
            guest_pc,
            recovery,
            block_key,
        })
    }

    /// Whether `entry` addresses a block THIS process installed from the live
    /// arena. Two binary searches over the live address index, never a scan.
    ///
    /// The publication path no longer needs this — `PublicationAuthority`
    /// answers "which region owns this address" from the stable RX payload
    /// without a lock — but it remains the per-BLOCK check the address index
    /// supports, which is what the install tests assert on.
    #[cfg(test)]
    fn owns_live_entry(&self, entry: types::CacheVa) -> bool {
        let cache_pc = entry.host().raw();
        let index = &self.live_published_index;
        let at = index.partition_point(|indexed| indexed.start.raw() <= cache_pc);
        at.checked_sub(1)
            .and_then(|at| index.get(at))
            .and_then(|indexed| self.published.get(indexed.block))
            .is_some_and(|block| {
                let start = block.entry.host().raw();
                start
                    .checked_add(block.len)
                    .is_some_and(|end| (start..end).contains(&cache_pc))
            })
    }

    #[cfg(test)]
    fn live_source_page_hint(
        &self,
        source_page: carrick_guest_mem::GuestVa,
    ) -> Option<&LiveSourcePageHint> {
        self.live_source_pages.get(&source_page)
    }

    #[doc(hidden)]
    pub fn translate(
        &mut self,
        tid: i32,
        memory: &NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<TranslationResult, types::DsrError> {
        #[cfg(feature = "alloc-owner-census")]
        let _owner = crate::alloc_owner_census::scope(
            crate::alloc_owner_wire::AllocationOwner::TranslationOrchestration,
        );
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
            self.live_blocks.remove(&stale);
            self.published_blocks.remove(stale);
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
        if let Some(entry) = self.blocks.get(&key).copied() {
            if self.profiling {
                self.stats.add(ResolverStat::CacheLookupHits, 1);
            }
            self.published_blocks.insert(
                key,
                PublishedBlockLookup {
                    entry,
                    trusted_entry: self.trusted_entries.get(&key).copied(),
                },
            );
            probes::dsr_cache_event(
                tid,
                probes::DsrCacheEventKind::BlockHit,
                guest.raw(),
                generation.get(),
                u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            );
            return Ok(TranslationResult {
                entry,
                generation,
                outcome: TranslationOutcome::BlockIndexHit,
                emitted_bytes: 0,
                cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            });
        }
        // The read-only exact READY lookup sits at the TOP of the
        // authoritative INITIAL miss: above decode, above the persistent unit
        // store, and above any private-cache mutation.
        let live_ready = self.live_ready_consultation(guest, generation, &observation);
        if let LiveConsultation::Installed(entry) = live_ready {
            self.drain_pending_links_to_live(key, entry)?;
            probes::dsr_cache_event(
                tid,
                // The live lane's OWN event kind. Reusing `BlockHit` here made
                // a live serve indistinguishable from a private cache hit in
                // every trace.
                probes::DsrCacheEventKind::LiveReadyHit,
                guest.raw(),
                generation.get(),
                u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
            );
            return Ok(TranslationResult {
                entry,
                generation,
                outcome: TranslationOutcome::LiveArena,
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
                        xlat_census::PublicationCensus::ArtifactReplay,
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
                self.shared_translation.is_some() || self.live_translation.is_some(),
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

            // The plan exists exactly once. Only a READY MISS may race for the
            // block: a named private fallback above (BUILDING, FAILED, a
            // corrupt record, an unconfigured lane) is immediate and never
            // retried here.
            if live_ready == LiveConsultation::Miss
                && let LiveConsultation::Installed(entry) = self.live_winner_publication(
                    &block,
                    guest,
                    generation,
                    &observation,
                    memory.address_mode().into(),
                    block_source_words.as_ref(),
                )
            {
                self.drain_pending_links_to_live(key, entry)?;
                probes::dsr_cache_event(
                    tid,
                    // Not `BlockPublish`: that means a PRIVATE emission into
                    // this process's bump cache.
                    probes::DsrCacheEventKind::LiveWinnerPublish,
                    guest.raw(),
                    generation.get(),
                    u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
                );
                return Ok(TranslationResult {
                    entry,
                    generation,
                    outcome: TranslationOutcome::LiveArena,
                    emitted_bytes: 0,
                    cache_used_bytes: u64::try_from(self.cache.used_bytes()).unwrap_or(u64::MAX),
                });
            }

            probes::dsr_translate_subphase_begin(
                tid,
                probes::DsrTranslationSubphase::Emit,
                guest.raw(),
                generation.get(),
            );
            let emit_started = self.profiling.then(std::time::Instant::now);
            let emitted_result = (|| {
                if let Some(configuration) = live_sizing_configuration_with(
                    self.live_translation.as_ref(),
                    live_sizing_census::armed,
                ) && generation == types::CodeGeneration::INITIAL
                    && matches!(
                        block.terminal_exit(),
                        block::PlannedExit::Syscall { .. }
                            | block::PlannedExit::Direct { .. }
                            | block::PlannedExit::Indirect { .. }
                            | block::PlannedExit::Continue { .. }
                    )
                    && let Some(segment) = configuration.image.segments.iter().find(|segment| {
                        segment
                            .guest_start
                            .raw()
                            .checked_add(segment.guest_len.get())
                            .is_some_and(|end| {
                                block.start.raw() >= segment.guest_start.raw()
                                    && block.end.raw() <= end
                            })
                    })
                    && let Some(source_words) = block_source_words.clone()
                {
                    let key = configuration.image.key_for_segment(segment);
                    let unit_digest = configuration
                        .unit_digests
                        .get(&segment.guest_start)
                        .copied()
                        .ok_or_else(|| {
                            types::DsrError::CachePolicy(
                                "live sizing segment has no exact unit digest".to_string(),
                            )
                        })?;
                    let prepared = emit::prepare_shared_initial(
                        &key,
                        &block,
                        memory.address_mode().into(),
                        source_words,
                    )?;
                    live_sizing_census::record_prepared(
                        configuration.host_page_size,
                        unit_digest,
                        block.start,
                        &prepared,
                    )?;
                }
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
                xlat_census::PublicationCensus::Fresh {
                    entry: guest,
                    block_start: block.start,
                    block_end: block.end,
                },
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
        match self.trusted_entries.get(&key) {
            Some(offset) => types::CacheVa::published(carrick_guest_mem::HostVa(
                entry.host().raw() + offset.get() as usize,
            )),
            None => entry,
        }
    }

    /// Where a PRIVATE direct link should branch for `key`, and which
    /// executable region owns that address. `None` means no translation
    /// exists yet, so the site waits in `pending`.
    ///
    /// The two publication indexes are consulted in publication-authority
    /// order and never merged:
    ///
    /// * `blocks` — the private publication authority. The link targets the
    ///   block's trusted entry when it has one, its guarded entry otherwise.
    /// * `live_blocks` — this process view's live arena. A shared INITIAL
    ///   block publishes no trusted entry, so the link targets its entry.
    ///   This is the "private sources may patch to live targets" direction;
    ///   the reverse never happens, because a live block's own links are
    ///   emitted into immutable arena code that this process never patches.
    fn direct_link_target(
        &self,
        key: PublishedBlockKey,
    ) -> Option<(PublicationAuthority, types::CacheVa)> {
        if let Some(entry) = self.blocks.get(&key).copied() {
            return Some((
                PublicationAuthority::Private,
                self.trusted_target(key, entry),
            ));
        }
        self.live_blocks
            .get(&key)
            .copied()
            .map(|entry| (PublicationAuthority::Live, entry))
    }

    /// Patch every PRIVATE direct-link site waiting on `key` to the live block
    /// now installed for it.
    ///
    /// The mirror of `publish_emitted_with_metadata`'s pending drain: a
    /// private source that linked to this guest target before any translation
    /// existed waits in `pending`, and a live installation IS a publication of
    /// that target. Without this the site would wait forever — the private
    /// translator may never publish that key at all — so every traversal would
    /// keep paying a gateway round trip and the entry would never be reclaimed.
    ///
    /// Idempotent: a repeat lookup finds no pending sites for the key.
    fn drain_pending_links_to_live(
        &mut self,
        key: PublishedBlockKey,
        entry: types::CacheVa,
    ) -> Result<(), types::DsrError> {
        let Some(sites) = self.pending.remove(&key) else {
            return Ok(());
        };
        for site in sites {
            // The private cache and the arena are independent mappings, so
            // whether a private source can even reach a live target is a real
            // and previously unmeasured question (6E seam 2). Count both
            // answers; neither changes what the code does.
            let stat = match self.patch_direct_link_if_reachable(site, entry, key.0)? {
                DirectLinkPatch::Patched => ResolverStat::LiveLinksPatched,
                DirectLinkPatch::OutOfReach => ResolverStat::LiveLinksOutOfReach,
            };
            self.stats.add(stat, 1);
        }
        Ok(())
    }

    fn patch_direct_link_if_reachable(
        &mut self,
        site: cache::LinkSite,
        target: types::CacheVa,
        target_guest: carrick_guest_mem::GuestVa,
    ) -> Result<DirectLinkPatch, types::DsrError> {
        match encode_aarch64_direct_branch(site, target) {
            Ok(word) => {
                self.cache.patch_code_word(site, word)?;
                self.direct_link_incoming
                    .entry(target_guest.raw() & !0xfff)
                    .or_default()
                    .push(site);
                Ok(DirectLinkPatch::Patched)
            }
            Err(types::DsrError::CachePolicy(reason))
                if reason.contains("outside AArch64 B range") =>
            {
                Ok(DirectLinkPatch::OutOfReach)
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
        insert_published_index(&mut self.private_published_index, entry);
        self.published.push(block);
    }

    /// Record one LIVE block: the same `published` list and the same ordered
    /// address index shape, over the arena's RX payload instead of the private
    /// cache. Deliberately NOT `push_published`: the two address indexes cover
    /// disjoint mappings and each must stay internally ordered.
    fn push_published_live(&mut self, block: PublishedBlock) {
        let entry = PublishedIndexEntry {
            start: block.entry.host(),
            block: self.published.len(),
        };
        insert_published_index(&mut self.live_published_index, entry);
        self.published.push(block);
    }

    fn clear_published(&mut self) {
        self.published_blocks.clear();
        self.published.clear();
        self.private_published_index.clear();
        self.live_published_index.clear();
        self.live_blocks.clear();
        self.live_source_pages.clear();
        // Task 7: an in-process exec retires the outgoing image's revoked
        // ranges with the rest of its live bookkeeping. The successor image
        // starts with an empty catalog over the SAME inherited arena — and
        // the retired `live_target_authority` OnceLock, though never cleared,
        // stays unreachable: with `published`/`live_published_index` emptied
        // here no address can resolve to a retired live block, and with this
        // catalog emptied no retired range can classify a stale abort.
        self.revoked_live_chunks.clear();
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
    ///
    /// The live index is the second search: live blocks execute from the arena
    /// mapping, which is disjoint from the private cache, and the arena's
    /// append-only chunk allocator keeps live extents disjoint from each other.
    fn published_block_containing(&self, cache_pc: usize) -> Option<&PublishedBlock> {
        [&self.private_published_index, &self.live_published_index]
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
                // A live-arena block: same lazy contract as a unit block, but
                // the undecoded COLD stream lives in the arena's mapped
                // metadata pool. Resolving it is what makes the extent's first
                // touch a FAULT-time cost rather than an install-time one.
                PublishedBlockMetadata::Live {
                    authority,
                    host_bias,
                } => {
                    let cold_bytes = authority.cold_metadata().map_err(|reason| {
                        types::DsrError::CachePolicy(format!(
                            "live COLD metadata refused at fault for cache PC \
                             0x{cache_pc:x}: {reason:?}"
                        ))
                    })?;
                    let cold = artifact_spike::decode_shared_initial_cold(cold_bytes)?;
                    let guest = cold
                        .map
                        .iter()
                        .find(|entry| entry.cache == offset)
                        .map(|entry| entry.guest);
                    let action = cold.recovery.rebind_for_cache(offset, *host_bias)?;
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
        if let Some(published) = self.process.published_blocks.get(guest, generation) {
            self.block_cache.insert(guest, generation, published.entry);
            probes::dsr_cache_event(
                self.tid,
                probes::DsrCacheEventKind::BlockHit,
                guest.raw(),
                generation.get(),
                // The gauge is diagnostic only. Reading the exact bump-cache
                // cursor would reintroduce the process-state lock this index
                // exists to avoid, so retain the last value this thread saw
                // on a write-path publication.
                self.last_cache_used_bytes,
            );
            return Ok(TranslationResult {
                entry: published.entry,
                generation,
                outcome: TranslationOutcome::BlockIndexHit,
                emitted_bytes: 0,
                cache_used_bytes: self.last_cache_used_bytes,
            });
        }
        // A process-index miss falls through to the exclusive write path.
        // `ProcessState::translate` re-checks `blocks.get` itself as its very
        // first lookup (after a no-op `invalidate_page` when the page hasn't
        // changed), so a block another thread inserted in the index-to-write
        // gap is found there -- no duplicate translation -- and a genuine
        // miss is translated exactly as before.
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

    /// Publish `target` into the per-thread indirect target cache, carrying
    /// the resolved publication kind into the entry FLAVOR (see
    /// `gateway::IndirectTargetCacheEntry`):
    ///
    /// - a PRIVATE-cache target with a trusted entry publishes flavor 1 —
    ///   the trusted-entry code address plus the target page's generation
    ///   atomic, so the emitted hot path validates staleness inline and
    ///   lands past the guard;
    /// - everything else — a LIVE-arena target, a shared-unit target, a
    ///   private block without a trusted entry — publishes flavor 0: the
    ///   guarded entry plus the owning region's stable `TargetCacheAuthority`,
    ///   which the emitted slow path re-validates the entry against and then
    ///   installs before branching.
    ///
    /// A live target is therefore published like any other cross-region
    /// target, and the fail-safe the pre-6E skip provided is preserved by
    /// construction: `publication_authority` refuses an entry no region owns,
    /// so an unowned entry still never reaches the cache.
    ///
    /// Callable only after `translate()` returned — publication into the
    /// independently synchronized block index happens before that call
    /// returns, so no process-state lock is needed here.
    fn publish_indirect_target(
        &mut self,
        memory: &NativeMappedMemory,
        target: carrick_guest_mem::GuestVa,
        translated: &TranslationResult,
    ) -> Result<(), types::DsrError> {
        let authority = self.process.publication_authority(translated.entry)?;
        if authority == PublicationAuthority::Private {
            let trusted = self
                .process
                .published_blocks
                .get(target, translated.generation)
                .filter(|published| published.entry == translated.entry)
                .and_then(|published| published.trusted_entry);
            if let Some(offset) = trusted {
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
                    translated.entry.host().raw() as u64 + u64::from(offset.get()),
                    generation_atomic,
                    translated.generation,
                );
                return Ok(());
            }
        }
        let record = self.process.executable_authority(authority)? as *const _;
        self.indirect_cache
            .publish(target, translated.generation, translated.entry, record);
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
            optimistic_decode_discards: process.optimistic_decode_discards,
            optimistic_decode_discard_ns: process.optimistic_decode_discard_ns,
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
            // Process-scoped, like the `shared_*` family directly above.
            live_index_hits: process.live_index_hits,
            live_ready_hits: process.live_ready_hits,
            live_ready_misses: process.live_ready_misses,
            live_publish_wins: process.live_publish_wins,
            live_publish_adoptions: process.live_publish_adoptions,
            live_blocks_installed: process.live_blocks_installed,
            live_code_bytes: process.live_code_bytes,
            live_hot_bytes: process.live_hot_bytes,
            live_cold_bytes: process.live_cold_bytes,
            live_links_patched: process.live_links_patched,
            live_links_out_of_reach: process.live_links_out_of_reach,
            live_fallbacks: process.live_fallbacks,
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
                // A live block was not translated by this entry: it was either
                // already published by someone (an index hit in the shared
                // sense) or won and published without a private emission.
                TranslationOutcome::SharedUnit | TranslationOutcome::LiveArena => {
                    probes::DsrPrepareOutcome::BlockIndexHit
                }
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
            // Fail-closed: an entry no executable region owns never becomes a
            // prepared entry, so it can never be branched to.
            authority: match self.process.publication_authority(entry) {
                Ok(authority) => authority,
                Err(error) => {
                    if PROFILE {
                        probes::dsr_prepare_end(
                            self.tid,
                            guest.raw(),
                            entry.host().raw() as u64,
                            generation.get(),
                            probes::DsrPrepareOutcome::Failed,
                        );
                    }
                    return Err(error);
                }
            },
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
        // Installed unit blocks replay into the private cache, so a prepared
        // entry is private unless the live arena owns it; either way the
        // gateway installs the EXACT owning region's range, and the process
        // catalog covers both so a kick inside either one classifies as
        // authoritative translated code.
        let authority = match self.process.executable_authority(prepared.authority) {
            Ok(authority) => authority,
            Err(error) => {
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
        };
        let gateway_result = gateway::enter_translated_with_executable_authority(
            prepared.entry,
            snapshot,
            &mut exit,
            &self.indirect_cache,
            authority,
            prepared.address_mode,
            self.process.executable_range_catalog(),
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

    /// Task 7 recovery for one CLASSIFIED stale live instruction abort.
    ///
    /// Restores the guest snapshot from the lazy live metadata (any
    /// mid-lowering rewrite action plus the exact resume PC), removes the
    /// stale block from the process and thread lookup state, and resumes
    /// through `ThreadExit::Kick` so the runtime re-enters the NORMAL private
    /// translation path against the newly observed generation. The revoked
    /// chunk is never remapped or reactivated.
    #[allow(clippy::too_many_arguments)]
    fn recover_stale_live_abort(
        &mut self,
        snapshot: &mut NativeUcontextSnapshot,
        stale: LiveStaleRecovery,
        rewrite_scratch: u64,
        rewrite_context_scratch: u64,
        generation_pstate_scratch: u64,
        indirect_x15_scratch: u64,
        indirect_x30_scratch: u64,
        physical_reserved: u64,
    ) -> Result<ThreadExit, types::DsrError> {
        if let Some(recovery) = stale.recovery {
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
        snapshot.pc = recovery_resume_pc(stale.guest_pc, stale.recovery)?;
        // Thread lookup state must stop serving the revoked chunk: the
        // per-thread block memo and the inline indirect target cache could
        // otherwise branch straight back into PROT_NONE code on every
        // traversal. Recovery is rare, so a full clear (both already exist
        // for the exec handoff) is proportionate and refills on demand.
        self.block_cache.clear();
        self.indirect_cache.clear();
        // Process lookup indexes: idempotent — revocation already removed
        // the mutated page's blocks in the revoking process, but a fork
        // child classifying against an inherited catalog scrubs its own copy
        // here.
        {
            let mut state = probes::acquire_with_synchronization_reason(
                probes::DsrSynchronizationKind::ProcessStateWrite,
                || self.process.state.write(),
            );
            state.live_blocks.remove(&stale.block_key);
            state.published_blocks.remove(stale.block_key);
        }
        Ok(ThreadExit::Kick)
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
                // Task 7: consume ONLY the measured stale shape — an
                // instruction abort with pc == far inside a chunk THIS
                // process revoked — and recover it exactly. Every other
                // shape falls through to the unchanged fault path below.
                let stale = self.process.state.read().stale_live_instruction_abort(
                    snapshot.esr,
                    snapshot.pc,
                    snapshot.far,
                );
                if let Some(stale) = stale {
                    return self.recover_stale_live_abort(
                        snapshot,
                        stale,
                        rewrite_scratch,
                        rewrite_context_scratch,
                        generation_pstate_scratch,
                        indirect_x15_scratch,
                        indirect_x30_scratch,
                        physical_reserved,
                    );
                }
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
        DsrErrorProbeExt as _, ForkChildRepairRecorder, LiveArenaRuntimePolicy,
        LiveArenaSizingCensus, LiveArenaSizingTotals, LiveTranslationConfiguration,
        NativeDsrExitProbeExt as _, ProcessTranslator, SensitiveMetadata, ThreadTranslator,
        TranslatedRangeCatalog, TranslatedRangeRecorder, live_arena_runtime_policy_from,
        live_sizing_configuration_with, merge_sensitive_metadata,
        translation_source_words_required,
    };
    use crate::{emit, types};
    use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};
    use carrick_dsr::probes::{
        DsrCacheLifecyclePhase, TranslatedPrivateRange, TranslatedRangeAdd, TranslatedRangeEpoch,
        TranslatedRangeReady, TranslatedRangeReset, TranslatedRangeSequence,
    };
    use carrick_guest_mem::{GuestVa, HostVa};
    use std::ptr::NonNull;
    use std::sync::{Arc, Barrier};

    #[cfg(feature = "alloc-owner-census")]
    #[test]
    fn allocation_owner_translation_orchestration_wraps_process_translation() {
        let source = include_str!("translator.rs");
        let body = source
            .split_once("    pub fn translate(\n")
            .expect("process translation function")
            .1
            .split_once("    /// Record one published block")
            .expect("process translation function end")
            .0;
        let owner = body
            .find("AllocationOwner::TranslationOrchestration")
            .expect("translation orchestration owner");
        let observation = body
            .find("let observation = memory.dsr_generation_observation(guest)?")
            .expect("translation generation observation");
        assert!(owner < observation);
    }

    #[cfg(feature = "alloc-owner-census")]
    use crate::alloc_owner_census::test_support as allocation_census;

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
            authority: super::PublicationAuthority::Private,
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

    #[cfg(feature = "alloc-owner-census")]
    #[test]
    fn exec_handoff_disarms_outgoing_allocations_and_rearms_the_successor_epoch() {
        use crate::alloc_owner_wire::AllocationOwner;

        let _census = allocation_census::lock();
        let output_dir = std::env::temp_dir().join(format!(
            "carrick-alloc-owner-census-tests-{}",
            std::process::id()
        ));
        match std::fs::remove_dir_all(&output_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove allocation census test directory: {error}"),
        }
        std::fs::create_dir_all(&output_dir).expect("create allocation census test directory");
        allocation_census::configure_output_dir(&output_dir);
        allocation_census::reset_and_arm(0, 0);
        allocation_census::record(AllocationOwner::PublicationMap, 41);

        let process = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator"),
        );
        let mut translator = ThreadTranslator::for_process(process, 91);
        translator.budget =
            carrick_dsr::profile::ThreadBudget::enabled_for_test(unsafe { libc::getpid() }, 91);
        let replacement = Arc::new(
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT)
                .expect("replacement translator"),
        );
        let mut sink_state = None;

        translator
            .reset_for_exec_with_sink(replacement, |_| {
                sink_state = Some(allocation_census::state());
            })
            .expect("commit exec handoff");

        assert_eq!(
            sink_state,
            Some(allocation_census::State::Transition),
            "NATIVEPERF serialization must run while allocation counting is disarmed"
        );
        assert_eq!(allocation_census::state(), allocation_census::State::Armed);
        assert_eq!(allocation_census::identity(), (1, 0));
        assert!(allocation_census::snapshot().iter().all(|owner| {
            owner.requested_bytes == 0
                && owner.alloc_calls == 0
                && owner.zeroed_calls == 0
                && owner.realloc_calls == 0
        }));
        assert!(!allocation_census::lifecycle_error());
        allocation_census::reset_disabled();
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
    fn default_translation_path_never_consults_sizing_authority() {
        use std::cell::Cell;

        let consulted = Cell::new(false);
        let selected =
            live_sizing_configuration_with(Option::<&LiveTranslationConfiguration>::None, || {
                consulted.set(true);
                true
            });

        assert!(selected.is_none());
        assert!(
            !consulted.get(),
            "the default hot path must short-circuit before sizing authority"
        );
    }

    #[test]
    fn live_arena_policy_is_exact_and_fails_closed() {
        use std::ffi::OsStr;

        assert_eq!(
            live_arena_runtime_policy_from(None).expect("default policy"),
            LiveArenaRuntimePolicy::Disabled
        );
        assert_eq!(
            live_arena_runtime_policy_from(Some(OsStr::new("0"))).expect("off policy"),
            LiveArenaRuntimePolicy::Disabled
        );
        assert_eq!(
            live_arena_runtime_policy_from(Some(OsStr::new("compiler"))).expect("compiler policy"),
            LiveArenaRuntimePolicy::Compiler
        );
        for invalid in ["", "1", "Compiler", "compiler ", "all"] {
            assert!(
                live_arena_runtime_policy_from(Some(OsStr::new(invalid))).is_err(),
                "invalid policy {invalid:?} must fail closed"
            );
        }
    }

    #[test]
    fn live_sizing_counts_exact_prepared_outputs_and_checked_page_alignment() {
        let mut census = LiveArenaSizingCensus::new(0x4000).expect("sizing census");
        let first = emit::SharedInitialLengths {
            code: 1,
            hot: 7,
            cold: 11,
        };
        let second = emit::SharedInitialLengths {
            code: 0x4001,
            hot: 13,
            cold: 17,
        };

        census
            .record([0x11; 32], GuestVa(0x4000), first)
            .expect("first prepared output");
        census
            .record([0x22; 32], GuestVa(0x8000), second)
            .expect("second prepared output");
        // The same exact block can be encountered repeatedly in one process;
        // sizing is over the unique arena record, not translation frequency.
        census
            .record([0x11; 32], GuestVa(0x4000), first)
            .expect("duplicate exact output");
        assert!(
            census
                .record(
                    [0x11; 32],
                    GuestVa(0x4000),
                    emit::SharedInitialLengths {
                        code: first.code + 4,
                        ..first
                    },
                )
                .is_err(),
            "one exact block cannot have two prepared shapes"
        );

        assert_eq!(
            census.totals(),
            LiveArenaSizingTotals {
                prepared_blocks: 2,
                aligned_code_bytes: 0xc000,
                hot_bytes: 20,
                cold_bytes: 28,
                aligned_hot_bytes: 24,
                aligned_cold_bytes: 40,
            }
        );
    }

    #[test]
    fn live_sizing_totals_come_from_real_prepared_shared_initial_output() {
        use crate::block::{BlockPlan, PlannedExit};
        use crate::emit::EmitAddressMode;
        use crate::shared_cache::{
            AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
            NativePageProfileIdentity, SourceFingerprint, TranslationUnitKey,
        };
        use crate::types::CodeGeneration;

        let start = GuestVa(0x4000);
        let words = [0xd400_0001_u32];
        let key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x7a; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(0x4000).expect("file length"),
            start,
            GuestCodeLen::new(0x4000).expect("guest length"),
            SourceFingerprint::from_words(&words),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        );
        let plan = BlockPlan {
            start,
            end: GuestVa(start.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest: start,
                resume: GuestVa(start.raw() + 4),
            },
            extensions: Vec::new(),
        };
        let prepared =
            emit::prepare_shared_initial(&key, &plan, EmitAddressMode::Direct, words.to_vec())
                .expect("prepare real shared INITIAL fixture");
        assert_eq!(
            prepared.lengths(),
            emit::SharedInitialLengths {
                code: 40,
                hot: 5,
                cold: 28,
            },
            "the known one-syscall fixture has hand-checked prepared lengths"
        );

        let mut census = LiveArenaSizingCensus::new(0x4000).expect("sizing census");
        census
            .record_prepared(
                key.live_digest().expect("live key digest"),
                start,
                &prepared,
            )
            .expect("record real prepared output");
        assert_eq!(
            census.totals(),
            LiveArenaSizingTotals {
                prepared_blocks: 1,
                aligned_code_bytes: 0x4000,
                hot_bytes: 5,
                cold_bytes: 28,
                aligned_hot_bytes: 8,
                aligned_cold_bytes: 32,
            }
        );
    }

    #[test]
    fn live_sizing_rejects_alignment_and_addition_overflow() {
        assert!(LiveArenaSizingCensus::new(0).is_err());
        assert!(LiveArenaSizingCensus::new(0x1000).is_err());
        assert!(LiveArenaSizingCensus::new(0x3000).is_err());

        let mut census = LiveArenaSizingCensus::new(0x4000).expect("sizing census");
        assert!(
            census
                .record(
                    [0x33; 32],
                    GuestVa(0x4000),
                    emit::SharedInitialLengths {
                        code: u64::MAX,
                        hot: 0,
                        cold: 0,
                    },
                )
                .is_err()
        );

        let mut census = LiveArenaSizingCensus::with_totals_for_test(
            0x4000,
            LiveArenaSizingTotals {
                prepared_blocks: u64::MAX,
                aligned_code_bytes: 0,
                hot_bytes: 0,
                cold_bytes: 0,
                aligned_hot_bytes: 0,
                aligned_cold_bytes: 0,
            },
        );
        assert!(
            census
                .record(
                    [0x44; 32],
                    GuestVa(0x8000),
                    emit::SharedInitialLengths {
                        code: 4,
                        hot: 0,
                        cold: 0,
                    },
                )
                .is_err()
        );

        let mut census = LiveArenaSizingCensus::with_totals_for_test(
            0x4000,
            LiveArenaSizingTotals {
                prepared_blocks: 0,
                aligned_code_bytes: 0,
                hot_bytes: u64::MAX,
                cold_bytes: 0,
                aligned_hot_bytes: 0,
                aligned_cold_bytes: 0,
            },
        );
        let error = census
            .record(
                [0x55; 32],
                GuestVa(0xc000),
                emit::SharedInitialLengths {
                    code: 4,
                    hot: 1,
                    cold: 0,
                },
            )
            .expect_err("raw HOT byte addition must be checked");
        assert!(error.to_string().contains("HOT byte sum overflowed"));
    }

    #[test]
    fn live_sizing_export_contains_unique_identities_lengths_and_totals() {
        let mut census = LiveArenaSizingCensus::new(0x4000).expect("sizing census");
        census
            .record(
                [0xab; 32],
                GuestVa(0x1234),
                emit::SharedInitialLengths {
                    code: 12,
                    hot: 9,
                    cold: 17,
                },
            )
            .expect("prepared output");

        let export = census.render_for_test("process-exit");
        assert!(export.starts_with("LIVEARENASIZE1 reason=process-exit host_page=16384\n"));
        assert!(export.contains(
            "BLOCK unit=abababababababababababababababababababababababababababababababab guest=0x1234 code=12 code_cursor=16384 hot=9 hot_cursor=16 cold=17 cold_cursor=24"
        ));
        assert!(export.contains(
            "TOTAL prepared=1 code_cursor=16384 hot=9 hot_cursor=16 cold=17 cold_cursor=24"
        ));
    }

    #[test]
    fn warm_process_lookup_does_not_take_the_translation_state_lock() {
        let source = include_str!("translator.rs");
        let body = source
            .split_once("    fn translate_read_mostly(\n")
            .expect("read-mostly translation function")
            .1
            .split_once("    fn translate<const PROFILE: bool>(\n")
            .expect("read-mostly translation function end")
            .0;

        assert!(
            body.contains("self.process.published_blocks.get(guest, generation)"),
            "warm process hits must use the independently synchronized published-block index"
        );
        assert!(
            !body.contains("self.process.state.read()"),
            "a translating writer must not force warm process hits into psynch_cvwait"
        );
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
    fn live_configuration_uses_exact_unit_keys_without_persistent_store() {
        use crate::shared_cache::{
            AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
            NativePageProfileIdentity, SharedExecutableSegment, SharedImageConfig,
        };

        let image = SharedImageConfig {
            executable: ExecutableIdentity::Digest([0x5a; 32]),
            page_profile: NativePageProfileIdentity::Native16k,
            address_mode: AddressModeIdentity::Direct,
            segments: vec![SharedExecutableSegment::new(
                ImageFileOffset::new(0x1200),
                ImageFileLen::new(8).expect("file length"),
                GuestVa(0x4000),
                GuestCodeLen::new(8).expect("guest length"),
                vec![0xd503_201f, 0xd65f_03c0].into(),
            )],
        };
        let expected = image
            .key_for_segment(&image.segments[0])
            .live_digest()
            .expect("exact live digest");
        let exact_stem = image
            .key_for_segment(&image.segments[0])
            .file_stem()
            .expect("exact unit stem");
        let translator =
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");

        translator
            .configure_live_image_matching_for_test(image, 0x4000, &exact_stem)
            .expect("live-only exact image configuration");

        assert_eq!(translator.live_unit_digests_for_test(), vec![expected]);
        assert!(!translator.shared_store_configured_for_test());
    }

    #[test]
    fn compiler_live_selector_rejects_every_nonexact_unit_key() {
        use crate::shared_cache::{
            AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
            NativePageProfileIdentity, SharedExecutableSegment, SharedImageConfig,
        };
        let image = SharedImageConfig {
            executable: ExecutableIdentity::Digest([0x6b; 32]),
            page_profile: NativePageProfileIdentity::Native16k,
            address_mode: AddressModeIdentity::Direct,
            segments: vec![SharedExecutableSegment::new(
                ImageFileOffset::new(0),
                ImageFileLen::new(4).expect("file length"),
                GuestVa(0x10000),
                GuestCodeLen::new(4).expect("guest length"),
                vec![0xd65f_03c0].into(),
            )],
        };
        let translator =
            ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT).expect("translator");

        assert!(
            !translator
                .configure_live_image_matching_for_test(image, 0x4000, "not-the-exact-key")
                .expect("nonmatching configuration")
        );
        assert!(translator.live_unit_digests_for_test().is_empty());
    }

    /// Task 6D: the translator side of the live arena — the READY lookup at
    /// the top of an authoritative INITIAL miss, the unique-winner
    /// publication, every named fallback, and the bookkeeping that must stay
    /// OUT of the private publication path.
    ///
    /// The arena protocol itself (claim lifecycle, the 6B transaction, the
    /// READY consumer's hash/HOT/generation/W^X validation) is proven against
    /// real mapped objects in `carrick-native-darwin`. What these tests own is
    /// the wiring: which paths are consulted, in what order, what a fallback
    /// is named, and what an installed live block may and may not touch.
    mod live_arena_wiring {
        use super::super::{
            LiveConsultation, LiveFallback, ProcessState, ProcessTranslator, PublicationAuthority,
            PublishedBlockLookup, PublishedBlockMetadata, ThreadTranslator, TranslationOutcome,
            TranslationResult, cache, emit, types,
        };
        use super::TEST_HOST_JIT;
        use crate::block::{BlockPlan, PlannedExit};
        use crate::emit::{EmitAddressMode, PreparedSharedInitial};
        use crate::live_arena::{
            LiveBlockAuthority, LiveBlockExtents, LiveOwnedChunkIdentity, LivePrivateReason,
            LivePublishOutcome, LiveReadyOutcome, LiveReservation, LiveRxPayload,
            LiveTranslationAuthority,
        };
        use crate::shared_cache::{
            AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
            NativePageProfileIdentity, SharedExecutableSegment, SharedImageConfig,
            TranslationUnitKey,
        };
        use carrick_dsr::cache::{PageGenerationObservation, PageGenerationTable};
        use carrick_dsr::profile;
        use carrick_guest_mem::{GuestVa, HostVa};
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const SEGMENT_START: u64 = 0x4000;
        const SEGMENT_LEN: u64 = 0x4000;
        /// One `svc #0`: the smallest plan shape B3 accepts.
        const SYSCALL_WORD: u32 = 0xd400_0001;

        fn live_image() -> SharedImageConfig {
            SharedImageConfig {
                executable: ExecutableIdentity::Digest([0x6d; 32]),
                page_profile: NativePageProfileIdentity::Native16k,
                address_mode: AddressModeIdentity::Direct,
                segments: vec![SharedExecutableSegment::new(
                    ImageFileOffset::new(0),
                    ImageFileLen::new(SEGMENT_LEN).expect("file length"),
                    GuestVa(SEGMENT_START),
                    GuestCodeLen::new(SEGMENT_LEN).expect("guest length"),
                    vec![SYSCALL_WORD].into(),
                )],
            }
        }

        fn live_key() -> TranslationUnitKey {
            let image = live_image();
            image.key_for_segment(&image.segments[0])
        }

        fn syscall_plan(start: GuestVa) -> BlockPlan {
            BlockPlan {
                start,
                end: GuestVa(start.raw() + 4),
                generation: types::CodeGeneration::INITIAL,
                instructions: Vec::new(),
                exit: PlannedExit::Syscall {
                    guest: start,
                    resume: GuestVa(start.raw() + 4),
                },
                extensions: Vec::new(),
            }
        }

        fn prepared_block(start: GuestVa) -> PreparedSharedInitial {
            emit::prepare_shared_initial(
                &live_key(),
                &syscall_plan(start),
                EmitAddressMode::Direct,
                vec![SYSCALL_WORD],
            )
            .expect("prepare a real shared INITIAL block")
        }

        /// One contiguous stand-in for the arena's RX payload.
        ///
        /// Blocks are bump-allocated out of it exactly as the arena's chunk
        /// allocator appends them, so every installed entry lies inside ONE
        /// interval — which is what the process view's target authority and
        /// its executable-range catalog node describe. A `Box<[u8]>` per block
        /// would scatter entries across unrelated heap allocations and could
        /// not model a single RX payload at all.
        struct FakeLiveArena {
            bytes: Box<[u8]>,
            next: AtomicUsize,
        }

        impl FakeLiveArena {
            const CAPACITY: usize = 64 * 1024;

            fn new() -> Arc<Self> {
                Arc::new(Self {
                    bytes: vec![0_u8; Self::CAPACITY].into_boxed_slice(),
                    next: AtomicUsize::new(0),
                })
            }

            fn base(&self) -> usize {
                self.bytes.as_ptr() as usize
            }

            fn payload(&self) -> LiveRxPayload {
                LiveRxPayload::new(HostVa(self.base()), HostVa(self.base() + Self::CAPACITY))
                    .expect("a nonempty fake RX payload")
            }

            /// Reserve `len` bytes, 4-aligned and strictly ascending, like the
            /// arena's append-only code cursor.
            fn reserve(&self, len: usize) -> usize {
                let aligned = len.next_multiple_of(4);
                let offset = self.next.fetch_add(aligned, Ordering::Relaxed);
                assert!(
                    offset + aligned <= Self::CAPACITY,
                    "fake live arena exhausted"
                );
                offset
            }
        }

        /// One installed live block, carved out of the fixture's RX payload.
        ///
        /// The code bytes are this fixture's own — the point of these tests is
        /// the translator's bookkeeping over an ALREADY-VALIDATED block, not
        /// the mapped-arena protocol — but the COLD stream is real prepared
        /// output, so the lazy decode under test is the production decode.
        struct FakeLiveBlock {
            arena: Arc<FakeLiveArena>,
            offset: usize,
            len: usize,
            hot_len: usize,
            cold: Vec<u8>,
            guest_start: GuestVa,
            source_page: GuestVa,
            group_slot: u32,
            chunk_index: u32,
            cold_reads: AtomicUsize,
        }

        impl FakeLiveBlock {
            fn from_prepared(
                arena: &Arc<FakeLiveArena>,
                prepared: &PreparedSharedInitial,
                guest_start: GuestVa,
            ) -> Self {
                let len = prepared.code_bytes().len();
                let offset = arena.reserve(len);
                Self {
                    arena: Arc::clone(arena),
                    offset,
                    len,
                    hot_len: prepared.hot_bytes().len(),
                    cold: prepared.cold_bytes().to_vec(),
                    guest_start,
                    source_page: GuestVa(guest_start.raw() & !(16 * 1024 - 1)),
                    group_slot: 7,
                    chunk_index: 3,
                    cold_reads: AtomicUsize::new(0),
                }
            }
        }

        impl LiveBlockAuthority for FakeLiveBlock {
            fn entry(&self) -> HostVa {
                HostVa(self.arena.base() + self.offset)
            }
            /// The block's real prepared extents, at this fixture's own
            /// offsets: `code_len()` is the trait's default over the code
            /// extent, so the installed length and the counted bytes come
            /// from one number here exactly as they do in the real arena.
            fn extents(&self) -> LiveBlockExtents {
                LiveBlockExtents {
                    code: LiveReservation {
                        offset: self.offset as u64,
                        len: self.len as u64,
                    },
                    hot: LiveReservation {
                        offset: 0,
                        len: self.hot_len as u64,
                    },
                    cold: LiveReservation {
                        offset: 0,
                        len: self.cold.len() as u64,
                    },
                }
            }
            fn guest_start(&self) -> GuestVa {
                self.guest_start
            }
            fn source_page(&self) -> GuestVa {
                self.source_page
            }
            fn group_slot(&self) -> u32 {
                self.group_slot
            }
            fn chunk_index(&self) -> u32 {
                self.chunk_index
            }
            fn cold_metadata(&self) -> Result<&[u8], LivePrivateReason> {
                self.cold_reads.fetch_add(1, Ordering::Relaxed);
                Ok(&self.cold)
            }
        }

        /// What the fake authority answers with. One scripted outcome per
        /// path keeps each fallback test a single named arm.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum FakeReady {
            Miss,
            Hit,
            /// A READY record whose acquired block resolves no usable
            /// process-local entry: the install-time refusal
            /// (`LiveFallback::UnresolvedEntry`) that no scripted arm could
            /// otherwise reach.
            HitUnresolvable,
            Private(LivePrivateReason),
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum FakeWinner {
            Publish,
            /// A racing publisher already reached READY.
            RacedToReady,
            Private(LivePrivateReason),
            PrepareRefused,
        }

        /// One observed `revoke_source_range` call: the mutated range and
        /// the caller's typed hints.
        type RecordedRevocation = (
            std::ops::Range<GuestVa>,
            Vec<crate::live_arena::LiveSourceChunkHint>,
        );

        struct FakeAuthority {
            arena: Arc<FakeLiveArena>,
            ready: Mutex<FakeReady>,
            winner: FakeWinner,
            prepares: AtomicUsize,
            ready_lookups: AtomicUsize,
            enumerations: AtomicUsize,
            installed: Mutex<Vec<Arc<FakeLiveBlock>>>,
            /// Task 7: every `revoke_source_range` call this authority saw,
            /// with the caller's hint chunks — the seam's observation point.
            revocations: Mutex<Vec<RecordedRevocation>>,
            /// Scripted revocation outcomes: per 16 KiB source page, the
            /// local RX chunks a revocation of that page protects. Tests set
            /// this to cover the entries they installed.
            revoke_plan: Mutex<
                std::collections::BTreeMap<GuestVa, Vec<crate::live_arena::LiveRevokedChunk>>,
            >,
        }

        impl FakeAuthority {
            fn new(ready: FakeReady, winner: FakeWinner) -> Arc<Self> {
                Self::sharing(&FakeLiveArena::new(), ready, winner)
            }

            /// A second view of the SAME RX payload — the in-process exec
            /// shape, where the replacement image installs a fresh process
            /// view over the arena it inherited.
            fn sharing(
                arena: &Arc<FakeLiveArena>,
                ready: FakeReady,
                winner: FakeWinner,
            ) -> Arc<Self> {
                Arc::new(Self {
                    arena: Arc::clone(arena),
                    ready: Mutex::new(ready),
                    winner,
                    prepares: AtomicUsize::new(0),
                    ready_lookups: AtomicUsize::new(0),
                    enumerations: AtomicUsize::new(0),
                    installed: Mutex::new(Vec::new()),
                    revocations: Mutex::new(Vec::new()),
                    revoke_plan: Mutex::new(std::collections::BTreeMap::new()),
                })
            }

            /// Script the chunks a revocation of `source_page` protects.
            fn plan_revocation(
                &self,
                source_page: u64,
                chunks: Vec<crate::live_arena::LiveRevokedChunk>,
            ) {
                self.revoke_plan
                    .lock()
                    .expect("revoke plan")
                    .insert(GuestVa(source_page), chunks);
            }

            fn recorded_revocations(&self) -> Vec<RecordedRevocation> {
                self.revocations.lock().expect("revocations").clone()
            }

            fn block(
                &self,
                prepared: &PreparedSharedInitial,
                guest_start: GuestVa,
            ) -> Arc<FakeLiveBlock> {
                let block = Arc::new(FakeLiveBlock::from_prepared(
                    &self.arena,
                    prepared,
                    guest_start,
                ));
                self.installed
                    .lock()
                    .expect("installed")
                    .push(Arc::clone(&block));
                block
            }

            fn last_installed(&self) -> Arc<FakeLiveBlock> {
                Arc::clone(
                    self.installed
                        .lock()
                        .expect("installed")
                        .last()
                        .expect("one installed block"),
                )
            }
        }

        /// `Box<dyn LiveBlockAuthority>` over a shared fixture handle, so a
        /// test can still read the fixture's counters after installation.
        struct SharedFakeBlock(Arc<FakeLiveBlock>);

        impl LiveBlockAuthority for SharedFakeBlock {
            fn entry(&self) -> HostVa {
                self.0.entry()
            }
            fn extents(&self) -> LiveBlockExtents {
                self.0.extents()
            }
            fn guest_start(&self) -> GuestVa {
                self.0.guest_start()
            }
            fn source_page(&self) -> GuestVa {
                self.0.source_page()
            }
            fn group_slot(&self) -> u32 {
                self.0.group_slot()
            }
            fn chunk_index(&self) -> u32 {
                self.0.chunk_index()
            }
            fn cold_metadata(&self) -> Result<&[u8], LivePrivateReason> {
                self.0.cold_metadata()
            }
        }

        /// A block whose entry resolves to zero: the shape
        /// `install_live_block` refuses by name.
        struct UnresolvableFakeBlock(Arc<FakeLiveBlock>);

        impl LiveBlockAuthority for UnresolvableFakeBlock {
            fn entry(&self) -> HostVa {
                HostVa(0)
            }
            fn extents(&self) -> LiveBlockExtents {
                self.0.extents()
            }
            fn guest_start(&self) -> GuestVa {
                self.0.guest_start()
            }
            fn source_page(&self) -> GuestVa {
                self.0.source_page()
            }
            fn group_slot(&self) -> u32 {
                self.0.group_slot()
            }
            fn chunk_index(&self) -> u32 {
                self.0.chunk_index()
            }
            fn cold_metadata(&self) -> Result<&[u8], LivePrivateReason> {
                self.0.cold_metadata()
            }
        }

        impl LiveTranslationAuthority for FakeAuthority {
            fn acquire_ready(
                &self,
                _key: &TranslationUnitKey,
                guest_start: GuestVa,
                _generation: &PageGenerationObservation,
            ) -> LiveReadyOutcome {
                self.ready_lookups.fetch_add(1, Ordering::Relaxed);
                match *self.ready.lock().expect("ready script") {
                    FakeReady::Miss => LiveReadyOutcome::Miss,
                    FakeReady::Private(reason) => LiveReadyOutcome::Private(reason),
                    FakeReady::HitUnresolvable => {
                        let prepared = prepared_block(guest_start);
                        let block = self.block(&prepared, guest_start);
                        LiveReadyOutcome::Installed(Box::new(UnresolvableFakeBlock(block)))
                    }
                    FakeReady::Hit => {
                        let prepared = prepared_block(guest_start);
                        LiveReadyOutcome::Installed(Box::new(SharedFakeBlock(
                            self.block(&prepared, guest_start),
                        )))
                    }
                }
            }

            fn publish_winner(
                &self,
                _key: &TranslationUnitKey,
                guest_start: GuestVa,
                _block_end: GuestVa,
                _generation: &PageGenerationObservation,
                _owner_pid: i32,
                prepare: &mut dyn FnMut() -> Result<PreparedSharedInitial, types::DsrError>,
            ) -> LivePublishOutcome {
                match self.winner {
                    FakeWinner::Private(reason) => LivePublishOutcome::Private(reason),
                    // A racing winner reached READY first: no `prepare` runs.
                    FakeWinner::RacedToReady => {
                        let prepared = prepared_block(guest_start);
                        LivePublishOutcome::Installed(Box::new(SharedFakeBlock(
                            self.block(&prepared, guest_start),
                        )))
                    }
                    FakeWinner::PrepareRefused => {
                        self.prepares.fetch_add(1, Ordering::Relaxed);
                        LivePublishOutcome::PrepareRefused(types::DsrError::CachePolicy(
                            "test preparation refused".to_string(),
                        ))
                    }
                    FakeWinner::Publish => {
                        self.prepares.fetch_add(1, Ordering::Relaxed);
                        match prepare() {
                            Ok(prepared) => LivePublishOutcome::Installed(Box::new(
                                SharedFakeBlock(self.block(&prepared, guest_start)),
                            )),
                            Err(error) => LivePublishOutcome::PrepareRefused(error),
                        }
                    }
                }
            }

            fn active_chunks_for_source_page(
                &self,
                source_page: GuestVa,
            ) -> Vec<LiveOwnedChunkIdentity> {
                self.enumerations.fetch_add(1, Ordering::Relaxed);
                vec![LiveOwnedChunkIdentity {
                    group_slot: 7,
                    chunk_index: 11,
                    unit_key_digest: [0; 32],
                    source_page: source_page.raw(),
                }]
            }

            fn rx_payload(&self) -> Option<LiveRxPayload> {
                Some(self.arena.payload())
            }

            fn revoke_source_range(
                &self,
                range: std::ops::Range<GuestVa>,
                hint_chunks: &[crate::live_arena::LiveSourceChunkHint],
            ) -> Result<Vec<crate::live_arena::LiveRevokedChunk>, types::DsrError> {
                self.revocations
                    .lock()
                    .expect("revocations")
                    .push((range.clone(), hint_chunks.to_vec()));
                let plan = self.revoke_plan.lock().expect("revoke plan");
                let mut revoked: Vec<crate::live_arena::LiveRevokedChunk> = Vec::new();
                const PAGE: u64 = 16 * 1024;
                let mut page = range.start.raw() & !(PAGE - 1);
                let last = range.end.raw().saturating_sub(1) & !(PAGE - 1);
                while page <= last {
                    if let Some(chunks) = plan.get(&GuestVa(page)) {
                        for chunk in chunks {
                            if !revoked
                                .iter()
                                .any(|seen| seen.chunk_index == chunk.chunk_index)
                            {
                                revoked.push(*chunk);
                            }
                        }
                    }
                    page += PAGE;
                }
                Ok(revoked)
            }
        }

        /// A view whose RX payload cannot be resolved: the named refusal that
        /// keeps a payload-less authority from ever being installed.
        struct PayloadlessAuthority;

        impl LiveTranslationAuthority for PayloadlessAuthority {
            fn acquire_ready(
                &self,
                _key: &TranslationUnitKey,
                _guest_start: GuestVa,
                _generation: &PageGenerationObservation,
            ) -> LiveReadyOutcome {
                LiveReadyOutcome::Miss
            }

            fn publish_winner(
                &self,
                _key: &TranslationUnitKey,
                _guest_start: GuestVa,
                _block_end: GuestVa,
                _generation: &PageGenerationObservation,
                _owner_pid: i32,
                _prepare: &mut dyn FnMut() -> Result<PreparedSharedInitial, types::DsrError>,
            ) -> LivePublishOutcome {
                LivePublishOutcome::Private(LivePrivateReason::InvalidRecord)
            }

            fn active_chunks_for_source_page(
                &self,
                _source_page: GuestVa,
            ) -> Vec<LiveOwnedChunkIdentity> {
                Vec::new()
            }

            fn rx_payload(&self) -> Option<LiveRxPayload> {
                None
            }

            fn revoke_source_range(
                &self,
                _range: std::ops::Range<GuestVa>,
                _hint_chunks: &[crate::live_arena::LiveSourceChunkHint],
            ) -> Result<Vec<crate::live_arena::LiveRevokedChunk>, types::DsrError> {
                Ok(Vec::new())
            }
        }

        struct Lane {
            translator: Arc<ProcessTranslator>,
            generations: PageGenerationTable,
            authority: Arc<FakeAuthority>,
        }

        impl Lane {
            fn new(ready: FakeReady, winner: FakeWinner) -> Self {
                Self::with_authority(FakeAuthority::new(ready, winner))
            }

            fn with_authority(authority: Arc<FakeAuthority>) -> Self {
                let translator = Arc::new(
                    ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT)
                        .expect("process translator"),
                );
                Self::configure(&translator);
                translator
                    .install_live_authority(Arc::clone(&authority) as Arc<_>)
                    .expect("install the live authority");
                Self {
                    translator,
                    generations: PageGenerationTable::new(0x4000).expect("generation table"),
                    authority,
                }
            }

            fn configure(translator: &ProcessTranslator) {
                assert!(
                    translator
                        .configure_live_image_matching_for_test(
                            live_image(),
                            0x4000,
                            &live_key().file_stem().expect("exact unit stem"),
                        )
                        .expect("configure the live image"),
                    "the fixture image must select its own exact unit key"
                );
            }

            /// Same lane without a live authority: the policy-off default.
            fn unconfigured() -> Self {
                let authority = FakeAuthority::new(FakeReady::Miss, FakeWinner::Publish);
                Self {
                    translator: Arc::new(
                        ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT)
                            .expect("process translator"),
                    ),
                    generations: PageGenerationTable::new(0x4000).expect("generation table"),
                    authority,
                }
            }

            fn observe(&self, guest: GuestVa) -> PageGenerationObservation {
                self.generations.observe(guest).expect("observation")
            }

            fn with_state<R>(&self, body: impl FnOnce(&mut ProcessState) -> R) -> R {
                body(&mut self.translator.state.write())
            }

            /// Install one live block through the production READY path and
            /// return its process-local RX entry.
            fn install_ready(&self, guest: GuestVa) -> types::CacheVa {
                let observation = self.observe(guest);
                match self.with_state(|state| {
                    state.live_ready_consultation(
                        guest,
                        types::CodeGeneration::INITIAL,
                        &observation,
                    )
                }) {
                    LiveConsultation::Installed(entry) => entry,
                    other => panic!("the fixture's READY hit must install: {other:?}"),
                }
            }

            /// This process's live-lane counters, read straight off the
            /// process state the production paths increment.
            fn stats(&self) -> super::super::ResolverStats {
                self.translator.state.read().stats
            }

            /// The fallback-class counters as `(class, count)` for every
            /// class that moved — the shape an assertion can name.
            fn fallbacks(&self) -> Vec<(profile::LiveLaneFallbackClass, u64)> {
                let stats = self.stats();
                profile::LiveLaneFallbackClass::ALL
                    .into_iter()
                    .filter(|class| stats.live_fallbacks[class.index()] != 0)
                    .map(|class| (class, stats.live_fallbacks[class.index()]))
                    .collect()
            }

            fn private_cache_entry(&self) -> types::CacheVa {
                types::CacheVa::published(HostVa(
                    usize::try_from(self.translator.cache_host_range().start)
                        .expect("cache address fits usize"),
                ))
            }
        }

        fn assert_private_indexes_untouched(state: &ProcessState) {
            assert_eq!(
                state.cache.used_bytes(),
                0,
                "a live install must never emit into the private cache"
            );
            assert!(
                state.blocks.is_empty(),
                "`blocks` is the PRIVATE publication authority"
            );
            assert!(
                state.pending.is_empty(),
                "a live block never waits in `pending`"
            );
            assert!(
                state.direct_link_incoming.is_empty(),
                "a live block is never a mutable incoming-link target"
            );
            assert!(
                state.trusted_entries.is_empty(),
                "a live block publishes no private trusted entry"
            );
            assert!(
                state.private_published_index.is_empty(),
                "a live block belongs to the LIVE address index"
            );
        }

        #[test]
        fn ready_hit_installs_without_mutating_the_private_cache() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            let consultation = lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });

            let LiveConsultation::Installed(entry) = consultation else {
                panic!("a READY hit must install: {consultation:?}");
            };
            lane.with_state(|state| {
                assert_private_indexes_untouched(state);
                assert_eq!(
                    state.live_blocks.len(),
                    1,
                    "the installed block is the live index's"
                );
                assert_eq!(state.live_published_index.len(), 1);
                assert!(state.owns_live_entry(entry));
                assert_eq!(
                    state
                        .published_blocks
                        .get(guest, types::CodeGeneration::INITIAL),
                    Some(super::super::PublishedBlockLookup {
                        entry,
                        trusted_entry: None,
                    }),
                    "the read-side mirror serves the live entry with no trusted entry"
                );
            });
        }

        #[test]
        fn a_second_ready_lookup_is_served_from_the_live_index() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            let first = lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });
            let second = lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });

            assert_eq!(first, second, "the same entry is served twice");
            assert_eq!(
                lane.authority.ready_lookups.load(Ordering::Relaxed),
                1,
                "an installed live block is not re-validated on every entry"
            );
            lane.with_state(|state| assert_eq!(state.live_published_index.len(), 1));
        }

        #[test]
        fn miss_then_winner_publication_installs_the_prepared_block() {
            let lane = Lane::new(FakeReady::Miss, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            let ready = lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });
            assert_eq!(ready, LiveConsultation::Miss);

            let published = lane.with_state(|state| {
                state.live_winner_publication(
                    &syscall_plan(guest),
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )
            });

            let LiveConsultation::Installed(entry) = published else {
                panic!("the unique winner must install its own block: {published:?}");
            };
            assert_eq!(
                lane.authority.prepares.load(Ordering::Relaxed),
                1,
                "the winner prepares exactly once"
            );
            lane.with_state(|state| {
                assert_private_indexes_untouched(state);
                assert!(state.owns_live_entry(entry));
            });
        }

        #[test]
        fn a_race_lost_to_a_ready_publisher_installs_without_preparing() {
            let lane = Lane::new(FakeReady::Miss, FakeWinner::RacedToReady);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            let published = lane.with_state(|state| {
                state.live_winner_publication(
                    &syscall_plan(guest),
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )
            });

            assert!(matches!(published, LiveConsultation::Installed(_)));
            assert_eq!(
                lane.authority.prepares.load(Ordering::Relaxed),
                0,
                "consuming another publisher's record must not translate twice"
            );
        }

        #[test]
        fn every_ineligibility_falls_back_immediately_with_its_own_name() {
            let guest = GuestVa(SEGMENT_START);

            // The policy-off default: no authority is installed at all.
            let unconfigured = Lane::unconfigured();
            let observation = unconfigured.observe(guest);
            assert_eq!(
                unconfigured.with_state(|state| state.live_ready_consultation(
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation
                )),
                LiveConsultation::Private(LiveFallback::Unconfigured)
            );

            // Regenerated: no INITIAL-keyed record can serve this page.
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let observation = lane.observe(guest);
            assert_eq!(
                lane.with_state(|state| state.live_ready_consultation(
                    guest,
                    types::CodeGeneration::claimed(2),
                    &observation
                )),
                LiveConsultation::Private(LiveFallback::Regenerated)
            );

            // Outside the ONE configured live segment.
            let outside = GuestVa(SEGMENT_START + SEGMENT_LEN);
            let outside_observation = lane.observe(outside);
            assert_eq!(
                lane.with_state(|state| state.live_ready_consultation(
                    outside,
                    types::CodeGeneration::INITIAL,
                    &outside_observation
                )),
                LiveConsultation::Private(LiveFallback::OutsideSegment)
            );

            // Every arena refusal keeps its own name through the seam.
            for reason in [
                LivePrivateReason::Building,
                LivePrivateReason::Failed,
                LivePrivateReason::CasLost,
                LivePrivateReason::InvalidRecord,
                LivePrivateReason::Capacity,
                LivePrivateReason::ExhaustedProbes,
                LivePrivateReason::KeyEncoding,
                LivePrivateReason::UnknownState,
            ] {
                let refusing = Lane::new(FakeReady::Private(reason), FakeWinner::Publish);
                let observation = refusing.observe(guest);
                assert_eq!(
                    refusing.with_state(|state| state.live_ready_consultation(
                        guest,
                        types::CodeGeneration::INITIAL,
                        &observation
                    )),
                    LiveConsultation::Private(LiveFallback::Arena(reason)),
                    "{reason:?} must reach the translator unrenamed"
                );
                refusing.with_state(|state| assert_private_indexes_untouched(state));
            }

            // BUILDING, a lost block CAS, corruption, and capacity are the
            // WINNER path's own refusals and are equally immediate.
            for reason in [
                LivePrivateReason::Building,
                LivePrivateReason::CasLost,
                LivePrivateReason::Capacity,
                LivePrivateReason::InvalidRecord,
            ] {
                let refusing = Lane::new(FakeReady::Miss, FakeWinner::Private(reason));
                let observation = refusing.observe(guest);
                assert_eq!(
                    refusing.with_state(|state| state.live_winner_publication(
                        &syscall_plan(guest),
                        guest,
                        types::CodeGeneration::INITIAL,
                        &observation,
                        EmitAddressMode::Direct,
                        Some(&vec![SYSCALL_WORD]),
                    )),
                    LiveConsultation::Private(LiveFallback::Arena(reason)),
                    "{reason:?} must reach the translator unrenamed"
                );
                refusing.with_state(|state| assert_private_indexes_untouched(state));
            }
        }

        #[test]
        fn the_winner_path_rejects_every_ineligible_plan_shape() {
            let guest = GuestVa(SEGMENT_START);
            let lane = Lane::new(FakeReady::Miss, FakeWinner::Publish);
            let observation = lane.observe(guest);

            // Sensitive, exclusive, and unsupported terminal exits own their
            // whole block and are never shared INITIAL code.
            for exit in [
                PlannedExit::Sensitive {
                    guest,
                    word: SYSCALL_WORD,
                    exit: types::SensitiveExit {
                        kind: types::SensitiveKind::ReadTpidr,
                        register: None,
                        resume: GuestVa(guest.raw() + 4),
                    },
                    fusion: None,
                },
                PlannedExit::Unsupported {
                    guest,
                    word: 0,
                    op: bad64::Op::UDF,
                },
            ] {
                let plan = BlockPlan {
                    exit,
                    ..syscall_plan(guest)
                };
                assert_eq!(
                    lane.with_state(|state| state.live_winner_publication(
                        &plan,
                        guest,
                        types::CodeGeneration::INITIAL,
                        &observation,
                        EmitAddressMode::Direct,
                        Some(&vec![SYSCALL_WORD]),
                    )),
                    LiveConsultation::Private(LiveFallback::UnsupportedShape)
                );
            }

            // A decoded interval that leaves its 16 KiB source page.
            let crossing = BlockPlan {
                end: GuestVa(SEGMENT_START + 16 * 1024 + 4),
                ..syscall_plan(guest)
            };
            assert_eq!(
                lane.with_state(|state| state.live_winner_publication(
                    &crossing,
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )),
                LiveConsultation::Private(LiveFallback::CrossPage)
            );

            // No exact source words: nothing can be prepared.
            assert_eq!(
                lane.with_state(|state| state.live_winner_publication(
                    &syscall_plan(guest),
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    None,
                )),
                LiveConsultation::Private(LiveFallback::SourceWordsUnavailable)
            );

            assert_eq!(
                lane.authority.prepares.load(Ordering::Relaxed),
                0,
                "an ineligible plan must never reach the claim protocol"
            );
            lane.with_state(|state| assert_private_indexes_untouched(state));
        }

        #[test]
        fn a_refused_preparation_falls_back_privately() {
            let lane = Lane::new(FakeReady::Miss, FakeWinner::PrepareRefused);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            assert_eq!(
                lane.with_state(|state| state.live_winner_publication(
                    &syscall_plan(guest),
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )),
                LiveConsultation::Private(LiveFallback::PrepareRefused)
            );
            lane.with_state(|state| assert_private_indexes_untouched(state));
        }

        #[test]
        fn cold_metadata_decodes_only_when_a_fault_interrogates_it() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            let LiveConsultation::Installed(entry) = lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            }) else {
                panic!("the fixture installs a READY block");
            };
            let block = lane.authority.last_installed();
            assert_eq!(
                block.cold_reads.load(Ordering::Relaxed),
                0,
                "installing must not touch the block's COLD extent"
            );

            // The prepared block's own pc map names its first cache offset;
            // reconstructing that PC is the only thing that decodes COLD.
            let (map, _recovery) = lane.with_state(|state| {
                state.published[0]
                    .metadata
                    .materialize()
                    .expect("decode the live COLD stream")
            });
            let first = map.first().copied().expect("a nonempty live pc map");
            let reads_after_materialize = block.cold_reads.load(Ordering::Relaxed);
            assert!(reads_after_materialize >= 1);

            let cache_pc = GuestVa(entry.host().raw() as u64 + u64::from(first.cache.get()));
            let (resolved, _action) = lane
                .with_state(|state| state.guest_pc_for_cache(cache_pc))
                .expect("a live cache PC resolves through the live address index");
            assert_eq!(resolved, first.guest);
            assert!(
                block.cold_reads.load(Ordering::Relaxed) > reads_after_materialize,
                "fault reconstruction decodes the mapped COLD stream on demand"
            );
        }

        #[test]
        fn the_source_page_hint_is_descriptor_authoritative_and_enumerated_once() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });

            let page = GuestVa(SEGMENT_START & !(16 * 1024 - 1));
            lane.with_state(|state| {
                let hint = state.live_source_page_hint(page).expect("a page hint");
                assert!(
                    hint.chunks.contains(&3) && hint.chunks.contains(&11),
                    "the hint carries the block's own chunk AND every ACTIVE \
                     descriptor the enumeration found: {hint:?}"
                );
                assert!(hint.groups.contains(&7));
            });
            assert_eq!(
                lane.authority.enumerations.load(Ordering::Relaxed),
                1,
                "one enumeration per newly observed chunk, not per install"
            );
        }

        /// A live install registers its page dependency, so a guest code write
        /// makes `translate`'s invalidation loop name the block stale.
        ///
        /// Scope, deliberately: this proves the REGISTRATION, not the removal.
        /// The removal itself lives in `ProcessState::translate`, which needs a
        /// mapped image these process-state-level tests do not build; what it
        /// does with a stale key (`blocks`/`live_blocks`/`published_blocks`
        /// removal) is asserted structurally below instead of driven.
        ///
        /// The parity that matters and is easy to misread: a stale block is
        /// removed from the LOOKUP indexes only. It stays in `published` and in
        /// its address index — exactly as a stale PRIVATE block does — because
        /// those exist for fault reconstruction over code that may still be
        /// executing, and are cleared wholesale by `clear_published` at exec.
        #[test]
        fn a_live_block_registers_its_page_dependency_for_invalidation() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);
            lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });

            let key = (guest, types::CodeGeneration::INITIAL);
            let stale = lane.with_state(|state| {
                state
                    .dependencies
                    .invalidate_page(observation.page(), types::CodeGeneration::claimed(2))
            });
            assert_eq!(
                stale,
                vec![key],
                "the live block registered its page dependency"
            );

            // The removals `translate`'s loop performs for each stale key.
            lane.with_state(|state| {
                state.blocks.remove(&key);
                state.live_blocks.remove(&key);
                state.published_blocks.remove(key);
                assert!(state.live_blocks.is_empty());
                assert!(
                    state
                        .published_blocks
                        .get(guest, types::CodeGeneration::INITIAL)
                        .is_none()
                );
                // Parity with a stale private block: the fault-reconstruction
                // list and its address index deliberately retain the entry.
                assert_eq!(state.published.len(), 1);
                assert_eq!(state.live_published_index.len(), 1);
            });

            // `clear_published` is what actually empties them, at exec.
            lane.with_state(|state| {
                state.clear_published();
                assert!(state.published.is_empty());
                assert!(state.live_published_index.is_empty());
                assert!(state.live_source_pages.is_empty());
            });
        }

        #[test]
        fn a_live_translation_result_is_named_live() {
            assert_ne!(
                TranslationOutcome::LiveArena,
                TranslationOutcome::Translated
            );
            assert_ne!(
                TranslationOutcome::LiveArena,
                TranslationOutcome::SharedUnit
            );
        }

        #[test]
        fn an_installed_live_block_carries_the_live_publication_kind() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);
            lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });
            lane.with_state(|state| {
                assert!(matches!(
                    state.published[0].metadata,
                    PublishedBlockMetadata::Live { .. }
                ));
            });
        }

        // ---------------------------------------------------------------
        // Task 6E — target authority, gateway routing, catalog ownership
        // ---------------------------------------------------------------

        #[test]
        fn a_live_entry_resolves_to_the_process_views_stable_target_authority() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let live = lane.install_ready(GuestVa(SEGMENT_START));
            let payload = lane.authority.arena.payload();

            assert_eq!(
                lane.translator
                    .publication_authority(live)
                    .expect("a live entry has an executable authority"),
                PublicationAuthority::Live,
            );
            assert_eq!(
                lane.translator
                    .publication_authority(lane.private_cache_entry())
                    .expect("a private cache entry has an executable authority"),
                PublicationAuthority::Private,
            );

            let record = lane
                .translator
                .executable_authority(PublicationAuthority::Live)
                .expect("the live target authority is installed");
            assert_eq!(
                record.host_range(),
                payload.host_range(),
                "the target authority describes the process view's RX payload exactly"
            );
            assert!(record.owns(live), "and it owns the installed entry");
            // ONE record for the whole payload, not one per block: the address
            // emitted code caches must not change per installed block.
            let second = lane.install_ready(GuestVa(SEGMENT_START + 4));
            assert_ne!(live, second);
            assert!(std::ptr::eq(
                record,
                lane.translator
                    .executable_authority(PublicationAuthority::Live)
                    .expect("the live target authority is still installed"),
            ));
        }

        #[test]
        fn an_entry_no_executable_region_owns_fails_closed_by_name() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            lane.install_ready(GuestVa(SEGMENT_START));
            // A host address in neither the private cache nor the RX payload.
            let stray = types::CacheVa::published(HostVa(0x10));

            let error = lane
                .translator
                .publication_authority(stray)
                .expect_err("an unowned entry must never resolve an authority");

            assert!(
                error.to_string().contains("has no executable authority"),
                "{error}"
            );
        }

        #[test]
        fn the_executable_range_catalog_registers_the_live_rx_payload() {
            let unconfigured = Lane::unconfigured();
            let private_pc = usize::try_from(unconfigured.translator.cache_host_range().start)
                .expect("cache address fits usize");
            assert!(
                unconfigured
                    .translator
                    .executable_range_catalog()
                    .contains(private_pc),
                "the private cache is catalogued with or without a live authority"
            );

            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let live = lane.install_ready(GuestVa(SEGMENT_START));
            let payload = lane.authority.arena.payload();
            let catalog = lane.translator.executable_range_catalog();

            assert!(
                catalog.contains(live.host().raw()),
                "a live RX PC must classify as authoritative translated code"
            );
            assert!(catalog.contains(payload.start().raw()));
            assert!(!catalog.contains(payload.end().raw()));
            assert!(
                catalog.contains(
                    usize::try_from(lane.translator.cache_host_range().start)
                        .expect("cache address fits usize")
                ),
                "registering the live payload must not displace the private range"
            );
            assert!(!catalog.contains(0x10));
        }

        #[test]
        fn installing_a_live_authority_refuses_an_absent_or_disagreeing_rx_payload() {
            let translator = Arc::new(
                ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT)
                    .expect("process translator"),
            );
            Lane::configure(&translator);

            let error = translator
                .install_live_authority(Arc::new(PayloadlessAuthority) as Arc<_>)
                .expect_err("a view without an RX payload can never be an authority");
            assert!(
                error.to_string().contains("exposes no RX payload range"),
                "{error}"
            );
            assert!(
                translator
                    .executable_authority(PublicationAuthority::Live)
                    .is_err(),
                "a refused install mints no target authority"
            );

            let first = FakeAuthority::new(FakeReady::Hit, FakeWinner::Publish);
            translator
                .install_live_authority(Arc::clone(&first) as Arc<_>)
                .expect("install the live authority");
            // The exec reset retires the authority; a replacement image
            // re-installs over the SAME inherited arena.
            translator.state.write().live_authority = None;

            let elsewhere = FakeAuthority::new(FakeReady::Hit, FakeWinner::Publish);
            let error = translator
                .install_live_authority(Arc::clone(&elsewhere) as Arc<_>)
                .expect_err("a different RX payload must not silently replace the record");
            assert!(
                error
                    .to_string()
                    .contains("disagrees with this process's installed target authority"),
                "{error}"
            );

            let same_arena =
                FakeAuthority::sharing(&first.arena, FakeReady::Hit, FakeWinner::Publish);
            translator
                .install_live_authority(Arc::clone(&same_arena) as Arc<_>)
                .expect("the same RX payload re-installs");
        }

        #[test]
        fn a_private_direct_link_resolves_a_live_target_instead_of_waiting_in_pending() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let key = (guest, types::CodeGeneration::INITIAL);
            let live = lane.install_ready(guest);
            // Resolved BEFORE the write guard below: `cache_host_range` takes
            // its own read guard and the lock is not reentrant.
            let private = lane.private_cache_entry();

            lane.with_state(|state| {
                assert_eq!(
                    state.direct_link_target(key),
                    Some((PublicationAuthority::Live, live)),
                    "a live-only key resolves to the arena entry"
                );
                assert_eq!(
                    state.direct_link_target((GuestVa(SEGMENT_START + 0x40), key.1)),
                    None,
                    "an untranslated key still waits in `pending`"
                );
                // The private publication authority keeps precedence and keeps
                // targeting its trusted entry.
                state.blocks.insert(key, private);
                state
                    .trusted_entries
                    .insert(key, types::CacheOffset::published(8));
                assert_eq!(
                    state.direct_link_target(key),
                    Some((
                        PublicationAuthority::Private,
                        types::CacheVa::published(HostVa(private.host().raw() + 8)),
                    )),
                );
            });
        }

        #[test]
        fn a_live_installation_drains_the_private_links_pending_on_its_key() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let key = (guest, types::CodeGeneration::INITIAL);
            let site = cache::LinkSite {
                source: lane.private_cache_entry(),
                slot: types::CacheOffset::published(0),
            };
            lane.with_state(|state| {
                state.pending.entry(key).or_default().push(site);
            });

            let live = lane.install_ready(guest);
            lane.with_state(|state| {
                state
                    .drain_pending_links_to_live(key, live)
                    .expect("drain the private sites waiting on this key")
            });

            lane.with_state(|state| {
                assert!(
                    !state.pending.contains_key(&key),
                    "a live installation IS a publication of that key"
                );
                // Whether the branch encodes depends on the ±128 MiB reach
                // between the private cache and the arena, but a recorded
                // incoming site is always a PRIVATE source: a live block's own
                // code is immutable arena bytes this process never patches.
                for sites in state.direct_link_incoming.values() {
                    for recorded in sites {
                        assert_eq!(
                            lane.translator
                                .publication_authority(recorded.source)
                                .expect("a recorded link source has an authority"),
                            PublicationAuthority::Private,
                            "a LIVE source must never enter the mutable link indexes"
                        );
                    }
                }
            });
        }

        #[test]
        fn an_indirect_publication_carries_the_resolved_kind_into_the_entry_flavor() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let memory =
                crate::mapped_memory::NativeMappedMemory::shared_install_test_fixture(4096);
            let generation = types::CodeGeneration::INITIAL;
            let live_guest = GuestVa(SEGMENT_START);
            let live = lane.install_ready(live_guest);
            let private_entry = lane.private_cache_entry();
            let live_record = lane
                .translator
                .executable_authority(PublicationAuthority::Live)
                .expect("the live target authority is installed")
                as *const _ as u64;
            let private_record = lane
                .translator
                .executable_authority(PublicationAuthority::Private)
                .expect("the private target authority always exists")
                as *const _ as u64;
            let mut thread = ThreadTranslator::for_process(Arc::clone(&lane.translator), 11);
            let resolved = |entry: types::CacheVa, outcome: TranslationOutcome| TranslationResult {
                entry,
                generation,
                outcome,
                emitted_bytes: 0,
                cache_used_bytes: 0,
            };

            // A LIVE target is FLAVOR 0: the guarded entry plus the process
            // view's stable target authority, which the emitted slow path
            // re-validates the entry against and installs. Pre-6E this
            // publication was SKIPPED.
            thread
                .publish_indirect_target(
                    &memory,
                    live_guest,
                    &resolved(live, TranslationOutcome::LiveArena),
                )
                .expect("publish a live target");
            assert_eq!(
                thread.indirect_cache_entry_for_test(live_guest),
                Some((live.host().raw() as u64, live_record, 0)),
                "a live target publishes flavor 0 against the LIVE authority"
            );

            // A PRIVATE target with a trusted entry stays FLAVOR 1.
            let trusted_guest = GuestVa(SEGMENT_START + 0x100);
            lane.translator.published_blocks.insert(
                (trusted_guest, generation),
                PublishedBlockLookup {
                    entry: private_entry,
                    trusted_entry: Some(types::CacheOffset::published(8)),
                },
            );
            thread
                .publish_indirect_target(
                    &memory,
                    trusted_guest,
                    &resolved(private_entry, TranslationOutcome::Translated),
                )
                .expect("publish a private trusted target");
            let (tagged, generation_atomic, trusted_code) = thread
                .indirect_cache_entry_for_test(trusted_guest)
                .expect("a published private trusted way");
            assert_eq!(tagged, (generation.get() << 1) | 1, "flavor 1 tag");
            assert_ne!(generation_atomic, 0, "flavor 1 carries the page generation");
            assert_eq!(trusted_code, private_entry.host().raw() as u64 + 8);

            // A PRIVATE target WITHOUT one is flavor 0 against the private
            // authority — the same shape as a live target, different record.
            let plain_guest = GuestVa(SEGMENT_START + 0x200);
            thread
                .publish_indirect_target(
                    &memory,
                    plain_guest,
                    &resolved(private_entry, TranslationOutcome::Translated),
                )
                .expect("publish a private guarded target");
            assert_eq!(
                thread.indirect_cache_entry_for_test(plain_guest),
                Some((private_entry.host().raw() as u64, private_record, 0)),
            );
            assert_ne!(
                live_record, private_record,
                "the two regions publish DIFFERENT authority records"
            );

            // And the fail-safe the pre-6E skip provided survives: an entry no
            // region owns never reaches emitted code.
            let stray_guest = GuestVa(SEGMENT_START + 0x300);
            let error = thread
                .publish_indirect_target(
                    &memory,
                    stray_guest,
                    &resolved(
                        types::CacheVa::published(HostVa(0x10)),
                        TranslationOutcome::Translated,
                    ),
                )
                .expect_err("an unowned entry must never be cached");
            assert!(
                error.to_string().contains("has no executable authority"),
                "{error}"
            );
            assert_eq!(thread.indirect_cache_entry_for_test(stray_guest), None);
        }

        #[test]
        fn a_prepared_entry_carries_the_executable_authority_that_owns_it() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let memory =
                crate::mapped_memory::NativeMappedMemory::shared_install_test_fixture(4096);
            let guest = GuestVa(SEGMENT_START);
            // The live install must be observed through the SAME generation
            // table `prepare_entry` reads, so the published lookup mirror is
            // keyed on the generation the prepare re-derives.
            let observation = memory
                .dsr_generation_observation(guest)
                .expect("fixture observation");
            let live = match lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            }) {
                LiveConsultation::Installed(entry) => entry,
                other => panic!("the fixture's READY hit must install: {other:?}"),
            };
            let mut thread = ThreadTranslator::for_process(Arc::clone(&lane.translator), 12);

            let prepared = thread
                .prepare_entry::<false>(
                    &memory,
                    &super::super::NativeUcontextSnapshot {
                        pc: guest.raw(),
                        ..Default::default()
                    },
                )
                .expect("a live block resolves through the published lookup mirror");

            assert_eq!(prepared.entry, live);
            assert_eq!(
                prepared.executable_authority(),
                PublicationAuthority::Live,
                "the gateway must enter a live block under the LIVE cache range, \
                 not the private one"
            );
        }

        #[test]
        fn an_exec_reset_retires_the_live_configuration_authority_and_catalog_node() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let live = lane.install_ready(GuestVa(SEGMENT_START));
            assert!(
                lane.translator
                    .executable_range_catalog()
                    .contains(live.host().raw())
            );

            let mut thread = ThreadTranslator::for_process(Arc::clone(&lane.translator), 6);
            let mut token = thread
                .prepare_direct_binding_exec_reset()
                .expect("mint the retiring translator's exec authority");
            lane.translator
                .reset_after_fork_for_exec(&thread, &mut token)
                .expect("commit the exec reset");

            lane.with_state(|state| {
                assert!(
                    state.live_translation.is_none(),
                    "the outgoing image's live unit key is retired"
                );
                assert!(
                    state.live_authority.is_none(),
                    "and so is this process's authority over the arena for it"
                );
                assert!(state.live_blocks.is_empty());
                assert!(state.live_published_index.is_empty());
            });
            assert!(
                !lane
                    .translator
                    .executable_range_catalog()
                    .contains(live.host().raw()),
                "the RX payload's catalog node is dropped with the authority"
            );

            // The replacement image re-configures and re-installs over the
            // same inherited arena, and the lane comes back.
            Lane::configure(&lane.translator);
            lane.translator
                .install_live_authority(Arc::clone(&lane.authority) as Arc<_>)
                .expect("re-install for the replacement image");
            assert!(
                lane.translator
                    .executable_range_catalog()
                    .contains(live.host().raw()),
                "and the payload is catalogued again"
            );
        }

        /// Task 7: revocation of mutated source pages and the exact
        /// stale-instruction-abort classifier. Shared INITIAL code omits its
        /// per-block generation guard, so these tests pin the ONLY two
        /// defenses: a guest write revokes the matching RX chunks through the
        /// one seam, and only the measured stale abort shape
        /// (EC 0x20|0x21, pc == far, pc in a revoked chunk) is ever consumed.
        mod live_revoke {
            use super::*;
            use crate::live_arena::LiveRevokedChunk;

            /// The measured fd-backed revoked-chunk abort ESR on this host
            /// (see `live_revoke_abort_shape_probe_records_signal_esr_far_pc`
            /// in carrick-native-darwin): EC 0x20 (instruction abort, lower
            /// EL), IFSC 0x06, delivered as SIGBUS with FAR == PC.
            const MEASURED_STALE_ESR: u64 = 0x8200_0006;
            /// A data abort from EL0 (EC 0x24) with the same IFSC bits.
            const DATA_ABORT_ESR: u64 = 0x9000_0006;

            /// Install one live block per page and script the authority's
            /// revocation plan to cover each installed entry with one exact
            /// chunk.
            fn planned_chunk(
                lane: &Lane,
                chunk_index: u32,
                source_page: u64,
                covering: types::CacheVa,
            ) -> LiveRevokedChunk {
                let _ = lane;
                LiveRevokedChunk {
                    chunk_index,
                    source_page: GuestVa(source_page),
                    rx_start: HostVa(covering.host().raw() & !0x3ff),
                    rx_len: 0x400,
                }
            }

            #[test]
            fn guest_write_revokes_only_matching_source_page_chunks() {
                let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
                let page_a = SEGMENT_START;
                let page_b = SEGMENT_START + 16 * 1024;
                let first = lane.install_ready(GuestVa(page_a));
                let second = lane.install_ready(GuestVa(page_a + 0x100));
                // A live block on ANOTHER page, installed through the same
                // production bookkeeping (segment gating bypassed: this test
                // owns index hygiene, not eligibility).
                let observation_b = lane.observe(GuestVa(page_b));
                let prepared = prepared_block(GuestVa(page_b));
                let block_b = lane.authority.block(&prepared, GuestVa(page_b));
                lane.with_state(|state| {
                    state
                        .install_live_block(
                            (GuestVa(page_b), types::CodeGeneration::INITIAL),
                            &observation_b,
                            None,
                            Box::new(SharedFakeBlock(block_b)),
                        )
                        .expect("install the other page's live block")
                });

                // Multiple chunks (and, in the real arena, multiple unit
                // digests) for the mutated page; one chunk for the other page
                // that must NOT be revoked. Chunk ranges are DISJOINT like
                // the real arena's: the second models another exact digest's
                // chunk for the same page.
                let chunk_one = planned_chunk(&lane, 3, page_a, first);
                assert!(
                    (chunk_one.rx_start.raw()..chunk_one.rx_start.raw() + chunk_one.rx_len)
                        .contains(&second.host().raw()),
                    "fixture: both installed entries share the first chunk"
                );
                let chunk_two = LiveRevokedChunk {
                    chunk_index: 9,
                    source_page: GuestVa(page_a),
                    rx_start: HostVa(chunk_one.rx_start.raw() + chunk_one.rx_len),
                    rx_len: chunk_one.rx_len,
                };
                lane.authority
                    .plan_revocation(page_a, vec![chunk_one, chunk_two]);
                lane.authority
                    .plan_revocation(page_b, vec![planned_chunk(&lane, 21, page_b, first)]);

                let revoked = lane
                    .translator
                    .revoke_live_source_range(GuestVa(page_a)..GuestVa(page_a + 4))
                    .expect("revocation must succeed");
                assert_eq!(revoked, 2, "both of the mutated page's chunks");

                let calls = lane.authority.recorded_revocations();
                assert_eq!(calls.len(), 1, "one callback per mutation note");
                assert!(
                    calls[0].0.start.raw() <= page_a && calls[0].0.end.raw() > page_a,
                    "the callback names the mutated range: {:?}",
                    calls[0].0
                );
                assert!(
                    calls[0].0.end.raw() <= page_b,
                    "the callback must not cover the untouched page: {:?}",
                    calls[0].0
                );
                // The process-local hint travels as validated hints, and the
                // install-time hint recorded the block's own chunk plus the
                // descriptor enumeration's.
                assert!(
                    calls[0]
                        .1
                        .iter()
                        .any(|hint| hint.source_page == GuestVa(page_a)),
                    "hints carry the mutated page: {:?}",
                    calls[0].1
                );
                assert!(
                    calls[0]
                        .1
                        .iter()
                        .all(|hint| hint.source_page == GuestVa(page_a)),
                    "hints must not leak other pages: {:?}",
                    calls[0].1
                );

                let catalog = lane.translator.revoked_live_chunks_for_test();
                assert_eq!(
                    catalog,
                    vec![chunk_one, chunk_two],
                    "the catalog holds exactly the mutated page's chunks, \
                     ascending by rx_start"
                );

                lane.with_state(|state| {
                    assert!(
                        !state
                            .live_blocks
                            .contains_key(&(GuestVa(page_a), types::CodeGeneration::INITIAL)),
                        "the mutated page's block leaves the live lookup index"
                    );
                    assert!(
                        !state.live_blocks.contains_key(&(
                            GuestVa(page_a + 0x100),
                            types::CodeGeneration::INITIAL
                        )),
                    );
                    assert!(
                        state
                            .live_blocks
                            .contains_key(&(GuestVa(page_b), types::CodeGeneration::INITIAL)),
                        "the untouched page's block survives"
                    );
                    assert!(
                        state
                            .published_blocks
                            .get(GuestVa(page_a), types::CodeGeneration::INITIAL)
                            .is_none(),
                        "the read-side mirror stops serving the revoked block"
                    );
                    assert!(
                        state
                            .published_blocks
                            .get(GuestVa(page_b), types::CodeGeneration::INITIAL)
                            .is_some(),
                    );
                    assert!(
                        !state.live_published_index.is_empty(),
                        "the ADDRESS index is retained: it is the fault-recovery \
                         index, not a lookup index"
                    );
                });
            }

            /// One lane with an installed live block whose entry the scripted
            /// revocation covers — the classifier fixture every consumption
            /// test starts from.
            fn revoked_lane() -> (Lane, types::CacheVa) {
                let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
                let guest = GuestVa(SEGMENT_START);
                let entry = lane.install_ready(guest);
                lane.authority.plan_revocation(
                    SEGMENT_START,
                    vec![planned_chunk(&lane, 3, SEGMENT_START, entry)],
                );
                lane.translator
                    .revoke_live_source_range(GuestVa(SEGMENT_START)..GuestVa(SEGMENT_START + 4))
                    .expect("revocation must succeed");
                (lane, entry)
            }

            /// Positive control shared by the negative tests: the EXACT
            /// measured shape at the revoked entry IS consumed, with the
            /// block's guest PC recovered. A stubbed classifier fails here,
            /// so none of the negative pins can pass vacuously.
            fn assert_consumes_measured_shape(lane: &Lane, entry: types::CacheVa) {
                let pc = entry.host().raw() as u64;
                lane.with_state(|state| {
                    let recovery = state
                        .stale_live_instruction_abort(MEASURED_STALE_ESR, pc, pc)
                        .expect("the measured stale shape must be consumed");
                    assert_eq!(recovery.guest_pc, GuestVa(SEGMENT_START));
                });
            }

            #[test]
            fn data_abort_in_revoked_chunk_is_not_consumed() {
                let (lane, entry) = revoked_lane();
                assert_consumes_measured_shape(&lane, entry);
                let pc = entry.host().raw() as u64;
                lane.with_state(|state| {
                    assert!(
                        state
                            .stale_live_instruction_abort(DATA_ABORT_ESR, pc, pc)
                            .is_none(),
                        "a data abort is not the stale shape even inside a \
                         revoked chunk"
                    );
                });
            }

            #[test]
            fn instruction_abort_in_foreign_prot_none_range_is_not_consumed() {
                let (lane, entry) = revoked_lane();
                assert_consumes_measured_shape(&lane, entry);
                let foreign = (entry.host().raw() as u64) + 0x10_0000;
                lane.with_state(|state| {
                    assert!(
                        state
                            .stale_live_instruction_abort(MEASURED_STALE_ESR, foreign, foreign)
                            .is_none(),
                        "an instruction abort outside every revoked chunk \
                         falls through to the normal fault path"
                    );
                });
            }

            #[test]
            fn mismatched_pc_and_far_is_not_consumed() {
                let (lane, entry) = revoked_lane();
                assert_consumes_measured_shape(&lane, entry);
                let pc = entry.host().raw() as u64;
                lane.with_state(|state| {
                    assert!(
                        state
                            .stale_live_instruction_abort(MEASURED_STALE_ESR, pc, pc + 8)
                            .is_none(),
                        "pc != far is not the exact stale shape"
                    );
                });
            }

            #[test]
            fn in_process_exec_drops_retired_live_ranges() {
                let (lane, entry) = revoked_lane();
                assert!(
                    !lane.translator.revoked_live_chunks_for_test().is_empty(),
                    "the fixture must revoke before the exec reset"
                );

                let mut thread = ThreadTranslator::for_process(Arc::clone(&lane.translator), 6);
                let mut token = thread
                    .prepare_direct_binding_exec_reset()
                    .expect("mint the retiring translator's exec authority");
                lane.translator
                    .reset_after_fork_for_exec(&thread, &mut token)
                    .expect("commit the exec reset");

                assert!(
                    lane.translator.revoked_live_chunks_for_test().is_empty(),
                    "an in-process exec drops the retired revoked ranges"
                );
                let pc = entry.host().raw() as u64;
                lane.with_state(|state| {
                    assert!(
                        state
                            .stale_live_instruction_abort(MEASURED_STALE_ESR, pc, pc)
                            .is_none(),
                        "no retired range may classify after the reset"
                    );
                });
            }

            /// mprotect, munmap and remap all reach the ONE revocation seam
            /// (`note_dsr_code_mutation` -> `revoke_live_source_range`), so
            /// no executable-lifecycle event can mutate a source page while a
            /// stale shared chunk stays executable.
            #[test]
            fn mprotect_munmap_and_remap_share_the_revocation_seam() {
                use carrick_guest_mem::GuestMemory as _;
                const PAGE: usize = 16 * 1024;

                let process = Arc::new(
                    ProcessTranslator::new_with_host(64 * 1024, &TEST_HOST_JIT)
                        .expect("process translator"),
                );
                let authority = FakeAuthority::new(FakeReady::Miss, FakeWinner::Publish);
                process
                    .install_live_authority(Arc::clone(&authority) as Arc<_>)
                    .expect("install the recording authority");

                let mapped = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        2 * PAGE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON | libc::MAP_PRIVATE,
                        -1,
                        0,
                    )
                };
                assert_ne!(mapped, libc::MAP_FAILED, "map the seam fixture");
                let base = mapped as u64;
                let mut memory = crate::mapped_memory::NativeMappedMemory {
                    address_mode: carrick_dsr::address::NativeAddressMode::Direct,
                    owned_host_ranges: Arc::new(vec![
                        HostVa(mapped as usize)..HostVa(mapped as usize + 2 * PAGE),
                    ]),
                    regions: vec![crate::mapped_memory::NativeMappedRegion {
                        start: base,
                        end: base + 2 * PAGE as u64,
                        host_protects: true,
                        shared_futex: false,
                        guest_writable: false,
                        default_prot: carrick_abi::LINUX_PROT_READ | carrick_abi::LINUX_PROT_EXEC,
                        shared_key_base: 0,
                        shared_key_offset: 0,
                    }],
                    protections: carrick_guest_mem::protections::MemoryProtections::default(),
                    native_prot_ranges: crate::prot_ranges::NativeProtRanges::default(),
                    native_write_exec_writable_pages: std::collections::BTreeSet::new(),
                    linux4k_page_protections: std::collections::BTreeMap::new(),
                    exclusive_sequences: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
                    host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
                    host_page_size: PAGE as u64,
                    linux_page_size: PAGE as u64,
                    dsr_generations: cache::PageGenerationTable::new(PAGE as u64)
                        .expect("generation table"),
                    dsr_translator: Some(Arc::clone(&process)),
                };

                // Leg 1 — mprotect: dropping exec from an executable page.
                memory
                    .protect_range(base, PAGE, carrick_abi::LINUX_PROT_READ)
                    .expect("mprotect leg");
                assert_eq!(
                    authority.recorded_revocations().len(),
                    1,
                    "mprotect reaches the revocation seam"
                );

                // Restoring exec is itself a code-visibility transition and
                // notes again — count it so the remap delta below is exact.
                memory
                    .protect_range(
                        base,
                        PAGE,
                        carrick_abi::LINUX_PROT_READ | carrick_abi::LINUX_PROT_EXEC,
                    )
                    .expect("restore exec");
                let after_restore = authority.recorded_revocations().len();

                // Leg 2 — remap: a fresh mapping replacing executable code.
                memory
                    .map_host_alias(base, PAGE as u64, &[], None, false)
                    .expect("remap leg");
                assert_eq!(
                    authority.recorded_revocations().len(),
                    after_restore + 1,
                    "a remap over executable code reaches the same seam"
                );

                // Leg 3 — munmap: the second executable page unmaps.
                let before_unmap = authority.recorded_revocations().len();
                memory
                    .unmap_range(base + PAGE as u64, PAGE)
                    .expect("munmap leg");
                assert_eq!(
                    authority.recorded_revocations().len(),
                    before_unmap + 1,
                    "munmap reaches the same seam"
                );

                unsafe {
                    libc::munmap(mapped, 2 * PAGE);
                }
            }
        }

        /// Task 6F: the live lane's typed counters.
        ///
        /// Every one of these asserts on the counters the PRODUCTION paths
        /// increment, read straight off `ProcessState::stats` — there is no
        /// test-only counting seam, so a counter that stops being incremented
        /// fails here.
        #[test]
        fn every_live_fallback_reason_maps_to_its_own_counter_class() {
            let arena_reasons = [
                LivePrivateReason::Building,
                LivePrivateReason::Failed,
                LivePrivateReason::CasLost,
                LivePrivateReason::InvalidRecord,
                LivePrivateReason::Capacity,
                LivePrivateReason::ExhaustedProbes,
                LivePrivateReason::KeyEncoding,
                LivePrivateReason::WriteAttempted,
                LivePrivateReason::UnknownState,
            ];
            let every_reason: Vec<LiveFallback> = [
                LiveFallback::Unconfigured,
                LiveFallback::Regenerated,
                LiveFallback::OutsideSegment,
                LiveFallback::CrossPage,
                LiveFallback::UnsupportedShape,
                LiveFallback::SourceWordsUnavailable,
                LiveFallback::PrepareRefused,
                LiveFallback::UnresolvedEntry,
            ]
            .into_iter()
            .chain(arena_reasons.into_iter().map(LiveFallback::Arena))
            .collect();

            let classes: Vec<profile::LiveLaneFallbackClass> = every_reason
                .iter()
                .map(|reason| profile::LiveLaneFallbackClass::from(*reason))
                .collect();

            // Total AND injective: the arena's nine refusals keep their own
            // names instead of collapsing into one `arena` bucket, which is
            // exactly what makes a mis-attributed fallback visible.
            assert_eq!(
                classes.len(),
                profile::LiveLaneFallbackClass::COUNT,
                "every named reason has a class and every class has a reason"
            );
            let mut indexes: Vec<usize> = classes.iter().map(|class| class.index()).collect();
            indexes.sort_unstable();
            indexes.dedup();
            assert_eq!(
                indexes,
                (0..profile::LiveLaneFallbackClass::COUNT).collect::<Vec<_>>(),
                "two reasons must never share one counter"
            );
        }

        #[test]
        fn each_named_fallback_increments_exactly_its_own_counter() {
            let observed =
                |lane: &Lane| -> Vec<(profile::LiveLaneFallbackClass, u64)> { lane.fallbacks() };

            // 1. The policy-off default: no authority, no configured image.
            let unconfigured = Lane::unconfigured();
            let guest = GuestVa(SEGMENT_START);
            let observation = unconfigured.observe(guest);
            unconfigured.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });
            assert_eq!(
                observed(&unconfigured),
                vec![(profile::LiveLaneFallbackClass::Unconfigured, 1)]
            );

            // 2. A regenerated page.
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let regenerated = types::CodeGeneration::INITIAL
                .next()
                .expect("a second generation");
            lane.with_state(|state| {
                state.live_ready_consultation(guest, regenerated, &lane.observe(guest))
            });
            assert_eq!(
                observed(&lane),
                vec![(profile::LiveLaneFallbackClass::Regenerated, 1)]
            );

            // 3. A block no configured live segment contains.
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let outside = GuestVa(SEGMENT_START + SEGMENT_LEN + 0x1000);
            let outside_observation = lane.observe(outside);
            lane.with_state(|state| {
                state.live_ready_consultation(
                    outside,
                    types::CodeGeneration::INITIAL,
                    &outside_observation,
                )
            });
            assert_eq!(
                observed(&lane),
                vec![(profile::LiveLaneFallbackClass::OutsideSegment, 1)]
            );

            // 4. An installed block that resolves no process-local entry.
            let lane = Lane::new(FakeReady::HitUnresolvable, FakeWinner::Publish);
            let observation = lane.observe(guest);
            lane.with_state(|state| {
                state.live_ready_consultation(guest, types::CodeGeneration::INITIAL, &observation)
            });
            assert_eq!(
                observed(&lane),
                vec![(profile::LiveLaneFallbackClass::UnresolvedEntry, 1)]
            );

            // 5. Every one of the arena's own named refusals, unrenamed.
            for (reason, class) in [
                (
                    LivePrivateReason::Building,
                    profile::LiveLaneFallbackClass::ArenaBuilding,
                ),
                (
                    LivePrivateReason::Failed,
                    profile::LiveLaneFallbackClass::ArenaFailed,
                ),
                (
                    LivePrivateReason::CasLost,
                    profile::LiveLaneFallbackClass::ArenaCasLost,
                ),
                (
                    LivePrivateReason::InvalidRecord,
                    profile::LiveLaneFallbackClass::ArenaInvalidRecord,
                ),
                (
                    LivePrivateReason::Capacity,
                    profile::LiveLaneFallbackClass::ArenaCapacity,
                ),
                (
                    LivePrivateReason::ExhaustedProbes,
                    profile::LiveLaneFallbackClass::ArenaExhaustedProbes,
                ),
                (
                    LivePrivateReason::KeyEncoding,
                    profile::LiveLaneFallbackClass::ArenaKeyEncoding,
                ),
                (
                    LivePrivateReason::WriteAttempted,
                    profile::LiveLaneFallbackClass::ArenaWriteAttempted,
                ),
                (
                    LivePrivateReason::UnknownState,
                    profile::LiveLaneFallbackClass::ArenaUnknownState,
                ),
            ] {
                let lane = Lane::new(FakeReady::Private(reason), FakeWinner::Publish);
                let observation = lane.observe(guest);
                lane.with_state(|state| {
                    state.live_ready_consultation(
                        guest,
                        types::CodeGeneration::INITIAL,
                        &observation,
                    )
                });
                assert_eq!(
                    observed(&lane),
                    vec![(class, 1)],
                    "the arena's {reason:?} must reach its own counter"
                );
            }

            // 6. The winner path's own plan screens, each on a fresh lane so
            // the asserted counter is the only one that moved.
            let winner_cases: Vec<(
                &str,
                BlockPlan,
                Option<Vec<u32>>,
                profile::LiveLaneFallbackClass,
            )> = vec![
                (
                    "a terminal exit a shared block cannot republish",
                    BlockPlan {
                        exit: PlannedExit::Unsupported {
                            guest,
                            word: 0,
                            op: bad64::Op::UDF,
                        },
                        ..syscall_plan(guest)
                    },
                    Some(vec![SYSCALL_WORD]),
                    profile::LiveLaneFallbackClass::UnsupportedShape,
                ),
                (
                    "a decoded interval that leaves its source page",
                    BlockPlan {
                        end: GuestVa(guest.raw() + 16 * 1024 + 4),
                        ..syscall_plan(guest)
                    },
                    Some(vec![SYSCALL_WORD]),
                    profile::LiveLaneFallbackClass::CrossPage,
                ),
                (
                    "a block whose exact source words are unavailable",
                    syscall_plan(guest),
                    None,
                    profile::LiveLaneFallbackClass::SourceWordsUnavailable,
                ),
            ];
            for (what, plan, words, class) in winner_cases {
                let lane = Lane::new(FakeReady::Miss, FakeWinner::Publish);
                let observation = lane.observe(guest);
                lane.with_state(|state| {
                    state.live_winner_publication(
                        &plan,
                        guest,
                        types::CodeGeneration::INITIAL,
                        &observation,
                        EmitAddressMode::Direct,
                        words.as_ref(),
                    )
                });
                assert_eq!(observed(&lane), vec![(class, 1)], "{what}");
            }

            // 7. The unique winner's own preparation refusing.
            let lane = Lane::new(FakeReady::Miss, FakeWinner::PrepareRefused);
            let observation = lane.observe(guest);
            lane.with_state(|state| {
                state.live_winner_publication(
                    &syscall_plan(guest),
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )
            });
            assert_eq!(
                observed(&lane),
                vec![(profile::LiveLaneFallbackClass::PrepareRefused, 1)]
            );
        }

        #[test]
        fn a_ready_hit_a_publish_win_and_a_fallback_are_separable_in_one_runs_counters() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let served = GuestVa(SEGMENT_START);
            let raced = GuestVa(SEGMENT_START + 0x40);

            // A fresh READY acquisition, then a repeat serve of the same key.
            let first = lane.install_ready(served);
            let second = lane.install_ready(served);
            assert_eq!(first, second);

            // A miss on a second key, then this process winning its race.
            *lane.authority.ready.lock().expect("ready script") = FakeReady::Miss;
            let observation = lane.observe(raced);
            let miss = lane.with_state(|state| {
                state.live_ready_consultation(raced, types::CodeGeneration::INITIAL, &observation)
            });
            assert_eq!(miss, LiveConsultation::Miss);
            let published = lane.with_state(|state| {
                state.live_winner_publication(
                    &syscall_plan(raced),
                    raced,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )
            });
            assert!(matches!(published, LiveConsultation::Installed(_)));

            // And one immediate private fallback.
            *lane.authority.ready.lock().expect("ready script") =
                FakeReady::Private(LivePrivateReason::Building);
            let building = GuestVa(SEGMENT_START + 0x80);
            let building_observation = lane.observe(building);
            lane.with_state(|state| {
                state.live_ready_consultation(
                    building,
                    types::CodeGeneration::INITIAL,
                    &building_observation,
                )
            });

            let stats = lane.stats();
            assert_eq!(
                (
                    stats.live_ready_hits,
                    stats.live_index_hits,
                    stats.live_ready_misses,
                    stats.live_publish_wins,
                    stats.live_publish_adoptions,
                    stats.live_blocks_installed,
                ),
                (1, 1, 1, 1, 0, 2),
                "a fresh READY acquisition, a repeat index serve, a miss and a \
                 winning publication are four different things"
            );
            assert_eq!(
                lane.fallbacks(),
                vec![(profile::LiveLaneFallbackClass::ArenaBuilding, 1)]
            );
        }

        #[test]
        fn a_publication_served_without_preparing_counts_as_an_adoption_not_a_win() {
            let lane = Lane::new(FakeReady::Miss, FakeWinner::RacedToReady);
            let guest = GuestVa(SEGMENT_START);
            let observation = lane.observe(guest);

            let published = lane.with_state(|state| {
                state.live_winner_publication(
                    &syscall_plan(guest),
                    guest,
                    types::CodeGeneration::INITIAL,
                    &observation,
                    EmitAddressMode::Direct,
                    Some(&vec![SYSCALL_WORD]),
                )
            });
            assert!(matches!(published, LiveConsultation::Installed(_)));

            let stats = lane.stats();
            assert_eq!(
                (stats.live_publish_wins, stats.live_publish_adoptions),
                (0, 1),
                "a race this process lost and was still served from is an \
                 ADOPTION: it prepared nothing"
            );
            assert_eq!(
                lane.authority.prepares.load(Ordering::Relaxed),
                0,
                "and the fixture agrees no preparation ran"
            );
        }

        #[test]
        fn the_live_byte_counters_are_the_published_blocks_exact_extents() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            lane.install_ready(guest);

            let block = lane.authority.last_installed();
            let extents = block.extents();
            let prepared = prepared_block(guest);
            let stats = lane.stats();
            assert_eq!(
                (
                    stats.live_blocks_installed,
                    stats.live_code_bytes,
                    stats.live_hot_bytes,
                    stats.live_cold_bytes,
                ),
                (1, extents.code.len, extents.hot.len, extents.cold.len,),
                "the counted bytes are the installed block's own extents"
            );
            assert_eq!(
                (
                    stats.live_code_bytes,
                    stats.live_hot_bytes,
                    stats.live_cold_bytes
                ),
                (
                    prepared.code_bytes().len() as u64,
                    prepared.hot_bytes().len() as u64,
                    prepared.cold_bytes().len() as u64,
                ),
                "and those extents are the real prepared block's sizes"
            );
        }

        #[test]
        fn the_private_cache_gauge_never_absorbs_a_live_byte() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let before = lane.with_state(|state| state.cache.used_bytes());

            lane.install_ready(guest);

            let after = lane.with_state(|state| state.cache.used_bytes());
            let stats = lane.stats();
            assert!(
                stats.live_code_bytes > 0,
                "the fixture installed a nonempty live block"
            );
            assert_eq!(
                before, after,
                "`cache_used_bytes` is the PRIVATE bump cache's occupancy; a \
                 live block executes from the arena and must never move it"
            );

            // And the same must hold of the EXPORTED gauge, which is where a
            // "just add the live bytes in" mistake would actually be made.
            let thread = ThreadTranslator::for_process(Arc::clone(&lane.translator), 11);
            let snapshot = thread.profile_snapshot();
            assert_eq!(
                snapshot.cache_used_bytes, after,
                "the exported private gauge must not have absorbed the live bytes"
            );
            assert_eq!(
                snapshot.live_code_bytes, stats.live_code_bytes,
                "the live bytes are exported as their OWN counters"
            );
        }

        #[test]
        fn a_live_installation_counts_the_private_links_it_patched() {
            let lane = Lane::new(FakeReady::Hit, FakeWinner::Publish);
            let guest = GuestVa(SEGMENT_START);
            let key = (guest, types::CodeGeneration::INITIAL);
            let site = cache::LinkSite {
                source: lane.private_cache_entry(),
                slot: types::CacheOffset::published(0),
            };
            lane.with_state(|state| {
                state.pending.entry(key).or_default().push(site);
            });

            let live = lane.install_ready(guest);
            lane.with_state(|state| {
                state
                    .drain_pending_links_to_live(key, live)
                    .expect("drain the private sites waiting on this key")
            });

            let stats = lane.stats();
            assert_eq!(
                stats.live_links_patched + stats.live_links_out_of_reach,
                1,
                "every drained site is counted exactly once, patched or not"
            );
            // Which of the two fires depends on the ±128 MiB reach between
            // this process's private cache and the arena — the real and
            // previously unmeasured question these two counters exist to
            // answer — so the test pins the accounting, not the distance.
            let recorded = lane.with_state(|state| {
                state
                    .direct_link_incoming
                    .values()
                    .map(|sites| sites.len() as u64)
                    .sum::<u64>()
            });
            assert_eq!(
                recorded, stats.live_links_patched,
                "a site counted as patched is a site recorded for severing"
            );
        }
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
            let observation = memory
                .dsr_generation_observation(plan.start)
                .expect("record-time observation");
            let mut scratch = crate::test_jit::test_cache(256 * 1024);
            let (emitted, artifact) = emit::emit_block_recording_artifact(
                &mut scratch,
                plan,
                emit::GenerationGuard::new(observation.current_atomic(), CodeGeneration::INITIAL),
                emit::EmitAddressMode::Direct,
                vec![0xd503_201f],
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

        #[cfg(feature = "alloc-owner-census")]
        #[test]
        fn allocation_owner_publication_indexes_owns_process_index_growth() {
            use crate::alloc_owner_census::test_support as census;
            use crate::alloc_owner_wire::AllocationOwner;
            use crate::translator::{TranslationOutcome, xlat_census};

            let _census = census::lock();
            let memory = NativeMappedMemory::shared_install_test_fixture(4096);
            let process =
                ProcessTranslator::new_with_host(256 * 1024, &TEST_HOST_JIT).expect("translator");
            let plan = syscall_plan(BLOCK_A);
            let observation = memory
                .dsr_generation_observation(BLOCK_A)
                .expect("publication observation");
            let source_page = observation.page();
            let mut state = process.state.write();
            let emitted = emit::emit_block(&mut state.cache, &plan, emit::EmitAddressMode::Direct)
                .expect("emit publication fixture");
            let emitted_bytes = u64::try_from(emitted.len()).expect("emitted byte count");
            census::reset_and_arm(0, 0);
            let before = census::snapshot();

            let published = state
                .publish_emitted(
                    &memory,
                    (BLOCK_A, CodeGeneration::INITIAL),
                    source_page,
                    observation,
                    emitted,
                    emitted_bytes,
                    TranslationOutcome::Translated,
                    xlat_census::PublicationCensus::Fresh {
                        entry: BLOCK_A,
                        block_start: plan.start,
                        block_end: plan.end,
                    },
                )
                .expect("publish allocation-owner fixture");
            std::hint::black_box(published);
            let after = census::snapshot();

            census::assert_only_requested_bytes_increased(
                &before,
                &after,
                &[AllocationOwner::PublicationIndexes],
            );
            census::reset_disabled();
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
            let store = Arc::new(LookupFixtureStore {
                unit: std::sync::Mutex::new(Some(unit)),
                loads: std::sync::atomic::AtomicU64::new(0),
            });
            let translator =
                ProcessTranslator::new_with_host(256 * 1024, &TEST_HOST_JIT).expect("translator");
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
            fixture_for_unit(unit, code)
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
            let guests: Vec<GuestVa> = candidates
                .iter()
                .map(|candidate| candidate.guest_start)
                .collect();
            let fixture = lookup_fixture(candidates);
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
            let published = installed
                .translator
                .published_blocks
                .get(key.0, key.1)
                .expect("installed block is visible in the warm-reader index");
            assert_eq!(published.entry, entry);
            assert_eq!(
                published.trusted_entry.map(|offset| offset.get()),
                Some(trusted.offset),
                "the warm-reader index must mirror trusted-entry authority"
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
            assert!(fixture.translator.published_blocks.is_empty());
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
            assert!(installed.translator.published_blocks.is_empty());
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
    /// V5: every file carries one exact `MEMORY` row for publication-owned
    /// retained metadata, JIT bytes, and transient direct-link capacity. The
    /// row is source-local accounting, not an address-shape inference.
    pub const CENSUS_SCHEMA: &str = "XLATCENSUS5";

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

    /// Source-local allocation facts for blocks published during one drained
    /// process-image epoch. Every byte count is measured at the allocation's
    /// retaining call site; none is inferred from a VM address.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct CensusMemory {
        /// Blocks translated privately and retaining owned map/recovery Vecs.
        pub private_blocks: u64,
        /// Blocks replayed from an attached unit. Their cold metadata remains
        /// mapped in the unit rather than becoming owned Vecs.
        pub unit_blocks: u64,
        /// Executable bytes copied into the process-private JIT cache by both
        /// publication routes.
        pub jit_bytes_written: u64,
        /// Logical entries retained in private instruction maps.
        pub owned_map_entries: u64,
        /// Initialized bytes retained in private instruction-map Vecs.
        pub owned_map_len_bytes: u64,
        /// Heap capacity retained by private instruction-map Vecs.
        pub owned_map_capacity_bytes: u64,
        /// Logical entries retained in private recovery tables.
        pub owned_recovery_entries: u64,
        /// Initialized bytes retained in private recovery Vecs.
        pub owned_recovery_len_bytes: u64,
        /// Heap capacity retained by private recovery Vecs.
        pub owned_recovery_capacity_bytes: u64,
        /// Final capacity of direct-link Vecs consumed and dropped during
        /// publication. Kept separate because it is transient, not retained.
        pub direct_link_capacity_bytes: u64,
    }

    impl CensusMemory {
        fn is_empty(self) -> bool {
            self == Self::default()
        }

        fn add(&mut self, other: Self) {
            self.private_blocks = self.private_blocks.saturating_add(other.private_blocks);
            self.unit_blocks = self.unit_blocks.saturating_add(other.unit_blocks);
            self.jit_bytes_written = self
                .jit_bytes_written
                .saturating_add(other.jit_bytes_written);
            self.owned_map_entries = self
                .owned_map_entries
                .saturating_add(other.owned_map_entries);
            self.owned_map_len_bytes = self
                .owned_map_len_bytes
                .saturating_add(other.owned_map_len_bytes);
            self.owned_map_capacity_bytes = self
                .owned_map_capacity_bytes
                .saturating_add(other.owned_map_capacity_bytes);
            self.owned_recovery_entries = self
                .owned_recovery_entries
                .saturating_add(other.owned_recovery_entries);
            self.owned_recovery_len_bytes = self
                .owned_recovery_len_bytes
                .saturating_add(other.owned_recovery_len_bytes);
            self.owned_recovery_capacity_bytes = self
                .owned_recovery_capacity_bytes
                .saturating_add(other.owned_recovery_capacity_bytes);
            self.direct_link_capacity_bytes = self
                .direct_link_capacity_bytes
                .saturating_add(other.direct_link_capacity_bytes);
        }
    }

    /// Why a block reached the publication seam. Keeping this typed prevents
    /// an artifact replay from being counted as either a fresh translation or
    /// a shared-unit replay while all three paths share one armed census check.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PublicationCensus {
        /// A block emitted from guest instructions in this process image.
        Fresh {
            entry: GuestVa,
            block_start: GuestVa,
            block_end: GuestVa,
        },
        /// A block replayed from an attached shared translation unit.
        UnitReplay,
        /// A block replayed from the legacy whole-artifact cache.
        ArtifactReplay,
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
        /// Allocation facts drained at the same image/lifecycle boundary.
        pub memory: CensusMemory,
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
            let _ = writeln!(
                out,
                "MEMORY|private_blocks={}|unit_blocks={}|jit_bytes_written={}|owned_map_entries={}|owned_map_len_bytes={}|owned_map_capacity_bytes={}|owned_recovery_entries={}|owned_recovery_len_bytes={}|owned_recovery_capacity_bytes={}|direct_link_capacity_bytes={}",
                self.memory.private_blocks,
                self.memory.unit_blocks,
                self.memory.jit_bytes_written,
                self.memory.owned_map_entries,
                self.memory.owned_map_len_bytes,
                self.memory.owned_map_capacity_bytes,
                self.memory.owned_recovery_entries,
                self.memory.owned_recovery_len_bytes,
                self.memory.owned_recovery_capacity_bytes,
                self.memory.direct_link_capacity_bytes,
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
                memory: CensusMemory::default(),
            };
            let distinct = parse_u64(field(&fields, "distinct", header_line)?, header_line)?;
            let mut saw_store = false;
            let mut saw_memory = false;
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
                    Some("MEMORY") => {
                        if saw_memory {
                            return Err(CensusParseError {
                                line: line_number,
                                reason: "census file has a second MEMORY line".to_string(),
                            });
                        }
                        file.memory = parse_memory(line, line_number)?;
                        saw_memory = true;
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
                            reason: "expected a STORE, MEMORY, SKIP, MISS, SEG or VA line"
                                .to_string(),
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
            if !saw_memory {
                return Err(CensusParseError {
                    line: header_line,
                    reason: "census file has no MEMORY line".to_string(),
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

    fn parse_memory(line_text: &str, line: usize) -> Result<CensusMemory, CensusParseError> {
        const NAMES: [&str; 10] = [
            "private_blocks",
            "unit_blocks",
            "jit_bytes_written",
            "owned_map_entries",
            "owned_map_len_bytes",
            "owned_map_capacity_bytes",
            "owned_recovery_entries",
            "owned_recovery_len_bytes",
            "owned_recovery_capacity_bytes",
            "direct_link_capacity_bytes",
        ];
        let mut parts = line_text.split('|');
        if parts.next() != Some("MEMORY") {
            return Err(CensusParseError {
                line,
                reason: "expected a MEMORY line".to_string(),
            });
        }
        let mut values = BTreeMap::new();
        for part in parts {
            let (name, value) = part.split_once('=').ok_or_else(|| CensusParseError {
                line,
                reason: format!("memory field {part:?} is not key=value"),
            })?;
            if !NAMES.contains(&name) {
                return Err(CensusParseError {
                    line,
                    reason: format!("unknown memory field {name:?}"),
                });
            }
            if values.insert(name, value).is_some() {
                return Err(CensusParseError {
                    line,
                    reason: format!("duplicate memory field {name:?}"),
                });
            }
        }
        if values.len() != NAMES.len() {
            let missing = NAMES
                .into_iter()
                .filter(|name| !values.contains_key(name))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CensusParseError {
                line,
                reason: format!("memory line is missing {missing}"),
            });
        }
        let value = |name| {
            values.get(name).copied().ok_or_else(|| CensusParseError {
                line,
                reason: format!("memory line is missing {name}"),
            })
        };
        let memory = CensusMemory {
            private_blocks: parse_u64(value("private_blocks")?, line)?,
            unit_blocks: parse_u64(value("unit_blocks")?, line)?,
            jit_bytes_written: parse_u64(value("jit_bytes_written")?, line)?,
            owned_map_entries: parse_u64(value("owned_map_entries")?, line)?,
            owned_map_len_bytes: parse_u64(value("owned_map_len_bytes")?, line)?,
            owned_map_capacity_bytes: parse_u64(value("owned_map_capacity_bytes")?, line)?,
            owned_recovery_entries: parse_u64(value("owned_recovery_entries")?, line)?,
            owned_recovery_len_bytes: parse_u64(value("owned_recovery_len_bytes")?, line)?,
            owned_recovery_capacity_bytes: parse_u64(
                value("owned_recovery_capacity_bytes")?,
                line,
            )?,
            direct_link_capacity_bytes: parse_u64(value("direct_link_capacity_bytes")?, line)?,
        };
        if memory.owned_map_len_bytes > memory.owned_map_capacity_bytes
            || memory.owned_recovery_len_bytes > memory.owned_recovery_capacity_bytes
        {
            return Err(CensusParseError {
                line,
                reason: "initialized metadata bytes exceed retained capacity".to_string(),
            });
        }
        Ok(memory)
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
        memory: CensusMemory,
    }

    impl CensusState {
        /// Add both halves of one publication transaction. Returns whether the
        /// store's lock-free replay counter must also advance.
        fn add_publication(
            &mut self,
            publication: PublicationCensus,
            memory: CensusMemory,
        ) -> bool {
            self.memory.add(memory);
            match publication {
                PublicationCensus::Fresh {
                    entry,
                    block_start,
                    block_end,
                } => {
                    self.total = self.total.saturating_add(1);
                    let key = {
                        let (segment, coverage) = self
                            .image
                            .as_ref()
                            .map_or((None, SegmentCoverage::Outside), |image| {
                                classify(&image.segments, entry, block_start, block_end)
                            });
                        (entry, segment, coverage)
                    };
                    let count = self.records.entry(key).or_insert(0);
                    *count = count.saturating_add(1);
                    false
                }
                PublicationCensus::UnitReplay => true,
                PublicationCensus::ArtifactReplay => false,
            }
        }
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

    /// Install the image whose fresh [`record_publication`] calls belong to.
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

    /// Record exact allocation facts and the publication outcome with ONE
    /// cached armed check. Fresh translations formerly called `record` after
    /// publication and shared-unit replays called `record_lookup_replayed`
    /// before returning; folding those identities into this seam avoids adding
    /// a second diagnostic branch to either shipped hot path.
    pub fn record_publication(
        publication: PublicationCensus,
        memory: impl FnOnce() -> CensusMemory,
    ) {
        if !armed() {
            return;
        }
        arm_backstop();
        let memory = memory();
        if let Ok(mut state) = state().lock()
            && state.add_publication(publication, memory)
        {
            bump_replayed();
        }
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
            state.memory = CensusMemory::default();
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
        if guard.total == 0 && store.is_empty() && guard.memory.is_empty() {
            return;
        }
        let total = std::mem::take(&mut guard.total);
        let records = std::mem::take(&mut guard.records);
        let image = guard.image.clone();
        let memory = std::mem::take(&mut guard.memory);
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
            memory,
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
        fn publication_transaction_accumulates_memory_and_only_fresh_blocks() {
            let mut state = CensusState {
                image: Some(CensusImage {
                    identity: "11".repeat(32),
                    segments: vec![CensusSegment {
                        guest_start: GuestVa(0x40_0000),
                        guest_len: 0x1000,
                        unit_stem: "22".repeat(32),
                    }],
                }),
                ..CensusState::default()
            };
            let private = CensusMemory {
                private_blocks: 1,
                jit_bytes_written: 96,
                owned_map_entries: 2,
                owned_map_len_bytes: 32,
                owned_map_capacity_bytes: 64,
                owned_recovery_entries: 3,
                owned_recovery_len_bytes: 288,
                owned_recovery_capacity_bytes: 384,
                direct_link_capacity_bytes: 32,
                ..CensusMemory::default()
            };
            assert!(!state.add_publication(
                PublicationCensus::Fresh {
                    entry: GuestVa(0x40_0010),
                    block_start: GuestVa(0x40_0010),
                    block_end: GuestVa(0x40_0020),
                },
                private,
            ));

            let unit = CensusMemory {
                unit_blocks: 1,
                jit_bytes_written: 48,
                direct_link_capacity_bytes: 16,
                ..CensusMemory::default()
            };
            assert!(state.add_publication(PublicationCensus::UnitReplay, unit));

            let artifact = CensusMemory {
                private_blocks: 1,
                jit_bytes_written: 24,
                owned_map_entries: 1,
                owned_map_len_bytes: 16,
                owned_map_capacity_bytes: 32,
                ..CensusMemory::default()
            };
            assert!(!state.add_publication(PublicationCensus::ArtifactReplay, artifact,));

            assert_eq!(state.total, 1, "only fresh translation increments total");
            assert_eq!(
                state.records,
                BTreeMap::from([(
                    (GuestVa(0x40_0010), Some(0), SegmentCoverage::Contained,),
                    1,
                )])
            );
            assert_eq!(
                state.memory,
                CensusMemory {
                    private_blocks: 2,
                    unit_blocks: 1,
                    jit_bytes_written: 168,
                    owned_map_entries: 3,
                    owned_map_len_bytes: 48,
                    owned_map_capacity_bytes: 96,
                    owned_recovery_entries: 3,
                    owned_recovery_len_bytes: 288,
                    owned_recovery_capacity_bytes: 384,
                    direct_link_capacity_bytes: 48,
                }
            );
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
                memory: CensusMemory::default(),
            };
            let identity = "cd".repeat(32);
            let stem = "aa".repeat(32);
            let expected = format!(
                "XLATCENSUS5|pid=4242|seq=1|reason=host-self-reexec|total=5|distinct=2|image={identity}|segments=1\n\
                 STORE|consulted=4|loaded=1|replayed=7|file_miss=1|recording_claimed=0|recording_declined=1|load_ns=1500000|publish_ns=2500000\n\
                 MEMORY|private_blocks=0|unit_blocks=0|jit_bytes_written=0|owned_map_entries=0|owned_map_len_bytes=0|owned_map_capacity_bytes=0|owned_recovery_entries=0|owned_recovery_len_bytes=0|owned_recovery_capacity_bytes=0|direct_link_capacity_bytes=0\n\
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
                memory: CensusMemory {
                    private_blocks: 1,
                    unit_blocks: 2,
                    jit_bytes_written: 4096,
                    owned_map_entries: 3,
                    owned_map_len_bytes: 48,
                    owned_map_capacity_bytes: 64,
                    owned_recovery_entries: 5,
                    owned_recovery_len_bytes: 480,
                    owned_recovery_capacity_bytes: 512,
                    direct_link_capacity_bytes: 96,
                },
            };
            let expected = "XLATCENSUS5|pid=7|seq=0|reason=process-exit|total=1|distinct=1|image=-|segments=0\n\
                            STORE|consulted=0|loaded=0|replayed=0|file_miss=0|recording_claimed=0|recording_declined=0|load_ns=0|publish_ns=0\n\
                            MEMORY|private_blocks=1|unit_blocks=2|jit_bytes_written=4096|owned_map_entries=3|owned_map_len_bytes=48|owned_map_capacity_bytes=64|owned_recovery_entries=5|owned_recovery_len_bytes=480|owned_recovery_capacity_bytes=512|direct_link_capacity_bytes=96\n\
                            SKIP|lane-unconfigured|1\n\
                            VA|0x1000|-|outside|1\n";
            assert_eq!(file.render(), expected);
            assert_eq!(CensusFile::parse(expected), Ok(file));
        }

        #[test]
        fn parse_fails_closed_on_a_truncated_or_mislabelled_file() {
            const HEADER: &str = "XLATCENSUS5|pid=1|seq=0|reason=process-exit|total=0|distinct=0|image=-|segments=0\n";
            const STORE: &str = "STORE|consulted=0|loaded=0|replayed=0|file_miss=0|recording_claimed=0|recording_declined=0|load_ns=0|publish_ns=0\n";
            const MEMORY: &str = "MEMORY|private_blocks=0|unit_blocks=0|jit_bytes_written=0|owned_map_entries=0|owned_map_len_bytes=0|owned_map_capacity_bytes=0|owned_recovery_entries=0|owned_recovery_len_bytes=0|owned_recovery_capacity_bytes=0|direct_link_capacity_bytes=0\n";
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
                    format!("{HEADER}{STORE}{MEMORY}").replace("distinct=0", "distinct=1"),
                    "distinct mismatch",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}").replace("process-exit", "fell-over"),
                    "reason",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}VA|400010|-|outside|1\n").replace("total=0", "total=1")
                        .replace("distinct=0", "distinct=1"),
                    "unprefixed hex",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}SEG|0|0x1000|0x10|aa\n"),
                    "segment without image",
                ),
                (HEADER.to_string(), "no STORE line"),
                (
                    format!("{HEADER}{STORE}{MEMORY}SKIP|not-a-skip|1\n"),
                    "unknown skip reason",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}MISS|not-a-reason|1\n"),
                    "unknown miss reason",
                ),
                (
                    // consulted must equal loaded + file_miss + misses.
                    format!("{HEADER}{STORE}{MEMORY}").replace("consulted=0", "consulted=3"),
                    "store outcomes do not account for consulted",
                ),
                (
                    // A file miss always carries exactly one election verdict.
                    format!("{HEADER}{STORE}{MEMORY}").replace(
                        "consulted=0|loaded=0|replayed=0|file_miss=0",
                        "consulted=1|loaded=0|replayed=0|file_miss=1",
                    ),
                    "file miss without an election verdict",
                ),
                (
                    // Two STORE lines: the second used to overwrite the first
                    // wholesale, so "last one wins" parsed clean.
                    format!("{HEADER}{STORE}{STORE}{MEMORY}"),
                    "second STORE line",
                ),
                (
                    format!("{HEADER}{STORE}"),
                    "missing MEMORY line",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}{MEMORY}"),
                    "second MEMORY line",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}").replace(
                        "direct_link_capacity_bytes=0",
                        "surprise=0",
                    ),
                    "unknown MEMORY field",
                ),
                (
                    format!("{HEADER}{STORE}{MEMORY}")
                        .replace("owned_map_len_bytes=0", "owned_map_len_bytes=1"),
                    "initialized metadata exceeds capacity",
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
            const HEADER: &str = "XLATCENSUS5|pid=1|seq=0|reason=process-exit|total=0|distinct=0|image=-|segments=0\n";
            const STORE: &str = "STORE|consulted=0|loaded=0|replayed=0|file_miss=0|recording_claimed=0|recording_declined=0|load_ns=0|publish_ns=0\n";
            const MEMORY: &str = "MEMORY|private_blocks=0|unit_blocks=0|jit_bytes_written=0|owned_map_entries=0|owned_map_len_bytes=0|owned_map_capacity_bytes=0|owned_recovery_entries=0|owned_recovery_len_bytes=0|owned_recovery_capacity_bytes=0|direct_link_capacity_bytes=0\n";
            let reordered =
                format!("{HEADER}SKIP|segment-repeat|7\nMISS|no-authority|0\n{STORE}{MEMORY}");
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
                memory: CensusMemory::default(),
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
