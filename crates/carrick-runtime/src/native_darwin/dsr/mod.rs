use std::collections::BTreeMap;
use std::sync::Arc;

use carrick_observability::probes;
use parking_lot::Mutex;

pub(super) mod block;
pub(super) mod cache;
pub(super) mod decode;
pub(super) mod emit;
pub(super) mod gateway;
#[cfg(test)]
mod oracle;
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
        address: carrick_guest_mem::GuestVa,
    },
    Kick,
    Unsupported(String),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ThreadFault {
    Host { signal: i32, code: i32 },
    Guest { signum: i32, code: i32 },
}

#[derive(Clone, Copy)]
pub(super) struct PreparedEntry {
    entry: types::CacheVa,
    generation: types::CodeGeneration,
    cache_start: usize,
    cache_end: usize,
}

pub(super) struct PreparedExit {
    exit: types::NativeDsrExit,
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
    profiling: bool,
    last_kick: Option<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>)>,
}

pub(super) struct ProcessTranslator {
    state: Mutex<ProcessState>,
}

struct ProcessState {
    cache: cache::TranslationCache,
    blocks: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::CacheVa>,
    pending: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), Vec<cache::LinkSite>>,
    stats: ResolverStats,
    sensitive: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::SensitiveExit>,
    unsupported: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), (u32, bad64::Op)>,
    published: Vec<PublishedBlock>,
    dependencies: cache::PageBlockDependencies,
    publications: cache::ConcurrentPublicationIndex,
    profiling: bool,
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
    pub(super) cache_used_bytes: usize,
    pub(super) cache_capacity_bytes: usize,
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
            profiling: std::env::var_os("CARRICK_DSR_PROFILE").is_some(),
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
        self.last_kick = None;
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

    pub(super) fn reset_for_exec(&mut self, next: Arc<ProcessTranslator>) {
        self.process = next;
        self.resume_entry = None;
        self.indirect_cache.clear();
        self.stats = ResolverStats::default();
        self.last_kick = None;
        let (used_bytes, block_count, generation_count) = self.process.lifecycle_snapshot();
        probes::dsr_cache_lifecycle(
            self.tid,
            probes::DsrCacheLifecyclePhase::ExecResetEnd,
            used_bytes,
            block_count,
            generation_count,
        );
    }

    pub(super) fn profile_snapshot(&self) -> ProfileSnapshot {
        let process = self.process.state.lock();
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
            cache_used_bytes: process.cache.used_bytes(),
            cache_capacity_bytes: process.cache.capacity_bytes(),
        }
    }
}

impl Drop for ThreadTranslator {
    fn drop(&mut self) {
        if !self.profiling {
            return;
        }
        let profile = self.profile_snapshot();
        super::child_write_stderr(
            format!(
                "native dsr profile gateway_entries={} syscall_exits={} \
                 direct_resolver_exits={} indirect_resolver_exits={} \
                 one_entry_hits={} cache_lookups={} cache_lookup_hits={} \
                 translations={} translation_ns={} duplicate_publications={} \
                 invalidated_blocks={} cache_used_bytes={} cache_capacity_bytes={}\n",
                profile.gateway_entries,
                profile.syscall_exits,
                profile.direct_resolver_exits,
                profile.resolver_exits,
                profile.one_entry_hits,
                profile.cache_lookups,
                profile.cache_lookup_hits,
                profile.translations,
                profile.translation_ns,
                profile.duplicate_publications,
                profile.invalidated_blocks,
                profile.cache_used_bytes,
                profile.cache_capacity_bytes,
            )
            .as_bytes(),
        );
    }
}

impl ProcessTranslator {
    pub(super) fn new(capacity: usize) -> Result<Self, types::DsrError> {
        let translator = Self {
            state: Mutex::new(ProcessState {
                cache: cache::TranslationCache::new(capacity)?,
                blocks: BTreeMap::new(),
                pending: BTreeMap::new(),
                stats: ResolverStats::default(),
                sensitive: BTreeMap::new(),
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
        let state = self.state.lock();
        (
            u64::try_from(state.cache.used_bytes()).unwrap_or(u64::MAX),
            u64::try_from(state.blocks.len()).unwrap_or(u64::MAX),
            u64::try_from(state.dependencies.page_count()).unwrap_or(u64::MAX),
        )
    }

    fn after_fork_child(&self) {
        let state = self.state.lock();
        state.cache.after_fork_child();
        state.publications.after_fork_child();
        let capacity = u64::try_from(state.cache.capacity_bytes()).unwrap_or(u64::MAX);
        drop(state);
        probes::dsr_cache_capacity(probes::DsrCacheRole::Child, capacity);
    }

    pub(super) fn reset_after_fork_for_exec(&self) {
        let mut state = self.state.lock();
        state.published.clear();
        state.cache.reset_after_fork_for_exec();
        state.blocks.clear();
        state.pending.clear();
        state.stats = ResolverStats::default();
        state.sensitive.clear();
        state.unsupported.clear();
        state.dependencies = cache::PageBlockDependencies::default();
        state.publications.reset_for_exec();
    }
}

impl ProcessState {
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
            self.stats.invalidated_blocks = self
                .stats
                .invalidated_blocks
                .saturating_add(u64::try_from(stale_blocks.len()).unwrap_or(u64::MAX));
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
            self.stats.cache_lookups = self.stats.cache_lookups.saturating_add(1);
        }
        if let Some(entry) = self.blocks.get(&key) {
            if self.profiling {
                self.stats.cache_lookup_hits = self.stats.cache_lookup_hits.saturating_add(1);
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
            let block = block::plan_block(memory, guest, generation, 256)?;
            if observation.current() != generation {
                return Err(types::DsrError::GenerationChanged {
                    page: guest.raw(),
                    expected: generation.get(),
                    observed: observation.current().get(),
                });
            }
            if let block::PlannedExit::Sensitive {
                guest: sensitive_guest,
                exit,
                ..
            } = block.exit
            {
                self.sensitive.insert((sensitive_guest, generation), exit);
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
            let emitted = emit::emit_block_with_generation(
                &mut self.cache,
                &block,
                emit::GenerationGuard::new(observation.current_atomic(), generation),
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
                self.stats.translation_ns = self.stats.translation_ns.saturating_add(
                    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                );
            }
            self.stats.translations = self.stats.translations.saturating_add(1);
            let entry = emitted.entry();
            let published_entry = self.publications.get_or_publish(key, || entry);
            if published_entry != entry {
                self.stats.duplicate_publications =
                    self.stats.duplicate_publications.saturating_add(1);
                return Ok(TranslationResult {
                    entry: published_entry,
                    generation,
                    outcome: TranslationOutcome::Translated,
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
            self.dependencies.record(source_page, guest, generation);

            for link in links {
                let target_generation = memory.dsr_generation_observation(link.target)?.expected();
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
    fn translate(
        &mut self,
        memory: &super::NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<TranslationResult, types::DsrError> {
        self.process.state.lock().translate(self.tid, memory, guest)
    }

    fn guest_pc_for_cache(
        &self,
        cache_pc: carrick_guest_mem::GuestVa,
    ) -> Result<(carrick_guest_mem::GuestVa, Option<emit::RecoveryAction>), types::DsrError> {
        self.process.state.lock().guest_pc_for_cache(cache_pc)
    }

    fn resolve_indirect(
        &mut self,
        memory: &super::NativeMappedMemory,
        _source: carrick_guest_mem::GuestVa,
        target: carrick_guest_mem::GuestVa,
    ) -> Result<(types::CacheVa, types::CodeGeneration), types::DsrError> {
        self.stats.resolver_exits = self.stats.resolver_exits.saturating_add(1);
        let translated = self.translate(memory, target)?;
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
        let process = self.process.state.lock().stats;
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
        }
    }

    pub(super) fn profiling_enabled(&self) -> bool {
        self.profiling
    }

    pub(super) fn prepare_entry<const PROFILE: bool>(
        &mut self,
        memory: &super::NativeMappedMemory,
        snapshot: &super::NativeUcontextSnapshot,
    ) -> Result<PreparedEntry, types::DsrError> {
        let guest = carrick_guest_mem::GuestVa(snapshot.pc);
        if PROFILE {
            probes::dsr_prepare_begin(self.tid, guest.raw());
        }
        let selection = (|| -> Result<_, types::DsrError> {
            match self.resume_entry.take() {
                Some((cached_guest, generation, entry))
                    if cached_guest == guest
                        && memory.dsr_generation_observation(guest)?.expected() == generation =>
                {
                    self.stats.one_entry_hits = self.stats.one_entry_hits.saturating_add(1);
                    Ok((entry, generation, probes::DsrPrepareOutcome::ResumeEntryHit))
                }
                _ => {
                    let translated = self.translate(memory, guest)?;
                    let outcome = match translated.outcome {
                        TranslationOutcome::BlockIndexHit => {
                            probes::DsrPrepareOutcome::BlockIndexHit
                        }
                        TranslationOutcome::Translated => probes::DsrPrepareOutcome::Translated,
                    };
                    Ok((translated.entry, translated.generation, outcome))
                }
            }
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
        let cache_range = self.process.state.lock().cache.host_range();
        let prepared = PreparedEntry {
            entry,
            generation,
            cache_start: cache_range.start,
            cache_end: cache_range.end,
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
        if self.profiling {
            self.stats.gateway_entries = self.stats.gateway_entries.saturating_add(1);
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

    pub(super) fn finish_exit(
        &mut self,
        memory: &super::NativeMappedMemory,
        snapshot: &mut super::NativeUcontextSnapshot,
        prepared: PreparedEntry,
        exit: PreparedExit,
    ) -> Result<ThreadExit, types::DsrError> {
        if self.profiling {
            match exit.exit {
                types::NativeDsrExit::Syscall { .. } => {
                    self.stats.syscall_exits = self.stats.syscall_exits.saturating_add(1);
                }
                types::NativeDsrExit::ResolveDirect { .. } => {
                    self.stats.direct_resolver_exits =
                        self.stats.direct_resolver_exits.saturating_add(1);
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
                if let Err(error) = self.translate(memory, target) {
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
                        address: target,
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
                        address: target,
                    });
                }
                let (entry, target_generation) = match self.resolve_indirect(memory, source, target)
                {
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
                let exit = self
                    .process
                    .state
                    .lock()
                    .sensitive
                    .get(&(guest_pc, generation))
                    .copied()
                    .ok_or_else(|| {
                        types::DsrError::BlockPolicy(format!(
                            "missing sensitive-exit metadata for guest PC 0x{:x}",
                            guest_pc.raw()
                        ))
                    })?;
                ThreadExit::Sensitive(exit)
            }
            types::NativeDsrExit::Unsupported { guest_pc, .. } => {
                let (word, op) = self
                    .process
                    .state
                    .lock()
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
                snapshot.pc = guest_pc.raw();
                ThreadExit::Fault {
                    kind: ThreadFault::Host { signal, code },
                    address,
                }
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
                snapshot.pc = guest_pc.raw();
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

fn recover_rewrite_state(
    snapshot: &mut super::NativeUcontextSnapshot,
    action: emit::RecoveryAction,
    saved_scratch: u64,
    saved_context_scratch: u64,
    saved_generation_pstate: u64,
    saved_indirect_x15: u64,
    saved_indirect_x30: u64,
) -> Result<(), types::DsrError> {
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
        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratch { register, .. } => {
            (register, None)
        }
        emit::RecoveryAction::RestoreScratchAndContext {
            register,
            context_register,
        }
        | emit::RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
            register,
            context_register,
            ..
        } => (register, Some(context_register)),
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
    use super::types::{DirectKind, IndirectKind, InstAction, PcRelativeKind, SensitiveKind};
    use carrick_guest_mem::{GuestMemory, GuestVa};
    use proptest::prelude::*;

    const PC: GuestVa = GuestVa(0x1000);

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
        let mut memory = super::super::NativeMappedMemory::map_with_code_mode(
            &image,
            layout,
            page_size,
            page_size,
            carrick_spec::NativeCodeModeRequest::Dsr,
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
                let mut state = process.state.lock();
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
                    address: target,
                    rewrite_scratch: 0,
                    rewrite_context_scratch: 0,
                    generation_pstate_scratch: 0,
                    indirect_x15_scratch: 0,
                    indirect_x30_scratch: 0,
                    physical_x18: 0,
                    gateway_phase: 0,
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
    fn dsr_indirect_resolver_stats_start_at_zero() {
        let translator = super::ThreadTranslator::new(16 * 1024).expect("create translator");
        assert_eq!(translator.resolver_stats(), super::ResolverStats::default());
        let profile = translator.profile_snapshot();
        assert_eq!(profile.gateway_entries, 0);
        assert_eq!(profile.syscall_exits, 0);
        assert_eq!(profile.cache_lookups, 0);
        assert_eq!(profile.cache_used_bytes, 0);
        assert_eq!(profile.cache_capacity_bytes, 16 * 1024);
    }

    #[test]
    fn dsr_exec_switch_keeps_retiring_translator_metadata_alive() {
        let old = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create old translator"),
        );
        let key = (PC, super::types::CodeGeneration::INITIAL);
        let entry = super::types::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        old.state.lock().publications.get_or_publish(key, || entry);
        let mut thread = super::ThreadTranslator::for_process(std::sync::Arc::clone(&old), 0);
        let next = std::sync::Arc::new(
            super::ProcessTranslator::new(16 * 1024).expect("create next translator"),
        );

        thread.reset_for_exec(next);

        assert_eq!(
            old.state.lock().publications.published_count(),
            1,
            "pre-exec threads must retain old PC metadata until their Arc retires"
        );
    }

    #[test]
    fn dsr_fork_child_exec_reuses_and_clears_inherited_translator() {
        let process =
            super::ProcessTranslator::new(16 * 1024).expect("create inherited translator");
        let key = (PC, super::types::CodeGeneration::INITIAL);
        let entry = super::types::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        process
            .state
            .lock()
            .publications
            .get_or_publish(key, || entry);

        process.reset_after_fork_for_exec();

        let state = process.state.lock();
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
            Ok(InstAction::VirtualizedX18X28ReadOnly {
                word: 0xa900_4b82,
                ..
            })
        ));
        assert!(matches!(
            classify(0xf900_0e5c, PC),
            Ok(InstAction::VirtualizedX18X28ReadOnly {
                word: 0xf900_0e5c,
                ..
            })
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
            Ok(InstAction::VirtualizedX18WriteX28Read {
                word: 0xa94d_cb8f,
                ..
            })
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
        for word in [0xd280_0032, 0xf940_0240] {
            assert!(super::decode::decoded_operands_mention_x18(word, PC));
            assert!(matches!(
                classify(word, PC),
                Ok(InstAction::VirtualizedX18 { word: observed, .. }) if observed == word
            ));
        }
        for word in [0xd280_003c, 0xf940_0380] {
            assert!(super::decode::decoded_operands_mention_x28(word, PC));
            assert!(matches!(
                classify(word, PC),
                Ok(InstAction::VirtualizedX28 { word: observed, .. }) if observed == word
            ));
        }
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
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::LiteralLoad && inst.target == GuestVa(0x1008)
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
