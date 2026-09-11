//! CRASH and core capture concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task T11). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

pub(crate) struct PreparedCorePublication {
    pub(crate) snapshot: crate::dispatch::CoreProcessSnapshot,
    pub(crate) payload: crate::core_dump::CorePayload,
    pub(crate) generation: u64,
    pub(crate) fatal_tid: i32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CrashLeaseDrainBudget {
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
}

impl CrashLeaseDrainBudget {
    pub(crate) const DEFAULT: Self = Self {
        timeout: Duration::from_secs(10),
        poll_interval: Duration::from_micros(200),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrashLeaseDrainTimeout {
    Waiting(ThreadId),
    Busy(ThreadId),
}

impl std::fmt::Display for CrashLeaseDrainTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Waiting(tid) => write!(
                formatter,
                "HVPatch crash lease drain timed out waiting for sibling vCPU tid {}",
                tid.raw()
            ),
            Self::Busy(owner) => write!(
                formatter,
                "HVPatch crash lease drain timed out behind freeze owner tid {}",
                owner.raw()
            ),
        }
    }
}

pub(crate) fn crash_lease_drain_park_duration(
    poll_interval: Duration,
    remaining: Duration,
) -> Duration {
    poll_interval.min(remaining)
}

pub(crate) fn acquire_crash_lease_drain<N>(
    registry: &dyn VcpuRegistry,
    owner: ThreadId,
    budget: CrashLeaseDrainBudget,
    mut nudge: N,
) -> Result<carrick_hal::VcpuLeaseDrainGuard, CrashLeaseDrainTimeout>
where
    N: FnMut(),
{
    let deadline = Instant::now() + budget.timeout;
    let waiter = std::thread::current();
    let callback: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || waiter.unpark());

    loop {
        let subscription = match registry.subscribe_lease_drain(owner, Arc::clone(&callback)) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => return Ok(guard),
            carrick_hal::VcpuLeaseDrainEnrollment::Waiting { subscription, .. }
            | carrick_hal::VcpuLeaseDrainEnrollment::Busy { subscription, .. } => subscription,
        };

        nudge();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            std::thread::park_timeout(crash_lease_drain_park_duration(
                budget.poll_interval,
                remaining,
            ));
            drop(subscription);
            if Instant::now() < deadline {
                continue;
            }
        } else {
            drop(subscription);
        }

        return match registry.subscribe_lease_drain(owner, Arc::clone(&callback)) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => Ok(guard),
            carrick_hal::VcpuLeaseDrainEnrollment::Waiting { tid, .. } => {
                Err(CrashLeaseDrainTimeout::Waiting(tid))
            }
            carrick_hal::VcpuLeaseDrainEnrollment::Busy { owner, .. } => {
                Err(CrashLeaseDrainTimeout::Busy(owner))
            }
        };
    }
}

pub(crate) fn finish_crash_collection<T>(
    authority: &crate::kernel::CrashCaptureAuthority,
    barrier: &crate::fork_quiesce::QuiesceBarrier,
    quiesced: bool,
    lease_drain_guard: Option<carrick_hal::VcpuLeaseDrainGuard>,
    result: Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    authority.stop_collecting();
    if quiesced {
        barrier.end_quiesce();
    }
    barrier.end_fork();
    drop(lease_drain_guard);
    result
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    #[cfg(test)]
    pub(crate) fn install_crash_lease_drain_budget_for_test(
        &mut self,
        budget: CrashLeaseDrainBudget,
    ) {
        self.crash_lease_drain_budget = budget;
    }

    pub(crate) fn crash_lease_drain_budget(&self) -> CrashLeaseDrainBudget {
        #[cfg(test)]
        {
            self.crash_lease_drain_budget
        }
        #[cfg(not(test))]
        {
            CrashLeaseDrainBudget::DEFAULT
        }
    }

    /// The crash generation this thread's safe point should answer, if a fatal
    /// sibling is collecting one right now.
    pub(crate) fn collecting_crash_generation(
        &self,
    ) -> Option<crate::kernel::CrashCaptureGeneration> {
        self.crash_capture
            .as_ref()
            .and_then(|authority| authority.collecting())
    }

    pub(crate) fn stash_parked_registers(&self, engine: &E) -> Result<(), RuntimeError> {
        if let Ok(Some(registers)) = engine.aarch64_core_registers() {
            if let Some(thread) = self.kernel_thread.as_ref() {
                thread.stash_parked_registers(registers);
            }
        }
        Ok(())
    }

    pub(crate) fn publish_crash_registers_if_requested(
        &self,
        engine: &E,
    ) -> Result<(), RuntimeError> {
        let Some(mut generation) = self.collecting_crash_generation() else {
            return Ok(());
        };
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "register-generation")
        {
            generation = generation.skewed_for_failpoint();
        }
        let registers = engine.aarch64_core_registers()?.ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks complete AArch64 register authority".to_owned(),
            )
        })?;
        let thread = self.kernel_thread.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks authoritative Kernel thread".to_owned(),
            )
        })?;
        thread.publish_crash_registers(generation, registers);
        Ok(())
    }

    /// Answer a collecting fatal sibling with "I cannot publish".
    ///
    /// Every park that reaches the task-local quiesce barrier WITHOUT a
    /// readable register file must call this before blocking. Such a thread
    /// (waiting for a vCPU lease, or for a sibling to materialise) does not
    /// resume until the barrier drops, so it can never publish for this
    /// generation — and a collector that kept waiting for it burned its full
    /// ten-second deadline and then published no core at all.
    pub(crate) fn withdraw_from_crash_capture(&self) {
        let (Some(generation), Some(thread)) = (
            self.collecting_crash_generation(),
            self.kernel_thread.as_ref(),
        ) else {
            return;
        };
        thread.withdraw_from_crash_capture(generation);
    }

    pub(crate) fn capture_core_for_publication(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        fatal: FatalSignalRecord,
    ) -> Result<Option<PreparedCorePublication>, RuntimeError> {
        // Linux default actions that carry a core. Other fatal signals still
        // publish a signal wait status, but never set WCOREDUMP.
        if !matches!(fatal.signo, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) {
            return Ok(None);
        }
        let context = kernel
            .dispatcher
            .capture_kernel_context(self.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!("capture core Kernel context: {error}"))
            })?;
        let process_pid = kernel
            .hvpatch_process
            .as_ref()
            .map(crate::hvpatch::ProcessContext::pid)
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "HVPatch crash capture lacks process identity authority".to_owned(),
                )
            })?;
        let barrier = kernel.process_fork_barrier.as_ref().ok_or_else(|| {
            RuntimeError::Configuration("HVPatch crash capture lacks task-local barrier".to_owned())
        })?;
        let authority = kernel.crash_capture.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks generation authority".to_owned(),
            )
        })?;
        let generation = authority
            .issue()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let lifecycle = |phase, outcome| {
            crate::probes::hvpatch_core_lifecycle(
                phase,
                process_pid,
                fatal.tid.raw(),
                generation.get(),
                outcome,
            );
        };
        lifecycle(0, 0);
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "capture-timeout")
        {
            lifecycle(6, 1);
            return Err(RuntimeError::Configuration(
                "core publication failpoint capture-timeout".to_owned(),
            ));
        }
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "capture-interrupted")
        {
            lifecycle(6, 1);
            return Err(RuntimeError::Configuration(
                "core publication failpoint capture-interrupted".to_owned(),
            ));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !barrier.try_begin_fork() {
            if std::time::Instant::now() >= deadline {
                lifecycle(6, 1);
                return Err(RuntimeError::Configuration(
                    "HVPatch crash capture timed out behind fork/exec quiesce".to_owned(),
                ));
            }
            std::thread::yield_now();
        }
        // Advertise BEFORE the barrier rises: a thread that parked without
        // seeing the generation would owe a register file it can never publish.
        authority.advertise(generation);
        let mut quiesced = false;
        let mut lease_drain_guard = None;
        let result = (|| {
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "capture-registers")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint capture-registers".to_owned(),
                ));
            }
            self.publish_crash_registers_if_requested(engine)?;
            // Raise the barrier whenever this task has a sibling at all. A
            // sibling parked in a futex has already released its vCPU lease,
            // so registry membership cannot decide whether the barrier is
            // needed. The identity-aware enrollment below answers its own
            // narrower question and freezes the empty sibling lease set through
            // the complete live-memory snapshot. CrashQuorum remains the sole
            // register-collection predicate.
            let crash_participants = context
                .task()
                .crash_barrier_participants(context.thread().key())
                .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            if crash_participants.requires_quiesce() {
                barrier.set_quiescing();
                quiesced = true;
            }
            lease_drain_guard = Some(
                acquire_crash_lease_drain(
                    &*self.kicker,
                    self.this_tid,
                    self.crash_lease_drain_budget(),
                    || {
                        self.kicker.kick_all_except(self.this_tid);
                        self.futex.notify_signal_pending();
                        self.platform_futex.notify_signal_pending();
                        kernel.signal_arrival.wake_all_waiters();
                    },
                )
                .map_err(|timeout| RuntimeError::Configuration(timeout.to_string()))?,
            );
            lifecycle(1, 0);

            engine.prepare_core_snapshot().map_err(|error| {
                RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "prepare coherent core memory snapshot: {error}"
                )))
            })?;

            // Identity, auxv, VMAs, file provenance, cwd and RLIMIT belong to
            // the same all-thread safe point as the register files. Taking
            // this before raising the barrier would admit a concurrent
            // mmap/exec mutation between the two halves of the core.
            let process = kernel
                .dispatcher
                .core_process_snapshot(&context)
                .map_err(|error| {
                    RuntimeError::FsBackend(anyhow::anyhow!(
                        "capture quiesced core process state: {error}"
                    ))
                })?;
            if !process.dumpable || process.rlimit_core == 0 {
                return Ok(None);
            }

            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "missing-thread")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint missing-thread".to_owned(),
                ));
            }
            let fatal_visible_tid = u32::try_from(fatal.tid.raw())
                .ok()
                .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(&context, tid))
                .and_then(|tid| i32::try_from(tid).ok())
                .ok_or_else(|| {
                    RuntimeError::Configuration(format!(
                        "fatal thread {} is outside its container namespace",
                        fatal.tid.raw()
                    ))
                })?;
            // The quorum is the ONLY register-collection predicate, and it
            // re-reads the task's live membership on every poll. Three
            // populations used to be conflated here: the task's thread count,
            // the live vCPU-lease count, and a one-shot membership snapshot.
            // Each over-counted, and every over-count cost the full deadline
            // and then published no core: a thread retiring mid-collection, a
            // thread whose host loop had already returned (a terminal-claim
            // loser after `exit_group`), a thread admitted into the graph whose
            // host loop was cancelled before it ever ran, and a live thread
            // parked at the barrier from a path with no readable register file.
            let quorum =
                crate::kernel::CrashQuorum::open(std::sync::Arc::clone(context.task()), generation);
            // Structural fix: no wall-clock deadline; quorum blocks.
            let mut threads = loop {
                match quorum.poll() {
                    crate::kernel::CrashQuorumPoll::Complete(files) => {
                        break files
                            .into_iter()
                            .map(|file| {
                                let visible_tid = u32::try_from(file.tid.raw())
                                    .ok()
                                    .and_then(|tid| {
                                        crate::namespace::pid::kernel_to_ns_for(&context, tid)
                                    })
                                    .and_then(|tid| i32::try_from(tid).ok())
                                    .ok_or_else(|| {
                                        RuntimeError::Configuration(format!(
                                            "core thread {} is outside its container namespace",
                                            file.tid.raw()
                                        ))
                                    })?;
                                let registers = file.registers;
                                let mut gregs = [0_u64; crate::core_dump::AARCH64_GREGS];
                                gregs[..31].copy_from_slice(&registers.gprs);
                                gregs[31] = registers.sp_el0;
                                // The engine selects live PC/PSTATE for a vCPU
                                // force-exited directly from EL0, or saved
                                // ELR/SPSR while a syscall is parked in EL1. A
                                // synchronous fatal owner is independently
                                // identified by its positive kernel si_code and
                                // uses the raw exception ELR/SPSR pair. Raw
                                // pairs remain in Kernel authority.
                                let synchronous_fatal_owner =
                                    file.tid == fatal.tid && fatal.code > 0;
                                let (resume_pc, resume_pstate) =
                                    core_note_resume_pair(&registers, synchronous_fatal_owner);
                                gregs[32] = resume_pc;
                                gregs[33] = resume_pstate;
                                Ok(crate::core_dump::ThreadState {
                                    tid: visible_tid,
                                    registers: crate::core_dump::ThreadRegisters {
                                        gregs,
                                        tpidr_el0: registers.tpidr_el0,
                                        vregs: registers.vregs,
                                        fpsr: registers.fpsr,
                                        fpcr: registers.fpcr,
                                    },
                                    current_signal: if file.tid == fatal.tid {
                                        fatal.signo
                                    } else {
                                        0
                                    },
                                })
                            })
                            .collect::<Result<Vec<_>, RuntimeError>>()?;
                    }
                    crate::kernel::CrashQuorumPoll::Waiting(tid) => {
                        let _ = tid;
                        // Structural fix: capture blocks indefinitely
                        // every live thread of the process at crash
                        // generation has published or proven exited.
                        // No deadline: under host CPU delay,
                        // a timeout turns delay into lost siblings.
                        // blocked.
                    }
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            };
            threads.sort_by_key(|thread| (thread.tid != fatal_visible_tid, thread.tid));
            if std::env::var_os("CARRICK_CORE_FAILPOINT").is_some_and(|value| value == "capture-mm")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint capture-mm".to_owned(),
                ));
            }
            if process.auxv.is_empty()
                || std::env::var_os("CARRICK_CORE_FAILPOINT")
                    .is_some_and(|value| value == "missing-auxv")
            {
                return Err(RuntimeError::Configuration(
                    "core capture missing authoritative auxv".to_owned(),
                ));
            }
            if process.maps.is_empty()
                || std::env::var_os("CARRICK_CORE_FAILPOINT")
                    .is_some_and(|value| value == "missing-vma")
            {
                return Err(RuntimeError::Configuration(
                    "core capture missing authoritative VMA state".to_owned(),
                ));
            }
            let _readable_bytes = process
                .maps
                .iter()
                .filter(|map| map.read)
                .try_fold(0_u64, |total, map| {
                    total.checked_add(map.end.saturating_sub(map.start))
                })
                .ok_or_else(|| {
                    RuntimeError::Configuration(
                        "core readable-region byte count overflowed".to_owned(),
                    )
                })?;
            // No pre-emptive refusal on size: core(5) truncates an oversized
            // dump rather than suppressing it, and `build_payload` applies
            // RLIMIT_CORE at serialisation. Failing closed here published NO
            // core and therefore cleared WCOREDUMP for any process whose
            // readable regions merely exceeded the limit.
            let deferred_anonymous = kernel
                .dispatcher
                .deferred_anonymous_state(context.shared().mm().id());
            let mut regions = Vec::with_capacity(process.maps.len());
            let mut dumpable_maps = Vec::with_capacity(process.maps.len());
            for map in &process.maps {
                let size = map.end.saturating_sub(map.start);
                let flags = crate::core_dump::region_flags(map.read, map.write, map.execute);
                if !map.read {
                    regions.push(crate::core_dump::MemoryRegion {
                        start: map.start,
                        flags,
                        bytes: &[],
                        size,
                        dumped: false,
                    });
                    dumpable_maps.push(false);
                    continue;
                }
                // Linux's default coredump filter omits the CONTENTS of
                // executable file-backed mappings (program/library text): the
                // oracle core lists them as PT_LOAD with p_filesz = 0 while
                // still dumping readable data/RELRO file mappings in full.
                // The `coredumpfile` probe pins this — its in-core instruction
                // lookup at the thread PCs must FAIL exactly as it does
                // against a Linux core. Overlap (not containment) match: the
                // loader's image VMA runs past the file extent (bss tail).
                // Known approximation: carrick's main/interp images are one
                // merged VMA (text+data+bss), so their DATA drops out of the
                // core alongside the text where Linux, with split VMAs, keeps
                // it; no conformance row observes that today.
                let file_backed = process
                    .file_mappings
                    .iter()
                    .any(|fm| fm.start < map.end && map.start < fm.end);
                if file_backed && map.execute {
                    regions.push(crate::core_dump::MemoryRegion {
                        start: map.start,
                        flags,
                        bytes: &[],
                        size,
                        dumped: false,
                    });
                    dumpable_maps.push(false);
                    continue;
                }
                // `MADV_DONTDUMP`: same shape Linux produces -- the VMA is
                // still a PT_LOAD, with no contents behind it.
                if process
                    .dump_omitted
                    .iter()
                    .any(|&(start, end)| start < map.end && map.start < end)
                {
                    regions.push(crate::core_dump::MemoryRegion {
                        start: map.start,
                        flags,
                        bytes: &[],
                        size,
                        dumped: false,
                    });
                    dumpable_maps.push(false);
                    continue;
                }
                regions.push(crate::core_dump::MemoryRegion {
                    start: map.start,
                    flags,
                    bytes: &[],
                    size,
                    dumped: true,
                });
                dumpable_maps.push(true);
            }
            let mappings = process.file_mappings.clone();
            // How many `NT_PRSTATUS` notes Linux would have written, versus how
            // many carrick actually collected. They differ exactly when a live
            // thread WITHDREW from the quorum — parked where its register file
            // is unreadable — which is a real, bounded fidelity gap and is
            // reported rather than hidden behind a failed-closed core.
            let required_threads = context
                .task()
                .core_note_participants()
                .required_note_count_for_probe();
            let thread_count = u64::try_from(threads.len()).unwrap_or(u64::MAX);
            let mapping_count = u64::try_from(mappings.len()).unwrap_or(u64::MAX);
            let region_count = u64::try_from(regions.len()).unwrap_or(u64::MAX);
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "missing-file-identity")
            {
                return Err(RuntimeError::Configuration(
                    "core capture missing file mapping identity".to_owned(),
                ));
            }
            let mm = context.shared().mm().id().raw();
            let asid = kernel
                .hvpatch_process
                .as_ref()
                .and_then(crate::hvpatch::ProcessContext::mm_binding)
                .map(|binding| u32::from(binding.asid.raw()))
                .ok_or_else(|| {
                    RuntimeError::Configuration(
                        "core capture missing HVPatch ASID authority".to_owned(),
                    )
                })?;
            crate::probes::hvpatch_core_context(
                generation.get(),
                mm,
                asid,
                required_threads,
                thread_count,
            );
            lifecycle(2, 0);
            let dump = crate::core_dump::CoreDump {
                identity: process.identity.clone(),
                signal: crate::core_dump::SignalInfo {
                    signo: fatal.signo,
                    code: fatal.code,
                    errno: 0,
                    addr: fatal.addr,
                },
                threads,
                auxv: process.auxv.clone(),
                mappings,
                regions,
            };
            let segment_offsets = dump.load_segment_file_offsets().map_err(|error| {
                RuntimeError::FsBackend(anyhow::anyhow!("layout core segment offsets: {error}"))
            })?;
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "memory-read")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint memory-read".to_owned(),
                ));
            }
            let mut extents = Vec::new();
            let mut remaining_budget = process.rlimit_core;
            for (idx, map) in process.maps.iter().enumerate() {
                if !dumpable_maps[idx] || remaining_budget == 0 {
                    continue;
                }
                let seg_offset = segment_offsets[idx];
                let length = usize::try_from(map.end.saturating_sub(map.start)).map_err(|_| {
                    RuntimeError::Configuration(format!(
                        "core region length does not fit host usize at {:#x}",
                        map.start
                    ))
                })?;
                let subranges: Vec<std::ops::Range<carrick_guest_mem::GuestVa>> =
                    match &deferred_anonymous {
                        Some(deferred) => deferred
                            .materialized_subranges(carrick_guest_mem::GuestVa(map.start), length),
                        None => {
                            vec![
                                carrick_guest_mem::GuestVa(map.start)
                                    ..carrick_guest_mem::GuestVa(map.end),
                            ]
                        }
                    };
                for sub in subranges {
                    if remaining_budget == 0 {
                        break;
                    }
                    let sub_start = sub.start.raw();
                    let sub_len =
                        usize::try_from(sub.end.raw().saturating_sub(sub_start)).unwrap_or(0);
                    if sub_len == 0 {
                        continue;
                    }
                    let to_read =
                        sub_len.min(usize::try_from(remaining_budget).unwrap_or(usize::MAX));
                    if to_read == 0 {
                        break;
                    }
                    let bytes = engine
                        .read_core_bytes(sub_start, to_read)
                        .map_err(|error| {
                            RuntimeError::Trap(TrapError::Hypervisor(format!(
                                "read core region {:#x}..{:#x}: {error}",
                                sub_start,
                                sub_start.saturating_add(to_read as u64)
                            )))
                        })?;
                    let relative_offset = sub_start.saturating_sub(map.start);
                    let file_offset = seg_offset.saturating_add(relative_offset);
                    remaining_budget = remaining_budget.saturating_sub(bytes.len() as u64);
                    extents.push(crate::core_dump::CoreExtent {
                        offset: file_offset,
                        bytes,
                    });
                }
            }
            let payload = dump
                .build_payload(process.rlimit_core, extents)
                .map_err(|error| {
                    RuntimeError::FsBackend(anyhow::anyhow!("build core payload: {error}"))
                })?;
            if std::env::var_os("CARRICK_CORE_FAILPOINT").is_some_and(|value| value == "validator")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint validator".to_owned(),
                ));
            }
            let digest = payload.manifest_digest();
            let mut hash_words = [0_u64; 4];
            for (word, octets) in hash_words.iter_mut().zip(digest.chunks_exact(8)) {
                let mut octet_array = [0_u8; 8];
                octet_array.copy_from_slice(octets);
                *word = u64::from_be_bytes(octet_array);
            }
            crate::probes::hvpatch_core_census(
                generation.get(),
                mapping_count,
                4_u64.saturating_add(thread_count.saturating_mul(3)),
                region_count,
                payload.emitted_bytes(),
            );
            crate::probes::hvpatch_core_hash(generation.get(), hash_words);
            lifecycle(3, 0);
            Ok(Some(PreparedCorePublication {
                snapshot: process,
                payload,
                generation: generation.get(),
                fatal_tid: fatal.tid.raw(),
            }))
        })();
        if result.is_err() || matches!(&result, Ok(None)) {
            lifecycle(6, if result.is_err() { 1 } else { 2 });
        }
        finish_crash_collection(authority, barrier, quiesced, lease_drain_guard, result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        CrashCaptureTestEngine, EndpointTestSignalArrival, EndpointTestSignalPump,
        NoopPlatformFutex, registration_test_handle,
    };
    use super::*;
    use crate::dispatch::SyscallDispatcher;
    use carrick_hal::ThreadId;
    use parking_lot::Mutex;
    use std::time::Duration;

    fn register_crash_test_vcpu(
        registry: &dyn VcpuRegistry,
        tid: ThreadId,
        in_guest: &carrick_hal::InGuestFlag,
    ) {
        assert!(matches!(
            registry
                .subscribe_register(tid, registration_test_handle(), in_guest, Arc::new(|| {}),),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
    }

    struct CrashCallbackRegistry {
        inner: carrick_hal::GenericVcpuRegistry,
        callback_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CrashCallbackRegistry {
        fn new(callback_calls: Arc<std::sync::atomic::AtomicUsize>) -> Self {
            Self {
                inner: carrick_hal::GenericVcpuRegistry::new(),
                callback_calls,
            }
        }
    }

    impl VcpuRegistry for CrashCallbackRegistry {
        fn poll_lease_drain(&self, except: ThreadId) -> carrick_hal::VcpuLeaseDrainPoll {
            self.inner.poll_lease_drain(except)
        }

        fn subscribe_lease_drain(
            &self,
            except: ThreadId,
            callback: Arc<dyn Fn() + Send + Sync + 'static>,
        ) -> carrick_hal::VcpuLeaseDrainEnrollment {
            let callback_calls = Arc::clone(&self.callback_calls);
            self.inner.subscribe_lease_drain(
                except,
                Arc::new(move || {
                    callback_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    callback();
                }),
            )
        }

        fn subscribe_register(
            &self,
            tid: ThreadId,
            handle: Box<dyn carrick_hal::VcpuKickDyn>,
            in_guest: &carrick_hal::InGuestFlag,
            callback: Arc<dyn Fn() + Send + Sync + 'static>,
        ) -> carrick_hal::VcpuRegistrationEnrollment {
            self.inner
                .subscribe_register(tid, handle, in_guest, callback)
        }

        fn unregister(&self, tid: ThreadId) {
            self.inner.unregister(tid);
        }

        fn kick(&self, tid: ThreadId) {
            self.inner.kick(tid);
        }

        fn kick_if_in_guest(&self, tid: ThreadId) -> bool {
            self.inner.kick_if_in_guest(tid)
        }

        fn kick_all(&self) {
            self.inner.kick_all();
        }

        fn kick_all_in_guest(&self) -> bool {
            self.inner.kick_all_in_guest()
        }

        fn kick_all_except(&self, except: ThreadId) {
            self.inner.kick_all_except(except);
        }

        fn any_other_in_guest(&self, except: ThreadId) -> bool {
            self.inner.any_other_in_guest(except)
        }

        fn is_in_guest(&self, tid: ThreadId) -> bool {
            self.inner.is_in_guest(tid)
        }

        fn debug_registered_vcpus(&self) -> Vec<(ThreadId, bool)> {
            self.inner.debug_registered_vcpus()
        }
    }

    #[test]
    fn crash_lease_drain_short_budget_reports_exact_waiting_tid() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let owner = ThreadId::synthetic_for_tests(70_221);
        let sibling = ThreadId::synthetic_for_tests(70_222);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_crash_test_vcpu(&registry, owner, &owner_in_guest);
        register_crash_test_vcpu(&registry, sibling, &sibling_in_guest);

        let timeout = match acquire_crash_lease_drain(
            &registry,
            owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {},
        ) {
            Ok(_) => panic!("a live sibling must exhaust the zero crash-drain budget"),
            Err(timeout) => timeout,
        };

        assert!(matches!(
            timeout,
            CrashLeaseDrainTimeout::Waiting(tid) if tid == sibling
        ));
    }

    #[test]
    fn crash_lease_drain_short_budget_reports_busy_owner() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let freeze_owner = ThreadId::synthetic_for_tests(70_223);
        let competing_owner = ThreadId::synthetic_for_tests(70_224);
        let freeze = match registry.subscribe_lease_drain(freeze_owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("first crash owner must acquire the unique drain freeze"),
        };

        let timeout = match acquire_crash_lease_drain(
            &registry,
            competing_owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {},
        ) {
            Ok(_) => panic!("a competing freeze must exhaust the zero crash-drain budget"),
            Err(timeout) => timeout,
        };

        assert!(matches!(
            timeout,
            CrashLeaseDrainTimeout::Busy(owner) if owner == freeze_owner
        ));
        drop(freeze);
    }

    #[test]
    fn crash_lease_drain_freezes_late_registration() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let owner = ThreadId::synthetic_for_tests(70_225);
        let late = ThreadId::synthetic_for_tests(70_226);
        let guard = acquire_crash_lease_drain(
            &registry,
            owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {},
        )
        .expect("an empty sibling set must freeze atomically");
        let late_in_guest = carrick_hal::InGuestFlag::for_guest_thread();

        let enrollment = registry.subscribe_register(
            late,
            registration_test_handle(),
            &late_in_guest,
            Arc::new(|| {}),
        );
        assert!(matches!(
            &enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Waiting {
                owner: waiting_owner,
                ..
            } if *waiting_owner == owner
        ));
        assert_eq!(
            registry.poll_lease_drain(owner),
            carrick_hal::VcpuLeaseDrainPoll::Complete
        );
        drop(enrollment);
        drop(guard);
    }

    #[test]
    fn crash_guard_source_spans_quorum_and_read_core_bytes() {
        let source = include_str!("crash.rs");
        let capture = source
            .split("fn capture_core_for_publication(")
            .nth(1)
            .and_then(|tail| tail.split("#[cfg(test)]").next())
            .expect("bounded crash publication body");
        let barrier_acquire = capture.find("while !barrier.try_begin_fork()").unwrap();
        let advertise = capture.find("authority.advertise(generation)").unwrap();
        let envelope = capture.find("let result = (|| {").unwrap();
        let envelope_end = capture
            .rfind("})();")
            .expect("exact protected crash publication closure end")
            + "})();".len();
        let finish = capture.rfind("finish_crash_collection(").unwrap();
        assert!(envelope < envelope_end);
        assert!(envelope_end < finish);
        assert!(barrier_acquire < advertise);
        assert!(advertise < envelope);

        let protected = &capture[envelope..envelope_end];
        let barrier_raise = protected.find("barrier.set_quiescing()").unwrap();
        let acquire = protected.find("acquire_crash_lease_drain(").unwrap();
        let prepare = protected.find("engine.prepare_core_snapshot()").unwrap();
        let quorum = protected.find("quorum.poll()").unwrap();
        let read = protected.find(".read_core_bytes").unwrap();
        let serialize = protected.find(".build_payload(").unwrap();
        let publication = protected.find("PreparedCorePublication {").unwrap();
        assert!(barrier_raise < acquire);
        assert!(acquire < prepare);
        assert!(prepare < quorum);
        assert!(quorum < read);
        assert!(read < serialize);
        assert!(serialize < publication);
        assert_eq!(
            protected.matches(".read_core_bytes").count(),
            capture.matches(".read_core_bytes").count(),
            "every live engine read must remain inside the drain-guard closure"
        );
        assert!(
            protected
                .contains(".map_err(|timeout| RuntimeError::Configuration(timeout.to_string()))?")
        );
        assert!(!protected.contains("finish_crash_collection("));
        assert!(!capture[..finish].contains("drop(lease_drain_guard)"));
        assert!(!capture.contains("kicker.count()"));

        let cleanup = source
            .split("fn finish_crash_collection")
            .nth(1)
            .and_then(|tail| tail.split("impl<E: ThreadedEngine + 'static>").next())
            .expect("bounded common crash cleanup helper");
        let stop = cleanup.find("authority.stop_collecting()").unwrap();
        let end_quiesce = cleanup.find("barrier.end_quiesce()").unwrap();
        let end_fork = cleanup.find("barrier.end_fork()").unwrap();
        let drop_guard = cleanup.find("drop(lease_drain_guard)").unwrap();
        assert!(stop < end_quiesce);
        assert!(end_quiesce < end_fork);
        assert!(end_fork < drop_guard);
    }

    #[test]
    fn crash_teardown_releases_barrier_before_guard() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let barrier = Arc::new(crate::fork_quiesce::QuiesceBarrier::new());
        let authority = crate::kernel::CrashCaptureAuthority::default();
        let generation = authority.issue().expect("test crash generation");
        authority.advertise(generation);
        assert!(barrier.try_begin_fork());
        barrier.set_quiescing();
        let owner = ThreadId::synthetic_for_tests(70_227);
        let late = ThreadId::synthetic_for_tests(70_228);
        let guard = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("crash owner must freeze the empty sibling set"),
        };
        let saw_quiescing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let observed = Arc::clone(&saw_quiescing);
        let callback_barrier = Arc::clone(&barrier);
        let late_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let enrollment = registry.subscribe_register(
            late,
            registration_test_handle(),
            &late_in_guest,
            Arc::new(move || {
                observed.store(
                    callback_barrier.is_quiescing(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }),
        );
        assert!(matches!(
            &enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));

        finish_crash_collection(
            &authority,
            &barrier,
            true,
            Some(guard),
            Ok::<_, RuntimeError>(()),
        )
        .expect("crash cleanup must preserve the successful result");

        assert!(!saw_quiescing.load(std::sync::atomic::Ordering::SeqCst));
        drop(enrollment);
    }

    #[test]
    fn crash_lease_drain_timeout_releases_collection_and_barriers() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_229);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve crash sibling")
            .prepare(ThreadId::synthetic_for_tests(70_230))
            .expect("prepare crash sibling")
            .commit()
            .expect("publish crash sibling")
            .start_thread()
            .expect("start crash sibling")
            .into_context();
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process.clone());
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            Some(process.clone()),
            None,
            None,
        ));
        let barrier = kernel
            .process_fork_barrier
            .clone()
            .expect("HVPatch crash barrier");
        let authority = kernel
            .crash_capture
            .clone()
            .expect("HVPatch crash authority");
        let owner = ThreadId::synthetic_for_tests(70_229);
        let sibling_tid = ThreadId::synthetic_for_tests(70_230);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let kicker = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        register_crash_test_vcpu(kicker.as_ref(), owner, &owner_in_guest);
        register_crash_test_vcpu(kicker.as_ref(), sibling_tid, &sibling_in_guest);
        let kicker: Arc<dyn VcpuRegistry> = kicker;
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(owner)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            Some(Arc::clone(&barrier)),
            Some(Arc::clone(&authority)),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            owner,
            Arc::new(Mutex::new(Vec::new())),
            kicker,
            owner_in_guest,
            1_000,
        );
        state.install_crash_lease_drain_budget_for_test(CrashLeaseDrainBudget {
            timeout: Duration::ZERO,
            poll_interval: Duration::from_micros(1),
        });
        let mut engine = CrashCaptureTestEngine::default();

        let result = state.capture_core_for_publication(
            &kernel,
            &mut engine,
            FatalSignalRecord {
                image_generation: kernel.fatal_signal.current_generation(),
                tid: root.thread().key().tid,
                signo: 11,
                code: 1,
                addr: 0xdead,
            },
        );

        let error = match result {
            Ok(_) => panic!("a live waiting lease must time out real crash capture"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(&sibling_tid.raw().to_string()),
            "timeout must report the exact waiting sibling: {error}"
        );
        assert_eq!(root.task().key(), sibling.task().key());
        assert!(authority.collecting().is_none());
        assert!(!barrier.is_quiescing());
        assert!(barrier.try_begin_fork());
        barrier.end_fork();
    }

    #[test]
    fn capture_core_sparse_large_vma_reads_only_materialized_subranges_and_preserves_filesz() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_260);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        let worker = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve crash worker")
            .prepare(ThreadId::synthetic_for_tests(70_261))
            .expect("prepare crash worker")
            .commit()
            .expect("publish crash worker")
            .start_thread()
            .expect("start crash worker")
            .into_context();
        let dispatcher = SyscallDispatcher::new();
        let mut auxv_bytes = Vec::new();
        auxv_bytes.extend_from_slice(&6_u64.to_le_bytes()); // AT_PAGESZ
        auxv_bytes.extend_from_slice(&4096_u64.to_le_bytes());
        auxv_bytes.extend_from_slice(&0_u64.to_le_bytes()); // AT_NULL
        auxv_bytes.extend_from_slice(&0_u64.to_le_bytes());
        dispatcher.set_auxv_image(auxv_bytes);
        dispatcher.bind_hvpatch_process(process.clone());
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            Some(process.clone()),
            None,
            None,
        ));
        let barrier = kernel
            .process_fork_barrier
            .clone()
            .expect("HVPatch crash barrier");
        let authority = kernel
            .crash_capture
            .clone()
            .expect("HVPatch crash authority");
        let owner = ThreadId::synthetic_for_tests(70_261);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let kicker = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        register_crash_test_vcpu(kicker.as_ref(), owner, &owner_in_guest);
        let kicker: Arc<dyn VcpuRegistry> = kicker;
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(owner)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            Some(Arc::clone(&barrier)),
            Some(Arc::clone(&authority)),
            Some(Arc::clone(worker.thread())),
            Some(process.pid()),
            worker.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            owner,
            Arc::new(Mutex::new(Vec::new())),
            kicker,
            owner_in_guest,
            1_000,
        );
        state.service_kernel_context = Some(worker.retain_exact());

        let sparse_addr = 0x0000_1000_0000_0000_u64;
        let sparse_len = 64 * 1024 * 1024 * 1024_usize; // 64 GiB

        let deferred = kernel
            .dispatcher
            .deferred_anonymous_state(root.task().shared().mm().id())
            .expect("deferred anonymous state");
        deferred
            .reserve_fresh(carrick_guest_mem::GuestVa(sparse_addr), sparse_len)
            .expect("reserve fresh 64GiB VMA");

        // Touch 3 distinct pages: first, middle, last
        let page_first = sparse_addr;
        let page_middle = sparse_addr + 32 * 1024 * 1024 * 1024;
        let page_last = sparse_addr + (64 << 30) - 4096;

        deferred
            .begin_materialization(carrick_guest_mem::GuestVa(page_first), 4096)
            .expect("materialize first")
            .commit();
        deferred
            .begin_materialization(carrick_guest_mem::GuestVa(page_middle), 4096)
            .expect("materialize middle")
            .commit();
        deferred
            .begin_materialization(carrick_guest_mem::GuestVa(page_last), 4096)
            .expect("materialize last")
            .commit();

        kernel.dispatcher.record_dynamic_mapping(
            sparse_addr,
            sparse_len as u64,
            carrick_abi::LinuxProtFlags::READ | carrick_abi::LinuxProtFlags::WRITE,
            crate::vfs::ProcMapSharing::Private,
            String::new(),
        );

        let tracker = Arc::new(Mutex::new(Vec::new()));
        let mut engine = CrashCaptureTestEngine {
            read_tracker: Some(Arc::clone(&tracker)),
            ..CrashCaptureTestEngine::default()
        };
        engine.guest_memory.insert(page_first, vec![0x11; 4096]);
        engine.guest_memory.insert(page_middle, vec![0x22; 4096]);
        engine.guest_memory.insert(page_last, vec![0x33; 4096]);

        let result = state.capture_core_for_publication(
            &kernel,
            &mut engine,
            FatalSignalRecord {
                image_generation: kernel.fatal_signal.current_generation(),
                tid: worker.thread().key().tid,
                signo: 11,
                code: 1,
                addr: page_first,
            },
        );

        let prepared = result
            .expect("capture core must succeed")
            .expect("fatal signal must yield prepared publication");

        // 1. Verify read_core_bytes was called ONLY for the 3 touched pages (total 12 KiB)
        let reads = tracker.lock().clone();
        assert_eq!(
            reads.len(),
            3,
            "must only read the 3 touched pages, got {} reads: {:?}",
            reads.len(),
            reads
        );
        for (addr, len) in &reads {
            assert_eq!(*len, 4096, "each read must be page-sized");
            assert!(
                *addr == page_first || *addr == page_middle || *addr == page_last,
                "unexpected read at address {addr:#x}"
            );
        }

        // 2. Verify payload extents and size
        assert_eq!(prepared.payload.extents.len(), 3);
        assert!(
            prepared.payload.emitted_bytes() < 32 * 1024,
            "emitted bytes must be O(touched bytes), got {}",
            prepared.payload.emitted_bytes()
        );

        // 3. Verify PT_LOAD in ELF header preserves filesz == memsz == 64 GiB
        let phdr_bytes = &prepared.payload.header;
        let ehdr_size = usize::from(crate::core_dump::EHDR_SIZE);
        let phdr_size = usize::from(crate::core_dump::PHDR_SIZE);
        let phnum = crate::core_dump::read_u16(phdr_bytes, 56).unwrap() as usize;
        let mut found_sparse_load = false;
        for i in 0..phnum {
            let offset = ehdr_size + i * phdr_size;
            let kind = crate::core_dump::read_u32(phdr_bytes, offset).unwrap();
            let vaddr = crate::core_dump::read_u64(phdr_bytes, offset + 16).unwrap();
            let filesz = crate::core_dump::read_u64(phdr_bytes, offset + 32).unwrap();
            let memsz = crate::core_dump::read_u64(phdr_bytes, offset + 40).unwrap();
            if kind == crate::core_dump::PT_LOAD && vaddr == sparse_addr {
                assert_eq!(
                    filesz, sparse_len as u64,
                    "PT_LOAD filesz must equal VMA length"
                );
                assert_eq!(
                    memsz, sparse_len as u64,
                    "PT_LOAD memsz must equal VMA length"
                );
                found_sparse_load = true;
                break;
            }
        }
        assert!(
            found_sparse_load,
            "must find PT_LOAD for 64GiB sparse VMA in ELF header"
        );
    }

    #[test]
    fn capture_core_engine_read_error_fails_closed() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_270);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        let worker = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve crash worker")
            .prepare(ThreadId::synthetic_for_tests(70_271))
            .expect("prepare crash worker")
            .commit()
            .expect("publish crash worker")
            .start_thread()
            .expect("start crash worker")
            .into_context();
        let dispatcher = SyscallDispatcher::new();
        let mut auxv_bytes = Vec::new();
        auxv_bytes.extend_from_slice(&6_u64.to_le_bytes()); // AT_PAGESZ
        auxv_bytes.extend_from_slice(&4096_u64.to_le_bytes());
        auxv_bytes.extend_from_slice(&0_u64.to_le_bytes()); // AT_NULL
        auxv_bytes.extend_from_slice(&0_u64.to_le_bytes());
        dispatcher.set_auxv_image(auxv_bytes);
        dispatcher.bind_hvpatch_process(process.clone());
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            Some(process.clone()),
            None,
            None,
        ));
        let barrier = kernel
            .process_fork_barrier
            .clone()
            .expect("HVPatch crash barrier");
        let authority = kernel
            .crash_capture
            .clone()
            .expect("HVPatch crash authority");
        let owner = ThreadId::synthetic_for_tests(70_271);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let kicker = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        register_crash_test_vcpu(kicker.as_ref(), owner, &owner_in_guest);
        let kicker: Arc<dyn VcpuRegistry> = kicker;
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(owner)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            Some(Arc::clone(&barrier)),
            Some(Arc::clone(&authority)),
            Some(Arc::clone(worker.thread())),
            Some(process.pid()),
            worker.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            owner,
            Arc::new(Mutex::new(Vec::new())),
            kicker,
            owner_in_guest,
            1_000,
        );
        state.service_kernel_context = Some(worker.retain_exact());

        let target_addr = 0x0000_1000_0000_0000_u64;
        let target_len = 4096_usize;

        let deferred = kernel
            .dispatcher
            .deferred_anonymous_state(root.task().shared().mm().id())
            .expect("deferred anonymous state");
        deferred
            .reserve_fresh(carrick_guest_mem::GuestVa(target_addr), target_len)
            .expect("reserve VMA");
        deferred
            .begin_materialization(carrick_guest_mem::GuestVa(target_addr), target_len)
            .expect("materialize")
            .commit();

        kernel.dispatcher.record_dynamic_mapping(
            target_addr,
            target_len as u64,
            carrick_abi::LinuxProtFlags::READ | carrick_abi::LinuxProtFlags::WRITE,
            crate::vfs::ProcMapSharing::Private,
            String::new(),
        );

        let mut engine = CrashCaptureTestEngine {
            fail_read_at: Some(target_addr),
            ..CrashCaptureTestEngine::default()
        };

        let result = state.capture_core_for_publication(
            &kernel,
            &mut engine,
            FatalSignalRecord {
                image_generation: kernel.fatal_signal.current_generation(),
                tid: worker.thread().key().tid,
                signo: 11,
                code: 1,
                addr: target_addr,
            },
        );

        assert!(
            result.is_err(),
            "engine read error during core capture must fail closed"
        );
    }

    #[test]
    fn crash_lease_drain_callback_before_park_completes_without_poll_interval() {
        let callback_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let registry = Arc::new(CrashCallbackRegistry::new(Arc::clone(&callback_calls)));
        let owner = ThreadId::synthetic_for_tests(70_233);
        let sibling = ThreadId::synthetic_for_tests(70_234);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_crash_test_vcpu(registry.as_ref(), owner, &owner_in_guest);
        register_crash_test_vcpu(registry.as_ref(), sibling, &sibling_in_guest);
        let nudge_entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release_nudge = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        let worker_registry = Arc::clone(&registry);
        let worker_nudge_entered = Arc::clone(&nudge_entered);
        let worker_release_nudge = Arc::clone(&release_nudge);
        let worker = std::thread::spawn(move || {
            let result = acquire_crash_lease_drain(
                worker_registry.as_ref(),
                owner,
                CrashLeaseDrainBudget {
                    timeout: Duration::from_secs(2),
                    poll_interval: Duration::from_secs(1),
                },
                || {
                    worker_nudge_entered.store(true, std::sync::atomic::Ordering::SeqCst);
                    while !worker_release_nudge.load(std::sync::atomic::Ordering::SeqCst) {
                        std::thread::yield_now();
                    }
                },
            )
            .map(drop);
            done_tx.send(result).expect("publish drain result");
        });

        let nudge_deadline = Instant::now() + Duration::from_secs(1);
        while !nudge_entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                Instant::now() < nudge_deadline,
                "worker must subscribe before parking"
            );
            std::thread::yield_now();
        }
        registry.unregister(sibling);
        assert_eq!(
            callback_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "membership change must exercise the subscribed unpark callback"
        );
        release_nudge.store(true, std::sync::atomic::Ordering::SeqCst);
        done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("an unpark token published before park must avoid the one-second poll")
            .expect("membership removal must complete acquisition");
        worker.join().expect("crash-drain worker");
    }

    #[test]
    fn crash_lease_drain_deadline_reenrolls_after_waiting_member_leaves() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let owner = ThreadId::synthetic_for_tests(70_231);
        let sibling = ThreadId::synthetic_for_tests(70_232);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_crash_test_vcpu(&registry, owner, &owner_in_guest);
        register_crash_test_vcpu(&registry, sibling, &sibling_in_guest);
        let mut nudged = false;

        let guard = acquire_crash_lease_drain(
            &registry,
            owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {
                assert!(
                    !nudged,
                    "the zero-budget path must perform one final enrollment"
                );
                nudged = true;
                registry.unregister(sibling);
            },
        )
        .expect("the final atomic enrollment must observe the sibling removal");

        assert!(nudged);
        drop(guard);
    }

    #[test]
    fn crash_lease_drain_park_caps_to_remaining_budget() {
        assert_eq!(
            crash_lease_drain_park_duration(Duration::from_secs(1), Duration::from_millis(7)),
            Duration::from_millis(7)
        );
        assert_eq!(
            crash_lease_drain_park_duration(Duration::from_micros(200), Duration::from_secs(1)),
            Duration::from_micros(200)
        );
    }
}
