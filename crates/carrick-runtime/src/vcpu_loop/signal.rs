//! SIGNAL concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

pub(crate) fn signal_wait_slice(
    deadline: &mut Option<Instant>,
    timeout: Option<Duration>,
) -> Option<Duration> {
    if let Some(timeout) = timeout {
        let target = deadline.get_or_insert_with(|| Instant::now() + timeout);
        let now = Instant::now();
        if now >= *target {
            return None;
        }
        Some((*target - now).min(SIGNAL_WAIT_SLICE))
    } else {
        *deadline = None;
        Some(SIGNAL_WAIT_SLICE)
    }
}

pub(crate) fn signal_wait_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|target| Instant::now() >= target)
}

pub(crate) use carrick_kernel::kernel::continuation::raise_sigpipe_for_blocking_write;

pub(crate) fn partial_write_interrupt_outcome(
    write: &carrick_kernel::dispatch::BlockingWrite,
) -> DispatchOutcome {
    if write.offset() > 0 {
        DispatchOutcome::Returned {
            value: write.offset() as i64,
        }
    } else {
        DispatchOutcome::Errno {
            errno: crate::linux_abi::LINUX_EINTR,
        }
    }
}

// ===================================================================
// EL0 synchronous-fault translation (moved from runtime/fault.rs; the
// classifier fns are pure and the delivery fn is generic over the engine).
// ===================================================================

/// Map an EL0 synchronous-fault `ESR_EL1` to the Linux `(signum, si_code)` the
/// kernel would deliver, or `None` for a class we don't translate (kept fatal).
pub(crate) fn el0_fault_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const BUS_ADRALN: i32 = 1;
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let segv_code = if (0x0c..=0x0f).contains(&dfsc) {
        SEGV_ACCERR
    } else {
        SEGV_MAPERR
    };
    match ec {
        0x20 | 0x21 => Some((SIGSEGV, segv_code)), // instruction abort
        0x24 | 0x25 => {
            if dfsc == 0x21 {
                Some((SIGBUS, BUS_ADRALN)) // alignment fault
            } else {
                Some((SIGSEGV, segv_code))
            }
        }
        _ => None,
    }
}

/// The EL0 access direction behind a translation or permission fault
/// `ESR_EL1`, for authenticating a possibly stale fault against the live
/// stage-1 leaf. `None` for every other fault class (alignment, access-flag,
/// address-size, external abort): those never resolve by retry.
pub(crate) fn el0_fault_access(esr: u64) -> Option<carrick_mmu_core::aarch64::LeafAccess> {
    use carrick_mmu_core::aarch64::LeafAccess;
    const WNR: u64 = 1 << 6;
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    if !((0x04..=0x07).contains(&dfsc) || (0x0c..=0x0f).contains(&dfsc)) {
        return None;
    }
    match ec {
        0x20 | 0x21 => Some(LeafAccess::Execute),
        0x24 | 0x25 => Some(if esr & WNR != 0 {
            LeafAccess::Write
        } else {
            LeafAccess::Read
        }),
        _ => None,
    }
}

// `el0_debug_signal` (a pure AArch64 ESR_EL1 architectural fact) moved to
// `carrick_aarch64::esr`; re-exported so the HVF lowering below and
// every `el0_debug_signal` call path resolve unchanged.
pub(crate) use carrick_aarch64::esr::el0_debug_signal;

/// Lower a raw aarch64 `EL0Fault` (raw `ESR_EL1` + `elr`/`far`) to the
/// ISA-neutral resolved signal triple `(signum, si_code, fault_addr)`, or `None`
/// for a class we don't translate (kept fatal → caller terminates by SIGSEGV).
///
/// This is the aarch64 → [`TrapError::GuestFault`] lowering. It MUST cover BOTH
/// fault arms so the GuestFault path is byte-identical to the historical
/// `EL0Fault` path: `el0_debug_signal` (BRK/single-step/HW-bp → SIGTRAP/TRAP_*)
/// is tried FIRST (so a debug exception carries the faulting PC as `si_addr`),
/// then `el0_fault_signal` (instruction/data abort → SIGSEGV/SIGBUS, carrying
/// `FAR_EL1` as `si_addr`). Mapping only `el0_fault_signal` would regress
/// BRK/single-step SIGTRAP delivery (ptrace, Go TestDebugCall).
pub(crate) fn lower_el0_fault(esr: u64, elr: u64, far: u64) -> Option<(i32, i32, u64)> {
    if let Some((signum, si_code)) = el0_debug_signal(esr) {
        Some((signum, si_code, elr))
    } else {
        el0_fault_signal(esr).map(|(signum, si_code)| (signum, si_code, far))
    }
}

pub(crate) enum FaultSignalDisposition {
    Stopped,
    Injected,
    Terminate(i32),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FaultSignal {
    pub signum: i32,
    pub si_code: i32,
    pub si_addr: u64,
    pub interrupted_pc: Option<u64>,
}

impl From<carrick_kernel::kernel::objects::PtraceSynchronousFault> for FaultSignal {
    fn from(fault: carrick_kernel::kernel::objects::PtraceSynchronousFault) -> Self {
        Self {
            signum: fault.signal.raw(),
            si_code: fault.si_code,
            si_addr: fault.si_addr,
            interrupted_pc: fault.interrupted_pc,
        }
    }
}

/// Apply Linux's synchronous-fault signal rules to any syscall trap adapter.
/// Backend-specific code resolves paging first, then calls this helper with the
/// final signal triple and decides how to terminate its host process.
pub(crate) fn inject_fault_signal<T: SyscallTrap>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    this_tid: ThreadId,
    fault: &mut FaultSignal,
) -> Result<FaultSignalDisposition, RuntimeError> {
    // This is the single synchronous-signal admission point, including a
    // ptrace-resumed fault. Classify before ptrace, disposition and injection
    // so none of those exits can bypass the file BUS range.
    let incoming = fault.signum;
    let bus = incoming == crate::linux_abi::LINUX_SIGSEGV
        && dispatcher.mmap_fault_is_sigbus(fault.si_addr);
    if bus {
        fault.signum = crate::linux_abi::LINUX_SIGBUS;
        fault.si_code = 2; // BUS_ADRERR
    }
    crate::probes::hvpatch_fault_delivery(
        fault.si_addr,
        incoming,
        fault.signum,
        bus,
        this_tid.raw(),
    );
    crate::probes::signal_deliver(this_tid.raw(), fault.signum);
    if let Ok(signal) = carrick_kernel::kernel::LinuxSignal::for_signal_number(fault.signum)
        && carrick_kernel::exec_helpers::stop_for_ptrace_fault(
            dispatcher,
            carrick_kernel::kernel::objects::PtraceSynchronousFault {
                signal,
                si_code: fault.si_code,
                si_addr: fault.si_addr,
                interrupted_pc: fault.interrupted_pc,
            },
        )
    {
        return Ok(FaultSignalDisposition::Stopped);
    }
    carrick_kernel::exec_helpers::stop_for_debug_signal(fault.signum);

    let action = dispatcher.registered_signal_handler(context, fault.signum);
    if dispatcher.signal_blocked(context, this_tid, fault.signum) || action.is_none() {
        return Ok(FaultSignalDisposition::Terminate(fault.signum));
    }
    // INVARIANT: the `action.is_none()` arm above returned, so this is `Some`.
    #[allow(clippy::unwrap_used)]
    let action = action.unwrap();
    let sa_flags = carrick_abi::LinuxSaFlags::from_bits_truncate(action.sa_flags);
    let restorer = if sa_flags.contains(carrick_abi::LinuxSaFlags::RESTORER) {
        action.sa_restorer
    } else {
        0
    };
    let altstack = if sa_flags.contains(carrick_abi::LinuxSaFlags::ONSTACK) {
        dispatcher.signal_altstack(context, this_tid)
    } else {
        None
    };
    let saved_sigmask = dispatcher
        .enter_signal_handler(context, this_tid, fault.signum, action)
        .raw();
    match trap.inject_signal(carrick_hal::SignalInjection {
        signum: fault.signum,
        handler: action.sa_handler,
        sa_restorer: restorer,
        pending_syscall_retval: None,
        interrupted_pc: fault.interrupted_pc,
        altstack,
        saved_sigmask,
        fault_siginfo: Some((fault.si_code, fault.si_addr)),
        queued_siginfo: None,
        restart_syscall: false,
    }) {
        Ok(()) => Ok(FaultSignalDisposition::Injected),
        Err(TrapError::SignalDeliveryFault) => {
            crate::probes::hvpatch_fault_signal_frame_failure(
                fault.si_addr,
                fault.signum,
                this_tid.raw(),
            );
            Ok(FaultSignalDisposition::Terminate(11))
        }
        Err(error) => Err(error.into()),
    }
}

/// Deliver a synchronous guest fault as a Linux signal, exactly as the kernel
/// does, from the ALREADY-RESOLVED [`TrapError::GuestFault`] triple. Returns
/// `Some(outcome)` to terminate, `None` to resume into the injected handler.
///
/// `interrupted_pc` is the faulting instruction's PC iff the sigframe should
/// record it as the resume target (aarch64's direct-EL0-abort path); `None`
/// means the injected frame re-runs the faulting instruction from the engine's
/// own saved PC. ISA-neutral: aarch64 lowers `EL0Fault` to this via
/// [`lower_el0_fault`]; x86 backends emit `GuestFault` directly (CR2 →
/// `fault_addr`).
pub(super) fn deliver_fault_signal<E: ThreadedEngine>(
    kernel: &Kernel,
    context: &carrick_kernel::kernel::KernelContext,
    engine: &mut E,
    this_tid: ThreadId,
    fatal_image_generation: u64,
    mut fault: FaultSignal,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    let dispatcher = &kernel.dispatcher;
    // Capture the forked-child flag up front so the `terminate` closure does not
    // borrow `engine` — it is now also called in the inject-failure arm below,
    // after a &mut engine use, and a closure-held &engine would conflict. (M1b)
    let is_forked_child = engine.is_forked_child();
    let disposition = inject_fault_signal(engine, dispatcher, context, this_tid, &mut fault)?;
    let terminate = |signum: i32| -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        crate::probes::hvpatch_fault_terminal(fault.si_addr, signum, fault.si_code, this_tid.raw());
        if super::requires_no_unwind_host_exit(kernel, is_forked_child) {
            let out = dispatcher.stdout();
            let err = dispatcher.stderr();
            dispatcher.cleanup_sysv_ipc_on_process_exit();
            forked_child_die_by_signal(&*dispatcher.host_signal, signum, &out, &err);
        }
        kernel.record_fatal_signal(super::FatalSignalRecord {
            image_generation: fatal_image_generation,
            tid: context.thread().key().tid,
            signo: signum,
            code: fault.si_code,
            addr: fault.si_addr,
        });
        let result = assemble_run_result(kernel, 128 + signum, Some(signum), traps, false);
        Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))))
    };

    match disposition {
        FaultSignalDisposition::Stopped => Ok(None),
        FaultSignalDisposition::Injected => Ok(None),
        FaultSignalDisposition::Terminate(signum) => terminate(signum),
    }
}

fn apply_first_touch(
    prot: u64,
    access: Option<carrick_mmu_core::aarch64::LeafAccess>,
    protect: impl FnOnce() -> bool,
    commit: impl FnOnce(),
) -> Option<bool> {
    use carrick_mmu_core::aarch64::LeafAccess;
    let required = match access {
        // Preserve the current protection lowering: any accessible leaf is
        // readable, including write-only and execute-only Linux requests.
        Some(LeafAccess::Read) => {
            crate::linux_abi::LINUX_PROT_READ
                | crate::linux_abi::LINUX_PROT_WRITE
                | crate::linux_abi::LINUX_PROT_EXEC
        }
        Some(LeafAccess::Write) => crate::linux_abi::LINUX_PROT_WRITE,
        Some(LeafAccess::Execute) => crate::linux_abi::LINUX_PROT_EXEC,
        None => return Some(false),
    };
    if prot & required == 0 {
        return Some(false);
    }
    if !protect() {
        return None;
    }
    commit();
    Some(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameGrantClaim {
    None,
    ResponsePending,
    Accepted(carrick_el1_abi::FrameGrantRequest),
}

fn frame_grant_access(access: Option<carrick_mmu_core::aarch64::LeafAccess>) -> Option<u64> {
    use carrick_mmu_core::aarch64::LeafAccess;
    match access? {
        LeafAccess::Read => Some(crate::linux_abi::LINUX_PROT_READ),
        LeafAccess::Write => Some(crate::linux_abi::LINUX_PROT_WRITE),
        LeafAccess::Execute => Some(crate::linux_abi::LINUX_PROT_EXEC),
    }
}

/// The event-ring encoding of a decoded fault access.
pub(super) fn ring_access(
    access: Option<carrick_mmu_core::aarch64::LeafAccess>,
) -> carrick_kernel::event_ring::RingAccess {
    use carrick_kernel::event_ring::RingAccess;
    use carrick_mmu_core::aarch64::LeafAccess;
    match access {
        None => RingAccess::Unknown,
        Some(LeafAccess::Read) => RingAccess::Read,
        Some(LeafAccess::Write) => RingAccess::Write,
        Some(LeafAccess::Execute) => RingAccess::Execute,
    }
}

fn claim_frame_grant_request(
    mailbox: &carrick_el1_abi::FrameGrantMailbox,
    mm_key: u64,
    fault_va: u64,
    access: Option<carrick_mmu_core::aarch64::LeafAccess>,
) -> FrameGrantClaim {
    if frame_grant_access(access).is_some_and(|actual| {
        mailbox
            .response_for_fault(mm_key, fault_va, actual)
            .is_some()
    }) {
        return FrameGrantClaim::ResponsePending;
    }
    let Some(actual) = frame_grant_access(access) else {
        return FrameGrantClaim::None;
    };
    mailbox
        .claim_request_for_fault(mm_key, fault_va, actual)
        .map_or(FrameGrantClaim::None, FrameGrantClaim::Accepted)
}

fn publish_frame_grant_refusal(
    mailbox: &carrick_el1_abi::FrameGrantMailbox,
    request: carrick_el1_abi::FrameGrantRequest,
    status: u64,
) {
    if !mailbox.publish_refusal(status) {
        carrick_fatal::carrick_fatal!(
            "hvpatch::el1_frame_grant",
            "claimed frame-grant request could not publish backend refusal: mm={} generation={} status={}",
            request.mm_key,
            request.request_generation,
            status
        );
    }
}

/// Drop an exact EL1 request when the host resolved or delivered the fault
/// without producing a frame grant. Requests are hints; leaving one pending
/// would make the carrier-wide mailbox one fault behind every later exit.
pub(super) fn cancel_frame_grant_request(
    mailbox_slot: Option<usize>,
    mm_key: u64,
    address: u64,
    access: Option<carrick_mmu_core::aarch64::LeafAccess>,
) {
    let Some(actual) = frame_grant_access(access) else {
        return;
    };
    if let Some(mailbox) = mailbox_slot.and_then(carrick_el1_abi::frame_grant_mailbox_host_for_slot)
    {
        let _ = mailbox.cancel_request_for_fault(mm_key, address, actual);
    }
}

/// Guest EL1 bulk frame grants for first touch. `CARRICK_EL1_FRAME_GRANT=0`
/// ignores EL1's requests (the fault path cancels them) so every first touch
/// takes the host path.
fn el1_frame_grants_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_EL1_FRAME_GRANT").map_or(true, |value| value.trim() != "0")
    })
}

/// The operator's choice for the guest descriptor lane, read once per carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DescriptorLaneHatch {
    /// The lane is admitted wherever the writer census admits it.
    Default,
    /// `CARRICK_EL1_DESCRIPTOR_LANE=0`: every MM stays on the host-owned
    /// lane, whatever the census says.
    Disabled,
}

impl DescriptorLaneHatch {
    /// Parse `CARRICK_EL1_DESCRIPTOR_LANE`: exactly `0` (trimmed) disables.
    pub(super) fn from_env_value(value: Option<&str>) -> Self {
        match value {
            Some(value) if value.trim() == "0" => Self::Disabled,
            _ => Self::Default,
        }
    }

    /// This carrier's hatch.
    pub(super) fn current() -> Self {
        static HATCH: std::sync::OnceLock<DescriptorLaneHatch> = std::sync::OnceLock::new();
        *HATCH.get_or_init(|| {
            Self::from_env_value(std::env::var("CARRICK_EL1_DESCRIPTOR_LANE").ok().as_deref())
        })
    }
}

/// Every host writer family that still stores live stage-1 descriptors. The
/// guest-owned lane is admitted for an MM only when every one of them submits
/// descriptor transactions instead; a single unconverted writer would be
/// refused on that lane and turn an ordinary host edit into a guest fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GuestDescriptorLanePrecondition {
    /// The descriptor transaction slots are placed in the installed EL1 region.
    pub(super) slots_placed: bool,
    /// Bulk first-touch frame grants (this path).
    pub(super) frame_grants: bool,
    /// Host syscall copyout into prepared pages (`commit_prepared_host_write`).
    pub(super) host_copyout: bool,
    /// Fork parent COW arming (`build_process_spec`): built as EL1
    /// transactions, applied synchronously on the forking vCPU through the
    /// host-driven drain call and settled before the fork commits
    /// (`apply_guest_fork_arm`); EL1 drains an MM's submissions before any of
    /// its threads returns to EL0.
    pub(super) fork_parent_arming: bool,
    /// Backend COW, sparse/foreign materialization and exec publication.
    pub(super) backend_writers: bool,
}

impl GuestDescriptorLanePrecondition {
    /// The writer census of this build. Host copyout publishes through the
    /// verified EL1 Publish/Write receipt before the kernel commits residency
    /// (`commit_prepared_host_write` -> `publish_copyout`). Every backend
    /// writer family submits descriptor transactions on the guest lane: the
    /// shared terminal rule (mprotect, munmap retirement, retired reset, BUS
    /// tags, fork arming), table reclaim receipts, alias maps, retained
    /// reuse, sparse/file materialization, frame-grant replacement and
    /// foreign-MM COW; exec publishes an offline image before the new MM
    /// selects its lane.
    pub(super) fn current() -> Self {
        Self {
            slots_placed: carrick_el1_abi::descriptor_txn_slots_host().is_some(),
            frame_grants: true,
            host_copyout: true,
            fork_parent_arming: true,
            backend_writers: true,
        }
    }

    pub(super) fn admits(self) -> bool {
        self.slots_placed
            && self.frame_grants
            && self.host_copyout
            && self.fork_parent_arming
            && self.backend_writers
    }

    /// Whether an MM may select the guest lane under `hatch`. The operator
    /// hatch is its own reason, never folded into a census field.
    pub(super) fn admission(
        self,
        hatch: DescriptorLaneHatch,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestLaneRefusal> {
        use carrick_mmu_core::aarch64::GuestLaneRefusal;
        if hatch == DescriptorLaneHatch::Disabled {
            return Err(GuestLaneRefusal::OperatorHatch);
        }
        if !self.admits() {
            return Err(GuestLaneRefusal::Census);
        }
        Ok(())
    }
}

/// Select the guest-owned lane for `engine`'s MM when the precondition
/// admits it. Called where an engine binds an MM (initial runner and exec);
/// fork children inherit their parent's lane. Never demotes a guest-owned MM.
fn select_guest_descriptor_lane<E: ThreadedEngine>(
    engine: &mut E,
    precondition: GuestDescriptorLanePrecondition,
    hatch: DescriptorLaneHatch,
) -> bool {
    use carrick_mmu_core::aarch64::LiveDescriptorOwner;
    if engine.live_descriptor_owner() == LiveDescriptorOwner::Guest {
        return true;
    }
    if let Err(reason) = precondition.admission(hatch) {
        engine.record_guest_descriptor_lane_refusal(reason);
        return false;
    }
    engine.select_live_descriptor_owner(LiveDescriptorOwner::Guest)
}

/// An MM an engine has just made its own: the initial runner's MM, or the
/// replacement MM an exec committed. It carries the kernel's ownership of
/// the MM, so the MM's admission to guest ownership decides from the MM
/// itself rather than from a bare generation.
pub(super) struct BoundMm {
    pub(super) mm: std::sync::Arc<carrick_kernel::kernel::objects::Mm>,
    pub(super) asid_generation: u64,
}

/// Admit an MM an engine binds: bind the engine's snapshot identity to it
/// and select its live descriptor lane. This is the single admission point
/// for the initial runner and exec commit. Fork children do not pass here:
/// they inherit their parent's lane with their stage-1 authority
/// (`Stage1Authority::child_with_manager`) at fork commit.
pub(super) fn admit_bound_mm<E: ThreadedEngine>(engine: &mut E, bound: &BoundMm) -> bool {
    engine.bind_task_snapshot_identity(bound.mm.id().raw(), bound.asid_generation);
    select_guest_descriptor_lane(
        engine,
        GuestDescriptorLanePrecondition::current(),
        DescriptorLaneHatch::current(),
    )
}

/// Whether EL1 completed fork-COW copies of `mm` the host has not settled
/// yet: until it does, the host's mapping view names the old frames of those
/// spans while their live leaves name EL1's grants.
pub(super) fn guest_cow_awaiting_settlement(mm: carrick_kernel::kernel::MmId) -> bool {
    carrick_el1_abi::cow_grant_pool_host().is_some_and(|pool| pool.has_completions_for(mm.raw()))
}

/// Host-retained copy of one submitted guest-lane frame grant: the exact
/// transaction (never re-read from shared memory) and what the host commits
/// once EL1's receipt verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PendingGuestGrant {
    pub(super) txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    /// The fault and span that produced the first-touch plan; settlement
    /// re-derives the plan under the MM mutation guard and requires it
    /// unchanged before committing.
    pub(super) fault_va: u64,
    pub(super) requested_len: u64,
    pub(super) plan: (u64, u64, u64),
    pub(super) residency: carrick_el1_abi::FrameGrantResidencyIdentity,
}

/// What settling one guest grant did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GuestGrantSettlement {
    /// EL1 published it; residency was committed for exactly this span.
    Committed(carrick_mmu_core::aarch64::descriptor_txn::PageSpan),
    /// EL1 refused or rolled it back; nothing was committed and its table
    /// grants returned. The fault path starts over.
    Refused(carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal),
}

/// Per-vCPU-slot ledger of submitted guest grants, mirroring the shared
/// `DescriptorTxnSlots`. The entry lock is held across submission so a
/// receipt can never be settled before its host copy exists.
pub(super) struct GuestGrantLedger {
    pending:
        [parking_lot::Mutex<Option<PendingGuestGrant>>; carrick_el1_abi::EL1_STACK_SLOTS as usize],
    /// Occupied entries, so a boundary with nothing pending skips the scan.
    occupied: std::sync::atomic::AtomicUsize,
}

impl GuestGrantLedger {
    pub(super) const fn new() -> Self {
        Self {
            pending: [const { parking_lot::const_mutex(None) };
                carrick_el1_abi::EL1_STACK_SLOTS as usize],
            occupied: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Submit `pending` through `slot`. `false`: the slot is busy or out of
    /// range; nothing was submitted.
    pub(super) fn submit(
        &self,
        slots: &carrick_el1_abi::DescriptorTxnSlots,
        slot: usize,
        pending: PendingGuestGrant,
    ) -> bool {
        let Some(entry) = self.pending.get(slot) else {
            return false;
        };
        let mut entry = entry.lock();
        if entry.is_some() {
            return false;
        }
        // Count the entry BEFORE EL1 can see the submission: EL1 finds work
        // only through the slots' summary, which `slots.submit` publishes,
        // and a boundary woken by EL1's receipt then reads a nonzero count.
        // Counting after (as this did) let `settle_ready`'s empty-ledger skip
        // miss a receipt published in between.
        self.occupied
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !slots.submit(slot, &pending.txn) {
            self.occupied
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return false;
        }
        *entry = Some(pending);
        true
    }

    /// Whether any guest grant is pending anywhere in the carrier.
    pub(super) fn is_occupied(&self) -> bool {
        self.occupied.load(std::sync::atomic::Ordering::Acquire) != 0
    }

    fn release(&self, entry: &mut Option<PendingGuestGrant>) {
        if entry.take().is_some() {
            self.occupied
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Release every slot and ledger entry of an MM that is retiring (final
    /// teardown or exec replacement). An unclaimed submission is withdrawn,
    /// and a published receipt is consumed: the MM's tables and grants retire
    /// with it, so nothing is settled or committed. A submission EL1 is
    /// still applying stays until its receipt, which a later call releases.
    /// Returns the entries released.
    pub(super) fn withdraw_mm(
        &self,
        slots: &carrick_el1_abi::DescriptorTxnSlots,
        mm_key: u64,
    ) -> usize {
        let mut released = 0;
        for (slot, entry) in self.pending.iter().enumerate() {
            let mut entry = lock_ledger_slot(entry);
            let Some(pending) = *entry else {
                continue;
            };
            if pending.txn.id.mm_key.get() != mm_key {
                continue;
            }
            if slots.withdraw(slot, pending.txn.id)
                || slots.take_receipt(slot, pending.txn.id).is_some()
            {
                self.release(&mut entry);
                released += 1;
            }
        }
        released
    }

    /// Settle every receipt EL1 has published for `mm_key`, in slot order.
    /// Returns how many were settled.
    pub(super) fn settle_ready<Err>(
        &self,
        slots: &carrick_el1_abi::DescriptorTxnSlots,
        mm_key: u64,
        mut settle: impl FnMut(
            PendingGuestGrant,
            carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
        ) -> Result<GuestGrantSettlement, Err>,
    ) -> Result<usize, Err> {
        // One load when nothing is pending anywhere. `submit` counts an entry
        // before EL1 can see its submission, so a receipt implies a nonzero
        // count here (see `submit`).
        if !self.is_occupied() {
            return Ok(0);
        }
        let mut settled = 0;
        for (slot, entry) in self.pending.iter().enumerate() {
            let taken = {
                let mut entry = lock_ledger_slot(entry);
                match *entry {
                    Some(pending) if pending.txn.id.mm_key.get() == mm_key => {
                        let receipt = slots.take_receipt(slot, pending.txn.id);
                        if receipt.is_some() {
                            self.release(&mut entry);
                        }
                        receipt.map(|receipt| (pending, receipt))
                    }
                    _ => None,
                }
            };
            if let Some((pending, receipt)) = taken {
                settle(pending, receipt)?;
                settled += 1;
            }
        }
        Ok(settled)
    }
}

#[cfg(test)]
thread_local! {
    /// Ledger slot locks this thread has taken: the settle boundary's
    /// structural work budget.
    static LEDGER_SLOT_LOCKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn ledger_slot_locks_on_this_thread() -> usize {
    LEDGER_SLOT_LOCKS.with(std::cell::Cell::get)
}

fn lock_ledger_slot(
    entry: &parking_lot::Mutex<Option<PendingGuestGrant>>,
) -> parking_lot::MutexGuard<'_, Option<PendingGuestGrant>> {
    #[cfg(test)]
    LEDGER_SLOT_LOCKS.with(|locks| locks.set(locks.get() + 1));
    entry.lock()
}

/// Carrier-wide ledger for the shared EL1 descriptor transaction slots.
static GUEST_GRANT_LEDGER: GuestGrantLedger = GuestGrantLedger::new();

/// Release a retiring MM's descriptor transaction slots, ledger entries and
/// frame-grant mailbox work, at final-MM teardown and at exec replacement,
/// beside its residency records. A slot left SUBMITTED, or a mailbox left
/// holding the MM's request or refusal, would refuse every later grant on
/// that vCPU slot, whichever MM it next runs. Returns the descriptor entries
/// released.
pub(super) fn withdraw_guest_descriptor_work(mm_key: u64) -> usize {
    for slot in 0..carrick_el1_abi::EL1_STACK_SLOTS as usize {
        if let Some(mailbox) = carrick_el1_abi::frame_grant_mailbox_host_for_slot(slot) {
            let _ = mailbox.withdraw_mm(mm_key);
        }
    }
    carrick_el1_abi::descriptor_txn_slots_host()
        .map_or(0, |slots| GUEST_GRANT_LEDGER.withdraw_mm(slots, mm_key))
}

impl PendingGuestGrant {
    /// What the backend published for this grant before submission, as the
    /// backend's single rollback names it.
    pub(super) fn rollback(&self) -> carrick_hal::threaded::El1FrameGrantRollback {
        carrick_hal::threaded::El1FrameGrantRollback {
            mm_key: self.residency.mm_key,
            semantic_base: self.residency.semantic_base,
            len: self.residency.len,
            ready: carrick_hal::El1FrameGrantReady {
                physical_ipa: self.residency.physical_ipa,
                frame_id: self.residency.frame_id,
                mapping_id: self.residency.mapping_id,
                owner_generation: self.residency.owner_generation,
                inventory_revision: self.residency.inventory_revision,
            },
        }
    }
}

/// The backend side of settling one guest grant receipt.
pub(super) trait GuestGrantBackend {
    /// Authenticate EL1's receipt against the retained submission and
    /// return its unused table grants.
    fn verify(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>;
    /// Finish what the backend deferred until EL1's verified receipt: a
    /// grant replacing a private predecessor retires that old owner and
    /// registers its own alias only now.
    fn complete(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<(), TrapError>;
    /// Undo what the backend published for a grant EL1 never exposed.
    fn roll_back(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<bool, TrapError>;
}

/// The production backend: the engine that prepared the MM's grants.
pub(super) struct EngineGrantBackend<'a, E>(pub(super) &'a mut E);

impl<E: ThreadedEngine> GuestGrantBackend for EngineGrantBackend<'_, E> {
    fn verify(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
    {
        self.0.settle_el1_descriptor_receipt(txn, receipt)
    }

    fn complete(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<(), TrapError> {
        self.0.complete_el1_frame_grant(grant)
    }

    fn roll_back(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<bool, TrapError> {
        self.0.roll_back_el1_frame_grant(grant)
    }
}

/// Authenticate one guest grant receipt, then complete the backend's
/// deferred publication and commit exactly its resident span. Residency is
/// never committed before EL1's publication is proven, and an
/// unauthenticated or indeterminate receipt fails stopped. A grant that
/// replaces a private predecessor retires that old owner only here, after
/// the verified receipt and before residency. A refused or rolled-back grant
/// exposed no leaf, so its predecessor is left exactly as it was and what
/// the backend published for the grant before submission is rolled back.
pub(super) fn settle_guest_frame_grant(
    pending: PendingGuestGrant,
    receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    backend: &mut impl GuestGrantBackend,
    commit: impl FnOnce(
        &PendingGuestGrant,
        carrick_mmu_core::aarch64::descriptor_txn::PageSpan,
    ) -> Result<(), TrapError>,
) -> Result<GuestGrantSettlement, TrapError> {
    use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
    match receipt.outcome {
        DescriptorOutcome::Applied(_) => {
            let verified = backend.verify(&pending.txn, receipt)?;
            backend.complete(pending.rollback())?;
            commit(&pending, verified.resident())?;
            Ok(GuestGrantSettlement::Committed(verified.resident()))
        }
        DescriptorOutcome::Refused(refusal) | DescriptorOutcome::RolledBack(refusal) => {
            // Settlement returns the grants of a refused transaction and
            // reports it as not applied, which is the expected answer here.
            let _ = backend.verify(&pending.txn, receipt);
            backend.roll_back(pending.rollback())?;
            Ok(GuestGrantSettlement::Refused(refusal))
        }
        DescriptorOutcome::Indeterminate(refusal) => Err(TrapError::Hypervisor(format!(
            "EL1 descriptor transaction {:?} could not roll back: {refusal:?}",
            pending.txn.id
        ))),
    }
}

/// Settle every guest-lane grant receipt for the MM this boundary mutates.
pub(super) fn settle_guest_frame_grants<E: ThreadedEngine>(
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    engine: &mut E,
    mutation: &carrick_kernel::dispatch::mm_mutation::MmMutationGuard<'_>,
) -> Result<(), TrapError> {
    let Some(slots) = carrick_el1_abi::descriptor_txn_slots_host() else {
        return Ok(());
    };
    let mm_key = mutation.host_alias_permit().mm().raw();
    GUEST_GRANT_LEDGER.settle_ready(slots, mm_key, |pending, receipt| {
        settle_guest_frame_grant(
            pending,
            &receipt,
            &mut EngineGrantBackend(&mut *engine),
            |pending, _resident| {
                let permit = mutation.host_alias_permit();
                let plan = dispatcher
                    .resident_frame_grant_plan(&permit, pending.fault_va, pending.requested_len)
                    .filter(|plan| (plan.start(), plan.len(), plan.prot()) == pending.plan)
                    .ok_or_else(|| {
                        TrapError::Hypervisor(format!(
                            "EL1 published grant {:?} but its first-touch plan changed",
                            pending.txn.id
                        ))
                    })?;
                dispatcher.commit_resident_frame_grant(plan);
                if let Some(table) = carrick_el1_abi::frame_grant_residency_host() {
                    let _ = table.publish(pending.residency);
                }
                Ok(())
            },
        )
    })?;
    Ok(())
}

/// Whether a forwarded-syscall boundary must settle guest grants before it
/// services the syscall, so `mincore` and every other reader of residency
/// sees what EL1 already published. Cheap when nothing is pending.
pub(super) fn guest_grants_awaiting_settlement() -> bool {
    GUEST_GRANT_LEDGER.is_occupied()
}

#[cfg(test)]
use carrick_aarch64::descriptor_drain::GuestDrainVenue;
use carrick_aarch64::descriptor_drain::{EngineDrainVenue, apply_guest_descriptor_txns_now};

/// Fork parent arm on the guest-owned lane: applied synchronously on the
/// forking vCPU before the fork commits and before any parent thread can run
/// again. A failure here leaves the parent's frames shared with a child that
/// may already exist, so it fails stopped.
pub(super) fn apply_guest_fork_arm<E: ThreadedEngine>(
    engine: &mut E,
    txns: Vec<carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn>,
) {
    let Some(slots) = carrick_el1_abi::descriptor_txn_slots_host() else {
        carrick_fatal::carrick_fatal!(
            "hvpatch::guest_fork_arm",
            "guest fork arm has no descriptor transaction slots"
        );
    };
    if let Err(error) = apply_guest_descriptor_txns_now(&mut EngineDrainVenue(engine), slots, &txns)
    {
        carrick_fatal::carrick_fatal!(
            "hvpatch::guest_fork_arm",
            "guest fork parent arm failed: {error}"
        );
    }
}

/// Whether a guest descriptor transaction for `mm_key` is in flight over
/// `address`: the fault predates EL1's publication and must retry, never
/// take a host first-touch path that would race the guest's edit.
pub(super) fn guest_descriptor_edit_in_flight(
    slots: Option<&carrick_el1_abi::DescriptorTxnSlots>,
    mm_key: u64,
    address: u64,
) -> bool {
    slots.is_some_and(|slots| slots.pending_covering(mm_key, address))
}

/// Resolve a fault whose read-only outer classification placed it inside a
/// first-touch or grow-down extent. This entry point cannot be called without
/// structural mutation authority and is kept separate from ordinary signal
/// delivery. `Ok(true)` means the faulting instruction must be retried.
///
/// When no pending edit names the page, the fault may still be stale: a
/// sibling thread faulted on the same page, won the authority first and
/// committed it, so this thread's fault predates a leaf that is now valid.
/// The engine answers that from the LIVE stage-1 leaf for the exact access
/// the syndrome decoded; a fault whose access class the caller could not
/// decode is delivered as before.
pub(super) fn resolve_mutating_fault<E: ThreadedEngine>(
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    engine: &mut E,
    address: u64,
    access: Option<carrick_mmu_core::aarch64::LeafAccess>,
    tid: carrick_kernel::kernel::LinuxTid,
    mutation: &mut carrick_kernel::dispatch::mm_mutation::MmMutationGuard<'_>,
) -> Result<bool, TrapError> {
    use carrick_observability::probes::HvpatchFirstTouchDeliverReason as DeliverReason;
    let notify_first_touch_deliver = |reason: DeliverReason| {
        crate::probes::hvpatch_first_touch_deliver(address, reason, tid.raw());
        if let Ok(context) = dispatcher.capture_kernel_context(tid) {
            context.kernel().auditors().first_touch_delivered(
                context.task().key(),
                address,
                reason,
            );
        }
    };
    use carrick_kernel::event_ring::{
        self as ring, FirstTouchGrowdown, FirstTouchResident, FirstTouchStale,
        FrameGrantClaimOutcome, FrameGrantDecision,
    };
    let ring_tid = tid.raw();
    let mm_key = mutation.host_alias_permit().mm().raw();
    reconcile_guest_frame_commits(dispatcher, engine, mutation);
    settle_guest_frame_grants(dispatcher, engine, mutation)?;
    if guest_descriptor_edit_in_flight(
        carrick_el1_abi::descriptor_txn_slots_host(),
        mm_key,
        address,
    ) {
        cancel_frame_grant_request(engine.mailbox_slot(), mm_key, address, access);
        return Ok(true);
    }
    if !el1_frame_grants_enabled() {
        cancel_frame_grant_request(engine.mailbox_slot(), mm_key, address, access);
    }
    if el1_frame_grants_enabled()
        && let Some(mailbox) = engine
            .mailbox_slot()
            .and_then(carrick_el1_abi::frame_grant_mailbox_host_for_slot)
    {
        let claim = claim_frame_grant_request(mailbox, mm_key, address, access);
        let (outcome, generation) = match claim {
            FrameGrantClaim::None => (FrameGrantClaimOutcome::None, 0),
            FrameGrantClaim::ResponsePending => (FrameGrantClaimOutcome::ResponsePending, 0),
            FrameGrantClaim::Accepted(request) => {
                (FrameGrantClaimOutcome::Accepted, request.request_generation)
            }
        };
        ring::rec_el1_frame_grant_claim(
            ring_tid,
            mm_key,
            address,
            ring_access(access),
            outcome,
            generation,
        );
        match claim {
            FrameGrantClaim::None => {}
            FrameGrantClaim::ResponsePending => return Ok(true),
            FrameGrantClaim::Accepted(request) => {
                let permit = mutation.host_alias_permit();
                let Some(plan) =
                    dispatcher.resident_frame_grant_plan(&permit, address, request.requested_len)
                else {
                    ring::rec_el1_frame_grant_decision(
                        ring_tid,
                        request.request_generation,
                        FrameGrantDecision::NoPlan,
                        0,
                        request.requested_len,
                        None,
                        None,
                    );
                    publish_frame_grant_refusal(
                        mailbox,
                        request,
                        carrick_el1_abi::FRAME_GRANT_ERR_DENIED,
                    );
                    return Ok(true);
                };
                let prot = plan.prot();
                crate::probes::hvpatch_el1_frame_grant_plan(
                    request.fault_va,
                    plan.start(),
                    plan.len(),
                    prot,
                    request.request_generation,
                );
                ring::rec_el1_frame_grant_decision(
                    ring_tid,
                    request.request_generation,
                    FrameGrantDecision::PlanFound,
                    prot,
                    plan.len(),
                    Some(plan.start()),
                    None,
                );
                if apply_first_touch(prot, access, || true, || {}) != Some(true) {
                    ring::rec_el1_frame_grant_decision(
                        ring_tid,
                        request.request_generation,
                        FrameGrantDecision::FirstTouchDenied,
                        prot,
                        plan.len(),
                        None,
                        None,
                    );
                    publish_frame_grant_refusal(
                        mailbox,
                        request,
                        carrick_el1_abi::FRAME_GRANT_ERR_DENIED,
                    );
                    return Ok(true);
                }
                let service = carrick_hal::El1FrameGrantRequest {
                    mm_key: request.mm_key,
                    request_generation: request.request_generation,
                    fault_va: request.fault_va,
                    access: request.access,
                    semantic_base: plan.start(),
                    len: plan.len(),
                    permissions: prot,
                };
                let Some(ready) = engine.prepare_el1_frame_grant(service)? else {
                    ring::rec_el1_frame_grant_decision(
                        ring_tid,
                        request.request_generation,
                        FrameGrantDecision::PrepareRefused,
                        prot,
                        service.len,
                        None,
                        None,
                    );
                    publish_frame_grant_refusal(
                        mailbox,
                        request,
                        carrick_el1_abi::FRAME_GRANT_ERR_DENIED,
                    );
                    return Ok(true);
                };
                let fault_page = plan.fault_page();
                let plan_shape = (plan.start(), plan.len(), plan.prot());
                let deferred_to_guest = std::cell::Cell::new(false);
                let residency_identity = carrick_el1_abi::FrameGrantResidencyIdentity {
                    mm_key: request.mm_key,
                    semantic_base: service.semantic_base,
                    physical_ipa: ready.physical_ipa,
                    len: service.len,
                    mapping_id: ready.mapping_id,
                    frame_id: ready.frame_id,
                    owner_generation: ready.owner_generation,
                    inventory_revision: ready.inventory_revision,
                };
                let completed = mailbox.complete_grant(
                    carrick_el1_abi::FrameGrantReady {
                        mm_key: request.mm_key,
                        request_generation: request.request_generation,
                        semantic_base: service.semantic_base,
                        physical_ipa: ready.physical_ipa,
                        len: service.len,
                        permissions: service.permissions,
                        frame_id: ready.frame_id,
                        mapping_id: ready.mapping_id,
                        owner_generation: ready.owner_generation,
                        inventory_revision: ready.inventory_revision,
                    },
                    |grant| {
                        use carrick_hal::threaded::{
                            El1FrameGrantPublication, El1FrameGrantPublished,
                        };
                        match engine.publish_el1_frame_grant(El1FrameGrantPublication {
                            mm_key: grant.mm_key,
                            semantic_base: grant.semantic_base,
                            len: grant.len,
                            fault_va: fault_page,
                            permissions: grant.permissions,
                            ready,
                        })? {
                            El1FrameGrantPublished::OnHost => Ok::<bool, TrapError>(true),
                            El1FrameGrantPublished::Unsupported
                            | El1FrameGrantPublished::Refused(_) => Ok(false),
                            // Guest-owned lane: EL1 publishes. The mailbox
                            // slot is released now; residency is committed
                            // only when the verified receipt settles, and a
                            // fault in the span retries until then.
                            El1FrameGrantPublished::Submit(txn) => {
                                let pending = PendingGuestGrant {
                                    txn,
                                    fault_va: address,
                                    requested_len: request.requested_len,
                                    plan: plan_shape,
                                    residency: residency_identity,
                                };
                                let submitted = match (
                                    carrick_el1_abi::descriptor_txn_slots_host(),
                                    engine.mailbox_slot(),
                                ) {
                                    (Some(slots), Some(slot)) => {
                                        GUEST_GRANT_LEDGER.submit(slots, slot, pending)
                                    }
                                    _ => false,
                                };
                                if submitted {
                                    deferred_to_guest.set(true);
                                    Ok(true)
                                } else {
                                    engine.abandon_el1_descriptor_txn(&txn)?;
                                    Ok(false)
                                }
                            }
                        }
                    },
                    || {
                        if deferred_to_guest.get() {
                            // Committed by `settle_guest_frame_grants`.
                            return;
                        }
                        dispatcher.commit_resident_frame_grant(plan);
                        // A full journal is safe: prepared leaves still use
                        // the existing host first-touch path. Publish only
                        // after stage-1, stage-2 and inventory are live.
                        if let Some(table) = carrick_el1_abi::frame_grant_residency_host() {
                            let _ = table.publish(residency_identity);
                        }
                    },
                )?;
                if !completed {
                    // Nothing exposed the prepared backing: undo exactly what
                    // `prepare_el1_frame_grant` published before refusing.
                    EngineGrantBackend(&mut *engine).roll_back(
                        carrick_hal::threaded::El1FrameGrantRollback {
                            mm_key: service.mm_key,
                            semantic_base: service.semantic_base,
                            len: service.len,
                            ready,
                        },
                    )?;
                    publish_frame_grant_refusal(
                        mailbox,
                        request,
                        carrick_el1_abi::FRAME_GRANT_ERR_DENIED,
                    );
                } else {
                    ring::rec_el1_frame_grant_decision(
                        ring_tid,
                        request.request_generation,
                        FrameGrantDecision::Ready,
                        service.permissions,
                        service.len,
                        Some(service.semantic_base),
                        Some(ready.physical_ipa),
                    );
                }
                return Ok(true);
            }
        }
    }
    let mut first_touch = ring::FirstTouchRecord {
        tid: ring_tid,
        mm_key,
        fault_va: address,
        access: ring_access(access),
        resident: FirstTouchResident::NotReached,
        growdown: FirstTouchGrowdown::NotReached,
        stale: FirstTouchStale::NotReached,
    };
    {
        let permit = mutation.host_alias_permit();
        let plan = dispatcher.resident_fault_plan(&permit, address);
        if let Some(plan) = plan {
            let page = plan.page();
            let prot = plan.prot();
            let access_code = access.map_or(3, |a| a as u32);
            match apply_first_touch(
                prot,
                access,
                || match engine.protect_range(
                    page,
                    crate::linux_abi::LINUX_PAGE_SIZE as usize,
                    prot,
                ) {
                    Ok(()) => true,
                    Err(error) => {
                        crate::probes::resident_fault_protection_error(page, prot, &error);
                        crate::probes::hvpatch_first_touch_refused(page, access_code, 1, &error);
                        false
                    }
                },
                || dispatcher.commit_resident_fault(plan),
            ) {
                Some(true) => {
                    first_touch.resident = FirstTouchResident::Committed;
                    ring::rec_first_touch(&first_touch);
                    return Ok(true);
                }
                Some(false) => {
                    notify_first_touch_deliver(DeliverReason::ArmingDenies);
                    first_touch.resident = FirstTouchResident::ArmingDenied;
                    ring::rec_first_touch(&first_touch);
                    return Ok(false);
                }
                None => {
                    notify_first_touch_deliver(DeliverReason::BackendRefused);
                    first_touch.resident = FirstTouchResident::BackendRefused;
                }
            }
        } else {
            notify_first_touch_deliver(DeliverReason::NoPendingEdit);
            first_touch.resident = FirstTouchResident::NoPlan;
        }
    }
    {
        let permit = mutation.host_alias_permit();
        first_touch.growdown = match dispatcher.mmap_growdown_fault_plan(&permit, address) {
            None => FirstTouchGrowdown::NoPlan,
            Some(plan) => {
                match engine.protect_range(
                    plan.start(),
                    plan.len(),
                    crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                ) {
                    Ok(()) => {
                        dispatcher.commit_mmap_growdown(plan);
                        first_touch.growdown = FirstTouchGrowdown::Committed;
                        ring::rec_first_touch(&first_touch);
                        return Ok(true);
                    }
                    Err(error) => {
                        let access_code = access.map_or(3, |a| a as u32);
                        crate::probes::hvpatch_first_touch_refused(
                            plan.start(),
                            access_code,
                            2,
                            &error,
                        );
                    }
                }
                FirstTouchGrowdown::ProtectFailed
            }
        };
    }
    let Some(access) = access else {
        first_touch.stale = FirstTouchStale::AccessUnknown;
        ring::rec_first_touch(&first_touch);
        return Ok(false);
    };
    let retried = engine.resolve_stale_stage1_fault(address, access)?;
    if retried {
        crate::probes::hvpatch_stale_stage1_retry(address, access as u32, tid.raw());
        first_touch.stale = FirstTouchStale::Retried;
    } else {
        notify_first_touch_deliver(DeliverReason::StaleLeafNotRetried);
        first_touch.stale = FirstTouchStale::NotRetried;
    }
    ring::rec_first_touch(&first_touch);
    Ok(retried)
}

/// Adopt only guest-marked pages whose current hardware-visible leaf still
/// validates the exact IPA. The caller's MM guard excludes EL1 editors, so
/// host and guest cannot commit the same page concurrently.
pub(super) fn reconcile_guest_frame_commits<E: ThreadedEngine>(
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    engine: &E,
    mutation: &carrick_kernel::dispatch::mm_mutation::MmMutationGuard<'_>,
) {
    let Some(table) = carrick_el1_abi::frame_grant_residency_host() else {
        return;
    };
    table.for_each_dirty_mm(mutation.mm_id().raw(), |slot, identity, bits| {
        for (word_index, mut word) in bits.into_iter().enumerate() {
            while word != 0 {
                let bit = word.trailing_zeros() as u64;
                word &= word - 1;
                let page = identity.semantic_base + (word_index as u64 * 64 + bit) * 4096;
                if page >= identity.semantic_base + identity.len {
                    continue;
                }
                let expected_ipa = identity.physical_ipa + page - identity.semantic_base;
                if engine.live_el1_grant_page(page, expected_ipa) {
                    let _ = dispatcher.reconcile_el1_resident_page(mutation, page);
                }
            }
        }
        let _ = table.ack_dirty(slot, identity);
    });
}

/// `CARRICK_ABORT_ON_GUEST_FAULT_SIGNAL=1`: turn the first synchronous
/// SIGSEGV/SIGBUS the host is about to deliver to an EL0 guest thread into a
/// `carrick_fatal!`, so a core or `carrick debug lldb-run` captures the event
/// ring, `CARRICK_LAST_FATAL` and every stack at that instant. Read once per
/// carrier; any other value (or unset) leaves delivery unchanged.
fn abort_on_guest_fault_signal_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_ABORT_ON_GUEST_FAULT_SIGNAL").is_ok_and(|value| value.trim() == "1")
    })
}

/// Whether `signum` is a synchronous memory-fault signal the abort hatch
/// converts (SIGSEGV or SIGBUS; never the debug-class SIGTRAP).
fn is_memory_fault_signal(signum: i32) -> bool {
    signum == crate::linux_abi::LINUX_SIGSEGV || signum == crate::linux_abi::LINUX_SIGBUS
}

/// Abort instead of delivering a memory-fault signal when the
/// `CARRICK_ABORT_ON_GUEST_FAULT_SIGNAL` hatch is armed. The caller records
/// the ring first, so the core holds the decision that led here.
pub(super) fn abort_on_guest_fault_signal_if_armed(
    record: &carrick_kernel::event_ring::FaultSignalRecord,
) {
    if !is_memory_fault_signal(record.signum) || !abort_on_guest_fault_signal_enabled() {
        return;
    }
    carrick_fatal::carrick_fatal!(
        "hvpatch::guest_fault_signal",
        "CARRICK_ABORT_ON_GUEST_FAULT_SIGNAL: tid={} mm={:?} signal={} si_code={} addr={:#x} pc={:#x} esr={:#x} mutating={} access={:?} walk={:?}",
        record.tid,
        record.mm_key,
        record.signum,
        record.si_code,
        record.fault_address,
        record.pc,
        record.esr,
        record.requires_mm_mutation,
        record.access,
        record.walk
    );
}

/// Summarize the live stage-1 walk of `far` for the event ring.
pub(super) fn ring_stage1_walk<E: ThreadedEngine>(
    engine: &E,
    far: u64,
    access: Option<carrick_mmu_core::aarch64::LeafAccess>,
) -> Option<carrick_kernel::event_ring::RingStage1Walk> {
    let (_ttbr, walk) = engine.diagnostic_fault_page_tables(far)?;
    let (level, descriptor) = carrick_mmu_core::aarch64::terminal_entry(walk);
    Some(carrick_kernel::event_ring::RingStage1Walk {
        terminal_level: level as u8,
        terminal_descriptor: descriptor,
        terminal_valid: carrick_mmu_core::aarch64::descriptor_is_valid(descriptor),
        permits_access: access.is_some_and(|access| {
            carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(descriptor, access)
        }),
    })
}

/// Every non-idle frame-grant mailbox as `(slot, state)`, read without locks
/// or allocation (each state is one relaxed atomic load).
pub(super) fn busy_frame_grant_mailboxes() -> impl Iterator<Item = (usize, u32)> {
    (0..carrick_el1_abi::EL1_STACK_SLOTS as usize).filter_map(|slot| {
        let mailbox = carrick_el1_abi::frame_grant_mailbox_host_for_slot(slot)?;
        let state = mailbox.state.load(std::sync::atomic::Ordering::Relaxed);
        (state != carrick_el1_abi::FRAME_GRANT_MAILBOX_IDLE).then_some((slot, state))
    })
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn complete_signal_thread(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        target: ThreadId,
        signum: i32,
        kernel_target: Option<carrick_kernel::kernel::ThreadKey>,
    ) -> Result<i64, RuntimeError> {
        let retval: i64 = if let Some(exact) = kernel_target {
            if exact.tid.raw() != target.raw() {
                return Err(RuntimeError::Configuration(
                    "Kernel-native thread signal target identity mismatch".to_owned(),
                ));
            }
            let context = self.service_kernel_context.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "Kernel-native thread signal lost caller context".to_owned(),
                )
            })?;
            let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "Kernel-native thread signal has no runtime directory".to_owned(),
                )
            })?;
            let (scheduler, service) = directory.continuation_services(context.kernel());
            let _ = service.publish_signal_for_thread(exact);
            let _ = scheduler.wake(exact);
            0
        } else if self.registry.is_live(target) {
            kernel
                .dispatcher
                .host_signal
                .publish_pending_for(target.raw(), signum);
            self.kicker.kick(target);
            0
        } else {
            crate::linux_abi::LINUX_ESRCH.guest_retval()
        };
        self.complete_returned(engine, &kernel.reporter, retval)
    }
}

thread_local! {
    // Per-vCPU-thread count of signal HANDLERS delivered to the guest. The vCPU
    // loop's trap watchdog measures traps since this last advanced (not lifetime
    // total): a guest legitimately busy-waiting for a signal makes millions of
    // syscalls but is responsive, so each delivered handler resets the budget. A
    // genuinely stuck guest delivers no handlers and still trips the watchdog.
    static SIGNAL_PROGRESS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Note that a signal handler was delivered to the guest on this vCPU thread —
/// progress that resets the trap watchdog (see the vCPU loop).
pub(crate) fn note_signal_progress() {
    SIGNAL_PROGRESS.with(|c| c.set(c.get().wrapping_add(1)));
}

/// This vCPU thread's running count of delivered signal handlers.
pub(crate) fn signal_progress_count() -> u64 {
    SIGNAL_PROGRESS.with(std::cell::Cell::get)
}

/// Reset the executor-local watchdog baseline while returning the exact prior
/// task's progress receipt. A successor must always begin from zero.
pub(crate) fn reset_signal_progress_for_executor_boundary() -> u64 {
    SIGNAL_PROGRESS.with(|progress| progress.replace(0))
}

pub(crate) fn signal_progress_is_zero_for_executor_boundary() -> bool {
    SIGNAL_PROGRESS.with(|progress| progress.get() == 0)
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SignalRestartContext {
    pub last_syscall_retval: Option<i64>,
    pub interrupted_pc: Option<u64>,
    pub continuation_restart: Option<bool>,
}

pub(crate) fn deliver_pending_signal<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    deliver_pending_signal_with_restart(
        trap,
        dispatcher,
        context,
        SignalRestartContext {
            last_syscall_retval,
            interrupted_pc,
            continuation_restart: None,
        },
        tid,
    )
}

pub(crate) fn deliver_pending_signal_with_restart<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    restart: SignalRestartContext,
    tid: ThreadId,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    deliver_signal_with_restart(trap, dispatcher, context, restart, tid, None)
}

pub(crate) fn deliver_reserved_signal_with_restart<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    restart: SignalRestartContext,
    tid: ThreadId,
    reserved: carrick_kernel::kernel::continuation::ReservedSignal,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    if !reserved.consume() {
        return Err(RuntimeError::Configuration(
            "reserved signal was already consumed".to_owned(),
        ));
    }
    let caught = {
        let action = reserved.action();
        action.sa_handler != carrick_abi::LINUX_SIG_DFL
            && action.sa_handler != carrick_abi::LINUX_SIG_IGN
    };
    let result =
        deliver_signal_with_restart(trap, dispatcher, context, restart, tid, Some(&reserved));
    if !caught {
        reserved.restore_persistent_after_default_action();
    }
    result
}

fn deliver_signal_with_restart<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    restart: SignalRestartContext,
    tid: ThreadId,
    reserved: Option<&carrick_kernel::kernel::continuation::ReservedSignal>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    let SignalRestartContext {
        last_syscall_retval,
        interrupted_pc,
        continuation_restart,
    } = restart;
    // Drain the cross-process explicit-signal ring into pending state, so the
    // normal delivery below runs each with the sender's identity.
    if reserved.is_none() {
        dispatcher.drain_xsignals_process_directed(context);
    }

    let pending = reserved.map_or_else(
        || dispatcher.host_signal.take_pending_for(tid.raw()),
        carrick_kernel::kernel::continuation::ReservedSignal::signum,
    );
    // A dispatcher dequeue returns owner and payload atomically. A host-slot
    // signal remains thread-directed and consumes its per-thread payload below.
    let (pending, dequeued_siginfo, from_dispatcher, job_control_generation) =
        if let Some(reserved) = reserved {
            (
                pending,
                reserved.siginfo(),
                true,
                reserved.job_control_generation(),
            )
        } else if pending == 0 {
            match dispatcher.take_deliverable_pending_from(context, tid) {
                Some(pending) => (
                    pending.signum,
                    pending.siginfo,
                    true,
                    pending.job_control_generation,
                ),
                None => return Ok(None),
            }
        } else {
            (pending, None, false, None)
        };
    crate::probes::signal_deliver(tid.raw(), pending);
    // A blocked signal must not be delivered — hold it pending until the guest
    // unblocks it.
    if reserved.is_none() && dispatcher.signal_blocked(context, tid, pending) {
        dispatcher.mark_signal_pending(context, tid, pending);
        return Ok(Some(PendingSignalAction::ignored()));
    }
    if carrick_kernel::exec_helpers::stop_for_ptrace_signal(dispatcher, pending) {
        return Ok(Some(PendingSignalAction::ignored()));
    }
    carrick_kernel::exec_helpers::stop_for_debug_signal(pending);
    let raw_action = if let Some(reserved) = reserved {
        reserved.action()
    } else if let Some(action) = dispatcher.take_pending_signal_action(context, tid, pending) {
        action
    } else {
        dispatcher.signal_action(context, pending)
    };
    let delivery_action =
        carrick_kernel::kernel::evaluate_signal_delivery_action(pending, raw_action);
    match delivery_action {
        carrick_kernel::kernel::SignalDeliveryAction::Ignore => {
            Ok(Some(PendingSignalAction::ignored()))
        }
        carrick_kernel::kernel::SignalDeliveryAction::Stop => Ok(Some(PendingSignalAction::stop(
            pending,
            job_control_generation,
        ))),
        carrick_kernel::kernel::SignalDeliveryAction::Terminate => {
            Ok(Some(PendingSignalAction::terminate(pending)))
        }
        carrick_kernel::kernel::SignalDeliveryAction::Handler { .. } => {
            let action = raw_action;
            // A handler is about to run in the guest: real progress, resets the
            // trap watchdog (a busy-wait-for-signal loop is not a hang).
            note_signal_progress();
            // Block the signal (+ its sa_mask) for the duration of the handler, as
            // the kernel does — restored by rt_sigreturn.
            let sa_flags = carrick_abi::LinuxSaFlags::from_bits_truncate(action.sa_flags);
            let restorer = if sa_flags.contains(carrick_abi::LinuxSaFlags::RESTORER) {
                action.sa_restorer
            } else {
                0
            };
            // SA_ONSTACK: run the handler on the alternate signal stack if one is
            // installed.
            let altstack = if sa_flags.contains(carrick_abi::LinuxSaFlags::ONSTACK) {
                dispatcher.signal_altstack(context, tid)
            } else {
                None
            };
            // SA_RESTART: if this handler interrupted a blocking, restartable
            // syscall that returned EINTR, restart it instead of surfacing the
            // EINTR.
            let at_syscall_boundary = interrupted_pc.is_none();
            let retval_is_eintr =
                last_syscall_retval == Some(crate::linux_abi::LINUX_EINTR.guest_retval());
            let handler_wants_restart = sa_flags.contains(carrick_abi::LinuxSaFlags::RESTART);
            let syscall_restartable = trap.last_syscall_nr().is_some_and(is_restartable_syscall);
            let restart_syscall = continuation_restart.unwrap_or({
                at_syscall_boundary
                    && retval_is_eintr
                    && handler_wants_restart
                    && syscall_restartable
            });
            // Publish WHICH predicate decided. All four live in one boolean, so
            // from outside "the guest saw EINTR under SA_RESTART" is otherwise a
            // dead end — you cannot tell a missing syscall from the restartable
            // set apart from a retval that was never EINTR in the first place.
            let restart_predicates = i32::from(at_syscall_boundary)
                | (i32::from(retval_is_eintr) << 1)
                | (i32::from(handler_wants_restart) << 2)
                | (i32::from(syscall_restartable) << 3);
            let syscall_nr = trap.last_syscall_nr().map_or(-1, |nr| nr as i64);
            let syscall_retval = last_syscall_retval.unwrap_or(0);
            crate::probes::signal_restart_decision(
                tid.raw(),
                pending,
                syscall_nr,
                syscall_retval,
                restart_predicates,
            );
            carrick_kernel::event_ring::rec_signal_restart_decision(
                tid.raw(),
                pending,
                syscall_nr,
                syscall_retval,
                restart_predicates,
                interrupted_pc,
            );
            // Wire form for the sigframe build (see the synchronous-fault arm).
            let saved_sigmask = dispatcher
                .enter_signal_handler(context, tid, pending, action)
                .raw();
            // If rt_sigqueueinfo queued a caller-supplied siginfo for this (tid,
            // signum), hand it to inject_signal. Dispatcher-owned pending
            // dequeues already carried the exact payload; host-slot delivery
            // consumes only the matching per-thread queue.
            let queued_siginfo = if reserved.is_some() {
                dequeued_siginfo
            } else {
                let queued_siginfo = dequeued_siginfo
                    .or_else(|| {
                        (!from_dispatcher)
                            .then(|| dispatcher.take_pending_siginfo(context, tid, pending))
                            .flatten()
                    })
                    .or_else(|| {
                        carrick_signal_linux::child_watch::take_siginfo(tid.raw(), pending).map(
                            |info| {
                                const CLD_EXITED: i32 = 1;
                                let ns_pid = carrick_kernel::namespace::pid::host_to_ns_or_self_for(
                                    context,
                                    info.host_pid as u32,
                                ) as i32;
                                let linux_status = if info.si_code == CLD_EXITED {
                                    info.host_status
                                } else {
                                    dispatcher
                                        .host_signal
                                        .host_to_linux_signum(info.host_status)
                                };
                                crate::linux_abi::LinuxSiginfo::child_exit(
                                    pending,
                                    ns_pid,
                                    info.host_uid,
                                    info.si_code,
                                    linux_status,
                                )
                            },
                        )
                    });
                #[cfg(test)]
                let queued_siginfo = queued_siginfo.or_else(|| {
                    let sender_host = dispatcher.host_signal.last_sender_for(pending);
                    (sender_host > 0).then(|| {
                        let ns_pid = carrick_kernel::namespace::pid::host_to_ns_or_self_for(
                            context,
                            sender_host as u32,
                        ) as i32;
                        let uid = carrick_kernel::cred_ipc::read_target(sender_host)
                            .unwrap_or(carrick_abi::NsUid::ROOT);
                        crate::linux_abi::LinuxSiginfo::kill(
                            pending,
                            crate::linux_abi::LINUX_SI_USER,
                            ns_pid,
                            uid.raw(),
                        )
                    })
                });
                queued_siginfo
            };
            match trap.inject_signal(carrick_hal::SignalInjection {
                signum: pending,
                handler: action.sa_handler,
                sa_restorer: restorer,
                pending_syscall_retval: last_syscall_retval,
                interrupted_pc,
                altstack,
                saved_sigmask,
                fault_siginfo: None, // SI_USER-shaped (tkill/sysmon); faults use deliver_fault_signal
                queued_siginfo,
                restart_syscall,
            }) {
                Ok(()) => {
                    carrick_kernel::event_ring::rec_signal_inject(
                        tid.raw(),
                        pending,
                        restart_syscall,
                    );
                    Ok(Some(PendingSignalAction::ignored()))
                }
                // Linux force_sigsegv: the signal frame couldn't be written to the
                // user stack. Terminate the whole thread-group by SIGSEGV (exit
                // 139).
                Err(TrapError::SignalDeliveryFault) => {
                    Ok(Some(PendingSignalAction::terminate(11))) // SIGSEGV
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    static PTRACE_SIGNAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Default)]
    struct NoopTrap {
        restart: bool,
        delivered_signum: i32,
        delivered_handler: u64,
        delivered_interrupted_pc: Option<u64>,
        delivered_fault_siginfo: Option<(i32, u64)>,
    }

    impl crate::trap::SyscallTrap for NoopTrap {
        fn next_syscall(&mut self) -> Result<Option<crate::trap::RawSyscall>, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn current_pc(&self) -> Result<u64, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn complete_syscall(&mut self, _return_value: i64) -> Result<(), TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn execve_into(
            &mut self,
            _new_image: &crate::memory::AddressSpace,
        ) -> Result<(), TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn inject_signal(&mut self, signal: carrick_hal::SignalInjection) -> Result<(), TrapError> {
            self.restart = signal.restart_syscall;
            self.delivered_signum = signal.signum;
            self.delivered_handler = signal.handler;
            self.delivered_interrupted_pc = signal.interrupted_pc;
            self.delivered_fault_siginfo = signal.fault_siginfo;
            Ok(())
        }

        fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }
    }

    #[test]
    fn reserved_delivery_cannot_borrow_later_signal_action_or_restart_class() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let authority = context.signal_authority();
        let first = carrick_kernel::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let second = carrick_kernel::kernel::LinuxSignal::for_signal_number(12).expect("SIGUSR2");
        let mut restart = carrick_abi::LinuxSigaction::empty();
        restart.sa_handler = 0x1110;
        restart.sa_flags = carrick_abi::LINUX_SA_RESTART;
        let mut no_restart = carrick_abi::LinuxSigaction::empty();
        no_restart.sa_handler = 0x2220;
        authority.install_action(first, restart);
        authority.install_action(second, no_restart);
        authority.enqueue_thread_standard(first, None);
        let dequeued = authority
            .take_lowest_in(carrick_abi::SigSet::EMPTY.with(10))
            .expect("first reservation");
        let (action_generation, action) = authority.action_with_generation(first);
        let reserved = carrick_kernel::kernel::continuation::ReservedSignal::kernel(
            authority.clone(),
            dequeued,
            action_generation,
            action,
            carrick_abi::SigSet::EMPTY,
        );
        authority.enqueue_thread_standard(second, None);

        let mut trap = NoopTrap::default();
        deliver_reserved_signal_with_restart(
            &mut trap,
            &dispatcher,
            &context,
            SignalRestartContext {
                last_syscall_retval: Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
                interrupted_pc: None,
                continuation_restart: Some(true),
            },
            ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            reserved,
        )
        .expect("reserved delivery")
        .expect("handler action");
        assert_eq!(trap.delivered_signum, 10);
        let restart_handler = restart.sa_handler;
        assert_eq!(trap.delivered_handler, restart_handler);
        assert!(trap.restart);
        assert_eq!(
            authority
                .take_lowest_in(carrick_abi::SigSet::EMPTY.with(12))
                .expect("second remains pending")
                .pending
                .signal
                .raw(),
            12
        );
    }

    #[test]
    fn reserved_ppoll_pselect_default_terminate_and_stop_ignore_restored_persistent_block() {
        for (pid, signum, expect_terminate) in [(15_466, 10, true), (15_467, 20, false)] {
            let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
                pid,
                ThreadId::synthetic_for_tests(pid),
                "reserved default action".to_owned(),
            )
            .expect("bootstrap input");
            let (_kernel, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("reserved default kernel");
            let dispatcher = SyscallDispatcher::new();
            let authority = context.signal_authority();
            let signal =
                carrick_kernel::kernel::LinuxSignal::for_signal_number(signum).expect("signal");
            let persistent = carrick_abi::SigSet::EMPTY.with(signum);
            authority.set_blocked(carrick_abi::SigSet::EMPTY);
            authority.enqueue_thread_standard(signal, None);
            let dequeued = authority
                .take_lowest_in(carrick_abi::SigSet::EMPTY.with(signum))
                .expect("temporary mask reserves default signal");
            let (action_generation, action) = authority.action_with_generation(signal);
            let reserved = carrick_kernel::kernel::continuation::ReservedSignal::kernel(
                authority.clone(),
                dequeued,
                action_generation,
                action,
                persistent,
            );
            authority.set_blocked(persistent);

            let action = deliver_reserved_signal_with_restart(
                &mut NoopTrap::default(),
                &dispatcher,
                &context,
                SignalRestartContext {
                    last_syscall_retval: Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
                    interrupted_pc: None,
                    continuation_restart: Some(false),
                },
                ThreadId::synthetic_for_tests(pid),
                reserved,
            )
            .expect("reserved default delivery")
            .expect("default action");
            if expect_terminate {
                assert_eq!(action.term_signal, Some(signum));
                assert_eq!(action.stop_signal, None);
            } else {
                assert_eq!(action.term_signal, None);
                assert_eq!(action.stop_signal, Some(signum));
            }
            assert_eq!(authority.blocked(), persistent);
        }
    }

    #[test]
    fn reserved_default_action_wins_over_concurrent_sigaction_change() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let authority = context.signal_authority();
        let signum = 10;
        let signal =
            carrick_kernel::kernel::LinuxSignal::for_signal_number(signum).expect("SIGUSR1");
        authority.enqueue_thread_standard(signal, None);
        let dequeued = authority
            .take_lowest_in(carrick_abi::SigSet::EMPTY.with(signum))
            .expect("reserve default SIGUSR1");
        let (action_generation, action) = authority.action_with_generation(signal);
        let reserved = carrick_kernel::kernel::continuation::ReservedSignal::kernel(
            authority.clone(),
            dequeued,
            action_generation,
            action,
            carrick_abi::SigSet::EMPTY,
        );
        let mut ignored = carrick_abi::LinuxSigaction::empty();
        ignored.sa_handler = carrick_abi::LINUX_SIG_IGN;
        authority.install_action(signal, ignored);

        let action = deliver_reserved_signal_with_restart(
            &mut NoopTrap::default(),
            &dispatcher,
            &context,
            SignalRestartContext {
                last_syscall_retval: Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
                interrupted_pc: None,
                continuation_restart: Some(false),
            },
            ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            reserved,
        )
        .expect("reserved default delivery")
        .expect("captured default action");
        assert_eq!(action.term_signal, Some(signum));
    }

    #[test]
    fn ptrace_signal_stop_queued_host_sigkill_remains_terminal() {
        let _guard = PTRACE_SIGNAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::guest_cpu::init_child_table();
        let parent = std::process::id();
        let prepared = crate::guest_cpu::prepare_child_record_pre_fork(parent, 0, 0, false, 0)
            .expect("prepare host queued-sigkill child");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            crate::guest_cpu::complete_child_record_post_fork_child();
            // A real host child that takes a real host signal: the bridge must
            // translate Linux signums to Darwin's (SIGSTOP is 19 on Linux but
            // 17 on macOS), so this is the platform bridge, not the Null one.
            let dispatcher = SyscallDispatcher::with_bridges(crate::platform_bridges());
            dispatcher.set_ptrace_traceme_for_test();
            let tid = ThreadId::main_from_host_pid();
            dispatcher.mark_signal_pending(
                &dispatcher.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGKILL,
            );
            let mut trap = NoopTrap::default();
            let _ = deliver_pending_signal(
                &mut trap,
                &dispatcher,
                &dispatcher.exact_signal_context_for_test(),
                None,
                tid,
                None,
            );
            unsafe { libc::_exit(70) };
        }

        crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFSIGNALED(exit_status));
        assert_eq!(libc::WTERMSIG(exit_status), libc::SIGKILL);
        let _ = crate::guest_cpu::reap_child_guest_ns(child as u32);
    }

    #[test]
    fn synchronous_fault_stops_for_ptrace_before_default_termination() {
        let _guard = PTRACE_SIGNAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::guest_cpu::init_child_table();
        let parent = std::process::id();
        let prepared = crate::guest_cpu::prepare_child_record_pre_fork(parent, 0, 0, false, 0)
            .expect("prepare synchronous-fault tracee");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            crate::guest_cpu::complete_child_record_post_fork_child();
            // A real host child that takes a real host signal: the bridge must
            // translate Linux signums to Darwin's (SIGSTOP is 19 on Linux but
            // 17 on macOS), so this is the platform bridge, not the Null one.
            let dispatcher = SyscallDispatcher::with_bridges(crate::platform_bridges());
            dispatcher.set_ptrace_traceme_for_test();
            let context = dispatcher.exact_signal_context_for_test();
            let tid = ThreadId::main_from_host_pid();
            let disposition = inject_fault_signal(
                &mut NoopTrap::default(),
                &dispatcher,
                &context,
                tid,
                &mut FaultSignal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    si_code: 2,
                    si_addr: 0xfeed_0000,
                    interrupted_pc: Some(0x4000),
                },
            );
            let stopped_before_delivery =
                matches!(disposition, Ok(FaultSignalDisposition::Stopped));
            unsafe { libc::_exit(i32::from(!stopped_before_delivery)) };
        }

        crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut stop_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) },
            child
        );
        if !libc::WIFSTOPPED(stop_status) || libc::WSTOPSIG(stop_status) != libc::SIGSTOP {
            if !libc::WIFEXITED(stop_status) && !libc::WIFSIGNALED(stop_status) {
                let _ = unsafe { libc::kill(child, libc::SIGKILL) };
                let _ = unsafe { libc::waitpid(child, &mut stop_status, 0) };
            }
            panic!(
                "synchronous SIGSEGV must become a ptrace delivery stop first; status={stop_status}"
            );
        }
        assert_eq!(unsafe { libc::kill(child, libc::SIGCONT) }, 0);
        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFEXITED(exit_status));
        assert_eq!(libc::WEXITSTATUS(exit_status), 0);
        let _ = crate::guest_cpu::reap_child_guest_ns(child as u32);
    }

    #[test]
    fn synchronous_fault_reinjection_preserves_siginfo_pc_and_forced_rules() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = ThreadId::main_from_host_pid();
        let signal =
            carrick_kernel::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGSEGV)
                .expect("SIGSEGV");
        let mut caught = carrick_abi::LinuxSigaction::empty();
        caught.sa_handler = 0x7000;
        caught.sa_flags = carrick_abi::LINUX_SA_SIGINFO;
        context.signal_authority().install_action(signal, caught);
        let mut trap = NoopTrap::default();
        assert!(matches!(
            inject_fault_signal(
                &mut trap,
                &dispatcher,
                &context,
                tid,
                &mut FaultSignal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    si_code: 2,
                    si_addr: 0xfeed_4000,
                    interrupted_pc: Some(0x4000_1234),
                },
            ),
            Ok(FaultSignalDisposition::Injected)
        ));
        assert_eq!(trap.delivered_signum, crate::linux_abi::LINUX_SIGSEGV);
        assert_eq!(trap.delivered_interrupted_pc, Some(0x4000_1234));
        assert_eq!(trap.delivered_fault_siginfo, Some((2, 0xfeed_4000)));

        context
            .signal_authority()
            .set_blocked(carrick_abi::SigSet::EMPTY.with(crate::linux_abi::LINUX_SIGSEGV));
        assert!(matches!(
            inject_fault_signal(
                &mut NoopTrap::default(),
                &dispatcher,
                &context,
                tid,
                &mut FaultSignal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    si_code: 2,
                    si_addr: 0xfeed_4000,
                    interrupted_pc: Some(0x4000_1234),
                },
            ),
            Ok(FaultSignalDisposition::Terminate(
                crate::linux_abi::LINUX_SIGSEGV
            ))
        ));

        context
            .signal_authority()
            .set_blocked(carrick_abi::SigSet::EMPTY);
        let mut ignored = carrick_abi::LinuxSigaction::empty();
        ignored.sa_handler = carrick_abi::LINUX_SIG_IGN;
        context.signal_authority().install_action(signal, ignored);
        assert!(matches!(
            inject_fault_signal(
                &mut NoopTrap::default(),
                &dispatcher,
                &context,
                tid,
                &mut FaultSignal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    si_code: 2,
                    si_addr: 0xfeed_4000,
                    interrupted_pc: Some(0x4000_1234),
                },
            ),
            Ok(FaultSignalDisposition::Terminate(
                crate::linux_abi::LINUX_SIGSEGV
            ))
        ));
    }

    #[test]
    fn forked_private_file_bus_tail_is_classified_at_synchronous_injection() {
        let parent = SyscallDispatcher::new();
        let base = 0x6000_00c0_0000;
        let page = parent.linux_page_size();
        parent.record_mmap_bus_fault_range_for_test(base + 3 * page, page);
        let child = parent.fork_clone_in_process(
            ThreadId::synthetic_for_tests(781),
            ThreadId::synthetic_for_tests(782),
            781,
            782,
        );
        let fault_addr = base + 3 * page + 8;
        assert!(child.mmap_fault_is_sigbus(fault_addr));
        let context = child.exact_signal_context_for_test();
        let tid = ThreadId::main_from_host_pid();
        assert!(matches!(
            inject_fault_signal(
                &mut NoopTrap::default(),
                &child,
                &context,
                tid,
                &mut FaultSignal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    si_code: 1,
                    si_addr: fault_addr,
                    interrupted_pc: Some(0x2240d8),
                },
            ),
            Ok(FaultSignalDisposition::Terminate(
                crate::linux_abi::LINUX_SIGBUS
            ))
        ));
    }

    #[test]
    fn default_sigcont_resumes_without_terminating() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = ThreadId::main_from_host_pid();
        dispatcher.mark_signal_pending(&context, tid, crate::linux_abi::LINUX_SIGCONT);

        let action = deliver_pending_signal(
            &mut NoopTrap::default(),
            &dispatcher,
            &context,
            None,
            tid,
            None,
        )
        .expect("deliver default SIGCONT")
        .expect("SIGCONT produces an explicit nonterminal action");

        assert_eq!(action.term_signal, None);
        assert_eq!(action.stop_signal, None);
    }

    #[test]
    fn initially_blocked_write_then_reader_close_returns_epipe_and_queues_sigpipe() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = context.thread().registry_id();
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let fill = [0u8; 4096];
        loop {
            let written = unsafe { libc::write(fds[1], fill.as_ptr().cast(), fill.len()) };
            if written < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN)
                );
                break;
            }
        }
        let mut write =
            carrick_kernel::dispatch::BlockingWrite::for_tests(fds[1], vec![0x5a], 0, tid, true)
                .expect("pin blocked pipe writer");
        assert!(matches!(
            carrick_kernel::dispatch::drive_blocking_write(&mut write, &*dispatcher.host_signal),
            carrick_kernel::dispatch::BlockingWriteStep::Wait
        ));
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);
        let carrick_kernel::dispatch::BlockingWriteStep::Done(outcome) =
            carrick_kernel::dispatch::drive_blocking_write(&mut write, &*dispatcher.host_signal)
        else {
            panic!("closed reader must complete the blocked write");
        };
        let outcome = raise_sigpipe_for_blocking_write(&dispatcher, &context, &write, outcome);
        assert_eq!(
            outcome,
            DispatchOutcome::Errno {
                errno: crate::linux_abi::LINUX_EPIPE
            }
        );
        assert!(
            context
                .signal_authority()
                .thread_pending()
                .contains(crate::linux_abi::LINUX_SIGPIPE)
        );
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);
    }

    #[test]
    fn continuation_restart_decision_controls_real_handler_injection() {
        for expected in [false, true] {
            let dispatcher = SyscallDispatcher::new();
            let context = dispatcher.exact_signal_context_for_test();
            let tid = ThreadId::main_from_host_pid();
            let signal = carrick_kernel::kernel::LinuxSignal::for_signal_number(
                crate::linux_abi::LINUX_SIGUSR1,
            )
            .expect("SIGUSR1");
            let mut action = carrick_abi::LinuxSigaction::empty();
            action.sa_handler = 0x1234;
            context.signal_authority().install_action(signal, action);
            dispatcher.mark_signal_pending(&context, tid, crate::linux_abi::LINUX_SIGUSR1);
            let mut trap = NoopTrap::default();
            let delivered = deliver_pending_signal_with_restart(
                &mut trap,
                &dispatcher,
                &context,
                SignalRestartContext {
                    last_syscall_retval: Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
                    interrupted_pc: None,
                    continuation_restart: Some(expected),
                },
                tid,
            )
            .expect("handler injection")
            .expect("pending handler");
            assert_eq!(delivered.term_signal, None);
            assert_eq!(trap.restart, expected);
        }
    }
}

#[cfg(test)]
mod first_touch_access_tests {
    use super::*;
    use carrick_mmu_core::aarch64::LeafAccess;

    #[test]
    fn abort_hatch_converts_only_memory_fault_signals() {
        assert!(is_memory_fault_signal(crate::linux_abi::LINUX_SIGSEGV));
        assert!(is_memory_fault_signal(crate::linux_abi::LINUX_SIGBUS));
        // BRK / single-step deliver SIGTRAP through the same arm; a debugger
        // session must never trip the hatch.
        assert!(!is_memory_fault_signal(5));
        assert!(!is_memory_fault_signal(4));
    }

    #[test]
    fn ring_access_preserves_the_decoded_direction() {
        use carrick_kernel::event_ring::RingAccess;
        assert_eq!(ring_access(None), RingAccess::Unknown);
        assert_eq!(ring_access(Some(LeafAccess::Read)), RingAccess::Read);
        assert_eq!(ring_access(Some(LeafAccess::Write)), RingAccess::Write);
        assert_eq!(ring_access(Some(LeafAccess::Execute)), RingAccess::Execute);
    }

    #[test]
    fn frame_grant_claim_requires_the_exact_mm_fault_and_access() {
        let request = carrick_el1_abi::FrameGrantRequest {
            mm_key: 7,
            request_generation: 11,
            fault_va: 0x4000_3123,
            requested_len: carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE,
            access: crate::linux_abi::LINUX_PROT_WRITE,
        };
        let mailbox = carrick_el1_abi::FrameGrantMailbox::new();
        assert!(mailbox.try_publish_request(request));
        let FrameGrantClaim::Accepted(claimed) = claim_frame_grant_request(
            &mailbox,
            request.mm_key,
            request.fault_va,
            Some(LeafAccess::Write),
        ) else {
            panic!("exact request must be accepted");
        };
        assert_eq!(claimed, request);
        assert!(mailbox.publish_refusal(carrick_el1_abi::FRAME_GRANT_ERR_DENIED));
        assert!(matches!(
            claim_frame_grant_request(
                &mailbox,
                request.mm_key,
                request.fault_va,
                Some(LeafAccess::Write)
            ),
            FrameGrantClaim::ResponsePending
        ));
        let response = mailbox
            .claim_response(request.mm_key, request.request_generation)
            .expect("claimed response");
        assert_eq!(response.status, carrick_el1_abi::FRAME_GRANT_ERR_DENIED);
        assert!(mailbox.finish_response(request.mm_key, request.request_generation));

        for (mm, fault, access) in [
            (
                request.mm_key + 1,
                request.fault_va,
                Some(LeafAccess::Write),
            ),
            (
                request.mm_key,
                request.fault_va + 4096,
                Some(LeafAccess::Write),
            ),
            (request.mm_key, request.fault_va, Some(LeafAccess::Read)),
            (request.mm_key, request.fault_va, None),
        ] {
            assert!(mailbox.try_publish_request(request));
            assert!(matches!(
                claim_frame_grant_request(&mailbox, mm, fault, access),
                FrameGrantClaim::None
            ));
            let FrameGrantClaim::Accepted(claimed) = claim_frame_grant_request(
                &mailbox,
                request.mm_key,
                request.fault_va,
                Some(LeafAccess::Write),
            ) else {
                panic!("an unrelated host fault must leave the request claimable");
            };
            assert_eq!(claimed, request);
            assert!(mailbox.publish_refusal(carrick_el1_abi::FRAME_GRANT_ERR_DENIED));
            let response = mailbox
                .claim_response(request.mm_key, request.request_generation)
                .expect("refusal response");
            assert_eq!(response.status, carrick_el1_abi::FRAME_GRANT_ERR_DENIED);
            assert!(mailbox.finish_response(request.mm_key, request.request_generation));
        }
        assert!(matches!(
            claim_frame_grant_request(
                &mailbox,
                request.mm_key,
                request.fault_va,
                Some(LeafAccess::Write)
            ),
            FrameGrantClaim::None
        ));
    }

    #[test]
    fn denied_first_touch_does_not_edit_or_commit_residency() {
        for (prot, access) in [
            (1, Some(LeafAccess::Write)),
            (3, Some(LeafAccess::Execute)),
            (1, None),
        ] {
            let dispatcher = SyscallDispatcher::new();
            let page = 0x4000_0000;
            dispatcher.seed_resident_fault_for_test(page, prot);
            let edits = std::cell::Cell::new(0);
            dispatcher
                .with_resident_fault_plan_for_test(page, |plan| {
                    assert_eq!(
                        apply_first_touch(
                            plan.prot(),
                            access,
                            || {
                                edits.set(edits.get() + 1);
                                true
                            },
                            || dispatcher.commit_resident_fault(plan)
                        ),
                        Some(false)
                    );
                })
                .expect("pending first touch");
            assert_eq!(edits.get(), 0);
            assert!(
                dispatcher
                    .with_resident_fault_plan_for_test(page, |plan| drop(plan))
                    .is_some()
            );
        }
    }

    #[test]
    fn allowed_first_touch_commits_only_after_successful_protection() {
        for (prot, access) in [
            (1, LeafAccess::Read),
            (2, LeafAccess::Read),
            (4, LeafAccess::Read),
            (3, LeafAccess::Write),
            (5, LeafAccess::Execute),
        ] {
            for succeeds in [false, true] {
                let dispatcher = SyscallDispatcher::new();
                let page = 0x4000_0000;
                dispatcher.seed_resident_fault_for_test(page, prot);
                let edits = std::cell::Cell::new(0);
                dispatcher
                    .with_resident_fault_plan_for_test(page, |plan| {
                        assert_eq!(
                            apply_first_touch(
                                plan.prot(),
                                Some(access),
                                || {
                                    edits.set(edits.get() + 1);
                                    succeeds
                                },
                                || dispatcher.commit_resident_fault(plan)
                            ),
                            succeeds.then_some(true)
                        );
                    })
                    .expect("pending first touch");
                assert_eq!(edits.get(), 1);
                assert_eq!(
                    dispatcher
                        .with_resident_fault_plan_for_test(page, |plan| drop(plan))
                        .is_some(),
                    !succeeds
                );
            }
        }
    }

    #[test]
    fn backend_refusal_fires_first_touch_refused_probe() {
        let dispatcher = SyscallDispatcher::new();
        let page = 0x4000_0000;
        dispatcher.seed_resident_fault_for_test(page, 3);
        let error =
            carrick_guest_mem::MemoryError::HostMap("stage-1 table allocation failed".to_owned());
        let refused_page = std::cell::Cell::new(0);
        let refused_site = std::cell::Cell::new(0);
        dispatcher
            .with_resident_fault_plan_for_test(page, |plan| {
                let access = LeafAccess::Write;
                let access_code = access as u32;
                let page = plan.page();
                let prot = plan.prot();
                assert_eq!(
                    apply_first_touch(
                        prot,
                        Some(access),
                        || {
                            crate::probes::resident_fault_protection_error(page, prot, &error);
                            crate::probes::hvpatch_first_touch_refused(
                                page,
                                access_code,
                                1,
                                &error,
                            );
                            refused_page.set(page);
                            refused_site.set(1);
                            false
                        },
                        || dispatcher.commit_resident_fault(plan)
                    ),
                    None
                );
            })
            .expect("pending first touch");
        assert_eq!(refused_page.get(), page);
        assert_eq!(refused_site.get(), 1);
        assert!(
            dispatcher
                .with_resident_fault_plan_for_test(page, |plan| drop(plan))
                .is_some()
        );
        crate::probes::hvpatch_first_touch_refused(0x4000_1000, 3, 2, &error);
    }
}

#[cfg(test)]
mod guest_descriptor_lane_tests {
    use super::*;
    use carrick_aarch64::engine::Stage1Authority;
    use carrick_el1_abi::{DescriptorTxnSlots, FrameGrantResidencyIdentity};
    use carrick_mem::memory::{
        AARCH64_LINUX_PAGE_TABLE_LAYOUT, LINUX_HVPATCH_GLOBAL_FRAME_BASE, LINUX_MMAP_BASE,
        LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE, stage1_hvpatch_page_tables,
    };
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, CallerInvalidatesAsid, DescriptorApplied, DescriptorOp, DescriptorOutcome,
        DescriptorReceipt, DescriptorRefusal, InlineJournal, PageSpan, PrimaryTableWords,
        ReclaimedTables, apply_submitted_descriptor_txn,
    };
    use carrick_mmu_core::aarch64::{
        GuestLeafPublication, GuestPermissionEdit, HostArenaResolver, LiveDescriptorOwner,
        PageTableManager, SubstrateGpa,
    };
    use std::num::NonZeroU64;
    use std::sync::Arc;

    struct BufferResolver {
        buf: parking_lot::Mutex<Vec<u8>>,
    }

    unsafe impl HostArenaResolver for BufferResolver {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            (base == LINUX_PAGE_TABLES_BASE).then(|| self.buf.lock().as_mut_ptr())
        }
        fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
            (base == LINUX_PAGE_TABLES_BASE).then(|| self.buf.lock().as_ptr())
        }
    }

    const MM: u64 = 41;
    const VA: u64 = LINUX_MMAP_BASE + 0x80_0000;
    const IPA: u64 = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    /// A live MM on the guest-owned lane, selected in-test.
    fn guest_lane() -> (Stage1Authority, Arc<BufferResolver>) {
        let mut manager = PageTableManager::new(
            stage1_hvpatch_page_tables(),
            LINUX_PAGE_TABLES_BASE,
            AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        manager.set_prot_none(VA, 0x20_0000, None).unwrap();
        let mut bytes = manager.as_bytes().to_vec();
        bytes.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let resolver = Arc::new(BufferResolver {
            buf: parking_lot::Mutex::new(bytes),
        });
        let authority = Stage1Authority::new_with_manager(Some(manager));
        unsafe {
            authority.bind_live_backing(
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>
            );
        }
        authority.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
        (authority, resolver)
    }

    /// EL1's side: claim the submission in `slot` and execute it.
    fn el1_apply(
        resolver: &BufferResolver,
        slots: &DescriptorTxnSlots,
        slot: usize,
    ) -> Option<DescriptorReceipt> {
        let mut buf = resolver.buf.lock();
        let maintenance = CallerInvalidatesAsid;
        let words = unsafe {
            PrimaryTableWords::new(
                buf.as_mut_ptr().cast(),
                LINUX_PAGE_TABLES_BASE,
                LINUX_PAGE_TABLES_SIZE as usize,
                &maintenance,
            )
        }
        .unwrap();
        apply_submitted_descriptor_txn(
            slots.slot(slot)?,
            MM,
            &words,
            SubstrateGpa(LINUX_PAGE_TABLES_BASE),
            &mut InlineJournal::new(),
            || {},
        )
    }

    fn residency() -> FrameGrantResidencyIdentity {
        FrameGrantResidencyIdentity {
            mm_key: MM,
            semantic_base: VA,
            physical_ipa: IPA,
            len: 4 * 4096,
            mapping_id: 2,
            frame_id: 1,
            owner_generation: 3,
            inventory_revision: 4,
        }
    }

    fn grant_op(fault: u64) -> DescriptorOp {
        DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: VA,
                ipa: IPA,
                len: 4 * 4096,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(fault, 4096),
            backing: BackingIdentity {
                frame_id: nz(1),
                mapping_id: nz(2),
                owner_generation: nz(3),
                inventory_revision: nz(4),
            },
        }
    }

    /// The engine's settlement side over a bare authority, recording the
    /// backend rollbacks it is asked for.
    struct AuthorityBackend<'a> {
        authority: &'a Stage1Authority,
        rolled_back: Vec<carrick_hal::threaded::El1FrameGrantRollback>,
        completed: Vec<carrick_hal::threaded::El1FrameGrantRollback>,
    }

    impl<'a> AuthorityBackend<'a> {
        fn new(authority: &'a Stage1Authority) -> Self {
            Self {
                authority,
                rolled_back: Vec::new(),
                completed: Vec::new(),
            }
        }
    }

    impl GuestGrantBackend for AuthorityBackend<'_> {
        fn verify(
            &mut self,
            txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
            receipt: &DescriptorReceipt,
        ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
        {
            self.authority
                .settle_guest_descriptor_receipt(txn, receipt)
                .map_err(|error| TrapError::Hypervisor(format!("{error:?}")))
        }

        fn complete(
            &mut self,
            grant: carrick_hal::threaded::El1FrameGrantRollback,
        ) -> Result<(), TrapError> {
            self.completed.push(grant);
            Ok(())
        }

        fn roll_back(
            &mut self,
            grant: carrick_hal::threaded::El1FrameGrantRollback,
        ) -> Result<bool, TrapError> {
            self.rolled_back.push(grant);
            Ok(true)
        }
    }

    fn settle_with(
        authority: &Stage1Authority,
        commits: &mut Vec<(PendingGuestGrant, PageSpan)>,
    ) -> impl FnMut(PendingGuestGrant, DescriptorReceipt) -> Result<GuestGrantSettlement, TrapError>
    {
        move |pending, receipt| {
            settle_guest_frame_grant(
                pending,
                &receipt,
                &mut AuthorityBackend::new(authority),
                |pending, resident| {
                    commits.push((*pending, resident));
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn every_writer_family_is_converted_and_the_hatch_refuses_by_its_own_reason() {
        use carrick_mmu_core::aarch64::GuestLaneRefusal;
        let current = GuestDescriptorLanePrecondition::current();
        assert!(current.frame_grants && current.fork_parent_arming);
        assert!(current.host_copyout && current.backend_writers);
        let placed = GuestDescriptorLanePrecondition {
            slots_placed: true,
            ..current
        };
        assert_eq!(placed.admission(DescriptorLaneHatch::Default), Ok(()));
        assert_eq!(
            placed.admission(DescriptorLaneHatch::Disabled),
            Err(GuestLaneRefusal::OperatorHatch)
        );
        let unplaced = GuestDescriptorLanePrecondition {
            slots_placed: false,
            ..current
        };
        assert_eq!(
            unplaced.admission(DescriptorLaneHatch::Default),
            Err(GuestLaneRefusal::Census)
        );
        assert_eq!(
            unplaced.admission(DescriptorLaneHatch::Disabled),
            Err(GuestLaneRefusal::OperatorHatch),
            "the hatch is reported as itself, never as a census gap"
        );
        for (value, hatch) in [
            (None, DescriptorLaneHatch::Default),
            (Some("0"), DescriptorLaneHatch::Disabled),
            (Some(" 0\n"), DescriptorLaneHatch::Disabled),
            (Some("1"), DescriptorLaneHatch::Default),
            (Some(""), DescriptorLaneHatch::Default),
            (Some("00"), DescriptorLaneHatch::Default),
        ] {
            assert_eq!(
                DescriptorLaneHatch::from_env_value(value),
                hatch,
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_lane_is_refused_while_any_writer_family_is_unconverted() {
        let all = GuestDescriptorLanePrecondition {
            slots_placed: true,
            frame_grants: true,
            host_copyout: true,
            fork_parent_arming: true,
            backend_writers: true,
        };
        assert!(all.admits());
        for missing in 0..5 {
            let mut partial = all;
            match missing {
                0 => partial.slots_placed = false,
                1 => partial.frame_grants = false,
                2 => partial.host_copyout = false,
                3 => partial.fork_parent_arming = false,
                _ => partial.backend_writers = false,
            }
            assert!(!partial.admits(), "missing writer {missing}");
        }
    }

    #[test]
    fn guest_grant_retries_until_its_receipt_then_commits_exact_residency_once() {
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        let fault = VA + 2 * 4096;
        let txn = authority
            .prepare_guest_descriptor_txn(nz(MM), grant_op(fault))
            .unwrap();
        let pending = PendingGuestGrant {
            txn,
            fault_va: fault,
            requested_len: 0x20_0000,
            plan: (VA, 4 * 4096, 3),
            residency: residency(),
        };
        let untouched = resolver.buf.lock().clone();
        assert!(ledger.submit(&slots, 4, pending));
        assert!(!ledger.submit(&slots, 4, pending), "one grant per slot");
        assert_eq!(*resolver.buf.lock(), untouched, "the host stored nothing");

        // Until EL1 publishes, a fault in the span retries on the host.
        assert!(guest_descriptor_edit_in_flight(
            Some(&slots),
            MM,
            VA + 0x3abc
        ));
        assert!(!guest_descriptor_edit_in_flight(Some(&slots), MM + 1, VA));
        assert!(!guest_descriptor_edit_in_flight(
            Some(&slots),
            MM,
            VA + 4 * 4096
        ));
        assert!(!guest_descriptor_edit_in_flight(None, MM, VA));
        let mut commits = Vec::new();
        assert_eq!(
            ledger
                .settle_ready(&slots, MM, settle_with(&authority, &mut commits))
                .unwrap(),
            0
        );
        assert!(commits.is_empty(), "no residency before the receipt");

        let receipt = el1_apply(&resolver, &slots, 4).expect("EL1 claims its MM's work");
        assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
        assert!(!guest_descriptor_edit_in_flight(Some(&slots), MM, fault));
        // Another MM's boundary never settles this MM's receipt.
        assert_eq!(
            ledger
                .settle_ready(&slots, MM + 1, settle_with(&authority, &mut commits))
                .unwrap(),
            0
        );
        assert_eq!(
            ledger
                .settle_ready(&slots, MM, settle_with(&authority, &mut commits))
                .unwrap(),
            1
        );
        assert_eq!(commits, vec![(pending, PageSpan::new(fault, 4096))]);
        assert_eq!(
            authority.with_manager(|manager| manager.translate(fault)),
            Some(Some(IPA + 2 * 4096))
        );
        assert_eq!(
            authority.with_manager(|manager| manager.translate(VA)),
            Some(None),
            "the rest of the grant stays prepared"
        );
        assert_eq!(
            ledger
                .settle_ready(&slots, MM, settle_with(&authority, &mut commits))
                .unwrap(),
            0,
            "a receipt settles exactly once"
        );
        assert!(ledger.submit(&slots, 4, pending), "the slot is free again");
    }

    /// Work budget: a mutating-fault boundary with nothing pending costs one
    /// load, not a lock per vCPU slot. Before the skip every boundary locked
    /// all `EL1_STACK_SLOTS` entries, lane off included.
    #[test]
    fn an_empty_ledger_settles_without_locking_a_slot() {
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        let before = ledger_slot_locks_on_this_thread();
        let settled = ledger
            .settle_ready(&slots, MM, |_, _| -> Result<_, TrapError> {
                unreachable!("nothing is pending")
            })
            .unwrap();
        assert_eq!(settled, 0);
        assert_eq!(ledger_slot_locks_on_this_thread() - before, 0);
    }

    /// A submission is visible to EL1 (through the slots' summary, as the EL1
    /// fault path finds work) only after the ledger counts it, so a boundary
    /// woken by EL1's receipt can never read an empty ledger and skip it.
    /// Three threads: the host submits, "EL1" applies as soon as it sees the
    /// submission and wakes the settler, and the settler must settle exactly
    /// that receipt on its first try.
    #[test]
    fn a_receipt_published_concurrently_with_submission_is_never_skipped() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::time::Duration;

        const ROUNDS: usize = 2_000;
        const SLOT: usize = 4;
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        let fault = VA + 2 * 4096;
        let pending = PendingGuestGrant {
            txn: authority
                .prepare_guest_descriptor_txn(nz(MM), grant_op(fault))
                .unwrap(),
            fault_va: fault,
            requested_len: 0x20_0000,
            plan: (VA, 4 * 4096, 3),
            residency: residency(),
        };
        let visible_while_empty = AtomicUsize::new(0);
        let done = AtomicBool::new(false);
        let (published_tx, published_rx) = mpsc::channel::<()>();
        let (settled_tx, settled_rx) = mpsc::channel::<usize>();
        let wait = Duration::from_secs(10);
        let (slots, ledger, resolver) = (&*slots, &ledger, &*resolver);
        let (visible_while_empty, done) = (&visible_while_empty, &done);

        std::thread::scope(|scope| {
            // EL1: discover work exactly as `carrick-el1`'s fault path does.
            scope.spawn(move || {
                let mut applied = 0;
                while applied < ROUNDS && !done.load(Ordering::Acquire) {
                    if slots.submitted_for(MM).next().is_none() {
                        std::hint::spin_loop();
                        continue;
                    }
                    if !ledger.is_occupied() {
                        visible_while_empty.fetch_add(1, Ordering::Relaxed);
                    }
                    el1_apply(resolver, slots, SLOT).expect("EL1 claims the submission");
                    applied += 1;
                    published_tx.send(()).unwrap();
                }
            });
            // Settler: one settle per published receipt, never a retry.
            scope.spawn(move || {
                for _ in 0..ROUNDS {
                    if published_rx.recv_timeout(wait).is_err() {
                        done.store(true, Ordering::Release);
                        return;
                    }
                    let settled = ledger
                        .settle_ready(slots, MM, |_, _| -> Result<_, TrapError> {
                            Ok(GuestGrantSettlement::Committed(PageSpan::new(fault, 4096)))
                        })
                        .unwrap();
                    settled_tx.send(settled).unwrap();
                }
            });
            // Host: submit the next grant once the last one settled.
            let mut total = 0;
            for round in 0..ROUNDS {
                assert!(ledger.submit(slots, SLOT, pending), "round {round}");
                let settled = settled_rx
                    .recv_timeout(wait)
                    .unwrap_or_else(|_| panic!("round {round}: no settlement"));
                assert_eq!(settled, 1, "round {round}: the receipt was skipped");
                total += settled;
            }
            done.store(true, Ordering::Release);
            assert_eq!(total, ROUNDS);
        });
        assert_eq!(
            visible_while_empty.load(Ordering::Relaxed),
            0,
            "EL1 saw a submission the ledger did not count"
        );
        assert!(!ledger.is_occupied());
    }

    #[test]
    fn refused_or_indeterminate_guest_grants_never_commit_residency() {
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        let txn = authority
            .prepare_guest_descriptor_txn(nz(MM), grant_op(VA))
            .unwrap();
        let pending = PendingGuestGrant {
            txn,
            fault_va: VA,
            requested_len: 0x20_0000,
            plan: (VA, 4 * 4096, 3),
            residency: residency(),
        };
        assert!(ledger.submit(&slots, 0, pending));
        el1_apply(&resolver, &slots, 0).unwrap();
        let mut commits = Vec::new();
        ledger
            .settle_ready(&slots, MM, settle_with(&authority, &mut commits))
            .unwrap();
        commits.clear();

        // Planned against one graph, executed against a changed one: EL1
        // refuses whole and nothing is committed.
        let protect = authority
            .prepare_guest_descriptor_txn(
                nz(MM),
                DescriptorOp::Protect(GuestPermissionEdit {
                    va: VA,
                    len: 4 * 4096,
                    readable: true,
                    writable: false,
                    executable: false,
                }),
            )
            .unwrap();
        let retire = authority
            .prepare_guest_descriptor_txn(nz(MM), DescriptorOp::Retire(PageSpan::new(VA, 4096)))
            .unwrap();
        assert!(ledger.submit(
            &slots,
            1,
            PendingGuestGrant {
                txn: retire,
                ..pending
            }
        ));
        el1_apply(&resolver, &slots, 1).unwrap();
        ledger
            .settle_ready(&slots, MM, settle_with(&authority, &mut commits))
            .unwrap();
        assert!(ledger.submit(
            &slots,
            2,
            PendingGuestGrant {
                txn: protect,
                ..pending
            }
        ));
        let refused = el1_apply(&resolver, &slots, 2).unwrap();
        assert_eq!(
            refused.outcome,
            DescriptorOutcome::Refused(DescriptorRefusal::NotPrivateAnonymous)
        );
        let mut outcomes = Vec::new();
        ledger
            .settle_ready(&slots, MM, |pending, receipt| {
                let outcome = settle_guest_frame_grant(
                    pending,
                    &receipt,
                    &mut AuthorityBackend::new(&authority),
                    |_, _| panic!("a refused transaction must not commit"),
                );
                if let Ok(settled) = outcome {
                    outcomes.push(settled);
                }
                Ok::<_, TrapError>(GuestGrantSettlement::Refused(DescriptorRefusal::Contended))
            })
            .unwrap();
        assert!(outcomes.contains(&GuestGrantSettlement::Refused(
            DescriptorRefusal::NotPrivateAnonymous
        )));

        // An indeterminate rollback fails stopped.
        let indeterminate = DescriptorReceipt {
            id: txn.id,
            digest: txn.digest(),
            outcome: DescriptorOutcome::Indeterminate(DescriptorRefusal::Contended),
        };
        assert!(
            settle_guest_frame_grant(pending, &indeterminate, &mut PanicBackend, |_, _| panic!(
                "never committed"
            ),)
            .is_err()
        );
        // An applied receipt that does not authenticate fails stopped too.
        let forged = DescriptorReceipt {
            id: txn.id,
            digest: txn.digest() ^ 1,
            outcome: DescriptorOutcome::Applied(DescriptorApplied {
                pages: 4,
                resident: PageSpan::new(VA, 4096),
                tables_linked: 0,
                reclaimed: ReclaimedTables::NONE,
                live_stores: 1,
                flush_required: true,
            }),
        };
        assert!(
            settle_guest_frame_grant(
                pending,
                &forged,
                &mut AuthorityBackend::new(&authority),
                |_, _| panic!("never committed"),
            )
            .is_err()
        );
    }

    /// A backend that must not be consulted.
    struct PanicBackend;

    impl GuestGrantBackend for PanicBackend {
        fn verify(
            &mut self,
            _txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
            _receipt: &DescriptorReceipt,
        ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
        {
            panic!("never verified")
        }

        fn complete(
            &mut self,
            _grant: carrick_hal::threaded::El1FrameGrantRollback,
        ) -> Result<(), TrapError> {
            panic!("never completed")
        }

        fn roll_back(
            &mut self,
            _grant: carrick_hal::threaded::El1FrameGrantRollback,
        ) -> Result<bool, TrapError> {
            panic!("never rolled back")
        }
    }

    /// The backend registered backing, inventory, an alias and a mapping
    /// row, and committed the pristine transition, before EL1 published.
    /// A refused or rolled-back receipt exposed no leaf, so settlement must
    /// hand exactly that publication to the backend's rollback, once; an
    /// applied one must not.
    #[test]
    fn a_refused_or_rolled_back_guest_grant_rolls_back_its_publication_once() {
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let txn = authority
            .prepare_guest_descriptor_txn(nz(MM), grant_op(VA))
            .unwrap();
        let pending = PendingGuestGrant {
            txn,
            fault_va: VA,
            requested_len: 0x20_0000,
            plan: (VA, 4 * 4096, 3),
            residency: residency(),
        };
        for outcome in [
            DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot),
            DescriptorOutcome::RolledBack(DescriptorRefusal::Contended),
        ] {
            let receipt = DescriptorReceipt {
                id: txn.id,
                digest: txn.digest(),
                outcome,
            };
            let mut backend = AuthorityBackend::new(&authority);
            assert!(matches!(
                settle_guest_frame_grant(pending, &receipt, &mut backend, |_, _| panic!(
                    "a refused grant never commits"
                )),
                Ok(GuestGrantSettlement::Refused(_))
            ));
            assert_eq!(
                backend.rolled_back,
                vec![pending.rollback()],
                "{outcome:?} left the grant's backing registered"
            );
            assert!(backend.completed.is_empty(), "{outcome:?} completed");
        }
        let rollback = pending.rollback();
        assert_eq!(
            (rollback.mm_key, rollback.semantic_base, rollback.len),
            (MM, VA, 4 * 4096)
        );
        assert_eq!(rollback.ready.physical_ipa, IPA);
        assert_eq!(rollback.ready.owner_generation, 3);
        // Applied: the grant is live; nothing is rolled back.
        assert!(slots.submit(0, &txn));
        let applied = el1_apply(&resolver, &slots, 0).unwrap();
        let mut backend = AuthorityBackend::new(&authority);
        assert!(matches!(
            settle_guest_frame_grant(pending, &applied, &mut backend, |_, _| Ok(())),
            Ok(GuestGrantSettlement::Committed(_))
        ));
        assert!(backend.rolled_back.is_empty());
        assert_eq!(backend.completed, vec![pending.rollback()]);
    }

    /// What a settlement asked of the backend, and when residency was
    /// committed, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum GrantEvent {
        Verified,
        Completed(carrick_hal::threaded::El1FrameGrantRollback),
        RolledBack(carrick_hal::threaded::El1FrameGrantRollback),
        Committed,
    }

    struct RecordingBackend<'a> {
        authority: &'a Stage1Authority,
        log: &'a std::cell::RefCell<Vec<GrantEvent>>,
    }

    impl GuestGrantBackend for RecordingBackend<'_> {
        fn verify(
            &mut self,
            txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
            receipt: &DescriptorReceipt,
        ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
        {
            let verified = self
                .authority
                .settle_guest_descriptor_receipt(txn, receipt)
                .map_err(|error| TrapError::Hypervisor(format!("{error:?}")));
            if verified.is_ok() {
                self.log.borrow_mut().push(GrantEvent::Verified);
            }
            verified
        }

        fn complete(
            &mut self,
            grant: carrick_hal::threaded::El1FrameGrantRollback,
        ) -> Result<(), TrapError> {
            self.log.borrow_mut().push(GrantEvent::Completed(grant));
            Ok(())
        }

        fn roll_back(
            &mut self,
            grant: carrick_hal::threaded::El1FrameGrantRollback,
        ) -> Result<bool, TrapError> {
            self.log.borrow_mut().push(GrantEvent::RolledBack(grant));
            Ok(true)
        }
    }

    const NEXT_IPA: u64 = IPA + 0x20_0000;

    /// A grant over the span of a retired predecessor, with its own backing.
    fn replacement_op(fault: u64) -> DescriptorOp {
        DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: VA,
                ipa: NEXT_IPA,
                len: 4 * 4096,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(fault, 4096),
            backing: BackingIdentity {
                frame_id: nz(5),
                mapping_id: nz(6),
                owner_generation: nz(7),
                inventory_revision: nz(8),
            },
        }
    }

    fn replacement_pending(
        txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        fault: u64,
    ) -> PendingGuestGrant {
        PendingGuestGrant {
            txn,
            fault_va: fault,
            requested_len: 0x20_0000,
            plan: (VA, 4 * 4096, 3),
            residency: FrameGrantResidencyIdentity {
                physical_ipa: NEXT_IPA,
                mapping_id: 6,
                frame_id: 5,
                owner_generation: 7,
                inventory_revision: 8,
                ..residency()
            },
        }
    }

    /// Publish a first grant through EL1 and then retire its span the way a
    /// discard or unmap does on this lane: the leaves keep their outputs as
    /// retired leases for the host's reconciliation, while the backend still
    /// names the old owner until something replaces it.
    fn retired_predecessor(
        authority: &Stage1Authority,
        resolver: &BufferResolver,
        slots: &DescriptorTxnSlots,
    ) {
        for op in [
            grant_op(VA),
            DescriptorOp::Retire(PageSpan::new(VA, 4 * 4096)),
        ] {
            let txn = authority.prepare_guest_descriptor_txn(nz(MM), op).unwrap();
            assert!(slots.submit(7, &txn));
            let receipt = el1_apply(resolver, slots, 7).unwrap();
            assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
            authority
                .settle_guest_descriptor_receipt(&txn, &receipt)
                .unwrap();
            let _ = slots.take_receipt(7, txn.id);
        }
        assert_eq!(
            authority.with_manager(|manager| manager.translate(VA)),
            Some(None)
        );
        assert_eq!(
            authority.with_manager(|manager| manager.translate_retained_output(VA)),
            Some(Some(IPA)),
            "the predecessor's retired lease is still named by its leaves"
        );
    }

    /// A grant that replaces a private predecessor is published by EL1 over
    /// the predecessor's retired leaves. The backend may retire the old owner
    /// and register the new grant only once EL1's receipt verifies, and
    /// before the host commits residency for it.
    #[test]
    fn a_replacement_grant_completes_its_backend_only_after_the_verified_receipt() {
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        retired_predecessor(&authority, &resolver, &slots);

        let fault = VA + 4096;
        let txn = authority
            .prepare_guest_descriptor_txn(nz(MM), replacement_op(fault))
            .expect("a retired predecessor admits the replacement grant");
        let pending = replacement_pending(txn, fault);
        assert!(ledger.submit(&slots, 3, pending));
        let log = std::cell::RefCell::new(Vec::new());
        let mut settle = |pending: PendingGuestGrant, receipt: DescriptorReceipt| {
            settle_guest_frame_grant(
                pending,
                &receipt,
                &mut RecordingBackend {
                    authority: &authority,
                    log: &log,
                },
                |_, resident| {
                    assert_eq!(resident, PageSpan::new(fault, 4096));
                    log.borrow_mut().push(GrantEvent::Committed);
                    Ok(())
                },
            )
        };
        assert_eq!(ledger.settle_ready(&slots, MM, &mut settle).unwrap(), 0);
        assert!(
            log.borrow().is_empty(),
            "the old owner stays until EL1 publishes the replacement"
        );

        let receipt = el1_apply(&resolver, &slots, 3).unwrap();
        assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
        assert_eq!(ledger.settle_ready(&slots, MM, &mut settle).unwrap(), 1);
        assert_eq!(
            *log.borrow(),
            vec![
                GrantEvent::Verified,
                GrantEvent::Completed(pending.rollback()),
                GrantEvent::Committed,
            ],
            "retire the predecessor after the verified receipt, before residency"
        );
        assert_eq!(
            authority.with_manager(|manager| manager.translate(fault)),
            Some(Some(NEXT_IPA + 4096))
        );
        assert_eq!(
            authority.with_manager(|manager| manager.translate_retained_output(VA)),
            Some(Some(NEXT_IPA)),
            "the rest of the span is prepared on the replacement's backing"
        );
    }

    /// EL1 refuses a replacement whose span another publication took first.
    /// The backend never completes it (the predecessor stays exactly as it
    /// was) and rolls back only the new grant's own publication, once.
    #[test]
    fn a_refused_replacement_grant_leaves_its_predecessor_and_rolls_back_once() {
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        retired_predecessor(&authority, &resolver, &slots);

        let fault = VA + 4096;
        let replacement = authority
            .prepare_guest_descriptor_txn(nz(MM), replacement_op(fault))
            .unwrap();
        let pending = replacement_pending(replacement, fault);
        assert!(ledger.submit(&slots, 3, pending));
        // A competing publication over the same span executes first.
        let competing = authority
            .prepare_guest_descriptor_txn(nz(MM), grant_op(VA))
            .unwrap();
        assert!(slots.submit(5, &competing));
        let taken = el1_apply(&resolver, &slots, 5).unwrap();
        assert!(matches!(taken.outcome, DescriptorOutcome::Applied(_)));
        authority
            .settle_guest_descriptor_receipt(&competing, &taken)
            .unwrap();

        let refused = el1_apply(&resolver, &slots, 3).unwrap();
        assert!(
            matches!(
                refused.outcome,
                DescriptorOutcome::Refused(_) | DescriptorOutcome::RolledBack(_)
            ),
            "{:?}",
            refused.outcome
        );
        let log = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            ledger
                .settle_ready(&slots, MM, |pending, receipt| {
                    settle_guest_frame_grant(
                        pending,
                        &receipt,
                        &mut RecordingBackend {
                            authority: &authority,
                            log: &log,
                        },
                        |_, _| panic!("a refused replacement never commits residency"),
                    )
                })
                .unwrap(),
            1
        );
        assert_eq!(
            *log.borrow(),
            vec![GrantEvent::RolledBack(pending.rollback())],
            "no predecessor retirement for a grant EL1 never exposed"
        );
        assert_eq!(
            authority.with_manager(|manager| manager.translate(VA)),
            Some(Some(IPA)),
            "the competing publication is untouched"
        );
    }

    #[test]
    fn a_retiring_mm_releases_exactly_its_slots_and_ledger_entries() {
        let (authority, resolver) = guest_lane();
        let slots = Box::new(DescriptorTxnSlots::new());
        let ledger = GuestGrantLedger::new();
        let pending_for = |txn| PendingGuestGrant {
            txn,
            fault_va: VA,
            requested_len: 0x20_0000,
            plan: (VA, 4 * 4096, 3),
            residency: residency(),
        };
        // Slot 0: applied, receipt unsettled. Slot 1: submitted, unclaimed.
        let applied = authority
            .prepare_guest_descriptor_txn(nz(MM), grant_op(VA))
            .unwrap();
        assert!(ledger.submit(&slots, 0, pending_for(applied)));
        el1_apply(&resolver, &slots, 0).unwrap();
        let unclaimed = authority
            .prepare_guest_descriptor_txn(
                nz(MM),
                DescriptorOp::Retire(PageSpan::new(VA + 4096, 4096)),
            )
            .unwrap();
        assert!(ledger.submit(&slots, 1, pending_for(unclaimed)));
        // Another MM's pending work on slot 2 is untouched.
        let other_lane = guest_lane().0;
        let other = other_lane
            .prepare_guest_descriptor_txn(nz(MM + 1), grant_op(VA))
            .unwrap();
        assert!(ledger.submit(
            &slots,
            2,
            PendingGuestGrant {
                txn: other,
                ..pending_for(other)
            }
        ));

        assert_eq!(ledger.withdraw_mm(&slots, MM), 2);
        assert!(!guest_descriptor_edit_in_flight(
            Some(&slots),
            MM,
            VA + 4096
        ));
        let mut commits = Vec::new();
        assert_eq!(
            ledger
                .settle_ready(&slots, MM, settle_with(&authority, &mut commits))
                .unwrap(),
            0
        );
        assert!(commits.is_empty(), "a retired MM commits no residency");
        // Both slots serve the next MM that runs on them.
        assert!(ledger.submit(&slots, 0, pending_for(unclaimed)));
        assert!(ledger.withdraw_mm(&slots, MM) == 1);
        assert!(guest_descriptor_edit_in_flight(Some(&slots), MM + 1, VA));
        assert_eq!(ledger.withdraw_mm(&slots, MM + 1), 1);
    }

    /// Lane selection sits where an engine binds an MM, and a retiring MM
    /// releases its descriptor work beside its residency records, at final
    /// teardown and at exec replacement.
    #[test]
    fn mm_bind_and_retirement_sites_select_and_withdraw_the_guest_lane() {
        let binding = include_str!("binding.rs");
        let exec = include_str!("exec.rs");
        for (source, bind, retire) in [
            (
                binding,
                "let owned_mm = context.shared().mm();",
                "table.retire_overlapping(terminal_mm.raw(), 0, u64::MAX);",
            ),
            (
                exec,
                "let committed_owned_mm = committed_context.shared().mm();",
                "table.retire_overlapping(old_mm_id.raw(), 0, u64::MAX);",
            ),
        ] {
            let after_bind = source.split(bind).nth(1).expect("MM bind site");
            let next = &after_bind[..after_bind.len().min(600)];
            assert!(next.contains("super::signal::admit_bound_mm("));
            assert!(!next.contains("bind_task_snapshot_identity("));
            let after_retire = source.split(retire).nth(1).expect("retirement site");
            let next = &after_retire[..after_retire.len().min(200)];
            assert!(next.contains("withdraw_guest_descriptor_work("));
        }
    }

    /// EL1 as the drain call sees it: apply every submission for the MM in
    /// the frame, from any slot, and answer the count.
    struct FakeVenue<'a> {
        resolver: &'a BufferResolver,
        slots: &'a DescriptorTxnSlots,
        authority: &'a Stage1Authority,
        ttbr0: u64,
        block: bool,
        max_in_flight: usize,
        /// EL1 refuses (before any store) every submission from this
        /// ordinal on; earlier ones apply.
        refuse_from: Option<usize>,
        answered: usize,
    }

    impl GuestDrainVenue for FakeVenue<'_> {
        fn slot(&self) -> Option<usize> {
            Some(9)
        }
        fn live_ttbr0(&mut self) -> Result<u64, TrapError> {
            Ok(self.ttbr0)
        }
        fn drain_call(
            &mut self,
            mut frame: carrick_el1_abi::TrapFrame,
        ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
            assert_eq!(frame.esr, carrick_el1_abi::DESCRIPTOR_DRAIN_ESR);
            assert_eq!(frame.slot, 9, "the frame is the calling vCPU's");
            let mm = frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM];
            let in_flight = self.slots.submitted_for(mm).count();
            self.max_in_flight = self.max_in_flight.max(in_flight);
            if self.block {
                frame.x[0] = carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED;
                return Ok(frame);
            }
            let mut applied = 0;
            // As EL1 does: in the host's submission (generation) order.
            let indexes: Vec<usize> = self
                .slots
                .submitted_in_order(mm)
                .filter_map(|slot| {
                    self.slots
                        .as_slice()
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, slot))
                })
                .collect();
            for index in indexes {
                if self.refuse_from.is_some_and(|from| self.answered >= from) {
                    let claimed = self.slots.slot(index).unwrap().claim_for_mm(mm).unwrap();
                    // A refusal stored nothing, so no invalidation is owed.
                    claimed.complete(
                        carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Refused(
                            carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::Occupied,
                        ),
                        || {},
                    );
                } else {
                    el1_apply_mm(self.resolver, self.slots, index, mm).unwrap();
                }
                self.answered += 1;
                applied += 1;
            }
            frame.x[0] = applied;
            Ok(frame)
        }
        fn settle(
            &mut self,
            txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
            receipt: &DescriptorReceipt,
        ) -> Result<
            carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
            carrick_aarch64::descriptor_drain::GuestPublishError,
        > {
            self.authority
                .settle_guest_descriptor_receipt(txn, receipt)
                .map_err(|error| {
                    carrick_aarch64::descriptor_drain::GuestPublishError::from_settle(
                        error,
                        "fake venue settle",
                    )
                })
        }
    }

    fn el1_apply_mm(
        resolver: &BufferResolver,
        slots: &DescriptorTxnSlots,
        slot: usize,
        mm: u64,
    ) -> Option<DescriptorReceipt> {
        let mut buf = resolver.buf.lock();
        let maintenance = CallerInvalidatesAsid;
        let words = unsafe {
            PrimaryTableWords::new(
                buf.as_mut_ptr().cast(),
                LINUX_PAGE_TABLES_BASE,
                LINUX_PAGE_TABLES_SIZE as usize,
                &maintenance,
            )
        }
        .unwrap();
        apply_submitted_descriptor_txn(
            slots.slot(slot)?,
            mm,
            &words,
            SubstrateGpa(LINUX_PAGE_TABLES_BASE),
            &mut InlineJournal::new(),
            || {},
        )
    }

    fn resident_grant(authority: &Stage1Authority, resolver: &BufferResolver) {
        let slots = DescriptorTxnSlots::new();
        let txn = authority
            .prepare_guest_descriptor_txn(nz(MM), {
                let DescriptorOp::Prepare {
                    publication,
                    backing,
                    ..
                } = grant_op(VA)
                else {
                    unreachable!()
                };
                DescriptorOp::Prepare {
                    publication,
                    resident: PageSpan::new(VA, 4 * 4096),
                    backing,
                }
            })
            .unwrap();
        assert!(slots.submit(0, &txn));
        el1_apply(resolver, &slots, 0).unwrap();
        let receipt = slots.take_receipt(0, txn.id).unwrap();
        authority
            .settle_guest_descriptor_receipt(&txn, &receipt)
            .unwrap();
    }

    fn writable(authority: &Stage1Authority, va: u64) -> bool {
        authority
            .with_manager(|manager| {
                carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(
                    carrick_mmu_core::aarch64::terminal_descriptor(manager.debug_walk(va)),
                    carrick_mmu_core::aarch64::LeafAccess::Write,
                )
            })
            .unwrap()
    }

    #[test]
    fn prepared_copyout_refusal_preserves_the_leaf_and_releases_the_slot() {
        for failure in ["wrong root", "wrong backing", "blocked", "read only"] {
            let (authority, resolver) = guest_lane();
            let slots = DescriptorTxnSlots::new();
            let mut op = grant_op(VA);
            if let DescriptorOp::Prepare { publication, .. } = &mut op {
                publication.writable = failure != "read only";
            }
            let txn = authority.prepare_guest_descriptor_txn(nz(MM), op).unwrap();
            assert!(slots.submit(0, &txn));
            el1_apply(&resolver, &slots, 0).unwrap();
            authority
                .settle_guest_descriptor_receipt(&txn, &slots.take_receipt(0, txn.id).unwrap())
                .unwrap();
            let page = VA + 4096;
            let before = authority
                .with_manager(|manager| manager.debug_walk(page))
                .unwrap();
            let mut venue = FakeVenue {
                resolver: &resolver,
                slots: &slots,
                authority: &authority,
                ttbr0: LINUX_PAGE_TABLES_BASE + if failure == "wrong root" { 4096 } else { 0 },
                block: failure == "blocked",
                max_in_flight: 0,
                refuse_from: None,
                answered: 0,
            };
            assert!(
                carrick_aarch64::descriptor_drain::publish_copyout(
                    &mut venue,
                    &authority,
                    &slots,
                    nz(MM),
                    page,
                    IPA + if failure == "wrong backing" {
                        8192
                    } else {
                        4096
                    },
                )
                .is_err(),
                "{failure}"
            );
            assert_eq!(
                authority
                    .with_manager(|manager| manager.debug_walk(page))
                    .unwrap(),
                before,
                "{failure}"
            );
            assert!(
                slots.as_slice().iter().all(|slot| slot.state() == 0),
                "{failure}"
            );
        }
    }

    #[test]
    fn prepared_copyout_publishes_only_its_page_through_the_guest_executor() {
        let (authority, resolver) = guest_lane();
        let slots = DescriptorTxnSlots::new();
        let txn = authority
            .prepare_guest_descriptor_txn(nz(MM), grant_op(VA))
            .unwrap();
        assert!(slots.submit(0, &txn));
        el1_apply(&resolver, &slots, 0).unwrap();
        authority
            .settle_guest_descriptor_receipt(&txn, &slots.take_receipt(0, txn.id).unwrap())
            .unwrap();
        let page = VA + 4096;
        assert!(!writable(&authority, page));
        let mut venue = FakeVenue {
            resolver: &resolver,
            slots: &slots,
            authority: &authority,
            ttbr0: LINUX_PAGE_TABLES_BASE,
            block: false,
            max_in_flight: 0,
            refuse_from: None,
            answered: 0,
        };
        let receipt = carrick_aarch64::descriptor_drain::publish_copyout(
            &mut venue,
            &authority,
            &slots,
            nz(MM),
            page,
            IPA + 4096,
        )
        .unwrap();
        assert_eq!(receipt.resident(), PageSpan::new(page, 4096));
        assert!(writable(&authority, page));
        assert!(!writable(&authority, page + 4096));
        assert_eq!(venue.max_in_flight, 1);
        assert_eq!(slots.submitted_for(MM).count(), 0);
    }

    #[test]
    fn the_fork_arm_lands_in_order_and_settles_before_the_fork_commits() {
        let (authority, resolver) = guest_lane();
        resident_grant(&authority, &resolver);
        assert!(writable(&authority, VA) && writable(&authority, VA + 3 * 4096));
        let arm: Vec<_> = [(VA, 2 * 4096), (VA + 3 * 4096, 4096)]
            .into_iter()
            .map(|(va, len)| {
                let op = authority
                    .with_manager(|manager| manager.fork_arm_op(va, len, false, false, false))
                    .unwrap();
                authority.prepare_guest_descriptor_txn(nz(MM), op).unwrap()
            })
            .collect();
        let slots = Box::new(DescriptorTxnSlots::new());
        let mut venue = FakeVenue {
            resolver: &resolver,
            slots: &slots,
            authority: &authority,
            ttbr0: LINUX_PAGE_TABLES_BASE | (7 << 48),
            block: false,
            max_in_flight: 0,
            refuse_from: None,
            answered: 0,
        };
        let receipts = apply_guest_descriptor_txns_now(&mut venue, &slots, &arm).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            venue.max_in_flight, 1,
            "one submission at a time, settled in order"
        );
        assert!(!writable(&authority, VA));
        assert!(!writable(&authority, VA + 4096));
        assert!(writable(&authority, VA + 2 * 4096), "outside the arm");
        assert!(!writable(&authority, VA + 3 * 4096));
        assert!(slots.as_slice().iter().all(|slot| slot.state() == 0));
    }

    #[test]
    fn a_fork_arm_on_the_wrong_vcpu_or_blocked_is_an_error_and_leaves_no_slot() {
        let (authority, resolver) = guest_lane();
        resident_grant(&authority, &resolver);
        let op = authority
            .with_manager(|manager| manager.fork_arm_op(VA, 4096, false, false, false))
            .unwrap();
        let arm = [authority.prepare_guest_descriptor_txn(nz(MM), op).unwrap()];
        let slots = Box::new(DescriptorTxnSlots::new());
        let mut venue = FakeVenue {
            resolver: &resolver,
            slots: &slots,
            authority: &authority,
            ttbr0: (LINUX_PAGE_TABLES_BASE + 0x1000) | (7 << 48),
            block: false,
            max_in_flight: 0,
            refuse_from: None,
            answered: 0,
        };
        assert!(apply_guest_descriptor_txns_now(&mut venue, &slots, &arm).is_err());
        assert!(
            writable(&authority, VA),
            "another root's vCPU applies nothing"
        );
        venue.ttbr0 = LINUX_PAGE_TABLES_BASE | (7 << 48);
        venue.block = true;
        assert!(apply_guest_descriptor_txns_now(&mut venue, &slots, &arm).is_err());
        assert!(writable(&authority, VA));
        assert!(
            slots.as_slice().iter().all(|slot| slot.state() == 0),
            "a failed drain withdraws its submission"
        );
    }

    /// Only an EL1 refusal of the FIRST transaction is a clean "nothing
    /// live" answer a caller may roll back on; a refusal after an earlier
    /// transaction applied leaves the publication partial.
    #[test]
    fn a_drain_classifies_a_first_refusal_clean_and_a_later_one_unsettled() {
        use carrick_aarch64::descriptor_drain::GuestPublishError;
        for (refuse_from, clean) in [(0, true), (1, false)] {
            let (authority, resolver) = guest_lane();
            resident_grant(&authority, &resolver);
            let arm: Vec<_> = [(VA, 2 * 4096), (VA + 3 * 4096, 4096)]
                .into_iter()
                .map(|(va, len)| {
                    let op = authority
                        .with_manager(|manager| manager.fork_arm_op(va, len, false, false, false))
                        .unwrap();
                    authority.prepare_guest_descriptor_txn(nz(MM), op).unwrap()
                })
                .collect();
            let slots = Box::new(DescriptorTxnSlots::new());
            let mut venue = FakeVenue {
                resolver: &resolver,
                slots: &slots,
                authority: &authority,
                ttbr0: LINUX_PAGE_TABLES_BASE | (7 << 48),
                block: false,
                max_in_flight: 0,
                refuse_from: Some(refuse_from),
                answered: 0,
            };
            let error = apply_guest_descriptor_txns_now(&mut venue, &slots, &arm).unwrap_err();
            assert_eq!(
                matches!(error, GuestPublishError::NotApplied { .. }),
                clean,
                "refuse_from={refuse_from}: {error}"
            );
            assert_eq!(error.into_clean_refusal().is_ok(), clean);
            assert_eq!(
                writable(&authority, VA),
                clean,
                "first arm applied iff not clean"
            );
            assert!(
                writable(&authority, VA + 3 * 4096),
                "refused arm stored nothing"
            );
            assert!(slots.as_slice().iter().all(|slot| slot.state() == 0));
        }
    }

    /// The parent's guest arm is applied as soon as fork preparation recorded
    /// it, before the parent copyout (which can take a host COW on an armed
    /// span) and before the fork commits; and a forwarded syscall settles
    /// published grants before it is serviced.
    #[test]
    fn fork_commit_and_syscall_entry_order_guest_descriptor_work() {
        let lifecycle = include_str!("lifecycle.rs");
        let arm = lifecycle
            .split("fn arm_parent(&mut self, memory: &mut E)")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("arm_parent");
        let take = arm.find("take_guest_fork_arm_txns()").expect("arm taken");
        let apply = arm.find("apply_guest_fork_arm(").expect("arm applied");
        assert!(take < apply);
        let quiesce = include_str!("quiesce.rs");
        let armed = quiesce
            .find("ops.arm_parent(memory)")
            .expect("arm applied in prepare");
        let copyout = quiesce
            .find("let parent_outputs_published")
            .expect("parent copyout");
        let commit = quiesce
            .find("ops.commit_parent(memory)")
            .expect("fork commit");
        assert!(armed < copyout && copyout < commit);
        let module = include_str!("mod.rs");
        let service = module
            .split("fn service_threaded_syscall_for_executor(")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("syscall service");
        let settle = service
            .find("settle_guest_frame_grants(")
            .expect("settlement at syscall entry");
        let cow = service
            .find("guest_cow_awaiting_settlement(")
            .expect("guest COW settlement at syscall entry");
        let dispatch = service
            .find("service_threaded_syscall_for_executor_inner(")
            .expect("dispatch");
        assert!(settle < dispatch && cow < dispatch);
    }
}
