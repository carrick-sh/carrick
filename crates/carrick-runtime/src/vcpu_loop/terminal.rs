use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use crate::kernel::LinuxTid;
use crate::run_result::{RunResult, RuntimeError};
use carrick_fatal::carrick_fatal;
use carrick_hal::ThreadId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloneAdmissionClose {
    Exec { owner: ThreadId, generation: u64 },
    Fork { owner: ThreadId, generation: u64 },
    Exit { owner: ThreadId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloneAdmissionKind {
    ThreadClone,
    ProcessFork { owner: ThreadId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessExitClaim {
    Owner,
    LostToExec,
    AlreadyOwned,
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessExitClaimReceipt {
    pub(crate) claim: ProcessExitClaim,
    pub(crate) change_epoch: u64,
}

pub(crate) fn claim_from_in_flight(in_flight: usize) -> ProcessExitClaim {
    if in_flight == 0 {
        ProcessExitClaim::Owner
    } else {
        ProcessExitClaim::Pending
    }
}

pub(crate) fn next_clone_admission_change_epoch(current: u64) -> u64 {
    current.wrapping_add(1)
}

pub(crate) type CloneAdmissionListener = Arc<dyn Fn() + Send + Sync + 'static>;
pub(crate) type CloneAdmissionListeners = BTreeMap<u64, (u64, CloneAdmissionListener)>;

#[derive(Default)]
pub(crate) struct CloneAdmissionState {
    pub(crate) in_flight: usize,
    pub(crate) generation: u64,
    pub(crate) closing: Option<CloneAdmissionClose>,
    pub(crate) change_epoch: u64,
    pub(crate) next_listener: u64,
    pub(crate) listeners: CloneAdmissionListeners,
    #[cfg(test)]
    pub(crate) exec_terminal_handoff_hook: Option<Box<dyn FnOnce() + Send + 'static>>,
}

#[derive(Default)]
pub(crate) struct CloneAdmissionGate {
    pub(crate) state: Mutex<CloneAdmissionState>,
    pub(crate) changed: Condvar,
}

/// Outcome of asking the gate to admit a clone or a process fork.
pub(crate) enum CloneEnrollment {
    Admitted(CloneAdmissionPermit),
    /// A sibling process fork has closed admission while it reserves and
    /// publishes its child. The close lifts when that fork's
    /// `ForkCloneAdmission` drops, which bumps the change epoch; wait on
    /// `observed_epoch` and enroll again. Linux serializes these clones and
    /// never reports `EAGAIN` for them.
    Deferred {
        observed_epoch: u64,
    },
    /// Exec or exit closed admission for the rest of this process's life.
    Refused,
}

impl CloneEnrollment {
    #[cfg(test)]
    pub(crate) fn admitted(self) -> Option<CloneAdmissionPermit> {
        match self {
            Self::Admitted(permit) => Some(permit),
            Self::Deferred { .. } | Self::Refused => None,
        }
    }
}

pub(crate) struct CloneAdmissionChangeSubscription {
    gate: Weak<CloneAdmissionGate>,
    id: u64,
    expected_epoch: u64,
}

impl Drop for CloneAdmissionChangeSubscription {
    fn drop(&mut self) {
        let Some(gate) = self.gate.upgrade() else {
            return;
        };
        let mut state = gate.state.lock();
        if state
            .listeners
            .get(&self.id)
            .is_some_and(|(epoch, _)| *epoch == self.expected_epoch)
        {
            state.listeners.remove(&self.id);
        }
    }
}

impl CloneAdmissionGate {
    #[cfg(test)]
    pub(crate) fn install_exec_terminal_handoff_hook(&self, hook: impl FnOnce() + Send + 'static) {
        let previous = self
            .state
            .lock()
            .exec_terminal_handoff_hook
            .replace(Box::new(hook));
        assert!(
            previous.is_none(),
            "exec terminal handoff hook already armed"
        );
    }

    pub(crate) fn subscribe_change(
        self: &Arc<Self>,
        expected_epoch: u64,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Option<CloneAdmissionChangeSubscription> {
        let mut state = self.state.lock();
        if state.change_epoch != expected_epoch {
            drop(state);
            callback();
            return None;
        }
        state.next_listener = state
            .next_listener
            .checked_add(1)
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::vfork_wait", "Missing VforkParentWait barrier on thread context during clone admission status change subscription"));
        let id = state.next_listener;
        state.listeners.insert(id, (expected_epoch, callback));
        Some(CloneAdmissionChangeSubscription {
            gate: Arc::downgrade(self),
            id,
            expected_epoch,
        })
    }

    pub(crate) fn enroll_kind(self: &Arc<Self>, kind: CloneAdmissionKind) -> CloneEnrollment {
        let mut state = self.state.lock();
        match state.closing {
            Some(CloneAdmissionClose::Fork { .. }) => {
                return CloneEnrollment::Deferred {
                    observed_epoch: state.change_epoch,
                };
            }
            Some(CloneAdmissionClose::Exec { .. } | CloneAdmissionClose::Exit { .. }) => {
                return CloneEnrollment::Refused;
            }
            None => {}
        }
        let Some(in_flight) = state.in_flight.checked_add(1) else {
            return CloneEnrollment::Refused;
        };
        state.in_flight = in_flight;
        CloneEnrollment::Admitted(CloneAdmissionPermit {
            gate: Arc::clone(self),
            generation: state.generation,
            kind,
            active: true,
        })
    }

    pub(crate) fn enroll_thread_clone(self: &Arc<Self>) -> CloneEnrollment {
        self.enroll_kind(CloneAdmissionKind::ThreadClone)
    }

    pub(crate) fn enroll_process_fork(self: &Arc<Self>, owner: ThreadId) -> CloneEnrollment {
        self.enroll_kind(CloneAdmissionKind::ProcessFork { owner })
    }

    /// Advance the change epoch and detach every listener; the caller runs
    /// the returned callbacks after releasing the state lock.
    pub(crate) fn publish_change(state: &mut CloneAdmissionState) -> Vec<CloneAdmissionListener> {
        // Equality token only (`subscribe_change` asks "did it move?"), so
        // wrapping is well-defined rather than an exhaustion to abort on.
        state.change_epoch = next_clone_admission_change_epoch(state.change_epoch);
        std::mem::take(&mut state.listeners)
            .into_values()
            .map(|(_, callback)| callback)
            .collect()
    }

    pub(crate) fn close_for_exec(
        self: &Arc<Self>,
        owner: ThreadId,
    ) -> Result<ExecCloneAdmission, RuntimeError> {
        let mut state = self.state.lock();
        let generation = state.generation;
        match state.closing {
            None | Some(CloneAdmissionClose::Fork { .. }) => {
                // Exec is destructive and wins a race with an ordinary fork.
                // Promoting the close reason makes the fork permit observe
                // cancellation and drain itself before exec proceeds.
                state.closing = Some(CloneAdmissionClose::Exec { owner, generation });
            }
            Some(reason) => {
                return Err(RuntimeError::Unsupported(format!(
                    "cannot begin exec while clone admission is closing: {reason:?}"
                )));
            }
        }
        self.changed.notify_all();
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.in_flight != 0 {
            let now = Instant::now();
            if now >= deadline {
                state.closing = None;
                state.generation = state.generation.wrapping_add(1);
                self.changed.notify_all();
                return Err(RuntimeError::Unsupported(format!(
                    "exec clone-admission drain timed out: in_flight={}",
                    state.in_flight
                )));
            }
            self.changed
                .wait_for(&mut state, (deadline - now).min(Duration::from_millis(50)));
        }
        Ok(ExecCloneAdmission {
            gate: Arc::clone(self),
            owner,
            generation,
        })
    }

    pub(crate) fn try_close_for_fork(
        self: &Arc<Self>,
        owner: ThreadId,
        generation: u64,
    ) -> Result<Option<ForkCloneAdmission>, RuntimeError> {
        let mut state = self.state.lock();
        let close = CloneAdmissionClose::Fork { owner, generation };
        if state.generation != generation || state.closing.is_some_and(|current| current != close) {
            return Err(RuntimeError::Unsupported(
                "cannot begin fork while clone admission is closing".to_owned(),
            ));
        }
        state.closing = Some(close);
        self.changed.notify_all();
        // The caller's own process-fork permit remains enrolled. Every other
        // permit belongs to a thread clone admitted before the fork close and
        // must finish normally before the task snapshot can be reserved.
        if state.in_flight != 1 {
            return Ok(None);
        }
        Ok(Some(ForkCloneAdmission {
            gate: Arc::clone(self),
            owner,
            generation,
        }))
    }

    pub(crate) fn try_claim_process_exit(
        &self,
        owner: ThreadId,
    ) -> Result<ProcessExitClaimReceipt, RuntimeError> {
        let mut state = self.state.lock();
        let claim = match state.closing {
            Some(CloneAdmissionClose::Exec { .. }) => ProcessExitClaim::LostToExec,
            Some(CloneAdmissionClose::Exit { owner: current }) if current != owner => {
                ProcessExitClaim::AlreadyOwned
            }
            Some(CloneAdmissionClose::Exit { .. }) => claim_from_in_flight(state.in_flight),
            Some(CloneAdmissionClose::Fork { .. }) | None => {
                state.closing = Some(CloneAdmissionClose::Exit { owner });
                state.change_epoch = next_clone_admission_change_epoch(state.change_epoch);
                let claim = claim_from_in_flight(state.in_flight);
                let change_epoch = state.change_epoch;
                if state.listeners.is_empty() {
                    self.changed.notify_all();
                    drop(state);
                    return Ok(ProcessExitClaimReceipt {
                        claim,
                        change_epoch,
                    });
                }
                let callbacks = std::mem::take(&mut state.listeners);
                self.changed.notify_all();
                drop(state);
                for (_, callback) in callbacks.into_values() {
                    callback();
                }
                return Ok(ProcessExitClaimReceipt {
                    claim,
                    change_epoch,
                });
            }
        };
        Ok(ProcessExitClaimReceipt {
            claim,
            change_epoch: state.change_epoch,
        })
    }

    pub(crate) fn wait_for_claimed_process_exit_clone_drain(
        &self,
        owner: ThreadId,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock();
        loop {
            match state.closing {
                Some(CloneAdmissionClose::Exit { owner: current }) if current == owner => {
                    if state.in_flight == 0 {
                        return Ok(());
                    }
                }
                other => {
                    return Err(RuntimeError::Configuration(format!(
                        "unexpected executor-failure exit lost clone-admission authority: {other:?}"
                    )));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(RuntimeError::CarrierFailed(format!(
                    "unexpected executor-failure clone-admission drain timed out: in_flight={}",
                    state.in_flight
                )));
            }
            self.changed
                .wait_for(&mut state, (deadline - now).min(Duration::from_millis(50)));
        }
    }
}

pub(crate) struct CloneAdmissionPermit {
    pub(crate) gate: Arc<CloneAdmissionGate>,
    pub(crate) generation: u64,
    pub(crate) kind: CloneAdmissionKind,
    pub(crate) active: bool,
}

impl CloneAdmissionPermit {
    pub(crate) fn is_cancelled(&self) -> bool {
        let state = self.gate.state.lock();
        if state.generation != self.generation {
            return true;
        }
        match state.closing {
            Some(CloneAdmissionClose::Exec { .. } | CloneAdmissionClose::Exit { .. }) => true,
            Some(CloneAdmissionClose::Fork { owner, generation }) => match self.kind {
                CloneAdmissionKind::ThreadClone => false,
                CloneAdmissionKind::ProcessFork {
                    owner: permit_owner,
                } => permit_owner != owner || self.generation != generation,
            },
            None => false,
        }
    }

    pub(crate) fn try_close_for_fork(
        &self,
        owner: ThreadId,
    ) -> Result<Option<ForkCloneAdmission>, RuntimeError> {
        if self.kind != (CloneAdmissionKind::ProcessFork { owner }) {
            return Err(RuntimeError::Unsupported(
                "fork close requires the matching process-fork permit".to_owned(),
            ));
        }
        self.gate.try_close_for_fork(owner, self.generation)
    }
}

impl Drop for CloneAdmissionPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.gate.state.lock();
        let Some(in_flight) = state.in_flight.checked_sub(1) else {
            carrick_fatal!(
                "hvpatch::task_backend_lifecycle",
                "HVPatch task backend destruction failed during permit teardown"
            );
        };
        state.in_flight = in_flight;
        self.active = false;
        let callbacks = CloneAdmissionGate::publish_change(&mut state);
        if state.in_flight == 0 || state.closing.is_some() {
            self.gate.changed.notify_all();
        }
        drop(state);
        for callback in callbacks {
            callback();
        }
    }
}

pub(crate) struct ForkCloneAdmission {
    pub(crate) gate: Arc<CloneAdmissionGate>,
    pub(crate) owner: ThreadId,
    pub(crate) generation: u64,
}

impl Drop for ForkCloneAdmission {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        if state.closing
            != Some(CloneAdmissionClose::Fork {
                owner: self.owner,
                generation: self.generation,
            })
        {
            return;
        }
        state.closing = None;
        // Reopening is a change every deferred clone/fork waits on; the
        // permit drop that follows is too late for a waiter that enrolled
        // against this exact close.
        let callbacks = CloneAdmissionGate::publish_change(&mut state);
        self.gate.changed.notify_all();
        drop(state);
        for callback in callbacks {
            callback();
        }
    }
}

pub(crate) struct ExecCloneAdmission {
    pub(crate) gate: Arc<CloneAdmissionGate>,
    pub(crate) owner: ThreadId,
    pub(crate) generation: u64,
}

impl ExecCloneAdmission {
    pub(crate) fn claim_process_exit(self) -> Result<ProcessExitClaimReceipt, RuntimeError> {
        self.claim_process_exit_with(|| {})
    }

    pub(crate) fn claim_process_exit_with(
        self,
        after_validate: impl FnOnce(),
    ) -> Result<ProcessExitClaimReceipt, RuntimeError> {
        let expected = CloneAdmissionClose::Exec {
            owner: self.owner,
            generation: self.generation,
        };
        let mut state = self.gate.state.lock();
        if state.closing != Some(expected) {
            return Err(RuntimeError::Configuration(
                "exec terminal handoff lost exact clone-admission owner".to_owned(),
            ));
        }
        after_validate();
        #[cfg(test)]
        if let Some(hook) = state.exec_terminal_handoff_hook.take() {
            hook();
        }
        state.closing = Some(CloneAdmissionClose::Exit { owner: self.owner });
        state.change_epoch = next_clone_admission_change_epoch(state.change_epoch);
        let change_epoch = state.change_epoch;
        let claim = claim_from_in_flight(state.in_flight);
        if state.listeners.is_empty() {
            self.gate.changed.notify_all();
            drop(state);
            return Ok(ProcessExitClaimReceipt {
                claim,
                change_epoch,
            });
        }
        let callbacks = std::mem::take(&mut state.listeners);
        self.gate.changed.notify_all();
        drop(state);
        for (_, callback) in callbacks.into_values() {
            callback();
        }
        Ok(ProcessExitClaimReceipt {
            claim,
            change_epoch,
        })
    }
}

impl Drop for ExecCloneAdmission {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        if state.closing
            == Some(CloneAdmissionClose::Exec {
                owner: self.owner,
                generation: self.generation,
            })
        {
            state.closing = None;
            state.generation = state.generation.wrapping_add(1);
            self.gate.changed.notify_all();
        }
    }
}

pub(crate) struct ExecTerminalHandoff {
    pub(crate) clone_admission: ExecCloneAdmission,
}

impl ExecTerminalHandoff {
    pub(crate) fn claim_process_exit(self) -> Result<ProcessExitClaimReceipt, RuntimeError> {
        self.clone_admission.claim_process_exit()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FatalSignalRecord {
    pub(crate) image_generation: u64,
    pub(crate) tid: LinuxTid,
    pub(crate) signo: i32,
    pub(crate) code: i32,
    pub(crate) addr: u64,
}

pub(crate) fn core_note_resume_pair(
    registers: &carrick_hal::Aarch64CoreRegisters,
    synchronous_fatal_owner: bool,
) -> (u64, u64) {
    if synchronous_fatal_owner
        && !carrick_hal::aarch64::ExecLevel::from_pstate(registers.pstate).is_guest()
    {
        (registers.elr_el1, registers.spsr_el1)
    } else {
        (registers.resume_pc, registers.resume_pstate)
    }
}

#[derive(Debug)]
pub(crate) struct FatalSignalState {
    pub(crate) image_generation: u64,
    pub(crate) recorded: Option<FatalSignalRecord>,
}

impl Default for FatalSignalState {
    fn default() -> Self {
        Self {
            image_generation: 1,
            recorded: None,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct FatalSignalAuthority(Mutex<FatalSignalState>);

impl FatalSignalAuthority {
    pub(crate) fn current_generation(&self) -> u64 {
        self.0.lock().image_generation
    }

    /// Rebind write-once fatal authority to the replacement exec image.  The
    /// expected generation prevents a stale exec owner from clearing a newer
    /// image's fatal record.
    pub(crate) fn rebind_after_exec(&self, expected_generation: u64) -> Option<u64> {
        let mut state = self.0.lock();
        if state.image_generation != expected_generation {
            return None;
        }
        let next = state.image_generation.checked_add(1)?;
        state.image_generation = next;
        state.recorded = None;
        Some(next)
    }

    /// Publish at most one fatal record for the image generation that produced
    /// it. A pre-exec loser that arrives after the replacement is committed is
    /// rejected rather than poisoning the new image's later crash authority.
    pub(crate) fn record(&self, record: FatalSignalRecord) -> bool {
        let mut state = self.0.lock();
        if state.image_generation != record.image_generation || state.recorded.is_some() {
            return false;
        }
        state.recorded = Some(record);
        true
    }

    pub(crate) fn recorded_for(&self, image_generation: u64) -> Option<FatalSignalRecord> {
        let state = self.0.lock();
        (state.image_generation == image_generation)
            .then_some(state.recorded)
            .flatten()
    }
}

pub(crate) fn fatal_for_terminal_owner(
    recorded: Option<FatalSignalRecord>,
    image_generation: u64,
    owner: LinuxTid,
    terminating_signal: Option<i32>,
) -> Option<FatalSignalRecord> {
    recorded.filter(|fatal| {
        fatal.image_generation == image_generation
            && fatal.tid == owner
            && terminating_signal == Some(fatal.signo)
    })
}

pub(crate) fn try_claim_persistent_process_exit_with(
    clone_admission: &CloneAdmissionGate,
    owner: ThreadId,
) -> Result<ProcessExitClaimReceipt, RuntimeError> {
    clone_admission.try_claim_process_exit(owner)
}

/// What a single vCPU loop did when it stopped.
pub(crate) enum VcpuLoopOutcome {
    /// Whole-process exit (last thread, exit_group, or fatal signal). Carries
    /// the assembled RunResult so the main thread can return it.
    ProcessExit(Box<RunResult>),
    /// Just this thread finished (`exit(2)` with siblings still alive). The
    /// host thread returns; its vCPU is left to the kernel at process exit.
    ThreadDone,
    /// Trap limit hit without exit (used for the main thread's RunResult).
    TrapLimit(Box<RunResult>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::SyscallDispatcher;
    use crate::vcpu_loop::KernelState;
    use carrick_hal::{SignalPumpControl, ThreadId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct EndpointTestSignalPump;

    impl SignalPumpControl for EndpointTestSignalPump {
        fn start_signal_pump(
            &self,
            _registry: &Arc<dyn carrick_hal::VcpuRegistry>,
            _futex: &Arc<dyn carrick_hal::PlatformFutex>,
        ) {
        }
    }

    struct EndpointTestSignalArrival;

    impl carrick_hal::SignalArrival for EndpointTestSignalArrival {
        fn wake_all_waiters(&self) {}
    }

    fn assert_exact_configuration_error(error: RuntimeError, expected: &str) {
        match error {
            RuntimeError::Configuration(actual) => assert_eq!(actual, expected),
            other => panic!("expected RuntimeError::Configuration({expected:?}), got {other:?}"),
        }
    }

    fn alias_context(pid: i32) -> crate::kernel::KernelContext {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "alias-inventory".to_owned(),
        )
        .expect("root bootstrap");
        crate::kernel::Kernel::bootstrap_root(bootstrap)
            .expect("root kernel")
            .1
    }

    #[test]
    fn fatal_core_authority_belongs_only_to_the_matching_terminal_owner() {
        let context = alias_context(67_104);
        let owner = context.thread().key().tid;
        let fatal = FatalSignalRecord {
            image_generation: 1,
            tid: owner,
            signo: 11,
            code: 1,
            addr: 0,
        };
        assert_eq!(
            fatal_for_terminal_owner(Some(fatal), 1, owner, Some(11)),
            Some(fatal)
        );
        assert_eq!(fatal_for_terminal_owner(Some(fatal), 1, owner, None), None);

        let other = alias_context(67_105).thread().key().tid;
        assert_eq!(
            fatal_for_terminal_owner(Some(fatal), 1, other, Some(11)),
            None,
            "a losing fatal thread cannot core-dump the winning owner"
        );
    }

    #[test]
    fn core_note_uses_exception_pair_only_for_synchronous_fatal_owner() {
        let vector_registers = carrick_hal::Aarch64CoreRegisters {
            resume_pc: 0x1111,
            resume_pstate: 0x2222,
            pstate: 0x3c5,
            elr_el1: 0x3333,
            spsr_el1: 0x4444,
            ..carrick_hal::Aarch64CoreRegisters::default()
        };
        assert_eq!(
            core_note_resume_pair(&vector_registers, false),
            (0x1111, 0x2222),
            "running and syscall-blocked siblings use the engine-selected EL0 pair"
        );
        assert_eq!(
            core_note_resume_pair(&vector_registers, true),
            (0x3333, 0x4444),
            "a positive si_code binds the fatal owner to the synchronous exception pair"
        );

        let direct_registers = carrick_hal::Aarch64CoreRegisters {
            resume_pc: 0x5555,
            resume_pstate: 0x3c0,
            pc: 0x5555,
            pstate: 0x3c0,
            elr_el1: 0x6666,
            spsr_el1: 0x7777,
            ..carrick_hal::Aarch64CoreRegisters::default()
        };
        assert_eq!(
            core_note_resume_pair(&direct_registers, true),
            (0x5555, 0x3c0),
            "a direct HVF EL0 abort must not publish stale ELR_EL1 state"
        );
    }

    #[test]
    fn fatal_core_authority_rebinds_at_exec_and_rejects_late_old_image_signal() {
        let context = alias_context(67_106);
        let owner = context.thread().key().tid;
        let authority = Arc::new(FatalSignalAuthority::default());
        let old_image = authority.current_generation();
        let old_fatal = FatalSignalRecord {
            image_generation: old_image,
            tid: owner,
            signo: 11,
            code: 1,
            addr: 0xfeed,
        };
        assert!(authority.record(old_fatal));

        let fatal_loser_release = Arc::new(std::sync::Barrier::new(2));
        let replacement_image = std::thread::scope(|scope| {
            let losing_authority = authority.clone();
            let losing_release = fatal_loser_release.clone();
            let losing_fatal = scope.spawn(move || {
                losing_release.wait();
                losing_authority.record(old_fatal)
            });
            let replacement_image = authority
                .rebind_after_exec(old_image)
                .expect("current exec generation rebinds");
            fatal_loser_release.wait();
            assert!(
                !losing_fatal.join().expect("fatal race participant"),
                "the pre-exec fatal participant released after exec must lose deterministically"
            );
            replacement_image
        });
        assert_ne!(replacement_image, old_image);
        assert_eq!(authority.recorded_for(replacement_image), None);

        let replacement_fatal = FatalSignalRecord {
            image_generation: replacement_image,
            tid: owner,
            signo: 6,
            code: 0,
            addr: 0,
        };
        assert!(authority.record(replacement_fatal));
        assert_eq!(
            fatal_for_terminal_owner(
                authority.recorded_for(replacement_image),
                replacement_image,
                owner,
                Some(6),
            ),
            Some(replacement_fatal)
        );
    }

    #[test]
    fn persistent_terminal_claim_has_one_owner_and_retries_without_blocking() {
        let kernel = KernelState::new(
            SyscallDispatcher::new(),
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        );
        let clone = kernel
            .clone_admission
            .enroll_thread_clone()
            .admitted()
            .expect("model admitted clone");
        let owner = ThreadId::synthetic_for_tests(70_300);
        let pending = kernel.try_claim_persistent_process_exit(owner).unwrap();
        assert_eq!(pending.claim, ProcessExitClaim::Pending);
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(ThreadId::synthetic_for_tests(70_301))
                .unwrap()
                .claim,
            ProcessExitClaim::AlreadyOwned
        );
        let wakes = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let subscription = kernel.clone_admission.subscribe_change(
            pending.change_epoch,
            Arc::new(move || {
                wake_count.fetch_add(1, Ordering::SeqCst);
            }),
        );
        drop(clone);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        drop(subscription);
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(owner)
                .unwrap()
                .claim,
            ProcessExitClaim::Owner
        );
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(ThreadId::synthetic_for_tests(70_301))
                .unwrap()
                .claim,
            ProcessExitClaim::AlreadyOwned
        );
    }

    #[test]
    fn persistent_terminal_claim_lost_to_exec_does_not_poison_later_owner() {
        let kernel = KernelState::new(
            SyscallDispatcher::new(),
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        );
        let exec_owner = ThreadId::synthetic_for_tests(70_302);
        let admission = kernel
            .clone_admission
            .close_for_exec(exec_owner)
            .expect("close for exec");
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(ThreadId::synthetic_for_tests(70_303))
                .expect("active-exec loss")
                .claim,
            ProcessExitClaim::LostToExec,
        );
        drop(admission);
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(ThreadId::synthetic_for_tests(70_304))
                .expect("later unrelated exit")
                .claim,
            ProcessExitClaim::Owner,
        );
    }

    #[test]
    fn exec_terminal_handoff_never_reopens_admission_to_competing_exec() {
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(74_100);
        let contender = ThreadId::synthetic_for_tests(74_101);
        let admission = gate.close_for_exec(owner).expect("close for exec");
        let initial_epoch = gate.state.lock().change_epoch;
        let notifications = Arc::new(AtomicUsize::new(0));
        let notification_count = Arc::clone(&notifications);
        let subscription = gate.subscribe_change(
            initial_epoch,
            Arc::new(move || {
                notification_count.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let (validated_tx, validated_rx) = std::sync::mpsc::channel();
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            let contender_gate = Arc::clone(&gate);
            let contender_thread = scope.spawn(move || {
                validated_rx.recv().expect("handoff validation");
                let encountered_held_mutex = contender_gate.state.try_lock().is_none();
                attempt_tx
                    .send(encountered_held_mutex)
                    .expect("record contender lock observation");
                contender_gate.close_for_exec(contender)
            });

            let claim = admission.claim_process_exit_with(|| {
                validated_tx.send(()).expect("release contender");
                assert!(
                    attempt_rx.recv().expect("contender reached gate"),
                    "contender must observe the gate mutex held during the exact transition"
                );
            });

            let receipt = claim.expect("exact handoff");
            assert_eq!(receipt.claim, ProcessExitClaim::Owner);
            assert_eq!(receipt.change_epoch, initial_epoch + 1);
            assert!(contender_thread.join().expect("contender join").is_err());
        });
        assert_eq!(notifications.load(Ordering::SeqCst), 1);
        drop(subscription);
        assert!(gate.enroll_thread_clone().admitted().is_none());
        assert!(gate.enroll_process_fork(contender).admitted().is_none());
        assert_eq!(
            gate.try_claim_process_exit(owner)
                .expect("same-owner retry")
                .claim,
            ProcessExitClaim::Owner,
        );
        assert_eq!(
            gate.try_claim_process_exit(contender)
                .expect("losing exit")
                .claim,
            ProcessExitClaim::AlreadyOwned,
        );
    }

    #[test]
    fn clone_admission_terminal_epochs_wrap_for_generic_and_exact_claims() {
        assert_eq!(next_clone_admission_change_epoch(u64::MAX), 0);

        let generic = Arc::new(CloneAdmissionGate::default());
        generic.state.lock().change_epoch = u64::MAX;
        let generic_wakes = Arc::new(AtomicUsize::new(0));
        let wake = Arc::clone(&generic_wakes);
        let _generic_subscription = generic.subscribe_change(
            u64::MAX,
            Arc::new(move || {
                wake.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let generic_receipt = generic
            .try_claim_process_exit(ThreadId::synthetic_for_tests(74_120))
            .expect("generic terminal epoch wrap");
        assert_eq!(generic_receipt.change_epoch, 0);
        assert_eq!(generic_wakes.load(Ordering::SeqCst), 1);

        let exact = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(74_121);
        let admission = exact.close_for_exec(owner).expect("close for exact wrap");
        exact.state.lock().change_epoch = u64::MAX;
        let exact_wakes = Arc::new(AtomicUsize::new(0));
        let wake = Arc::clone(&exact_wakes);
        let _exact_subscription = exact.subscribe_change(
            u64::MAX,
            Arc::new(move || {
                wake.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let exact_receipt = admission
            .claim_process_exit()
            .expect("exact terminal epoch wrap");
        assert_eq!(exact_receipt.change_epoch, 0);
        assert_eq!(exact_wakes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exec_terminal_handoff_rejects_owner_and_generation_mismatch() {
        for mismatch in ["owner", "generation"] {
            let gate = Arc::new(CloneAdmissionGate::default());
            let owner = ThreadId::synthetic_for_tests(74_110);
            let admission = gate.close_for_exec(owner).expect("close for exec");
            let mismatched = match mismatch {
                "owner" => CloneAdmissionClose::Exec {
                    owner: ThreadId::synthetic_for_tests(74_111),
                    generation: admission.generation,
                },
                "generation" => CloneAdmissionClose::Exec {
                    owner,
                    generation: admission.generation.wrapping_add(1),
                },
                _ => unreachable!(),
            };
            gate.state.lock().closing = Some(mismatched);

            let error = admission
                .claim_process_exit()
                .expect_err("mismatched handoff authority");

            assert_exact_configuration_error(
                error,
                "exec terminal handoff lost exact clone-admission owner",
            );
            assert_eq!(gate.state.lock().closing, Some(mismatched));
            assert!(
                gate.close_for_exec(ThreadId::synthetic_for_tests(74_112))
                    .is_err(),
                "failed exact validation must not reopen admission"
            );
        }
    }

    #[derive(serde::Serialize)]
    struct ExecTerminalPerfSample {
        operation: &'static str,
        sample: usize,
        iterations: usize,
        elapsed_ns: u128,
        ns_per_transition: f64,
        contender_admissions: usize,
    }

    struct ExecTerminalPerfCase {
        clone_admission: Arc<CloneAdmissionGate>,
        owner: ThreadId,
    }

    fn prepare_exec_terminal_perf_cases(iterations: usize) -> Vec<ExecTerminalPerfCase> {
        (0..iterations)
            .map(|index| {
                let owner = ThreadId::synthetic_for_tests(90_000 + index as i32);
                let clone_admission = Arc::new(CloneAdmissionGate::default());
                ExecTerminalPerfCase {
                    clone_admission,
                    owner,
                }
            })
            .collect()
    }

    fn prepare_exec_terminal_handoff_perf_cases(
        iterations: usize,
    ) -> (Vec<ExecTerminalPerfCase>, Vec<ExecCloneAdmission>) {
        let cases = prepare_exec_terminal_perf_cases(iterations);
        let exec_guards = cases
            .iter()
            .map(|case| {
                case.clone_admission
                    .close_for_exec(case.owner)
                    .expect("prepare uncontended exec admission")
            })
            .collect();
        (cases, exec_guards)
    }

    fn validate_exec_terminal_perf_transitions(cases: &[ExecTerminalPerfCase]) {
        for case in cases {
            assert_eq!(
                case.clone_admission.state.lock().closing,
                Some(CloneAdmissionClose::Exit { owner: case.owner })
            );
        }
    }

    fn observe_exec_terminal_contender_admissions(cases: &[ExecTerminalPerfCase]) -> usize {
        cases
            .iter()
            .enumerate()
            .filter(|(index, case)| {
                case.clone_admission
                    .close_for_exec(ThreadId::synthetic_for_tests(190_000 + *index as i32))
                    .is_ok()
            })
            .count()
    }

    #[test]
    fn exec_terminal_perf_observation_counts_successful_competing_exec_admissions() {
        let cases = prepare_exec_terminal_perf_cases(2);
        assert_eq!(observe_exec_terminal_contender_admissions(&cases), 2);
    }

    fn run_exec_terminal_perf_sample(
        operation: &'static str,
        sample: usize,
        iterations: usize,
    ) -> ExecTerminalPerfSample {
        let exec_error_to_terminal = operation == "exec_error_to_terminal";
        let (cases, exec_guards) = if exec_error_to_terminal {
            let (cases, exec_guards) = prepare_exec_terminal_handoff_perf_cases(iterations);
            assert_eq!(cases.len(), exec_guards.len());
            (cases, Some(exec_guards))
        } else {
            (prepare_exec_terminal_perf_cases(iterations), None)
        };

        let elapsed_ns = if let Some(exec_guards) = exec_guards {
            let started = Instant::now();
            for exec_guard in exec_guards {
                let _ = exec_guard.claim_process_exit();
            }
            started.elapsed().as_nanos()
        } else {
            let started = Instant::now();
            for case in &cases {
                let _ = try_claim_persistent_process_exit_with(
                    case.clone_admission.as_ref(),
                    case.owner,
                );
            }
            started.elapsed().as_nanos()
        };
        validate_exec_terminal_perf_transitions(&cases);
        let contender_admissions = observe_exec_terminal_contender_admissions(&cases);
        drop(cases);

        ExecTerminalPerfSample {
            operation,
            sample,
            iterations,
            elapsed_ns,
            ns_per_transition: elapsed_ns as f64 / iterations as f64,
            contender_admissions,
        }
    }

    fn run_exec_terminal_perf_samples(iterations: usize, warmups: usize, samples: usize) {
        for operation in ["generic_exit_claim", "exec_error_to_terminal"] {
            for warmup in 0..warmups {
                let _ = run_exec_terminal_perf_sample(operation, warmup, iterations);
            }
            for sample in 0..samples {
                let receipt = run_exec_terminal_perf_sample(operation, sample, iterations);
                println!(
                    "CARRICK_EXEC_TERMINAL_PERF|{}",
                    serde_json::to_string(&receipt).expect("serialize perf sample")
                );
            }
        }
    }

    #[test]
    #[ignore = "manual release-mode performance receipt"]
    fn clone_admission_terminal_claim_cost_receipt() {
        let iterations = std::env::var("CARRICK_HANDOFF_PERF_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100_000_usize);
        let warmups = std::env::var("CARRICK_HANDOFF_PERF_WARMUPS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5_usize);
        let samples = std::env::var("CARRICK_HANDOFF_PERF_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(30_usize);
        assert!(iterations >= 100_000);
        assert!(warmups >= 5);
        assert!(samples >= 30);
        run_exec_terminal_perf_samples(iterations, warmups, samples);
    }

    #[test]
    fn clone_admission_cancels_enrolled_process_fork_before_exec_drain() {
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(1003);
        let process_fork = gate
            .enroll_process_fork(owner)
            .admitted()
            .expect("process fork admission");

        std::thread::scope(|scope| {
            let exec = scope.spawn(|| gate.close_for_exec(owner));
            while !process_fork.is_cancelled() {
                std::thread::yield_now();
            }
            assert!(
                matches!(gate.enroll_thread_clone(), CloneEnrollment::Refused),
                "new process forks must be rejected after exec closes admission"
            );
            drop(process_fork);
            drop(
                exec.join()
                    .expect("exec closer")
                    .expect("exec admission drain"),
            );
        });
        assert!(gate.enroll_thread_clone().admitted().is_some());
    }

    #[test]
    fn clone_enrollment_defers_behind_a_fork_close_and_wakes_on_reopen() {
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(1005);
        let CloneEnrollment::Admitted(process_fork) = gate.enroll_process_fork(owner) else {
            panic!("process fork admission");
        };
        let fork_close = process_fork
            .try_close_for_fork(owner)
            .expect("fork close")
            .expect("no clone in flight");

        let CloneEnrollment::Deferred { observed_epoch } = gate.enroll_thread_clone() else {
            panic!("a clone inside a fork close waits");
        };
        assert!(
            matches!(
                gate.enroll_process_fork(ThreadId::synthetic_for_tests(1006)),
                CloneEnrollment::Deferred { .. }
            ),
            "a second fork inside a fork close waits"
        );
        let wakes = Arc::new(AtomicUsize::new(0));
        let wake = Arc::clone(&wakes);
        let subscription = gate.subscribe_change(
            observed_epoch,
            Arc::new(move || {
                wake.fetch_add(1, Ordering::SeqCst);
            }),
        );
        assert!(
            subscription.is_some(),
            "epoch unchanged while the close holds"
        );
        drop(fork_close);
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "reopening the gate wakes the deferred clone"
        );
        assert!(matches!(
            gate.enroll_thread_clone(),
            CloneEnrollment::Admitted(_)
        ));
        drop(process_fork);

        let CloneEnrollment::Admitted(exec_fork) = gate.enroll_process_fork(owner) else {
            panic!("process fork admission");
        };
        std::thread::scope(|scope| {
            let exec = scope.spawn(|| gate.close_for_exec(owner));
            while !exec_fork.is_cancelled() {
                std::thread::yield_now();
            }
            assert!(
                matches!(gate.enroll_thread_clone(), CloneEnrollment::Refused),
                "an exec close is terminal for the process, not a wait"
            );
            drop(exec_fork);
            drop(exec.join().expect("exec closer").expect("exec drain"));
        });
    }

    #[test]
    fn fork_admission_drains_existing_clones_without_cancelling_them() {
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(1004);
        let process_fork = gate
            .enroll_process_fork(owner)
            .admitted()
            .expect("process fork admission");
        let existing_clone = gate
            .enroll_thread_clone()
            .admitted()
            .expect("existing clone admission");

        assert!(
            process_fork.try_close_for_fork(owner).unwrap().is_none(),
            "fork close must yield while an admitted clone publishes"
        );
        assert!(
            matches!(gate.enroll_thread_clone(), CloneEnrollment::Deferred { .. }),
            "new clones wait behind fork"
        );
        assert!(
            !existing_clone.is_cancelled(),
            "a clone admitted before fork must finish, not leak EAGAIN"
        );
        drop(existing_clone);
        let fork = process_fork
            .try_close_for_fork(owner)
            .expect("retry fork close")
            .expect("fork admission drain");
        assert!(!process_fork.is_cancelled());
        drop(fork);

        drop(process_fork);
        assert!(gate.enroll_thread_clone().admitted().is_some());
    }
}
