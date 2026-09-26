//! Host waits transfer an existing execution slot, never create one.
//!
//! The run-queue lifecycle mutex serializes the slot ledger and its condvar.
//! Placement locks are only taken inside that mutex (readers must release
//! placement before acquiring lifecycle). CPU queue locks and kick callbacks
//! are never taken while lifecycle is held. The normal no-handoff claim path
//! does not acquire lifecycle.

use super::*;
use std::marker::PhantomData;

/// One conserved CPU slot and its exact host-wait claimants.
#[derive(Clone, Debug)]
pub struct HostWaitSlotSnapshot {
    pub root: ExecutorId,
    pub cpu: GuestCpuId,
    pub owner: Option<ExecutorId>,
    pub waiters: Vec<(ExecutorBinding, bool)>,
}

/// Coherent, kernel-local work counters and ownership; never inferred from
/// global host-thread counts. Acquisition failure is represented by `None`.
#[derive(Clone, Debug)]
pub struct HostWaitCensus {
    pub entered: u64,
    pub resumed: u64,
    pub slots: Vec<HostWaitSlotSnapshot>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ExecutorPlacement {
    pub cpu: Option<GuestCpuId>,
    pub slot: Option<ExecutorId>,
    pub waiting: bool,
}

#[derive(Debug)]
struct Waiter {
    binding: ExecutorBinding,
    ready: bool,
}

#[derive(Debug)]
pub(super) struct HandoffSlot {
    cpu: GuestCpuId,
    root: ExecutorRegistration,
    owner: Option<ExecutorRegistration>,
    waiters: BTreeMap<ExecutorId, Waiter>,
}

/// Scoped ownership of a host wait on one exact execution lease.
///
/// Dropping this guard reacquires the execution slot, including on unwind.
/// The lease cannot be consumed or replaced until the guard is finished.
/// It does not move a task, its registers, or its thread-affine vCPU.
#[must_use = "keep the guard alive for the entire external host operation"]
pub struct HostWaitToken<'a> {
    queue: Arc<RunQueueInner>,
    executors: Arc<ExecutorDirectory>,
    preemption: Arc<Mutex<PreemptionState>>,
    preemption_condvar: Arc<Condvar>,
    registration: ExecutorRegistration,
    binding: ExecutorBinding,
    slot: ExecutorId,
    cpu: GuestCpuId,
    process: SchedProcessId,
    preserved_reasons: PreemptionReasons,
    active: bool,
    lease: PhantomData<&'a ThreadExecutionLease>,
    // The retained backend/vCPU belongs to the entering host thread.
    owner_thread: PhantomData<std::rc::Rc<()>>,
}

impl HostWaitToken<'_> {
    pub fn is_active(&self) -> bool {
        self.active
    }
    pub fn cpu(&self) -> GuestCpuId {
        self.cpu
    }
    pub fn executor(&self) -> ExecutorId {
        self.binding.executor
    }
    pub fn executor_epoch(&self) -> u64 {
        self.binding.executor_epoch
    }
    pub fn thread(&self) -> ThreadKey {
        self.binding.thread
    }
    pub fn generation(&self) -> ExecutionGeneration {
        self.binding.generation
    }

    fn resume(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.queue.state.lock();
        loop {
            let slot = state.handoffs.get_mut(&self.slot).unwrap_or_else(|| {
                carrick_fatal!(
                    "scheduler::host_wait",
                    "live host wait lost its execution slot"
                )
            });
            let waiter = slot
                .waiters
                .get_mut(&self.registration.id)
                .unwrap_or_else(|| {
                    carrick_fatal!("scheduler::host_wait", "live host wait lost its waiter")
                });
            if waiter.binding != self.binding {
                carrick_fatal!("scheduler::host_wait", "host wait binding changed")
            }
            waiter.ready = true;
            let first_ready = slot
                .waiters
                .iter()
                .find(|(_, wait)| wait.ready)
                .map(|(id, _)| *id);
            if slot.owner.is_none() && first_ready == Some(self.registration.id) {
                slot.owner = Some(self.registration.clone());
                slot.waiters.remove(&self.registration.id);
                *self.registration.placement.lock() = ExecutorPlacement {
                    cpu: Some(self.cpu),
                    slot: Some(self.slot),
                    waiting: false,
                };
                self.queue.set_executor_online(self.cpu, true);
                // Once the original owner is back and nobody is waiting,
                // return to the ordinary, non-handoff fast path.
                let handoff_complete =
                    slot.waiters.is_empty() && slot.root.id == self.registration.id;
                if handoff_complete {
                    self.registration.placement.lock().slot = None;
                    state.handoffs.remove(&self.slot);
                    self.queue.handoff_slots.fetch_sub(1, Ordering::Release);
                }
                self.active = false;
                state.host_wait_resumed =
                    state.host_wait_resumed.checked_add(1).unwrap_or_else(|| {
                        carrick_fatal!("scheduler::host_wait", "resume counter overflow")
                    });
                self.queue.changed.notify_all();
                drop(state);
                if let Some(kick) = self.executors.kick_of(self.registration.id) {
                    kick.host_wait_ended();
                }

                let thread_id = SchedThreadId::new(self.binding.thread.serial.raw());
                let dispatch_ctx = DispatchContext {
                    thread: thread_id,
                    process: self.process,
                    cpu: self.cpu,
                    load: self.queue.cpu_load(self.cpu),
                };
                let budget = self.queue.policy.on_dispatch(&dispatch_ctx);
                let mut reasons_to_restore = self.preserved_reasons;
                // A surviving handoff still needs a settlement boundary to
                // release its conserved slot. Once the original owner has
                // drained the handoff, returning from host I/O alone is not
                // preemption demand. Mandatory reasons remain independent.
                if handoff_complete {
                    reasons_to_restore.remove(PreemptionReasons::HOST_WAIT_RETURN);
                } else {
                    reasons_to_restore.insert(PreemptionReasons::HOST_WAIT_RETURN);
                }
                let (_ticket, sequence) = {
                    let mut preemption = self.preemption.lock();
                    let (ticket, seq) = preemption.register_residency(
                        self.binding,
                        self.cpu,
                        budget,
                        self.binding.thread,
                        self.binding.generation,
                    );
                    if !reasons_to_restore.is_empty() {
                        preemption.add_preemption_reason(self.registration.id, reasons_to_restore);
                    }
                    (ticket, seq)
                };
                crate::event_ring::rec_sched_dispatch(
                    self.binding.thread.serial.raw() as i32,
                    self.registration.id.raw(),
                    self.cpu.as_usize(),
                );
                crate::event_ring::rec_sched_budget(
                    self.registration.id.raw(),
                    budget.quantum().as_millis() as u32,
                    self.binding.generation.raw(),
                );
                self.queue.policy.on_event(&SchedulingEvent {
                    sequence,
                    thread: thread_id,
                    process: self.process,
                    cpu: Some(self.cpu),
                    kind: SchedulingEventKind::Dispatch,
                });
                recompute_demand_state(&self.queue, &self.preemption, &self.preemption_condvar);
                if !reasons_to_restore.is_empty() {
                    self.executors.deliver_kick_to(self.registration.id);
                    self.preemption_condvar.notify_all();
                }
                return;
            }
            let owner = slot.owner.as_ref().map(|owner| owner.id);
            drop(state);
            if let Some(owner) = owner {
                self.executors.deliver_kick_to(owner);
                // The borrower may be waiting for work in the guest (EL1
                // plan 1d), holding the slot with no thread to settle: force
                // its vCPU out so it rescans and releases the slot here.
                self.executors.wake_guest_idle_executor(owner);
            }
            self.queue.cpus[self.cpu.as_usize()].nudge();
            state = self.queue.state.lock();
            // Recheck after delivering the kick: settlement may already have
            // freed the slot. Predicate and notification share this lock.
            let can_resume = state.handoffs.get(&self.slot).is_some_and(|slot| {
                slot.owner.is_none()
                    && slot
                        .waiters
                        .iter()
                        .find(|(_, wait)| wait.ready)
                        .is_some_and(|(id, _)| *id == self.registration.id)
            });
            if !can_resume {
                self.queue.changed.wait(&mut state);
            }
        }
    }
}

impl Drop for HostWaitToken<'_> {
    fn drop(&mut self) {
        self.resume();
    }
}

impl Scheduler {
    pub fn host_wait_census(&self) -> Option<HostWaitCensus> {
        let state = self.queue.inner.state.try_lock()?;
        Some(HostWaitCensus {
            entered: state.host_wait_entered,
            resumed: state.host_wait_resumed,
            slots: state
                .handoffs
                .iter()
                .map(|(root, slot)| HostWaitSlotSnapshot {
                    root: *root,
                    cpu: slot.cpu,
                    owner: slot.owner.as_ref().map(|owner| owner.id),
                    waiters: slot
                        .waiters
                        .values()
                        .map(|waiter| (waiter.binding, waiter.ready))
                        .collect(),
                })
                .collect(),
        })
    }

    /// Return a borrowed CPU after the runtime has saved/detached the task and
    /// audited the idle backend boundary. Keep the exact execution binding and
    /// claim until settlement: ASID retirement may still need this owner thread.
    ///
    /// In particular, retirement must not retain the CPU needed by a returning
    /// host waiter that owes this executor an owner-thread invalidation ack.
    pub fn release_saved_host_wait_slot(
        &self,
        running: &RunnableThread,
        consumed: Option<&super::super::objects::ExecConsumedPredecessorAuthority>,
    ) -> Result<(), SchedulerError> {
        let _transition = self.generation_transition.lock();
        let queue = running.queue.upgrade().ok_or(RunQueueError::Closed)?;
        if !Arc::ptr_eq(&queue, &self.queue.inner)
            || self.executors.binding_for_thread(running.thread_key()) != Some(running.binding)
        {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        if let Some(consumed) = consumed {
            if consumed.thread_key() != running.thread_key()
                || consumed.generation() != running.generation()
                || consumed.executor() != running.executor()
                || consumed.executor_epoch() != running.executor_epoch()
                || !matches!(running.thread.execution_state(), ThreadExecutionState::Exited {
                    generation
                } if running.generation().next() == Some(generation))
            {
                return Err(RunQueueError::AuthorityMismatch.into());
            }
        } else {
            let lease = running
                .lease
                .as_ref()
                .ok_or(RunQueueError::AuthorityMismatch)?;
            running.thread.authenticate_task_state_authority(lease)?;
            if !matches!(running.thread.execution_state(), ThreadExecutionState::SwitchingOut {
                generation, executor, executor_epoch, ..
            } if generation == running.generation()
                && executor == running.executor()
                && executor_epoch == running.executor_epoch())
            {
                return Err(RunQueueError::AuthorityMismatch.into());
            }
        }
        if self.queue.inner.release_handoff(running.executor(), false) {
            self.preemption
                .lock()
                .finalize_residency(running.executor());
            self.recompute_demand();
        }
        Ok(())
    }

    /// Relinquish this executor's CPU while retaining its exact task lease.
    pub fn begin_host_wait<'a>(
        &self,
        running: &'a RunnableThread,
        registration: &ExecutorRegistration,
    ) -> Result<HostWaitToken<'a>, SchedulerError> {
        let queue = running.queue.upgrade().ok_or(RunQueueError::Closed)?;
        if !Arc::ptr_eq(&queue, &self.queue.inner) {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        let lease = running
            .lease
            .as_ref()
            .ok_or(RunQueueError::AuthorityMismatch)?;
        self.begin_host_wait_with_lease(lease, registration)
    }

    /// Runtime seam for the lease lent to `PersistentExecutor` for a quantum.
    /// A missing lease is never replaced by a lookup of numeric identities.
    pub fn begin_host_wait_with_lease<'a>(
        &self,
        lease: &'a ThreadExecutionLease,
        registration: &ExecutorRegistration,
    ) -> Result<HostWaitToken<'a>, SchedulerError> {
        let transition = self.generation_transition.lock();
        self.executors.authenticate(registration)?;
        let thread = self
            .kernel
            .exact_thread_for_scheduler(lease.thread_key())
            .ok_or(SchedulerError::UnknownThread)?;
        thread.validate_running_execution_lease(lease)?;
        let binding = ExecutorBinding {
            executor: lease.executor(),
            executor_epoch: lease.executor_epoch(),
            thread: lease.thread_key(),
            generation: lease.generation(),
        };
        if binding.executor != registration.id
            || self.executors.binding_for_thread(binding.thread) != Some(binding)
            || !matches!(thread.execution_state(), ThreadExecutionState::Running {
                generation, executor, executor_epoch, ..
            } if generation == binding.generation && executor == binding.executor && executor_epoch == binding.executor_epoch)
        {
            return Err(RunQueueError::AuthorityMismatch.into());
        }

        let mut state = self.queue.inner.state.lock();
        let placement = *registration.placement.lock();
        if placement.waiting {
            return Err(RunQueueError::ExecutorBusy.into());
        }
        let cpu = placement.cpu.ok_or(RunQueueError::AuthorityMismatch)?;
        let id = placement.slot.unwrap_or(registration.id);
        let slot = state.handoffs.entry(id).or_insert_with(|| {
            self.queue
                .inner
                .handoff_slots
                .fetch_add(1, Ordering::Release);
            HandoffSlot {
                cpu,
                root: registration.clone(),
                owner: Some(registration.clone()),
                waiters: BTreeMap::new(),
            }
        });
        if slot.owner.as_ref().map(|owner| owner.id) != Some(registration.id) {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        slot.owner = None;
        slot.waiters.insert(
            registration.id,
            Waiter {
                binding,
                ready: false,
            },
        );
        *registration.placement.lock() = ExecutorPlacement {
            cpu: None,
            slot: Some(id),
            waiting: true,
        };
        state.host_wait_entered = state
            .host_wait_entered
            .checked_add(1)
            .unwrap_or_else(|| carrick_fatal!("scheduler::host_wait", "enter counter overflow"));
        self.queue.inner.set_executor_online(cpu, false);
        self.queue.inner.changed.notify_all();
        drop(state);
        let guest_cpu = &self.queue.inner.cpus[cpu.as_usize()];
        guest_cpu.nudge();
        let process = SchedProcessId::new(thread.task_key().serial.raw());
        let (preserved_reasons, sequence) = {
            let mut preemption = self.preemption.lock();
            let old = preemption.finalize_residency(registration.id);
            let reasons = old
                .map(|r| r.reasons.difference(PreemptionReasons::FAIRNESS))
                .unwrap_or_default();
            let seq = preemption.next_sequence();
            (reasons, seq)
        };
        let thread_id = SchedThreadId::new(binding.thread.serial.raw());
        self.queue.inner.policy.on_event(&SchedulingEvent {
            sequence,
            thread: thread_id,
            process,
            cpu: Some(cpu),
            kind: SchedulingEventKind::Stop(SchedulingStopReason::HostWait),
        });
        self.recompute_demand();
        drop(transition);
        // Outside every scheduler lock: the executor moves the threads queued
        // on its stopped vCPU elsewhere, which may hand some back to their
        // host continuations.
        if let Some(kick) = self.executors.kick_of(registration.id) {
            kick.host_wait_began();
        }
        Ok(HostWaitToken {
            queue: Arc::clone(&self.queue.inner),
            executors: Arc::clone(&self.executors),
            preemption: Arc::clone(&self.preemption),
            preemption_condvar: Arc::clone(&self.preemption_condvar),
            registration: registration.clone(),
            binding,
            slot: id,
            cpu,
            process,
            preserved_reasons,
            active: true,
            lease: PhantomData,
            owner_thread: PhantomData,
        })
    }

    /// Finish a host wait before reentering guest memory or guest execution.
    pub fn end_host_wait(
        &self,
        running: &RunnableThread,
        registration: &ExecutorRegistration,
        mut token: HostWaitToken<'_>,
    ) -> Result<(), SchedulerError> {
        if !Arc::ptr_eq(&token.queue, &self.queue.inner)
            || !Arc::ptr_eq(&token.registration.placement, &registration.placement)
            || token.binding != running.binding
        {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        token.resume();
        Ok(())
    }
}

impl ExecutorDirectory {
    fn deliver_kick_to(&self, executor: ExecutorId) {
        let kick = self
            .state
            .lock()
            .entries
            .get(&executor)
            .map(|entry| Arc::clone(&entry.kick));
        if let Some(kick) = kick
            && let Some(binding) = kick.current_binding()
        {
            kick.deliver_exact(binding.token());
        }
    }

    pub(super) fn authenticate(
        &self,
        registration: &ExecutorRegistration,
    ) -> Result<(), RunQueueError> {
        let state = self.state.lock();
        match state.entries.get(&registration.id) {
            Some(entry) if Arc::ptr_eq(&entry.placement, &registration.placement) => Ok(()),
            _ => Err(RunQueueError::StaleExecutor),
        }
    }
}

impl RunQueueInner {
    /// Called with lifecycle locked, so publishing a vacancy cannot race the
    /// spare's final predicate check and condvar enrollment.
    pub(super) fn claim_handoff(
        &self,
        state: &mut RunQueueState,
        executor: &ExecutorRegistration,
    ) -> bool {
        if executor.in_host_wait() {
            return false;
        }
        let reserved = executor.placement.lock().slot;
        for (id, slot) in &mut state.handoffs {
            // The original M remains the fallback owner of this slot until
            // all waiters drain. It cannot acquire a second slot meanwhile.
            if reserved.is_some_and(|reserved| reserved != *id) {
                continue;
            }
            if slot.owner.is_none() && !slot.waiters.values().any(|waiter| waiter.ready) {
                slot.owner = Some(executor.clone());
                *executor.placement.lock() = ExecutorPlacement {
                    cpu: Some(slot.cpu),
                    slot: Some(*id),
                    waiting: false,
                };
                self.set_executor_online(slot.cpu, true);
                return true;
            }
        }
        false
    }

    pub(super) fn release_handoff(&self, executor: ExecutorId, only_if_returning: bool) -> bool {
        if self.handoff_slots.load(Ordering::Acquire) == 0 {
            return false;
        }
        let mut state = self.state.lock();
        let id = state.handoffs.iter().find_map(|(id, slot)| {
            (slot.owner.as_ref().map(|owner| owner.id) == Some(executor)
                && (!only_if_returning || slot.waiters.values().any(|wait| wait.ready)))
            .then_some(*id)
        });
        let Some(id) = id else {
            return false;
        };
        let slot = state.handoffs.get_mut(&id).unwrap_or_else(|| {
            carrick_fatal!("scheduler::host_wait", "owned slot vanished under its lock")
        });
        let owner = slot.owner.take().unwrap_or_else(|| {
            carrick_fatal!("scheduler::host_wait", "slot owner vanished under its lock")
        });
        *owner.placement.lock() = ExecutorPlacement {
            cpu: None,
            slot: (owner.id == slot.root.id).then_some(id),
            waiting: false,
        };
        let cpu = slot.cpu;
        self.set_executor_online(cpu, false);
        if slot.waiters.is_empty() {
            *slot.root.placement.lock() = ExecutorPlacement {
                cpu: Some(cpu),
                slot: None,
                waiting: false,
            };
            self.set_executor_online(cpu, true);
            state.handoffs.remove(&id);
            self.handoff_slots.fetch_sub(1, Ordering::Release);
        }
        self.changed.notify_all();
        drop(state);
        self.cpus[cpu.as_usize()].nudge();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_wait_census_reports_contention_without_waiting() {
        let input = crate::kernel::RootBootstrap::for_reference_model(
            59_500,
            carrick_hal::ThreadId::synthetic_for_tests(59_500),
            "host wait census contention".to_owned(),
        )
        .unwrap();
        let (kernel, _) = Kernel::bootstrap_root(input).unwrap();
        let scheduler = Scheduler::new(kernel);
        let held = scheduler.queue.inner.state.lock();
        assert!(scheduler.scheduler_summary().host_wait.is_none());
        drop(held);
        let census = scheduler.scheduler_summary().host_wait.unwrap();
        assert_eq!(census.entered, 0);
        assert_eq!(census.resumed, 0);
        assert!(census.slots.is_empty());
    }
}
