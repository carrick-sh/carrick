//! Exact-thread terminal work; no syscall replay or user errno owns this cursor.
use super::*;
use carrick_core::terminal::{TerminalAccess, ThreadTerminalIdentity};
use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};
use carrick_guest_arch::{Access, GuestLen};
use carrick_personality_linux::thread_cleanup::CleanupPoll;

struct CleanupCopy<'s, 'a, C: ProcessContext, S: NativeProcessService<'a, C>> {
    service: &'s mut S,
    mm: &'s S::Mm,
    error: Option<NativeProcessError>,
    marker: core::marker::PhantomData<(&'a (), C)>,
}
impl<'a, C: ProcessContext, S: NativeProcessService<'a, C>> CleanupCopy<'_, 'a, C, S> {
    fn result(
        &mut self,
        result: Result<(), NativeProcessError>,
        request: GuestCopyRequest,
    ) -> CopyOutcome {
        match result {
            Ok(()) => CopyOutcome::Done,
            Err(NativeProcessError::Fault) => CopyOutcome::Fault,
            Err(error) => {
                self.error = Some(error);
                CopyOutcome::NotYet(request)
            }
        }
    }
    fn access(&mut self, access: TerminalAccess<'_>) -> CopyOutcome {
        let request = GuestCopyRequest {
            address: access.address(),
            len: access.len(),
            access: access.access(),
        };
        if !carrick_guest_arch::lower_half_range(request.address.raw(), request.len.raw()) {
            return CopyOutcome::Fault;
        }
        let result = self.service.terminal_access(self.mm, access);
        self.result(result, request)
    }
}
impl<'a, C: ProcessContext, S: NativeProcessService<'a, C>> UserCopy for CleanupCopy<'_, 'a, C, S> {
    fn copy_in(&mut self, bytes: &mut [u8], address: UserVa) -> CopyOutcome {
        self.access(TerminalAccess::Read { address, bytes })
    }
    fn copy_out(&mut self, address: UserVa, bytes: &[u8]) -> CopyOutcome {
        let request = GuestCopyRequest {
            address,
            len: GuestLen::new(bytes.len() as u64),
            access: Access::Write,
        };
        if !carrick_guest_arch::lower_half_range(address.raw(), request.len.raw()) {
            return CopyOutcome::Fault;
        }
        let result = match self.service.copy_owned_bytes(self.mm, address, bytes) {
            Err(NativeProcessError::Unsupported) => {
                // Byte-write selection may identify missing backing before
                // publishing a supply window. Preparation owns that window;
                // the terminal cursor still owns the store and its wake.
                match self.service.prepare_owned_write(
                    self.mm,
                    carrick_core::mm::transaction::CopyoutRequest {
                        address,
                        len: request.len,
                    },
                ) {
                    Ok(()) => self.service.copy_owned_bytes(self.mm, address, bytes),
                    Err(error) => Err(error),
                }
            }
            result => result,
        };
        self.result(result, request)
    }
    fn atomic_load_u32(&mut self, address: UserVa, value: &mut u32) -> CopyOutcome {
        if address.raw() & 3 != 0 {
            return CopyOutcome::Fault;
        }
        self.access(TerminalAccess::Load { address, value })
    }
    fn atomic_compare_exchange_u32(
        &mut self,
        address: UserVa,
        expected: u32,
        desired: u32,
        observed: &mut u32,
    ) -> CopyOutcome {
        if address.raw() & 3 != 0 {
            return CopyOutcome::Fault;
        }
        self.access(TerminalAccess::CompareExchange {
            address,
            expected,
            desired,
            observed,
        })
    }
}
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    #[inline(never)]
    pub(super) fn finish_thread_cleanup(
        &mut self,
        status: carrick_sched_core::process::TerminationStatus,
    ) -> Result<Option<LifecycleOutcome>, NativeProcessError> {
        let mm = self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?
            .native()
            .resources()
            .mm
            .clone();
        let existing = self.runtime.graph.lock().pending.take_cleanup(self.record);
        let mut owner = match existing {
            Some(owner) => owner,
            None => {
                let identity =
                    ThreadTerminalIdentity::from_exit(self.binding, self.control.entry(), status)
                        .ok_or(NativeProcessError::Stale)?;
                let mut cleanup = Box::new(carrick_core::terminal::ThreadCleanup::new(
                    identity,
                    carrick_personality_linux::thread_cleanup::ThreadCleanup::new(
                        self.control.robust_list().0,
                        self.calling_tid,
                        self.control.clear_child_tid(),
                    ),
                ));
                // Process close has its own admitted terminal transaction.
                // A raw pooled exit must retain its ABI admission before any
                // memory wait, so a later fork cannot revoke the exit window.
                let graph = self.runtime.graph.lock();
                if !graph.pending.has_exit(&self.key)
                    && let Some(entry) = self.control.entry()
                {
                    let page = graph
                        .owner
                        .task(self.key)
                        .map_err(|_| NativeProcessError::Stale)?
                        .native()
                        .resources()
                        .page;
                    match page.begin_exit(entry) {
                        Ok(admission) => cleanup.retain_admission(admission),
                        Err(carrick_core::lifecycle::TransitionError::GateClosed(gate))
                            if gate.is_terminal() => {}
                        Err(_) => return Err(NativeProcessError::Quarantined),
                    }
                }
                cleanup
            }
        };
        loop {
            let cursor = owner
                .resume(self.binding)
                .ok_or(NativeProcessError::Stale)?;
            let mut copy = CleanupCopy {
                service: self.service,
                mm: &mm,
                error: None,
                marker: core::marker::PhantomData,
            };
            match cursor.poll(&mut copy) {
                CleanupPoll::Done => {
                    let clear = self.control.clear_child_tid();
                    self.control.mark_child_tid_cleared_in_zone(clear);
                    self.runtime
                        .graph
                        .lock()
                        .pending
                        .put_cleanup(self.record, owner);
                    return Ok(None);
                }
                CleanupPoll::Wake(address) => {
                    self.wake_terminal_word(address)?;
                    owner
                        .resume(self.binding)
                        .ok_or(NativeProcessError::Stale)?
                        .wake_completed();
                }
                CleanupPoll::Wait(request) => {
                    let error = copy.error.ok_or(NativeProcessError::Quarantined)?;
                    self.runtime
                        .graph
                        .lock()
                        .pending
                        .put_cleanup(self.record, owner);
                    match self.begin_terminal_copy(request, error)? {
                        NativeResume::Left(None) => {
                            return Ok(Some(LifecycleOutcome::Transferred {
                                progress: carrick_core::Served::Idle,
                                result: SyscallResult::new(0),
                            }));
                        }
                        NativeResume::NoPending => {
                            owner = self
                                .runtime
                                .graph
                                .lock()
                                .pending
                                .take_cleanup(self.record)
                                .ok_or(NativeProcessError::Quarantined)?;
                        }
                        _ => return Err(NativeProcessError::Quarantined),
                    }
                }
            }
        }
    }
    fn wake_terminal_word(&mut self, address: UserVa) -> Result<(), NativeProcessError> {
        let zone = self.source.zone;
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(self.binding.mm.raw(), address.raw()),
            &carrick_sched_core::ShortLockSpin,
        );
        let mut effects = WakeEffects::default();
        let wake = zone.wake_placed(
            &guard,
            self.binding.mm.raw(),
            address.raw(),
            carrick_personality_linux::thread::CHILD_TID_WAKE_MASK,
            carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
            Waker::El1 {
                slot: self.source.slot,
            },
            &mut [],
            &mut effects,
        );
        drop(guard);
        match wake {
            Err(carrick_sched_core::WakeRefusal::Unplaceable) => {
                self.service.wake_unplaceable_wait(ProcessWaitChannel {
                    mm: self.binding.mm,
                    address: NonZeroU64::new(address.raw()).ok_or(NativeProcessError::Invalid)?,
                })
            }
            Err(_) => Err(NativeProcessError::Quarantined),
            Ok(_) => {
                self.service.wake_effects(effects);
                Ok(())
            }
        }
    }
}
