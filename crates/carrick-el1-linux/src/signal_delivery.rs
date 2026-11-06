//! One native process signal selection and handler-publication owner for both ISAs.

extern crate alloc;
use alloc::boxed::Box;

use super::native_process_runtime::{NativeProcessEntry, NativeProcessError, NativeProcessService};
use carrick_el1_abi::{BlockedMask, CurrentTask};
use carrick_guest_arch::{ProcessContext, UserVa};
use carrick_personality_linux::dispatch::CompletionRoute;
use carrick_personality_linux::signal::{ProcessSignals, SignalBackend};
use carrick_signal_core::policy::{self, SigBlockMask, Signal};

/// Machine-specific register operations surrounding the shared selection.
pub trait SignalMachine<C> {
    type Backend: SignalBackend;
    fn backend(&mut self) -> &mut Self::Backend;
    fn user_sp(
        &self,
        frame: &<Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
    ) -> UserVa;
    fn restart(
        &self,
        frame: &mut <Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
        original: &C,
    ) -> bool;
    fn restart_forwarded(
        &self,
        _frame: &mut <Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
    ) -> Option<bool> {
        None
    }
    fn group_exit_custody(&self, task: &CurrentTask) -> CompletionRoute;
    fn restart_from_argument(
        &self,
        _frame: &mut <Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
        _argument: u64,
    ) -> bool {
        false
    }

    /// Save the live, completed return before service custody releases CPU.
    fn save_return(
        &self,
        frame: &<Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
        fpstate: &[u8],
        context: &mut C,
    ) -> bool;

    /// Original argument carried by a forwarded restart marker.
    fn forwarded_restart_argument(
        &self,
        _frame: &<Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
    ) -> Option<u64> {
        None
    }
    /// Reflect the successfully published frame in a saved execution context.
    fn published_stack(&mut self, _sp: UserVa) {}
}

#[inline(never)]
pub fn deliver_signal_on_syscall_return<'a, M, C, S, A>(
    task: &CurrentTask,
    slot: &carrick_el1_abi::ThreadControlSlot,
    process: &mut NativeProcessEntry<'_, 'a, M, C, S>,
    frame: &mut <A::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
    fpstate: &[u8],
    machine: &mut A,
) -> Option<CompletionRoute>
where
    M: Clone,
    C: ProcessContext,
    S: NativeProcessService<'a, C, Mm = M>,
    A: SignalMachine<C>,
    <A::Backend as carrick_guest_arch::ArchTypes>::NativeFrame: Clone,
{
    if !process.matches_signal_return(task, slot) {
        return None;
    }
    if !carrick_personality_linux::signal::signal_delivery_before_work(
        CompletionRoute::Served,
        &task.linux,
    ) {
        process.defer_signal_return_for_work();
        return None;
    }

    let mut prepared = None;
    loop {
        let mut thread_blocked = SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(slot.blocked().0),
        );
        let saved_mask = process.peek_suspend_mask().unwrap_or(thread_blocked);
        let mut selected = if let Some(selected) = process.take_signal_push() {
            selected
        } else {
            let Some(selected) =
                process.take_deliverable_after_suspend(&mut thread_blocked, saved_mask)
            else {
                let _ = process.take_suspend_mask();
                slot.init_blocked(BlockedMask(saved_mask.signals().bits()));
                if let Some(original) = process.take_interrupted_child_wait() {
                    let _ = machine.restart(frame, original.as_ref());
                } else {
                    let _ = machine.restart_forwarded(frame);
                }
                return None;
            };
            super::native_process_runtime::SignalPush::new(selected, thread_blocked, saved_mask)
        };
        let sig = selected.signal;
        let action = selected.action;
        let info = selected.info;
        let thread_blocked = selected.blocked;
        let saved_mask = selected.saved_mask;
        if !matches!(action.disposition, policy::Disposition::Handler(_)) {
            // No frame is owed for an ignored/default disposition.
            let _ = process.take_suspend_mask();
            slot.init_blocked(BlockedMask(saved_mask.signals().bits()));
            let original = process.take_interrupted_child_wait();
            match action.disposition {
                policy::Disposition::Ignore => {}
                policy::Disposition::Default => {
                    if slot
                        .synchronous_fault()
                        .is_some_and(|(signal, _, _, _)| signal == sig)
                    {
                        slot.synchronous_fault_default();
                        return None;
                    }
                    if let policy::Delivery::Terminate { .. } = policy::default_delivery(sig) {
                        return Some(match process.exit_with_signal(sig) {
                            Ok(_) => CompletionRoute::Suspended,
                            Err(NativeProcessError::GroupExitCustody) => {
                                machine.group_exit_custody(task)
                            }
                            Err(_) => CompletionRoute::InvalidCompletion,
                        });
                    }
                }
                policy::Disposition::Handler(_) => unreachable!(),
            }
            if let Some(original) = original {
                let _ = machine.restart(frame, original.as_ref());
            } else {
                let _ = machine.restart_forwarded(frame);
            }
            return None;
        }
        let policy::Disposition::Handler(handler) = action.disposition else {
            unreachable!()
        };
        let failure = || SignalDeliveryFailure {
            original: sig,
            blocked: thread_blocked,
        };
        if selected.failed {
            drop(selected);
            return force_delivery_fault(task, slot, process, frame, fpstate, machine, failure());
        }
        // No register, suspend-mask, interrupted-wait or altstack publication
        // precedes the final copied byte. A park retains the exact selection.
        let mut staged = Box::new(frame.clone());
        if action.flags.restart {
            let restarted = if let Some(original) = process.peek_interrupted_child_wait() {
                Some(machine.restart(&mut staged, original.as_ref()))
            } else if let Some(argument) = selected.forwarded_restart {
                Some(machine.restart_from_argument(&mut staged, argument))
            } else {
                let argument = machine.forwarded_restart_argument(&staged);
                let restarted = machine.restart_forwarded(&mut staged);
                if restarted == Some(true) {
                    selected.forwarded_restart = argument;
                }
                restarted
            };
            if restarted == Some(false) {
                drop(selected);
                return force_delivery_fault(
                    task,
                    slot,
                    process,
                    frame,
                    fpstate,
                    machine,
                    failure(),
                );
            }
        }
        let interrupted_sp = machine.user_sp(frame);
        let Some((sp, stack)) = carrick_personality_linux::signal::delivery_stack(
            slot.read_altstack(),
            interrupted_sp,
            action.flags.on_stack,
        ) else {
            drop(selected);
            return force_delivery_fault(task, slot, process, frame, fpstate, machine, failure());
        };
        let params = carrick_personality_linux::signal::SignalFrameParams {
            stack,
            signal: sig,
            sigcode: info.as_ref().map_or(0, |i| i.si_code),
            fault_addr: info.as_ref().map_or(0, |i| i.si_addr),
            handler: UserVa::new(handler.0),
            restorer: action.restorer.map(|r| UserVa::new(r.0)),
            mask: saved_mask,
            sp,
            interrupted_sp,
        };
        let info_bytes = info.as_ref().map(|i| {
            // SAFETY: the borrowed ABI record is contiguous for its own size.
            unsafe {
                core::slice::from_raw_parts(i as *const _ as *const u8, core::mem::size_of_val(i))
            }
        });
        let mut refusal = None;
        let mut copied_index = 0;
        let setup = machine.backend().setup_signal_frame(
            &mut staged,
            params,
            info_bytes,
            fpstate,
            &mut |address, bytes| {
                let mut offset = 0;
                while offset < bytes.len() {
                    let Some(raw) = address.raw().checked_add(offset as u64) else {
                        return carrick_core::personality::CopyOutcome::Fault;
                    };
                    let address = UserVa::new(raw);
                    let count = (4096 - (raw as usize & 4095)).min(bytes.len() - offset);
                    let piece = &bytes[offset..offset + count];
                    if let Some((previous, committed)) = selected.copied.get(copied_index) {
                        if *previous != address || committed.as_slice() != piece {
                            return carrick_core::personality::CopyOutcome::Fault;
                        }
                    } else {
                        match process.copy_signal_frame(address, piece) {
                            carrick_core::personality::CopyOutcome::Done => {
                                selected.copied.push((address, piece.to_vec()));
                            }
                            outcome => {
                                if let carrick_core::personality::CopyOutcome::NotYet(request) =
                                    outcome
                                {
                                    refusal = Some(request);
                                }
                                return outcome;
                            }
                        }
                    }
                    copied_index += 1;
                    offset += count;
                }
                carrick_core::personality::CopyOutcome::Done
            },
        );
        if let Some(request) = refusal {
            // A successful in-ring preparation must permit progress. An
            // identical second refusal is an invariant failure, not a spin.
            if process.signal_copy_needs_backing() {
                if prepared == Some(request.address) {
                    return Some(CompletionRoute::InvalidCompletion);
                }
                prepared = Some(request.address);
            }
            if !machine.save_return(frame, fpstate, process.resume_context_mut()) {
                return Some(CompletionRoute::InvalidCompletion);
            }
            process.retain_signal_push(selected);
            match process.prepare_signal_push(request) {
                Ok(super::native_process_runtime::NativeResume::NoPending) => continue,
                Ok(super::native_process_runtime::NativeResume::Left(None)) => {
                    return Some(CompletionRoute::Suspended);
                }
                _ => return Some(CompletionRoute::InvalidCompletion),
            }
        }
        let Ok(published_sp) = setup else {
            drop(selected);
            return force_delivery_fault(task, slot, process, frame, fpstate, machine, failure());
        };
        let _ = process.take_suspend_mask();
        let _ = process.take_interrupted_child_wait();
        *frame = *staged;
        machine.published_stack(published_sp);
        if slot
            .synchronous_fault()
            .is_some_and(|(signal, _, _, _)| signal == sig)
        {
            slot.clear_synchronous_fault();
        }
        commit_handler_stack(slot, stack, sp, interrupted_sp, action.flags.on_stack);
        let mask = policy::handler_block_mask(sig, action, thread_blocked);
        let _ = slot
            .store_blocked_then_read_pending(BlockedMask(mask.signals().bits()), slot.pending());
        return None;
    }
}

fn commit_handler_stack(
    slot: &carrick_el1_abi::ThreadControlSlot,
    saved: carrick_syscall_abi::LinuxSignalStack,
    selected_sp: UserVa,
    interrupted_sp: UserVa,
    on_stack: bool,
) {
    if on_stack
        && selected_sp != interrupted_sp
        && (saved.ss_flags as u32 & carrick_syscall_abi::LINUX_SS_AUTODISARM as u32) != 0
    {
        slot.write_altstack(carrick_personality_linux::abi::thread::AltStack::DISABLED);
    }
}

struct SignalDeliveryFailure {
    original: Signal,
    blocked: SigBlockMask,
}

fn force_delivery_fault<'a, M, C, S, A>(
    task: &CurrentTask,
    slot: &carrick_el1_abi::ThreadControlSlot,
    process: &mut NativeProcessEntry<'_, 'a, M, C, S>,
    frame: &mut <A::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
    fpstate: &[u8],
    machine: &mut A,
    failure: SignalDeliveryFailure,
) -> Option<CompletionRoute>
where
    M: Clone,
    C: ProcessContext,
    S: NativeProcessService<'a, C, Mm = M>,
    A: SignalMachine<C>,
    <A::Backend as carrick_guest_arch::ArchTypes>::NativeFrame: Clone,
{
    let SignalDeliveryFailure { original, blocked } = failure;
    if let Some((_, code, address, _)) = slot.synchronous_fault() {
        // Match host synchronous injection: an unusable handler stack is
        // terminal SIGSEGV, including when the original fault was SIGBUS.
        slot.publish_synchronous_fault(Signal::SEGV, code, address);
        slot.synchronous_fault_default();
        return None;
    }
    if original == Signal::SEGV {
        return Some(match process.exit_with_signal(Signal::SEGV) {
            Ok(_) => CompletionRoute::Suspended,
            Err(NativeProcessError::GroupExitCustody) => machine.group_exit_custody(task),
            Err(_) => CompletionRoute::InvalidCompletion,
        });
    }
    if process.force_sigsegv(blocked).is_err() {
        return Some(CompletionRoute::InvalidCompletion);
    }
    let mask = blocked.signals().without(Signal::SEGV);
    let _ = slot.store_blocked_then_read_pending(BlockedMask(mask.bits()), slot.pending());
    deliver_signal_on_syscall_return(task, slot, process, frame, fpstate, machine)
}

#[cfg(test)]
mod altstack_tests {
    use super::*;
    use carrick_personality_linux::abi::thread::AltStack;

    #[test]
    fn caught_onstack_handler_disarms_only_after_switching_stacks() {
        let slot = carrick_el1_abi::ThreadControlSlot::new();
        let setting = AltStack {
            sp: 0x10_0000,
            size: 8192,
            flags: carrick_syscall_abi::LINUX_SS_AUTODISARM as u32,
        };
        slot.write_altstack(setting);
        let (_, saved) = carrick_personality_linux::signal::delivery_stack(
            setting,
            UserVa::new(0x20_0000),
            true,
        )
        .unwrap();
        commit_handler_stack(
            &slot,
            saved,
            UserVa::new(0x10_2000),
            UserVa::new(0x20_0000),
            true,
        );
        assert!(slot.read_altstack().is_disabled());
        let restored = carrick_personality_linux::signal::restored_altstack(
            saved,
            carrick_guest_arch::GuestIsa::Aarch64,
        )
        .unwrap();
        let flags = restored.flags;
        assert_eq!(flags, carrick_syscall_abi::LINUX_SS_AUTODISARM as u32);
    }

    #[test]
    fn production_deliver_signal_on_syscall_return_preserves_interrupted_sp_and_masks_daif() {
        use crate::native_process_runtime::host_test_support::{
            NativeSignalFixture, take_signal_frames as take_signal_copies,
        };
        use carrick_core_abi::{
            EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding, SnapshotGeneration,
        };
        use carrick_personality_linux::signal::arm;
        use zerocopy::FromBytes;

        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(777),
            generation: SnapshotGeneration::from_raw(1),
            mm: EntryMmKey::from_raw(1),
            thread_generation: EntryThreadGeneration::from_raw(1),
        };
        let fixture = NativeSignalFixture::new(
            binding,
            EntryTaskKey::from_raw(777),
            carrick_core_abi::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(5).unwrap(),
            ),
        );
        fixture.install_sigint_handler(false);

        let _ = take_signal_copies();
        let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
        queue
            .admit(carrick_el1_abi::ExternalSignalRecord::new(
                carrick_core_abi::EntryEventIdentity::from_binding(binding),
                binding,
                fixture.record(),
                carrick_el1_abi::SignalEventGeneration::new(core::num::NonZeroU64::MIN),
                carrick_signal_core::policy::Signal::from_number(2).unwrap(),
                carrick_el1_abi::ExternalSignalSource::Terminal,
            ))
            .unwrap();
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x40_0000,
            // Interrupted EL0 SPSR with Z+C flags (0x6000_0000) and internal EL0 DAIF (0x3c0).
            // Before the fix, deliver_signal_on_syscall_return -> setup_arm_signal_frame -> build
            // fails in arm::encode because 0x3c0 is rejected by validate_pstate, causing
            // deliver_signal_on_syscall_return to take force_delivery_fault (SIGSEGV) instead of
            // writing the handler frame!
            spsr: 0x6000_03c0,
            ..Default::default()
        };
        let (drained, route) = fixture.drain_and_deliver(&queue, &mut frame);
        assert_eq!(drained, 1);
        assert_eq!(
            route, None,
            "deliver_signal_on_syscall_return must deliver SIGINT to handler without faulting on internal DAIF"
        );
        let copies = take_signal_copies();
        assert_eq!(copies.len(), 1, "signal frame must be copied to user stack");
        let (_, bytes) = &copies[0];
        let built = arm::SignalFrame::ref_from_bytes(bytes).unwrap();
        let saved_sp = built.rt.ucontext.uc_mcontext.sp;
        let saved_pstate = built.rt.ucontext.uc_mcontext.pstate;
        assert_eq!(saved_sp, 0x40_0000);
        assert_eq!(saved_pstate, 0x6000_0000);
    }
    #[test]
    fn production_signal_frame_fault_keeps_terminal_branch() {
        use crate::native_process_runtime::host_test_support::{
            NativeSignalFixture, take_signal_copy_attempts,
            take_signal_frames as take_signal_copies,
        };
        use carrick_core_abi::{
            EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding, SnapshotGeneration,
        };

        // An invalid user address remains the existing terminal delivery fault.
        {
            let error = NativeProcessError::Fault;
            let binding = ExecutionBinding {
                task: EntryTaskKey::from_raw(777),
                generation: SnapshotGeneration::from_raw(1),
                mm: EntryMmKey::from_raw(1),
                thread_generation: EntryThreadGeneration::from_raw(1),
            };
            let fixture = NativeSignalFixture::new(
                binding,
                binding.task,
                carrick_core_abi::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(5).unwrap(),
                ),
            );
            fixture.install_sigint_handler(false);
            let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
            queue
                .admit(carrick_el1_abi::ExternalSignalRecord::new(
                    carrick_core_abi::EntryEventIdentity::from_binding(binding),
                    binding,
                    fixture.record(),
                    carrick_el1_abi::SignalEventGeneration::new(core::num::NonZeroU64::MIN),
                    Signal::from_number(2).unwrap(),
                    carrick_el1_abi::ExternalSignalSource::Terminal,
                ))
                .unwrap();
            let mut frame = carrick_el1_abi::TrapFrame {
                elr: 0x40_0000,
                spsr: 0x6000_03c0,
                ..Default::default()
            };
            let before = frame;
            let _ = take_signal_copy_attempts();
            let _ = take_signal_copies();
            let (drained, route) =
                fixture.drain_and_deliver_with_copy_error(&queue, &mut frame, Some(error));
            assert_eq!(drained, 1);
            assert_eq!(route, Some(CompletionRoute::Suspended));
            assert!(take_signal_copies().is_empty());
            let attempts = take_signal_copy_attempts();
            assert_eq!(attempts.len(), 1, "one copy attempt, no retry or replay");
            assert!(attempts[0].1 <= 4096);
            assert_eq!(
                attempts[0].0.raw(),
                (0x40_0000
                    - core::mem::size_of::<carrick_personality_linux::signal::arm::SignalFrame>()
                        as u64)
                    & !15
            );
            assert_eq!(frame.elr, before.elr);
            assert_eq!(frame.spsr, before.spsr);
            assert_eq!(frame.x, before.x);
        }
    }
}
