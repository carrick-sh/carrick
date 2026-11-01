//! One native process signal selection and handler-publication owner for both ISAs.

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
    /// Restore the original architectural return word and rewind one syscall
    /// instruction. Eligibility and SA_RESTART remain shared policy above this
    /// ISA-only operation.
    fn restart_from_return_word(
        &self,
        _frame: &mut <Self::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
        _original_return: u64,
    ) -> bool {
        false
    }
    fn group_exit_custody(&self, task: &CurrentTask) -> CompletionRoute;
}

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
{
    if !carrick_personality_linux::signal::signal_delivery_before_work(
        CompletionRoute::Served,
        &task.linux,
    ) {
        return None;
    }

    let mut thread_blocked =
        SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::from_bits(slot.blocked().0));
    let saved_mask = process.take_suspend_mask().unwrap_or(thread_blocked);
    slot.init_blocked(BlockedMask(saved_mask.signals().bits()));
    // Every completed checkpoint consumes this exact member's interrupted wait,
    // including a handler without SA_RESTART. It cannot leak into a later SVC.
    let mut interrupted_child_wait = process.take_interrupted_child_wait();
    let forwarded_restart = slot.take_forwarded_restart();
    let mut rewind_interrupted_wait =
        |_process: &mut NativeProcessEntry<'_, 'a, M, C, S>,
         frame: &mut <A::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
         machine: &mut A| {
            if let Some(original) = interrupted_child_wait.take() {
                Some(machine.restart(frame, original.as_ref()))
            } else if let Some(restart) = forwarded_restart {
                restart
                    .eligible
                    .then(|| machine.restart_from_return_word(frame, restart.original_return))
            } else {
                machine.restart_forwarded(frame)
            }
        };
    let Some((sig, info, action)) =
        process.take_deliverable_after_suspend(&mut thread_blocked, saved_mask)
    else {
        let _ = rewind_interrupted_wait(process, frame, machine);
        return None;
    };
    match action.disposition {
        policy::Disposition::Ignore => {
            if carrick_signal_core::wait::interrupted_wait(
                carrick_signal_core::wait::RestartClass::IfSaRestart,
                carrick_signal_core::wait::WaitProgress::Blocked,
                None,
            ) == carrick_signal_core::wait::WaitDecision::Continue
            {
                let _ = rewind_interrupted_wait(process, frame, machine);
            }
            None
        }
        policy::Disposition::Default => {
            // The host already classified this synchronous fault. Select its
            // disposition here once, then return only a fatal verdict to the
            // existing host core/exit path. Carrier signal tables stay out.
            if slot
                .synchronous_fault()
                .is_some_and(|(signal, _, _, _)| signal == sig)
            {
                slot.synchronous_fault_default();
                return None;
            }
            if let policy::Delivery::Terminate { .. } = policy::default_delivery(sig) {
                Some(match process.exit_with_signal(sig) {
                    Ok(_) => CompletionRoute::Suspended,
                    Err(NativeProcessError::GroupExitCustody) => machine.group_exit_custody(task),
                    Err(_) => CompletionRoute::InvalidCompletion,
                })
            } else {
                if carrick_signal_core::wait::interrupted_wait(
                    carrick_signal_core::wait::RestartClass::IfSaRestart,
                    carrick_signal_core::wait::WaitProgress::Blocked,
                    None,
                ) == carrick_signal_core::wait::WaitDecision::Continue
                {
                    let _ = rewind_interrupted_wait(process, frame, machine);
                }
                None
            }
        }
        policy::Disposition::Handler(handler) => {
            let restarted = if carrick_signal_core::wait::interrupted_wait(
                carrick_signal_core::wait::RestartClass::IfSaRestart,
                carrick_signal_core::wait::WaitProgress::Blocked,
                Some(action.flags.restart),
            ) == carrick_signal_core::wait::WaitDecision::Restart
            {
                rewind_interrupted_wait(process, frame, machine)
            } else {
                None
            };
            if restarted == Some(false) {
                return force_delivery_fault(
                    task,
                    slot,
                    process,
                    frame,
                    fpstate,
                    machine,
                    SignalDeliveryFailure {
                        original: sig,
                        blocked: thread_blocked,
                    },
                );
            }
            let interrupted_sp = machine.user_sp(frame);
            let selected_stack = carrick_personality_linux::signal::delivery_stack(
                slot.read_altstack(),
                interrupted_sp,
                action.flags.on_stack,
            );
            let Some((sp, stack)) = selected_stack else {
                return force_delivery_fault(
                    task,
                    slot,
                    process,
                    frame,
                    fpstate,
                    machine,
                    SignalDeliveryFailure {
                        original: sig,
                        blocked: thread_blocked,
                    },
                );
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
                // SAFETY: a borrowed ABI record is contiguous for its own size.
                unsafe {
                    core::slice::from_raw_parts(
                        i as *const _ as *const u8,
                        core::mem::size_of_val(i),
                    )
                }
            });
            let setup = machine.backend().setup_signal_frame(
                frame,
                params,
                info_bytes,
                fpstate,
                &mut |va, bytes| process.copy_signal_frame(va, bytes).is_ok(),
            );
            if setup.is_err() {
                return force_delivery_fault(
                    task,
                    slot,
                    process,
                    frame,
                    fpstate,
                    machine,
                    SignalDeliveryFailure {
                        original: sig,
                        blocked: thread_blocked,
                    },
                );
            }
            if slot
                .synchronous_fault()
                .is_some_and(|(signal, _, _, _)| signal == sig)
            {
                slot.clear_synchronous_fault();
            }
            commit_handler_stack(slot, stack, sp, interrupted_sp, action.flags.on_stack);
            let mask = policy::handler_block_mask(sig, action, thread_blocked);
            let _ = slot.store_blocked_then_read_pending(
                BlockedMask(mask.signals().bits()),
                slot.pending(),
            );
            None
        }
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
            NativeSignalFixture, take_signal_copies,
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
}

#[cfg(test)]
mod resumed_forward_tests {
    use super::*;
    use crate::native_process_runtime::host_test_support::{
        NativeSignalFixture, take_signal_copies,
    };
    use carrick_core_abi::{
        BirthSerial, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
        SnapshotGeneration,
    };
    use carrick_personality_linux::abi::thread::ForwardedSyscallRestart;
    use carrick_sched_core::ParkedContextWords;
    use zerocopy::FromBytes;

    struct X86Machine(crate::x86_signal::LinuxX86Backend);
    impl SignalMachine<ParkedContextWords> for X86Machine {
        type Backend = crate::x86_signal::LinuxX86Backend;
        fn backend(&mut self) -> &mut Self::Backend {
            &mut self.0
        }
        fn user_sp(&self, frame: &crate::x86_signal::NativeFrame) -> UserVa {
            UserVa::new(frame.rsp)
        }
        fn restart(&self, _: &mut crate::x86_signal::NativeFrame, _: &ParkedContextWords) -> bool {
            false
        }
        fn restart_from_return_word(
            &self,
            frame: &mut crate::x86_signal::NativeFrame,
            word: u64,
        ) -> bool {
            crate::x86_signal::restart_from_return_word(frame, word)
        }
        fn group_exit_custody(&self, _: &CurrentTask) -> CompletionRoute {
            CompletionRoute::Suspended
        }
    }

    fn fixture(id: u64) -> (NativeSignalFixture, ExecutionBinding) {
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(id),
            generation: SnapshotGeneration::from_raw(1),
            mm: EntryMmKey::from_raw(1),
            thread_generation: EntryThreadGeneration::from_raw(1),
        };
        let fixture = NativeSignalFixture::new(
            binding,
            binding.task,
            BirthSerial::of_task(carrick_sched_core::process::TaskSerial::from_raw_u64(5).unwrap()),
        );
        // The generic fixture expects SIGINT to have a handler. These controls
        // start without one and install it explicitly only when needed.
        fixture.ignore_signal(2);
        (fixture, binding)
    }
    fn enqueue(
        fixture: &NativeSignalFixture,
        binding: ExecutionBinding,
        queue: &carrick_el1_abi::SharedSignalIngressQueue,
        signal: Signal,
    ) {
        queue
            .admit(carrick_el1_abi::ExternalSignalRecord::new(
                carrick_core_abi::EntryEventIdentity::from_binding(binding),
                binding,
                fixture.record(),
                queue.issue_event_generation().unwrap(),
                signal,
                carrick_el1_abi::ExternalSignalSource::Terminal,
            ))
            .unwrap();
    }

    #[test]
    fn x86_resumed_forward_delivers_once_and_uses_shared_restart_decision() {
        for (index, restart, eligible) in [(0, true, true), (1, false, true), (2, true, false)] {
            let (fixture, binding) = fixture(179_000 + index);
            fixture.install_sigint_handler(restart);
            let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
            enqueue(&fixture, binding, &queue, Signal::from_number(2).unwrap());
            assert!(
                fixture
                    .control_slot()
                    .arm_forwarded_restart(ForwardedSyscallRestart {
                        original_return: 0,
                        eligible
                    })
            );
            let mut frame = crate::x86_signal::NativeFrame {
                rcx: 0x400002,
                r11: 0x202,
                rsp: 0x400000,
                rax: carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
                rdi: 17,
                rsi: 0x500000,
                rdx: 1,
                ..Default::default()
            };
            let _ = take_signal_copies();
            let mut machine = X86Machine(crate::x86_signal::LinuxX86Backend);
            let fpstate = [0; carrick_sched_core::X86_XSAVE_BYTES];
            assert_eq!(
                fixture.drain_and_deliver_with(&queue, &mut frame, &fpstate, &mut machine),
                (1, None)
            );
            let copies = take_signal_copies();
            let frames: Vec<_> = copies
                .iter()
                .filter(|(_, bytes)| {
                    bytes.len() == core::mem::size_of::<carrick_syscall_abi::X8664Rtsigframe>()
                })
                .collect();
            assert_eq!(frames.len(), 1);
            let saved =
                carrick_syscall_abi::X8664Rtsigframe::read_from_bytes(&frames[0].1).unwrap();
            let pc = saved.uc.uc_mcontext.rip;
            let value = saved.uc.uc_mcontext.rax;
            let fd = saved.uc.uc_mcontext.rdi;
            assert_eq!(
                pc,
                if restart && eligible {
                    0x400000
                } else {
                    0x400002
                }
            );
            assert_eq!(
                value,
                if restart && eligible {
                    0
                } else {
                    carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
                }
            );
            assert_eq!(fd, 17);
            assert_eq!(frame.rcx, 0x7000);
            assert!(!fixture.control_slot().forwarded_restart_armed());
            assert_eq!(
                fixture.drain_and_deliver_with(&queue, &mut frame, &fpstate, &mut machine),
                (0, None)
            );
            assert!(take_signal_copies().is_empty());
            assert_eq!(frame.rcx, 0x7000);
        }
    }

    #[test]
    fn x86_empty_ignored_and_blocked_checkpoints_consume_restart_once() {
        for (index, disposition) in ["empty", "ignored", "blocked"].into_iter().enumerate() {
            let (fixture, binding) = fixture(179_020 + index as u64);
            let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
            match disposition {
                "ignored" => fixture.ignore_signal(2),
                "blocked" => {
                    fixture.install_sigint_handler(true);
                    fixture.set_blocked_mask(BlockedMask(Signal::from_number(2).unwrap().bit()));
                }
                _ => (),
            }
            if disposition != "empty" {
                enqueue(&fixture, binding, &queue, Signal::from_number(2).unwrap());
            }
            assert!(
                fixture
                    .control_slot()
                    .arm_forwarded_restart(ForwardedSyscallRestart {
                        original_return: 0,
                        eligible: true,
                    })
            );
            let mut frame = crate::x86_signal::NativeFrame {
                rcx: 0x400002,
                r11: 0x202,
                rsp: 0x400000,
                rax: carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
                ..Default::default()
            };
            let _ = take_signal_copies();
            let mut machine = X86Machine(crate::x86_signal::LinuxX86Backend);
            let fpstate = [0; carrick_sched_core::X86_XSAVE_BYTES];
            let (_, route) =
                fixture.drain_and_deliver_with(&queue, &mut frame, &fpstate, &mut machine);
            assert_eq!(route, None);
            assert_eq!((frame.rcx, frame.rax), (0x400000, 0));
            assert!(!fixture.control_slot().forwarded_restart_armed());
            assert!(take_signal_copies().is_empty());
            // A later checkpoint must not rewind an unrelated instruction.
            frame.rcx = 0x500002;
            let (_, route) =
                fixture.drain_and_deliver_with(&queue, &mut frame, &fpstate, &mut machine);
            assert_eq!(route, None);
            assert_eq!(frame.rcx, 0x500002);
            assert!(take_signal_copies().is_empty());
            if disposition == "blocked" {
                fixture.set_blocked_mask(BlockedMask(0));
                let (_, route) =
                    fixture.drain_and_deliver_with(&queue, &mut frame, &fpstate, &mut machine);
                assert_eq!(route, None);
                assert_eq!(frame.rcx, 0x7000);
                let copies = take_signal_copies();
                let (_, bytes) = copies
                    .iter()
                    .find(|(_, bytes)| {
                        bytes.len() == core::mem::size_of::<carrick_syscall_abi::X8664Rtsigframe>()
                    })
                    .unwrap();
                let saved = carrick_syscall_abi::X8664Rtsigframe::read_from_bytes(bytes).unwrap();
                let pc = saved.uc.uc_mcontext.rip;
                assert_eq!(
                    pc, 0x500002,
                    "unblocking cannot reuse a settled restart witness"
                );
            }
        }
    }

    #[test]
    fn x86_default_fatal_checkpoint_consumes_restart_without_a_handler() {
        let (fixture, binding) = fixture(179_030);
        let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
        enqueue(&fixture, binding, &queue, Signal::from_number(15).unwrap());
        assert!(
            fixture
                .control_slot()
                .arm_forwarded_restart(ForwardedSyscallRestart {
                    original_return: 0,
                    eligible: true,
                })
        );
        let mut frame = crate::x86_signal::NativeFrame {
            rcx: 0x400002,
            r11: 0x202,
            rsp: 0x400000,
            rax: carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
            ..Default::default()
        };
        let _ = take_signal_copies();
        let mut machine = X86Machine(crate::x86_signal::LinuxX86Backend);
        let fpstate = [0; carrick_sched_core::X86_XSAVE_BYTES];
        let (drained, route) =
            fixture.drain_and_deliver_with(&queue, &mut frame, &fpstate, &mut machine);
        assert_eq!(drained, 1);
        assert_eq!(route, Some(CompletionRoute::Suspended));
        assert!(!fixture.control_slot().forwarded_restart_armed());
        assert!(take_signal_copies().is_empty());
    }

    #[test]
    fn arm_resumed_forward_delivers_once_and_uses_shared_restart_decision() {
        for (index, restart, eligible) in [(0, true, true), (1, false, true), (2, true, false)] {
            let (fixture, binding) = fixture(179_010 + index);
            fixture.install_sigint_handler(restart);
            let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
            enqueue(&fixture, binding, &queue, Signal::from_number(2).unwrap());
            let mut frame = carrick_el1_abi::TrapFrame {
                elr: 0x400004,
                esr: if eligible { 0xfffe } else { 0xfffd },
                far: 17,
                spsr: 0x600003c0,
                ..Default::default()
            };
            frame.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
            frame.x[8] = 63;
            let _ = take_signal_copies();
            assert_eq!(fixture.drain_and_deliver(&queue, &mut frame), (1, None));
            let copies = take_signal_copies();
            assert_eq!(copies.len(), 1);
            let saved =
                carrick_personality_linux::signal::arm::SignalFrame::read_from_bytes(&copies[0].1)
                    .unwrap();
            let pc = saved.rt.ucontext.uc_mcontext.pc;
            let value = saved.rt.ucontext.uc_mcontext.regs[0];
            assert_eq!(
                pc,
                if restart && eligible {
                    0x400000
                } else {
                    0x400004
                }
            );
            assert_eq!(
                value,
                if restart && eligible {
                    17
                } else {
                    carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
                }
            );
            assert_eq!(frame.elr, 0x7000);
            assert!(!fixture.control_slot().forwarded_restart_armed());
            assert_eq!(fixture.drain_and_deliver(&queue, &mut frame), (0, None));
            assert!(take_signal_copies().is_empty());
        }
    }
}
