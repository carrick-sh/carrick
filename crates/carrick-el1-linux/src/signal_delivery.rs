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
        original: C,
    ) -> bool;
    fn group_exit_custody(&self, task: &CurrentTask) -> CompletionRoute;
}

pub fn deliver_signal_on_syscall_return<'a, M, C, S, A>(
    task: &CurrentTask,
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
    let (_, slot) = task.lifecycle_refs()?;
    let mut thread_blocked =
        SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::from_bits(slot.blocked().0));
    let saved_mask = process.take_suspend_mask().unwrap_or(thread_blocked);
    slot.init_blocked(BlockedMask(saved_mask.signals().bits()));
    let (sig, info, action) =
        process.take_deliverable_after_suspend(&mut thread_blocked, saved_mask)?;
    match action.disposition {
        policy::Disposition::Ignore => None,
        policy::Disposition::Default => {
            if let policy::Delivery::Terminate { .. } = policy::default_delivery(sig) {
                Some(match process.exit_with_signal(sig.number() as u8) {
                    Ok(_) => CompletionRoute::Suspended,
                    Err(NativeProcessError::GroupExitCustody) => machine.group_exit_custody(task),
                    Err(_) => CompletionRoute::InvalidCompletion,
                })
            } else {
                None
            }
        }
        policy::Disposition::Handler(handler) => {
            if let Some(original) = process.take_interrupted_child_wait()
                && action.flags.restart
                && !machine.restart(frame, original)
            {
                return force_delivery_fault(
                    task,
                    process,
                    frame,
                    fpstate,
                    machine,
                    sig,
                    thread_blocked,
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
                    process,
                    frame,
                    fpstate,
                    machine,
                    sig,
                    thread_blocked,
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
                    process,
                    frame,
                    fpstate,
                    machine,
                    sig,
                    thread_blocked,
                );
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

fn force_delivery_fault<'a, M, C, S, A>(
    task: &CurrentTask,
    process: &mut NativeProcessEntry<'_, 'a, M, C, S>,
    frame: &mut <A::Backend as carrick_guest_arch::ArchTypes>::NativeFrame,
    fpstate: &[u8],
    machine: &mut A,
    original: Signal,
    blocked: SigBlockMask,
) -> Option<CompletionRoute>
where
    M: Clone,
    C: ProcessContext,
    S: NativeProcessService<'a, C, Mm = M>,
    A: SignalMachine<C>,
{
    if original == Signal::SEGV {
        return Some(
            match process.exit_with_signal(Signal::SEGV.number() as u8) {
                Ok(_) => CompletionRoute::Suspended,
                Err(NativeProcessError::GroupExitCustody) => machine.group_exit_custody(task),
                Err(_) => CompletionRoute::InvalidCompletion,
            },
        );
    }
    let (_, slot) = task.lifecycle_refs()?;
    if process.force_sigsegv(blocked).is_err() {
        return Some(CompletionRoute::InvalidCompletion);
    }
    let mask = blocked.signals().without(Signal::SEGV);
    let _ = slot.store_blocked_then_read_pending(BlockedMask(mask.bits()), slot.pending());
    deliver_signal_on_syscall_return(task, process, frame, fpstate, machine)
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
        let restored = carrick_personality_linux::signal::restored_altstack(saved).unwrap();
        let flags = restored.flags;
        assert_eq!(flags, carrick_syscall_abi::LINUX_SS_AUTODISARM as u32);
    }
}
