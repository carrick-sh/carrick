//! Native stack and saved-context binding pending the CPL0 context owner.

use super::{ArchError, X86Backend};
use carrick_guest_arch::{
    EntryBackend, EntryEvent, KernelStackPointer, NativeEntrySnapshot, NativeReturnWord,
    ReturnKind, UserFlags, UserReturn, UserVa,
};

#[path = "../../../../carrick-x86/src/cpl0_entry.rs"]
pub mod native;
#[path = "../../../../carrick-x86/src/cpl0_scheduler.rs"]
#[allow(dead_code)] // Linked CPL0 callers use the public TLS and XSAVE leaves.
pub mod scheduler;

impl EntryBackend for X86Backend {
    fn current_stack_pointer(&mut self) -> Result<KernelStackPointer, Self::Error> {
        let sp: u64;
        // SAFETY: CPL0 reads its current kernel stack pointer without changing
        // the stack or memory; the caller still authenticates its CPU binding.
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        Ok(KernelStackPointer::new(sp))
    }
    fn decode_entry(&mut self, frame: &Self::NativeFrame) -> Result<EntryEvent, Self::Error> {
        if frame.valid_user_return() {
            Ok(EntryEvent::Syscall)
        } else {
            Err(ArchError::InvalidFrame)
        }
    }
    fn snapshot<'a>(
        &mut self,
        frame: &'a Self::NativeFrame,
    ) -> Result<NativeEntrySnapshot<'a, Self::NativeFrame>, Self::Error> {
        Ok(frame.snapshot())
    }
    fn set_result(
        &mut self,
        frame: &mut Self::NativeFrame,
        result: NativeReturnWord,
    ) -> Result<(), Self::Error> {
        frame.rax = result.0;
        Ok(())
    }
    fn save_context(
        &mut self,
        _frame: &Self::NativeFrame,
    ) -> Result<Self::SavedContext, Self::Error> {
        carrick_x86_unbound_thread_cpu()
    }
    fn load_context(
        &mut self,
        _frame: &mut Self::NativeFrame,
        _saved: &Self::SavedContext,
    ) -> Result<(), Self::Error> {
        carrick_x86_unbound_thread_cpu()
    }
    fn prepare_user_return(
        &mut self,
        frame: &Self::NativeFrame,
    ) -> Result<UserReturn, Self::Error> {
        if !frame.valid_user_return() {
            return Err(ArchError::InvalidFrame);
        }
        Ok(UserReturn {
            pc: UserVa::new(frame.rcx),
            stack: UserVa::new(frame.rsp),
            flags: UserFlags::new(frame.r11),
            kind: ReturnKind::ExceptionReturn,
        })
    }
}

/// No x86 slot binding has been published for the ARM stack-slot caller.
#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_stack_slot() -> ! {
    // SAFETY: an unsupported guest-kernel path must fault at CPL0 rather
    // than returning an unauthenticated stack slot.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// The ARM ThreadCpu record must never be interpreted as x86 context.
#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_thread_cpu() -> ! {
    // SAFETY: the invalid context path must stop before state publication.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
