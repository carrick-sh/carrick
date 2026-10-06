//! Native stack and saved-context binding pending the CPL0 context owner.

use super::X86Backend;
use carrick_guest_arch::{
    EntryBackend, EntryEvent, KernelStackPointer, NativeEntrySnapshot, NativeReturnWord, UserReturn,
};

impl EntryBackend for X86Backend {
    fn current_stack_pointer(&mut self) -> Result<KernelStackPointer, Self::Error> {
        carrick_x86_unbound_stack_slot()
    }
    fn decode_entry(&mut self, _frame: &Self::NativeFrame) -> Result<EntryEvent, Self::Error> {
        carrick_x86_unbound_thread_cpu()
    }
    fn snapshot(
        &mut self,
        _frame: &Self::NativeFrame,
    ) -> Result<NativeEntrySnapshot<'_, Self::NativeFrame>, Self::Error> {
        carrick_x86_unbound_thread_cpu()
    }
    fn set_result(
        &mut self,
        _frame: &mut Self::NativeFrame,
        _result: NativeReturnWord,
    ) -> Result<(), Self::Error> {
        carrick_x86_unbound_thread_cpu()
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
        _frame: &Self::NativeFrame,
    ) -> Result<UserReturn, Self::Error> {
        carrick_x86_unbound_thread_cpu()
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
