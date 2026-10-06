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

/// Native syscall-return state. The caller keeps its task and MM custody;
/// this value owns only machine registers captured on the current CPL0 CPU.
pub struct SavedSyscallContext {
    frame: native::NativeFrame,
    fs_base: u64,
    gs_base: u64,
    xsave: scheduler::XsaveArea,
}

const _: () = assert!(core::mem::align_of::<scheduler::XsaveArea>() == 64);

#[path = "context_words.rs"]
pub mod context_words;
pub use context_words::ParkedContextWords;

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
        frame: &Self::NativeFrame,
    ) -> Result<Self::SavedContext, Self::Error> {
        if !frame.valid_user_return() {
            return Err(ArchError::InvalidFrame);
        }
        let fs_base = scheduler::read_tls(scheduler::NativeTlsRegister::Fs);
        let gs_base = scheduler::read_tls(scheduler::NativeTlsRegister::UserGs);
        let mut xsave = scheduler::XsaveArea::ZERO;
        scheduler::save_extended(&mut xsave);
        Ok(SavedSyscallContext {
            frame: *frame,
            fs_base,
            gs_base,
            xsave,
        })
    }
    fn load_context(
        &mut self,
        frame: &mut Self::NativeFrame,
        saved: &Self::SavedContext,
    ) -> Result<(), Self::Error> {
        if !saved.frame.valid_user_return() {
            return Err(ArchError::InvalidFrame);
        }
        scheduler::write_tls(scheduler::NativeTlsRegister::Fs, saved.fs_base);
        scheduler::write_tls(scheduler::NativeTlsRegister::UserGs, saved.gs_base);
        scheduler::restore_extended(&saved.xsave);
        *frame = saved.frame;
        Ok(())
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

/// Read the current CPU binding published through GS:[16].
#[inline(always)]
pub fn current_cpu_binding() -> Option<&'static native::CpuBinding> {
    let binding_address: u64;
    // SAFETY: SWAPGS has installed the retained per-vCPU binding before
    // any shared-kernel entry; GS:[16] is its immutable self pointer.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[16]",
            out(reg) binding_address,
            options(nostack, preserves_flags)
        );
    }
    if binding_address == 0 {
        return None;
    }
    // SAFETY: stopped-host bootstrap owns this binding through vCPU
    // retirement. Its slot is immutable after publication.
    Some(unsafe { &*(binding_address as *const native::CpuBinding) })
}

/// The current CPU's supervisor stack slot index.
pub fn current_stack_slot() -> Option<usize> {
    let binding = current_cpu_binding()?;
    let sp: u64;
    // SAFETY: CPL0 reads its current stack pointer.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    let stack_end = binding.kernel_stack.checked_add(16)?;
    if sp < stack_end.checked_sub(0x1_0000)? || sp > stack_end {
        return None;
    }
    Some(binding.cpu_slot as usize)
}

/// The current CPU's thread CPU identifier.
pub fn current_thread_cpu() -> u64 {
    current_cpu_binding().map_or(0, |b| b.cpu_slot as u64)
}

/// A CPL0-only fixture syscall that exercises this shared kernel context module.
pub const CONTEXT_WITNESS: u64 = 0xffff_ffff_ffff_ff30;

pub fn witness(op: u64) -> u64 {
    match op {
        0 => current_stack_slot().map_or(u64::MAX, |s| s as u64),
        1 => current_thread_cpu(),
        _ => u64::MAX,
    }
}
