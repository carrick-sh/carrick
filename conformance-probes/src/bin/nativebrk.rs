//! Guest-authored AArch64 BRK remains an ordinary Linux SIGTRAP after Carrick's
//! private BRK transport is removed.

#[cfg(target_arch = "aarch64")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "aarch64")]
static DELIVERED: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "aarch64")]
static TRAP_BRKPT: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "aarch64")]
extern "C" fn handler(_signal: i32, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    unsafe {
        DELIVERED.store(true, Ordering::SeqCst);
        TRAP_BRKPT.store((*info).si_code == libc::TRAP_BRKPT, Ordering::SeqCst);
        let context = context.cast::<libc::ucontext_t>();
        (*context).uc_mcontext.pc = (*context).uc_mcontext.pc.wrapping_add(4);
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn execute_guest_brk() {
    core::arch::asm!("brk #0x1234", options(nostack));
}

#[cfg(target_arch = "aarch64")]
fn main() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()) != 0 {
            println!("sigaction_failed=true");
            return;
        }
        execute_guest_brk();
    }

    println!("delivered_sigtrap={}", DELIVERED.load(Ordering::SeqCst));
    println!("si_code_trap_brkpt={}", TRAP_BRKPT.load(Ordering::SeqCst));
    println!("resumed_after_brk=true");
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("nativebrk requires aarch64");
}
