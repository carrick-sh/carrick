//! Leaving an `SA_ONSTACK` handler with `siglongjmp` must not leave the thread
//! permanently marked as executing on the alternate signal stack.
//!
//! Linux treats the handler as gone once userspace jumps back to the saved
//! context: a later `sigaltstack(NULL, &old)` query does not report
//! `SS_ONSTACK`, changing the altstack is allowed, and a later signal can use
//! the configured altstack again. Carrick used to track altstack activity only
//! with frames popped by `rt_sigreturn`, so `siglongjmp` stranded stale
//! `SS_ONSTACK` state.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

const ALT_SIZE: usize = 64 * 1024;

#[repr(align(16))]
#[allow(dead_code)]
struct JumpBuf([usize; 64]);

static mut JUMP_BUF: JumpBuf = JumpBuf([0; 64]);
static mut ALT1: [u8; ALT_SIZE] = [0; ALT_SIZE];
static mut ALT2: [u8; ALT_SIZE] = [0; ALT_SIZE];

static MODE: AtomicI32 = AtomicI32::new(0);
static FIRST_SP: AtomicUsize = AtomicUsize::new(0);
static SECOND_SP: AtomicUsize = AtomicUsize::new(0);
static FIRST_SEEN: AtomicI32 = AtomicI32::new(0);
static SECOND_SEEN: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" {
    #[link_name = "__sigsetjmp"]
    fn c_sigsetjmp(env: *mut libc::c_void, savesigs: libc::c_int) -> libc::c_int;
    fn siglongjmp(env: *mut libc::c_void, val: libc::c_int) -> !;
}

extern "C" fn handler(_sig: i32) {
    let local = 0u8;
    let sp = &local as *const u8 as usize;
    match MODE.load(Ordering::SeqCst) {
        1 => {
            FIRST_SEEN.store(1, Ordering::SeqCst);
            FIRST_SP.store(sp, Ordering::SeqCst);
            unsafe {
                siglongjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1);
            }
        }
        2 => {
            SECOND_SEEN.store(1, Ordering::SeqCst);
            SECOND_SP.store(sp, Ordering::SeqCst);
        }
        _ => {}
    }
}

fn ptr_in_range(ptr: usize, base: *mut u8, len: usize) -> bool {
    let start = base as usize;
    let end = start.saturating_add(len);
    ptr >= start && ptr < end
}

unsafe fn query_onstack() -> Option<bool> {
    let mut old: libc::stack_t = std::mem::zeroed();
    if libc::sigaltstack(core::ptr::null(), &mut old) != 0 {
        return None;
    }
    Some((old.ss_flags & libc::SS_ONSTACK) != 0)
}

fn main() {
    unsafe {
        let alt1 = core::ptr::addr_of_mut!(ALT1).cast::<u8>();
        let alt2 = core::ptr::addr_of_mut!(ALT2).cast::<u8>();
        let ss1 = libc::stack_t {
            ss_sp: alt1.cast::<libc::c_void>(),
            ss_flags: 0,
            ss_size: ALT_SIZE,
        };
        let ss2 = libc::stack_t {
            ss_sp: alt2.cast::<libc::c_void>(),
            ss_flags: 0,
            ss_size: ALT_SIZE,
        };

        let altstack_ok = libc::sigaltstack(&ss1, core::ptr::null_mut()) == 0;
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        let install_ok = libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut()) == 0;

        MODE.store(1, Ordering::SeqCst);
        let jumped = if c_sigsetjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) == 0 {
            libc::raise(libc::SIGUSR1);
            false
        } else {
            true
        };
        MODE.store(0, Ordering::SeqCst);

        let after_jump_onstack = query_onstack();
        let replace_rc = libc::sigaltstack(&ss2, core::ptr::null_mut());
        let replace_errno = if replace_rc == 0 { 0 } else { errno() };

        MODE.store(2, Ordering::SeqCst);
        libc::raise(libc::SIGUSR1);
        MODE.store(0, Ordering::SeqCst);
        let after_second_onstack = query_onstack();

        let first_sp = FIRST_SP.load(Ordering::SeqCst);
        let second_sp = SECOND_SP.load(Ordering::SeqCst);

        report!(
            altstack_ok = altstack_ok,
            install_ok = install_ok,
            first_handler_seen = FIRST_SEEN.load(Ordering::SeqCst) == 1,
            first_handler_on_alt = ptr_in_range(first_sp, alt1, ALT_SIZE),
            siglongjmp_returned = jumped,
            after_longjmp_not_onstack = after_jump_onstack == Some(false),
            replace_altstack_ok = replace_rc == 0,
            replace_altstack_errno = replace_errno,
            second_handler_seen = SECOND_SEEN.load(Ordering::SeqCst) == 1,
            second_handler_on_replaced_alt = ptr_in_range(second_sp, alt2, ALT_SIZE),
            after_second_not_onstack = after_second_onstack == Some(false),
        );
    }
}
