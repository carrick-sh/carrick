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

static FAULT_SIGNAL: AtomicI32 = AtomicI32::new(0);
static FAULT_CODE: AtomicI32 = AtomicI32::new(0);
static FAULT_ADDRESS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn fault_handler(signal: i32, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    unsafe {
        FAULT_SIGNAL.store(signal, Ordering::SeqCst);
        FAULT_CODE.store((*info).si_code, Ordering::SeqCst);
        FAULT_ADDRESS.store((*info).si_addr() as usize, Ordering::SeqCst);
        siglongjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1);
    }
}

/// Real faulting instruction, with no Rust reference to inaccessible storage.
unsafe fn fault_read(address: *mut libc::c_void) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("ldr xzr, [{address}]", address = in(reg) address, options(nostack));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov al, byte ptr [{address}]", address = in(reg) address, out("al") _, options(nostack));
    }
}

/// The root handles MAPERR and a file-backed BUS_ADRERR, then returns through
/// libc siglongjmp. Default/blocked termination is covered by the native-owner
/// component bindings and the signed crash/core fixture.
static REAP_CHILD: AtomicI32 = AtomicI32::new(0);
extern "C" fn reap_deadline(_: i32) {
    unsafe {
        let child = REAP_CHILD.load(Ordering::SeqCst);
        if child > 0 {
            libc::kill(child, libc::SIGKILL);
        }
        libc::_exit(124);
    }
}

extern "C" fn unexpected_fault_handler(_: i32) {
    unsafe {
        libc::_exit(99);
    }
}

unsafe fn fault_termination(blocked: bool) -> i32 {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let address = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if address == libc::MAP_FAILED || libc::munmap(address, page) != 0 {
            return -errno();
        }
        let mut pipe = [-1; 2];
        if libc::pipe(pipe.as_mut_ptr()) != 0 {
            return -errno();
        }
        let child = libc::fork();
        if child == 0 {
            libc::close(pipe[0]);
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = if blocked {
                unexpected_fault_handler as *const () as usize
            } else {
                libc::SIG_DFL
            };
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGSEGV, &action, core::ptr::null_mut()) != 0 {
                libc::_exit(98);
            }
            if blocked {
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGSEGV);
                if libc::sigprocmask(libc::SIG_BLOCK, &mask, core::ptr::null_mut()) != 0 {
                    libc::_exit(97);
                }
            }
            fault_read(address);
            libc::_exit(96);
        }
        libc::close(pipe[1]);
        if child < 0 {
            libc::close(pipe[0]);
            return -errno();
        }
        let mut pfd = libc::pollfd {
            fd: pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        let completed = libc::poll(&mut pfd, 1, 5000) > 0 && pfd.revents & libc::POLLHUP != 0;
        libc::close(pipe[0]);
        if !completed {
            libc::kill(child, libc::SIGKILL);
        }
        // The pipe bounds fault completion. Independently bound reaping too:
        // a broken guest exit path must fail the fixture rather than hang it.
        REAP_CHILD.store(child, Ordering::SeqCst);
        let mut deadline: libc::sigaction = std::mem::zeroed();
        deadline.sa_sigaction = reap_deadline as *const () as usize;
        libc::sigemptyset(&mut deadline.sa_mask);
        if libc::sigaction(libc::SIGALRM, &deadline, core::ptr::null_mut()) != 0 {
            libc::kill(child, libc::SIGKILL);
            libc::_exit(125);
        }
        libc::alarm(5);
        let mut status = 0;
        let waited = libc::waitpid(child, &mut status, 0) == child;
        libc::alarm(0);
        REAP_CHILD.store(0, Ordering::SeqCst);
        if completed && waited && libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else if waited && libc::WIFEXITED(status) {
            1000 + libc::WEXITSTATUS(status)
        } else {
            -1
        }
    }
}

unsafe fn classified_faults() {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = fault_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        let installed = libc::sigaction(libc::SIGSEGV, &action, core::ptr::null_mut()) == 0
            && libc::sigaction(libc::SIGBUS, &action, core::ptr::null_mut()) == 0;
        let mapped = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let unmapped = mapped != libc::MAP_FAILED && libc::munmap(mapped, page) == 0;
        let maperr_returned = if installed
            && unmapped
            && c_sigsetjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) == 0
        {
            fault_read(mapped);
            false
        } else {
            installed && unmapped
        };
        report!(
            maperr_siglongjmp = maperr_returned,
            maperr_signal = FAULT_SIGNAL.load(Ordering::SeqCst),
            maperr_si_code = FAULT_CODE.load(Ordering::SeqCst),
            maperr_si_addr_matches = FAULT_ADDRESS.load(Ordering::SeqCst) == mapped as usize,
        );
        let mut name = *b"/tmp/carrick-fault-XXXXXX\0";
        let fd = libc::mkstemp(name.as_mut_ptr().cast());
        let mut mapping = libc::MAP_FAILED;
        if fd >= 0 {
            libc::unlink(name.as_ptr().cast());
            if libc::ftruncate(fd, page as libc::off_t) == 0 {
                mapping = libc::mmap(
                    core::ptr::null_mut(),
                    2 * page,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
            }
            libc::close(fd);
        }
        let setup_errno = if mapping == libc::MAP_FAILED {
            errno()
        } else {
            0
        };
        let address = mapping.wrapping_byte_add(page);
        FAULT_SIGNAL.store(0, Ordering::SeqCst);
        FAULT_CODE.store(0, Ordering::SeqCst);
        let bus_returned = if installed
            && mapping != libc::MAP_FAILED
            && c_sigsetjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) == 0
        {
            fault_read(address);
            false
        } else {
            installed && mapping != libc::MAP_FAILED
        };
        report!(
            bus_setup_errno = setup_errno,
            bus_siglongjmp = bus_returned,
            bus_signal = FAULT_SIGNAL.load(Ordering::SeqCst),
            bus_si_code = FAULT_CODE.load(Ordering::SeqCst),
            bus_si_addr_matches = FAULT_ADDRESS.load(Ordering::SeqCst) == address as usize,
        );
        if mapping != libc::MAP_FAILED {
            libc::munmap(mapping, 2 * page);
        }
    }
}

fn main() {
    unsafe {
        classified_faults();
        let default_signal = fault_termination(false);
        let blocked_signal = fault_termination(true);
        report!(
            default_fault_signal = default_signal,
            blocked_fault_signal = blocked_signal
        );
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
