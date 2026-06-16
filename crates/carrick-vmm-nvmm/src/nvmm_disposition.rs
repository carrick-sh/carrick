//! NVMM glue for mirroring guest signal dispositions onto NetBSD host handlers.

use std::os::raw::c_int;

use carrick_signal_core::host_disposition;

use crate::nvmm_signum::{host_to_linux_signum, linux_to_host_signum};

pub fn is_nvmm_claimed(linux_signum: i32) -> bool {
    if matches!(linux_signum, 1 | 2 | 3 | 15) {
        return true;
    }
    if linux_signum == carrick_abi::LINUX_SIGCHLD {
        return true;
    }
    if linux_signum == carrick_abi::LINUX_SIGPIPE {
        return true;
    }
    linux_signum == crate::nvmm_kicker::kick_signal()
        || linux_signum == crate::nvmm_xsig::nudge_signum()
}

fn nvmm_routable(linux_signum: i32) -> bool {
    host_disposition::is_host_routable(linux_signum) && !is_nvmm_claimed(linux_signum)
}

extern "C" fn nvmm_routed_handler(
    host_signum: c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let linux_signum = host_to_linux_signum(host_signum);
    if !info.is_null() {
        // SAFETY: kernel supplies a valid siginfo_t to SA_SIGINFO handlers.
        carrick_signal_core::record_sender(linux_signum, unsafe { (*info).si_pid() });
    }
    if let Some(bit) = carrick_signal_core::pending_bit(linux_signum) {
        carrick_signal_core::proc_pending_fetch_or(bit);
    }
    crate::nvmm_signal_pump::poke();
}

pub fn ensure_host_handler(linux_signum: i32) {
    if !nvmm_routable(linux_signum) {
        return;
    }
    if host_disposition::mark_installed(linux_signum) {
        return;
    }
    install_sigaction(
        linux_signum,
        nvmm_routed_handler as *const () as libc::sighandler_t,
    );
}

pub fn set_host_ignore(linux_signum: i32) {
    if !nvmm_routable(linux_signum) {
        return;
    }
    install_sigaction(linux_signum, libc::SIG_IGN);
    host_disposition::clear_installed(linux_signum);
}

pub fn set_host_default(linux_signum: i32) {
    if !nvmm_routable(linux_signum) {
        return;
    }
    install_sigaction(linux_signum, libc::SIG_DFL);
    host_disposition::clear_installed(linux_signum);
}

pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    let installed = host_disposition::installed_mask();
    for linux_signum in 1..=64i32 {
        let install_bit = 1u64 << (linux_signum - 1);
        if installed & install_bit == 0 || is_nvmm_claimed(linux_signum) {
            continue;
        }
        let ignored_bit = 1u64 << linux_signum;
        if ignored_mask & ignored_bit != 0 {
            continue;
        }
        install_sigaction(linux_signum, libc::SIG_DFL);
        host_disposition::clear_installed(linux_signum);
    }
}

fn install_sigaction(linux_signum: i32, handler: libc::sighandler_t) {
    let host_signum = linux_to_host_signum(linux_signum);
    let is_action = handler != libc::SIG_IGN && handler != libc::SIG_DFL;
    // SAFETY: zeroed sigaction is the documented empty action form; host_signum
    // is derived from a routable Linux signum.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = if is_action {
            libc::SA_RESTART | libc::SA_SIGINFO
        } else {
            0
        };
        libc::sigaction(host_signum, &action, std::ptr::null_mut());
    }
}
