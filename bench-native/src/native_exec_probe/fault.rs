use super::errno;
use super::report::{ProbeReport, Status};
use std::sync::atomic::{AtomicBool, Ordering};

static IN_GUEST_WINDOW: AtomicBool = AtomicBool::new(false);

pub fn fault_discriminator() -> Result<ProbeReport, String> {
    let guest_code = run_fault_child(true)?;
    let host_code = run_fault_child(false)?;

    let status = if guest_code == 90 && host_code == 91 {
        Status::Pass
    } else {
        Status::Fail
    };

    Ok(ProbeReport::new("fault-discriminator", status)
        .field("guest_fault_exit", guest_code)
        .field("host_fault_exit", host_code))
}

fn run_fault_child(mark_guest: bool) -> Result<i32, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: errno={}", errno()));
    }

    if pid == 0 {
        child_fault(mark_guest);
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Err(format!("waitpid failed: waitpid={wait} errno={}", errno()));
    }

    if libc::WIFEXITED(status_word) {
        Ok(libc::WEXITSTATUS(status_word))
    } else {
        Ok(128)
    }
}

fn child_fault(mark_guest: bool) -> ! {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = fault_handler as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(88);
        }
        if libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(89);
        }

        IN_GUEST_WINDOW.store(mark_guest, Ordering::SeqCst);
        std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1);
        libc::_exit(87);
    }
}

extern "C" fn fault_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _uap: *mut libc::c_void,
) {
    let in_guest = IN_GUEST_WINDOW.load(Ordering::SeqCst);
    unsafe {
        libc::_exit(if in_guest { 90 } else { 91 });
    }
}
