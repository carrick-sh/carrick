use super::errno;
use super::report::{ProbeReport, Status};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UcontextSnapshot {
    x: [u64; 9],
    sp: u64,
    pc: u64,
}

unsafe extern "C" {
    fn carrick_snapshot_ucontext(uap: *mut libc::c_void, out: *mut UcontextSnapshot)
        -> libc::c_int;
}

pub fn brk_trap() -> Result<ProbeReport, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("brk-trap", Status::Fail).field("fork_errno", errno()));
    }

    if pid == 0 {
        child_brk_trap();
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("brk-trap", Status::Fail)
            .field("waitpid", wait)
            .field("errno", errno()));
    }

    if libc::WIFEXITED(status_word) {
        let code = libc::WEXITSTATUS(status_word);
        let status = if code == 0 {
            Status::Pass
        } else {
            Status::Fail
        };
        return Ok(ProbeReport::new("brk-trap", status).field("child_exit", code));
    }

    Ok(ProbeReport::new("brk-trap", Status::Fail).field("status_word", status_word))
}

fn child_brk_trap() -> ! {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = brk_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(80);
        }

        std::arch::asm!(
            "mov x0, #123",
            "mov x8, #172",
            "brk #0xf000",
            options(nostack)
        );

        libc::_exit(81);
    }
}

extern "C" fn brk_handler(_sig: libc::c_int, _info: *mut libc::siginfo_t, uap: *mut libc::c_void) {
    let mut snapshot = UcontextSnapshot::default();
    let rc = unsafe { carrick_snapshot_ucontext(uap, &mut snapshot) };
    let ok = rc == 0 && snapshot.x[0] == 123 && snapshot.x[8] == 172 && snapshot.pc != 0;
    unsafe {
        libc::_exit(if ok { 0 } else { 82 });
    }
}
