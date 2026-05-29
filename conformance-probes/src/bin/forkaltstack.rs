//! sigaltstack(2) is inherited across fork(2) on Linux. carrick keys the
//! alternate signal stack by tid (dispatch/signal.rs:44) and the threaded fork
//! child gets a new tid (runtime.rs:1611), so the inherited altstack may be
//! lost. (The signal-MASK half of the same finding is REFUTED by maskfork.rs's
//! MATCH; this probe isolates the alternate-stack half, which no probe covers —
//! altstacktid.rs tests per-thread altstack and never forks.)

use conformance_probes::report;
use core::mem::MaybeUninit;

fn main() {
    unsafe {
        let mut stack = vec![0u8; libc::SIGSTKSZ];
        let ss = libc::stack_t {
            ss_sp: stack.as_mut_ptr() as *mut libc::c_void,
            ss_flags: 0,
            ss_size: stack.len(),
        };
        let set_ok = libc::sigaltstack(&ss, core::ptr::null_mut()) == 0;

        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            let mut cur: libc::stack_t = MaybeUninit::zeroed().assume_init();
            libc::sigaltstack(core::ptr::null(), &mut cur);
            // Inherited iff ss_sp is set and SS_DISABLE is clear.
            let inherited = !cur.ss_sp.is_null() && (cur.ss_flags & libc::SS_DISABLE) == 0;
            let b = [inherited as u8];
            libc::write(fds[1], b.as_ptr() as *const libc::c_void, 1);
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut b = [0u8; 1];
        libc::read(fds[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        let mut st = 0;
        while libc::wait4(pid, &mut st, 0, core::ptr::null_mut()) < 0 {}
        report!(
            parent_set_altstack_ok = set_ok,
            // Linux: true. carrick (if bug): false.
            child_inherits_altstack = b[0] != 0,
        );
    }
}
