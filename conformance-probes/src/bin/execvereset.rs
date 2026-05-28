//! execve(2) signal-disposition reset. Linux semantics on exec:
//!   * caught handlers (sa_handler == real address) -> reset to SIG_DFL
//!   * SIG_IGN dispositions -> preserved
//!   * the blocked signal mask -> preserved
//!   * blocked pending signals -> preserved across the exec
//!   * the alternate signal stack -> empirically PRESERVED (Linux current
//!     behavior; the man page's "not preserved" wording predates the kernel)
//!
//! Carrick's old image's handler ADDRESS used to leak into the new image; when
//! the new image then took the signal, carrick jumped to that stale address.
//! This stands in for the LTP shell-wrapped-test "mass segfault" class (the
//! 34e1c9a fix) that bit dash's SIGCHLD handler through every `/bin/sh -c CMD`.
//!
//! Single-binary probe with two stages: stage1 sets the dispositions up and
//! `execve`s itself with arg "stage2"; stage2 queries the new image's state and
//! prints booleans the harness diffs against real Linux line-for-line.

use conformance_probes::{
    block_signal, current_disposition, errno, install_handler, install_ign, is_blocked, is_pending,
    report,
};
use std::env;
use std::ffi::CString;

extern "C" fn caught_handler(_: i32) {
    // A REAL handler address — the bug was carrick leaking *this* address into
    // the new image's handler table after execve. Body is irrelevant; we never
    // invoke it (the signal is raised after stage2's exec, with default-disp).
}

unsafe fn arm_altstack(buf: &mut [u8]) -> bool {
    let ss = libc::stack_t {
        ss_sp: buf.as_mut_ptr() as *mut libc::c_void,
        ss_flags: 0,
        ss_size: buf.len(),
    };
    libc::sigaltstack(&ss, core::ptr::null_mut()) == 0
}

fn stage1(exe_arg: &str) {
    unsafe {
        // Caught SIGCHLD: the dash-handler class — must reset to SIG_DFL.
        let _ = install_handler(libc::SIGCHLD, caught_handler, 0);
        // Another caught (real handler address) on SIGUSR2 to double-check.
        let _ = install_handler(libc::SIGUSR2, caught_handler, 0);
        // SIG_IGN for SIGPIPE: must SURVIVE execve.
        let _ = install_ign(libc::SIGPIPE);

        // Alt signal stack. Leak the buf — execve replaces the address space
        // immediately, so this isn't a real leak; sigaltstack only stored the
        // pointer/size in the kernel's task struct (which Linux preserves).
        let mut stack_buf: Vec<u8> = vec![0; 64 * 1024];
        let alt_armed = arm_altstack(&mut stack_buf);
        core::mem::forget(stack_buf);
        if !alt_armed {
            report!(stage1_altstack_armed = false);
            std::process::exit(2);
        }

        // Blocked mask: must SURVIVE. Then raise pending SIGUSR1 - blocked +
        // pending should also survive (Linux preserves the queued signal across
        // the exec for the new image to handle/unblock).
        let _ = block_signal(libc::SIGUSR1);
        libc::raise(libc::SIGUSR1);

        // execve self with stage2 arg.
        let path = CString::new(exe_arg).expect("argv[0]");
        let stage2_arg = CString::new("stage2").expect("stage2");
        let argv: [*const libc::c_char; 3] = [path.as_ptr(), stage2_arg.as_ptr(), core::ptr::null()];
        let env = CString::new("CARRICK_EXECVE_MARK=1").expect("env");
        let envp: [*const libc::c_char; 2] = [env.as_ptr(), core::ptr::null()];
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        // Only reached if execve fails.
        report!(stage1_execve_failed_errno = errno());
        std::process::exit(3);
    }
}

fn stage2() {
    unsafe {
        let sigchld_reset_to_dfl = current_disposition(libc::SIGCHLD) == libc::SIG_DFL;
        let sigusr2_reset_to_dfl = current_disposition(libc::SIGUSR2) == libc::SIG_DFL;
        let sigpipe_still_ign = current_disposition(libc::SIGPIPE) == libc::SIG_IGN;

        let mut alt: libc::stack_t = std::mem::zeroed();
        libc::sigaltstack(core::ptr::null(), &mut alt);
        let altstack_size_is_zero = alt.ss_size == 0;
        let altstack_sp_is_null = alt.ss_sp.is_null();
        let altstack_flag_disabled = (alt.ss_flags & libc::SS_DISABLE) != 0;

        let sigusr1_mask_preserved = is_blocked(libc::SIGUSR1);
        let sigusr1_pending_preserved = is_pending(libc::SIGUSR1);

        report!(
            sigchld_reset_to_dfl = sigchld_reset_to_dfl,
            sigusr2_reset_to_dfl = sigusr2_reset_to_dfl,
            sigpipe_still_ign = sigpipe_still_ign,
            altstack_size_is_zero = altstack_size_is_zero,
            altstack_sp_is_null = altstack_sp_is_null,
            altstack_flag_disabled = altstack_flag_disabled,
            sigusr1_mask_preserved = sigusr1_mask_preserved,
            sigusr1_pending_preserved = sigusr1_pending_preserved,
        );
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let stage = args.get(1).map(String::as_str).unwrap_or("stage1");
    match stage {
        "stage1" => {
            let exe = args.first().map(String::as_str).unwrap_or("/tmp/p");
            stage1(exe);
        }
        "stage2" => stage2(),
        other => println!("unknown_stage={other}"),
    }
}
