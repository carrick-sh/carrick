//! execve(2) signal-disposition reset. Linux contract (signal(7)): across an
//! execve, the dispositions of CAUGHT signals are reset to SIG_DFL, while the
//! dispositions of IGNORED signals are left unchanged. A lib test covers the
//! dispatcher's reset logic; this pins the guest-visible behaviour end to end
//! through a real execve.
//!
//! The probe runs in two phases. The first phase installs a handler for SIGUSR1
//! (caught) and SIG_IGN for SIGUSR2 (ignored), then re-execs itself with an
//! `post` marker arg. The second phase (argv[1] == "post") reports the inherited
//! dispositions: SIGUSR1 must be back to SIG_DFL, SIGUSR2 must still be SIG_IGN.
//!
//! Deterministic booleans only (never pids/addresses/timing), so the harness can
//! diff carrick against real Linux line-for-line. A failed execve emits the same
//! keys as `false` rather than hanging or printing nothing.

use std::ffi::CString;

extern "C" fn caught(_sig: i32) {}

/// Current disposition (`sa_handler`) for `sig` via `sigaction(sig, NULL, &old)`.
unsafe fn disposition(sig: i32) -> usize {
    let mut old: libc::sigaction = std::mem::zeroed();
    libc::sigaction(sig, std::ptr::null(), &mut old);
    old.sa_sigaction
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Phase 2: post-exec. Report the dispositions inherited across execve.
    if args.get(1).map(String::as_str) == Some("post") {
        unsafe {
            let usr1_reset = disposition(libc::SIGUSR1) == libc::SIG_DFL;
            let usr2_preserved = disposition(libc::SIGUSR2) == libc::SIG_IGN;
            println!("execve_caught_handler_reset_to_dfl={usr1_reset}");
            println!("execve_ignored_disposition_preserved={usr2_preserved}");
        }
        return;
    }

    // Phase 1: install a caught handler for SIGUSR1 and SIG_IGN for SIGUSR2,
    // then re-exec ourselves with the `post` marker.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = caught as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

        let mut ign: libc::sigaction = std::mem::zeroed();
        ign.sa_sigaction = libc::SIG_IGN;
        ign.sa_flags = 0;
        libc::sigemptyset(&mut ign.sa_mask);
        libc::sigaction(libc::SIGUSR2, &ign, std::ptr::null_mut());

        // Re-exec via argv[0] (the harness invokes the probe by absolute path)
        // with the marker arg. An empty environment is sufficient — the post
        // phase only inspects signal dispositions.
        let prog =
            CString::new(args[0].clone()).unwrap_or_else(|_| CString::new("/tmp/p").unwrap());
        let post = CString::new("post").unwrap();
        let argv = [prog.as_ptr(), post.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }

    // execve only returns on failure — emit the keys as false so a broken exec
    // path shows up as a divergence, not as missing output.
    println!("execve_caught_handler_reset_to_dfl=false");
    println!("execve_ignored_disposition_preserved=false");
}
