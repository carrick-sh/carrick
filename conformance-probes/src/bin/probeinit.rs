//! probeinit: TRANSPORT HELPER, not a probe (excluded from the gated set).
//!
//! The container-injection transport runs every probe as a CHILD of the
//! container init (`/bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p &&
//! /tmp/p'` — sh is ns-pid 1, the probe is its forked child at `/tmp/p`).
//! The native musl campaign cannot bootstrap through the image's dynamic
//! glibc utilities, so it binds the probe into the image and executes it
//! directly — which made the probe ITSELF ns-pid 1 and left `/tmp/p`
//! nonexistent, diverging from the oracle for any topology-sensitive probe
//! (`pidnsroot`: getppid()==1; `sigwaitalarm`: re-exec of the hardcoded
//! `/tmp/p`).
//!
//! This static musl helper restores the oracle's process shape as the
//! container command: fork `/tmp/p` (argv0 `/tmp/p`, inherited env + stdio,
//! stdin already at EOF), then behave like the pid-1 shell — reap every
//! child that reparents to it and propagate the probe's exit status
//! (`128+signal` for a signalled probe, sh-style).
fn main() {
    unsafe {
        let probe = libc::fork();
        if probe == 0 {
            let path = b"/tmp/p\0";
            let argv = [path.as_ptr() as *const libc::c_char, std::ptr::null()];
            libc::execv(path.as_ptr() as *const libc::c_char, argv.as_ptr());
            // Mirror sh's "command not found / not executable" exit codes.
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::_exit(if errno == libc::ENOENT { 127 } else { 126 });
        }
        if probe < 0 {
            eprintln!("probeinit: fork failed");
            libc::_exit(126);
        }
        loop {
            let mut status = 0;
            let reaped = libc::wait(&mut status);
            if reaped == probe {
                if libc::WIFEXITED(status) {
                    libc::_exit(libc::WEXITSTATUS(status));
                }
                if libc::WIFSIGNALED(status) {
                    libc::_exit(128 + libc::WTERMSIG(status));
                }
                libc::_exit(126);
            }
            if reaped < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                // ECHILD before the probe's own reap cannot happen (the probe
                // is our child); treat any other failure as fatal.
                eprintln!("probeinit: wait failed (errno {errno})");
                libc::_exit(126);
            }
            // A reparented orphan: reaped, keep waiting for the probe.
        }
    }
}
