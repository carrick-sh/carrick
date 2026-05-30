//! execve with NON-UTF-8 argv/env conformance probe.
//!
//! Linux argv/envp (and paths) are opaque NUL-terminated BYTE strings, not
//! UTF-8. A guest may legitimately pass non-UTF-8 bytes — e.g. CPython's
//! regrtest sets a non-ASCII `PYTHONREGRTEST_UNICODE_GUARD` env var, so every
//! subprocess spawn inherits it. carrick used to read argv/env as Rust `String`
//! and returned EINVAL when the bytes weren't valid UTF-8, so the execve failed
//! (OSError [Errno 22]) — which broke test_subprocess/select/wait3/struct/
//! itertools/base64. The fix carries argv/env as raw bytes through the execve
//! path.
//!
//! Deterministic: fork a child that execve's a no-op binary (/bin/true, which
//! ignores argv+env) with a non-UTF-8 arg AND a non-UTF-8 env var; the parent
//! reaps it. If execve honoured the bytes, /bin/true runs and exits 0; if carrick
//! still rejected them, the child's post-exec `_exit(127)` fires. Prints booleans.

use std::ffi::CString;
use std::ptr;

fn main() {
    // argv[1] and an env var both carry invalid-UTF-8 bytes (0xe7 0x77 0xf0,
    // exactly the regrtest guard shape). CString only forbids interior NULs —
    // non-UTF-8 is fine.
    let prog = CString::new("/bin/true").unwrap();
    let arg0 = CString::new("/bin/true").unwrap();
    let arg1 = CString::new(&b"weird-\xe7\x77\xf0"[..]).unwrap();
    let envv = CString::new(&b"CARRICK_GUARD=g-\xe7\x77\xf0"[..]).unwrap();

    let argv = [arg0.as_ptr(), arg1.as_ptr(), ptr::null()];
    let envp = [envv.as_ptr(), ptr::null()];

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: execve with the non-UTF-8 argv/env. If it returns, exec failed.
        unsafe {
            libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
            // Reached only if execve failed (e.g. carrick's old EINVAL path).
            libc::_exit(127);
        }
    }
    println!("forked={}", pid > 0);

    let mut status: libc::c_int = 0;
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    let exited = libc::WIFEXITED(status);
    let code = libc::WEXITSTATUS(status);
    println!("child_reaped={}", w == pid);
    // /bin/true exits 0 when execve honoured the non-UTF-8 argv/env; a 127 means
    // execve failed (the bug).
    println!("execve_nonutf8_ok={}", exited && code == 0);
}
