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
//! Deterministic: fork a child that execve's this probe into a marker mode with
//! a non-UTF-8 arg AND a non-UTF-8 env var; the parent reaps it. If execve
//! honoured the bytes, the marker validates them and exits 0; if carrick
//! still rejected them, the child's post-exec `_exit(127)` fires. Prints booleans.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::ptr;

fn main() {
    const ARG_BYTES: &[u8] = b"weird-\xe7\x77\xf0";
    const ENV_BYTES: &[u8] = b"g-\xe7\x77\xf0";
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg.as_os_str().as_bytes() == ARG_BYTES)
    {
        let env_ok = std::env::var_os("CARRICK_GUARD")
            .is_some_and(|value| value.as_os_str().as_bytes() == ENV_BYTES);
        std::process::exit(if env_ok { 0 } else { 126 });
    }

    // argv[1] and an env var both carry invalid-UTF-8 bytes (0xe7 0x77 0xf0,
    // exactly the regrtest guard shape). CString only forbids interior NULs —
    // non-UTF-8 is fine.
    let prog = CString::new(std::env::args().next().unwrap_or_default()).unwrap();
    let arg0 = prog.clone();
    let arg1 = CString::new(ARG_BYTES).unwrap();
    let envv = CString::new([b"CARRICK_GUARD=".as_slice(), ENV_BYTES].concat()).unwrap();

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
    // The marker mode exits 0 when execve preserved the non-UTF-8 argv/env; a
    // 127 means execve failed (the bug).
    println!("execve_nonutf8_ok={}", exited && code == 0);
}
