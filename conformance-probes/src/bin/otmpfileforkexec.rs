//! O_TMPFILE fork+exec coherence probe.
//!
//! Models test_faulthandler's pattern: open an unnamed temp file
//! (`tempfile.TemporaryFile()` == `open(dir, O_TMPFILE|O_RDWR)`), hand the fd
//! to a FORKED + EXEC'd subprocess that writes a known payload to it, then the
//! PARENT lseeks to 0 and reads the payload back. This ONLY works if the fd is
//! a real kernel fd shared across fork(2) and inherited across exec(2): an
//! in-memory per-process model loses the child's write entirely.
//!
//! Steps, all reported as booleans (deterministic):
//!   open_ok        — O_TMPFILE|O_RDWR open succeeded
//!   rdonly_einval  — O_RDONLY|O_TMPFILE is rejected with EINVAL (kernel rule)
//!   child_status0  — the exec'd child exited 0 (it wrote + closed cleanly)
//!   parent_readback— the parent read back EXACTLY the bytes the child wrote
//!
//! On real Linux all four are true. Under carrick they are true iff O_TMPFILE
//! is backed by a fork+exec-coherent host fd.

use std::ffi::CString;

const PAYLOAD: &str = "carrick-o-tmpfile-payload-0123456789";
// glibc/musl on aarch64 Linux: __O_TMPFILE | O_DIRECTORY.
const O_TMPFILE: libc::c_int = 0o20000000 | libc::O_DIRECTORY;

fn open_tmpfile(access: libc::c_int) -> libc::c_int {
    let dir = CString::new("/tmp").unwrap();
    unsafe { libc::open(dir.as_ptr(), O_TMPFILE | access, 0o600) }
}

fn main() {
    // 1. O_RDONLY | O_TMPFILE must fail EINVAL (write access is mandatory).
    let ro = open_tmpfile(libc::O_RDONLY);
    let rdonly_einval =
        ro < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL);
    if ro >= 0 {
        unsafe { libc::close(ro) };
    }

    // 2. Open the real unnamed temp file.
    let fd = open_tmpfile(libc::O_RDWR);
    let open_ok = fd >= 0;
    if !open_ok {
        println!("open_ok=false");
        println!("rdonly_einval={rdonly_einval}");
        println!("child_status0=false");
        println!("parent_readback=false");
        return;
    }

    // 3. Fork + exec a child that writes PAYLOAD to the inherited fd via
    //    /bin/sh. The child references the fd by number (it is NOT O_CLOEXEC),
    //    proving exec-inheritance, then the parent reads it back.
    let child_pid = unsafe { libc::fork() };
    if child_pid == 0 {
        // Child: exec `sh -c 'printf %s PAYLOAD >&FD'`. Using a shell forces a
        // real execve so this exercises exec-inheritance, not just fork.
        let cmd = format!("printf %s '{PAYLOAD}' >&{fd}");
        let sh = CString::new("/bin/sh").unwrap();
        let dash_c = CString::new("-c").unwrap();
        let cmd_c = CString::new(cmd).unwrap();
        let argv = [
            sh.as_ptr(),
            dash_c.as_ptr(),
            cmd_c.as_ptr(),
            std::ptr::null(),
        ];
        unsafe {
            libc::execv(sh.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(child_pid, &mut status, 0) };
    let child_status0 = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

    // 4. Parent reads the payload back from offset 0.
    let mut buf = vec![0u8; PAYLOAD.len() + 8];
    let n = unsafe {
        libc::lseek(fd, 0, libc::SEEK_SET);
        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    let parent_readback =
        n == PAYLOAD.len() as isize && &buf[..PAYLOAD.len()] == PAYLOAD.as_bytes();

    unsafe { libc::close(fd) };

    println!("open_ok={open_ok}");
    println!("rdonly_einval={rdonly_einval}");
    println!("child_status0={child_status0}");
    println!("parent_readback={parent_readback}");
}
