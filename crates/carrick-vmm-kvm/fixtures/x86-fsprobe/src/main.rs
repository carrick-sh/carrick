//! M1 differential fixture (audit #1): calls `uname(2)` — canonical syscall 160,
//! which the standalone ~15-syscall `run_elf_kvm_x86` loop returns `-ENOSYS` for,
//! but the full `SyscallDispatcher` services. Cross-compiled to
//! x86_64-unknown-linux-musl (static, non-PIE ET_EXEC) by build.sh. Printing the
//! nodename makes the run observable; exit 0 iff `uname` succeeded — so the same
//! binary failing under the standalone loop and succeeding under the dispatcher
//! is the proof that x86 reached the real dispatcher.
fn main() {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::uname(&mut u) };
    if rc != 0 {
        eprintln!("uname failed: rc={rc}");
        std::process::exit(1);
    }
    // SAFETY: a successful uname() NUL-terminates each utsname field.
    let node = unsafe { std::ffi::CStr::from_ptr(u.nodename.as_ptr()) };
    let sys = unsafe { std::ffi::CStr::from_ptr(u.sysname.as_ptr()) };
    println!(
        "uname.sysname={} uname.nodename={}",
        sys.to_string_lossy(),
        node.to_string_lossy()
    );
}
