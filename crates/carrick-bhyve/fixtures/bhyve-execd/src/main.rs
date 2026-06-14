//! SP2 fixture: the execve TARGET ("execd"). A tiny static-musl x86_64 program
//! that prints `execd ok` and `_exit(0)`. The CALLER (`bhyve-execve`) execve's
//! this binary; reaching its output proves `BhyveTrapEngine::execve_into`
//! rebuilt a fresh VM from the second image and ran it from its `_start`.
//!
//! Uses raw `write(1, ...)` + `_exit(0)` (no stdio buffering / atexit) so the
//! marker is delivered deterministically by the freshly-rebuilt guest.
fn main() {
    let msg = b"execd ok\n";
    // SAFETY: write(2)/_exit(2) on stdout in a single-threaded program.
    unsafe {
        libc::write(1, msg.as_ptr().cast(), msg.len());
        libc::_exit(0);
    }
}
