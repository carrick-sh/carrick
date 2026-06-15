//! SP2 fixture: the execve CALLER. A static-musl x86_64 program that `execve`s
//! the deployed `bhyve-execd` target (which prints `execd ok` + `_exit(0)`).
//! Reaching execd's output proves `BhyveVmm::execve_rebuild` replaced the
//! guest image with a freshly-rebuilt VM and ran the second program.
//!
//! PATH RESOLUTION (see Cargo.toml): the target is the ABSOLUTE deployed host
//! path of execd. The dispatcher's `load_execve_image` resolves an absolute
//! execve path overlay-first, then falls back to the literal host fs
//! (`std::fs::read`) — which is ON for a bare run-elf dispatcher — so the
//! deployed host path resolves. Baked at compile time; override with
//! `CARRICK_EXECD_PATH`.
use std::ffi::CString;

/// Absolute host path of the deployed execd target. The default matches the
/// `/root/fixtures/execd` deploy location on the FreeBSD test box; override at
/// build time via `CARRICK_EXECD_PATH`.
const EXECD_PATH: &str = match option_env!("CARRICK_EXECD_PATH") {
    Some(p) => p,
    None => "/root/fixtures/execd",
};

fn main() {
    let path = CString::new(EXECD_PATH).expect("execd path has no NUL");
    let arg0 = path.clone();
    // argv = [execd_path, NULL]; envp = [NULL].
    let argv: [*const libc::c_char; 2] = [arg0.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];

    // SAFETY: `path`/`arg0` outlive the call; argv/envp are NULL-terminated.
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        // execve only returns on failure — report a distinct non-zero code so a
        // failed resolution is not mistaken for the target's exit 0.
        libc::_exit(1);
    }
}
