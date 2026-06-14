//! SP2 fixture: `vfork(2)` + `execve(2)` — the DOMINANT vfork pattern. The guest
//! `vfork`s (raw `SYS_vfork = 58`), the child immediately `execve`s the deployed
//! `bhyve-execd` target (prints `execd ok` + `_exit(0)`), the parent — released
//! the moment the child's `execve` succeeds (the loop writes the vfork pipe) —
//! `wait4`s and asserts `WEXITSTATUS == 0`, then prints `vfork-exec ok` +
//! `_exit(0)`.
//!
//! What this proves on bhyve (SP2): the whole vfork+exec path through the trait
//! DEFAULT `fork_vfork() → self.fork()` (a fork-COPY: a fresh, OWNED child VM,
//! SP1) — there is NO shared bhyve VM (true cross-process CLONE_VM was proven
//! infeasible; see the vfork design-correction in
//! `docs/superpowers/specs/2026-06-14-bhyve-process-model-2-vfork-execve-design.md`).
//! Flow: the fork-copy child runs its OWN vCPU → hits `execve` → `execve_into`
//! rebuilds a FRESH VM from the second image AND releases the suspended parent
//! by writing the vfork pipe → the parent resumes on its LIVE VM and reaps the
//! re-imaged child's exit 0. Same shape as the KVM x86 lane.
//!
//! vfork contract: a `vfork` child that RETURNS from the calling function or
//! mutates the (shared) parent stack is UB. So we use the RAW `syscall(SYS_vfork)`
//! and the child does NOTHING but `execve` — all of execve's arguments
//! (path/argv/envp) are constructed in the PARENT frame BEFORE the vfork, so the
//! child writes no new locals between the syscall and the exec.
//!
//! PATH RESOLUTION (see Cargo.toml + the `execve` fixture): the target is the
//! ABSOLUTE deployed host path of execd. `load_execve_image` resolves an
//! absolute execve path overlay-first, then via the host-fs fallback
//! (`std::fs::read`) which is ON for the bare run-elf dispatcher — so the
//! deployed execd is found. Baked at compile time; override with
//! `CARRICK_EXECD_PATH`.
//!
//! Static-musl x86_64 (same loader requirements as the other bhyve fixtures).
use std::ffi::CString;

/// Linux x86_64 `vfork` syscall number (asm-generic / x86_64 unistd: 58).
const SYS_VFORK: libc::c_long = 58;

/// Absolute host path of the deployed execd target. The default matches the
/// `/root/fixtures/execd` deploy location on the FreeBSD test box; override at
/// build time via `CARRICK_EXECD_PATH`.
const EXECD_PATH: &str = match option_env!("CARRICK_EXECD_PATH") {
    Some(p) => p,
    None => "/root/fixtures/execd",
};

fn main() {
    // Construct ALL execve arguments in the PARENT frame, BEFORE the vfork, so
    // the child branch writes no new stack locals (vfork shared-stack contract).
    let path = CString::new(EXECD_PATH).expect("execd path has no NUL");
    let arg0 = path.clone();
    // argv = [execd_path, NULL]; envp = [NULL].
    let argv: [*const libc::c_char; 2] = [arg0.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];

    // SAFETY: a single raw vfork(2) in a single-threaded program. The child
    // branch only `execve`s (arguments built above) — it never returns from this
    // frame and writes no new locals, honoring the shared-stack vfork contract.
    let ret = unsafe { libc::syscall(SYS_VFORK) };
    if ret == 0 {
        // CHILD: immediately execve the deployed execd target. execve only
        // returns on failure → report a distinct non-zero code via `_exit` so a
        // failed resolution is not mistaken for the target's exit 0.
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    if ret < 0 {
        // vfork itself failed.
        unsafe { libc::_exit(1) };
    }

    // PARENT (resumed after the child's execve released it): reap + verify the
    // re-imaged child exited 0.
    let child = ret as i32;
    let mut st: libc::c_int = 0;
    let w = unsafe { libc::wait4(child, &mut st, 0, std::ptr::null_mut()) };
    if w != child {
        unsafe { libc::_exit(2) };
    }
    let code = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        -1
    };
    if code != 0 {
        unsafe { libc::_exit(3) };
    }

    // Success: the vfork child fork-copied a fresh VM, execve'd execd (which
    // rebuilt a fresh VM, ran to "execd ok" + exit 0, and released the parent on
    // exec), and the parent resumed + reaped WEXITSTATUS 0.
    let msg = b"vfork-exec ok\n";
    // SAFETY: writing a fixed byte slice to stdout (fd 1).
    unsafe {
        libc::write(1, msg.as_ptr().cast(), msg.len());
        libc::_exit(0);
    }
}
