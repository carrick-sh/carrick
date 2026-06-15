//! SP2 fixture: `vfork(2)` WITHOUT exec — the vfork child immediately `_exit(9)`
//! (no execve, no return from the calling frame), the parent `wait4`s and
//! asserts `WEXITSTATUS == 9`, then prints `vfork-exit ok` + `_exit(0)`.
//!
//! What this proves on bhyve (SP2): bhyve uses the trait DEFAULT
//! `fork_vfork() → self.fork()` — vfork is a fork-COPY (a fresh, OWNED child VM
//! eagerly copied from the parent's guest RAM, SP1), NOT a shared parent VM.
//! True cross-process `CLONE_VM` (two processes on ONE bhyve VM) was proven
//! infeasible (permanent `active_cpus` + suspend rendezvous + `vm_run` EINVAL);
//! see the vfork design-correction in
//! `docs/superpowers/specs/2026-06-14-bhyve-process-model-2-vfork-execve-design.md`.
//! This is correct for every conforming vfork user (POSIX: the child may only
//! `exec`/`_exit`), and matches the KVM x86 lane. The generic loop's vfork-pipe
//! suspends the parent until the child `_exit`s (write end closed → pipe EOF);
//! the parent then resumes on its own LIVE VM and reaps the child via the shared
//! `wait_proc_exit`. The child runs to `_exit(9)` on its OWN fresh VM exactly
//! like the passing `fork` test.
//!
//! vfork contract: a `vfork` child that RETURNS from the calling function is UB
//! (it shares the parent's stack). We therefore use the RAW `syscall(SYS_vfork =
//! 58)` directly (musl's `vfork()` wrapper may be unavailable / UB-to-call from
//! Rust) and have the child do NOTHING but `_exit(9)` — no stack writes, no
//! return — between the syscall and the exit.
//!
//! Static-musl x86_64 (same loader requirements as the other bhyve fixtures).

/// Linux x86_64 `vfork` syscall number (asm-generic / x86_64 unistd: 58).
const SYS_VFORK: libc::c_long = 58;

fn main() {
    // SAFETY: a single raw vfork(2) in a single-threaded program. The child
    // branch does the absolute minimum (`_exit(9)`) — it never returns from this
    // frame and writes no locals, honoring the shared-stack vfork contract.
    let ret = unsafe { libc::syscall(SYS_VFORK) };
    if ret == 0 {
        // CHILD: `_exit(9)` immediately. No execve, no return, no stack mutation.
        unsafe { libc::_exit(9) };
    }
    if ret < 0 {
        // vfork itself failed.
        unsafe { libc::_exit(1) };
    }

    // PARENT (resumed after the child's _exit released it): reap + verify.
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
    if code != 9 {
        unsafe { libc::_exit(3) };
    }

    // Success: the vfork child shared the parent VM, _exit(9)'d without
    // destroying it, and the parent resumed + reaped WEXITSTATUS 9.
    let msg = b"vfork-exit ok\n";
    // SAFETY: writing a fixed byte slice to stdout (fd 1).
    unsafe {
        libc::write(1, msg.as_ptr().cast(), msg.len());
        libc::_exit(0);
    }
}
