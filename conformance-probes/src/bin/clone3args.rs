//! clone3(2) argument validation. Stands in for LTP `clone301`, `clone302`,
//! `clone303`, `clone05`, `clone08`.
//!
//! clone3 is sysno 435 on aarch64; its signature is
//!   int clone3(struct clone_args *args, size_t size)
//! and the kernel rejects calls where `size` doesn't match a recognised
//! `clone_args` layout, where an unknown flag bit is set, or where the
//! argument pair is internally inconsistent.
//!
//! Coverage shape (mirrors `iouring`'s "unavailable OR correct" pattern):
//! Docker's default seccomp profile filters clone3 → ENOSYS, so under the
//! Docker oracle every call returns -1/ENOSYS and the booleans evaluate to
//! "rejected appropriately". Under carrick (which implements clone3) the same
//! booleans require the real kernel error. The probe stays a regression guard
//! either way — carrick must not silently accept a malformed clone3.
//!
//! Invariants encoded, all boolean:
//!
//!   * Happy path — `clone3({.flags=0, .exit_signal=SIGCHLD}, sizeof(args))`
//!     either (a) is blocked at the seccomp layer (rc=-1, ENOSYS) OR
//!     (b) returns a positive child pid and the child reaps clean with
//!     `WIFEXITED && WEXITSTATUS == 0`. (LTP clone301)
//!   * Truncated size — `clone3(args, 8)` returns -1 with errno in
//!     {EINVAL, ENOSYS} (8 < CLONE_ARGS_SIZE_VER0=64). (LTP clone302)
//!   * Invalid flag bit — `clone3({.flags = 1<<63 | ...})` returns -1 with
//!     errno in {EINVAL, ENOSYS} (bit 63 is reserved). (LTP clone303)
//!   * Inconsistent stack-size pair — `clone3({.stack=0, .stack_size=8192})`
//!     returns -1 with errno in {EINVAL, ENOSYS}: stack==0 with non-zero
//!     stack_size is rejected. (LTP clone05 / clone08 in spirit.)
//!
//! Deterministic output: booleans only. No pids, no raw errnos.
//!
//! Note: `libc` does not expose `struct clone_args`, so we build a
//! `#[repr(C)] CloneArgs` with the v1 layout (11 u64s = 88 bytes) and pass it
//! by pointer to `libc::syscall(SYS_clone3, …)`.

use conformance_probes::{errno, reap, report};

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

unsafe fn clone3(args: *mut CloneArgs, size: usize) -> i64 {
    libc::syscall(libc::SYS_clone3, args, size as libc::c_long) as i64
}

/// True if `errno` is one of the kernel's documented "reject this clone3" codes.
/// `EINVAL` is the real per-argument rejection; `ENOSYS` is what Docker's
/// default seccomp profile substitutes when the call is filtered.
fn rejected_errno(er: i32) -> bool {
    er == libc::EINVAL || er == libc::ENOSYS
}

fn case_happy_path() {
    unsafe {
        let mut args = CloneArgs::default();
        args.exit_signal = libc::SIGCHLD as u64;
        let size = core::mem::size_of::<CloneArgs>();

        let rc = clone3(&mut args, size);
        let er = errno();
        if rc == 0 {
            // Child: just exit. No stdio writes from the child — the parent's
            // reap result is the only observation we want on stdout.
            libc::_exit(0);
        }
        // Two acceptable Linux outcomes:
        //   (a) seccomp-blocked: rc == -1, errno == ENOSYS
        //   (b) succeeded: rc > 0, parent reaps a clean exit
        let blocked = rc == -1 && er == libc::ENOSYS;
        let succeeded = if rc > 0 {
            let (_, status) = reap(rc as i32);
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        } else {
            false
        };
        report!(clone3_happy_rejected_or_succeeded = blocked || succeeded);
    }
}

fn case_truncated_size() {
    unsafe {
        let mut args = CloneArgs::default();
        args.exit_signal = libc::SIGCHLD as u64;
        // 8 bytes is smaller than the smallest valid clone_args
        // (CLONE_ARGS_SIZE_VER0 == 64). Linux returns EINVAL; Docker
        // seccomp returns ENOSYS — both count as "rejected".
        let rc = clone3(&mut args, 8);
        let er = errno();
        report!(
            clone3_truncated_rc_minus_one = rc == -1,
            clone3_truncated_rejected = rc == -1 && rejected_errno(er),
        );
    }
}

fn case_invalid_flag_bit() {
    unsafe {
        let mut args = CloneArgs::default();
        // Bit 63 is reserved-zero in the clone3 flags space. The kernel
        // rejects any unknown bit with EINVAL.
        args.flags = 1u64 << 63;
        args.exit_signal = libc::SIGCHLD as u64;
        let size = core::mem::size_of::<CloneArgs>();
        let rc = clone3(&mut args, size);
        let er = errno();
        report!(
            clone3_badflag_rc_minus_one = rc == -1,
            clone3_badflag_rejected = rc == -1 && rejected_errno(er),
        );
    }
}

fn case_inconsistent_stack_pair() {
    unsafe {
        let mut args = CloneArgs::default();
        // stack == 0 with stack_size != 0 is an internally inconsistent
        // pair; the kernel rejects with EINVAL before forking anything.
        // This is the LTP clone05/08-shaped argument-pair check.
        args.flags = 0;
        args.exit_signal = libc::SIGCHLD as u64;
        args.stack = 0;
        args.stack_size = 8192;
        let size = core::mem::size_of::<CloneArgs>();
        let rc = clone3(&mut args, size);
        let er = errno();
        report!(
            clone3_badstack_rc_minus_one = rc == -1,
            clone3_badstack_rejected = rc == -1 && rejected_errno(er),
        );
    }
}

fn main() {
    case_happy_path();
    case_truncated_size();
    case_invalid_flag_bit();
    case_inconsistent_stack_pair();
}
