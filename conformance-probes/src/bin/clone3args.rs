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
//!   * clone302 negative cases — bad extra-size user buffer, CLONE_SIGHAND
//!     without CLONE_VM, CLONE_THREAD without CLONE_SIGHAND, CLONE_FS with
//!     CLONE_NEWNS, invalid CLONE_PIDFD pointer, and invalid exit_signal are
//!     rejected before forking.
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

fn efault_or_blocked(er: i32) -> bool {
    er == libc::EFAULT || er == libc::ENOSYS
}

unsafe fn rejected_without_child(
    args: &mut CloneArgs,
    size: usize,
    errno_ok: fn(i32) -> bool,
) -> bool {
    let rc = clone3(args, size);
    let er = errno();
    if rc == 0 {
        libc::_exit(0);
    }
    if rc > 0 {
        let _ = reap(rc as i32);
        return false;
    }
    rc == -1 && errno_ok(er)
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

fn case_extra_size_fault() {
    unsafe {
        // The RUNTIME page size, not a hardcoded 4096: libc rounds mprotect to
        // page granularity, so on a 16 KiB-page kernel a 4096-based layout
        // would PROT_NONE the whole two-page mapping and this probe's own
        // `*args_ptr` store below would (correctly) SIGSEGV. The faulting tail
        // must start exactly at the second page for every geometry.
        let page = libc::sysconf(libc::_SC_PAGESIZE);
        if page <= 0 {
            report!(clone3_extra_size_efault_or_blocked = false);
            return;
        }
        let page = page as usize;
        let mapping = libc::mmap(
            core::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if mapping == libc::MAP_FAILED {
            report!(clone3_extra_size_efault_or_blocked = false);
            return;
        }
        let second = (mapping as usize + page) as *mut libc::c_void;
        let _ = libc::mprotect(second, page, libc::PROT_NONE);
        let args_ptr =
            (mapping as usize + page - core::mem::size_of::<CloneArgs>()) as *mut CloneArgs;
        *args_ptr = CloneArgs::default();
        (*args_ptr).exit_signal = libc::SIGCHLD as u64;
        let ok = rejected_without_child(
            args_ptr.as_mut().unwrap(),
            core::mem::size_of::<CloneArgs>() + 1,
            efault_or_blocked,
        );
        let _ = libc::munmap(mapping, page * 2);
        report!(clone3_extra_size_efault_or_blocked = ok);
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

fn case_flag_consistency() {
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_FS: u64 = 0x0000_0200;
    const CLONE_SIGHAND: u64 = 0x0000_0800;
    const CLONE_PIDFD: u64 = 0x0000_1000;
    const CLONE_THREAD: u64 = 0x0001_0000;
    const CLONE_NEWNS: u64 = 0x0002_0000;

    unsafe {
        let size = core::mem::size_of::<CloneArgs>();

        let mut sighand_no_vm = CloneArgs {
            flags: CLONE_SIGHAND,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let sighand_no_vm_ok = rejected_without_child(&mut sighand_no_vm, size, rejected_errno);

        let mut thread_no_sighand = CloneArgs {
            flags: CLONE_VM | CLONE_THREAD,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let thread_no_sighand_ok =
            rejected_without_child(&mut thread_no_sighand, size, rejected_errno);

        let mut fs_newns = CloneArgs {
            flags: CLONE_FS | CLONE_NEWNS,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let fs_newns_ok = rejected_without_child(&mut fs_newns, size, rejected_errno);

        let mut invalid_pidfd = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: 1,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let invalid_pidfd_ok = rejected_without_child(&mut invalid_pidfd, size, efault_or_blocked);

        let mut invalid_signal = CloneArgs {
            exit_signal: 0x100,
            ..CloneArgs::default()
        };
        let invalid_signal_ok = rejected_without_child(&mut invalid_signal, size, rejected_errno);

        report!(
            clone3_sighand_no_vm_rejected = sighand_no_vm_ok,
            clone3_thread_no_sighand_rejected = thread_no_sighand_ok,
            clone3_fs_newns_rejected = fs_newns_ok,
            clone3_invalid_pidfd_efault_or_blocked = invalid_pidfd_ok,
            clone3_invalid_signal_rejected = invalid_signal_ok,
        );
    }
}

fn case_newpid_fork() {
    const CLONE_NEWPID: u64 = 0x2000_0000;

    unsafe {
        let mut args = CloneArgs {
            flags: CLONE_NEWPID,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let rc = clone3(&mut args, core::mem::size_of::<CloneArgs>());
        let er = errno();
        let ok = if rc == 0 {
            libc::_exit(0);
        } else if rc > 0 {
            let (_, status) = reap(rc as i32);
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        } else {
            er == libc::ENOSYS || er == libc::EPERM
        };
        report!(clone3_newpid_fork_or_blocked = ok);
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
    case_extra_size_fault();
    case_truncated_size();
    case_flag_consistency();
    case_newpid_fork();
    case_invalid_flag_bit();
    case_inconsistent_stack_pair();
}
