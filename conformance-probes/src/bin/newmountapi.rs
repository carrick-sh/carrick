//! New mount API (fsopen/fsconfig/fsmount/fspick/move_mount/open_tree/
//! mount_setattr) under the DEFAULT container capability profile: every entry
//! point is EPERM — before any argument validation — because the container
//! contract (Docker's default cap/seccomp profile) gates the whole family on
//! CAP_SYS_ADMIN. That gate is the guest-visible behaviour LTP's `tst_fd.c`
//! pins (`TCONF: Skipping fsopen: EPERM (1)`), and it is exactly what a
//! default `docker run` observes for every argument shape (bad flags, bad
//! fds, NULL pointers included — the profile denies before the kernel
//! validates). statmount/listmount are ENOSYS on the oracle kernel and stay
//! ENOSYS in carrick. Deterministic, line-exact carrick-vs-Linux.
//!
//! Oracle: `docker run --rm --platform linux/arm64 alpine:3` (default caps),
//! captured 2026-08-18 against LinuxKit 7.0.12; red against the pre-change
//! carrick (ENOSYS for the whole family).

use conformance_probes::errno;

// Unified post-424 syscall numbers (identical on aarch64 and x86_64).
const NR_OPEN_TREE: libc::c_long = 428;
const NR_MOVE_MOUNT: libc::c_long = 429;
const NR_FSOPEN: libc::c_long = 430;
const NR_FSCONFIG: libc::c_long = 431;
const NR_FSMOUNT: libc::c_long = 432;
const NR_FSPICK: libc::c_long = 433;
const NR_MOUNT_SETATTR: libc::c_long = 442;
const NR_STATMOUNT: libc::c_long = 457;
const NR_LISTMOUNT: libc::c_long = 458;

const OPEN_TREE_CLONE: u64 = 0x1;
const AT_FDCWD: libc::c_long = -100;

fn eperm(name: &str, r: libc::c_long) {
    println!("{name}_eperm={}", r == -1 && errno() == libc::EPERM);
}

fn main() {
    unsafe {
        let root = c"/".as_ptr();
        let ext2 = c"ext2".as_ptr();
        let ro = c"ro".as_ptr();
        let empty = c"".as_ptr();

        // fsopen: the cap gate precedes flag/pointer validation (a NULL
        // fs_name with invalid flags is still EPERM, not EINVAL/EFAULT).
        eperm("fsopen", libc::syscall(NR_FSOPEN, ext2, 0u64));
        eperm(
            "fsopen_null_badflags",
            libc::syscall(NR_FSOPEN, core::ptr::null::<libc::c_char>(), 0x10u64),
        );

        // fsconfig: cap gate precedes the fd<0-EINVAL and unknown-cmd-
        // EOPNOTSUPP checks.
        eperm(
            "fsconfig_badfd",
            libc::syscall(NR_FSCONFIG, -1i32, 0u32, ro, core::ptr::null::<u8>(), 0i32),
        );
        eperm(
            "fsconfig_badcmd",
            libc::syscall(
                NR_FSCONFIG,
                1i32,
                100u32,
                core::ptr::null::<u8>(),
                core::ptr::null::<u8>(),
                0i32,
            ),
        );

        // fsmount: cap gate precedes flag validation and the EBADF check.
        eperm(
            "fsmount_badfd",
            libc::syscall(NR_FSMOUNT, -1i32, 0u64, 0u64),
        );
        eperm(
            "fsmount_badflags",
            libc::syscall(NR_FSMOUNT, -1i32, 0x100u64, 0u64),
        );

        // fspick: cap gate precedes flag validation and path resolution.
        eperm(
            "fspick_root",
            libc::syscall(NR_FSPICK, AT_FDCWD, root, 0u64),
        );
        eperm(
            "fspick_badflags",
            libc::syscall(NR_FSPICK, AT_FDCWD, root, 0x100u64),
        );

        // open_tree: EPERM for the plain and CLONE forms alike (bare Linux
        // would allow the plain form unprivileged; the container profile —
        // carrick's contract — does not).
        eperm(
            "open_tree_root",
            libc::syscall(NR_OPEN_TREE, AT_FDCWD, root, 0u64),
        );
        eperm(
            "open_tree_clone",
            libc::syscall(NR_OPEN_TREE, AT_FDCWD, root, OPEN_TREE_CLONE),
        );
        eperm(
            "open_tree_badflags",
            libc::syscall(NR_OPEN_TREE, AT_FDCWD, root, 0x10u64),
        );

        // move_mount: cap gate precedes flag validation and the empty-path
        // ENOENT.
        eperm(
            "move_mount_empty",
            libc::syscall(NR_MOVE_MOUNT, -1i32, empty, -1i32, empty, 0u64),
        );
        eperm(
            "move_mount_badflags",
            libc::syscall(NR_MOVE_MOUNT, -1i32, empty, -1i32, empty, 0x1000u64),
        );

        // mount_setattr: cap gate precedes the size<32 EINVAL and the NULL-
        // attr EFAULT.
        eperm(
            "mount_setattr_badsize",
            libc::syscall(
                NR_MOUNT_SETATTR,
                AT_FDCWD,
                root,
                0u64,
                core::ptr::null::<u8>(),
                8usize,
            ),
        );
        eperm(
            "mount_setattr_nullattr",
            libc::syscall(
                NR_MOUNT_SETATTR,
                AT_FDCWD,
                root,
                0u64,
                core::ptr::null::<u8>(),
                32usize,
            ),
        );

        // statmount/listmount: ENOSYS on the oracle kernel; carrick honestly
        // keeps them unimplemented.
        let req = [0u64; 8];
        let mut buf = [0u8; 256];
        let r = libc::syscall(
            NR_STATMOUNT,
            req.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            0u64,
        );
        println!("statmount_enosys={}", r == -1 && errno() == libc::ENOSYS);
        let mut ids = [0u64; 16];
        let r = libc::syscall(NR_LISTMOUNT, req.as_ptr(), ids.as_mut_ptr(), 16usize, 0u64);
        println!("listmount_enosys={}", r == -1 && errno() == libc::ENOSYS);
    }
}
