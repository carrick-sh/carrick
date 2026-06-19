//! Legacy x86_64-only fs syscalls. glibc AND musl issue the LEGACY x86_64 numbers
//! for these wrappers (unlink=87, rmdir=84, link=86, symlink=88, chmod=90,
//! chown=92, rename=82, creat=85, mknod=133), NOT their asm-generic `*at`
//! successors. carrick's unified dispatcher is keyed on the asm-generic/aarch64
//! canonical numbers, so `carrick_hal::x8664_arch::normalize_syscall` must
//! arg-shim each legacy call to its `*at` canonical (e.g. unlink(path) ->
//! unlinkat(AT_FDCWD, path, 0)) or it falls through to -ENOSYS.
//!
//! Oracle-gated: every line is `true` on real Linux (glibc + musl). Any `false`
//! is a missing shim. mkdir(83)/access are already shimmed (regression guards).

use conformance_probes::report;

fn main() {
    unsafe {
        let dir = b"/tmp/cr_lfs\0".as_ptr() as *const libc::c_char;
        let f = b"/tmp/cr_lfs/f\0".as_ptr() as *const libc::c_char;
        let f2 = b"/tmp/cr_lfs/f2\0".as_ptr() as *const libc::c_char;
        let sym = b"/tmp/cr_lfs/l\0".as_ptr() as *const libc::c_char;
        let fifo = b"/tmp/cr_lfs/fifo\0".as_ptr() as *const libc::c_char;

        // Clean slate (ignore errors).
        libc::unlink(f);
        libc::unlink(f2);
        libc::unlink(sym);
        libc::unlink(fifo);
        libc::rmdir(dir);

        let mkdir_ok = libc::mkdir(dir, 0o755) == 0;

        // creat(85)
        let fd = libc::creat(f, 0o644);
        let creat_ok = fd >= 0;
        if fd >= 0 {
            libc::write(fd, b"hi".as_ptr() as *const libc::c_void, 2);
            libc::close(fd);
        }

        // chmod(90) + verify
        let chmod_ok = libc::chmod(f, 0o600) == 0;
        let mut st: libc::stat = std::mem::zeroed();
        let chmod_verified = libc::stat(f, &mut st) == 0 && (st.st_mode & 0o777) == 0o600;

        // chown(92) to self (no-op, must succeed)
        let chown_ok = libc::chown(f, libc::getuid(), libc::getgid()) == 0;

        // link(86) + nlink verify
        let link_ok = libc::link(f, f2) == 0;
        let link_verified = libc::stat(f, &mut st) == 0 && st.st_nlink == 2;

        // unlink(87)
        let unlink_ok = libc::unlink(f2) == 0;
        let unlink_verified = libc::stat(f, &mut st) == 0 && st.st_nlink == 1;

        // symlink(88) + readlink(89)
        let symlink_ok = libc::symlink(b"f\0".as_ptr() as *const libc::c_char, sym) == 0;
        let mut buf = [0u8; 16];
        let n = libc::readlink(sym, buf.as_mut_ptr() as *mut libc::c_char, 16);
        let readlink_ok = n == 1 && buf[0] == b'f';

        // rename(82)
        let rename_ok = libc::rename(f, f2) == 0;
        let rename_verified = libc::access(f, libc::F_OK) != 0 && libc::access(f2, libc::F_OK) == 0;

        // mknod(133) FIFO
        let mknod_ok = libc::mknod(fifo, libc::S_IFIFO | 0o644, 0) == 0;
        let mknod_verified =
            libc::stat(fifo, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO;

        report!(
            mkdir = mkdir_ok,
            creat = creat_ok,
            chmod = chmod_ok,
            chmod_verified = chmod_verified,
            chown = chown_ok,
            link = link_ok,
            link_verified = link_verified,
            unlink = unlink_ok,
            unlink_verified = unlink_verified,
            symlink = symlink_ok,
            readlink = readlink_ok,
            rename = rename_ok,
            rename_verified = rename_verified,
            mknod = mknod_ok,
            mknod_verified = mknod_verified,
        );

        // Cleanup.
        libc::unlink(sym);
        libc::unlink(f2);
        libc::unlink(fifo);
        libc::rmdir(dir);
    }
}
