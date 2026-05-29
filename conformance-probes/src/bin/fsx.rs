//! Extended filesystem probe. Exercises statfs/fstatfs, utimensat, fadvise64,
//! fallocate, sync/syncfs/fsync/fdatasync, xattr family, faccessat2,
//! readlinkat, chdir+getcwd, and mknod/mknodat. Prints one labelled line per
//! observation. The conformance harness runs this identical static binary
//! under carrick and real Linux and diffs line by line — a divergent line
//! names the exact failing syscall.
//!
//! Deterministic only: no inodes, timestamps, addresses, or sizes that vary.
//! We print booleans, fixed contents, and errnos. Several of these syscalls
//! (fallocate, xattr family, mknod) are known-unsupported or divergent areas
//! in carrick — we print the errno so the diff documents the exact gap.

use std::ffi::CString;

fn main() {
    // statfs / fstatfs on "/": booleans only (block size and total blocks vary
    // by host, so we only assert they are positive).
    {
        let path = CString::new("/").unwrap();
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(path.as_ptr(), &mut st) };
        if rc != 0 {
            println!("statfs_root=ERR:{}", errno());
        } else {
            println!(
                "statfs_root bsize_pos={} blocks_pos={}",
                st.f_bsize > 0,
                st.f_blocks > 0
            );
        }

        let fd = open("/", libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if fd < 0 {
            println!("fstatfs_root=ERR:{}", errno());
        } else {
            let mut fst: libc::statfs = unsafe { std::mem::zeroed() };
            let frc = unsafe { libc::fstatfs(fd, &mut fst) };
            if frc != 0 {
                println!("fstatfs_root=ERR:{}", errno());
            } else {
                println!(
                    "fstatfs_root bsize_pos={} blocks_pos={}",
                    fst.f_bsize > 0,
                    fst.f_blocks > 0
                );
            }
            unsafe { libc::close(fd) };
        }
    }

    // utimensat: create /tmp/ut, set atime+mtime to a fixed epoch, stat back,
    // assert mtime equals the fixed value (boolean).
    {
        const FIXED: i64 = 1_000_000_000;
        let fd = open("/tmp/ut", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        let path = CString::new("/tmp/ut").unwrap();
        let times = [
            libc::timespec { tv_sec: FIXED as _, tv_nsec: 0 },
            libc::timespec { tv_sec: FIXED as _, tv_nsec: 0 },
        ];
        let rc = unsafe {
            libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0)
        };
        if rc != 0 {
            println!("utimensat=ERR:{}", errno());
        } else {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let src = unsafe { libc::stat(path.as_ptr(), &mut st) };
            if src != 0 {
                println!("utimensat_stat=ERR:{}", errno());
            } else {
                println!("utimensat_mtime_ok={}", st.st_mtime as i64 == FIXED);
            }
        }
    }

    // fadvise64(POSIX_FADV_SEQUENTIAL) on an open file: rc (0 on success).
    {
        let fd = open("/tmp/ut", libc::O_RDONLY, 0);
        if fd < 0 {
            println!("fadvise=ERR:{}", errno());
        } else {
            let rc = unsafe {
                libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL)
            };
            // posix_fadvise returns the errno directly (0 on success).
            if rc != 0 {
                println!("fadvise=ERR:{}", rc);
            } else {
                println!("fadvise rc={}", rc);
            }
            unsafe { libc::close(fd) };
        }
    }

    // fallocate(0, offset 0, len 4096) on a fresh file: rc + size after.
    // carrick may not support fallocate; print errno on failure so the diff
    // reveals it.
    {
        let fd = open("/tmp/falloc", libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd < 0 {
            println!("fallocate=ERR:{}", errno());
        } else {
            let rc = unsafe { libc::fallocate(fd, 0, 0, 4096) };
            if rc != 0 {
                println!("fallocate=ERR:{}", errno());
            } else {
                println!("fallocate rc={}", rc);
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let src = unsafe { libc::fstat(fd, &mut st) };
                if src != 0 {
                    println!("fallocate_size=ERR:{}", errno());
                } else {
                    println!("fallocate_size={}", st.st_size);
                }
            }
            unsafe { libc::close(fd) };
        }
    }

    // sync(): no return value. Just exercise it and confirm we returned.
    {
        unsafe { libc::sync() };
        println!("sync rc=0");
    }

    // syncfs() on an open fd: rc (0 on success).
    {
        let fd = open("/tmp/ut", libc::O_RDONLY, 0);
        if fd < 0 {
            println!("syncfs=ERR:{}", errno());
        } else {
            let rc = unsafe { libc::syncfs(fd) };
            if rc != 0 {
                println!("syncfs=ERR:{}", errno());
            } else {
                println!("syncfs rc={}", rc);
            }
            unsafe { libc::close(fd) };
        }
    }

    // fsync / fdatasync on an open (writable) file: rc (0 on success).
    {
        let fd = open("/tmp/fsy", libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd < 0 {
            println!("fsync=ERR:{}", errno());
        } else {
            let data = b"sync";
            unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
            let r1 = unsafe { libc::fsync(fd) };
            if r1 != 0 {
                println!("fsync=ERR:{}", errno());
            } else {
                println!("fsync rc={}", r1);
            }
            let r2 = unsafe { libc::fdatasync(fd) };
            if r2 != 0 {
                println!("fdatasync=ERR:{}", errno());
            } else {
                println!("fdatasync rc={}", r2);
            }
            unsafe { libc::close(fd) };
        }
    }

    // xattr family on a file. On real Linux (ext4/overlay) these often return
    // ENOTSUP/ENODATA; carrick likely ENOSYS/ENOTSUP. Print the errno so the
    // diff documents the gap. This is a known-unsupported area.
    {
        let fd = open("/tmp/xattr", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        let path = CString::new("/tmp/xattr").unwrap();
        let name = CString::new("user.carrick").unwrap();
        let val = b"v";

        let sr = unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                val.as_ptr() as *const _,
                val.len(),
                0,
            )
        };
        println!("setxattr={}", rc_or_err(sr as i64));

        let mut buf = [0u8; 64];
        let gr = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        println!("getxattr={}", rc_or_err(gr as i64));

        let lr = unsafe {
            libc::listxattr(path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
        };
        println!("listxattr={}", rc_or_err(lr as i64));

        // removexattr round-trip: drop the attr just set, then a get must report
        // ENODATA and a second remove (now absent) likewise ENODATA; removing
        // from a non-existent path is ENOENT (distinct from ENODATA).
        let rr = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) };
        println!("removexattr={}", rc_or_err(rr as i64));
        let gr2 = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        println!("getxattr_after_remove={}", rc_or_err(gr2 as i64));
        let rr2 = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) };
        println!("removexattr_absent={}", rc_or_err(rr2 as i64));
        let nopath = CString::new("/tmp/xattr_nope").unwrap();
        let rr3 = unsafe { libc::removexattr(nopath.as_ptr(), name.as_ptr()) };
        println!("removexattr_nopath={}", rc_or_err(rr3 as i64));
    }

    // access modes via faccessat2 with AT_EACCESS on /etc/passwd (R_OK): rc.
    // faccessat2 is a raw syscall (no libc wrapper across all versions); call
    // it directly via syscall(2).
    {
        let path = CString::new("/etc/passwd").unwrap();
        let rc = unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                libc::AT_FDCWD as libc::c_long,
                path.as_ptr() as libc::c_long,
                libc::R_OK as libc::c_long,
                libc::AT_EACCESS as libc::c_long,
            )
        };
        if rc != 0 {
            println!("faccessat2_passwd_r=ERR:{}", errno());
        } else {
            println!("faccessat2_passwd_r rc={}", rc);
        }
    }

    // readlinkat on /proc/self/exe: print whether result is non-empty
    // (boolean). Do NOT print the path (it differs across hosts).
    {
        let path = CString::new("/proc/self/exe").unwrap();
        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                path.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        if n < 0 {
            println!("readlinkat_exe=ERR:{}", errno());
        } else {
            println!("readlinkat_exe_nonempty={}", n > 0);
        }
    }

    // chdir + getcwd round-trip to /tmp: print getcwd (expect /tmp).
    {
        let tmp = CString::new("/tmp").unwrap();
        let cr = unsafe { libc::chdir(tmp.as_ptr()) };
        if cr != 0 {
            println!("chdir_tmp=ERR:{}", errno());
        } else {
            let mut buf = [0u8; 4096];
            let p = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut _, buf.len()) };
            if p.is_null() {
                println!("getcwd=ERR:{}", errno());
            } else {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
                println!("getcwd={}", String::from_utf8_lossy(&buf[..len]));
            }
        }
    }

    // mknod / mknodat a regular file (S_IFREG): rc + existence. carrick may
    // differ — print errno on failure.
    {
        let path = CString::new("/tmp/mknod_reg").unwrap();
        let rc = unsafe {
            libc::mknod(path.as_ptr(), libc::S_IFREG | 0o644, 0)
        };
        if rc != 0 {
            println!("mknod_reg=ERR:{}", errno());
        } else {
            println!("mknod_reg rc={}", rc);
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let exists = unsafe { libc::stat(path.as_ptr(), &mut st) } == 0;
        println!("mknod_reg_exists={}", exists);

        let path2 = CString::new("/tmp/mknodat_reg").unwrap();
        let rc2 = unsafe {
            libc::mknodat(libc::AT_FDCWD, path2.as_ptr(), libc::S_IFREG | 0o644, 0)
        };
        if rc2 != 0 {
            println!("mknodat_reg=ERR:{}", errno());
        } else {
            println!("mknodat_reg rc={}", rc2);
        }
        let mut st2: libc::stat = unsafe { std::mem::zeroed() };
        let exists2 = unsafe { libc::stat(path2.as_ptr(), &mut st2) } == 0;
        println!("mknodat_reg_exists={}", exists2);
    }
}

/// Open helper returning the raw fd (or -1 on error).
fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Render a syscall result: "rc=N" on success (>=0) else "ERR:<errno>".
fn rc_or_err(rc: i64) -> String {
    if rc < 0 {
        format!("ERR:{}", errno())
    } else {
        format!("rc={}", rc)
    }
}
