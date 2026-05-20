//! readlinkat edge-cases + fstat st_mode TYPE-bit probe. Prints one labelled
//! line per observation. The conformance harness runs this identical static
//! binary under carrick and real Linux and diffs line by line — a divergent
//! line names the exact failing behavior.
//!
//! Deterministic only: no fd numbers, timestamps, pids, addresses, inodes, or
//! resolved paths. Fallible calls render as `=ERR:<errno>`.
//!
//! Part A targets the EINVAL-vs-ENOENT distinction that realpath(3) relies on
//! when probing whether a path component is a symlink. Part B documents the
//! S_IFMT type bits fstat reports for various fd kinds. The eventfd and stdin
//! lines are DOCUMENTATION of anon_inode / pipe-stdin behavior — they may
//! legitimately differ and are not necessarily bugs (see notes below).

use std::ffi::CString;

fn main() {
    // -- PART A: readlinkat edge cases -------------------------------------

    // Fixed symlink: unlink first so the run is deterministic, then create
    // /tmp/ls_link -> /tmp/ls_target (target need not exist).
    let link = CString::new("/tmp/ls_link").unwrap();
    let target = "/tmp/ls_target";
    let target_c = CString::new(target).unwrap();
    unsafe { libc::unlink(link.as_ptr()) };
    let sl = unsafe { libc::symlinkat(target_c.as_ptr(), libc::AT_FDCWD, link.as_ptr()) };
    if sl != 0 {
        println!("symlink_setup=ERR:{}", errno());
    }

    // readlinkat on the symlink: rc>0 and returned target text matches.
    {
        let mut buf = [0u8; 256];
        let n = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                link.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        println!("readlinkat_sym_rc_pos={}", n > 0);
        let got = if n > 0 {
            String::from_utf8_lossy(&buf[..n as usize]).into_owned()
        } else {
            String::new()
        };
        println!("readlinkat_sym_target_match={}", got == target);
    }

    // readlinkat on a REGULAR file -> EINVAL(22) on Linux.
    println!("readlinkat_regfile_errno={}", readlinkat_errno("/etc/hostname"));

    // readlinkat on a DIRECTORY -> EINVAL(22).
    println!("readlinkat_dir_errno={}", readlinkat_errno("/etc"));

    // readlinkat on a NONEXISTENT path -> ENOENT(2).
    println!("readlinkat_missing_errno={}", readlinkat_errno("/no/such"));

    // readlinkat into a SHORT buffer (size 4) on the symlink whose target
    // ("/tmp/ls_target") is longer -> Linux truncates, returns 4, no error.
    {
        let mut buf = [0u8; 4];
        let n = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                link.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n < 0 {
            println!("readlinkat_short_count=ERR:{}", errno());
        } else {
            println!("readlinkat_short_count={}", n);
        }
    }

    // readlinkat("/proc/self/exe") -> result non-empty (do NOT print the path).
    {
        let exe = CString::new("/proc/self/exe").unwrap();
        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                exe.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n < 0 {
            println!("readlinkat_procexe_nonempty=ERR:{}", errno());
        } else {
            println!("readlinkat_procexe_nonempty={}", n > 0);
        }
    }

    // -- PART B: fstat st_mode TYPE bits (S_IFMT) for various fd kinds ------

    // Regular file.
    {
        let fd = open("/etc/hostname", libc::O_RDONLY, 0);
        if fd < 0 {
            println!("fstat_regfile=ERR:{}", errno());
        } else {
            println!("fstat_regfile={}", fstat_type(fd));
            unsafe { libc::close(fd) };
        }
    }

    // Directory.
    {
        let fd = open("/etc", libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if fd < 0 {
            println!("fstat_dir=ERR:{}", errno());
        } else {
            println!("fstat_dir={}", fstat_type(fd));
            unsafe { libc::close(fd) };
        }
    }

    // Symlink via lstat (newfstatat with AT_SYMLINK_NOFOLLOW) -> "lnk".
    {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                libc::AT_FDCWD,
                link.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            println!("lstat_symlink=ERR:{}", errno());
        } else {
            println!("lstat_symlink={}", type_token(st.st_mode));
        }
    }

    // Pipe: both ends should be "fifo".
    {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
        if rc != 0 {
            println!("fstat_pipe_rd=ERR:{}", errno());
            println!("fstat_pipe_wr=ERR:{}", errno());
        } else {
            println!("fstat_pipe_rd={}", fstat_type(fds[0]));
            println!("fstat_pipe_wr={}", fstat_type(fds[1]));
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
        }
    }

    // eventfd: DOCUMENTATION line — Linux historically reports a non-symbolic
    // type for anon_inode fds; print whatever the token resolves to so the
    // diff reveals any carrick/Linux mismatch (not necessarily a bug).
    {
        let fd = unsafe { libc::eventfd(0, 0) };
        if fd < 0 {
            println!("fstat_eventfd=ERR:{}", errno());
        } else {
            println!("fstat_eventfd={}", fstat_type(fd));
            unsafe { libc::close(fd) };
        }
    }

    // socketpair AF_UNIX -> "sock".
    {
        let mut sv = [0i32; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
        };
        if rc != 0 {
            println!("fstat_socket=ERR:{}", errno());
        } else {
            println!("fstat_socket={}", fstat_type(sv[0]));
            unsafe {
                libc::close(sv[0]);
                libc::close(sv[1]);
            }
        }
    }

    // stdin (fd 0): DOCUMENTATION line — under the harness stdin is a pipe and
    // under `docker run -i` it is also a pipe ("fifo"); the token may differ
    // from a TTY/regular-file environment. Documented via the diff.
    {
        println!("fstat_stdin={}", fstat_type(0));
    }
}

/// Open helper returning the raw fd (or -1 on error).
fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

/// fstat the fd and return its S_IFMT type token, or "ERR:<errno>".
fn fstat_type(fd: i32) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        format!("ERR:{}", errno())
    } else {
        type_token(st.st_mode).to_string()
    }
}

/// Map st_mode & S_IFMT to a fixed deterministic token.
fn type_token(mode: libc::mode_t) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFREG => "reg",
        libc::S_IFDIR => "dir",
        libc::S_IFLNK => "lnk",
        libc::S_IFIFO => "fifo",
        libc::S_IFSOCK => "sock",
        libc::S_IFCHR => "chr",
        libc::S_IFBLK => "blk",
        _ => "other",
    }
}

/// readlinkat a path with a generous buffer; return the errno on failure or
/// 0 on (unexpected) success. Used for the EINVAL/ENOENT edge cases.
fn readlinkat_errno(path: &str) -> i32 {
    let c = CString::new(path).unwrap();
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::readlinkat(
            libc::AT_FDCWD,
            c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n < 0 {
        errno()
    } else {
        0
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
