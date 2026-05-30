//! Symlink-follow, dangling-symlink, named-pipe-fstat and trailing-slash
//! create edge cases. Each is a place where a macOS-host detail leaked a
//! non-Linux result the CPython fs tests caught (test_shutil copytree/rmtree,
//! test_copyfile_nonexistent_dir). The harness diffs this static binary under
//! carrick and real Linux line by line; on Linux every boolean is `true`.
//!
//! Deterministic only: fixed /tmp paths, no inodes/pids/timestamps; cleanup
//! first so the run is repeatable.

use std::ffi::CString;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn main() {
    unsafe {
        libc::umask(0);

        // -- DANGLING SYMLINK: stat(follow) is ENOENT, lstat is the link -----
        //
        // A symlink to a non-existent target. lstat reports the link (S_IFLNK);
        // stat (which follows) must fail ENOENT — os.path.exists(dangling) is
        // therefore False, as on Linux. carrick's host backend used to report
        // the dead link as a present regular file (exists → True), so
        // shutil.copytree silently copied the dead link instead of raising.
        let dl = cstr("/tmp/slf_dangling");
        libc::unlink(dl.as_ptr());
        let made = libc::symlink(c"/tmp/slf_NO_SUCH_TARGET".as_ptr(), dl.as_ptr()) == 0;
        println!("dangling_setup={}", made);

        let mut lst: libc::stat = std::mem::zeroed();
        let lrc = libc::lstat(dl.as_ptr(), &mut lst);
        println!(
            "dangling_lstat_islnk={}",
            lrc == 0 && (lst.st_mode & libc::S_IFMT) == libc::S_IFLNK
        );

        let mut st: libc::stat = std::mem::zeroed();
        let src = libc::stat(dl.as_ptr(), &mut st);
        println!(
            "dangling_stat_enoent={}",
            src == -1 && errno() == libc::ENOENT
        );
        libc::unlink(dl.as_ptr());

        // -- SYMLINK-to-REAL-FILE: stat(follow) reports the TARGET's mode -----
        let tgt = cstr("/tmp/slf_target");
        let lnk = cstr("/tmp/slf_link");
        libc::unlink(lnk.as_ptr());
        libc::unlink(tgt.as_ptr());
        let fd = libc::open(
            tgt.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o640,
        );
        if fd >= 0 {
            libc::close(fd);
        }
        libc::chmod(tgt.as_ptr(), 0o640);
        libc::symlink(tgt.as_ptr(), lnk.as_ptr());
        let mut ls: libc::stat = std::mem::zeroed();
        let lr = libc::stat(lnk.as_ptr(), &mut ls); // follow
        println!(
            "symlink_follow_target_mode={}",
            lr == 0
                && (ls.st_mode & 0o777) == 0o640
                && (ls.st_mode & libc::S_IFMT) == libc::S_IFREG
        );

        // -- TRAILING-SLASH O_CREAT: always EISDIR ---------------------------
        //
        // open("path/", O_CREAT) can never create a regular file (the trailing
        // slash forces directory semantics) — EISDIR on Linux whether the path
        // exists or not. carrick used to ignore the slash and create the file.
        let ts = cstr("/tmp/slf_nodir/");
        let r1 = libc::open(
            ts.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        println!(
            "create_trailing_slash_eisdir={}",
            r1 == -1 && errno() == libc::EISDIR
        );
        if r1 >= 0 {
            libc::close(r1);
        }
        // Sanity: WITHOUT the trailing slash the create succeeds.
        let nots = cstr("/tmp/slf_nodir");
        libc::unlink(nots.as_ptr());
        let r2 = libc::open(
            nots.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        println!("create_no_slash_ok={}", r2 >= 0);
        if r2 >= 0 {
            libc::close(r2);
        }
        libc::unlink(nots.as_ptr());

        // -- NAMED FIFO: fstat(open) samestat lstat(path) --------------------
        //
        // shutil.rmtree's safe-fd walk lstat()s a path then fstat()s the fd it
        // opened and refuses to recurse unless they samestat. A FIFO opened by
        // path (modelled as a host pipe) used to fstat a SYNTHETIC inode/mode
        // (0o600) that didn't match the real lstat — rmtree mis-classified the
        // pipe as a symlink. fstat must report the real FIFO inode/mode.
        let fifo = cstr("/tmp/slf_fifo");
        libc::unlink(fifo.as_ptr());
        let mk = libc::mkfifo(fifo.as_ptr(), 0o644);
        println!("fifo_setup={}", mk == 0);
        if mk == 0 {
            let mut lf: libc::stat = std::mem::zeroed();
            let lfr = libc::lstat(fifo.as_ptr(), &mut lf);
            let mut flags = libc::O_RDONLY | libc::O_NONBLOCK;
            flags |= libc::O_NOFOLLOW;
            let ffd = libc::open(fifo.as_ptr(), flags);
            let mut ff: libc::stat = std::mem::zeroed();
            let ffr = if ffd >= 0 {
                libc::fstat(ffd, &mut ff)
            } else {
                -1
            };
            if lfr == 0 && ffd >= 0 && ffr == 0 {
                println!(
                    "fifo_fstat_isfifo={}",
                    (ff.st_mode & libc::S_IFMT) == libc::S_IFIFO
                );
                println!(
                    "fifo_samestat={}",
                    lf.st_ino == ff.st_ino && lf.st_dev == ff.st_dev
                );
                println!(
                    "fifo_mode_match={}",
                    (lf.st_mode & 0o777) == (ff.st_mode & 0o777)
                );
            } else {
                println!("fifo_fstat_isfifo=ERR:{}/{}/{}", lfr, ffd, ffr);
                println!("fifo_samestat=ERR");
                println!("fifo_mode_match=ERR");
            }
            if ffd >= 0 {
                libc::close(ffd);
            }
        }
        libc::unlink(fifo.as_ptr());
        libc::unlink(lnk.as_ptr());
        libc::unlink(tgt.as_ptr());
    }
}
