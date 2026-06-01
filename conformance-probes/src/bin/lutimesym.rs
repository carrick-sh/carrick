//! `utimensat(AT_SYMLINK_NOFOLLOW)` (a.k.a. lutimes) sets the SYMLINK's own
//! timestamps, NOT the target's (libuv fs_lutime). On the --fs host overlay
//! backend carrick set times via open()+futimens, which follows the link — so
//! the target's mtime changed and the symlink's did not.
//!
//!  * link_time_set:   lstat(symlink).mtime == the time we set.
//!  * target_untouched: stat(target).mtime != the time we set (link not followed).

use std::mem::zeroed;

const TGT: &[u8] = b"/tmp/lut_target\0";
const LNK: &[u8] = b"/tmp/lut_link\0";
const PAST: i64 = 400497753; // fixed past epoch (well before "now")

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    libc::unlink(TGT.as_ptr().cast());
    libc::unlink(LNK.as_ptr().cast());

    let fd = libc::open(TGT.as_ptr().cast(), libc::O_CREAT | libc::O_WRONLY, 0o644);
    if fd < 0 {
        println!("setup=false open_target");
        return;
    }
    libc::close(fd);
    if libc::symlink(TGT.as_ptr().cast(), LNK.as_ptr().cast()) != 0 {
        println!("setup=false symlink");
        return;
    }

    let times = [
        libc::timespec {
            tv_sec: PAST,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: PAST,
            tv_nsec: 0,
        },
    ];
    let r = libc::utimensat(
        libc::AT_FDCWD,
        LNK.as_ptr().cast(),
        times.as_ptr(),
        libc::AT_SYMLINK_NOFOLLOW,
    );

    let mut lst: libc::stat = zeroed();
    libc::lstat(LNK.as_ptr().cast(), &mut lst);
    let mut tst: libc::stat = zeroed();
    libc::stat(TGT.as_ptr().cast(), &mut tst);

    let link_mtime = lst.st_mtime as i64;
    let tgt_mtime = tst.st_mtime as i64;
    let link_time_set = link_mtime == PAST;
    let target_untouched = tgt_mtime != PAST;

    println!("utimensat_rc={r}");
    // Do NOT print the raw mtimes — target_mtime is the current wall-clock time
    // (non-deterministic): the carrick and Docker runs can straddle a 1-second
    // boundary under the gate's concurrent load and DIFF. The booleans below
    // (link set to the fixed PAST epoch; target left untouched) are the
    // deterministic contract.
    println!("link_time_set={link_time_set}");
    println!("target_untouched={target_untouched}");

    libc::unlink(LNK.as_ptr().cast());
    libc::unlink(TGT.as_ptr().cast());
}
